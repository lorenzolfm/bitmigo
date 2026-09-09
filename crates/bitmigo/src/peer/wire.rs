// SPDX-License-Identifier: MIT OR Apache-2.0

//! v1 framing, with the bounds the `bitcoin` crate does not impose.
//!
//! The crate at 0.32.102 gives correct v1 framing and verifies the payload checksum, but
//! its `MAX_MSG_SIZE` is five megabytes against Core's four, and it enforces no inventory,
//! locator, header or address counts at all (R4 §6.3, §8.10). Every one of those is a
//! number an anonymous peer picks, so all of them are imposed here, *above* the crate:
//!
//! - the length is refused **before** a byte of payload is read, so nothing is ever
//!   allocated from a length a peer declared beyond a cap this node chose;
//! - the cap itself is dynamic — four megabytes only while this peer owes us a block,
//!   half a megabyte otherwise — because the only message that legitimately reaches four
//!   megabytes is a `block`, and a headers-first node never has to accept one it did not
//!   ask for (BM-D5 decision 4);
//! - the item counts are checked after decoding, against Core's own constants, so that a
//!   fifty-thousand-entry `inv` is a disconnect rather than a walk.
//!
//! The framer is a state machine rather than a loop because its socket has a one-second
//! read timeout: a message arrives across as many calls as the peer chooses to spread it
//! over, and the deadline that bounds a peer dribbling one byte at a time lives here, on
//! the whole message, where no per-read timeout can be defeated by sending one more byte.

use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};

/// Core's `CMessageHeader`: magic, twelve bytes of message type, a little-endian length and
/// four bytes of checksum.
pub const HEADER_BYTES: usize = 24;

/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH`. The crate's own `MAX_MSG_SIZE` is 5 MB, which is
/// why this is imposed here rather than inherited (R4 §8.10).
pub const MAX_MESSAGE_LEN: usize = 4_000_000;

/// Core's `MAX_INV_SZ`, for `inv`, `getdata` and `notfound`. Core calls `Misbehaving` past
/// it, which in v31.1 means an immediate disconnect (R4 §8.8).
pub const MAX_INV_ITEMS: usize = 50_000;

/// Core's `MAX_LOCATOR_SZ`, for `getheaders` and `getblocks`. One of the four places Core
/// disconnects rather than ignores (R4 §8.7).
pub const MAX_LOCATOR_ITEMS: usize = 101;

/// Core's `MAX_HEADERS_RESULTS`. Protocol, not policy: its own comment says changing it is
/// a protocol upgrade (R4 §8.2).
pub const MAX_HEADERS_ITEMS: usize = 2_000;

/// Core's `MAX_ADDR_TO_SEND`, which BIP155 states as well: "One message can contain up to
/// 1,000 addresses. Clients SHOULD reject messages with more addresses".
pub const MAX_ADDR_ITEMS: usize = 1_000;

/// Why a frame was refused. Every variant is a disconnect: none of them is something a
/// correct peer does, and none of them leaves the stream at a message boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The four leading bytes are another network's.
    WrongMagic {
        /// What arrived.
        seen: [u8; 4],
    },
    /// The message type is not twelve bytes of printable ASCII zero-padded to the end.
    BadCommand,
    /// The declared length is past Core's own protocol maximum.
    TooLong {
        /// What the peer declared.
        declared: usize,
    },
    /// The declared length is within the protocol maximum but past what this peer is
    /// currently allowed to make this node hold.
    OverCap {
        /// What the peer declared.
        declared: usize,
        /// What it was allowed.
        cap: usize,
    },
    /// The payload did not decode: a bad checksum, a truncated body, trailing bytes.
    Malformed,
    /// More inventory, header or address entries than the protocol allows.
    TooManyItems {
        /// How many arrived.
        seen: usize,
        /// How many were allowed.
        allowed: usize,
    },
    /// A message was begun and not finished inside [`MESSAGE_DEADLINE`].
    Stalled,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongMagic { seen } => write!(f, "wrong magic {seen:02x?}"),
            Self::BadCommand => f.write_str("invalid message type"),
            Self::TooLong { declared } => write!(f, "message of {declared} bytes"),
            Self::OverCap { declared, cap } => {
                write!(f, "message of {declared} bytes over the {cap} byte cap")
            }
            Self::Malformed => f.write_str("malformed message"),
            Self::TooManyItems { seen, allowed } => {
                write!(f, "{seen} items where {allowed} are allowed")
            }
            Self::Stalled => f.write_str("message deadline"),
        }
    }
}

/// What one call to [`Framer::read`] produced.
#[derive(Debug)]
pub enum Frame {
    /// A whole message, and the bytes it took on the wire.
    Message(NetworkMessage, usize),
    /// Nothing completed; the socket had nothing more to give this instant.
    Idle,
    /// The peer closed, or this node shut the socket down.
    Eof,
}

/// One peer's read side: the buffer, how much of the current message is in it, and when
/// that message started arriving.
pub struct Framer {
    magic: Magic,
    /// Header and payload contiguously, so that the whole frame decodes without a copy.
    buffer: Vec<u8>,
    /// Bytes of the current frame that have arrived.
    got: usize,
    /// The declared payload length, once the header has been read.
    declared: Option<usize>,
    /// When the first byte of the current message arrived.
    started: Option<Instant>,
    /// How long one message may take from its first byte to its last.
    deadline: Duration,
}

impl Framer {
    /// A framer for one connection, with the buffer allocated once.
    ///
    /// The deadline is passed rather than read from the constant so that a test can watch
    /// the rule fire without waiting two minutes for it.
    pub fn new(magic: Magic, initial_bytes: usize, deadline: Duration) -> Framer {
        assert!(initial_bytes >= HEADER_BYTES);
        assert!(!deadline.is_zero());
        Framer {
            magic,
            buffer: vec![0u8; initial_bytes],
            got: 0,
            declared: None,
            started: None,
            deadline,
        }
    }

    /// Forget a half-read message and keep the buffer.
    ///
    /// Called between connections: the buffer is the thread's, the message state is the
    /// connection's, and a reader that has grown its buffer for one peer's block keeps it
    /// for the next peer's.
    pub fn reset(&mut self) {
        self.got = 0;
        self.declared = None;
        self.started = None;
    }

    /// Whether a message is half-read. A connection with nothing in progress can be closed
    /// at a message boundary; one with a message in progress cannot.
    #[allow(
        dead_code,
        reason = "evidence for the tests that the length was accepted"
    )]
    pub fn in_progress(&self) -> bool {
        self.got > 0
    }

    /// Read once, and return a message if that completed one.
    ///
    /// `cap` is what this peer may make the node hold *right now*: [`MAX_MESSAGE_LEN`] only
    /// while it owes a block, and the idle cap otherwise. Exactly one read per call, so the
    /// caller's socket timeout stays the thread's only blocking point.
    pub fn read(&mut self, stream: &TcpStream, cap: usize) -> Result<Frame, WireError> {
        assert!(
            cap <= MAX_MESSAGE_LEN,
            "the protocol maximum is the hard cap"
        );
        let want = self.want();
        assert!(
            want > self.got,
            "a completed frame is taken before the next read"
        );
        assert!(
            want <= self.buffer.len(),
            "the buffer is grown before it is filled"
        );

        let filled = match self.buffer.get_mut(self.got..want) {
            Some(room) => match (&*stream).read(room) {
                Ok(0) => return Ok(Frame::Eof),
                Ok(read) => read,
                Err(error) => return self.after_idle(&error),
            },
            // Unreachable behind the two assertions above; a `Result` rather than a panic
            // because this module never panics on a path a peer can reach.
            None => return Err(WireError::Malformed),
        };
        if self.started.is_none() {
            self.started = Some(Instant::now());
        }
        self.got = self.got.saturating_add(filled);
        self.settle(cap)
    }

    /// How far into the buffer the next read may fill: the header, until it says how long
    /// the payload is, and then the whole frame.
    fn want(&self) -> usize {
        match self.declared {
            None => HEADER_BYTES,
            Some(declared) => HEADER_BYTES.saturating_add(declared),
        }
    }

    /// What the bytes that just arrived amount to: a header, whose length is checked and
    /// whose payload is made room for; a whole message; or neither yet.
    fn settle(&mut self, cap: usize) -> Result<Frame, WireError> {
        if self.declared.is_none() {
            if self.got < HEADER_BYTES {
                return Ok(Frame::Idle);
            }
            let declared = self.parse_header(cap)?;
            self.declared = Some(declared);
            let want = HEADER_BYTES.saturating_add(declared);
            if self.buffer.len() < want {
                // The only allocation a peer's declared length can cause, and it has just
                // been bounded by `cap`. The buffer is kept afterwards.
                self.buffer.resize(want, 0);
            }
        }
        let declared = self.declared.unwrap_or_default();
        if self.got >= HEADER_BYTES.saturating_add(declared) {
            return self.finish(declared);
        }
        Ok(Frame::Idle)
    }

    /// Core's `V1Transport::readHeader`, in its order: magic, message type, length.
    fn parse_header(&self, cap: usize) -> Result<usize, WireError> {
        let header = self
            .buffer
            .get(..HEADER_BYTES)
            .ok_or(WireError::Malformed)?;
        let magic: [u8; 4] = header
            .get(..4)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(WireError::Malformed)?;
        if magic != self.magic.to_bytes() {
            return Err(WireError::WrongMagic { seen: magic });
        }
        let command = header.get(4..16).ok_or(WireError::Malformed)?;
        if !is_message_type_valid(command) {
            return Err(WireError::BadCommand);
        }
        let length: [u8; 4] = header
            .get(16..20)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(WireError::Malformed)?;
        let declared = usize::try_from(u32::from_le_bytes(length)).unwrap_or(usize::MAX);
        if declared > MAX_MESSAGE_LEN {
            return Err(WireError::TooLong { declared });
        }
        if declared > cap {
            return Err(WireError::OverCap { declared, cap });
        }
        Ok(declared)
    }

    /// Decode the frame in the buffer and reset for the next one. The crate verifies the
    /// checksum here, which is why this node does not hash the payload a second time.
    fn finish(&mut self, declared: usize) -> Result<Frame, WireError> {
        let wire_len = HEADER_BYTES.saturating_add(declared);
        let frame = self.buffer.get(..wire_len).ok_or(WireError::Malformed)?;
        let decoded: RawNetworkMessage = deserialize(frame).map_err(|_| WireError::Malformed)?;
        self.got = 0;
        self.declared = None;
        self.started = None;
        let message = decoded.into_payload();
        check_counts(&message)?;
        Ok(Frame::Message(message, wire_len))
    }

    /// A read that gave nothing. The timeouts are ticks, not errors — but a message that
    /// was begun and not finished inside the deadline is the dribbler this bound exists
    /// for, and no per-read timeout can catch it.
    fn after_idle(&self, error: &std::io::Error) -> Result<Frame, WireError> {
        match error.kind() {
            std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted => match self.started {
                Some(started) if started.elapsed() > self.deadline => Err(WireError::Stalled),
                _ => Ok(Frame::Idle),
            },
            _ => Ok(Frame::Eof),
        }
    }
}

/// Core's `CMessageHeader::IsMessageTypeValid`: printable ASCII up to the first zero, and
/// nothing but zeros after it.
fn is_message_type_valid(command: &[u8]) -> bool {
    let mut padding = false;
    for byte in command {
        if padding {
            if *byte != 0 {
                return false;
            }
        } else if *byte == 0 {
            padding = true;
        } else if !(0x20..=0x7e).contains(byte) {
            return false;
        }
    }
    true
}

/// The counts the crate leaves to its caller. Core's numbers, and Core's verdict: every one
/// of these is a disconnect rather than a truncation, because a peer that sends one is not
/// speaking the protocol.
pub fn check_counts(message: &NetworkMessage) -> Result<(), WireError> {
    let (seen, allowed) = match message {
        NetworkMessage::Inv(items)
        | NetworkMessage::GetData(items)
        | NetworkMessage::NotFound(items) => (items.len(), MAX_INV_ITEMS),
        NetworkMessage::GetHeaders(request) => (request.locator_hashes.len(), MAX_LOCATOR_ITEMS),
        NetworkMessage::GetBlocks(request) => (request.locator_hashes.len(), MAX_LOCATOR_ITEMS),
        NetworkMessage::Headers(headers) => (headers.len(), MAX_HEADERS_ITEMS),
        NetworkMessage::Addr(addresses) => (addresses.len(), MAX_ADDR_ITEMS),
        NetworkMessage::AddrV2(addresses) => (addresses.len(), MAX_ADDR_ITEMS),
        _ => return Ok(()),
    };
    if seen > allowed {
        return Err(WireError::TooManyItems { seen, allowed });
    }
    Ok(())
}

/// One message, framed and ready for a writer thread.
///
/// Encoding is where this node is a peer rather than a judge, so the crate does all of it:
/// the length and the checksum are computed from the payload it just serialized, and cannot
/// disagree with it.
pub fn encode(magic: Magic, message: NetworkMessage) -> Vec<u8> {
    let frame = serialize(&RawNetworkMessage::new(magic, message));
    assert!(frame.len() >= HEADER_BYTES, "a frame carries its header");
    frame
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
