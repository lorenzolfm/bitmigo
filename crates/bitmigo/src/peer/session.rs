// SPDX-License-Identifier: MIT OR Apache-2.0

//! One connection's protocol state, and everything this node does with a message before the
//! chain thread ever sees it.
//!
//! The reader thread owns this, and owning it is the point. The handshake, the timers, the
//! receipt-time consensus checks and the decision to disconnect all happen on the thread of
//! the peer that caused them: a peer that sends a garbage block pays for the merkle root
//! itself, a peer that dribbles pays with its own thread, and neither costs any other peer
//! anything. The only shared thing a session touches is the bounded queue at the end of it,
//! and that is the one place in the node where blocking is the correct answer (BM-D5
//! decisions 5 and 7).
//!
//! The verdicts are all [`Disconnect`], never a score. Core's `Misbehaving` has no score at
//! v31.1 either: every call is an immediate disconnect, so the whole vocabulary is the
//! enumerable list in [`super::disconnect`] and there is no threshold to get wrong.

use std::time::Instant;

use bitcoin::Block;
use bitcoin::block::Header;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitmigo_consensus::block::{accept_block, check_block};
use bitmigo_consensus::header::check_header;

use super::{
    Connection, Disconnect, Handshake, MAX_MESSAGE_LEN, PEER_TIMEOUT, PING_INTERVAL, READ_CAP_IDLE,
    SlotKind, encode, nonce,
};
use crate::runtime::Shared;
use crate::runtime::queue::PeerMessage;

/// One connection, from the first byte to the reason it ended.
pub struct Session<'a> {
    shared: &'a Shared,
    connection: &'a Connection,
    handshake: Handshake,
    last_received: Instant,
    last_ping_sent: Instant,
    /// The nonce of a `ping` that has not been answered, and when it went out.
    outstanding_ping: Option<(u64, Instant)>,
    received: u64,
}

impl<'a> Session<'a> {
    /// A session for a connection that has just been claimed.
    pub fn new(shared: &'a Shared, connection: &'a Connection) -> Session<'a> {
        let now = Instant::now();
        let start_height = start_height(shared);
        Session {
            shared,
            connection,
            handshake: Handshake::new(
                connection.index.kind(),
                nonce(),
                connection.address,
                start_height,
            ),
            last_received: now,
            last_ping_sent: now,
            outstanding_ping: None,
            received: 0,
        }
    }

    /// What this node says before it has heard anything.
    ///
    /// Only the side that dialled speaks first, which is Core's rule: the dialler knows what
    /// it dialled, and the side that accepted knows nothing until it is told.
    pub fn open(&mut self) -> Result<(), Disconnect> {
        if self.connection.index.kind() != SlotKind::Outbound {
            return Ok(());
        }
        let version = self.handshake.our_version();
        self.send(version)
    }

    /// How large a message this peer may send right now.
    ///
    /// The whole of BM-D5 decision 4's dynamic cap, in one expression: four megabytes to a
    /// peer that owes this node a block, half a megabyte to everybody else. Thirty-two
    /// peers at the full cap would be a hundred and twenty-eight megabytes an attacker
    /// chooses; thirty-two peers that have been asked for nothing are sixteen.
    pub fn cap(&self) -> usize {
        if self.connection.requests.outstanding() > 0 {
            MAX_MESSAGE_LEN
        } else {
            READ_CAP_IDLE
        }
    }

    /// The clocks, checked once per read tick.
    ///
    /// Three timeouts, shortest first: a peer that never finishes the handshake is holding
    /// a slot for nothing; a peer that does not answer a ping is gone without saying so; a
    /// peer that says nothing at all for twenty minutes is the same thing without the
    /// evidence. Core's numbers, and Core's order.
    pub fn tick(&mut self) -> Result<(), Disconnect> {
        if self.handshake.timed_out() {
            return Err(Disconnect::HandshakeTimeout);
        }
        if !self.handshake.is_ready() {
            return Ok(());
        }
        if let Some((_, sent)) = self.outstanding_ping {
            if sent.elapsed() > PEER_TIMEOUT {
                return Err(Disconnect::PingTimeout);
            }
        } else if self.last_ping_sent.elapsed() > PING_INTERVAL {
            let nonce = nonce();
            self.send(NetworkMessage::Ping(nonce))?;
            self.last_ping_sent = Instant::now();
            self.outstanding_ping = Some((nonce, Instant::now()));
        }
        if self.last_received.elapsed() > PEER_TIMEOUT {
            return Err(Disconnect::Silent);
        }
        Ok(())
    }

    /// Take one message off the wire.
    pub fn receive(&mut self, message: NetworkMessage, wire_len: usize) -> Result<(), Disconnect> {
        self.last_received = Instant::now();
        self.received = self.received.saturating_add(1);

        let was_ready = self.handshake.is_ready();
        for reply in self.handshake.receive(&message)? {
            self.send(reply)?;
        }
        if !self.handshake.is_ready() {
            return Ok(());
        }
        if !was_ready {
            self.connection.mark_ready();
            println!(
                "bitmigo: peer {} ready: {} ({}) at {}",
                self.connection.index,
                self.handshake.peer_user_agent(),
                self.handshake.peer_version(),
                self.connection.address,
            );
        }
        self.dispatch(message, wire_len)
    }

    /// What every message that is not the handshake's means to this node.
    ///
    /// The refusals are Core's, and every one of them is a disconnect rather than silence
    /// because Core does the same (R4 §4.2, §8.7): a peer that asks a node with no mempool
    /// for its mempool, or a node offering no `NODE_BLOOM` for a bloom filter, is not
    /// speaking to the node it thinks it is.
    fn dispatch(&mut self, message: NetworkMessage, wire_len: usize) -> Result<(), Disconnect> {
        match message {
            NetworkMessage::Ping(nonce) => self.send(NetworkMessage::Pong(nonce)),
            NetworkMessage::Pong(nonce) => {
                // Unsolicited pongs and mismatched nonces are logged, never punished:
                // Core's rule, and there is nothing an attacker gains by either.
                if self.outstanding_ping.is_some_and(|(sent, _)| sent == nonce) {
                    self.outstanding_ping = None;
                }
                Ok(())
            }
            NetworkMessage::Block(block) => self.block(block, wire_len),
            NetworkMessage::Headers(headers) => self.headers(headers, wire_len),
            NetworkMessage::Inv(items) => self.inventory(items, wire_len),
            // Requests and answers the chain thread owns: what to ask for next, what to
            // serve, and what a peer has told us about other peers.
            NetworkMessage::GetHeaders(_)
            | NetworkMessage::GetData(_)
            | NetworkMessage::NotFound(_)
            | NetworkMessage::GetAddr
            | NetworkMessage::Addr(_)
            | NetworkMessage::AddrV2(_) => self.forward(message, wire_len),
            // A transaction, after this node said `fRelay = 0`. Core's exact verdict.
            NetworkMessage::Tx(_) => Err(Disconnect::TransactionRelay),
            NetworkMessage::MemPool => Err(Disconnect::Mempool),
            NetworkMessage::FilterLoad(_)
            | NetworkMessage::FilterAdd(_)
            | NetworkMessage::FilterClear => Err(Disconnect::BloomFilter),
            NetworkMessage::GetCFilters(_)
            | NetworkMessage::GetCFHeaders(_)
            | NetworkMessage::GetCFCheckpt(_) => Err(Disconnect::CompactFilter),
            // Everything else is ignored, which for several of these is the whole defence:
            // never sending `sendcmpct` is what forbids a peer from ever asking for a
            // compact block, and never sending `getblocks` is what makes the answer to one
            // somebody else's problem (R4 §4.2, §7).
            _ => Ok(()),
        }
    }

    /// A block, which is the only message that reaches four megabytes and the only one that
    /// costs real work to check.
    ///
    /// The order is the rule: the request first, so that an unrequested block is refused
    /// before a hash is computed; then `check_block`, which needs nothing but the block;
    /// then `accept_block` against the context that travelled with the request, which is
    /// fixed by ancestors that cannot change and so needs no lock on anything.
    fn block(&mut self, block: Block, wire_len: usize) -> Result<(), Disconnect> {
        let hash = block.block_hash();
        let request = self
            .connection
            .requests
            .take(hash)
            .ok_or(Disconnect::UnrequestedBlock { hash })?;
        assert_eq!(request.hash, hash, "a request answers the block it named");

        check_block(&block, &self.shared.params).map_err(Disconnect::InvalidBlock)?;
        accept_block(&block, &request.context).map_err(Disconnect::InvalidBlock)?;
        self.forward(NetworkMessage::Block(block), wire_len)
    }

    /// Headers, checked for proof of work here and placed in the tree by the chain thread.
    ///
    /// `check_header` is context-free, so it runs on this thread; `accept_header` needs the
    /// header's ancestors and belongs to the thread that owns the tree. Doing the cheap
    /// half here means a peer that sends two thousand headers with no work behind them pays
    /// for two thousand hashes on its own thread and reaches nothing shared.
    fn headers(&mut self, headers: Vec<Header>, wire_len: usize) -> Result<(), Disconnect> {
        // Bounded by `MAX_HEADERS_ITEMS`, which the framer enforced before this was built.
        for header in &headers {
            check_header(header, &self.shared.params).map_err(Disconnect::InvalidHeader)?;
        }
        self.forward(NetworkMessage::Headers(headers), wire_len)
    }

    /// An inventory. Block announcements are the chain thread's; transaction announcements
    /// are Core's "inv sent in violation of protocol", because this node said it wanted none.
    fn inventory(&mut self, items: Vec<Inventory>, wire_len: usize) -> Result<(), Disconnect> {
        // Bounded by `MAX_INV_ITEMS`, enforced by the framer.
        for item in &items {
            match item {
                Inventory::Transaction(_)
                | Inventory::WitnessTransaction(_)
                | Inventory::WTx(_) => {
                    return Err(Disconnect::TransactionRelay);
                }
                _ => {}
            }
        }
        self.forward(NetworkMessage::Inv(items), wire_len)
    }

    /// Hand a message to the chain thread.
    ///
    /// The one place in the node a thread may wait for room on a queue, and it waits here
    /// because waiting here stops one socket and no other: the kernel stops acknowledging
    /// this peer's data, and every other peer carries on untouched.
    fn forward(&self, message: NetworkMessage, wire_len: usize) -> Result<(), Disconnect> {
        let queued = PeerMessage::new(self.connection.index, message, wire_len);
        self.shared
            .to_chain
            .send(queued)
            .map(|_sent| ())
            .map_err(|_closed| Disconnect::NodeStopping)
    }

    /// Queue one message for this connection's writer thread.
    fn send(&self, message: NetworkMessage) -> Result<(), Disconnect> {
        let frame = encode(self.shared.network.magic(), message);
        self.connection
            .outbox
            .push(frame)
            .map_err(|_full| Disconnect::OutboxFull)
    }

    /// How many messages this connection has delivered.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// What the peer said it was, for the line printed when the connection ends.
    pub fn peer_user_agent(&self) -> &str {
        self.handshake.peer_user_agent()
    }
}

/// The height this node claims in its `version`, from the published snapshot rather than
/// from the chain thread's own state: the operator surface reads the same copy.
fn start_height(shared: &Shared) -> i32 {
    let height = shared.status.read().tip_height.get();
    i32::try_from(height).unwrap_or(i32::MAX)
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
