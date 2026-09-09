// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every reason this node ends a connection, in one enum.
//!
//! Core's `Misbehaving` carries no score at v31.1: every call to it is an immediate
//! discourage-and-disconnect, so there is no partial credit and no threshold to tune
//! (R4 §8.8). That makes the whole set of reasons enumerable, which is what this type is —
//! the list a test can walk end to end, rather than a string built at each call site.
//!
//! [`Disconnect::misbehaving`] is the second half of it. A peer that closed its socket and
//! a peer that sent a fifty-thousand-entry `inv` are both disconnected, but only one of
//! them told us something about itself; the address manager will want that distinction, and
//! recording it where the reason is decided is cheaper than reconstructing it later.

use bitcoin::BlockHash;
use bitcoin::p2p::ServiceFlags;
use bitmigo_consensus::block::BlockError;
use bitmigo_consensus::header::HeaderError;

use super::wire::WireError;

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disconnect {
    /// The frame was not one: wrong magic, an impossible length, a bad checksum, more
    /// items than the protocol allows, or a message that never finished arriving.
    Wire(WireError),
    /// Core's `MIN_PEER_PROTO_VERSION`: "disconnect from peers older than this".
    ObsoleteVersion {
        /// What the peer advertised.
        version: u32,
    },
    /// The peer echoed the nonce this node put in its own `version`.
    ConnectedToSelf,
    /// An outbound peer that cannot serve what this node dialled it for. Core's
    /// `HasAllDesirableServiceFlags`, checked only on connections this node made.
    MissingServices {
        /// What the peer offered.
        offered: ServiceFlags,
        /// What this node needs from a peer it dialled.
        wanted: ServiceFlags,
    },
    /// `wtxidrelay`, `sendaddrv2` or `sendtxrcncl` after `verack`. One of the four places
    /// Core disconnects rather than ignores (R4 §8.7).
    NegotiationAfterVerack {
        /// Which message.
        command: &'static str,
    },
    /// Core's `DEFAULT_PEER_CONNECT_TIMEOUT`: the handshake never finished.
    HandshakeTimeout,
    /// Core's `TIMEOUT_INTERVAL`: a ping went unanswered for twenty minutes.
    PingTimeout,
    /// The same twenty minutes of silence, with no ping outstanding to blame.
    Silent,
    /// A transaction, or an inventory of one, after this node said `fRelay = 0`. Core's
    /// "transaction sent in violation of protocol".
    TransactionRelay,
    /// `filterload`, `filteradd` or `filterclear` from a node that does not offer
    /// `NODE_BLOOM` — which this one cannot, having no mempool (BIP111).
    BloomFilter,
    /// `getcfilters`, `getcfheaders` or `getcfcheckpt` without `NODE_COMPACT_FILTERS`.
    /// BIP157 says only "SHOULD NOT respond"; Core disconnects, and so does this.
    CompactFilter,
    /// `mempool`, which BIP35 gates on `NODE_BLOOM`.
    Mempool,
    /// A `block` this node never asked for. The rule that keeps the four-megabyte read cap
    /// from applying to anybody who has not been given one (BM-D5 decision 4).
    UnrequestedBlock {
        /// What arrived.
        hash: BlockHash,
    },
    /// A header that failed `check_header` or `accept_header`.
    InvalidHeader(HeaderError),
    /// A block that failed `check_block` or `accept_block`.
    InvalidBlock(BlockError),
    /// The peer took a `getdata` and did not answer it inside
    /// `nPowTargetSpacing * (1 + 0.5 * other peers downloading)`.
    BlockDownloadTimeout,
    /// The peer is holding the left edge of the download window while every other peer has
    /// run out of blocks to fetch. Core's "Peer is stalling block download".
    BlockStalling,
    /// The peer took the headers sync and stopped answering, while still answering pings —
    /// which is why no other timer here can see it.
    HeadersTimeout,
    /// This node's tip has not moved and its outbound slots are full, so the peer that has
    /// told it least about the chain makes way for one it has not spoken to yet.
    StaleTip,
    /// The peer stopped reading and its megabyte of queued replies filled up.
    OutboxFull,
    /// A write did not complete inside `SO_SNDTIMEO`, or the socket failed.
    WriteFailed,
    /// The peer closed the connection.
    PeerClosed,
    /// The node is stopping, and every socket goes with it.
    NodeStopping,
}

impl Disconnect {
    /// Whether the peer earned this.
    ///
    /// Everything a correct peer can do — closing its socket, going quiet, being dialled by
    /// a node that is shutting down — is false; everything that is a protocol violation or
    /// an invalid block is true. This is the classification Core spends `Misbehaving` on,
    /// recorded where it is decided rather than inferred later.
    pub fn misbehaving(&self) -> bool {
        match self {
            // Wrong magic leads the harmless list, and a real bitcoind is why: Core opens
            // an outbound connection with BIP324's v2 handshake whenever it does not
            // already know the peer speaks v1, so its first sixteen bytes are random and
            // read as another network's magic. It reconnects over v1 straight afterwards
            // and the handshake completes (R4 §6.2). Blaming that would have this node
            // discourage every Core node that dialled it. Matched before the framing arm
            // below, which is what makes it the exception.
            Self::Wire(WireError::WrongMagic { .. })
            | Self::ConnectedToSelf
            | Self::MissingServices { .. }
            | Self::HandshakeTimeout
            | Self::PingTimeout
            | Self::Silent
            | Self::BlockDownloadTimeout
            | Self::BlockStalling
            | Self::HeadersTimeout
            | Self::StaleTip
            | Self::OutboxFull
            | Self::WriteFailed
            | Self::PeerClosed
            | Self::NodeStopping => false,
            Self::Wire(_)
            | Self::ObsoleteVersion { .. }
            | Self::NegotiationAfterVerack { .. }
            | Self::TransactionRelay
            | Self::BloomFilter
            | Self::CompactFilter
            | Self::Mempool
            | Self::UnrequestedBlock { .. }
            | Self::InvalidHeader(_)
            | Self::InvalidBlock(_) => true,
        }
    }
}

impl std::fmt::Display for Disconnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire(error) => write!(f, "{error}"),
            Self::ObsoleteVersion { version } => write!(f, "obsolete version {version}"),
            Self::ConnectedToSelf => f.write_str("connected to self"),
            Self::MissingServices { offered, wanted } => {
                write!(f, "services {offered} where {wanted} are wanted")
            }
            Self::NegotiationAfterVerack { command } => {
                write!(f, "{command} after verack")
            }
            Self::HandshakeTimeout => f.write_str("version handshake timeout"),
            Self::PingTimeout => f.write_str("ping timeout"),
            Self::Silent => f.write_str("inactivity timeout"),
            Self::TransactionRelay => f.write_str("transaction sent in violation of protocol"),
            Self::BloomFilter => f.write_str("bloom filter without NODE_BLOOM"),
            Self::CompactFilter => f.write_str("filter request without NODE_COMPACT_FILTERS"),
            Self::Mempool => f.write_str("mempool request without NODE_BLOOM"),
            Self::UnrequestedBlock { hash } => write!(f, "unrequested block {hash}"),
            Self::InvalidHeader(error) => write!(f, "{error}"),
            Self::InvalidBlock(error) => write!(f, "{error}"),
            Self::BlockDownloadTimeout => f.write_str("timeout downloading block"),
            Self::BlockStalling => f.write_str("stalling block download"),
            Self::HeadersTimeout => f.write_str("timeout downloading headers"),
            Self::StaleTip => f.write_str("stale tip, making way for a new peer"),
            Self::OutboxFull => f.write_str("send buffer full"),
            Self::WriteFailed => f.write_str("write failed"),
            Self::PeerClosed => f.write_str("peer closed the connection"),
            Self::NodeStopping => f.write_str("node stopping"),
        }
    }
}

impl From<WireError> for Disconnect {
    fn from(error: WireError) -> Disconnect {
        Disconnect::Wire(error)
    }
}

#[cfg(test)]
#[path = "disconnect_tests.rs"]
mod tests;
