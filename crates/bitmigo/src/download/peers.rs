// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the schedule knows about one connection, and the three questions asked of every
//! peer before it is asked for anything.
//!
//! One row per slot, in a fixed array the chain thread owns: thirty-two rows built at
//! startup, reset when a slot changes hands, and never allocated again. A row is plain
//! `Copy` data because everything that reads or writes it is the chain thread, and a row
//! that outlives its connection is the one bug this module has to be careful about — which
//! is what [`PeerDownload::connection`] is for.

use std::time::{Duration, Instant};

use bitcoin::p2p::ServiceFlags;
use bitmigo_consensus::params::BlockTime;

use crate::chain::NodeId;

/// Core's `HEADERS_DOWNLOAD_TIMEOUT_BASE`: what a peer gets to answer a `getheaders` in
/// before the sync is taken off it, on top of the per-header allowance below.
const HEADERS_TIMEOUT_BASE: Duration = Duration::from_mins(15);

/// Core's `HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER`. A node that is a year behind is asking for
/// fifty thousand headers, and the allowance grows with how many that is.
const HEADERS_TIMEOUT_PER_HEADER: Duration = Duration::from_millis(1);

/// What this node knows about one peer's chain, and what it has asked that peer for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerDownload {
    /// Which connection this row describes, by the instant that connection was made.
    ///
    /// A slot is reused, so a row has to be able to tell one connection from the next: the
    /// blocks asked of the peer that has gone are not owed by the peer that replaced it.
    pub connection: Option<Instant>,
    /// The most-work header this peer has told this node it has, as far as the tree knows.
    ///
    /// Core keeps a second field for a hash it has been told about and has no header for;
    /// this node answers such an announcement with a `getheaders` and lets the header set
    /// this, which costs one round trip and no state that can be poisoned by a stranger.
    pub best_known: Option<NodeId>,
    /// The last block this node and the peer are known to share: the left edge of the
    /// window, and Core's `pindexLastCommonBlock`.
    pub last_common: Option<NodeId>,
    /// When the block at the head of this peer's in-flight list became the head, which is
    /// what the block download timeout measures. Core's `m_downloading_since`.
    pub downloading_since: Option<Instant>,
    /// Since when this peer has been holding the left edge of the window while others have
    /// nothing left to fetch. Core's `m_stalling_since`.
    pub stalling_since: Option<Instant>,
    /// When the last `getheaders` went out, whether or not it has been answered. Core's
    /// `m_last_getheaders_timestamp`, and the rate limit reads it.
    pub getheaders_at: Option<Instant>,
    /// Whether headers are being synced from this peer. Core's `fSyncStarted`, and this
    /// node counts the rows rather than keeping a counter beside them.
    pub sync_started: bool,
    /// When that sync must have made progress by. Cleared by a short `headers`, which is
    /// the peer saying it has no more.
    pub sync_deadline: Option<Instant>,
    /// Whether this node has asked the peer to announce new blocks with `headers`.
    pub sendheaders_sent: bool,
}

impl PeerDownload {
    /// Forget everything: the slot is empty, or holds a different connection.
    pub fn reset(&mut self, connection: Option<Instant>) {
        *self = PeerDownload {
            connection,
            ..PeerDownload::default()
        };
    }

    /// Whether this row is up to date about what is in the slot: the same connection, or
    /// an empty row for an empty slot.
    pub fn describes(&self, connection: Option<Instant>) -> bool {
        self.connection == connection
    }
}

/// Whether a peer can serve blocks at all: Core's `CanServeBlocks`.
pub fn can_serve_blocks(services: ServiceFlags) -> bool {
    services.has(ServiceFlags::NETWORK) || services.has(ServiceFlags::NETWORK_LIMITED)
}

/// Whether a peer keeps only the last few hundred blocks: Core's `IsLimitedPeer`. Such a
/// peer is worth asking for the blocks it still has and nothing else.
pub fn is_limited(services: ServiceFlags) -> bool {
    !services.has(ServiceFlags::NETWORK) && services.has(ServiceFlags::NETWORK_LIMITED)
}

/// Whether a peer can serve a block with its witnesses in it.
///
/// This node asks for `MSG_WITNESS_BLOCK` and nothing else, because every block it will
/// ever validate is validated with the witness rules available (`docs/consensus-rules.md`:
/// Core applies the witness flags from genesis minus three exception blocks). A peer that
/// cannot send witnesses can send this node no block it can use, so it is asked for none —
/// which is Core's `CanServeWitnesses` reached from the other end.
pub fn can_serve_witnesses(services: ServiceFlags) -> bool {
    services.has(ServiceFlags::WITNESS)
}

/// How long a peer has to answer a `getheaders` before the sync is taken off it.
///
/// Core's `HEADERS_DOWNLOAD_TIMEOUT_BASE + HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER * (seconds
/// since the best header) / nPowTargetSpacing`: a quarter of an hour, plus a millisecond
/// for every header this node is likely to be behind by.
pub fn headers_timeout(best_header: BlockTime, now: BlockTime, spacing: Duration) -> Duration {
    assert!(!spacing.is_zero(), "a chain has a target spacing");
    let behind = u64::from(now.get().saturating_sub(best_header.get()));
    let headers = behind / spacing.as_secs().max(1);
    HEADERS_TIMEOUT_BASE.saturating_add(
        HEADERS_TIMEOUT_PER_HEADER.saturating_mul(u32::try_from(headers).unwrap_or(u32::MAX)),
    )
}

#[cfg(test)]
#[path = "peers_tests.rs"]
mod tests;
