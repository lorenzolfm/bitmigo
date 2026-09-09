// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one timeout the whole node shares, and the one it works out per peer.
//!
//! **The stalling timeout is shared and adaptive**, which is the part worth explaining.
//! Stalling is not "this peer is slow"; it is "the window cannot move, because the block at
//! its left edge is in flight from somebody who has not sent it, and everybody else has run
//! out of things to fetch". The obvious answer — disconnect the peer holding it — is wrong
//! when the reason nothing is arriving is *this* node's own bandwidth: it would disconnect
//! peer after peer and arrive back where it started with fewer connections. So Core doubles
//! the window on each disconnect it causes, up to sixty-four seconds, and decays it back
//! towards two as blocks come in; this node does the same, with the decay hung on the
//! arrivals it can see today (see [`StallTimeout::decay`]).
//!
//! **The block download timeout is per peer and widens with the others.** A peer gets one
//! target spacing to answer, plus half a spacing for every *other* peer that also has
//! blocks in flight, because thirty-two peers sharing one link are each entitled to a
//! smaller share of it. Only blocks this node asked for count towards the widening — the
//! whole in-flight table is this node's own bookkeeping — so a peer cannot buy itself time
//! by naming blocks that do not exist, which is the trap Core's comment on
//! `nOtherPeersWithValidatedDownloads` names.

use std::time::Duration;

/// Core's `BLOCK_STALLING_TIMEOUT_DEFAULT`, and the floor the decay returns to.
pub const STALLING_TIMEOUT_DEFAULT: Duration = Duration::from_secs(2);

/// Core's `BLOCK_STALLING_TIMEOUT_MAX`, and the ceiling the doubling stops at.
pub const STALLING_TIMEOUT_MAX: Duration = Duration::from_secs(64);

/// Core's decay per connected block, as the numerator and denominator of 0.85. Integer
/// arithmetic, so that the same sequence of events gives the same timeout on every machine.
const DECAY_NUMERATOR: u32 = 85;
const DECAY_DENOMINATOR: u32 = 100;

const _: () = assert!(DECAY_NUMERATOR < DECAY_DENOMINATOR, "a decay shrinks");

/// Core's `BLOCK_DOWNLOAD_TIMEOUT_BASE`: one target spacing for the peer itself.
const DOWNLOAD_TIMEOUT_BASE: u32 = 1;

/// Core's `BLOCK_DOWNLOAD_TIMEOUT_PER_PEER`, as a half rather than a float: every other
/// peer with blocks in flight buys this peer half a spacing more.
const DOWNLOAD_TIMEOUT_PER_PEER_HALVES: u32 = 1;

/// The window one peer has to send a block before it is holding up everybody else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StallTimeout {
    current: Duration,
}

impl StallTimeout {
    /// The timeout a node starts with.
    pub fn new() -> StallTimeout {
        StallTimeout {
            current: STALLING_TIMEOUT_DEFAULT,
        }
    }

    /// How long a peer may hold the left edge of the window right now.
    pub fn get(self) -> Duration {
        assert!(self.current >= STALLING_TIMEOUT_DEFAULT);
        assert!(self.current <= STALLING_TIMEOUT_MAX);
        self.current
    }

    /// A stalling peer has just been disconnected: give the next one twice as long.
    ///
    /// Core's reason, and it is about this node rather than about the peer: "so that we
    /// don't disconnect multiple peers if our own bandwidth is insufficient".
    pub fn doubled(&mut self) {
        self.current = self
            .current
            .saturating_mul(2)
            .min(STALLING_TIMEOUT_MAX)
            .max(STALLING_TIMEOUT_DEFAULT);
    }

    /// A block has arrived: decay back towards the default.
    ///
    /// Core decays on each *connected* block, in `BlockConnected`. Nothing reports a
    /// connect back to the chain thread yet — that report arrives with the chainstate
    /// (BM-10) — so this is hung on the arrival instead. The two coincide for every block
    /// of an initial sync, which is the load the timeout exists for, and the field this
    /// reads is a local policy knob rather than anything a peer can observe (R4 §8.2).
    pub fn decay(&mut self) {
        let millis = u32::try_from(self.current.as_millis()).unwrap_or(u32::MAX);
        let decayed = millis
            .saturating_mul(DECAY_NUMERATOR)
            .saturating_div(DECAY_DENOMINATOR);
        self.current = Duration::from_millis(u64::from(decayed)).max(STALLING_TIMEOUT_DEFAULT);
    }
}

impl Default for StallTimeout {
    fn default() -> StallTimeout {
        StallTimeout::new()
    }
}

/// How long this peer has to answer the block at the head of its list.
///
/// `nPowTargetSpacing * (1 + 0.5 * other peers with downloads in flight)`, in whole halves
/// of a spacing so that there is no rounding to argue about.
pub fn download_timeout(spacing: Duration, others_downloading: usize) -> Duration {
    assert!(!spacing.is_zero(), "a chain has a target spacing");
    let others = u32::try_from(others_downloading).unwrap_or(u32::MAX);
    let halves = DOWNLOAD_TIMEOUT_BASE
        .saturating_mul(2)
        .saturating_add(others.saturating_mul(DOWNLOAD_TIMEOUT_PER_PEER_HALVES));
    spacing.saturating_mul(halves) / 2
}

#[cfg(test)]
#[path = "timeouts_tests.rs"]
mod tests;
