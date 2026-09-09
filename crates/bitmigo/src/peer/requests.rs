// SPDX-License-Identifier: MIT OR Apache-2.0

//! What this node has asked one peer for, and has not been given yet.
//!
//! Two rules hang off this table, both of them BM-D5 decision 4's:
//!
//! - **Unrequested `block` messages are refused.** A headers-first node asks for every
//!   block it wants; a block nobody asked for is either a mistake or an attempt to make
//!   this node do four megabytes of work on the sender's schedule.
//! - **The read cap follows it.** A peer with an outstanding request may send a
//!   four-megabyte message; a peer with none may not send more than half a megabyte. That
//!   is what keeps thirty-two anonymous peers from holding a hundred and twenty-eight
//!   megabytes of this node's memory between them.
//!
//! Each record carries the block's [`Context`], which is BM-D5 decision 5: a block's
//! context is fixed by its ancestors' headers, which are immutable once accepted, so the
//! request can carry everything the receipt-time checks need and the reader thread can run
//! `check_block` and `accept_block` without touching a single piece of shared state.
//!
//! Filling this table is the download scheduler's work. What lives here is the table, the
//! bound on it, and the two rules the reader thread reads off it.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use bitcoin::BlockHash;
use bitmigo_consensus::header::Context;

use crate::runtime::sync::lock;

/// Core's `MAX_BLOCKS_IN_TRANSIT_PER_PEER` (R4 §3.1). A bound on how much of the download
/// window one peer can be holding, and so on how many four-megabyte reads it can have
/// licensed at once.
pub const MAX_BLOCKS_IN_FLIGHT: usize = 16;

/// One block asked of one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRequest {
    /// The block asked for.
    pub hash: BlockHash,
    /// Everything the receipt-time checks need, fixed by the block's ancestors.
    pub context: Context,
    /// When the `getdata` was queued, which is what the stall timeout is measured from.
    pub requested_at: Instant,
}

/// One peer's outstanding block requests, oldest first.
///
/// A deque rather than a map: sixteen entries scanned linearly is a handful of comparisons
/// against a block that has just cost a merkle root, and a bounded scan has no worst case
/// an adversary can choose.
pub struct Requests {
    outstanding: Mutex<VecDeque<BlockRequest>>,
    max: usize,
}

impl Requests {
    /// An empty table at the per-peer bound.
    pub fn new() -> Requests {
        Requests::with_bound(MAX_BLOCKS_IN_FLIGHT)
    }

    /// An empty table at a stated bound.
    pub fn with_bound(max: usize) -> Requests {
        assert!(max > 0 && max <= MAX_BLOCKS_IN_FLIGHT);
        Requests {
            outstanding: Mutex::new(VecDeque::with_capacity(max)),
            max,
        }
    }

    #[allow(
        dead_code,
        reason = "the reader reads this table; the scheduler that fills it is BM-23"
    )]
    /// Record a request. Refuses past the bound, and refuses a block already asked of this
    /// peer: both would be this node's own scheduling bug, and neither is worth the state.
    pub fn record(&self, request: BlockRequest) -> bool {
        let mut outstanding = lock(&self.outstanding);
        if outstanding.len() >= self.max {
            return false;
        }
        if outstanding.iter().any(|held| held.hash == request.hash) {
            return false;
        }
        outstanding.push_back(request);
        true
    }

    /// Take the request this block answers. `None` is the refuse-unrequested rule: the peer
    /// sent a block nobody asked it for.
    pub fn take(&self, hash: BlockHash) -> Option<BlockRequest> {
        let mut outstanding = lock(&self.outstanding);
        let at = outstanding.iter().position(|held| held.hash == hash)?;
        outstanding.remove(at)
    }

    /// How many blocks this peer owes. Zero is what makes its read cap the idle one.
    pub fn outstanding(&self) -> usize {
        lock(&self.outstanding).len()
    }

    /// When the oldest outstanding request was made, which is what a stall is measured
    /// from. The scheduler owns the timeout itself.
    #[allow(dead_code, reason = "the adaptive 2-64 s stall timeout is BM-23's")]
    pub fn oldest(&self) -> Option<Instant> {
        lock(&self.outstanding)
            .front()
            .map(|held| held.requested_at)
    }

    /// Give up on everything asked of this peer: the connection has ended, and the blocks
    /// go back to the scheduler to ask somebody else for.
    pub fn clear(&self) -> usize {
        let mut outstanding = lock(&self.outstanding);
        let given_up = outstanding.len();
        outstanding.clear();
        given_up
    }
}

impl Default for Requests {
    fn default() -> Requests {
        Requests::new()
    }
}

#[cfg(test)]
#[path = "requests_tests.rs"]
mod tests;
