// SPDX-License-Identifier: MIT OR Apache-2.0

//! The reorg driver: what the validation thread should do next to move the chainstate onto
//! the most-work chain.
//!
//! One function of the tree, and it covers both cases, because a sync *is* a reorg with
//! nothing to disconnect. Walk back from the target to the last block it shares with the
//! active chain, take the active chain off down to there, then put the target's blocks on
//! from there upward. BM-D1 decision 4: there is no refusal depth — most work wins, as Core
//! does since checkpoints were removed — and a reorg of [`REORG_WARNING_DEPTH`] or more
//! raises a warning on the operator surface rather than a refusal.
//!
//! Two bounds hold it. The plan is capped at the room the connect queue has, so the chain
//! thread never builds a list it cannot hand over and a million-block reorg is a million
//! blocks of *work*, not a million-entry allocation; and the walk to the fork point is
//! bounded by the tree, which is bounded by [`crate::chain::MAX_TREE_HEADERS`].
//!
//! BM-D1 decision 4 also asks the driver to assert undo exists for every step before it
//! starts, which is exactly what the loop below does — but the assertion can no longer
//! fail, because [`HeaderStatus::Connected`] carries the undo record. A step without undo
//! is not a step this module refuses to take; it is a value nothing can construct.

use bitcoin::BlockHash;
use bitmigo_consensus::params::{ChainParams, Height};

use crate::chain::tree::{HeaderStatus, HeaderTree, NodeId};
use crate::runtime::queue::{ConnectJob, JobKind};

/// The reorg depth an operator is told about. Six confirmations is the number the rest of
/// the ecosystem treats as settled, so a reorg that reaches it is news whether or not this
/// node had a choice about following it.
pub const REORG_WARNING_DEPTH: usize = 6;

/// What to hand the validation thread next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reorg {
    fork: NodeId,
    depth: usize,
    jobs: Vec<ConnectJob>,
    missing: Option<BlockHash>,
}

#[allow(
    dead_code,
    reason = "the chain thread reads the depth; handing the jobs over waits on the \
              report that comes back with the chainstate, which is BM-10's"
)]
impl Reorg {
    /// The last block the active chain and the target chain share.
    #[must_use]
    pub fn fork(&self) -> NodeId {
        self.fork
    }

    /// How many blocks come off the active chain in total — not how many are in this
    /// batch. This is the number the six-block warning reads.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The jobs, in the order validation must apply them: disconnects from the tip
    /// downward, then connects upward.
    #[must_use]
    pub fn jobs(&self) -> &[ConnectJob] {
        &self.jobs
    }

    /// Nothing to do: the chainstate is already on the most-work chain this node can build.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Whether an operator should hear about this one.
    #[must_use]
    pub fn is_deep(&self) -> bool {
        self.depth >= REORG_WARNING_DEPTH
    }

    /// The first block on the target chain whose bytes have not arrived, if that is what
    /// stopped the plan short. The download scheduler's cue, and the reason a node that is
    /// merely behind produces a short plan rather than an error.
    #[must_use]
    pub fn missing(&self) -> Option<BlockHash> {
        self.missing
    }
}

impl HeaderTree {
    /// Plan the next `limit` steps towards the most-work header chain.
    ///
    /// Takes `&mut self` because a job carries its block's `Context`, and assembling one
    /// walks the difficulty period through the tree's own scratch buffer. Nothing about the
    /// tree itself changes.
    pub fn reorg(&mut self, params: &ChainParams, limit: usize) -> Reorg {
        assert!(limit > 0, "a plan of no steps is not a plan");
        let target = self.best_header();
        let fork = self.fork_point(target);
        let depth = self.steps_between(self.tip(), fork);
        let mut jobs = Vec::with_capacity(limit);
        self.plan_disconnects(fork, limit, &mut jobs, params);
        let missing = self.plan_connects(target, fork, limit, &mut jobs, params);
        assert!(jobs.len() <= limit);
        Reorg {
            fork,
            depth,
            jobs,
            missing,
        }
    }

    /// The last block on the active chain that `target` descends from.
    ///
    /// Every ancestor of the tip is [`HeaderStatus::Connected`] and nothing else is, so the
    /// question "is this on the active chain" is one field, and the walk always terminates:
    /// genesis is connected in every tree.
    fn fork_point(&self, target: NodeId) -> NodeId {
        // Core's `CChain::FindFork`: drop to the tip's height first, so the walk that
        // follows is bounded by the depth of the fork and not by how far the headers have
        // run ahead of the blocks. During a sync those are a million apart and the fork is
        // genesis, which this reaches in one logarithmic step.
        let tip_height = self.entry(self.tip()).height();
        let mut walk = self.ancestor(target, tip_height).unwrap_or(target);
        let mut steps: usize = 0;
        while !self.is_active(walk) {
            steps = steps.saturating_add(1);
            assert!(steps <= self.len(), "a walk longer than the tree");
            walk = self
                .entry(walk)
                .parent()
                .expect("genesis is active in every tree");
        }
        walk
    }

    /// How many blocks lie between a node and one of its ancestors.
    fn steps_between(&self, node: NodeId, ancestor: NodeId) -> usize {
        let above = self.entry(node).height().get();
        let below = self.entry(ancestor).height().get();
        assert!(below <= above);
        usize::try_from(above.saturating_sub(below)).expect("a height difference fits")
    }

    /// Take the active chain off, tip first, down to the fork.
    ///
    /// The undo assertion BM-D1 decision 4 asks for is made over the *whole* disconnect
    /// side before a single job is emitted, so a reorg this node cannot finish is never
    /// started — even though the walk that checks it can no longer fail, since a connected
    /// block carries its undo record in its status.
    fn plan_disconnects(
        &mut self,
        fork: NodeId,
        limit: usize,
        jobs: &mut Vec<ConnectJob>,
        params: &ChainParams,
    ) {
        let mut walk = self.tip();
        while walk != fork {
            let entry = self.entry(walk);
            assert!(
                matches!(entry.status(), HeaderStatus::Connected { .. }),
                "{walk} is on the active chain without an undo record",
            );
            walk = entry.parent().expect("the fork is an ancestor of the tip");
        }

        let mut walk = self.tip();
        while walk != fork && jobs.len() < limit {
            let entry = self.entry(walk);
            let (hash, location) = (entry.hash(), entry.status().location());
            let parent = entry.parent().expect("the fork is an ancestor of the tip");
            let location = location.expect("a connected block has bytes");
            let context = self.context_of(walk, params);
            jobs.push(ConnectJob {
                kind: JobKind::Disconnect,
                hash,
                context,
                location,
            });
            walk = parent;
        }
    }

    /// Put the target's blocks on, from just above the fork, while their bytes are here.
    ///
    /// Returns the first block whose bytes are missing, which is where the connectable
    /// prefix ends and the download schedule's work begins.
    fn plan_connects(
        &mut self,
        target: NodeId,
        fork: NodeId,
        limit: usize,
        jobs: &mut Vec<ConnectJob>,
        params: &ChainParams,
    ) -> Option<BlockHash> {
        let last = self.entry(target).height().get();
        let mut height = self.entry(fork).height().get().saturating_add(1);
        while jobs.len() < limit && height <= last {
            let Some(node) = self.ancestor(target, Height::new(height)) else {
                panic!("a height at or below the target has an ancestor")
            };
            let entry = self.entry(node);
            let (hash, status) = (entry.hash(), entry.status());
            assert!(
                !status.is_terminal(),
                "the most-work header chain has an invalid block on it",
            );
            let Some(location) = status.location() else {
                return Some(hash);
            };
            let context = self.context_of(node, params);
            jobs.push(ConnectJob {
                kind: JobKind::Connect,
                hash,
                context,
                location,
            });
            height = height.saturating_add(1);
        }
        None
    }
}

#[cfg(test)]
#[path = "reorg_tests.rs"]
mod tests;
