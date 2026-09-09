// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which blocks to ask one peer for next.
//!
//! Core's `FindNextBlocksToDownload`, and the two numbers in it are the whole shape of an
//! initial sync. The **window** is a thousand and twenty-four blocks past the last block
//! this node and the peer are known to share: a block outside it is not worth asking for,
//! because the chainstate cannot reach it until everything below it has been connected, and
//! a node that asked for the whole chain at once would hold the whole chain in memory. The
//! **batch** is at least a hundred and twenty-eight headers, walked at a time, because the
//! arena has no child pointers: one skip-list walk to the top of a batch and then parent
//! links down it costs one logarithmic step per batch rather than one per block.
//!
//! The walk skips two kinds of block and notices a third. It skips a block whose bytes this
//! node already has, moving the left edge of the window up as it goes; it skips a block
//! already in flight, from this peer or any other, because plain block download never asks
//! two peers for the same block. And if it reaches the end of the window having collected
//! nothing at all, the peer holding the first in-flight block it saw is the one holding
//! everybody up — that is [`Walk::staller`], and it is the only input the stalling timeout
//! has.

use std::collections::{HashMap, HashSet};

use bitcoin::BlockHash;
use bitmigo_consensus::params::Height;

use super::peers::PeerDownload;
use super::{BLOCK_DOWNLOAD_WINDOW, InFlight, WALK_BATCH};
use crate::chain::{HeaderTree, NodeId};
use crate::peer::SlotIndex;

/// Core's `NODE_NETWORK_LIMITED_MIN_BLOCKS` less the two blocks of slack it allows for: a
/// peer that keeps only the recent chain is asked for nothing deeper than this.
const LIMITED_PEER_DEPTH: u32 = 288 - 2;

/// What one pass over one peer's window found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Walk {
    /// The blocks to ask this peer for, lowest first.
    pub blocks: Vec<NodeId>,
    /// The peer that is holding the window still, if nothing could be collected because of
    /// it. Core's `nodeStaller`.
    pub staller: Option<SlotIndex>,
}

/// Everything the walk reads and does not own.
pub struct Window<'a> {
    /// The header tree, which the chain thread owns.
    pub tree: &'a HeaderTree,
    /// Every block this node has asked anybody for.
    pub in_flight: &'a HashMap<BlockHash, InFlight>,
    /// Every block that has arrived and has nowhere yet to be kept (see [`super::Schedule`]).
    pub delivered: &'a HashSet<BlockHash>,
    /// The work a chain must carry before this node will spend bandwidth on it.
    pub minimum_chain_work: [u8; 32],
}

impl Window<'_> {
    /// Whether this node already has the block behind a header.
    fn have(&self, node: NodeId) -> bool {
        let entry = self.tree.entry(node);
        entry.status().location().is_some() || self.delivered.contains(&entry.hash())
    }
}

/// The next blocks to ask `peer` for, at most `want` of them.
///
/// Updates the peer's last common block as it walks, which is what makes the next pass
/// start where this one stopped rather than at the fork point every time.
pub fn next_blocks(
    window: &Window<'_>,
    state: &mut PeerDownload,
    peer: SlotIndex,
    want: usize,
    limited: bool,
) -> Walk {
    assert!(want > 0 && want <= super::MAX_BLOCKS_IN_FLIGHT);
    let mut walk = Walk::default();
    let tree = window.tree;
    let Some(best) = state.best_known else {
        return walk;
    };
    // Nothing this peer has is worth having: its chain is no better than the one already
    // connected here, or it does not carry the work this chain is defined to need.
    let best_work = tree.entry(best).chainwork();
    if best_work < tree.entry(tree.tip()).chainwork() {
        return walk;
    }
    if best_work.to_be_bytes() < window.minimum_chain_work {
        return walk;
    }

    let mut common = common_block(tree, state, best);
    state.last_common = Some(common);
    if common == best {
        return walk;
    }

    let best_height = tree.entry(best).height().get();
    let window_end = tree
        .entry(common)
        .height()
        .get()
        .saturating_add(BLOCK_DOWNLOAD_WINDOW);
    let last = best_height.min(window_end);
    let mut height = tree.entry(common).height().get().saturating_add(1);
    // The first in-flight block seen, which is the candidate staller: Core's `waitingfor`.
    let mut waiting_for: Option<SlotIndex> = None;

    while walk.blocks.len() < want && height <= last {
        let span = u32::try_from(WALK_BATCH.max(want)).unwrap_or(u32::MAX);
        let batch_end = last.min(height.saturating_add(span).saturating_sub(1));
        for node in batch(tree, best, height, batch_end) {
            let entry = tree.entry(node);
            // Core bails out here rather than skipping: a chain with a block this node has
            // already refused is not a chain worth fetching any part of.
            if entry.status().is_terminal() {
                state.last_common = Some(common);
                return walk;
            }
            if window.have(node) {
                // Contiguously, and only contiguously: a block above a gap says nothing
                // about what this node and the peer share.
                if entry.height().get() == tree.entry(common).height().get().saturating_add(1) {
                    common = node;
                }
                continue;
            }
            if let Some(held) = window.in_flight.get(&entry.hash()) {
                waiting_for = waiting_for.or(Some(held.peer));
                continue;
            }
            if limited && entry.height().get().saturating_add(LIMITED_PEER_DEPTH) < best_height {
                continue;
            }
            walk.blocks.push(node);
            if walk.blocks.len() >= want {
                break;
            }
        }
        height = batch_end.saturating_add(1);
    }

    state.last_common = Some(common);
    // Nothing to fetch, and somebody else's block is why: that peer is holding the window.
    if walk.blocks.is_empty() && waiting_for.is_some_and(|held| held != peer) {
        walk.staller = waiting_for;
    }
    walk
}

/// The left edge of this peer's window.
///
/// Core's two steps: start at the active chain at the peer's height when there is no left
/// edge yet, then take the last block that edge and the peer's best block share. The second
/// step is what moves it back when a peer turns out to be on a fork.
fn common_block(tree: &HeaderTree, state: &PeerDownload, best: NodeId) -> NodeId {
    let known = state.last_common.unwrap_or_else(|| {
        let tip_height = tree.entry(tree.tip()).height();
        let height = tip_height.min(tree.entry(best).height());
        tree.ancestor(tree.tip(), height)
            .expect("a height at or below the tip has an ancestor")
    });
    last_common_ancestor(tree, known, best)
}

/// The deepest block two nodes share. Core's `LastCommonAncestor`.
fn last_common_ancestor(tree: &HeaderTree, left: NodeId, right: NodeId) -> NodeId {
    let (mut left, mut right) = (left, right);
    let height = tree.entry(left).height().min(tree.entry(right).height());
    left = tree.ancestor(left, height).expect("a height at or below");
    right = tree.ancestor(right, height).expect("a height at or below");
    let mut steps: usize = 0;
    while left != right {
        steps = steps.saturating_add(1);
        assert!(steps <= tree.len(), "a walk longer than the tree");
        left = tree.entry(left).parent().expect("genesis is shared");
        right = tree.entry(right).parent().expect("genesis is shared");
    }
    left
}

/// The ancestors of `best` from `first` to `last` inclusive, lowest first.
///
/// One skip-list walk to the top of the range and then parent links down it: the arena has
/// no child pointers, so this is how a forward walk is done at all.
fn batch(tree: &HeaderTree, best: NodeId, first: u32, last: u32) -> Vec<NodeId> {
    assert!(first <= last, "a batch runs upwards");
    let span = usize::try_from(last.saturating_sub(first).saturating_add(1)).unwrap_or(usize::MAX);
    let mut nodes = Vec::with_capacity(span);
    let mut node = tree
        .ancestor(best, Height::new(last))
        .expect("the range is below the peer's best block");
    loop {
        nodes.push(node);
        if tree.entry(node).height().get() <= first {
            break;
        }
        node = tree
            .entry(node)
            .parent()
            .expect("above genesis has a parent");
    }
    assert!(nodes.len() == span, "a batch is the range it was asked for");
    nodes.reverse();
    nodes
}

#[cfg(test)]
#[path = "window_tests.rs"]
mod tests;
