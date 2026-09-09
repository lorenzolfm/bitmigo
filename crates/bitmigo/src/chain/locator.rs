// SPDX-License-Identifier: MIT OR Apache-2.0

//! Locators, and the `getheaders` answer read off the same structure.
//!
//! A locator is how two nodes find the last block they agree on without either of them
//! saying how long its chain is: a list of hashes walking back from a tip, at step one for
//! the first ten and then doubling, always ending at genesis
//! (`chain.cpp: LocatorEntries`). The receiver takes the first entry it has on its own
//! active chain and serves forward from there.
//!
//! Serving it deterministically is a requirement, not a nicety. Core's headers presync
//! asks the same range twice and aborts the sync on any disagreement between the two passes
//! (R4 §2.4, `headerssync.cpp: ValidateAndStoreRedownloadedHeader`), so a node that answers
//! from anything but its own active chain — say, the most-work header chain, which moves
//! while blocks are still downloading — would look to every syncing Core peer like an
//! attacker. [`HeaderTree::headers_after`] reads the active chain and nothing else.

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitmigo_consensus::params::Height;

use crate::chain::tree::{HeaderTree, NodeId};
use crate::peer::{MAX_HEADERS_ITEMS, MAX_LOCATOR_ITEMS};

/// The most entries a locator this node builds can have.
///
/// Eleven at step one, then a doubling step that covers the remaining height in `log2` of
/// it, then genesis: thirty-three at a tree of [`crate::chain::MAX_TREE_HEADERS`], and
/// fewer on any real chain. Core reserves thirty-two for the same list and refuses one of
/// more than [`MAX_LOCATOR_ITEMS`] on receipt, so this stays far inside what a peer accepts.
#[allow(
    dead_code,
    reason = "the locators this bounds are built by BM-23 and BM-24"
)]
pub const MAX_LOCATOR_ENTRIES: usize = 40;

#[allow(
    dead_code,
    reason = "the download schedule builds locators (BM-23) and the block server answers \
              getheaders from them (BM-24); both read this, and both are tested here first"
)]
impl HeaderTree {
    /// The locator for a node's chain, in Core's shape.
    #[must_use]
    pub fn locator(&self, from: NodeId) -> Vec<BlockHash> {
        let mut have = Vec::with_capacity(MAX_LOCATOR_ENTRIES);
        let mut step: u32 = 1;
        let mut walk = from;
        loop {
            let entry = self.entry(walk);
            have.push(entry.hash());
            assert!(have.len() <= MAX_LOCATOR_ENTRIES, "a locator ran away");
            if entry.height() == Height::GENESIS {
                break;
            }
            let back = Height::new(entry.height().get().saturating_sub(step));
            walk = self
                .ancestor(walk, back)
                .expect("a height at or below this one has an ancestor");
            if have.len() > 10 {
                step = step.saturating_mul(2);
            }
        }
        have
    }

    /// The first hash in `locator` that is on this node's active chain, or genesis.
    ///
    /// Core's `FindForkInGlobalIndex`. Bounded by the number of entries the framer already
    /// refused a message for exceeding, so a peer cannot buy a long scan with a long list.
    #[must_use]
    pub fn fork_in_active_chain(&self, locator: &[BlockHash]) -> NodeId {
        assert!(locator.len() <= MAX_LOCATOR_ITEMS, "the framer bounds this");
        for hash in locator.iter().take(MAX_LOCATOR_ITEMS) {
            if let Some(node) = self.node_of(*hash)
                && self.is_active(node)
            {
                return node;
            }
        }
        NodeId::GENESIS
    }

    /// The answer to one `getheaders`: the active chain forward from the locator's fork
    /// point, at most `max` of them, stopping after `stop` if that block is on the way.
    ///
    /// `stop` is the message's `hash_stop`; the all-zero hash a peer sends when it wants
    /// whatever there is names no block and so clamps nothing.
    #[must_use]
    pub fn headers_after(&self, locator: &[BlockHash], stop: BlockHash, max: usize) -> Vec<Header> {
        assert!(max > 0 && max <= MAX_HEADERS_ITEMS);
        let fork = self.fork_in_active_chain(locator);
        let first = self.entry(fork).height().get().saturating_add(1);
        let tip_height = self.entry(self.tip()).height().get();
        if first > tip_height {
            return Vec::new();
        }
        let span = u32::try_from(max).expect("a bounded count fits");
        let mut last = tip_height.min(first.saturating_add(span).saturating_sub(1));
        // Core pushes the stop block and then breaks, so it is the last header served.
        if let Some(node) = self.node_of(stop) {
            let height = self.entry(node).height().get();
            if self.is_active(node) && height >= first && height < last {
                last = height;
            }
        }

        let mut headers = Vec::with_capacity(
            usize::try_from(last.saturating_sub(first).saturating_add(1)).expect("bounded by max"),
        );
        let mut walk = self
            .ancestor(self.tip(), Height::new(last))
            .expect("a height at or below the tip has an ancestor");
        // Backwards, because the arena has no child pointers, then turned around: one walk
        // of `max` steps rather than `max` walks of the skip list.
        loop {
            let entry = self.entry(walk);
            headers.push(*entry.header());
            if entry.height().get() <= first {
                break;
            }
            walk = entry.parent().expect("above genesis has a parent");
        }
        headers.reverse();
        assert!(headers.len() <= max);
        headers
    }
}

#[cfg(test)]
#[path = "locator_tests.rs"]
mod tests;
