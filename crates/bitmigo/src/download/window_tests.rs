// SPDX-License-Identifier: MIT OR Apache-2.0

//! The window walk: what it collects, what it skips, and where it stops.
//!
//! Regtest headers are nearly free to mine, so these build the shapes a real peer would
//! have to spend work on — a chain a thousand blocks long, a fork under the tip, a peer
//! whose best block is on a branch this node has already refused.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use bitcoin::BlockHash;
use bitmigo_consensus::params::{ChainParams, Height};

use super::{LIMITED_PEER_DEPTH, Walk, Window, next_blocks};
use crate::chain::{HeaderTree, Invalidity, NodeId, fixture};
use crate::download::InFlight;
use crate::download::peers::PeerDownload;
use crate::peer::SlotIndex;

/// A tree holding `count` regtest headers above genesis, and their nodes.
fn chain_of(count: usize) -> (ChainParams, HeaderTree, Vec<NodeId>) {
    let params = fixture::params();
    let mut tree = HeaderTree::new(&params);
    let headers = fixture::chain(&params.genesis().header, count, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    (params, tree, nodes)
}

/// Everything the walk reads, with nothing in flight and nothing delivered.
struct Held {
    in_flight: HashMap<BlockHash, InFlight>,
    delivered: HashSet<BlockHash>,
}

impl Held {
    fn new() -> Held {
        Held {
            in_flight: HashMap::new(),
            delivered: HashSet::new(),
        }
    }

    fn window<'a>(&'a self, tree: &'a HeaderTree) -> Window<'a> {
        Window {
            tree,
            in_flight: &self.in_flight,
            delivered: &self.delivered,
            minimum_chain_work: [0u8; 32],
        }
    }

    /// Say that `peer` has been asked for this block.
    fn asked(&mut self, tree: &HeaderTree, node: NodeId, peer: SlotIndex) {
        self.in_flight.insert(
            tree.entry(node).hash(),
            InFlight {
                peer,
                requested_at: Instant::now(),
            },
        );
    }
}

/// A peer whose best known block is `best`.
fn peer_at(best: NodeId) -> PeerDownload {
    PeerDownload {
        best_known: Some(best),
        ..PeerDownload::default()
    }
}

fn slot(position: usize) -> SlotIndex {
    SlotIndex::from_position(position)
}

/// The heights the walk asked for.
fn heights(tree: &HeaderTree, walk: &Walk) -> Vec<u32> {
    walk.blocks
        .iter()
        .map(|node| tree.entry(*node).height().get())
        .collect()
}

#[test]
fn a_peer_that_has_said_nothing_is_asked_for_nothing() {
    let (_params, tree, _nodes) = chain_of(4);
    let held = Held::new();
    let mut state = PeerDownload::default();

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    assert!(walk.blocks.is_empty());
    assert_eq!(walk.staller, None);
    assert_eq!(
        state.last_common, None,
        "there is nothing to have in common"
    );
}

#[test]
fn a_peer_whose_chain_is_no_better_than_ours_is_asked_for_nothing() {
    let (_params, mut tree, nodes) = chain_of(4);
    let last = *nodes.last().expect("four headers");
    fixture::connect_through(&mut tree, last);
    let held = Held::new();
    let mut state = peer_at(last);

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    assert!(walk.blocks.is_empty(), "its chain is the one we are on");
    assert_eq!(state.last_common, Some(last));
}

#[test]
fn the_walk_asks_for_the_blocks_above_the_last_common_block() {
    let (_params, tree, nodes) = chain_of(40);
    let held = Held::new();
    let mut state = peer_at(*nodes.last().expect("forty headers"));

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    // Sixteen, lowest first, starting one above genesis: the tip is genesis, and that is
    // the last block this node and the peer share.
    assert_eq!(heights(&tree, &walk), (1..=16).collect::<Vec<u32>>());
    assert_eq!(state.last_common, Some(NodeId::GENESIS));
}

#[test]
fn the_walk_asks_for_no_more_than_it_was_asked_for() {
    let (_params, tree, nodes) = chain_of(40);
    let held = Held::new();
    let mut state = peer_at(*nodes.last().expect("forty headers"));

    for want in [1, 3, 16] {
        let mut state = state;
        let walk = next_blocks(&held.window(&tree), &mut state, slot(0), want, false);
        assert_eq!(walk.blocks.len(), want);
    }
    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);
    assert_eq!(walk.blocks.len(), 16);
}

#[test]
fn the_window_stops_a_thousand_and_twenty_four_blocks_past_the_last_common_block() {
    let (_params, tree, nodes) = chain_of(1100);
    let mut held = Held::new();
    // Everything inside the window is already asked for, of somebody else.
    for node in nodes.iter().take(1024) {
        held.asked(&tree, *node, slot(1));
    }
    let mut state = peer_at(*nodes.last().expect("eleven hundred headers"));

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    // Block 1025 exists, its header is in the tree, and the peer has it — and it is still
    // not asked for, because the left edge of the window has not moved.
    assert!(
        walk.blocks.is_empty(),
        "the window is a thousand and twenty-four blocks wide, not the whole chain",
    );
    assert_eq!(state.last_common, Some(NodeId::GENESIS));
}

#[test]
fn the_left_edge_moves_over_the_blocks_this_node_already_has() {
    let (_params, mut tree, nodes) = chain_of(40);
    // Ten blocks whose bytes are on the disk, and block twenty-one with a gap under it.
    for node in nodes.iter().take(10) {
        fixture::check(&mut tree, *node);
    }
    let gapped = *nodes.get(20).expect("forty headers");
    fixture::check(&mut tree, gapped);
    assert_eq!(tree.entry(gapped).height(), Height::new(21));
    let held = Held::new();
    let mut state = peer_at(*nodes.last().expect("forty headers"));

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    // Eleven to twenty, then twenty-one skipped because its bytes are already here, then
    // on past it: sixteen blocks asked for, and none of them one this node holds.
    let expected: Vec<u32> = (11..=20).chain(22..=27).collect();
    assert_eq!(heights(&tree, &walk), expected);
    let common = state.last_common.expect("ten blocks in common");
    assert_eq!(
        tree.entry(common).height(),
        Height::new(10),
        "the edge stops at the gap: a block above one is no evidence about what we share",
    );
}

#[test]
fn a_block_that_has_arrived_is_not_asked_for_again() {
    let (_params, tree, nodes) = chain_of(40);
    let mut held = Held::new();
    let first = *nodes.first().expect("forty headers");
    held.delivered.insert(tree.entry(first).hash());
    let mut state = peer_at(*nodes.last().expect("forty headers"));

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    assert_eq!(heights(&tree, &walk), (2..=17).collect::<Vec<u32>>());
    assert_eq!(
        state.last_common,
        Some(first),
        "a block held is a block shared"
    );
}

#[test]
fn a_block_already_in_flight_is_left_to_the_peer_that_owes_it() {
    let (_params, tree, nodes) = chain_of(40);
    let mut held = Held::new();
    let third = *nodes.get(2).expect("forty headers");
    held.asked(&tree, third, slot(1));
    let mut state = peer_at(*nodes.last().expect("forty headers"));

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    let asked = heights(&tree, &walk);
    assert!(
        !asked.contains(&3),
        "no block is asked of two peers at once"
    );
    assert_eq!(asked.len(), 16);
    assert_eq!(walk.staller, None, "there was plenty else to fetch");
}

#[test]
fn the_peer_holding_the_left_edge_of_a_full_window_is_the_staller() {
    let (_params, tree, nodes) = chain_of(1100);
    let mut held = Held::new();
    // The whole window is in flight from one other peer, so this one can collect nothing.
    for node in nodes.iter().take(1024) {
        held.asked(&tree, *node, slot(1));
    }
    let mut state = peer_at(*nodes.last().expect("eleven hundred headers"));

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    assert!(walk.blocks.is_empty());
    assert_eq!(
        walk.staller,
        Some(slot(1)),
        "the first block seen, and whose"
    );
}

#[test]
fn a_peer_is_never_named_the_staller_of_its_own_window() {
    let (_params, tree, nodes) = chain_of(1100);
    let mut held = Held::new();
    for node in nodes.iter().take(1024) {
        held.asked(&tree, *node, slot(0));
    }
    let mut state = peer_at(*nodes.last().expect("eleven hundred headers"));

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    assert!(walk.blocks.is_empty());
    assert_eq!(
        walk.staller, None,
        "a peer waiting on itself is not stalled"
    );
}

#[test]
fn a_pruned_peer_is_asked_only_for_the_blocks_it_still_has() {
    let (_params, tree, nodes) = chain_of(500);
    let held = Held::new();
    let best = *nodes.last().expect("five hundred headers");
    let mut state = peer_at(best);

    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, true);

    let best_height = tree.entry(best).height().get();
    let lowest = best_height.saturating_sub(LIMITED_PEER_DEPTH);
    let asked = heights(&tree, &walk);
    assert_eq!(asked.len(), 16);
    assert!(
        asked.iter().all(|height| *height >= lowest),
        "a limited peer keeps {LIMITED_PEER_DEPTH} blocks, and is asked for those",
    );
}

#[test]
fn a_fork_moves_the_last_common_block_back_to_the_fork_point() {
    let params = fixture::params();
    let mut tree = HeaderTree::new(&params);
    let trunk = fixture::chain(&params.genesis().header, 10, 1, &params);
    let trunk_nodes = fixture::accept_all(&mut tree, &trunk, &params);
    // A branch off the fifth block, mined with a different merkle root.
    let fork_at = trunk.get(4).copied().expect("ten headers");
    let branch = fixture::chain(&fork_at, 8, 2, &params);
    let branch_nodes = fixture::accept_all(&mut tree, &branch, &params);
    fixture::connect_through(&mut tree, *trunk_nodes.last().expect("ten headers"));

    let held = Held::new();
    let mut state = peer_at(*branch_nodes.last().expect("eight headers"));
    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);

    let common = state.last_common.expect("the fork point is shared");
    assert_eq!(tree.entry(common).height(), Height::new(5));
    assert_eq!(heights(&tree, &walk), (6..=13).collect::<Vec<u32>>());
}

#[test]
fn a_chain_with_a_refused_block_on_it_is_not_fetched_past_that_block() {
    let (_params, mut tree, nodes) = chain_of(40);
    let bad = *nodes.get(4).expect("forty headers");
    tree.invalidate(
        bad,
        Invalidity::AcceptHeader(bitmigo_consensus::header::HeaderError::HighHash),
    );
    let held = Held::new();
    let mut state = peer_at(*nodes.get(3).expect("forty headers"));
    // The peer's own best block is still good; the walk stops when it reaches the bad one.
    let walk = next_blocks(&held.window(&tree), &mut state, slot(0), 16, false);
    assert_eq!(heights(&tree, &walk), vec![1, 2, 3, 4]);

    let mut beyond = peer_at(*nodes.get(8).expect("forty headers"));
    let walk = next_blocks(&held.window(&tree), &mut beyond, slot(0), 16, false);
    assert_eq!(
        heights(&tree, &walk),
        vec![1, 2, 3, 4],
        "nothing above a block this node has refused is worth a byte",
    );
}
