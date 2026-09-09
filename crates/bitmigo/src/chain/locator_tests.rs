// SPDX-License-Identifier: MIT OR Apache-2.0

//! Locators, and the `getheaders` answer read off the same structure.

use super::MAX_LOCATOR_ENTRIES;
use crate::chain::fixture;
use crate::chain::tree::{HeaderTree, NodeId};
use crate::peer::MAX_HEADERS_ITEMS;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use bitmigo_consensus::params::{ChainParams, Height};

/// A tree with `count` headers on genesis, of which the first `connected` are blocks whose
/// coins are in the chainstate.
fn chain_of(count: usize, connected: usize) -> (HeaderTree, ChainParams, Vec<BlockHash>) {
    let params = fixture::params();
    let mut tree = HeaderTree::new(&params);
    let headers = fixture::chain(&params.genesis().header, count, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    if connected > 0 {
        fixture::connect_through(&mut tree, *nodes.get(connected - 1).expect("in range"));
    }
    let mut hashes = vec![params.genesis_hash()];
    hashes.extend(headers.iter().map(bitcoin::block::Header::block_hash));
    (tree, params, hashes)
}

#[test]
fn a_locator_walks_back_by_one_ten_times_and_then_doubles() {
    let (tree, _params, hashes) = chain_of(64, 0);
    let tip = tree.best_header();
    let locator = tree.locator(tip);

    // The first eleven entries are consecutive, from the tip downward.
    for (step, hash) in locator.iter().take(11).enumerate() {
        let height = 64 - u32::try_from(step).expect("bounded");
        let at = usize::try_from(height).expect("a height fits");
        assert_eq!(*hash, *hashes.get(at).expect("in range"));
    }
    // It always ends at genesis, which is what lets two nodes that share nothing else still
    // find a fork point.
    assert_eq!(locator.last(), Some(hashes.first().expect("genesis")));
    assert!(locator.len() <= MAX_LOCATOR_ENTRIES);

    // And every step after the tenth is at least as large as the one before it.
    let heights: Vec<u32> = locator
        .iter()
        .map(|hash| {
            let node = tree
                .node_of(*hash)
                .expect("the locator names our own blocks");
            tree.entry(node).height().get()
        })
        .collect();
    for pair in heights.windows(3).skip(9) {
        if let [first, second, third] = pair {
            assert!(first - second <= second - third);
        }
    }
}

#[test]
fn a_locator_from_genesis_is_one_entry() {
    let (tree, params, _hashes) = chain_of(4, 0);
    assert_eq!(tree.locator(NodeId::GENESIS), vec![params.genesis_hash()]);
}

#[test]
fn the_fork_point_is_the_first_locator_entry_on_the_active_chain() {
    let (tree, _params, hashes) = chain_of(20, 8);
    let unknown = BlockHash::from_byte_array([9u8; 32]);

    // Blocks 9 to 20 have headers but no coins, so they are not on the active chain.
    let locator = vec![
        unknown,
        *hashes.get(12).expect("in range"),
        *hashes.get(6).expect("in range"),
        *hashes.first().expect("genesis"),
    ];
    let fork = tree.fork_in_active_chain(&locator);
    assert_eq!(tree.entry(fork).height(), Height::new(6));

    // A locator naming nothing this node has falls back to genesis, as Core's does.
    assert_eq!(tree.fork_in_active_chain(&[unknown]), NodeId::GENESIS,);
    assert_eq!(tree.fork_in_active_chain(&[]), NodeId::GENESIS);
}

#[test]
fn getheaders_is_answered_from_the_active_chain_and_stops_at_its_tip() {
    let (tree, _params, hashes) = chain_of(30, 10);
    let locator = vec![*hashes.get(4).expect("in range")];
    let headers = tree.headers_after(&locator, fixture::nothing(), MAX_HEADERS_ITEMS);

    // Six headers: five to ten. The twenty above them are headers this node has and blocks
    // it has not, and serving those would be claiming a chain it cannot yet defend.
    assert_eq!(headers.len(), 6);
    for (step, header) in headers.iter().enumerate() {
        let height = 5 + step;
        assert_eq!(header.block_hash(), *hashes.get(height).expect("in range"));
    }
}

#[test]
fn getheaders_stops_after_the_block_the_peer_named() {
    let (tree, _params, hashes) = chain_of(30, 20);
    let locator = vec![*hashes.get(2).expect("in range")];
    let stop = *hashes.get(7).expect("in range");
    let headers = tree.headers_after(&locator, stop, MAX_HEADERS_ITEMS);

    // Core pushes the stop block and then breaks, so it is the last one served.
    assert_eq!(headers.len(), 5);
    assert_eq!(
        headers.last().map(bitcoin::block::Header::block_hash),
        Some(stop),
    );
}

#[test]
fn getheaders_never_serves_more_than_it_was_asked_for() {
    let (tree, _params, hashes) = chain_of(30, 30);
    let locator = vec![*hashes.first().expect("genesis")];
    let headers = tree.headers_after(&locator, fixture::nothing(), 4);

    assert_eq!(headers.len(), 4);
    assert_eq!(
        headers.first().map(bitcoin::block::Header::block_hash),
        Some(*hashes.get(1).expect("in range")),
    );
}

#[test]
fn a_peer_already_at_the_tip_is_answered_with_nothing() {
    let (tree, _params, hashes) = chain_of(12, 12);
    let locator = vec![*hashes.get(12).expect("the tip")];
    assert!(
        tree.headers_after(&locator, fixture::nothing(), MAX_HEADERS_ITEMS)
            .is_empty()
    );
}

#[test]
fn the_same_locator_twice_gets_the_same_answer() {
    // Presync asks for the same range a second time and aborts the sync on any difference
    // (R4 §2.4), so a serving node that answered from anything that moves would look like
    // an attacker to every syncing Core peer.
    let (tree, _params, hashes) = chain_of(40, 25);
    let locator = tree.locator(tree.tip());
    let first = tree.headers_after(&locator, fixture::nothing(), MAX_HEADERS_ITEMS);
    let second = tree.headers_after(&locator, fixture::nothing(), MAX_HEADERS_ITEMS);
    assert_eq!(first, second);

    // And the answer follows the active chain, not the most-work headers: fifteen of these
    // blocks are still undownloaded, and none of them is served.
    let from_genesis = tree.headers_after(
        &[*hashes.first().expect("genesis")],
        fixture::nothing(),
        MAX_HEADERS_ITEMS,
    );
    assert_eq!(from_genesis.len(), 25);
}
