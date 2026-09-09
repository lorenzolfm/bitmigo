// SPDX-License-Identifier: MIT OR Apache-2.0

//! The header tree: what goes in, what is refused, what the refusal costs the sender, and
//! the invariants Core asserts in `CheckBlockIndex` (storage doc §3.4).

use super::{
    AcceptError, Accepted, HeaderStatus, HeaderTree, Invalidity, NodeId, add_work, skip_height,
};
use crate::chain::fixture;
use bitcoin::block::Version;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::FromHex;
use bitcoin::pow::Work;
use bitcoin::{BlockHash, CompactTarget};
use bitmigo_consensus::header::{
    HeaderError, block_work, decode_target, hash_meets_target, median_time_past,
};
use bitmigo_consensus::params::{BlockTime, ChainParams, Height};

/// A regtest chain mined by the system bitcoind v31.1.0, genesis to height 200: one 80-byte
/// header per line, hex. See `tests/data/README.md` for how it is regenerated and why 200.
const BITCOIND_REGTEST_HEADERS: &str = include_str!("../../tests/data/regtest-headers.hex");

/// The invariants Core's `CheckBlockIndex` asserts, in the shape this tree has them
/// (storage doc §3.4). Run after anything that moves a status or a chain.
fn check_invariants(tree: &HeaderTree) {
    let genesis = tree.entry(NodeId::GENESIS);
    assert_eq!(genesis.height(), Height::GENESIS);
    assert_eq!(genesis.parent(), None);
    assert_eq!(genesis.status(), HeaderStatus::Genesis);
    assert!(tree.len() <= super::MAX_TREE_HEADERS);

    let mut connected: usize = 0;
    for node in tree.nodes() {
        let entry = tree.entry(node);
        let Some(parent) = entry.parent() else {
            assert_eq!(node, NodeId::GENESIS, "only genesis has no parent");
            continue;
        };
        let above = tree.entry(parent);
        // Parents come first, heights are consecutive, and work never decreases.
        assert!(parent < node, "a child is appended after its parent");
        assert_eq!(entry.height(), above.height().next());
        assert!(entry.chainwork() > above.chainwork());
        assert_eq!(tree.node_of(entry.hash()), Some(node));
        assert_eq!(tree.ancestor(node, above.height()), Some(parent));

        // A block is connected only if its parent is: the active chain has no gaps.
        if entry.status().is_connected() {
            connected = connected.saturating_add(1);
            assert!(above.status().is_connected());
        }
        // Undo exists for every step of the active chain, by construction.
        if let HeaderStatus::Connected { undo, .. } = entry.status() {
            assert!(undo.len > 0);
        }
        // A terminal parent leaves no non-terminal child.
        if above.status().is_terminal() {
            assert!(entry.status().is_terminal());
        }
        // Nothing has more work than the best header unless it is invalid.
        if entry.chainwork() > tree.entry(tree.best_header()).chainwork() {
            assert!(entry.status().is_terminal());
        }
    }

    // The active chain is exactly the tip and its ancestors, genesis included.
    let tip = tree.entry(tree.tip());
    assert!(tip.status().is_connected());
    assert_eq!(
        connected,
        usize::try_from(tip.height().get()).expect("a height fits"),
        "connected blocks above genesis are the tip's ancestors and nothing else",
    );
    assert!(!tree.entry(tree.best_header()).status().is_terminal());
}

fn tree() -> (HeaderTree, ChainParams) {
    let params = fixture::params();
    let tree = HeaderTree::new(&params);
    (tree, params)
}

#[test]
fn a_new_tree_is_the_chains_genesis_and_nothing_else() {
    let (tree, params) = tree();
    assert_eq!(tree.len(), 1);
    assert_eq!(tree.tip(), NodeId::GENESIS);
    assert_eq!(tree.best_header(), NodeId::GENESIS);
    assert_eq!(tree.entry(NodeId::GENESIS).hash(), params.genesis_hash());
    // Genesis is its own state: no parent, no context, no undo, and never disconnected.
    assert_eq!(tree.entry(NodeId::GENESIS).status(), HeaderStatus::Genesis);
    assert!(tree.is_active(NodeId::GENESIS));
    check_invariants(&tree);
}

#[test]
fn headers_accepted_in_order_build_a_chain() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 20, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);

    assert_eq!(tree.len(), 21);
    assert_eq!(tree.best_header(), *nodes.last().expect("twenty nodes"));
    assert_eq!(tree.entry(tree.best_header()).height(), Height::new(20));
    // The tip has not moved: a header says nothing about the block behind it.
    assert_eq!(tree.tip(), NodeId::GENESIS);
    for (index, node) in nodes.iter().enumerate() {
        let height = u32::try_from(index).expect("bounded") + 1;
        assert_eq!(tree.entry(*node).height(), Height::new(height));
        assert_eq!(tree.entry(*node).status(), HeaderStatus::HeaderAccepted);
    }
    check_invariants(&tree);
}

#[test]
fn accepting_a_header_hands_back_the_context_its_block_is_judged_against() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 14, 1, &params);
    fixture::accept_all(&mut tree, &headers, &params);
    let mut times = vec![BlockTime::new(params.genesis().header.time)];
    for header in &headers {
        times.push(BlockTime::new(header.time));
    }

    let last = headers.last().copied().expect("fourteen headers");
    let next = fixture::child(&last, 1, &params);
    let Accepted::First { context, .. } = tree
        .accept(&next, &params, fixture::now())
        .expect("a fixture header goes in")
    else {
        panic!("a header mined here is new");
    };

    assert_eq!(context.height(), Height::new(15));
    assert_eq!(context.previous_time(), BlockTime::new(last.time));
    // The median of the eleven timestamps ending at the parent, computed the other way.
    let window: Vec<BlockTime> = times.iter().rev().take(11).copied().collect();
    assert_eq!(context.median_time_past(), median_time_past(&window));
    // Regtest never retargets, so the required bits are the pow limit's, every time.
    assert_eq!(context.required_bits(), last.bits);
    // Every regtest deployment is buried at height one, so the rules are all on by now.
    assert!(context.rules().bip34_active());
    assert!(context.rules().segwit_active());
    // Core zeroes regtest's BIP34 block hash, so no ancestor can ever match it and the
    // BIP30 duplicate scan runs forever on this chain — which is the tree's own answer to
    // `rules_at` arriving, and the reason it goes looking for that ancestor at all. The
    // boundary is checked by every header at height one, where `rules_at` asserts the
    // ancestor is *not* supplied at the deployment's own height.
    assert!(context.rules().bip30_check_required());
}

#[test]
fn the_same_header_twice_is_the_same_node() {
    let (mut tree, params) = tree();
    let header = fixture::child(&params.genesis().header, 1, &params);
    let first = tree.accept(&header, &params, fixture::now()).expect("new");
    let again = tree
        .accept(&header, &params, fixture::now())
        .expect("known");

    assert!(matches!(first, Accepted::First { .. }));
    assert_eq!(again, Accepted::Duplicate { node: first.node() });
    assert_eq!(tree.len(), 2);
    check_invariants(&tree);
}

#[test]
fn a_header_with_no_work_is_refused_and_never_stored() {
    let (mut tree, params) = tree();
    let mut forged = fixture::child(&params.genesis().header, 1, &params);
    forged.bits = CompactTarget::from_consensus(0x0300_0001);

    let error = tree
        .accept(&forged, &params, fixture::now())
        .expect_err("no work behind it");
    assert_eq!(error, AcceptError::CheckHeader(HeaderError::HighHash));
    // The whole point: a header an attacker did not pay for buys no room in the tree.
    assert_eq!(tree.len(), 1);
    assert_eq!(error.peer_fault(), Some(HeaderError::HighHash));
    check_invariants(&tree);
}

#[test]
fn a_header_whose_parent_is_unknown_is_refused_and_nobody_is_blamed() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 2, 1, &params);
    let orphan = headers.last().copied().expect("two headers");

    let error = tree
        .accept(&orphan, &params, fixture::now())
        .expect_err("headers-first has no orphan buffer");
    assert_eq!(
        error,
        AcceptError::UnknownParent {
            previous: orphan.prev_blockhash,
        },
    );
    assert_eq!(tree.len(), 1);
    assert_eq!(error.peer_fault(), None);
}

#[test]
fn a_header_that_fails_a_contextual_rule_is_stored_as_invalid_and_blamed() {
    let (mut tree, params) = tree();
    // `nTime` at the parent's own time: not past its median time past, which for a chain of
    // one block is the genesis timestamp itself.
    let genesis = params.genesis().header;
    let early = fixture::child_at(&genesis, 1, genesis.time, &params);

    let error = tree
        .accept(&early, &params, fixture::now())
        .expect_err("time-too-old");
    let AcceptError::Invalid { node, invalidity } = error else {
        panic!("a contextual failure is final, so it is recorded: {error:?}")
    };
    assert!(matches!(
        invalidity,
        Invalidity::AcceptHeader(HeaderError::TimeTooOld { .. }),
    ));
    // Stored, because the context is fixed by ancestors and can never make it valid later.
    assert_eq!(tree.len(), 2);
    assert_eq!(
        tree.entry(node).status(),
        HeaderStatus::Invalid { invalidity }
    );
    assert!(error.peer_fault().is_some());
    // And it is not a candidate for anything.
    assert_eq!(tree.best_header(), NodeId::GENESIS);
    check_invariants(&tree);
}

#[test]
fn a_header_below_the_version_floor_is_invalid() {
    let (mut tree, params) = tree();
    // Regtest buries BIP34, BIP66 and BIP65 at height one, so the floor there is four.
    let mut old = fixture::child(&params.genesis().header, 1, &params);
    old.version = Version::from_consensus(3);
    // Re-mined at the lower version: the nonce that worked is for a different header.
    let target = decode_target(old.bits, params.pow_limit()).expect("regtest's own bits");
    old.nonce = 0;
    while !hash_meets_target(old.block_hash(), target) {
        old.nonce = old.nonce.saturating_add(1);
    }

    let error = tree
        .accept(&old, &params, fixture::now())
        .expect_err("bad-version");
    assert!(matches!(
        error,
        AcceptError::Invalid {
            invalidity: Invalidity::AcceptHeader(HeaderError::BadVersion { .. }),
            ..
        },
    ));
    assert!(error.peer_fault().is_some());
}

#[test]
fn a_header_from_the_future_is_refused_without_being_condemned() {
    let (mut tree, params) = tree();
    let header = fixture::child(&params.genesis().header, 1, &params);
    // A clock two hours and a second behind the header's own timestamp.
    let now = BlockTime::new(header.time.saturating_sub(7_201));

    let error = tree
        .accept(&header, &params, now)
        .expect_err("more than two hours ahead");
    assert!(matches!(error, AcceptError::TooFarInFuture { .. }));
    assert_eq!(error.peer_fault(), None);
    // Not stored: there is no state that means "perhaps later", so the header must be able
    // to arrive again and be taken.
    assert_eq!(tree.len(), 1);

    let later = BlockTime::new(header.time);
    assert!(tree.accept(&header, &params, later).is_ok());
    assert_eq!(tree.len(), 2);
    check_invariants(&tree);
}

#[test]
fn a_child_of_an_invalid_header_inherits_the_verdict_and_costs_its_sender_nothing() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 4, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    let culprit_node = *nodes.first().expect("four nodes");
    let culprit = tree.entry(culprit_node).hash();

    tree.invalidate(
        culprit_node,
        Invalidity::CheckBlock(bitmigo_consensus::block::BlockError::DuplicateTransactions),
    );

    // The three headers already above it inherited the verdict in one pass.
    for node in nodes.iter().skip(1) {
        assert_eq!(
            tree.entry(*node).status(),
            HeaderStatus::InvalidAncestor { culprit },
        );
    }
    // And so does one that arrives afterwards.
    let extra = fixture::child(headers.last().expect("four headers"), 2, &params);
    let error = tree
        .accept(&extra, &params, fixture::now())
        .expect_err("its ancestor is invalid");
    let AcceptError::InvalidAncestor { node, culprit: on } = error else {
        panic!("expected an inherited verdict: {error:?}")
    };
    assert_eq!(on, culprit);
    assert_eq!(
        tree.entry(node).status(),
        HeaderStatus::InvalidAncestor { culprit }
    );
    // The relayer of somebody else's bad block answers for nothing.
    assert_eq!(error.peer_fault(), None);
    // With that branch gone, the best header falls back to genesis.
    assert_eq!(tree.best_header(), NodeId::GENESIS);
    check_invariants(&tree);
}

#[test]
fn invalidating_one_branch_leaves_the_other_as_the_best_header() {
    let (mut tree, params) = tree();
    let genesis = params.genesis().header;
    let long = fixture::chain(&genesis, 6, 1, &params);
    let short = fixture::chain(&genesis, 4, 2, &params);
    let long_nodes = fixture::accept_all(&mut tree, &long, &params);
    let short_nodes = fixture::accept_all(&mut tree, &short, &params);

    // More work wins while both are good.
    assert_eq!(tree.best_header(), *long_nodes.last().expect("six"));

    tree.invalidate(
        *long_nodes.first().expect("six"),
        Invalidity::Confirm(bitmigo_consensus::block::ConfirmError::BadCoinbaseAmount {
            paid: 1,
            allowed: 0,
        }),
    );
    assert_eq!(tree.best_header(), *short_nodes.last().expect("four"));
    check_invariants(&tree);
}

#[test]
fn equal_work_keeps_the_header_that_arrived_first() {
    let (mut tree, params) = tree();
    let genesis = params.genesis().header;
    let first = fixture::chain(&genesis, 3, 1, &params);
    let second = fixture::chain(&genesis, 3, 2, &params);
    let first_nodes = fixture::accept_all(&mut tree, &first, &params);
    let second_nodes = fixture::accept_all(&mut tree, &second, &params);

    assert_ne!(first_nodes.last(), second_nodes.last());
    assert_eq!(
        tree.entry(*first_nodes.last().expect("three")).chainwork(),
        tree.entry(*second_nodes.last().expect("three")).chainwork(),
    );
    // Core's `nSequenceId` tie-break: two nodes given the same headers pick the same chain.
    assert_eq!(tree.best_header(), *first_nodes.last().expect("three"));
    check_invariants(&tree);
}

#[test]
fn a_block_walks_from_header_to_checked_to_connected_and_back() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 3, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    let first = *nodes.first().expect("three");

    tree.block_checked(first, fixture::location(1));
    assert_eq!(
        tree.entry(first).status(),
        HeaderStatus::BlockChecked {
            location: fixture::location(1),
        },
    );
    assert_eq!(tree.tip(), NodeId::GENESIS, "bytes on disk are not a tip");

    tree.connected(first, fixture::undo(1));
    assert_eq!(
        tree.entry(first).status(),
        HeaderStatus::Connected {
            location: fixture::location(1),
            undo: fixture::undo(1),
        },
    );
    assert_eq!(tree.tip(), first);
    check_invariants(&tree);

    tree.disconnected(first);
    // The bytes stay where they were: the store never deletes, so coming back this way
    // costs nothing.
    assert_eq!(
        tree.entry(first).status(),
        HeaderStatus::BlockChecked {
            location: fixture::location(1),
        },
    );
    assert_eq!(tree.tip(), NodeId::GENESIS);
    check_invariants(&tree);
}

#[test]
#[should_panic(expected = "connects somewhere other than the tip")]
fn a_block_cannot_connect_anywhere_but_the_tip() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 3, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    let second = *nodes.get(1).expect("three");
    tree.block_checked(second, fixture::location(2));
    tree.connected(second, fixture::undo(2));
}

#[test]
#[should_panic(expected = "only a checked block connects")]
fn a_block_whose_bytes_are_unknown_cannot_connect() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 1, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    tree.connected(*nodes.first().expect("one"), fixture::undo(1));
}

#[test]
#[should_panic(expected = "is not the tip")]
fn only_the_tip_disconnects() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 2, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    fixture::connect_through(&mut tree, *nodes.last().expect("two"));
    tree.disconnected(*nodes.first().expect("two"));
}

#[test]
#[should_panic(expected = "on the active chain")]
fn a_block_on_the_active_chain_is_taken_off_before_it_is_refused() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 2, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    let first = *nodes.first().expect("two");
    fixture::connect_through(&mut tree, first);
    tree.invalidate(
        first,
        Invalidity::CheckBlock(bitmigo_consensus::block::BlockError::DuplicateTransactions),
    );
}

#[test]
fn the_skip_list_reaches_every_ancestor_the_parent_walk_does() {
    let (mut tree, params) = tree();
    let headers = fixture::chain(&params.genesis().header, 300, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    let tip = *nodes.last().expect("three hundred");

    for height in 0..=300u32 {
        let target = Height::new(height);
        let found = tree.ancestor(tip, target).expect("at or below the tip");
        assert_eq!(tree.entry(found).height(), target);
        // The same answer a walk of parent links gives, which is what the skip list is
        // an optimisation of and nothing more.
        let mut walk = tip;
        while tree.entry(walk).height() > target {
            walk = tree.entry(walk).parent().expect("above genesis");
        }
        assert_eq!(found, walk);
    }
    assert_eq!(tree.ancestor(NodeId::GENESIS, Height::new(1)), None);
}

#[test]
fn the_skip_heights_are_cores_own() {
    // `chain.cpp: GetSkipHeight`, spot-checked against the shape its comment describes.
    assert_eq!(skip_height(0), 0);
    assert_eq!(skip_height(1), 0);
    assert_eq!(skip_height(2), 0);
    assert_eq!(skip_height(3), 1);
    assert_eq!(skip_height(4), 0);
    assert_eq!(skip_height(12), 8);
    assert_eq!(skip_height(4096), 0);
    // Every skip goes backwards, which is what makes the walk terminate.
    for height in 2..10_000u32 {
        assert!(skip_height(height) < height);
    }
}

#[test]
fn chain_work_is_summed_without_trusting_a_library_to_panic() {
    let genesis_work = block_work(CompactTarget::from_consensus(0x207f_ffff));
    let doubled = add_work(genesis_work, genesis_work);
    assert_eq!(doubled, genesis_work + genesis_work);
    assert_eq!(add_work(Work::from_be_bytes([0u8; 32]), doubled), doubled);
}

#[test]
#[should_panic(expected = "more hashing than exists")]
fn chain_work_past_the_end_of_the_type_is_an_assertion_of_ours() {
    let most = Work::from_be_bytes([0xFFu8; 32]);
    let _ = add_work(most, most);
}

#[test]
fn a_hash_the_tree_has_never_seen_names_no_node() {
    let (tree, _params) = tree();
    assert_eq!(tree.node_of(BlockHash::from_byte_array([7u8; 32])), None);
}

#[test]
fn the_tree_stops_at_its_cap_and_blames_nobody_for_it() {
    // Signet's header target is the pow limit, so a peer there can mine forks by the
    // million and nothing but this cap is in the way (R4 §2.3: Core's own answer is the
    // presync this node does not have). Reaching it must be a stall an operator can see,
    // not an allocation an attacker chooses.
    let params = fixture::params();
    let mut tree = HeaderTree::with_cap(&params, 5);
    let headers = fixture::chain(&params.genesis().header, 6, 1, &params);
    let taken = headers.iter().take(4);
    for header in taken {
        assert!(tree.accept(header, &params, fixture::now()).is_ok());
    }
    assert_eq!(tree.len(), 5);

    let over = headers.get(4).expect("six headers");
    let error = tree
        .accept(over, &params, fixture::now())
        .expect_err("the tree is full");
    assert_eq!(error, AcceptError::TreeFull);
    // The peer that happened to send the header that did not fit is not the one that filled
    // the tree, and punishing it would only rotate which peer is refused.
    assert_eq!(error.peer_fault(), None);
    assert_eq!(tree.len(), 5);
    check_invariants(&tree);
}

#[test]
fn bitcoinds_own_regtest_chain_goes_into_the_tree_header_for_header() {
    // The differential check for everything the tree contributes to a verdict. Acceptance
    // *is* the comparison: `accept_header` refuses a header whose `nBits` is not exactly
    // what the difficulty period this tree walked produced, and whose `nTime` is not past
    // the median of the eleven timestamps it gathered. Two hundred and one of Core's own
    // headers going in is two hundred and one agreements with `GetNextWorkRequired` and
    // `GetMedianTimePast` — the boundary at height 144 included, which is the one place on
    // regtest where the walk has to have found the right slice.
    let params = fixture::params();
    let mut tree = HeaderTree::new(&params);
    let mut lines = BITCOIND_REGTEST_HEADERS.lines();
    let genesis = decode_header(lines.next().expect("the file starts at genesis"));
    assert_eq!(genesis.block_hash(), params.genesis_hash());

    let mut height: u32 = 0;
    for line in lines {
        let header = decode_header(line);
        height = height.saturating_add(1);
        let accepted = tree
            .accept(&header, &params, fixture::now())
            .unwrap_or_else(|error| panic!("bitcoind's own header at {height}: {error}"));
        assert_eq!(tree.entry(accepted.node()).height(), Height::new(height));
        assert_eq!(tree.entry(accepted.node()).hash(), header.block_hash());
    }
    assert_eq!(height, 200, "one period boundary and then some");
    assert_eq!(tree.entry(tree.best_header()).height(), Height::new(200));
    check_invariants(&tree);
}

/// One line of `tests/data/regtest-headers.hex`.
fn decode_header(line: &str) -> bitcoin::block::Header {
    let bytes = Vec::<u8>::from_hex(line.trim()).expect("a hex header");
    assert_eq!(bytes.len(), 80, "a header is eighty bytes");
    deserialize(&bytes).expect("bitcoind wrote it")
}
