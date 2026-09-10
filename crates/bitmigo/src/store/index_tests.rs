// SPDX-License-Identifier: MIT OR Apache-2.0

//! The block index: what it writes down, what it re-derives, and what it does with a
//! commit a crash caught in the middle.

use std::fs::{self, OpenOptions};
use std::path::PathBuf;

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitmigo_consensus::block::{BlockError, ConfirmError};
use bitmigo_consensus::params::{ChainParams, Height};

use super::{JOURNAL_FILE, Journal};
use crate::chain::fixture as headers;
use crate::chain::{HeaderStatus, HeaderTree, Invalidity, NodeId, Stage};
use crate::store::DataDir;

/// A journal in a directory of its own, and the chain it is for.
fn journal() -> (DataDir, ChainParams, Journal) {
    let directory = DataDir::transient().expect("a test data directory");
    let params = headers::params();
    let journal = Journal::open(&directory.index(), &params).expect("an empty journal");
    (directory, params, journal)
}

/// A tree with `count` headers on it, and the headers themselves.
fn tree_of(params: &ChainParams, count: usize) -> (HeaderTree, Vec<Header>) {
    let mut tree = HeaderTree::new(params);
    let chain = headers::chain(&params.genesis().header, count, 1, params);
    headers::accept_all(&mut tree, &chain, params);
    (tree, chain)
}

/// Commit whatever has changed, the way the chain thread does.
fn commit(journal: &mut Journal, tree: &mut HeaderTree) -> usize {
    let written = journal.append(tree.dirty(), tree).expect("a commit");
    tree.clear_dirty();
    written
}

/// Load a journal from scratch, as a restart would.
fn reload(
    directory: &DataDir,
    params: &ChainParams,
    marker: BlockHash,
) -> (HeaderTree, super::Loaded) {
    let mut journal = Journal::open(&directory.index(), params).expect("the journal reopens");
    let mut tree = HeaderTree::new(params);
    let report = journal
        .load(&mut tree, params, headers::now(), marker)
        .expect("a load");
    (tree, report)
}

#[test]
fn the_headers_come_back_and_so_do_their_bytes() {
    let (directory, params, mut journal) = journal();
    let (mut tree, chain) = tree_of(&params, 20);
    let checked: Vec<NodeId> = tree.nodes().skip(1).take(12).collect();
    for node in checked {
        headers::check(&mut tree, node);
    }
    assert_eq!(commit(&mut journal, &mut tree), 20, "one record per header");

    let (back, report) = reload(&directory, &params, params.genesis_hash());
    assert_eq!(report.records, 20);
    assert_eq!(back.len(), 21, "genesis comes from the parameters");
    assert_eq!(report.torn, 0);
    assert_eq!(report.rejected, 0);
    for (index, header) in chain.iter().enumerate() {
        let node = back
            .node_of(header.block_hash())
            .expect("a header came back");
        let height = u32::try_from(index).unwrap() + 1;
        assert_eq!(back.entry(node).height(), Height::new(height));
        // Height, chain work, the parent link and the skip pointer are recomputed, so the
        // record carries none of them and they still have to be right.
        assert!(back.entry(node).chainwork() > back.entry(NodeId::GENESIS).chainwork());
        let expected = if index < 12 {
            HeaderStatus::BlockChecked {
                location: headers::location(height),
            }
        } else {
            HeaderStatus::HeaderAccepted
        };
        assert_eq!(back.entry(node).status(), expected);
    }
}

#[test]
fn the_markers_chain_is_connected_and_everything_above_it_is_demoted() {
    // BM-D4's load rule: persisted status is a hint, the coin store's marker is the truth.
    let (directory, params, mut journal) = journal();
    let (mut tree, chain) = tree_of(&params, 10);
    let last = tree.nodes().last().expect("a tip");
    headers::connect_through(&mut tree, last);
    assert_eq!(tree.entry(tree.tip()).height(), Height::new(10));
    commit(&mut journal, &mut tree);

    // A coin store that got as far as height four.
    let marker = chain.get(3).expect("height four").block_hash();
    let (back, report) = reload(&directory, &params, marker);
    assert_eq!(report.connected, 4);
    assert_eq!(back.entry(back.tip()).hash(), marker);
    for (index, header) in chain.iter().enumerate() {
        let node = back.node_of(header.block_hash()).expect("a header");
        let connected = back.entry(node).status().is_connected();
        assert_eq!(connected, index < 4, "height {} is wrong", index + 1);
        // The bytes are still there and still checked either way: demoting costs a
        // reconnect, never a re-download.
        assert!(back.entry(node).status().location().is_some());
    }

    // And with the marker at the tip, nothing is demoted at all.
    let (whole, report) = reload(&directory, &params, tree.entry(last).hash());
    assert_eq!(report.connected, 10);
    assert_eq!(whole.entry(whole.tip()).height(), Height::new(10));
}

#[test]
fn a_marker_the_index_does_not_have_refuses_to_start() {
    // The coin store holding coins for a block the index cannot name is the one shape the
    // ordering rule is supposed to make impossible, so it is a refusal and not a rewind.
    let (directory, params, mut journal) = journal();
    let (mut tree, _) = tree_of(&params, 4);
    commit(&mut journal, &mut tree);

    let mut journal = Journal::open(&directory.index(), &params).unwrap();
    let mut back = HeaderTree::new(&params);
    let error = journal
        .load(
            &mut back,
            &params,
            headers::now(),
            BlockHash::from_byte_array([7u8; 32]),
        )
        .expect_err("a marker with no block");
    assert!(error.to_string().contains("the block index does not have"));
}

#[test]
fn a_block_below_the_marker_with_no_undo_record_refuses_to_start() {
    // Connected is the state that carries an undo record, and a reorg past this block
    // would have nothing to work from. Starting anyway would be starting on a lie.
    let (directory, params, mut journal) = journal();
    let (mut tree, chain) = tree_of(&params, 4);
    let checked: Vec<NodeId> = tree.nodes().skip(1).collect();
    for node in checked {
        headers::check(&mut tree, node);
    }
    commit(&mut journal, &mut tree);

    let mut journal = Journal::open(&directory.index(), &params).unwrap();
    let mut back = HeaderTree::new(&params);
    let marker = chain.get(1).expect("height two").block_hash();
    let error = journal
        .load(&mut back, &params, headers::now(), marker)
        .expect_err("no undo record below the marker");
    assert!(error.to_string().contains("no undo record"));
}

#[test]
fn a_commit_caught_in_the_middle_loses_that_commit_and_nothing_else() {
    let (directory, params, mut journal) = journal();
    let (mut tree, chain) = tree_of(&params, 6);
    commit(&mut journal, &mut tree);
    let path = directory.index().join(JOURNAL_FILE);
    let whole = fs::metadata(&path).unwrap().len();

    // Every way the last record can be short of whole, one byte at a time.
    for missing in 1..40u64 {
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(whole.saturating_sub(missing)).unwrap();
        drop(file);
        let (back, report) = reload(&directory, &params, params.genesis_hash());
        assert!(
            report.torn > 0 || report.records < 6,
            "{missing} was not noticed"
        );
        assert!(back.len() >= 6, "only the last record is lost");
        assert!(back.node_of(chain.first().unwrap().block_hash()).is_some());
    }
}

#[test]
fn a_record_whose_checksum_does_not_match_is_the_same_event() {
    let (directory, params, mut journal) = journal();
    let (mut tree, _) = tree_of(&params, 6);
    commit(&mut journal, &mut tree);

    // A byte of the last record turned over: the same thing a torn write looks like, and
    // the same answer.
    let path = directory.index().join(JOURNAL_FILE);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len().saturating_sub(8);
    if let Some(byte) = bytes.get_mut(last) {
        *byte ^= 0xff;
    }
    fs::write(&path, &bytes).unwrap();

    let (back, report) = reload(&directory, &params, params.genesis_hash());
    assert!(report.torn > 0);
    assert_eq!(back.len(), 6, "five headers and genesis");
}

#[test]
fn a_journal_that_is_not_this_chains_is_refused_before_a_header_is_read() {
    let directory = DataDir::transient().expect("a test data directory");
    let regtest = headers::params();
    let journal = Journal::open(&directory.index(), &regtest).expect("a journal");
    drop(journal);

    let signet = ChainParams::signet(bitmigo_consensus::block::signet::default_challenge());
    let Err(error) = Journal::open(&directory.index(), &signet) else {
        panic!("another chain's index was opened")
    };
    assert!(error.to_string().contains("chain"));
}

#[test]
fn a_file_that_is_not_a_journal_is_refused() {
    let directory = DataDir::transient().expect("a test data directory");
    let params = headers::params();
    let path: PathBuf = directory.index().join(JOURNAL_FILE);

    fs::write(
        &path,
        b"not a bitmigo index at all, but long enough to read a header from",
    )
    .unwrap();
    let Err(error) = Journal::open(&directory.index(), &params) else {
        panic!("not an index was opened")
    };
    assert!(error.to_string().contains("not a bitmigo block index"));

    // Too short to hold a header, which is what an interrupted create looks like.
    fs::write(&path, b"bmgoIDX").unwrap();
    let Err(error) = Journal::open(&directory.index(), &params) else {
        panic!("half a header was opened")
    };
    assert!(error.to_string().contains("no index header"));

    // The right format, a version this build does not write.
    let mut bytes = b"bmgoIDX\x01".to_vec();
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 32]);
    fs::write(&path, &bytes).unwrap();
    let Err(error) = Journal::open(&directory.index(), &params) else {
        panic!("a later version was opened")
    };
    assert!(error.to_string().contains("version 2"));
}

#[test]
fn only_what_changed_is_written() {
    let (_directory, params, mut journal) = journal();
    let (mut tree, _) = tree_of(&params, 8);
    assert_eq!(commit(&mut journal, &mut tree), 8);
    assert_eq!(commit(&mut journal, &mut tree), 0, "nothing changed");

    // An entry that changes twice between commits is written once, and the last state is
    // the one that lands.
    let node = tree.nodes().nth(1).expect("height one");
    headers::check(&mut tree, node);
    tree.connected(node, headers::undo(1));
    assert_eq!(tree.dirty().len(), 1);
    assert_eq!(commit(&mut journal, &mut tree), 1);
}

#[test]
fn a_rewrite_is_a_snapshot_and_the_journal_stops_growing() {
    let (directory, params, mut journal) = journal();
    let (mut tree, chain) = tree_of(&params, 40);
    let path = directory.index().join(JOURNAL_FILE);
    commit(&mut journal, &mut tree);

    // Change the same entries over and over, the way a chain that reorgs does: the
    // journal grows until it passes twice the live count, and a rewrite takes it back.
    let target = tree.nodes().nth(30).expect("height thirty");
    let mut grew = 0u64;
    for _ in 0..100 {
        headers::connect_through(&mut tree, target);
        while tree.tip() != NodeId::GENESIS {
            tree.disconnected(tree.tip());
        }
        commit(&mut journal, &mut tree);
        grew = grew.max(fs::metadata(&path).unwrap().len());
    }
    let settled = fs::metadata(&path).unwrap().len();
    assert!(
        settled < grew,
        "a rewrite took the journal back: {settled} < {grew}"
    );

    // What it holds is still every entry, and a rewrite asked for outright is one record
    // per entry — genesis excepted, which comes from the chain parameters.
    journal.rewrite(&tree).expect("a rewrite");
    let (back, report) = reload(&directory, &params, params.genesis_hash());
    assert_eq!(report.records, 40);
    assert_eq!(back.len(), 41);
    for header in &chain {
        assert!(back.node_of(header.block_hash()).is_some());
    }
}

#[test]
fn a_verdict_a_replay_can_re_derive_is_not_written_down() {
    let (directory, params, mut journal) = journal();
    let mut tree = HeaderTree::new(&params);
    // `nTime` at the parent's own time, which is not past its median time past: refused by
    // `accept_header`, stored, and refused again on every replay for the same reason.
    let genesis = params.genesis().header;
    let early = headers::child_at(&genesis, 1, genesis.time, &params);
    assert!(tree.accept(&early, &params, headers::now()).is_err());
    // And a child of it, which inherits.
    let below = headers::child(&early, 2, &params);
    assert!(tree.accept(&below, &params, headers::now()).is_err());
    commit(&mut journal, &mut tree);

    let (back, _) = reload(&directory, &params, params.genesis_hash());
    // The reason came back, and not because it was written down: the rule re-derived it.
    let node = back
        .node_of(early.block_hash())
        .expect("stored, so replayed");
    assert!(matches!(
        back.entry(node).status(),
        HeaderStatus::Invalid {
            invalidity: Invalidity::AcceptHeader(_),
        },
    ));
    let child = back
        .node_of(below.block_hash())
        .expect("the descendant too");
    assert!(matches!(
        back.entry(child).status(),
        HeaderStatus::InvalidAncestor { .. },
    ));
}

#[test]
fn a_verdict_a_replay_cannot_re_derive_comes_back_as_its_stage() {
    // `confirm` and `check_block` need the block, so neither refusal re-derives itself
    // from a header. What the index keeps is the stage, and what that buys is that the
    // block is never built on again.
    let (directory, params, mut journal) = journal();
    let mut tree = HeaderTree::new(&params);
    let genesis = params.genesis().header;
    let left = headers::chain(&genesis, 5, 1, &params);
    let right = headers::chain(&genesis, 3, 2, &params);
    headers::accept_all(&mut tree, &left, &params);
    headers::accept_all(&mut tree, &right, &params);

    let refused = tree.node_of(left.get(2).unwrap().block_hash()).unwrap();
    tree.invalidate(
        refused,
        Invalidity::Confirm(ConfirmError::BadCoinbaseAmount {
            paid: 51,
            allowed: 50,
        }),
    );
    let also = tree.node_of(right.get(1).unwrap().block_hash()).unwrap();
    tree.invalidate(
        also,
        Invalidity::CheckBlock(BlockError::DuplicateTransactions),
    );
    commit(&mut journal, &mut tree);

    let (back, _) = reload(&directory, &params, params.genesis_hash());
    for (header, stage) in [
        (left.get(2).unwrap(), Stage::Confirm),
        (right.get(1).unwrap(), Stage::CheckBlock),
    ] {
        let node = back.node_of(header.block_hash()).expect("a header");
        assert_eq!(
            back.entry(node).status(),
            HeaderStatus::Invalid {
                invalidity: Invalidity::Reloaded { stage },
            },
        );
    }
    // Which is what it is for: the most-work header is on neither refused branch.
    assert!(!back.entry(back.best_header()).status().is_terminal());
    assert_eq!(back.entry(back.best_header()).height(), Height::new(2));
}

#[test]
fn a_refusal_below_another_one_comes_back_as_the_descendant_it_is() {
    // Two verdicts on one branch: the replay applies them in the arena's order, parents
    // first, so the block below inherits rather than keeping its own stage. Nothing is
    // lost — terminal is terminal either way — and the culprit it names is the earlier
    // one, which is the more useful of the two answers.
    let (directory, params, mut journal) = journal();
    let (mut tree, chain) = tree_of(&params, 5);
    let below = tree.nodes().nth(3).expect("height three");
    tree.invalidate(
        below,
        Invalidity::Confirm(ConfirmError::Bip30 {
            outpoint: bitcoin::OutPoint::null(),
        }),
    );
    let above = tree.nodes().nth(2).expect("height two");
    tree.invalidate(
        above,
        Invalidity::CheckBlock(BlockError::DuplicateTransactions),
    );
    commit(&mut journal, &mut tree);

    let (back, _) = reload(&directory, &params, params.genesis_hash());
    let node = back
        .node_of(chain.get(2).unwrap().block_hash())
        .expect("a header");
    assert_eq!(
        back.entry(node).status(),
        HeaderStatus::InvalidAncestor {
            culprit: chain.get(1).unwrap().block_hash(),
        },
    );
}

#[test]
fn every_stage_survives_the_byte_it_is_written_as() {
    for stage in [
        Stage::AcceptHeader,
        Stage::CheckBlock,
        Stage::AcceptBlock,
        Stage::Confirm,
        Stage::Connect,
    ] {
        assert_eq!(Stage::of_tag(stage.tag()), Some(stage));
    }
    assert_eq!(Stage::of_tag(0), None);
    assert_eq!(Stage::of_tag(6), None);
    // The tags are stated, not derived from the variant order, so a new stage cannot
    // silently renumber a file already on somebody's disk.
    assert_eq!(Stage::AcceptHeader.tag(), 1);
    assert_eq!(Stage::Connect.tag(), 5);
}

#[test]
fn an_empty_store_loads_as_an_empty_tree() {
    let (directory, params, journal) = journal();
    drop(journal);
    let (back, report) = reload(&directory, &params, params.genesis_hash());
    assert_eq!(
        report,
        super::Loaded {
            records: 0,
            headers: 1,
            connected: 0,
            torn: 0,
            rejected: 0,
        }
    );
    assert_eq!(back.len(), 1);
    assert_eq!(back.tip(), NodeId::GENESIS);
}
