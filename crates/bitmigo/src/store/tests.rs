// SPDX-License-Identifier: MIT OR Apache-2.0

//! The store as a whole, against a hundred and six blocks bitcoind mined.
//!
//! Every other test in this module tree is about one piece. This one is the ticket's own
//! claim: a store that bitcoind's own regtest blocks were written into, closed, opened
//! again, and found to hold exactly what went in — the bytes byte for byte, the undo
//! records paired back with the inputs they came from, and the header tree rebuilt out of
//! an index that carries neither heights nor chain work.

use bitcoin::Block;
use bitmigo_consensus::params::{ChainParams, Height};

use super::{ChainStore, Scratch, Store, UndoRecord, UndoStore};
use crate::chain::{HeaderStatus, HeaderTree, node_time};
use crate::store::fixture;

/// A regtest chain, which is the one the fixture blocks are on.
fn params() -> ChainParams {
    crate::chain::fixture::params()
}

/// Write every fixture block into a store, connecting each one as it goes.
///
/// The order is the node's own: the bytes first, then the index record that names them,
/// which is the ordering rule [`ChainStore::commit`] exists to keep.
fn fill(chain: &mut ChainStore, undo: &mut UndoStore, tree: &mut HeaderTree, blocks: &[Block]) {
    let params = params();
    let raw = fixture::raw();
    let coins = fixture::coins(blocks);
    for (height, block) in blocks.iter().enumerate().skip(1) {
        let bytes = raw.get(height).expect("a fixture block");
        let node = tree
            .accept(&block.header, &params, node_time())
            .expect("bitcoind's own header")
            .node();

        let location = chain.write_block(bytes).expect("a block write");
        tree.block_checked(node, location);

        let previous = block.header.prev_blockhash;
        let record = UndoRecord::of(&fixture::spent_by(block, &coins), &[], block);
        let placed = undo
            .write_undo(&record.encode(), previous)
            .expect("an undo write");
        tree.connected(node, placed);
    }
    undo.undo.sync().expect("the undo series reaches the disk");
    chain.commit(tree).expect("a commit");
}

#[test]
fn a_store_bitcoinds_blocks_were_written_into_comes_back_whole() {
    let scratch = Scratch::new();
    let params = params();
    let blocks = fixture::blocks();
    let raw = fixture::raw();
    assert_eq!(blocks.len(), 106, "the fixture chain is genesis to 105");

    let tip = {
        let (_store, mut chain, mut undo) =
            Store::open(scratch.open().expect("the lock"), &params).expect("an empty store");
        let mut tree = HeaderTree::new(&params);
        fill(&mut chain, &mut undo, &mut tree, &blocks);
        assert_eq!(tree.entry(tree.tip()).height(), Height::new(105));
        tree.entry(tree.tip()).hash()
    };

    // Everything above is dropped, which releases the lock: this is a restart.
    let (store, mut chain, _undo) =
        Store::open(scratch.open().expect("the lock again"), &params).expect("the store reopens");
    let mut tree = HeaderTree::new(&params);
    let report = chain
        .index
        .load(&mut tree, &params, node_time(), tip)
        .expect("the index replays");

    assert_eq!(report.records, 105);
    assert_eq!(report.headers, 106);
    assert_eq!(report.connected, 105);
    assert_eq!(report.torn, 0);
    assert_eq!(report.rejected, 0);
    assert_eq!(tree.entry(tree.tip()).hash(), tip);

    let coins = fixture::coins(&blocks);
    for (height, block) in blocks.iter().enumerate().skip(1) {
        let node = tree
            .node_of(block.block_hash())
            .expect("a header came back");
        let entry = tree.entry(node);
        // Height and chain work are recomputed from `prev_blockhash`, so getting them
        // right is a claim about the load and not about the record.
        assert_eq!(entry.height(), Height::new(u32::try_from(height).unwrap()));
        let HeaderStatus::Connected { location, undo } = entry.status() else {
            panic!("height {height} came back as {:?}", entry.status())
        };

        // The bytes, exactly as bitcoind serialised them. Byte-identical serving is the
        // whole reason the store never normalises on write (R4 §8.6).
        let bytes = store.read_block(location).expect("a block reads back");
        assert_eq!(&bytes, raw.get(height).expect("a fixture block"));

        // And the record that takes the block back off, checked against the block before
        // it and paired with the inputs it belongs to.
        let record = store
            .read_undo(undo, block.header.prev_blockhash)
            .expect("an undo record reads back");
        let record = UndoRecord::decode(&record).expect("what was written decodes");
        let restored = record.resolve(block).expect("every index names an input");
        let spent = fixture::spent_by(block, &coins);
        assert_eq!(restored.len(), spent.len());
        for (coin, (outpoint, stored)) in spent.iter().zip(restored) {
            assert_eq!(outpoint, coin.outpoint);
            assert_eq!(stored.output, coin.output);
            assert_eq!(stored.height, coin.height);
            assert_eq!(stored.coinbase, coin.coinbase);
        }
    }
}

#[test]
fn an_undo_record_cannot_be_read_as_another_blocks() {
    let scratch = Scratch::new();
    let params = params();
    let blocks = fixture::blocks();
    let (store, mut chain, mut undo) =
        Store::open(scratch.open().expect("the lock"), &params).expect("an empty store");
    let mut tree = HeaderTree::new(&params);
    fill(&mut chain, &mut undo, &mut tree, &blocks);

    let block = blocks.get(103).expect("a spending block");
    let node = tree.node_of(block.block_hash()).expect("a header");
    let HeaderStatus::Connected { undo, .. } = tree.entry(node).status() else {
        panic!("the block is connected")
    };
    assert!(store.read_undo(undo, block.header.prev_blockhash).is_ok());
    // The hash Core folds into the trailer is the previous block's, so a record read for
    // the wrong block is refused rather than deserialised into the wrong coins.
    let wrong = blocks.get(50).expect("another block").block_hash();
    let error = store
        .read_undo(undo, wrong)
        .expect_err("another block's record");
    assert!(error.to_string().contains("does not match its checksum"));
}

#[test]
fn a_restart_with_no_coin_store_yet_demotes_the_whole_chain() {
    // What the node does today, and BM-D4's load rule with its one term: an empty UTXO set
    // corresponds to the block before any coin existed, so every block is connected again.
    // The bytes stay where they are, so nothing is downloaded twice.
    let scratch = Scratch::new();
    let params = params();
    let blocks = fixture::blocks();
    {
        let (_store, mut chain, mut undo) =
            Store::open(scratch.open().expect("the lock"), &params).expect("an empty store");
        let mut tree = HeaderTree::new(&params);
        fill(&mut chain, &mut undo, &mut tree, &blocks);
    }

    let (_store, mut chain, _undo) =
        Store::open(scratch.open().expect("the lock again"), &params).expect("the store reopens");
    let mut tree = HeaderTree::new(&params);
    let report = chain
        .index
        .load(&mut tree, &params, node_time(), params.genesis_hash())
        .expect("the index replays");

    assert_eq!(report.connected, 0);
    assert_eq!(tree.entry(tree.tip()).height(), Height::GENESIS);
    assert_eq!(tree.entry(tree.best_header()).height(), Height::new(105));
    for block in blocks.iter().skip(1) {
        let node = tree.node_of(block.block_hash()).expect("a header");
        assert!(
            matches!(tree.entry(node).status(), HeaderStatus::BlockChecked { .. }),
            "the bytes are still there and still checked",
        );
    }
}

#[test]
fn the_second_start_finds_the_cursor_rather_than_writing_over_the_first() {
    let scratch = Scratch::new();
    let params = params();
    let blocks = fixture::blocks();
    let raw = fixture::raw();
    let first = {
        let (_store, mut chain, mut undo) =
            Store::open(scratch.open().expect("the lock"), &params).expect("an empty store");
        let mut tree = HeaderTree::new(&params);
        fill(&mut chain, &mut undo, &mut tree, &blocks);
        chain.blocks.cursor()
    };

    let (store, mut chain, _undo) =
        Store::open(scratch.open().expect("the lock again"), &params).expect("the store reopens");
    assert_eq!(
        chain.blocks.cursor(),
        first,
        "the cursor is read off the files"
    );

    // A block appended after the restart lands after everything the first run wrote, and
    // the first run's bytes are still readable.
    let extra = raw.first().expect("genesis' bytes");
    let placed = chain.write_block(extra).expect("an append");
    chain.blocks.sync().expect("a sync");
    assert_eq!(placed.offset, first.1 + 8);
    assert_eq!(store.read_block(placed).expect("the new block"), *extra);
}
