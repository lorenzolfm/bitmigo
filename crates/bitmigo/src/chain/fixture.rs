// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regtest headers, mined here, for the tree's own tests.
//!
//! Regtest's pow limit is about `2^255`, so roughly every other nonce produces a hash that
//! meets it: a chain of a few hundred headers costs a few hundred hashes, and the tests can
//! build the shapes a peer would have to spend real work to build — forks, deep reorgs, a
//! header that fails one contextual rule and nothing else.

use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, TxMerkleNode};
use bitmigo_consensus::header::{decode_target, hash_meets_target};
use bitmigo_consensus::params::{BlockTime, ChainParams, RegtestOverrides};

use crate::chain::tree::{HeaderTree, NodeId, UndoLocation};
use crate::runtime::queue::BlockLocation;

/// The spacing between the headers these fixtures mine. Regtest's own target spacing, so a
/// chain built here never trips the minimum-difficulty rule's two-spacing gap.
pub const SPACING: u32 = 600;

/// A clock far past any fixture's timestamps, so no test depends on the wall clock.
pub fn now() -> BlockTime {
    BlockTime::new(2_000_000_000)
}

/// The chain these fixtures are on.
pub fn params() -> ChainParams {
    ChainParams::regtest(RegtestOverrides::default())
}

/// One header on top of `previous`, mined until its hash meets its own target.
///
/// `salt` goes into the merkle root, so two children of the same parent are two different
/// blocks: that is how a fork is built.
pub fn child(previous: &Header, salt: u32, params: &ChainParams) -> Header {
    child_at(
        previous,
        salt,
        previous.time.saturating_add(SPACING),
        params,
    )
}

/// One header on top of `previous`, at a stated `nTime`.
pub fn child_at(previous: &Header, salt: u32, time: u32, params: &ChainParams) -> Header {
    let mut root = [0u8; 32];
    for (slot, byte) in root.iter_mut().zip(salt.to_le_bytes()) {
        *slot = byte;
    }
    let mut header = Header {
        // Above the version floor every regtest deployment implies from height one.
        version: Version::from_consensus(4),
        prev_blockhash: previous.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array(root),
        time,
        bits: previous.bits,
        nonce: 0,
    };
    let target = decode_target(header.bits, params.pow_limit()).expect("regtest's own bits");
    while !hash_meets_target(header.block_hash(), target) {
        header.nonce = header.nonce.saturating_add(1);
        assert!(header.nonce < 1_000_000, "regtest headers are nearly free");
    }
    header
}

/// `count` headers on top of `from`, each the child of the last.
pub fn chain(from: &Header, count: usize, salt: u32, params: &ChainParams) -> Vec<Header> {
    let mut headers = Vec::with_capacity(count);
    let mut previous = *from;
    for _ in 0..count {
        let next = child(&previous, salt, params);
        headers.push(next);
        previous = next;
    }
    headers
}

/// A hash no fixture ever mines, for the `hash_stop` a peer sends when it wants everything.
pub fn nothing() -> BlockHash {
    BlockHash::all_zeros()
}

/// A stand-in for where a block's bytes are, distinct per height so a test can tell one
/// from another. BM-D4 gives these their real values.
pub fn location(height: u32) -> BlockLocation {
    BlockLocation {
        file: 0,
        offset: height.saturating_mul(1000),
        len: 285,
    }
}

/// A stand-in for where a block's undo record is.
pub fn undo(height: u32) -> UndoLocation {
    UndoLocation {
        file: 0,
        offset: height.saturating_mul(100),
        len: 42,
    }
}

/// Accept every header into the tree, asserting each one goes in as new.
pub fn accept_all(tree: &mut HeaderTree, headers: &[Header], params: &ChainParams) -> Vec<NodeId> {
    let mut nodes = Vec::with_capacity(headers.len());
    for header in headers {
        let accepted = tree
            .accept(header, params, now())
            .expect("a fixture header goes in");
        nodes.push(accepted.node());
    }
    nodes
}

/// Give a block bytes on the disk, without connecting it.
pub fn check(tree: &mut HeaderTree, node: NodeId) {
    let height = tree.entry(node).height().get();
    tree.block_checked(node, location(height));
}

/// Take the chainstate from the tip up to `node`, one block at a time, the way validation
/// would report each connect back.
pub fn connect_through(tree: &mut HeaderTree, node: NodeId) {
    let mut path = Vec::new();
    let mut walk = node;
    while walk != tree.tip() {
        path.push(walk);
        walk = tree.entry(walk).parent().expect("the tip is an ancestor");
    }
    path.reverse();
    for step in path {
        let height = tree.entry(step).height().get();
        if tree.entry(step).status().location().is_none() {
            tree.block_checked(step, location(height));
        }
        tree.connected(step, undo(height));
    }
}
