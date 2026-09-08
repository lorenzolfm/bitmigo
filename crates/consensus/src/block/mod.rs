// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block rules that need no coins: the two receipt-time stages of the pipeline.
//!
//! [`check_block`] is Core's `CheckBlock`: context-free, everything a block can be judged on
//! from its own bytes (§2.8). [`accept_block`] is exactly `ContextualCheckBlock`: the rules
//! that need the block's height and its predecessor's median time past, all of which arrive
//! in the [`Context`] the header stages already use, so the node can run both at receipt
//! (BM-D1 decision 9) and write the raw bytes knowing they passed every header-only check.
//! The coins path, [`populate`], [`confirm`] and [`connect`] over the same `Context`, runs
//! in chain order and produces the [`BlockDelta`]; it lives in `coins`.
//!
//! The signet solution check belongs in `check_block` (§2.8); the `signet` module adds it
//! behind a `BlockChallenge` on [`ChainParams`], which is why `check_block` already takes the
//! parameters.

mod coins;
mod merkle;

use core::fmt;

use bitcoin::block::Header;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::{Block, Transaction, VarInt};

use crate::header::{Context, HeaderError, check_header};
use crate::params::{BlockTime, ChainParams, Height};
use crate::script::{ScriptNum, push_encoding};
use crate::tx::{
    MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, TxError, WITNESS_SCALE_FACTOR, check_tx, is_final,
    legacy_sigop_count,
};

pub use coins::{
    BlockDelta, ConfirmError, Confirmed, ConnectError, InputCoin, InputSource, MAX_BLOCK_INPUTS,
    MAX_BLOCK_OUTPUTS, Prefetch, confirm, connect, populate,
};
pub use merkle::{MerkleRoot, merkle_root};

/// Core's `MINIMUM_WITNESS_COMMITMENT`: a coinbase output is the witness commitment when its
/// script is at least this long and opens with [`WITNESS_COMMITMENT_HEADER`] (§2.6).
pub const WITNESS_COMMITMENT_SIZE_MIN: usize = 38;

/// `OP_RETURN`, a 36-byte push, and BIP141's four magic bytes.
pub const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// The coinbase witness carries exactly one item of this size, the witness reserved value.
pub const WITNESS_RESERVED_VALUE_SIZE: usize = 32;

/// Why a block was refused, in the vocabulary of Core's reject reasons; `Display` gives the
/// reason string. The fields are the evidence: what was required and what was seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockError {
    /// The header failed [`check_header`].
    Header(HeaderError),
    /// `bad-txnmrklroot`: the transactions do not hash to the header's merkle root.
    BadMerkleRoot {
        /// The root the transactions do hash to.
        computed: [u8; 32],
    },
    /// `bad-txns-duplicate`: the transaction list repeats its tail (CVE-2012-2459).
    DuplicateTransactions,
    /// `bad-blk-length`: no transactions, or too many, or a base size over a block's.
    BadLength {
        /// The transaction count.
        tx_count: usize,
        /// The non-witness serialized size, bytes.
        base_size: u64,
    },
    /// `bad-cb-missing`: the first transaction is not a coinbase.
    CoinbaseMissing,
    /// `bad-cb-multiple`: a later transaction is a coinbase.
    CoinbaseMultiple {
        /// Its index in the block.
        index: usize,
    },
    /// A transaction failed [`check_tx`]; the reason string is the transaction's.
    Transaction {
        /// Its index in the block.
        index: usize,
        /// Why.
        error: TxError,
    },
    /// `bad-blk-sigops`: the legacy signature operations, scaled, exceed the block budget.
    BadSigOps {
        /// The unscaled legacy count.
        count: u64,
    },
    /// `bad-txns-nonfinal`: a transaction's lock time is not satisfied at this height and
    /// cutoff.
    NonFinal {
        /// Its index in the block.
        index: usize,
    },
    /// `bad-cb-height`: the coinbase `scriptSig` does not start with the height (BIP34).
    BadCoinbaseHeight {
        /// The height the block sits at.
        expected: Height,
    },
    /// `bad-witness-nonce-size`: the coinbase witness is not one 32-byte item.
    WitnessNonceSize,
    /// `bad-witness-merkle-match`: the commitment does not match the witness tree.
    WitnessMerkleMismatch,
    /// `unexpected-witness`: witness data in a block that commits to none.
    UnexpectedWitness {
        /// The first transaction carrying a witness.
        index: usize,
    },
    /// `bad-blk-weight`: the block weight exceeds [`MAX_BLOCK_WEIGHT`].
    BadWeight {
        /// The weight seen.
        weight: u64,
    },
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => error.fmt(f),
            Self::Transaction { error, .. } => error.fmt(f),
            Self::BadMerkleRoot { .. } => f.write_str("bad-txnmrklroot"),
            Self::DuplicateTransactions => f.write_str("bad-txns-duplicate"),
            Self::BadLength { .. } => f.write_str("bad-blk-length"),
            Self::CoinbaseMissing => f.write_str("bad-cb-missing"),
            Self::CoinbaseMultiple { .. } => f.write_str("bad-cb-multiple"),
            Self::BadSigOps { .. } => f.write_str("bad-blk-sigops"),
            Self::NonFinal { .. } => f.write_str("bad-txns-nonfinal"),
            Self::BadCoinbaseHeight { .. } => f.write_str("bad-cb-height"),
            Self::WitnessNonceSize => f.write_str("bad-witness-nonce-size"),
            Self::WitnessMerkleMismatch => f.write_str("bad-witness-merkle-match"),
            Self::UnexpectedWitness { .. } => f.write_str("unexpected-witness"),
            Self::BadWeight { .. } => f.write_str("bad-blk-weight"),
        }
    }
}

impl std::error::Error for BlockError {}

/// Core's `CheckBlock`, in its order: the header's proof of work, the merkle root and its
/// mutation check, the size limits, one coinbase first and no other, `CheckTransaction` on
/// every transaction, and the legacy signature operation budget (§2.8). Context-free.
///
/// The witness data is not read here: it is committed to by the coinbase, and only
/// [`accept_block`] can tell whether a commitment is expected.
pub fn check_block(block: &Block, params: &ChainParams) -> Result<(), BlockError> {
    check_header(&block.header, params).map_err(BlockError::Header)?;

    // Every check that a peer could fail by sending the wrong transactions for an honest
    // header comes before any that would mark the header invalid.
    check_merkle_root(block)?;

    let tx_count = block.txdata.len();
    let sizes = block_sizes(block);
    if tx_count == 0
        || sizes.tx_count * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
        || sizes.base * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    {
        return Err(BlockError::BadLength {
            tx_count,
            base_size: sizes.base,
        });
    }

    let first = block.txdata.first().expect("tx_count > 0");
    if !first.is_coinbase() {
        return Err(BlockError::CoinbaseMissing);
    }
    for (index, tx) in block.txdata.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(BlockError::CoinbaseMultiple { index });
        }
    }

    for (index, tx) in block.txdata.iter().enumerate() {
        check_tx(tx).map_err(|error| BlockError::Transaction { index, error })?;
    }

    // An underestimate, as Core's is: P2SH and witness sigops need the coins.
    let mut count: u64 = 0;
    for tx in &block.txdata {
        count += legacy_sigop_count(tx);
    }
    if count * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST {
        return Err(BlockError::BadSigOps { count });
    }
    Ok(())
}

/// Core's `CheckMerkleRoot`: the root first, then the mutation flag, so a block with the
/// wrong transactions is `bad-txnmrklroot` even if it also repeats them.
fn check_merkle_root(block: &Block) -> Result<(), BlockError> {
    let leaves: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect();
    let found = merkle_root(leaves);
    if found.root != block.header.merkle_root.to_byte_array() {
        return Err(BlockError::BadMerkleRoot {
            computed: found.root,
        });
    }
    if found.mutated {
        return Err(BlockError::DuplicateTransactions);
    }
    Ok(())
}

/// The two serialized sizes of a block, bytes, and its transaction count, all as the
/// 64-bit numbers the limits are compared in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockSizes {
    tx_count: u64,
    /// Without witnesses: `GetSerializeSize(TX_NO_WITNESS(block))`.
    base: u64,
    /// With witnesses: `GetSerializeSize(TX_WITH_WITNESS(block))`.
    total: u64,
}

impl BlockSizes {
    /// BIP141: `base * 3 + total`.
    fn weight(self) -> u64 {
        assert!(self.total >= self.base);
        self.base * (WITNESS_SCALE_FACTOR - 1) + self.total
    }
}

fn block_sizes(block: &Block) -> BlockSizes {
    let header_size = u64::try_from(Header::SIZE).expect("80");
    let count_size = u64::try_from(VarInt::from(block.txdata.len()).size()).expect("1..=9");
    let mut sizes = BlockSizes {
        tx_count: u64::try_from(block.txdata.len()).expect("usize fits u64"),
        base: header_size + count_size,
        total: header_size + count_size,
    };
    for tx in &block.txdata {
        let base = u64::try_from(tx.base_size()).expect("usize fits u64");
        let total = u64::try_from(tx.total_size()).expect("usize fits u64");
        assert!(total >= base);
        sizes.base += base;
        sizes.total += total;
    }
    sizes
}

/// Core's `ContextualCheckBlock`, in its order: every transaction final against the BIP113
/// cutoff, the BIP34 height in the coinbase, the witness commitment or the absence of any
/// witness, and the block weight (§2.8). Needs nothing beyond [`Context`].
///
/// Runs after [`check_block`] has passed, which is what makes the coinbase's shape a
/// precondition here rather than a verdict.
pub fn accept_block(block: &Block, context: &Context) -> Result<(), BlockError> {
    let coinbase = block
        .txdata
        .first()
        .expect("check_block passed: a coinbase first");
    assert!(coinbase.is_coinbase());
    let rules = context.rules();

    // BIP113: once CSV is active the cutoff is the previous block's median time past.
    let cutoff = if rules.csv_active() {
        context.median_time_past()
    } else {
        BlockTime::new(block.header.time)
    };
    for (index, tx) in block.txdata.iter().enumerate() {
        if !is_final(tx, context.height(), cutoff) {
            return Err(BlockError::NonFinal { index });
        }
    }

    if rules.bip34_active() {
        let expected = height_script(context.height());
        let script_sig = coinbase.input.first().expect("a coinbase has one input");
        if !script_sig.script_sig.as_bytes().starts_with(&expected) {
            return Err(BlockError::BadCoinbaseHeight {
                expected: context.height(),
            });
        }
    }

    check_witness_malleation(block, rules.segwit_active())?;

    // After the coinbase witness is pinned by the commitment: before that, an attacker could
    // inflate the weight through it without changing the block hash.
    let weight = block_sizes(block).weight();
    if weight > MAX_BLOCK_WEIGHT {
        return Err(BlockError::BadWeight { weight });
    }
    Ok(())
}

/// Core's `CScript() << nHeight`: `OP_1`..`OP_16` for 1..=16, otherwise the shortest push of
/// the height as a `CScriptNum` (§2.3). Zero would be `OP_0`, but genesis has no context.
fn height_script(height: Height) -> Vec<u8> {
    const OP_1: u8 = 0x51;
    assert!(height > Height::GENESIS);
    let value = height.get();
    if (1..=16).contains(&value) {
        return vec![OP_1 + u8::try_from(value - 1).expect("0..=15")];
    }
    let script = push_encoding(&ScriptNum::from_i64(i64::from(value)).encode());
    // A height needs at most four bytes (Height::MAX is i32::MAX), plus the push opcode.
    assert!(script.len() >= 2);
    assert!(script.len() <= 5);
    script
}

/// Core's `CheckWitnessMalleation`. With segwit active and a commitment present: the
/// coinbase witness is one 32-byte reserved value and the commitment is
/// `SHA256d(witness_root || reserved_value)`. Otherwise no transaction may carry a witness.
fn check_witness_malleation(block: &Block, expect_commitment: bool) -> Result<(), BlockError> {
    let coinbase = block.txdata.first().expect("check_block passed");
    if expect_commitment && let Some(position) = witness_commitment_index(coinbase) {
        let witness = &coinbase.input.first().expect("one input").witness;
        let reserved = witness
            .nth(0)
            .filter(|item| item.len() == WITNESS_RESERVED_VALUE_SIZE);
        let Some(reserved) = reserved.filter(|_| witness.len() == 1) else {
            return Err(BlockError::WitnessNonceSize);
        };

        let root = witness_root(block);
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&root);
        preimage[32..].copy_from_slice(reserved);
        let commitment = sha256d::Hash::hash(&preimage).to_byte_array();

        let output = coinbase
            .output
            .get(position)
            .expect("the index of an output");
        let script = output.script_pubkey.as_bytes();
        let committed = script
            .get(WITNESS_COMMITMENT_HEADER.len()..WITNESS_COMMITMENT_SIZE_MIN)
            .expect("the script is at least WITNESS_COMMITMENT_SIZE_MIN long");
        if committed != commitment {
            return Err(BlockError::WitnessMerkleMismatch);
        }
        return Ok(());
    }
    for (index, tx) in block.txdata.iter().enumerate() {
        if tx.input.iter().any(|input| !input.witness.is_empty()) {
            return Err(BlockError::UnexpectedWitness { index });
        }
    }
    Ok(())
}

/// Core's `GetWitnessCommitmentIndex`: the last coinbase output that looks like a
/// commitment, or `None` (§2.6).
#[must_use]
pub fn witness_commitment_index(coinbase: &Transaction) -> Option<usize> {
    let mut found = None;
    for (index, output) in coinbase.output.iter().enumerate() {
        let script = output.script_pubkey.as_bytes();
        if script.len() >= WITNESS_COMMITMENT_SIZE_MIN
            && script.starts_with(&WITNESS_COMMITMENT_HEADER)
        {
            found = Some(index);
        }
    }
    found
}

/// Core's `BlockWitnessMerkleRoot`: the tree over `wtxid`s with the coinbase leaf zeroed,
/// no mutation check (§2.6).
#[must_use]
pub fn witness_root(block: &Block) -> [u8; 32] {
    assert!(!block.txdata.is_empty());
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(block.txdata.len());
    leaves.push([0u8; 32]);
    for tx in block.txdata.iter().skip(1) {
        leaves.push(tx.compute_wtxid().to_byte_array());
    }
    assert_eq!(leaves.len(), block.txdata.len());
    merkle_root(leaves).root
}

#[cfg(test)]
mod coins_tests;
#[cfg(test)]
mod tests;
