// SPDX-License-Identifier: MIT OR Apache-2.0

//! The undo record: everything connecting a block destroyed, so that disconnecting it can
//! put the set back exactly as it was.
//!
//! BM-D1 decision 10 made the `BlockDelta` the storage unit, and a delta is a *net*
//! change: `spent` and `overwritten` out, `created` in. Disconnecting is the same type
//! swapped. Of those three lists only two need writing down — `created` is a pure function
//! of the block, whose bytes are on the disk and are never deleted — so the record is the
//! two that are not:
//!
//! ```text
//!   varint(spent)        { varint(input) ‖ coin }*
//!   varint(overwritten)  { outpoint(36)  ‖ coin }*
//! ```
//!
//! # Why the inputs are numbered
//!
//! A restored coin has to be put back at an outpoint, and the outpoint is already in the
//! block: `delta.spent` is, in order, the coins behind the block's non-coinbase inputs
//! that were not created inside the block itself. Core writes nothing at all here and
//! recovers the pairing by position, walking transactions and inputs backwards. That works,
//! and it means the same "was this spend in-block" filter has to run identically on the
//! connect and the disconnect path, with a disagreement between them staying silent until
//! a UTXO-set hash diverges.
//!
//! So each coin carries the index of the input it belongs to instead — two or three bytes,
//! about 8 GB over a whole mainnet history, against the 97 GB that writing the outpoint out
//! in full would cost. The record is then self-describing against the block: the decoder
//! refuses indices that do not ascend or that name no input, and [`UndoRecord::resolve`] is
//! the one place the pairing is made.
//!
//! Overwritten coins are the other way round — they sit at outpoints the block *creates*,
//! not spends — so they carry their outpoint. There are two such blocks in Bitcoin's whole
//! history (mainnet 91842 and 91880), each overwriting one coinbase output.

#![allow(
    dead_code,
    reason = "undo records are produced and consumed by the chainstate (BM-10); the \
              encoding, its bounds and the pairing with a block are complete here"
)]

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{Hash, HashEngine, sha256d};
use bitcoin::{Block, BlockHash, OutPoint, Txid};
use bitmigo_consensus::script::MAX_SCRIPT_SIZE;
use bitmigo_consensus::tx::{Coin, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR};

use super::coin::{self, StoredCoin};
use super::reader::{DecodeError, Reader, put_varint};

/// The 32-byte `SHA256d` trailer Core puts after every undo record, over the previous
/// block's hash and the record's bytes. Blocks are self-verifying and carry none; an undo
/// record has nothing else to vouch for it.
pub const TRAILER_BYTES: u32 = 32;

/// The smallest a non-coinbase input can be: a 36-byte outpoint, a one-byte empty
/// `scriptSig` length, and a four-byte sequence.
const MIN_INPUT_BYTES: u64 = 41;

/// The smallest an output can be: an eight-byte value and a one-byte empty script.
const MIN_OUTPUT_BYTES: u64 = 9;

/// A block's base data is at most a quarter of its weight, so this is the most inputs it
/// can have — 24,390 — and therefore the most coins one record restores.
pub const MAX_BLOCK_INPUTS: u64 = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR / MIN_INPUT_BYTES;

/// The same for outputs, which is what bounds the overwritten list.
pub const MAX_BLOCK_OUTPUTS: u64 = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR / MIN_OUTPUT_BYTES;

/// One coin, at its largest: the height-and-coinbase word, the compressed amount, the
/// script's own length, and a `scriptPubKey` at the size above which an output is
/// unspendable and so never becomes a coin at all.
#[allow(
    clippy::as_conversions,
    reason = "a constant widening in a constant expression, checked below"
)]
const MAX_COIN_BYTES: u64 = 5 + 9 + 3 + MAX_SCRIPT_SIZE as u64;

const _: () = assert!(MAX_SCRIPT_SIZE == 10_000, "the coin bound is read off this");

/// The largest record consensus permits, which is not a small number: a block that spends
/// 24,390 coins whose scripts are each at [`MAX_SCRIPT_SIZE`], and overwrites as many
/// outputs as it has. Nothing allocates this — it is the bound the series asserts an
/// append against and refuses a read past, and the reason an oversized record gets a file
/// of its own.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "a constant expression whose own assertion is the bounds check"
)]
pub const MAX_UNDO_RECORD_BYTES: u32 = {
    let spent = MAX_BLOCK_INPUTS * (3 + MAX_COIN_BYTES);
    let overwritten = MAX_BLOCK_OUTPUTS * (36 + MAX_COIN_BYTES);
    let total = 5 + spent + 5 + overwritten;
    assert!(
        total < (u32::MAX as u64) - 64,
        "an offset stays inside a u32"
    );
    total as u32
};

/// One coin an undo record puts back, and which input took it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndoCoin {
    /// Its position in the block's non-coinbase inputs, in block order.
    pub input: u32,
    /// The coin that input spent.
    pub coin: StoredCoin,
}

/// What connecting one block destroyed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UndoRecord {
    /// The coins of earlier blocks the block spent, in block order.
    pub spent: Vec<UndoCoin>,
    /// The coins the block's coinbase overwrote. Empty on every block but mainnet 91842
    /// and 91880.
    pub overwritten: Vec<(OutPoint, StoredCoin)>,
}

impl UndoRecord {
    /// Build the record for a block that has just been connected.
    ///
    /// `spent` and `overwritten` are the delta's own lists, so the walk is one forward pass:
    /// the delta is in block order over the same inputs, with the in-block spends left out.
    /// The assertions are claims about this node's own two lists agreeing, which is exactly
    /// what an assertion is for — and what stops a disagreement reaching the disk.
    pub fn of(spent: &[Coin], overwritten: &[Coin], block: &Block) -> UndoRecord {
        let outpoints = spends(block);
        assert!(spent.len() <= outpoints.len(), "more coins than inputs");
        let mut coins = Vec::with_capacity(spent.len());
        let mut cursor = 0usize;
        for coin in spent {
            let mut index = cursor;
            while outpoints
                .get(index)
                .is_some_and(|outpoint| *outpoint != coin.outpoint)
            {
                index = index.saturating_add(1);
            }
            assert!(
                index < outpoints.len(),
                "the delta is in the block's own input order",
            );
            coins.push(UndoCoin {
                input: u32::try_from(index).unwrap_or(u32::MAX),
                coin: stored(coin),
            });
            cursor = index.saturating_add(1);
        }
        UndoRecord {
            spent: coins,
            overwritten: overwritten
                .iter()
                .map(|coin| (coin.outpoint, stored(coin)))
                .collect(),
        }
    }

    /// The bytes that go into the series.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.spent.len().saturating_mul(32));
        put_varint(&mut bytes, u64::try_from(self.spent.len()).unwrap_or(0));
        for entry in &self.spent {
            put_varint(&mut bytes, u64::from(entry.input));
            coin::put(&mut bytes, &entry.coin);
        }
        put_varint(
            &mut bytes,
            u64::try_from(self.overwritten.len()).unwrap_or(0),
        );
        for (outpoint, entry) in &self.overwritten {
            bytes.extend_from_slice(&serialize(outpoint));
            coin::put(&mut bytes, entry);
        }
        bytes
    }

    /// Read one back.
    ///
    /// Every count is refused before anything is reserved for it, and the input indices
    /// must ascend: two coins claiming one input would put two coins at one outpoint.
    pub fn decode(bytes: &[u8]) -> Result<UndoRecord, DecodeError> {
        let mut reader = Reader::new(bytes);
        let count = reader.count(MAX_BLOCK_INPUTS)?;
        let mut spent = Vec::with_capacity(count);
        let mut previous: Option<u32> = None;
        for _ in 0..count {
            let input = u32::try_from(reader.count(MAX_BLOCK_INPUTS)?).unwrap_or(u32::MAX);
            if previous.is_some_and(|last| input <= last) {
                return Err(DecodeError::NotAscending { input });
            }
            previous = Some(input);
            spent.push(UndoCoin {
                input,
                coin: coin::read(&mut reader)?,
            });
        }

        let count = reader.count(MAX_BLOCK_OUTPUTS)?;
        let mut overwritten = Vec::with_capacity(count);
        for _ in 0..count {
            let txid = reader.hash()?;
            let vout = reader.u32_le()?;
            overwritten.push((outpoint(txid, vout), coin::read(&mut reader)?));
        }
        reader.finish()?;
        Ok(UndoRecord { spent, overwritten })
    }

    /// Pair every restored coin with the outpoint it goes back to.
    ///
    /// The disconnect path's one call (BM-10): the block is read from the store, and this
    /// says which of its inputs each coin came from. An index that names no input is an
    /// error rather than a panic, because the bytes came off a disk.
    pub fn resolve(&self, block: &Block) -> Result<Vec<(OutPoint, StoredCoin)>, DecodeError> {
        let outpoints = spends(block);
        let mut restored =
            Vec::with_capacity(self.spent.len().saturating_add(self.overwritten.len()));
        for entry in &self.spent {
            let index = usize::try_from(entry.input).unwrap_or(usize::MAX);
            let outpoint = outpoints.get(index).ok_or(DecodeError::TooLong {
                declared: u64::from(entry.input),
                limit: u64::try_from(outpoints.len()).unwrap_or(u64::MAX),
            })?;
            restored.push((*outpoint, entry.coin.clone()));
        }
        restored.extend(self.overwritten.iter().cloned());
        Ok(restored)
    }
}

/// Core's undo checksum: `SHA256d(previous block hash ‖ record)`.
///
/// The previous block's hash rather than this one's, exactly as Core writes it: it is what
/// `DisconnectBlock` has in its hand as it reads, and folding it in means a record cannot
/// be read back as some other block's.
pub fn trailer(record: &[u8], previous: BlockHash) -> [u8; 32] {
    let mut engine = sha256d::Hash::engine();
    engine.input(&previous.to_byte_array());
    engine.input(record);
    sha256d::Hash::from_engine(engine).to_byte_array()
}

/// Every outpoint the block spends, in block order, the coinbase's left out.
///
/// One definition, used by the writer and the reader, so the two cannot drift apart.
fn spends(block: &Block) -> Vec<OutPoint> {
    block
        .txdata
        .iter()
        .skip(1)
        .flat_map(|transaction| transaction.input.iter())
        .map(|input| input.previous_output)
        .collect()
}

/// A consensus coin as the disk holds it: the outpoint is dropped, because the record
/// says where it is instead.
fn stored(coin: &Coin) -> StoredCoin {
    StoredCoin {
        height: coin.height,
        coinbase: coin.coinbase,
        output: coin.output.clone(),
    }
}

/// An outpoint from the thirty-six bytes on the disk.
fn outpoint(txid: [u8; 32], vout: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array(txid),
        vout,
    }
}

#[cfg(test)]
#[path = "undo_tests.rs"]
mod tests;
