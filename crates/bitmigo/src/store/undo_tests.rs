// SPDX-License-Identifier: MIT OR Apache-2.0

//! The undo record, against blocks bitcoind actually mined and spends it actually made.
//!
//! The record is the half of a disconnect that cannot be recomputed, so the test that
//! matters is the round trip through a real block: build it from the delta's own lists,
//! write it, read it back, and pair every coin with the outpoint it goes to.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, TxOut, Txid};
use bitmigo_consensus::params::Height;
use bitmigo_consensus::tx::Coin;

use super::{
    DecodeError, MAX_BLOCK_INPUTS, MAX_BLOCK_OUTPUTS, MAX_UNDO_RECORD_BYTES, StoredCoin, UndoCoin,
    UndoRecord, trailer,
};
use crate::store::fixture;

/// A coin at a stated outpoint, for the cases the fixture chain does not reach.
fn coin(seed: u8, vout: u32) -> Coin {
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([seed; 32]),
        vout,
    };
    Coin {
        outpoint,
        output: TxOut {
            value: Amount::from_sat(u64::from(seed) * 1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, seed]),
        },
        height: Height::new(u32::from(seed)),
        coinbase: seed.is_multiple_of(2),
    }
}

#[test]
fn every_spend_bitcoind_made_survives_the_record() {
    let blocks = fixture::blocks();
    let coins = fixture::coins(&blocks);
    let mut spends = 0usize;
    for block in &blocks {
        let spent = fixture::spent_by(block, &coins);
        if spent.is_empty() {
            continue;
        }
        spends = spends.saturating_add(spent.len());

        let record = UndoRecord::of(&spent, &[], block);
        let bytes = record.encode();
        let back = UndoRecord::decode(&bytes).expect("what was written reads back");
        assert_eq!(back, record);

        // The pairing is the whole reason an input index is written down rather than an
        // outpoint: this is where the thirty-six bytes come back from.
        let restored = back.resolve(block).expect("every index names an input");
        assert_eq!(restored.len(), spent.len());
        for (coin, (outpoint, stored)) in spent.iter().zip(restored) {
            assert_eq!(
                outpoint, coin.outpoint,
                "a coin went back to the wrong place"
            );
            assert_eq!(stored.height, coin.height);
            assert_eq!(stored.coinbase, coin.coinbase);
            assert_eq!(stored.output, coin.output);
        }
    }
    assert!(spends >= 4, "the fixture chain makes real spends");
}

#[test]
fn a_block_that_spends_nothing_has_an_empty_record() {
    let blocks = fixture::blocks();
    let coinbase_only = blocks.first().expect("genesis");
    let record = UndoRecord::of(&[], &[], coinbase_only);
    assert_eq!(record, UndoRecord::default());
    // Two counts and nothing else.
    assert_eq!(record.encode(), vec![0x00, 0x00]);
    assert_eq!(UndoRecord::decode(&record.encode()), Ok(record));
}

#[test]
fn an_overwritten_coin_carries_its_outpoint_because_the_block_creates_it() {
    // Mainnet 91842 and 91880: a duplicate coinbase overwrites a coin that sits at an
    // outpoint the block *creates*, so there is no input to number it against.
    let blocks = fixture::blocks();
    let block = blocks.get(2).expect("a block");
    let overwritten = coin(9, 0);
    let record = UndoRecord::of(&[], std::slice::from_ref(&overwritten), block);
    let back = UndoRecord::decode(&record.encode()).expect("a round trip");
    let restored = back.resolve(block).expect("nothing to pair");
    assert_eq!(restored.len(), 1);
    assert_eq!(
        restored.first().map(|entry| entry.0),
        Some(overwritten.outpoint)
    );
}

#[test]
fn two_coins_may_not_claim_one_input() {
    // Ascending indices are what makes a record a function from inputs to coins. Two coins
    // on one input would put two coins at one outpoint, which is a set that is wrong.
    let record = UndoRecord {
        spent: vec![
            UndoCoin {
                input: 3,
                coin: stored(1),
            },
            UndoCoin {
                input: 3,
                coin: stored(2),
            },
        ],
        overwritten: Vec::new(),
    };
    assert_eq!(
        UndoRecord::decode(&record.encode()),
        Err(DecodeError::NotAscending { input: 3 }),
    );

    let backwards = UndoRecord {
        spent: vec![
            UndoCoin {
                input: 4,
                coin: stored(1),
            },
            UndoCoin {
                input: 1,
                coin: stored(2),
            },
        ],
        overwritten: Vec::new(),
    };
    assert_eq!(
        UndoRecord::decode(&backwards.encode()),
        Err(DecodeError::NotAscending { input: 1 }),
    );
}

#[test]
fn an_index_that_names_no_input_is_an_error_and_not_a_panic() {
    let blocks = fixture::blocks();
    let block = blocks.get(103).expect("a spending block");
    let record = UndoRecord {
        spent: vec![UndoCoin {
            input: 5_000,
            coin: stored(1),
        }],
        overwritten: Vec::new(),
    };
    assert!(matches!(
        record.resolve(block),
        Err(DecodeError::TooLong { .. }),
    ));
}

#[test]
fn a_count_no_block_could_have_is_refused_before_anything_is_reserved() {
    let mut bytes = Vec::new();
    super::put_varint(&mut bytes, MAX_BLOCK_INPUTS + 1);
    assert!(matches!(
        UndoRecord::decode(&bytes),
        Err(DecodeError::TooLong { .. }),
    ));

    let mut bytes = Vec::new();
    super::put_varint(&mut bytes, 0);
    super::put_varint(&mut bytes, MAX_BLOCK_OUTPUTS + 1);
    assert!(matches!(
        UndoRecord::decode(&bytes),
        Err(DecodeError::TooLong { .. }),
    ));
}

#[test]
fn a_record_cut_anywhere_is_an_error() {
    let blocks = fixture::blocks();
    let coins = fixture::coins(&blocks);
    let block = blocks.get(103).expect("a spending block");
    let whole = UndoRecord::of(&fixture::spent_by(block, &coins), &[], block).encode();
    assert!(whole.len() > 40, "the record has coins in it");
    for cut in 0..whole.len() {
        assert!(
            UndoRecord::decode(whole.get(..cut).unwrap_or_default()).is_err(),
            "a record cut at {cut} decoded",
        );
    }
    // And bytes after the record, which is the other half of self-delimiting.
    let mut extra = whole.clone();
    extra.push(0);
    assert_eq!(
        UndoRecord::decode(&extra),
        Err(DecodeError::Trailing { left: 1 }),
    );
}

#[test]
fn the_trailer_binds_a_record_to_the_block_before_it() {
    let record = UndoRecord::default().encode();
    let one = trailer(&record, BlockHash::from_byte_array([1u8; 32]));
    let other = trailer(&record, BlockHash::from_byte_array([2u8; 32]));
    assert_ne!(one, other, "a record cannot be read as another block's");
    assert_eq!(one, trailer(&record, BlockHash::from_byte_array([1u8; 32])));
}

#[test]
fn the_record_bound_is_the_one_consensus_implies() {
    // A block's base data is a quarter of its weight, an input is at least 41 bytes of it
    // and an output at least 9, and a coin's script stops at the size above which an
    // output is unspendable. The overwritten term dominates a bound that the two blocks in
    // Bitcoin's history that reach it at all reach with one output each.
    assert_eq!(MAX_BLOCK_INPUTS, 24_390);
    assert_eq!(MAX_BLOCK_OUTPUTS, 111_111);
    assert_eq!(MAX_UNDO_RECORD_BYTES, 1_361_386_693);
    // Which still leaves an offset inside a u32 once a file has rolled for it.
    assert!(u64::from(MAX_UNDO_RECORD_BYTES) + 64 < u64::from(u32::MAX));
}

/// A stand-in coin for the cases that are about the record and not about the coin.
fn stored(seed: u8) -> StoredCoin {
    StoredCoin {
        height: Height::new(u32::from(seed)),
        coinbase: false,
        output: TxOut {
            value: Amount::from_sat(u64::from(seed)),
            script_pubkey: ScriptBuf::from_bytes(vec![seed]),
        },
    }
}
