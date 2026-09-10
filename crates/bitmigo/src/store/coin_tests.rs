// SPDX-License-Identifier: MIT OR Apache-2.0

//! The coin encoder, against bitcoind's own outputs and against Core's own arithmetic.
//!
//! The property that matters is exact: a coin put back must serialize identically to the
//! one taken out, or this node's UTXO-set hash leaves every other node's behind. So the
//! first test round-trips every coin bitcoind's regtest chain creates, and the rest are
//! the corners a hundred blocks of ordinary transactions do not reach.

use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::{Amount, TxOut};
use bitmigo_consensus::params::Height;
use bitmigo_consensus::script::MAX_SCRIPT_SIZE;
use bitmigo_consensus::tx::MAX_MONEY;

use super::{DecodeError, Reader, StoredCoin, compress_amount, decompress_amount, put, read};
use crate::store::fixture;

/// Encode, decode, and say what it cost.
fn round_trip(coin: &StoredCoin) -> usize {
    let mut bytes = Vec::new();
    put(&mut bytes, coin);
    let mut reader = Reader::new(&bytes);
    let back = read(&mut reader).expect("what this encoder wrote, it reads");
    reader.finish().expect("a coin is self-delimiting");
    assert_eq!(&back, coin, "a coin did not survive the disk");
    bytes.len()
}

/// A coin with a chosen script.
fn coin(script: ScriptBuf, value: u64) -> StoredCoin {
    StoredCoin {
        height: Height::new(700_000),
        coinbase: false,
        output: TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        },
    }
}

#[test]
fn every_coin_bitcoind_created_survives_the_encoder() {
    let blocks = fixture::blocks();
    let coins = fixture::coins(&blocks);
    assert!(coins.len() > 110, "the fixture chain has coins in it");
    for entry in coins.values() {
        round_trip(&StoredCoin {
            height: entry.height,
            coinbase: entry.coinbase,
            output: entry.output.clone(),
        });
    }
}

#[test]
fn cores_amount_compression_is_cores_arithmetic() {
    // `compressor.cpp: CompressAmount`, worked through for the values its comment names:
    // a round number costs a byte or two where nine would otherwise be spent.
    assert_eq!(compress_amount(0), 0);
    assert_eq!(compress_amount(1), 1);
    assert_eq!(compress_amount(1_000_000), 7);
    assert_eq!(compress_amount(100_000_000), 9);
    assert_eq!(compress_amount(5_000_000_000), 50);
    assert_eq!(compress_amount(MAX_MONEY), 21_000_000);
    for value in [0, 1, 7, 546, 100_000_000, 5_000_000_000, MAX_MONEY] {
        assert_eq!(decompress_amount(compress_amount(value)), Ok(value));
    }
}

#[test]
fn every_amount_that_can_be_a_coin_survives() {
    // The exhaustive check is out of reach, so: every power of ten, every power of two,
    // and their neighbours — which is where a "strip the trailing zeros" scheme goes wrong.
    let mut values = vec![0, MAX_MONEY];
    let mut ten: u64 = 1;
    while ten <= MAX_MONEY {
        values.extend([ten.saturating_sub(1), ten, ten.saturating_add(1)]);
        ten = ten.saturating_mul(10);
    }
    for shift in 0..51 {
        let two = 1u64 << shift;
        if two <= MAX_MONEY {
            values.extend([two.saturating_sub(1), two, two.saturating_add(1)]);
        }
    }
    for value in values {
        assert_eq!(
            decompress_amount(compress_amount(value)),
            Ok(value),
            "{value} did not survive",
        );
    }
}

#[test]
fn an_amount_no_encoder_wrote_is_refused_rather_than_returned() {
    // Bytes off a disk, not a value from this node: anything above MAX_MONEY came from
    // somewhere else, and a coin is never worth more than the money there is.
    assert!(decompress_amount(u64::MAX).is_err());
    assert!(decompress_amount(compress_amount(MAX_MONEY).saturating_add(10)).is_err());
}

#[test]
fn the_templates_are_the_sizes_they_exist_to_be() {
    let hash = [0x11u8; 20];
    let mut p2pkh = vec![0x76, 0xa9, 0x14];
    p2pkh.extend_from_slice(&hash);
    p2pkh.extend_from_slice(&[0x88, 0xac]);
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend_from_slice(&hash);
    p2sh.push(0x87);
    let mut p2pk = vec![0x21, 0x02];
    p2pk.extend_from_slice(&[0x33u8; 32]);
    p2pk.push(0xac);
    let mut witness = vec![0x00, 0x14];
    witness.extend_from_slice(&hash);

    // Three bytes of height and one of amount, so the rest is the script: a twenty-five
    // byte P2PKH costs twenty-one, a thirty-five byte P2PK thirty-three, and a witness
    // program is stored as it stands behind its own length.
    let value = 5_000_000_000;
    assert_eq!(round_trip(&coin(ScriptBuf::from_bytes(p2pkh), value)), 25);
    assert_eq!(round_trip(&coin(ScriptBuf::from_bytes(p2sh), value)), 25);
    assert_eq!(round_trip(&coin(ScriptBuf::from_bytes(p2pk), value)), 37);
    assert_eq!(round_trip(&coin(ScriptBuf::from_bytes(witness), value)), 27);
}

#[test]
fn a_script_that_only_looks_like_a_template_is_stored_as_it_stands() {
    // Strictness is the whole safety of a template: a script one byte off P2PKH that were
    // compressed as one would come back as a different script and a different coin.
    let hash = [0x11u8; 20];
    let mut nearly = vec![0x76, 0xa9, 0x14];
    nearly.extend_from_slice(&hash);
    nearly.extend_from_slice(&[0x88, 0xad]);
    round_trip(&coin(ScriptBuf::from_bytes(nearly), 1));

    // A P2PK whose key does not start 02 or 03 is not the compressed form.
    let mut odd = vec![0x21, 0x04];
    odd.extend_from_slice(&[0x33u8; 32]);
    odd.push(0xac);
    round_trip(&coin(ScriptBuf::from_bytes(odd), 1));

    // The empty script, and one byte of it.
    round_trip(&coin(ScriptBuf::new(), 0));
    round_trip(&coin(ScriptBuf::from_bytes(vec![0x51]), 1));
}

#[test]
fn the_longest_script_a_coin_can_have_survives() {
    let script = ScriptBuf::from_bytes(vec![0x51; MAX_SCRIPT_SIZE]);
    assert_eq!(round_trip(&coin(script, MAX_MONEY)), 10_009);
}

#[test]
fn cores_uncompressed_pubkey_templates_are_refused_rather_than_guessed_at() {
    // Templates 4 and 5 need an elliptic-curve point decompression to read a coin back.
    // This store never writes one, so meeting one means the file is not ours.
    for template in [4u8, 5u8] {
        let mut bytes = vec![0x00, 0x01, template];
        bytes.extend_from_slice(&[0x33u8; 32]);
        let mut reader = Reader::new(&bytes);
        assert_eq!(read(&mut reader), Err(DecodeError::BadTag { tag: 4 }));
    }
}

#[test]
fn a_script_longer_than_a_coin_can_hold_is_refused() {
    // Core turns one into a bare OP_RETURN, which is lossy. Here such an output is
    // unspendable and never becomes a coin, so the bytes did not come from this encoder.
    let mut bytes = vec![0x00, 0x01];
    let over = u64::try_from(MAX_SCRIPT_SIZE).unwrap() + 6 + 1;
    super::put_varint(&mut bytes, over);
    let mut reader = Reader::new(&bytes);
    assert!(matches!(
        read(&mut reader),
        Err(DecodeError::TooLong { .. }),
    ));
}

#[test]
fn a_coin_cut_in_half_is_an_error() {
    let whole = {
        let mut bytes = Vec::new();
        put(
            &mut bytes,
            &coin(ScriptBuf::from_bytes(vec![0x51; 40]), 12_345),
        );
        bytes
    };
    for cut in 0..whole.len() {
        let mut reader = Reader::new(whole.get(..cut).unwrap_or_default());
        assert!(read(&mut reader).is_err(), "a coin cut at {cut} decoded");
    }
}
