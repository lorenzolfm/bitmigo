// SPDX-License-Identifier: MIT OR Apache-2.0

//! How a coin is written down: Core's amount and script compression, and nothing else.
//!
//! One coin encoder for the whole node. The undo record uses it here; the coin store uses
//! it next (BM-27), and two encodings for one value is how a chainstate and the record that
//! rolls it back come to disagree.
//!
//! The scheme is Core's (`compressor.cpp`, `docs/storage-layouts.md` §1.1), because it is
//! measured, documented and roughly halves an archival node's undo footprint — 21 bytes a
//! coin against 45. It is not Core's *file*: nothing reads these bytes but bitmigo, so the
//! two places this deviates are deliberate.
//!
//! **Uncompressed P2PK is stored raw.** Core's templates 4 and 5 keep only the x coordinate
//! and a parity bit, and decompress the point with `CPubKey::Decompress` on the way back
//! out. That puts an elliptic-curve operation — and a failure mode — on the path that reads
//! a coin off the disk, to save 32 bytes on the pre-2012 outputs that use the form: about
//! 48 MB across the whole of mainnet. Reading is refused rather than ignored, so a file
//! that contains one was not written by this node.
//!
//! **A script longer than [`MAX_SCRIPT_SIZE`] is refused, not truncated.** Core turns one
//! into a bare `OP_RETURN` on read, which is lossy; here such an output is unspendable
//! (`tx::is_unspendable`) and never enters the set at all, so the case is an assertion on
//! the way in and an error on the way out.

#![allow(
    dead_code,
    reason = "the coin encoder is used by the undo record and by the coin store (BM-27); \
              every template is exercised by this module's own tests"
)]

use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::{Amount, TxOut};
use bitmigo_consensus::params::Height;
use bitmigo_consensus::script::MAX_SCRIPT_SIZE;
use bitmigo_consensus::tx::MAX_MONEY;

use super::reader::{DecodeError, Reader, put_varint};

/// Core's `nSpecialScripts`: template numbers below this select a form, and anything from
/// it up is `6 + the raw length`.
const SPECIAL_SCRIPTS: u64 = 6;

/// `OP_DUP OP_HASH160 <20> … OP_EQUALVERIFY OP_CHECKSIG`.
const P2PKH_LEN: usize = 25;

/// `OP_HASH160 <20> … OP_EQUAL`.
const P2SH_LEN: usize = 23;

/// `<33> … OP_CHECKSIG`, the compressed form.
const P2PK_COMPRESSED_LEN: usize = 35;

/// A coin as the disk holds it: what a spent output has to be re-created from.
///
/// The four fields are exactly what `DisconnectBlock` needs and why (storage doc §2.3): the
/// coin put back must serialize identically to the one that was taken out, or this node's
/// UTXO-set hash leaves every other node's behind; the height and the coinbase flag are
/// needed again for maturity and BIP30 when the block is connected a second time.
///
/// Core writes a `0x00` byte here as well — a retired transaction-version field kept for
/// compatibility with records written before 0.15. This store has no such records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCoin {
    /// The height of the block that created the coin.
    pub height: Height,
    /// Whether that block's coinbase created it.
    pub coinbase: bool,
    /// Its value and `scriptPubKey`.
    pub output: TxOut,
}

/// Append a coin.
pub fn put(bytes: &mut Vec<u8>, coin: &StoredCoin) {
    // A height is a `u32`, so doubling one and setting the low bit stays inside a `u64`.
    let code = u64::from(coin.height.get())
        .saturating_mul(2)
        .saturating_add(u64::from(coin.coinbase));
    assert_eq!(code >> 1, u64::from(coin.height.get()));
    put_varint(bytes, code);
    put_varint(bytes, compress_amount(coin.output.value.to_sat()));
    put_script(bytes, &coin.output.script_pubkey);
}

/// Read one back.
pub fn read(reader: &mut Reader<'_>) -> Result<StoredCoin, DecodeError> {
    let code = reader.varint()?;
    let coinbase = code & 1 == 1;
    let height = u32::try_from(code >> 1).map_err(|_| DecodeError::TooLong {
        declared: code >> 1,
        limit: u64::from(u32::MAX),
    })?;
    let value = decompress_amount(reader.varint()?)?;
    let script_pubkey = read_script(reader)?;
    Ok(StoredCoin {
        height: Height::new(height),
        coinbase,
        output: TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        },
    })
}

/// Core's `CompressAmount`: strip the trailing decimal zeros a bitcoin amount almost always
/// has, so that a round number costs two or three bytes instead of nine.
fn compress_amount(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let mut left = value;
    let mut exponent: u64 = 0;
    while left.is_multiple_of(10) && exponent < 9 {
        left /= 10;
        exponent = exponent.saturating_add(1);
    }
    if exponent < 9 {
        let digit = left % 10;
        assert!((1..=9).contains(&digit), "the zeros were stripped above");
        left /= 10;
        // 1 + (n * 9 + d - 1) * 10 + e, in the order that cannot overflow a u64 for any
        // amount: `left` is at most MAX_MONEY / 10 here.
        left.saturating_mul(9)
            .saturating_add(digit)
            .saturating_sub(1)
            .saturating_mul(10)
            .saturating_add(exponent)
            .saturating_add(1)
    } else {
        left.saturating_sub(1)
            .saturating_mul(10)
            .saturating_add(9)
            .saturating_add(1)
    }
}

/// Core's `DecompressAmount`, refusing what Core cannot be handed: this reads bytes off a
/// disk, and a value above [`MAX_MONEY`] never came out of [`compress_amount`].
fn decompress_amount(encoded: u64) -> Result<u64, DecodeError> {
    let too_long = |value: u64| DecodeError::TooLong {
        declared: value,
        limit: MAX_MONEY,
    };
    if encoded == 0 {
        return Ok(0);
    }
    let mut left = encoded.saturating_sub(1);
    let exponent = left % 10;
    left /= 10;
    let mut value = if exponent < 9 {
        let digit = (left % 9).saturating_add(1);
        left /= 9;
        left.checked_mul(10)
            .and_then(|shifted| shifted.checked_add(digit))
            .ok_or_else(|| too_long(encoded))?
    } else {
        left.checked_add(1).ok_or_else(|| too_long(encoded))?
    };
    for _ in 0..exponent {
        value = value.checked_mul(10).ok_or_else(|| too_long(encoded))?;
    }
    if value > MAX_MONEY {
        return Err(too_long(value));
    }
    Ok(value)
}

/// Append a `scriptPubKey` under Core's templates.
fn put_script(bytes: &mut Vec<u8>, script: &bitcoin::Script) {
    let script = script.as_bytes();
    assert!(
        script.len() <= MAX_SCRIPT_SIZE,
        "a longer script is unspendable and never reaches a coin",
    );
    if let Some(hash) = p2pkh_hash(script) {
        put_varint(bytes, 0);
        bytes.extend_from_slice(hash);
    } else if let Some(hash) = p2sh_hash(script) {
        put_varint(bytes, 1);
        bytes.extend_from_slice(hash);
    } else if let Some((parity, key)) = p2pk_compressed(script) {
        put_varint(bytes, u64::from(parity));
        bytes.extend_from_slice(key);
    } else {
        // The assertion above bounds the length at MAX_SCRIPT_SIZE, so the cast is exact.
        let length = u64::try_from(script.len()).unwrap_or(u64::MAX);
        put_varint(bytes, length.saturating_add(SPECIAL_SCRIPTS));
        bytes.extend_from_slice(script);
    }
}

/// Read one back into the bytes it was written from.
fn read_script(reader: &mut Reader<'_>) -> Result<ScriptBuf, DecodeError> {
    let template = reader.varint()?;
    match template {
        0 => {
            let hash = reader.take(20)?;
            let mut script = Vec::with_capacity(P2PKH_LEN);
            script.extend_from_slice(&[0x76, 0xa9, 0x14]);
            script.extend_from_slice(hash);
            script.extend_from_slice(&[0x88, 0xac]);
            Ok(ScriptBuf::from_bytes(script))
        }
        1 => {
            let hash = reader.take(20)?;
            let mut script = Vec::with_capacity(P2SH_LEN);
            script.extend_from_slice(&[0xa9, 0x14]);
            script.extend_from_slice(hash);
            script.push(0x87);
            Ok(ScriptBuf::from_bytes(script))
        }
        2 | 3 => {
            let key = reader.take(32)?;
            let mut script = Vec::with_capacity(P2PK_COMPRESSED_LEN);
            script.push(0x21);
            // The arm is two or three, and both are one byte.
            script.push(u8::try_from(template).unwrap_or(2));
            script.extend_from_slice(key);
            script.push(0xac);
            Ok(ScriptBuf::from_bytes(script))
        }
        // Core's uncompressed-P2PK templates, which this store never writes.
        4 | 5 => Err(DecodeError::BadTag { tag: 4 }),
        _ => {
            let length = template.saturating_sub(SPECIAL_SCRIPTS);
            let limit = u64::try_from(MAX_SCRIPT_SIZE).unwrap_or(u64::MAX);
            if length > limit {
                return Err(DecodeError::TooLong {
                    declared: length,
                    limit,
                });
            }
            let count = usize::try_from(length).map_err(|_| DecodeError::TooLong {
                declared: length,
                limit,
            })?;
            Ok(ScriptBuf::from_bytes(reader.take(count)?.to_vec()))
        }
    }
}

/// `76 a9 14 <20 bytes> 88 ac`, and the twenty bytes.
fn p2pkh_hash(script: &[u8]) -> Option<&[u8]> {
    if script.len() != P2PKH_LEN {
        return None;
    }
    let opens = script.starts_with(&[0x76, 0xa9, 0x14]);
    let closes = script.ends_with(&[0x88, 0xac]);
    if opens && closes {
        script.get(3..23)
    } else {
        None
    }
}

/// `a9 14 <20 bytes> 87`, and the twenty bytes.
fn p2sh_hash(script: &[u8]) -> Option<&[u8]> {
    if script.len() != P2SH_LEN {
        return None;
    }
    if script.starts_with(&[0xa9, 0x14]) && script.ends_with(&[0x87]) {
        script.get(2..22)
    } else {
        None
    }
}

/// `21 <02|03> <32 bytes> ac`: the parity byte, and the x coordinate.
fn p2pk_compressed(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() != P2PK_COMPRESSED_LEN {
        return None;
    }
    if script.first() != Some(&0x21) || script.last() != Some(&0xac) {
        return None;
    }
    let parity = *script.get(1)?;
    if parity != 2 && parity != 3 {
        return None;
    }
    Some((parity, script.get(2..34)?))
}

#[cfg(test)]
#[path = "coin_tests.rs"]
mod tests;
