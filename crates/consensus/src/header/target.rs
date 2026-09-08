// SPDX-License-Identifier: MIT OR Apache-2.0

//! The compact target encoding (`nBits`), the work a block proves, and the proof-of-work
//! comparison, each byte-for-byte with Core's `arith_uint256`, `pow.cpp` and `chain.cpp`.
//!
//! `nBits` is a 32-bit float without a fraction: one byte of size and three of mantissa, the
//! mantissa's top bit a sign that a target must never carry. Decoding is Core's `SetCompact`
//! plus `DeriveTarget`'s four range checks; encoding is `GetCompact`, whose re-encoding of a
//! computed target is what the next block's `nBits` must equal exactly (§1.1). The
//! precision `nBits` loses is normative: the retarget multiplies the decoded, already
//! truncated target and truncates again on the way out (§1.2).

use core::fmt;

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::pow::{CompactTarget, Target, Work};

use super::uint::U256;

/// Why `nBits` does not name a target the chain accepts. Core folds all four into the one
/// reject reason `high-hash`; the variant is the evidence Core's log line would carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TargetError {
    /// The mantissa's sign bit is set with a non-zero mantissa.
    Negative,
    /// The size byte puts a non-zero mantissa above 256 bits.
    Overflow,
    /// The decoded target is zero, which no hash can meet.
    Zero,
    /// The decoded target is easier than the chain's `powLimit`.
    AbovePowLimit,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Negative => "nBits encodes a negative target",
            Self::Overflow => "nBits overflows 256 bits",
            Self::Zero => "nBits encodes a zero target",
            Self::AbovePowLimit => "nBits encodes a target above powLimit",
        })
    }
}

impl std::error::Error for TargetError {}

/// The mantissa's sign bit.
const SIGN_BIT: u32 = 0x0080_0000;
/// The mantissa without its sign bit.
const MANTISSA_MASK: u32 = 0x007f_ffff;

/// `SetCompact`'s three outputs before the value is formed: size, unsigned mantissa, and
/// the two flags. The value itself is [`expand`].
#[derive(Clone, Copy, Debug)]
struct Compact {
    size: u32,
    word: u32,
    negative: bool,
    overflow: bool,
}

fn split(bits: CompactTarget) -> Compact {
    let bits = bits.to_consensus();
    let size = bits >> 24;
    let mut word = bits & MANTISSA_MASK;
    // Core shifts a short mantissa in place before it reads the flags, so `0x00923456`
    // is neither negative nor anything: its mantissa is gone.
    if size <= 3 {
        word >>= 8 * (3 - size);
    }
    Compact {
        size,
        word,
        negative: word != 0 && (bits & SIGN_BIT) != 0,
        overflow: word != 0
            && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32)),
    }
}

/// The value `SetCompact` forms, for a compact that does not overflow: with a size of at
/// most 34 and the mantissa bounded per size, every shift stays below the width.
fn expand(compact: Compact) -> U256 {
    assert!(!compact.overflow);
    if compact.word == 0 {
        return U256::ZERO;
    }
    if compact.size <= 3 {
        // Already shifted by `split`.
        U256::from_u64(u64::from(compact.word))
    } else {
        let shift = 8 * (compact.size - 3);
        assert!(shift <= 248);
        U256::from_u64(u64::from(compact.word)).shl(shift)
    }
}

/// Core's `GetCompact(false)`: the canonical `nBits` for a target.
fn compress(value: U256) -> u32 {
    let mut size = value.bits().div_ceil(8);
    let mut compact = if size <= 3 {
        value.low_u64() << (8 * (3 - size))
    } else {
        value.shr(8 * (size - 3)).low_u64()
    };
    assert!(compact <= 0x00ff_ffff);
    // A mantissa with the sign bit set is written one byte shorter and one size larger.
    if compact & u64::from(SIGN_BIT) != 0 {
        compact >>= 8;
        size += 1;
    }
    assert_eq!(compact & !u64::from(MANTISSA_MASK), 0);
    assert!(size < 256);
    u32::try_from(compact).expect("three bytes") | (size << 24)
}

fn target_to_uint(target: Target) -> U256 {
    U256::from_be_bytes(target.to_be_bytes())
}

fn uint_to_target(value: U256) -> Target {
    Target::from_be_bytes(value.to_be_bytes())
}

/// Core's `DeriveTarget`: the target `bits` names, if the chain accepts it (§1.1). The
/// checks are Core's four; their order here only picks the evidence, Core reports one word.
pub fn decode_target(bits: CompactTarget, pow_limit: Target) -> Result<Target, TargetError> {
    let compact = split(bits);
    if compact.negative {
        return Err(TargetError::Negative);
    }
    if compact.overflow {
        return Err(TargetError::Overflow);
    }
    let value = expand(compact);
    if value.is_zero() {
        return Err(TargetError::Zero);
    }
    if value > target_to_uint(pow_limit) {
        return Err(TargetError::AbovePowLimit);
    }
    let target = uint_to_target(value);
    assert!(target > Target::ZERO);
    assert!(target <= pow_limit);
    Ok(target)
}

/// Core's `GetCompact`: the one `nBits` a computed target is written as. Decoding it gives
/// back a target no larger than the input; the low bits are the precision `nBits` lacks.
#[must_use]
pub fn encode_target(target: Target) -> CompactTarget {
    let encoded = CompactTarget::from_consensus(compress(target_to_uint(target)));
    assert!(split(encoded).word <= MANTISSA_MASK);
    encoded
}

/// Core's `GetBlockProof`: `(~target / (target + 1)) + 1`, and zero for an `nBits` that is
/// negative, overflows or names a zero target (§1.1). Not a validity rule, but the number
/// the most-work choice sums, so two nodes must agree on it.
#[must_use]
pub fn block_work(bits: CompactTarget) -> Work {
    let compact = split(bits);
    if compact.negative || compact.overflow {
        return Work::from_be_bytes([0; 32]);
    }
    let target = expand(compact);
    if target.is_zero() {
        return Work::from_be_bytes([0; 32]);
    }
    // A target is at most 0x7fffff << 232, so neither addition can carry out of 256 bits.
    let plus_one = target
        .checked_add(U256::ONE)
        .expect("target below 2^256 - 1");
    let quotient = target.not().div(plus_one);
    let work = quotient
        .checked_add(U256::ONE)
        .expect("quotient below 2^255");
    assert!(!work.is_zero());
    Work::from_be_bytes(work.to_be_bytes())
}

/// Core's `UintToArith256(hash) <= target`: the block hash read as a little-endian integer
/// is at most the target.
#[must_use]
pub fn hash_meets_target(hash: BlockHash, target: Target) -> bool {
    U256::from_le_bytes(hash.to_byte_array()) <= target_to_uint(target)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test fixtures index arrays and vectors whose lengths the tests assert"
)]
mod tests {
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::{CompactTarget, Target};

    use super::{
        TargetError, block_work, compress, decode_target, encode_target, expand, hash_meets_target,
        split,
    };
    use crate::script::vectors::Prng;

    const MAINNET_POW_LIMIT: u32 = 0x1d00_ffff;

    fn compact(bits: u32) -> CompactTarget {
        CompactTarget::from_consensus(bits)
    }

    fn mainnet_limit() -> Target {
        Target::from_compact(compact(MAINNET_POW_LIMIT))
    }

    /// Core's `bignum_SetCompact` vectors from `arith_uint256_tests.cpp`: input, decoded
    /// value as hex, re-encoding, negative, overflow.
    #[test]
    fn set_compact_vectors_from_core() {
        let cases: [(u32, &str, u32, bool, bool); 21] = [
            (0x0000_0000, "0", 0, false, false),
            (0x0012_3456, "0", 0, false, false),
            (0x0100_3456, "0", 0, false, false),
            (0x0200_0056, "0", 0, false, false),
            (0x0300_0000, "0", 0, false, false),
            (0x0400_0000, "0", 0, false, false),
            (0x0092_3456, "0", 0, false, false),
            (0x0180_3456, "0", 0, false, false),
            (0x0280_0056, "0", 0, false, false),
            (0x0380_0000, "0", 0, false, false),
            (0x0480_0000, "0", 0, false, false),
            (0x0112_3456, "12", 0x0112_0000, false, false),
            (0x01fe_dcba, "7e", 0x017e_0000, true, false),
            (0x0212_3456, "1234", 0x0212_3400, false, false),
            (0x0312_3456, "123456", 0x0312_3456, false, false),
            (0x0412_3456, "12345600", 0x0412_3456, false, false),
            (0x0492_3456, "12345600", 0x0412_3456, true, false),
            (0x0500_9234, "92340000", 0x0500_9234, false, false),
            (
                0x2012_3456,
                "1234560000000000000000000000000000000000000000000000000000000000",
                0x2012_3456,
                false,
                false,
            ),
            (
                0x1d00_ffff,
                "ffff0000000000000000000000000000000000000000000000000000",
                0x1d00_ffff,
                false,
                false,
            ),
            (
                0x207f_ffff,
                "7fffff0000000000000000000000000000000000000000000000000000000000",
                0x207f_ffff,
                false,
                false,
            ),
        ];
        for (bits, hex, reencoded, negative, overflow) in cases {
            let split = split(compact(bits));
            assert_eq!(split.negative, negative, "{bits:#x}");
            assert_eq!(split.overflow, overflow, "{bits:#x}");
            let value = expand(split);
            assert_eq!(
                format!("{:x}", Target::from_be_bytes(value.to_be_bytes())),
                format!("{hex:0>64}")
            );
            assert_eq!(compress(value), reencoded, "{bits:#x}");
        }
        // 0xff123456 overflows without being negative.
        let overflow = split(compact(0xff12_3456));
        assert!(overflow.overflow);
        assert!(!overflow.negative);
        // Core: "make sure that we don't generate compacts with the 0x00800000 bit set".
        assert_eq!(compress(super::U256::from_u64(0x80)), 0x0200_8000);
    }

    /// Core's `pow_tests.cpp` cases for `CheckProofOfWork`, as evidence variants.
    #[test]
    fn derive_target_rejects_cores_four_cases() {
        let limit = mainnet_limit();
        // GetCompact(true) of powLimit.
        assert_eq!(
            decode_target(compact(0x1d80_ffff), limit),
            Err(TargetError::Negative)
        );
        // ~0x00800000
        assert_eq!(
            decode_target(compact(0xff7f_ffff), limit),
            Err(TargetError::Overflow)
        );
        assert_eq!(decode_target(compact(0), limit), Err(TargetError::Zero));
        assert_eq!(
            decode_target(compact(0x0100_0000), limit),
            Err(TargetError::Zero)
        );
        // powLimit * 2, re-encoded.
        assert_eq!(
            decode_target(compact(0x1d01_fffe), limit),
            Err(TargetError::AbovePowLimit)
        );
        assert_eq!(decode_target(compact(MAINNET_POW_LIMIT), limit), Ok(limit));
    }

    #[test]
    fn a_hash_meets_a_target_at_or_below_it() {
        let limit = mainnet_limit();
        let limit_hash = BlockHash::from_byte_array(limit.to_le_bytes());
        assert!(hash_meets_target(limit_hash, limit));
        // powLimit * 2 as a hash is above powLimit.
        let doubled = Target::from_compact(compact(0x1d01_fffe));
        assert!(!hash_meets_target(
            BlockHash::from_byte_array(doubled.to_le_bytes()),
            limit
        ));
        assert!(hash_meets_target(BlockHash::all_zeros(), limit));
        assert!(!hash_meets_target(
            BlockHash::from_byte_array([0xff; 32]),
            limit
        ));
        // Agrees with the pinned crate's own comparison.
        let mut prng = Prng::new(7);
        for _ in 0..1000 {
            let mut bytes = [0u8; 32];
            for byte in &mut bytes {
                *byte = u8::try_from(prng.below(256)).unwrap();
            }
            bytes[31] &= 0x03;
            let hash = BlockHash::from_byte_array(bytes);
            assert_eq!(hash_meets_target(hash, limit), limit.is_met_by(hash));
        }
    }

    /// Mainnet genesis: `0x1d00ffff` proves `0x100010001`, the chainwork every explorer
    /// shows for block 0.
    #[test]
    fn block_work_of_genesis() {
        let work = block_work(compact(MAINNET_POW_LIMIT));
        let mut expected = [0u8; 32];
        expected[27..].copy_from_slice(&0x0000_0001_0001_0001u64.to_be_bytes()[3..]);
        assert_eq!(work.to_be_bytes(), expected);
        // Regtest: 0x207fffff proves exactly 2 per block.
        let mut two = [0u8; 32];
        two[31] = 2;
        assert_eq!(block_work(compact(0x207f_ffff)).to_be_bytes(), two);
        // Invalid nBits count for nothing.
        assert_eq!(block_work(compact(0x1d80_ffff)).to_be_bytes(), [0; 32]);
        assert_eq!(block_work(compact(0xff12_3456)).to_be_bytes(), [0; 32]);
        assert_eq!(block_work(compact(0)).to_be_bytes(), [0; 32]);
    }

    /// Core's formula by hand on the smallest target: `(~1 / 2) + 1 = 2^255`. The pinned
    /// crate answers `2^256 - 1` here, so it is not the oracle for tiny targets.
    #[test]
    fn block_work_of_the_smallest_target_follows_cores_formula() {
        let mut expected = [0u8; 32];
        expected[0] = 0x80;
        // Size 1 shifts the mantissa right by two bytes, so target 1 is 0x01010000.
        assert_eq!(block_work(compact(0x0101_0000)).to_be_bytes(), expected);
        assert_eq!(block_work(compact(0x0101_ffef)).to_be_bytes(), expected);
        assert_eq!(block_work(compact(0x0200_0100)).to_be_bytes(), expected);
        // Target 2: ~2 = 3 * 0x5555...5554 + 1, so (~2 / 3) + 1 = 0x5555...5555.
        assert_eq!(block_work(compact(0x0102_0000)).to_be_bytes(), [0x55u8; 32]);
    }

    /// Over random `nBits`, the pinned crate's `Target::from_compact`, `to_compact_lossy`
    /// and `to_work` agree with the decoder, encoder and work wherever the crate defines
    /// them: it has no overflow flag and no `powLimit`, and its `to_work` departs from
    /// Core's formula on targets below 2^32, which no chain can name (see the next test).
    #[test]
    fn codec_and_work_agree_with_the_pinned_crate() {
        let mut prng = Prng::new(0xbeef);
        let mut decoded = 0;
        for _ in 0..50_000 {
            let bits = compact(prng.next_u32());
            let split = split(bits);
            if split.negative || split.overflow {
                continue;
            }
            let value = expand(split);
            let target = Target::from_be_bytes(value.to_be_bytes());
            assert_eq!(target, Target::from_compact(bits), "{bits:?}");
            assert_eq!(encode_target(target), target.to_compact_lossy(), "{bits:?}");
            if value.bits() >= 32 {
                assert_eq!(block_work(bits), target.to_work(), "{bits:?}");
                decoded += 1;
            }
            // Re-encoding a decoded target is the identity on canonical nBits, and decoding
            // a re-encoding never grows the target.
            let round = Target::from_compact(encode_target(target));
            assert!(round <= target);
        }
        // Roughly one size byte in seven survives the overflow rule.
        assert!(decoded > 2_000);
    }
}
