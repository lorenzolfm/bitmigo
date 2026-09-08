// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`ScriptNum`]: Core's `CScriptNum`, and `CastToBool`.
//!
//! Script numbers are little-endian sign-magnitude byte strings: the top bit of the last
//! byte is the sign, so `0x80` alone is negative zero. Operands are limited to four bytes
//! (five for the lock-time opcodes), results are not: `OP_ADD` of two four-byte numbers may
//! produce a five-byte one that is fine to push and fails only if used as an operand again.
//! Core throws `scriptnum_error` for an oversized operand and the interpreter turns it into
//! `SCRIPTNUM`; here [`ScriptNum::decode`] returns that error. Minimal encoding is
//! `MINIMALDATA`, a policy rule, so nothing here checks it: a consensus decoder accepts
//! `0x0100` as one, and so does this one.

use super::ScriptError;

/// `CScriptNum::nDefaultMaxNumSize`: the operand limit for every numeric opcode.
pub const SCRIPTNUM_SIZE_MAX: usize = 4;
/// The operand limit for `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` (BIP65).
pub const SCRIPTNUM_LOCKTIME_SIZE_MAX: usize = 5;

/// A script number, held as the `i64` Core holds it in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScriptNum(i64);

impl ScriptNum {
    pub const ZERO: ScriptNum = ScriptNum(0);
    pub const ONE: ScriptNum = ScriptNum(1);

    /// `CScriptNum(vch, false, size_max)`: rejects more than `size_max` bytes, decodes the
    /// rest. `size_max` is one of the two limits above.
    pub fn decode(bytes: &[u8], size_max: usize) -> Result<ScriptNum, ScriptError> {
        assert!(size_max <= SCRIPTNUM_LOCKTIME_SIZE_MAX);
        if bytes.len() > size_max {
            return Err(ScriptError::Scriptnum);
        }
        let Some((&last, _)) = bytes.split_last() else {
            return Ok(ScriptNum::ZERO);
        };
        let mut magnitude: i64 = 0;
        // Bounded by size_max, five bytes at most, so the shifts stay under 40 bits.
        for (index, &byte) in bytes.iter().enumerate() {
            magnitude |= i64::from(byte) << (8 * index);
        }
        let value = if last & 0x80 != 0 {
            let sign_bit = 0x80_i64 << (8 * (bytes.len() - 1));
            -(magnitude & !sign_bit)
        } else {
            magnitude
        };
        assert!(value.unsigned_abs() < 1 << 39);
        Ok(ScriptNum(value))
    }

    /// A number the interpreter computed rather than decoded: an `OP_1..OP_16` constant, or
    /// a lock time. Anything a script can produce is well under 2^40.
    #[must_use]
    pub fn from_i64(value: i64) -> ScriptNum {
        assert!(value.unsigned_abs() < 1 << 40);
        ScriptNum(value)
    }

    /// A number from a count the interpreter computed: a stack depth or an element size.
    #[must_use]
    pub fn from_usize(value: usize) -> ScriptNum {
        ScriptNum(i64::try_from(value).expect("a count fits i64"))
    }

    /// A number from a boolean, as Core's `CScriptNum(bool)` conversions do.
    #[must_use]
    pub const fn from_bool(value: bool) -> ScriptNum {
        if value {
            ScriptNum::ONE
        } else {
            ScriptNum::ZERO
        }
    }

    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }

    /// `CScriptNum::getint`: the value clamped to `i32`.
    #[must_use]
    pub fn to_clamped_i32(self) -> i32 {
        i32::try_from(self.0).unwrap_or(if self.0 < 0 { i32::MIN } else { i32::MAX })
    }

    /// `CScriptNum::serialize`: the minimal sign-magnitude encoding, empty for zero.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        if self.0 == 0 {
            return Vec::new();
        }
        let negative = self.0 < 0;
        let mut magnitude = self.0.unsigned_abs();
        let mut bytes = Vec::with_capacity(9);
        // Bounded: a u64 has eight bytes.
        while magnitude > 0 {
            bytes.push(u8::try_from(magnitude & 0xff).expect("one byte"));
            magnitude >>= 8;
        }
        let last = *bytes
            .last()
            .expect("a non-zero value has at least one byte");
        if last & 0x80 != 0 {
            // The top bit is taken by the magnitude: spend a byte on the sign.
            bytes.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            *bytes.last_mut().expect("non-empty") |= 0x80;
        }
        assert!(bytes.len() <= 9);
        bytes
    }

    /// Operands are at most 40 bits, so no arithmetic here can overflow; the checks turn a
    /// broken invariant into a panic all the same.
    #[must_use]
    pub fn add(self, other: ScriptNum) -> ScriptNum {
        ScriptNum(self.0.checked_add(other.0).expect("operands are bounded"))
    }

    #[must_use]
    pub fn sub(self, other: ScriptNum) -> ScriptNum {
        ScriptNum(self.0.checked_sub(other.0).expect("operands are bounded"))
    }

    #[must_use]
    pub fn neg(self) -> ScriptNum {
        ScriptNum(self.0.checked_neg().expect("operands are bounded"))
    }

    #[must_use]
    pub fn abs(self) -> ScriptNum {
        if self.0 < 0 { self.neg() } else { self }
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Core's `CastToBool`: any non-zero byte makes the value true, except that a lone `0x80`
/// in the last position is negative zero and does not.
#[must_use]
pub fn cast_to_bool(bytes: &[u8]) -> bool {
    // Bounded by the element size.
    for (index, &byte) in bytes.iter().enumerate() {
        if byte != 0 {
            let is_last = index == bytes.len() - 1;
            if is_last && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::ScriptError;
    use super::{SCRIPTNUM_LOCKTIME_SIZE_MAX, SCRIPTNUM_SIZE_MAX, ScriptNum, cast_to_bool};

    #[test]
    fn encode_is_minimal_sign_magnitude() {
        let cases: [(i64, &[u8]); 12] = [
            (0, &[]),
            (1, &[0x01]),
            (-1, &[0x81]),
            (127, &[0x7f]),
            (128, &[0x80, 0x00]),
            (-128, &[0x80, 0x80]),
            (255, &[0xff, 0x00]),
            (-255, &[0xff, 0x80]),
            (256, &[0x00, 0x01]),
            (0x7fff_ffff, &[0xff, 0xff, 0xff, 0x7f]),
            (-0x7fff_ffff, &[0xff, 0xff, 0xff, 0xff]),
            (0x8000_0000, &[0x00, 0x00, 0x00, 0x80, 0x00]),
        ];
        for (value, bytes) in cases {
            assert_eq!(ScriptNum(value).encode(), bytes, "{value}");
            let decoded = ScriptNum::decode(bytes, SCRIPTNUM_LOCKTIME_SIZE_MAX).expect("fits");
            assert_eq!(decoded.value(), value, "{value}");
        }
    }

    #[test]
    fn decode_accepts_non_minimal_and_negative_zero() {
        assert_eq!(ScriptNum::decode(&[0x00], 4), Ok(ScriptNum::ZERO));
        assert_eq!(ScriptNum::decode(&[0x80], 4), Ok(ScriptNum::ZERO));
        assert_eq!(ScriptNum::decode(&[0x01, 0x00], 4), Ok(ScriptNum::ONE));
        assert_eq!(ScriptNum::decode(&[0x01, 0x80], 4), Ok(ScriptNum(-1)));
        assert_eq!(
            ScriptNum::decode(&[0x00, 0x00, 0x00, 0x80], 4),
            Ok(ScriptNum::ZERO)
        );
    }

    #[test]
    fn decode_enforces_the_operand_limit() {
        assert_eq!(
            ScriptNum::decode(&[0; 5], SCRIPTNUM_SIZE_MAX),
            Err(ScriptError::Scriptnum)
        );
        assert_eq!(
            ScriptNum::decode(&[1; 5], SCRIPTNUM_LOCKTIME_SIZE_MAX),
            Ok(ScriptNum(0x01_0101_0101))
        );
        assert_eq!(
            ScriptNum::decode(&[0; 6], SCRIPTNUM_LOCKTIME_SIZE_MAX),
            Err(ScriptError::Scriptnum)
        );
    }

    #[test]
    fn clamped_int_matches_getint() {
        assert_eq!(ScriptNum(5).to_clamped_i32(), 5);
        assert_eq!(ScriptNum(-5).to_clamped_i32(), -5);
        assert_eq!(ScriptNum(1 << 33).to_clamped_i32(), i32::MAX);
        assert_eq!(ScriptNum(-(1 << 33)).to_clamped_i32(), i32::MIN);
    }

    #[test]
    fn arithmetic_and_predicates() {
        assert_eq!(ScriptNum(3).add(ScriptNum(4)), ScriptNum(7));
        assert_eq!(ScriptNum(3).sub(ScriptNum(4)), ScriptNum(-1));
        assert_eq!(ScriptNum(-3).abs(), ScriptNum(3));
        assert_eq!(ScriptNum(3).neg(), ScriptNum(-3));
        assert!(ScriptNum::ZERO.is_zero());
        assert_eq!(ScriptNum::from_bool(true), ScriptNum::ONE);
        assert_eq!(ScriptNum::from_usize(1000).value(), 1000);
    }

    #[test]
    fn cast_to_bool_knows_negative_zero() {
        assert!(!cast_to_bool(&[]));
        assert!(!cast_to_bool(&[0x00]));
        assert!(!cast_to_bool(&[0x00, 0x00]));
        assert!(!cast_to_bool(&[0x80]));
        assert!(!cast_to_bool(&[0x00, 0x80]));
        assert!(cast_to_bool(&[0x01]));
        assert!(cast_to_bool(&[0x80, 0x00]));
        assert!(cast_to_bool(&[0x00, 0x01]));
        assert!(cast_to_bool(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        ]));
    }
}
