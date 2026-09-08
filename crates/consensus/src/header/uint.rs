// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`U256`]: the 256-bit unsigned integer the target rules compute in.
//!
//! Core does this arithmetic in `arith_uint256`, and the rules that read it are consensus:
//! the compact encoding of a target, the retarget multiply and divide, and the work a block
//! proves. The pinned `bitcoin` crate keeps its own 256-bit type private and exposes only
//! derived operations, so bitmigo carries the arithmetic here, small and bounded: four limbs,
//! every loop over them fixed, and every overflow either asserted impossible or reported to
//! the caller. `bitcoin::pow::Target` and `Work` stay the interchange types; this one never
//! leaves the `header` module.

/// Four 64-bit limbs, most significant first, so the derived ordering is the numeric one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct U256([u64; 4]);

/// Limbs per value; every loop below runs this many times.
const LIMBS: usize = 4;
const LIMB_BITS: u32 = 64;

impl U256 {
    pub(super) const ZERO: U256 = U256([0; LIMBS]);
    pub(super) const ONE: U256 = U256([0, 0, 0, 1]);
    pub(super) const BITS: u32 = 256;

    pub(super) const fn from_u64(value: u64) -> U256 {
        U256([0, 0, 0, value])
    }

    /// From the big-endian bytes `Target::to_be_bytes` produces.
    pub(super) fn from_be_bytes(bytes: [u8; 32]) -> U256 {
        let mut limbs = [0u64; LIMBS];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *limb = u64::from_be_bytes(*chunk);
        }
        U256(limbs)
    }

    /// From little-endian bytes: the order a block hash's bytes carry when read as the
    /// integer Core compares against the target (`UintToArith256`).
    pub(super) fn from_le_bytes(mut bytes: [u8; 32]) -> U256 {
        bytes.reverse();
        Self::from_be_bytes(bytes)
    }

    pub(super) fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(self.0) {
            *chunk = limb.to_be_bytes();
        }
        bytes
    }

    pub(super) fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    /// Core's `bits()`: one more than the position of the highest set bit; zero for zero.
    pub(super) fn bits(self) -> u32 {
        for (index, limb) in self.0.iter().enumerate() {
            if *limb != 0 {
                let limbs_below = u32::try_from(LIMBS - 1 - index).expect("at most three");
                return limbs_below * LIMB_BITS + (LIMB_BITS - limb.leading_zeros());
            }
        }
        0
    }

    /// The low 64 bits; Core's `GetLow64`.
    pub(super) fn low_u64(self) -> u64 {
        self.0[LIMBS - 1]
    }

    /// `self << shift`, for a shift below the width; bits shifted past the top are lost, as
    /// in `arith_uint256`. Core also accepts larger shifts and yields zero; the callers here
    /// never ask, so a larger shift is a bug.
    pub(super) fn shl(self, shift: u32) -> U256 {
        assert!(shift < Self::BITS);
        let limb_shift = usize::try_from(shift / LIMB_BITS).expect("below four");
        let bit_shift = shift % LIMB_BITS;
        let source = |index: usize| self.0.get(index).copied().unwrap_or(0);
        let mut limbs = [0u64; LIMBS];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let high = source(index + limb_shift);
            let low = source(index + limb_shift + 1);
            *limb = if bit_shift == 0 {
                high
            } else {
                (high << bit_shift) | (low >> (LIMB_BITS - bit_shift))
            };
        }
        U256(limbs)
    }

    /// `self >> shift`, for a shift below the width.
    pub(super) fn shr(self, shift: u32) -> U256 {
        assert!(shift < Self::BITS);
        let limb_shift = usize::try_from(shift / LIMB_BITS).expect("below four");
        let bit_shift = shift % LIMB_BITS;
        let source = |index: Option<usize>| index.and_then(|i| self.0.get(i)).copied().unwrap_or(0);
        let mut limbs = [0u64; LIMBS];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let low = source(index.checked_sub(limb_shift));
            let high = source(index.checked_sub(limb_shift + 1));
            *limb = if bit_shift == 0 {
                low
            } else {
                (low >> bit_shift) | (high << (LIMB_BITS - bit_shift))
            };
        }
        U256(limbs)
    }

    pub(super) fn not(self) -> U256 {
        U256(self.0.map(|limb| !limb))
    }

    /// `self + other`, or `None` past the width.
    pub(super) fn checked_add(self, other: U256) -> Option<U256> {
        let mut limbs = [0u64; LIMBS];
        let mut carry = false;
        // Least significant limb first.
        for ((limb, a), b) in limbs.iter_mut().zip(self.0).zip(other.0).rev() {
            let (sum, overflow_a) = a.overflowing_add(b);
            let (sum, overflow_b) = sum.overflowing_add(u64::from(carry));
            *limb = sum;
            carry = overflow_a || overflow_b;
        }
        if carry { None } else { Some(U256(limbs)) }
    }

    /// `self - other`; the caller guarantees `self >= other`.
    pub(super) fn sub(self, other: U256) -> U256 {
        assert!(self >= other);
        let mut limbs = [0u64; LIMBS];
        let mut borrow = false;
        for ((limb, a), b) in limbs.iter_mut().zip(self.0).zip(other.0).rev() {
            let (difference, underflow_a) = a.overflowing_sub(b);
            let (difference, underflow_b) = difference.overflowing_sub(u64::from(borrow));
            *limb = difference;
            borrow = underflow_a || underflow_b;
        }
        assert!(!borrow);
        U256(limbs)
    }

    /// `self * factor`, or `None` past the width. Core's `operator*=(uint32_t)` wraps
    /// instead; the one consensus caller, the retarget, cannot reach a wrap on any tabled
    /// chain, and asserts so.
    pub(super) fn checked_mul_u64(self, factor: u64) -> Option<U256> {
        let mut limbs = [0u64; LIMBS];
        let mut carry: u128 = 0;
        for (limb, a) in limbs.iter_mut().zip(self.0).rev() {
            let product = u128::from(a) * u128::from(factor) + carry;
            *limb = u64::try_from(product & u128::from(u64::MAX)).expect("masked");
            carry = product >> LIMB_BITS;
        }
        if carry != 0 { None } else { Some(U256(limbs)) }
    }

    /// `self / divisor`, truncating.
    pub(super) fn div_u64(self, divisor: u64) -> U256 {
        assert!(divisor > 0);
        let mut limbs = [0u64; LIMBS];
        let mut remainder: u128 = 0;
        // Most significant limb first.
        for (limb, a) in limbs.iter_mut().zip(self.0) {
            let current = (remainder << LIMB_BITS) | u128::from(a);
            *limb = u64::try_from(current / u128::from(divisor)).expect("quotient fits");
            remainder = current % u128::from(divisor);
        }
        U256(limbs)
    }

    /// `self / divisor`, truncating: Core's `operator/=`, shift-and-subtract over at most
    /// 256 positions.
    pub(super) fn div(self, divisor: U256) -> U256 {
        assert!(!divisor.is_zero());
        let dividend_bits = self.bits();
        let divisor_bits = divisor.bits();
        if divisor_bits > dividend_bits {
            return Self::ZERO;
        }
        let mut remainder = self;
        let mut quotient = Self::ZERO;
        // From the highest position the divisor fits under, down to zero: bounded by BITS.
        for shift in (0..=(dividend_bits - divisor_bits)).rev() {
            let shifted = divisor.shl(shift);
            if remainder >= shifted {
                remainder = remainder.sub(shifted);
                quotient = quotient.set_bit(shift);
            }
        }
        assert!(remainder < divisor);
        quotient
    }

    fn set_bit(self, bit: u32) -> U256 {
        assert!(bit < Self::BITS);
        let index = LIMBS - 1 - usize::try_from(bit / LIMB_BITS).expect("below four");
        let mut limbs = self.0;
        let limb = limbs.get_mut(index).expect("below four");
        *limb |= 1u64 << (bit % LIMB_BITS);
        U256(limbs)
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test fixtures index arrays and vectors whose lengths the tests assert"
)]
mod tests {
    use super::U256;
    use crate::script::vectors::Prng;

    fn from_u128(value: u128) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        U256::from_be_bytes(bytes)
    }

    fn to_u128(value: U256) -> u128 {
        let bytes = value.to_be_bytes();
        assert!(bytes[..16].iter().all(|byte| *byte == 0));
        let mut low = [0u8; 16];
        low.copy_from_slice(&bytes[16..]);
        u128::from_be_bytes(low)
    }

    #[test]
    fn byte_orders_round_trip() {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let value = U256::from_be_bytes(bytes);
        assert_eq!(value.to_be_bytes(), bytes);
        let mut reversed = bytes;
        reversed.reverse();
        assert_eq!(U256::from_le_bytes(reversed), value);
        assert_eq!(value.low_u64(), 0x1819_1a1b_1c1d_1e1f);
    }

    #[test]
    fn bits_counts_from_the_highest_set_bit() {
        assert_eq!(U256::ZERO.bits(), 0);
        assert_eq!(U256::ONE.bits(), 1);
        assert_eq!(U256::from_u64(0xffff).bits(), 16);
        assert_eq!(U256::from_u64(u64::MAX).bits(), 64);
        assert_eq!(U256::ONE.shl(64).bits(), 65);
        assert_eq!(U256::ONE.shl(255).bits(), 256);
        assert_eq!(U256::ZERO.not().bits(), 256);
    }

    /// Every operation agrees with `u128` wherever the operands fit in it; the generator
    /// covers the limb boundaries by mixing widths.
    #[test]
    fn arithmetic_agrees_with_u128() {
        let mut prng = Prng::new(0x5eed_0bad_cafe_f00d);
        for _ in 0..20_000 {
            let width_a = prng.below(129);
            let width_b = prng.below(129);
            let a = random_u128(&mut prng, width_a);
            let b = random_u128(&mut prng, width_b);
            let (big_a, big_b) = (from_u128(a), from_u128(b));

            assert_eq!(big_a.cmp(&big_b), a.cmp(&b));
            if let Some(sum) = a.checked_add(b) {
                assert_eq!(big_a.checked_add(big_b).map(to_u128), Some(sum));
            }
            if a >= b {
                assert_eq!(to_u128(big_a.sub(big_b)), a - b);
            }
            let factor = u64::try_from(b & u128::from(u64::MAX)).unwrap();
            if let Some(product) = a.checked_mul(u128::from(factor)) {
                assert_eq!(big_a.checked_mul_u64(factor).map(to_u128), Some(product));
            }
            if factor != 0 {
                assert_eq!(to_u128(big_a.div_u64(factor)), a / u128::from(factor));
            }
            if let Some(quotient) = a.checked_div(b) {
                assert_eq!(to_u128(big_a.div(big_b)), quotient);
            }
            let shift = u32::try_from(prng.below(128)).unwrap();
            assert_eq!(to_u128(big_a.shr(shift)), a >> shift);
            if a.leading_zeros() >= shift {
                assert_eq!(to_u128(big_a.shl(shift)), a << shift);
            }
        }
    }

    fn random_u128(prng: &mut Prng, width: u64) -> u128 {
        let full = (u128::from(prng.next_u64()) << 64) | u128::from(prng.next_u64());
        if width == 0 {
            0
        } else {
            full >> (128 - u32::try_from(width).unwrap())
        }
    }

    #[test]
    fn shifts_cross_every_limb() {
        let one_high = U256::ONE.shl(255);
        assert_eq!(one_high.to_be_bytes()[0], 0x80);
        assert_eq!(one_high.shr(255), U256::ONE);
        assert_eq!(U256::ONE.shl(64).shl(64).shl(64).shr(192), U256::ONE);
        assert_eq!(U256::ONE.shl(200).shr(100).shr(100), U256::ONE);
        // Bits shifted past the top are lost, as in arith_uint256.
        assert_eq!(U256::ONE.shl(255).shl(1), U256::ZERO);
        assert_eq!(U256::ZERO.not().shl(1).to_be_bytes()[31], 0xfe);
    }

    #[test]
    fn add_reports_overflow_and_sub_borrows_across_limbs() {
        let max = U256::ZERO.not();
        assert_eq!(max.checked_add(U256::ONE), None);
        assert_eq!(max.checked_add(U256::ZERO), Some(max));
        let two_pow_64 = U256::ONE.shl(64);
        assert_eq!(two_pow_64.sub(U256::ONE), U256::from_u64(u64::MAX));
        assert_eq!(
            U256::from_u64(u64::MAX).checked_add(U256::ONE),
            Some(two_pow_64)
        );
    }

    #[test]
    fn wide_division_matches_the_work_formula_on_known_values() {
        // (~t / (t + 1)) + 1 for t = 0xffff << 208 is 0x1_0001_0001: mainnet genesis work.
        let target = U256::from_u64(0xffff).shl(208);
        let work = target
            .not()
            .div(target.checked_add(U256::ONE).unwrap())
            .checked_add(U256::ONE)
            .unwrap();
        assert_eq!(work, U256::from_u64(0x1_0001_0001));
        // A divisor above the dividend gives zero; equal operands give one.
        assert_eq!(U256::ONE.div(target), U256::ZERO);
        assert_eq!(target.div(target), U256::ONE);
        assert_eq!(U256::ZERO.not().div(U256::ONE), U256::ZERO.not());
    }

    #[test]
    #[should_panic(expected = "!divisor.is_zero()")]
    fn division_by_zero_is_a_bug() {
        let _unreachable = U256::ONE.div(U256::ZERO);
    }

    #[test]
    #[should_panic(expected = "shift < Self::BITS")]
    fn a_full_width_shift_is_a_bug() {
        let _unreachable = U256::ONE.shl(256);
    }
}
