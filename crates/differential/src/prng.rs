// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Prng`]: a deterministic generator with a one-word state, so that every case the fuzzer
//! builds is reproducible from a `u64` and nothing else.
//!
//! `SplitMix64`: any seed is valid (xorshift would need a non-zero state), the output is well
//! mixed even for adjacent seeds, and the whole thing is six lines. Statistical quality
//! beyond that is not the point; a case is a function of its seed, and that is.

/// A `SplitMix64` generator.
#[derive(Clone, Debug)]
pub struct Prng {
    state: u64,
}

impl Prng {
    /// A generator that will replay the same sequence for the same `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Prng {
        Prng { state: seed }
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The next 32 bits: the top half of a word, which `SplitMix64` mixes best.
    pub fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() >> 32).expect("the top 32 bits fit")
    }

    /// One byte.
    pub fn next_u8(&mut self) -> u8 {
        u8::try_from(self.next_u64() >> 56).expect("the top 8 bits fit")
    }

    /// A value in `0..bound`. The modulo bias is immaterial for bounds far below 2^64.
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0);
        let value = self.next_u64() % bound;
        assert!(value < bound);
        value
    }

    /// A value in `0..bound`, for indexing.
    pub fn below_usize(&mut self, bound: usize) -> usize {
        usize::try_from(self.below(u64::try_from(bound).expect("fits"))).expect("fits")
    }

    /// True with probability `numerator / denominator`.
    pub fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
        assert!(numerator <= denominator);
        self.below(denominator) < numerator
    }

    /// One of `items`, uniformly.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        assert!(!items.is_empty());
        items.get(self.below_usize(items.len())).expect("in range")
    }

    /// `len` random bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let bytes: Vec<u8> = (0..len).map(|_| self.next_u8()).collect();
        assert_eq!(bytes.len(), len);
        bytes
    }

    /// 32 random bytes.
    pub fn bytes_32(&mut self) -> [u8; 32] {
        self.bytes(32).try_into().expect("32 bytes")
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index out of bounds fails the test with a panic, as intended"
    )]

    use super::Prng;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = Prng::new(7);
        let mut b = Prng::new(7);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        assert_ne!(Prng::new(7).next_u64(), Prng::new(8).next_u64());
    }

    #[test]
    fn below_stays_below() {
        let mut prng = Prng::new(0);
        for _ in 0..1000 {
            assert!(prng.below(3) < 3);
            assert!(prng.below_usize(17) < 17);
        }
        assert!(prng.chance(1, 1));
        assert!(!prng.chance(0, 1));
    }

    #[test]
    fn pick_covers_every_item() {
        let mut prng = Prng::new(1);
        let mut seen = [false; 5];
        for _ in 0..200 {
            seen[*prng.pick(&[0usize, 1, 2, 3, 4])] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }
}
