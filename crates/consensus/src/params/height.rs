// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Height`] and [`BlockTime`]: two `u32` newtypes the type checker keeps apart.
//!
//! Core stores a block height as `int` and a header timestamp as `uint32_t`, and nothing
//! stops one from being compared with the other. Here each is its own type with only the
//! operations the rules need. There is deliberately no `From<u32>`: every height and every
//! time enters through a constructor that says what the number is.

/// A block height. Genesis is 0.
///
/// Bounded by `i32::MAX` because Core stores heights as `int` and its argument parsing
/// rejects anything larger; a `u32` above that bound is a bug, not a tall chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Height(u32);

impl Height {
    /// The genesis block.
    pub const GENESIS: Height = Height(0);
    /// The largest representable height, `i32::MAX`.
    pub const MAX: Height = Height(0x7FFF_FFFF);

    /// Wraps a height, asserting it fits Core's `int`.
    #[must_use]
    pub const fn new(height: u32) -> Height {
        assert!(height <= Height::MAX.0);
        Height(height)
    }

    /// The height as a number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The height of the block after this one.
    #[must_use]
    pub fn next(self) -> Height {
        assert!(self < Height::MAX);
        let next = Height(self.0 + 1);
        assert!(next > self);
        next
    }

    /// Whether a block at this height starts a difficulty period: Core retargets when
    /// `(prev.height + 1) % interval == 0`, so the question is asked of the new block's
    /// height. Genesis is a boundary by this definition, which is harmless because nothing
    /// retargets before it.
    #[must_use]
    pub fn is_retarget_boundary(self, interval: u32) -> bool {
        assert!(interval > 0);
        self.0.is_multiple_of(interval)
    }
}

const _: () = assert!(Height::MAX.0 == i32::MAX.unsigned_abs());

/// A header timestamp, `nTime`: seconds since the Unix epoch as the 32-bit field carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockTime(u32);

impl BlockTime {
    /// Wraps a header timestamp.
    #[must_use]
    pub const fn new(seconds: u32) -> BlockTime {
        BlockTime(seconds)
    }

    /// The timestamp as a number of seconds.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Seconds from `earlier` to `self`, signed. Timestamps are not monotonic, so a block
    /// may legitimately carry an earlier time than its ancestor; Core computes the retarget
    /// timespan in `int64_t` for the same reason.
    #[must_use]
    pub fn timespan_since(self, earlier: BlockTime) -> i64 {
        let timespan = i64::from(self.0) - i64::from(earlier.0);
        assert!(u32::try_from(timespan.unsigned_abs()).is_ok());
        timespan
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockTime, Height};

    #[test]
    fn height_accepts_core_int_range() {
        assert_eq!(Height::new(0), Height::GENESIS);
        assert_eq!(Height::new(0x7FFF_FFFF), Height::MAX);
        assert_eq!(Height::new(227_931).get(), 227_931);
    }

    #[test]
    #[should_panic(expected = "height <= Height::MAX.0")]
    fn height_above_i32_max_is_a_bug() {
        let _unreachable = Height::new(0x8000_0000);
    }

    #[test]
    fn next_counts_by_one() {
        assert_eq!(Height::GENESIS.next(), Height::new(1));
        assert_eq!(Height::new(0x7FFF_FFFE).next(), Height::MAX);
    }

    #[test]
    #[should_panic(expected = "self < Height::MAX")]
    fn next_past_max_is_a_bug() {
        let _unreachable = Height::MAX.next();
    }

    /// The retarget test is asked of the new block's height, so 2016 is a boundary and 2015
    /// is not; the off-by-one Core preserves lives in the window, not here.
    #[test]
    fn retarget_boundary_is_a_multiple_of_the_interval() {
        assert!(Height::GENESIS.is_retarget_boundary(2016));
        assert!(!Height::new(2015).is_retarget_boundary(2016));
        assert!(Height::new(2016).is_retarget_boundary(2016));
        assert!(!Height::new(2017).is_retarget_boundary(2016));
        assert!(Height::new(144).is_retarget_boundary(144));
    }

    #[test]
    fn heights_and_times_order_as_numbers() {
        assert!(Height::new(1) < Height::new(2));
        assert!(BlockTime::new(1_231_006_505) < BlockTime::new(1_231_469_665));
    }

    #[test]
    fn timespan_is_signed() {
        let earlier = BlockTime::new(1_231_006_505);
        let later = BlockTime::new(1_231_469_665);
        assert_eq!(later.timespan_since(earlier), 463_160);
        assert_eq!(earlier.timespan_since(later), -463_160);
        assert_eq!(
            BlockTime::new(u32::MAX).timespan_since(BlockTime::new(0)),
            4_294_967_295
        );
    }
}
