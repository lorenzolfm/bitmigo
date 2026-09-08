// SPDX-License-Identifier: MIT OR Apache-2.0

//! The next block's required `nBits` and the median time past, from the headers the node
//! hands over: Core's `GetNextWorkRequired`, `CalculateNextWorkRequired` and
//! `CBlockIndex::GetMedianTimePast` (§1.2, §1.3) without a block index to walk.
//!
//! Core walks `pprev` pointers to find the first block of the period and, on chains with the
//! minimum-difficulty rule, the last block that was not mined at `powLimit`. This crate takes
//! exact inputs (BM-D1 decision 1), so the node passes the headers of the current difficulty
//! period up to and including the previous block, as [`HeaderFacts`], and the function
//! asserts that slice is the one Core would have walked: it starts at a period boundary, its
//! heights are consecutive, and its length is what the previous height implies.

use bitcoin::block::Header;
use bitcoin::pow::{CompactTarget, Target};

use super::target::{decode_target, encode_target};
use super::uint::U256;
use crate::params::{BlockTime, ChainParams, Height};

/// Core's `nMedianTimeSpan`: the median time past is the median of this many timestamps.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// The three fields of a stored header the retarget rules read: Core's `CBlockIndex`
/// `nHeight`, `nBits` and `nTime`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderFacts {
    /// The header's height on its chain.
    pub height: Height,
    /// The header's `nBits`.
    pub bits: CompactTarget,
    /// The header's `nTime`.
    pub time: BlockTime,
}

impl HeaderFacts {
    /// The facts of `header`, which the node knows sits at `height`.
    #[must_use]
    pub fn from_header(height: Height, header: &Header) -> HeaderFacts {
        HeaderFacts {
            height,
            bits: header.bits,
            time: BlockTime::new(header.time),
        }
    }
}

/// Core's `GetMedianTimePast` over the timestamps of a block and its ancestors, newest or
/// oldest first, up to [`MEDIAN_TIME_SPAN`] of them and fewer only near genesis: sort and
/// take the middle, rounding down.
#[must_use]
pub fn median_time_past(times: &[BlockTime]) -> BlockTime {
    assert!(!times.is_empty());
    assert!(times.len() <= MEDIAN_TIME_SPAN);
    let mut sorted = [BlockTime::new(0); MEDIAN_TIME_SPAN];
    let (window, _) = sorted.split_at_mut(times.len());
    window.copy_from_slice(times);
    window.sort_unstable();
    *window
        .get(times.len() / 2)
        .expect("the middle of a non-empty window")
}

/// Core's `GetNextWorkRequired`: the `nBits` the block after `period`'s last header must
/// carry. `period` holds the headers of the difficulty period the previous block belongs
/// to, from its first block to the previous block inclusive; `new_block_time` is the
/// candidate block's own `nTime`, which only the minimum-difficulty rule reads.
#[must_use]
pub fn next_required_bits(
    params: &ChainParams,
    period: &[HeaderFacts],
    new_block_time: BlockTime,
) -> CompactTarget {
    let interval = params.difficulty_adjustment_interval();
    let previous = check_period(period, interval);
    let pow_limit_bits = encode_target(params.pow_limit());

    // Only change once per difficulty adjustment interval.
    if !previous.height.next().is_retarget_boundary(interval) {
        if params.allow_min_difficulty() {
            return min_difficulty_bits(params, period, new_block_time, pow_limit_bits);
        }
        return previous.bits;
    }

    // At a boundary the period is complete, and its first block is the one Core's
    // `nHeightFirst = last - (interval - 1)` names: the window spans interval - 1 gaps.
    assert_eq!(period.len(), usize::try_from(interval).expect("fits"));
    let first = *period.first().expect("non-empty");
    calculate_next_bits(&Retarget::of(params), previous, first)
}

/// Asserts `period` is the slice Core would have walked and returns its last header.
fn check_period(period: &[HeaderFacts], interval: u32) -> HeaderFacts {
    assert!(!period.is_empty());
    assert!(period.len() <= usize::try_from(interval).expect("fits"));
    let first = period.first().expect("non-empty");
    assert!(first.height.is_retarget_boundary(interval));
    let previous = *period.last().expect("non-empty");
    let expected_len = previous.height.get() % interval + 1;
    assert_eq!(
        period.len(),
        usize::try_from(expected_len).expect("fits"),
        "the period runs from its boundary to the previous header"
    );
    // Bounded by the interval.
    for pair in period.windows(2) {
        if let [earlier, later] = pair {
            assert_eq!(
                earlier.height.next(),
                later.height,
                "the period's heights are consecutive"
            );
        }
    }
    previous
}

/// Core's "special difficulty rule for testnet", regtest included: a block more than two
/// spacings after its predecessor must be mined at `powLimit`; otherwise the target is that
/// of the last block in the period not itself mined at `powLimit`, the period's first block
/// counting whatever its `nBits`.
fn min_difficulty_bits(
    params: &ChainParams,
    period: &[HeaderFacts],
    new_block_time: BlockTime,
    pow_limit_bits: CompactTarget,
) -> CompactTarget {
    let previous = period.last().expect("checked");
    if new_block_time.timespan_since(previous.time) > 2 * params.pow_target_spacing() {
        return pow_limit_bits;
    }
    let interval = params.difficulty_adjustment_interval();
    // Bounded by the interval; the first entry is a boundary, so the loop always returns.
    for facts in period.iter().rev() {
        let is_boundary = facts.height.is_retarget_boundary(interval);
        if is_boundary || facts.bits != pow_limit_bits {
            return facts.bits;
        }
    }
    panic!("a checked period starts at a boundary");
}

/// The chain parameters `CalculateNextWorkRequired` reads, so the arithmetic can be tested
/// on combinations no tabled chain has, such as BIP94 with retargeting on.
#[derive(Clone, Copy, Debug)]
struct Retarget {
    pow_limit: Target,
    target_timespan: i64,
    no_retargeting: bool,
    enforce_bip94: bool,
}

impl Retarget {
    fn of(params: &ChainParams) -> Retarget {
        let retarget = Retarget {
            pow_limit: params.pow_limit(),
            target_timespan: params.pow_target_timespan(),
            no_retargeting: params.no_retargeting(),
            enforce_bip94: params.enforce_bip94(),
        };
        retarget.assert_multiply_fits();
        retarget
    }

    /// Core multiplies in a wrapping `arith_uint256`. The largest product is
    /// `powLimit * 4 * timespan`; mainnet's and signet's fit (signet's by a margin of
    /// 4.6e12 in 2^256), and regtest never multiplies. A chain where it wrapped would
    /// need the wrap mirrored here, so the constructor refuses one instead.
    fn assert_multiply_fits(&self) {
        assert!(self.target_timespan > 0);
        if self.no_retargeting {
            return;
        }
        let largest = u64::try_from(4 * self.target_timespan).expect("positive");
        let limit = U256::from_be_bytes(self.pow_limit.to_be_bytes());
        assert!(limit.checked_mul_u64(largest).is_some());
    }
}

/// Core's `CalculateNextWorkRequired`: the target of the period's last block (its first
/// under BIP94) scaled by the clamped actual timespan over the target timespan, capped at
/// `powLimit`, in 256-bit integer arithmetic on the decoded targets (§1.2).
fn calculate_next_bits(
    rules: &Retarget,
    previous: HeaderFacts,
    first: HeaderFacts,
) -> CompactTarget {
    if rules.no_retargeting {
        return previous.bits;
    }
    assert!(previous.height > first.height);
    let target_timespan = rules.target_timespan;
    let actual_timespan = previous
        .time
        .timespan_since(first.time)
        .clamp(target_timespan / 4, target_timespan * 4);
    assert!(actual_timespan > 0);

    // Under BIP94 the first block's difficulty is the base, so one late timestamp cannot
    // destroy the period's real difficulty. A header on the accepted chain carries `nBits`
    // that `check_header` already derived, so decoding cannot fail.
    let base = if rules.enforce_bip94 {
        first.bits
    } else {
        previous.bits
    };
    let base = decode_target(base, rules.pow_limit).expect("an accepted header's nBits");

    let scaled = U256::from_be_bytes(base.to_be_bytes())
        .checked_mul_u64(u64::try_from(actual_timespan).expect("positive"))
        .expect("asserted to fit by Retarget::of")
        .div_u64(u64::try_from(target_timespan).expect("positive"));
    let limit = U256::from_be_bytes(rules.pow_limit.to_be_bytes());
    let capped = if scaled > limit { limit } else { scaled };
    let next = encode_target(Target::from_be_bytes(capped.to_be_bytes()));
    assert!(decode_target(next, rules.pow_limit).is_ok());
    next
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test fixtures index arrays and vectors whose lengths the tests assert"
)]
mod tests {
    use bitcoin::pow::{CompactTarget, Target};

    use super::{
        HeaderFacts, MEDIAN_TIME_SPAN, Retarget, calculate_next_bits, median_time_past,
        next_required_bits,
    };
    use crate::params::{BlockTime, ChainParams, Height, RegtestOverrides};

    fn compact(bits: u32) -> CompactTarget {
        CompactTarget::from_consensus(bits)
    }

    fn facts(height: u32, bits: u32, time: u32) -> HeaderFacts {
        HeaderFacts {
            height: Height::new(height),
            bits: compact(bits),
            time: BlockTime::new(time),
        }
    }

    fn times(seconds: &[u32]) -> Vec<BlockTime> {
        seconds.iter().map(|s| BlockTime::new(*s)).collect()
    }

    /// Core's `pow_tests.cpp`: `get_next_work`, `_pow_limit`, `_lower_limit_actual` and
    /// `_upper_limit_actual`, each a `(previous, first block time, expected)` triple.
    #[test]
    fn calculate_next_work_required_fixtures_from_core() {
        let rules = Retarget::of(&ChainParams::mainnet());
        let cases = [
            // Blocks 30240 -> 32255: the first mainnet retarget.
            (
                facts(32_255, 0x1d00_ffff, 1_262_152_739),
                1_261_130_161,
                0x1d00_d86a,
            ),
            // Blocks 0 -> 2015: capped at powLimit.
            (
                facts(2_015, 0x1d00_ffff, 1_233_061_996),
                1_231_006_505,
                0x1d00_ffff,
            ),
            // Blocks 66528 -> 68543: the actual timespan clamped from below.
            (
                facts(68_543, 0x1c05_a3f4, 1_279_297_671),
                1_279_008_237,
                0x1c01_68fd,
            ),
            // Block 46367 with a made-up first time: clamped from above.
            (
                facts(46_367, 0x1c38_7f6f, 1_269_211_443),
                1_263_163_443,
                0x1d00_e1fd,
            ),
        ];
        for (previous, first_time, expected) in cases {
            let first = facts(previous.height.get() - 2015, 0x1d00_ffff, first_time);
            assert_eq!(
                calculate_next_bits(&rules, previous, first),
                compact(expected),
                "{previous:?}"
            );
        }
    }

    /// The same first retarget through the public function, with a full 2016-header
    /// period whose interior is irrelevant to a chain without the minimum-difficulty rule.
    #[test]
    fn first_mainnet_retarget_through_next_required_bits() {
        let params = ChainParams::mainnet();
        let mut period = Vec::with_capacity(2016);
        for height in 30_240..=32_255 {
            let time = if height == 30_240 {
                1_261_130_161
            } else if height == 32_255 {
                1_262_152_739
            } else {
                1_261_130_161 + (height - 30_240) * 500
            };
            period.push(facts(height, 0x1d00_ffff, time));
        }
        assert_eq!(
            next_required_bits(&params, &period, BlockTime::new(1_262_153_464)),
            compact(0x1d00_d86a)
        );
        // Off a boundary mainnet repeats the previous nBits whatever the timestamps.
        let partial = &period[..2015];
        assert_eq!(
            next_required_bits(&params, partial, BlockTime::new(1_300_000_000)),
            compact(0x1d00_ffff)
        );
    }

    /// Under BIP94 the base is the first block's target; without it, the last block's.
    /// Same clamped timespan, so the two answers differ only by the base.
    #[test]
    fn bip94_retargets_from_the_first_block_of_the_period() {
        let mainnet = ChainParams::mainnet();
        let plain = Retarget::of(&mainnet);
        let bip94 = Retarget {
            enforce_bip94: true,
            ..plain
        };
        // Blocks 66528 -> 68543 as above, but the period opened at a different difficulty.
        let first = facts(66_528, 0x1c0a_0000, 1_279_008_237);
        let previous = facts(68_543, 0x1c05_a3f4, 1_279_297_671);
        assert_eq!(
            calculate_next_bits(&plain, previous, first),
            compact(0x1c01_68fd)
        );
        // 0x0a0000 << 200 * 302400 / 1209600 = 0x0a0000 / 4 << 200 = 0x028000 << 200,
        // which GetCompact writes as 0x1c028000.
        assert_eq!(
            calculate_next_bits(&bip94, previous, first),
            compact(0x1c02_8000)
        );
    }

    #[test]
    fn no_retargeting_repeats_the_previous_bits() {
        let params = ChainParams::regtest(RegtestOverrides::default());
        let rules = Retarget::of(&params);
        let first = facts(0, 0x207f_ffff, 1_296_688_602);
        let previous = facts(143, 0x207f_ffff, 1_296_688_602 + 143 * 5_000);
        assert_eq!(
            calculate_next_bits(&rules, previous, first),
            compact(0x207f_ffff)
        );
        // Through the public function with a full regtest period.
        let period: Vec<HeaderFacts> = (0..144)
            .map(|height| facts(height, 0x207f_ffff, 1_296_688_602 + height * 5_000))
            .collect();
        assert_eq!(
            next_required_bits(&params, &period, BlockTime::new(1_300_000_000)),
            compact(0x207f_ffff)
        );
    }

    /// Regtest carries the minimum-difficulty rule: twenty minutes late means `powLimit`;
    /// otherwise the last block not mined at `powLimit`, stopping at the period's start.
    #[test]
    fn minimum_difficulty_rule_on_regtest() {
        let params = ChainParams::regtest(RegtestOverrides::default());
        let limit = 0x207f_ffff;
        let harder = 0x2000_ffff;
        let base_time = 1_296_688_602;
        let period = [
            facts(144, limit, base_time),
            facts(145, harder, base_time + 600),
            facts(146, limit, base_time + 1_200),
            facts(147, limit, base_time + 1_800),
        ];
        let previous_time = base_time + 1_800;
        // More than 2 * 600 s after the previous block: powLimit is required.
        assert_eq!(
            next_required_bits(&params, &period, BlockTime::new(previous_time + 1_201)),
            compact(limit)
        );
        // Exactly 1200 s is not more: walk back past the powLimit blocks to height 145.
        assert_eq!(
            next_required_bits(&params, &period, BlockTime::new(previous_time + 1_200)),
            compact(harder)
        );
        // Timestamps may go backwards; still the walk-back.
        assert_eq!(
            next_required_bits(&params, &period, BlockTime::new(base_time)),
            compact(harder)
        );
        // Every block since the boundary at powLimit: the boundary's own bits, powLimit.
        let all_limit = [
            facts(144, limit, base_time),
            facts(145, limit, base_time + 600),
        ];
        assert_eq!(
            next_required_bits(&params, &all_limit, BlockTime::new(base_time + 700)),
            compact(limit)
        );
        // The boundary block's bits are taken whatever they are, and genesis is a boundary.
        let from_genesis = [facts(0, harder, base_time), facts(1, limit, base_time + 1)];
        assert_eq!(
            next_required_bits(&params, &from_genesis, BlockTime::new(base_time + 2)),
            compact(harder)
        );
        let boundary_only = [facts(288, harder, base_time)];
        assert_eq!(
            next_required_bits(&params, &boundary_only, BlockTime::new(base_time + 1)),
            compact(harder)
        );
    }

    #[test]
    #[should_panic(expected = "first.height.is_retarget_boundary(interval)")]
    fn a_period_not_starting_at_a_boundary_is_a_bug() {
        let params = ChainParams::mainnet();
        let period = [facts(1, 0x1d00_ffff, 1), facts(2, 0x1d00_ffff, 2)];
        let _unreachable = next_required_bits(&params, &period, BlockTime::new(3));
    }

    #[test]
    #[should_panic(expected = "heights are consecutive")]
    fn a_period_with_a_gap_is_a_bug() {
        let params = ChainParams::mainnet();
        // Right length and boundary, wrong interior.
        let period = [
            facts(2016, 0x1d00_ffff, 1),
            facts(2018, 0x1d00_ffff, 2),
            facts(2018, 0x1d00_ffff, 3),
        ];
        let _unreachable = next_required_bits(&params, &period, BlockTime::new(4));
    }

    #[test]
    #[should_panic(expected = "from its boundary to the previous header")]
    fn a_period_of_the_wrong_length_is_a_bug() {
        let params = ChainParams::mainnet();
        let period = [facts(2016, 0x1d00_ffff, 1)];
        // Height 2016 % 2016 + 1 = 1: fine. A last height of 2018 needs three entries.
        let _fine = next_required_bits(&params, &period, BlockTime::new(2));
        let short = [facts(2016, 0x1d00_ffff, 1), facts(2018, 0x1d00_ffff, 2)];
        let _unreachable = next_required_bits(&params, &short, BlockTime::new(3));
    }

    /// Core: sort, take index `n / 2`. Even counts take the upper middle.
    #[test]
    fn median_time_past_is_the_middle_of_the_sorted_window() {
        assert_eq!(median_time_past(&times(&[5])), BlockTime::new(5));
        assert_eq!(median_time_past(&times(&[5, 3])), BlockTime::new(5));
        assert_eq!(median_time_past(&times(&[3, 5])), BlockTime::new(5));
        assert_eq!(median_time_past(&times(&[9, 1, 5])), BlockTime::new(5));
        let eleven = times(&[11, 1, 10, 2, 9, 3, 8, 4, 7, 5, 6]);
        assert_eq!(eleven.len(), MEDIAN_TIME_SPAN);
        assert_eq!(median_time_past(&eleven), BlockTime::new(6));
        // Order of the input is irrelevant; duplicates count.
        assert_eq!(
            median_time_past(&times(&[7, 7, 7, 1, 1, 1, 1, 9, 9, 9, 9])),
            BlockTime::new(7)
        );
    }

    #[test]
    #[should_panic(expected = "times.len() <= MEDIAN_TIME_SPAN")]
    fn twelve_timestamps_is_a_bug() {
        let _unreachable = median_time_past(&times(&[0; 12]));
    }

    #[test]
    #[should_panic(expected = "!times.is_empty()")]
    fn no_timestamps_is_a_bug() {
        let _unreachable = median_time_past(&[]);
    }

    #[test]
    fn header_facts_read_the_three_fields() {
        let params = ChainParams::mainnet();
        let genesis = HeaderFacts::from_header(Height::GENESIS, &params.genesis().header);
        assert_eq!(genesis, facts(0, 0x1d00_ffff, 1_231_006_505));
        assert_eq!(Target::from_compact(genesis.bits), params.pow_limit());
    }
}
