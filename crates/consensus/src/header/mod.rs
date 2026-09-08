// SPDX-License-Identifier: MIT OR Apache-2.0

//! Header rules: proof of work, the compact target, difficulty retargeting, median time
//! past, and the two header stages of the validation pipeline.
//!
//! The pipeline splits header validation where Core and libbitcoin do (BM-D1 decision 2).
//! [`check_header`] is Core's `CheckBlockHeader`: context-free, the hash meets the target
//! its own `nBits` names and that target is one the chain allows. [`accept_header`] is
//! `ContextualCheckBlockHeader` minus its one clock-dependent rule: `nBits` equals the
//! required target, `nTime` is after the median time past, the BIP94 timewarp bound where
//! the chain enforces it, and the version floor (§1.2–1.4, §1.6). The future-time rule
//! (`nTime <= now + 2h`) needs a clock this crate does not have; the node applies it before
//! calling, with the [`MAX_FUTURE_BLOCK_TIME`] exported here so the constant lives once.
//!
//! Everything contextual arrives in a [`Context`] the node assembles from its header tree
//! with the pure helpers in this module: [`next_required_bits`] and [`median_time_past`]
//! over [`HeaderFacts`], and [`block_work`] for the most-work choice. The same `Context` is
//! what the block stages read, so one struct, built once per block, carries every fact
//! the chain contributes to a verdict.

mod retarget;
mod target;
mod uint;

pub use retarget::{HeaderFacts, MEDIAN_TIME_SPAN, median_time_past, next_required_bits};
pub use target::{TargetError, block_work, decode_target, encode_target, hash_meets_target};

use core::fmt;

use bitcoin::block::Header;
use bitcoin::pow::CompactTarget;

use crate::params::{BlockTime, ChainParams, Height, Rules};

/// Core's `MAX_TIMEWARP` (BIP94): a block that opens a difficulty period may be at most
/// this many seconds earlier than its predecessor, on chains that enforce BIP94.
pub const MAX_TIMEWARP: i64 = 600;

/// Core's `MAX_FUTURE_BLOCK_TIME`: a header more than this far ahead of the node's clock is
/// refused, but not marked invalid, because it may be valid later (§1.3). The node's rule,
/// since this crate has no clock; the constant is here so the two agree.
pub const MAX_FUTURE_BLOCK_TIME: i64 = 2 * 60 * 60;

/// What the chain contributes to validating one block: the facts every contextual stage
/// reads, assembled by the node from its header tree and consumed by [`accept_header`] and
/// the block stages. Private fields: there is no context for genesis, and the node cannot
/// build one by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    height: Height,
    median_time_past: BlockTime,
    previous_time: BlockTime,
    required_bits: CompactTarget,
    rules: Rules,
}

impl Context {
    /// The context for the block at `height`, whose predecessor's median time past and
    /// `nTime` are given, which must carry `required_bits` (from [`next_required_bits`])
    /// and is validated under `rules` (from `ChainParams::rules_at`).
    #[must_use]
    pub fn new(
        height: Height,
        median_time_past: BlockTime,
        previous_time: BlockTime,
        required_bits: CompactTarget,
        rules: Rules,
    ) -> Context {
        // Core asserts pindexPrev != nullptr: genesis has no context.
        assert!(height > Height::GENESIS);
        Context {
            height,
            median_time_past,
            previous_time,
            required_bits,
            rules,
        }
    }

    /// The block's height.
    #[must_use]
    pub fn height(&self) -> Height {
        self.height
    }

    /// The median time past of the previous block: the median of the last eleven `nTime`s.
    #[must_use]
    pub fn median_time_past(&self) -> BlockTime {
        self.median_time_past
    }

    /// The previous block's `nTime`.
    #[must_use]
    pub fn previous_time(&self) -> BlockTime {
        self.previous_time
    }

    /// The `nBits` the block must carry, exactly: Core compares the encodings, so a second
    /// encoding of the same target is as wrong as a different target.
    #[must_use]
    pub fn required_bits(&self) -> CompactTarget {
        self.required_bits
    }

    /// The rules in force for the block.
    #[must_use]
    pub fn rules(&self) -> &Rules {
        &self.rules
    }
}

/// Why a header was refused, in the vocabulary of Core's reject reasons; `Display` gives
/// the reason string. The fields are the evidence: what was required and what was seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeaderError {
    /// `high-hash`: `nBits` names no target the chain allows.
    InvalidTarget(TargetError),
    /// `high-hash`: the header's hash is above its own target.
    HighHash,
    /// `bad-diffbits`: `nBits` is not the required encoding.
    BadDiffBits {
        /// What the chain required.
        required: CompactTarget,
    },
    /// `time-too-old`: `nTime` is not after the previous block's median time past.
    TimeTooOld {
        /// The median time past `nTime` had to exceed.
        median_time_past: BlockTime,
    },
    /// `time-timewarp-attack`: the first block of a difficulty period is more than
    /// [`MAX_TIMEWARP`] seconds before its predecessor (BIP94).
    Timewarp {
        /// The previous block's `nTime`.
        previous_time: BlockTime,
    },
    /// `bad-version(0x%08x)`: `nVersion`, read as a signed integer, is below the floor.
    BadVersion {
        /// The header's `nVersion`.
        version: i32,
        /// The smallest version the height allows.
        floor: i32,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget(_) | Self::HighHash => f.write_str("high-hash"),
            Self::BadDiffBits { .. } => f.write_str("bad-diffbits"),
            Self::TimeTooOld { .. } => f.write_str("time-too-old"),
            Self::Timewarp { .. } => f.write_str("time-timewarp-attack"),
            Self::BadVersion { version, .. } => write!(f, "bad-version({version:#010x})"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// Core's `CheckBlockHeader`: the proof of work against the header's own `nBits` (§1.1).
/// Context-free, so it runs on receipt before the header is placed on any chain.
pub fn check_header(header: &Header, params: &ChainParams) -> Result<(), HeaderError> {
    let target =
        decode_target(header.bits, params.pow_limit()).map_err(HeaderError::InvalidTarget)?;
    if !hash_meets_target(header.block_hash(), target) {
        return Err(HeaderError::HighHash);
    }
    Ok(())
}

/// Core's `ContextualCheckBlockHeader` minus the clock rule, in Core's order: required
/// `nBits`, median time past, BIP94 timewarp, version floor (§1.2–1.4). The caller has
/// passed [`check_header`] and applied the future-time rule itself.
pub fn accept_header(
    header: &Header,
    params: &ChainParams,
    context: &Context,
) -> Result<(), HeaderError> {
    if header.bits != context.required_bits {
        return Err(HeaderError::BadDiffBits {
            required: context.required_bits,
        });
    }

    let time = BlockTime::new(header.time);
    if time <= context.median_time_past {
        return Err(HeaderError::TimeTooOld {
            median_time_past: context.median_time_past,
        });
    }

    // Testnet4 and regtest with `-test=bip94` only: the block opening a period may not
    // reach back more than MAX_TIMEWARP before its predecessor.
    if params.enforce_bip94() {
        let interval = params.difficulty_adjustment_interval();
        if context.height.is_retarget_boundary(interval)
            && time.timespan_since(context.previous_time) < -MAX_TIMEWARP
        {
            return Err(HeaderError::Timewarp {
                previous_time: context.previous_time,
            });
        }
    }

    // The future-time rule sits here in Core; the node applied it before calling.

    let version = header.version.to_consensus();
    let floor = context.rules.version_floor();
    if version < floor {
        return Err(HeaderError::BadVersion { version, floor });
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test fixtures index arrays and vectors whose lengths the tests assert"
)]
mod tests {
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::deserialize;
    use bitcoin::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::{CompactTarget, Target, Work};
    use bitcoin::{BlockHash, Network};

    use super::{
        Context, HeaderError, HeaderFacts, MAX_TIMEWARP, MEDIAN_TIME_SPAN, TargetError,
        accept_header, block_work, check_header, decode_target, hash_meets_target,
        median_time_past, next_required_bits,
    };
    use crate::params::{BlockTime, ChainParams, Height, RegtestOverrides};
    use crate::script::vectors::Json;

    /// Fifteen regtest headers mined by bitcoind v31.1.0 under `setmocktime`, with Core's
    /// own `mediantime`, `bits` and `chainwork` for each (`tests/data/README.md`).
    const REGTEST_HEADERS_JSON: &str = include_str!("../../tests/data/regtest-headers.json");

    struct Fixture {
        header: Header,
        hash: BlockHash,
        median_time_past: BlockTime,
        bits: CompactTarget,
        chainwork: Work,
    }

    fn fixture() -> Vec<Fixture> {
        let rows = Json::parse(REGTEST_HEADERS_JSON);
        rows.as_array()
            .iter()
            .enumerate()
            .map(|(height, row)| {
                assert_eq!(row.get("height").as_i64(), i64::try_from(height).unwrap());
                let header: Header = deserialize(&row.get("header").as_bytes()).unwrap();
                let mut chainwork = [0u8; 32];
                chainwork.copy_from_slice(&row.get("chainwork").as_bytes());
                Fixture {
                    header,
                    hash: row.get("hash").as_str().parse().unwrap(),
                    median_time_past: BlockTime::new(
                        u32::try_from(row.get("mediantime").as_i64()).unwrap(),
                    ),
                    bits: CompactTarget::from_consensus(
                        u32::from_str_radix(row.get("bits").as_str(), 16).unwrap(),
                    ),
                    chainwork: Work::from_be_bytes(chainwork),
                }
            })
            .collect()
    }

    fn compact(bits: u32) -> CompactTarget {
        CompactTarget::from_consensus(bits)
    }

    fn regtest() -> ChainParams {
        ChainParams::regtest(RegtestOverrides::default())
    }

    /// The context the node would build for the header at `height` of the fixture chain.
    fn fixture_context(params: &ChainParams, rows: &[Fixture], height: usize) -> Context {
        assert!(height >= 1);
        let interval = usize::try_from(params.difficulty_adjustment_interval()).unwrap();
        let previous = height - 1;
        let period_start = previous - previous % interval;
        let period: Vec<HeaderFacts> = rows[period_start..height]
            .iter()
            .enumerate()
            .map(|(offset, row)| {
                let height = u32::try_from(period_start + offset).unwrap();
                HeaderFacts::from_header(Height::new(height), &row.header)
            })
            .collect();
        let candidate = &rows[height];
        let window_start = height.saturating_sub(MEDIAN_TIME_SPAN);
        let times: Vec<BlockTime> = rows[window_start..height]
            .iter()
            .map(|row| BlockTime::new(row.header.time))
            .collect();
        let block_height = Height::new(u32::try_from(height).unwrap());
        Context::new(
            block_height,
            median_time_past(&times),
            BlockTime::new(rows[previous].header.time),
            next_required_bits(params, &period, BlockTime::new(candidate.header.time)),
            params.rules_at(block_height, candidate.hash, None),
        )
    }

    #[test]
    fn fixture_is_the_regtest_chain_bitcoind_mined() {
        let rows = fixture();
        assert_eq!(rows.len(), 15);
        let params = regtest();
        assert_eq!(rows[0].header, params.genesis().header);
        for (height, row) in rows.iter().enumerate() {
            assert_eq!(row.header.block_hash(), row.hash);
            assert_eq!(row.header.bits, row.bits);
            if height > 0 {
                assert_eq!(row.header.prev_blockhash, rows[height - 1].hash);
            }
        }
        // Times go backwards in places, which is what makes the median fixture worth having.
        assert!(rows[4].header.time < rows[3].header.time);
        assert!(rows[12].header.time < rows[11].header.time);
    }

    /// Core's `mediantime` for every header, including the short windows near genesis.
    #[test]
    fn median_time_past_matches_bitcoind() {
        let rows = fixture();
        for height in 0..rows.len() {
            let window_start = (height + 1).saturating_sub(MEDIAN_TIME_SPAN);
            let times: Vec<BlockTime> = rows[window_start..=height]
                .iter()
                .map(|row| BlockTime::new(row.header.time))
                .collect();
            assert_eq!(
                median_time_past(&times),
                rows[height].median_time_past,
                "{height}"
            );
        }
    }

    /// Core's `chainwork` for every header is the running sum of `block_work`.
    #[test]
    fn chainwork_matches_bitcoind() {
        let rows = fixture();
        let mut total = block_work(rows[0].header.bits);
        assert_eq!(total, rows[0].chainwork);
        for row in &rows[1..] {
            total = total + block_work(row.header.bits);
            assert_eq!(total, row.chainwork);
        }
    }

    /// Every fixture header passes both stages with the context the node would build.
    #[test]
    fn bitcoind_headers_pass_check_and_accept() {
        let rows = fixture();
        let params = regtest();
        assert_eq!(check_header(&rows[0].header, &params), Ok(()));
        for height in 1..rows.len() {
            let context = fixture_context(&params, &rows, height);
            assert_eq!(context.required_bits(), rows[height].header.bits);
            assert_eq!(
                context.median_time_past(),
                rows[height - 1].median_time_past
            );
            assert_eq!(
                check_header(&rows[height].header, &params),
                Ok(()),
                "{height}"
            );
            assert_eq!(
                accept_header(&rows[height].header, &params, &context),
                Ok(()),
                "{height}"
            );
        }
    }

    #[test]
    fn genesis_headers_meet_their_targets() {
        assert_eq!(
            check_header(
                &ChainParams::mainnet().genesis().header,
                &ChainParams::mainnet()
            ),
            Ok(())
        );
        assert_eq!(
            check_header(&regtest().genesis().header, &regtest()),
            Ok(())
        );
        // Signet's constructor arrives with the signet module; its genesis is checked
        // against the inventory's powLimit (§1.1) directly.
        let signet = genesis_block(Network::Signet).header;
        let signet_limit = Target::from_compact(compact(0x1e03_77ae));
        let target = decode_target(signet.bits, signet_limit).unwrap();
        assert_eq!(target, signet_limit);
        assert!(hash_meets_target(signet.block_hash(), target));
        assert_eq!(
            signet.block_hash().to_string(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
    }

    #[test]
    fn check_header_refuses_a_hash_above_the_target() {
        let params = ChainParams::mainnet();
        let mut header = params.genesis().header;
        header.nonce += 1;
        assert_eq!(check_header(&header, &params), Err(HeaderError::HighHash));
        // A regtest header at mainnet's difficulty: the target is fine, the hash is not.
        let regtest_genesis = regtest().genesis().header;
        assert_eq!(check_header(&regtest_genesis, &regtest()), Ok(()));
        let mut hard = regtest_genesis;
        hard.bits = compact(0x1d00_ffff);
        assert_eq!(check_header(&hard, &regtest()), Err(HeaderError::HighHash));
    }

    #[test]
    fn check_header_refuses_bits_the_chain_does_not_allow() {
        let params = ChainParams::mainnet();
        let cases = [
            (0x1d80_ffff, TargetError::Negative),
            (0xff7f_ffff, TargetError::Overflow),
            (0x0000_0000, TargetError::Zero),
            (0x1d01_fffe, TargetError::AbovePowLimit),
            // Regtest's powLimit is above mainnet's.
            (0x207f_ffff, TargetError::AbovePowLimit),
        ];
        for (bits, error) in cases {
            let mut header = params.genesis().header;
            header.bits = compact(bits);
            assert_eq!(
                check_header(&header, &params),
                Err(HeaderError::InvalidTarget(error)),
                "{bits:#x}"
            );
        }
    }

    #[test]
    fn accept_header_refuses_the_wrong_bits() {
        let rows = fixture();
        let params = regtest();
        let context = fixture_context(&params, &rows, 5);
        let mut header = rows[5].header;
        header.bits = compact(0x1d00_ffff);
        assert_eq!(
            accept_header(&header, &params, &context),
            Err(HeaderError::BadDiffBits {
                required: compact(0x207f_ffff)
            })
        );
    }

    /// `0x207fff00` and `0x21007fff` name the same target; Core compares the encodings, so
    /// only the canonical one passes.
    #[test]
    fn accept_header_refuses_a_second_encoding_of_the_required_target() {
        let params = regtest();
        let canonical = compact(0x207f_ff00);
        let alternative = compact(0x2100_7fff);
        assert_eq!(
            Target::from_compact(canonical),
            Target::from_compact(alternative)
        );
        assert_eq!(
            super::encode_target(Target::from_compact(alternative)),
            canonical
        );
        let height = Height::new(7);
        let context = Context::new(
            height,
            BlockTime::new(1_296_688_602),
            BlockTime::new(1_296_688_602),
            canonical,
            params.rules_at(height, BlockHash::from_byte_array([0x33; 32]), None),
        );
        let mut header = params.genesis().header;
        header.version = Version::from_consensus(4);
        header.time = 1_296_688_603;
        header.bits = canonical;
        assert_eq!(accept_header(&header, &params, &context), Ok(()));
        header.bits = alternative;
        assert_eq!(
            accept_header(&header, &params, &context),
            Err(HeaderError::BadDiffBits {
                required: canonical
            })
        );
    }

    #[test]
    fn accept_header_refuses_a_time_at_or_below_the_median() {
        let rows = fixture();
        let params = regtest();
        let context = fixture_context(&params, &rows, 7);
        let median = rows[6].median_time_past;
        let mut header = rows[7].header;
        header.time = median.get();
        assert_eq!(
            accept_header(&header, &params, &context),
            Err(HeaderError::TimeTooOld {
                median_time_past: median
            })
        );
        header.time = median.get() - 1_000;
        assert!(accept_header(&header, &params, &context).is_err());
        header.time = median.get() + 1;
        assert_eq!(accept_header(&header, &params, &context), Ok(()));
    }

    /// Regtest's floor is 4 from height 1 (BIP34, BIP66 and BIP65 at 1); the comparison is
    /// signed, so every negative version is below it.
    #[test]
    fn accept_header_enforces_the_version_floor() {
        let rows = fixture();
        let params = regtest();
        let context = fixture_context(&params, &rows, 3);
        assert_eq!(context.rules().version_floor(), 4);
        let mut header = rows[3].header;
        for version in [3, 1, 0, -1, i32::MIN] {
            header.version = Version::from_consensus(version);
            assert_eq!(
                accept_header(&header, &params, &context),
                Err(HeaderError::BadVersion { version, floor: 4 }),
                "{version}"
            );
        }
        header.version = Version::from_consensus(4);
        assert_eq!(accept_header(&header, &params, &context), Ok(()));
        header.version = Version::from_consensus(0x2000_0000);
        assert_eq!(accept_header(&header, &params, &context), Ok(()));

        // With every deployment moved past the fixture, version 1 is fine again.
        let late = ChainParams::regtest(RegtestOverrides {
            bip34: Some(Height::new(100)),
            bip66: Some(Height::new(100)),
            bip65: Some(Height::new(100)),
            ..RegtestOverrides::default()
        });
        let context = fixture_context(&late, &rows, 3);
        assert_eq!(context.rules().version_floor(), 1);
        header.version = Version::from_consensus(1);
        assert_eq!(accept_header(&header, &late, &context), Ok(()));
    }

    /// A synthetic header at a regtest period boundary (height 144) under `-test=bip94`.
    fn timewarp_case(bip94: bool, height: u32, time_offset: i64) -> Result<(), HeaderError> {
        let params = ChainParams::regtest(RegtestOverrides {
            bip94,
            ..RegtestOverrides::default()
        });
        let previous_time = BlockTime::new(1_296_800_000);
        let block_height = Height::new(height);
        let rules = params.rules_at(block_height, BlockHash::from_byte_array([0x22; 32]), None);
        let context = Context::new(
            block_height,
            BlockTime::new(1_296_700_000),
            previous_time,
            compact(0x207f_ffff),
            rules,
        );
        let mut header = params.genesis().header;
        header.version = Version::from_consensus(4);
        let Ok(time) = u32::try_from(i64::from(previous_time.get()) + time_offset) else {
            panic!("the offsets under test stay within u32");
        };
        header.time = time;
        accept_header(&header, &params, &context)
    }

    #[test]
    fn timewarp_bound_applies_at_period_boundaries_under_bip94() {
        let previous_time = BlockTime::new(1_296_800_000);
        assert_eq!(
            timewarp_case(true, 144, -MAX_TIMEWARP - 1),
            Err(HeaderError::Timewarp { previous_time })
        );
        // Exactly MAX_TIMEWARP earlier is allowed: the comparison is strict.
        assert_eq!(timewarp_case(true, 144, -MAX_TIMEWARP), Ok(()));
        assert_eq!(
            timewarp_case(true, 288, -MAX_TIMEWARP - 1),
            Err(HeaderError::Timewarp { previous_time })
        );
        // Not a boundary, or not a BIP94 chain: no bound beyond the median time past.
        assert_eq!(timewarp_case(true, 145, -MAX_TIMEWARP - 1), Ok(()));
        assert_eq!(timewarp_case(true, 143, -MAX_TIMEWARP - 1), Ok(()));
        assert_eq!(timewarp_case(false, 144, -MAX_TIMEWARP - 1), Ok(()));
        assert_eq!(timewarp_case(false, 144, -50_000), Ok(()));
    }

    #[test]
    fn errors_display_cores_reject_reasons() {
        assert_eq!(HeaderError::HighHash.to_string(), "high-hash");
        assert_eq!(
            HeaderError::InvalidTarget(TargetError::Overflow).to_string(),
            "high-hash"
        );
        assert_eq!(
            HeaderError::BadDiffBits {
                required: compact(1)
            }
            .to_string(),
            "bad-diffbits"
        );
        assert_eq!(
            HeaderError::TimeTooOld {
                median_time_past: BlockTime::new(1)
            }
            .to_string(),
            "time-too-old"
        );
        assert_eq!(
            HeaderError::Timewarp {
                previous_time: BlockTime::new(1)
            }
            .to_string(),
            "time-timewarp-attack"
        );
        assert_eq!(
            HeaderError::BadVersion {
                version: 1,
                floor: 4
            }
            .to_string(),
            "bad-version(0x00000001)"
        );
        assert_eq!(
            HeaderError::BadVersion {
                version: -1,
                floor: 2
            }
            .to_string(),
            "bad-version(0xffffffff)"
        );
    }

    #[test]
    #[should_panic(expected = "height > Height::GENESIS")]
    fn a_context_for_genesis_is_a_bug() {
        let params = regtest();
        let rules = params.rules_at(Height::GENESIS, params.genesis_hash(), None);
        let _unreachable = Context::new(
            Height::GENESIS,
            BlockTime::new(0),
            BlockTime::new(0),
            compact(0x207f_ffff),
            rules,
        );
    }
}
