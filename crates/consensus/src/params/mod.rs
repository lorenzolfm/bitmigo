// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-chain constants, and the rules in force for one block.
//!
//! Bitcoin Core answers "which rules apply to this block" in `GetBlockScriptFlags` plus a
//! handful of `DeploymentActiveAt` calls spread through `validation.cpp`. This module folds
//! them into one function, [`ChainParams::rules_at`], which takes a height and a block hash
//! and returns the [`Rules`] every contextual check reads. Two facts about Core shape it,
//! both from `docs/consensus-rules.md` §4.2 and §5 (Core v31.1):
//!
//! - **Every deployment is buried.** Core's validation never consults the BIP9 versionbits
//!   state. P2SH, WITNESS and TAPROOT are applied from genesis minus a per-block exception
//!   list keyed by hash, and DERSIG, CLTV, CSV and NULLDUMMY switch on at fixed heights. A
//!   future softfork means new rule code and a new height, here as in Core; there is no
//!   state machine to get wrong, and no `-vbparams`.
//! - **Exceptions only relax.** The exception list may remove flags from the always-on set
//!   and nothing else. The constructor asserts it.
//!
//! [`ChainParams`] has private fields and named constructors, so a chain where Taproot
//! activates before segwit, or where a height is confused with a timestamp, cannot be
//! written down. It holds only what validation reads. The node keeps its own table of what
//! validation never reads: network magic, ports, DNS seeds, minimum chain work.
//!
//! Three chains are tabled: mainnet, signet and regtest. Signet's constructor and its block
//! challenge arrive with the `signet` module; testnet3 and testnet4 are data to add if a
//! rule ever needs them. There are no checkpoints, because Core has none.

mod height;
mod regtest;
mod rules;

pub use height::{BlockTime, Height};
pub use regtest::{RegtestArgError, RegtestOverrides};
pub use rules::{BIP34_IMPLIES_BIP30_LIMIT, Bip30, Rules, block_subsidy};
// The flag type belongs to the interpreter; `Rules` produces it, so it is re-exported
// here for callers that only know about chain parameters.
pub use crate::script::ScriptFlags;

use bitcoin::block::Block;
use bitcoin::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::pow::Target;
use bitcoin::{BlockHash, Network};

/// A block hash as `BlockHash::to_byte_array` lays it out: the reverse of the displayed hex.
/// Tables hold this instead of `BlockHash` because the pinned crates offer no `const`
/// constructor for one, and a table that is checked at compile time is worth the conversion.
type HashBytes = [u8; 32];

/// The chains bitmigo knows. The node's network table is keyed by the same enum and asserts
/// equality when it pairs a network with its `ChainParams`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Chain {
    /// The chain other people's money is on.
    Mainnet,
    /// BIP325 signet: mainnet's rules plus a block-signature challenge.
    Signet,
    /// The local test chain the differential harness runs against `bitcoind -regtest`.
    Regtest,
}

/// BIP34's buried height and, where the chain has one, the block at that height. Core skips
/// the BIP30 duplicate-coinbase scan once that exact block is an ancestor (§2.5); signet and
/// regtest carry no hash and never skip it.
#[derive(Clone, Copy, Debug)]
struct Bip34 {
    height: Height,
    hash: Option<HashBytes>,
}

/// The heights at which each buried deployment switches on (§5.2). Taproot has no height:
/// it is always on, so "taproot before segwit" is not a thing this struct can say.
#[derive(Clone, Copy, Debug)]
struct BuriedHeights {
    bip34: Bip34,
    bip66: Height,
    bip65: Height,
    csv: Height,
    segwit: Height,
}

/// One block whose script flags replace the always-on set: Core's `script_flag_exceptions`.
#[derive(Clone, Copy, Debug)]
struct ScriptFlagException {
    hash: HashBytes,
    flags: ScriptFlags,
}

/// One block Core exempts from the BIP30 scan, keyed by height and hash: `IsBIP30Repeat`.
#[derive(Clone, Copy, Debug)]
struct Bip30RepeatException {
    height: Height,
    hash: HashBytes,
}

/// The most exception blocks any chain tables. Mainnet has two, testnet3 one, so the tables
/// are small enough to scan on every `rules_at`.
const SCRIPT_FLAG_EXCEPTIONS_MAX: usize = 2;
/// Mainnet has the only two BIP30 repeats (§2.5).
const BIP30_REPEAT_EXCEPTIONS_MAX: usize = 2;

const MAINNET_GENESIS_HASH: HashBytes =
    hash_bytes("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
const REGTEST_GENESIS_HASH: HashBytes =
    hash_bytes("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");
/// Block 227931, the first block BIP34 covers on mainnet (§5.2).
const MAINNET_BIP34_HASH: HashBytes =
    hash_bytes("000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");

/// `powLimit`, big-endian, as `kernel/chainparams.cpp` writes it (§1.1).
const MAINNET_POW_LIMIT: [u8; 32] =
    hex_bytes("00000000ffff0000000000000000000000000000000000000000000000000000");
const REGTEST_POW_LIMIT: [u8; 32] =
    hex_bytes("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/// Mainnet's two blocks verified under fewer flags than the always-on set (§4.2, §6).
static MAINNET_SCRIPT_FLAG_EXCEPTIONS: [ScriptFlagException; 2] = [
    // Block 170060: the one historical BIP16 violation, mined before BIP16's 2012-04-01
    // switch. Core verifies it with no flags at all.
    ScriptFlagException {
        hash: hash_bytes("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"),
        flags: ScriptFlags::NONE,
    },
    // Block 692261: the one taproot-rule violation, mined before taproot's activation at
    // 709632. Core keeps P2SH and WITNESS and drops TAPROOT.
    ScriptFlagException {
        hash: hash_bytes("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"),
        flags: ScriptFlags::P2SH.union(ScriptFlags::WITNESS),
    },
];

/// The two 2010 blocks whose coinbases duplicate earlier ones (§2.5). Their coins overwrite
/// the originals; the coins path handles that, this table only says "do not scan".
static MAINNET_BIP30_REPEAT_EXCEPTIONS: [Bip30RepeatException; 2] = [
    Bip30RepeatException {
        height: Height::new(91_842),
        hash: hash_bytes("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"),
    },
    Bip30RepeatException {
        height: Height::new(91_880),
        hash: hash_bytes("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"),
    },
];

/// Everything validation reads about a chain. Private fields; built by [`Self::mainnet`] and
/// [`Self::regtest`] (and `signet`, once the `signet` module lands), which assert every
/// invariant once so the accessors never have to.
#[derive(Clone, Debug)]
pub struct ChainParams {
    chain: Chain,
    genesis: Block,
    pow_limit: Target,
    /// `nPowTargetTimespan`, seconds. Signed because retarget arithmetic is (§1.2).
    pow_target_timespan: i64,
    /// `nPowTargetSpacing`, seconds.
    pow_target_spacing: i64,
    /// `fPowNoRetargeting`: regtest keeps the genesis difficulty forever.
    no_retargeting: bool,
    /// `fPowAllowMinDifficultyBlocks`: a block twenty minutes late may use `powLimit`.
    allow_min_difficulty: bool,
    /// `enforce_BIP94`: the timewarp and first-block retarget rules.
    enforce_bip94: bool,
    /// `nSubsidyHalvingInterval`, a count of blocks, so not a `Height`.
    halving_interval: u32,
    buried: BuriedHeights,
    script_flag_exceptions: &'static [ScriptFlagException],
    bip30_repeat_exceptions: &'static [Bip30RepeatException],
}

impl ChainParams {
    /// Mainnet, as `CMainParams` in Core v31.1.
    #[must_use]
    pub fn mainnet() -> ChainParams {
        let params = ChainParams {
            chain: Chain::Mainnet,
            genesis: genesis_block(Network::Bitcoin),
            pow_limit: Target::from_be_bytes(MAINNET_POW_LIMIT),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            no_retargeting: false,
            allow_min_difficulty: false,
            enforce_bip94: false,
            halving_interval: 210_000,
            buried: BuriedHeights {
                bip34: Bip34 {
                    height: Height::new(227_931),
                    hash: Some(MAINNET_BIP34_HASH),
                },
                bip66: Height::new(363_725),
                bip65: Height::new(388_381),
                csv: Height::new(419_328),
                segwit: Height::new(481_824),
            },
            script_flag_exceptions: &MAINNET_SCRIPT_FLAG_EXCEPTIONS,
            bip30_repeat_exceptions: &MAINNET_BIP30_REPEAT_EXCEPTIONS,
        };
        params.assert_invariants(MAINNET_GENESIS_HASH);
        params
    }

    /// Regtest, as `CRegTestParams` in Core v31.1 with the given overrides applied. Core's
    /// defaults: BIP34, BIP66, BIP65 and CSV at 1, segwit at 0, BIP94 off (§5.5).
    #[must_use]
    pub fn regtest(overrides: RegtestOverrides) -> ChainParams {
        let default = Height::new(1);
        let params = ChainParams {
            chain: Chain::Regtest,
            genesis: genesis_block(Network::Regtest),
            pow_limit: Target::from_be_bytes(REGTEST_POW_LIMIT),
            pow_target_timespan: 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            no_retargeting: true,
            allow_min_difficulty: true,
            enforce_bip94: overrides.bip94,
            halving_interval: 150,
            buried: BuriedHeights {
                bip34: Bip34 {
                    height: overrides.bip34.unwrap_or(default),
                    hash: None,
                },
                bip66: overrides.bip66.unwrap_or(default),
                bip65: overrides.bip65.unwrap_or(default),
                csv: overrides.csv.unwrap_or(default),
                segwit: overrides.segwit.unwrap_or(Height::GENESIS),
            },
            script_flag_exceptions: &[],
            bip30_repeat_exceptions: &[],
        };
        params.assert_invariants(REGTEST_GENESIS_HASH);
        params
    }

    /// The invariants every constructor establishes. `genesis_hash` is the inventory's
    /// constant for the chain (§1.5); the block itself comes from the `bitcoin` crate, so
    /// this is also the check that the pinned crate hashes the way the network does.
    fn assert_invariants(&self, genesis_hash: HashBytes) {
        assert_eq!(self.genesis.block_hash().to_byte_array(), genesis_hash);
        assert_eq!(self.genesis.txdata.len(), 1);
        assert!(self.pow_limit > Target::ZERO);
        assert!(self.pow_target_spacing > 0);
        assert!(self.pow_target_timespan >= self.pow_target_spacing);
        assert_eq!(self.pow_target_timespan % self.pow_target_spacing, 0);
        assert!(self.halving_interval > 0);

        assert!(self.script_flag_exceptions.len() <= SCRIPT_FLAG_EXCEPTIONS_MAX);
        for exception in self.script_flag_exceptions {
            // Exceptions only relax. Core installs the exception's flags in place of the
            // always-on set and then adds the height-gated ones, so a flag here that is
            // outside the always-on set would be one Core never applies to that block.
            assert!(exception.flags.is_subset_of(rules::ALWAYS_ON_SCRIPT_FLAGS));
        }
        assert!(self.bip30_repeat_exceptions.len() <= BIP30_REPEAT_EXCEPTIONS_MAX);

        // Only mainnet's BIP34 block is a real hash; Core zeroes it on signet and regtest,
        // which is what makes those chains scan for BIP30 duplicates forever.
        if self.chain != Chain::Mainnet {
            assert!(self.buried.bip34.hash.is_none());
        }
    }

    /// Which chain these parameters describe.
    #[must_use]
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// The genesis block. Its coinbase output never enters the UTXO set (§1.5).
    #[must_use]
    pub fn genesis(&self) -> &Block {
        &self.genesis
    }

    /// The genesis block's hash.
    #[must_use]
    pub fn genesis_hash(&self) -> BlockHash {
        self.genesis.block_hash()
    }

    /// `powLimit`: the easiest target a block may claim (§1.1).
    #[must_use]
    pub fn pow_limit(&self) -> Target {
        self.pow_limit
    }

    /// `nPowTargetTimespan` in seconds: two weeks on mainnet, one day on regtest.
    #[must_use]
    pub fn pow_target_timespan(&self) -> i64 {
        self.pow_target_timespan
    }

    /// `nPowTargetSpacing` in seconds: ten minutes everywhere.
    #[must_use]
    pub fn pow_target_spacing(&self) -> i64 {
        self.pow_target_spacing
    }

    /// Blocks per difficulty period: 2016 on mainnet, 144 on regtest (§1.2).
    #[must_use]
    pub fn difficulty_adjustment_interval(&self) -> u32 {
        // Exact by the constructor's invariant.
        let interval = self.pow_target_timespan / self.pow_target_spacing;
        let interval = u32::try_from(interval).expect("an interval of blocks fits u32");
        assert!(interval > 0);
        interval
    }

    /// `fPowNoRetargeting`.
    #[must_use]
    pub fn no_retargeting(&self) -> bool {
        self.no_retargeting
    }

    /// `fPowAllowMinDifficultyBlocks`.
    #[must_use]
    pub fn allow_min_difficulty(&self) -> bool {
        self.allow_min_difficulty
    }

    /// `enforce_BIP94`.
    #[must_use]
    pub fn enforce_bip94(&self) -> bool {
        self.enforce_bip94
    }

    /// `nSubsidyHalvingInterval`, in blocks (§2.7).
    #[must_use]
    pub fn halving_interval(&self) -> u32 {
        self.halving_interval
    }

    /// The BIP34 height. The node fetches the hash of this block on a block's chain and
    /// passes it to [`Self::rules_at`] as `bip34_ancestor` once the block is above it.
    #[must_use]
    pub fn bip34_height(&self) -> Height {
        self.buried.bip34.height
    }
}

/// Parses 64 lower-case hex digits into bytes in the order written, at compile time. A typo
/// in a constant is a build error, not a chain split.
#[allow(
    clippy::indexing_slicing,
    reason = "runs at compile time only; the length is asserted and an out-of-range index \
              fails the build"
)]
const fn hex_bytes(hex: &str) -> [u8; 32] {
    let digits = hex.as_bytes();
    assert!(digits.len() == 64);
    let mut bytes = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        let high = hex_digit(digits[2 * index]);
        let low = hex_digit(digits[2 * index + 1]);
        bytes[index] = (high << 4) | low;
        index += 1;
    }
    bytes
}

/// Parses a block hash written the way Core, explorers and `docs/consensus-rules.md` write
/// it, then reverses it into `to_byte_array` order.
#[allow(
    clippy::indexing_slicing,
    reason = "runs at compile time only; both arrays are 32 long and the index is below 32"
)]
const fn hash_bytes(hex: &str) -> HashBytes {
    let displayed = hex_bytes(hex);
    let mut bytes = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        bytes[index] = displayed[31 - index];
        index += 1;
    }
    bytes
}

const fn hex_digit(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("hash constants are written in lower-case hex"),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::CompactTarget;

    use super::{Chain, ChainParams, HashBytes, Height, RegtestOverrides, hash_bytes};

    /// The `to_byte_array` order is the displayed hex reversed; the genesis hash is the one
    /// value everyone has memorised, so it pins the direction.
    #[test]
    fn hash_bytes_reverses_the_displayed_hex() {
        let bytes: HashBytes =
            hash_bytes("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        assert_eq!(bytes[0], 0x6f);
        assert_eq!(bytes[1], 0xe2);
        assert_eq!(bytes[26], 0x19);
        assert_eq!(bytes[27], 0x00);
        assert_eq!(bytes[31], 0x00);
    }

    #[test]
    fn mainnet_matches_core() {
        let params = ChainParams::mainnet();
        assert_eq!(params.chain(), Chain::Mainnet);
        assert_eq!(
            params.genesis_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        );
        assert_eq!(
            params.pow_limit().to_compact_lossy(),
            CompactTarget::from_consensus(0x1d00_ffff)
        );
        assert_eq!(params.pow_target_timespan(), 1_209_600);
        assert_eq!(params.pow_target_spacing(), 600);
        assert_eq!(params.difficulty_adjustment_interval(), 2016);
        assert!(!params.no_retargeting());
        assert!(!params.allow_min_difficulty());
        assert!(!params.enforce_bip94());
        assert_eq!(params.halving_interval(), 210_000);
        assert_eq!(params.bip34_height(), Height::new(227_931));
    }

    #[test]
    fn regtest_defaults_match_core() {
        let params = ChainParams::regtest(RegtestOverrides::default());
        assert_eq!(params.chain(), Chain::Regtest);
        assert_eq!(
            params.genesis_hash().to_string(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        );
        assert_eq!(
            params.pow_limit().to_compact_lossy(),
            CompactTarget::from_consensus(0x207f_ffff)
        );
        assert_eq!(params.pow_target_timespan(), 86_400);
        assert_eq!(params.difficulty_adjustment_interval(), 144);
        assert!(params.no_retargeting());
        assert!(params.allow_min_difficulty());
        assert!(!params.enforce_bip94());
        assert_eq!(params.halving_interval(), 150);
        assert_eq!(params.bip34_height(), Height::new(1));
    }

    #[test]
    fn regtest_overrides_apply() {
        let overrides = RegtestOverrides {
            bip34: Some(Height::new(500)),
            bip94: true,
            ..RegtestOverrides::default()
        };
        let params = ChainParams::regtest(overrides);
        assert!(params.enforce_bip94());
        assert_eq!(params.bip34_height(), Height::new(500));
    }
}
