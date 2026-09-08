// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Rules`]: the answer to "which rules apply to this block", and how it is computed.
//!
//! One function, [`ChainParams::rules_at`], replaces Core's `GetBlockScriptFlags`, the
//! `DeploymentActiveAt` / `DeploymentActiveAfter` calls in `validation.cpp`, the version
//! floor in `ContextualCheckBlockHeader` and the BIP30 predicate in `ConnectBlock`. Every
//! contextual check reads the result; none of them re-derives an activation from a height.

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;

use super::{ChainParams, Height, ScriptFlags};

/// Core resumes the BIP30 duplicate-coinbase scan from this height, named after its constant
/// in `ConnectBlock`. Pre-BIP34 coinbases exist whose scriptSig happens to encode a later
/// height (the lowest still unspent is 1,983,702), so a height-prefixed coinbase from that
/// block on could duplicate one (§2.5).
pub const BIP34_IMPLIES_BIP30_LIMIT: Height = Height::new(1_983_702);

/// Core's `COIN`: satoshis per bitcoin.
const COIN: u64 = 100_000_000;

/// Core's `GetBlockSubsidy` stops halving here, because shifting a 64-bit amount by 64 is
/// undefined; the subsidy is zero from then on (§2.7).
const HALVINGS_MAX: u32 = 64;

/// What the coins path does about BIP30, the rule that no output of a block may already
/// exist unspent in the UTXO set (§2.5). Three states, because Core has three: the scan,
/// the scan skipped, and the two 2010 blocks whose coinbases overwrite an earlier coin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Bip30 {
    /// Every output of the block must be absent from the set: the node looks each one up
    /// and `confirm` rejects the block (`bad-txns-BIP30`) if any is found.
    Enforce,
    /// Core skips the scan: mainnet from the block after BIP34's until
    /// [`BIP34_IMPLIES_BIP30_LIMIT`]. The node does not look, and `confirm` asserts it
    /// found nothing, because Core would crash on an overwrite here.
    Skip,
    /// Mainnet 91842 and 91880: the node looks as for `Enforce`, and what it finds is the
    /// coin the coinbase overwrites, carried in the delta so the set and its hash can
    /// follow Core's.
    Overwrite,
}

/// The flags Core applies to every block before the exception list and the buried heights
/// are consulted (`GetBlockScriptFlags`, §4.2).
pub(super) const ALWAYS_ON_SCRIPT_FLAGS: ScriptFlags = ScriptFlags::P2SH
    .union(ScriptFlags::WITNESS)
    .union(ScriptFlags::TAPROOT);

/// The rules in force for one block. Produced only by [`ChainParams::rules_at`]; the
/// fields agree with one another by construction and there is no way to build a set that
/// does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each field is an independent rule switch that Core also keeps as its own \
              predicate; folding them into an enum would invent states Core does not have"
)]
pub struct Rules {
    script_flags: ScriptFlags,
    version_floor: i32,
    bip34_active: bool,
    csv_active: bool,
    segwit_active: bool,
    bip30: Bip30,
    subsidy: u64,
}

impl Rules {
    /// The script verification flags for every input in the block.
    #[must_use]
    pub fn script_flags(&self) -> ScriptFlags {
        self.script_flags
    }

    /// The smallest `nVersion` the header may carry: 1, then 2 from BIP34, 3 from BIP66 and
    /// 4 from BIP65 (§1.4). Signed like the field, so every negative version is below it.
    #[must_use]
    pub fn version_floor(&self) -> i32 {
        self.version_floor
    }

    /// The coinbase must start with the block height (BIP34).
    #[must_use]
    pub fn bip34_active(&self) -> bool {
        self.bip34_active
    }

    /// BIP68 sequence locks apply and lock times are measured against median time past
    /// (BIP68, BIP112, BIP113).
    #[must_use]
    pub fn csv_active(&self) -> bool {
        self.csv_active
    }

    /// The witness commitment is enforced (BIP141).
    #[must_use]
    pub fn segwit_active(&self) -> bool {
        self.segwit_active
    }

    /// What the coins path does about BIP30 for this block.
    #[must_use]
    pub fn bip30(&self) -> Bip30 {
        self.bip30
    }

    /// The coins path must reject any output that already exists in the UTXO set (BIP30).
    /// False only where Core skips the scan: the two 2010 repeat blocks, and the mainnet
    /// window from the block after BIP34's until [`BIP34_IMPLIES_BIP30_LIMIT`].
    #[must_use]
    pub fn bip30_check_required(&self) -> bool {
        self.bip30 == Bip30::Enforce
    }

    /// The block subsidy at this height, satoshis: what the coinbase may pay on top of the
    /// fees (§2.7). Not a rule switch, but the one amount validation reads, kept here so
    /// the coins path needs nothing beyond the `Context`.
    #[must_use]
    pub fn subsidy(&self) -> u64 {
        self.subsidy
    }
}

/// Core's `GetBlockSubsidy`: 50 BTC halved once per `halving_interval` blocks, zero after
/// [`HALVINGS_MAX`] halvings (§2.7).
#[must_use]
pub fn block_subsidy(height: Height, halving_interval: u32) -> u64 {
    assert!(halving_interval > 0);
    // Floor division: every block of a period pays the same.
    let halvings = height.get() / halving_interval;
    if halvings >= HALVINGS_MAX {
        return 0;
    }
    let subsidy = (50 * COIN) >> halvings;
    assert!(subsidy <= 50 * COIN);
    subsidy
}

impl ChainParams {
    /// The rules for the block `hash` at `height`. `bip34_ancestor` is the hash of the block
    /// at the BIP34 height on this block's chain, which the node passes whenever the block
    /// is above that height and never otherwise; the crate compares it to its constant, so
    /// the node reports a fact and cannot assert a match.
    #[must_use]
    pub fn rules_at(
        &self,
        height: Height,
        hash: BlockHash,
        bip34_ancestor: Option<BlockHash>,
    ) -> Rules {
        if bip34_ancestor.is_some() {
            assert!(height > self.buried.bip34.height);
        }
        let buried = &self.buried;

        // Core's order: the exception list replaces the always-on set, then the buried
        // deployments add their flags. Block 692261 therefore has DERSIG and NULLDUMMY even
        // though its exception entry names only P2SH and WITNESS.
        let mut script_flags = self.script_flags_base(hash);
        if height >= buried.bip66 {
            script_flags = script_flags.union(ScriptFlags::DERSIG);
        }
        if height >= buried.bip65 {
            script_flags = script_flags.union(ScriptFlags::CHECKLOCKTIMEVERIFY);
        }
        if height >= buried.csv {
            script_flags = script_flags.union(ScriptFlags::CHECKSEQUENCEVERIFY);
        }
        if height >= buried.segwit {
            script_flags = script_flags.union(ScriptFlags::NULLDUMMY);
        }

        let rules = Rules {
            script_flags,
            version_floor: self.version_floor_at(height),
            bip34_active: height >= buried.bip34.height,
            csv_active: height >= buried.csv,
            segwit_active: height >= buried.segwit,
            bip30: self.bip30_at(height, hash, bip34_ancestor),
            subsidy: block_subsidy(height, self.halving_interval),
        };

        // Each derived field is paired with the flag it came from. BIP34 only implies the
        // floor: regtest may put BIP65 below BIP34, so the floor can be 4 with BIP34 off.
        assert_eq!(
            rules.script_flags.contains(ScriptFlags::NULLDUMMY),
            rules.segwit_active
        );
        assert_eq!(
            rules
                .script_flags
                .contains(ScriptFlags::CHECKSEQUENCEVERIFY),
            rules.csv_active
        );
        if rules.bip34_active {
            assert!(rules.version_floor >= 2);
        }
        assert!(rules.script_flags.is_subset_of(ScriptFlags::MANDATORY));
        rules
    }

    /// The always-on set, or the exception entry for this hash if there is one.
    fn script_flags_base(&self, hash: BlockHash) -> ScriptFlags {
        let bytes = hash.to_byte_array();
        let mut base = ALWAYS_ON_SCRIPT_FLAGS;
        let mut matched = 0;
        // Bounded by the constructor: at most SCRIPT_FLAG_EXCEPTIONS_MAX entries.
        for exception in self.script_flag_exceptions {
            if exception.hash == bytes {
                base = exception.flags;
                matched += 1;
            }
        }
        assert!(matched <= 1);
        base
    }

    /// `ContextualCheckBlockHeader` rejects `nVersion < 2` from BIP34, `< 3` from BIP66 and
    /// `< 4` from BIP65, each on its own height. Regtest may order those heights any way it
    /// likes, so the floor is the largest that applies, not the last that activated.
    fn version_floor_at(&self, height: Height) -> i32 {
        let buried = &self.buried;
        let mut floor = 1;
        if height >= buried.bip34.height {
            floor = 2;
        }
        if height >= buried.bip66 {
            floor = 3;
        }
        if height >= buried.bip65 {
            floor = 4;
        }
        assert!(floor >= 1);
        assert!(floor <= 4);
        floor
    }

    /// Core's `ConnectBlock`: `fEnforceBIP30 = !IsBIP30Repeat(block)`, then cleared when the
    /// ancestor at the BIP34 height is the BIP34 block, then forced back on from
    /// [`BIP34_IMPLIES_BIP30_LIMIT`]. A repeat block is the one case where the scan is off
    /// and a coin does get overwritten.
    fn bip30_at(
        &self,
        height: Height,
        hash: BlockHash,
        bip34_ancestor: Option<BlockHash>,
    ) -> Bip30 {
        let bytes = hash.to_byte_array();
        let mut is_repeat_exception = false;
        // Bounded by the constructor: at most BIP30_REPEAT_EXCEPTIONS_MAX entries.
        for exception in self.bip30_repeat_exceptions {
            if exception.height == height && exception.hash == bytes {
                is_repeat_exception = true;
            }
        }

        let bip34_block_is_ancestor = match (self.buried.bip34.hash, bip34_ancestor) {
            (Some(expected), Some(actual)) => expected == actual.to_byte_array(),
            _ => false,
        };
        if bip34_block_is_ancestor {
            assert!(height > self.buried.bip34.height);
        }

        if is_repeat_exception {
            // Both repeat blocks predate BIP34, let alone the limit.
            assert!(!bip34_block_is_ancestor);
            assert!(height < BIP34_IMPLIES_BIP30_LIMIT);
            return Bip30::Overwrite;
        }
        if bip34_block_is_ancestor && height < BIP34_IMPLIES_BIP30_LIMIT {
            return Bip30::Skip;
        }
        Bip30::Enforce
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;

    use super::super::{ChainParams, Height, RegtestOverrides, ScriptFlags};
    use super::{BIP34_IMPLIES_BIP30_LIMIT, Bip30, COIN, HALVINGS_MAX, block_subsidy};

    fn hash(hex: &str) -> BlockHash {
        hex.parse().unwrap()
    }

    /// A hash no exception table contains.
    fn ordinary() -> BlockHash {
        BlockHash::from_byte_array([0x11; 32])
    }

    const BIP34_BLOCK: &str = "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8";
    const P2SH_EXCEPTION: &str = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22";
    const TAPROOT_EXCEPTION: &str =
        "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad";
    const BIP30_REPEAT_91842: &str =
        "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec";
    const BIP30_REPEAT_91880: &str =
        "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721";

    const ALWAYS_ON: ScriptFlags = ScriptFlags::P2SH
        .union(ScriptFlags::WITNESS)
        .union(ScriptFlags::TAPROOT);

    /// Mainnet's flags at each buried height and the block before it. The ancestor is the
    /// BIP34 block wherever the height allows, as the node would pass it.
    #[test]
    fn mainnet_flags_switch_on_at_each_buried_height() {
        let params = ChainParams::mainnet();
        let bip34 = Some(hash(BIP34_BLOCK));
        let at = |height: u32, ancestor: Option<BlockHash>| {
            params
                .rules_at(Height::new(height), ordinary(), ancestor)
                .script_flags()
        };

        assert_eq!(at(0, None), ALWAYS_ON);
        assert_eq!(at(227_930, None), ALWAYS_ON);
        assert_eq!(at(227_931, None), ALWAYS_ON);
        assert_eq!(at(363_724, bip34), ALWAYS_ON);
        let dersig = ALWAYS_ON.union(ScriptFlags::DERSIG);
        assert_eq!(at(363_725, bip34), dersig);
        assert_eq!(at(388_380, bip34), dersig);
        let cltv = dersig.union(ScriptFlags::CHECKLOCKTIMEVERIFY);
        assert_eq!(at(388_381, bip34), cltv);
        assert_eq!(at(419_327, bip34), cltv);
        let csv = cltv.union(ScriptFlags::CHECKSEQUENCEVERIFY);
        assert_eq!(at(419_328, bip34), csv);
        assert_eq!(at(481_823, bip34), csv);
        assert_eq!(at(481_824, bip34), ScriptFlags::MANDATORY);
        assert_eq!(at(1_000_000, bip34), ScriptFlags::MANDATORY);
    }

    #[test]
    fn mainnet_activations_follow_the_heights() {
        let params = ChainParams::mainnet();
        let bip34 = Some(hash(BIP34_BLOCK));

        let before_bip34 = params.rules_at(Height::new(227_930), ordinary(), None);
        assert!(!before_bip34.bip34_active());
        assert_eq!(before_bip34.version_floor(), 1);

        let at_bip34 = params.rules_at(Height::new(227_931), ordinary(), None);
        assert!(at_bip34.bip34_active());
        assert_eq!(at_bip34.version_floor(), 2);
        assert!(!at_bip34.csv_active());
        assert!(!at_bip34.segwit_active());

        assert_eq!(
            params
                .rules_at(Height::new(363_725), ordinary(), bip34)
                .version_floor(),
            3
        );
        assert_eq!(
            params
                .rules_at(Height::new(388_380), ordinary(), bip34)
                .version_floor(),
            3
        );
        assert_eq!(
            params
                .rules_at(Height::new(388_381), ordinary(), bip34)
                .version_floor(),
            4
        );

        let at_csv = params.rules_at(Height::new(419_328), ordinary(), bip34);
        assert!(at_csv.csv_active());
        assert!(!at_csv.segwit_active());

        let at_segwit = params.rules_at(Height::new(481_824), ordinary(), bip34);
        assert!(at_segwit.segwit_active());
        assert!(
            !params
                .rules_at(Height::new(481_823), ordinary(), bip34)
                .segwit_active()
        );
    }

    /// Block 170060 predates every buried height, so its exception leaves nothing at all.
    #[test]
    fn p2sh_exception_block_has_no_flags() {
        let params = ChainParams::mainnet();
        let rules = params.rules_at(Height::new(170_060), hash(P2SH_EXCEPTION), None);
        assert_eq!(rules.script_flags(), ScriptFlags::NONE);
        assert!(rules.bip30_check_required());
    }

    /// Block 692261 is above every buried height: the exception drops TAPROOT, and the
    /// height-gated flags are added back on top, as Core does.
    #[test]
    fn taproot_exception_block_keeps_the_height_gated_flags() {
        let params = ChainParams::mainnet();
        let rules = params.rules_at(
            Height::new(692_261),
            hash(TAPROOT_EXCEPTION),
            Some(hash(BIP34_BLOCK)),
        );
        let expected = ScriptFlags::P2SH
            .union(ScriptFlags::WITNESS)
            .union(ScriptFlags::DERSIG)
            .union(ScriptFlags::CHECKLOCKTIMEVERIFY)
            .union(ScriptFlags::CHECKSEQUENCEVERIFY)
            .union(ScriptFlags::NULLDUMMY);
        assert_eq!(rules.script_flags(), expected);
        assert!(!rules.script_flags().contains(ScriptFlags::TAPROOT));
        assert!(!rules.bip30_check_required());
    }

    /// Core keys the exceptions by hash alone, so the same hash at another height would get
    /// the same base. Only a fork could produce that; the test pins the semantics.
    #[test]
    fn exceptions_are_keyed_by_hash_not_height() {
        let params = ChainParams::mainnet();
        let rules = params.rules_at(Height::new(1), hash(P2SH_EXCEPTION), None);
        assert_eq!(rules.script_flags(), ScriptFlags::NONE);
    }

    #[test]
    fn bip30_window_edges_on_mainnet() {
        let params = ChainParams::mainnet();
        let bip34 = Some(hash(BIP34_BLOCK));
        let required = |height: u32, ancestor: Option<BlockHash>| {
            params
                .rules_at(Height::new(height), ordinary(), ancestor)
                .bip30_check_required()
        };

        // Below and at the BIP34 height the ancestor does not exist yet: always scan.
        assert!(required(0, None));
        assert!(required(227_930, None));
        assert!(required(227_931, None));
        // Above it, the scan is skipped only when the ancestor is the BIP34 block.
        assert!(!required(227_932, bip34));
        assert!(required(227_932, Some(ordinary())));
        assert!(required(227_932, None));
        // Until the limit, where it resumes for good.
        assert!(!required(BIP34_IMPLIES_BIP30_LIMIT.get() - 1, bip34));
        assert!(required(BIP34_IMPLIES_BIP30_LIMIT.get(), bip34));
        assert!(required(5_000_000, bip34));
    }

    /// The three states, at the heights that pick them: enforce before BIP34 and from the
    /// limit on, skip in between on the BIP34 chain, overwrite at the two repeat blocks.
    #[test]
    fn bip30_has_three_states() {
        let params = ChainParams::mainnet();
        let bip34 = Some(hash(BIP34_BLOCK));
        let at = |height: u32, block: BlockHash, ancestor: Option<BlockHash>| {
            params
                .rules_at(Height::new(height), block, ancestor)
                .bip30()
        };
        assert_eq!(at(91_841, ordinary(), None), Bip30::Enforce);
        assert_eq!(at(91_842, hash(BIP30_REPEAT_91842), None), Bip30::Overwrite);
        assert_eq!(at(91_880, hash(BIP30_REPEAT_91880), None), Bip30::Overwrite);
        assert_eq!(at(227_931, ordinary(), None), Bip30::Enforce);
        assert_eq!(at(227_932, ordinary(), bip34), Bip30::Skip);
        assert_eq!(at(227_932, ordinary(), Some(ordinary())), Bip30::Enforce);
        assert_eq!(at(1_983_701, ordinary(), bip34), Bip30::Skip);
        assert_eq!(at(1_983_702, ordinary(), bip34), Bip30::Enforce);
        let regtest = ChainParams::regtest(RegtestOverrides::default());
        assert_eq!(
            regtest
                .rules_at(Height::new(91_842), hash(BIP30_REPEAT_91842), None)
                .bip30(),
            Bip30::Enforce
        );
    }

    /// Core's `TestBlockSubsidyHalvings` for mainnet, regtest and one more interval, and
    /// `subsidy_limit_test`: the sum over the schedule is the 20,999,999.9769 BTC that will
    /// ever exist.
    #[test]
    fn block_subsidy_halves_on_schedule_and_sums_below_max_money() {
        for interval in [210_000, 150, 1_000] {
            let initial = 50 * COIN;
            let mut previous = initial * 2;
            for halvings in 0..HALVINGS_MAX {
                let subsidy = block_subsidy(Height::new(halvings * interval), interval);
                assert!(subsidy <= initial);
                assert_eq!(subsidy, previous / 2, "{interval} {halvings}");
                previous = subsidy;
            }
            assert_eq!(
                block_subsidy(Height::new(HALVINGS_MAX * interval), interval),
                0
            );
        }
        let mainnet = ChainParams::mainnet();
        let mut sum: u64 = 0;
        for height in (0..14_000_000).step_by(1_000) {
            let subsidy = block_subsidy(Height::new(height), mainnet.halving_interval());
            assert!(subsidy <= 50 * COIN);
            sum += subsidy * 1_000;
            assert!(sum <= 21_000_000 * COIN);
        }
        assert_eq!(sum, 2_099_999_997_690_000);
        assert_eq!(
            mainnet
                .rules_at(Height::new(840_000), ordinary(), Some(hash(BIP34_BLOCK)))
                .subsidy(),
            312_500_000
        );
        assert_eq!(
            ChainParams::regtest(RegtestOverrides::default())
                .rules_at(Height::new(150), ordinary(), None)
                .subsidy(),
            25 * COIN
        );
    }

    #[test]
    fn bip30_repeat_blocks_skip_the_scan() {
        let params = ChainParams::mainnet();
        let repeat_91842 = params.rules_at(Height::new(91_842), hash(BIP30_REPEAT_91842), None);
        assert!(!repeat_91842.bip30_check_required());
        let repeat_91880 = params.rules_at(Height::new(91_880), hash(BIP30_REPEAT_91880), None);
        assert!(!repeat_91880.bip30_check_required());

        // Height and hash must both match.
        assert!(
            params
                .rules_at(Height::new(91_842), ordinary(), None)
                .bip30_check_required()
        );
        assert!(
            params
                .rules_at(Height::new(91_843), hash(BIP30_REPEAT_91842), None)
                .bip30_check_required()
        );
    }

    /// Regtest has no BIP34 hash, so whatever the node reports as the ancestor, the scan
    /// runs. The same holds for signet.
    #[test]
    fn regtest_never_skips_bip30() {
        let params = ChainParams::regtest(RegtestOverrides::default());
        assert!(
            params
                .rules_at(Height::new(0), ordinary(), None)
                .bip30_check_required()
        );
        assert!(
            params
                .rules_at(Height::new(5), ordinary(), Some(ordinary()))
                .bip30_check_required()
        );
        assert!(
            params
                .rules_at(Height::new(5), ordinary(), Some(hash(BIP34_BLOCK)))
                .bip30_check_required()
        );
        assert!(
            params
                .rules_at(Height::new(2_000_000), ordinary(), Some(ordinary()))
                .bip30_check_required()
        );
    }

    /// Core's regtest: segwit from genesis, everything else from height 1.
    #[test]
    fn regtest_defaults() {
        let params = ChainParams::regtest(RegtestOverrides::default());

        let genesis = params.rules_at(Height::GENESIS, params.genesis_hash(), None);
        assert_eq!(
            genesis.script_flags(),
            ALWAYS_ON.union(ScriptFlags::NULLDUMMY)
        );
        assert!(genesis.segwit_active());
        assert!(!genesis.bip34_active());
        assert!(!genesis.csv_active());
        assert_eq!(genesis.version_floor(), 1);

        let first = params.rules_at(Height::new(1), ordinary(), None);
        assert_eq!(first.script_flags(), ScriptFlags::MANDATORY);
        assert!(first.bip34_active());
        assert!(first.csv_active());
        assert_eq!(first.version_floor(), 4);
    }

    /// The harness moves segwit to exercise pre-activation rules; NULLDUMMY moves with it.
    #[test]
    fn regtest_override_moves_an_activation() {
        let overrides = RegtestOverrides {
            segwit: Some(Height::new(10)),
            ..RegtestOverrides::default()
        };
        let params = ChainParams::regtest(overrides);

        let before = params.rules_at(Height::new(9), ordinary(), Some(ordinary()));
        assert!(!before.segwit_active());
        assert!(!before.script_flags().contains(ScriptFlags::NULLDUMMY));
        assert!(before.script_flags().contains(ScriptFlags::TAPROOT));

        let after = params.rules_at(Height::new(10), ordinary(), Some(ordinary()));
        assert!(after.segwit_active());
        assert_eq!(after.script_flags(), ScriptFlags::MANDATORY);
    }

    /// With BIP65 moved below BIP34, a block between them must still carry version 4: the
    /// floor is the largest applicable, not the most recent.
    #[test]
    fn regtest_version_floor_is_the_largest_applicable() {
        let overrides = RegtestOverrides {
            bip34: Some(Height::new(100)),
            bip66: Some(Height::new(200)),
            bip65: Some(Height::new(1)),
            ..RegtestOverrides::default()
        };
        let params = ChainParams::regtest(overrides);
        let rules = params.rules_at(Height::new(50), ordinary(), None);
        assert_eq!(rules.version_floor(), 4);
        assert!(!rules.bip34_active());
        assert!(
            rules
                .script_flags()
                .contains(ScriptFlags::CHECKLOCKTIMEVERIFY)
        );
        assert!(!rules.script_flags().contains(ScriptFlags::DERSIG));
    }

    #[test]
    #[should_panic(expected = "height > self.buried.bip34.height")]
    fn an_ancestor_below_the_bip34_height_is_a_node_bug() {
        let params = ChainParams::mainnet();
        let _unreachable =
            params.rules_at(Height::new(227_931), ordinary(), Some(hash(BIP34_BLOCK)));
    }
}
