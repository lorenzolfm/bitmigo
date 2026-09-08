// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the coins path: bitcoind's regtest blocks connected end to end from a coin
//! store built out of the fixture itself, Core's `tx_valid.json` and `tx_invalid.json`
//! through `confirm` and `connect`, and one mutation of a real block per rule.

#![allow(
    clippy::indexing_slicing,
    reason = "test fixtures index arrays and vectors whose lengths the tests assert"
)]

use std::collections::BTreeMap;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use super::tests::{Fixture, context, context_at, fixture, regtest};
use super::{
    BlockDelta, ConfirmError, Confirmed, ConnectError, InputCoin, InputSource, MAX_BLOCK_INPUTS,
    MAX_BLOCK_OUTPUTS, Prefetch, confirm, connect, populate,
};
use crate::header::Context;
use crate::params::{Bip30, BlockTime, ChainParams, Height, RegtestOverrides};
use crate::script::vectors::{CORE_TX_INVALID_JSON, CORE_TX_VALID_JSON, Json, parse_tx_row};
use crate::script::{ScriptError, ScriptFlags, push_encoding};
use crate::tx::{
    Coin, MAX_BLOCK_WEIGHT, MAX_MONEY, SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
    TxInputsError, WITNESS_SCALE_FACTOR, check_tx, value_out,
};

const BIP34_BLOCK: &str = "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8";
const BIP30_REPEAT_91842: &str = "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec";

/// What the node's chainstate would hold: the coins by outpoint, and the median time past
/// of every block it has seen, for BIP68 time locks.
struct Store {
    coins: BTreeMap<OutPoint, Coin>,
    median_time_past: BTreeMap<Height, BlockTime>,
}

impl Store {
    fn new(rows: &[Fixture]) -> Store {
        let mut median_time_past = BTreeMap::new();
        for row in rows {
            if row.height > 0 {
                let previous = Height::new(row.height - 1);
                median_time_past.insert(previous, row.previous_median_time_past);
            }
        }
        Store {
            coins: BTreeMap::new(),
            median_time_past,
        }
    }

    /// The node's side of `populate`: fetch what it asked for, and the block's own
    /// outputs where BIP30 wants them looked up.
    fn prefetch(&self, block: &Block, sources: &[InputSource], bip30: Bip30) -> Prefetch {
        let mut spent = Vec::new();
        let inputs = block.txdata.iter().skip(1).flat_map(|tx| tx.input.iter());
        for (input, source) in inputs.zip(sources) {
            let fetched = match source {
                InputSource::InBlock { .. } => None,
                InputSource::Chain { time_locked } => {
                    self.coins
                        .get(&input.previous_output)
                        .map(|coin| InputCoin {
                            coin: coin.clone(),
                            median_time_past: time_locked.then(|| {
                                let before = Height::new(coin.height.get() - 1);
                                *self
                                    .median_time_past
                                    .get(&before)
                                    .expect("a fixture height")
                            }),
                        })
                }
            };
            spent.push(fetched);
        }
        let mut existing = Vec::new();
        if bip30 != Bip30::Skip {
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                for vout in 0..u32::try_from(tx.output.len()).unwrap() {
                    if let Some(coin) = self.coins.get(&OutPoint { txid, vout }) {
                        existing.push(coin.clone());
                    }
                }
            }
        }
        Prefetch { spent, existing }
    }

    /// Storage's side of the delta: spent and overwritten out, created in.
    fn apply(&mut self, delta: &BlockDelta) {
        for coin in delta.spent.iter().chain(&delta.overwritten) {
            assert_eq!(self.coins.remove(&coin.outpoint).as_ref(), Some(coin));
        }
        for coin in &delta.created {
            assert!(self.coins.insert(coin.outpoint, coin.clone()).is_none());
        }
    }

    /// The same type swapped: created out, spent and overwritten back in.
    fn unapply(&mut self, delta: &BlockDelta) {
        for coin in &delta.created {
            assert_eq!(self.coins.remove(&coin.outpoint).as_ref(), Some(coin));
        }
        for coin in delta.spent.iter().chain(&delta.overwritten) {
            assert!(self.coins.insert(coin.outpoint, coin.clone()).is_none());
        }
    }

    fn total_value(&self) -> u64 {
        self.coins
            .values()
            .map(|coin| coin.output.value.to_sat())
            .sum()
    }
}

/// Runs the three stages on `row` at `height` against `store`, without applying.
fn run(
    params: &ChainParams,
    store: &Store,
    row: &Fixture,
    height: u32,
) -> Result<Confirmed, ConfirmError> {
    let context = context_at(params, row, height);
    let sources = populate(&row.block);
    let prefetch = store.prefetch(&row.block, &sources, context.rules().bip30());
    confirm(&row.block, &prefetch, &context)
}

/// The store after connecting every fixture block below `height`.
fn store_below(rows: &[Fixture], height: u32) -> Store {
    let params = regtest();
    let mut store = Store::new(rows);
    for row in rows
        .iter()
        .filter(|row| row.height > 0 && row.height < height)
    {
        let confirmed = run(&params, &store, row, row.height).unwrap();
        store.apply(&confirmed.delta);
    }
    store
}

fn with_block(row: &Fixture, block: Block) -> Fixture {
    Fixture { block, ..*row }
}

/// Points every later input that spent transaction `index` under its old txid at its new
/// one, so a mutation of that transaction does not orphan the block's in-block chain.
fn relink(block: &mut Block, index: usize, old_txid: Txid) {
    let new_txid = block.txdata[index].compute_txid();
    for tx in block.txdata.iter_mut().skip(index + 1) {
        for input in &mut tx.input {
            if input.previous_output.txid == old_txid {
                input.previous_output.txid = new_txid;
            }
        }
    }
}

/// The bounds are the block's base size over the smallest input and output.
#[test]
fn bounds_follow_from_the_block_size() {
    assert_eq!(MAX_BLOCK_INPUTS, 24_390);
    assert_eq!(MAX_BLOCK_OUTPUTS, 111_111);
    let base_size_max = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR;
    assert_eq!(u64::try_from(MAX_BLOCK_INPUTS).unwrap(), base_size_max / 41);
    assert_eq!(u64::try_from(MAX_BLOCK_OUTPUTS).unwrap(), base_size_max / 9);
}

/// Block 102 is bitcoind's own in-block chain: the wallet spent the height-1 coinbase, then
/// its change, then that change again, all in one block. Blocks 103 and 104 spend coins of
/// earlier blocks; 104's first input carries the disable flag and no lock.
#[test]
fn populate_reads_the_block_alone() {
    let rows = fixture();
    let chain = InputSource::Chain { time_locked: false };
    assert_eq!(populate(&rows[1].block), vec![]);
    assert_eq!(
        populate(&rows[3].block),
        vec![
            chain,
            InputSource::InBlock { tx_index: 1 },
            InputSource::InBlock { tx_index: 1 },
            InputSource::InBlock { tx_index: 2 },
            InputSource::InBlock { tx_index: 2 },
        ]
    );
    assert_eq!(populate(&rows[4].block), vec![chain]);
    assert_eq!(populate(&rows[5].block), vec![chain, chain]);

    // A time lock is flagged from the sequence and the version alone.
    let mut block = rows[5].block.clone();
    block.txdata[1].input[0].sequence = Sequence::from_consensus(SEQUENCE_LOCKTIME_TYPE_FLAG | 1);
    let time_locked = InputSource::Chain { time_locked: true };
    assert_eq!(populate(&block), vec![time_locked, chain]);
    block.txdata[1].version = Version::ONE;
    assert_eq!(populate(&block), vec![chain, chain]);
    block.txdata[1].version = Version::TWO;
    block.txdata[1].input[0].sequence =
        Sequence::from_consensus(SEQUENCE_LOCKTIME_DISABLE_FLAG | SEQUENCE_LOCKTIME_TYPE_FLAG | 1);
    assert_eq!(populate(&block), vec![chain, chain]);

    // An output created later in the block, or an unspendable one, is not in the block.
    let mut block = rows[3].block.clone();
    block.txdata.swap(2, 3);
    assert_eq!(populate(&block)[0..3], [chain, chain, chain]);
    let mut block = rows[3].block.clone();
    let commitment = OutPoint {
        txid: block.txdata[0].compute_txid(),
        vout: 1,
    };
    block.txdata[3].input[0].previous_output = commitment;
    assert_eq!(populate(&block)[3], chain);
}

/// Every bitcoind block from height 1 confirms and connects against the store the earlier
/// ones built, the deltas describe exactly the net change, and unapplying them in reverse
/// empties the store again.
#[test]
fn bitcoind_blocks_confirm_and_connect_from_their_own_coins() {
    let rows = fixture();
    let params = regtest();
    let mut store = Store::new(&rows);
    let mut deltas = Vec::new();
    for row in rows.iter().skip(1) {
        let context = context(&params, row);
        let confirmed = run(&params, &store, row, row.height).unwrap();
        let delta = confirmed.delta;
        assert_eq!(delta.height, Height::new(row.height));
        assert_eq!(delta.hash, row.hash);
        assert_eq!(delta.overwritten, vec![]);
        assert_eq!(
            connect(&row.block, &confirmed.prevouts, &context),
            Ok(()),
            "{}",
            row.height
        );
        store.apply(&delta);
        deltas.push((delta, confirmed.prevouts));
    }

    // Block 102: the height-1 coinbase in and four in-block coins for `connect`; the
    // delta nets those out, leaving the coinbase spent and three outputs created (the
    // OP_RETURN commitment is never a coin); the fees are what the coinbase claims.
    let (delta_102, prevouts_102) = &deltas[2];
    assert_eq!(prevouts_102.len(), 5);
    assert_eq!(prevouts_102[0].height, Height::new(1));
    assert!(prevouts_102[0].coinbase);
    for coin in &prevouts_102[1..] {
        assert_eq!(coin.height, Height::new(102));
        assert!(!coin.coinbase);
    }
    assert_eq!(delta_102.spent, vec![prevouts_102[0].clone()]);
    assert_eq!(delta_102.created.len(), 3);
    assert!(delta_102.created[0].coinbase);
    assert_eq!(delta_102.created[0].outpoint.vout, 0);
    assert_eq!(
        delta_102.created[1].outpoint.txid,
        rows[3].block.txdata[3].compute_txid()
    );
    let fees = |delta: &BlockDelta| {
        let spent: u64 = delta
            .spent
            .iter()
            .map(|coin| coin.output.value.to_sat())
            .sum();
        let created: u64 = delta
            .created
            .iter()
            .filter(|coin| !coin.coinbase)
            .map(|coin| coin.output.value.to_sat())
            .sum();
        spent - created
    };
    assert_eq!(fees(delta_102), 7_690);
    assert_eq!(fees(&deltas[3].0), 1_770);
    assert_eq!(fees(&deltas[4].0), 4_219_990_540);
    assert_eq!(fees(&deltas[5].0), 0);
    assert_eq!(deltas[4].1.len(), 2);
    assert_eq!(deltas[4].0.spent, deltas[4].1);

    // Six coinbases minus the one spent, plus the unspent change: every satoshi accounted.
    assert_eq!(store.coins.len(), 9);
    assert_eq!(store.total_value(), 6 * 50 * 100_000_000);

    for (delta, _) in deltas.iter().rev() {
        store.unapply(delta);
    }
    assert!(store.coins.is_empty());
}

#[test]
fn confirm_refuses_missing_and_spent_inputs() {
    let rows = fixture();
    let params = regtest();
    let store = store_below(&rows, 102);
    let row = &rows[3];

    // The store lost the coin.
    let context = context(&params, row);
    let mut prefetch = store.prefetch(&row.block, &populate(&row.block), Bip30::Enforce);
    prefetch.spent[0] = None;
    assert_eq!(
        confirm(&row.block, &prefetch, &context),
        Err(ConfirmError::InputsMissingOrSpent { index: 1, input: 0 })
    );

    // An in-block coin spent twice: transaction 3 takes what transaction 2 already spent.
    let mut block = row.block.clone();
    block.txdata[3].input[0].previous_output = block.txdata[2].input[0].previous_output;
    assert_eq!(
        run(&params, &store, &with_block(row, block), 102),
        Err(ConfirmError::InputsMissingOrSpent { index: 3, input: 0 })
    );

    // A spend of an output created later in the block: not in the view yet.
    let mut block = row.block.clone();
    block.txdata.swap(2, 3);
    assert_eq!(
        run(&params, &store, &with_block(row, block), 102),
        Err(ConfirmError::InputsMissingOrSpent { index: 2, input: 0 })
    );

    // A spend of the coinbase's OP_RETURN output: never a coin.
    let mut block = row.block.clone();
    block.txdata[3].input[0].previous_output = OutPoint {
        txid: block.txdata[0].compute_txid(),
        vout: 1,
    };
    assert_eq!(
        run(&params, &store, &with_block(row, block), 102),
        Err(ConfirmError::InputsMissingOrSpent { index: 3, input: 0 })
    );

    // A chain coin spent twice in one block.
    let store = store_below(&rows, 104);
    let row = &rows[5];
    let mut block = row.block.clone();
    block.txdata[2].input[0].previous_output = block.txdata[1].input[0].previous_output;
    assert_eq!(
        run(&params, &store, &with_block(row, block), 104),
        Err(ConfirmError::InputsMissingOrSpent { index: 2, input: 0 })
    );
}

/// The height-1 coinbase is 99 deep at height 100 and 100 deep at 101; a block's own
/// coinbase is 0 deep.
#[test]
fn confirm_enforces_coinbase_maturity() {
    let rows = fixture();
    let params = regtest();
    let store = store_below(&rows, 102);
    let row = &rows[3];
    assert_eq!(
        run(&params, &store, row, 100),
        Err(ConfirmError::Inputs {
            index: 1,
            error: TxInputsError::PrematureCoinbaseSpend {
                input: 0,
                depth: 99
            }
        })
    );
    assert!(run(&params, &store, row, 101).is_ok());

    let mut block = row.block.clone();
    block.txdata[1].input[0].previous_output = OutPoint {
        txid: block.txdata[0].compute_txid(),
        vout: 0,
    };
    assert_eq!(populate(&block)[0], InputSource::InBlock { tx_index: 0 });
    assert_eq!(
        run(&params, &store, &with_block(row, block), 102),
        Err(ConfirmError::Inputs {
            index: 1,
            error: TxInputsError::PrematureCoinbaseSpend { input: 0, depth: 0 }
        })
    );
}

#[test]
fn confirm_bounds_values_fees_and_the_coinbase() {
    let rows = fixture();
    let params = regtest();
    let store = store_below(&rows, 102);
    let row = &rows[3];
    let context_102 = context(&params, row);

    // A coin the store reports above MAX_MONEY.
    let mut prefetch = store.prefetch(&row.block, &populate(&row.block), Bip30::Enforce);
    prefetch.spent[0].as_mut().unwrap().coin.output.value = Amount::from_sat(MAX_MONEY + 1);
    assert_eq!(
        confirm(&row.block, &prefetch, &context_102),
        Err(ConfirmError::Inputs {
            index: 1,
            error: TxInputsError::InputValuesOutOfRange { input: 0 }
        })
    );

    // Outputs above the inputs.
    let mut block = row.block.clone();
    block.txdata[1].output[0].value = Amount::from_sat(5_000_000_000);
    assert_eq!(
        run(&params, &store, &with_block(row, block), 102),
        Err(ConfirmError::Inputs {
            index: 1,
            error: TxInputsError::InBelowOut {
                value_in: 5_000_000_000,
                value_out: 5_100_000_000
            }
        })
    );

    // The coinbase claims one satoshi too many; and at height 150 the subsidy has halved.
    let mut block = row.block.clone();
    block.txdata[0].output[0].value = Amount::from_sat(5_000_007_691);
    assert_eq!(
        run(&params, &store, &with_block(row, block), 102),
        Err(ConfirmError::BadCoinbaseAmount {
            paid: 5_000_007_691,
            allowed: 5_000_007_690
        })
    );
    assert_eq!(
        run(&params, &store, row, 150),
        Err(ConfirmError::BadCoinbaseAmount {
            paid: 5_000_007_690,
            allowed: 2_500_007_690
        })
    );

    // Two fees that are each in range but sum above MAX_MONEY.
    let store = store_below(&rows, 104);
    let row = &rows[5];
    let context_104 = context(&params, row);
    let mut prefetch = store.prefetch(&row.block, &populate(&row.block), Bip30::Enforce);
    for fetched in prefetch.spent.iter_mut().flatten() {
        fetched.coin.output.value = Amount::from_sat(MAX_MONEY);
    }
    assert_eq!(
        confirm(&row.block, &prefetch, &context_104),
        Err(ConfirmError::AccumulatedFeeOutOfRange { index: 2 })
    );
}

/// A mainnet context for the fixture's coinbase-only block 105 at `height`, on a chain
/// whose block at the BIP34 height is `ancestor`.
fn mainnet_context(row: &Fixture, height: u32, hash: &str, ancestor: Option<&str>) -> Context {
    let hash: BlockHash = hash.parse().unwrap();
    let ancestor = ancestor.map(|hash| hash.parse().unwrap());
    Context::new(
        Height::new(height),
        row.previous_median_time_past,
        row.previous_time,
        row.block.header.bits,
        ChainParams::mainnet().rules_at(Height::new(height), hash, ancestor),
    )
}

/// The coin the fixture's block 105 coinbase would overwrite, had it been mined in 2010.
fn coin_under_coinbase(row: &Fixture) -> Coin {
    Coin {
        outpoint: OutPoint {
            txid: row.block.txdata[0].compute_txid(),
            vout: 0,
        },
        output: row.block.txdata[0].output[0].clone(),
        height: Height::new(91_722),
        coinbase: true,
    }
}

/// Under `Enforce` a reported coin refuses the block; at mainnet 91842 the same coin is
/// overwritten: it leaves in the delta, the new one arrives, and a store applying and
/// unapplying the delta ends where it began.
#[test]
fn confirm_enforces_bip30_and_overwrites_at_the_repeat_blocks() {
    let rows = fixture();
    let params = regtest();
    let row = &rows[6];
    let existing = coin_under_coinbase(row);
    let prefetch = Prefetch {
        spent: vec![],
        existing: vec![existing.clone()],
    };

    let enforce = context(&params, row);
    assert_eq!(enforce.rules().bip30(), Bip30::Enforce);
    assert_eq!(
        confirm(&row.block, &prefetch, &enforce),
        Err(ConfirmError::Bip30 {
            outpoint: existing.outpoint
        })
    );

    let overwrite = mainnet_context(row, 91_842, BIP30_REPEAT_91842, None);
    assert_eq!(overwrite.rules().bip30(), Bip30::Overwrite);
    let confirmed = confirm(&row.block, &prefetch, &overwrite).unwrap();
    let delta = confirmed.delta;
    assert_eq!(delta.overwritten, vec![existing.clone()]);
    assert_eq!(delta.created.len(), 1);
    assert_eq!(delta.created[0].outpoint, existing.outpoint);
    assert_eq!(delta.created[0].height, Height::new(91_842));
    assert_eq!(delta.spent, vec![]);
    assert_eq!(confirmed.prevouts, vec![]);
    let mut store = Store::new(&rows);
    store.coins.insert(existing.outpoint, existing.clone());
    store.apply(&delta);
    assert_eq!(store.coins.get(&existing.outpoint), Some(&delta.created[0]));
    store.unapply(&delta);
    assert_eq!(store.coins.get(&existing.outpoint), Some(&existing));
}

/// Even at a repeat block only the coinbase may overwrite; and between BIP34 and the
/// limit, with nothing reported, the block confirms. The fixture coinbase claims the
/// regtest subsidy, so it is trimmed to mainnet's halved one there.
#[test]
fn confirm_limits_bip30_overwrites_to_the_coinbase_and_skips_after_bip34() {
    let rows = fixture();
    let store = store_below(&rows, 104);
    let row = &rows[5];
    let overwrite = mainnet_context(row, 91_842, BIP30_REPEAT_91842, None);
    let mut prefetch = store.prefetch(&row.block, &populate(&row.block), Bip30::Enforce);
    let spend_outpoint = OutPoint {
        txid: row.block.txdata[1].compute_txid(),
        vout: 0,
    };
    prefetch.existing.push(Coin {
        outpoint: spend_outpoint,
        output: row.block.txdata[1].output[0].clone(),
        height: Height::new(50),
        coinbase: false,
    });
    assert_eq!(
        confirm(&row.block, &prefetch, &overwrite),
        Err(ConfirmError::Bip30 {
            outpoint: spend_outpoint
        })
    );

    let row = &rows[6];
    let ordinary = "1111111111111111111111111111111111111111111111111111111111111111";
    let skip = mainnet_context(row, 300_000, ordinary, Some(BIP34_BLOCK));
    assert_eq!(skip.rules().bip30(), Bip30::Skip);
    let mut halved = row.block.clone();
    halved.txdata[0].output[0].value = Amount::from_sat(2_500_000_000);
    assert_eq!(
        confirm(&halved, &Prefetch::default(), &skip).map(|_| ()),
        Ok(())
    );
}

#[test]
#[should_panic(expected = "Core skips the scan")]
fn confirm_refuses_a_lookup_where_core_skips_bip30() {
    let rows = fixture();
    let row = &rows[6];
    let ordinary = "1111111111111111111111111111111111111111111111111111111111111111";
    let skip = mainnet_context(row, 300_000, ordinary, Some(BIP34_BLOCK));
    let prefetch = Prefetch {
        spent: vec![],
        existing: vec![coin_under_coinbase(row)],
    };
    let _unreachable = confirm(&row.block, &prefetch, &skip);
}

/// BIP68 over real coins: an in-block coin sits at the block's own height, so any lock
/// fails; a coin from the previous block satisfies a one-block lock and not a two-block
/// one; a time lock measures from the median time past before the coin's block.
#[test]
fn confirm_enforces_bip68() {
    let rows = fixture();
    let params = regtest();
    let store = store_below(&rows, 102);
    let row = &rows[3];
    let locked = |sequence: u32, version: Version| {
        let mut block = row.block.clone();
        let old_txid = block.txdata[2].compute_txid();
        block.txdata[2].input[0].sequence = Sequence::from_consensus(sequence);
        block.txdata[2].version = version;
        relink(&mut block, 2, old_txid);
        with_block(row, block)
    };
    let outcome = |row: &Fixture, params: &ChainParams| run(params, &store, row, 102).map(|_| ());
    assert_eq!(
        outcome(&locked(1, Version::TWO), &params),
        Err(ConfirmError::SequenceLocked { index: 2 })
    );
    assert_eq!(
        outcome(
            &locked(SEQUENCE_LOCKTIME_TYPE_FLAG | 1, Version::TWO),
            &params
        ),
        Err(ConfirmError::SequenceLocked { index: 2 })
    );
    assert_eq!(
        outcome(
            &locked(SEQUENCE_LOCKTIME_DISABLE_FLAG | 1, Version::TWO),
            &params
        ),
        Ok(())
    );
    assert_eq!(outcome(&locked(1, Version::ONE), &params), Ok(()));
    let late_csv = ChainParams::regtest(RegtestOverrides {
        csv: Some(Height::new(1_000)),
        ..RegtestOverrides::default()
    });
    assert_eq!(outcome(&locked(1, Version::TWO), &late_csv), Ok(()));

    let store = store_below(&rows, 104);
    let row = &rows[5];
    let locked = |sequence: u32| {
        let mut block = row.block.clone();
        block.txdata[1].input[0].sequence = Sequence::from_consensus(sequence);
        with_block(row, block)
    };
    assert!(run(&params, &store, &locked(1), 104).is_ok());
    assert_eq!(
        run(&params, &store, &locked(2), 104),
        Err(ConfirmError::SequenceLocked { index: 1 })
    );
    // Block 102's median time past plus 511 seconds is past block 103's.
    assert_eq!(
        rows[4].previous_median_time_past,
        BlockTime::new(1_788_900_250)
    );
    assert_eq!(row.previous_median_time_past, BlockTime::new(1_788_900_251));
    assert_eq!(
        run(
            &params,
            &store,
            &locked(SEQUENCE_LOCKTIME_TYPE_FLAG | 1),
            104
        ),
        Err(ConfirmError::SequenceLocked { index: 1 })
    );
}

/// A P2SH input reveals its redeem script's sigops only with the coin: 20,000 of them fill
/// the budget exactly, one more is over it.
#[test]
fn confirm_counts_sigops_with_the_coins() {
    let rows = fixture();
    let params = regtest();
    let store = store_below(&rows, 104);
    let row = &rows[5];
    let redeem = |count: usize| {
        let mut block = row.block.clone();
        block.txdata[1].input[0].script_sig =
            ScriptBuf::from_bytes(push_encoding(&vec![0xac; count]));
        block.txdata[1].input[0].witness = Witness::new();
        with_block(row, block)
    };
    assert!(run(&params, &store, &redeem(20_000), 104).is_ok());
    assert_eq!(
        run(&params, &store, &redeem(20_001), 104),
        Err(ConfirmError::BadSigOps { cost: 80_004 })
    );
}

#[test]
fn connect_reports_the_first_failing_input() {
    let rows = fixture();
    let params = regtest();
    let store = store_below(&rows, 104);
    let row = &rows[5];
    let context = context(&params, row);
    let prevouts = run(&params, &store, row, 104).unwrap().prevouts;

    let mut block = row.block.clone();
    block.txdata[2].input[0].script_sig = ScriptBuf::new();
    assert_eq!(
        connect(&block, &prevouts, &context),
        Err(ConnectError {
            index: 2,
            input: 0,
            error: ScriptError::InvalidStackOperation
        })
    );
    let mut block = row.block.clone();
    let mut witness: Vec<Vec<u8>> = block.txdata[1].input[0].witness.to_vec();
    witness[0][10] ^= 0x01;
    block.txdata[1].input[0].witness = Witness::from_slice(&witness);
    assert_eq!(
        connect(&block, &prevouts, &context),
        Err(ConnectError {
            index: 1,
            input: 0,
            error: ScriptError::EvalFalse
        })
    );
}

/// The block Core's transaction vectors would sit in: a minimal coinbase and the row's
/// transaction, whose inputs the store holds as coins of height 1.
struct VectorBlock {
    block: Block,
    prefetch: Prefetch,
}

fn vector_block(tx: &Transaction, prevouts: &[TxOut]) -> VectorBlock {
    let amounts_given = prevouts.iter().any(|prevout| prevout.value.to_sat() > 0);
    let coinbase = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x51, 0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let spent = tx
        .input
        .iter()
        .zip(prevouts)
        .map(|(input, prevout)| {
            let mut output = prevout.clone();
            // The legacy rows carry no amounts; give each coin enough to pay the outputs.
            if !amounts_given {
                output.value = Amount::from_sat(value_out(tx));
            }
            Some(InputCoin {
                coin: Coin {
                    outpoint: input.previous_output,
                    output,
                    height: Height::new(1),
                    coinbase: false,
                },
                median_time_past: Some(BlockTime::new(0)),
            })
        })
        .collect();
    VectorBlock {
        block: Block {
            header: regtest().genesis().header,
            txdata: vec![coinbase, tx.clone()],
        },
        prefetch: Prefetch {
            spent,
            existing: vec![],
        },
    }
}

/// A context high enough that every relative lock a vector can carry is satisfied, under
/// the regtest rules with the deployments in `excluded` pushed above it.
fn vector_context(excluded: ScriptFlags) -> Context {
    const HEIGHT: u32 = 100_000;
    const OFF: u32 = 200_000;
    let off = |flag: ScriptFlags| excluded.contains(flag).then_some(Height::new(OFF));
    let params = ChainParams::regtest(RegtestOverrides {
        bip66: off(ScriptFlags::DERSIG),
        bip65: off(ScriptFlags::CHECKLOCKTIMEVERIFY),
        csv: off(ScriptFlags::CHECKSEQUENCEVERIFY),
        segwit: off(ScriptFlags::NULLDUMMY),
        ..RegtestOverrides::default()
    });
    let hash = BlockHash::from_byte_array([0x22; 32]);
    let rules = params.rules_at(Height::new(HEIGHT), hash, None);
    assert_eq!(
        rules.script_flags(),
        ScriptFlags::MANDATORY.difference(excluded)
    );
    Context::new(
        Height::new(HEIGHT),
        BlockTime::new(1_600_000_000),
        BlockTime::new(1_600_000_100),
        params.genesis().header.bits,
        rules,
    )
}

const ALWAYS_ON: ScriptFlags = ScriptFlags::P2SH
    .union(ScriptFlags::WITNESS)
    .union(ScriptFlags::TAPROOT);

/// Every `tx_valid.json` row confirms and connects on a regtest chain with the row's
/// excluded deployments pushed above the block. At v31.1 no row excludes an always-on
/// flag, which no chain could turn off, and every row's amounts cover its outputs.
#[test]
fn tx_valid_rows_confirm_and_connect() {
    let rows = Json::parse(CORE_TX_VALID_JSON);
    let (mut connected, mut coinbase) = (0, 0);
    for row in rows.as_array() {
        let Some(row) = parse_tx_row(row) else {
            continue;
        };
        if row.tx.is_coinbase() {
            coinbase += 1;
            continue;
        }
        let excluded = row.flags.consensus;
        assert_eq!(
            excluded.intersection(ALWAYS_ON),
            ScriptFlags::NONE,
            "{}",
            row.text
        );
        let context = vector_context(excluded);
        let vector = vector_block(&row.tx, &row.prevouts);
        let confirmed = confirm(&vector.block, &vector.prefetch, &context)
            .unwrap_or_else(|error| panic!("{error}: {}", row.text));
        assert_eq!(
            connect(&vector.block, &confirmed.prevouts, &context),
            Ok(()),
            "{}",
            row.text
        );
        connected += 1;
    }
    assert_eq!((connected, coinbase), (119, 2));
}

/// Every `tx_invalid.json` row that passes `check_tx` fails at `confirm` or at `connect`
/// under the full rule set. The nine `BADTX` rows never reach a block, and a row whose
/// listed flags include a policy one is invalid only under that policy.
#[test]
fn tx_invalid_rows_fail_confirm_or_connect() {
    let rows = Json::parse(CORE_TX_INVALID_JSON);
    let (mut confirm_refused, mut connect_refused, mut bad_tx, mut policy) = (0, 0, 0, 0);
    for row in rows.as_array() {
        let cells = row.as_array();
        if cells[0].is_array() && cells[2] == Json::Str("BADTX".into()) {
            bad_tx += 1;
            continue;
        }
        let Some(row) = parse_tx_row(row) else {
            continue;
        };
        assert_eq!(check_tx(&row.tx), Ok(()), "{}", row.text);
        assert!(!row.tx.is_coinbase(), "{}", row.text);
        if !row.flags.policy.is_empty() {
            policy += 1;
            continue;
        }
        let context = vector_context(ScriptFlags::NONE);
        let vector = vector_block(&row.tx, &row.prevouts);
        match confirm(&vector.block, &vector.prefetch, &context) {
            Ok(confirmed) => {
                assert!(
                    connect(&vector.block, &confirmed.prevouts, &context).is_err(),
                    "{}",
                    row.text
                );
                connect_refused += 1;
            }
            Err(_) => confirm_refused += 1,
        }
    }
    assert_eq!(
        (confirm_refused, connect_refused, bad_tx, policy),
        (0, 70, 9, 14)
    );
}

#[test]
#[should_panic(expected = "one entry per input")]
fn confirm_with_a_short_prefetch_is_a_bug() {
    let rows = fixture();
    let params = regtest();
    let row = &rows[3];
    let _unreachable = confirm(&row.block, &Prefetch::default(), &context(&params, row));
}

#[test]
#[should_panic(expected = "populate said InBlock")]
fn confirm_with_a_fetched_in_block_coin_is_a_bug() {
    let rows = fixture();
    let params = regtest();
    let store = store_below(&rows, 102);
    let row = &rows[3];
    let mut prefetch = store.prefetch(&row.block, &populate(&row.block), Bip30::Enforce);
    prefetch.spent[1] = prefetch.spent[0].clone();
    let _unreachable = confirm(&row.block, &prefetch, &context(&params, row));
}

#[test]
#[should_panic(expected = "one of the block's own outpoints")]
fn confirm_with_a_foreign_existing_coin_is_a_bug() {
    let rows = fixture();
    let params = regtest();
    let row = &rows[6];
    let prefetch = Prefetch {
        spent: vec![],
        existing: vec![Coin {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([0x33; 32]),
                vout: 0,
            },
            output: row.block.txdata[0].output[0].clone(),
            height: Height::new(1),
            coinbase: true,
        }],
    };
    let _unreachable = confirm(&row.block, &prefetch, &context(&params, row));
}

#[test]
fn errors_display_cores_reject_reasons() {
    let outpoint = OutPoint::null();
    let cases = [
        (ConfirmError::Bip30 { outpoint }, "bad-txns-BIP30"),
        (
            ConfirmError::InputsMissingOrSpent { index: 1, input: 0 },
            "bad-txns-inputs-missingorspent",
        ),
        (
            ConfirmError::Inputs {
                index: 1,
                error: TxInputsError::PrematureCoinbaseSpend { input: 0, depth: 3 },
            },
            "bad-txns-premature-spend-of-coinbase",
        ),
        (
            ConfirmError::AccumulatedFeeOutOfRange { index: 1 },
            "bad-txns-accumulated-fee-outofrange",
        ),
        (
            ConfirmError::SequenceLocked { index: 1 },
            "bad-txns-nonfinal",
        ),
        (ConfirmError::BadSigOps { cost: 0 }, "bad-blk-sigops"),
        (
            ConfirmError::BadCoinbaseAmount {
                paid: 1,
                allowed: 0,
            },
            "bad-cb-amount",
        ),
    ];
    for (error, reason) in cases {
        assert_eq!(error.to_string(), reason);
    }
    let script = ConnectError {
        index: 1,
        input: 0,
        error: ScriptError::EvalFalse,
    };
    assert_eq!(
        script.to_string(),
        "block-script-verify-flag-failed (EVAL_FALSE)"
    );
}
