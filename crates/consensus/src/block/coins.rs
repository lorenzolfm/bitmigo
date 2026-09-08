// SPDX-License-Identifier: MIT OR Apache-2.0

//! The coins path: the three stages that run in chain order, once the block is next on the
//! most-work chain, and produce the [`BlockDelta`] storage applies (BM-D1 decisions 1, 2,
//! 10).
//!
//! The crate never looks a coin up. [`populate`] reads the block alone and tells the node,
//! input by input, what to fetch: nothing for an output created earlier in the same block,
//! otherwise the coin, and for an input under a BIP68 time lock also the median time past
//! the lock is measured from. The node answers with a [`Prefetch`]. [`confirm`] is Core's
//! `ConnectBlock` minus the scripts, in Core's order: BIP30, then per transaction
//! `CheckTxInputs`, the fee, BIP68 and the signature operation budget, then the coinbase
//! amount; it returns the delta. [`connect`] is the scripts, a bounded loop over
//! `verify_input` with one `TxPrecomputed` per transaction (BM-D2 decision 4), so the node
//! can fan it out later without an API change.
//!
//! A missing coin is a verdict, not a lookup failure: the node reports what its store holds
//! and the crate decides what that means for the block.

use core::fmt;

use bitcoin::{Block, BlockHash, OutPoint, Transaction, TxOut, Txid};

use crate::header::Context;
use crate::params::{Bip30, BlockTime, Height};
use crate::script::{ScriptError, TxPrecomputed, verify_input};
use crate::tx::{
    Coin, MAX_BLOCK_SIGOPS_COST, MAX_MONEY, RelativeLockBase, SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_TYPE_FLAG, TxInputsError, bip68_applies, check_tx_inputs, is_unspendable,
    sequence_locks_satisfied, sigop_cost, value_out,
};

/// A block's base size limit, `MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR`, as the `usize`
/// the counts below are measured in; the tests tie the two together.
const BLOCK_BASE_SIZE_MAX: usize = 1_000_000;
/// The smallest serialized input, bytes: outpoint, empty `scriptSig`, sequence.
const TX_IN_SIZE_MIN: usize = 36 + 1 + 4;
/// The smallest serialized output, bytes: value and an empty script.
const TX_OUT_SIZE_MIN: usize = 8 + 1;

/// More inputs than fit a block's base size (§2.1): the bound on every loop over inputs.
pub const MAX_BLOCK_INPUTS: usize = BLOCK_BASE_SIZE_MAX / TX_IN_SIZE_MIN;
/// More outputs than fit a block's base size: the bound on every loop over outputs.
pub const MAX_BLOCK_OUTPUTS: usize = BLOCK_BASE_SIZE_MAX / TX_OUT_SIZE_MIN;

/// Where one input's coin comes from, and so what the node fetches before [`confirm`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InputSource {
    /// A spendable output of transaction `tx_index` of this block, earlier than the
    /// spending one. Nothing to fetch: the node passes `None` and `confirm` resolves it.
    InBlock {
        /// The creating transaction's index in the block.
        tx_index: usize,
    },
    /// A coin of an earlier block, or nothing: the node fetches whatever unspent coin its
    /// store holds at the outpoint.
    Chain {
        /// The input carries a BIP68 time lock, so the node also fetches the median time
        /// past of the block before the coin's ([`RelativeLockBase`]).
        time_locked: bool,
    },
}

/// What the node fetched for one input the block spends from the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputCoin {
    /// The unspent coin at the input's outpoint.
    pub coin: Coin,
    /// The median time past of the block at `coin.height - 1`, when [`populate`] flagged
    /// the input as time-locked; `None` otherwise.
    pub median_time_past: Option<BlockTime>,
}

/// The node's answers to [`populate`]: everything [`confirm`] reads beyond the block.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Prefetch {
    /// One entry per input of every transaction but the coinbase, in block order: the
    /// coin the store holds at the outpoint, or `None` when it holds none or the input's
    /// [`InputSource`] is `InBlock`.
    pub spent: Vec<Option<InputCoin>>,
    /// The unspent coins the store holds at this block's own outpoints, for BIP30. Looked
    /// up for every output of every transaction when the block's [`Bip30`] state is
    /// `Enforce` or `Overwrite`; left empty under `Skip`.
    pub existing: Vec<Coin>,
}

/// What connecting a block changes in the UTXO set: the storage unit (BM-D1 decision 10).
/// A net change: an output created and spent inside the block appears in neither list, so
/// `spent` and `created` never share an outpoint and storage applies the delta as two set
/// operations in either order, deleting `spent` and `overwritten`, inserting `created`.
/// Undo is `spent` and `overwritten` verbatim; disconnecting is the same type swapped,
/// `created` deleted and the other two inserted. The `muhash` update is the same lists.
///
/// Core's undo also records the in-block spends, because `DisconnectBlock` walks the
/// transactions one by one; a delta over the set has no use for them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDelta {
    /// The connected block's height: the new tip.
    pub height: Height,
    /// The connected block's hash: the new tip.
    pub hash: BlockHash,
    /// The coins of earlier blocks this block spends, in block order.
    pub spent: Vec<Coin>,
    /// The coins the coinbase overwrote, with their old height: non-empty only at mainnet
    /// 91842 and 91880 (§2.5). Core's undo forgets these; carrying them makes a disconnect
    /// exact.
    pub overwritten: Vec<Coin>,
    /// The spendable outputs the block created and did not spend itself, in block order,
    /// at this height.
    pub created: Vec<Coin>,
}

/// What [`confirm`] hands back: the delta for storage, and the coins for [`connect`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmed {
    /// What the block changes in the UTXO set.
    pub delta: BlockDelta,
    /// The coin behind every input of every transaction but the coinbase, in block order,
    /// the block's own outputs included: exactly what [`connect`] verifies against.
    pub prevouts: Vec<Coin>,
}

/// Why [`confirm`] refused a block, in the vocabulary of Core's reject reasons; `Display`
/// gives the reason string. The fields are the evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfirmError {
    /// `bad-txns-BIP30`: an output of the block already exists unspent.
    Bip30 {
        /// The outpoint that exists.
        outpoint: OutPoint,
    },
    /// `bad-txns-inputs-missingorspent`: an input spends nothing the set or the block
    /// holds, or something spent earlier in the block.
    InputsMissingOrSpent {
        /// The transaction's index in the block.
        index: usize,
        /// The input's index.
        input: usize,
    },
    /// A transaction failed [`check_tx_inputs`]; the reason string is the transaction's.
    Inputs {
        /// The transaction's index in the block.
        index: usize,
        /// Why.
        error: TxInputsError,
    },
    /// `bad-txns-accumulated-fee-outofrange`: the block's fees sum above `MAX_MONEY`.
    AccumulatedFeeOutOfRange {
        /// The transaction whose fee took the sum over.
        index: usize,
    },
    /// `bad-txns-nonfinal`: a transaction's BIP68 relative locks are not satisfied.
    SequenceLocked {
        /// The transaction's index in the block.
        index: usize,
    },
    /// `bad-blk-sigops`: the signature operation cost, coins counted, exceeds the budget.
    BadSigOps {
        /// The running cost after the transaction that took it over.
        cost: u64,
    },
    /// `bad-cb-amount`: the coinbase pays more than the subsidy plus the fees.
    BadCoinbaseAmount {
        /// What the coinbase pays.
        paid: u64,
        /// The most it may pay.
        allowed: u64,
    },
}

impl fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inputs { error, .. } => error.fmt(f),
            Self::Bip30 { .. } => f.write_str("bad-txns-BIP30"),
            Self::InputsMissingOrSpent { .. } => f.write_str("bad-txns-inputs-missingorspent"),
            Self::AccumulatedFeeOutOfRange { .. } => {
                f.write_str("bad-txns-accumulated-fee-outofrange")
            }
            Self::SequenceLocked { .. } => f.write_str("bad-txns-nonfinal"),
            Self::BadSigOps { .. } => f.write_str("bad-blk-sigops"),
            Self::BadCoinbaseAmount { .. } => f.write_str("bad-cb-amount"),
        }
    }
}

impl std::error::Error for ConfirmError {}

/// Why [`connect`] refused a block: the first input whose scripts fail. `Display` gives
/// Core's `block-script-verify-flag-failed`, with the error named as the vectors name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectError {
    /// The transaction's index in the block.
    pub index: usize,
    /// The input's index.
    pub input: usize,
    /// Why the scripts failed.
    pub error: ScriptError,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "block-script-verify-flag-failed ({})", self.error)
    }
}

impl std::error::Error for ConnectError {}

/// The transactions of a block by txid, for resolving spends of outputs created in it. A
/// txid that repeats maps to its first position: the second copy fails on its own inputs.
struct TxidIndex {
    /// Sorted by txid, one entry per distinct txid.
    entries: Vec<(Txid, usize)>,
}

impl TxidIndex {
    fn new(block: &Block) -> TxidIndex {
        assert!(!block.txdata.is_empty());
        let mut entries: Vec<(Txid, usize)> = block
            .txdata
            .iter()
            .enumerate()
            .map(|(index, tx)| (tx.compute_txid(), index))
            .collect();
        entries.sort_unstable();
        entries.dedup_by_key(|entry| entry.0);
        assert!(entries.len() <= block.txdata.len());
        TxidIndex { entries }
    }

    fn position(&self, txid: Txid) -> Option<usize> {
        let found = self
            .entries
            .binary_search_by_key(&txid, |entry| entry.0)
            .ok()?;
        assert!(found < self.entries.len());
        let entry = self.entries.get(found)?;
        assert_eq!(entry.0, txid);
        Some(entry.1)
    }
}

/// The spendable output `outpoint` names, if a transaction before `spender` created it in
/// this block: what Core's view holds of the block so far when `spender` is checked. An
/// unspendable output is never in the view, and neither is one of a later transaction.
fn in_block_output<'a>(
    block: &'a Block,
    txids: &TxidIndex,
    spender: usize,
    outpoint: OutPoint,
) -> Option<(usize, &'a TxOut)> {
    let creator = txids.position(outpoint.txid)?;
    if creator >= spender {
        return None;
    }
    assert!(
        creator < block.txdata.len(),
        "the index was built from this block"
    );
    let tx = block.txdata.get(creator)?;
    let output = tx.output.get(usize::try_from(outpoint.vout).ok()?)?;
    if is_unspendable(&output.script_pubkey) {
        return None;
    }
    Some((creator, output))
}

/// The inputs of every transaction but the coinbase: the length of `Prefetch::spent`.
fn input_count(block: &Block) -> usize {
    let count: usize = block.txdata.iter().skip(1).map(|tx| tx.input.len()).sum();
    assert!(
        count <= MAX_BLOCK_INPUTS,
        "check_block passed: the base size bounds the inputs"
    );
    count
}

/// Core's `CTxIn` reading of `nSequence`: a relative lock in time, not blocks.
fn is_time_locked(sequence: u32) -> bool {
    sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG == 0 && sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0
}

/// libbitcoin's `populate`: for every input of every transaction but the coinbase, in
/// block order, where its coin comes from. Runs after `check_block`; bounded by the
/// block's input count.
#[must_use]
pub fn populate(block: &Block) -> Vec<InputSource> {
    let coinbase = block
        .txdata
        .first()
        .expect("check_block passed: a coinbase first");
    assert!(coinbase.is_coinbase());
    let txids = TxidIndex::new(block);
    let mut sources = Vec::with_capacity(input_count(block));
    for (index, tx) in block.txdata.iter().enumerate().skip(1) {
        assert!(!tx.is_coinbase());
        let bip68 = bip68_applies(tx);
        for input in &tx.input {
            let source = match in_block_output(block, &txids, index, input.previous_output) {
                Some((tx_index, _)) => InputSource::InBlock { tx_index },
                None => InputSource::Chain {
                    time_locked: bip68 && is_time_locked(input.sequence.to_consensus_u32()),
                },
            };
            sources.push(source);
        }
    }
    assert_eq!(sources.len(), input_count(block));
    sources
}

/// Core's `ConnectBlock` without the scripts, in its order, over the block, the node's
/// [`Prefetch`] and the [`Context`]: BIP30 over every output; then per transaction, in
/// block order, the inputs resolved against the set and the block so far, `CheckTxInputs`,
/// the fee total, BIP68, the signature operation budget; then the coinbase amount against
/// the subsidy plus the fees (§2.3, §2.5, §2.7, §3.1). Returns the [`BlockDelta`] and the
/// coins [`connect`] needs.
///
/// Runs after `check_block` and `accept_block` have passed; never for genesis, whose
/// coinbase is not spendable and which has no `Context`.
pub fn confirm(
    block: &Block,
    prefetch: &Prefetch,
    context: &Context,
) -> Result<Confirmed, ConfirmError> {
    let coinbase = block
        .txdata
        .first()
        .expect("check_block passed: a coinbase first");
    assert!(coinbase.is_coinbase());
    let input_count = input_count(block);
    assert_eq!(
        prefetch.spent.len(),
        input_count,
        "one entry per input, as populate said"
    );
    let txids = TxidIndex::new(block);

    let overwritten = check_bip30(block, &txids, &prefetch.existing, context.rules().bip30())?;

    let mut confirmed = Confirmed {
        delta: BlockDelta {
            height: context.height(),
            hash: block.block_hash(),
            spent: Vec::with_capacity(input_count),
            overwritten,
            created: Vec::new(),
        },
        prevouts: Vec::with_capacity(input_count),
    };
    let mut view = BlockView {
        block,
        txids,
        spent: std::collections::BTreeSet::new(),
    };
    let mut fees: u64 = 0;
    let mut sigop_cost_total: u64 = 0;
    let mut next_entry = 0;
    for (index, tx) in block.txdata.iter().enumerate() {
        let entries = prefetch
            .spent
            .get(next_entry..next_entry + tx.input.len() * usize::from(index > 0))
            .expect("prefetch.spent.len() == input_count");
        next_entry += entries.len();

        let mut outputs: Vec<TxOut> = Vec::with_capacity(entries.len());
        if index > 0 {
            let resolved = view.resolve(index, tx, entries, context)?;
            fees += confirm_inputs(index, tx, &resolved, context, fees)?;
            outputs.extend(resolved.iter().map(|input| input.coin.output.clone()));
            for input in resolved {
                if !input.in_block {
                    confirmed.delta.spent.push(input.coin.clone());
                }
                confirmed.prevouts.push(input.coin);
            }
        }
        sigop_cost_total += sigop_cost(tx, &outputs, context.rules().script_flags());
        if sigop_cost_total > MAX_BLOCK_SIGOPS_COST {
            return Err(ConfirmError::BadSigOps {
                cost: sigop_cost_total,
            });
        }
        add_created(&mut confirmed.delta.created, tx, index, context.height());
    }
    assert_eq!(next_entry, input_count);
    assert_eq!(confirmed.prevouts.len(), input_count);

    let paid = value_out(coinbase);
    let allowed = fees + context.rules().subsidy();
    if paid > allowed {
        return Err(ConfirmError::BadCoinbaseAmount { paid, allowed });
    }
    view.net(&mut confirmed.delta);
    Ok(confirmed)
}

/// The per-transaction rules between the inputs being resolved and the signature
/// operations: `CheckTxInputs`, the fee against the running total, BIP68. Returns the fee.
fn confirm_inputs(
    index: usize,
    tx: &Transaction,
    resolved: &[ResolvedInput],
    context: &Context,
    fees_so_far: u64,
) -> Result<u64, ConfirmError> {
    assert!(index > 0);
    assert_eq!(resolved.len(), tx.input.len());
    let coins: Vec<Coin> = resolved.iter().map(|input| input.coin.clone()).collect();
    let fee = check_tx_inputs(tx, &coins, context.height())
        .map_err(|error| ConfirmError::Inputs { index, error })?;
    // Both terms are at most MAX_MONEY, so the sum cannot overflow.
    assert!(fees_so_far <= MAX_MONEY);
    if fees_so_far + fee > MAX_MONEY {
        return Err(ConfirmError::AccumulatedFeeOutOfRange { index });
    }
    let bases: Vec<RelativeLockBase> = resolved.iter().map(|input| input.base).collect();
    if !sequence_locks_satisfied(tx, &bases, context) {
        return Err(ConfirmError::SequenceLocked { index });
    }
    Ok(fee)
}

/// BIP30 as `ConnectBlock` applies it, before any transaction: under `Enforce` an existing
/// coin at any of the block's outpoints refuses the block; under `Overwrite` the existing
/// coins are the coinbase's to overwrite; under `Skip` the node did not look. Returns the
/// overwritten coins (§2.5).
fn check_bip30(
    block: &Block,
    txids: &TxidIndex,
    existing: &[Coin],
    bip30: Bip30,
) -> Result<Vec<Coin>, ConfirmError> {
    assert!(existing.len() <= MAX_BLOCK_OUTPUTS);
    let mut seen = std::collections::BTreeSet::new();
    for coin in existing {
        // The node reports facts about this block's outputs; anything else is its bug.
        let creator = txids
            .position(coin.outpoint.txid)
            .expect("an existing coin sits at one of the block's own outpoints");
        let tx = block.txdata.get(creator).expect("an index of the block");
        assert!(usize::try_from(coin.outpoint.vout).is_ok_and(|vout| vout < tx.output.len()));
        assert!(
            seen.insert(coin.outpoint),
            "an existing coin is reported once"
        );
        match bip30 {
            Bip30::Enforce => {
                return Err(ConfirmError::Bip30 {
                    outpoint: coin.outpoint,
                });
            }
            // Core's `AddCoin` throws on overwriting an unspent coin that is not a
            // coinbase's; the two repeat blocks only overwrite coinbase outputs.
            Bip30::Overwrite if creator > 0 => {
                return Err(ConfirmError::Bip30 {
                    outpoint: coin.outpoint,
                });
            }
            Bip30::Overwrite => {}
            Bip30::Skip => panic!("the node looked up outputs where Core skips the scan"),
        }
    }
    if bip30 == Bip30::Overwrite {
        assert_eq!(seen.len(), existing.len());
        return Ok(existing.to_vec());
    }
    Ok(Vec::new())
}

/// Core's view of the block so far: what the block created and what it spent, before the
/// transaction being checked. Backed by the node's prefetch for everything older.
struct BlockView<'a> {
    block: &'a Block,
    txids: TxidIndex,
    /// Every outpoint spent by an earlier transaction of the block, bounded by the input
    /// count.
    spent: std::collections::BTreeSet<OutPoint>,
}

/// One input as the view resolved it.
struct ResolvedInput {
    coin: Coin,
    base: RelativeLockBase,
    /// The coin is an output of this block: not in the set, so not in the delta.
    in_block: bool,
}

impl BlockView<'_> {
    /// Core's `HaveInputs` and the `prevheights` gathering, for transaction `index`: the
    /// coin behind every input, from the block or from the prefetch, none of them spent
    /// earlier in the block; and what each input's relative lock is measured from.
    fn resolve(
        &mut self,
        index: usize,
        tx: &Transaction,
        entries: &[Option<InputCoin>],
        context: &Context,
    ) -> Result<Vec<ResolvedInput>, ConfirmError> {
        assert!(index > 0);
        assert_eq!(entries.len(), tx.input.len());
        let mut resolved = Vec::with_capacity(tx.input.len());
        for (input, (txin, entry)) in tx.input.iter().zip(entries).enumerate() {
            let outpoint = txin.previous_output;
            let missing = ConfirmError::InputsMissingOrSpent { index, input };
            let (coin, median_time_past, in_block) = if let Some((creator, output)) =
                in_block_output(self.block, &self.txids, index, outpoint)
            {
                assert!(entry.is_none(), "populate said InBlock: nothing to fetch");
                let coin = Coin {
                    outpoint,
                    output: output.clone(),
                    height: context.height(),
                    coinbase: creator == 0,
                };
                // The block before this one: the coin's height minus one.
                (coin, Some(context.median_time_past()), true)
            } else {
                let Some(fetched) = entry else {
                    return Err(missing);
                };
                assert_eq!(
                    fetched.coin.outpoint, outpoint,
                    "the prefetch is in input order"
                );
                (fetched.coin.clone(), fetched.median_time_past, false)
            };
            if !self.spent.insert(outpoint) {
                return Err(missing);
            }
            resolved.push(ResolvedInput {
                base: RelativeLockBase {
                    height: coin.height,
                    median_time_past,
                },
                coin,
                in_block,
            });
        }
        assert_eq!(resolved.len(), tx.input.len());
        Ok(resolved)
    }

    /// Drops from `created` what the block spent itself, leaving the net change, and
    /// asserts the two lists share no outpoint. A chain coin at one of the block's own
    /// outpoints is a BIP30 duplicate that `Skip` let through: Core's `AddCoin` throws
    /// there, and so does this.
    fn net(&self, delta: &mut BlockDelta) {
        let before = delta.created.len();
        delta
            .created
            .retain(|coin| !self.spent.contains(&coin.outpoint));
        assert!(delta.created.len() <= before);
        assert!(delta.created.len() <= MAX_BLOCK_OUTPUTS);
        for coin in &delta.spent {
            assert!(
                self.txids.position(coin.outpoint.txid).is_none(),
                "a spent coin cannot share an outpoint with a created one"
            );
        }
    }
}

/// Core's `AddCoins`: every spendable output of `tx` becomes a coin at `height`.
fn add_created(created: &mut Vec<Coin>, tx: &Transaction, index: usize, height: Height) {
    let txid = tx.compute_txid();
    let coinbase = index == 0;
    assert_eq!(coinbase, tx.is_coinbase());
    for (vout, output) in tx.output.iter().enumerate() {
        if is_unspendable(&output.script_pubkey) {
            continue;
        }
        created.push(Coin {
            outpoint: OutPoint {
                txid,
                vout: u32::try_from(vout).expect("check_tx passed: outputs fit a block"),
            },
            output: output.clone(),
            height,
            coinbase,
        });
    }
}

/// The scripts: Core's `CheckInputScripts` for every transaction but the coinbase, one
/// `TxPrecomputed` per transaction and `verify_input` per input under the block's flags,
/// the first failure winning. `prevouts` is [`Confirmed::prevouts`]: one coin per input, in
/// block order. Nothing else happens here, so the node may run it wherever it likes.
pub fn connect(block: &Block, prevouts: &[Coin], context: &Context) -> Result<(), ConnectError> {
    let coinbase = block
        .txdata
        .first()
        .expect("check_block passed: a coinbase first");
    assert!(coinbase.is_coinbase());
    assert_eq!(prevouts.len(), input_count(block), "one coin per input");
    let flags = context.rules().script_flags();
    let mut next_coin = 0;
    for (index, tx) in block.txdata.iter().enumerate().skip(1) {
        assert!(!tx.is_coinbase());
        let coins = prevouts
            .get(next_coin..next_coin + tx.input.len())
            .expect("prevouts.len() == input_count");
        next_coin += coins.len();
        let outputs: Vec<TxOut> = tx
            .input
            .iter()
            .zip(coins)
            .map(|(input, coin)| {
                assert_eq!(
                    coin.outpoint, input.previous_output,
                    "the coins are in input order"
                );
                coin.output.clone()
            })
            .collect();
        let precomputed = TxPrecomputed::new(tx, &outputs);
        for input in 0..tx.input.len() {
            verify_input(tx, input, &outputs, &precomputed, flags).map_err(|error| {
                ConnectError {
                    index,
                    input,
                    error,
                }
            })?;
        }
    }
    assert_eq!(next_coin, prevouts.len());
    Ok(())
}
