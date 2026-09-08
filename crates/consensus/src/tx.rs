// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction rules: Core's `CheckTransaction` as [`check_tx`], the finality predicate
//! `IsFinalTx` as [`is_final`], and the constants the block rules share with them (§2.1,
//! §2.2, §2.3, §3.1); then the rules that read the coins a transaction spends, each a
//! function of one transaction and exactly the facts about its inputs, handed over as a
//! [`Coin`] per input: `CheckTxInputs` as [`check_tx_inputs`], BIP68 as
//! [`sequence_locks_satisfied`], and `GetTransactionSigOpCost` as [`sigop_cost`]. The
//! block's coins path calls the second group once per transaction in block order; the
//! scripts are the `script` module's.

use core::fmt;

use bitcoin::consensus::encode::serialize;
use bitcoin::{OutPoint, Script, Transaction, TxOut};

use crate::header::Context;
use crate::params::{BlockTime, Height};
use crate::script::{
    MAX_SCRIPT_SIZE, ScriptFlags, SigOpMode, p2sh_sigop_count, sigop_count, witness_sigop_count,
};

/// Core's `WITNESS_SCALE_FACTOR`: a base byte weighs this many witness bytes (BIP141).
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// Core's `MAX_BLOCK_WEIGHT`: the block weight limit, and through the scale factor the
/// 1,000,000-byte limit on the base serialization of a block or a transaction (§2.1).
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Core's `MAX_BLOCK_SIGOPS_COST`: the signature operation budget of a block, in the units
/// `GetTransactionSigOpCost` reports, where one legacy sigop costs [`WITNESS_SCALE_FACTOR`].
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// Core's `MAX_MONEY`: 21,000,000 BTC in satoshis. Any output value or sum above it is
/// invalid (CVE-2010-5139).
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Core's `LOCKTIME_THRESHOLD`: an `nLockTime` below it is a block height, at or above it a
/// Unix time (§3.1).
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// A coinbase `scriptSig` is at least this long (§2.3).
pub const COINBASE_SCRIPT_SIG_SIZE_MIN: usize = 2;
/// A coinbase `scriptSig` is at most this long (§2.3).
pub const COINBASE_SCRIPT_SIG_SIZE_MAX: usize = 100;

/// Core's `CTxIn::SEQUENCE_FINAL`: an input with this `nSequence` opts out of `nLockTime`.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// Core's `COINBASE_MATURITY`: a coinbase output may be spent once this many blocks deep,
/// the spending block counted (§2.3).
pub const COINBASE_MATURITY: u32 = 100;

/// Core's `SEQUENCE_LOCKTIME_DISABLE_FLAG`: bit 31 of `nSequence` set means no relative
/// lock (BIP68).
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// Core's `SEQUENCE_LOCKTIME_TYPE_FLAG`: bit 22 set means the lock is in time, clear means
/// blocks (BIP68).
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// Core's `SEQUENCE_LOCKTIME_MASK`: the low sixteen bits carry the lock's value (BIP68).
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;
/// Core's `SEQUENCE_LOCKTIME_GRANULARITY`: a time lock counts in units of 512 seconds,
/// `value << 9` (BIP68).
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;

/// An unspent transaction output, with the facts the rules read about it: where it sits,
/// what it pays, which block created it and whether that was a coinbase. Core's `Coin`
/// plus its `COutPoint` key, because a coin here is a value the node hands the crate and
/// the crate hands back in a delta, and it must say what it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    /// The transaction and output index that created it.
    pub outpoint: OutPoint,
    /// The output: value and `scriptPubKey`.
    pub output: TxOut,
    /// The height of the block that created it.
    pub height: Height,
    /// Whether that block's coinbase created it, for maturity (§2.3).
    pub coinbase: bool,
}

impl Coin {
    /// The bytes the UTXO set hashes for this coin, Core's `TxOutSer`:
    /// `outpoint || u32 LE ((height << 1) | coinbase) || CTxOut` (§7). One encoder, so the
    /// live `muhash` and a `hash_serialized_3` cannot disagree about a coin.
    #[must_use]
    pub fn hash_record(&self) -> Vec<u8> {
        // A coin in the set is spendable: unspendable outputs are never added (§7).
        assert!(!is_unspendable(&self.output.script_pubkey));
        let code = (self.height.get() << 1) | u32::from(self.coinbase);
        assert_eq!(code >> 1, self.height.get());
        let outpoint = serialize(&self.outpoint);
        let output = serialize(&self.output);
        assert_eq!(outpoint.len(), 36);
        let mut record = Vec::with_capacity(outpoint.len() + 4 + output.len());
        record.extend_from_slice(&outpoint);
        record.extend_from_slice(&code.to_le_bytes());
        record.extend_from_slice(&output);
        assert_eq!(record.len(), 40 + output.len());
        record
    }
}

/// Core's `CScript::IsUnspendable`: a `scriptPubKey` that opens with `OP_RETURN` or is
/// longer than [`MAX_SCRIPT_SIZE`] can never be satisfied, so its output never enters the
/// UTXO set (§7).
#[must_use]
pub fn is_unspendable(script_pubkey: &Script) -> bool {
    const OP_RETURN: u8 = 0x6a;
    let bytes = script_pubkey.as_bytes();
    bytes.first() == Some(&OP_RETURN) || bytes.len() > MAX_SCRIPT_SIZE
}

/// Why `CheckTxInputs` refused a transaction, in the vocabulary of Core's reject reasons;
/// `Display` gives the reason string. The missing-or-spent case is the block's, because
/// only the block knows what was spent earlier in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxInputsError {
    /// `bad-txns-premature-spend-of-coinbase`: a coinbase output spent before
    /// [`COINBASE_MATURITY`].
    PrematureCoinbaseSpend {
        /// The input's index.
        input: usize,
        /// How deep the coinbase was, the spending block counted.
        depth: u32,
    },
    /// `bad-txns-inputvalues-outofrange`: an input value, or the running sum, above
    /// [`MAX_MONEY`].
    InputValuesOutOfRange {
        /// The input whose value took it out of range.
        input: usize,
    },
    /// `bad-txns-in-belowout`: the inputs pay less than the outputs.
    InBelowOut {
        /// The sum of the input values.
        value_in: u64,
        /// The sum of the output values.
        value_out: u64,
    },
}

impl fmt::Display for TxInputsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PrematureCoinbaseSpend { .. } => "bad-txns-premature-spend-of-coinbase",
            Self::InputValuesOutOfRange { .. } => "bad-txns-inputvalues-outofrange",
            Self::InBelowOut { .. } => "bad-txns-in-belowout",
        })
    }
}

impl std::error::Error for TxInputsError {}

/// Core's `CheckTxInputs` after `HaveInputs`, in its order: per input, coinbase maturity
/// then the value and running sum in range; then inputs at least the outputs (§2.3, §3.1).
/// Returns the fee. `coins` is one per input, in input order, the block having resolved
/// which exist; `spend_height` is the block's.
pub fn check_tx_inputs(
    tx: &Transaction,
    coins: &[Coin],
    spend_height: Height,
) -> Result<u64, TxInputsError> {
    assert!(!tx.is_coinbase());
    assert_eq!(coins.len(), tx.input.len(), "one coin per input");
    let mut value_in: u64 = 0;
    for (input, (txin, coin)) in tx.input.iter().zip(coins).enumerate() {
        assert_eq!(coin.outpoint, txin.previous_output);
        // A coin from a later block cannot be spent; one from this block has depth 0.
        assert!(coin.height <= spend_height);
        if coin.coinbase {
            let depth = spend_height.get() - coin.height.get();
            if depth < COINBASE_MATURITY {
                return Err(TxInputsError::PrematureCoinbaseSpend { input, depth });
            }
        }
        // Core adds first and then checks both terms; a value above MAX_MONEY, including
        // the top bit its signed CAmount would read as negative, fails either way.
        let value = coin.output.value.to_sat();
        if value > MAX_MONEY {
            return Err(TxInputsError::InputValuesOutOfRange { input });
        }
        // Both terms are at most MAX_MONEY, so the sum cannot overflow.
        value_in += value;
        if value_in > MAX_MONEY {
            return Err(TxInputsError::InputValuesOutOfRange { input });
        }
    }
    let value_out = value_out(tx);
    if value_in < value_out {
        return Err(TxInputsError::InBelowOut {
            value_in,
            value_out,
        });
    }
    let fee = value_in - value_out;
    // Core's `bad-txns-fee-outofrange` is unreachable, and says so: both sums are in range
    // and the difference is non-negative.
    assert!(fee <= MAX_MONEY);
    Ok(fee)
}

/// Core's `CTransaction::GetValueOut`: the sum of the output values, which [`check_tx`] has
/// already bounded.
#[must_use]
pub fn value_out(tx: &Transaction) -> u64 {
    let mut total: u64 = 0;
    for output in &tx.output {
        total += output.value.to_sat();
        assert!(total <= MAX_MONEY, "check_tx passed: outputs in MoneyRange");
    }
    total
}

/// What an input's relative lock is measured from (BIP68): the height of the block that
/// created the coin, and, for a time lock, the median time past of the block before that
/// one, which the node reads from its header tree. `None` when the input carries no time
/// lock; the coins path asserts it is present when one does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelativeLockBase {
    /// The coin's height: `Coin::height`, or the block's own for a coin created in it.
    pub height: Height,
    /// The median time past of the block at `height - 1`.
    pub median_time_past: Option<BlockTime>,
}

/// Core's `SequenceLocks`: `CalculateSequenceLocks` folded into `EvaluateSequenceLocks`.
/// Are every input's relative locks satisfied by the block `context` describes (BIP68)?
/// Always, before CSV or for a transaction below version 2, the version compared unsigned
/// as Core's `uint32_t` is. `bases` is one per input, in input order.
#[must_use]
pub fn sequence_locks_satisfied(
    tx: &Transaction,
    bases: &[RelativeLockBase],
    context: &Context,
) -> bool {
    assert_eq!(bases.len(), tx.input.len(), "one base per input");
    if !bip68_applies(tx) || !context.rules().csv_active() {
        return true;
    }
    // Core's `-1`: the lock is the last invalid height or time, so -1 means none.
    let mut height_min: i64 = -1;
    let mut time_min: i64 = -1;
    for (input, base) in tx.input.iter().zip(bases) {
        let sequence = input.sequence.to_consensus_u32();
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }
        let value = i64::from(sequence & SEQUENCE_LOCKTIME_MASK);
        assert!(value <= 0xffff);
        if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            let coin_time = base
                .median_time_past
                .expect("populate flagged the input as time-locked");
            let lock = i64::from(coin_time.get()) + (value << SEQUENCE_LOCKTIME_GRANULARITY) - 1;
            time_min = time_min.max(lock);
        } else {
            let lock = i64::from(base.height.get()) + value - 1;
            height_min = height_min.max(lock);
        }
    }
    let height = i64::from(context.height().get());
    let median_time_past = i64::from(context.median_time_past().get());
    height_min < height && time_min < median_time_past
}

/// BIP68 reads `nSequence` only on transactions of version 2 or more, the version compared
/// as the `uint32_t` Core stores, so a negative `i32` is a very large version.
#[must_use]
pub fn bip68_applies(tx: &Transaction) -> bool {
    tx.version.0.cast_unsigned() >= 2
}

/// Core's `GetTransactionSigOpCost`: the legacy count scaled, plus, for a spend, the P2SH
/// redeem script's count scaled when `P2SH` is in `flags`, plus the witness program's
/// unscaled count when `WITNESS` is (§2.2). `prevouts` is one per input, in input order,
/// and empty for a coinbase, whose inputs have none.
#[must_use]
pub fn sigop_cost(tx: &Transaction, prevouts: &[TxOut], flags: ScriptFlags) -> u64 {
    let mut cost = legacy_sigop_count(tx) * WITNESS_SCALE_FACTOR;
    if tx.is_coinbase() {
        assert!(prevouts.is_empty());
        return cost;
    }
    assert_eq!(prevouts.len(), tx.input.len(), "one prevout per input");
    for (input, prevout) in tx.input.iter().zip(prevouts) {
        let script_sig = input.script_sig.as_bytes();
        let script_pubkey = prevout.script_pubkey.as_bytes();
        if flags.contains(ScriptFlags::P2SH) {
            cost += u64::from(p2sh_sigop_count(script_pubkey, script_sig)) * WITNESS_SCALE_FACTOR;
        }
        cost += u64::from(witness_sigop_count(
            script_sig,
            script_pubkey,
            &input.witness,
            flags,
        ));
    }
    cost
}

/// Why `CheckTransaction` refused a transaction, in the vocabulary of Core's reject reasons;
/// `Display` gives the reason string. The fields are the evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxError {
    /// `bad-txns-vin-empty`: no inputs.
    VinEmpty,
    /// `bad-txns-vout-empty`: no outputs.
    VoutEmpty,
    /// `bad-txns-oversize`: the base serialization exceeds a block's.
    Oversize {
        /// The non-witness serialized size, bytes.
        base_size: u64,
    },
    /// `bad-txns-vout-negative`: an output value that Core's signed `CAmount` reads as
    /// negative, that is, one with the top bit set.
    VoutNegative {
        /// The output's index.
        index: usize,
    },
    /// `bad-txns-vout-toolarge`: an output value above [`MAX_MONEY`].
    VoutTooLarge {
        /// The output's index.
        index: usize,
    },
    /// `bad-txns-txouttotal-toolarge`: the running sum of output values left `MoneyRange`.
    TxOutTotalTooLarge {
        /// The index of the output whose value took the sum over.
        index: usize,
    },
    /// `bad-txns-inputs-duplicate`: two inputs spend the same outpoint (CVE-2018-17144).
    InputsDuplicate {
        /// The outpoint spent twice.
        outpoint: OutPoint,
    },
    /// `bad-cb-length`: a coinbase `scriptSig` outside 2..=100 bytes.
    CoinbaseLength {
        /// The `scriptSig` length seen.
        size: usize,
    },
    /// `bad-txns-prevout-null`: a null outpoint on a transaction that is not a coinbase.
    PrevoutNull {
        /// The input's index.
        index: usize,
    },
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::VinEmpty => "bad-txns-vin-empty",
            Self::VoutEmpty => "bad-txns-vout-empty",
            Self::Oversize { .. } => "bad-txns-oversize",
            Self::VoutNegative { .. } => "bad-txns-vout-negative",
            Self::VoutTooLarge { .. } => "bad-txns-vout-toolarge",
            Self::TxOutTotalTooLarge { .. } => "bad-txns-txouttotal-toolarge",
            Self::InputsDuplicate { .. } => "bad-txns-inputs-duplicate",
            Self::CoinbaseLength { .. } => "bad-cb-length",
            Self::PrevoutNull { .. } => "bad-txns-prevout-null",
        })
    }
}

impl std::error::Error for TxError {}

/// Core's `CheckTransaction`, in its order: shape, base size, output values, duplicate
/// inputs, then the coinbase `scriptSig` length or the null-prevout rule (§3.1). Context-free:
/// the block rules run it on every transaction of a block, coinbase included.
pub fn check_tx(tx: &Transaction) -> Result<(), TxError> {
    if tx.input.is_empty() {
        return Err(TxError::VinEmpty);
    }
    if tx.output.is_empty() {
        return Err(TxError::VoutEmpty);
    }
    // The witness is left out because it has not been checked for malleability yet; the
    // block's witness commitment does that.
    let base_size = base_size(tx);
    if base_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT {
        return Err(TxError::Oversize { base_size });
    }

    check_output_values(tx)?;
    check_inputs_distinct(tx)?;

    if tx.is_coinbase() {
        let script_sig = tx.input.first().expect("a coinbase has one input");
        let size = script_sig.script_sig.len();
        if !(COINBASE_SCRIPT_SIG_SIZE_MIN..=COINBASE_SCRIPT_SIG_SIZE_MAX).contains(&size) {
            return Err(TxError::CoinbaseLength { size });
        }
    } else {
        for (index, input) in tx.input.iter().enumerate() {
            if input.previous_output.is_null() {
                return Err(TxError::PrevoutNull { index });
            }
        }
    }
    Ok(())
}

/// The non-witness serialized size, as the 64-bit number the limit is compared in.
fn base_size(tx: &Transaction) -> u64 {
    u64::try_from(tx.base_size()).expect("usize fits u64")
}

/// Each output value and their running sum stay in `MoneyRange` (CVE-2010-5139). The value
/// is a `u64` here and an `int64_t` in Core, so a top bit set is Core's "negative" case.
fn check_output_values(tx: &Transaction) -> Result<(), TxError> {
    const SIGN_BIT: u64 = 1 << 63;
    assert!(!tx.output.is_empty());
    let mut total: u64 = 0;
    for (index, output) in tx.output.iter().enumerate() {
        let value = output.value.to_sat();
        if value & SIGN_BIT != 0 {
            return Err(TxError::VoutNegative { index });
        }
        if value > MAX_MONEY {
            return Err(TxError::VoutTooLarge { index });
        }
        // Both terms are at most MAX_MONEY, so the sum cannot overflow.
        total += value;
        if total > MAX_MONEY {
            return Err(TxError::TxOutTotalTooLarge { index });
        }
    }
    assert!(total <= MAX_MONEY);
    Ok(())
}

/// No two inputs spend the same outpoint (CVE-2018-17144). Sorting a copy is O(n log n) in
/// the input count, which the base size bounds at about 24,000.
fn check_inputs_distinct(tx: &Transaction) -> Result<(), TxError> {
    assert!(!tx.input.is_empty());
    let mut outpoints: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
    outpoints.sort_unstable();
    for pair in outpoints.windows(2) {
        if let [first, second] = pair {
            assert!(first <= second);
            if first == second {
                return Err(TxError::InputsDuplicate { outpoint: *first });
            }
        }
    }
    Ok(())
}

/// Core's `IsFinalTx`: may `tx` be included in the block at `height` whose lock-time cutoff
/// is `cutoff` (the block's own time, or the previous block's median time past once BIP113
/// applies)? A zero `nLockTime` is always final; otherwise the lock is a height below
/// [`LOCKTIME_THRESHOLD`] and a time at or above it, and it must be strictly below the
/// respective bound, unless every input carries [`SEQUENCE_FINAL`] (§3.1).
#[must_use]
pub fn is_final(tx: &Transaction, height: Height, cutoff: BlockTime) -> bool {
    let lock_time = tx.lock_time.to_consensus_u32();
    if lock_time == 0 {
        return true;
    }
    let bound = if lock_time < LOCKTIME_THRESHOLD {
        height.get()
    } else {
        cutoff.get()
    };
    if lock_time < bound {
        return true;
    }
    // Bounded by the input count.
    tx.input
        .iter()
        .all(|input| input.sequence.to_consensus_u32() == SEQUENCE_FINAL)
}

/// Core's `GetLegacySigOpCount`: the inaccurate count over every `scriptSig` and every
/// `scriptPubKey`, coinbase included (§2.2). Unscaled: the caller multiplies by
/// [`WITNESS_SCALE_FACTOR`] to compare with [`MAX_BLOCK_SIGOPS_COST`].
#[must_use]
pub fn legacy_sigop_count(tx: &Transaction) -> u64 {
    let mut count: u64 = 0;
    for input in &tx.input {
        count += u64::from(sigop_count(
            input.script_sig.as_bytes(),
            SigOpMode::Inaccurate,
        ));
    }
    for output in &tx.output {
        count += u64::from(sigop_count(
            output.script_pubkey.as_bytes(),
            SigOpMode::Inaccurate,
        ));
    }
    // At most one CHECKMULTISIG per script byte, and the base size bounds the script bytes.
    assert!(count <= 20 * base_size(tx));
    count
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test fixtures index arrays and vectors whose lengths the tests assert"
)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::hex::FromHex;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    use super::{
        COINBASE_MATURITY, COINBASE_SCRIPT_SIG_SIZE_MAX, Coin, LOCKTIME_THRESHOLD,
        MAX_BLOCK_WEIGHT, MAX_MONEY, RelativeLockBase, SEQUENCE_FINAL,
        SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_GRANULARITY, SEQUENCE_LOCKTIME_MASK,
        SEQUENCE_LOCKTIME_TYPE_FLAG, TxError, TxInputsError, WITNESS_SCALE_FACTOR, bip68_applies,
        check_tx, check_tx_inputs, is_final, is_unspendable, legacy_sigop_count,
        sequence_locks_satisfied, sigop_cost, value_out,
    };
    use crate::header::Context;
    use crate::params::{BlockTime, ChainParams, Height, RegtestOverrides};
    use crate::script::vectors::{
        CORE_SIGHASH_JSON, CORE_TX_INVALID_JSON, CORE_TX_VALID_JSON, Json,
    };
    use crate::script::{MAX_SCRIPT_SIZE, ScriptFlags, push_encoding};

    fn tx_from_hex(hex: &str) -> Transaction {
        deserialize(&Vec::<u8>::from_hex(hex).unwrap()).unwrap()
    }

    fn input(txid_byte: u8, vout: u32) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([txid_byte; 32]),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    fn output(sat: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }
    }

    fn simple_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input(1, 0)],
            output: vec![output(1_000)],
        }
    }

    /// The constants agree with the pinned crate's, so the two cannot drift apart unseen.
    #[test]
    fn constants_match_rust_bitcoin() {
        assert_eq!(MAX_MONEY, Amount::MAX_MONEY.to_sat());
        assert_eq!(LOCKTIME_THRESHOLD, bitcoin::absolute::LOCK_TIME_THRESHOLD);
        assert_eq!(SEQUENCE_FINAL, Sequence::MAX.to_consensus_u32());
        assert_eq!(MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR, 1_000_000);
    }

    /// Every transaction in `tx_valid.json` passes `CheckTransaction` before Core runs its
    /// scripts; so must every one in `tx_invalid.json` that is not marked `BADTX`, whose
    /// failure is a script's.
    #[test]
    fn core_transaction_vectors_pass_check_tx() {
        let mut checked = 0;
        for (file, badtx_expected) in [(CORE_TX_VALID_JSON, 0), (CORE_TX_INVALID_JSON, 9)] {
            let mut badtx = 0;
            for row in Json::parse(file).as_array() {
                let row = row.as_array();
                if !row[0].is_array() {
                    continue;
                }
                let tx = tx_from_hex(row[1].as_str());
                if row[2] == Json::Str("BADTX".into()) {
                    assert!(check_tx(&tx).is_err(), "{row:?}");
                    badtx += 1;
                } else {
                    assert_eq!(check_tx(&tx), Ok(()), "{row:?}");
                    checked += 1;
                }
            }
            assert_eq!(badtx, badtx_expected);
        }
        assert_eq!(checked, 121 + 70 + 14);
    }

    /// The nine `BADTX` rows, in file order, each hit the rule its comment names.
    #[test]
    fn core_badtx_rows_hit_their_rules() {
        let expected = [
            TxError::VoutEmpty,
            TxError::VoutNegative { index: 0 },
            TxError::VoutTooLarge { index: 0 },
            TxError::TxOutTotalTooLarge { index: 1 },
            TxError::InputsDuplicate {
                outpoint: OutPoint {
                    txid: "0000000000000000000000000000000000000000000000000000000000000100"
                        .parse()
                        .unwrap(),
                    vout: 0,
                },
            },
            TxError::CoinbaseLength { size: 1 },
            TxError::CoinbaseLength { size: 101 },
            TxError::PrevoutNull { index: 0 },
            TxError::PrevoutNull { index: 1 },
        ];
        let mut seen = Vec::new();
        for row in Json::parse(CORE_TX_INVALID_JSON).as_array() {
            let row = row.as_array();
            if row[0].is_array() && row[2] == Json::Str("BADTX".into()) {
                seen.push(check_tx(&tx_from_hex(row[1].as_str())).unwrap_err());
            }
        }
        assert_eq!(seen, expected);
    }

    /// Core's sighash harness requires `CheckTransaction` on each of its 500 random
    /// transactions, which exercise many inputs and outputs of arbitrary value.
    #[test]
    fn core_sighash_transactions_pass_check_tx() {
        let rows = Json::parse(CORE_SIGHASH_JSON);
        let mut checked = 0;
        for row in rows.as_array() {
            let row = row.as_array();
            if row.len() != 5 {
                continue;
            }
            let tx = tx_from_hex(row[0].as_str());
            assert_eq!(check_tx(&tx), Ok(()), "{row:?}");
            checked += 1;
        }
        assert_eq!(checked, 500);
    }

    #[test]
    fn check_tx_refuses_an_empty_side() {
        let mut tx = simple_tx();
        tx.input.clear();
        assert_eq!(check_tx(&tx), Err(TxError::VinEmpty));
        let mut tx = simple_tx();
        tx.output.clear();
        assert_eq!(check_tx(&tx), Err(TxError::VoutEmpty));
        // Both empty: inputs are checked first.
        tx.input.clear();
        assert_eq!(check_tx(&tx), Err(TxError::VinEmpty));
    }

    /// One byte over the 1,000,000-byte base limit fails; exactly at it passes.
    #[test]
    fn check_tx_refuses_an_oversize_base_serialization() {
        let mut tx = simple_tx();
        let overhead = tx.base_size() - tx.output[0].script_pubkey.len();
        // A script this long carries a five-byte length prefix instead of one byte.
        let script_len = 1_000_000 - overhead - 4;
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x00; script_len]);
        assert_eq!(tx.base_size(), 1_000_000);
        assert_eq!(check_tx(&tx), Ok(()));
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x00; script_len + 1]);
        assert_eq!(
            check_tx(&tx),
            Err(TxError::Oversize {
                base_size: 1_000_001
            })
        );
    }

    #[test]
    fn check_tx_bounds_output_values_and_their_sum() {
        let mut tx = simple_tx();
        tx.output = vec![output(MAX_MONEY)];
        assert_eq!(check_tx(&tx), Ok(()));
        tx.output = vec![output(MAX_MONEY + 1)];
        assert_eq!(check_tx(&tx), Err(TxError::VoutTooLarge { index: 0 }));
        tx.output = vec![output(1), output(u64::MAX)];
        assert_eq!(check_tx(&tx), Err(TxError::VoutNegative { index: 1 }));
        tx.output = vec![output(MAX_MONEY), output(0), output(1)];
        assert_eq!(check_tx(&tx), Err(TxError::TxOutTotalTooLarge { index: 2 }));
        tx.output = vec![output(MAX_MONEY - 1), output(1)];
        assert_eq!(check_tx(&tx), Ok(()));
    }

    #[test]
    fn check_tx_refuses_duplicate_inputs_wherever_they_sit() {
        let mut tx = simple_tx();
        tx.input = vec![input(1, 0), input(2, 0), input(1, 1), input(2, 0)];
        assert_eq!(
            check_tx(&tx),
            Err(TxError::InputsDuplicate {
                outpoint: input(2, 0).previous_output
            })
        );
        tx.input = vec![input(1, 0), input(2, 0), input(1, 1)];
        assert_eq!(check_tx(&tx), Ok(()));
    }

    #[test]
    fn check_tx_bounds_the_coinbase_script_sig() {
        let mut coinbase = simple_tx();
        coinbase.input = vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x51; 2]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }];
        assert!(coinbase.is_coinbase());
        assert_eq!(check_tx(&coinbase), Ok(()));
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51; 1]);
        assert_eq!(
            check_tx(&coinbase),
            Err(TxError::CoinbaseLength { size: 1 })
        );
        coinbase.input[0].script_sig =
            ScriptBuf::from_bytes(vec![0x51; COINBASE_SCRIPT_SIG_SIZE_MAX]);
        assert_eq!(check_tx(&coinbase), Ok(()));
        coinbase.input[0].script_sig =
            ScriptBuf::from_bytes(vec![0x51; COINBASE_SCRIPT_SIG_SIZE_MAX + 1]);
        assert_eq!(
            check_tx(&coinbase),
            Err(TxError::CoinbaseLength { size: 101 })
        );
    }

    /// A null prevout is only legal as the single input of a coinbase.
    #[test]
    fn check_tx_refuses_a_null_prevout_outside_a_coinbase() {
        let mut tx = simple_tx();
        tx.input = vec![input(1, 0), input(0, u32::MAX)];
        assert!(!tx.is_coinbase());
        assert_eq!(check_tx(&tx), Err(TxError::PrevoutNull { index: 1 }));
    }

    #[test]
    fn is_final_follows_core_s_three_cases() {
        let height = Height::new(500);
        let cutoff = BlockTime::new(1_700_000_000);
        let mut tx = simple_tx();
        tx.input[0].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;

        tx.lock_time = LockTime::ZERO;
        assert!(is_final(&tx, height, cutoff));

        // A height lock is final strictly below the block height.
        tx.lock_time = LockTime::from_consensus(499);
        assert!(is_final(&tx, height, cutoff));
        tx.lock_time = LockTime::from_consensus(500);
        assert!(!is_final(&tx, height, cutoff));

        // A time lock is final strictly below the cutoff; the threshold itself is a time.
        tx.lock_time = LockTime::from_consensus(LOCKTIME_THRESHOLD);
        assert!(is_final(&tx, height, cutoff));
        tx.lock_time = LockTime::from_consensus(cutoff.get() - 1);
        assert!(is_final(&tx, height, cutoff));
        tx.lock_time = LockTime::from_consensus(cutoff.get());
        assert!(!is_final(&tx, height, cutoff));

        // Every input final: the lock time is ignored. One input not final: it is not.
        tx.input[0].sequence = Sequence::MAX;
        assert!(is_final(&tx, height, cutoff));
        tx.input.push(input(2, 0));
        tx.input[1].sequence = Sequence::from_consensus(SEQUENCE_FINAL - 1);
        assert!(!is_final(&tx, height, cutoff));
    }

    #[test]
    fn legacy_sigop_count_sums_every_script_of_the_transaction() {
        let mut tx = simple_tx();
        assert_eq!(legacy_sigop_count(&tx), 0);
        tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0xac, 0xad]);
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x52, 0xae]),
        });
        assert_eq!(legacy_sigop_count(&tx), 22);
    }

    #[test]
    fn errors_display_cores_reject_reasons() {
        let cases = [
            (TxError::VinEmpty, "bad-txns-vin-empty"),
            (TxError::VoutEmpty, "bad-txns-vout-empty"),
            (TxError::Oversize { base_size: 1 }, "bad-txns-oversize"),
            (TxError::VoutNegative { index: 0 }, "bad-txns-vout-negative"),
            (TxError::VoutTooLarge { index: 0 }, "bad-txns-vout-toolarge"),
            (
                TxError::TxOutTotalTooLarge { index: 0 },
                "bad-txns-txouttotal-toolarge",
            ),
            (
                TxError::InputsDuplicate {
                    outpoint: OutPoint::null(),
                },
                "bad-txns-inputs-duplicate",
            ),
            (TxError::CoinbaseLength { size: 0 }, "bad-cb-length"),
            (TxError::PrevoutNull { index: 0 }, "bad-txns-prevout-null"),
        ];
        for (error, reason) in cases {
            assert_eq!(error.to_string(), reason);
        }
    }

    fn coin(value: u64, height: u32, coinbase: bool) -> Coin {
        Coin {
            outpoint: input(1, 0).previous_output,
            output: output(value),
            height: Height::new(height),
            coinbase,
        }
    }

    /// The constants agree with the pinned crate's spellings of BIP68.
    #[test]
    fn bip68_constants_match_rust_bitcoin() {
        assert_eq!(
            SEQUENCE_LOCKTIME_DISABLE_FLAG,
            Sequence::ENABLE_LOCKTIME_NO_RBF.to_consensus_u32() & (1 << 31)
        );
        assert_eq!(SEQUENCE_LOCKTIME_TYPE_FLAG, 1 << 22);
        assert_eq!(SEQUENCE_LOCKTIME_MASK, 0xffff);
        assert_eq!(1u64 << SEQUENCE_LOCKTIME_GRANULARITY, 512);
        assert_eq!(COINBASE_MATURITY, 100);
    }

    /// `TxOutSer` byte for byte: the outpoint as serialized, the height and coinbase flag
    /// packed little-endian, then the output as serialized, which is what
    /// `feature_utxo_set_hash.py` feeds its `MuHash`.
    #[test]
    fn coin_hash_record_is_cores_txoutser() {
        let coin = Coin {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([0x11; 32]),
                vout: 1,
            },
            output: TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            height: Height::new(5),
            coinbase: true,
        };
        let mut expected = vec![0x11; 32];
        expected.extend_from_slice(&[1, 0, 0, 0]);
        expected.extend_from_slice(&[11, 0, 0, 0]);
        expected.extend_from_slice(&[0xe8, 0x03, 0, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(&[0x01, 0x51]);
        assert_eq!(coin.hash_record(), expected);

        // Coinbase clear flips the low bit only; the height fills the rest.
        let plain = Coin {
            coinbase: false,
            height: Height::new(0x7fff_ffff),
            ..coin.clone()
        };
        assert_eq!(&plain.hash_record()[36..40], &[0xfe, 0xff, 0xff, 0xff]);
        assert_eq!(
            plain.hash_record().len(),
            36 + 4 + bitcoin::consensus::encode::serialize(&plain.output).len()
        );
    }

    #[test]
    #[should_panic(expected = "is_unspendable")]
    fn hash_record_of_an_unspendable_output_is_a_bug() {
        let mut coin = coin(1, 1, false);
        coin.output.script_pubkey = ScriptBuf::from_bytes(vec![0x6a]);
        let _unreachable = coin.hash_record();
    }

    #[test]
    fn is_unspendable_is_op_return_or_oversize() {
        let script = |bytes: Vec<u8>| is_unspendable(&ScriptBuf::from_bytes(bytes));
        assert!(script(vec![0x6a]));
        assert!(script(vec![0x6a, 0x01, 0x00]));
        assert!(!script(vec![]));
        assert!(!script(vec![0x51]));
        assert!(!script(vec![0x00, 0x6a]));
        assert!(!script(vec![0x51; MAX_SCRIPT_SIZE]));
        assert!(script(vec![0x51; MAX_SCRIPT_SIZE + 1]));
    }

    /// Maturity counts the spending block: 100 deep spends, 99 does not; a coin of the
    /// spending block itself is 0 deep.
    #[test]
    fn check_tx_inputs_enforces_coinbase_maturity() {
        let tx = simple_tx();
        let coinbase = coin(1_000, 1, true);
        assert_eq!(
            check_tx_inputs(&tx, std::slice::from_ref(&coinbase), Height::new(100)),
            Err(TxInputsError::PrematureCoinbaseSpend {
                input: 0,
                depth: 99
            })
        );
        assert_eq!(
            check_tx_inputs(&tx, std::slice::from_ref(&coinbase), Height::new(101)),
            Ok(0)
        );
        assert_eq!(
            check_tx_inputs(&tx, &[coinbase], Height::new(1)),
            Err(TxInputsError::PrematureCoinbaseSpend { input: 0, depth: 0 })
        );
        assert_eq!(
            check_tx_inputs(&tx, &[coin(1_000, 1, false)], Height::new(1)),
            Ok(0)
        );
    }

    /// Core checks each value and the running sum, and reports the input that took it out
    /// of range; then the inputs must cover the outputs, and the difference is the fee.
    #[test]
    fn check_tx_inputs_bounds_values_and_returns_the_fee() {
        let mut tx = simple_tx();
        tx.input.push(input(2, 0));
        let second = |value: u64| Coin {
            outpoint: input(2, 0).previous_output,
            ..coin(value, 1, false)
        };
        assert_eq!(
            check_tx_inputs(
                &tx,
                &[coin(MAX_MONEY + 1, 1, false), second(0)],
                Height::new(1)
            ),
            Err(TxInputsError::InputValuesOutOfRange { input: 0 })
        );
        assert_eq!(
            check_tx_inputs(&tx, &[coin(MAX_MONEY, 1, false), second(1)], Height::new(1)),
            Err(TxInputsError::InputValuesOutOfRange { input: 1 })
        );
        assert_eq!(
            check_tx_inputs(&tx, &[coin(u64::MAX, 1, false), second(0)], Height::new(1)),
            Err(TxInputsError::InputValuesOutOfRange { input: 0 })
        );
        assert_eq!(
            check_tx_inputs(&tx, &[coin(999, 1, false), second(0)], Height::new(1)),
            Err(TxInputsError::InBelowOut {
                value_in: 999,
                value_out: 1_000
            })
        );
        assert_eq!(
            check_tx_inputs(&tx, &[coin(999, 1, false), second(501)], Height::new(1)),
            Ok(500)
        );
        assert_eq!(
            check_tx_inputs(&tx, &[coin(MAX_MONEY, 1, false), second(0)], Height::new(1)),
            Ok(MAX_MONEY - 1_000)
        );
        assert_eq!(value_out(&tx), 1_000);
    }

    #[test]
    #[should_panic(expected = "one coin per input")]
    fn check_tx_inputs_with_the_wrong_coin_count_is_a_bug() {
        let _unreachable = check_tx_inputs(&simple_tx(), &[], Height::new(1));
    }

    fn context_at(height: u32, median_time_past: u32, csv: Option<Height>) -> Context {
        let params = ChainParams::regtest(RegtestOverrides {
            csv,
            ..RegtestOverrides::default()
        });
        let hash = bitcoin::BlockHash::from_byte_array([0x11; 32]);
        Context::new(
            Height::new(height),
            BlockTime::new(median_time_past),
            BlockTime::new(median_time_past + 1),
            params.genesis().header.bits,
            params.rules_at(Height::new(height), hash, None),
        )
    }

    /// Core's `miner_tests`: a height lock of `n` on a coin at `h` is satisfied from block
    /// `h + n` on; a time lock of `n` measures `n * 512` seconds from the median time past
    /// before the coin's block against the median time past before this one, with the
    /// same last-invalid semantics as `nLockTime`.
    #[test]
    fn sequence_locks_follow_bip68() {
        let context = context_at(200, 1_000_000, None);
        let locked = |sequence: u32, height: u32, median_time_past: Option<u32>| {
            let mut tx = simple_tx();
            tx.input[0].sequence = Sequence::from_consensus(sequence);
            let base = RelativeLockBase {
                height: Height::new(height),
                median_time_past: median_time_past.map(BlockTime::new),
            };
            sequence_locks_satisfied(&tx, &[base], &context)
        };
        // Relative height: coin at 190, lock 10, satisfied at 200 and not with the coin
        // one block later.
        assert!(locked(10, 190, None));
        assert!(!locked(10, 191, None));
        assert!(locked(0, 200, None));
        assert!(!locked(1, 200, None));
        assert!(!locked(0xffff, 1, None));

        // Relative time: 1024 seconds from a base 1024 before the median, satisfied only
        // when the base is at least that far back.
        let time = SEQUENCE_LOCKTIME_TYPE_FLAG | 2;
        assert!(locked(time, 100, Some(1_000_000 - 1_024)));
        assert!(!locked(time, 100, Some(1_000_000 - 1_023)));
        assert!(locked(
            SEQUENCE_LOCKTIME_TYPE_FLAG,
            100,
            Some(1_000_000 - 1)
        ));
        assert!(!locked(
            SEQUENCE_LOCKTIME_TYPE_FLAG | 1,
            100,
            Some(1_000_000 - 1)
        ));

        // The disable flag, and bits above the mask, carry no lock.
        assert!(locked(SEQUENCE_LOCKTIME_DISABLE_FLAG | 0xffff, 200, None));
        assert!(locked(SEQUENCE_LOCKTIME_DISABLE_FLAG | time, 200, None));
        assert!(locked(1 << 16, 200, None));
    }

    /// Two inputs: the strictest lock of each kind wins, and the kinds are independent.
    #[test]
    fn sequence_locks_take_the_strictest_input() {
        let context = context_at(200, 1_000_000, None);
        let mut tx = simple_tx();
        tx.input.push(input(2, 0));
        tx.input[0].sequence = Sequence::from_consensus(5);
        tx.input[1].sequence = Sequence::from_consensus(SEQUENCE_LOCKTIME_TYPE_FLAG | 1);
        let base = |height: u32, median_time_past: u32| RelativeLockBase {
            height: Height::new(height),
            median_time_past: Some(BlockTime::new(median_time_past)),
        };
        assert!(sequence_locks_satisfied(
            &tx,
            &[base(195, 0), base(0, 1_000_000 - 512)],
            &context
        ));
        assert!(!sequence_locks_satisfied(
            &tx,
            &[base(196, 0), base(0, 1_000_000 - 512)],
            &context
        ));
        assert!(!sequence_locks_satisfied(
            &tx,
            &[base(195, 0), base(0, 1_000_000 - 511)],
            &context
        ));
    }

    /// Below version 2, or before CSV, no sequence is a lock; the version compares as
    /// `uint32_t`, so a negative one is above 2.
    #[test]
    fn sequence_locks_need_version_two_and_csv() {
        let mut tx = simple_tx();
        tx.input[0].sequence = Sequence::from_consensus(1);
        let base = RelativeLockBase {
            height: Height::new(200),
            median_time_past: None,
        };
        let active = context_at(200, 1_000_000, None);
        assert!(!sequence_locks_satisfied(&tx, &[base], &active));
        tx.version = Version::ONE;
        assert!(!bip68_applies(&tx));
        assert!(sequence_locks_satisfied(&tx, &[base], &active));
        tx.version = Version(-1);
        assert!(bip68_applies(&tx));
        assert!(!sequence_locks_satisfied(&tx, &[base], &active));
        tx.version = Version::TWO;
        let inactive = context_at(200, 1_000_000, Some(Height::new(1_000)));
        assert!(!inactive.rules().csv_active());
        assert!(sequence_locks_satisfied(&tx, &[base], &inactive));
    }

    #[test]
    #[should_panic(expected = "time-locked")]
    fn sequence_locks_without_the_time_base_is_a_bug() {
        let mut tx = simple_tx();
        tx.input[0].sequence = Sequence::from_consensus(SEQUENCE_LOCKTIME_TYPE_FLAG | 1);
        let base = RelativeLockBase {
            height: Height::new(100),
            median_time_past: None,
        };
        let _unreachable =
            sequence_locks_satisfied(&tx, &[base], &context_at(200, 1_000_000, None));
    }

    /// A spend of output 0 of `creation`, with the given `scriptSig` and witness.
    fn spend_of(creation: &Transaction, script_sig: Vec<u8>, witness: &[Vec<u8>]) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: creation.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(witness),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    /// A coinbase-shaped transaction paying to `script_pubkey`, as Core's `BuildTxs`.
    fn creation_of(script_pubkey: Vec<u8>) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(script_pubkey),
            }],
        }
    }

    fn p2sh(redeem_script: &[u8]) -> Vec<u8> {
        use bitcoin::hashes::hash160;
        let mut script = vec![0xa9, 0x14];
        script.extend_from_slice(&hash160::Hash::hash(redeem_script).to_byte_array());
        script.push(0x87);
        script
    }

    fn p2wsh(witness_script: &[u8]) -> Vec<u8> {
        use bitcoin::hashes::sha256;
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&sha256::Hash::hash(witness_script).to_byte_array());
        script
    }

    /// Core's `GetTxSigOpCost`, case by case: legacy counting is inaccurate and reads only
    /// the transaction's own scripts; P2SH reveals the redeem script under the flag;
    /// witness programs cost unscaled, only under `WITNESS`, only for version 0, and never
    /// on a coinbase.
    #[test]
    fn sigop_cost_is_cores_get_transaction_sig_op_cost() {
        let flags = ScriptFlags::WITNESS.union(ScriptFlags::P2SH);
        let pubkey = vec![0x02; 33];
        let mut multisig = vec![0x51];
        multisig.extend(push_encoding(&pubkey));
        multisig.extend(push_encoding(&pubkey));
        multisig.extend([0x52, 0xaf]);
        let prevout = |script_pubkey: &[u8]| TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        };

        // Multisig, legacy counting.
        let creation = creation_of(multisig.clone());
        let spend = spend_of(&creation, vec![0x00, 0x00], &[]);
        assert_eq!(sigop_cost(&spend, &[prevout(&multisig)], flags), 0);
        assert_eq!(sigop_cost(&creation, &[], flags), 20 * WITNESS_SCALE_FACTOR);

        // Multisig nested in P2SH.
        let mut script_sig = vec![0x00, 0x00];
        script_sig.extend(push_encoding(&multisig));
        let script_pubkey = p2sh(&multisig);
        let spend = spend_of(&creation_of(script_pubkey.clone()), script_sig, &[]);
        assert_eq!(
            sigop_cost(&spend, &[prevout(&script_pubkey)], flags),
            2 * WITNESS_SCALE_FACTOR
        );
        assert_eq!(
            sigop_cost(&spend, &[prevout(&script_pubkey)], ScriptFlags::NONE),
            0
        );

        // P2WPKH.
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend([0x33; 20]);
        let witness = [vec![], vec![]];
        let spend = spend_of(&creation_of(p2wpkh.clone()), vec![], &witness);
        assert_eq!(sigop_cost(&spend, &[prevout(&p2wpkh)], flags), 1);
        assert_eq!(
            sigop_cost(&spend, &[prevout(&p2wpkh)], ScriptFlags::P2SH),
            0
        );
        let mut version_one = p2wpkh.clone();
        version_one[0] = 0x51;
        assert_eq!(sigop_cost(&spend, &[prevout(&version_one)], flags), 0);
        let mut coinbase = spend.clone();
        coinbase.input[0].previous_output = OutPoint::null();
        assert!(coinbase.is_coinbase());
        assert_eq!(sigop_cost(&coinbase, &[], flags), 0);

        // P2WPKH nested in P2SH.
        let script_pubkey = p2sh(&p2wpkh);
        let spend = spend_of(
            &creation_of(script_pubkey.clone()),
            push_encoding(&p2wpkh),
            &witness,
        );
        assert_eq!(sigop_cost(&spend, &[prevout(&script_pubkey)], flags), 1);

        // P2WSH.
        let witness = [vec![], vec![], multisig.clone()];
        let script_pubkey = p2wsh(&multisig);
        let spend = spend_of(&creation_of(script_pubkey.clone()), vec![], &witness);
        assert_eq!(sigop_cost(&spend, &[prevout(&script_pubkey)], flags), 2);
        assert_eq!(
            sigop_cost(&spend, &[prevout(&script_pubkey)], ScriptFlags::P2SH),
            0
        );

        // P2WSH nested in P2SH.
        let redeem_script = p2wsh(&multisig);
        let script_pubkey = p2sh(&redeem_script);
        let spend = spend_of(
            &creation_of(script_pubkey.clone()),
            push_encoding(&redeem_script),
            &witness,
        );
        assert_eq!(sigop_cost(&spend, &[prevout(&script_pubkey)], flags), 2);
    }

    #[test]
    fn input_errors_display_cores_reject_reasons() {
        let cases = [
            (
                TxInputsError::PrematureCoinbaseSpend { input: 0, depth: 1 },
                "bad-txns-premature-spend-of-coinbase",
            ),
            (
                TxInputsError::InputValuesOutOfRange { input: 0 },
                "bad-txns-inputvalues-outofrange",
            ),
            (
                TxInputsError::InBelowOut {
                    value_in: 0,
                    value_out: 1,
                },
                "bad-txns-in-belowout",
            ),
        ];
        for (error, reason) in cases {
            assert_eq!(error.to_string(), reason);
        }
    }
}
