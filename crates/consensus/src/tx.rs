// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction rules that need no coins: Core's `CheckTransaction` as [`check_tx`], the
//! finality predicate `IsFinalTx` as [`is_final`], the legacy signature operation count, and
//! the constants the block rules share with them (§2.1, §2.2, §2.3, §3.1).
//!
//! Everything here is a function of one transaction and, for finality, the height and time
//! the containing block supplies. The rules that read the coins a transaction spends
//! (amounts, maturity, BIP68, scripts) belong to the coins path in `block`.

use core::fmt;

use bitcoin::{OutPoint, Transaction};

use crate::params::{BlockTime, Height};
use crate::script::{SigOpMode, sigop_count};

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
        COINBASE_SCRIPT_SIG_SIZE_MAX, LOCKTIME_THRESHOLD, MAX_BLOCK_WEIGHT, MAX_MONEY,
        SEQUENCE_FINAL, TxError, WITNESS_SCALE_FACTOR, check_tx, is_final, legacy_sigop_count,
    };
    use crate::params::{BlockTime, Height};
    use crate::script::vectors::{
        CORE_SIGHASH_JSON, CORE_TX_INVALID_JSON, CORE_TX_VALID_JSON, Json,
    };

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
}
