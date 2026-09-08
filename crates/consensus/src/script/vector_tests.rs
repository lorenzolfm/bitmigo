// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core's `script_tests.json`, `tx_valid.json` and `tx_invalid.json`, run through
//! [`verify_script`] under the consensus-only reduction of `docs/differential-testing.md`
//! §1.7.
//!
//! The interpreter has no policy switches, so a row's policy flags are stripped before it
//! runs. Core's own harness asserts that removing flags from a passing row keeps it passing,
//! so every `OK` row stays a must-pass. A row expecting a consensus error keeps its exact
//! error, because a policy flag only ever adds failure conditions: had one fired, Core would
//! have reported that flag's error instead. The exceptions are errors a policy flag can
//! produce on its own (`SCRIPTNUM` under `MINIMALDATA`, `SIG_DER` without `DERSIG`,
//! `CLEANSTACK` under the flag, `SIG_PUSHONLY` under `SIGPUSHONLY`): stripped, the row's
//! outcome is unknowable, so it is skipped and counted. Rows expecting a policy-only error
//! are skipped and counted. Rows carrying `TAPROOT` wait for the taproot verifier.
//!
//! Every test ends by asserting the counts of rows run, skipped and deferred, so that a
//! change to the reduction or to the vendored file shows up as a number, not silently.

#![allow(
    clippy::indexing_slicing,
    reason = "test-only code: an index out of bounds fails the test with a panic, as intended"
)]

use std::collections::HashMap;

use bitcoin::consensus::deserialize;
use bitcoin::hex::FromHex;
use bitcoin::{OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid, Witness};

use super::vectors::{
    CORE_SCRIPT_TESTS_JSON, CORE_TX_INVALID_JSON, CORE_TX_VALID_JSON, Expected, Json, ParsedFlags,
    crediting_transaction, parse_flags, parse_script, parse_script_error, spending_transaction,
};
use super::{ScriptError, ScriptFlags, TxPrecomputed, TxSigChecker, verify_script};

/// The consensus flags the interpreter implements today: everything but `TAPROOT`, which
/// waits for the taproot verifier. The transaction vectors run under this set.
const IMPLEMENTED: ScriptFlags = ScriptFlags::P2SH
    .union(ScriptFlags::DERSIG)
    .union(ScriptFlags::NULLDUMMY)
    .union(ScriptFlags::CHECKLOCKTIMEVERIFY)
    .union(ScriptFlags::CHECKSEQUENCEVERIFY)
    .union(ScriptFlags::WITNESS);

/// The six implemented flags one by one, for walking their subsets.
const IMPLEMENTED_FLAGS: [ScriptFlags; 6] = [
    ScriptFlags::P2SH,
    ScriptFlags::DERSIG,
    ScriptFlags::NULLDUMMY,
    ScriptFlags::CHECKLOCKTIMEVERIFY,
    ScriptFlags::CHECKSEQUENCEVERIFY,
    ScriptFlags::WITNESS,
];

/// Core's `TrimFlags`: `WITNESS` needs `P2SH` (and `CLEANSTACK` needs both, but it is policy).
fn trim_flags(flags: ScriptFlags) -> ScriptFlags {
    if flags.contains(ScriptFlags::P2SH) {
        flags
    } else {
        flags.difference(ScriptFlags::WITNESS)
    }
}

/// Every valid combination of the implemented flags.
fn implemented_combinations() -> Vec<ScriptFlags> {
    let mut combinations = Vec::new();
    for mask in 0u32..(1 << IMPLEMENTED_FLAGS.len()) {
        let mut flags = ScriptFlags::NONE;
        for (bit, flag) in IMPLEMENTED_FLAGS.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                flags = flags.union(*flag);
            }
        }
        if trim_flags(flags) == flags {
            combinations.push(flags);
        }
    }
    assert_eq!(combinations.len(), 48);
    combinations
}

/// `DoTest`'s main check: the crediting/spending pair, then `VerifyScript` on input 0.
fn verify(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &Witness,
    flags: ScriptFlags,
    amount: u64,
) -> Result<(), ScriptError> {
    let credit = crediting_transaction(script_pubkey, amount);
    let spend = spending_transaction(script_sig, witness.clone(), &credit);
    let prevouts = vec![credit.output[0].clone()];
    let precomputed = TxPrecomputed::new(&spend, &prevouts);
    let checker = TxSigChecker::new(&spend, 0, &prevouts, &precomputed);
    verify_script(
        Script::from_bytes(script_sig),
        Script::from_bytes(script_pubkey),
        witness,
        flags,
        &checker,
    )
}

/// The witness array of a row: hex items, then the amount in BTC.
fn parse_witness(json: &Json) -> (Witness, u64) {
    let elements = json.as_array();
    let (amount, items) = elements.split_last().expect("at least the amount");
    let items: Vec<Vec<u8>> = items
        .iter()
        .map(|item| {
            let text = item.as_str();
            assert!(!text.starts_with('#'), "taproot rows are deferred: {text}");
            Vec::<u8>::from_hex(text).expect("hex witness item")
        })
        .collect();
    (Witness::from_slice(&items), amount.as_satoshis())
}

/// What the interpreter must return for a row once its policy flags are gone, or `None`
/// when the row can no longer say.
fn reduce(expected: Expected, flags: &ParsedFlags) -> Option<Result<(), ScriptError>> {
    let error = match expected {
        Expected::Ok => return Some(Ok(())),
        Expected::Policy(_) => return None,
        Expected::Consensus(error) => error,
    };
    let consensus = flags.consensus;
    let attributable = match error {
        ScriptError::Scriptnum => !flags.has_policy("MINIMALDATA"),
        ScriptError::SigDer => consensus.contains(ScriptFlags::DERSIG),
        ScriptError::Cleanstack => !flags.has_policy("CLEANSTACK"),
        ScriptError::SigPushonly => !flags.has_policy("SIGPUSHONLY"),
        ScriptError::SigNulldummy => consensus.contains(ScriptFlags::NULLDUMMY),
        ScriptError::NegativeLocktime | ScriptError::UnsatisfiedLocktime => {
            consensus.contains(ScriptFlags::CHECKLOCKTIMEVERIFY)
                || consensus.contains(ScriptFlags::CHECKSEQUENCEVERIFY)
        }
        ScriptError::WitnessProgramWrongLength
        | ScriptError::WitnessProgramWitnessEmpty
        | ScriptError::WitnessProgramMismatch
        | ScriptError::WitnessMalleated
        | ScriptError::WitnessMalleatedP2sh
        | ScriptError::WitnessUnexpected => consensus.contains(ScriptFlags::WITNESS),
        _ => true,
    };
    if attributable { Some(Err(error)) } else { None }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ScriptCounts {
    comments: usize,
    run_ok: usize,
    run_err: usize,
    skipped_policy: usize,
    deferred_taproot: usize,
}

#[test]
fn script_tests_json() {
    let rows = Json::parse(CORE_SCRIPT_TESTS_JSON);
    let combinations = implemented_combinations();
    let mut counts = ScriptCounts::default();
    for row in rows.as_array() {
        let row = row.as_array();
        if row.len() == 1 {
            counts.comments += 1;
            continue;
        }
        let pos = usize::from(row[0].is_array());
        assert!(row.len() >= 4 + pos, "bad test: {row:?}");
        let flags = parse_flags(row[pos + 2].as_str());
        if flags.consensus.contains(ScriptFlags::TAPROOT) {
            counts.deferred_taproot += 1;
            continue;
        }
        let expected = parse_script_error(row[pos + 3].as_str());
        let Some(verdict) = reduce(expected, &flags) else {
            counts.skipped_policy += 1;
            continue;
        };
        let (witness, amount) = if pos == 1 {
            parse_witness(&row[0])
        } else {
            (Witness::new(), 0)
        };
        let script_sig = parse_script(row[pos].as_str());
        let script_pubkey = parse_script(row[pos + 1].as_str());
        // DoTest adds P2SH and WITNESS to any row that asks for CLEANSTACK.
        let mut run_flags = flags.consensus;
        if flags.has_policy("CLEANSTACK") {
            run_flags = run_flags
                .union(ScriptFlags::P2SH)
                .union(ScriptFlags::WITNESS);
        }
        assert_eq!(trim_flags(run_flags), run_flags, "bad test flags: {row:?}");

        let result = verify(&script_sig, &script_pubkey, &witness, run_flags, amount);
        assert_eq!(result, verdict, "{row:?}");
        // DoTest's second property: removing flags from a passing row, or adding them to a
        // failing one, never changes the verdict. Core samples 256 random sets; six flags
        // have 48 valid combinations, so all of them are tried.
        for &combination in &combinations {
            let (applicable, description) = if verdict.is_ok() {
                (combination.is_subset_of(run_flags), "subset")
            } else {
                (combination.contains(run_flags), "superset")
            };
            if applicable {
                let result = verify(&script_sig, &script_pubkey, &witness, combination, amount);
                assert_eq!(
                    result.is_ok(),
                    verdict.is_ok(),
                    "{description} {combination:?}: {row:?}"
                );
            }
        }
        if verdict.is_ok() {
            counts.run_ok += 1;
        } else {
            counts.run_err += 1;
        }
    }
    assert_eq!(
        counts,
        ScriptCounts {
            comments: 51,
            run_ok: 672,
            run_err: 416,
            skipped_policy: 129,
            deferred_taproot: 5,
        }
    );
}

/// A transaction row: the spent outputs keyed by outpoint, the transaction, its flag list.
struct TxRow {
    prevouts: Vec<TxOut>,
    tx: Transaction,
    flags: ParsedFlags,
    text: String,
}

/// Reads one `[[inputs...], hex, flags]` row, or `None` for a comment row.
fn parse_tx_row(row: &Json) -> Option<TxRow> {
    let row = row.as_array();
    if !row[0].is_array() {
        return None;
    }
    assert_eq!(row.len(), 3, "bad test: {row:?}");
    let mut spent: HashMap<OutPoint, TxOut> = HashMap::new();
    for input in row[0].as_array() {
        let input = input.as_array();
        assert!(input.len() == 3 || input.len() == 4, "bad test: {row:?}");
        let txid: Txid = input[0].as_str().parse().expect("a txid in display order");
        // Core casts the index through `uint32_t`, which is how `-1` becomes `0xffffffff`.
        let vout = u32::try_from(input[1].as_i64().rem_euclid(1 << 32)).expect("32 bits");
        let amount = input.get(3).map_or(0, |amount| {
            u64::try_from(amount.as_i64()).expect("a non-negative amount")
        });
        let previous = spent.insert(
            OutPoint { txid, vout },
            TxOut {
                value: bitcoin::Amount::from_sat(amount),
                script_pubkey: ScriptBuf::from_bytes(parse_script(input[2].as_str())),
            },
        );
        assert!(previous.is_none(), "duplicate prevout: {row:?}");
    }
    let tx: Transaction =
        deserialize(&Vec::<u8>::from_hex(row[1].as_str()).expect("hex")).expect("a transaction");
    let prevouts = tx
        .input
        .iter()
        .map(|input| {
            spent
                .get(&input.previous_output)
                .unwrap_or_else(|| panic!("bad test, prevout missing: {row:?}"))
                .clone()
        })
        .collect();
    Some(TxRow {
        prevouts,
        tx,
        flags: parse_flags(row[2].as_str()),
        text: format!("{row:?}"),
    })
}

/// Core's `CheckTxScripts`: every input through `VerifyScript`, stopping at the first failure.
fn check_tx_scripts(row: &TxRow, flags: ScriptFlags) -> Result<(), (usize, ScriptError)> {
    let precomputed = TxPrecomputed::new(&row.tx, &row.prevouts);
    for (index, input) in row.tx.input.iter().enumerate() {
        let checker = TxSigChecker::new(&row.tx, index, &row.prevouts, &precomputed);
        verify_script(
            &input.script_sig,
            &row.prevouts[index].script_pubkey,
            &input.witness,
            flags,
            &checker,
        )
        .map_err(|error| (index, error))?;
    }
    Ok(())
}

#[test]
fn tx_valid_json() {
    let rows = Json::parse(CORE_TX_VALID_JSON);
    let mut comments = 0;
    let mut run = 0;
    for row in rows.as_array() {
        let Some(row) = parse_tx_row(row) else {
            comments += 1;
            continue;
        };
        // The listed flags are the ones to EXCLUDE; the policy ones among them have nothing
        // to exclude here, and the consensus ones come off the implemented set.
        let flags = trim_flags(IMPLEMENTED.difference(row.flags.consensus));
        assert_eq!(check_tx_scripts(&row, flags), Ok(()), "{}", row.text);
        // Removing any one flag keeps a valid transaction valid.
        for flag in IMPLEMENTED_FLAGS {
            let fewer = trim_flags(flags.difference(flag));
            assert_eq!(
                check_tx_scripts(&row, fewer),
                Ok(()),
                "without {flag:?}: {}",
                row.text
            );
        }
        run += 1;
    }
    assert_eq!(comments, 129);
    assert_eq!(run, 121);
}

#[test]
fn tx_invalid_json() {
    let rows = Json::parse(CORE_TX_INVALID_JSON);
    let mut comments = 0;
    let mut run = 0;
    let mut skipped_badtx = 0;
    let mut skipped_policy = 0;
    for row in rows.as_array() {
        // Rows that fail CheckTransaction never reach the interpreter; that check belongs
        // to the transaction module and is not run here.
        if row
            .as_array()
            .get(2)
            .is_some_and(|flags| flags == &Json::Str("BADTX".into()))
        {
            skipped_badtx += 1;
            continue;
        }
        let Some(row) = parse_tx_row(row) else {
            comments += 1;
            continue;
        };
        // The listed flags are the ones to APPLY, and the list is minimal: a policy flag on
        // it means the row passes without it, so nothing here can assert.
        if !row.flags.policy.is_empty() {
            skipped_policy += 1;
            continue;
        }
        let flags = row.flags.consensus;
        assert_eq!(trim_flags(flags), flags, "bad test flags: {}", row.text);
        assert!(check_tx_scripts(&row, flags).is_err(), "{}", row.text);
        // Adding flags keeps an invalid transaction invalid.
        assert!(
            check_tx_scripts(&row, IMPLEMENTED).is_err(),
            "under all flags: {}",
            row.text
        );
        // Removing any one listed flag makes it valid: the list is minimal.
        for flag in IMPLEMENTED_FLAGS {
            if !flags.contains(flag) {
                continue;
            }
            let fewer = trim_flags(flags.difference(flag));
            assert_eq!(
                check_tx_scripts(&row, fewer),
                Ok(()),
                "without {flag:?}: {}",
                row.text
            );
        }
        run += 1;
    }
    assert_eq!(comments, 108);
    assert_eq!(run, 70);
    assert_eq!(skipped_badtx, 9);
    assert_eq!(skipped_policy, 14);
}
