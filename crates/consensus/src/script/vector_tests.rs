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
//! are skipped and counted. The five tapscript rows are built as Core's harness builds
//! them: `#SCRIPT#` items through the script parser, `#CONTROLBLOCK#` and
//! `#TAPROOTOUTPUT#` from a one-leaf tree under `key0`.
//!
//! Every test ends by asserting the counts of rows run and skipped, so that a change to the
//! reduction or to the vendored file shows up as a number, not silently.

#![allow(
    clippy::indexing_slicing,
    reason = "test-only code: an index out of bounds fails the test with a panic, as intended"
)]

use bitcoin::hex::FromHex;
use bitcoin::{Script, Witness};

use super::opcode::OP_1;
use super::taproot::TAPROOT_LEAF_TAPSCRIPT;
use super::vectors::{
    CORE_SCRIPT_TESTS_JSON, CORE_TX_INVALID_JSON, CORE_TX_VALID_JSON, Expected, Json, ParsedFlags,
    TxRow, crediting_transaction, parse_flags, parse_script, parse_script_error, parse_tx_row,
    spending_transaction, taproot_single_leaf,
};
use super::{ScriptError, ScriptFlags, TxPrecomputed, TxSigChecker, verify_script};

/// The seven consensus flags one by one, for walking their subsets.
const MANDATORY_FLAGS: [ScriptFlags; 7] = [
    ScriptFlags::P2SH,
    ScriptFlags::DERSIG,
    ScriptFlags::NULLDUMMY,
    ScriptFlags::CHECKLOCKTIMEVERIFY,
    ScriptFlags::CHECKSEQUENCEVERIFY,
    ScriptFlags::WITNESS,
    ScriptFlags::TAPROOT,
];

/// Core's `TrimFlags`: `WITNESS` needs `P2SH` (and `CLEANSTACK` needs both, but it is
/// policy). Core lets `TAPROOT` stand without `WITNESS`, where it can never be reached;
/// this interpreter asserts the implication instead, so the trim drops it too, which
/// changes no verdict.
fn trim_flags(flags: ScriptFlags) -> ScriptFlags {
    let mut trimmed = flags;
    if !trimmed.contains(ScriptFlags::P2SH) {
        trimmed = trimmed.difference(ScriptFlags::WITNESS);
    }
    if !trimmed.contains(ScriptFlags::WITNESS) {
        trimmed = trimmed.difference(ScriptFlags::TAPROOT);
    }
    trimmed
}

/// Every valid combination of the consensus flags: sixteen of the four free ones times the
/// four the two implications allow.
fn mandatory_combinations() -> Vec<ScriptFlags> {
    let mut combinations = Vec::new();
    for mask in 0u32..(1 << MANDATORY_FLAGS.len()) {
        let mut flags = ScriptFlags::NONE;
        for (bit, flag) in MANDATORY_FLAGS.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                flags = flags.union(*flag);
            }
        }
        if trim_flags(flags) == flags {
            combinations.push(flags);
        }
    }
    assert_eq!(combinations.len(), 64);
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

/// The scriptPubKey text Core's harness replaces by the generated taproot output.
const TAPROOT_OUTPUT_MARKER: &str = "0x51 0x20 #TAPROOTOUTPUT#";

/// A row's witness array, read: the items, the amount in satoshis, and the output key of
/// the one-leaf tree a `#CONTROLBLOCK#` item was built for, if there was one.
struct WitnessRow {
    witness: Witness,
    amount: u64,
    taproot_output: Option<[u8; 32]>,
}

/// The witness array of a row: hex items, or `#SCRIPT#` and `#CONTROLBLOCK#` items built
/// as `script_json_test` builds them, then the amount in BTC.
fn parse_witness(json: &Json) -> WitnessRow {
    let elements = json.as_array();
    let (amount, items) = elements.split_last().expect("at least the amount");
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut taproot_output = None;
    for item in items {
        let text = item.as_str();
        if let Some(script) = text.strip_prefix("#SCRIPT#") {
            stack.push(parse_script(script));
        } else if text == "#CONTROLBLOCK#" {
            // The leaf is the item before the control block.
            let leaf = stack
                .last()
                .expect("the leaf script precedes its control block");
            let (control, output_key) = taproot_single_leaf(leaf, TAPROOT_LEAF_TAPSCRIPT);
            stack.push(control);
            taproot_output = Some(output_key);
        } else {
            stack.push(Vec::<u8>::from_hex(text).expect("hex witness item"));
        }
    }
    WitnessRow {
        witness: Witness::from_slice(&stack),
        amount: amount.as_satoshis(),
        taproot_output,
    }
}

/// The scripts and witness of one `script_tests.json` row, ready to run.
struct RowInputs {
    script_sig: Vec<u8>,
    script_pubkey: Vec<u8>,
    witness: Witness,
    amount: u64,
}

/// Reads a row's scriptSig, scriptPubKey and optional witness array, with the taproot
/// markers built as Core's harness builds them. `pos` is 1 when the row has a witness.
fn parse_row_inputs(row: &[Json], pos: usize) -> RowInputs {
    assert!(pos <= 1);
    let witness_row = if pos == 1 {
        parse_witness(&row[0])
    } else {
        WitnessRow {
            witness: Witness::new(),
            amount: 0,
            taproot_output: None,
        }
    };
    let script_pubkey = if row[pos + 1].as_str() == TAPROOT_OUTPUT_MARKER {
        let output_key = witness_row.taproot_output.expect("a #CONTROLBLOCK# item");
        let mut script = vec![OP_1, 0x20];
        script.extend(output_key);
        script
    } else {
        parse_script(row[pos + 1].as_str())
    };
    RowInputs {
        script_sig: parse_script(row[pos].as_str()),
        script_pubkey,
        witness: witness_row.witness,
        amount: witness_row.amount,
    }
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
}

#[test]
fn script_tests_json() {
    let rows = Json::parse(CORE_SCRIPT_TESTS_JSON);
    let combinations = mandatory_combinations();
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
        let expected = parse_script_error(row[pos + 3].as_str());
        let Some(verdict) = reduce(expected, &flags) else {
            counts.skipped_policy += 1;
            continue;
        };
        let RowInputs {
            script_sig,
            script_pubkey,
            witness,
            amount,
        } = parse_row_inputs(row, pos);
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
        // failing one, never changes the verdict. Core samples 256 random sets; seven flags
        // have 64 valid combinations, so all of them are tried.
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
            run_ok: 675,
            run_err: 418,
            skipped_policy: 129,
        }
    );
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
        let flags = trim_flags(ScriptFlags::MANDATORY.difference(row.flags.consensus));
        assert_eq!(check_tx_scripts(&row, flags), Ok(()), "{}", row.text);
        // Removing any one flag keeps a valid transaction valid.
        for flag in MANDATORY_FLAGS {
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
            check_tx_scripts(&row, ScriptFlags::MANDATORY).is_err(),
            "under all flags: {}",
            row.text
        );
        // Removing any one listed flag makes it valid: the list is minimal.
        for flag in MANDATORY_FLAGS {
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
