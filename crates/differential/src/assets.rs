// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core's `script_assets_test.json` (`docs/differential-testing.md` §1.6), run through
//! `verify_input` under the 128-combination subset/superset rule.
//!
//! Each record is one input of one transaction with every prevout, the flags the spender
//! was built for, and a `success` and/or `failure` spending path (scriptSig and witness).
//! Core's `AssetTest` checks, over every valid combination of the seven consensus flags,
//! that `success` verifies under each combination that is a *subset* of the record's flags
//! (every combination when the record is `final`), and that `failure` fails under each
//! combination that is a *superset*. The rule is what makes the corpus consensus-only: a
//! success path is one that every softer rule set accepts, a failure path one that every
//! stricter rule set rejects. The runner replays exactly that, and on a wrong verdict also
//! prints the oracle's, so that a disagreement with the corpus can be triaged as "bitmigo
//! alone" or "Core 26 too".

use std::path::Path;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hex::FromHex;
use bitcoin::{ScriptBuf, Transaction, TxOut, Witness};
use bitmigo_consensus::script::{ScriptFlags, TxPrecomputed, verify_input};

use crate::generate::FLAGS;
use crate::json::Json;
use crate::oracle;

/// The environment variable naming the corpus file; absent means skip.
pub const CORPUS_ENV: &str = "BITMIGO_SCRIPT_ASSETS";
/// The most records one file may hold: a bound on the walk, generous next to Core's
/// unminimised ten-run dumps.
pub const RECORDS_MAX: u64 = 50_000_000;

/// What a run checked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Records read.
    pub records: u64,
    /// `success` paths verified (one per applicable flag combination).
    pub success_checks: u64,
    /// `failure` paths verified.
    pub failure_checks: u64,
}

/// One record decoded.
struct Record {
    tx: Transaction,
    prevouts: Vec<TxOut>,
    index: usize,
    flags: ScriptFlags,
    is_final: bool,
    comment: String,
}

/// A spending path: scriptSig and witness for the input under test.
struct SpendPath {
    script_sig: ScriptBuf,
    witness: Witness,
}

/// The 64 valid combinations of the seven flags: Core's `AllConsensusFlags`, which skips
/// `WITNESS` without `P2SH` and `TAPROOT` without `WITNESS`.
#[must_use]
pub fn all_consensus_flags() -> Vec<ScriptFlags> {
    let mut combinations = Vec::with_capacity(64);
    for mask in 0u32..128 {
        let mut flags = ScriptFlags::NONE;
        for (bit, flag) in FLAGS.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                flags = flags.union(*flag);
            }
        }
        if flags.contains(ScriptFlags::WITNESS) && !flags.contains(ScriptFlags::P2SH) {
            continue;
        }
        if flags.contains(ScriptFlags::TAPROOT) && !flags.contains(ScriptFlags::WITNESS) {
            continue;
        }
        combinations.push(flags);
    }
    assert_eq!(combinations.len(), 64);
    combinations
}

/// Core's flag names for this corpus, comma separated; only the seven consensus names occur.
#[must_use]
pub fn parse_flags(text: &str) -> ScriptFlags {
    const NAMES: [(&str, ScriptFlags); 7] = [
        ("P2SH", ScriptFlags::P2SH),
        ("DERSIG", ScriptFlags::DERSIG),
        ("NULLDUMMY", ScriptFlags::NULLDUMMY),
        ("CHECKLOCKTIMEVERIFY", ScriptFlags::CHECKLOCKTIMEVERIFY),
        ("CHECKSEQUENCEVERIFY", ScriptFlags::CHECKSEQUENCEVERIFY),
        ("WITNESS", ScriptFlags::WITNESS),
        ("TAPROOT", ScriptFlags::TAPROOT),
    ];
    let mut flags = ScriptFlags::NONE;
    for name in text.split(',').filter(|name| !name.is_empty()) {
        let (_, flag) = NAMES
            .iter()
            .find(|(known, _)| *known == name)
            .unwrap_or_else(|| panic!("not a consensus flag: {name}"));
        flags = flags.union(*flag);
    }
    flags
}

fn hex(json: &Json) -> Vec<u8> {
    Vec::<u8>::from_hex(json.as_str()).expect("a hex string")
}

fn decode_record(json: &Json) -> Record {
    let tx: Transaction = deserialize(&hex(json.get("tx"))).expect("a transaction");
    let prevouts: Vec<TxOut> = json
        .get("prevouts")
        .as_array()
        .iter()
        .map(|item| deserialize::<TxOut>(&hex(item)).expect("a serialized CTxOut"))
        .collect();
    assert_eq!(prevouts.len(), tx.input.len(), "one prevout per input");
    let index = usize::try_from(json.get("index").as_i64()).expect("a non-negative index");
    assert!(index < tx.input.len());
    Record {
        tx,
        prevouts,
        index,
        flags: parse_flags(json.get("flags").as_str()),
        is_final: json.field("final").is_some_and(Json::as_bool),
        comment: json.get("comment").as_str().to_owned(),
    }
}

fn decode_path(json: &Json) -> SpendPath {
    let witness: Vec<Vec<u8>> = json.get("witness").as_array().iter().map(hex).collect();
    SpendPath {
        script_sig: ScriptBuf::from_bytes(hex(json.get("scriptSig"))),
        witness: Witness::from_slice(&witness),
    }
}

/// Verifies the record's input with `path` under `flags`, on bitmigo and, for the message
/// only, on the oracle.
fn verdicts(record: &Record, path: &SpendPath, flags: ScriptFlags) -> (bool, bool) {
    let mut tx = record.tx.clone();
    let input = tx
        .input
        .get_mut(record.index)
        .expect("index < tx.input.len()");
    input.script_sig = path.script_sig.clone();
    input.witness = path.witness.clone();
    let precomputed = TxPrecomputed::new(&tx, &record.prevouts);
    let bitmigo = verify_input(&tx, record.index, &record.prevouts, &precomputed, flags).is_ok();
    let core = oracle::verify(&serialize(&tx), record.index, &record.prevouts, flags);
    (bitmigo, core)
}

/// Runs one record over every flag combination; returns the success and failure checks made.
fn run_record(json: &Json, combinations: &[ScriptFlags]) -> (u64, u64) {
    let record = decode_record(json);
    let success = json.field("success").map(decode_path);
    let failure = json.field("failure").map(decode_path);
    assert!(
        success.is_some() || failure.is_some(),
        "a record with no path"
    );
    let mut checks = (0, 0);
    for &flags in combinations {
        if let Some(path) = &success
            && (record.is_final || flags.is_subset_of(record.flags))
        {
            let (bitmigo, core) = verdicts(&record, path, flags);
            assert!(
                bitmigo,
                "success path rejected under {flags:?} (Core 26 says {core}): {}",
                record.comment
            );
            checks.0 += 1;
        }
        if let Some(path) = &failure
            && flags.contains(record.flags)
        {
            let (bitmigo, core) = verdicts(&record, path, flags);
            assert!(
                !bitmigo,
                "failure path accepted under {flags:?} (Core 26 says {core}): {}",
                record.comment
            );
            checks.1 += 1;
        }
    }
    checks
}

/// Runs every record of a corpus held in memory, one record's tree at a time.
#[must_use]
pub fn run_corpus(bytes: &[u8]) -> Summary {
    let combinations = all_consensus_flags();
    let mut summary = Summary::default();
    let mut position = skip_to_first_record(bytes);
    for _ in 0..RECORDS_MAX {
        if bytes.get(position) == Some(&b']') {
            return summary;
        }
        let (record, next) = Json::parse_at(bytes, position);
        assert!(next > position);
        let (success, failure) = run_record(&record, &combinations);
        summary.records += 1;
        summary.success_checks += success;
        summary.failure_checks += failure;
        position = skip_separators(bytes, next);
    }
    panic!("more than {RECORDS_MAX} records");
}

/// Past the opening `[` and any whitespace.
fn skip_to_first_record(bytes: &[u8]) -> usize {
    let mut position = 0;
    while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
        position += 1;
    }
    assert_eq!(
        bytes.get(position),
        Some(&b'['),
        "the corpus is a JSON array"
    );
    skip_separators(bytes, position + 1)
}

/// Past whitespace and at most one comma.
fn skip_separators(bytes: &[u8], mut position: usize) -> usize {
    let mut commas = 0;
    while let Some(&byte) = bytes.get(position) {
        if byte == b',' {
            commas += 1;
            assert!(commas <= 1, "two commas at {position}");
        } else if !byte.is_ascii_whitespace() {
            break;
        }
        position += 1;
    }
    position
}

/// Reads and runs the corpus at `path`.
#[must_use]
pub fn run_file(path: &Path) -> Summary {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    run_corpus(&bytes)
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::serialize;
    use bitcoin::hex::DisplayHex;
    use bitmigo_consensus::script::ScriptFlags;

    use super::{CORPUS_ENV, all_consensus_flags, parse_flags, run_corpus, run_file};
    use crate::case::Case;
    use crate::fuzz::case_for_seed;

    /// A record in the corpus's shape built from a case: its spending transaction without
    /// the solved fields, one prevout, and the solved fields as the given path.
    fn record(case: &Case, flags: &str, path: &str, is_final: bool) -> String {
        let unsigned = Case {
            script_sig: Vec::new(),
            witness: Vec::new(),
            ..case.clone()
        };
        let tx = serialize(&unsigned.spending_transaction()).to_lower_hex_string();
        let prevout = serialize(&case.prevout()).to_lower_hex_string();
        let witness: Vec<String> = case
            .witness
            .iter()
            .map(|item| format!("\"{}\"", item.to_lower_hex_string()))
            .collect();
        let final_field = if is_final { ", \"final\": true" } else { "" };
        format!(
            "{{\"tx\": \"{tx}\", \"prevouts\": [\"{prevout}\"], \"index\": 0, \
             \"flags\": \"{flags}\", \
             \"comment\": \"synthetic\"{final_field}, \"{path}\": {{\"scriptSig\": \"{}\", \
             \"witness\": [{}]}}}}",
            case.script_sig.to_lower_hex_string(),
            witness.join(", ")
        )
    }

    /// The first seeds whose case is a valid or an invalid spend under `MANDATORY`.
    fn find_case(valid: bool, taproot: bool) -> Case {
        for seed in 0..10_000 {
            let mut case = case_for_seed(seed);
            case.flags = ScriptFlags::MANDATORY;
            let is_taproot = case.script_pubkey.starts_with(&[0x51, 0x20]);
            if case.bitmigo_verdict() == valid && is_taproot == taproot {
                return case;
            }
        }
        panic!("no such case in 10,000 seeds");
    }

    #[test]
    fn sixty_four_valid_combinations() {
        let all = all_consensus_flags();
        assert_eq!(all.first(), Some(&ScriptFlags::NONE));
        assert_eq!(all.last(), Some(&ScriptFlags::MANDATORY));
        assert_eq!(
            parse_flags(
                "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT"
            ),
            ScriptFlags::MANDATORY
        );
        assert_eq!(parse_flags(""), ScriptFlags::NONE);
    }

    #[test]
    fn synthetic_corpus_runs_under_the_lattice() {
        const TAPROOT_FLAGS: &str =
            "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT";
        const LEGACY_FLAGS: &str =
            "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY";
        let taproot_ok = find_case(true, true);
        let legacy_ok = find_case(true, false);
        let taproot_bad = find_case(false, true);
        let corpus = format!(
            "[\n{},\n{},\n{}\n]\n",
            record(&taproot_ok, TAPROOT_FLAGS, "success", true),
            record(&legacy_ok, LEGACY_FLAGS, "success", false),
            record(&taproot_bad, TAPROOT_FLAGS, "failure", false),
        );
        let summary = run_corpus(corpus.as_bytes());
        assert_eq!(summary.records, 3);
        // final: all 64; legacy flags: the 48 combinations without TAPROOT (TAPROOT needs
        // WITNESS and P2SH, so only 16 of the 64 carry it).
        assert_eq!(summary.success_checks, 64 + 48);
        // failure under supersets of all seven flags: MANDATORY alone.
        assert_eq!(summary.failure_checks, 1);
    }

    #[test]
    #[should_panic(expected = "failure path accepted")]
    fn a_valid_spend_labelled_failure_is_caught() {
        let case = find_case(true, false);
        let corpus = format!("[{}]", record(&case, "P2SH", "failure", false));
        let summary = run_corpus(corpus.as_bytes());
        assert_eq!(summary.records, 1);
    }

    /// The real corpus, when BM-19 has produced it and `BITMIGO_SCRIPT_ASSETS` names it.
    #[test]
    fn script_assets_corpus() {
        let Ok(path) = std::env::var(CORPUS_ENV) else {
            eprintln!("skipping script_assets_corpus: {CORPUS_ENV} is not set");
            return;
        };
        let summary = run_file(std::path::Path::new(&path));
        assert!(summary.records > 0, "an empty corpus");
        eprintln!("script_assets_corpus: {summary:?}");
    }
}
