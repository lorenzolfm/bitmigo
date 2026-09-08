// SPDX-License-Identifier: MIT OR Apache-2.0

//! `bitmigo-differential`: the fuzzer and the corpus runner from the command line.
//!
//! ```text
//! bitmigo-differential fuzz [--seed <u64>] [--iterations <u64>]
//! bitmigo-differential assets <path/to/script_assets_test.json>
//! ```
//!
//! `fuzz` exits 1 on any mismatch after printing each one with the seed that rebuilds it;
//! `--iterations 1 --seed <case seed>` replays one. `assets` exits 1 on the first record
//! bitmigo gets wrong, with the record's comment.

use std::path::Path;
use std::process::ExitCode;

use bitmigo_differential::{assets, fuzz};

/// The default run: under a minute of a debug build on a laptop.
const ITERATIONS_DEFAULT: u64 = 50_000;
const SEED_DEFAULT: u64 = 1;
const USAGE: &str = "usage:\n  bitmigo-differential fuzz [--seed <u64>] [--iterations <u64>]\n  \
                     bitmigo-differential assets <path>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    match (args.first().map(String::as_str), rest) {
        (Some("fuzz"), _) => run_fuzz(rest),
        (Some("assets"), [path]) => run_assets(Path::new(path)),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Parses `--seed` and `--iterations`, each optional, each once.
fn parse_fuzz_args(args: &[String]) -> Result<(u64, u64), String> {
    let mut seed = SEED_DEFAULT;
    let mut iterations = ITERATIONS_DEFAULT;
    let mut pairs = args.chunks(2);
    for _ in 0..args.len().div_ceil(2) {
        let Some(pair) = pairs.next() else { break };
        let [flag, value] = pair else {
            return Err(format!("{} needs a value", pair.join(" ")));
        };
        let parsed: u64 = value
            .parse()
            .map_err(|_| format!("{flag} takes a u64, got {value}"))?;
        match flag.as_str() {
            "--seed" => seed = parsed,
            "--iterations" => iterations = parsed,
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok((seed, iterations))
}

fn run_fuzz(args: &[String]) -> ExitCode {
    let (seed, iterations) = match parse_fuzz_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    println!("fuzzing {iterations} case(s) from seed {seed}");
    let report = fuzz::run(seed, iterations);
    print!("{report}");
    if report.mismatches.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_assets(path: &Path) -> ExitCode {
    let summary = assets::run_file(path);
    println!(
        "{} record(s): {} success check(s), {} failure check(s), all as Core expects",
        summary.records, summary.success_checks, summary.failure_checks
    );
    ExitCode::SUCCESS
}
