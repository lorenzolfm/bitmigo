// SPDX-License-Identifier: MIT OR Apache-2.0

//! The differential loop: build a case, ask both interpreters, compare the booleans.
//!
//! Every case is a function of one `u64`, the master seed plus the iteration number, so a
//! mismatch is reproduced by running one iteration from the seed it prints. The report
//! counts how the two agreed as well as whether: a fuzzer that only ever agreed on
//! "invalid" would be measuring nothing, so the counts are asserted downstream.

use bitcoin::secp256k1::Secp256k1;
use core::fmt;

use crate::case::Case;
use crate::generate::random_case;
use crate::prng::Prng;
use crate::templates::signed_case;

/// Mismatches kept before the loop stops: enough to see a pattern, few enough to read.
pub const MISMATCHES_MAX: usize = 16;

/// One disagreement.
#[derive(Clone, Debug)]
pub struct Mismatch {
    /// `Prng::new(case_seed)` rebuilds this case.
    pub case_seed: u64,
    /// The case itself.
    pub case: Case,
    /// bitmigo's verdict.
    pub bitmigo: bool,
    /// Core's verdict.
    pub oracle: bool,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "mismatch at case seed {}:", self.case_seed)?;
        writeln!(
            f,
            "  bitmigo: {}  core: {}",
            verdict(self.bitmigo),
            verdict(self.oracle)
        )?;
        write!(f, "{}", self.case)
    }
}

fn verdict(valid: bool) -> &'static str {
    if valid { "valid" } else { "invalid" }
}

/// What one run compared.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Cases compared.
    pub compared: u64,
    /// Cases both interpreters accepted.
    pub agreed_valid: u64,
    /// Cases both interpreters rejected.
    pub agreed_invalid: u64,
    /// Disagreements, at most [`MISMATCHES_MAX`].
    pub mismatches: Vec<Mismatch>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} compared: {} agreed valid, {} agreed invalid, {} mismatch(es)",
            self.compared,
            self.agreed_valid,
            self.agreed_invalid,
            self.mismatches.len()
        )?;
        for mismatch in &self.mismatches {
            write!(f, "{mismatch}")?;
        }
        Ok(())
    }
}

/// The case for `case_seed`: two draws in three are signed templates, one is unstructured.
#[must_use]
pub fn case_for_seed(case_seed: u64) -> Case {
    let secp = Secp256k1::new();
    let mut prng = Prng::new(case_seed);
    if prng.chance(2, 3) {
        signed_case(&secp, &mut prng)
    } else {
        random_case(&mut prng)
    }
}

/// Compares the two interpreters on `iterations` cases seeded `seed`, `seed + 1`, ... and
/// stops early once [`MISMATCHES_MAX`] disagreements are in hand.
#[must_use]
pub fn run(seed: u64, iterations: u64) -> Report {
    let mut report = Report::default();
    for iteration in 0..iterations {
        let case_seed = seed.wrapping_add(iteration);
        let case = case_for_seed(case_seed);
        let bitmigo = case.bitmigo_verdict();
        let oracle = case.oracle_verdict();
        report.compared += 1;
        match (bitmigo, oracle) {
            (true, true) => report.agreed_valid += 1,
            (false, false) => report.agreed_invalid += 1,
            _ => report.mismatches.push(Mismatch {
                case_seed,
                case,
                bitmigo,
                oracle,
            }),
        }
        if report.mismatches.len() >= MISMATCHES_MAX {
            break;
        }
    }
    assert!(report.compared <= iterations);
    assert_eq!(
        report.compared,
        report.agreed_valid
            + report.agreed_invalid
            + u64::try_from(report.mismatches.len()).expect("fits")
    );
    report
}

#[cfg(test)]
mod tests {
    use super::{case_for_seed, run};

    /// The short run `cargo test` performs: no disagreement, and enough agreed-valid cases
    /// that the signed templates are known to be reaching the signature checks.
    #[test]
    fn short_run_agrees() {
        let report = run(1, 1_000);
        assert!(report.mismatches.is_empty(), "{report}");
        assert_eq!(report.compared, 1_000);
        assert!(report.agreed_valid >= 200, "{report}");
        assert!(report.agreed_invalid >= 200, "{report}");
    }

    #[test]
    fn a_case_is_a_function_of_its_seed() {
        assert_eq!(case_for_seed(42), case_for_seed(42));
        assert_ne!(case_for_seed(42), case_for_seed(43));
    }
}
