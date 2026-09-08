// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Case`]: one spend to put to both interpreters, and the two verdicts.
//!
//! A case is exactly what Core's `script_tests.json` harness (`DoTest`) feeds
//! `VerifyScript`: a scriptPubKey with an amount, a scriptSig, a witness and the flags.
//! `DoTest` wraps them in a crediting transaction (one null input, one output paying the
//! scriptPubKey) and a spending transaction (one input spending it, one output of the same
//! amount to an empty script), and this module builds the same pair, so that a mismatch the
//! fuzzer prints could be pasted into Core's own test as a row. The scriptSig and witness do
//! not enter any signature hash, which is what lets a template sign an unsigned spend and
//! then store only the solved fields.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::hex::DisplayHex;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitmigo_consensus::script::{ScriptFlags, TxPrecomputed, verify_input};
use core::fmt;

use crate::oracle;

/// The largest script a case may carry: Core's `MAX_SCRIPT_SIZE` (10,000) plus room to
/// overshoot it on purpose, so that `SCRIPT_SIZE` itself is reachable.
pub const SCRIPT_LEN_MAX: usize = 12_000;
/// The most witness items a case may carry. Core's limit is 1,000 elements for a v0
/// program; the generator stays far below it and asserts that it did.
pub const WITNESS_ITEMS_MAX: usize = 64;
/// `MAX_MONEY`: no output may exceed it, and Core's digest would reject one that did.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// One spend: the output being spent and the input that spends it, under `flags`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    /// The flags both interpreters verify under; a subset of `MANDATORY` honouring
    /// `WITNESS ⇒ P2SH` and `TAPROOT ⇒ WITNESS`.
    pub flags: ScriptFlags,
    /// The scriptPubKey of the output being spent.
    pub script_pubkey: Vec<u8>,
    /// The value of the output being spent, in satoshis.
    pub amount: u64,
    /// The spending input's scriptSig.
    pub script_sig: Vec<u8>,
    /// The spending input's witness stack, bottom first.
    pub witness: Vec<Vec<u8>>,
}

impl Case {
    /// Checks the bounds every generator must respect. Called by both verdicts so that an
    /// over-size case fails loudly instead of measuring how the two libraries handle it.
    pub fn assert_bounded(&self) {
        assert!(self.flags.is_subset_of(ScriptFlags::MANDATORY));
        if self.flags.contains(ScriptFlags::WITNESS) {
            assert!(self.flags.contains(ScriptFlags::P2SH));
        }
        if self.flags.contains(ScriptFlags::TAPROOT) {
            assert!(self.flags.contains(ScriptFlags::WITNESS));
        }
        assert!(self.script_pubkey.len() <= SCRIPT_LEN_MAX);
        assert!(self.script_sig.len() <= SCRIPT_LEN_MAX);
        assert!(self.witness.len() <= WITNESS_ITEMS_MAX);
        assert!(self.amount <= MAX_MONEY);
    }

    /// `BuildCreditingTransaction`: version 1, one null-prevout input with scriptSig
    /// `OP_0 OP_0`, one output paying `amount` to `script_pubkey`.
    #[must_use]
    pub fn crediting_transaction(&self) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![self.prevout()],
        }
    }

    /// The output being spent, as the spending transaction's one prevout.
    #[must_use]
    pub fn prevout(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: ScriptBuf::from_bytes(self.script_pubkey.clone()),
        }
    }

    /// `BuildSpendingTransaction`: version 1, one input spending the crediting
    /// transaction's output with this case's scriptSig and witness, one output of the same
    /// amount to an empty script. With empty `script_sig` and `witness` it is the unsigned
    /// transaction a template signs.
    #[must_use]
    pub fn spending_transaction(&self) -> Transaction {
        let credit = self.crediting_transaction();
        let spend = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: credit.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::from_bytes(self.script_sig.clone()),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&self.witness),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(self.amount),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        assert_eq!(spend.input.len(), 1);
        let input = spend.input.first().expect("one input");
        assert_eq!(input.witness.len(), self.witness.len());
        spend
    }

    /// bitmigo's verdict, through the seam the node uses.
    #[must_use]
    pub fn bitmigo_verdict(&self) -> bool {
        self.assert_bounded();
        let tx = self.spending_transaction();
        let prevouts = [self.prevout()];
        let precomputed = TxPrecomputed::new(&tx, &prevouts);
        verify_input(&tx, 0, &prevouts, &precomputed, self.flags).is_ok()
    }

    /// Core's verdict, through `libbitcoinconsensus`.
    #[must_use]
    pub fn oracle_verdict(&self) -> bool {
        self.assert_bounded();
        let tx_bytes = serialize(&self.spending_transaction());
        let prevouts = [self.prevout()];
        oracle::verify(&tx_bytes, 0, &prevouts, self.flags)
    }
}

impl fmt::Display for Case {
    /// One field per line, hex where Core's vectors would use hex, so that a printed case
    /// can be replayed by hand against either interpreter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  flags:         {:?}", self.flags)?;
        writeln!(f, "  amount:        {}", self.amount)?;
        writeln!(
            f,
            "  script_pubkey: {}",
            self.script_pubkey.to_lower_hex_string()
        )?;
        writeln!(
            f,
            "  script_sig:    {}",
            self.script_sig.to_lower_hex_string()
        )?;
        writeln!(f, "  witness:       {} item(s)", self.witness.len())?;
        for item in &self.witness {
            writeln!(f, "    {}", item.to_lower_hex_string())?;
        }
        let tx_bytes = serialize(&self.spending_transaction());
        writeln!(f, "  spending_tx:   {}", tx_bytes.to_lower_hex_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index out of bounds fails the test with a panic, as intended"
    )]

    use bitmigo_consensus::script::ScriptFlags;

    use super::Case;

    fn anyone_can_spend() -> Case {
        Case {
            flags: ScriptFlags::MANDATORY,
            script_pubkey: vec![0x51],
            amount: 1,
            script_sig: Vec::new(),
            witness: Vec::new(),
        }
    }

    #[test]
    fn both_interpreters_agree_on_the_trivial_cases() {
        let yes = anyone_can_spend();
        assert!(yes.bitmigo_verdict());
        assert!(yes.oracle_verdict());
        let no = Case {
            script_pubkey: vec![0x00],
            ..anyone_can_spend()
        };
        assert!(!no.bitmigo_verdict());
        assert!(!no.oracle_verdict());
    }

    #[test]
    fn the_spending_transaction_spends_the_crediting_one() {
        let case = anyone_can_spend();
        let credit = case.crediting_transaction();
        let spend = case.spending_transaction();
        assert_eq!(spend.input[0].previous_output.txid, credit.compute_txid());
        assert_eq!(spend.output[0].value, credit.output[0].value);
        assert!(format!("{case}").contains("script_pubkey: 51"));
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn taproot_without_witness_is_refused() {
        let case = Case {
            flags: ScriptFlags::P2SH.union(ScriptFlags::TAPROOT),
            ..anyone_can_spend()
        };
        assert!(case.bitmigo_verdict());
    }
}
