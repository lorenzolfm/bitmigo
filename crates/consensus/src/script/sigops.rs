// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature operation counting: Core's `CScript::GetSigOpCount(bool fAccurate)` (§2.2).
//!
//! The count is a static scan, not an execution: every `CHECKSIG` in the script counts,
//! whether or not a branch would ever reach it, and the scan stops silently at the first
//! opcode that fails to parse, exactly as Core's does. The block rules add the counts of
//! every script in a block and compare the total with `MAX_BLOCK_SIGOPS_COST`.

use super::interpreter::MAX_PUBKEYS_PER_MULTISIG;
use super::opcode::{
    OP_1, OP_16, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_INVALIDOPCODE, Opcode,
};
use super::reader::Reader;

/// How a `CHECKMULTISIG` is counted: Core's `fAccurate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigOpMode {
    /// Every `CHECKMULTISIG` counts `MAX_PUBKEYS_PER_MULTISIG`. The legacy count, applied to
    /// every `scriptSig` and `scriptPubKey` of every transaction in a block.
    Inaccurate,
    /// A `CHECKMULTISIG` preceded by `OP_1`..`OP_16` counts that many keys; any other one
    /// counts the maximum. Applied to P2SH redeem scripts and P2WSH witness scripts (BIP16).
    Accurate,
}

/// Core's `CScript::GetSigOpCount(fAccurate)`: the signature operations `script` would cost
/// if every opcode in it executed.
#[must_use]
pub fn sigop_count(script: &[u8], mode: SigOpMode) -> u32 {
    let mut count: u32 = 0;
    let mut previous = Opcode(OP_INVALIDOPCODE);
    let mut reader = Reader::new(script);
    // Every opcode consumes at least one byte, so the script length bounds the loop.
    for _ in 0..=script.len() {
        let Some(read) = reader.next_op() else { break };
        // Core: `if (!GetOp(pc, opcode)) break;`, keeping what was counted so far.
        let Ok(op) = read else { break };
        match op.opcode.byte() {
            OP_CHECKSIG | OP_CHECKSIGVERIFY => count += 1,
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let keys_max = u32::try_from(MAX_PUBKEYS_PER_MULTISIG).expect("20 fits");
                let is_small_integer = (OP_1..=OP_16).contains(&previous.byte());
                if mode == SigOpMode::Accurate && is_small_integer {
                    let keys = u32::try_from(previous.small_integer()).expect("1..=16");
                    assert!(keys >= 1);
                    assert!(keys <= keys_max);
                    count += keys;
                } else {
                    count += keys_max;
                }
            }
            _ => {}
        }
        previous = op.opcode;
    }
    // Each opcode adds at most MAX_PUBKEYS_PER_MULTISIG and occupies at least one byte.
    assert!(u64::from(count) <= 20 * u64::try_from(script.len()).expect("usize fits u64"));
    count
}

#[cfg(test)]
mod tests {
    use bitcoin::Script;

    use super::super::opcode::{
        OP_0, OP_1, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
        OP_DUP, OP_PUSHDATA1, OP_PUSHDATA2,
    };
    use super::super::vectors::{CORE_SCRIPT_TESTS_JSON, Json, parse_script};
    use super::{SigOpMode, sigop_count};

    const OP_2: u8 = OP_1 + 1;
    const OP_3: u8 = OP_1 + 2;

    #[test]
    fn checksig_counts_one_and_checkmultisig_counts_twenty_in_legacy_mode() {
        let script = [
            OP_DUP,
            OP_CHECKSIG,
            OP_CHECKSIGVERIFY,
            OP_2,
            OP_CHECKMULTISIG,
        ];
        assert_eq!(sigop_count(&script, SigOpMode::Inaccurate), 22);
        assert_eq!(sigop_count(&script, SigOpMode::Accurate), 4);
        assert_eq!(sigop_count(&[], SigOpMode::Inaccurate), 0);
        assert_eq!(
            sigop_count(&[OP_CHECKMULTISIGVERIFY], SigOpMode::Accurate),
            20
        );
    }

    /// Core reads `lastOpcode` as the previous opcode, whatever it was: a data push or `OP_0`
    /// before a `CHECKMULTISIG` is not a key count, so the maximum applies.
    #[test]
    fn accurate_mode_needs_a_small_integer_immediately_before() {
        assert_eq!(
            sigop_count(&[OP_3, OP_CHECKMULTISIG], SigOpMode::Accurate),
            3
        );
        assert_eq!(
            sigop_count(&[OP_3, OP_DUP, OP_CHECKMULTISIG], SigOpMode::Accurate),
            20
        );
        assert_eq!(
            sigop_count(&[OP_3, 0x01, 0x02, OP_CHECKMULTISIG], SigOpMode::Accurate),
            20
        );
        assert_eq!(
            sigop_count(&[OP_0, OP_CHECKMULTISIG], SigOpMode::Accurate),
            20
        );
        assert_eq!(
            sigop_count(
                &[OP_1, OP_CHECKMULTISIG, OP_CHECKMULTISIG],
                SigOpMode::Accurate
            ),
            21
        );
    }

    /// A truncated push ends the scan; what came before it still counts.
    #[test]
    fn a_parse_failure_stops_the_scan_and_keeps_the_count() {
        let script = [
            OP_CHECKSIG,
            OP_CHECKSIG,
            OP_PUSHDATA1,
            0x10,
            0xaa,
            OP_CHECKSIG,
        ];
        assert_eq!(sigop_count(&script, SigOpMode::Inaccurate), 2);
        let script = [OP_CHECKSIG, OP_PUSHDATA2, 0xff];
        assert_eq!(sigop_count(&script, SigOpMode::Inaccurate), 1);
    }

    /// Every script in Core's vectors, both modes, against rust-bitcoin's counter, whose
    /// semantics match Core's including the stop at a parse error.
    #[test]
    fn agrees_with_rust_bitcoin_on_the_vector_scripts() {
        let rows = Json::parse(CORE_SCRIPT_TESTS_JSON);
        let mut compared = 0;
        for row in rows.as_array() {
            // A witness row opens with an array; a comment row has one string only.
            let row = row.as_array();
            let scripts: Vec<&Json> = row.iter().filter(|item| !item.is_array()).take(2).collect();
            if row.len() < 2 {
                continue;
            }
            for text in scripts {
                // The taproot rows use `#TAPROOTOUTPUT#`-style placeholders the vector
                // runner fills in; there is no script to count here.
                if text.as_str().contains('#') {
                    continue;
                }
                let bytes = parse_script(text.as_str());
                let script = Script::from_bytes(&bytes);
                assert_eq!(
                    usize::try_from(sigop_count(&bytes, SigOpMode::Inaccurate)).unwrap(),
                    script.count_sigops_legacy(),
                    "{text:?}"
                );
                assert_eq!(
                    usize::try_from(sigop_count(&bytes, SigOpMode::Accurate)).unwrap(),
                    script.count_sigops(),
                    "{text:?}"
                );
                compared += 1;
            }
        }
        assert!(compared > 2_000);
    }
}
