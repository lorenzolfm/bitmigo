// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature operation counting: Core's `CScript::GetSigOpCount(bool fAccurate)` (§2.2).
//!
//! The count is a static scan, not an execution: every `CHECKSIG` in the script counts,
//! whether or not a branch would ever reach it, and the scan stops silently at the first
//! opcode that fails to parse, exactly as Core's does. The block rules add the counts of
//! every script in a block and compare the total with `MAX_BLOCK_SIGOPS_COST`: the legacy
//! count at receipt, and once the coins are known [`p2sh_sigop_count`] over the redeem
//! script and [`witness_sigop_count`] over the witness program (`GetTransactionSigOpCost`).

use bitcoin::Witness;

use super::ScriptFlags;
use super::interpreter::MAX_PUBKEYS_PER_MULTISIG;
use super::opcode::{
    OP_1, OP_16, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_INVALIDOPCODE, Opcode,
};
use super::reader::Reader;
use super::verify::{is_pay_to_script_hash, witness_program};

/// `WITNESS_V0_KEYHASH_SIZE`: a P2WPKH program, which costs one signature operation.
const WITNESS_V0_KEYHASH_SIZE: usize = 20;
/// `WITNESS_V0_SCRIPTHASH_SIZE`: a P2WSH program, which costs what its script does.
const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;

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

/// Core's `GetP2SHSigOpCount` for one input: when `script_pubkey` is P2SH, the accurate
/// count of the redeem script, being the last item `script_sig` pushes
/// (`CScript::GetSigOpCount(scriptSig)`, BIP16); zero for any other output. A `scriptSig`
/// that is not push-only counts zero, as does one whose last item is a small integer.
#[must_use]
pub fn p2sh_sigop_count(script_pubkey: &[u8], script_sig: &[u8]) -> u32 {
    if !is_pay_to_script_hash(script_pubkey) {
        return 0;
    }
    match last_push(script_sig) {
        Some(redeem_script) => sigop_count(redeem_script, SigOpMode::Accurate),
        None => 0,
    }
}

/// Core's `CountWitnessSigOps`: the signature operations of the witness program an input
/// spends, native or wrapped in P2SH (BIP141). Zero without the `WITNESS` flag, for a
/// program of any version but 0, and for a P2SH input whose `scriptSig` is not push-only.
#[must_use]
pub fn witness_sigop_count(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &Witness,
    flags: ScriptFlags,
) -> u32 {
    if !flags.contains(ScriptFlags::WITNESS) {
        return 0;
    }
    assert!(flags.contains(ScriptFlags::P2SH));
    if let Some((version, program)) = witness_program(script_pubkey) {
        return witness_program_sigop_count(version, program, witness);
    }
    if is_pay_to_script_hash(script_pubkey)
        && let Some(redeem_script) = last_push(script_sig)
        && let Some((version, program)) = witness_program(redeem_script)
    {
        return witness_program_sigop_count(version, program, witness);
    }
    0
}

/// Core's `WitnessSigOps`: one for P2WPKH; the accurate count of the witness script, the
/// last witness item, for P2WSH; nothing for a missing witness or another version.
fn witness_program_sigop_count(version: u8, program: &[u8], witness: &Witness) -> u32 {
    assert!(program.len() >= 2);
    assert!(program.len() <= 40);
    if version != 0 {
        return 0;
    }
    if program.len() == WITNESS_V0_KEYHASH_SIZE {
        return 1;
    }
    if program.len() == WITNESS_V0_SCRIPTHASH_SIZE
        && let Some(witness_script) = witness.last()
    {
        return sigop_count(witness_script, SigOpMode::Accurate);
    }
    0
}

/// The data of the last push in a push-only script: what a P2SH `scriptSig` leaves on top
/// of the stack. `None` when an opcode above `OP_16` or a truncated push is met, where
/// Core's `GetOp` loop gives up; `Some(&[])` when the last opcode is `OP_0` or `OP_1..OP_16`,
/// whose "data" Core's `GetOp` clears.
fn last_push(script_sig: &[u8]) -> Option<&[u8]> {
    let mut last: &[u8] = &[];
    let mut reader = Reader::new(script_sig);
    // Every opcode consumes at least one byte, so the script length bounds the loop.
    for _ in 0..=script_sig.len() {
        let Some(read) = reader.next_op() else { break };
        let Ok(op) = read else { return None };
        if op.opcode.byte() > OP_16 {
            return None;
        }
        last = op.push;
    }
    Some(last)
}

#[cfg(test)]
mod tests {
    use bitcoin::Script;

    use super::super::ScriptFlags;
    use super::super::opcode::{
        OP_0, OP_1, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
        OP_DUP, OP_PUSHDATA1, OP_PUSHDATA2,
    };
    use super::super::reader::push_encoding;
    use super::super::vectors::{CORE_SCRIPT_TESTS_JSON, Json, parse_script};
    use super::{SigOpMode, p2sh_sigop_count, sigop_count, witness_sigop_count};

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

    /// Core's `GetSigOpCount` test, the P2SH half: the redeem script is the last push of
    /// the `scriptSig`, counted accurately; a `scriptSig` that is not push-only, or ends
    /// in a small integer, reveals nothing; and a non-P2SH output is not this count's.
    #[test]
    fn p2sh_sigop_count_reads_the_redeem_script() {
        use bitcoin::hashes::{Hash, hash160};
        let dummy = [0u8; 20];
        let mut s1 = vec![OP_1];
        s1.extend(push_encoding(&dummy));
        s1.extend(push_encoding(&dummy));
        s1.extend([0x52, OP_CHECKMULTISIG, 0x63, OP_CHECKSIG, 0x68]);
        assert_eq!(sigop_count(&s1, SigOpMode::Accurate), 3);
        assert_eq!(sigop_count(&s1, SigOpMode::Inaccurate), 21);
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&hash160::Hash::hash(&s1).to_byte_array());
        p2sh.push(0x87);
        let mut script_sig = vec![0x00];
        script_sig.extend(push_encoding(&s1));
        assert_eq!(p2sh_sigop_count(&p2sh, &script_sig), 3);

        let mut s2 = vec![OP_1];
        for _ in 0..3 {
            s2.extend(push_encoding(&[0x02; 33]));
        }
        s2.extend([0x53, OP_CHECKMULTISIG]);
        assert_eq!(sigop_count(&s2, SigOpMode::Accurate), 3);
        assert_eq!(sigop_count(&s2, SigOpMode::Inaccurate), 20);
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&hash160::Hash::hash(&s2).to_byte_array());
        p2sh.push(0x87);
        assert_eq!(sigop_count(&p2sh, SigOpMode::Accurate), 0);
        let mut script_sig_2 = vec![OP_1];
        script_sig_2.extend(push_encoding(&dummy));
        script_sig_2.extend(push_encoding(&dummy));
        script_sig_2.extend(push_encoding(&s2));
        assert_eq!(p2sh_sigop_count(&p2sh, &script_sig_2), 3);

        // Not push-only, ending in a small integer, truncated, or not P2SH at all.
        let mut not_push_only = script_sig_2.clone();
        not_push_only.push(OP_CHECKSIG);
        assert_eq!(p2sh_sigop_count(&p2sh, &not_push_only), 0);
        let mut ends_in_two = script_sig_2.clone();
        ends_in_two.push(0x52);
        assert_eq!(p2sh_sigop_count(&p2sh, &ends_in_two), 0);
        let mut truncated = script_sig_2.clone();
        truncated.pop();
        assert_eq!(p2sh_sigop_count(&p2sh, &truncated), 0);
        assert_eq!(p2sh_sigop_count(&s1, &script_sig), 0);
    }

    /// `CountWitnessSigOps`: nothing without `WITNESS`; one for P2WPKH; the accurate count
    /// of the last witness item for P2WSH, nothing when there is no witness; the same
    /// through a P2SH wrapper whose `scriptSig` is push-only; nothing for version 1.
    #[test]
    fn witness_sigop_count_reads_the_program_and_the_witness() {
        use bitcoin::Witness;
        use bitcoin::hashes::{Hash, hash160, sha256};
        let flags = ScriptFlags::P2SH.union(ScriptFlags::WITNESS);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend([0x33; 20]);
        let empty = Witness::new();
        assert_eq!(witness_sigop_count(&[], &p2wpkh, &empty, flags), 1);
        assert_eq!(
            witness_sigop_count(&[], &p2wpkh, &empty, ScriptFlags::P2SH),
            0
        );
        let mut taproot = vec![OP_1, 0x20];
        taproot.extend([0x33; 32]);
        assert_eq!(witness_sigop_count(&[], &taproot, &empty, flags), 0);

        let witness_script = vec![OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIGVERIFY];
        let mut p2wsh = vec![0x00, 0x20];
        p2wsh.extend_from_slice(&sha256::Hash::hash(&witness_script).to_byte_array());
        let witness = Witness::from_slice(&[vec![0x01], witness_script.clone()]);
        assert_eq!(witness_sigop_count(&[], &p2wsh, &witness, flags), 3);
        assert_eq!(witness_sigop_count(&[], &p2wsh, &empty, flags), 0);

        let mut wrapper = vec![0xa9, 0x14];
        wrapper.extend_from_slice(&hash160::Hash::hash(&p2wsh).to_byte_array());
        wrapper.push(0x87);
        let script_sig = push_encoding(&p2wsh);
        assert_eq!(
            witness_sigop_count(&script_sig, &wrapper, &witness, flags),
            3
        );
        let mut not_push_only = script_sig.clone();
        not_push_only.push(OP_CHECKSIG);
        assert_eq!(
            witness_sigop_count(&not_push_only, &wrapper, &witness, flags),
            0
        );
        assert_eq!(witness_sigop_count(&script_sig, &p2wsh, &witness, flags), 3);
        assert_eq!(
            witness_sigop_count(&script_sig, &witness_script, &witness, flags),
            0
        );
    }
}
