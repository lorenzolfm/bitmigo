// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`verify_script`]: Core's `VerifyScript`, the entry point for one input.
//!
//! The order is Core's and every step of it is consensus: scriptSig, then scriptPubKey on
//! the same stack (never concatenated, CVE-2010-5141), then a true top; then, if the
//! scriptPubKey is a witness program, the witness; then, if it is P2SH, the redeem script
//! from the copy of the stack taken before the scriptPubKey ran, and the witness again if
//! the redeem script is a witness program. `SIGPUSHONLY` and `CLEANSTACK` are checked here
//! by Core under their flags; both are policy and have no branch. Taproot's witness branch
//! is not built yet: this function asserts the `TAPROOT` flag is off, so that no caller can
//! mistake "not implemented" for "anyone can spend".

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Script, Witness};

use super::checker::TxSigChecker;
use super::interpreter::{ExecData, eval_script};
use super::num::cast_to_bool;
use super::opcode::{OP_0, OP_1, OP_16, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160};
use super::reader::{Reader, push_encoding};
use super::stack::{MAX_SCRIPT_ELEMENT_SIZE, Stack};
use super::{ScriptError, ScriptFlags, SigVersion};

/// `WITNESS_V0_KEYHASH_SIZE`: a P2WPKH program.
const WITNESS_V0_KEYHASH_SIZE: usize = 20;
/// `WITNESS_V0_SCRIPTHASH_SIZE`: a P2WSH program.
const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
/// `WITNESS_V1_TAPROOT_SIZE`: a taproot program.
const WITNESS_V1_TAPROOT_SIZE: usize = 32;
/// The shortest and longest witness program scripts: a version byte, a push opcode and 2
/// to 40 bytes (BIP141).
const WITNESS_PROGRAM_SCRIPT_LEN_MIN: usize = 4;
const WITNESS_PROGRAM_SCRIPT_LEN_MAX: usize = 42;

/// Core's `VerifyScript`: does `script_sig` plus `witness` satisfy `script_pubkey` under
/// `flags`, for the input `checker` describes?
///
/// # Errors
///
/// The first [`ScriptError`] the evaluation hits, named as Core names it.
///
/// # Panics
///
/// If `flags` sets `WITNESS` without `P2SH` or `TAPROOT` without `WITNESS`, neither of which
/// [`crate::params::ChainParams::rules_at`] can produce; and, until the taproot verifier
/// lands, if `TAPROOT` is set at all.
pub fn verify_script(
    script_sig: &Script,
    script_pubkey: &Script,
    witness: &Witness,
    flags: ScriptFlags,
    checker: &TxSigChecker<'_>,
) -> Result<(), ScriptError> {
    if flags.contains(ScriptFlags::WITNESS) {
        assert!(flags.contains(ScriptFlags::P2SH));
    }
    if flags.contains(ScriptFlags::TAPROOT) {
        assert!(flags.contains(ScriptFlags::WITNESS));
    }
    assert!(
        !flags.contains(ScriptFlags::TAPROOT),
        "taproot verification is not built yet"
    );
    let script_sig = script_sig.as_bytes();
    let script_pubkey = script_pubkey.as_bytes();

    let mut exec = ExecData::legacy();
    let mut stack = Stack::new();
    eval_script(
        script_sig,
        &mut stack,
        flags,
        SigVersion::Base,
        &mut exec,
        checker,
    )?;
    let stack_copy = if flags.contains(ScriptFlags::P2SH) {
        Some(stack.clone())
    } else {
        None
    };
    eval_script(
        script_pubkey,
        &mut stack,
        flags,
        SigVersion::Base,
        &mut exec,
        checker,
    )?;
    if stack.is_empty() || !cast_to_bool(stack.top(1)) {
        return Err(ScriptError::EvalFalse);
    }

    let mut had_witness = false;
    if flags.contains(ScriptFlags::WITNESS)
        && let Some((version, program)) = witness_program(script_pubkey)
    {
        had_witness = true;
        // The scriptSig must be exactly empty, or a third party could add to it.
        if !script_sig.is_empty() {
            return Err(ScriptError::WitnessMalleated);
        }
        verify_witness_program(witness, version, program, flags, checker, false)?;
        // Core resizes the stack to one element here for CLEANSTACK; that check is policy.
    }

    if flags.contains(ScriptFlags::P2SH) && is_pay_to_script_hash(script_pubkey) {
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigPushonly);
        }
        let mut stack = stack_copy.expect("P2SH is set, so the copy was taken");
        // The scriptPubKey's HASH160 EQUAL consumed something, so the copy is not empty.
        assert!(!stack.is_empty());
        let redeem_script = stack.pop();
        had_witness = verify_redeem_script(
            script_sig,
            &redeem_script,
            &mut stack,
            witness,
            flags,
            checker,
        )?;
    }

    // CLEANSTACK is policy; nothing to check here.

    if flags.contains(ScriptFlags::WITNESS) && !had_witness && !witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }
    Ok(())
}

/// The P2SH second half: runs the redeem script over the stack that fed it, then, if it is
/// a witness program, the witness. Returns whether a witness program was found.
fn verify_redeem_script(
    script_sig: &[u8],
    redeem_script: &[u8],
    stack: &mut Stack,
    witness: &Witness,
    flags: ScriptFlags,
    checker: &TxSigChecker<'_>,
) -> Result<bool, ScriptError> {
    let mut exec = ExecData::legacy();
    eval_script(
        redeem_script,
        stack,
        flags,
        SigVersion::Base,
        &mut exec,
        checker,
    )?;
    if stack.is_empty() || !cast_to_bool(stack.top(1)) {
        return Err(ScriptError::EvalFalse);
    }
    if !flags.contains(ScriptFlags::WITNESS) {
        return Ok(false);
    }
    let Some((version, program)) = witness_program(redeem_script) else {
        return Ok(false);
    };
    // The scriptSig must be exactly one push of the redeem script, or a third party could
    // add to it.
    if script_sig != push_encoding(redeem_script) {
        return Err(ScriptError::WitnessMalleatedP2sh);
    }
    verify_witness_program(witness, version, program, flags, checker, true)?;
    Ok(true)
}

/// Core's `VerifyWitnessProgram`: v0 is P2WSH or P2WPKH by program length and nothing else;
/// every other version is anyone-can-spend until a softfork says otherwise. The one that
/// did, taproot, is not built yet and cannot be reached with `TAPROOT` off.
fn verify_witness_program(
    witness: &Witness,
    version: u8,
    program: &[u8],
    flags: ScriptFlags,
    checker: &TxSigChecker<'_>,
    is_p2sh: bool,
) -> Result<(), ScriptError> {
    assert!(program.len() >= 2);
    assert!(program.len() <= 40);
    let items: Vec<&[u8]> = witness.iter().collect();
    if version == 0 {
        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            // BIP141 P2WSH: the last item is the script, the rest its stack.
            let Some((script, stack_items)) = items.split_last() else {
                return Err(ScriptError::WitnessProgramWitnessEmpty);
            };
            if sha256::Hash::hash(script).as_byte_array() != program {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            return execute_witness_script(
                stack_items,
                script,
                flags,
                SigVersion::WitnessV0,
                checker,
            );
        }
        if program.len() == WITNESS_V0_KEYHASH_SIZE {
            // BIP141 P2WPKH: signature and key, run through the implied P2PKH script.
            if items.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            let exec_script = p2wpkh_script(program);
            return execute_witness_script(
                &items,
                &exec_script,
                flags,
                SigVersion::WitnessV0,
                checker,
            );
        }
        return Err(ScriptError::WitnessProgramWrongLength);
    }
    if version == 1 && program.len() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh {
        // BIP341 taproot. Before its activation a v1 program is anyone-can-spend; the
        // verifier for after it is the pair of this assertion in `verify_script`.
        assert!(!flags.contains(ScriptFlags::TAPROOT));
        return Ok(());
    }
    // Pay-to-anchor and every other version, size and P2SH combination: anyone can spend,
    // so that a future softfork can give them meaning. DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    // would reject them; it is policy.
    Ok(())
}

/// Core's `ExecuteWitnessScript` for v0: every item within the element limit, then the
/// script, then exactly one true element left, flag or no flag.
fn execute_witness_script(
    items: &[&[u8]],
    exec_script: &[u8],
    flags: ScriptFlags,
    sig_version: SigVersion,
    checker: &TxSigChecker<'_>,
) -> Result<(), ScriptError> {
    // The OP_SUCCESS scan and the initial stack count arrive with tapscript.
    assert_eq!(sig_version, SigVersion::WitnessV0);
    for item in items {
        if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
    }
    let mut stack = Stack::from_items(items.iter().map(|item| item.to_vec()).collect());
    let mut exec = ExecData::legacy();
    eval_script(
        exec_script,
        &mut stack,
        flags,
        sig_version,
        &mut exec,
        checker,
    )?;
    // Scripts inside a witness implicitly require cleanstack behaviour.
    if stack.len() != 1 {
        return Err(ScriptError::Cleanstack);
    }
    if !cast_to_bool(stack.top(1)) {
        return Err(ScriptError::EvalFalse);
    }
    Ok(())
}

/// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`: what a P2WPKH program stands
/// for, and its BIP143 scriptCode.
#[must_use]
pub fn p2wpkh_script(program: &[u8]) -> Vec<u8> {
    assert_eq!(program.len(), WITNESS_V0_KEYHASH_SIZE);
    let mut script = vec![OP_DUP, OP_HASH160, 0x14];
    script.extend_from_slice(program);
    script.push(OP_EQUALVERIFY);
    script.push(OP_CHECKSIG);
    assert_eq!(script.len(), 25);
    script
}

/// `CScript::IsPayToScriptHash`: exactly `OP_HASH160 <20 bytes> OP_EQUAL` (BIP16).
#[must_use]
pub fn is_pay_to_script_hash(script: &[u8]) -> bool {
    matches!(script, [OP_HASH160, 0x14, .., OP_EQUAL] if script.len() == 23)
}

/// `CScript::IsWitnessProgram`: a version opcode (`OP_0`, `OP_1..OP_16`) then one direct
/// push of 2 to 40 bytes that ends the script (BIP141). Returns the version and program.
#[must_use]
pub fn witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < WITNESS_PROGRAM_SCRIPT_LEN_MIN
        || script.len() > WITNESS_PROGRAM_SCRIPT_LEN_MAX
    {
        return None;
    }
    let [version_byte, push_len, program @ ..] = script else {
        return None;
    };
    let version = match *version_byte {
        OP_0 => 0,
        OP_1..=OP_16 => version_byte - OP_1 + 1,
        _ => return None,
    };
    if usize::from(*push_len) + 2 != script.len() {
        return None;
    }
    assert_eq!(program.len(), usize::from(*push_len));
    Some((version, program))
}

/// `CScript::IsPushOnly`: nothing above `OP_16`, and no truncated push. `OP_RESERVED`
/// counts as a push here, as in Core; executing it fails anyway.
#[must_use]
pub fn is_push_only(script: &[u8]) -> bool {
    let mut reader = Reader::new(script);
    // Bounded by the script length.
    while let Some(step) = reader.next_op() {
        let Ok(op) = step else {
            return false;
        };
        if op.opcode.byte() > OP_16 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index out of bounds fails the test with a panic"
    )]

    use bitcoin::hashes::{Hash, hash160};
    use bitcoin::{Script, Witness};

    use super::super::opcode::*;
    use super::super::vectors::{crediting_transaction, spending_transaction};
    use super::super::{ScriptFlags, TxPrecomputed, TxSigChecker};
    use super::{
        is_pay_to_script_hash, is_push_only, p2wpkh_script, verify_script, witness_program,
    };

    #[test]
    fn p2sh_pattern_is_exact() {
        let mut p2sh = vec![OP_HASH160, 0x14];
        p2sh.extend([0xab; 20]);
        p2sh.push(OP_EQUAL);
        assert!(is_pay_to_script_hash(&p2sh));
        p2sh.push(OP_NOP);
        assert!(!is_pay_to_script_hash(&p2sh));
        p2sh.pop();
        p2sh[1] = 0x13;
        assert!(!is_pay_to_script_hash(&p2sh));
        assert!(!is_pay_to_script_hash(&[]));
    }

    #[test]
    fn witness_program_detection_follows_bip141() {
        let mut p2wpkh = vec![OP_0, 0x14];
        p2wpkh.extend([0xcd; 20]);
        assert_eq!(witness_program(&p2wpkh), Some((0, &[0xcd; 20][..])));
        let mut p2tr = vec![OP_1, 0x20];
        p2tr.extend([0xef; 32]);
        assert_eq!(witness_program(&p2tr), Some((1, &[0xef; 32][..])));
        assert_eq!(
            witness_program(&[OP_16, 0x02, 0x4e, 0x73]),
            Some((16, &[0x4e, 0x73][..]))
        );
        let mut v16_40 = vec![OP_16, 0x28];
        v16_40.extend([0x01; 40]);
        assert_eq!(witness_program(&v16_40), Some((16, &[0x01; 40][..])));
        // Too short, too long, a non-version opcode, a push that does not end the script,
        // and a PUSHDATA1 instead of a direct push.
        assert_eq!(witness_program(&[OP_0, 0x01, 0xaa]), None);
        let mut too_long = vec![OP_0, 0x29];
        too_long.extend([0x01; 41]);
        assert_eq!(witness_program(&too_long), None);
        assert_eq!(witness_program(&[OP_NOP, 0x02, 0xaa, 0xbb]), None);
        assert_eq!(witness_program(&[OP_0, 0x02, 0xaa, 0xbb, OP_NOP]), None);
        assert_eq!(
            witness_program(&[OP_0, OP_PUSHDATA1, 0x02, 0xaa, 0xbb]),
            None
        );
    }

    #[test]
    fn push_only_stops_at_op_16() {
        assert!(is_push_only(&[]));
        assert!(is_push_only(&[
            OP_0,
            0x02,
            0xaa,
            0xbb,
            OP_PUSHDATA1,
            0x00,
            OP_16,
            OP_RESERVED
        ]));
        assert!(!is_push_only(&[OP_1, OP_NOP]));
        assert!(!is_push_only(&[OP_1, OP_DUP]));
        assert!(!is_push_only(&[0x02, 0xaa]));
    }

    #[test]
    fn p2wpkh_script_is_the_bip143_template() {
        let program = [0x11; 20];
        let script = p2wpkh_script(&program);
        assert_eq!(&script[..3], &[OP_DUP, OP_HASH160, 0x14]);
        assert_eq!(&script[3..23], &program);
        assert_eq!(&script[23..], &[OP_EQUALVERIFY, OP_CHECKSIG]);
    }

    fn verify(script_sig: &[u8], script_pubkey: &[u8], flags: ScriptFlags) {
        let credit = crediting_transaction(script_pubkey, 0);
        let spend = spending_transaction(script_sig, Witness::new(), &credit);
        let prevouts = vec![credit.output[0].clone()];
        let precomputed = TxPrecomputed::new(&spend, &prevouts);
        let checker = TxSigChecker::new(&spend, 0, &prevouts, &precomputed);
        let result = verify_script(
            Script::from_bytes(script_sig),
            Script::from_bytes(script_pubkey),
            &Witness::new(),
            flags,
            &checker,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    #[should_panic(expected = "taproot verification is not built yet")]
    fn taproot_flag_is_refused_until_built() {
        verify(&[OP_1], &[], ScriptFlags::MANDATORY);
    }

    #[test]
    #[should_panic(expected = "flags.contains(ScriptFlags::P2SH)")]
    fn witness_without_p2sh_is_refused() {
        verify(&[OP_1], &[], ScriptFlags::WITNESS);
    }

    #[test]
    fn p2sh_wrapped_v0_program_needs_the_exact_push() {
        // A P2SH-P2WPKH spend whose scriptSig pushes the redeem script with OP_PUSHDATA1
        // instead of the direct push: the hash matches, the malleability rule does not.
        let mut redeem = vec![OP_0, 0x14];
        redeem.extend([0x22; 20]);
        let hash = hash160::Hash::hash(&redeem);
        let mut script_pubkey = vec![OP_HASH160, 0x14];
        script_pubkey.extend(hash.as_byte_array());
        script_pubkey.push(OP_EQUAL);
        let mut script_sig = vec![OP_PUSHDATA1, 0x16];
        script_sig.extend(&redeem);

        let credit = crediting_transaction(&script_pubkey, 0);
        let witness = Witness::from_slice(&[vec![0x30; 70], vec![0x02; 33]]);
        let spend = spending_transaction(&script_sig, witness.clone(), &credit);
        let prevouts = vec![credit.output[0].clone()];
        let precomputed = TxPrecomputed::new(&spend, &prevouts);
        let checker = TxSigChecker::new(&spend, 0, &prevouts, &precomputed);
        let flags = ScriptFlags::P2SH.union(ScriptFlags::WITNESS);
        let result = verify_script(
            Script::from_bytes(&script_sig),
            Script::from_bytes(&script_pubkey),
            &witness,
            flags,
            &checker,
        );
        assert_eq!(result, Err(super::ScriptError::WitnessMalleatedP2sh));
        // Without WITNESS the same spend is a plain P2SH spend that leaves the program on
        // the stack, and the witness is not looked at.
        let result = verify_script(
            Script::from_bytes(&script_sig),
            Script::from_bytes(&script_pubkey),
            &witness,
            ScriptFlags::P2SH,
            &checker,
        );
        assert_eq!(result, Ok(()));
    }
}
