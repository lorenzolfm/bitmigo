// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`verify_script`]: Core's `VerifyScript`, the entry point for one input; and
//! [`verify_input`], the same for an input named by its index.
//!
//! The order is Core's and every step of it is consensus: scriptSig, then scriptPubKey on
//! the same stack (never concatenated, CVE-2010-5141), then a true top; then, if the
//! scriptPubKey is a witness program, the witness; then, if it is P2SH, the redeem script
//! from the copy of the stack taken before the scriptPubKey ran, and the witness again if
//! the redeem script is a witness program. `SIGPUSHONLY` and `CLEANSTACK` are checked here
//! by Core under their flags; both are policy and have no branch. A witness program is v0
//! (P2WPKH, P2WSH), a v1 32-byte taproot output when `TAPROOT` is set (BIP341: the annex,
//! the key path, the script path with its commitment and the tapscript rules around
//! `ExecuteWitnessScript`), or anyone-can-spend.

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Script, Transaction, TxOut, Witness};

use super::checker::TxSigChecker;
use super::interpreter::{ExecData, MAX_STACK_SIZE, TapscriptExec, eval_script};
use super::num::cast_to_bool;
use super::opcode::{OP_0, OP_1, OP_16, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160};
use super::reader::{Reader, push_encoding};
use super::sighash::{ANNEX_TAG, TaprootSpend, TxPrecomputed};
use super::stack::{MAX_SCRIPT_ELEMENT_SIZE, Stack};
use super::taproot::{
    ControlBlock, TAPROOT_LEAF_TAPSCRIPT, tapleaf_hash, validation_weight,
    verify_taproot_commitment,
};
use super::{ScriptError, ScriptFlags, SigVersion};

/// `WITNESS_V0_KEYHASH_SIZE`: a P2WPKH program.
const WITNESS_V0_KEYHASH_SIZE: usize = 20;
/// `WITNESS_V0_SCRIPTHASH_SIZE`: a P2WSH program.
const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
/// `WITNESS_V1_TAPROOT_SIZE`: a taproot program, the output key.
const WITNESS_V1_TAPROOT_SIZE: usize = 32;
/// The shortest and longest witness program scripts: a version byte, a push opcode and 2
/// to 40 bytes (BIP141).
const WITNESS_PROGRAM_SCRIPT_LEN_MIN: usize = 4;
const WITNESS_PROGRAM_SCRIPT_LEN_MAX: usize = 42;

/// Verifies input `index` of `tx` against the output it spends, under `flags`: the seam the
/// node calls once per input, sharing one `precomputed` per transaction across inputs and
/// threads (BM-D2 decision 4).
///
/// # Errors
///
/// The first [`ScriptError`] the evaluation hits, named as Core names it.
///
/// # Panics
///
/// If `index` is not an input of `tx`, `prevouts` is not one output per input, or
/// `precomputed` was built for another transaction; and on the flag combinations
/// [`verify_script`] refuses.
pub fn verify_input(
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    precomputed: &TxPrecomputed,
    flags: ScriptFlags,
) -> Result<(), ScriptError> {
    assert!(index < tx.input.len());
    assert_eq!(prevouts.len(), tx.input.len(), "one prevout per input");
    let input = tx.input.get(index).expect("index < tx.input.len()");
    let prevout = prevouts.get(index).expect("one prevout per input");
    let checker = TxSigChecker::new(tx, index, prevouts, precomputed);
    verify_script(
        &input.script_sig,
        &prevout.script_pubkey,
        &input.witness,
        flags,
        &checker,
    )
}

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
/// [`crate::params::ChainParams::rules_at`] can produce.
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
/// a native v1 32-byte program is taproot once `TAPROOT` is set; every other version, size
/// and wrapping is anyone-can-spend until a softfork says otherwise.
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
    if version == 0 {
        let items: Vec<&[u8]> = witness.iter().collect();
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
                ExecData::legacy(),
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
                ExecData::legacy(),
                checker,
            );
        }
        return Err(ScriptError::WitnessProgramWrongLength);
    }
    if version == 1
        && !is_p2sh
        && let Ok(output_key) = <&[u8; WITNESS_V1_TAPROOT_SIZE]>::try_from(program)
    {
        // BIP341 taproot. Before its activation a v1 program is anyone-can-spend.
        if !flags.contains(ScriptFlags::TAPROOT) {
            return Ok(());
        }
        return verify_taproot(witness, output_key, flags, checker);
    }
    // Pay-to-anchor and every other version, size and P2SH combination: anyone can spend,
    // so that a future softfork can give them meaning. DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    // would reject them; it is policy.
    Ok(())
}

/// The taproot arm of `VerifyWitnessProgram` (BIP341): strip the annex, then either the
/// key path, one Schnorr signature over the output key, or the script path, a leaf and a
/// control block whose commitment must hold before the leaf runs as tapscript.
fn verify_taproot(
    witness: &Witness,
    output_key: &[u8; 32],
    flags: ScriptFlags,
    checker: &TxSigChecker<'_>,
) -> Result<(), ScriptError> {
    assert!(flags.contains(ScriptFlags::TAPROOT));
    let mut items: Vec<&[u8]> = witness.iter().collect();
    if items.is_empty() {
        return Err(ScriptError::WitnessProgramWitnessEmpty);
    }
    // With two or more items, a last one starting with 0x50 is the annex: not part of the
    // spend, but committed to by every signature. Non-standard by policy, valid by consensus.
    let mut annex = None;
    if items.len() >= 2
        && items
            .last()
            .is_some_and(|last| last.first() == Some(&ANNEX_TAG))
    {
        annex = items.pop();
    }
    if let [signature] = items.as_slice() {
        // Key path: the signature is over the output key itself, no script involved.
        return checker.check_schnorr(signature, output_key, TaprootSpend::KeyPath, annex);
    }
    // Script path: the control block is last, the leaf script just before it.
    let control = items.pop().expect("two or more items");
    let script = items.pop().expect("two or more items");
    let control = ControlBlock::parse(control)?;
    let leaf_hash = tapleaf_hash(control.leaf_version, script);
    if !verify_taproot_commitment(&control, output_key, &leaf_hash) {
        return Err(ScriptError::WitnessProgramMismatch);
    }
    if control.leaf_version != TAPROOT_LEAF_TAPSCRIPT {
        // An unknown leaf version succeeds without running, so that a softfork can define
        // it. DISCOURAGE_UPGRADABLE_TAPROOT_VERSION would reject it; it is policy.
        return Ok(());
    }
    let exec = ExecData::tapscript(TapscriptExec {
        leaf_hash,
        annex,
        validation_weight_left: validation_weight(witness),
    });
    execute_witness_script(&items, script, flags, SigVersion::Tapscript, exec, checker)
}

/// Core's `ExecuteWitnessScript`: for tapscript, the `OP_SUCCESS` scan and the initial stack
/// count first; then every item within the element limit, the script, and exactly one true
/// element left, flag or no flag.
fn execute_witness_script(
    items: &[&[u8]],
    exec_script: &[u8],
    flags: ScriptFlags,
    sig_version: SigVersion,
    mut exec: ExecData<'_>,
    checker: &TxSigChecker<'_>,
) -> Result<(), ScriptError> {
    assert_ne!(sig_version, SigVersion::Base);
    if sig_version == SigVersion::Tapscript {
        // OP_SUCCESSx overrides everything, the item limits included, so it is looked for
        // before they are checked (BIP342).
        if has_op_success(exec_script)? {
            return Ok(());
        }
        // Tapscript bounds the initial stack; the altstack is empty here.
        if items.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }
    for item in items {
        if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
    }
    let mut stack = Stack::from_items(items.iter().map(|item| item.to_vec()).collect());
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

/// The `OP_SUCCESS` scan of `ExecuteWitnessScript`: the whole tapscript is parsed before it
/// runs, and the first `OP_SUCCESSx` makes the spend valid whatever else the script holds. A
/// truncated push met before one fails as `BAD_OPCODE`, as `GetOp` fails in Core.
/// `DISCOURAGE_OP_SUCCESS` would reject a success opcode; it is policy.
fn has_op_success(script: &[u8]) -> Result<bool, ScriptError> {
    let mut reader = Reader::new(script);
    // Bounded by the script length: every step consumes at least one byte.
    while let Some(step) = reader.next_op() {
        if step?.opcode.is_success() {
            return Ok(true);
        }
    }
    Ok(false)
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

    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::{Hash, hash160};
    use bitcoin::{Amount, Script, ScriptBuf, Transaction, TxOut, Witness};
    use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

    use super::super::interpreter::CODESEPARATOR_POS_NONE;
    use super::super::opcode::*;
    use super::super::sighash::{SIGHASH_ALL, SIGHASH_DEFAULT, TaprootSpend, taproot_sighash};
    use super::super::taproot::{TAPROOT_LEAF_TAPSCRIPT, tapleaf_hash, validation_weight};
    use super::super::vectors::{
        BIP341_WALLET_TEST_VECTORS_JSON, Json, crediting_transaction, spending_transaction,
        taproot_single_leaf,
    };
    use super::super::{ScriptError, ScriptFlags, TxPrecomputed, TxSigChecker};
    use super::{
        is_pay_to_script_hash, is_push_only, p2wpkh_script, verify_input, verify_script,
        witness_program,
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

    /// `DoTest`'s pair for one row, then `verify_script` on input 0.
    fn verify(
        script_sig: &[u8],
        script_pubkey: &[u8],
        witness: &Witness,
        flags: ScriptFlags,
    ) -> Result<(), ScriptError> {
        let credit = crediting_transaction(script_pubkey, 0);
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

    #[test]
    #[should_panic(expected = "flags.contains(ScriptFlags::P2SH)")]
    fn witness_without_p2sh_is_refused() {
        verify(&[OP_1], &[], &Witness::new(), ScriptFlags::WITNESS).expect("unreached");
    }

    #[test]
    #[should_panic(expected = "flags.contains(ScriptFlags::WITNESS)")]
    fn taproot_without_witness_is_refused() {
        let flags = ScriptFlags::P2SH.union(ScriptFlags::TAPROOT);
        verify(&[OP_1], &[], &Witness::new(), flags).expect("unreached");
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
        let witness = Witness::from_slice(&[vec![0x30; 70], vec![0x02; 33]]);
        let flags = ScriptFlags::P2SH.union(ScriptFlags::WITNESS);
        assert_eq!(
            verify(&script_sig, &script_pubkey, &witness, flags),
            Err(ScriptError::WitnessMalleatedP2sh)
        );
        // Without WITNESS the same spend is a plain P2SH spend that leaves the program on
        // the stack, and the witness is not looked at.
        assert_eq!(
            verify(&script_sig, &script_pubkey, &witness, ScriptFlags::P2SH),
            Ok(())
        );
    }

    /// `OP_1 <32-byte key>`: a taproot output.
    fn p2tr_script(output_key: &[u8; 32]) -> Vec<u8> {
        let mut script = vec![OP_1, 0x20];
        script.extend(output_key);
        script
    }

    /// A one-input spend of a taproot output paying `amount`, with the witness to be filled
    /// in: the transaction and its prevouts, for signing and for verifying.
    fn taproot_spend(output_key: &[u8; 32], witness: Witness) -> (Transaction, Vec<TxOut>) {
        let credit = crediting_transaction(&p2tr_script(output_key), 100_000);
        let spend = spending_transaction(&[], witness, &credit);
        let prevouts = vec![credit.output[0].clone()];
        (spend, prevouts)
    }

    fn verify_taproot_spend(
        spend: &Transaction,
        prevouts: &[TxOut],
        flags: ScriptFlags,
    ) -> Result<(), ScriptError> {
        let precomputed = TxPrecomputed::new(spend, prevouts);
        verify_input(spend, 0, prevouts, &precomputed, flags)
    }

    /// A BIP340 signature over `digest` by `keypair`, with `hash_type` appended unless it is
    /// the default.
    fn schnorr_sign(keypair: &Keypair, digest: [u8; 32], hash_type: u8) -> Vec<u8> {
        let secp = Secp256k1::new();
        let mut signature = secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), keypair)
            .serialize()
            .to_vec();
        if hash_type != SIGHASH_DEFAULT {
            signature.push(hash_type);
        }
        signature
    }

    fn keypair(seed: u8) -> Keypair {
        let mut secret = [0u8; 32];
        secret[31] = seed;
        Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&secret).expect("a small nonzero scalar"),
        )
    }

    #[test]
    fn taproot_key_path_is_one_schnorr_signature() {
        let keypair = keypair(7);
        let output_key = keypair.x_only_public_key().0.serialize();
        let (spend, prevouts) = taproot_spend(&output_key, Witness::new());
        let precomputed = TxPrecomputed::new(&spend, &prevouts);
        let digest = |hash_type, annex| {
            taproot_sighash(
                &spend,
                0,
                &prevouts,
                hash_type,
                TaprootSpend::KeyPath,
                annex,
                &precomputed,
            )
            .expect("a defined hash type")
        };
        let flags = ScriptFlags::MANDATORY;
        let signed = |witness: Witness, flags| {
            let (spend, prevouts) = taproot_spend(&output_key, witness);
            verify_taproot_spend(&spend, &prevouts, flags)
        };

        let default_sig = schnorr_sign(&keypair, digest(SIGHASH_DEFAULT, None), SIGHASH_DEFAULT);
        assert_eq!(signed(Witness::from_slice(&[&default_sig]), flags), Ok(()));
        let all_sig = schnorr_sign(&keypair, digest(SIGHASH_ALL, None), SIGHASH_ALL);
        assert_eq!(signed(Witness::from_slice(&[&all_sig]), flags), Ok(()));
        // Without TAPROOT the program is anyone-can-spend, whatever the witness.
        let pre_activation = flags.difference(ScriptFlags::TAPROOT);
        assert_eq!(
            signed(Witness::from_slice(&[&[0u8][..]]), pre_activation),
            Ok(())
        );

        // An annex is stripped and committed to: a signature that ignored it fails, one
        // that signed it passes; and a lone item starting with 0x50 is the signature.
        let annex = [0x50, 0xaa, 0xbb];
        let witness = Witness::from_slice(&[&default_sig[..], &annex[..]]);
        assert_eq!(signed(witness, flags), Err(ScriptError::SchnorrSig));
        let annex_sig = schnorr_sign(
            &keypair,
            digest(SIGHASH_DEFAULT, Some(&annex)),
            SIGHASH_DEFAULT,
        );
        let witness = Witness::from_slice(&[&annex_sig[..], &annex[..]]);
        assert_eq!(signed(witness, flags), Ok(()));
        let witness = Witness::from_slice(&[&annex]);
        assert_eq!(signed(witness, flags), Err(ScriptError::SchnorrSigSize));

        // The failures Core names.
        assert_eq!(
            signed(Witness::new(), flags),
            Err(ScriptError::WitnessProgramWitnessEmpty)
        );
        let mut wrong = default_sig.clone();
        wrong[10] ^= 1;
        assert_eq!(
            signed(Witness::from_slice(&[&wrong]), flags),
            Err(ScriptError::SchnorrSig)
        );
        let mut explicit_default = default_sig.clone();
        explicit_default.push(SIGHASH_DEFAULT);
        assert_eq!(
            signed(Witness::from_slice(&[&explicit_default]), flags),
            Err(ScriptError::SchnorrSigHashtype)
        );
        assert_eq!(
            signed(Witness::from_slice(&[&default_sig[..63]]), flags),
            Err(ScriptError::SchnorrSigSize)
        );
        // A non-empty scriptSig on a native program is malleation, before any of that.
        let credit = crediting_transaction(&p2tr_script(&output_key), 100_000);
        let spend = spending_transaction(&[OP_0], Witness::from_slice(&[&default_sig]), &credit);
        let prevouts = vec![credit.output[0].clone()];
        assert_eq!(
            verify_taproot_spend(&spend, &prevouts, flags),
            Err(ScriptError::WitnessMalleated)
        );
    }

    /// The programs a v1 32-byte push is not: P2SH-wrapped, or of another size. Anyone can
    /// spend them with TAPROOT set, as without.
    #[test]
    fn taproot_applies_to_native_v1_32_byte_programs_only() {
        let flags = ScriptFlags::MANDATORY;
        let junk = Witness::from_slice(&[&[0xaa][..]]);
        let mut v1_33 = vec![OP_1, 0x21];
        v1_33.extend([0x33; 33]);
        assert_eq!(verify(&[], &v1_33, &junk, flags), Ok(()));
        let p2a = [OP_1, 0x02, 0x4e, 0x73];
        assert_eq!(verify(&[], &p2a, &junk, flags), Ok(()));
        let redeem = p2tr_script(&[0x44; 32]);
        let mut script_pubkey = vec![OP_HASH160, 0x14];
        script_pubkey.extend(hash160::Hash::hash(&redeem).as_byte_array());
        script_pubkey.push(OP_EQUAL);
        let mut script_sig = vec![0x22];
        script_sig.extend(&redeem);
        assert_eq!(verify(&script_sig, &script_pubkey, &junk, flags), Ok(()));
    }

    #[test]
    fn taproot_script_path_checks_the_commitment_then_runs_the_leaf() {
        let flags = ScriptFlags::MANDATORY;
        let leaf = [OP_1];
        let (control, output_key) = taproot_single_leaf(&leaf, TAPROOT_LEAF_TAPSCRIPT);
        let run = |items: &[&[u8]], output_key: &[u8; 32]| {
            let (spend, prevouts) = taproot_spend(output_key, Witness::from_slice(items));
            verify_taproot_spend(&spend, &prevouts, flags)
        };
        assert_eq!(run(&[&leaf, &control], &output_key), Ok(()));
        // An annex rides along a script path too.
        assert_eq!(run(&[&leaf, &control, &[0x50]], &output_key), Ok(()));
        // A false leaf, a leaf leaving two items, and a leaf that fails.
        let (control_0, output_0) = taproot_single_leaf(&[OP_0], TAPROOT_LEAF_TAPSCRIPT);
        assert_eq!(
            run(&[&[OP_0], &control_0], &output_0),
            Err(ScriptError::EvalFalse)
        );
        let (control_11, output_11) = taproot_single_leaf(&[OP_1, OP_1], TAPROOT_LEAF_TAPSCRIPT);
        assert_eq!(
            run(&[&[OP_1, OP_1], &control_11], &output_11),
            Err(ScriptError::Cleanstack)
        );
        let (control_ret, output_ret) = taproot_single_leaf(&[OP_RETURN], TAPROOT_LEAF_TAPSCRIPT);
        assert_eq!(
            run(&[&[OP_RETURN], &control_ret], &output_ret),
            Err(ScriptError::OpReturn)
        );

        // The commitment: wrong parity, wrong output key, another leaf, wrong sizes.
        let mut flipped = control.clone();
        flipped[0] ^= 1;
        assert_eq!(
            run(&[&leaf, &flipped], &output_key),
            Err(ScriptError::WitnessProgramMismatch)
        );
        assert_eq!(
            run(&[&leaf, &control], &output_0),
            Err(ScriptError::WitnessProgramMismatch)
        );
        assert_eq!(
            run(&[&[OP_0], &control], &output_key),
            Err(ScriptError::WitnessProgramMismatch)
        );
        let mut with_node = control.clone();
        with_node.extend([0x11; 32]);
        assert_eq!(
            run(&[&leaf, &with_node], &output_key),
            Err(ScriptError::WitnessProgramMismatch)
        );
        assert_eq!(
            run(&[&leaf, &control[..32]], &output_key),
            Err(ScriptError::TaprootWrongControlSize)
        );
        let mut too_long = control.clone();
        too_long.push(0);
        assert_eq!(
            run(&[&leaf, &too_long], &output_key),
            Err(ScriptError::TaprootWrongControlSize)
        );

        // An unknown leaf version succeeds without running: even OP_RETURN passes.
        let (control_unknown, output_unknown) = taproot_single_leaf(&[OP_RETURN], 0xc2);
        assert_eq!(
            run(&[&[OP_RETURN], &control_unknown], &output_unknown),
            Ok(())
        );
        // ... but only when its commitment holds.
        let mut as_tapscript = control_unknown.clone();
        as_tapscript[0] = TAPROOT_LEAF_TAPSCRIPT | (as_tapscript[0] & 1);
        assert_eq!(
            run(&[&[OP_RETURN], &as_tapscript], &output_unknown),
            Err(ScriptError::WitnessProgramMismatch)
        );
    }

    #[test]
    fn tapscript_op_success_overrides_everything() {
        let flags = ScriptFlags::MANDATORY;
        let run = |items: &[&[u8]], leaf: &[u8]| {
            let (control, output_key) = taproot_single_leaf(leaf, TAPROOT_LEAF_TAPSCRIPT);
            let mut witness: Vec<&[u8]> = items.to_vec();
            witness.push(leaf);
            witness.push(&control);
            let (spend, prevouts) = taproot_spend(&output_key, Witness::from_slice(&witness));
            verify_taproot_spend(&spend, &prevouts, flags)
        };
        // OP_SUCCESS80 (OP_RESERVED), then a truncated push: valid. OP_SUCCESS254 too.
        assert_eq!(run(&[], &[OP_RESERVED, OP_PUSHDATA1]), Ok(()));
        assert_eq!(run(&[], &[OP_IF, 0xfe]), Ok(()));
        // A disabled opcode is a success opcode in tapscript.
        assert_eq!(run(&[], &[OP_CAT]), Ok(()));
        // A parse error before any success opcode fails, as does one with none.
        assert_eq!(run(&[], &[OP_PUSHDATA1]), Err(ScriptError::BadOpcode));
        assert_eq!(
            run(&[], &[OP_1, 0x03, 0xaa, OP_RESERVED]),
            Err(ScriptError::BadOpcode)
        );
        assert_eq!(run(&[], &[OP_VERIF]), Err(ScriptError::BadOpcode));
        // The success scan comes before the item limits: an oversized item and an oversized
        // stack both pass with a success opcode, and fail their own way without one.
        let big = vec![0u8; 521];
        assert_eq!(run(&[&big], &[OP_RESERVED]), Ok(()));
        assert_eq!(run(&[&big], &[OP_DROP, OP_1]), Err(ScriptError::PushSize));
        let many: Vec<&[u8]> = vec![&[][..]; 1001];
        assert_eq!(run(&many, &[OP_RESERVED]), Ok(()));
        assert_eq!(run(&many, &[OP_1]), Err(ScriptError::StackSize));
        let enough: Vec<&[u8]> = vec![&[][..]; 1000];
        assert_eq!(run(&enough, &[OP_1]), Err(ScriptError::StackSize));
        let fits: Vec<&[u8]> = vec![&[][..]; 999];
        assert_eq!(run(&fits, &[OP_1]), Err(ScriptError::Cleanstack));
        // No size limit and no opcode limit in tapscript: 20,003 bytes, 20,002 opcodes.
        let mut long = Vec::new();
        for _ in 0..10_001 {
            long.push(OP_1);
            long.push(OP_DROP);
        }
        long.push(OP_1);
        assert_eq!(run(&[], &long), Ok(()));
    }

    /// The budget is `50 + the serialized witness`, control block and leaf included, and
    /// each non-empty signature costs 50: one signature reused through `OP_DUP` finds the
    /// edge, since a fresh 64-byte signature would always pay for itself.
    #[test]
    fn tapscript_sigop_budget_comes_from_the_witness_size() {
        let flags = ScriptFlags::MANDATORY;
        let keypair = keypair(9);
        let pubkey = keypair.x_only_public_key().0.serialize();
        let run = |checks: usize| {
            let mut leaf = Vec::new();
            for _ in 1..checks {
                leaf.push(OP_DUP);
                leaf.push(0x20);
                leaf.extend(pubkey);
                leaf.push(OP_CHECKSIGVERIFY);
            }
            leaf.push(0x20);
            leaf.extend(pubkey);
            leaf.push(OP_CHECKSIG);
            let (control, output_key) = taproot_single_leaf(&leaf, TAPROOT_LEAF_TAPSCRIPT);
            let (spend, prevouts) = taproot_spend(&output_key, Witness::new());
            let precomputed = TxPrecomputed::new(&spend, &prevouts);
            let spend_kind = TaprootSpend::Tapscript {
                leaf_hash: tapleaf_hash(TAPROOT_LEAF_TAPSCRIPT, &leaf),
                codesep_pos: CODESEPARATOR_POS_NONE,
            };
            let digest = taproot_sighash(
                &spend,
                0,
                &prevouts,
                SIGHASH_DEFAULT,
                spend_kind,
                None,
                &precomputed,
            )
            .expect("default hash type");
            let signature = schnorr_sign(&keypair, digest, SIGHASH_DEFAULT);
            let witness = Witness::from_slice(&[&signature, &leaf, &control]);
            let budget = validation_weight(&witness);
            let (spend, prevouts) = taproot_spend(&output_key, witness);
            (budget, verify_taproot_spend(&spend, &prevouts, flags))
        };
        let (budget_10, verdict_10) = run(10);
        assert!(budget_10 >= 500);
        assert_eq!(verdict_10, Ok(()));
        let (budget_11, verdict_11) = run(11);
        assert!(budget_11 < 550);
        assert_eq!(verdict_11, Err(ScriptError::TapscriptValidationWeight));
    }

    /// BIP341's fully signed transaction: seven key-path inputs over every hash type, one
    /// P2PKH and one P2WPKH, all through `verify_input` under the mandatory flags.
    #[test]
    fn verify_input_accepts_the_bip341_signed_transaction() {
        let vectors = Json::parse(BIP341_WALLET_TEST_VECTORS_JSON);
        let case = &vectors.get("keyPathSpending").as_array()[0];
        let tx: Transaction =
            deserialize(&case.get("auxiliary").get("fullySignedTx").as_bytes()).expect("a tx");
        let prevouts: Vec<TxOut> = case
            .get("given")
            .get("utxosSpent")
            .as_array()
            .iter()
            .map(|utxo| TxOut {
                value: Amount::from_sat(
                    u64::try_from(utxo.get("amountSats").as_i64()).expect("positive"),
                ),
                script_pubkey: ScriptBuf::from_bytes(utxo.get("scriptPubKey").as_bytes()),
            })
            .collect();
        assert_eq!(tx.input.len(), 9);
        assert_eq!(prevouts.len(), 9);
        let precomputed = TxPrecomputed::new(&tx, &prevouts);
        for index in 0..tx.input.len() {
            assert_eq!(
                verify_input(&tx, index, &prevouts, &precomputed, ScriptFlags::MANDATORY),
                Ok(()),
                "input {index}"
            );
        }
        // A damaged key-path signature is caught, and only on its own input.
        let mut damaged = tx.clone();
        let mut signature = damaged.input[3].witness.to_vec();
        signature[0][5] ^= 1;
        damaged.input[3].witness = Witness::from_slice(&signature);
        let precomputed = TxPrecomputed::new(&damaged, &prevouts);
        assert_eq!(
            verify_input(&damaged, 3, &prevouts, &precomputed, ScriptFlags::MANDATORY),
            Err(ScriptError::SchnorrSig)
        );
        assert_eq!(
            verify_input(&damaged, 4, &prevouts, &precomputed, ScriptFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    #[should_panic(expected = "index < tx.input.len()")]
    fn verify_input_refuses_an_index_past_the_inputs() {
        let credit = crediting_transaction(&[OP_1], 0);
        let spend = spending_transaction(&[], Witness::new(), &credit);
        let prevouts = vec![credit.output[0].clone()];
        let precomputed = TxPrecomputed::new(&spend, &prevouts);
        verify_input(&spend, 1, &prevouts, &precomputed, ScriptFlags::MANDATORY)
            .expect("unreached");
    }

    #[test]
    #[should_panic(expected = "one prevout per input")]
    fn verify_input_refuses_a_prevout_count_mismatch() {
        let credit = crediting_transaction(&[OP_1], 0);
        let spend = spending_transaction(&[], Witness::new(), &credit);
        let prevouts = vec![credit.output[0].clone()];
        let precomputed = TxPrecomputed::new(&spend, &prevouts);
        verify_input(&spend, 0, &[], &precomputed, ScriptFlags::MANDATORY).expect("unreached");
    }
}
