// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`ScriptError`]: why a script failed, in Bitcoin Core's vocabulary.
//!
//! Every variant is a `SCRIPT_ERR_*` that consensus validation can actually produce, named
//! without the prefix; `Display` gives the spelling Core's test vectors use, so an expected
//! error in `script_tests.json` compares by string. Policy-only errors have no variant: a
//! node that cannot represent `SCRIPT_ERR_SIG_HIGH_S` cannot reject a block for it. The
//! absent ones, for the record: `SIG_HASHTYPE`, `MINIMALDATA`, `SIG_HIGH_S`, `PUBKEYTYPE`,
//! `MINIMALIF`, `SIG_NULLFAIL`, `WITNESS_PUBKEYTYPE`, `OP_CODESEPARATOR`,
//! `SIG_FINDANDDELETE` and the five `DISCOURAGE_*`; and `UNKNOWN_ERROR`, which Core sets
//! before evaluating and never returns.
//!
//! `CLEANSTACK` is consensus, despite the flag of the same name being policy: a witness
//! script must leave exactly one element, flag or no flag.

use core::fmt;

/// A consensus script failure, named as Core names it, in Core's enum order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScriptError {
    /// The final stack was empty or its top was false.
    EvalFalse,
    /// `OP_VERIFY` on a false value.
    Verify,
    /// `OP_EQUALVERIFY` on unequal elements.
    Equalverify,
    /// `OP_CHECKMULTISIGVERIFY` on a failed check.
    Checkmultisigverify,
    /// `OP_CHECKSIGVERIFY` on a failed check.
    Checksigverify,
    /// `OP_NUMEQUALVERIFY` on unequal numbers.
    Numequalverify,
    /// A legacy or v0 script over 10,000 bytes.
    ScriptSize,
    /// A push, or a witness item, over 520 bytes.
    PushSize,
    /// More than 201 counted opcodes.
    OpCount,
    /// Stack plus altstack over 1,000 elements.
    StackSize,
    /// `CHECKMULTISIG` with a negative signature count, or more signatures than keys.
    SigCount,
    /// `CHECKMULTISIG` with a negative key count, or more than 20 keys.
    PubkeyCount,
    /// A truncated push, an unknown or reserved opcode executed, `OP_VERIF`/`OP_VERNOTIF`
    /// anywhere, or `OP_CHECKSIGADD` outside tapscript.
    BadOpcode,
    /// One of the fifteen disabled opcodes, executed or not.
    DisabledOpcode,
    /// Fewer elements than the opcode consumes, or a `PICK`/`ROLL` depth out of range.
    InvalidStackOperation,
    /// `OP_FROMALTSTACK` on an empty altstack.
    InvalidAltstackOperation,
    /// `OP_RETURN` executed.
    OpReturn,
    /// `OP_ELSE`/`OP_ENDIF` without an `OP_IF`, or an `OP_IF` left open at the end.
    UnbalancedConditional,
    /// A lock-time operand below zero.
    NegativeLocktime,
    /// The transaction does not satisfy the lock the script demands.
    UnsatisfiedLocktime,
    /// A signature that is not strict DER, under `DERSIG` (BIP66).
    SigDer,
    /// A P2SH scriptSig containing a non-push opcode (BIP16).
    SigPushonly,
    /// A `CHECKMULTISIG` dummy element that is not empty, under `NULLDUMMY` (BIP147).
    SigNulldummy,
    /// A witness script that left other than exactly one element.
    Cleanstack,
    /// A v0 program that is neither 20 nor 32 bytes.
    WitnessProgramWrongLength,
    /// A P2WSH spend with no witness items.
    WitnessProgramWitnessEmpty,
    /// A P2WSH script whose hash is not the program, or a P2WPKH witness of other than
    /// two items.
    WitnessProgramMismatch,
    /// A native witness program with a non-empty scriptSig.
    WitnessMalleated,
    /// A P2SH-wrapped witness program whose scriptSig is not exactly one push.
    WitnessMalleatedP2sh,
    /// Witness data on an input whose scripts are not a witness program.
    WitnessUnexpected,
    /// A Schnorr signature was neither 64 nor 65 bytes (BIP341).
    SchnorrSigSize,
    /// A 65-byte Schnorr signature carried hash type `0x00`, or any signature carried a hash
    /// type outside `{0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}`, or asked for `SINGLE` at an
    /// input with no matching output (BIP341).
    SchnorrSigHashtype,
    /// A well-formed Schnorr signature did not verify against the key (BIP340).
    SchnorrSig,
    /// The tapscript sigop budget went negative (BIP342).
    TapscriptValidationWeight,
    /// `CHECKMULTISIG` in tapscript (BIP342).
    TapscriptCheckmultisig,
    /// A tapscript `OP_IF` argument other than empty or `0x01` (BIP342).
    TapscriptMinimalif,
    /// An empty public key in a tapscript signature check (BIP342).
    TapscriptEmptyPubkey,
    /// A numeric operand over its byte limit.
    Scriptnum,
}

impl ScriptError {
    /// Core's `ScriptErrorString` name minus the `SCRIPT_ERR_` prefix: the vector spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ScriptError::EvalFalse => "EVAL_FALSE",
            ScriptError::Verify => "VERIFY",
            ScriptError::Equalverify => "EQUALVERIFY",
            ScriptError::Checkmultisigverify => "CHECKMULTISIGVERIFY",
            ScriptError::Checksigverify => "CHECKSIGVERIFY",
            ScriptError::Numequalverify => "NUMEQUALVERIFY",
            ScriptError::ScriptSize => "SCRIPT_SIZE",
            ScriptError::PushSize => "PUSH_SIZE",
            ScriptError::OpCount => "OP_COUNT",
            ScriptError::StackSize => "STACK_SIZE",
            ScriptError::SigCount => "SIG_COUNT",
            ScriptError::PubkeyCount => "PUBKEY_COUNT",
            ScriptError::BadOpcode => "BAD_OPCODE",
            ScriptError::DisabledOpcode => "DISABLED_OPCODE",
            ScriptError::InvalidStackOperation => "INVALID_STACK_OPERATION",
            ScriptError::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            ScriptError::OpReturn => "OP_RETURN",
            ScriptError::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            ScriptError::NegativeLocktime => "NEGATIVE_LOCKTIME",
            ScriptError::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            ScriptError::SigDer => "SIG_DER",
            ScriptError::SigPushonly => "SIG_PUSHONLY",
            ScriptError::SigNulldummy => "SIG_NULLDUMMY",
            ScriptError::Cleanstack => "CLEANSTACK",
            ScriptError::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            ScriptError::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            ScriptError::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            ScriptError::WitnessMalleated => "WITNESS_MALLEATED",
            ScriptError::WitnessMalleatedP2sh => "WITNESS_MALLEATED_P2SH",
            ScriptError::WitnessUnexpected => "WITNESS_UNEXPECTED",
            ScriptError::SchnorrSigSize => "SCHNORR_SIG_SIZE",
            ScriptError::SchnorrSigHashtype => "SCHNORR_SIG_HASHTYPE",
            ScriptError::SchnorrSig => "SCHNORR_SIG",
            ScriptError::TapscriptValidationWeight => "TAPSCRIPT_VALIDATION_WEIGHT",
            ScriptError::TapscriptCheckmultisig => "TAPSCRIPT_CHECKMULTISIG",
            ScriptError::TapscriptMinimalif => "TAPSCRIPT_MINIMALIF",
            ScriptError::TapscriptEmptyPubkey => "TAPSCRIPT_EMPTY_PUBKEY",
            ScriptError::Scriptnum => "SCRIPTNUM",
        }
    }

    /// Every variant, in Core's order, for tests that walk the table.
    #[cfg(test)]
    pub const ALL: [ScriptError; 38] = [
        ScriptError::EvalFalse,
        ScriptError::Verify,
        ScriptError::Equalverify,
        ScriptError::Checkmultisigverify,
        ScriptError::Checksigverify,
        ScriptError::Numequalverify,
        ScriptError::ScriptSize,
        ScriptError::PushSize,
        ScriptError::OpCount,
        ScriptError::StackSize,
        ScriptError::SigCount,
        ScriptError::PubkeyCount,
        ScriptError::BadOpcode,
        ScriptError::DisabledOpcode,
        ScriptError::InvalidStackOperation,
        ScriptError::InvalidAltstackOperation,
        ScriptError::OpReturn,
        ScriptError::UnbalancedConditional,
        ScriptError::NegativeLocktime,
        ScriptError::UnsatisfiedLocktime,
        ScriptError::SigDer,
        ScriptError::SigPushonly,
        ScriptError::SigNulldummy,
        ScriptError::Cleanstack,
        ScriptError::WitnessProgramWrongLength,
        ScriptError::WitnessProgramWitnessEmpty,
        ScriptError::WitnessProgramMismatch,
        ScriptError::WitnessMalleated,
        ScriptError::WitnessMalleatedP2sh,
        ScriptError::WitnessUnexpected,
        ScriptError::SchnorrSigSize,
        ScriptError::SchnorrSigHashtype,
        ScriptError::SchnorrSig,
        ScriptError::TapscriptValidationWeight,
        ScriptError::TapscriptCheckmultisig,
        ScriptError::TapscriptMinimalif,
        ScriptError::TapscriptEmptyPubkey,
        ScriptError::Scriptnum,
    ];
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for ScriptError {}

#[cfg(test)]
mod tests {
    use super::ScriptError;

    #[test]
    fn display_is_the_vector_spelling() {
        assert_eq!(ScriptError::SchnorrSigSize.to_string(), "SCHNORR_SIG_SIZE");
        assert_eq!(
            ScriptError::WitnessMalleatedP2sh.to_string(),
            "WITNESS_MALLEATED_P2SH"
        );
        assert_eq!(ScriptError::Scriptnum.to_string(), "SCRIPTNUM");
    }

    #[test]
    fn names_are_distinct_and_upper_snake() {
        let mut names: Vec<&str> = ScriptError::ALL.iter().map(|e| e.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ScriptError::ALL.len());
        for name in names {
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "{name}"
            );
        }
    }
}
