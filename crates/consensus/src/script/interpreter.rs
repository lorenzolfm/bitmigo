// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`eval_script`]: Core's `EvalScript`, one opcode at a time.
//!
//! The loop is `interpreter.cpp`'s loop in the same order: read the opcode, reject an
//! oversized push, count it, reject a disabled opcode, then either push, dispatch, or skip
//! it because a surrounding `OP_IF` is false, and finally check the stack limit. Where Core
//! has one `switch`, [`Machine::execute`] dispatches to one function per opcode group so that
//! each fits on a screen; every branch Core takes is a branch here, and every policy check
//! Core makes (`MINIMALDATA`, `DISCOURAGE_*`, `NULLFAIL`, `CONST_SCRIPTCODE`, `MINIMALIF`
//! under v0) is a comment saying it is policy. Stack access goes through [`Stack`]'s
//! depth-checked methods, numbers through [`ScriptNum`], and signature checks through
//! [`TxSigChecker`].
//!
//! The same loop serves tapscript, with the branches BIP342 changes (`OP_IF` minimality,
//! `OP_CHECKSIGADD`, the sigop budget, no size or opcode limits, no `CHECKMULTISIG`) taken
//! on [`SigVersion::Tapscript`]; the `OP_SUCCESS` scan and the taproot commitment that lead
//! there belong to the witness verifier.

#![allow(
    clippy::wildcard_imports,
    reason = "the opcode table is this file's vocabulary; naming a hundred constants would \
              hide the code"
)]

use std::borrow::Cow;

use bitcoin::Script;
use bitcoin::hashes::{Hash, hash160, ripemd160, sha1, sha256, sha256d};

use super::checker::{SEQUENCE_LOCKTIME_DISABLE_FLAG, TxSigChecker};
use super::num::{SCRIPTNUM_LOCKTIME_SIZE_MAX, SCRIPTNUM_SIZE_MAX, ScriptNum, cast_to_bool};
use super::opcode::*;
use super::reader::{Op, OpRead, Reader, push_encoding, read_op};
use super::sighash::TaprootSpend;
use super::stack::{MAX_SCRIPT_ELEMENT_SIZE, Stack};
use super::{ScriptError, ScriptFlags, SigVersion};

/// `MAX_SCRIPT_SIZE`: legacy and v0 scripts above this fail before executing.
pub const MAX_SCRIPT_SIZE: usize = 10_000;
/// `MAX_STACK_SIZE`: stack plus altstack, checked after every opcode.
pub const MAX_STACK_SIZE: usize = 1_000;
/// `MAX_OPS_PER_SCRIPT`: counted opcodes per legacy or v0 script.
pub const MAX_OPS_PER_SCRIPT: usize = 201;
/// `MAX_PUBKEYS_PER_MULTISIG`.
pub const MAX_PUBKEYS_PER_MULTISIG: i32 = 20;
/// `VALIDATION_WEIGHT_PER_SIGOP_PASSED`: what each non-empty tapscript signature costs.
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;
/// BIP342's `codesep_pos` when no `OP_CODESEPARATOR` has executed.
pub const CODESEPARATOR_POS_NONE: u32 = 0xffff_ffff;
/// The most `op_count` can reach: the limit, plus one multisig's keys past it.
const OP_COUNT_MAX: usize = MAX_OPS_PER_SCRIPT + 20;

/// What a tapscript signature check needs from the spend around it: Core's
/// `ScriptExecutionData` fields that `VerifyWitnessProgram` fills before executing a leaf.
#[derive(Clone, Copy, Debug)]
pub struct TapscriptExec<'a> {
    /// `m_tapleaf_hash`: the tagged hash of the leaf being executed.
    pub leaf_hash: [u8; 32],
    /// `m_annex_hash`'s preimage: the annex as taken from the witness, `0x50` included.
    pub annex: Option<&'a [u8]>,
    /// `m_validation_weight_left`: the sigop budget, `VALIDATION_WEIGHT_OFFSET` plus the
    /// serialized witness size at the start.
    pub validation_weight_left: i64,
}

/// Core's `ScriptExecutionData`: what one execution knows beyond its stack.
#[derive(Clone, Copy, Debug)]
pub struct ExecData<'a> {
    /// `m_codeseparator_pos`: opcode index of the last executed `OP_CODESEPARATOR`.
    codesep_pos: u32,
    /// Present exactly when the script is a tapscript leaf.
    tapscript: Option<TapscriptExec<'a>>,
}

impl<'a> ExecData<'a> {
    /// Execution data for a legacy or v0 script.
    #[must_use]
    pub const fn legacy() -> ExecData<'static> {
        ExecData {
            codesep_pos: CODESEPARATOR_POS_NONE,
            tapscript: None,
        }
    }

    /// Execution data for a tapscript leaf.
    #[must_use]
    #[allow(
        dead_code,
        reason = "the taproot verifier that builds one is the next layer; the tapscript \
                  branches it feeds are tested through this constructor"
    )]
    pub const fn tapscript(exec: TapscriptExec<'a>) -> ExecData<'a> {
        ExecData {
            codesep_pos: CODESEPARATOR_POS_NONE,
            tapscript: Some(exec),
        }
    }

    /// The budget left after execution, for tests of the sigop rule.
    #[cfg(test)]
    pub fn validation_weight_left(&self) -> Option<i64> {
        self.tapscript.map(|exec| exec.validation_weight_left)
    }
}

/// Core's `ConditionStack`: the nest of `OP_IF`s around the current opcode, kept as its
/// depth and the depth of the outermost false, because only "any false?" is ever asked.
#[derive(Clone, Copy, Debug)]
struct ConditionStack {
    depth: u32,
    first_false: Option<u32>,
}

impl ConditionStack {
    const fn new() -> ConditionStack {
        ConditionStack {
            depth: 0,
            first_false: None,
        }
    }

    const fn is_empty(self) -> bool {
        self.depth == 0
    }

    /// Whether the current opcode executes: every enclosing branch is taken.
    const fn all_true(self) -> bool {
        self.first_false.is_none()
    }

    fn push(&mut self, value: bool) {
        if self.first_false.is_none() && !value {
            self.first_false = Some(self.depth);
        }
        self.depth += 1;
        // An OP_IF is one byte, so the depth is bounded by the script size.
        assert!(self.depth <= 10_001);
    }

    fn pop(&mut self) {
        assert!(self.depth > 0);
        self.depth -= 1;
        if self.first_false == Some(self.depth) {
            self.first_false = None;
        }
    }

    /// `OP_ELSE`: flips the innermost branch. Flipping any false but the outermost is
    /// unobservable, so only that one is tracked.
    fn toggle_top(&mut self) {
        assert!(self.depth > 0);
        let top = self.depth - 1;
        match self.first_false {
            None => self.first_false = Some(top),
            Some(first) if first == top => self.first_false = None,
            Some(_) => {}
        }
    }
}

/// Core's `EvalScript`: runs `script` against `stack` and returns why it failed, if it did.
///
/// `exec` must be [`ExecData::tapscript`] exactly when `sig_version` is
/// [`SigVersion::Tapscript`]. On return `exec` carries the last `OP_CODESEPARATOR` position.
pub fn eval_script(
    script: &[u8],
    stack: &mut Stack,
    flags: ScriptFlags,
    sig_version: SigVersion,
    exec: &mut ExecData<'_>,
    checker: &TxSigChecker<'_>,
) -> Result<(), ScriptError> {
    assert_eq!(
        exec.tapscript.is_some(),
        sig_version == SigVersion::Tapscript
    );
    // Tapscript has neither the size nor the opcode limit (BIP342).
    let counts_ops = sig_version != SigVersion::Tapscript;
    if counts_ops && script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }
    exec.codesep_pos = CODESEPARATOR_POS_NONE;
    let mut machine = Machine {
        script,
        stack,
        altstack: Stack::new(),
        conditions: ConditionStack::new(),
        op_count: 0,
        codesep_start: 0,
        flags,
        sig_version,
        exec,
        checker,
    };

    let mut reader = Reader::new(script);
    // Bounded by the script length: every step consumes at least one byte.
    while let Some(step) = reader.next_op() {
        let op = step?;
        if op.push.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        if counts_ops && op.opcode.counts_toward_op_limit() {
            machine.op_count += 1;
            if machine.op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptError::OpCount);
            }
        }
        if op.opcode.is_disabled() {
            return Err(ScriptError::DisabledOpcode);
        }
        // CONST_SCRIPTCODE would reject OP_CODESEPARATOR here; it is policy.

        let executing = machine.conditions.all_true();
        if executing && op.opcode.is_push() {
            // MINIMALDATA would demand the shortest push opcode; it is policy.
            machine.stack.push(op.push.to_vec());
        } else if executing || op.opcode.is_conditional() {
            machine.execute(op, executing, reader.opcode_index())?;
        }

        if machine.stack.len() + machine.altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }
    assert!(machine.op_count <= OP_COUNT_MAX);

    if !machine.conditions.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }
    Ok(())
}

/// One execution in flight: the locals of Core's `EvalScript`.
struct Machine<'m, 'x> {
    script: &'m [u8],
    stack: &'m mut Stack,
    altstack: Stack,
    conditions: ConditionStack,
    op_count: usize,
    /// Core's `pbegincodehash`: where the `scriptCode` starts.
    codesep_start: usize,
    flags: ScriptFlags,
    sig_version: SigVersion,
    exec: &'m mut ExecData<'x>,
    checker: &'m TxSigChecker<'m>,
}

impl Machine<'_, '_> {
    /// Core's `switch (opcode)`, for an opcode that is executing or is one of the
    /// conditionals, which run inside unexecuted branches too. Anything unlisted, including
    /// `OP_VERIF` and `OP_VERNOTIF`, is `BAD_OPCODE`.
    fn execute(
        &mut self,
        op: Op<'_>,
        executing: bool,
        opcode_index: u32,
    ) -> Result<(), ScriptError> {
        match op.opcode.byte() {
            OP_1NEGATE | OP_1..=OP_16 => {
                let value = ScriptNum::from_i64(op.opcode.small_integer());
                self.stack.push(value.encode());
                Ok(())
            }
            // DISCOURAGE_UPGRADABLE_NOPS would reject the numbered NOPs; it is policy.
            OP_NOP | OP_NOP1 | OP_NOP4..=OP_NOP10 => Ok(()),
            OP_CHECKLOCKTIMEVERIFY => self.check_locktime(),
            OP_CHECKSEQUENCEVERIFY => self.check_sequence(),
            OP_IF | OP_NOTIF => self.branch(op.opcode, executing),
            OP_ELSE => {
                if self.conditions.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                self.conditions.toggle_top();
                Ok(())
            }
            OP_ENDIF => {
                if self.conditions.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                self.conditions.pop();
                Ok(())
            }
            OP_VERIFY => {
                self.stack.require(1)?;
                if !cast_to_bool(self.stack.top(1)) {
                    return Err(ScriptError::Verify);
                }
                self.stack.pop();
                Ok(())
            }
            OP_RETURN => Err(ScriptError::OpReturn),
            OP_TOALTSTACK..=OP_2SWAP => self.stack_op_pairs(op.opcode.byte()),
            OP_IFDUP..=OP_TUCK => self.stack_op_singles(op.opcode.byte()),
            OP_SIZE => {
                self.stack.require(1)?;
                let size = ScriptNum::from_usize(self.stack.top(1).len());
                self.stack.push(size.encode());
                Ok(())
            }
            OP_EQUAL | OP_EQUALVERIFY => self.equal(op.opcode.byte()),
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                self.numeric_unary(op.opcode.byte())
            }
            OP_ADD | OP_SUB | OP_BOOLAND..=OP_MAX => self.numeric_binary(op.opcode.byte()),
            OP_WITHIN => self.within(),
            OP_RIPEMD160..=OP_HASH256 => self.hash(op.opcode.byte()),
            OP_CODESEPARATOR => {
                // The scriptCode starts after the separator, which is where the reader is.
                self.codesep_start = op.end;
                self.exec.codesep_pos = opcode_index;
                Ok(())
            }
            OP_CHECKSIG | OP_CHECKSIGVERIFY => self.checksig(op.opcode.byte()),
            OP_CHECKSIGADD => self.checksigadd(),
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => self.checkmultisig(op.opcode.byte()),
            _ => Err(ScriptError::BadOpcode),
        }
    }

    /// `OP_CHECKLOCKTIMEVERIFY` (BIP65): a NOP until its flag, then a five-byte operand
    /// left on the stack.
    fn check_locktime(&mut self) -> Result<(), ScriptError> {
        if !self.flags.contains(ScriptFlags::CHECKLOCKTIMEVERIFY) {
            return Ok(());
        }
        self.stack.require(1)?;
        let lock_time = ScriptNum::decode(self.stack.top(1), SCRIPTNUM_LOCKTIME_SIZE_MAX)?;
        if lock_time.value() < 0 {
            return Err(ScriptError::NegativeLocktime);
        }
        if !self.checker.check_locktime(lock_time.value()) {
            return Err(ScriptError::UnsatisfiedLocktime);
        }
        Ok(())
    }

    /// `OP_CHECKSEQUENCEVERIFY` (BIP112): as above, and a NOP again when the operand's
    /// disable bit is set, so that the bit stays free for a later softfork.
    fn check_sequence(&mut self) -> Result<(), ScriptError> {
        if !self.flags.contains(ScriptFlags::CHECKSEQUENCEVERIFY) {
            return Ok(());
        }
        self.stack.require(1)?;
        let sequence = ScriptNum::decode(self.stack.top(1), SCRIPTNUM_LOCKTIME_SIZE_MAX)?;
        if sequence.value() < 0 {
            return Err(ScriptError::NegativeLocktime);
        }
        if sequence.value() & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Ok(());
        }
        if !self.checker.check_sequence(sequence.value()) {
            return Err(ScriptError::UnsatisfiedLocktime);
        }
        Ok(())
    }

    /// `OP_IF` and `OP_NOTIF`: inside an unexecuted branch they consume nothing and open a
    /// false branch, so that the matching `OP_ENDIF` still balances.
    fn branch(&mut self, opcode: Opcode, executing: bool) -> Result<(), ScriptError> {
        let mut value = false;
        if executing {
            self.stack.require(1)?;
            let argument = self.stack.top(1);
            if self.sig_version == SigVersion::Tapscript {
                // BIP342 makes minimal IF arguments consensus; under v0 the same rule is
                // the MINIMALIF policy flag.
                let minimal = argument.is_empty() || argument == [1];
                if !minimal {
                    return Err(ScriptError::TapscriptMinimalif);
                }
            }
            value = cast_to_bool(argument);
            if opcode.byte() == OP_NOTIF {
                value = !value;
            }
            self.stack.pop();
        }
        self.conditions.push(value);
        Ok(())
    }

    /// The altstack moves and the two- and three-element stack opcodes.
    fn stack_op_pairs(&mut self, opcode: u8) -> Result<(), ScriptError> {
        match opcode {
            OP_TOALTSTACK => {
                self.stack.require(1)?;
                let item = self.stack.pop();
                self.altstack.push(item);
            }
            OP_FROMALTSTACK => {
                if self.altstack.is_empty() {
                    return Err(ScriptError::InvalidAltstackOperation);
                }
                let item = self.altstack.pop();
                self.stack.push(item);
            }
            OP_2DROP => {
                // (x1 x2 -- )
                self.stack.require(2)?;
                self.stack.pop();
                self.stack.pop();
            }
            OP_2DUP => {
                // (x1 x2 -- x1 x2 x1 x2)
                self.stack.require(2)?;
                let x1 = self.stack.top(2).to_vec();
                let x2 = self.stack.top(1).to_vec();
                self.stack.push(x1);
                self.stack.push(x2);
            }
            OP_3DUP => {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                self.stack.require(3)?;
                let x1 = self.stack.top(3).to_vec();
                let x2 = self.stack.top(2).to_vec();
                let x3 = self.stack.top(1).to_vec();
                self.stack.push(x1);
                self.stack.push(x2);
                self.stack.push(x3);
            }
            OP_2OVER => {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                self.stack.require(4)?;
                let x1 = self.stack.top(4).to_vec();
                let x2 = self.stack.top(3).to_vec();
                self.stack.push(x1);
                self.stack.push(x2);
            }
            OP_2ROT => {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                self.stack.require(6)?;
                let x1 = self.stack.remove(6);
                let x2 = self.stack.remove(5);
                self.stack.push(x1);
                self.stack.push(x2);
            }
            OP_2SWAP => {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                self.stack.require(4)?;
                self.stack.swap(4, 2);
                self.stack.swap(3, 1);
            }
            _ => unreachable!("dispatched on OP_TOALTSTACK..=OP_2SWAP"),
        }
        Ok(())
    }

    /// The one-element stack opcodes.
    fn stack_op_singles(&mut self, opcode: u8) -> Result<(), ScriptError> {
        match opcode {
            OP_IFDUP => {
                // (x -- 0 | x x)
                self.stack.require(1)?;
                if cast_to_bool(self.stack.top(1)) {
                    let x = self.stack.top(1).to_vec();
                    self.stack.push(x);
                }
            }
            OP_DEPTH => {
                let depth = ScriptNum::from_usize(self.stack.len());
                self.stack.push(depth.encode());
            }
            OP_DROP => {
                self.stack.require(1)?;
                self.stack.pop();
            }
            OP_DUP => {
                self.stack.require(1)?;
                let x = self.stack.top(1).to_vec();
                self.stack.push(x);
            }
            OP_NIP => {
                // (x1 x2 -- x2)
                self.stack.require(2)?;
                self.stack.remove(2);
            }
            OP_OVER => {
                // (x1 x2 -- x1 x2 x1)
                self.stack.require(2)?;
                let x1 = self.stack.top(2).to_vec();
                self.stack.push(x1);
            }
            OP_PICK | OP_ROLL => self.pick_or_roll(opcode)?,
            OP_ROT => {
                // (x1 x2 x3 -- x2 x3 x1)
                self.stack.require(3)?;
                self.stack.swap(3, 2);
                self.stack.swap(2, 1);
            }
            OP_SWAP => {
                self.stack.require(2)?;
                self.stack.swap(2, 1);
            }
            OP_TUCK => {
                // (x1 x2 -- x2 x1 x2)
                self.stack.require(2)?;
                let x2 = self.stack.top(1).to_vec();
                self.stack.insert(2, x2);
            }
            _ => unreachable!("dispatched on OP_IFDUP..=OP_TUCK"),
        }
        Ok(())
    }

    /// `OP_PICK` copies, `OP_ROLL` moves: `(xn ... x0 n -- ... x0 xn)`. The depth is read as
    /// a script number, then clamped to `int` as Core's `getint` does.
    fn pick_or_roll(&mut self, opcode: u8) -> Result<(), ScriptError> {
        self.stack.require(2)?;
        let n = ScriptNum::decode(self.stack.top(1), SCRIPTNUM_SIZE_MAX)?.to_clamped_i32();
        self.stack.pop();
        let Ok(n) = usize::try_from(n) else {
            return Err(ScriptError::InvalidStackOperation);
        };
        if n >= self.stack.len() {
            return Err(ScriptError::InvalidStackOperation);
        }
        let item = self.stack.top(n + 1).to_vec();
        if opcode == OP_ROLL {
            self.stack.remove(n + 1);
        }
        self.stack.push(item);
        Ok(())
    }

    /// `OP_EQUAL` compares bytes, not numbers: `OP_NOTEQUAL` never existed because `1` and
    /// `0x0100` would compare unequal.
    fn equal(&mut self, opcode: u8) -> Result<(), ScriptError> {
        self.stack.require(2)?;
        let x2 = self.stack.pop();
        let x1 = self.stack.pop();
        let equal = x1 == x2;
        self.stack.push_bool(equal);
        if opcode == OP_EQUALVERIFY {
            if !equal {
                return Err(ScriptError::Equalverify);
            }
            self.stack.pop();
        }
        Ok(())
    }

    fn numeric_unary(&mut self, opcode: u8) -> Result<(), ScriptError> {
        self.stack.require(1)?;
        let n = ScriptNum::decode(self.stack.top(1), SCRIPTNUM_SIZE_MAX)?;
        let result = match opcode {
            OP_1ADD => n.add(ScriptNum::ONE),
            OP_1SUB => n.sub(ScriptNum::ONE),
            OP_NEGATE => n.neg(),
            OP_ABS => n.abs(),
            OP_NOT => ScriptNum::from_bool(n.is_zero()),
            OP_0NOTEQUAL => ScriptNum::from_bool(!n.is_zero()),
            _ => unreachable!("dispatched on the six unary opcodes"),
        };
        self.stack.pop();
        self.stack.push(result.encode());
        Ok(())
    }

    fn numeric_binary(&mut self, opcode: u8) -> Result<(), ScriptError> {
        // (x1 x2 -- out)
        self.stack.require(2)?;
        let x1 = ScriptNum::decode(self.stack.top(2), SCRIPTNUM_SIZE_MAX)?;
        let x2 = ScriptNum::decode(self.stack.top(1), SCRIPTNUM_SIZE_MAX)?;
        let result = match opcode {
            OP_ADD => x1.add(x2),
            OP_SUB => x1.sub(x2),
            OP_BOOLAND => ScriptNum::from_bool(!x1.is_zero() && !x2.is_zero()),
            OP_BOOLOR => ScriptNum::from_bool(!x1.is_zero() || !x2.is_zero()),
            OP_NUMEQUAL | OP_NUMEQUALVERIFY => ScriptNum::from_bool(x1 == x2),
            OP_NUMNOTEQUAL => ScriptNum::from_bool(x1 != x2),
            OP_LESSTHAN => ScriptNum::from_bool(x1 < x2),
            OP_GREATERTHAN => ScriptNum::from_bool(x1 > x2),
            OP_LESSTHANOREQUAL => ScriptNum::from_bool(x1 <= x2),
            OP_GREATERTHANOREQUAL => ScriptNum::from_bool(x1 >= x2),
            OP_MIN => x1.min(x2),
            OP_MAX => x1.max(x2),
            _ => unreachable!("dispatched on the thirteen binary opcodes"),
        };
        self.stack.pop();
        self.stack.pop();
        self.stack.push(result.encode());
        if opcode == OP_NUMEQUALVERIFY {
            if !cast_to_bool(self.stack.top(1)) {
                return Err(ScriptError::Numequalverify);
            }
            self.stack.pop();
        }
        Ok(())
    }

    fn within(&mut self) -> Result<(), ScriptError> {
        // (x min max -- out)
        self.stack.require(3)?;
        let x = ScriptNum::decode(self.stack.top(3), SCRIPTNUM_SIZE_MAX)?;
        let min = ScriptNum::decode(self.stack.top(2), SCRIPTNUM_SIZE_MAX)?;
        let max = ScriptNum::decode(self.stack.top(1), SCRIPTNUM_SIZE_MAX)?;
        let inside = min <= x && x < max;
        self.stack.pop();
        self.stack.pop();
        self.stack.pop();
        self.stack.push_bool(inside);
        Ok(())
    }

    fn hash(&mut self, opcode: u8) -> Result<(), ScriptError> {
        self.stack.require(1)?;
        let input = self.stack.pop();
        let digest = match opcode {
            OP_RIPEMD160 => ripemd160::Hash::hash(&input).to_byte_array().to_vec(),
            OP_SHA1 => sha1::Hash::hash(&input).to_byte_array().to_vec(),
            OP_SHA256 => sha256::Hash::hash(&input).to_byte_array().to_vec(),
            OP_HASH160 => hash160::Hash::hash(&input).to_byte_array().to_vec(),
            OP_HASH256 => sha256d::Hash::hash(&input).to_byte_array().to_vec(),
            _ => unreachable!("dispatched on the five hash opcodes"),
        };
        assert!(digest.len() == 20 || digest.len() == 32);
        self.stack.push(digest);
        Ok(())
    }

    /// The `scriptCode`: the script from after the last executed `OP_CODESEPARATOR`.
    fn script_code(&self) -> &[u8] {
        assert!(self.codesep_start <= self.script.len());
        self.script
            .get(self.codesep_start..)
            .expect("the separator position is inside the script")
    }

    /// `OP_CHECKSIG` and `OP_CHECKSIGVERIFY`: `(sig pubkey -- bool)`.
    fn checksig(&mut self, opcode: u8) -> Result<(), ScriptError> {
        self.stack.require(2)?;
        let pubkey = self.stack.pop();
        let signature = self.stack.pop();
        let success = self.eval_checksig(&signature, &pubkey)?;
        self.stack.push_bool(success);
        if opcode == OP_CHECKSIGVERIFY {
            if !success {
                return Err(ScriptError::Checksigverify);
            }
            self.stack.pop();
        }
        Ok(())
    }

    /// `OP_CHECKSIGADD` (BIP342): `(sig n pubkey -- n + 1)` on success, `n` otherwise.
    fn checksigadd(&mut self) -> Result<(), ScriptError> {
        if self.sig_version != SigVersion::Tapscript {
            return Err(ScriptError::BadOpcode);
        }
        self.stack.require(3)?;
        let pubkey = self.stack.pop();
        let n = ScriptNum::decode(self.stack.top(1), SCRIPTNUM_SIZE_MAX)?;
        self.stack.pop();
        let signature = self.stack.pop();
        let success = self.eval_checksig(&signature, &pubkey)?;
        self.stack
            .push(n.add(ScriptNum::from_bool(success)).encode());
        Ok(())
    }

    /// Core's `EvalChecksig`: `Err` fails the script, `Ok(false)` is a false on the stack.
    fn eval_checksig(&mut self, signature: &[u8], pubkey: &[u8]) -> Result<bool, ScriptError> {
        match self.sig_version {
            SigVersion::Base | SigVersion::WitnessV0 => {
                self.eval_checksig_pre_tapscript(signature, pubkey)
            }
            SigVersion::Tapscript => self.eval_checksig_tapscript(signature, pubkey),
        }
    }

    /// `EvalChecksigPreTapscript`: the legacy `FindAndDelete` of the signature from the
    /// scriptCode, the DER rule, then libsecp256k1.
    fn eval_checksig_pre_tapscript(
        &self,
        signature: &[u8],
        pubkey: &[u8],
    ) -> Result<bool, ScriptError> {
        let script_code: Cow<'_, [u8]> = if self.sig_version == SigVersion::Base {
            // CONST_SCRIPTCODE would fail the script when anything was deleted; it is policy.
            Cow::Owned(find_and_delete(self.script_code(), &push_encoding(signature)).0)
        } else {
            Cow::Borrowed(self.script_code())
        };
        check_signature_encoding(signature, self.flags)?;
        // CheckPubKeyEncoding enforces STRICTENC and WITNESS_PUBKEYTYPE, both policy: an
        // unparsable key is a false from the checker, not an error.
        let success = self.checker.check_ecdsa(
            signature,
            pubkey,
            Script::from_bytes(&script_code),
            self.sig_version,
        );
        // NULLFAIL would demand an empty signature after a failed check; it is policy.
        Ok(success)
    }

    /// `EvalChecksigTapscript` (BIP342): the budget is charged before anything else, an
    /// empty key fails, a 32-byte key is BIP340, and any other key length is an unknown
    /// type that passes (`DISCOURAGE_UPGRADABLE_PUBKEYTYPE` is policy).
    fn eval_checksig_tapscript(
        &mut self,
        signature: &[u8],
        pubkey: &[u8],
    ) -> Result<bool, ScriptError> {
        let codesep_pos = self.exec.codesep_pos;
        let exec = self
            .exec
            .tapscript
            .as_mut()
            .expect("tapscript execution carries its data");
        let success = !signature.is_empty();
        if success {
            exec.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
            if exec.validation_weight_left < 0 {
                return Err(ScriptError::TapscriptValidationWeight);
            }
        }
        if pubkey.is_empty() {
            return Err(ScriptError::TapscriptEmptyPubkey);
        }
        // Exactly 32 bytes is a BIP340 key; `try_from` fails on any other length.
        if let Ok(pubkey) = <&[u8; 32]>::try_from(pubkey)
            && success
        {
            let spend = TaprootSpend::Tapscript {
                leaf_hash: exec.leaf_hash,
                codesep_pos,
            };
            self.checker
                .check_schnorr(signature, pubkey, spend, exec.annex)?;
        }
        Ok(success)
    }

    /// `OP_CHECKMULTISIG` and `OP_CHECKMULTISIGVERIFY`:
    /// `([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)`, plus the dummy
    /// element the original implementation consumed by mistake, which `NULLDUMMY` pins to
    /// empty. `i`, `ikey` and `isig` are Core's depths from the top of the stack.
    fn checkmultisig(&mut self, opcode: u8) -> Result<(), ScriptError> {
        if self.sig_version == SigVersion::Tapscript {
            return Err(ScriptError::TapscriptCheckmultisig);
        }
        let mut i: usize = 1;
        self.stack.require(i)?;
        let key_count_i32 =
            ScriptNum::decode(self.stack.top(i), SCRIPTNUM_SIZE_MAX)?.to_clamped_i32();
        if !(0..=MAX_PUBKEYS_PER_MULTISIG).contains(&key_count_i32) {
            return Err(ScriptError::PubkeyCount);
        }
        let key_count = count_from(key_count_i32);
        self.op_count += key_count;
        if self.op_count > MAX_OPS_PER_SCRIPT {
            return Err(ScriptError::OpCount);
        }
        i += 1;
        let ikey = i;
        i += key_count;
        self.stack.require(i)?;
        let sig_count_i32 =
            ScriptNum::decode(self.stack.top(i), SCRIPTNUM_SIZE_MAX)?.to_clamped_i32();
        if sig_count_i32 < 0 || sig_count_i32 > key_count_i32 {
            return Err(ScriptError::SigCount);
        }
        let sig_count = count_from(sig_count_i32);
        i += 1;
        let isig = i;
        i += sig_count;
        self.stack.require(i)?;

        let script_code = self.multisig_script_code(isig, sig_count);
        let success = self.checkmultisig_verify(ikey, isig, key_count, sig_count, &script_code)?;

        // Clean up the stack of actual arguments: everything but the dummy.
        for _ in 1..i {
            self.stack.pop();
        }
        // The dummy element the original implementation popped without looking.
        self.stack.require(1)?;
        if self.flags.contains(ScriptFlags::NULLDUMMY) && !self.stack.top(1).is_empty() {
            return Err(ScriptError::SigNulldummy);
        }
        self.stack.pop();

        self.stack.push_bool(success);
        if opcode == OP_CHECKMULTISIGVERIFY {
            if !success {
                return Err(ScriptError::Checkmultisigverify);
            }
            self.stack.pop();
        }
        Ok(())
    }

    /// The multisig scriptCode: from the last separator, minus every signature under
    /// legacy rules. Each `FindAndDelete` runs on the result of the previous one, as Core's
    /// loop does, and none under v0 (BIP143).
    fn multisig_script_code(&self, isig: usize, sig_count: usize) -> Vec<u8> {
        let mut script_code = self.script_code().to_vec();
        if self.sig_version == SigVersion::Base {
            // Bounded by the signature count, at most 20.
            for k in 0..sig_count {
                let signature = self.stack.top(isig + k);
                // CONST_SCRIPTCODE would fail on a deletion; it is policy.
                script_code = find_and_delete(&script_code, &push_encoding(signature)).0;
            }
        }
        script_code
    }

    /// Core's matching loop: signatures and keys are walked in order, a failed check moves
    /// the key pointer only, and the operation fails as soon as more signatures remain
    /// than keys. STRICTENC would make the order observable through its errors; it is policy.
    fn checkmultisig_verify(
        &self,
        mut ikey: usize,
        mut isig: usize,
        mut keys_left: usize,
        mut sigs_left: usize,
        script_code: &[u8],
    ) -> Result<bool, ScriptError> {
        let mut iterations = 0;
        // Bounded by the key count: every iteration consumes one key.
        while sigs_left > 0 {
            iterations += 1;
            assert!(iterations <= MAX_PUBKEYS_PER_MULTISIG);
            let signature = self.stack.top(isig);
            let pubkey = self.stack.top(ikey);
            check_signature_encoding(signature, self.flags)?;
            let ok = self.checker.check_ecdsa(
                signature,
                pubkey,
                Script::from_bytes(script_code),
                self.sig_version,
            );
            if ok {
                isig += 1;
                sigs_left -= 1;
            }
            ikey += 1;
            keys_left -= 1;
            if sigs_left > keys_left {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A `CHECKMULTISIG` count that has passed its range check.
fn count_from(count: i32) -> usize {
    usize::try_from(count).expect("checked non-negative")
}

/// Core's `CheckSignatureEncoding` under consensus flags: an empty signature always passes
/// (it is how a multisig skips a key), and `DERSIG` demands strict DER of any other. `LOW_S`
/// and `STRICTENC` add further checks; both are policy.
pub fn check_signature_encoding(signature: &[u8], flags: ScriptFlags) -> Result<(), ScriptError> {
    if signature.is_empty() {
        return Ok(());
    }
    if flags.contains(ScriptFlags::DERSIG) && !is_valid_signature_encoding(signature) {
        return Err(ScriptError::SigDer);
    }
    Ok(())
}

/// Core's `IsValidSignatureEncoding` (BIP66): `0x30 len 0x02 lenR R 0x02 lenS S hashtype`,
/// R and S positive and not padded, every length consistent.
#[must_use]
pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    let at = |index: usize| *sig.get(index).expect("index checked against the length");
    // Minimum and maximum size constraints.
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    // A signature is of type 0x30 (compound), and its length covers everything but the
    // hash type byte.
    if at(0) != 0x30 || usize::from(at(1)) != sig.len() - 3 {
        return false;
    }
    let len_r = usize::from(at(3));
    // Make sure the length of the S element is still inside the signature.
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = usize::from(at(5 + len_r));
    // The two element lengths and the seven framing bytes make up the whole signature.
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    // R is a non-empty, non-negative integer with no unnecessary leading zero.
    if at(2) != 0x02 || len_r == 0 || at(4) & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && at(4) == 0x00 && at(5) & 0x80 == 0 {
        return false;
    }
    // The same for S.
    if at(len_r + 4) != 0x02 || len_s == 0 || at(len_r + 6) & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && at(len_r + 6) == 0x00 && at(len_r + 7) & 0x80 == 0 {
        return false;
    }
    true
}

/// Core's `FindAndDelete`: removes every occurrence of `pattern` that starts at an opcode
/// boundary of `script`, in one pass. Returns the new script and how many were removed.
///
/// The walk is Core's exactly: at each boundary, every consecutive copy of the pattern is
/// skipped before the next opcode is read, so a match may swallow bytes that were the
/// middle of a push and leave what follows to be re-parsed; and a truncated push ends the
/// walk with the rest of the script copied through. Both are consensus.
#[must_use]
pub fn find_and_delete(script: &[u8], pattern: &[u8]) -> (Vec<u8>, usize) {
    if pattern.is_empty() {
        return (script.to_vec(), 0);
    }
    let mut result = Vec::with_capacity(script.len());
    let mut found = 0;
    let mut pc = 0;
    let mut pc2 = 0;
    let mut iterations = 0;
    // Bounded by the script length: each iteration advances `pc` or ends the walk.
    loop {
        iterations += 1;
        assert!(iterations <= script.len() + 1);
        result.extend_from_slice(script.get(pc2..pc).expect("pc2 <= pc <= len"));
        while script.len() - pc >= pattern.len()
            && script.get(pc..pc + pattern.len()) == Some(pattern)
        {
            pc += pattern.len();
            found += 1;
        }
        pc2 = pc;
        if pc >= script.len() {
            break;
        }
        match read_op(script, pc) {
            OpRead::Op { next, .. } => pc = next,
            OpRead::Truncated { .. } => break,
        }
    }
    if found == 0 {
        return (script.to_vec(), 0);
    }
    result.extend_from_slice(script.get(pc2..).expect("pc2 <= len"));
    assert_eq!(result.len() + found * pattern.len(), script.len());
    (result, found)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index out of bounds fails the test with a panic"
    )]

    use bitcoin::hex::FromHex;
    use secp256k1::{Keypair, Secp256k1};

    use super::super::opcode::*;
    use super::super::sighash::{TaprootSpend, taproot_sighash};
    use super::super::stack::{MAX_SCRIPT_ELEMENT_SIZE, Stack};
    use super::super::vectors::{
        Prng, crediting_transaction, random_prevouts, random_transaction, spending_transaction,
    };
    use super::super::{ScriptError, ScriptFlags, SigVersion, TxPrecomputed, TxSigChecker};
    use super::{
        CODESEPARATOR_POS_NONE, ExecData, MAX_OPS_PER_SCRIPT, MAX_SCRIPT_SIZE, MAX_STACK_SIZE,
        TapscriptExec, eval_script, find_and_delete, is_valid_signature_encoding,
    };

    fn hex(text: &str) -> Vec<u8> {
        Vec::<u8>::from_hex(text).expect("valid hex")
    }

    /// Runs `script` over `stack` as a legacy script under `flags`, against a checker for a
    /// transaction whose scripts are empty: enough for every opcode but the signature ones.
    fn run(script: &[u8], stack: &mut Stack, flags: ScriptFlags) -> Result<(), ScriptError> {
        let credit = crediting_transaction(&[], 0);
        let spend = spending_transaction(&[], bitcoin::Witness::new(), &credit);
        let prevouts = vec![credit.output[0].clone()];
        let precomputed = TxPrecomputed::new(&spend, &prevouts);
        let checker = TxSigChecker::new(&spend, 0, &prevouts, &precomputed);
        let mut exec = ExecData::legacy();
        eval_script(script, stack, flags, SigVersion::Base, &mut exec, &checker)
    }

    fn run_fresh(script: &[u8]) -> Result<Stack, ScriptError> {
        let mut stack = Stack::new();
        run(script, &mut stack, ScriptFlags::NONE)?;
        Ok(stack)
    }

    /// Core's `script_FindAndDelete` cases, verbatim.
    #[test]
    fn find_and_delete_matches_core() {
        let cases: [(&str, &str, &str, usize); 16] = [
            // (script, pattern, expected, found)
            ("5152", "", "5152", 0),
            ("515253", "52", "5153", 1),
            ("535153535453", "53", "5154", 4),
            ("0302ff03", "0302ff03", "", 1),
            ("0302ff030302ff03", "0302ff03", "", 2),
            // FindAndDelete matches entire opcodes.
            ("0302ff030302ff03", "02", "0302ff030302ff03", 0),
            ("0302ff030302ff03", "ff", "0302ff030302ff03", 0),
            // Stripping the push-three-bytes prefix leaves 02ff03, a push of two bytes.
            ("0302ff030302ff03", "03", "02ff0302ff03", 2),
            // A byte sequence spanning opcodes does not match inside them.
            ("02feed5169", "feed51", "02feed5169", 0),
            ("02feed5169", "02feed51", "69", 1),
            ("516902feed5169", "feed51", "516902feed5169", 0),
            ("516902feed5169", "02feed51", "516969", 1),
            // Single pass: the first deletion does not create a second match.
            ("00005151", "0051", "0051", 1),
            ("000051005151", "0051", "0051", 2),
            // An invalid push at the end can be removed, and is copied through otherwise.
            ("0003feed", "03feed", "00", 1),
            ("0003feed", "00", "03feed", 1),
        ];
        for (script, pattern, expected, found) in cases {
            assert_eq!(
                find_and_delete(&hex(script), &hex(pattern)),
                (hex(expected), found),
                "{script} minus {pattern}"
            );
        }
    }

    #[test]
    fn strict_der_follows_bip66() {
        let valid = hex(
            "3044022030a8f5b5e3d9e5a2ad0d6d2d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e0220\
             1f2e3d4c5b6a79880706050403020100ff00112233445566778899aabbccddee01",
        );
        assert!(is_valid_signature_encoding(&valid));
        // Wrong type byte, a length that does not cover the signature, negative R, a padded
        // S, and sizes outside 9..=73.
        let mut wrong_type = valid.clone();
        wrong_type[0] = 0x31;
        assert!(!is_valid_signature_encoding(&wrong_type));
        let mut short_len = valid.clone();
        short_len[1] -= 1;
        assert!(!is_valid_signature_encoding(&short_len));
        let mut negative_r = valid.clone();
        negative_r[4] |= 0x80;
        assert!(!is_valid_signature_encoding(&negative_r));
        let padded_s = hex("300602010102020001ff01");
        assert!(!is_valid_signature_encoding(&padded_s));
        assert!(!is_valid_signature_encoding(&hex("3006020101020101")));
        assert!(!is_valid_signature_encoding(&[0x30; 74]));
        // The shortest valid signature: one-byte R and S, plus the hash type.
        assert!(is_valid_signature_encoding(&hex("300602010102010101")));
        // R needs its leading zero when the next byte has the high bit set.
        assert!(is_valid_signature_encoding(&hex("30070202008002010101")));
        assert!(!is_valid_signature_encoding(&hex("30070202000102010101")));
    }

    #[test]
    fn script_size_limit_is_legacy_and_v0_only() {
        // Nineteen pushes of 520 bytes plus 63 OP_1s is exactly 10,000 bytes.
        let mut script = Vec::new();
        for _ in 0..19 {
            script.extend([OP_PUSHDATA2, 0x08, 0x02]);
            script.extend([0xaa; MAX_SCRIPT_ELEMENT_SIZE]);
        }
        script.extend([OP_1; 63]);
        assert_eq!(script.len(), MAX_SCRIPT_SIZE);
        assert_eq!(run_fresh(&script).expect("at the limit").len(), 82);
        script.push(OP_1);
        assert_eq!(run_fresh(&script), Err(ScriptError::ScriptSize));
    }

    #[test]
    fn push_size_limit() {
        let mut script = vec![OP_PUSHDATA2, 0x08, 0x02];
        script.extend([0xaa; MAX_SCRIPT_ELEMENT_SIZE]);
        assert_eq!(run_fresh(&script).expect("at the limit").len(), 1);
        let mut script = vec![OP_PUSHDATA2, 0x09, 0x02];
        script.extend([0xaa; MAX_SCRIPT_ELEMENT_SIZE + 1]);
        assert_eq!(run_fresh(&script), Err(ScriptError::PushSize));
    }

    #[test]
    fn op_count_limit_counts_multisig_keys() {
        let mut script = vec![OP_NOP; MAX_OPS_PER_SCRIPT];
        script.push(OP_1);
        assert!(run_fresh(&script).is_ok());
        script.push(OP_NOP);
        assert_eq!(run_fresh(&script), Err(ScriptError::OpCount));
        // 199 NOPs, then a 0-of-1 CHECKMULTISIG: 199 + 1 + 1 key = 201.
        let mut script = vec![OP_NOP; 199];
        script.extend([OP_0, OP_0, OP_1, OP_1, OP_CHECKMULTISIG]);
        assert_eq!(run_fresh(&script).expect("201 ops").items(), &[vec![1]]);
        let mut script = vec![OP_NOP; 200];
        script.extend([OP_0, OP_0, OP_1, OP_1, OP_CHECKMULTISIG]);
        assert_eq!(run_fresh(&script), Err(ScriptError::OpCount));
        // Unexecuted opcodes count too; pushes and small integers do not.
        let mut script = vec![OP_0, OP_IF];
        script.extend([OP_NOP; 199]);
        script.extend([OP_ENDIF, OP_1]);
        assert!(run_fresh(&script).is_ok());
        script.insert(2, OP_NOP);
        assert_eq!(run_fresh(&script), Err(ScriptError::OpCount));
    }

    #[test]
    fn stack_size_limit_counts_both_stacks() {
        let script = vec![OP_1; MAX_STACK_SIZE];
        assert_eq!(
            run_fresh(&script).expect("at the limit").len(),
            MAX_STACK_SIZE
        );
        let script = vec![OP_1; MAX_STACK_SIZE + 1];
        assert_eq!(run_fresh(&script), Err(ScriptError::StackSize));
        // 999 on the stack and one moved to the altstack is 1,000; one more is not.
        let mut script = vec![OP_1; MAX_STACK_SIZE];
        script.push(OP_TOALTSTACK);
        assert!(run_fresh(&script).is_ok());
        script.push(OP_1);
        assert_eq!(run_fresh(&script), Err(ScriptError::StackSize));
    }

    #[test]
    fn multisig_count_limits() {
        // 21 keys, and a negative count.
        let script = [OP_0, OP_0, 0x01, 0x15, OP_CHECKMULTISIG];
        assert_eq!(run_fresh(&script), Err(ScriptError::PubkeyCount));
        let script = [OP_0, OP_0, OP_1NEGATE, OP_CHECKMULTISIG];
        assert_eq!(run_fresh(&script), Err(ScriptError::PubkeyCount));
        // Twenty keys of one byte each, no signatures: fine.
        let mut script = vec![OP_0, OP_0];
        script.extend([OP_1; 20]);
        script.extend([0x01, 0x14, OP_CHECKMULTISIG]);
        assert_eq!(run_fresh(&script).expect("20 keys").items(), &[vec![1]]);
        // More signatures than keys, and a negative signature count.
        let script = [OP_0, 0x52, OP_1, OP_1, OP_CHECKMULTISIG];
        assert_eq!(run_fresh(&script), Err(ScriptError::SigCount));
        let script = [OP_0, OP_1NEGATE, OP_1, OP_1, OP_CHECKMULTISIG];
        assert_eq!(run_fresh(&script), Err(ScriptError::SigCount));
        // Missing dummy, then the dummy under NULLDUMMY.
        let script = [OP_0, OP_1, OP_1, OP_CHECKMULTISIG];
        assert_eq!(run_fresh(&script), Err(ScriptError::InvalidStackOperation));
        let script = [OP_1, OP_0, OP_1, OP_1, OP_CHECKMULTISIG];
        assert!(run_fresh(&script).is_ok());
        let mut stack = Stack::new();
        assert_eq!(
            run(&script, &mut stack, ScriptFlags::NULLDUMMY),
            Err(ScriptError::SigNulldummy)
        );
    }

    #[test]
    fn scriptnum_operand_limits() {
        let five_bytes = [0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
        let mut script = five_bytes.to_vec();
        script.push(OP_1ADD);
        assert_eq!(run_fresh(&script), Err(ScriptError::Scriptnum));
        // A four-byte result may exceed four bytes and be pushed; using it fails.
        let script = hex("04ffffff7f")
            .into_iter()
            .chain([OP_1ADD])
            .collect::<Vec<u8>>();
        let stack = run_fresh(&script).expect("the result is pushed");
        assert_eq!(stack.items(), &[hex("0000008000")]);
        let mut script = script;
        script.push(OP_1ADD);
        assert_eq!(run_fresh(&script), Err(ScriptError::Scriptnum));
        // The lock-time opcodes read five bytes; six is too many.
        let mut script = five_bytes.to_vec();
        script.push(OP_CHECKLOCKTIMEVERIFY);
        let mut stack = Stack::new();
        assert_eq!(
            run(&script, &mut stack, ScriptFlags::CHECKLOCKTIMEVERIFY),
            Err(ScriptError::UnsatisfiedLocktime)
        );
        let mut script = hex("06010000000000");
        script.push(OP_CHECKSEQUENCEVERIFY);
        let mut stack = Stack::new();
        assert_eq!(
            run(&script, &mut stack, ScriptFlags::CHECKSEQUENCEVERIFY),
            Err(ScriptError::Scriptnum)
        );
        // Without their flags both are NOPs, whatever the operand.
        assert!(run_fresh(&script).is_ok());
    }

    #[test]
    fn unexecuted_branches_still_parse() {
        let script = [OP_0, OP_IF, OP_CAT, OP_ENDIF, OP_1];
        assert_eq!(run_fresh(&script), Err(ScriptError::DisabledOpcode));
        let script = [OP_0, OP_IF, OP_VERIF, OP_ENDIF, OP_1];
        assert_eq!(run_fresh(&script), Err(ScriptError::BadOpcode));
        let script = [OP_0, OP_IF, OP_RESERVED, OP_VER, 0xff, OP_ENDIF, OP_1];
        assert!(run_fresh(&script).is_ok());
        let script = [OP_0, OP_IF, OP_PUSHDATA1, 0x05, 0x00, OP_ENDIF, OP_1];
        assert_eq!(run_fresh(&script), Err(ScriptError::BadOpcode));
        assert_eq!(
            run_fresh(&[OP_1, OP_IF]),
            Err(ScriptError::UnbalancedConditional)
        );
        assert_eq!(
            run_fresh(&[OP_ENDIF]),
            Err(ScriptError::UnbalancedConditional)
        );
        assert_eq!(
            run_fresh(&[OP_ELSE]),
            Err(ScriptError::UnbalancedConditional)
        );
        // A false OP_IF inside an unexecuted branch consumes nothing.
        let script = [OP_0, OP_IF, OP_IF, OP_ENDIF, OP_ENDIF, OP_DEPTH];
        assert_eq!(run_fresh(&script).expect("balanced").items(), &[vec![]]);
    }

    #[test]
    fn checksigadd_is_tapscript_only() {
        let script = [OP_0, OP_0, OP_0, OP_CHECKSIGADD];
        assert_eq!(run_fresh(&script), Err(ScriptError::BadOpcode));
    }

    /// A tapscript execution setup: a transaction, a key, a leaf hash and a checker.
    struct Tapscript {
        tx: bitcoin::Transaction,
        prevouts: Vec<bitcoin::TxOut>,
        secp: Secp256k1<secp256k1::All>,
        keypair: Keypair,
        pubkey: [u8; 32],
        leaf_hash: [u8; 32],
    }

    fn tapscript(seed: u64) -> Tapscript {
        let mut prng = Prng::new(seed);
        let tx = random_transaction(&mut prng);
        let prevouts = random_prevouts(&mut prng, tx.input.len());
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &prng.bytes_32()).expect("valid key");
        let pubkey = keypair.x_only_public_key().0.serialize();
        Tapscript {
            tx,
            prevouts,
            secp,
            keypair,
            pubkey,
            leaf_hash: prng.bytes_32(),
        }
    }

    impl Tapscript {
        fn sign(&self, codesep_pos: u32) -> Vec<u8> {
            let precomputed = TxPrecomputed::new(&self.tx, &self.prevouts);
            let spend = TaprootSpend::Tapscript {
                leaf_hash: self.leaf_hash,
                codesep_pos,
            };
            let digest =
                taproot_sighash(&self.tx, 0, &self.prevouts, 0x00, spend, None, &precomputed)
                    .expect("default hash type");
            let message = secp256k1::Message::from_digest(digest);
            self.secp
                .sign_schnorr_no_aux_rand(&message, &self.keypair)
                .serialize()
                .to_vec()
        }

        fn run(
            &self,
            script: &[u8],
            items: Vec<Vec<u8>>,
            budget: i64,
        ) -> (Result<(), ScriptError>, Stack, Option<i64>) {
            let precomputed = TxPrecomputed::new(&self.tx, &self.prevouts);
            let checker = TxSigChecker::new(&self.tx, 0, &self.prevouts, &precomputed);
            let mut exec = ExecData::tapscript(TapscriptExec {
                leaf_hash: self.leaf_hash,
                annex: None,
                validation_weight_left: budget,
            });
            let mut stack = Stack::from_items(items);
            let result = eval_script(
                script,
                &mut stack,
                ScriptFlags::MANDATORY,
                SigVersion::Tapscript,
                &mut exec,
                &checker,
            );
            (result, stack, exec.validation_weight_left())
        }
    }

    #[test]
    fn tapscript_checksig_charges_the_budget_and_verifies() {
        let setup = tapscript(11);
        let mut script = vec![0x20];
        script.extend(setup.pubkey);
        script.push(OP_CHECKSIG);
        let signature = setup.sign(CODESEPARATOR_POS_NONE);

        let (result, stack, budget) = setup.run(&script, vec![signature.clone()], 100);
        assert_eq!(result, Ok(()));
        assert_eq!(stack.items(), &[vec![1]]);
        assert_eq!(budget, Some(50));
        // Out of budget: charged before the signature is looked at.
        let (result, _, _) = setup.run(&script, vec![signature.clone()], 49);
        assert_eq!(result, Err(ScriptError::TapscriptValidationWeight));
        // An empty signature is a false, costs nothing, and is never verified.
        let (result, stack, budget) = setup.run(&script, vec![Vec::new()], 10);
        assert_eq!(result, Ok(()));
        assert_eq!(stack.items(), &[vec![]]);
        assert_eq!(budget, Some(10));
        // A wrong signature fails the script, not the check.
        let mut wrong = signature.clone();
        wrong[5] ^= 1;
        let (result, _, _) = setup.run(&script, vec![wrong], 100);
        assert_eq!(result, Err(ScriptError::SchnorrSig));
        // An empty key fails; an unknown key length passes without verifying.
        let (result, _, _) = setup.run(&[OP_0, OP_CHECKSIG], vec![signature.clone()], 100);
        assert_eq!(result, Err(ScriptError::TapscriptEmptyPubkey));
        let mut unknown_key = vec![0x21];
        unknown_key.extend([7u8; 33]);
        unknown_key.push(OP_CHECKSIG);
        let (result, stack, budget) = setup.run(&unknown_key, vec![vec![9; 64]], 100);
        assert_eq!(result, Ok(()));
        assert_eq!(stack.items(), &[vec![1]]);
        assert_eq!(budget, Some(50));
    }

    #[test]
    fn tapscript_codeseparator_position_enters_the_signature() {
        let setup = tapscript(12);
        let mut script = vec![OP_NOP, OP_CODESEPARATOR, 0x20];
        script.extend(setup.pubkey);
        script.push(OP_CHECKSIG);
        // The separator is the second opcode: position 1.
        let (result, _, _) = setup.run(&script, vec![setup.sign(1)], 100);
        assert_eq!(result, Ok(()));
        let (result, _, _) = setup.run(&script, vec![setup.sign(CODESEPARATOR_POS_NONE)], 100);
        assert_eq!(result, Err(ScriptError::SchnorrSig));
    }

    #[test]
    fn tapscript_checksigadd_counts_successes() {
        let setup = tapscript(13);
        let signature = setup.sign(CODESEPARATOR_POS_NONE);
        // (sig n pubkey -- n+1): the key is pushed by the script, the rest is on the stack.
        let mut script = vec![0x20];
        script.extend(setup.pubkey);
        script.push(OP_CHECKSIGADD);
        let (result, stack, _) = setup.run(&script, vec![signature.clone(), vec![2]], 100);
        assert_eq!(result, Ok(()));
        assert_eq!(stack.items(), &[vec![3]]);
        let (result, stack, _) = setup.run(&script, vec![Vec::new(), vec![2]], 100);
        assert_eq!(result, Ok(()));
        assert_eq!(stack.items(), &[vec![2]]);
        let (result, _, _) = setup.run(&script, vec![signature], 100);
        assert_eq!(result, Err(ScriptError::InvalidStackOperation));
    }

    #[test]
    fn tapscript_rules_without_signatures() {
        let setup = tapscript(14);
        // CHECKMULTISIG is gone.
        let (result, _, _) = setup.run(&[OP_0, OP_0, OP_0, OP_CHECKMULTISIG], vec![], 100);
        assert_eq!(result, Err(ScriptError::TapscriptCheckmultisig));
        // Minimal IF arguments are consensus.
        let (result, _, _) = setup.run(&[OP_IF, OP_ENDIF, OP_1], vec![vec![2]], 100);
        assert_eq!(result, Err(ScriptError::TapscriptMinimalif));
        let (result, _, _) = setup.run(&[OP_IF, OP_ENDIF, OP_1], vec![vec![1, 0]], 100);
        assert_eq!(result, Err(ScriptError::TapscriptMinimalif));
        let (result, stack, _) = setup.run(&[OP_NOTIF, OP_ENDIF, OP_1], vec![vec![]], 100);
        assert_eq!(result, Ok(()));
        assert_eq!(stack.items(), &[vec![1]]);
        // No script size and no opcode limit.
        let mut script = vec![OP_NOP; MAX_SCRIPT_SIZE + 1];
        script.push(OP_1);
        let (result, stack, _) = setup.run(&script, vec![], 100);
        assert_eq!(result, Ok(()));
        assert_eq!(stack.items(), &[vec![1]]);
        // The stack limit stays.
        let (result, _, _) = setup.run(&[OP_1; MAX_STACK_SIZE + 1], vec![], 100);
        assert_eq!(result, Err(ScriptError::StackSize));
    }
}
