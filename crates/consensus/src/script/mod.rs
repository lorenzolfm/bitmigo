// SPDX-License-Identifier: MIT OR Apache-2.0

//! Script: the interpreter, the signature hashes and the signature checker.
//!
//! The module is laid out as Core's `script/interpreter.cpp` is, one layer at a time from
//! the bottom. [`TxPrecomputed`] (Core's `PrecomputedTransactionData`) and the three digest
//! functions behind it turn a transaction, an input and a `scriptCode` into 32 bytes;
//! [`TxSigChecker`] (`GenericTransactionSignatureChecker`) turns those into a yes or no from
//! libsecp256k1; `eval_script` (`EvalScript`) runs one script over a bounded stack and asks
//! the checker; [`verify_script`] (`VerifyScript`) runs the scripts of one input in Core's
//! order, P2SH and witness v0 included. Taproot's witness branch is the piece still to come.
//!
//! Nothing here reads the chain: a checker holds one transaction, the outputs it spends and
//! the precompute built from them, and every answer is a pure function of those. That is what
//! lets Core's vectors drive the same code the node runs. And nothing here knows a policy
//! rule: [`ScriptFlags`] holds the seven consensus flags and [`ScriptError`] the errors
//! consensus can produce, so the interpreter cannot be asked to enforce `STRICTENC`.

mod checker;
mod error;
mod interpreter;
mod num;
mod opcode;
mod reader;
mod script_flags;
mod sighash;
mod stack;
#[cfg(test)]
mod vector_tests;
#[cfg(test)]
mod vectors;
mod verify;

pub use checker::TxSigChecker;
pub use error::ScriptError;
pub use script_flags::ScriptFlags;
pub use sighash::{TaprootSpend, TxPrecomputed};
pub use verify::verify_script;

/// The rules a script executes under: Core's `SigVersion` minus `TAPROOT`, because the
/// taproot key path executes no script. A key-path signature is checked through
/// [`TaprootSpend::KeyPath`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigVersion {
    /// Pre-segwit scripts, P2SH redeem scripts included: legacy sighash, `FindAndDelete`.
    Base,
    /// Segwit v0 programs (P2WPKH, P2WSH): the BIP143 digest.
    WitnessV0,
    /// A BIP342 leaf under a taproot output: Schnorr signatures, the BIP341 digest.
    Tapscript,
}
