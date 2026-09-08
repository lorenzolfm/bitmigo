// SPDX-License-Identifier: MIT OR Apache-2.0

//! Script: the interpreter, the signature hashes and the signature checker.
//!
//! The module is laid out as Core's `script/interpreter.cpp` is, one layer at a time from
//! the bottom. [`TxPrecomputed`] (Core's `PrecomputedTransactionData`) and the three digest
//! functions behind it turn a transaction, an input and a `scriptCode` into 32 bytes;
//! [`TxSigChecker`] (`GenericTransactionSignatureChecker`) turns those into a yes or no from
//! libsecp256k1; `eval_script` (`EvalScript`) runs one script over a bounded stack and asks
//! the checker; [`verify_script`] (`VerifyScript`) runs the scripts of one input in Core's
//! order, P2SH, witness v0 and taproot included, with the BIP341 commitment in `taproot`;
//! and [`verify_input`] is the seam the node calls, one input of one transaction at a time
//! over a shared [`TxPrecomputed`] (BM-D2 decision 4).
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
mod taproot;
#[cfg(test)]
mod vector_tests;
// The JSON reader and the PRNG serve the other modules' tests too.
#[cfg(test)]
pub(crate) mod vectors;
mod verify;

pub use checker::TxSigChecker;
pub use error::ScriptError;
pub use script_flags::ScriptFlags;
pub use sighash::{TaprootSpend, TxPrecomputed};
pub use verify::{verify_input, verify_script};

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
