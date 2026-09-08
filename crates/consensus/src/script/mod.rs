// SPDX-License-Identifier: MIT OR Apache-2.0

//! Script: the signature hashes and the signature checker, with the interpreter to follow.
//!
//! The module is laid out as Core's `script/interpreter.cpp` is, one layer at a time from the
//! bottom. This first layer is everything that turns a transaction, an input and a
//! `scriptCode` into a 32-byte digest and a yes or no from libsecp256k1: [`TxPrecomputed`]
//! (Core's `PrecomputedTransactionData`), the three digest functions behind it, and
//! [`TxSigChecker`] (Core's `GenericTransactionSignatureChecker`). The interpreter itself,
//! Core's `EvalScript` and `VerifyScript`, lands next and adds to [`ScriptError`].
//!
//! Nothing here reads the chain: a checker holds one transaction, the outputs it spends and
//! the precompute built from them, and every answer is a pure function of those. That is what
//! lets Core's vectors drive the same code the node runs.

mod checker;
mod error;
mod reader;
mod sighash;
#[cfg(test)]
mod vectors;

pub use checker::TxSigChecker;
pub use error::ScriptError;
pub use sighash::{TaprootSpend, TxPrecomputed};

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
