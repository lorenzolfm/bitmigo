// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`ScriptError`]: why a script failed, in Bitcoin Core's vocabulary.
//!
//! Every variant is a `SCRIPT_ERR_*` that consensus validation can actually produce, named
//! without the prefix; `Display` gives the spelling Core's test vectors use, so an expected
//! error in `script_tests.json` compares by string. Policy-only errors have no variant: a
//! node that cannot represent `SCRIPT_ERR_SIG_HIGH_S` cannot reject a block for it.
//!
//! The enum starts with the three errors the signature checker raises; the interpreter adds
//! its own when it lands.

use core::fmt;

/// A consensus script failure, named as Core names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScriptError {
    /// A Schnorr signature was neither 64 nor 65 bytes (BIP341).
    SchnorrSigSize,
    /// A 65-byte Schnorr signature carried hash type `0x00`, or any signature carried a hash
    /// type outside `{0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}`, or asked for `SINGLE` at an
    /// input with no matching output (BIP341).
    SchnorrSigHashtype,
    /// A well-formed Schnorr signature did not verify against the key (BIP340).
    SchnorrSig,
}

impl ScriptError {
    /// Core's `ScriptErrorString` name minus the `SCRIPT_ERR_` prefix: the vector spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ScriptError::SchnorrSigSize => "SCHNORR_SIG_SIZE",
            ScriptError::SchnorrSigHashtype => "SCHNORR_SIG_HASHTYPE",
            ScriptError::SchnorrSig => "SCHNORR_SIG",
        }
    }
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
            ScriptError::SchnorrSigHashtype.to_string(),
            "SCHNORR_SIG_HASHTYPE"
        );
        assert_eq!(ScriptError::SchnorrSig.to_string(), "SCHNORR_SIG");
    }
}
