// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`ScriptFlags`]: which script rules a block is verified under.
//!
//! This type is a stand-in. The script interpreter, when it lands, owns the flag type and
//! this module will produce values of that type instead; until then the seven flags block
//! validation can apply live here. The bit positions are Core's (`script/interpreter.h`),
//! so a value here and a `SCRIPT_VERIFY_*` mask there can be compared side by side.

use core::fmt;

/// A set of script verification flags.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    /// No flags: pre-BIP16 script rules. Core's `SCRIPT_VERIFY_NONE`.
    pub const NONE: ScriptFlags = ScriptFlags(0);
    /// Evaluate P2SH subscripts (BIP16).
    pub const P2SH: ScriptFlags = ScriptFlags(1 << 0);
    /// Signatures must be strict DER (BIP66).
    pub const DERSIG: ScriptFlags = ScriptFlags(1 << 2);
    /// The `CHECKMULTISIG` dummy element must be empty (BIP147).
    pub const NULLDUMMY: ScriptFlags = ScriptFlags(1 << 4);
    /// `OP_CHECKLOCKTIMEVERIFY` is enforced (BIP65).
    pub const CHECKLOCKTIMEVERIFY: ScriptFlags = ScriptFlags(1 << 9);
    /// `OP_CHECKSEQUENCEVERIFY` is enforced (BIP112).
    pub const CHECKSEQUENCEVERIFY: ScriptFlags = ScriptFlags(1 << 10);
    /// Segregated witness v0 programs are evaluated (BIP141, BIP143).
    pub const WITNESS: ScriptFlags = ScriptFlags(1 << 11);
    /// Taproot programs are evaluated (BIP341, BIP342).
    pub const TAPROOT: ScriptFlags = ScriptFlags(1 << 17);

    /// Every flag block validation can apply: Core's `MANDATORY_SCRIPT_VERIFY_FLAGS`
    /// (`docs/consensus-rules.md` §4.2). Everything else Core knows is relay policy.
    pub const MANDATORY: ScriptFlags = ScriptFlags::P2SH
        .union(ScriptFlags::DERSIG)
        .union(ScriptFlags::NULLDUMMY)
        .union(ScriptFlags::CHECKLOCKTIMEVERIFY)
        .union(ScriptFlags::CHECKSEQUENCEVERIFY)
        .union(ScriptFlags::WITNESS)
        .union(ScriptFlags::TAPROOT);

    /// The flags in either set.
    #[must_use]
    pub const fn union(self, other: ScriptFlags) -> ScriptFlags {
        ScriptFlags(self.0 | other.0)
    }

    /// Whether every flag of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: ScriptFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether every flag of `self` is set in `other`.
    #[must_use]
    pub const fn is_subset_of(self, other: ScriptFlags) -> bool {
        other.contains(self)
    }

    /// The raw mask, in Core's bit positions.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Name per flag, for `Debug`. The order is Core's enum order.
const FLAG_NAMES: [(ScriptFlags, &str); 7] = [
    (ScriptFlags::P2SH, "P2SH"),
    (ScriptFlags::DERSIG, "DERSIG"),
    (ScriptFlags::NULLDUMMY, "NULLDUMMY"),
    (ScriptFlags::CHECKLOCKTIMEVERIFY, "CHECKLOCKTIMEVERIFY"),
    (ScriptFlags::CHECKSEQUENCEVERIFY, "CHECKSEQUENCEVERIFY"),
    (ScriptFlags::WITNESS, "WITNESS"),
    (ScriptFlags::TAPROOT, "TAPROOT"),
];

impl fmt::Debug for ScriptFlags {
    /// Prints `NONE` or the set flags joined by `|`, so a failing test names the rules.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == ScriptFlags::NONE {
            return f.write_str("NONE");
        }
        let mut written = 0;
        for (flag, name) in FLAG_NAMES {
            if self.contains(flag) {
                if written > 0 {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                written += 1;
            }
        }
        assert!(written > 0);
        assert!(written <= FLAG_NAMES.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ScriptFlags;

    #[test]
    fn bit_positions_are_cores() {
        assert_eq!(ScriptFlags::P2SH.bits(), 1);
        assert_eq!(ScriptFlags::DERSIG.bits(), 4);
        assert_eq!(ScriptFlags::NULLDUMMY.bits(), 16);
        assert_eq!(ScriptFlags::CHECKLOCKTIMEVERIFY.bits(), 512);
        assert_eq!(ScriptFlags::CHECKSEQUENCEVERIFY.bits(), 1024);
        assert_eq!(ScriptFlags::WITNESS.bits(), 2048);
        assert_eq!(ScriptFlags::TAPROOT.bits(), 131_072);
        assert_eq!(
            ScriptFlags::MANDATORY.bits(),
            1 | 4 | 16 | 512 | 1024 | 2048 | 131_072
        );
    }

    #[test]
    fn subset_and_contains_agree() {
        let p2sh_witness = ScriptFlags::P2SH.union(ScriptFlags::WITNESS);
        assert!(p2sh_witness.contains(ScriptFlags::P2SH));
        assert!(!p2sh_witness.contains(ScriptFlags::TAPROOT));
        assert!(p2sh_witness.is_subset_of(ScriptFlags::MANDATORY));
        assert!(!ScriptFlags::MANDATORY.is_subset_of(p2sh_witness));
        assert!(ScriptFlags::NONE.is_subset_of(ScriptFlags::NONE));
        assert!(ScriptFlags::NONE.contains(ScriptFlags::NONE));
    }

    #[test]
    fn debug_names_the_rules() {
        assert_eq!(format!("{:?}", ScriptFlags::NONE), "NONE");
        assert_eq!(
            format!("{:?}", ScriptFlags::WITNESS.union(ScriptFlags::P2SH)),
            "P2SH|WITNESS",
        );
        assert_eq!(
            format!("{:?}", ScriptFlags::MANDATORY),
            "P2SH|DERSIG|NULLDUMMY|CHECKLOCKTIMEVERIFY|CHECKSEQUENCEVERIFY|WITNESS|TAPROOT",
        );
    }
}
