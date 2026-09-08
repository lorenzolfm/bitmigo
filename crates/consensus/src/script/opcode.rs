// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opcode bytes under Core's names (`script/script.h: opcodetype`), and the few questions
//! the interpreter asks of one byte before it dispatches on it.
//!
//! The constants are plain `u8`s so that a `match` can use ranges (`OP_1..=OP_16`); the
//! [`Opcode`] newtype exists so that an opcode read from a script cannot be confused with a
//! push length or a stack depth in a signature. Names are Core's exactly, `OP_NOP2` and
//! `OP_NOP3` spelled by their BIP65 and BIP112 meanings as `script.h` spells them.

#![allow(
    dead_code,
    reason = "the table names every byte Core names; the interpreter dispatches on ranges \
              that cover the reserved ones, and the test parser reads them all"
)]

/// An empty push: `OP_0`, also `OP_FALSE`.
pub const OP_0: u8 = 0x00;
/// The next byte is the push size.
pub const OP_PUSHDATA1: u8 = 0x4c;
/// The next two bytes, little-endian, are the push size.
pub const OP_PUSHDATA2: u8 = 0x4d;
/// The next four bytes, little-endian, are the push size.
pub const OP_PUSHDATA4: u8 = 0x4e;
/// Pushes the number -1.
pub const OP_1NEGATE: u8 = 0x4f;
/// Fails when executed; does not count toward the opcode limit.
pub const OP_RESERVED: u8 = 0x50;
/// Pushes the number 1, also `OP_TRUE`; `OP_2` to `OP_16` follow it.
pub const OP_1: u8 = 0x51;
/// Pushes the number 16.
pub const OP_16: u8 = 0x60;

// Control.
pub const OP_NOP: u8 = 0x61;
pub const OP_VER: u8 = 0x62;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_RETURN: u8 = 0x6a;

// Stack.
pub const OP_TOALTSTACK: u8 = 0x6b;
pub const OP_FROMALTSTACK: u8 = 0x6c;
pub const OP_2DROP: u8 = 0x6d;
pub const OP_2DUP: u8 = 0x6e;
pub const OP_3DUP: u8 = 0x6f;
pub const OP_2OVER: u8 = 0x70;
pub const OP_2ROT: u8 = 0x71;
pub const OP_2SWAP: u8 = 0x72;
pub const OP_IFDUP: u8 = 0x73;
pub const OP_DEPTH: u8 = 0x74;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_NIP: u8 = 0x77;
pub const OP_OVER: u8 = 0x78;
pub const OP_PICK: u8 = 0x79;
pub const OP_ROLL: u8 = 0x7a;
pub const OP_ROT: u8 = 0x7b;
pub const OP_SWAP: u8 = 0x7c;
pub const OP_TUCK: u8 = 0x7d;

// Splice: all disabled but `OP_SIZE`.
pub const OP_CAT: u8 = 0x7e;
pub const OP_SUBSTR: u8 = 0x7f;
pub const OP_LEFT: u8 = 0x80;
pub const OP_RIGHT: u8 = 0x81;
pub const OP_SIZE: u8 = 0x82;

// Bit logic: all disabled but the two equality tests.
pub const OP_INVERT: u8 = 0x83;
pub const OP_AND: u8 = 0x84;
pub const OP_OR: u8 = 0x85;
pub const OP_XOR: u8 = 0x86;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_RESERVED1: u8 = 0x89;
pub const OP_RESERVED2: u8 = 0x8a;

// Numeric.
pub const OP_1ADD: u8 = 0x8b;
pub const OP_1SUB: u8 = 0x8c;
pub const OP_2MUL: u8 = 0x8d;
pub const OP_2DIV: u8 = 0x8e;
pub const OP_NEGATE: u8 = 0x8f;
pub const OP_ABS: u8 = 0x90;
pub const OP_NOT: u8 = 0x91;
pub const OP_0NOTEQUAL: u8 = 0x92;
pub const OP_ADD: u8 = 0x93;
pub const OP_SUB: u8 = 0x94;
pub const OP_MUL: u8 = 0x95;
pub const OP_DIV: u8 = 0x96;
pub const OP_MOD: u8 = 0x97;
pub const OP_LSHIFT: u8 = 0x98;
pub const OP_RSHIFT: u8 = 0x99;
pub const OP_BOOLAND: u8 = 0x9a;
pub const OP_BOOLOR: u8 = 0x9b;
pub const OP_NUMEQUAL: u8 = 0x9c;
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
pub const OP_LESSTHAN: u8 = 0x9f;
pub const OP_GREATERTHAN: u8 = 0xa0;
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
pub const OP_MIN: u8 = 0xa3;
pub const OP_MAX: u8 = 0xa4;
pub const OP_WITHIN: u8 = 0xa5;

// Crypto.
pub const OP_RIPEMD160: u8 = 0xa6;
pub const OP_SHA1: u8 = 0xa7;
pub const OP_SHA256: u8 = 0xa8;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_HASH256: u8 = 0xaa;
pub const OP_CODESEPARATOR: u8 = 0xab;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

// Expansion.
pub const OP_NOP1: u8 = 0xb0;
/// `OP_NOP2` before BIP65.
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
/// `OP_NOP3` before BIP112.
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
pub const OP_NOP4: u8 = 0xb3;
pub const OP_NOP5: u8 = 0xb4;
pub const OP_NOP6: u8 = 0xb5;
pub const OP_NOP7: u8 = 0xb6;
pub const OP_NOP8: u8 = 0xb7;
pub const OP_NOP9: u8 = 0xb8;
pub const OP_NOP10: u8 = 0xb9;
/// BIP342: tapscript only, `BAD_OPCODE` elsewhere.
pub const OP_CHECKSIGADD: u8 = 0xba;
/// Never valid; also what `GetScriptOp` reports when it cannot read one.
pub const OP_INVALIDOPCODE: u8 = 0xff;

/// One opcode byte as read from a script.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Opcode(pub u8);

impl Opcode {
    /// The raw byte, for dispatching on Core's constants.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self.0
    }

    /// A data push: `OP_0`, the direct pushes and the three `OP_PUSHDATA`s. `OP_1NEGATE`
    /// and `OP_1..OP_16` are not pushes in this sense; they carry no data bytes.
    #[must_use]
    pub const fn is_push(self) -> bool {
        self.0 <= OP_PUSHDATA4
    }

    /// The fifteen opcodes disabled after CVE-2010-5137. They fail the script when parsed,
    /// executed or not.
    #[must_use]
    pub const fn is_disabled(self) -> bool {
        matches!(
            self.0,
            OP_CAT
                | OP_SUBSTR
                | OP_LEFT
                | OP_RIGHT
                | OP_INVERT
                | OP_AND
                | OP_OR
                | OP_XOR
                | OP_2MUL
                | OP_2DIV
                | OP_MUL
                | OP_DIV
                | OP_MOD
                | OP_LSHIFT
                | OP_RSHIFT
        )
    }

    /// `OP_IF` through `OP_ENDIF`: dispatched even inside an unexecuted branch, which is why
    /// `OP_VERIF` and `OP_VERNOTIF` fail wherever they appear.
    #[must_use]
    pub const fn is_conditional(self) -> bool {
        self.0 >= OP_IF && self.0 <= OP_ENDIF
    }

    /// Whether the opcode counts toward `MAX_OPS_PER_SCRIPT`: everything above `OP_16`, so
    /// pushes, the small integers and `OP_RESERVED` are free.
    #[must_use]
    pub const fn counts_toward_op_limit(self) -> bool {
        self.0 > OP_16
    }

    /// The number `OP_1NEGATE` and `OP_1..OP_16` push: Core's `opcode - (OP_1 - 1)`.
    #[must_use]
    pub fn small_integer(self) -> i64 {
        assert!(self.0 == OP_1NEGATE || (OP_1..=OP_16).contains(&self.0));
        let value = i64::from(self.0) - i64::from(OP_1 - 1);
        assert!(value >= -1);
        assert!(value <= 16);
        assert_ne!(value, 0);
        value
    }
}

/// The opcode names Core's `ParseScript` accepts, for the test vectors' script language:
/// `GetOpName` for every byte from `OP_NOP` to `MAX_OPCODE` (`OP_NOP10`), plus
/// `OP_RESERVED`. The parser also admits each name without its `OP_` prefix; the pushes and
/// small integers are spelled as decimals and hex, never by name, and `OP_CHECKSIGADD` is
/// written as raw hex because it sits above `MAX_OPCODE`.
#[cfg(test)]
pub const PARSER_NAMES: [(u8, &str); 90] = [
    (OP_RESERVED, "OP_RESERVED"),
    (OP_NOP, "OP_NOP"),
    (OP_VER, "OP_VER"),
    (OP_IF, "OP_IF"),
    (OP_NOTIF, "OP_NOTIF"),
    (OP_VERIF, "OP_VERIF"),
    (OP_VERNOTIF, "OP_VERNOTIF"),
    (OP_ELSE, "OP_ELSE"),
    (OP_ENDIF, "OP_ENDIF"),
    (OP_VERIFY, "OP_VERIFY"),
    (OP_RETURN, "OP_RETURN"),
    (OP_TOALTSTACK, "OP_TOALTSTACK"),
    (OP_FROMALTSTACK, "OP_FROMALTSTACK"),
    (OP_2DROP, "OP_2DROP"),
    (OP_2DUP, "OP_2DUP"),
    (OP_3DUP, "OP_3DUP"),
    (OP_2OVER, "OP_2OVER"),
    (OP_2ROT, "OP_2ROT"),
    (OP_2SWAP, "OP_2SWAP"),
    (OP_IFDUP, "OP_IFDUP"),
    (OP_DEPTH, "OP_DEPTH"),
    (OP_DROP, "OP_DROP"),
    (OP_DUP, "OP_DUP"),
    (OP_NIP, "OP_NIP"),
    (OP_OVER, "OP_OVER"),
    (OP_PICK, "OP_PICK"),
    (OP_ROLL, "OP_ROLL"),
    (OP_ROT, "OP_ROT"),
    (OP_SWAP, "OP_SWAP"),
    (OP_TUCK, "OP_TUCK"),
    (OP_CAT, "OP_CAT"),
    (OP_SUBSTR, "OP_SUBSTR"),
    (OP_LEFT, "OP_LEFT"),
    (OP_RIGHT, "OP_RIGHT"),
    (OP_SIZE, "OP_SIZE"),
    (OP_INVERT, "OP_INVERT"),
    (OP_AND, "OP_AND"),
    (OP_OR, "OP_OR"),
    (OP_XOR, "OP_XOR"),
    (OP_EQUAL, "OP_EQUAL"),
    (OP_EQUALVERIFY, "OP_EQUALVERIFY"),
    (OP_RESERVED1, "OP_RESERVED1"),
    (OP_RESERVED2, "OP_RESERVED2"),
    (OP_1ADD, "OP_1ADD"),
    (OP_1SUB, "OP_1SUB"),
    (OP_2MUL, "OP_2MUL"),
    (OP_2DIV, "OP_2DIV"),
    (OP_NEGATE, "OP_NEGATE"),
    (OP_ABS, "OP_ABS"),
    (OP_NOT, "OP_NOT"),
    (OP_0NOTEQUAL, "OP_0NOTEQUAL"),
    (OP_ADD, "OP_ADD"),
    (OP_SUB, "OP_SUB"),
    (OP_MUL, "OP_MUL"),
    (OP_DIV, "OP_DIV"),
    (OP_MOD, "OP_MOD"),
    (OP_LSHIFT, "OP_LSHIFT"),
    (OP_RSHIFT, "OP_RSHIFT"),
    (OP_BOOLAND, "OP_BOOLAND"),
    (OP_BOOLOR, "OP_BOOLOR"),
    (OP_NUMEQUAL, "OP_NUMEQUAL"),
    (OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY"),
    (OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL"),
    (OP_LESSTHAN, "OP_LESSTHAN"),
    (OP_GREATERTHAN, "OP_GREATERTHAN"),
    (OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL"),
    (OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL"),
    (OP_MIN, "OP_MIN"),
    (OP_MAX, "OP_MAX"),
    (OP_WITHIN, "OP_WITHIN"),
    (OP_RIPEMD160, "OP_RIPEMD160"),
    (OP_SHA1, "OP_SHA1"),
    (OP_SHA256, "OP_SHA256"),
    (OP_HASH160, "OP_HASH160"),
    (OP_HASH256, "OP_HASH256"),
    (OP_CODESEPARATOR, "OP_CODESEPARATOR"),
    (OP_CHECKSIG, "OP_CHECKSIG"),
    (OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY"),
    (OP_CHECKMULTISIG, "OP_CHECKMULTISIG"),
    (OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY"),
    (OP_NOP1, "OP_NOP1"),
    (OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY"),
    (OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY"),
    (OP_NOP4, "OP_NOP4"),
    (OP_NOP5, "OP_NOP5"),
    (OP_NOP6, "OP_NOP6"),
    (OP_NOP7, "OP_NOP7"),
    (OP_NOP8, "OP_NOP8"),
    (OP_NOP9, "OP_NOP9"),
    (OP_NOP10, "OP_NOP10"),
];

#[cfg(test)]
mod tests {
    use super::{
        OP_1, OP_1NEGATE, OP_16, OP_CHECKSIGADD, OP_NOP, OP_NOP10, OP_RESERVED, Opcode,
        PARSER_NAMES,
    };

    #[test]
    fn predicates_partition_the_byte_space() {
        let mut disabled = 0;
        let mut counted = 0;
        for byte in 0..=u8::MAX {
            let opcode = Opcode(byte);
            if opcode.is_disabled() {
                disabled += 1;
                assert!(!opcode.is_push());
                assert!(opcode.counts_toward_op_limit());
            }
            if opcode.counts_toward_op_limit() {
                counted += 1;
                assert!(!opcode.is_push());
            }
            if opcode.is_conditional() {
                assert!(opcode.counts_toward_op_limit());
            }
        }
        assert_eq!(disabled, 15);
        assert_eq!(counted, usize::from(u8::MAX - OP_16));
    }

    #[test]
    fn small_integers_are_their_opcode_offsets() {
        assert_eq!(Opcode(OP_1NEGATE).small_integer(), -1);
        assert_eq!(Opcode(OP_1).small_integer(), 1);
        assert_eq!(Opcode(OP_16).small_integer(), 16);
        assert_eq!(Opcode(0x5a).small_integer(), 10);
    }

    #[test]
    fn parser_names_are_core_s_map() {
        let mut bytes: Vec<u8> = PARSER_NAMES.iter().map(|(byte, _)| *byte).collect();
        bytes.sort_unstable();
        bytes.dedup();
        assert_eq!(bytes.len(), PARSER_NAMES.len());
        // Every byte from OP_NOP to MAX_OPCODE (OP_NOP10) has a name, plus OP_RESERVED.
        for byte in OP_NOP..=OP_NOP10 {
            assert!(bytes.contains(&byte), "{byte:#04x} is unnamed");
        }
        assert!(bytes.contains(&OP_RESERVED));
        assert!(!bytes.contains(&OP_CHECKSIGADD));
        for (byte, name) in PARSER_NAMES {
            assert!(name.starts_with("OP_"), "{byte:#04x}");
        }
    }
}
