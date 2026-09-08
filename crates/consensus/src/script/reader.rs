// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading one opcode at a time, exactly as Core's `GetScriptOp` does.
//!
//! Only the shape the signature hash needs lives here for now: where an opcode ends, and
//! where Core's cursor is left when a push runs past the end of the script. That second fact
//! is consensus: `CTransactionSignatureSerializer::SerializeScriptCode` writes the bytes up
//! to the cursor, not to the end of the script, so a truncated push silently drops its tail
//! from the legacy digest. The interpreter's full `Reader` (BM-16) grows out of this function.

/// `OP_PUSHDATA1`: the next byte is the push size.
const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_PUSHDATA2`: the next two bytes, little-endian, are the push size.
const OP_PUSHDATA2: u8 = 0x4d;
/// `OP_PUSHDATA4`: the next four bytes, little-endian, are the push size.
const OP_PUSHDATA4: u8 = 0x4e;
/// `OP_CODESEPARATOR`.
pub const OP_CODESEPARATOR: u8 = 0xab;

/// Where `GetScriptOp` left its cursor after one call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpRead {
    /// A whole opcode, push data included. `next` is the first byte after it.
    Op {
        /// The opcode byte.
        opcode: u8,
        /// The position after the opcode and its data.
        next: usize,
    },
    /// A push whose size field or data runs past the end of the script. `next` is where Core
    /// stops: after the opcode byte and whatever size bytes it could read.
    Truncated {
        /// The position Core's cursor was left at.
        next: usize,
    },
}

/// Reads the opcode starting at `position`, which must be inside the script.
#[must_use]
pub fn read_op(script: &[u8], position: usize) -> OpRead {
    assert!(position < script.len());
    let opcode = *script.get(position).expect("position is inside the script");
    let mut next = position + 1;
    if opcode > OP_PUSHDATA4 {
        return OpRead::Op { opcode, next };
    }

    let size_field_len = match opcode {
        OP_PUSHDATA1 => 1,
        OP_PUSHDATA2 => 2,
        OP_PUSHDATA4 => 4,
        _ => 0,
    };
    let Some(size_field) = script.get(next..next + size_field_len) else {
        return OpRead::Truncated { next };
    };
    let data_len = match size_field {
        [] => usize::from(opcode),
        [byte] => usize::from(*byte),
        [low, high] => usize::from(u16::from_le_bytes([*low, *high])),
        [a, b, c, d] => usize::try_from(u32::from_le_bytes([*a, *b, *c, *d]))
            .expect("a 32-bit push size fits usize"),
        _ => unreachable!("size fields are 0, 1, 2 or 4 bytes"),
    };
    next += size_field_len;
    assert!(next <= script.len());

    if script.len() - next < data_len {
        return OpRead::Truncated { next };
    }
    next += data_len;
    assert!(next <= script.len());
    OpRead::Op { opcode, next }
}

#[cfg(test)]
mod tests {
    use super::{OP_CODESEPARATOR, OpRead, read_op};

    #[test]
    fn plain_opcodes_are_one_byte() {
        let script = [0x76, OP_CODESEPARATOR, 0xac];
        assert_eq!(
            read_op(&script, 0),
            OpRead::Op {
                opcode: 0x76,
                next: 1
            }
        );
        assert_eq!(
            read_op(&script, 1),
            OpRead::Op {
                opcode: OP_CODESEPARATOR,
                next: 2
            }
        );
        assert_eq!(
            read_op(&script, 2),
            OpRead::Op {
                opcode: 0xac,
                next: 3
            }
        );
    }

    #[test]
    fn pushes_carry_their_data() {
        let script = [
            0x02, 0xaa, 0xbb, 0x4c, 0x01, 0xcc, 0x4d, 0x01, 0x00, 0xdd, 0x00,
        ];
        assert_eq!(
            read_op(&script, 0),
            OpRead::Op {
                opcode: 0x02,
                next: 3
            }
        );
        assert_eq!(
            read_op(&script, 3),
            OpRead::Op {
                opcode: 0x4c,
                next: 6
            }
        );
        assert_eq!(
            read_op(&script, 6),
            OpRead::Op {
                opcode: 0x4d,
                next: 10
            }
        );
        // OP_0 is a zero-length push.
        assert_eq!(
            read_op(&script, 10),
            OpRead::Op {
                opcode: 0x00,
                next: 11
            }
        );
        let pushdata4 = [0x4e, 0x02, 0x00, 0x00, 0x00, 0xee, 0xff];
        assert_eq!(
            read_op(&pushdata4, 0),
            OpRead::Op {
                opcode: 0x4e,
                next: 7
            }
        );
    }

    /// Core's cursor stops after the size bytes it managed to read, which is what the legacy
    /// sighash serialiser then writes up to.
    #[test]
    fn truncated_pushes_stop_where_core_stops() {
        assert_eq!(read_op(&[0x02, 0xaa], 0), OpRead::Truncated { next: 1 });
        assert_eq!(read_op(&[0x4c], 0), OpRead::Truncated { next: 1 });
        assert_eq!(
            read_op(&[0x4c, 0x05, 0x01], 0),
            OpRead::Truncated { next: 2 }
        );
        assert_eq!(read_op(&[0x4d, 0x01], 0), OpRead::Truncated { next: 1 });
        assert_eq!(
            read_op(&[0x4d, 0x02, 0x00, 0x01], 0),
            OpRead::Truncated { next: 3 }
        );
        assert_eq!(
            read_op(&[0x4e, 0x01, 0x00, 0x00], 0),
            OpRead::Truncated { next: 1 }
        );
        assert_eq!(
            read_op(&[0x4e, 0x01, 0x00, 0x00, 0x00], 0),
            OpRead::Truncated { next: 5 }
        );
    }
}
