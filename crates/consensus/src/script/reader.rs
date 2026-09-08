// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading a script one opcode at a time, exactly as Core's `GetScriptOp` does.
//!
//! Two facts about that function are consensus and shape everything here. A push whose size
//! field or data runs past the end of the script is a failed read, and the failure leaves
//! Core's cursor after the opcode byte and whatever size bytes it could read;
//! `CTransactionSignatureSerializer::SerializeScriptCode` writes bytes up to that cursor, so
//! a truncated push silently drops its tail from the legacy digest. And the interpreter turns
//! that same failed read into `BAD_OPCODE`, while `FindAndDelete` and `IsPushOnly` stop at it.
//! [`read_op`] is the raw step with the cursor semantics; [`Reader`] wraps it for the loops,
//! counting opcodes as it goes for BIP342's `codesep_pos`.

use super::ScriptError;
use super::opcode::{OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, Opcode};

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

/// One opcode as the interpreter sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Op<'a> {
    /// The opcode byte.
    pub opcode: Opcode,
    /// The data a push carries; empty for every other opcode.
    pub push: &'a [u8],
    /// The position after this opcode: where Core's `pc` points during its execution, and
    /// therefore where the `scriptCode` starts after an `OP_CODESEPARATOR`.
    pub end: usize,
}

/// A cursor over a script that yields one [`Op`] per step and counts them.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    script: &'a [u8],
    position: usize,
    ops_read: u32,
}

impl<'a> Reader<'a> {
    /// A cursor at the start of `script`.
    #[must_use]
    pub const fn new(script: &'a [u8]) -> Reader<'a> {
        Reader {
            script,
            position: 0,
            ops_read: 0,
        }
    }

    /// The next opcode, `None` at the end of the script, or [`ScriptError::BadOpcode`] where
    /// `GetScriptOp` fails on a truncated push. After the error the cursor is where Core's
    /// would be; callers that continue past it are mirroring `FindAndDelete`, nothing else.
    pub fn next_op(&mut self) -> Option<Result<Op<'a>, ScriptError>> {
        if self.position >= self.script.len() {
            assert_eq!(self.position, self.script.len());
            return None;
        }
        let start = self.position;
        match read_op(self.script, start) {
            OpRead::Op { opcode, next } => {
                assert!(next > start);
                assert!(next <= self.script.len());
                self.position = next;
                self.ops_read += 1;
                let opcode = Opcode(opcode);
                let push = if opcode.is_push() {
                    push_data(self.script, start, next)
                } else {
                    &[]
                };
                Some(Ok(Op {
                    opcode,
                    push,
                    end: next,
                }))
            }
            OpRead::Truncated { next } => {
                self.position = next;
                Some(Err(ScriptError::BadOpcode))
            }
        }
    }

    /// The byte position of the cursor.
    #[cfg(test)]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Core's `opcode_pos` for the opcode most recently read: zero-based, pushes included,
    /// unexecuted branches included.
    #[must_use]
    pub fn opcode_index(&self) -> u32 {
        assert!(self.ops_read > 0);
        self.ops_read - 1
    }
}

/// Core's `CScript() << data`: the shortest push opcode for `data`, then the bytes. This is
/// the pattern `FindAndDelete` removes and the exact scriptSig a P2SH-wrapped witness program
/// demands (BIP141).
#[must_use]
pub fn push_encoding(data: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(data.len() + 5);
    if data.len() < usize::from(OP_PUSHDATA1) {
        script.push(u8::try_from(data.len()).expect("below 0x4c"));
    } else if let Ok(len) = u8::try_from(data.len()) {
        script.push(OP_PUSHDATA1);
        script.push(len);
    } else if let Ok(len) = u16::try_from(data.len()) {
        script.push(OP_PUSHDATA2);
        script.extend_from_slice(&len.to_le_bytes());
    } else {
        let len = u32::try_from(data.len()).expect("a push fits 32 bits");
        script.push(OP_PUSHDATA4);
        script.extend_from_slice(&len.to_le_bytes());
    }
    script.extend_from_slice(data);
    assert!(script.len() > data.len());
    script
}

/// The data bytes of the push in `start..next`, given that `read_op` succeeded on it.
fn push_data(script: &[u8], start: usize, next: usize) -> &[u8] {
    let opcode = *script.get(start).expect("start is inside the script");
    let size_field_len = match opcode {
        OP_PUSHDATA1 => 1,
        OP_PUSHDATA2 => 2,
        OP_PUSHDATA4 => 4,
        _ => 0,
    };
    let data_start = start + 1 + size_field_len;
    assert!(data_start <= next);
    script.get(data_start..next).expect("inside the script")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index out of bounds fails the test with a panic"
    )]

    use super::super::ScriptError;
    use super::super::opcode::{OP_CODESEPARATOR, OP_PUSHDATA1, OP_PUSHDATA2, Opcode};
    use super::{Op, OpRead, Reader, push_encoding, read_op};

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

    #[test]
    fn reader_yields_pushes_with_their_data_and_counts_opcodes() {
        let script = [
            0x00,
            0x02,
            0xaa,
            0xbb,
            OP_PUSHDATA1,
            0x01,
            0xcc,
            OP_PUSHDATA2,
            0x01,
            0x00,
            0xdd,
            0x51,
            OP_CODESEPARATOR,
            0xac,
        ];
        let mut reader = Reader::new(&script);
        let expected = [
            (Opcode(0x00), &[][..], 1),
            (Opcode(0x02), &[0xaa, 0xbb][..], 4),
            (Opcode(OP_PUSHDATA1), &[0xcc][..], 7),
            (Opcode(OP_PUSHDATA2), &[0xdd][..], 11),
            (Opcode(0x51), &[][..], 12),
            (Opcode(OP_CODESEPARATOR), &[][..], 13),
            (Opcode(0xac), &[][..], 14),
        ];
        for (index, (opcode, push, end)) in expected.into_iter().enumerate() {
            assert_eq!(
                reader.next_op(),
                Some(Ok(Op { opcode, push, end })),
                "op {index}"
            );
            assert_eq!(reader.opcode_index(), u32::try_from(index).expect("small"));
            assert_eq!(reader.position(), end);
        }
        assert_eq!(reader.next_op(), None);
        assert_eq!(reader.next_op(), None);
    }

    #[test]
    fn reader_reports_a_truncated_push_as_bad_opcode() {
        let mut reader = Reader::new(&[0x51, 0x4c, 0x05, 0x01]);
        assert!(reader.next_op().expect("an op").is_ok());
        assert_eq!(reader.next_op(), Some(Err(ScriptError::BadOpcode)));
        assert_eq!(reader.position(), 3);
        // The opcode count does not include the failed read.
        assert_eq!(reader.opcode_index(), 0);
    }

    #[test]
    fn push_encoding_picks_the_shortest_opcode() {
        assert_eq!(push_encoding(&[]), vec![0x00]);
        assert_eq!(push_encoding(&[0xaa]), vec![0x01, 0xaa]);
        assert_eq!(push_encoding(&[0; 75])[..2], [0x4b, 0x00]);
        assert_eq!(push_encoding(&[0; 76])[..3], [0x4c, 0x4c, 0x00]);
        assert_eq!(push_encoding(&[0; 255])[..3], [0x4c, 0xff, 0x00]);
        assert_eq!(push_encoding(&[0; 256])[..4], [0x4d, 0x00, 0x01, 0x00]);
        assert_eq!(
            push_encoding(&vec![0; 65_536])[..6],
            [0x4e, 0x00, 0x00, 0x01, 0x00, 0x00]
        );
        // What the reader gets back is what went in.
        for len in [0, 1, 75, 76, 255, 256, 520, 65_536] {
            let data = vec![0x5a; len];
            let script = push_encoding(&data);
            let mut reader = Reader::new(&script);
            let op = reader.next_op().expect("one op").expect("well formed");
            assert_eq!(op.push, &data[..]);
            assert_eq!(op.end, script.len());
            assert_eq!(reader.next_op(), None);
        }
    }

    #[test]
    fn empty_script_yields_nothing() {
        let mut reader = Reader::new(&[]);
        assert_eq!(reader.next_op(), None);
        assert_eq!(reader.position(), 0);
    }
}
