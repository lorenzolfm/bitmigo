// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading bytes back off a disk that may have been cut in half, and the varint both
//! encoders use.
//!
//! Every decoder in this module tree is built on [`Reader`], which cannot read past its
//! slice and cannot panic. The bytes are this node's own, so the errors here are not about
//! a hostile sender: they are what a torn tail, a truncated file or a location naming the
//! wrong place looks like from the inside, and each of them has to be a value the caller
//! can act on rather than an abort.
//!
//! The varint is Core's `VARINT` — MSB base-128 with the "minus one per continuation"
//! offset (`serialize.h`), which btcd calls a VLQ and documents identically. Not LEB128 and
//! not the `bitcoin` crate's `CompactSize`: `docs/storage-layouts.md` describes Core's
//! layouts in this encoding, and using the same one keeps that document a valid reference
//! for reading bitmigo's own files.

use std::fmt;
use std::io;

/// Why a decode did not produce a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The slice ended in the middle of a field.
    Truncated {
        /// How many bytes the field needed.
        wanted: usize,
        /// How many were left.
        left: usize,
    },
    /// The record decoded, and then there were bytes after it.
    Trailing {
        /// How many.
        left: usize,
    },
    /// The four leading bytes are not this series'.
    BadMagic {
        /// What was there.
        seen: [u8; 4],
    },
    /// The record's checksum is not the checksum of its bytes.
    BadChecksum,
    /// A varint ran past the end, or past what a `u64` holds.
    BadVarint,
    /// A count or a length is past a bound this node states.
    TooLong {
        /// What the bytes said.
        declared: u64,
        /// The most this node will read.
        limit: u64,
    },
    /// Two coins of one undo record claim the same input, or claim them out of order.
    NotAscending {
        /// The index that did not follow the one before it.
        input: u32,
    },
    /// A tag byte names no state.
    BadTag {
        /// The byte.
        tag: u8,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated { wanted, left } => {
                write!(formatter, "truncated: wanted {wanted} bytes, {left} left")
            }
            DecodeError::Trailing { left } => write!(formatter, "{left} bytes after the record"),
            DecodeError::BadMagic { seen } => write!(formatter, "not this series: magic {seen:?}"),
            DecodeError::BadChecksum => formatter.write_str("checksum does not match"),
            DecodeError::BadVarint => formatter.write_str("varint runs past a u64"),
            DecodeError::TooLong { declared, limit } => {
                write!(formatter, "declared {declared}, past the bound of {limit}")
            }
            DecodeError::NotAscending { input } => {
                write!(formatter, "input {input} does not follow the one before it")
            }
            DecodeError::BadTag { tag } => write!(formatter, "no state is tagged {tag}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<DecodeError> for io::Error {
    fn from(error: DecodeError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

/// A cursor over bytes that are already in memory.
pub struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Read from the start of a slice.
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes }
    }

    /// The next `count` bytes.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        let (taken, rest) = self
            .bytes
            .split_at_checked(count)
            .ok_or(DecodeError::Truncated {
                wanted: count,
                left: self.bytes.len(),
            })?;
        self.bytes = rest;
        Ok(taken)
    }

    /// The next byte.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let byte = *self.take(1)?.first().ok_or(DecodeError::BadVarint)?;
        Ok(byte)
    }

    /// The next four bytes, little-endian.
    pub fn u32_le(&mut self) -> Result<u32, DecodeError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::BadVarint)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// The next thirty-two bytes.
    pub fn hash(&mut self) -> Result<[u8; 32], DecodeError> {
        self.take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated {
                wanted: 32,
                left: 0,
            })
    }

    /// The next varint.
    ///
    /// Core's `ReadVarInt`, refusing the two overflows it refuses: a shift that would carry
    /// the high seven bits off the top, and the increment at `u64::MAX`.
    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value: u64 = 0;
        // A `u64` is ten groups of seven bits at most; past that the bytes are not a varint
        // this encoder wrote, and the loop must end whatever they say.
        for _ in 0..10 {
            let byte = self.u8()?;
            if value > (u64::MAX >> 7) {
                return Err(DecodeError::BadVarint);
            }
            value = (value << 7) | u64::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            if value == u64::MAX {
                return Err(DecodeError::BadVarint);
            }
            value = value.saturating_add(1);
        }
        Err(DecodeError::BadVarint)
    }

    /// A count, refused before anything is reserved for it.
    ///
    /// The one rule that matters wherever a length precedes a body: nothing is allocated
    /// from a number until the number is inside a bound this node chose.
    pub fn count(&mut self, limit: u64) -> Result<usize, DecodeError> {
        let declared = self.varint()?;
        if declared > limit {
            return Err(DecodeError::TooLong { declared, limit });
        }
        usize::try_from(declared).map_err(|_| DecodeError::TooLong { declared, limit })
    }

    /// Nothing may follow the record.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Trailing {
                left: self.bytes.len(),
            })
        }
    }
}

/// Append Core's `VARINT` encoding of `value`.
pub fn put_varint(bytes: &mut Vec<u8>, value: u64) {
    // Core's `WriteVarInt`: the groups come out least significant first and are written in
    // reverse, so the buffer is at most ten bytes and is sized for it.
    let mut groups = [0u8; 10];
    let mut length = 0usize;
    let mut left = value;
    loop {
        let flag = if length == 0 { 0x00 } else { 0x80 };
        if let Some(slot) = groups.get_mut(length) {
            // The mask keeps seven bits, which is what a byte is being asked for.
            let group = u8::try_from(left & 0x7f).unwrap_or(0);
            *slot = group | flag;
        }
        if left <= 0x7f {
            break;
        }
        left = (left >> 7).saturating_sub(1);
        length = length.saturating_add(1);
    }
    assert!(length < groups.len(), "a u64 is ten groups of seven bits");
    for position in (0..=length).rev() {
        if let Some(group) = groups.get(position) {
            bytes.push(*group);
        }
    }
}

#[cfg(test)]
#[path = "reader_tests.rs"]
mod tests;
