// SPDX-License-Identifier: MIT OR Apache-2.0

//! One append-only series of flat files, and the two halves that use it.
//!
//! `<prefix>NNNNN.dat`, five digits as Core numbers them, 128 MiB apiece and plain append:
//! Core's `MAX_BLOCKFILE_SIZE` with Core's chunk preallocation dropped. Preallocation
//! exists to fight fragmentation, and it costs a finalise-and-truncate step plus a
//! zero-filled tail that recovery has to tell apart from data. The index is the authority
//! on what is committed either way, so plain append has neither (BM-D4 decision 4).
//!
//! 128 MiB leaves five bits of headroom against the `u32` offset in
//! [`BlockLocation`](crate::runtime::queue::BlockLocation), so **the bound that binds is
//! the constant, not the type's ceiling**, and every offset is asserted against the
//! constant.
//!
//! # Framing
//!
//! `magic(4) ‖ len(u32 LE) ‖ body`, and for the undo series a 32-byte trailer after the
//! body. The location names the **body**, so serving a block is one `pread(len)` at the
//! offset with no copy and no reserialisation (R4 §8.6). Core's framing minus the XOR key
//! it added in 28.0, which here would force a copy-and-unmask on every block served.
//!
//! Blocks carry no checksum: a block is self-verifying against its own hash, which is why
//! Core does not checksum them either. Undo records do, because nothing else can vouch for
//! them.
//!
//! # A record larger than the file
//!
//! Only the undo series can produce one, and consensus permits it: a block spending 24,390
//! coins whose `scriptPubKey`s are each at the consensus maximum is a quarter-gigabyte undo
//! record. Rather than abort on a chain the rules allow, such a record gets a file of its
//! own — the roll happens *before* a record that would take a non-empty file past the
//! threshold, so an oversized one always starts at offset zero and the offset stays inside
//! `max(128 MiB, the record)`, far below what a `u32` holds.

#![allow(
    dead_code,
    reason = "the block series is written by the receipt path (BM-9), the undo series by \
              the chainstate (BM-10), and both are read by the block server (BM-24); the \
              roll, the framing and the bounds are complete and tested here"
)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::FRAME_BYTES;
use super::handles::Handles;
use super::reader::DecodeError;

/// Core's `MAX_BLOCKFILE_SIZE`: when a record would take a file past this, the series
/// rolls to the next one.
pub const MAX_FILE_BYTES: u32 = 128 * 1024 * 1024;

const _: () = assert!(MAX_FILE_BYTES == 1 << 27, "Core's 128 MiB");

/// A `u32` offset reaches 2^32 and the threshold is 2^27, so the bound that binds is the
/// constant, five bits before the type's ceiling (BM-D4 decision 4).
const _: () = assert!(u32::MAX / MAX_FILE_BYTES == 31);

/// Where a record's body ended up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placed {
    /// Which file of the series.
    pub file: u32,
    /// Where the body starts in it.
    pub offset: u32,
    /// How long the body is.
    pub len: u32,
}

/// The name of one file of a series.
fn file_name(prefix: &str, number: u32) -> String {
    format!("{prefix}{number:05}.dat")
}

/// Open a series: the writer's cursor at the end of the highest-numbered file, and a
/// reader over all of them.
///
/// `max_record` is the series' own bound on one body, asserted on the way in and refused on
/// the way out; `trailer_bytes` is 0 or 32.
pub fn open(
    directory: &Path,
    prefix: &'static str,
    magic: [u8; 4],
    trailer_bytes: u32,
    max_record: u32,
) -> io::Result<(SeriesWriter, SeriesReader)> {
    open_with_bound(
        directory,
        prefix,
        magic,
        trailer_bytes,
        max_record,
        MAX_FILE_BYTES,
    )
}

/// The same series at a file bound a test can reach in a second.
///
/// The roll is the one behaviour that only shows up at the threshold, and a test that has
/// to write 128 MiB to see it is a test nobody runs.
pub fn open_with_bound(
    directory: &Path,
    prefix: &'static str,
    magic: [u8; 4],
    trailer_bytes: u32,
    max_record: u32,
    max_file: u32,
) -> io::Result<(SeriesWriter, SeriesReader)> {
    assert!(trailer_bytes == 0 || trailer_bytes == 32);
    assert!(max_file > 0 && max_file <= MAX_FILE_BYTES);
    let file = highest(directory, prefix)?;
    let path = directory.join(file_name(prefix, file));
    let handle = OpenOptions::new().create(true).append(true).open(&path)?;
    let offset = u32::try_from(handle.metadata()?.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is longer than a u32 offset", path.display()),
        )
    })?;
    let writer = SeriesWriter {
        directory: directory.to_path_buf(),
        prefix,
        magic,
        trailer_bytes,
        max_record,
        file,
        offset,
        handle,
        unsynced: false,
        max_file,
    };
    let reader = SeriesReader {
        directory: directory.to_path_buf(),
        prefix,
        magic,
        trailer_bytes,
        max_record,
        handles: Handles::new(),
    };
    Ok((writer, reader))
}

/// The highest-numbered file of a series, or zero when there is none yet.
///
/// Read from the directory rather than from a persisted cursor, so that the series and the
/// index recover independently: a crash between the two leaves bytes the index does not
/// name, and those are dead space, never a cursor that has to be believed.
fn highest(directory: &Path, prefix: &str) -> io::Result<u32> {
    let mut highest: u32 = 0;
    for entry in fs::read_dir(directory)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix(prefix) else {
            continue;
        };
        let Some(digits) = rest.strip_suffix(".dat") else {
            continue;
        };
        if digits.len() != 5 {
            continue;
        }
        if let Ok(number) = digits.parse::<u32>() {
            highest = highest.max(number);
        }
    }
    Ok(highest)
}

/// The single writer of one series. One per series, moved to the thread that owns it at
/// startup: not `Clone`, and there is no way to make a second.
pub struct SeriesWriter {
    directory: PathBuf,
    prefix: &'static str,
    magic: [u8; 4],
    trailer_bytes: u32,
    max_record: u32,
    max_file: u32,
    file: u32,
    offset: u32,
    handle: File,
    unsynced: bool,
}

impl SeriesWriter {
    /// Append one record and say where its body is.
    ///
    /// The bytes are durable only after [`SeriesWriter::sync`]; nothing may name them
    /// before then, which is the whole of BM-D4 decision 6's first ordering.
    pub fn append(&mut self, body: &[u8], trailer: Option<[u8; 32]>) -> io::Result<Placed> {
        assert_eq!(
            u32::from(trailer.is_some()).saturating_mul(32),
            self.trailer_bytes,
            "a series is checksummed or it is not",
        );
        let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
        assert!(
            len <= self.max_record,
            "{len} bytes is past this series' own bound of {}",
            self.max_record,
        );
        let record = FRAME_BYTES
            .saturating_add(len)
            .saturating_add(self.trailer_bytes);
        self.place(record)?;

        // One buffer and one `write_all`: a frame split across two calls is a frame a
        // reader could meet half of, and the header is what says how much to trust.
        let mut bytes = Vec::with_capacity(usize::try_from(record).unwrap_or(0));
        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(body);
        if let Some(trailer) = trailer {
            bytes.extend_from_slice(&trailer);
        }
        self.handle.write_all(&bytes)?;
        self.unsynced = true;

        let start = self.offset;
        self.offset = self.offset.saturating_add(record);
        assert!(self.offset > start, "an append moves the cursor");
        Ok(Placed {
            file: self.file,
            offset: start.saturating_add(FRAME_BYTES),
            len,
        })
    }

    /// Move to the next file when this record would take the current one past the
    /// threshold. An empty file takes any record, however large.
    fn place(&mut self, record: u32) -> io::Result<()> {
        if self.offset == 0 || self.offset.saturating_add(record) <= self.max_file {
            return Ok(());
        }
        self.sync()?;
        let next = self.file.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::StorageFull, "the series is at 2^32 files")
        })?;
        let path = self.directory.join(file_name(self.prefix, next));
        self.handle = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)?;
        // The new file's directory entry has to survive too, or the bytes in it are named
        // by an index record that points at a file the crash did not leave behind.
        File::open(&self.directory)?.sync_all()?;
        self.file = next;
        self.offset = 0;
        Ok(())
    }

    /// Make everything appended so far durable.
    pub fn sync(&mut self) -> io::Result<()> {
        if !self.unsynced {
            return Ok(());
        }
        // `sync_all`, not `sync_data`: an append changes the file's length, and a length
        // that has not reached the disk is a record that is not there.
        self.handle.sync_all()?;
        self.unsynced = false;
        Ok(())
    }

    /// Which file the cursor is in, and how far into it. What an operator sees, and what
    /// the tests assert the roll against.
    pub fn cursor(&self) -> (u32, u32) {
        (self.file, self.offset)
    }
}

/// Read access to a series, shared by every thread that serves or replays a record.
pub struct SeriesReader {
    directory: PathBuf,
    prefix: &'static str,
    magic: [u8; 4],
    trailer_bytes: u32,
    max_record: u32,
    handles: Handles,
}

impl SeriesReader {
    /// One record's body, and its trailer when the series has one.
    ///
    /// A single `pread` of the frame, the body and the trailer together: one syscall, and
    /// the frame is checked against what the caller asked for, so a location that names
    /// the wrong place is an error rather than a block-shaped pile of bytes.
    pub fn read(&self, file: u32, offset: u32, len: u32) -> io::Result<(Vec<u8>, [u8; 32])> {
        if len > self.max_record {
            return Err(DecodeError::TooLong {
                declared: u64::from(len),
                limit: u64::from(self.max_record),
            }
            .into());
        }
        let start = offset.checked_sub(FRAME_BYTES).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a location names a body, which never starts inside the frame",
            )
        })?;
        let whole = FRAME_BYTES
            .saturating_add(len)
            .saturating_add(self.trailer_bytes);
        let handle = self
            .handles
            .get(file, || self.directory.join(file_name(self.prefix, file)))?;
        let mut bytes = vec![0u8; usize::try_from(whole).unwrap_or(0)];
        handle.read_exact_at(&mut bytes, u64::from(start))?;
        self.split(&bytes, len)
    }

    /// Check the frame and hand back what is behind it.
    fn split(&self, bytes: &[u8], len: u32) -> io::Result<(Vec<u8>, [u8; 32])> {
        let mut reader = super::reader::Reader::new(bytes);
        let seen: [u8; 4] = reader
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::BadChecksum)?;
        if seen != self.magic {
            return Err(DecodeError::BadMagic { seen }.into());
        }
        let declared = reader.u32_le()?;
        if declared != len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the record here is {declared} bytes, not {len}"),
            ));
        }
        let body = reader.take(usize::try_from(len).unwrap_or(0))?.to_vec();
        let trailer = if self.trailer_bytes == 0 {
            [0u8; 32]
        } else {
            reader.hash()?
        };
        reader.finish()?;
        Ok((body, trailer))
    }

    /// How many files the table holds open, for the test that proves the bound.
    #[cfg(test)]
    pub fn open_files(&self) -> usize {
        self.handles.len()
    }
}

#[cfg(test)]
#[path = "series_tests.rs"]
mod tests;
