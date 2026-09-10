// SPDX-License-Identifier: MIT OR Apache-2.0

//! The block store: the append-only bytes, and the index that names them.
//!
//! Three things live on the disk under one lock — the blocks, their undo records, and the
//! index that says where each one is. The coin store joins them (BM-27); everything here is
//! BM-D4 decisions 3, 4, 5, 8 and 9.
//!
//! ```text
//!   $XDG_DATA_HOME/bitmigo/<chain>/
//!   ├── LOCK          held for the process's life, std File::try_lock
//!   ├── anchors.dat   BM-22's
//!   ├── blocks/       blk00000.dat …, undo00000.dat …   128 MiB, plain append
//!   ├── index/        journal.dat                        append-only, rewritten whole
//!   └── coins/        BM-27's
//! ```
//!
//! # Two series, one writer each
//!
//! Blocks and undo records are two independent flat-file series. Core mirrors `rev*.dat`
//! onto `blk*.dat` so that pruning can delete both together; bitmigo never prunes, and
//! mirroring would instead make the validation thread — which produces an undo record at
//! connect — follow the chain thread's file cursor. Independent series give each series
//! exactly one writer and one cursor, so neither is shared and neither is locked. The types
//! say so: [`SeriesWriter`] is not `Clone` and is handed to one thread at startup.
//!
//! Reads are the other way round: thirty-two peer writers serve blocks out of ~5,600 files
//! at mainnet, so [`SeriesReader`] is shared and bounds what that costs in descriptors
//! ([`handles`]).
//!
//! # The one ordering rule
//!
//! **A record that names bytes is committed only after those bytes are durable.** BM-D4
//! decision 6 applies it three times:
//!
//! | ordering | what it guarantees | kept by |
//! |---|---|---|
//! | block `fsync` → index record | every block location the index names is durable | here |
//! | undo `fsync` → index record | every undo location it names is durable | BM-10 |
//! | index record → coin manifest commit | every coin belongs to a block the index names | here |
//! | run `fsync` → manifest rename | the coin set is never ahead of its own marker | BM-27 |
//!
//! **The block leg is this module's, and it is one function.** [`ChainStore::commit`]
//! `fsync`s the block series and then appends the index batch, so no index record can name
//! block bytes that did not survive.
//!
//! **The third crosses a thread boundary** — the chain thread writes the index, the
//! validation thread commits the coin manifest — and BM-D5's table has no channel back. It
//! is kept structurally rather than by a handshake: **the chain thread never hands
//! validation a block the index has not committed**, so validation is free to commit its
//! manifest whenever it likes, because every block it was ever given was already named.
//! That is what makes the commit a batch on the chain thread rather than an `fsync` per
//! block, which BM-D4 rules out.
//!
//! **The undo leg is not this module's, and cannot be.** The undo series' writer belongs to
//! the validation thread, so [`ChainStore::commit`] cannot `fsync` it, and syncing on every
//! [`UndoStore::write_undo`] would be exactly the per-block `fsync` that is ruled out. What
//! closes it is the report that carries a connect back to the chain thread, which is BM-10's:
//! **an undo location must not be reported until [`SeriesWriter::sync`] has returned for the
//! record it names.** Until then an index record can name undo bytes a crash would lose. The
//! cost of getting it wrong is bounded but real — the load would find a `Connected` entry
//! whose undo record is short, and a reorg below it would have nothing to work from — so it
//! is stated here, beside the leg that is enforced, rather than left to be rediscovered.
//!
//! # What survives a crash
//!
//! `H`, the coin store's marker, is the truth, and nothing above it survives as a claim on
//! anything. Bytes that are durable but unnamed are dead space — Core's behaviour exactly,
//! and an archival node that never deletes has nowhere to put a reclaim. The index journal
//! discards a torn tail record and the blocks it named are downloaded again.
//!
//! # The bytes are ours, and are read as if they were not
//!
//! The denials below are [`crate::peer`]'s, for a different reason: nothing here is written
//! by a stranger, but a file that a crash cut in half, or a disk that returned a different
//! byte than it took, must produce a `Result` rather than an index out of range. Assertions
//! stay for this node's own invariants — an offset past the file bound, a record longer than
//! consensus allows — because those are claims about code, not about bytes.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod coin;
mod datadir;
#[cfg(test)]
pub mod fixture;
mod handles;
mod index;
mod reader;
mod series;
mod undo;

use std::io;

use bitcoin::BlockHash;
use bitmigo_consensus::params::ChainParams;

use crate::chain::UndoLocation;
use crate::runtime::queue::BlockLocation;

pub use datadir::DataDir;
#[cfg(test)]
pub use datadir::Scratch;
#[allow(
    unused_imports,
    reason = "`Loaded` is what a load hands the startup thread, and `MAX_FILE_BYTES` is \
              the bound the series' own tests roll against"
)]
pub use index::{Journal, Loaded};
#[allow(
    unused_imports,
    reason = "named here so the series' bound has one home"
)]
pub use series::{MAX_FILE_BYTES, SeriesReader, SeriesWriter};
#[allow(
    unused_imports,
    reason = "the undo record is written by the chainstate (BM-10) and read by its \
              disconnect; the encoding and its bounds are complete and tested here"
)]
pub use undo::{MAX_UNDO_RECORD_BYTES, UndoCoin, UndoRecord};

/// The `blkNNNNN.dat` series: raw blocks, exactly as they arrived.
const BLOCK_PREFIX: &str = "blk";

/// The `undoNNNNN.dat` series: one record per connected block.
const UNDO_PREFIX: &str = "undo";

/// Four bytes at the head of every record, so that a location that names the wrong place is
/// caught rather than deserialised. Core spells this the network's message start; the store
/// is not the network, and a store carried between chains is a mistake worth naming here as
/// well as in the directory it sits in.
const BLOCK_RECORD_MAGIC: [u8; 4] = *b"BMGB";

/// The same, for an undo record.
const UNDO_RECORD_MAGIC: [u8; 4] = *b"BMGU";

/// `magic(4) ‖ len(u32 LE)`, and then the body. Core's `STORAGE_HEADER_BYTES`.
const FRAME_BYTES: u32 = 8;

/// The largest block record: a block's serialized size never exceeds its weight, and
/// consensus caps that at four million.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "four million, in a constant expression"
)]
const MAX_BLOCK_RECORD_BYTES: u32 = bitmigo_consensus::tx::MAX_BLOCK_WEIGHT as u32;

/// What the whole node shares: the directory it is locked into, and read access to both
/// series. Every writer is somewhere else, owned by one thread.
pub struct Store {
    directory: DataDir,
    blocks: SeriesReader,
    undo: SeriesReader,
}

/// The chain thread's half: the block series' single writer, and the index.
///
/// Not `Clone` and not `Sync`-shared: it is moved into the chain thread at startup and
/// there is no second handle anywhere in the process.
pub struct ChainStore {
    /// The block series' one cursor.
    pub blocks: SeriesWriter,
    /// The index that names what the cursor has written.
    pub index: Journal,
}

/// The validation thread's half: the undo series' single writer.
pub struct UndoStore {
    /// The undo series' one cursor.
    pub undo: SeriesWriter,
}

impl Store {
    /// Open, or create, everything under a locked data directory.
    ///
    /// One call, on one thread, before any other thread exists: the lock must be refused
    /// while the node is still a single thread that can say why, and the two write cursors
    /// must be found before anything can append to them.
    pub fn open(
        directory: DataDir,
        params: &ChainParams,
    ) -> io::Result<(Store, ChainStore, UndoStore)> {
        let blocks = directory.blocks();
        let index = directory.index();
        let (block_writer, block_reader) = series::open(
            &blocks,
            BLOCK_PREFIX,
            BLOCK_RECORD_MAGIC,
            0,
            MAX_BLOCK_RECORD_BYTES,
        )?;
        let (undo_writer, undo_reader) = series::open(
            &blocks,
            UNDO_PREFIX,
            UNDO_RECORD_MAGIC,
            undo::TRAILER_BYTES,
            MAX_UNDO_RECORD_BYTES,
        )?;
        let journal = Journal::open(&index, params)?;
        Ok((
            Store {
                directory,
                blocks: block_reader,
                undo: undo_reader,
            },
            ChainStore {
                blocks: block_writer,
                index: journal,
            },
            UndoStore { undo: undo_writer },
        ))
    }

    /// One block's raw bytes, exactly as they arrived.
    ///
    /// The block server (BM-24) and the connect path (BM-10) both come here, and neither
    /// is on the thread that writes. Takes a [`BlockLocation`] and nothing else, so the
    /// bytes that make a block and the bytes that take it back off cannot be handed to
    /// each other's reader.
    #[allow(
        dead_code,
        reason = "the peer writers serve blocks from here (BM-24) and validation reads \
                  the block it is connecting (BM-10); the read and its bounds are tested"
    )]
    pub fn read_block(&self, at: BlockLocation) -> io::Result<Vec<u8>> {
        let (bytes, _) = self.blocks.read(at.file, at.offset, at.len)?;
        Ok(bytes)
    }

    /// One undo record, with its checksum checked against the block before it.
    ///
    /// Core folds the previous block's hash into the trailer so that a record cannot be
    /// read as another block's; the same hash is what the disconnect path already has in
    /// its hand, so checking costs it nothing.
    #[allow(dead_code, reason = "read by the disconnect path, BM-10")]
    pub fn read_undo(&self, at: UndoLocation, previous: BlockHash) -> io::Result<Vec<u8>> {
        let (bytes, trailer) = self.undo.read(at.file, at.offset, at.len)?;
        if trailer != undo::trailer(&bytes, previous) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the undo record after {previous} does not match its checksum"),
            ));
        }
        Ok(bytes)
    }

    /// The directory everything above sits in, and the lock that keeps it this node's.
    pub fn directory(&self) -> &DataDir {
        &self.directory
    }
}

impl UndoStore {
    /// Write one block's undo record, under the checksum Core puts on one.
    ///
    /// `previous` is the hash of the block before it, folded into the trailer so that a
    /// record cannot be read back as another block's. Durable only after the next
    /// [`SeriesWriter::sync`], which the validation thread does as it flushes.
    #[allow(dead_code, reason = "the chainstate writes undo records: BM-10")]
    pub fn write_undo(&mut self, bytes: &[u8], previous: BlockHash) -> io::Result<UndoLocation> {
        let placed = self
            .undo
            .append(bytes, Some(undo::trailer(bytes, previous)))?;
        Ok(UndoLocation {
            file: placed.file,
            offset: placed.offset,
            len: placed.len,
        })
    }
}

impl ChainStore {
    /// Write one block's raw bytes, exactly as they arrived (BM-D1 decision 9).
    ///
    /// Durable only after the next [`ChainStore::commit`], which is what makes the index
    /// record naming them safe to write.
    #[allow(dead_code, reason = "the receipt path writes blocks: BM-9")]
    pub fn write_block(&mut self, bytes: &[u8]) -> io::Result<BlockLocation> {
        let placed = self.blocks.append(bytes, None)?;
        Ok(BlockLocation {
            file: placed.file,
            offset: placed.offset,
            len: placed.len,
        })
    }

    /// Make the block bytes the index will name durable, then name them.
    ///
    /// The only place the index reaches the disk. The block file is `fsync`ed first, so no
    /// index record can point past the end of what survived; then the batch of changed
    /// entries is appended and `fsync`ed itself. The caller decides when — a batch, an
    /// interval, a shutdown, and before any block is handed to validation — never once per
    /// block.
    ///
    /// This covers the **block** series only. The undo series' writer is the validation
    /// thread's, so an entry that reached [`HeaderStatus::Connected`] here names an undo
    /// record whose bytes are durable only if the thread that wrote it `fsync`ed before it
    /// reported the connect. That rule is BM-10's to keep; see this module's header.
    ///
    /// [`HeaderStatus::Connected`]: crate::chain::HeaderStatus::Connected
    pub fn commit(&mut self, tree: &mut crate::chain::HeaderTree) -> io::Result<usize> {
        if tree.dirty().is_empty() {
            return Ok(0);
        }
        self.blocks.sync()?;
        let written = self.index.append(tree.dirty(), tree)?;
        tree.clear_dirty();
        Ok(written)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
