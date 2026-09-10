// SPDX-License-Identifier: MIT OR Apache-2.0

//! The block index: an append-only journal, rewritten whole.
//!
//! Its *content* was fixed by BM-8 and its *form* by BM-D4 decision 5. Per entry: the
//! 80-byte header and what is known about the block behind it. Nothing else — height,
//! chain work, the parent link and the skip pointer are all recomputed at load from
//! `prev_blockhash`, exactly as Core recomputes `nChainWork`, `nTimeMax` and `pskip` in
//! `LoadBlockIndex`.
//!
//! ```text
//!   file    magic(8) ‖ version(u32 LE) ‖ genesis hash(32)
//!   record  len(u32 LE) ‖ header(80) ‖ tag(1) ‖ tag's fields ‖ checksum(4)
//! ```
//!
//! One file, not a snapshot and a log: a rewrite *is* a snapshot, so there is one file kind
//! and one recovery path. Changed entries are appended in a batch at each commit — under a
//! megabyte per commit during a sync — and the whole thing is rewritten to a temporary file
//! and renamed once it passes twice the live entry count, which is about once per initial
//! block download.
//!
//! # The journal records what the node *has*, not what it concluded
//!
//! Everything that can be recomputed is recomputed, and that turns out to include most
//! verdicts. A header refused by `accept_header` is refused again by the replay, with the
//! same error, because the rule is a pure function of ancestors that cannot change; a
//! descendant of a refused block inherits the verdict the same way it did the first time.
//! So neither is written down at all.
//!
//! What replay cannot re-derive is a refusal by one of the four stages that need the block:
//! `check_block`, `accept_block`, `confirm`, `connect`. For those the journal keeps the
//! **stage and not the reason** — one byte, restored as
//! [`crate::chain::Invalidity::Reloaded`]. The evidence went into the
//! log when the block was refused; what has to survive a restart is that the block is never
//! built on again, and a stage says that in a byte rather than in a codec for four
//! error enums that exist to produce a line of text.
//!
//! # Load
//!
//! **Persisted status is a hint; the coin store's marker is the truth** (BM-D4 decision 6).
//! The loader replays the headers, gives back the block locations, and then connects the
//! chain from genesis *only as far as the marker*, leaving everything above it
//! `BlockChecked`. Demoting is always safe — the bytes are still there and still checked,
//! and the blocks are simply connected again. Believing the index is not.
//!
//! A torn tail record — the last commit caught by a `kill -9` — is discarded, and the
//! blocks it named are downloaded again. That is the only shape a partial write can take
//! here, because a record is never named by anything until the batch it is in has been
//! `fsync`ed.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{Hash, sha256d};
use bitmigo_consensus::params::{BlockTime, ChainParams};

use crate::chain::{
    AcceptError, HeaderStatus, HeaderTree, Invalidity, NodeId, Stage, UndoLocation,
};
use crate::runtime::queue::BlockLocation;

use super::reader::{DecodeError, Reader};

/// The journal's name, below `index/`.
const JOURNAL_FILE: &str = "journal.dat";

/// Where a rewrite is built before it is renamed over the journal.
const JOURNAL_TEMP: &str = "journal.tmp";

/// Eight bytes that say what this file is.
const JOURNAL_MAGIC: [u8; 8] = *b"bmgoIDX\x01";

/// The format version. A future change is refused rather than misread (BM-D4 decision 9).
const JOURNAL_VERSION: u32 = 1;

/// `magic ‖ version ‖ genesis hash`.
const FILE_HEADER_BYTES: usize = 8 + 4 + 32;

/// A block header on the wire, which is what a record carries.
const BLOCK_HEADER_BYTES: usize = 80;

/// Four bytes of `SHA256d` over the payload — the same shape Core's message checksum takes,
/// and enough to find the one place a torn tail can be. These bytes are this node's own;
/// nothing here is defending against somebody choosing them.
const CHECKSUM_BYTES: usize = 4;

/// The largest a record can be: the header, the tag, two locations, and the checksum.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "a hundred and nine, in a constant expression"
)]
const MAX_RECORD_BYTES: u32 = (BLOCK_HEADER_BYTES + 1 + 24 + CHECKSUM_BYTES) as u32;

/// Below this many live entries a rewrite is not worth doing, whatever the ratio says: a
/// tree with four headers in it would otherwise rewrite on almost every commit.
const MIN_LIVE_RECORDS: u64 = 1024;

/// What one record says about the block behind its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Persisted {
    /// The header, and no block.
    Accepted,
    /// The block's bytes are on the disk.
    Checked(BlockLocation),
    /// They are, and its coins were in the chainstate when this was written.
    Connected(BlockLocation, UndoLocation),
    /// A stage that needs the block refused it.
    Refused(Stage),
}

impl Persisted {
    /// What the tree is holding, or nothing when the tree's state is one replay re-derives
    /// by itself.
    fn of(status: HeaderStatus) -> Option<Persisted> {
        match status {
            // Genesis comes from the chain parameters, never from a peer or a file.
            HeaderStatus::Genesis => None,
            // A header-stage refusal and an invalid ancestor are both re-derived exactly by
            // the replay, so both are written as what they were before the verdict.
            HeaderStatus::HeaderAccepted
            | HeaderStatus::InvalidAncestor { .. }
            | HeaderStatus::Invalid {
                invalidity: Invalidity::AcceptHeader(_),
            } => Some(Persisted::Accepted),
            HeaderStatus::BlockChecked { location } => Some(Persisted::Checked(location)),
            HeaderStatus::Connected { location, undo } => {
                Some(Persisted::Connected(location, undo))
            }
            HeaderStatus::Invalid { invalidity } => Some(Persisted::Refused(invalidity.stage())),
        }
    }

    /// The tag byte and the fields behind it.
    fn encode(self, bytes: &mut Vec<u8>) {
        match self {
            Persisted::Accepted => bytes.push(0),
            Persisted::Checked(location) => {
                bytes.push(1);
                put_location(bytes, location.file, location.offset, location.len);
            }
            Persisted::Connected(location, undo) => {
                bytes.push(2);
                put_location(bytes, location.file, location.offset, location.len);
                put_location(bytes, undo.file, undo.offset, undo.len);
            }
            Persisted::Refused(stage) => {
                bytes.push(3);
                bytes.push(stage.tag());
            }
        }
    }

    /// Read one back.
    fn decode(reader: &mut Reader<'_>) -> Result<Persisted, DecodeError> {
        match reader.u8()? {
            0 => Ok(Persisted::Accepted),
            1 => Ok(Persisted::Checked(block_location(reader)?)),
            2 => {
                let location = block_location(reader)?;
                let (file, offset, len) = triple(reader)?;
                Ok(Persisted::Connected(
                    location,
                    UndoLocation { file, offset, len },
                ))
            }
            3 => {
                let tag = reader.u8()?;
                Ok(Persisted::Refused(
                    Stage::of_tag(tag).ok_or(DecodeError::BadTag { tag })?,
                ))
            }
            tag => Err(DecodeError::BadTag { tag }),
        }
    }
}

fn put_location(bytes: &mut Vec<u8>, file: u32, offset: u32, len: u32) {
    bytes.extend_from_slice(&file.to_le_bytes());
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
}

fn triple(reader: &mut Reader<'_>) -> Result<(u32, u32, u32), DecodeError> {
    Ok((reader.u32_le()?, reader.u32_le()?, reader.u32_le()?))
}

fn block_location(reader: &mut Reader<'_>) -> Result<BlockLocation, DecodeError> {
    let (file, offset, len) = triple(reader)?;
    Ok(BlockLocation { file, offset, len })
}

/// What a load found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Loaded {
    /// Records read, the ones a later record superseded included.
    pub records: usize,
    /// Headers now in the tree.
    pub headers: usize,
    /// Blocks connected, which is the tip's height.
    pub connected: usize,
    /// Bytes of a final record a crash cut in half, discarded.
    pub torn: usize,
    /// Headers the tree would not take back. Nonzero means the journal and the rules
    /// disagree, and everything after the first one was left unread.
    pub rejected: usize,
}

impl std::fmt::Display for Loaded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} records, {} headers, {} connected",
            self.records, self.headers, self.connected,
        )?;
        if self.torn > 0 {
            write!(formatter, ", {} bytes of a torn tail discarded", self.torn)?;
        }
        if self.rejected > 0 {
            write!(formatter, ", {} refused and the rest unread", self.rejected)?;
        }
        Ok(())
    }
}

/// The journal.
pub struct Journal {
    path: PathBuf,
    temp: PathBuf,
    directory: PathBuf,
    handle: File,
    records: u64,
}

impl Journal {
    /// Open the journal, creating it with its file header when there is none.
    ///
    /// The genesis hash goes in the header as well as the version: the data directory is
    /// keyed by chain, but a directory that was moved or a symlink that was pointed
    /// somewhere else is a mistake worth catching before a single header is replayed.
    pub fn open(directory: &Path, params: &ChainParams) -> io::Result<Journal> {
        let path = directory.join(JOURNAL_FILE);
        let genesis = params.genesis_hash();
        if path.exists() {
            verify_file_header(&path, genesis)?;
        } else {
            let mut file = File::create(&path)?;
            file.write_all(&file_header(genesis))?;
            file.sync_all()?;
            File::open(directory)?.sync_all()?;
        }
        let handle = OpenOptions::new().append(true).open(&path)?;
        Ok(Journal {
            path,
            temp: directory.join(JOURNAL_TEMP),
            directory: directory.to_path_buf(),
            handle,
            records: 0,
        })
    }

    /// Append the entries that have changed, and make them durable.
    ///
    /// One `write_all` and one `fsync` for the whole batch, which is what keeps the
    /// ordering rule affordable: the caller has already `fsync`ed the block file, and past
    /// this point every location in the batch names bytes that survived.
    pub fn append(&mut self, dirty: &[NodeId], tree: &HeaderTree) -> io::Result<usize> {
        let mut bytes = Vec::with_capacity(dirty.len().saturating_mul(96));
        let mut written = 0usize;
        for node in dirty {
            let entry = tree.entry(*node);
            let Some(status) = Persisted::of(entry.status()) else {
                continue;
            };
            put_record(&mut bytes, entry.header(), status);
            written = written.saturating_add(1);
        }
        if written == 0 {
            return Ok(0);
        }
        self.handle.write_all(&bytes)?;
        self.handle.sync_all()?;
        self.records = self
            .records
            .saturating_add(u64::try_from(written).unwrap_or(0));
        self.rewrite_if_stale(tree)?;
        Ok(written)
    }

    /// Rewrite the whole journal once it has grown past twice what is live in it.
    ///
    /// A rewrite is a snapshot: the temporary file is written and `fsync`ed, renamed over
    /// the journal, and the directory `fsync`ed so the rename itself survives. The old
    /// journal is never edited, so a crash at any point in here leaves one of the two
    /// whole files in place and nothing in between.
    fn rewrite_if_stale(&mut self, tree: &HeaderTree) -> io::Result<()> {
        let live = u64::try_from(tree.len()).unwrap_or(u64::MAX);
        if self.records <= live.max(MIN_LIVE_RECORDS).saturating_mul(2) {
            return Ok(());
        }
        self.rewrite(tree)
    }

    /// The rewrite itself, which a test can also ask for.
    pub fn rewrite(&mut self, tree: &HeaderTree) -> io::Result<()> {
        let genesis = tree.entry(NodeId::GENESIS).hash();
        let mut file = File::create(&self.temp)?;
        let mut bytes = file_header(genesis);
        let mut written = 0u64;
        for node in tree.nodes() {
            let entry = tree.entry(node);
            let Some(status) = Persisted::of(entry.status()) else {
                continue;
            };
            put_record(&mut bytes, entry.header(), status);
            written = written.saturating_add(1);
            // Bounded: the buffer never holds more than this before it reaches the file,
            // however many entries the tree has.
            if bytes.len() >= 1024 * 1024 {
                file.write_all(&bytes)?;
                bytes.clear();
            }
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&self.temp, &self.path)?;
        File::open(&self.directory)?.sync_all()?;
        self.handle = OpenOptions::new().append(true).open(&self.path)?;
        self.records = written;
        Ok(())
    }

    /// Replay the journal into the tree, and connect the chain as far as the marker.
    ///
    /// `marker` is the coin store's `H` — the block the on-disk UTXO set corresponds to.
    /// Until there is a coin store (BM-27) the caller passes genesis, which is exactly
    /// right: an empty set corresponds to the block before any coins existed, so every
    /// `Connected` entry is demoted and every block is connected again.
    pub fn load(
        &mut self,
        tree: &mut HeaderTree,
        params: &ChainParams,
        now: BlockTime,
        marker: BlockHash,
    ) -> io::Result<Loaded> {
        let (statuses, mut report) = self.replay(tree, params, now)?;
        apply(tree, &statuses);
        report.connected = connect_to_marker(tree, &statuses, marker)?;
        report.headers = tree.len();
        // Nothing above is a change the journal has not already got: replaying its own
        // contents must not make the next commit write them all back.
        tree.clear_dirty();
        Ok(report)
    }

    /// Read every record, putting the headers into the tree and keeping the last status
    /// each one was given.
    ///
    /// The statuses sit in a `Vec` beside the arena, indexed by [`NodeId::position`], and
    /// not in a map keyed by hash: at mainnet that is two million entries, and a map keyed
    /// by thirty-two bytes would be some hundred and seventy megabytes at startup where the
    /// `Vec` is a third of that. Bounded by the tree either way, and gone once the load is.
    fn replay(
        &mut self,
        tree: &mut HeaderTree,
        params: &ChainParams,
        now: BlockTime,
    ) -> io::Result<(Statuses, Loaded)> {
        let mut file = BufReader::new(File::open(&self.path)?);
        let mut header = [0u8; FILE_HEADER_BYTES];
        file.read_exact(&mut header)?;
        let mut statuses: Statuses = Vec::new();
        let mut report = Loaded::default();
        loop {
            match read_record(&mut file)? {
                Read1::End => break,
                Read1::Torn { bytes } => {
                    report.torn = bytes;
                    break;
                }
                Read1::Record { header, status } => {
                    report.records = report.records.saturating_add(1);
                    let Some(node) = accepted(tree, params, now, &header) else {
                        report.rejected = report.rejected.saturating_add(1);
                        break;
                    };
                    // The arena is dense and a child follows its parent, so this grows by
                    // one on a new header and not at all on a re-appended one.
                    if statuses.len() <= node.position() {
                        statuses.resize(node.position().saturating_add(1), None);
                    }
                    if let Some(slot) = statuses.get_mut(node.position()) {
                        *slot = Some(status);
                    }
                }
            }
        }
        assert!(statuses.len() <= tree.len(), "one slot per entry at most");
        self.records = u64::try_from(report.records).unwrap_or(u64::MAX);
        Ok((statuses, report))
    }
}

/// The last status the journal gave each entry, by arena position. `None` for genesis and
/// for anything a rejected record left unread.
type Statuses = Vec<Option<Persisted>>;

/// What the journal last said about one entry.
fn status_of(statuses: &Statuses, node: NodeId) -> Option<Persisted> {
    statuses.get(node.position()).copied().flatten()
}

/// Put a header back into the tree, and say where the tree kept it.
///
/// A header the tree refuses *and stores* — one `accept_header` turns down, or one whose
/// ancestor it turned down — is kept, because the tree has recorded the same verdict it
/// recorded the first time. A header it refuses and does *not* store leaves a hole, and
/// every record after it hangs off that hole, so the replay stops there.
fn accepted(
    tree: &mut HeaderTree,
    params: &ChainParams,
    now: BlockTime,
    header: &Header,
) -> Option<NodeId> {
    match tree.accept(header, params, now) {
        Ok(accepted) => Some(accepted.node()),
        Err(AcceptError::Invalid { node, .. } | AcceptError::InvalidAncestor { node, .. }) => {
            Some(node)
        }
        Err(
            AcceptError::CheckHeader(_)
            | AcceptError::UnknownParent { .. }
            | AcceptError::TooFarInFuture { .. }
            | AcceptError::TreeFull,
        ) => None,
    }
}

/// Give every entry the block data and the verdict the journal recorded for it.
///
/// Connecting is deliberately not done here: what is connected is the marker's business,
/// and a status that says `Connected` is only ever a hint about where the bytes are.
fn apply(tree: &mut HeaderTree, statuses: &Statuses) {
    // Collected first: the walk mutates what it walks over, and the arena's order —
    // parents before children — is what makes a verdict reach its descendants.
    let nodes: Vec<NodeId> = tree.nodes().collect();
    for node in nodes {
        let Some(status) = status_of(statuses, node) else {
            continue;
        };
        let entry = tree.entry(node);
        // A block whose ancestor was refused is terminal, whatever the journal says about
        // its bytes: the verdict the replay re-derived wins, and it is the stronger one.
        if entry.status().is_terminal() || matches!(entry.status(), HeaderStatus::Genesis) {
            continue;
        }
        match status {
            Persisted::Accepted => {}
            Persisted::Checked(location) | Persisted::Connected(location, _) => {
                tree.block_checked(node, location);
            }
            Persisted::Refused(stage) => {
                tree.invalidate(node, Invalidity::Reloaded { stage });
            }
        }
    }
}

/// Connect the active chain from genesis up to the marker, and no further.
///
/// Every block on the way needs the undo record that takes it back off again, because
/// [`HeaderStatus::Connected`] is the state that carries one and a reorg past this block
/// would otherwise have nothing to work from. A marker the journal cannot reach is a store
/// whose coins belong to a block this index does not have, and the only safe answer to
/// that is to refuse to start.
fn connect_to_marker(
    tree: &mut HeaderTree,
    statuses: &Statuses,
    marker: BlockHash,
) -> io::Result<usize> {
    let target = tree.node_of(marker).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the coin store is at {marker}, which the block index does not have"),
        )
    })?;
    let mut path = Vec::new();
    let mut walk = target;
    while walk != NodeId::GENESIS {
        path.push(walk);
        walk = match tree.entry(walk).parent() {
            Some(parent) => parent,
            None => break,
        };
    }
    path.reverse();
    let connected = path.len();
    for node in path {
        let hash = tree.entry(node).hash();
        let Some(Persisted::Connected(_, undo)) = status_of(statuses, node) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{hash} is below the coin store's marker with no undo record"),
            ));
        };
        tree.connected(node, undo);
    }
    Ok(connected)
}

/// The bytes at the head of the file.
fn file_header(genesis: BlockHash) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FILE_HEADER_BYTES);
    bytes.extend_from_slice(&JOURNAL_MAGIC);
    bytes.extend_from_slice(&JOURNAL_VERSION.to_le_bytes());
    bytes.extend_from_slice(&genesis.to_byte_array());
    bytes
}

/// Refuse a journal that is not this format, this version, or this chain's.
fn verify_file_header(path: &Path, genesis: BlockHash) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; FILE_HEADER_BYTES];
    file.read_exact(&mut bytes).map_err(|error| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("{} has no index header: {error}", path.display()),
        )
    })?;
    let mut reader = Reader::new(&bytes);
    let magic = reader.take(JOURNAL_MAGIC.len())?;
    if magic != JOURNAL_MAGIC {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("{} is not a bitmigo block index", path.display()),
        ));
    }
    let version = reader.u32_le()?;
    if version != JOURNAL_VERSION {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("block index version {version}, and this bitmigo writes {JOURNAL_VERSION}"),
        ));
    }
    let seen = BlockHash::from_byte_array(reader.hash()?);
    if seen != genesis {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("this block index is {seen}'s chain, not {genesis}'s"),
        ));
    }
    Ok(())
}

/// Append one record: the length, the payload, and four bytes of `SHA256d` over it.
fn put_record(bytes: &mut Vec<u8>, header: &Header, status: Persisted) {
    let mut payload = Vec::with_capacity(BLOCK_HEADER_BYTES + 25);
    payload.extend_from_slice(&serialize(header));
    assert_eq!(
        payload.len(),
        BLOCK_HEADER_BYTES,
        "a header is eighty bytes"
    );
    status.encode(&mut payload);
    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    assert!(
        length < MAX_RECORD_BYTES,
        "a record is bounded by its states"
    );
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&checksum(&payload));
}

/// The four bytes that say a record reached the disk whole.
fn checksum(payload: &[u8]) -> [u8; 4] {
    let digest = sha256d::Hash::hash(payload).to_byte_array();
    let mut four = [0u8; 4];
    four.copy_from_slice(digest.get(..4).unwrap_or(&[0, 0, 0, 0]));
    four
}

/// What came of trying to read one more record.
enum Read1 {
    /// A whole record.
    Record {
        /// Its header.
        header: Header,
        /// What it said about the block.
        status: Persisted,
    },
    /// The file ended exactly where a record would have started.
    End,
    /// The file ended inside one, or the last one does not match its checksum. Both are
    /// the same event — a commit a crash caught in the middle — and both are discarded.
    Torn {
        /// How many bytes were left over.
        bytes: usize,
    },
}

/// Read one record, or say why there was not one.
fn read_record(file: &mut BufReader<File>) -> io::Result<Read1> {
    let mut length = [0u8; 4];
    match file.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(Read1::End),
        Err(error) => return Err(error),
    }
    let declared = u32::from_le_bytes(length);
    if declared >= MAX_RECORD_BYTES {
        // Not a length this encoder ever wrote, so the tail from here is not a record.
        return Ok(Read1::Torn {
            bytes: usize::try_from(declared).unwrap_or(usize::MAX),
        });
    }
    let mut payload = vec![0u8; usize::try_from(declared).unwrap_or(0)];
    let mut four = [0u8; CHECKSUM_BYTES];
    if file.read_exact(&mut payload).is_err() || file.read_exact(&mut four).is_err() {
        return Ok(Read1::Torn {
            bytes: payload.len(),
        });
    }
    if four != checksum(&payload) {
        return Ok(Read1::Torn {
            bytes: payload.len(),
        });
    }
    parse_record(&payload).map_err(Into::into)
}

/// The header and the status inside one record's payload.
fn parse_record(payload: &[u8]) -> Result<Read1, DecodeError> {
    let mut reader = Reader::new(payload);
    let bytes = reader.take(BLOCK_HEADER_BYTES)?;
    let header: Header = deserialize(bytes).map_err(|_| DecodeError::Truncated {
        wanted: BLOCK_HEADER_BYTES,
        left: bytes.len(),
    })?;
    let status = Persisted::decode(&mut reader)?;
    reader.finish()?;
    Ok(Read1::Record { header, status })
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;
