// SPDX-License-Identifier: MIT OR Apache-2.0

//! The header tree: every header this node has ever accepted, what is known about the block
//! behind it, and the two chains that fall out of that.
//!
//! One thread owns this — the chain thread — so nothing here is locked and nothing is
//! copied for a reader. What an operator sees is the published snapshot the owner writes
//! once per tick.
//!
//! # Shape
//!
//! An append-only arena of [`HeaderEntry`], addressed by [`NodeId`], with a hash index
//! beside it. A child is always appended after its parent, which is the property two
//! operations lean on: invalidity propagates to every descendant in one ascending pass, and
//! the arena needs no child pointers to do it. Ancestors are reached through Core's skip
//! list (`chain.cpp: GetSkipHeight`, `CBlockIndex::GetAncestor`), so every walk backwards is
//! logarithmic and, more to the point, *bounded*.
//!
//! Two nodes are named at all times:
//!
//! - [`HeaderTree::best_header`] — the most-work header that is not invalid. It runs far
//!   ahead of the tip during a sync, and it is what the download scheduler aims at.
//! - [`HeaderTree::tip`] — the most-work block whose coins are in the chainstate. It moves
//!   only through [`HeaderTree::connected`] and [`HeaderTree::disconnected`], each of which
//!   asserts it is moving one step from the tip, so `Connected` and "on the active chain"
//!   are the same statement and neither can drift from the other.
//!
//! # Status is a state, not a set of flags
//!
//! BM-D1 decision 5. [`HeaderStatus`] carries its own evidence, so the states Core spells
//! with `nStatus` bits plus side tables cannot come apart here:
//!
//! - "have data" is [`HeaderStatus::BlockChecked`], which *is* the block's location. There
//!   is no `HAVE_DATA` bit that can be set without a position, and no position that can be
//!   read while the bit is clear.
//! - "connected" is [`HeaderStatus::Connected`], which carries the block's location *and*
//!   its undo record. BM-D1 decision 4 asks the reorg driver to assert undo exists for
//!   every step before it starts; here a step that lacks undo cannot be built.
//! - a failure is [`HeaderStatus::Invalid`], which carries an [`Invalidity`] — the stage
//!   that refused the block *and* that stage's own error, in one value. BM-D1 sketched
//!   this as `Invalid { stage, verdict }`; a pair can disagree with itself, so the two are
//!   folded into one enum whose variants each name their own error type.
//! - a descendant of a failure is [`HeaderStatus::InvalidAncestor`], pointing at the
//!   culprit. The reason is stored once, on the block that earned it.
//! - genesis is [`HeaderStatus::Genesis`]. It is the one block with no context, no parent
//!   and no undo, its bytes come from [`ChainParams`] rather than from a peer's word, and
//!   it can never be disconnected. Giving it its own state is what lets `Connected` demand
//!   an undo record unconditionally.
//!
//! # What must be persisted
//!
//! BM-D4 owns the encoding; this is the content, and it is small. Per node: the 80-byte
//! header and its [`HeaderStatus`] (which is what carries the block and undo positions).
//! Nothing else — height, chain work, the parent link and the skip pointer are all
//! recomputed at load from `prev_blockhash`, exactly as Core recomputes `nChainWork`,
//! `nTimeMax` and `pskip` in `LoadBlockIndex` (storage doc §3.2).
//!
//! **The load rule: persisted status is a hint, the chainstate tip is the truth.** A crash
//! between the index write and the coins write leaves headers claiming `Connected` for
//! blocks the on-disk UTXO set does not include (storage doc §3.5). So the loader takes the
//! chainstate's own best block as the tip and demotes every `Connected` entry above it to
//! `BlockChecked` — the bytes are still there and still checked, and the blocks are simply
//! connected again. Demoting is always safe; believing the index is not.
//!
//! # Against a hostile peer
//!
//! A header costs an attacker the proof of work in it, which is the whole defence on
//! mainnet and none of it on signet, where the header target sits at the pow limit and only
//! the *block* carries the challenge signature. So the tree is bounded outright by
//! [`MAX_TREE_HEADERS`] and refuses headers past it. Core's defence at this point is the
//! anti-DoS work threshold and the presync in `headerssync.cpp` (R4 §2.3, §2.4), which this
//! node does not have: a cap that stalls with an operator-visible line is a worse answer
//! than presync and a much better one than an unbounded map.
//!
//! The wire denials live in [`crate::peer`], where the bytes are parsed. What arrives here
//! is a decoded [`Header`] that has already passed [`check_header`] on the sending peer's
//! own thread, and every index in this module is one the tree itself minted — so the
//! assertions here are claims about this node's invariants, which is what an assertion is
//! for. The arithmetic is still explicit: heights go through [`Height::next`], which
//! asserts, and chain work is summed by [`add_work`], which asserts it never carries out.

use std::collections::HashMap;
use std::fmt;

use bitcoin::block::Header;
use bitcoin::pow::Work;
use bitcoin::{BlockHash, CompactTarget};
use bitmigo_consensus::block::{BlockError, ConfirmError, ConnectError};
use bitmigo_consensus::header::{
    Context, HeaderError, HeaderFacts, MAX_FUTURE_BLOCK_TIME, MEDIAN_TIME_SPAN, accept_header,
    block_work, check_header, median_time_past, next_required_bits,
};
use bitmigo_consensus::params::{BlockTime, ChainParams, Height};

use crate::runtime::queue::BlockLocation;

/// The most headers the tree will hold.
///
/// Mainnet stood at height 966,055 on 2026-09-08 (storage doc §4) and gains about 52,560
/// blocks a year, so this is the honest chain plus its forks until roughly the year 2210 —
/// the cap is never the thing that stops a mainnet node. It binds where headers are cheap:
/// on signet the header target is the pow limit, so a peer can mine forks by the million,
/// and this is the number that turns that from an out-of-memory into a stall the operator
/// can see. At roughly 260 bytes an entry — an 80-byte header, its hash, 32 bytes of chain
/// work, three indices, a status, and the hash map's own row — two million headers is about
/// half a gigabyte, beside a mainnet chainstate of thirteen.
pub const MAX_TREE_HEADERS: usize = 2 * 1024 * 1024;

/// The most steps [`HeaderTree::ancestor`] may take.
///
/// A tripwire, not a tuning knob. Core's own comment measures its skip list at "max 110
/// steps to go back up to 2**18 blocks"; the cap here is three more doublings than that, so
/// a walk that exceeds this bound has met a skip pointer that is wrong, and the right
/// answer is to stop loudly rather than to walk two million parents.
const MAX_ANCESTOR_STEPS: usize = 512;

const _: () = assert!(
    MAX_ANCESTOR_STEPS >= 110,
    "Core measures 110 steps over 2^18"
);

/// A node's position in the arena. Genesis is always zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// The root of every tree.
    pub const GENESIS: NodeId = NodeId(0);

    /// The node at an arena position.
    fn at(position: usize) -> NodeId {
        let index = u32::try_from(position).expect("the arena is capped well below u32::MAX");
        NodeId(index)
    }

    /// Its arena position: dense from zero, in the order the headers entered the tree.
    ///
    /// Public so that a pass over the whole tree can keep a table beside it as a `Vec`
    /// rather than a map keyed by hash — the block index's load is one (BM-26).
    #[must_use]
    pub fn position(self) -> usize {
        usize::try_from(self.0).expect("a u32 index fits a usize")
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "node {}", self.0)
    }
}

/// Where a block's undo record is on disk.
///
/// Its own type rather than a second [`BlockLocation`], so that the bytes that make a block
/// and the bytes that take it back off can never be handed to each other's reader. BM-D4
/// fixes the encoding; BM-10 is what fills these in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UndoLocation {
    /// Which undo file.
    pub file: u32,
    /// Where the record starts in it.
    pub offset: u32,
    /// How many bytes it is.
    pub len: u32,
}

/// Which of the pipeline's stages refused a block, with the evidence left behind.
///
/// The block index keeps one of these and not the error itself (BM-26): a header-stage
/// refusal is re-derived exactly by a replay, and for the four that need the block, what
/// has to survive a restart is that the block is never built on again. That is a byte,
/// against a codec for four error enums whose whole job is to produce a line of text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// `accept_header`.
    AcceptHeader,
    /// `check_block`.
    CheckBlock,
    /// `accept_block`.
    AcceptBlock,
    /// `confirm`.
    Confirm,
    /// `connect`.
    Connect,
}

impl Stage {
    /// The byte the index writes. Stated rather than derived from the variant order, so
    /// that adding a stage cannot silently renumber a file already on somebody's disk.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Stage::AcceptHeader => 1,
            Stage::CheckBlock => 2,
            Stage::AcceptBlock => 3,
            Stage::Confirm => 4,
            Stage::Connect => 5,
        }
    }

    /// The stage a byte names, or nothing.
    #[must_use]
    pub fn of_tag(tag: u8) -> Option<Stage> {
        match tag {
            1 => Some(Stage::AcceptHeader),
            2 => Some(Stage::CheckBlock),
            3 => Some(Stage::AcceptBlock),
            4 => Some(Stage::Confirm),
            5 => Some(Stage::Connect),
            _ => None,
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Stage::AcceptHeader => "accept_header",
            Stage::CheckBlock => "check_block",
            Stage::AcceptBlock => "accept_block",
            Stage::Confirm => "confirm",
            Stage::Connect => "connect",
        })
    }
}

/// Which of the pipeline's stages refused a block, and what it said.
///
/// One value rather than BM-D1's `{ stage, verdict }` pair: a stage and an error that can
/// be set independently can be set inconsistently, and the only way to read the evidence
/// then is to trust that whoever wrote it kept the two in step. Each variant names one
/// function of the consensus crate and carries that function's own error type, so the pair
/// is correct by construction and `Display` can give Core's reject reason unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "only the header stage refuses anything today; the block and coin stages are \
              wired by BM-9 and BM-10, and the vocabulary is complete and tested ahead of them"
)]
pub enum Invalidity {
    /// `accept_header` refused the header. Contextual, so it is final: the context is fixed
    /// by ancestors that cannot change.
    AcceptHeader(HeaderError),
    /// `check_block` refused the block.
    CheckBlock(BlockError),
    /// `accept_block` refused the block.
    AcceptBlock(BlockError),
    /// `confirm` refused it: the coins, the amounts, BIP30, BIP68 or the sigop cost.
    Confirm(ConfirmError),
    /// `connect` refused it: an input's scripts did not verify.
    Connect(ConnectError),
    /// A verdict this node reached in an earlier run and wrote to the block index. The
    /// evidence went to the log when it happened; what came back is the stage, which is
    /// what keeps the block off the chain (BM-26).
    Reloaded {
        /// The stage that refused it, that run.
        stage: Stage,
    },
}

impl Invalidity {
    /// Which stage this is, which is all the block index keeps.
    #[must_use]
    pub fn stage(self) -> Stage {
        match self {
            Invalidity::AcceptHeader(_) => Stage::AcceptHeader,
            Invalidity::CheckBlock(_) => Stage::CheckBlock,
            Invalidity::AcceptBlock(_) => Stage::AcceptBlock,
            Invalidity::Confirm(_) => Stage::Confirm,
            Invalidity::Connect(_) => Stage::Connect,
            Invalidity::Reloaded { stage } => stage,
        }
    }
}

impl fmt::Display for Invalidity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Invalidity::AcceptHeader(error) => write!(formatter, "accept_header: {error}"),
            Invalidity::CheckBlock(error) => write!(formatter, "check_block: {error}"),
            Invalidity::AcceptBlock(error) => write!(formatter, "accept_block: {error}"),
            Invalidity::Confirm(error) => write!(formatter, "confirm: {error}"),
            Invalidity::Connect(error) => write!(formatter, "connect: {error}"),
            Invalidity::Reloaded { stage } => {
                write!(formatter, "{stage} refused it in an earlier run")
            }
        }
    }
}

/// What is known about the block behind a header.
///
/// The transitions the seven functions can produce, and no others:
///
/// ```text
///                    check_block + accept_block       confirm + connect
///   HeaderAccepted ────────────────────────────▶ BlockChecked ─────────────▶ Connected
///         │                                        │      ▲                      │
///         │                                        │      └──────────────────────┘
///         │                                        │            reorg
///         ▼                                        ▼
///       Invalid ◀───────────────────────────────────
///         │  (its descendants, in one pass)
///         ▼
///   InvalidAncestor
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the block store that supplies a location is BM-9's and the chainstate that \
              supplies an undo record is BM-10's; the states and their transitions are here"
)]
pub enum HeaderStatus {
    /// The block every chain starts from. No parent, no context, no undo, and its bytes are
    /// in [`ChainParams`] rather than on a peer's word.
    Genesis,
    /// The header passed `check_header` and `accept_header`. The block itself is unknown.
    HeaderAccepted,
    /// The block passed `check_block` and `accept_block` and its bytes are on the disk,
    /// exactly as they arrived (BM-D1 decision 9). The store never deletes them.
    BlockChecked {
        /// Where those bytes are.
        location: BlockLocation,
    },
    /// The block's coins are in the chainstate, and the record that takes them back off
    /// exists. Equivalent to "on the active chain": nothing else reaches this state, and it
    /// is left only by [`HeaderTree::disconnected`], one step from the tip.
    Connected {
        /// Where the block's bytes are.
        location: BlockLocation,
        /// Where its undo record is.
        undo: UndoLocation,
    },
    /// A stage refused this block. Terminal, and the peer that sent it is at fault.
    Invalid {
        /// The stage that refused it and what that stage said.
        invalidity: Invalidity,
    },
    /// An ancestor was refused. Terminal, nobody is at fault, and the reason is stored once
    /// — on the culprit (BM-D1 decisions 5 and 6).
    InvalidAncestor {
        /// The nearest ancestor that earned an [`Invalidity`] of its own.
        culprit: BlockHash,
    },
}

impl HeaderStatus {
    /// Whether nothing further can happen to this block.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            HeaderStatus::Invalid { .. } | HeaderStatus::InvalidAncestor { .. }
        )
    }

    /// Whether the block's bytes are on the disk.
    #[must_use]
    pub fn location(self) -> Option<BlockLocation> {
        match self {
            HeaderStatus::BlockChecked { location } | HeaderStatus::Connected { location, .. } => {
                Some(location)
            }
            HeaderStatus::Genesis
            | HeaderStatus::HeaderAccepted
            | HeaderStatus::Invalid { .. }
            | HeaderStatus::InvalidAncestor { .. } => None,
        }
    }

    /// Whether this block's coins are in the chainstate — genesis included, which is the
    /// base of every active chain.
    #[must_use]
    pub fn is_connected(self) -> bool {
        matches!(self, HeaderStatus::Genesis | HeaderStatus::Connected { .. })
    }
}

/// One header and everything the tree knows about it.
#[derive(Clone, Debug)]
pub struct HeaderEntry {
    header: Header,
    hash: BlockHash,
    height: Height,
    chainwork: Work,
    parent: Option<NodeId>,
    skip: Option<NodeId>,
    status: HeaderStatus,
    /// Changed since the block index last had it. The flag is what keeps one entry to one
    /// place in [`HeaderTree::dirty`], however many times it changes between two commits.
    dirty: bool,
}

impl HeaderEntry {
    /// The header itself, which is what a `headers` message is made of, and what the
    /// block index writes down.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Its hash, computed once when it entered the tree.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.hash
    }

    /// Its height.
    #[must_use]
    pub fn height(&self) -> Height {
        self.height
    }

    /// The work of this header and every one below it: what the most-work choice compares.
    #[must_use]
    pub fn chainwork(&self) -> Work {
        self.chainwork
    }

    /// Its parent, absent only for genesis.
    #[must_use]
    pub fn parent(&self) -> Option<NodeId> {
        self.parent
    }

    /// What is known about the block behind it.
    #[must_use]
    pub fn status(&self) -> HeaderStatus {
        self.status
    }
}

/// Why a header did not enter the tree as a header this node will build on.
///
/// [`AcceptError::blames_peer`] is BM-D1 decision 6 in one method: a peer answers for its
/// own fault and for nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// `check_header` refused it: no proof of work, or an `nBits` naming no target the
    /// chain allows. Never stored — storing a header with no work behind it is exactly what
    /// an attacker would like this node to do.
    CheckHeader(HeaderError),
    /// The parent is not in the tree. Headers-first means there is no orphan buffer to park
    /// this in (BM-D1 decision 9); Core answers with a `getheaders` and no punishment
    /// (R4 §2.3, `HandleUnconnectingHeaders`).
    UnknownParent {
        /// The parent that is missing.
        previous: BlockHash,
    },
    /// `accept_header` refused it. Stored as [`HeaderStatus::Invalid`], because the context
    /// is fixed by ancestors and so the verdict can never change.
    Invalid {
        /// Where it was stored.
        node: NodeId,
        /// What refused it.
        invalidity: Invalidity,
    },
    /// Its parent is invalid. Stored as [`HeaderStatus::InvalidAncestor`] so the block is
    /// never requested, and nobody is punished for relaying it.
    InvalidAncestor {
        /// Where it was stored.
        node: NodeId,
        /// The ancestor that earned the verdict.
        culprit: BlockHash,
    },
    /// `nTime` is more than [`MAX_FUTURE_BLOCK_TIME`] beyond this node's clock. Refused and
    /// *not* stored: it may be valid in an hour, and there is no state that means "later".
    TooFarInFuture {
        /// The header's `nTime`.
        time: BlockTime,
        /// The latest `nTime` this node will take right now.
        limit: BlockTime,
    },
    /// The tree is at [`MAX_TREE_HEADERS`]. A header that would have been recorded
    /// `Invalid` is refused this way too, and so goes unrecorded: at the cap the node has
    /// stopped learning, and saying that plainly beats half-remembering.
    TreeFull,
}

impl AcceptError {
    /// What the peer that sent this header is at fault for, if anything.
    ///
    /// BM-D1 decision 6: a header that fails one of the seven functions is the sender's
    /// fault. An unconnecting header, a descendant of somebody else's invalid block, a
    /// clock that disagrees with ours and a tree of our own that is full are not. The
    /// evidence comes with the verdict rather than beside it, so this node cannot decide to
    /// disconnect somebody and then have nothing to say about why.
    #[must_use]
    pub fn peer_fault(&self) -> Option<HeaderError> {
        match self {
            AcceptError::CheckHeader(error)
            | AcceptError::Invalid {
                invalidity: Invalidity::AcceptHeader(error),
                ..
            } => Some(*error),
            AcceptError::Invalid { .. }
            | AcceptError::UnknownParent { .. }
            | AcceptError::InvalidAncestor { .. }
            | AcceptError::TooFarInFuture { .. }
            | AcceptError::TreeFull => None,
        }
    }
}

impl fmt::Display for AcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcceptError::CheckHeader(error) => write!(formatter, "check_header: {error}"),
            AcceptError::UnknownParent { previous } => {
                write!(formatter, "unknown parent {previous}")
            }
            AcceptError::Invalid { invalidity, .. } => write!(formatter, "{invalidity}"),
            AcceptError::InvalidAncestor { culprit, .. } => {
                write!(formatter, "descends from invalid block {culprit}")
            }
            AcceptError::TooFarInFuture { time, limit } => write!(
                formatter,
                "time-too-new: nTime {} is past {}",
                time.get(),
                limit.get()
            ),
            AcceptError::TreeFull => write!(formatter, "header tree is at {MAX_TREE_HEADERS}"),
        }
    }
}

/// A header that reached the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// New. The context is the one every later stage reads, and BM-D5 decision 5 is what
    /// makes handing it back the point: the download request carries it, so the whole
    /// receipt path can run on a peer's own thread without touching this tree.
    First {
        /// Where it was stored.
        node: NodeId,
        /// Everything the chain contributes to validating its block.
        context: Context,
    },
    /// Already known; nothing changed.
    Duplicate {
        /// Where it already was.
        node: NodeId,
    },
}

impl Accepted {
    /// Where the header is.
    #[must_use]
    pub fn node(self) -> NodeId {
        match self {
            Accepted::First { node, .. } | Accepted::Duplicate { node } => node,
        }
    }
}

/// Every header this node has accepted, and the two chains through them.
pub struct HeaderTree {
    entries: Vec<HeaderEntry>,
    index: HashMap<BlockHash, NodeId>,
    tip: NodeId,
    best_header: NodeId,
    /// Entries the block index has not been told about yet, in the order they first
    /// changed. Bounded by the tree, because an entry appears at most once.
    dirty: Vec<NodeId>,
    /// Scratch for [`next_required_bits`], reused so that assembling a context allocates
    /// nothing. Bounded by the difficulty adjustment interval.
    period: Vec<HeaderFacts>,
    cap: usize,
}

impl HeaderTree {
    /// A tree holding nothing but the chain's genesis block, which is connected by
    /// definition: its coins are the chainstate's starting point.
    #[must_use]
    pub fn new(params: &ChainParams) -> HeaderTree {
        HeaderTree::with_cap(params, MAX_TREE_HEADERS)
    }

    /// The same tree at a cap a test can reach in a second.
    ///
    /// The cap is the whole of this module's answer to a peer that mines headers for
    /// nothing, so it is worth being able to arrive at it on purpose rather than only in
    /// an argument.
    #[must_use]
    pub fn with_cap(params: &ChainParams, cap: usize) -> HeaderTree {
        assert!(cap > 0 && cap <= MAX_TREE_HEADERS);
        let header = params.genesis().header;
        let hash = header.block_hash();
        assert_eq!(hash, params.genesis_hash());
        let interval = params.difficulty_adjustment_interval();
        let genesis = HeaderEntry {
            header,
            hash,
            height: Height::GENESIS,
            chainwork: block_work(header.bits),
            parent: None,
            skip: None,
            status: HeaderStatus::Genesis,
            // Genesis comes from the chain parameters at every start, so it is never
            // written down and never dirty.
            dirty: false,
        };
        let mut index = HashMap::with_capacity(1024);
        index.insert(hash, NodeId::GENESIS);
        HeaderTree {
            entries: vec![genesis],
            index,
            tip: NodeId::GENESIS,
            best_header: NodeId::GENESIS,
            dirty: Vec::new(),
            period: Vec::with_capacity(usize::try_from(interval).expect("an interval fits")),
            cap,
        }
    }

    /// How many headers are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The node a hash names, if the tree has it.
    #[must_use]
    pub fn node_of(&self, hash: BlockHash) -> Option<NodeId> {
        self.index.get(&hash).copied()
    }

    /// One node. Panics on an id the tree did not mint, which is a bug in this node.
    #[must_use]
    pub fn entry(&self, node: NodeId) -> &HeaderEntry {
        self.entries
            .get(node.position())
            .expect("a node id comes from this tree")
    }

    /// The most-work block whose coins are in the chainstate.
    #[must_use]
    pub fn tip(&self) -> NodeId {
        self.tip
    }

    /// The most-work header that is not invalid: what the download scheduler aims at.
    #[must_use]
    pub fn best_header(&self) -> NodeId {
        self.best_header
    }

    /// Whether a node is on the active chain — which is to say, whether its coins are in
    /// the chainstate. The two are the same question because [`HeaderStatus::Connected`]
    /// is only ever entered and left at the tip.
    #[must_use]
    pub fn is_active(&self, node: NodeId) -> bool {
        self.entry(node).status.is_connected()
    }

    /// The ancestor of `node` at `height`, by Core's skip list
    /// (`chain.cpp: CBlockIndex::GetAncestor`). `None` if `height` is above `node`.
    #[must_use]
    pub fn ancestor(&self, node: NodeId, height: Height) -> Option<NodeId> {
        if height > self.entry(node).height {
            return None;
        }
        Some(self.walk_back(node, height))
    }

    /// The walk itself, once the target is known to be reachable.
    fn walk_back(&self, node: NodeId, height: Height) -> NodeId {
        let mut walk = node;
        let mut walk_height = self.entry(node).height;
        let mut steps: usize = 0;
        while walk_height > height {
            steps = steps.saturating_add(1);
            assert!(steps <= MAX_ANCESTOR_STEPS, "the skip list is malformed");
            let entry = self.entry(walk);
            if let Some(skip) = skip_toward(entry, walk_height, height) {
                walk_height = Height::new(skip_height(walk_height.get()));
                walk = skip;
                continue;
            }
            let Some(parent) = entry.parent else {
                panic!("a walk above genesis has a parent to take")
            };
            walk = parent;
            walk_height = Height::new(walk_height.get().saturating_sub(1));
        }
        walk
    }
}

/// Core's condition for following a skip pointer rather than a parent link: take it when it
/// lands on the target, or when it overshoots by less than the parent's own skip would.
fn skip_toward(entry: &HeaderEntry, from: Height, target: Height) -> Option<NodeId> {
    let skip = entry.skip?;
    let landing = skip_height(from.get());
    let previous_landing = skip_height(from.get().saturating_sub(1));
    let target = target.get();
    if landing == target {
        return Some(skip);
    }
    let overshoots_less =
        !(previous_landing < landing.saturating_sub(2) && previous_landing >= target);
    if landing > target && overshoots_less {
        return Some(skip);
    }
    None
}

impl HeaderTree {
    /// Place a header in the tree.
    ///
    /// The order is BM-8's: [`check_header`], the parent, the ancestors' verdict, the
    /// context assembled here, [`accept_header`], and last this node's own clock.
    ///
    /// The clock goes last, which is one step later than Core puts it (Core runs the
    /// future-time rule fourth of five in `ContextualCheckBlockHeader`, ahead of the version
    /// floor). Every rule in `accept_header` is clock-free and reads only ancestors, which
    /// are immutable, so a header that fails one of them is invalid forever and saying so is
    /// strictly more informative. The rule that must not be reordered is the other way
    /// round: a header refused only for being early is never recorded as invalid, because it
    /// may be perfectly good in an hour.
    pub fn accept(
        &mut self,
        header: &Header,
        params: &ChainParams,
        now: BlockTime,
    ) -> Result<Accepted, AcceptError> {
        let hash = header.block_hash();
        if let Some(node) = self.node_of(hash) {
            return Ok(Accepted::Duplicate { node });
        }
        check_header(header, params).map_err(AcceptError::CheckHeader)?;

        let previous = header.prev_blockhash;
        let parent = self
            .node_of(previous)
            .ok_or(AcceptError::UnknownParent { previous })?;
        if let Some(culprit) = self.culprit(parent) {
            let status = HeaderStatus::InvalidAncestor { culprit };
            let node = self.insert(*header, hash, parent, status)?;
            return Err(AcceptError::InvalidAncestor { node, culprit });
        }

        let context = self.context_for(parent, hash, header, params);
        if let Err(error) = accept_header(header, params, &context) {
            let invalidity = Invalidity::AcceptHeader(error);
            let node = self.insert(*header, hash, parent, HeaderStatus::Invalid { invalidity })?;
            return Err(AcceptError::Invalid { node, invalidity });
        }

        let limit = future_limit(now);
        let time = BlockTime::new(header.time);
        if time > limit {
            return Err(AcceptError::TooFarInFuture { time, limit });
        }

        let node = self.insert(*header, hash, parent, HeaderStatus::HeaderAccepted)?;
        Ok(Accepted::First { node, context })
    }

    /// Everything the chain contributes to validating one block already in the tree.
    ///
    /// The same value [`HeaderTree::accept`] handed back when the header arrived, rebuilt
    /// rather than stored: it is fixed by ancestors that cannot change, so the two can never
    /// differ, and a difficulty period walked through the scratch buffer costs less than
    /// carrying fifty bytes on every one of two million entries. What needs it is the
    /// download request (BM-D5 decision 5) and the connect job.
    pub fn context_of(&mut self, node: NodeId, params: &ChainParams) -> Context {
        let entry = self.entry(node);
        let parent = entry.parent.expect("genesis has no context");
        let hash = entry.hash;
        let header = entry.header;
        self.context_for(parent, hash, &header, params)
    }

    /// The nearest ancestor that earned an [`Invalidity`], `node` itself included.
    fn culprit(&self, node: NodeId) -> Option<BlockHash> {
        let entry = self.entry(node);
        match entry.status {
            HeaderStatus::Invalid { .. } => Some(entry.hash),
            HeaderStatus::InvalidAncestor { culprit } => Some(culprit),
            HeaderStatus::Genesis
            | HeaderStatus::HeaderAccepted
            | HeaderStatus::BlockChecked { .. }
            | HeaderStatus::Connected { .. } => None,
        }
    }

    /// Append one header under a parent already in the tree.
    fn insert(
        &mut self,
        header: Header,
        hash: BlockHash,
        parent: NodeId,
        status: HeaderStatus,
    ) -> Result<NodeId, AcceptError> {
        if self.entries.len() >= self.cap {
            return Err(AcceptError::TreeFull);
        }
        let above = self.entry(parent);
        let height = above.height.next();
        let chainwork = add_work(above.chainwork, block_work(header.bits));
        // Core's `BuildSkip`, and the reason every later walk is logarithmic.
        let skip = self.ancestor(parent, Height::new(skip_height(height.get())));
        assert!(skip.is_some(), "a skip height is never above the parent");

        let node = NodeId::at(self.entries.len());
        self.entries.push(HeaderEntry {
            header,
            hash,
            height,
            chainwork,
            parent: Some(parent),
            skip,
            status,
            // Every entry the tree gains is an entry the index has not got.
            dirty: true,
        });
        self.dirty.push(node);
        let seen = self.index.insert(hash, node);
        assert!(
            seen.is_none(),
            "a duplicate hash is caught before the insert"
        );

        // Equal work keeps the header that arrived first, which is Core's `nSequenceId`
        // tie-break and the reason two nodes given the same headers pick the same chain.
        if !status.is_terminal() && chainwork > self.entry(self.best_header).chainwork {
            self.best_header = node;
        }
        Ok(node)
    }

    /// Everything the chain contributes to validating the block after `parent`.
    fn context_for(
        &mut self,
        parent: NodeId,
        hash: BlockHash,
        header: &Header,
        params: &ChainParams,
    ) -> Context {
        let entry = self.entry(parent);
        let height = entry.height.next();
        let previous_time = BlockTime::new(entry.header.time);
        let median = self.median_time_past_at(parent);
        let required_bits = self.required_bits_after(parent, BlockTime::new(header.time), params);
        let bip34 = self.bip34_ancestor(parent, height, params);
        let rules = params.rules_at(height, hash, bip34);
        Context::new(height, median, previous_time, required_bits, rules)
    }

    /// The median of the last [`MEDIAN_TIME_SPAN`] timestamps ending at `node`, which is
    /// what the block after it must be later than.
    fn median_time_past_at(&self, node: NodeId) -> BlockTime {
        let mut times = [BlockTime::new(0); MEDIAN_TIME_SPAN];
        let mut count: usize = 0;
        let mut walk = Some(node);
        while count < MEDIAN_TIME_SPAN {
            let Some(current) = walk else { break };
            let entry = self.entry(current);
            if let Some(slot) = times.get_mut(count) {
                *slot = BlockTime::new(entry.header.time);
            }
            count = count.saturating_add(1);
            walk = entry.parent;
        }
        median_time_past(times.get(..count).expect("count never passes the span"))
    }

    /// The `nBits` the block after `parent` must carry.
    ///
    /// [`next_required_bits`] is given the whole difficulty period the parent belongs to,
    /// because that is the slice Core would have walked and the crate asserts it. The walk
    /// is bounded by the interval and reuses one buffer, so it allocates nothing; Core's
    /// shortcut of returning the previous `nBits` untouched away from a boundary is the
    /// optimisation to reach for if this ever shows up in an IBD profile, and correctness
    /// comes first.
    fn required_bits_after(
        &mut self,
        parent: NodeId,
        new_time: BlockTime,
        params: &ChainParams,
    ) -> CompactTarget {
        let interval = params.difficulty_adjustment_interval();
        let steps = self.entry(parent).height.get() % interval;
        let mut period = std::mem::take(&mut self.period);
        period.clear();
        let mut walk = parent;
        for _ in 0..=steps {
            let entry = self.entry(walk);
            period.push(HeaderFacts::from_header(entry.height, &entry.header));
            match entry.parent {
                Some(above) => walk = above,
                None => break,
            }
        }
        period.reverse();
        let bits = next_required_bits(params, &period, new_time);
        self.period = period;
        bits
    }

    /// The hash of the BIP34 block on this header's own chain, which is what tells
    /// `rules_at` whether the BIP30 scan can stop (BM-D3, `params::rules_at`).
    fn bip34_ancestor(
        &self,
        parent: NodeId,
        height: Height,
        params: &ChainParams,
    ) -> Option<BlockHash> {
        let bip34 = params.bip34_height();
        if height <= bip34 {
            return None;
        }
        let Some(node) = self.ancestor(parent, bip34) else {
            panic!("the BIP34 height is at or below the parent")
        };
        Some(self.entry(node).hash)
    }
}

#[allow(
    dead_code,
    reason = "the receipt path (BM-9) moves a header to BlockChecked and the chainstate \
              (BM-10) to Connected or Invalid; the state machine is complete and tested here"
)]
impl HeaderTree {
    /// The block's bytes are on the disk, having passed `check_block` and `accept_block`.
    pub fn block_checked(&mut self, node: NodeId, location: BlockLocation) {
        let status = self.entry(node).status;
        assert!(
            matches!(status, HeaderStatus::HeaderAccepted),
            "{node} is {status:?}, so its bytes were written twice",
        );
        self.entry_mut(node).status = HeaderStatus::BlockChecked { location };
        self.mark_dirty(node);
    }

    /// The block's coins are in the chainstate and its undo record is written.
    ///
    /// Asserts the block sits directly on the tip, which is what makes
    /// [`HeaderStatus::Connected`] and "on the active chain" the same statement.
    pub fn connected(&mut self, node: NodeId, undo: UndoLocation) {
        let entry = self.entry(node);
        assert_eq!(
            entry.parent,
            Some(self.tip),
            "{node} connects somewhere other than the tip",
        );
        let status = entry.status;
        let HeaderStatus::BlockChecked { location } = status else {
            panic!("{node} is {status:?}, and only a checked block connects")
        };
        self.entry_mut(node).status = HeaderStatus::Connected { location, undo };
        self.mark_dirty(node);
        self.tip = node;
    }

    /// The block's coins are back out of the chainstate. The bytes stay: the store never
    /// deletes, and a reorg that comes back this way finds them where they were.
    pub fn disconnected(&mut self, node: NodeId) {
        assert_eq!(node, self.tip, "{node} is not the tip");
        let entry = self.entry(node);
        let status = entry.status;
        let HeaderStatus::Connected { location, .. } = status else {
            panic!("{node} is {status:?}, and only a connected block disconnects")
        };
        let parent = entry
            .parent
            .expect("genesis is never the block disconnected");
        self.entry_mut(node).status = HeaderStatus::BlockChecked { location };
        self.mark_dirty(node);
        self.tip = parent;
    }

    /// A stage refused this block. Its descendants inherit the verdict, and the most-work
    /// header is chosen again from what is left.
    pub fn invalidate(&mut self, node: NodeId, invalidity: Invalidity) {
        let status = self.entry(node).status;
        assert!(!status.is_terminal(), "{node} is already {status:?}");
        assert!(
            !status.is_connected(),
            "{node} is on the active chain: a reorg takes it off before it is refused",
        );
        self.entry_mut(node).status = HeaderStatus::Invalid { invalidity };
        self.mark_dirty(node);
        // The descendants are not marked: an inherited verdict is written down as what the
        // entry was before it, because a replay re-derives the inheritance for itself.
        self.propagate_and_reselect(node);
    }

    /// Mark every descendant of `from`, then pick the most-work header that is left.
    ///
    /// One ascending pass over the arena does both, because a child is always appended
    /// after its parent: by the time a node is reached its parent's verdict is final. The
    /// pass is bounded by [`MAX_TREE_HEADERS`], and its rate is bounded by this node's own
    /// download schedule — a block can only be refused if this node asked for it.
    fn propagate_and_reselect(&mut self, from: NodeId) {
        assert!(self.entries.len() <= self.cap);
        let mut best = NodeId::GENESIS;
        let mut best_work = self.entry(NodeId::GENESIS).chainwork;
        for position in 0..self.entries.len() {
            let node = NodeId::at(position);
            if position > from.position() {
                self.inherit(node);
            }
            let entry = self.entry(node);
            if !entry.status.is_terminal() && entry.chainwork > best_work {
                best = node;
                best_work = entry.chainwork;
            }
        }
        self.best_header = best;
    }

    /// Give one node its parent's verdict, if the parent has one.
    fn inherit(&mut self, node: NodeId) {
        let entry = self.entry(node);
        if entry.status.is_terminal() {
            return;
        }
        let Some(parent) = entry.parent else { return };
        let Some(culprit) = self.culprit(parent) else {
            return;
        };
        assert!(
            !entry.status.is_connected(),
            "the active chain cannot descend from an invalid block",
        );
        self.entry_mut(node).status = HeaderStatus::InvalidAncestor { culprit };
    }

    /// Note that this entry has changed since the block index last saw it.
    ///
    /// Marked once however often it changes between two commits, and in the order it first
    /// changed — which is parents before children, because an entry is marked as it is
    /// inserted and a child is inserted after its parent.
    fn mark_dirty(&mut self, node: NodeId) {
        if self.entry(node).dirty {
            return;
        }
        self.entry_mut(node).dirty = true;
        self.dirty.push(node);
        assert!(
            self.dirty.len() <= self.entries.len(),
            "an entry is marked once",
        );
    }

    /// What the block index has not been told about yet.
    pub fn dirty(&self) -> &[NodeId] {
        &self.dirty
    }

    /// The index has them. Called only after the batch is durable, so that a failed write
    /// leaves every mark where it was.
    pub fn clear_dirty(&mut self) {
        for position in 0..self.dirty.len() {
            if let Some(node) = self.dirty.get(position).copied() {
                self.entry_mut(node).dirty = false;
            }
        }
        self.dirty.clear();
    }

    /// Every node, in the order they entered the tree — which is parents before children.
    pub fn nodes(&self) -> impl Iterator<Item = NodeId> {
        (0..self.entries.len()).map(NodeId::at)
    }

    fn entry_mut(&mut self, node: NodeId) -> &mut HeaderEntry {
        self.entries
            .get_mut(node.position())
            .expect("a node id comes from this tree")
    }
}

/// The latest `nTime` this node will take right now: Core's `MAX_FUTURE_BLOCK_TIME` past
/// the clock, saturating rather than wrapping at the end of the 32-bit timestamp field.
fn future_limit(now: BlockTime) -> BlockTime {
    let ahead = u32::try_from(MAX_FUTURE_BLOCK_TIME).expect("two hours, in seconds, is small");
    BlockTime::new(now.get().saturating_add(ahead))
}

/// Core's `GetSkipHeight`: the height a node's skip pointer lands on.
fn skip_height(height: u32) -> u32 {
    if height < 2 {
        return 0;
    }
    // Turning off the two lowest set bits of `height - 1` and adding one back, for odd
    // heights; turning off the lowest set bit, for even ones.
    if height.is_multiple_of(2) {
        invert_lowest_one(height)
    } else {
        invert_lowest_one(invert_lowest_one(height.saturating_sub(1))).saturating_add(1)
    }
}

/// Core's `InvertLowestOne`: clears the lowest set bit.
fn invert_lowest_one(value: u32) -> u32 {
    value & value.wrapping_sub(1)
}

/// Sum two chain works, asserting the total stays inside 256 bits.
///
/// `Work`'s own `Add` panics on overflow, which would be a library panic on a path a peer
/// feeds. It cannot happen — reaching 2^256 of accumulated work means an attacker has
/// computed 2^256 hashes, and only headers that passed `accept_header` are ever summed, so
/// every term is the work the chain itself required — but the claim is worth stating as an
/// assertion of ours rather than leaving as a trap in somebody else's operator.
fn add_work(total: Work, block: Work) -> Work {
    let left = total.to_be_bytes();
    let right = block.to_be_bytes();
    let mut sum = [0u8; 32];
    let mut carry: u16 = 0;
    for (byte, (left, right)) in sum.iter_mut().zip(left.iter().zip(right.iter())).rev() {
        let value = u16::from(*left) + u16::from(*right) + carry;
        *byte = u8::try_from(value & 0xFF).expect("masked to a byte");
        carry = value >> 8;
    }
    assert_eq!(
        carry, 0,
        "chain work past 2^256 is more hashing than exists"
    );
    Work::from_be_bytes(sum)
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
