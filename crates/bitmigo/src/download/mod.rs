// SPDX-License-Identifier: MIT OR Apache-2.0

//! The download schedule: what this node asks for, whom it asks, and what it does when the
//! answer does not come.
//!
//! Headers first, always. A peer's headers go into the header tree, and what comes back is
//! a chain of blocks this node knows it wants before it has spent a byte of bandwidth on
//! any of them; this module asks for those blocks. Two bounds shape the asking, and both
//! are Core's, because they are what a peer on the other side expects: at most **sixteen
//! blocks in flight per peer**, and never more than **a thousand and twenty-four blocks**
//! past the last block this node and that peer are known to share. Sixteen bounds what one
//! peer can make this node hold — and, with the refuse-unrequested rule, what it is allowed
//! to send at all; the window bounds what all thirty-two of them together can.
//!
//! Three clocks sit under that, each answering a different way of being useless. A peer
//! that takes a request and does not answer it is caught by the **block download timeout**;
//! a peer that holds the left edge of the window while everybody else has run out of work
//! is caught by the shared adaptive **stalling timeout**; a peer that takes the headers
//! sync and then goes quiet — while still answering pings, so no other timer sees it — is
//! caught by the **headers timeout**. [`timeouts`] holds the first two and the reasoning
//! behind them.
//!
//! Everything here runs on the chain thread, which owns the header tree, so the schedule is
//! plain data with no lock on it. What it hands the peer's own reader thread is the
//! in-flight record, and that record carries the block's `Context`: BM-D5 decision 5, and
//! the reason the whole receipt path — `check_block`, `accept_block` — runs on the thread
//! of the peer that sent the block and touches nothing shared.
//!
//! ```text
//!   headers ──▶ tree ──▶ window walk ──▶ getdata ──▶ 16 in flight ──▶ block ──▶ receipt
//!                 ▲          │                          │
//!                 └── getheaders                        └── stall / timeout ──▶ disconnect
//! ```

mod peers;
mod timeouts;
mod window;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitmigo_consensus::params::{BlockTime, Height};

use crate::chain::{HeaderStatus, HeaderTree, MAX_LOCATOR_ENTRIES, NodeId, node_time};
use crate::peer::{
    BlockRequest, Connection, Disconnect, MAX_BLOCKS_IN_FLIGHT, MAX_HEADERS_ITEMS, MAX_INV_ITEMS,
    OUTBOUND_SLOTS, PEER_SLOTS, PROTOCOL_VERSION, SlotIndex, SlotKind, SlotRole, encode,
};
use crate::runtime::Shared;

use peers::PeerDownload;
use timeouts::{StallTimeout, download_timeout};
use window::Window;

/// Core's `BLOCK_DOWNLOAD_WINDOW`. How far past the last common block this node will fetch:
/// far enough that a peer's round trip never idles the pipeline, near enough that what has
/// arrived and not yet been connected is a bounded amount of memory.
pub const BLOCK_DOWNLOAD_WINDOW: u32 = 1024;

/// The fewest headers the window walk steps over at a time. The arena has no child
/// pointers, so each batch costs one skip-list walk however long it is; a hundred and
/// twenty-eight is Core's number and makes that cost disappear.
const WALK_BATCH: usize = 128;

/// Core's `HEADERS_RESPONSE_TIME`. A second `getheaders` to the same peer inside this is
/// noise: the first one is still on the wire, and asking again only doubles the answer.
const HEADERS_RESPONSE_TIME: Duration = Duration::from_secs(120);

/// Core's `MAX_TIP_AGE`. A tip older than this is a node that is behind, whatever its work
/// says, and a node that is behind is still in its initial block download.
const MAX_TIP_AGE: Duration = Duration::from_hours(24);

/// Core's `STALE_CHECK_INTERVAL`: how often the node asks whether its tip has stopped
/// moving.
const STALE_CHECK_INTERVAL: Duration = Duration::from_mins(10);

/// Core's `MINIMUM_CONNECT_TIME`: a connection younger than this has not had a chance to be
/// useful yet, and dropping it proves nothing.
const MINIMUM_CONNECT_TIME: Duration = Duration::from_secs(30);

/// How many target spacings without the tip moving make it stale. Core's `TipMayBeStale`.
const STALE_TIP_SPACINGS: u32 = 3;

/// How many arrived-but-unstored blocks this node will ask for more on top of: one window,
/// spelled as a `usize` beside [`BLOCK_DOWNLOAD_WINDOW`]'s `u32`.
const MAX_UNSTORED_BLOCKS: usize = 1024;

/// How many it can end up holding: the gate above, plus every request that was already
/// outstanding when it closed. This is the bound on [`Schedule::delivered`], and it goes
/// away with the block store — see that field.
const MAX_DELIVERED_BLOCKS: usize = MAX_UNSTORED_BLOCKS + PEER_SLOTS * MAX_BLOCKS_IN_FLIGHT;

/// One block this node has asked for and has not been given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InFlight {
    /// Which peer was asked. The same block is never asked of two peers at once.
    peer: SlotIndex,
    /// When it was asked for.
    requested_at: Instant,
}

/// What this node is fetching, from whom, and since when.
pub struct Schedule {
    /// One row per slot, reset when a slot changes hands.
    peers: [PeerDownload; PEER_SLOTS],
    /// Every block asked of anybody: Core's `mapBlocksInFlight`, at one peer per hash
    /// rather than three, because nothing here asks two peers for the same block.
    in_flight: HashMap<BlockHash, InFlight>,
    /// Blocks that have arrived and have nowhere yet to be kept.
    ///
    /// A block becomes `BlockChecked` when its bytes reach the store, and the store is
    /// BM-9's; until then this set is what stops the walk asking for the same block again
    /// the instant it arrives, and what moves the left edge of the window over it. It is
    /// bounded by [`MAX_DELIVERED_BLOCKS`], and it goes away entirely once a block's own
    /// status can answer the question — a set that stands in for the disk is a set that
    /// has to be capped, which is what [`MAX_UNSTORED_BLOCKS`] does to the sync until the
    /// store exists.
    delivered: HashSet<BlockHash>,
    /// The one adaptive stalling window, shared by every peer.
    stalling: StallTimeout,
    /// The chain's target spacing, which is what the block download timeout is measured in.
    spacing: Duration,
    /// The work a chain must carry before this node spends bandwidth on it.
    minimum_chain_work: [u8; 32],
    /// Whether this node still considers itself behind. Latched: it is asked once and never
    /// asked again, as Core's `IsInitialBlockDownload` latches.
    initial_block_download: bool,
    /// The tip's height when it was last looked at, and when that was: the two fields the
    /// stale-tip check compares.
    tip_height: Height,
    tip_advanced_at: Instant,
    /// When the stale-tip check last ran.
    stale_checked_at: Instant,
    /// Blocks asked for, and blocks that arrived. The two numbers an operator wants when a
    /// sync is not moving.
    requested: u64,
    received: u64,
}

impl Schedule {
    /// The schedule of a node that has just started: nothing asked for, nobody known.
    pub fn new(shared: &Shared) -> Schedule {
        let spacing = u64::try_from(shared.params.pow_target_spacing()).unwrap_or(600);
        let now = Instant::now();
        Schedule {
            peers: [PeerDownload::default(); PEER_SLOTS],
            in_flight: HashMap::with_capacity(PEER_SLOTS * MAX_BLOCKS_IN_FLIGHT),
            delivered: HashSet::with_capacity(MAX_DELIVERED_BLOCKS),
            stalling: StallTimeout::new(),
            spacing: Duration::from_secs(spacing.max(1)),
            minimum_chain_work: shared.network.minimum_chain_work(),
            initial_block_download: true,
            tip_height: Height::GENESIS,
            // A node that has just started has not had a stale tip yet, however long it was
            // stopped for: the clock starts when this node does.
            tip_advanced_at: now,
            stale_checked_at: now,
            requested: 0,
            received: 0,
        }
    }

    /// One pass over the schedule, once per turn of the chain thread's loop.
    ///
    /// The order is the reasoning: forget the peers that have gone, notice where the chain
    /// is, ask for headers, ask for blocks, and only then judge anybody — a peer that has
    /// just been asked for something is not late yet.
    pub fn tick(&mut self, shared: &Shared, tree: &mut HeaderTree) {
        let now = Instant::now();
        self.reconcile(shared);
        self.note_tip(tree, now);
        self.update_initial_block_download(tree);
        self.ask_for_headers(shared, tree, now);
        self.ask_for_blocks(shared, tree, now);
        self.check_timeouts(shared, now);
        self.check_stale_tip(shared, tree, now);
    }

    /// Blocks asked for and not yet given, for the published status.
    pub fn blocks_in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Whether the node still considers itself behind.
    pub fn is_initial_block_download(&self) -> bool {
        self.initial_block_download
    }

    /// What the chain thread prints when it stops.
    pub fn summary(&self) -> String {
        format!(
            "{} blocks asked for, {} received, {} in flight",
            self.requested,
            self.received,
            self.in_flight.len(),
        )
    }

    /// Match the rows against the slots, and forget everything a peer that has gone owed.
    ///
    /// A slot is reused, so this is not bookkeeping for its own sake: the blocks asked of
    /// the peer that has gone must go back to the schedule, or the window's left edge would
    /// wait forever for a connection that no longer exists. The peer's own table was
    /// already emptied by its reader thread; this is the chain thread's half.
    fn reconcile(&mut self, shared: &Shared) {
        for position in 0..PEER_SLOTS {
            let index = SlotIndex::from_position(position);
            let since = shared.slots.connection(index).map(|held| held.since);
            if !self.describes(index, since) {
                self.forget(index, since);
            }
        }
    }

    /// Notice whether the chainstate has moved, which is what a stale tip is measured from.
    fn note_tip(&mut self, tree: &HeaderTree, now: Instant) {
        let height = tree.entry(tree.tip()).height();
        if height > self.tip_height {
            self.tip_height = height;
            self.tip_advanced_at = now;
        }
    }

    /// Ask, once, whether this node is still behind.
    ///
    /// Core's two conditions, and the latch: a tip carrying the work the chain is defined
    /// to have, and a tip young enough to be the real one. Latched because the answer
    /// changes what this node asks of whom, and a node that flickers in and out of its
    /// initial block download would change its mind about that every time a block was slow.
    fn update_initial_block_download(&mut self, tree: &HeaderTree) {
        if !self.initial_block_download {
            return;
        }
        let tip = tree.entry(tree.tip());
        if tip.chainwork().to_be_bytes() < self.minimum_chain_work {
            return;
        }
        let age = node_time().get().saturating_sub(tip.header().time);
        if u64::from(age) > MAX_TIP_AGE.as_secs() {
            return;
        }
        self.initial_block_download = false;
        println!(
            "bitmigo: caught up at height {}, {}",
            tip.height().get(),
            tip.hash(),
        );
    }

    /// The row for a slot, matched to the connection that is in it right now.
    ///
    /// A slot is reused, so a row is told whose it is every time it is touched: a message
    /// from the peer that has gone must not become state about the peer that replaced it,
    /// and a message that arrives before this row has ever been looked at must not be
    /// thrown away either. Both go through [`Schedule::forget`], so there is one rule for
    /// what happens when a slot changes hands and one place it is applied.
    fn row(&mut self, shared: &Shared, index: SlotIndex) -> &mut PeerDownload {
        let since = shared.slots.connection(index).map(|held| held.since);
        if !self.describes(index, since) {
            self.forget(index, since);
        }
        self.peers.get_mut(index.get()).expect("one row per slot")
    }

    /// Whether the row for a slot is up to date about what is in it.
    fn describes(&self, index: SlotIndex, since: Option<Instant>) -> bool {
        self.peers
            .get(index.get())
            .expect("one row per slot")
            .describes(since)
    }

    /// Forget everything about a slot: the row, and the blocks the peer that was in it was
    /// owing.
    ///
    /// The two halves belong together. A row without its in-flight entries would leave
    /// blocks nobody owes and nobody will ask for again — the window's left edge would wait
    /// on a connection that no longer exists, and the sync would stop for good.
    fn forget(&mut self, index: SlotIndex, since: Option<Instant>) {
        self.peers
            .get_mut(index.get())
            .expect("one row per slot")
            .reset(since);
        self.in_flight.retain(|_, held| held.peer != index);
    }

    /// How many peers have a block in flight right now.
    fn peers_downloading(&self) -> usize {
        let mut seen = [false; PEER_SLOTS];
        let mut count: usize = 0;
        for held in self.in_flight.values() {
            let slot = seen.get_mut(held.peer.get()).expect("one flag per slot");
            if !*slot {
                *slot = true;
                count = count.saturating_add(1);
            }
        }
        count
    }

    /// Whether this peer has a block in flight.
    fn is_downloading(&self, index: SlotIndex) -> bool {
        self.in_flight.values().any(|held| held.peer == index)
    }

    /// How many blocks this peer owes. The chain thread's own count, which is what the
    /// sixteen-per-peer bound is kept in: a bounded scan of at most five hundred and twelve
    /// entries, once per peer per pass.
    fn in_flight_for(&self, index: SlotIndex) -> usize {
        self.in_flight
            .values()
            .filter(|held| held.peer == index)
            .count()
    }

    /// When the oldest block still owed by this peer was asked for.
    fn oldest_request(&self, index: SlotIndex) -> Option<Instant> {
        self.in_flight
            .values()
            .filter(|held| held.peer == index)
            .map(|held| held.requested_at)
            .min()
    }
}

/// What one peer's `headers` message did to the header tree.
///
/// The tree's own answer, folded into what the schedule has to decide next: whether to ask
/// this peer for more, whether it has anything worth downloading, and whether the sync it
/// was given is making progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadersReceived {
    /// How many headers the message carried. A full message means the peer has more.
    pub count: usize,
    /// The last header of the batch that entered the tree, if any did.
    pub last: Option<NodeId>,
    /// The batch's first header had a parent this node has never seen.
    pub unconnecting: bool,
}

/// Asking for headers: whom to ask, when to ask again, and what to do with the answer.
impl Schedule {
    /// Ask for headers, and ask peers to announce new blocks with them.
    fn ask_for_headers(&mut self, shared: &Shared, tree: &HeaderTree, now: Instant) {
        let preferred = preferred_download_peers(shared);
        let mut syncing = self.syncs_started();
        let recent = best_header_is_recent(tree);
        for position in 0..PEER_SLOTS {
            let index = SlotIndex::from_position(position);
            let Some(connection) = shared.slots.connection(index) else {
                continue;
            };
            if !connection.is_ready() || !peers::can_serve_blocks(connection.services()) {
                continue;
            }
            self.ask_for_announcements(shared, &connection);
            if self.row(shared, index).sync_started {
                continue;
            }
            // An inbound peer is asked only when this node has dialled nobody at all.
            // Core also allows one when nothing is in flight anywhere; this node does not,
            // because a connection an attacker made is a poor place to learn the chain
            // from while there is any connection it did not make.
            if index.kind() == SlotKind::Inbound && preferred > 0 {
                continue;
            }
            // One sync at a time until the header chain is near enough to now that a
            // second opinion is cheap — which is also what gives block download somewhere
            // else to go, since a peer is asked for blocks only once it has said what it
            // has (R4 §2.2).
            if syncing > 0 && !recent {
                continue;
            }
            if self.start_headers_sync(shared, tree, index, now) {
                syncing = syncing.saturating_add(1);
            }
        }
    }

    /// Ask a peer, once, to announce new blocks with `headers` rather than `inv`.
    ///
    /// A headers announcement carries the block itself rather than a hash to go and ask
    /// about, so following the tip costs one round trip instead of two (R4 §2.5).
    fn ask_for_announcements(&mut self, shared: &Shared, connection: &Connection) {
        if self.row(shared, connection.index).sendheaders_sent {
            return;
        }
        self.row(shared, connection.index).sendheaders_sent = true;
        send(shared, connection, NetworkMessage::SendHeaders);
    }

    /// Start the headers sync from one peer.
    fn start_headers_sync(
        &mut self,
        shared: &Shared,
        tree: &HeaderTree,
        index: SlotIndex,
        now: Instant,
    ) -> bool {
        let best = tree.best_header();
        // One block below the best header this node has, which is Core's rule and worth
        // stating: a locator that starts at the best header lets a peer with the same
        // chain answer with an empty `headers`, and an empty answer is indistinguishable
        // from a peer that has nothing to say.
        let from = tree.entry(best).parent().unwrap_or(best);
        if !self.send_getheaders(shared, tree, index, from, now) {
            return false;
        }
        let deadline = now.checked_add(self.headers_deadline(tree)).unwrap_or(now);
        let row = self.row(shared, index);
        row.sync_started = true;
        row.sync_deadline = Some(deadline);
        true
    }

    /// How long a peer has to answer, given how far behind this node's headers are.
    fn headers_deadline(&self, tree: &HeaderTree) -> Duration {
        let best = tree.entry(tree.best_header());
        peers::headers_timeout(
            BlockTime::new(best.header().time),
            node_time(),
            self.spacing,
        )
    }

    /// Send one `getheaders`, unless one is already outstanding.
    ///
    /// Core's `MaybeSendGetHeaders` rate limit: a second request inside two minutes asks
    /// for an answer that is already on its way, and the only thing it can achieve is to
    /// have it sent twice.
    fn send_getheaders(
        &mut self,
        shared: &Shared,
        tree: &HeaderTree,
        index: SlotIndex,
        from: NodeId,
        now: Instant,
    ) -> bool {
        let outstanding = self
            .row(shared, index)
            .getheaders_at
            .is_some_and(|at| now.duration_since(at) < HEADERS_RESPONSE_TIME);
        if outstanding {
            return false;
        }
        let Some(connection) = shared.slots.connection(index) else {
            return false;
        };
        let locator = tree.locator(from);
        assert!(!locator.is_empty() && locator.len() <= MAX_LOCATOR_ENTRIES);
        let message = GetHeadersMessage {
            // The version this node advertises, not the `bitcoin` crate's 70001: a peer
            // reads it, and nothing this node sends should say two things about itself.
            version: PROTOCOL_VERSION,
            locator_hashes: locator,
            // No stop hash: whatever the peer has, up to its own two thousand.
            stop_hash: BlockHash::all_zeros(),
        };
        send(shared, &connection, NetworkMessage::GetHeaders(message));
        self.row(shared, index).getheaders_at = Some(now);
        true
    }

    /// A peer's `headers` message has been through the tree.
    ///
    /// Three things follow from it: an unconnecting batch is answered with a `getheaders`
    /// and nothing else (Core punishes nobody for it — a header this node has not caught up
    /// to yet is not a lie); a full batch means the peer has more, so ask from where it
    /// stopped; and a short batch is the peer saying that is all it has, which ends the
    /// deadline it was under.
    pub fn headers_answered(
        &mut self,
        shared: &Shared,
        tree: &HeaderTree,
        peer: SlotIndex,
        received: HeadersReceived,
    ) {
        assert!(
            received.count <= MAX_HEADERS_ITEMS,
            "the framer bounds this"
        );
        let now = Instant::now();
        if received.unconnecting {
            let from = tree.best_header();
            self.send_getheaders(shared, tree, peer, from, now);
            return;
        }
        // Any `headers` answers the outstanding request, an empty one included.
        self.row(shared, peer).getheaders_at = None;
        let Some(last) = received.last else {
            self.row(shared, peer).sync_deadline = None;
            return;
        };
        self.note_best_known(shared, tree, peer, last);
        if received.count < MAX_HEADERS_ITEMS {
            self.row(shared, peer).sync_deadline = None;
            return;
        }
        self.send_getheaders(shared, tree, peer, last, now);
        if self.row(shared, peer).sync_started {
            let deadline = now.checked_add(self.headers_deadline(tree)).unwrap_or(now);
            self.row(shared, peer).sync_deadline = Some(deadline);
        }
    }

    /// A peer has announced blocks by `inv`, which is what a peer that never got this
    /// node's `sendheaders` does, and what Core falls back to when its announcement queue
    /// runs long.
    ///
    /// A hash this node knows says what the peer has. A hash it does not know is answered
    /// with a `getheaders` rather than a `getdata`: a block is worth asking for only once
    /// its header is in the tree, because the header is what fixes the context the block is
    /// then validated against.
    pub fn announced(
        &mut self,
        shared: &Shared,
        tree: &HeaderTree,
        peer: SlotIndex,
        items: &[Inventory],
    ) {
        assert!(items.len() <= MAX_INV_ITEMS, "the framer bounds this");
        let mut unknown = false;
        for item in items.iter().take(MAX_INV_ITEMS) {
            let hash = match item {
                Inventory::Block(hash)
                | Inventory::WitnessBlock(hash)
                | Inventory::CompactBlock(hash) => *hash,
                _ => continue,
            };
            match tree.node_of(hash) {
                Some(node) => self.note_best_known(shared, tree, peer, node),
                None => unknown = true,
            }
        }
        if unknown {
            let from = tree.best_header();
            self.send_getheaders(shared, tree, peer, from, Instant::now());
        }
    }

    /// Remember the most-work header a peer has told this node it has.
    fn note_best_known(
        &mut self,
        shared: &Shared,
        tree: &HeaderTree,
        peer: SlotIndex,
        node: NodeId,
    ) {
        let work = tree.entry(node).chainwork();
        let row = self.row(shared, peer);
        let better = row
            .best_known
            .is_none_or(|known| tree.entry(known).chainwork() < work);
        if better {
            row.best_known = Some(node);
        }
    }

    /// How many peers headers are being synced from. Counted rather than kept beside the
    /// rows, because a counter and the thing it counts can disagree and rows cannot.
    fn syncs_started(&self) -> usize {
        self.peers.iter().filter(|row| row.sync_started).count()
    }
}

/// Asking for blocks: the window, the sixteen, and what comes back.
impl Schedule {
    /// Fill every peer's in-flight list as far as the window allows.
    fn ask_for_blocks(&mut self, shared: &Shared, tree: &mut HeaderTree, now: Instant) {
        // A window's worth of blocks has arrived and is still waiting for somewhere to be
        // kept: asking for more would be asking for blocks this node would have to drop.
        // The block store (BM-9) is what empties this, and what replaces it.
        if self.delivered.len() >= MAX_UNSTORED_BLOCKS {
            return;
        }
        let preferred = preferred_download_peers(shared);
        for position in 0..PEER_SLOTS {
            let index = SlotIndex::from_position(position);
            let Some(connection) = shared.slots.connection(index) else {
                continue;
            };
            if !connection.is_ready() || !self.may_ask(&connection, preferred) {
                continue;
            }
            // Counted from this thread's own map rather than from the peer's table: the
            // reader empties that table as blocks arrive, and asking for sixteen more
            // against a count that has already moved is how a peer ends up owing more than
            // sixteen. The two agree once the chain thread has taken the block off the
            // queue, and until then this is the conservative half.
            let outstanding = self.in_flight_for(index);
            let Some(want) = MAX_BLOCKS_IN_FLIGHT
                .checked_sub(outstanding)
                .filter(|room| *room > 0)
            else {
                continue;
            };
            let limited = peers::is_limited(connection.services());
            let walk = {
                let window = Window {
                    tree,
                    in_flight: &self.in_flight,
                    delivered: &self.delivered,
                    minimum_chain_work: self.minimum_chain_work,
                };
                let row = self.peers.get_mut(position).expect("one row per slot");
                window::next_blocks(&window, row, index, want, limited)
            };
            // Core marks a staller only when the peer asking has nothing of its own in
            // flight: a peer with work to do is not being held up by anybody.
            if let Some(staller) = walk.staller
                && outstanding == 0
            {
                let row = self.row(shared, staller);
                row.stalling_since = row.stalling_since.or(Some(now));
            }
            if !walk.blocks.is_empty() {
                self.request(shared, tree, &connection, &walk.blocks, now);
            }
        }
    }

    /// Whether this peer is one to ask for blocks at all.
    ///
    /// Witness first: every block this node validates is validated with the witness rules
    /// available, so a peer that cannot send witnesses can send it nothing it can use.
    /// Then the initial-block-download rule — during the first sync only the connections
    /// this node made itself are asked, because they are the ones an attacker did not
    /// choose; afterwards, anybody that can serve blocks (R4 §3.4).
    fn may_ask(&self, connection: &Connection, preferred: usize) -> bool {
        let services = connection.services();
        if !peers::can_serve_blocks(services) || !peers::can_serve_witnesses(services) {
            return false;
        }
        if !self.initial_block_download {
            return true;
        }
        connection.index.kind() == SlotKind::Outbound || preferred == 0
    }

    /// Ask one peer for these blocks, and write down that they were asked for.
    ///
    /// The record carries the block's context, which is BM-D5 decision 5 and the whole
    /// reason the receipt path needs nothing shared: the context is fixed by ancestors that
    /// cannot change, so the peer's own reader thread can run `check_block` and
    /// `accept_block` against it without looking at this tree at all.
    fn request(
        &mut self,
        shared: &Shared,
        tree: &mut HeaderTree,
        connection: &Connection,
        blocks: &[NodeId],
        now: Instant,
    ) {
        assert!(!blocks.is_empty() && blocks.len() <= MAX_BLOCKS_IN_FLIGHT);
        let mut items = Vec::with_capacity(blocks.len());
        for node in blocks {
            let entry = tree.entry(*node);
            let (hash, height) = (entry.hash(), entry.height());
            assert!(
                matches!(entry.status(), HeaderStatus::HeaderAccepted),
                "a block is asked for against a header already in the tree",
            );
            let context = tree.context_of(*node, &shared.params);
            assert_eq!(context.height(), height, "a context is the block's own");
            let request = BlockRequest {
                hash,
                context,
                requested_at: now,
            };
            assert!(
                connection.requests.record(request),
                "the peer's table holds no more than this thread has asked it for",
            );
            let held = InFlight {
                peer: connection.index,
                requested_at: now,
            };
            assert!(
                self.in_flight.insert(hash, held).is_none(),
                "the walk skips a block that is already in flight",
            );
            // `MSG_WITNESS_BLOCK`, which is the only block this node ever asks for: a
            // stripped block cannot be checked against a witness commitment.
            items.push(Inventory::WitnessBlock(hash));
        }
        assert!(
            self.in_flight_for(connection.index) <= MAX_BLOCKS_IN_FLIGHT,
            "sixteen blocks per peer is what bounds a four-megabyte read cap",
        );
        assert!(self.in_flight.len() <= PEER_SLOTS * MAX_BLOCKS_IN_FLIGHT);
        self.requested = self
            .requested
            .saturating_add(u64::try_from(items.len()).unwrap_or(0));
        let row = self.row(shared, connection.index);
        if row.downloading_since.is_none() {
            row.downloading_since = Some(now);
        }
        send(shared, connection, NetworkMessage::GetData(items));
    }

    /// A block this node asked for has arrived and been through the receipt-time checks on
    /// its peer's own thread.
    pub fn block_received(&mut self, shared: &Shared, peer: SlotIndex, hash: BlockHash) {
        let Some(held) = self.in_flight.remove(&hash) else {
            // Not asked for, or asked of a peer that has since gone: the reader refuses the
            // first outright, and the second is a block nobody owes any more. Neither is
            // worth a word to anybody.
            return;
        };
        assert_eq!(held.peer, peer, "a block answers the peer it was asked of");
        self.received = self.received.saturating_add(1);
        self.delivered.insert(hash);
        assert!(
            self.delivered.len() <= MAX_DELIVERED_BLOCKS,
            "the window bounds what can arrive before it is stored",
        );
        // A block arrived is the node's own bandwidth working; the stalling window shrinks
        // back towards its default.
        self.stalling.decay();
        let next = self.oldest_request(peer);
        let was_head = next.is_none_or(|oldest| held.requested_at <= oldest);
        let row = self.row(shared, peer);
        row.stalling_since = None;
        if next.is_none() {
            row.downloading_since = None;
        } else if was_head {
            // The head of the list has been answered; the next block's clock starts now
            // rather than when it was asked for, which is Core's `m_downloading_since`.
            row.downloading_since = Some(Instant::now());
        }
    }
}

/// The three clocks, and the peer rotation behind them.
impl Schedule {
    /// Judge everybody, once per pass.
    fn check_timeouts(&mut self, shared: &Shared, now: Instant) {
        let downloading = self.peers_downloading();
        let preferred = preferred_download_peers(shared);
        let stalling = self.stalling.get();
        for position in 0..PEER_SLOTS {
            let index = SlotIndex::from_position(position);
            let Some(connection) = shared.slots.connection(index) else {
                continue;
            };
            let row = *self.peers.get(position).expect("one row per slot");
            if row
                .stalling_since
                .is_some_and(|since| now.duration_since(since) > stalling)
            {
                connection.disconnect(Disconnect::BlockStalling);
                // Doubled rather than kept: if this node's own link is the bottleneck,
                // disconnecting one peer after another makes it worse, not better.
                self.stalling.doubled();
                self.row(shared, index).stalling_since = None;
                continue;
            }
            if let Some(since) = row.downloading_since {
                let others = downloading.saturating_sub(usize::from(self.is_downloading(index)));
                if now.duration_since(since) > download_timeout(self.spacing, others) {
                    connection.disconnect(Disconnect::BlockDownloadTimeout);
                    continue;
                }
            }
            self.check_headers_timeout(shared, &connection, row, preferred, now);
        }
    }

    /// A peer that took the headers sync and stopped.
    ///
    /// Disconnected only when there is somebody else to try, which is Core's rule and the
    /// right one: a node with one peer and a stalled sync is better off with the stalled
    /// sync than with no peer at all. When there is nobody else the deadline is dropped
    /// rather than re-armed, so the question is not asked again of a peer this node has
    /// already decided it cannot afford to lose.
    fn check_headers_timeout(
        &mut self,
        shared: &Shared,
        connection: &Connection,
        row: PeerDownload,
        preferred: usize,
        now: Instant,
    ) {
        if row.sync_deadline.is_none_or(|deadline| now <= deadline) {
            return;
        }
        let index = connection.index;
        let mine = usize::from(index.kind() == SlotKind::Outbound);
        if preferred.saturating_sub(mine) == 0 {
            self.row(shared, index).sync_deadline = None;
            return;
        }
        connection.disconnect(Disconnect::HeadersTimeout);
    }

    /// Ask, every ten minutes, whether this node's view of the chain has stopped moving.
    ///
    /// A tip that has not moved for three target spacings, with nothing in flight to
    /// explain it, is either a quiet network or a node that is only being told what its
    /// peers want it to hear. The answer to both is a connection those peers did not
    /// choose. Core opens one extra outbound above its maximum and prunes the worst of the
    /// old ones a little later; this node's slot table is preallocated and has no eleventh
    /// slot, so the same two steps happen in the other order — the least useful full-relay
    /// peer goes, and the connector fills the slot it leaves. The netgroup rule then makes
    /// the replacement a different part of the network by construction.
    fn check_stale_tip(&mut self, shared: &Shared, tree: &HeaderTree, now: Instant) {
        if now.duration_since(self.stale_checked_at) < STALE_CHECK_INTERVAL {
            return;
        }
        self.stale_checked_at = now;
        // Blocks in flight are the explanation: this node is not stuck, it is waiting.
        if !self.in_flight.is_empty() {
            return;
        }
        if now.duration_since(self.tip_advanced_at) < self.spacing * STALE_TIP_SPACINGS {
            return;
        }
        // Room to dial already: nothing has to be given up to get a new peer.
        if shared.slots.occupied(SlotKind::Outbound) < OUTBOUND_SLOTS {
            return;
        }
        let Some(index) = self.least_useful_outbound(shared, tree, now) else {
            return;
        };
        let Some(connection) = shared.slots.connection(index) else {
            return;
        };
        println!(
            "bitmigo: tip has not moved in {:?}; replacing peer {index}",
            now.duration_since(self.tip_advanced_at),
        );
        connection.disconnect(Disconnect::StaleTip);
    }

    /// The full-relay outbound peer that has told this node the least about the chain.
    ///
    /// Never a block-relay-only slot: those two are the anchors, and they are the
    /// connections an attacker who has poisoned the address table has not learned about.
    fn least_useful_outbound(
        &self,
        shared: &Shared,
        tree: &HeaderTree,
        now: Instant,
    ) -> Option<SlotIndex> {
        let mut worst: Option<(SlotIndex, u32)> = None;
        for position in 0..OUTBOUND_SLOTS {
            let index = SlotIndex::from_position(position);
            if index.role() != SlotRole::FullRelay {
                continue;
            }
            let Some(connection) = shared.slots.connection(index) else {
                continue;
            };
            // Core's `MINIMUM_CONNECT_TIME`: a connection this young has not been given a
            // chance to say anything yet.
            if now.duration_since(connection.since) < MINIMUM_CONNECT_TIME {
                continue;
            }
            let Some(row) = self.peers.get(position) else {
                continue;
            };
            let height = row
                .best_known
                .map_or(0, |node| tree.entry(node).height().get());
            if worst.is_none_or(|(_, lowest)| height < lowest) {
                worst = Some((index, height));
            }
        }
        worst.map(|(index, _)| index)
    }
}

/// How many peers this node would rather download from: the ones it dialled itself.
///
/// Core's `fPreferredDownload` is "outbound, or granted `NoBan`". This node has no
/// permission flags, so it is exactly the outbound half — the connections an attacker did
/// not choose for us.
fn preferred_download_peers(shared: &Shared) -> usize {
    shared.slots.occupied(SlotKind::Outbound)
}

/// Whether the header chain is near enough to now that a second peer may be asked for
/// headers as well.
fn best_header_is_recent(tree: &HeaderTree) -> bool {
    let best = tree.entry(tree.best_header());
    let age = node_time().get().saturating_sub(best.header().time);
    u64::from(age) <= MAX_TIP_AGE.as_secs()
}

/// Queue one message for a peer's writer thread.
///
/// A full outbox ends the connection rather than growing it: everything this node sends is
/// a request nobody is waiting on, and a peer that will not read is not worth a megabyte
/// (BM-D5 decision 7).
fn send(shared: &Shared, connection: &Connection, message: NetworkMessage) {
    let frame = encode(shared.network.magic(), message);
    if connection.outbox.push(frame).is_err() {
        connection.disconnect(Disconnect::OutboxFull);
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
