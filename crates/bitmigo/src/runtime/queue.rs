// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two queues the node's work flows along, and the one rule that makes their
//! backpressure safe: **only a peer reader may block on a full queue.**
//!
//! A peer reader that blocks is doing the right thing. It stops reading its socket, the
//! kernel stops acknowledging that peer's data, and the backpressure reaches exactly one
//! peer — the one sending faster than the node can validate. No other peer notices, because
//! no other peer shares that thread. This is the property a thread per peer was chosen for.
//!
//! The chain and validation threads must never block on a full queue, because each of them
//! is the only thread that can drain something else. They degrade by *not producing*
//! instead: the chain stops topping up the connect queue, blocks pile up in the download
//! window, the inbound queue fills, and the peer readers block. The pipeline degrades
//! backwards to TCP, with no unbounded buffer anywhere along it.
//!
//! The shape of the two types says which is which. [`PeerToChain::send`] blocks, and asserts
//! that its caller is a peer reader thread. [`ChainToValidation`] has no blocking send at
//! all: [`ChainToValidation::try_push`] hands the job back when the queue is full, and the
//! caller's only option is to keep it.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use bitcoin::p2p::message::NetworkMessage;
use bitcoin::{Block, BlockHash};
use bitmigo_consensus::header::Context;
use bitmigo_consensus::params::Height;

use crate::peer::{READER_THREAD_PREFIX, SlotIndex};
use crate::runtime::supervisor::current_thread_is;
use crate::runtime::sync::{lock, wait};

/// The inbound queue's bound in bytes. Items carry whole blocks, so a bound in items alone
/// would be a bound of a thousand times four megabytes: the byte bound is the real one, and
/// the item bound only keeps the deque itself small.
pub const PEER_TO_CHAIN_MAX_BYTES: usize = 32 * 1024 * 1024;

/// The inbound queue's bound in items.
pub const PEER_TO_CHAIN_MAX_ITEMS: usize = 1024;

/// The connect queue's bound. Deep enough that validation never waits on the chain thread
/// for the next block, shallow enough that a reorg throws away almost nothing.
pub const CHAIN_TO_VALIDATION_MAX_JOBS: usize = 64;

/// How long a blocked peer reader waits before looking at the queue again. It is woken by
/// the consumer, so this is a backstop that bounds every wait in the node, not a poll.
const SEND_TICK: Duration = Duration::from_millis(250);

/// What a peer reader hands the chain thread.
///
/// The receipt-time work has already happened on the reader's own thread, against the
/// context that came with the request: framing, the item counts, `check_header` or
/// `check_block` and `accept_block`. What crosses here is a message the chain thread only
/// has to record.
#[derive(Debug, PartialEq, Eq)]
pub struct PeerMessage {
    /// Which peer slot this came from.
    pub peer: SlotIndex,
    /// The message, decoded and already checked as far as one thread can check it.
    pub message: NetworkMessage,
    /// What it holds, measured once at construction.
    footprint: usize,
}

impl PeerMessage {
    /// One message from one peer, weighed as it is built.
    ///
    /// The weight is measured rather than assumed, and it is measured here rather than in
    /// [`Weighed::byte_len`] because the queue asks for it twice — once to make room and
    /// once to give the room back — and an answer that could differ between the two would
    /// let the accounting drift until the bound stopped binding.
    ///
    /// `wire_len` is what the message took on the wire. For everything but a block that is
    /// also what it takes in memory; a decoded block owns rather more than its serialized
    /// size, and since a block is the only message that reaches four megabytes, it is the
    /// only one worth walking.
    pub fn new(peer: SlotIndex, message: NetworkMessage, wire_len: usize) -> PeerMessage {
        let footprint = match &message {
            NetworkMessage::Block(block) => block_footprint(block),
            _ => wire_len,
        };
        PeerMessage {
            peer,
            message,
            footprint,
        }
    }
}

/// What a decoded block holds, walking it once.
///
/// Bounded by the block, which `check_block` has already held to Bitcoin's own size limit
/// before this is called, and cheap beside the merkle root the same thread has just
/// computed. Without it the inbound queue would be bounded in wire bytes while holding
/// several times that in memory, and a bound that is not the quantity it names is not one.
fn block_footprint(block: &Block) -> usize {
    let mut bytes = size_of::<Block>();
    for transaction in &block.txdata {
        bytes = bytes.saturating_add(size_of::<bitcoin::Transaction>());
        for input in &transaction.input {
            bytes = bytes
                .saturating_add(size_of::<bitcoin::TxIn>())
                .saturating_add(input.script_sig.len())
                .saturating_add(input.witness.size());
        }
        for output in &transaction.output {
            bytes = bytes
                .saturating_add(size_of::<bitcoin::TxOut>())
                .saturating_add(output.script_pubkey.len());
        }
    }
    bytes
}

/// How much memory an item on a bounded queue holds.
///
/// Implemented rather than assumed, because the queue's bound has to count what the item
/// *owns*, not what a `size_of` says about its handle.
pub trait Weighed {
    /// The bytes this item holds, including its own footprint.
    fn byte_len(&self) -> usize;
}

impl Weighed for PeerMessage {
    fn byte_len(&self) -> usize {
        size_of::<PeerMessage>().saturating_add(self.footprint)
    }
}

/// Whether a send had to wait for room, and for how long.
///
/// Returned rather than ignored so that backpressure is measurable: a node whose readers
/// spend their time here is validation-bound, and that is worth a number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// There was room; the item went straight on.
    Immediately,
    /// The queue was full and the caller waited this long.
    AfterWaiting(Duration),
}

/// The queue was closed: the node is stopping and nothing more will be read from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Closed;

/// What a receive returned.
#[derive(Debug, PartialEq, Eq)]
pub enum Received<T> {
    /// An item.
    Item(T),
    /// Nothing arrived before the timeout; the queue is still open.
    Empty,
    /// The queue is closed and drained. The consumer's loop ends here.
    Closed,
}

struct Inbox<T> {
    items: VecDeque<T>,
    bytes: usize,
    closed: bool,
}

/// Peer readers to the chain thread: bounded by bytes and by items, and the only queue in
/// the node with a blocking send.
pub struct PeerToChain<T: Weighed> {
    inbox: Mutex<Inbox<T>>,
    has_room: Condvar,
    has_items: Condvar,
    max_bytes: usize,
    max_items: usize,
}

impl<T: Weighed> PeerToChain<T> {
    /// The queue at the node's bounds.
    pub fn new() -> PeerToChain<T> {
        PeerToChain::with_bounds(PEER_TO_CHAIN_MAX_BYTES, PEER_TO_CHAIN_MAX_ITEMS)
    }

    /// The queue at bounds a test can reach in a second.
    pub fn with_bounds(max_bytes: usize, max_items: usize) -> PeerToChain<T> {
        assert!(max_bytes > 0 && max_items > 0);
        PeerToChain {
            inbox: Mutex::new(Inbox {
                items: VecDeque::with_capacity(max_items.min(PEER_TO_CHAIN_MAX_ITEMS)),
                bytes: 0,
                closed: false,
            }),
            has_room: Condvar::new(),
            has_items: Condvar::new(),
            max_bytes,
            max_items,
        }
    }

    /// Put an item on the queue, waiting for room if there is none.
    ///
    /// Asserts the caller is a peer reader. Every other thread in the node is the sole
    /// consumer of something, and a sole consumer that blocks here stops draining what it
    /// alone drains — which is how a bounded queue turns into a deadlock.
    pub fn send(&self, item: T) -> Result<Sent, Closed> {
        let weight = item.byte_len();
        assert!(weight > 0);
        assert!(
            weight <= self.max_bytes,
            "an item larger than the whole queue could never be sent",
        );

        let started = Instant::now();
        let mut waited = false;
        let mut inbox = lock(&self.inbox);
        while !inbox.closed && !fits(&inbox, weight, self.max_bytes, self.max_items) {
            if !waited {
                assert!(
                    current_thread_is(READER_THREAD_PREFIX),
                    "only a peer reader may block on a full queue",
                );
                waited = true;
            }
            inbox = wait(&self.has_room, inbox, SEND_TICK);
        }
        if inbox.closed {
            return Err(Closed);
        }
        inbox.bytes = inbox.bytes.saturating_add(weight);
        inbox.items.push_back(item);
        drop(inbox);
        self.has_items.notify_one();

        if waited {
            Ok(Sent::AfterWaiting(started.elapsed()))
        } else {
            Ok(Sent::Immediately)
        }
    }

    /// Put an item on the queue if there is room this instant, handing it back if not.
    #[allow(
        dead_code,
        reason = "the reader forwards with the blocking send; this is for the paths that \
                  must not wait, and for the tests that fill the queue"
    )]
    pub fn try_send(&self, item: T) -> Result<(), T> {
        let weight = item.byte_len();
        let mut inbox = lock(&self.inbox);
        if inbox.closed || !fits(&inbox, weight, self.max_bytes, self.max_items) {
            return Err(item);
        }
        inbox.bytes = inbox.bytes.saturating_add(weight);
        inbox.items.push_back(item);
        drop(inbox);
        self.has_items.notify_one();
        Ok(())
    }

    /// Take the oldest item, waiting up to `timeout` for one.
    pub fn recv(&self, timeout: Duration) -> Received<T> {
        let mut inbox = lock(&self.inbox);
        if inbox.items.is_empty() && !inbox.closed {
            inbox = wait(&self.has_items, inbox, timeout);
        }
        match inbox.items.pop_front() {
            Some(item) => {
                inbox.bytes = inbox.bytes.saturating_sub(item.byte_len());
                drop(inbox);
                self.has_room.notify_one();
                Received::Item(item)
            }
            None if inbox.closed => Received::Closed,
            None => Received::Empty,
        }
    }

    /// Stop the queue. Senders waiting for room return [`Closed`], and the consumer's loop
    /// ends once it has drained what is already here.
    pub fn close(&self) {
        lock(&self.inbox).closed = true;
        self.has_room.notify_all();
        self.has_items.notify_all();
    }

    /// Items waiting.
    pub fn len(&self) -> usize {
        lock(&self.inbox).items.len()
    }

    /// Bytes held by the items waiting.
    pub fn bytes(&self) -> usize {
        lock(&self.inbox).bytes
    }
}

impl<T: Weighed> Default for PeerToChain<T> {
    fn default() -> PeerToChain<T> {
        PeerToChain::new()
    }
}

/// Room for one more item of `weight`. An empty queue always has room: an item at the bound
/// must go somewhere, or the sender waits for a drain that can never come.
fn fits<T>(inbox: &Inbox<T>, weight: usize, max_bytes: usize, max_items: usize) -> bool {
    if inbox.items.len() >= max_items {
        return false;
    }
    inbox.items.is_empty() || inbox.bytes.saturating_add(weight) <= max_bytes
}

/// Where a block's bytes are on disk. The storage engine gives this its final shape; what
/// the queue needs is that a job names the block without carrying it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockLocation {
    /// Which block file.
    pub file: u32,
    /// Where the block starts in it.
    pub offset: u32,
    /// How many bytes it is.
    pub len: u32,
}

/// Connect this block, or disconnect it. A reorg travels the same queue as a sync, so the
/// validation thread has one loop and one order of work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the scheduler that builds jobs is the download module's work; the queue and \
              the job it carries are complete and tested ahead of it"
)]
pub enum JobKind {
    /// Apply the block to the chainstate.
    Connect,
    /// Take it back off, from the undo data.
    Disconnect,
}

/// One block of work for the validation thread.
///
/// The context travels with the job for the same reason it travels with a download request:
/// it is fixed by the block's ancestors, which are immutable once accepted, so the thread
/// that uses it needs no lock on the header tree to be sure of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectJob {
    /// Connect or disconnect.
    pub kind: JobKind,
    /// The block.
    pub hash: BlockHash,
    /// Everything the chain contributes to validating it, its height included.
    pub context: Context,
    /// Where its bytes are.
    pub location: BlockLocation,
}

impl ConnectJob {
    /// The block's height, which the context already carries.
    pub fn height(&self) -> Height {
        self.context.height()
    }
}

struct Jobs {
    queue: VecDeque<ConnectJob>,
    closed: bool,
}

/// The chain thread to the validation thread: a fixed number of jobs, pulled rather than
/// pushed.
///
/// There is deliberately no blocking send. The chain thread tops the queue up when the
/// connectable prefix advances and there is room, and does nothing at all when there is not.
pub struct ChainToValidation {
    jobs: Mutex<Jobs>,
    has_jobs: Condvar,
    max_jobs: usize,
}

impl ChainToValidation {
    /// The queue at the node's bound.
    pub fn new() -> ChainToValidation {
        ChainToValidation::with_bound(CHAIN_TO_VALIDATION_MAX_JOBS)
    }

    /// The queue at a bound a test chooses.
    pub fn with_bound(max_jobs: usize) -> ChainToValidation {
        assert!(max_jobs > 0);
        ChainToValidation {
            jobs: Mutex::new(Jobs {
                queue: VecDeque::with_capacity(max_jobs),
                closed: false,
            }),
            has_jobs: Condvar::new(),
            max_jobs,
        }
    }

    /// Add a job if there is room, handing it back if there is not.
    #[allow(
        dead_code,
        reason = "the scheduler that builds jobs is the download module's work; the queue \
                  is complete and tested ahead of it"
    )]
    pub fn try_push(&self, job: ConnectJob) -> Result<(), ConnectJob> {
        let mut jobs = lock(&self.jobs);
        if jobs.closed || jobs.queue.len() >= self.max_jobs {
            return Err(job);
        }
        jobs.queue.push_back(job);
        drop(jobs);
        self.has_jobs.notify_one();
        Ok(())
    }

    /// How many more jobs would fit. The chain thread's whole scheduling question.
    pub fn room(&self) -> usize {
        let jobs = lock(&self.jobs);
        self.max_jobs.saturating_sub(jobs.queue.len())
    }

    /// Take the next job, waiting up to `timeout` for one.
    pub fn pop(&self, timeout: Duration) -> Received<ConnectJob> {
        let mut jobs = lock(&self.jobs);
        if jobs.queue.is_empty() && !jobs.closed {
            jobs = wait(&self.has_jobs, jobs, timeout);
        }
        match jobs.queue.pop_front() {
            Some(job) => Received::Item(job),
            None if jobs.closed => Received::Closed,
            None => Received::Empty,
        }
    }

    /// Throw the queue away, which is what a reorg does: the jobs on it descend from a tip
    /// that is no longer the tip, and the chain thread will refill from the new one.
    pub fn discard(&self) -> usize {
        let mut jobs = lock(&self.jobs);
        let discarded = jobs.queue.len();
        jobs.queue.clear();
        discarded
    }

    /// Jobs waiting.
    #[allow(
        dead_code,
        reason = "the scheduler that builds jobs is the download module's work; the queue \
                  is complete and tested ahead of it"
    )]
    pub fn len(&self) -> usize {
        lock(&self.jobs).queue.len()
    }

    /// Stop the queue; validation's loop ends once it has drained what is here.
    pub fn close(&self) {
        lock(&self.jobs).closed = true;
        self.has_jobs.notify_all();
    }
}

impl Default for ChainToValidation {
    fn default() -> ChainToValidation {
        ChainToValidation::new()
    }
}

#[cfg(test)]
#[path = "queue_tests.rs"]
mod tests;
