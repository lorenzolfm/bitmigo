// SPDX-License-Identifier: MIT OR Apache-2.0

//! The slot table: thirty-two preallocated connection slots, and the handshake between the
//! thread that puts a socket into one and the two threads that were already waiting on it.

use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use bitcoin::p2p::ServiceFlags;

use super::discovery::netgroup;
use super::{
    BLOCK_RELAY_SLOTS, Disconnect, INBOUND_SLOTS, OUTBOUND_SLOTS, OUTBOX_MAX_BYTES, Outbox,
    PEER_SLOTS, Requests,
};
use crate::runtime::sync::{lock, wait};

/// How long a thread waiting for a connection sleeps before looking at the closing flag
/// again. Every wait in the node is bounded; this one is also woken directly.
const SLOT_TICK: Duration = Duration::from_millis(250);

/// The table is numbered in bytes, which is what lets a slot index be one.
const _: () = assert!(PEER_SLOTS <= 256);

/// Which half of the table a slot belongs to. A slot never changes sides: an inbound peer
/// cannot end up occupying one of the connections the node's own safety depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    /// Dialled by this node.
    Outbound,
    /// Accepted from the network.
    Inbound,
}

/// What a slot is for. The outbound half is split the way Core splits it, and the split is
/// a security parameter: a block-relay-only connection asks for headers and blocks and
/// gossips nothing, so an attacker who has learned this node's peers from address relay has
/// still learned nothing about these two, and they are the two that are remembered as
/// anchors across a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotRole {
    /// One of the eight outbound connections that also take part in address relay.
    FullRelay,
    /// One of the two outbound connections that ask only for blocks.
    BlockRelayOnly,
    /// A connection somebody else made.
    Inbound,
}

/// A slot's position in the table, `0..32`. Cannot be built out of range, so nothing that
/// holds one has to check it again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotIndex(u8);

impl SlotIndex {
    /// Wraps a slot number.
    pub fn new(index: u8) -> SlotIndex {
        assert!(usize::from(index) < PEER_SLOTS);
        SlotIndex(index)
    }

    /// Wraps a position in the table, which is how the supervisor numbers the peer threads.
    pub fn from_position(position: usize) -> SlotIndex {
        assert!(position < PEER_SLOTS);
        SlotIndex::new(u8::try_from(position).unwrap_or(u8::MAX))
    }

    /// The slot number.
    pub fn get(self) -> usize {
        usize::from(self.0)
    }

    /// Which half of the table the slot at this position belongs to. The first
    /// [`OUTBOUND_SLOTS`] are the node's own connections.
    pub fn kind(self) -> SlotKind {
        if self.get() < OUTBOUND_SLOTS {
            SlotKind::Outbound
        } else {
            SlotKind::Inbound
        }
    }

    /// What the slot is for. The last [`BLOCK_RELAY_SLOTS`] of the outbound half are the
    /// block-relay-only ones, which are also the anchors.
    pub fn role(self) -> SlotRole {
        match self.kind() {
            SlotKind::Inbound => SlotRole::Inbound,
            SlotKind::Outbound if self.get() < OUTBOUND_SLOTS.saturating_sub(BLOCK_RELAY_SLOTS) => {
                SlotRole::FullRelay
            }
            SlotKind::Outbound => SlotRole::BlockRelayOnly,
        }
    }
}

impl std::fmt::Display for SlotIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02}", self.0)
    }
}

/// A live connection, shared by the two threads that serve it.
///
/// One socket, not two halves: `&TcpStream` reads and writes, so the reader and the writer
/// each use it without either owning it, and the shutdown sequence can reach it from a third
/// thread to end both of their blocking calls at once.
#[derive(Clone)]
pub struct Connection {
    /// The socket.
    pub stream: Arc<TcpStream>,
    /// Who is on the other end.
    pub address: SocketAddr,
    /// When the connection was accepted or dialled.
    pub since: Instant,
    /// Which slot holds it, and so what it is for.
    pub index: SlotIndex,
    /// Framed messages waiting for this connection's writer thread. A megabyte, and the
    /// connection ends rather than the queue growing.
    pub outbox: Arc<Outbox>,
    /// The blocks this node has asked this peer for and not been given. The reader reads
    /// its own message-size cap off this, and refuses a block that answers nothing in it.
    pub requests: Arc<Requests>,
    /// Whether the handshake is through. The reader owns the exchange; this is how every
    /// other thread finds out, without asking the reader anything.
    ready: Arc<AtomicBool>,
    /// What the peer said it offers, written by the reader as it reads the `version` and
    /// before the connection is marked ready, so a ready connection always has them. The
    /// download schedule reads them to decide whether this peer can serve a block at all.
    services: Arc<AtomicU64>,
    /// Why the connection ended, set by whichever thread decided. First writer wins: a
    /// write that failed is why the read that follows it returns nothing.
    ended: Arc<Mutex<Option<Disconnect>>>,
}

impl Connection {
    /// Whether the `version`/`verack` exchange has completed. Until it has, this node
    /// neither asks the peer for anything nor answers it anything.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Say the exchange is through. The reader thread's to call, once.
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::SeqCst);
    }

    /// What the peer offers. `NONE` until its `version` has been read.
    pub fn services(&self) -> ServiceFlags {
        ServiceFlags::from(self.services.load(Ordering::SeqCst))
    }

    /// Record what the peer offered. The reader thread's to call, before `mark_ready`.
    pub fn set_services(&self, services: ServiceFlags) {
        self.services.store(services.to_u64(), Ordering::SeqCst);
    }

    /// End the connection from any thread, saying why.
    ///
    /// `shutdown(Both)` is the mechanism: it ends the reader's blocking `read` at once
    /// rather than after the read timeout, and closing the outbox ends the writer's wait.
    /// The slot itself is released by the reader, which is the thread that owns noticing
    /// that a connection is over — and which reports the reason recorded here rather than
    /// the end-of-file it sees, so that a failed write is not logged as a peer hanging up.
    pub fn disconnect(&self, reason: Disconnect) {
        let mut ended = lock(&self.ended);
        if ended.is_none() {
            *ended = Some(reason);
        }
        drop(ended);
        // A socket the peer has already closed answers `ENOTCONN`; nothing to do about it.
        let _shut = self.stream.shutdown(Shutdown::Both);
        self.outbox.close();
    }

    /// Why the connection ended, if a thread has already decided.
    pub fn ended(&self) -> Option<Disconnect> {
        *lock(&self.ended)
    }

    /// The address's network group, for the connector's diversity rule.
    pub fn netgroup(&self) -> [u8; 4] {
        netgroup(self.address)
    }
}

/// One preallocated slot. The struct exists from startup; only the connection in it comes
/// and goes.
pub struct PeerSlot {
    index: SlotIndex,
    state: Mutex<Option<Connection>>,
    changed: Condvar,
}

impl PeerSlot {
    /// Where this slot is in the table.
    pub fn index(&self) -> SlotIndex {
        self.index
    }

    /// Which half of the table it is in.
    pub fn kind(&self) -> SlotKind {
        self.index.kind()
    }
}

/// The whole table, and the counts the accept path checks before it does anything else.
pub struct PeerSlots {
    slots: [PeerSlot; PEER_SLOTS],
    outbound: AtomicUsize,
    inbound: AtomicUsize,
    closing: AtomicBool,
}

impl PeerSlots {
    /// The table, empty, with every slot's mutex and condition variable already built.
    pub fn new() -> PeerSlots {
        PeerSlots {
            slots: std::array::from_fn(|index| PeerSlot {
                // `from_fn` is called once per array position, so the index is exactly the
                // position and is bounded by `PEER_SLOTS`.
                index: SlotIndex::from_position(index),
                state: Mutex::new(None),
                changed: Condvar::new(),
            }),
            outbound: AtomicUsize::new(0),
            inbound: AtomicUsize::new(0),
            closing: AtomicBool::new(false),
        }
    }

    /// How many slots of a kind hold a connection.
    ///
    /// A counter rather than a scan, because this is the first thing `accept` asks and the
    /// answer must not cost thirty-two locks per connection attempt. [`PeerSlots::claim`] is
    /// still the authority: it hands back nothing when the table is genuinely full.
    pub fn occupied(&self, kind: SlotKind) -> usize {
        match kind {
            SlotKind::Outbound => self.outbound.load(Ordering::SeqCst),
            SlotKind::Inbound => self.inbound.load(Ordering::SeqCst),
        }
    }

    /// How many slots of a kind there are.
    pub fn capacity(kind: SlotKind) -> usize {
        match kind {
            SlotKind::Outbound => OUTBOUND_SLOTS,
            SlotKind::Inbound => INBOUND_SLOTS,
        }
    }

    /// Whether a connection of this kind could be taken. Cheap, and only a hint: the answer
    /// can be stale by the time the caller acts on it, which is why `claim` re-checks.
    pub fn has_room(&self, kind: SlotKind) -> bool {
        self.occupied(kind) < PeerSlots::capacity(kind)
    }

    /// Put a connection into the first free slot of its kind, waking the two threads that
    /// were waiting on it. `None` means the table is full and the caller must close the
    /// socket.
    pub fn claim(
        &self,
        kind: SlotKind,
        stream: TcpStream,
        address: SocketAddr,
    ) -> Option<SlotIndex> {
        if self.closing.load(Ordering::SeqCst) {
            return None;
        }
        let stream = Arc::new(stream);
        for slot in self.slots.iter().filter(|slot| slot.kind() == kind) {
            let mut state = lock(&slot.state);
            if state.is_some() {
                continue;
            }
            // Built inside the loop because a connection knows which slot it is in: the
            // reader reads its role off the index, and so do the anchors.
            *state = Some(Connection {
                stream: Arc::clone(&stream),
                address,
                since: Instant::now(),
                index: slot.index(),
                outbox: Arc::new(Outbox::with_bound(OUTBOX_MAX_BYTES)),
                requests: Arc::new(Requests::new()),
                ready: Arc::new(AtomicBool::new(false)),
                services: Arc::new(AtomicU64::new(ServiceFlags::NONE.to_u64())),
                ended: Arc::new(Mutex::new(None)),
            });
            drop(state);
            self.counter(kind).fetch_add(1, Ordering::SeqCst);
            slot.changed.notify_all();
            return Some(slot.index());
        }
        None
    }

    /// Empty a slot. The threads serving it go back to waiting for the next connection.
    pub fn release(&self, index: SlotIndex) {
        let Some(slot) = self.slot(index) else {
            return;
        };
        let mut state = lock(&slot.state);
        let was_occupied = state.take().is_some();
        drop(state);
        if was_occupied {
            self.counter(index.kind()).fetch_sub(1, Ordering::SeqCst);
        }
        slot.changed.notify_all();
    }

    /// Block until this slot has a connection, or until the table is closing.
    ///
    /// A connection already in the slot is handed over even while the table is closing, and
    /// the order of these two checks is that decision: a socket that was claimed between
    /// the shutdown being announced and this thread waking is still a connection somebody
    /// made, and it should be accounted for and reported rather than dropped silently. The
    /// thread that takes it sees the shutdown on its first pass and ends it at once.
    pub fn wait_for_connection(&self, index: SlotIndex) -> Option<Connection> {
        let slot = self.slot(index)?;
        let mut state = lock(&slot.state);
        loop {
            if let Some(connection) = state.clone() {
                return Some(connection);
            }
            if self.closing.load(Ordering::SeqCst) {
                return None;
            }
            state = wait(&slot.changed, state, SLOT_TICK);
        }
    }

    /// Block until this slot is empty again, or until the table is closing. What a writer
    /// does once its peer has gone: the reader owns noticing the end of a connection.
    pub fn wait_until_vacant(&self, index: SlotIndex) {
        let Some(slot) = self.slot(index) else {
            return;
        };
        let mut state = lock(&slot.state);
        while state.is_some() && !self.closing.load(Ordering::SeqCst) {
            state = wait(&slot.changed, state, SLOT_TICK);
        }
    }

    /// Close the table: `shutdown(Both)` on every live socket, and wake everything waiting.
    ///
    /// This is the mechanism the shutdown sequence relies on. A peer thread blocked in
    /// `read` returns immediately once its socket is shut down, rather than after the read
    /// timeout, and a peer that is dribbling one byte at a time does not get to decide how
    /// long the node takes to stop. Returns how many connections were live.
    pub fn shutdown_all(&self) -> usize {
        self.closing.store(true, Ordering::SeqCst);
        let mut live: usize = 0;
        for slot in &self.slots {
            let state = lock(&slot.state);
            if let Some(connection) = state.as_ref() {
                connection.disconnect(Disconnect::NodeStopping);
                live = live.saturating_add(1);
            }
            drop(state);
            slot.changed.notify_all();
        }
        live
    }

    /// The connection in a slot, for the threads that are neither its reader nor its
    /// writer: the chain thread queueing a reply, and the shutdown remembering anchors.
    #[allow(
        dead_code,
        reason = "the chain thread reaches a peer's outbox through this; queueing a reply \
                  is the block server's, BM-24"
    )]
    pub fn connection(&self, index: SlotIndex) -> Option<Connection> {
        let slot = self.slot(index)?;
        let state = lock(&slot.state);
        state.clone()
    }

    /// The network groups the live outbound connections are in.
    ///
    /// The connector's diversity rule reads this before it dials: an attacker who owns one
    /// /16 must not be able to take more than one of the ten connections this node's own
    /// safety depends on. A bounded scan of ten slots, once per dial.
    pub fn outbound_netgroups(&self) -> Vec<[u8; 4]> {
        let mut groups = Vec::with_capacity(OUTBOUND_SLOTS);
        for slot in self
            .slots
            .iter()
            .filter(|slot| slot.kind() == SlotKind::Outbound)
        {
            let state = lock(&slot.state);
            if let Some(connection) = state.as_ref() {
                groups.push(connection.netgroup());
            }
        }
        groups
    }

    /// The addresses of the live block-relay-only connections, which are what a clean stop
    /// writes down as anchors.
    pub fn anchor_addresses(&self) -> Vec<SocketAddr> {
        let mut addresses = Vec::with_capacity(BLOCK_RELAY_SLOTS);
        for slot in self
            .slots
            .iter()
            .filter(|slot| slot.index().role() == SlotRole::BlockRelayOnly)
        {
            let state = lock(&slot.state);
            if let Some(connection) = state.as_ref() {
                addresses.push(connection.address);
            }
        }
        assert!(addresses.len() <= BLOCK_RELAY_SLOTS);
        addresses
    }

    /// Backdate a connection, so that a test can reach the rules that apply only to one
    /// that has been up for a while — Core's `MINIMUM_CONNECT_TIME` among them.
    #[cfg(test)]
    pub fn backdate(&self, index: SlotIndex, by: Duration) {
        let Some(slot) = self.slot(index) else {
            return;
        };
        let mut state = lock(&slot.state);
        if let Some(connection) = state.as_mut() {
            connection.since = connection.since.checked_sub(by).unwrap_or(connection.since);
        }
    }

    /// Whether the table has been closed.
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    /// The slot at a position. A bounded scan rather than an index: this is called once when
    /// a thread starts and once per connection, never per message.
    fn slot(&self, index: SlotIndex) -> Option<&PeerSlot> {
        self.slots.iter().find(|slot| slot.index() == index)
    }

    fn counter(&self, kind: SlotKind) -> &AtomicUsize {
        match kind {
            SlotKind::Outbound => &self.outbound,
            SlotKind::Inbound => &self.inbound,
        }
    }
}

impl Default for PeerSlots {
    fn default() -> PeerSlots {
        PeerSlots::new()
    }
}

#[cfg(test)]
#[path = "slots_tests.rs"]
mod tests;
