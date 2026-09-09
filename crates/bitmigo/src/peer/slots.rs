// SPDX-License-Identifier: MIT OR Apache-2.0

//! The slot table: thirty-two preallocated connection slots, and the handshake between the
//! thread that puts a socket into one and the two threads that were already waiting on it.

use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::{INBOUND_SLOTS, OUTBOUND_SLOTS, PEER_SLOTS};
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
        let connection = Connection {
            stream: Arc::new(stream),
            address,
            since: Instant::now(),
        };
        for slot in self.slots.iter().filter(|slot| slot.kind() == kind) {
            let mut state = lock(&slot.state);
            if state.is_some() {
                continue;
            }
            *state = Some(connection);
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
    pub fn wait_for_connection(&self, index: SlotIndex) -> Option<Connection> {
        let slot = self.slot(index)?;
        let mut state = lock(&slot.state);
        loop {
            if self.closing.load(Ordering::SeqCst) {
                return None;
            }
            if let Some(connection) = state.clone() {
                return Some(connection);
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
                // A socket the peer has already closed answers `ENOTCONN`; there is nothing
                // to do about that and nothing to report.
                let _shut = connection.stream.shutdown(Shutdown::Both);
                live = live.saturating_add(1);
            }
            drop(state);
            slot.changed.notify_all();
        }
        live
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
