// SPDX-License-Identifier: MIT OR Apache-2.0

//! Peer slots and the threads that serve them.
//!
//! Thirty-two connections, preallocated at startup with two threads each: a reader that has
//! exactly one blocking point, its socket, and a writer that has exactly one, its outbound
//! queue. Neither shares a thread with another peer, so a peer that stops reading, sends
//! slowly, or sends nothing at all costs its own connection and no other.
//!
//! The split between outbound and inbound is a security parameter, not a resource one.
//! Outbound connections are the ones that decide whether the node can be eclipsed, so their
//! count is fixed and their slots are never given away to an inbound peer. Inbound
//! connections are pure service: an attacker who fills all of them denies third parties, not
//! this node, which is why a full inbound table is answered by closing the socket rather
//! than by evicting somebody.
//!
//! Everything below the `accept` is written against a hostile sender. That is what the
//! denials at the top of this module are for: no indexing, no `unwrap`, no `expect`, no
//! `panic!`, and no arithmetic that can wrap or overflow — a parse path is a `Result` by
//! construction. Assertions stay, because an assertion is a claim about this node's own
//! invariants rather than about what arrived on the wire.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

mod net;
mod slots;

pub use net::{connector, listener, reader, writer};
pub use slots::{Connection, PeerSlots, SlotIndex, SlotKind};

/// Connection slots, and so half the node's threads.
pub const PEER_SLOTS: usize = 32;

/// Outbound connections: Bitcoin Core's eclipse-resistance budget exactly — eight full-relay
/// peers in distinct network groups and two block-relay-only, two of which are anchors
/// remembered across restarts. This number answers a security question and is not a dial.
pub const OUTBOUND_SLOTS: usize = 10;

/// Inbound connections. Service to the network, and the only slots an anonymous peer can
/// take: filling them all denies other people's nodes, not this one.
pub const INBOUND_SLOTS: usize = 22;

const _: () = assert!(OUTBOUND_SLOTS + INBOUND_SLOTS == PEER_SLOTS);

/// The stack a peer thread gets. Stated rather than inherited: sixty-four threads at the
/// two megabytes a thread would otherwise take is a hundred and twenty-eight megabytes of
/// address space reserved for straight-line code that never recurses.
pub const PEER_THREAD_STACK_BYTES: usize = 512 * 1024;

/// How the supervisor names a peer reader. The inbound queue asserts on this: a reader may
/// block on a full queue and no other thread may.
pub const READER_THREAD_PREFIX: &str = "peer-reader-";

/// How the supervisor names a peer writer.
pub const WRITER_THREAD_PREFIX: &str = "peer-writer-";

/// `SO_RCVTIMEO`. A tick, not an error: it bounds how long a reader can sit in a `read` it
/// will never be woken from. The mechanism that ends a read at shutdown is `shutdown(Both)`
/// on the socket; this is the backstop behind it.
pub const READ_TICK: Duration = Duration::from_secs(1);

/// `SO_SNDTIMEO`. A write that has not completed in a minute is a peer that is not reading,
/// and the connection goes.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// The read buffer a peer thread allocates once and keeps. It grows to the size the protocol
/// allows only while a message that large is legitimately expected; the allocation is never
/// made from a length an anonymous peer declared.
pub const READ_BUFFER_INITIAL_BYTES: usize = 64 * 1024;
