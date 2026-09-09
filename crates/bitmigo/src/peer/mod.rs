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

mod disconnect;
mod discovery;
mod handshake;
mod net;
mod network;
mod outbox;
mod requests;
mod session;
mod slots;
mod wire;

pub use disconnect::Disconnect;
pub use discovery::{Candidates, MAX_ANCHORS};
pub use handshake::{Handshake, nonce};
pub use net::{connector, listener, reader, writer};
pub use network::Network;
pub use outbox::Outbox;
pub use requests::{BlockRequest, MAX_BLOCKS_IN_FLIGHT, Requests};
pub use slots::{Connection, PeerSlots, SlotIndex, SlotKind, SlotRole};
pub use wire::{
    Frame, Framer, MAX_HEADERS_ITEMS, MAX_INV_ITEMS, MAX_LOCATOR_ITEMS, MAX_MESSAGE_LEN, encode,
};

/// Connection slots, and so half the node's threads.
pub const PEER_SLOTS: usize = 32;

/// Outbound connections: Bitcoin Core's eclipse-resistance budget exactly — eight full-relay
/// peers in distinct network groups and two block-relay-only, two of which are anchors
/// remembered across restarts. This number answers a security question and is not a dial.
pub const OUTBOUND_SLOTS: usize = 10;

/// Inbound connections. Service to the network, and the only slots an anonymous peer can
/// take: filling them all denies other people's nodes, not this one.
pub const INBOUND_SLOTS: usize = 22;

/// How many of the outbound connections ask for blocks and nothing else. Core's
/// `MAX_BLOCK_RELAY_ONLY_CONNECTIONS`, and the same two are its `MAX_BLOCK_RELAY_ONLY_ANCHORS`:
/// a connection that never takes part in address relay is one an attacker who has poisoned
/// this node's address table has not learned about, and remembering it across a restart is
/// what stops an eclipse from surviving one.
pub const BLOCK_RELAY_SLOTS: usize = 2;

const _: () = assert!(BLOCK_RELAY_SLOTS < OUTBOUND_SLOTS);

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

/// What a peer may make this node hold when it owes us nothing.
///
/// A uniform four-megabyte cap would let thirty-two peers force a hundred and twenty-eight
/// megabytes of attacker-chosen buffer. The only message that legitimately reaches four
/// megabytes is a `block`, and a headers-first node never has to accept a block it did not
/// ask for — so the full cap applies only to a peer with an outstanding `getdata`, and an
/// inbound peer, which is never asked for anything until it has proved useful, can never
/// push this node past half a megabyte. With `fRelay = 0` there are no transaction
/// inventories, so nothing else comes close (BM-D5 decision 4).
pub const READ_CAP_IDLE: usize = 512 * 1024;

/// First header byte to last payload byte. A peer that spreads one message over longer than
/// this is the dribbler no per-read timeout can catch: it defeats [`READ_TICK`] by sending
/// one byte a second forever, and costs a thread for as long as it does.
pub const MESSAGE_DEADLINE: Duration = Duration::from_secs(120);

/// Core's `PING_INTERVAL`: how long a quiet connection waits before this node pings it.
pub const PING_INTERVAL: Duration = Duration::from_secs(120);

/// Core's `TIMEOUT_INTERVAL`: silence, or an unanswered ping, for this long is a peer that
/// has gone away without saying so.
pub const PEER_TIMEOUT: Duration = Duration::from_mins(20);

/// Core's `DEFAULT_PEER_CONNECT_TIMEOUT`: a connection that has not finished the handshake
/// in this long is dropped. It is the bound on how long an anonymous peer can hold a slot
/// without having said anything at all.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Core's `DEFAULT_MAXSENDBUFFER`, per peer. Core pauses the sender when the buffer fills;
/// this node disconnects instead, because everything it queues is a reply nobody is waiting
/// on and a peer that will not read is not worth a megabyte.
pub const OUTBOX_MAX_BYTES: usize = 1024 * 1024;

/// The protocol version this node advertises: Core's `PROTOCOL_VERSION` at v31.1, not the
/// `bitcoin` crate's 70001, which is below every feature gate from `SENDHEADERS_VERSION` up
/// (R4 §6.3).
pub const PROTOCOL_VERSION: u32 = 70_016;

/// Core's `MIN_PEER_PROTO_VERSION`: "disconnect from peers older than this proto version".
pub const MIN_PEER_PROTO_VERSION: u32 = 31_800;

/// What this node tells a peer it is. Bitcoin's convention, and the version this crate
/// carries: a peer that has to work around us should be able to tell which release it is.
pub const USER_AGENT: &str = concat!("/bitmigo:", env!("CARGO_PKG_VERSION"), "/");
