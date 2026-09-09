// SPDX-License-Identifier: MIT OR Apache-2.0

//! The four peer-facing thread bodies: the listener, the connector, and a reader and a
//! writer per slot.
//!
//! Each has exactly one place it can block, and each of those places belongs to one peer.
//! The listener blocks in `poll` on its own socket and on the self-pipe. A reader blocks in
//! `read` on its peer's socket, or — the one exception in the node — on the bounded queue
//! to the chain thread, which stops that socket and no other. A writer blocks on its peer's
//! outbox. Nothing here waits on anything a second peer can hold.

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Duration;

use super::discovery::netgroup;
use super::session::Session;
use super::{
    Connection, Disconnect, Frame, Framer, MESSAGE_DEADLINE, READ_BUFFER_INITIAL_BYTES, READ_TICK,
    SlotIndex, SlotKind, WRITE_TIMEOUT,
};
use crate::runtime::Shared;
use crate::runtime::signal::{Cause, SignalPipe, signalled};

/// How long the listener waits in `poll` before looking at the shutdown flag. A signal wakes
/// it through the self-pipe rather than through this, so it costs nothing in the usual case.
const LISTENER_TICK: Duration = Duration::from_secs(1);

/// How long the connector sleeps between passes when there is nothing to dial.
const CONNECTOR_TICK: Duration = Duration::from_millis(500);

/// How long a writer waits for something to send before looking at the shutdown flag.
const WRITER_TICK: Duration = Duration::from_millis(250);

/// How long a dial may take. Core's is sixty seconds for the whole handshake; the connect
/// itself is either quick or the address is not worth an outbound slot.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the connector waits after asking the DNS seeds before asking again. Core waits
/// eleven seconds between groups of three; one pass over a handful of seeds and then a
/// minute is the same discipline at this node's scale.
const SEED_INTERVAL: Duration = Duration::from_secs(60);

/// Accept failures in a row before the node treats the listening socket as lost. Anything
/// an incoming connection can cause — a peer that hangs up between `SYN` and `accept`, a
/// per-process descriptor limit — clears on its own; a socket that fails this many times
/// running is broken, and a node that cannot accept should say so rather than spin.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: usize = 16;

/// Accept connections until the node stops.
///
/// The listener is the one thread that must wait on a descriptor and on a signal at the same
/// time, so it owns the read end of the self-pipe and announces the shutdown for everybody
/// else. Its socket closes when this function returns, which is what stops new connections
/// arriving during a shutdown.
#[allow(
    clippy::needless_pass_by_value,
    reason = "the listener owns its socket: the socket closes when this returns, which is \
              what stops connections arriving during a shutdown"
)]
pub fn listener(shared: &Shared, socket: TcpListener, pipe: &SignalPipe) {
    if let Err(error) = socket.set_nonblocking(true) {
        eprintln!("bitmigo: listener: {error}");
        shared
            .shutdown
            .begin(Cause::Internal("listening socket unusable"));
        return;
    }
    let descriptor = socket.as_raw_fd();
    let mut errors: usize = 0;

    while !shared.shutdown.is_begun() {
        let woken = match pipe.wait(descriptor, LISTENER_TICK) {
            Ok(woken) => woken,
            Err(error) => {
                eprintln!("bitmigo: listener: {error}");
                shared
                    .shutdown
                    .begin(Cause::Internal("listener cannot wait"));
                break;
            }
        };
        if woken.signalled {
            let cause = signalled().map_or(Cause::Internal("shutdown requested"), Cause::Signal);
            shared.shutdown.begin(cause);
            break;
        }
        if woken.socket_ready {
            errors = accept_one(shared, &socket, errors);
            if errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                shared
                    .shutdown
                    .begin(Cause::Internal("listening socket failing"));
                break;
            }
        }
    }
}

/// Take one connection, and answer the only question that matters before the node has read
/// a single byte from it: is there a slot?
fn accept_one(shared: &Shared, socket: &TcpListener, errors: usize) -> usize {
    match socket.accept() {
        Ok((stream, address)) => {
            // The slot count first. An anonymous peer gets no buffer, no timer and no
            // thread of ours until the table says it can have one; a full table is answered
            // by closing the socket, not by evicting somebody who is already connected.
            if !shared.slots.has_room(SlotKind::Inbound) {
                drop(stream);
                return 0;
            }
            if let Err(error) = configure(&stream) {
                eprintln!("bitmigo: {address}: {error}");
                drop(stream);
                return 0;
            }
            // A claim that comes back empty lost the last slot to another connection
            // between the check and the claim, and the socket closed as it gave up on it.
            if let Some(index) = shared.slots.claim(SlotKind::Inbound, stream, address) {
                println!("bitmigo: peer {index} in from {address}");
            }
            0
        }
        // Nothing waiting after all: `poll` and `accept` are two syscalls, and the
        // connection can be withdrawn between them.
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
        Err(error) => {
            eprintln!("bitmigo: accept: {error}");
            errors.saturating_add(1)
        }
    }
}

/// The socket options every peer connection gets. The read timeout is what bounds a thread
/// that is waiting on a peer that has stopped talking; the write timeout is what bounds one
/// waiting on a peer that has stopped listening.
fn configure(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(READ_TICK))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    // Block download is request/response and latency-sensitive; there is nothing to coalesce.
    stream.set_nodelay(true)?;
    Ok(())
}

/// Dial outbound peers until the node stops.
///
/// Anchors first, because they are the only addresses this node has evidence about; then
/// whatever else is on the queue; then the DNS seeds, and only when the queue cannot supply
/// the two outbound connections Core's `SEED_OUTBOUND_CONNECTION_THRESHOLD` names. The one
/// rule applied to every candidate is netgroup diversity: an attacker who owns a /16 gets
/// one of these ten slots, not several.
pub fn connector(shared: &Shared) {
    let loaded = shared.candidates.load_anchors();
    if loaded > 0 {
        println!("bitmigo: {loaded} anchors to dial first");
    }
    let mut seeded_at: Option<std::time::Instant> = None;

    while !shared.shutdown.is_begun() {
        if shared.slots.has_room(SlotKind::Outbound) {
            match shared.candidates.next() {
                Some(address) => dial(shared, address),
                None => seed(shared, &mut seeded_at),
            }
        }
        // Nothing to do is the ordinary case: ten connections, and they last.
        if shared.shutdown.wait_timeout(CONNECTOR_TICK).is_some() {
            break;
        }
    }
}

/// Ask the DNS seeds, at most once per [`SEED_INTERVAL`], and only while this node has
/// fewer outbound connections than it takes to bootstrap from the network itself.
fn seed(shared: &Shared, seeded_at: &mut Option<std::time::Instant>) {
    if shared.slots.occupied(SlotKind::Outbound) >= super::discovery::SEED_OUTBOUND_THRESHOLD {
        return;
    }
    if seeded_at.is_some_and(|at| at.elapsed() < SEED_INTERVAL) {
        return;
    }
    *seeded_at = Some(std::time::Instant::now());
    let found = shared.candidates.query_seeds();
    if found > 0 {
        println!(
            "bitmigo: {found} addresses from the DNS seeds, {} to dial",
            shared.candidates.len(),
        );
    }
}

/// Dial one address, if it is worth an outbound slot.
fn dial(shared: &Shared, address: SocketAddr) {
    // The diversity rule, checked before the connect rather than after: an address in a
    // group this node is already connected to buys nothing and costs a slot.
    if shared
        .slots
        .outbound_netgroups()
        .contains(&netgroup(address))
    {
        return;
    }
    let Ok(stream) = TcpStream::connect_timeout(&address, DIAL_TIMEOUT) else {
        return;
    };
    if configure(&stream).is_err() {
        drop(stream);
        return;
    }
    if let Some(index) = shared.slots.claim(SlotKind::Outbound, stream, address) {
        println!("bitmigo: peer {index} out to {address}");
    }
}

/// Serve one slot's reads, connection after connection, until the node stops.
///
/// One blocking point, the socket, and it belongs to one peer. A peer that sends a byte an
/// hour holds up this thread and nothing else, which is the property the whole layout was
/// chosen for.
pub fn reader(shared: &Shared, index: SlotIndex) {
    // Allocated once for the life of the thread, never from a length a peer declared. It
    // grows to the size a block needs the first time this slot is asked for one, and stays
    // that size: a reader that has handled one block will handle another.
    let mut framer = Framer::new(
        shared.network.magic(),
        READ_BUFFER_INITIAL_BYTES,
        MESSAGE_DEADLINE,
    );

    // The connection first, and the shutdown flag second: this thread may be scheduled for
    // the first time *after* a shutdown has been announced, and a socket already in its
    // slot is one somebody made and one the node counted. Serving it costs a pass through
    // the loop below, which returns at its first check — and the connection is reported and
    // released rather than dropped without a word.
    while let Some(connection) = shared.slots.wait_for_connection(index) {
        framer.reset();
        let mut session = Session::new(shared, &connection);
        let reason = serve(shared, &connection, &mut session, &mut framer);
        end(&connection, &session, reason);
        shared.slots.release(index);
    }
}

/// One connection, from the opening `version` to the reason it ended.
fn serve(
    shared: &Shared,
    connection: &Connection,
    session: &mut Session<'_>,
    framer: &mut Framer,
) -> Disconnect {
    if let Err(reason) = session.open() {
        return reason;
    }
    loop {
        if shared.shutdown.is_begun() || shared.slots.is_closing() {
            return Disconnect::NodeStopping;
        }
        // The writer closes the outbox when a write fails, and `Outbox::push` closes it
        // when a peer stops reading; either way the connection is over and the reader is
        // the thread that says so.
        if connection.outbox.is_closed() {
            return Disconnect::OutboxFull;
        }
        if let Err(reason) = session.tick() {
            return reason;
        }
        match framer.read(&connection.stream, session.cap()) {
            Ok(Frame::Message(message, wire_len)) => {
                if let Err(reason) = session.receive(message, wire_len) {
                    return reason;
                }
            }
            Ok(Frame::Idle) => {}
            // A read that returns zero during a shutdown is this node's own
            // `shutdown(Both)` arriving, not the peer hanging up; saying so keeps the log
            // line honest about who ended the connection.
            Ok(Frame::Eof) => {
                return if shared.shutdown.is_begun() || shared.slots.is_closing() {
                    Disconnect::NodeStopping
                } else {
                    Disconnect::PeerClosed
                };
            }
            Err(error) => return Disconnect::Wire(error),
        }
    }
}

/// Close one connection down and say why, in one line an operator can read.
fn end(connection: &Connection, session: &Session<'_>, reason: Disconnect) {
    // Whoever decided first is who ended it: a write that failed is the reason the read
    // after it returned nothing, and reporting the read would blame the wrong side.
    let reason = connection.ended().unwrap_or(reason);
    connection.disconnect(reason);
    let given_up = connection.requests.clear();
    let blamed = if reason.misbehaving() {
        " (misbehaving)"
    } else {
        ""
    };
    // The peer's own name only once it has given one: before the handshake there is none,
    // and a blank where a name would go says nothing.
    let named = match session.peer_user_agent() {
        "" => String::new(),
        agent => format!(" {agent}"),
    };
    let returned = if given_up > 0 {
        format!(", {given_up} blocks back to the scheduler")
    } else {
        String::new()
    };
    println!(
        "bitmigo: peer {} gone: {reason}{blamed}, {} messages in {:?} from {}{named}{returned}",
        connection.index,
        session.received(),
        connection.since.elapsed(),
        connection.address,
    );
}

/// Serve one slot's writes until the node stops.
///
/// The writer's blocking point is its outbound queue, not its socket: a megabyte of queued
/// messages per peer, and a peer that lets that fill is disconnected rather than allowed to
/// slow the thread that produced them.
pub fn writer(shared: &Shared, index: SlotIndex) {
    // Paired with the reader's loop, and for the same reason: the table closing is what
    // ends both, so that the two threads serving one slot always agree about it.
    while let Some(connection) = shared.slots.wait_for_connection(index) {
        drain(shared, &connection);
        // The reader owns noticing that a connection is over and releasing the slot; this
        // thread waits for it to, so that the two never serve different connections.
        shared.slots.wait_until_vacant(index);
    }
}

/// Write queued frames until the connection ends.
fn drain(shared: &Shared, connection: &Connection) {
    while !shared.shutdown.is_begun() {
        match connection.outbox.pop(WRITER_TICK) {
            Some(frame) => {
                // `&TcpStream` writes without owning the socket, so the shutdown sequence
                // can end this call from another thread.
                if let Err(error) = (&*connection.stream).write_all(&frame) {
                    eprintln!("bitmigo: peer {}: write: {error}", connection.index);
                    // The reader is blocked in `read`; shutting the socket down is what
                    // ends that call now rather than at the read timeout, and the reason
                    // recorded here is what it reports.
                    connection.disconnect(Disconnect::WriteFailed);
                    break;
                }
            }
            None if connection.outbox.is_closed() => break,
            None => {}
        }
    }
}
