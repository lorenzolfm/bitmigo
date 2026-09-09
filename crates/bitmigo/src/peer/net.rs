// SPDX-License-Identifier: MIT OR Apache-2.0

//! The four peer-facing thread bodies: the listener, the connector, and a reader and a
//! writer per slot.
//!
//! What is settled here is the shape — which thread blocks where, what happens when the
//! table is full, and how a blocking call ends at shutdown. The protocol itself, from the
//! version handshake through framing to the receipt-time checks a reader performs against
//! the context that came with its request, is the peer module's next layer and is called out
//! where it will attach.

use std::io::Read;
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::time::Duration;

use super::{Connection, READ_BUFFER_INITIAL_BYTES, READ_TICK, SlotIndex, SlotKind, WRITE_TIMEOUT};
use crate::runtime::Shared;
use crate::runtime::queue::PeerMessage;
use crate::runtime::signal::{Cause, SignalPipe, signalled};

/// How long the listener waits in `poll` before looking at the shutdown flag. A signal wakes
/// it through the self-pipe rather than through this, so it costs nothing in the usual case.
const LISTENER_TICK: Duration = Duration::from_secs(1);

/// How long the connector sleeps between passes. Dialling has nothing to do yet.
const CONNECTOR_TICK: Duration = Duration::from_millis(500);

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
fn configure(stream: &std::net::TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(READ_TICK))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    // Block download is request/response and latency-sensitive; there is nothing to coalesce.
    stream.set_nodelay(true)?;
    Ok(())
}

/// Dial outbound peers until the node stops.
///
/// The thread exists from startup because every thread does, and because the slots it will
/// fill are already there. What it will do — read the anchors written at the last clean
/// stop, ask the address manager for candidates in distinct network groups, fall back to the
/// DNS seeds, and hand each connected socket to [`super::PeerSlots::claim`] — arrives with
/// the peer protocol, which is also what defines a connection as finished.
pub fn connector(shared: &Shared) {
    while shared.shutdown.wait_timeout(CONNECTOR_TICK).is_none() {}
}

/// Serve one slot's reads, connection after connection, until the node stops.
///
/// One blocking point, the socket, and it belongs to one peer. A peer that sends a byte an
/// hour holds up this thread and nothing else, which is the property the whole layout was
/// chosen for.
pub fn reader(shared: &Shared, index: SlotIndex) {
    // Allocated once for the life of the thread, never from a length a peer declared.
    let mut buffer = vec![0u8; READ_BUFFER_INITIAL_BYTES];

    while !shared.shutdown.is_begun() {
        let Some(connection) = shared.slots.wait_for_connection(index) else {
            break;
        };
        let read = drain(shared, index, &connection, buffer.as_mut_slice());
        println!(
            "bitmigo: peer {index} gone after {read} bytes in {:?} from {}",
            connection.since.elapsed(),
            connection.address,
        );
        shared.slots.release(index);
    }
}

/// Read until the peer goes away or the node stops, handing what arrives to the chain thread.
///
/// What crosses to the chain thread today is the bytes as they were read. Framing them into
/// messages under the protocol's own bounds, deserializing them, and running the receipt-time
/// header and block checks against the context that came with the request all belong between
/// the read and the send, on this thread, so that a garbage block is paid for by the thread
/// of the peer that sent it. What is already settled is the end of the path: the send below
/// is the only place in the node where a thread may wait for room on a queue, and it waits
/// here because waiting here stops one socket and no other.
fn drain(shared: &Shared, index: SlotIndex, connection: &Connection, buffer: &mut [u8]) -> u64 {
    let mut total: u64 = 0;
    while !shared.shutdown.is_begun() && !shared.slots.is_closing() {
        // `&TcpStream` reads without owning the socket, so the shutdown sequence can end
        // this call from another thread.
        let read = match (&*connection.stream).read(buffer) {
            // The peer closed, or `shutdown(Both)` reached the socket.
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => match error.kind() {
                // The read timeout: a tick, not an error.
                std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Interrupted => continue,
                _ => break,
            },
        };
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let message = PeerMessage {
            peer: index,
            bytes: buffer.get(..read).unwrap_or_default().to_vec(),
        };
        if shared.to_chain.send(message).is_err() {
            // The node is stopping and nothing will read the queue again.
            break;
        }
    }
    total
}

/// Serve one slot's writes until the node stops.
///
/// The writer's blocking point is its outbound queue, not its socket: a megabyte of queued
/// messages per peer, and a peer that lets that fill is disconnected rather than allowed to
/// slow the thread that produced them. The queue, the messages, and answering `getdata` by
/// reading a block's raw bytes straight off the disk arrive with the protocol; what the
/// thread does today is hold its half of the slot.
pub fn writer(shared: &Shared, index: SlotIndex) {
    while !shared.shutdown.is_begun() {
        if shared.slots.wait_for_connection(index).is_none() {
            break;
        }
        shared.slots.wait_until_vacant(index);
    }
}
