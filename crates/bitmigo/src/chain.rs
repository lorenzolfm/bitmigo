// SPDX-License-Identifier: MIT OR Apache-2.0

//! The chain thread.
//!
//! It owns the header tree, the block index, the download schedule, the in-flight map and
//! the block store's single write. Nothing else writes any of those, so none of them is
//! behind a lock, and the thread is a plain loop over one queue.
//!
//! The header tree, the schedule and the store are each their own module and each their own
//! piece of work; what is settled here is the loop they will hang from, and the two rules it
//! obeys. The chain thread never blocks on a full queue: when the validation thread is
//! behind, it stops topping up and lets the blocks pile up behind it. And it publishes its
//! summary of itself rather than letting anything read its state.

use std::time::Duration;

use crate::runtime::Shared;
use crate::runtime::queue::{PeerMessage, Received};

/// How long the thread waits for a message before looking at the shutdown flag and its
/// schedule again. Both a message and a shutdown wake it directly; this bounds the wait.
const CHAIN_TICK: Duration = Duration::from_millis(250);

/// Run until the node stops.
pub fn run(shared: &Shared) {
    let mut received: u64 = 0;
    while !shared.shutdown.is_begun() {
        match shared.to_chain.recv(CHAIN_TICK) {
            Received::Item(message) => {
                received = received.saturating_add(1);
                record(shared, message);
            }
            Received::Empty => {}
            Received::Closed => break,
        }
        schedule(shared);
        publish(shared);
    }
    flush(shared);
    // Validation stops when the shutdown is announced, but closing the queue behind it says
    // so plainly: nothing further will be scheduled.
    shared.to_validation.close();
    println!("bitmigo: chain stopped after {received} messages");
}

/// Take one message from a peer reader.
///
/// What arrives has already been through the receipt-time checks, on the reader's own thread
/// and against the context that travelled with the request, so this side is bookkeeping:
/// accept the header into the tree, write the block's raw bytes to the store exactly as they
/// arrived, move the block's status along, and clear it from the in-flight map. Those are
/// the header tree's and the block store's work; the queue and the thread are here.
fn record(shared: &Shared, message: PeerMessage) {
    let _ = shared;
    drop(message);
}

/// Top the connect queue up while the connectable prefix advances and there is room.
///
/// Pull-shaped on purpose: the answer to a full queue is to do nothing, not to wait. The
/// scheduler that decides which blocks to ask which peers for, and the walk along the
/// connectable prefix, arrive with the download module.
fn schedule(shared: &Shared) {
    let _room = shared.to_validation.room();
}

/// Publish what an operator may see: never the thread's own state, always a copy of it.
fn publish(shared: &Shared) {
    let mut status = shared.status.read();
    status.peers = shared
        .slots
        .occupied(crate::peer::SlotKind::Outbound)
        .saturating_add(shared.slots.occupied(crate::peer::SlotKind::Inbound));
    status.queued_messages = shared.to_chain.len();
    status.queued_bytes = shared.to_chain.bytes();
    shared.status.publish(status);
}

/// Get the block store and its index onto the disk before the process ends.
///
/// The store's `fsync` goes here, in the order the storage engine states: files, then index.
/// Doing it on a clean stop is what keeps crash recovery a backstop rather than the ordinary
/// path — every Ctrl-C would otherwise replay every block since the last periodic flush.
fn flush(shared: &Shared) {
    let _ = shared;
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::peer::{READER_THREAD_PREFIX, SlotIndex, SlotKind};
    use crate::runtime::Shared;
    use crate::runtime::queue::PeerMessage;
    use crate::runtime::signal::Cause;
    use bitcoin::p2p::message::NetworkMessage;
    use bitmigo_consensus::params::Chain;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread::{self, Builder};
    use std::time::{Duration, Instant};

    /// Run the chain thread under the name the supervisor gives it.
    fn spawn_chain(shared: &Arc<Shared>) -> thread::JoinHandle<()> {
        let running = Arc::clone(shared);
        Builder::new()
            .name("chain".to_owned())
            .spawn(move || run(&running))
            .expect("a test thread")
    }

    #[test]
    fn the_chain_thread_drains_what_the_readers_send_it() {
        let shared = Arc::new(Shared::testing(Chain::Regtest));
        let chain = spawn_chain(&shared);

        let sending = Arc::clone(&shared);
        let reader = Builder::new()
            .name(format!("{READER_THREAD_PREFIX}00"))
            .spawn(move || {
                for _ in 0..64 {
                    sending
                        .to_chain
                        .send(PeerMessage::new(
                            SlotIndex::new(0),
                            NetworkMessage::Ping(7),
                            1024,
                        ))
                        .expect("the queue is open");
                }
            })
            .expect("a test thread");
        reader.join().expect("the reader finishes");

        // Everything sent is taken: the queue empties even though nothing else is running.
        let deadline = Instant::now() + Duration::from_secs(5);
        while shared.to_chain.len() > 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(shared.to_chain.len(), 0);

        shared.shutdown.begin(Cause::Internal("test"));
        shared.to_chain.close();
        chain.join().expect("the chain thread stops");
    }

    #[test]
    fn the_operator_sees_the_peer_count_through_the_published_snapshot() {
        let shared = Arc::new(Shared::testing(Chain::Regtest));
        let listener = TcpListener::bind("127.0.0.1:0").expect("a test socket");
        let address = listener.local_addr().expect("a bound address");
        let _client = TcpStream::connect(address).expect("a test connection");
        let (server, peer) = listener.accept().expect("a test connection");
        assert!(
            shared
                .slots
                .claim(SlotKind::Inbound, server, peer)
                .is_some()
        );

        let chain = spawn_chain(&shared);
        let deadline = Instant::now() + Duration::from_secs(5);
        while shared.status.read().peers == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(shared.status.read().peers, 1);

        shared.shutdown.begin(Cause::Internal("test"));
        shared.to_chain.close();
        chain.join().expect("the chain thread stops");
    }
}
