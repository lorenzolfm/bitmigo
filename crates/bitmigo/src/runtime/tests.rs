// SPDX-License-Identifier: MIT OR Apache-2.0

//! The runtime driven to its bounds: the whole table started and stopped, the inbound half
//! of the slot table filled past the end, and the backpressure taken in the order it is
//! supposed to arrive in.

use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread::{self, Builder};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget};
use bitmigo_consensus::header::Context;
use bitmigo_consensus::params::{BlockTime, Chain, ChainParams, Height, RegtestOverrides};

use super::{Config, Runtime, Shared, THREAD_COUNT, THREAD_TABLE};
use crate::peer::{INBOUND_SLOTS, READER_THREAD_PREFIX, SlotIndex, SlotKind};
use crate::runtime::queue::{
    BlockLocation, CHAIN_TO_VALIDATION_MAX_JOBS, ConnectJob, JobKind, PEER_TO_CHAIN_MAX_BYTES,
    PEER_TO_CHAIN_MAX_ITEMS, PeerMessage, Received, Sent,
};
use crate::runtime::signal::{Cause, SignalPipe};

/// The largest message the protocol allows, which is what the inbound queue is bounded in
/// bytes for: a thousand of these would be four gigabytes.
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Wait for something to become true, or give up. Every wait in the tests is bounded.
fn within<P: Fn() -> bool>(limit: Duration, predicate: P) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    predicate()
}

fn job(height: u32) -> ConnectJob {
    let params = ChainParams::regtest(RegtestOverrides::default());
    let hash = BlockHash::all_zeros();
    let height = Height::new(height);
    ConnectJob {
        kind: JobKind::Connect,
        hash,
        context: Context::new(
            height,
            BlockTime::new(1_296_688_602),
            BlockTime::new(1_296_688_602),
            CompactTarget::from_consensus(0x207f_ffff),
            params.rules_at(height, hash, None),
        ),
        location: BlockLocation {
            file: 0,
            offset: 8,
            len: 285,
        },
    }
}

#[test]
fn the_table_accounts_for_every_thread_the_node_runs() {
    let counted: usize = THREAD_TABLE.iter().map(|row| row.count).sum();
    assert_eq!(counted, THREAD_COUNT);
    assert_eq!(THREAD_COUNT, 69);
    for row in &THREAD_TABLE {
        assert!(row.count > 0);
        assert!(row.stack_bytes >= 512 * 1024);
    }
}

#[test]
fn a_node_starts_its_whole_table_refuses_a_full_table_and_stops() {
    let config = Config {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        chain: Chain::Regtest,
        join_deadline: Duration::from_secs(5),
    };
    let pipe = SignalPipe::detached().expect("a test pipe");
    let runtime = Runtime::start(&config, pipe).expect("the node starts");
    let shared = Arc::clone(runtime.shared());
    let address = runtime.listen_address();
    assert_ne!(address.port(), 0);

    // Every inbound slot, and not one more.
    let mut peers = Vec::with_capacity(INBOUND_SLOTS);
    for _ in 0..INBOUND_SLOTS {
        peers.push(TcpStream::connect(address).expect("the node accepts"));
    }
    assert!(
        within(Duration::from_secs(5), || shared
            .slots
            .occupied(SlotKind::Inbound)
            == INBOUND_SLOTS),
        "the table filled",
    );

    // The next connection is closed straight away: the slot count is checked before the
    // node reads a byte, and a full table is answered by closing rather than by evicting.
    let refused = TcpStream::connect(address).expect("the listener still accepts");
    refused
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a test socket");
    let mut buffer = [0u8; 8];
    assert_eq!(
        (&refused).read(&mut buffer).ok(),
        Some(0),
        "a refused peer sees end of stream, not a hang",
    );
    // The peers already connected were not disturbed by it.
    assert_eq!(shared.slots.occupied(SlotKind::Inbound), INBOUND_SLOTS);
    assert_eq!(shared.slots.occupied(SlotKind::Outbound), 0);

    shared.shutdown.begin(Cause::Internal("test"));
    let report = runtime.shutdown(config.join_deadline);
    assert_eq!(report.joined, THREAD_COUNT, "{report}");
    assert!(report.outstanding.is_empty(), "{report}");
    drop(peers.pop());
}

#[test]
fn the_pipeline_degrades_backwards_from_validation_to_tcp() {
    let shared = Arc::new(Shared::new(Chain::Regtest));

    // 1. Validation stalls — a long connect, or a flush of the coin cache. Nothing pulls,
    //    so the connect queue fills to its bound.
    for height in 1..=CHAIN_TO_VALIDATION_MAX_JOBS {
        let height = u32::try_from(height).expect("a small height");
        assert!(shared.to_validation.try_push(job(height)).is_ok());
    }
    assert_eq!(shared.to_validation.len(), CHAIN_TO_VALIDATION_MAX_JOBS);
    assert_eq!(shared.to_validation.room(), 0);

    // 2. The chain thread's only move is to stop topping up. It does not block, and it does
    //    not drop the job: it hands it back to itself.
    let kept = shared.to_validation.try_push(job(65));
    assert!(
        kept.is_err(),
        "the chain thread never blocks on a full queue"
    );

    // 3. Not consuming is what fills the inbound queue, and it fills by bytes: blocks are
    //    four megabytes and the item bound is a thousand.
    let mut queued: usize = 0;
    while shared
        .to_chain
        .try_send(PeerMessage {
            peer: SlotIndex::new(0),
            bytes: vec![0u8; MAX_MESSAGE_BYTES],
        })
        .is_ok()
    {
        queued = queued.saturating_add(1);
        assert!(
            queued <= PEER_TO_CHAIN_MAX_ITEMS,
            "the byte bound binds first"
        );
    }
    assert!(queued >= 7, "roughly 32 MB of 4 MB messages: {queued}");
    assert!(shared.to_chain.bytes() <= PEER_TO_CHAIN_MAX_BYTES);
    assert!(shared.to_chain.len() < PEER_TO_CHAIN_MAX_ITEMS);

    // 4. Only now does anything block, and only a peer reader — which is exactly the thread
    //    whose peer is sending faster than the node can validate. TCP does the rest.
    let sending = Arc::clone(&shared);
    let reader = Builder::new()
        .name(format!("{READER_THREAD_PREFIX}00"))
        .spawn(move || {
            sending.to_chain.send(PeerMessage {
                peer: SlotIndex::new(0),
                bytes: vec![0u8; MAX_MESSAGE_BYTES],
            })
        })
        .expect("a test thread");

    thread::sleep(Duration::from_millis(50));
    assert_eq!(shared.to_chain.len(), queued, "the reader is still waiting");

    // 5. The chain thread takes one message, and the pipeline moves again.
    assert!(matches!(
        shared.to_chain.recv(Duration::from_millis(500)),
        Received::Item(_)
    ));
    let sent = reader.join().expect("the reader returns");
    assert!(
        matches!(sent, Ok(Sent::AfterWaiting(_))),
        "the send was backpressure, not a drop: {sent:?}",
    );
    assert_eq!(shared.to_chain.len(), queued);
}
