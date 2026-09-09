// SPDX-License-Identifier: MIT OR Apache-2.0

//! The chain thread: what it takes off the queue, what it puts in the snapshot, and what it
//! does to a peer that sends it a header with no work behind it.

use super::{fixture, node_time, run};
use crate::peer::{Disconnect, READER_THREAD_PREFIX, SlotIndex, SlotKind};
use crate::runtime::Shared;
use crate::runtime::queue::PeerMessage;
use crate::runtime::signal::Cause;
use bitcoin::block::Header;
use bitcoin::p2p::message::NetworkMessage;
use bitmigo_consensus::header::HeaderError;
use bitmigo_consensus::params::{BlockTime, Chain, Height};
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

/// Stop the node and wait for the chain thread to notice.
fn stop(shared: &Arc<Shared>, chain: thread::JoinHandle<()>) {
    shared.shutdown.begin(Cause::Internal("test"));
    shared.to_chain.close();
    chain.join().expect("the chain thread stops");
}

/// A connection in a slot, so that a verdict about a peer has somewhere to land.
fn connect_a_peer(shared: &Shared) -> (SlotIndex, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a test socket");
    let address = listener.local_addr().expect("a bound address");
    let client = TcpStream::connect(address).expect("a test connection");
    let (server, peer) = listener.accept().expect("a test connection");
    let index = shared
        .slots
        .claim(SlotKind::Inbound, server, peer)
        .expect("an empty table has room");
    (index, client)
}

/// Send one message the way a peer reader does, from a thread named like one.
fn send_as_reader(shared: &Arc<Shared>, peer: SlotIndex, message: NetworkMessage) {
    let sending = Arc::clone(shared);
    let reader = Builder::new()
        .name(format!("{READER_THREAD_PREFIX}00"))
        .spawn(move || {
            sending
                .to_chain
                .send(PeerMessage::new(peer, message, 1024))
                .expect("the queue is open");
        })
        .expect("a test thread");
    reader.join().expect("the reader finishes");
}

/// Wait for a condition the chain thread brings about, or give up.
fn until(condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    condition()
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
    assert!(until(|| shared.to_chain.len() == 0));
    stop(&shared, chain);
}

#[test]
fn the_operator_sees_the_peer_count_through_the_published_snapshot() {
    let shared = Arc::new(Shared::testing(Chain::Regtest));
    let (_index, _client) = connect_a_peer(&shared);

    let chain = spawn_chain(&shared);
    assert!(until(|| shared.status.read().peers == 1));
    stop(&shared, chain);
}

#[test]
fn the_published_snapshot_starts_at_the_chains_own_genesis() {
    let shared = Arc::new(Shared::testing(Chain::Regtest));
    let chain = spawn_chain(&shared);

    let genesis = shared.params.genesis_hash();
    assert!(until(|| shared.status.read().tip == Some(genesis)));
    let status = shared.status.read();
    // Both chains start at the same block, and neither is the `None` a node publishes
    // before its chain thread has run.
    assert_eq!(status.tip_height, Height::GENESIS);
    assert_eq!(status.header_tip, Some(genesis));
    assert_eq!(status.header_height, Height::GENESIS);
    assert_eq!(status.last_reorg_depth, 0);
    stop(&shared, chain);
}

#[test]
fn headers_from_a_peer_advance_the_header_chain() {
    let shared = Arc::new(Shared::testing(Chain::Regtest));
    let (peer, _client) = connect_a_peer(&shared);
    let chain = spawn_chain(&shared);

    let params = fixture::params();
    let headers = fixture::chain(&params.genesis().header, 12, 1, &params);
    let last = headers.last().copied().expect("twelve headers");
    send_as_reader(&shared, peer, NetworkMessage::Headers(headers));

    assert!(until(
        || shared.status.read().header_height == Height::new(12)
    ));
    let status = shared.status.read();
    assert_eq!(status.header_tip, Some(last.block_hash()));
    // The blocks behind them are still unknown, so the validated tip has not moved.
    assert_eq!(status.tip_height, Height::GENESIS);
    stop(&shared, chain);
}

#[test]
fn a_header_with_no_work_behind_it_ends_the_connection() {
    let shared = Arc::new(Shared::testing(Chain::Regtest));
    let (peer, _client) = connect_a_peer(&shared);
    let connection = shared.slots.connection(peer).expect("a claimed slot");
    let chain = spawn_chain(&shared);

    // A header whose hash is above the target it names: no work, so it never reaches the
    // tree at all, and the sender answers for it.
    let params = fixture::params();
    let mut forged: Header = fixture::child(&params.genesis().header, 1, &params);
    forged.bits = bitcoin::CompactTarget::from_consensus(0x0300_0001);
    send_as_reader(&shared, peer, NetworkMessage::Headers(vec![forged]));

    assert!(until(|| connection.ended().is_some()));
    assert_eq!(
        connection.ended(),
        Some(Disconnect::InvalidHeader(HeaderError::HighHash)),
    );
    assert_eq!(shared.status.read().header_height, Height::GENESIS);
    stop(&shared, chain);
}

#[test]
fn a_header_the_node_merely_cannot_place_costs_the_peer_nothing() {
    let shared = Arc::new(Shared::testing(Chain::Regtest));
    let (peer, _client) = connect_a_peer(&shared);
    let connection = shared.slots.connection(peer).expect("a claimed slot");
    let chain = spawn_chain(&shared);

    // The second header of a chain, sent without the first: Core answers an unconnecting
    // header with a `getheaders` and no punishment (R4 §2.3), and so does this node.
    let params = fixture::params();
    let headers = fixture::chain(&params.genesis().header, 2, 1, &params);
    let orphan = headers.last().copied().expect("two headers");
    send_as_reader(&shared, peer, NetworkMessage::Headers(vec![orphan]));

    // Nothing to wait for but the absence of a verdict, so give the thread a tick to have
    // one, then check it did not.
    thread::sleep(Duration::from_millis(300));
    assert_eq!(connection.ended(), None);
    assert_eq!(shared.status.read().header_height, Height::GENESIS);
    stop(&shared, chain);
}

#[test]
fn the_nodes_clock_is_seconds_since_the_epoch() {
    // A sanity check on the one place this module reads a clock: the fixtures' own
    // timestamps are in 2011, and every real reading is far past them.
    let genesis_time = BlockTime::new(fixture::params().genesis().header.time);
    assert!(node_time() > genesis_time);
}
