// SPDX-License-Identifier: MIT OR Apache-2.0

//! The schedule against real slots: what goes out to a peer, what comes back, and what
//! happens to a peer that answers slowly or not at all.
//!
//! Every test here drives the schedule the way the chain thread does — `tick` and the three
//! message hooks — and reads the result off the peer's own outbox, which is where a real
//! writer thread would find it.

use std::collections::HashSet;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{BlockHash, block::Header};
use bitmigo_consensus::params::{Chain, Height};

use super::{HeadersReceived, MAX_UNSTORED_BLOCKS, Schedule};
use crate::chain::{HeaderTree, NodeId, fixture, node_time};
use crate::peer::{
    Disconnect, MAX_BLOCKS_IN_FLIGHT, MAX_HEADERS_ITEMS, OUTBOUND_SLOTS, PROTOCOL_VERSION,
    SlotIndex, SlotKind,
};
use crate::runtime::Shared;

/// The shared state of a node on regtest, with nothing connected.
fn node() -> Arc<Shared> {
    Arc::new(Shared::testing(Chain::Regtest))
}

/// What an unpruned node offers.
fn full_node() -> ServiceFlags {
    let mut services = ServiceFlags::NETWORK;
    services.add(ServiceFlags::WITNESS);
    services.add(ServiceFlags::NETWORK_LIMITED);
    services
}

/// A live connection in the next free slot of its kind, past its handshake.
///
/// The client end is handed back and must be kept alive: a socket the other side has closed
/// is a connection the reader would end, and these tests are about the schedule.
fn connect(shared: &Shared, kind: SlotKind, services: ServiceFlags) -> (SlotIndex, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a test socket");
    let address = listener.local_addr().expect("a bound address");
    let client = TcpStream::connect(address).expect("a test connection");
    let (server, peer) = listener.accept().expect("a test connection");
    let index = shared.slots.claim(kind, server, peer).expect("a free slot");
    let connection = shared.slots.connection(index).expect("just claimed");
    connection.set_services(services);
    connection.mark_ready();
    (index, client)
}

/// Everything queued for a peer's writer thread, decoded and taken off.
fn sent(shared: &Shared, index: SlotIndex) -> Vec<NetworkMessage> {
    let connection = shared.slots.connection(index).expect("a live slot");
    let mut messages = Vec::new();
    while let Some(frame) = connection.outbox.pop(Duration::ZERO) {
        let decoded: RawNetworkMessage = deserialize(&frame).expect("this node's own frame");
        messages.push(decoded.payload().clone());
    }
    messages
}

/// The one `getdata` a peer was sent, and the blocks it asked for.
fn getdata(messages: &[NetworkMessage]) -> Vec<Inventory> {
    let mut items = Vec::new();
    for message in messages {
        if let NetworkMessage::GetData(asked) = message {
            items.extend(asked.iter().copied());
        }
    }
    items
}

/// Whether a `getheaders` went out.
fn asked_for_headers(messages: &[NetworkMessage]) -> bool {
    messages
        .iter()
        .any(|message| matches!(message, NetworkMessage::GetHeaders(_)))
}

/// A tree of `count` regtest headers above genesis, and the headers themselves.
fn chain_of(shared: &Shared, count: usize) -> (HeaderTree, Vec<Header>, Vec<NodeId>) {
    let mut tree = HeaderTree::new(&shared.params);
    let headers = fixture::chain(&shared.params.genesis().header, count, 1, &shared.params);
    let nodes = fixture::accept_all(&mut tree, &headers, &shared.params);
    (tree, headers, nodes)
}

/// A moment in the past, for the clocks a test cannot wait out.
fn ago(seconds: u64) -> Instant {
    Instant::now()
        .checked_sub(Duration::from_secs(seconds))
        .expect("a recent enough past")
}

#[test]
fn a_ready_peer_is_asked_to_announce_with_headers_and_then_for_headers() {
    let shared = node();
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());

    schedule.tick(&shared, &mut tree);

    let messages = sent(&shared, index);
    assert!(
        matches!(messages.first(), Some(NetworkMessage::SendHeaders)),
        "announcements by headers cost one round trip instead of two",
    );
    let Some(NetworkMessage::GetHeaders(request)) = messages.get(1) else {
        panic!("the sync starts with a getheaders: {messages:?}");
    };
    assert_eq!(
        request.version, PROTOCOL_VERSION,
        "the version we advertise"
    );
    assert_eq!(
        request.locator_hashes.first(),
        Some(&shared.params.genesis_hash()),
        "a locator from a tree holding only genesis is genesis",
    );
    assert_eq!(
        request.stop_hash,
        BlockHash::all_zeros(),
        "no stop hash: whatever the peer has, up to its own two thousand",
    );

    // Asked once. A second request inside two minutes asks for an answer already on its way.
    schedule.tick(&shared, &mut tree);
    assert!(sent(&shared, index).is_empty());
}

#[test]
fn only_one_peer_is_asked_for_headers_while_the_header_chain_is_old() {
    let shared = node();
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    let (first, _one) = connect(&shared, SlotKind::Outbound, full_node());
    let (second, _two) = connect(&shared, SlotKind::Outbound, full_node());

    schedule.tick(&shared, &mut tree);

    assert!(asked_for_headers(&sent(&shared, first)));
    let other = sent(&shared, second);
    assert!(
        !asked_for_headers(&other),
        "one sync at a time until the header chain is near enough to now",
    );
    assert!(matches!(other.first(), Some(NetworkMessage::SendHeaders)));
    assert_eq!(schedule.syncs_started(), 1);
}

#[test]
fn an_inbound_peer_is_not_asked_for_headers_while_this_node_has_dialled_somebody() {
    let shared = node();
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    let (inbound, _in) = connect(&shared, SlotKind::Inbound, full_node());
    let (outbound, _out) = connect(&shared, SlotKind::Outbound, full_node());

    schedule.tick(&shared, &mut tree);

    assert!(asked_for_headers(&sent(&shared, outbound)));
    assert!(
        !asked_for_headers(&sent(&shared, inbound)),
        "a connection an attacker made is a poor place to learn the chain from",
    );
}

#[test]
fn a_full_headers_message_is_answered_with_another_getheaders() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 4);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.tick(&shared, &mut tree);
    let _opening = sent(&shared, index);

    let last = *nodes.last().expect("four headers");
    schedule.headers_answered(
        &shared,
        &tree,
        index,
        HeadersReceived {
            // A full message is the peer saying it has more: Core's own protocol statement.
            count: MAX_HEADERS_ITEMS,
            last: Some(last),
            unconnecting: false,
        },
    );

    let messages = sent(&shared, index);
    let Some(NetworkMessage::GetHeaders(request)) = messages.first() else {
        panic!("a full batch is answered from where it stopped: {messages:?}");
    };
    assert_eq!(
        request.locator_hashes.first(),
        Some(&tree.entry(last).hash()),
        "the next request starts at the last header of the last one",
    );
    assert_eq!(schedule.row(&shared, index).best_known, Some(last));
}

#[test]
fn a_short_headers_message_is_the_peer_saying_that_is_all_it_has() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 4);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.tick(&shared, &mut tree);
    let _opening = sent(&shared, index);
    assert!(schedule.row(&shared, index).sync_deadline.is_some());

    schedule.headers_answered(
        &shared,
        &tree,
        index,
        HeadersReceived {
            count: 4,
            last: Some(*nodes.last().expect("four headers")),
            unconnecting: false,
        },
    );

    assert!(!asked_for_headers(&sent(&shared, index)));
    assert_eq!(
        schedule.row(&shared, index).sync_deadline,
        None,
        "a peer that has answered everything it has is not late",
    );
}

#[test]
fn an_unconnecting_headers_message_is_answered_with_a_getheaders_and_no_blame() {
    let shared = node();
    let tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    // No sync started for this peer, so nothing has been asked of it yet.
    let _opening = sent(&shared, index);

    schedule.headers_answered(
        &shared,
        &tree,
        index,
        HeadersReceived {
            count: 3,
            last: None,
            unconnecting: true,
        },
    );

    assert!(asked_for_headers(&sent(&shared, index)));
    let connection = shared.slots.connection(index).expect("a live slot");
    assert_eq!(
        connection.ended(),
        None,
        "a header this node has not caught up to is not a lie",
    );
}

#[test]
fn an_announcement_of_an_unknown_block_is_answered_with_a_getheaders() {
    let shared = node();
    let (tree, _headers, _nodes) = chain_of(&shared, 2);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    let _opening = sent(&shared, index);
    // The tick above sent one; the rate limit is not what this test is about.
    schedule.row(&shared, index).getheaders_at = None;

    let stranger = fixture::child(&shared.params.genesis().header, 99, &shared.params);
    schedule.announced(
        &shared,
        &tree,
        index,
        &[Inventory::Block(stranger.block_hash())],
    );

    assert!(
        asked_for_headers(&sent(&shared, index)),
        "a block is worth asking for only once its header fixes its context",
    );
    assert!(getdata(&sent(&shared, index)).is_empty());
}

#[test]
fn an_announcement_of_a_known_block_is_the_peer_saying_it_has_it() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 4);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    let last = *nodes.last().expect("four headers");

    schedule.announced(
        &shared,
        &tree,
        index,
        &[Inventory::Block(tree.entry(last).hash())],
    );
    assert_eq!(schedule.row(&shared, index).best_known, Some(last));

    schedule.tick(&shared, &mut tree);
    let asked = getdata(&sent(&shared, index));
    assert_eq!(
        asked.len(),
        4,
        "everything the peer has that this node lacks"
    );
}

#[test]
fn blocks_are_asked_for_with_the_witness_flag_and_a_context_that_travels_with_them() {
    let shared = node();
    let (mut tree, headers, nodes) = chain_of(&shared, 4);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.note_best_known(&shared, &tree, index, *nodes.last().expect("four headers"));

    schedule.tick(&shared, &mut tree);

    let asked = getdata(&sent(&shared, index));
    let first = headers.first().expect("four headers").block_hash();
    assert_eq!(
        asked.first(),
        Some(&Inventory::WitnessBlock(first)),
        "a stripped block cannot be checked against a witness commitment",
    );
    let connection = shared.slots.connection(index).expect("a live slot");
    assert_eq!(connection.requests.outstanding(), 4);
    let request = connection.requests.take(first).expect("the first block");
    assert_eq!(
        request.context.height(),
        Height::new(1),
        "the record carries the context the receipt path validates against",
    );
    assert_eq!(schedule.blocks_in_flight(), 4);
}

#[test]
fn sixteen_blocks_is_all_one_peer_is_asked_for() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 40);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.note_best_known(&shared, &tree, index, *nodes.last().expect("forty headers"));

    schedule.tick(&shared, &mut tree);
    assert_eq!(getdata(&sent(&shared, index)).len(), MAX_BLOCKS_IN_FLIGHT);

    // Nothing has come back, so nothing more is asked for.
    schedule.tick(&shared, &mut tree);
    assert!(getdata(&sent(&shared, index)).is_empty());
    assert_eq!(schedule.blocks_in_flight(), MAX_BLOCKS_IN_FLIGHT);
}

#[test]
fn a_block_that_has_arrived_is_not_asked_for_again() {
    let shared = node();
    let (mut tree, headers, nodes) = chain_of(&shared, 40);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.note_best_known(&shared, &tree, index, *nodes.last().expect("forty headers"));
    schedule.tick(&shared, &mut tree);
    let _opening = sent(&shared, index);

    let first = headers.first().expect("forty headers").block_hash();
    let connection = shared.slots.connection(index).expect("a live slot");
    // The reader takes the request as the block arrives, and refuses one that answers none.
    assert!(connection.requests.take(first).is_some());
    schedule.block_received(&shared, index, first);
    assert_eq!(schedule.blocks_in_flight(), MAX_BLOCKS_IN_FLIGHT - 1);

    schedule.tick(&shared, &mut tree);
    let asked = getdata(&sent(&shared, index));
    assert_eq!(asked.len(), 1, "one arrived, one more asked for");
    assert!(!asked.contains(&Inventory::WitnessBlock(first)));
}

#[test]
fn a_block_nobody_asked_for_changes_nothing_here() {
    let shared = node();
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    let stranger = fixture::child(&shared.params.genesis().header, 7, &shared.params);

    // The reader refuses it outright; this is the case where the peer that was asked has
    // gone in the meantime, and the table has already been emptied.
    schedule.block_received(&shared, index, stranger.block_hash());

    assert_eq!(schedule.blocks_in_flight(), 0);
}

#[test]
fn a_peer_that_goes_gives_its_blocks_back() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 40);
    let mut schedule = Schedule::new(&shared);
    let (first, _one) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.note_best_known(&shared, &tree, first, *nodes.last().expect("forty headers"));
    schedule.tick(&shared, &mut tree);
    assert_eq!(schedule.blocks_in_flight(), MAX_BLOCKS_IN_FLIGHT);

    // The slot is preallocated, so the next connection is very likely the same one — which
    // is exactly the case the row has to survive: a message from the peer that has gone
    // must not become state about the peer that replaced it.
    shared.slots.release(first);
    let (second, _two) = connect(&shared, SlotKind::Outbound, full_node());
    assert_eq!(
        second, first,
        "the free slot is the one that was just emptied"
    );
    // A message from the departed peer, arriving after its slot was taken.
    schedule.note_best_known(
        &shared,
        &tree,
        second,
        *nodes.last().expect("forty headers"),
    );
    schedule.tick(&shared, &mut tree);

    assert_eq!(
        schedule.blocks_in_flight(),
        MAX_BLOCKS_IN_FLIGHT,
        "the same sixteen blocks, asked again of somebody who still exists",
    );
    let connection = shared.slots.connection(second).expect("a live slot");
    assert_eq!(connection.requests.outstanding(), MAX_BLOCKS_IN_FLIGHT);
    assert_eq!(getdata(&sent(&shared, second)).len(), MAX_BLOCKS_IN_FLIGHT);
}

#[test]
fn a_peer_that_does_not_answer_a_getdata_is_disconnected() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 40);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.note_best_known(&shared, &tree, index, *nodes.last().expect("forty headers"));
    schedule.tick(&shared, &mut tree);

    // One target spacing on regtest is ten minutes, and this peer has had an hour.
    schedule.row(&shared, index).downloading_since = Some(ago(3600));
    schedule.tick(&shared, &mut tree);

    let connection = shared.slots.connection(index).expect("a live slot");
    assert_eq!(connection.ended(), Some(Disconnect::BlockDownloadTimeout));
    assert!(
        !Disconnect::BlockDownloadTimeout.misbehaving(),
        "slow is not dishonest"
    );
}

#[test]
fn a_peer_holding_the_window_is_disconnected_and_the_next_one_gets_longer() {
    let shared = node();
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());

    schedule.row(&shared, index).stalling_since = Some(ago(10));
    schedule.tick(&shared, &mut tree);

    let connection = shared.slots.connection(index).expect("a live slot");
    assert_eq!(connection.ended(), Some(Disconnect::BlockStalling));
    assert_eq!(
        schedule.stalling.get(),
        Duration::from_secs(4),
        "if our own link is the bottleneck, the next peer must get longer, not the same",
    );
    assert_eq!(schedule.row(&shared, index).stalling_since, None);
}

#[test]
fn the_headers_timeout_needs_somewhere_else_to_go() {
    let shared = node();
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    let (only, _one) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.tick(&shared, &mut tree);

    schedule.row(&shared, only).sync_deadline = Some(ago(60));
    schedule.tick(&shared, &mut tree);
    let connection = shared.slots.connection(only).expect("a live slot");
    assert_eq!(
        connection.ended(),
        None,
        "a node with one peer is better off with a slow sync than with no peer",
    );
    assert_eq!(schedule.row(&shared, only).sync_deadline, None);

    // With somebody else to try, the same peer goes.
    let (_other, _two) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.row(&shared, only).sync_deadline = Some(ago(60));
    schedule.tick(&shared, &mut tree);
    assert_eq!(connection.ended(), Some(Disconnect::HeadersTimeout));
}

#[test]
fn a_stale_tip_makes_way_for_a_peer_this_node_has_not_spoken_to() {
    let shared = node();
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    let mut clients = Vec::new();
    for _ in 0..OUTBOUND_SLOTS {
        let (index, client) = connect(&shared, SlotKind::Outbound, full_node());
        shared.slots.backdate(index, Duration::from_secs(60));
        clients.push(client);
    }

    schedule.stale_checked_at = ago(3600);
    schedule.tip_advanced_at = ago(3600);
    schedule.tick(&shared, &mut tree);

    let first = shared
        .slots
        .connection(SlotIndex::new(0))
        .expect("a live slot");
    assert_eq!(first.ended(), Some(Disconnect::StaleTip));
    for position in 1..OUTBOUND_SLOTS {
        let other = shared
            .slots
            .connection(SlotIndex::from_position(position))
            .expect("a live slot");
        assert_eq!(
            other.ended(),
            None,
            "one peer makes way, not the whole table"
        );
    }
}

#[test]
fn a_tip_that_has_stopped_moving_costs_nobody_their_slot_while_there_is_room_to_dial() {
    let shared = node();
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    shared.slots.backdate(index, Duration::from_secs(60));

    schedule.stale_checked_at = ago(3600);
    schedule.tip_advanced_at = ago(3600);
    schedule.tick(&shared, &mut tree);

    let connection = shared.slots.connection(index).expect("a live slot");
    assert_eq!(
        connection.ended(),
        None,
        "nine free outbound slots is nine new peers without giving anything up",
    );
}

#[test]
fn blocks_in_flight_hold_the_stale_tip_check_off() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 40);
    let mut schedule = Schedule::new(&shared);
    let mut clients = Vec::new();
    for _ in 0..OUTBOUND_SLOTS {
        let (index, client) = connect(&shared, SlotKind::Outbound, full_node());
        shared.slots.backdate(index, Duration::from_secs(60));
        clients.push(client);
    }
    schedule.note_best_known(
        &shared,
        &tree,
        SlotIndex::new(0),
        *nodes.last().expect("forty headers"),
    );

    schedule.stale_checked_at = ago(3600);
    schedule.tip_advanced_at = ago(3600);
    schedule.tick(&shared, &mut tree);

    assert!(schedule.blocks_in_flight() > 0);
    for position in 0..OUTBOUND_SLOTS {
        let connection = shared
            .slots
            .connection(SlotIndex::from_position(position))
            .expect("a live slot");
        assert_eq!(
            connection.ended(),
            None,
            "this node is not stuck, it is waiting",
        );
    }
}

#[test]
fn a_peer_that_cannot_serve_witnesses_is_asked_for_no_blocks() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 40);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, ServiceFlags::NETWORK);
    schedule.note_best_known(&shared, &tree, index, *nodes.last().expect("forty headers"));

    schedule.tick(&shared, &mut tree);

    assert!(getdata(&sent(&shared, index)).is_empty());
    assert_eq!(schedule.blocks_in_flight(), 0);
}

#[test]
fn during_the_initial_sync_only_the_peers_this_node_dialled_are_asked_for_blocks() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 40);
    let mut schedule = Schedule::new(&shared);
    let (inbound, _in) = connect(&shared, SlotKind::Inbound, full_node());
    let last = *nodes.last().expect("forty headers");
    schedule.note_best_known(&shared, &tree, inbound, last);

    // Nobody else: an inbound peer is all there is, and it is asked.
    schedule.tick(&shared, &mut tree);
    assert_eq!(getdata(&sent(&shared, inbound)).len(), MAX_BLOCKS_IN_FLIGHT);

    // Once this node has dialled somebody, the inbound peer is not asked for more.
    let (outbound, _out) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.note_best_known(&shared, &tree, outbound, last);
    schedule.tick(&shared, &mut tree);
    assert!(getdata(&sent(&shared, inbound)).is_empty());
    assert!(!getdata(&sent(&shared, outbound)).is_empty());
}

#[test]
fn the_initial_block_download_latches_off_at_a_tip_with_work_and_a_recent_time() {
    let shared = node();
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(&shared);
    assert!(schedule.is_initial_block_download());

    // A tip whose time is now, which on regtest is the whole of Core's two conditions: the
    // chain's minimum work is zero there, so the clock is what is left.
    let now = node_time();
    let header = fixture::child_at(
        &shared.params.genesis().header,
        1,
        now.get(),
        &shared.params,
    );
    let accepted = tree
        .accept(&header, &shared.params, now)
        .expect("a header at this node's own clock");
    fixture::connect_through(&mut tree, accepted.node());

    schedule.tick(&shared, &mut tree);
    assert!(!schedule.is_initial_block_download());

    // Latched: a tip that goes quiet again does not put the node back into its first sync.
    schedule.tip_height = Height::GENESIS;
    schedule.tick(&shared, &mut tree);
    assert!(!schedule.is_initial_block_download());
}

#[test]
fn a_window_of_blocks_with_nowhere_to_go_stops_the_asking() {
    let shared = node();
    let (mut tree, _headers, nodes) = chain_of(&shared, 40);
    let mut schedule = Schedule::new(&shared);
    let (index, _client) = connect(&shared, SlotKind::Outbound, full_node());
    schedule.note_best_known(&shared, &tree, index, *nodes.last().expect("forty headers"));

    // Until the block store exists, a block that has arrived is held here; a window of them
    // is as far as this node will run ahead of the disk it does not have yet.
    schedule.delivered = HashSet::from_iter((0..MAX_UNSTORED_BLOCKS).map(|salt| {
        fixture::child(
            &shared.params.genesis().header,
            u32::try_from(salt).expect("a bounded count"),
            &shared.params,
        )
        .block_hash()
    }));
    schedule.tick(&shared, &mut tree);

    assert!(getdata(&sent(&shared, index)).is_empty());
    assert_eq!(schedule.blocks_in_flight(), 0);
}
