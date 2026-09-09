// SPDX-License-Identifier: MIT OR Apache-2.0

//! What one connection does with a message, driven a message at a time.
//!
//! The refusal matrix is the substance here: Core disconnects rather than ignores in four
//! places a peer will hit by accident, and `Misbehaving` has no score, so the whole set of
//! things that end a connection is enumerable and each of them is one line below.

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Instant;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::message_bloom::{FilterAdd, FilterLoad};
use bitcoin::p2p::message_filter::GetCFilters;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::{Block, BlockHash, Txid};
use bitmigo_consensus::params::{BlockTime, Chain, Height};

use super::Session;
use crate::peer::requests::BlockRequest;
use crate::peer::{Connection, Disconnect, PROTOCOL_VERSION, SlotKind};
use crate::runtime::Shared;
use crate::runtime::queue::Received;

/// A node, a connected socket in a slot, and the peer's end of it.
fn connected(kind: SlotKind) -> (Arc<Shared>, Connection, TcpStream) {
    connected_on(kind, Chain::Regtest)
}

/// The same, on a stated chain.
fn connected_on(kind: SlotKind, chain: Chain) -> (Arc<Shared>, Connection, TcpStream) {
    let shared = Arc::new(Shared::testing(chain));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, address) = listener.accept().unwrap();
    let index = shared.slots.claim(kind, server, address).unwrap();
    let connection = shared.slots.connection(index).unwrap();
    (shared, connection, peer)
}

/// A `version` from a peer that offers everything this node wants.
fn their_version() -> NetworkMessage {
    let address = Address::new(&"127.0.0.1:18444".parse().unwrap(), ServiceFlags::NONE);
    let mut services = ServiceFlags::NETWORK;
    services.add(ServiceFlags::WITNESS);
    NetworkMessage::Version(VersionMessage {
        version: PROTOCOL_VERSION,
        services,
        timestamp: 0,
        receiver: address.clone(),
        sender: address,
        nonce: 7,
        user_agent: "/Satoshi:31.1.0/".to_owned(),
        start_height: 0,
        relay: true,
    })
}

/// Drive a session to the point where the handshake is through.
fn ready<'a>(shared: &'a Shared, connection: &'a Connection) -> Session<'a> {
    let mut session = Session::new(shared, connection);
    session.open().unwrap();
    session.receive(their_version(), 128).unwrap();
    session.receive(NetworkMessage::Verack, 24).unwrap();
    assert!(connection.is_ready());
    session
}

/// What the session queued for its writer, decoded back.
fn queued(connection: &Connection) -> Vec<NetworkMessage> {
    let mut messages = Vec::new();
    while let Some(frame) = connection.outbox.pop(std::time::Duration::ZERO) {
        let decoded: RawNetworkMessage = deserialize(&frame).unwrap();
        messages.push(decoded.into_payload());
    }
    messages
}

#[test]
fn an_outbound_connection_speaks_first_and_an_inbound_one_waits() {
    let (shared, connection, _peer) = connected(SlotKind::Outbound);
    let mut session = Session::new(&shared, &connection);
    session.open().unwrap();
    assert!(matches!(
        queued(&connection).first(),
        Some(NetworkMessage::Version(_)),
    ));

    let (shared, connection, _peer) = connected(SlotKind::Inbound);
    let mut session = Session::new(&shared, &connection);
    session.open().unwrap();
    assert_eq!(queued(&connection), Vec::new());

    // It answers with its own `version` and then a `verack`, once it has been told who it
    // is talking to.
    session.receive(their_version(), 128).unwrap();
    let replies = queued(&connection);
    assert_eq!(replies.len(), 2);
    assert!(matches!(replies.first(), Some(NetworkMessage::Version(_))));
    assert_eq!(replies.get(1), Some(&NetworkMessage::Verack));
}

#[test]
fn a_ping_is_answered_with_the_same_nonce() {
    let (shared, connection, _peer) = connected(SlotKind::Inbound);
    let mut session = ready(&shared, &connection);
    let _handshake = queued(&connection);

    session
        .receive(NetworkMessage::Ping(0xdead_beef), 32)
        .unwrap();
    assert_eq!(queued(&connection), vec![NetworkMessage::Pong(0xdead_beef)]);
}

/// Core logs an unsolicited pong and never punishes it, and neither does this.
#[test]
fn an_unsolicited_pong_is_ignored() {
    let (shared, connection, _peer) = connected(SlotKind::Inbound);
    let mut session = ready(&shared, &connection);
    assert!(session.receive(NetworkMessage::Pong(1), 32).is_ok());
}

/// The read cap follows the requests, which is the whole of BM-D5 decision 4.
#[test]
fn the_cap_is_four_megabytes_only_while_a_block_is_owed() {
    let (shared, connection, _peer) = connected(SlotKind::Outbound);
    let session = ready(&shared, &connection);
    assert_eq!(session.cap(), crate::peer::READ_CAP_IDLE);

    let hash = BlockHash::from_byte_array([3u8; 32]);
    assert!(connection.requests.record(BlockRequest {
        hash,
        context: context(),
        requested_at: Instant::now(),
    }));
    assert_eq!(session.cap(), crate::peer::MAX_MESSAGE_LEN);

    let _taken = connection.requests.take(hash);
    assert_eq!(session.cap(), crate::peer::READ_CAP_IDLE);
}

/// A context for a block at height one on regtest.
fn context() -> bitmigo_consensus::header::Context {
    let params = bitmigo_consensus::params::ChainParams::regtest(
        bitmigo_consensus::params::RegtestOverrides::default(),
    );
    let rules = params.rules_at(Height::new(1), BlockHash::from_byte_array([0u8; 32]), None);
    bitmigo_consensus::header::Context::new(
        Height::new(1),
        BlockTime::new(1_296_688_602),
        BlockTime::new(1_296_688_602),
        bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        rules,
    )
}

/// The refuse-unrequested rule: a block nobody asked for is refused before it costs a hash.
#[test]
fn a_block_nobody_asked_for_ends_the_connection() {
    let (shared, connection, _peer) = connected(SlotKind::Inbound);
    let mut session = ready(&shared, &connection);
    let block = shared.params.genesis().clone();

    let error = session
        .receive(NetworkMessage::Block(block.clone()), 300)
        .unwrap_err();
    assert_eq!(
        error,
        Disconnect::UnrequestedBlock {
            hash: block.block_hash(),
        },
    );
    assert!(error.misbehaving());
    // Nothing reached the chain thread.
    assert!(matches!(
        shared.to_chain.recv(std::time::Duration::ZERO),
        Received::Empty,
    ));
}

/// A block that was asked for is checked here, on this peer's own thread, against the
/// context that travelled with the request. Genesis under a height-one context fails, which
/// is what proves both stages ran.
#[test]
fn a_requested_block_is_checked_against_the_context_that_came_with_the_request() {
    let (shared, connection, _peer) = connected(SlotKind::Outbound);
    let mut session = ready(&shared, &connection);
    let block: Block = shared.params.genesis().clone();

    assert!(connection.requests.record(BlockRequest {
        hash: block.block_hash(),
        context: context(),
        requested_at: Instant::now(),
    }));
    let error = session
        .receive(NetworkMessage::Block(block), 300)
        .unwrap_err();
    assert!(matches!(error, Disconnect::InvalidBlock(_)), "{error:?}");
    // The request is spent either way: a block that answered it does not answer it twice.
    assert_eq!(connection.requests.outstanding(), 0);
}

/// Headers are checked for proof of work here, so a peer that sends two thousand headers
/// with nothing behind them pays for the hashes on its own thread.
///
/// Mainnet, because regtest's target is met by almost any hash: the rule is real on a chain
/// where work is real.
#[test]
fn a_header_without_work_ends_the_connection() {
    let (shared, connection, _peer) = connected_on(SlotKind::Outbound, Chain::Mainnet);
    let mut session = ready(&shared, &connection);
    let mut header = shared.params.genesis().header;
    header.nonce = header.nonce.wrapping_add(1);

    let error = session
        .receive(NetworkMessage::Headers(vec![header]), 106)
        .unwrap_err();
    assert!(matches!(error, Disconnect::InvalidHeader(_)), "{error:?}");
}

#[test]
fn a_header_with_work_reaches_the_chain_thread() {
    let (shared, connection, _peer) = connected(SlotKind::Outbound);
    let mut session = ready(&shared, &connection);
    let header = shared.params.genesis().header;

    session
        .receive(NetworkMessage::Headers(vec![header]), 106)
        .unwrap();
    match shared.to_chain.recv(std::time::Duration::ZERO) {
        Received::Item(queued) => {
            assert_eq!(queued.peer, connection.index);
            assert_eq!(queued.message, NetworkMessage::Headers(vec![header]));
        }
        other => panic!("{other:?}"),
    }
}

/// Everything Core disconnects for, and this node with it. One row per rule.
#[test]
fn the_refusal_matrix() {
    let filter = FilterLoad {
        filter: vec![0u8; 4],
        hash_funcs: 1,
        tweak: 0,
        flags: bitcoin::p2p::message_bloom::BloomFlags::None,
    };
    let rows: Vec<(NetworkMessage, Disconnect)> = vec![
        // `fRelay = 0` said this node wants no transactions; Core's own verdict for a peer
        // that sends one anyway.
        (
            NetworkMessage::Tx(shared_transaction()),
            Disconnect::TransactionRelay,
        ),
        (
            NetworkMessage::Inv(vec![Inventory::Transaction(Txid::from_byte_array(
                [0u8; 32],
            ))]),
            Disconnect::TransactionRelay,
        ),
        (
            NetworkMessage::Inv(vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array(
                [0u8; 32],
            ))]),
            Disconnect::TransactionRelay,
        ),
        // BIP35, gated on `NODE_BLOOM`, which a node with no mempool cannot offer.
        (NetworkMessage::MemPool, Disconnect::Mempool),
        // BIP37, and one of Core's four disconnect-rather-than-ignore cases.
        (NetworkMessage::FilterLoad(filter), Disconnect::BloomFilter),
        (
            NetworkMessage::FilterAdd(FilterAdd { data: vec![0u8; 4] }),
            Disconnect::BloomFilter,
        ),
        (NetworkMessage::FilterClear, Disconnect::BloomFilter),
        // BIP157 says only "SHOULD NOT respond"; Core disconnects, and so does this.
        (
            NetworkMessage::GetCFilters(GetCFilters {
                filter_type: 0,
                start_height: 0,
                stop_hash: BlockHash::from_byte_array([0u8; 32]),
            }),
            Disconnect::CompactFilter,
        ),
    ];

    for (message, expected) in rows {
        let (shared, connection, _peer) = connected(SlotKind::Inbound);
        let mut session = ready(&shared, &connection);
        let error = session.receive(message.clone(), 64).unwrap_err();
        assert_eq!(error, expected, "{}", message.cmd());
        assert!(error.misbehaving(), "{}", message.cmd());
    }
}

/// Everything this node answers by silence, which for several of these *is* the defence:
/// never sending `sendcmpct` is what forbids a peer from ever asking for a compact block.
#[test]
fn what_is_ignored_is_ignored_rather_than_punished() {
    let ignored = vec![
        NetworkMessage::SendHeaders,
        NetworkMessage::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct {
            send_compact: true,
            version: 2,
        }),
        NetworkMessage::FeeFilter(1000),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(
            vec![BlockHash::from_byte_array([0u8; 32])],
            BlockHash::from_byte_array([0u8; 32]),
        )),
    ];
    for message in ignored {
        let (shared, connection, _peer) = connected(SlotKind::Inbound);
        let mut session = ready(&shared, &connection);
        assert!(
            session.receive(message.clone(), 64).is_ok(),
            "{}",
            message.cmd()
        );
    }
}

/// A block inventory is an announcement, and announcements are the chain thread's.
#[test]
fn a_block_inventory_reaches_the_chain_thread() {
    let (shared, connection, _peer) = connected(SlotKind::Inbound);
    let mut session = ready(&shared, &connection);
    let inventory = vec![Inventory::Block(BlockHash::from_byte_array([5u8; 32]))];

    session
        .receive(NetworkMessage::Inv(inventory.clone()), 61)
        .unwrap();
    match shared.to_chain.recv(std::time::Duration::ZERO) {
        Received::Item(queued) => assert_eq!(queued.message, NetworkMessage::Inv(inventory)),
        other => panic!("{other:?}"),
    }
}

/// `getheaders` and `getdata` are what a peer syncing from this node sends, and both cross
/// to the chain thread, which owns the header tree and the block store's index.
#[test]
fn what_a_peer_asks_for_reaches_the_chain_thread() {
    let hash = BlockHash::from_byte_array([0u8; 32]);
    let asks = vec![
        NetworkMessage::GetHeaders(GetHeadersMessage::new(vec![hash], hash)),
        NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
        NetworkMessage::GetAddr,
    ];
    for message in asks {
        let (shared, connection, _peer) = connected(SlotKind::Inbound);
        let mut session = ready(&shared, &connection);
        session.receive(message.clone(), 64).unwrap();
        match shared.to_chain.recv(std::time::Duration::ZERO) {
            Received::Item(queued) => assert_eq!(queued.message, message),
            other => panic!("{other:?}"),
        }
    }
}

/// Nothing but the handshake is acted on until the handshake is through.
#[test]
fn a_transaction_before_the_handshake_is_ignored_rather_than_punished() {
    let (shared, connection, _peer) = connected(SlotKind::Inbound);
    let mut session = Session::new(&shared, &connection);
    // Core ignores everything that is not a negotiation message before `version`.
    assert!(
        session
            .receive(NetworkMessage::Tx(shared_transaction()), 64)
            .is_ok()
    );
    assert!(!connection.is_ready());
}

/// A transaction with no inputs and no outputs: the smallest thing that is still a `tx`.
fn shared_transaction() -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    }
}
