// SPDX-License-Identifier: MIT OR Apache-2.0

//! The handshake against Core's ordering rules (R4 §1.2), one test per row, and against the
//! three things this node says about itself in its own `version`.

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{CommandString, NetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;

use super::{Handshake, Stage, desirable_services, local_services, nonce};
use crate::peer::{Disconnect, MIN_PEER_PROTO_VERSION, PROTOCOL_VERSION, SlotKind, USER_AGENT};

const NONCE: u64 = 0x1234_5678_9abc_def0;

/// A `version` a well-behaved Core node would send us.
fn their_version(version: u32, services: ServiceFlags, nonce: u64) -> NetworkMessage {
    let address = Address::new(&"127.0.0.1:18444".parse().unwrap(), ServiceFlags::NONE);
    NetworkMessage::Version(VersionMessage {
        version,
        services,
        timestamp: 0,
        receiver: address.clone(),
        sender: address,
        nonce,
        user_agent: "/Satoshi:31.1.0/".to_owned(),
        start_height: 0,
        relay: true,
    })
}

fn full_relay() -> ServiceFlags {
    let mut services = ServiceFlags::NETWORK;
    services.add(ServiceFlags::WITNESS);
    services.add(ServiceFlags::NETWORK_LIMITED);
    services
}

fn outbound() -> Handshake {
    Handshake::new(SlotKind::Outbound, NONCE, peer(), 42)
}

fn inbound() -> Handshake {
    Handshake::new(SlotKind::Inbound, NONCE, peer(), 42)
}

fn peer() -> std::net::SocketAddr {
    "127.0.0.1:18444".parse().unwrap()
}

/// The three statements this node makes about itself, each of which is a decision.
#[test]
fn our_version_says_no_relay_the_three_service_bits_and_cores_protocol_version() {
    let handshake = outbound();
    let message = handshake.our_version();
    let NetworkMessage::Version(version) = message else {
        panic!("a version message");
    };

    // `fRelay = 0` is the whole mempool-less contract (R4 §8.3).
    assert!(!version.relay);
    // What an unpruned Core node advertises, all three bits (R4 §8.9).
    assert_eq!(version.services, full_relay());
    assert!(!version.services.has(ServiceFlags::BLOOM));
    assert!(!version.services.has(ServiceFlags::P2P_V2));
    // Core's, not the crate's 70001, which is below every feature gate (R4 §6.3).
    assert_eq!(version.version, PROTOCOL_VERSION);
    assert_eq!(version.version, 70_016);
    assert_eq!(version.user_agent, USER_AGENT);
    assert_eq!(version.start_height, 42);
    assert_eq!(version.nonce, NONCE);
}

#[test]
fn the_exchange_completes_and_answers_a_version_with_a_verack() {
    let mut handshake = inbound();
    assert_eq!(handshake.stage(), Stage::AwaitingVersion);

    // Both, and in this order: the side that accepted has not said who it is yet, so a
    // peer given only a `verack` would wait forever for the `version` it needs.
    let replies = handshake
        .receive(&their_version(PROTOCOL_VERSION, full_relay(), 1))
        .unwrap();
    assert_eq!(replies.len(), 2);
    assert!(matches!(replies.first(), Some(NetworkMessage::Version(_))));
    assert_eq!(replies.get(1), Some(&NetworkMessage::Verack));
    assert_eq!(handshake.stage(), Stage::AwaitingVerack);
    assert!(!handshake.is_ready());

    assert_eq!(
        handshake.receive(&NetworkMessage::Verack).unwrap(),
        Vec::new()
    );
    assert!(handshake.is_ready());
    assert_eq!(handshake.peer_version(), PROTOCOL_VERSION);
    assert_eq!(handshake.peer_services(), full_relay());
    assert_eq!(handshake.peer_user_agent(), "/Satoshi:31.1.0/");
}

#[test]
fn a_peer_older_than_cores_minimum_is_disconnected() {
    let mut handshake = inbound();
    let error = handshake
        .receive(&their_version(MIN_PEER_PROTO_VERSION - 1, full_relay(), 1))
        .unwrap_err();
    assert_eq!(
        error,
        Disconnect::ObsoleteVersion {
            version: MIN_PEER_PROTO_VERSION - 1,
        },
    );
    // The boundary itself is accepted: Core disconnects peers *older* than this.
    let mut handshake = inbound();
    assert!(
        handshake
            .receive(&their_version(MIN_PEER_PROTO_VERSION, full_relay(), 1))
            .is_ok()
    );
}

/// Our own nonce coming back is this node's socket talking to itself. Core checks it on
/// inbound connections, which are the only ones where it can happen.
#[test]
fn our_own_nonce_coming_back_is_a_self_connection() {
    let mut handshake = inbound();
    let error = handshake
        .receive(&their_version(PROTOCOL_VERSION, full_relay(), NONCE))
        .unwrap_err();
    assert_eq!(error, Disconnect::ConnectedToSelf);

    // An outbound connection cannot be to ourselves in the same way, and Core does not
    // check it there.
    let mut handshake = outbound();
    assert!(
        handshake
            .receive(&their_version(PROTOCOL_VERSION, full_relay(), NONCE))
            .is_ok()
    );
}

/// An outbound peer is dialled to be useful; an inbound one is merely answered.
#[test]
fn only_a_peer_this_node_dialled_has_to_be_useful() {
    let mut handshake = outbound();
    let error = handshake
        .receive(&their_version(PROTOCOL_VERSION, ServiceFlags::NETWORK, 1))
        .unwrap_err();
    assert_eq!(
        error,
        Disconnect::MissingServices {
            offered: ServiceFlags::NETWORK,
            wanted: desirable_services(),
        },
    );

    // The same peer, inbound: accepted. It costs nothing but one of twenty-two slots.
    let mut handshake = inbound();
    assert!(
        handshake
            .receive(&their_version(PROTOCOL_VERSION, ServiceFlags::NETWORK, 1))
            .is_ok()
    );
}

/// Witness data is required transitively: a peer without `NODE_WITNESS` is useless for
/// every mainnet block after segwit activated (R4 §1.4).
#[test]
fn a_peer_without_witness_is_no_use_for_block_download() {
    assert!(desirable_services().has(ServiceFlags::WITNESS));
    let mut handshake = outbound();
    let mut without = ServiceFlags::NETWORK;
    without.add(ServiceFlags::NETWORK_LIMITED);
    assert!(
        handshake
            .receive(&their_version(PROTOCOL_VERSION, without, 1))
            .is_err()
    );
}

/// Core logs "redundant version message" and keeps the connection; so does this.
#[test]
fn a_second_version_or_verack_is_ignored_rather_than_punished() {
    let mut handshake = inbound();
    assert!(
        handshake
            .receive(&their_version(PROTOCOL_VERSION, full_relay(), 1))
            .is_ok()
    );
    assert_eq!(
        handshake
            .receive(&their_version(PROTOCOL_VERSION, full_relay(), 1))
            .unwrap(),
        Vec::new(),
    );
    assert_eq!(handshake.stage(), Stage::AwaitingVerack);

    assert!(handshake.receive(&NetworkMessage::Verack).is_ok());
    assert!(handshake.is_ready());
    assert_eq!(
        handshake.receive(&NetworkMessage::Verack).unwrap(),
        Vec::new()
    );
    assert!(handshake.is_ready());
}

/// Anything before `version` is logged and ignored, connection kept. Core's row, and the
/// reason not to be stricter: an implementation that opens with `sendaddrv2` is odd, not
/// hostile.
#[test]
fn a_message_before_version_is_ignored_and_the_connection_kept() {
    let mut handshake = inbound();
    assert_eq!(
        handshake.receive(&NetworkMessage::Ping(1)).unwrap(),
        Vec::new()
    );
    assert_eq!(
        handshake.receive(&NetworkMessage::SendHeaders).unwrap(),
        Vec::new()
    );
    assert_eq!(handshake.stage(), Stage::AwaitingVersion);
    assert!(
        handshake
            .receive(&their_version(PROTOCOL_VERSION, full_relay(), 1))
            .is_ok()
    );
}

/// One of the four places Core disconnects rather than ignores (R4 §8.7).
#[test]
fn negotiation_messages_after_verack_are_a_disconnect() {
    for message in [NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2] {
        let mut handshake = inbound();
        // Before `verack` they are merely ignored, which is where Core accepts them.
        assert_eq!(handshake.receive(&message).unwrap(), Vec::new());
        assert!(
            handshake
                .receive(&their_version(PROTOCOL_VERSION, full_relay(), 1))
                .is_ok()
        );
        assert!(handshake.receive(&NetworkMessage::Verack).is_ok());

        assert_eq!(
            handshake.receive(&message).unwrap_err(),
            Disconnect::NegotiationAfterVerack {
                command: message.cmd(),
            },
        );
    }
}

/// BIP330: "Must not be sent if peer specified no support for transaction relay
/// (fRelay=0)", which this node always specifies. The crate has no variant for it, so it
/// arrives as an unknown command — and is a disconnect at any stage, not only after
/// `verack`.
#[test]
fn sendtxrcncl_is_refused_whenever_it_arrives() {
    let sendtxrcncl = NetworkMessage::Unknown {
        command: CommandString::try_from_static("sendtxrcncl").unwrap(),
        payload: vec![0u8; 12],
    };
    let mut handshake = inbound();
    assert_eq!(
        handshake.receive(&sendtxrcncl).unwrap_err(),
        Disconnect::TransactionRelay,
    );

    // Another unknown command is ignored "for extensibility", as Core puts it.
    let mut handshake = inbound();
    let unknown = NetworkMessage::Unknown {
        command: CommandString::try_from_static("somethingnw").unwrap(),
        payload: Vec::new(),
    };
    assert_eq!(handshake.receive(&unknown).unwrap(), Vec::new());
}

#[test]
fn the_service_bits_are_two_different_questions() {
    // What we offer, and what we require of a peer we dialled, are not the same set.
    assert!(local_services().has(ServiceFlags::NETWORK_LIMITED));
    assert!(!desirable_services().has(ServiceFlags::NETWORK_LIMITED));
    assert!(local_services().has(desirable_services()));
}

/// A nonce that repeated would make one connection look like a self-connection to the next.
#[test]
fn nonces_differ_between_connections() {
    let first = nonce();
    let second = nonce();
    assert_ne!(first, second);
    assert_ne!(first, 0);
}
