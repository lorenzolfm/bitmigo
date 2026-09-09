// SPDX-License-Identifier: MIT OR Apache-2.0

//! The framing bounds, each against the thing it exists to stop.
//!
//! Every test here writes bytes a peer could write. The ones that matter most write only a
//! *header*: the whole point of imposing the length before the payload is that a peer never
//! gets to make this node hold four megabytes by saying it will send them.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::{MAX_MSG_SIZE, NetworkMessage};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::{BlockHash, Txid};

use super::{
    Frame, Framer, HEADER_BYTES, MAX_ADDR_ITEMS, MAX_HEADERS_ITEMS, MAX_INV_ITEMS,
    MAX_LOCATOR_ITEMS, MAX_MESSAGE_LEN, WireError, check_counts, encode,
};
use crate::peer::{READ_BUFFER_INITIAL_BYTES, READ_CAP_IDLE};

const MAGIC: Magic = Magic::REGTEST;

/// A connected pair, and a framer reading the server end.
fn pair() -> (TcpStream, TcpStream, Framer) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let framer = Framer::new(MAGIC, READ_BUFFER_INITIAL_BYTES, Duration::from_secs(120));
    (client, server, framer)
}

/// Read until a message arrives, an error is returned, or the reads run out.
fn next(
    framer: &mut Framer,
    server: &TcpStream,
    cap: usize,
) -> Result<Option<NetworkMessage>, WireError> {
    for _ in 0..64 {
        match framer.read(server, cap)? {
            Frame::Message(message, _len) => return Ok(Some(message)),
            Frame::Idle => {}
            Frame::Eof => return Ok(None),
        }
    }
    Ok(None)
}

/// A twenty-four byte header that declares `declared` payload bytes and sends none of them.
fn header_only(command: &[u8; 12], declared: u32, magic: [u8; 4]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.extend_from_slice(&magic);
    header.extend_from_slice(command);
    header.extend_from_slice(&declared.to_le_bytes());
    header.extend_from_slice(&[0u8; 4]);
    assert_eq!(header.len(), HEADER_BYTES);
    header
}

#[test]
fn the_crate_bound_is_the_reason_this_module_exists() {
    // R4 §8.10: the crate would let a peer send a megabyte more than the protocol allows.
    const { assert!(MAX_MESSAGE_LEN < MAX_MSG_SIZE) };
    assert_eq!(MAX_MESSAGE_LEN, 4_000_000);
}

#[test]
fn a_message_survives_the_round_trip() {
    let (mut client, server, mut framer) = pair();
    client
        .write_all(&encode(MAGIC, NetworkMessage::Ping(0x0123_4567_89ab_cdef)))
        .unwrap();

    let message = next(&mut framer, &server, READ_CAP_IDLE).unwrap();
    assert_eq!(message, Some(NetworkMessage::Ping(0x0123_4567_89ab_cdef)));
}

/// A payload of zero bytes is a whole message and must not leave the framer waiting for one
/// more byte that will never come.
#[test]
fn an_empty_payload_is_a_whole_message() {
    let (mut client, server, mut framer) = pair();
    client
        .write_all(&encode(MAGIC, NetworkMessage::Verack))
        .unwrap();
    client
        .write_all(&encode(MAGIC, NetworkMessage::GetAddr))
        .unwrap();

    assert_eq!(
        next(&mut framer, &server, READ_CAP_IDLE).unwrap(),
        Some(NetworkMessage::Verack)
    );
    assert_eq!(
        next(&mut framer, &server, READ_CAP_IDLE).unwrap(),
        Some(NetworkMessage::GetAddr)
    );
}

/// The state machine: one message spread over as many writes as the peer likes.
#[test]
fn a_message_split_across_writes_still_arrives() {
    let (mut client, server, mut framer) = pair();
    let frame = encode(MAGIC, NetworkMessage::Pong(7));
    for byte in &frame {
        client.write_all(std::slice::from_ref(byte)).unwrap();
        client.flush().unwrap();
    }
    assert_eq!(
        next(&mut framer, &server, READ_CAP_IDLE).unwrap(),
        Some(NetworkMessage::Pong(7))
    );
}

#[test]
fn another_networks_magic_is_refused() {
    let (mut client, server, mut framer) = pair();
    client
        .write_all(&encode(Magic::BITCOIN, NetworkMessage::Verack))
        .unwrap();

    let error = next(&mut framer, &server, READ_CAP_IDLE).unwrap_err();
    assert_eq!(
        error,
        WireError::WrongMagic {
            seen: Magic::BITCOIN.to_bytes(),
        },
    );
}

/// The bound that matters: the length is refused with the payload still unsent.
#[test]
fn a_length_past_the_protocol_maximum_is_refused_before_the_payload() {
    let (mut client, server, mut framer) = pair();
    let declared = u32::try_from(MAX_MESSAGE_LEN + 1).unwrap();
    client
        .write_all(&header_only(
            b"block\0\0\0\0\0\0\0",
            declared,
            MAGIC.to_bytes(),
        ))
        .unwrap();

    let error = next(&mut framer, &server, MAX_MESSAGE_LEN).unwrap_err();
    assert_eq!(
        error,
        WireError::TooLong {
            declared: MAX_MESSAGE_LEN + 1,
        },
    );
}

/// The dynamic cap: the same declared length is refused from a peer that owes nothing and
/// accepted from one that owes a block.
#[test]
fn the_cap_follows_what_the_peer_was_asked_for() {
    let declared = u32::try_from(READ_CAP_IDLE + 1).unwrap();

    let (mut client, server, mut framer) = pair();
    client
        .write_all(&header_only(
            b"block\0\0\0\0\0\0\0",
            declared,
            MAGIC.to_bytes(),
        ))
        .unwrap();
    let error = next(&mut framer, &server, READ_CAP_IDLE).unwrap_err();
    assert_eq!(
        error,
        WireError::OverCap {
            declared: READ_CAP_IDLE + 1,
            cap: READ_CAP_IDLE,
        },
    );

    // The same header, from a peer with an outstanding `getdata`: accepted, and the framer
    // simply waits for the payload it was promised.
    let (mut client, server, mut framer) = pair();
    client
        .write_all(&header_only(
            b"block\0\0\0\0\0\0\0",
            declared,
            MAGIC.to_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        framer.read(&server, MAX_MESSAGE_LEN),
        Ok(Frame::Idle)
    ));
    assert!(framer.in_progress());
}

#[test]
fn a_message_type_that_is_not_one_is_refused() {
    // A non-zero byte after the padding: Core's `IsMessageTypeValid` rejects it, and so
    // does this, before the payload is read.
    let (mut client, server, mut framer) = pair();
    client
        .write_all(&header_only(b"ping\0\0\0\0\0\0\0\x01", 0, MAGIC.to_bytes()))
        .unwrap();
    assert_eq!(
        next(&mut framer, &server, READ_CAP_IDLE).unwrap_err(),
        WireError::BadCommand
    );

    // A control character before it.
    let (mut client, server, mut framer) = pair();
    client
        .write_all(&header_only(
            b"pi\x07g\0\0\0\0\0\0\0\0",
            0,
            MAGIC.to_bytes(),
        ))
        .unwrap();
    assert_eq!(
        next(&mut framer, &server, READ_CAP_IDLE).unwrap_err(),
        WireError::BadCommand
    );
}

/// The crate verifies the checksum, which is why this node does not hash the payload twice.
/// The test is that a corrupted payload does not reach the caller.
#[test]
fn a_corrupted_payload_does_not_decode() {
    let (mut client, server, mut framer) = pair();
    let mut frame = encode(MAGIC, NetworkMessage::Ping(1));
    let last = frame.len() - 1;
    if let Some(byte) = frame.get_mut(last) {
        *byte ^= 0xff;
    }
    client.write_all(&frame).unwrap();

    assert_eq!(
        next(&mut framer, &server, READ_CAP_IDLE).unwrap_err(),
        WireError::Malformed
    );
}

/// A peer that begins a message and does not finish it costs a thread for as long as it
/// keeps trickling. The deadline is on the whole message, which is why one more byte does
/// not reset it.
#[test]
fn a_message_that_never_finishes_is_a_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let mut framer = Framer::new(MAGIC, READ_BUFFER_INITIAL_BYTES, Duration::from_millis(50));

    let frame = encode(MAGIC, NetworkMessage::Pong(1));
    client
        .write_all(frame.get(..HEADER_BYTES).unwrap())
        .unwrap();
    client.flush().unwrap();

    let mut error = None;
    for _ in 0..64 {
        match framer.read(&server, READ_CAP_IDLE) {
            Ok(_) => std::thread::sleep(Duration::from_millis(10)),
            Err(seen) => {
                error = Some(seen);
                break;
            }
        }
    }
    assert_eq!(error, Some(WireError::Stalled));
}

/// The counts the crate documents as "not currently enforced by this implementation".
#[test]
fn the_item_counts_are_cores() {
    let inventory = vec![Inventory::Block(BlockHash::from_byte_array([0u8; 32])); MAX_INV_ITEMS];
    assert_eq!(
        check_counts(&NetworkMessage::Inv(inventory.clone())),
        Ok(())
    );

    let mut too_many = inventory;
    too_many.push(Inventory::Transaction(Txid::from_byte_array([1u8; 32])));
    assert_eq!(
        check_counts(&NetworkMessage::Inv(too_many.clone())),
        Err(WireError::TooManyItems {
            seen: MAX_INV_ITEMS + 1,
            allowed: MAX_INV_ITEMS,
        }),
    );
    // The same bound on the other two inventory-shaped messages.
    assert!(check_counts(&NetworkMessage::GetData(too_many.clone())).is_err());
    assert!(check_counts(&NetworkMessage::NotFound(too_many)).is_err());
}

#[test]
fn a_locator_longer_than_cores_is_refused() {
    let hash = BlockHash::from_byte_array([0u8; 32]);
    let request = GetHeadersMessage::new(vec![hash; MAX_LOCATOR_ITEMS], hash);
    assert_eq!(check_counts(&NetworkMessage::GetHeaders(request)), Ok(()));

    let request = GetHeadersMessage::new(vec![hash; MAX_LOCATOR_ITEMS + 1], hash);
    assert_eq!(
        check_counts(&NetworkMessage::GetHeaders(request)),
        Err(WireError::TooManyItems {
            seen: MAX_LOCATOR_ITEMS + 1,
            allowed: MAX_LOCATOR_ITEMS,
        }),
    );
}

#[test]
fn more_headers_or_addresses_than_the_protocol_allows_are_refused() {
    let header = Header {
        version: bitcoin::block::Version::ONE,
        prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x2000_ffff),
        nonce: 0,
    };
    assert!(check_counts(&NetworkMessage::Headers(vec![header; MAX_HEADERS_ITEMS])).is_ok());
    assert!(
        check_counts(&NetworkMessage::Headers(vec![
            header;
            MAX_HEADERS_ITEMS + 1
        ]))
        .is_err()
    );

    let address = bitcoin::p2p::address::Address::new(
        &"127.0.0.1:8333".parse().unwrap(),
        bitcoin::p2p::ServiceFlags::NONE,
    );
    let addresses = vec![(0u32, address); MAX_ADDR_ITEMS + 1];
    assert!(check_counts(&NetworkMessage::Addr(addresses)).is_err());
}
