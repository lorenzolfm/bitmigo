// SPDX-License-Identifier: MIT OR Apache-2.0

//! The slot table under the two things that happen to it: a full inbound half, and a
//! shutdown that has to end reads other threads are blocked in.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::{PeerSlots, SlotIndex, SlotKind};
use crate::peer::{INBOUND_SLOTS, OUTBOUND_SLOTS, PEER_SLOTS};

/// A connected pair of sockets, the way a test gets something a peer thread can block on.
fn pair() -> (TcpStream, TcpStream, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server, address)
}

#[test]
fn the_table_is_ten_outbound_and_twenty_two_inbound() {
    assert_eq!(OUTBOUND_SLOTS + INBOUND_SLOTS, PEER_SLOTS);
    assert_eq!(PeerSlots::capacity(SlotKind::Outbound), OUTBOUND_SLOTS);
    assert_eq!(PeerSlots::capacity(SlotKind::Inbound), INBOUND_SLOTS);
    for index in 0..PEER_SLOTS {
        let slot = SlotIndex::new(u8::try_from(index).unwrap());
        let expected = if index < OUTBOUND_SLOTS {
            SlotKind::Outbound
        } else {
            SlotKind::Inbound
        };
        assert_eq!(slot.kind(), expected);
    }
}

#[test]
fn the_inbound_half_fills_and_then_refuses_without_touching_the_outbound_half() {
    let slots = PeerSlots::new();
    let mut held = Vec::new();
    for _ in 0..INBOUND_SLOTS {
        let (client, server, address) = pair();
        held.push(client);
        assert!(slots.claim(SlotKind::Inbound, server, address).is_some());
    }
    assert_eq!(slots.occupied(SlotKind::Inbound), INBOUND_SLOTS);
    assert!(!slots.has_room(SlotKind::Inbound));

    // The twenty-third inbound connection has nowhere to go, and the node closes it rather
    // than evicting a peer that is already being served.
    let (client, server, address) = pair();
    held.push(client);
    assert!(slots.claim(SlotKind::Inbound, server, address).is_none());

    // The connections the node's own safety depends on were never at risk.
    assert_eq!(slots.occupied(SlotKind::Outbound), 0);
    assert!(slots.has_room(SlotKind::Outbound));
    let (client, server, address) = pair();
    held.push(client);
    assert!(slots.claim(SlotKind::Outbound, server, address).is_some());
}

#[test]
fn releasing_a_slot_puts_it_back_in_the_table() {
    let slots = PeerSlots::new();
    let (_client, server, address) = pair();
    let index = slots.claim(SlotKind::Inbound, server, address).unwrap();
    assert_eq!(slots.occupied(SlotKind::Inbound), 1);
    assert!(slots.wait_for_connection(index).is_some());

    slots.release(index);
    assert_eq!(slots.occupied(SlotKind::Inbound), 0);
    // Releasing twice is a no-op, not a counter that drifts.
    slots.release(index);
    assert_eq!(slots.occupied(SlotKind::Inbound), 0);
}

#[test]
fn a_thread_waiting_on_a_slot_is_woken_by_the_claim() {
    let slots = Arc::new(PeerSlots::new());
    let index = SlotIndex::new(u8::try_from(OUTBOUND_SLOTS).unwrap());
    let waiting = Arc::clone(&slots);
    let waiter = thread::spawn(move || {
        let started = Instant::now();
        let connection = waiting.wait_for_connection(index);
        (connection.is_some(), started.elapsed())
    });

    thread::sleep(Duration::from_millis(20));
    let (_client, server, address) = pair();
    assert_eq!(slots.claim(SlotKind::Inbound, server, address), Some(index));

    let (woken, elapsed) = waiter.join().unwrap();
    assert!(woken);
    // Woken by the claim, not by the tick behind it.
    assert!(elapsed < Duration::from_millis(200), "{elapsed:?}");
}

#[test]
fn closing_the_table_releases_a_thread_waiting_for_a_connection() {
    let slots = Arc::new(PeerSlots::new());
    let waiting = Arc::clone(&slots);
    let waiter = thread::spawn(move || waiting.wait_for_connection(SlotIndex::new(0)).is_none());
    thread::sleep(Duration::from_millis(20));
    assert_eq!(slots.shutdown_all(), 0);
    assert!(waiter.join().unwrap());
    assert!(slots.is_closing());
    // Nothing new is taken once the table is closing.
    let (_client, server, address) = pair();
    assert!(slots.claim(SlotKind::Inbound, server, address).is_none());
}

#[test]
fn closing_the_table_ends_a_read_a_thread_is_blocked_in() {
    let slots = Arc::new(PeerSlots::new());
    let (client, server, address) = pair();
    // The read timeout is the backstop; this test is about the mechanism in front of it, so
    // it is set far longer than the test can afford to wait.
    server
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let index = slots.claim(SlotKind::Inbound, server, address).unwrap();
    let connection = slots.wait_for_connection(index).unwrap();

    let reading = thread::spawn(move || {
        let mut buffer = [0u8; 64];
        let started = Instant::now();
        // The peer sends nothing at all: without the shutdown this blocks for thirty seconds.
        let read = (&*connection.stream).read(&mut buffer);
        (read.is_ok_and(|read| read == 0), started.elapsed())
    });

    thread::sleep(Duration::from_millis(50));
    assert_eq!(slots.shutdown_all(), 1);

    let (ended, elapsed) = reading.join().unwrap();
    assert!(ended, "the read ended at end of stream");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    drop(client);
}

#[test]
#[should_panic(expected = "assertion failed")]
fn a_slot_index_cannot_be_built_out_of_range() {
    let _out_of_range = SlotIndex::new(u8::try_from(PEER_SLOTS).unwrap());
}
