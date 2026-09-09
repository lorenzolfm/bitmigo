// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outbound queue at its bound, which is the one queue in the node that answers a full
//! queue by ending the connection.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::{Outbox, OutboxFull};
use crate::peer::OUTBOX_MAX_BYTES;

#[test]
fn frames_come_back_in_the_order_they_went_in() {
    let outbox = Outbox::with_bound(1024);
    assert!(outbox.push(vec![1u8; 4]).is_ok());
    assert!(outbox.push(vec![2u8; 4]).is_ok());
    assert_eq!(outbox.len(), 2);
    assert_eq!(outbox.bytes(), 8);

    assert_eq!(outbox.pop(Duration::ZERO), Some(vec![1u8; 4]));
    assert_eq!(outbox.pop(Duration::ZERO), Some(vec![2u8; 4]));
    assert_eq!(outbox.bytes(), 0);
    assert_eq!(outbox.pop(Duration::ZERO), None);
    assert!(!outbox.is_closed());
}

/// Core pauses its sender when the buffer fills; this node ends the connection, because a
/// peer that will not read what it asked for has already said what it is worth.
#[test]
fn a_peer_that_stops_reading_loses_the_connection_rather_than_the_bound() {
    let outbox = Outbox::with_bound(64);
    assert!(outbox.push(vec![0u8; 40]).is_ok());
    assert_eq!(outbox.push(vec![0u8; 40]), Err(OutboxFull));

    // Closed by the overflow, not merely refused: anything queued behind it would be
    // written to a connection that is about to end.
    assert!(outbox.is_closed());
    assert_eq!(outbox.push(vec![0u8; 1]), Err(OutboxFull));
}

/// The writer's only blocking point, and it is bounded like every other wait in the node.
#[test]
fn a_writer_waiting_on_an_empty_outbox_is_woken_by_a_push() {
    let outbox = Arc::new(Outbox::with_bound(1024));
    let waiting = Arc::clone(&outbox);
    let writer = thread::spawn(move || {
        let started = Instant::now();
        let frame = waiting.pop(Duration::from_secs(5));
        (frame, started.elapsed())
    });

    thread::sleep(Duration::from_millis(20));
    assert!(outbox.push(vec![9u8; 3]).is_ok());
    let (frame, waited) = writer.join().unwrap();
    assert_eq!(frame, Some(vec![9u8; 3]));
    assert!(waited < Duration::from_secs(5), "{waited:?}");
}

#[test]
fn closing_releases_a_writer_that_is_waiting() {
    let outbox = Arc::new(Outbox::with_bound(1024));
    let waiting = Arc::clone(&outbox);
    let writer = thread::spawn(move || waiting.pop(Duration::from_secs(5)));

    thread::sleep(Duration::from_millis(20));
    outbox.close();
    assert_eq!(writer.join().unwrap(), None);
    assert!(outbox.is_closed());
}

/// What is queued to a peer is a reply, never a block: blocks are written straight from the
/// disk. So a frame larger than the whole outbox is this node's bug, and says so.
#[test]
#[should_panic(expected = "a frame larger than the outbox")]
fn a_frame_larger_than_the_outbox_is_a_programming_error() {
    let outbox = Outbox::with_bound(64);
    let _too_big = outbox.push(vec![0u8; 65]);
}

#[test]
fn the_bound_is_cores_send_buffer() {
    assert_eq!(OUTBOX_MAX_BYTES, 1024 * 1024);
}
