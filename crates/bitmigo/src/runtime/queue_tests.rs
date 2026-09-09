// SPDX-License-Identifier: MIT OR Apache-2.0

//! The queues driven to their bounds, and the order the backpressure arrives in.

use std::sync::Arc;
use std::thread::{self, Builder};
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget};
use bitmigo_consensus::header::Context;
use bitmigo_consensus::params::{BlockTime, ChainParams, Height, RegtestOverrides};

use super::{
    BlockLocation, ChainToValidation, Closed, ConnectJob, JobKind, PeerMessage, PeerToChain,
    Received, Sent,
};
use crate::peer::{READER_THREAD_PREFIX, SlotIndex};

/// A message of `bytes` payload from slot zero.
fn message(bytes: usize) -> PeerMessage {
    PeerMessage {
        peer: SlotIndex::new(0),
        bytes: vec![0u8; bytes],
    }
}

/// A job for a block at `height`, with a regtest context.
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

/// Run `body` on a thread named the way the supervisor names a peer reader, which is what
/// the queue asserts on before it lets anyone block.
fn as_peer_reader<B>(body: B) -> thread::JoinHandle<()>
where
    B: FnOnce() + Send + 'static,
{
    Builder::new()
        .name(format!("{READER_THREAD_PREFIX}00"))
        .spawn(body)
        .expect("a test thread")
}

#[test]
fn a_send_with_room_does_not_wait() {
    let queue: PeerToChain<PeerMessage> = PeerToChain::with_bounds(1024 * 1024, 16);
    assert_eq!(queue.send(message(1024)), Ok(Sent::Immediately));
    assert_eq!(queue.len(), 1);
    assert!(queue.bytes() >= 1024);
}

#[test]
fn the_byte_bound_stops_a_queue_of_blocks_before_the_item_bound_does() {
    // 256 KiB messages fill a megabyte long before a thousand of them have arrived.
    let queue: PeerToChain<PeerMessage> = PeerToChain::with_bounds(1024 * 1024, 1024);
    let mut queued = 0;
    while queue.try_send(message(256 * 1024)).is_ok() {
        queued += 1;
    }
    // Three, not four: what a message owns is what is counted, and its own footprint is
    // part of that, so the fourth does not fit under the bound.
    assert_eq!(queued, 3);
    assert_eq!(queue.len(), 3);
    assert!(queue.bytes() <= 1024 * 1024);
    assert!(queue.bytes() > 768 * 1024);
}

#[test]
fn the_item_bound_stops_a_queue_of_small_messages_before_the_byte_bound_does() {
    let queue: PeerToChain<PeerMessage> = PeerToChain::with_bounds(1024 * 1024, 8);
    for _ in 0..8 {
        assert!(queue.try_send(message(1)).is_ok());
    }
    assert!(queue.try_send(message(1)).is_err());
    assert_eq!(queue.len(), 8);
    assert!(queue.bytes() < 1024);
}

#[test]
fn a_full_queue_blocks_its_reader_until_the_chain_drains_it() {
    let queue: Arc<PeerToChain<PeerMessage>> = Arc::new(PeerToChain::with_bounds(64 * 1024, 1024));
    assert!(queue.try_send(message(48 * 1024)).is_ok());

    let sender = Arc::clone(&queue);
    let reader = as_peer_reader(move || {
        // No room: this is the one blocking send the node has, and it is on a peer reader.
        let sent = sender
            .send(message(48 * 1024))
            .expect("the queue stays open");
        assert!(matches!(sent, Sent::AfterWaiting(_)), "{sent:?}");
    });

    // The send is still waiting: nothing has drained.
    thread::sleep(Duration::from_millis(50));
    assert_eq!(queue.len(), 1);

    // The chain thread takes one item, and the reader gets in.
    assert!(matches!(
        queue.recv(Duration::from_millis(500)),
        Received::Item(_)
    ));
    reader.join().expect("the reader returns once it has room");
    assert_eq!(queue.len(), 1);
}

#[test]
#[should_panic(expected = "only a peer reader may block on a full queue")]
fn a_thread_that_is_not_a_peer_reader_may_not_block() {
    let queue: PeerToChain<PeerMessage> = PeerToChain::with_bounds(4096, 1);
    assert!(queue.try_send(message(64)).is_ok());
    // This test's own thread is not a peer reader, so blocking here is the bug the
    // assertion exists to catch: a sole consumer that blocks stops draining.
    let _blocked = queue.send(message(64));
}

#[test]
#[should_panic(expected = "an item larger than the whole queue")]
fn an_item_larger_than_the_queue_is_a_programming_error() {
    let queue: PeerToChain<PeerMessage> = PeerToChain::with_bounds(1024, 16);
    let _too_big = queue.send(message(4096));
}

#[test]
fn an_item_at_the_bound_still_goes_through_an_empty_queue() {
    let queue: PeerToChain<PeerMessage> = PeerToChain::with_bounds(4096, 16);
    assert_eq!(queue.send(message(4000)), Ok(Sent::Immediately));
}

#[test]
fn closing_the_queue_releases_a_blocked_reader() {
    let queue: Arc<PeerToChain<PeerMessage>> = Arc::new(PeerToChain::with_bounds(4096, 1));
    assert!(queue.try_send(message(64)).is_ok());

    let sender = Arc::clone(&queue);
    let reader = as_peer_reader(move || {
        assert_eq!(sender.send(message(64)), Err(Closed));
    });
    thread::sleep(Duration::from_millis(20));
    queue.close();
    reader.join().expect("a closed queue releases its senders");
}

#[test]
fn a_closed_queue_is_drained_before_the_consumer_stops() {
    let queue: PeerToChain<PeerMessage> = PeerToChain::with_bounds(4096, 8);
    assert!(queue.try_send(message(16)).is_ok());
    queue.close();
    assert!(matches!(
        queue.recv(Duration::from_millis(10)),
        Received::Item(_)
    ));
    assert_eq!(queue.recv(Duration::from_millis(10)), Received::Closed);
    assert!(queue.try_send(message(16)).is_err());
}

#[test]
fn an_empty_queue_reports_empty_rather_than_closed() {
    let queue: PeerToChain<PeerMessage> = PeerToChain::with_bounds(4096, 8);
    assert_eq!(queue.recv(Duration::from_millis(10)), Received::Empty);
}

#[test]
fn the_connect_queue_fills_to_its_bound_and_hands_the_job_back() {
    let queue = ChainToValidation::with_bound(4);
    assert_eq!(queue.room(), 4);
    for height in 1..=4 {
        assert!(queue.try_push(job(height)).is_ok());
    }
    assert_eq!(queue.room(), 0);
    // The chain thread's only option is to keep the job and stop topping up.
    let refused = queue.try_push(job(5)).expect_err("the queue is full");
    assert_eq!(refused.height(), Height::new(5));
    assert_eq!(queue.len(), 4);
}

#[test]
fn a_reorg_discards_the_jobs_that_descend_from_the_old_tip() {
    let queue = ChainToValidation::with_bound(8);
    for height in 1..=5 {
        assert!(queue.try_push(job(height)).is_ok());
    }
    assert_eq!(queue.discard(), 5);
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.room(), 8);
}

#[test]
fn jobs_come_back_in_the_order_the_chain_scheduled_them() {
    let queue = ChainToValidation::with_bound(8);
    for height in 1..=3 {
        assert!(queue.try_push(job(height)).is_ok());
    }
    for height in 1..=3 {
        match queue.pop(Duration::from_millis(10)) {
            Received::Item(job) => assert_eq!(job.height(), Height::new(height)),
            other => panic!("expected a job, got {other:?}"),
        }
    }
    assert_eq!(queue.pop(Duration::from_millis(10)), Received::Empty);
}

#[test]
fn closing_the_connect_queue_ends_validations_loop() {
    let queue = ChainToValidation::with_bound(4);
    assert!(queue.try_push(job(1)).is_ok());
    queue.close();
    assert!(matches!(
        queue.pop(Duration::from_millis(10)),
        Received::Item(_)
    ));
    assert_eq!(queue.pop(Duration::from_millis(10)), Received::Closed);
    assert!(queue.try_push(job(2)).is_err());
}

#[test]
fn a_job_carries_the_height_its_context_fixes() {
    let job = job(42);
    assert_eq!(job.height(), Height::new(42));
    assert_eq!(job.context.height(), Height::new(42));
    assert_eq!(job.kind, JobKind::Connect);
}
