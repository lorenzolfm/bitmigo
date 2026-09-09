// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outstanding-request table, and the two rules read off it.

use std::time::Instant;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget};
use bitmigo_consensus::header::Context;
use bitmigo_consensus::params::{BlockTime, ChainParams, Height, RegtestOverrides};

use super::{BlockRequest, MAX_BLOCKS_IN_FLIGHT, Requests};

fn hash(byte: u8) -> BlockHash {
    BlockHash::from_byte_array([byte; 32])
}

/// A context for a block at height one on regtest: what a download request carries.
fn context() -> Context {
    let params = ChainParams::regtest(RegtestOverrides::default());
    let rules = params.rules_at(Height::new(1), hash(0), None);
    Context::new(
        Height::new(1),
        BlockTime::new(1_296_688_602),
        BlockTime::new(1_296_688_602),
        CompactTarget::from_consensus(0x207f_ffff),
        rules,
    )
}

fn request(byte: u8) -> BlockRequest {
    BlockRequest {
        hash: hash(byte),
        context: context(),
        requested_at: Instant::now(),
    }
}

#[test]
fn a_block_that_answers_a_request_is_taken_and_the_request_is_gone() {
    let requests = Requests::new();
    assert!(requests.record(request(1)));
    assert_eq!(requests.outstanding(), 1);

    let taken = requests.take(hash(1)).expect("the request this answers");
    assert_eq!(taken.hash, hash(1));
    assert_eq!(taken.context.height(), Height::new(1));
    // Once, not twice: a second copy of the same block answers nothing.
    assert!(requests.take(hash(1)).is_none());
    assert_eq!(requests.outstanding(), 0);
}

/// The refuse-unrequested rule, at the table: nothing was asked for, so nothing answers.
#[test]
fn a_block_nobody_asked_for_matches_nothing() {
    let requests = Requests::new();
    assert!(requests.take(hash(7)).is_none());

    assert!(requests.record(request(1)));
    assert!(requests.take(hash(2)).is_none());
    assert_eq!(requests.outstanding(), 1);
}

/// The bound is what keeps the four-megabyte read cap from being licensed indefinitely.
#[test]
fn the_table_is_bounded_at_cores_in_flight_limit() {
    let requests = Requests::new();
    for byte in 0..MAX_BLOCKS_IN_FLIGHT {
        assert!(requests.record(request(u8::try_from(byte).unwrap())));
    }
    assert_eq!(requests.outstanding(), MAX_BLOCKS_IN_FLIGHT);
    assert!(!requests.record(request(200)));
    assert_eq!(MAX_BLOCKS_IN_FLIGHT, 16);
}

#[test]
fn the_same_block_is_not_asked_of_the_same_peer_twice() {
    let requests = Requests::new();
    assert!(requests.record(request(1)));
    assert!(!requests.record(request(1)));
    assert_eq!(requests.outstanding(), 1);
}

#[test]
fn the_oldest_request_is_the_one_a_stall_is_measured_from() {
    let requests = Requests::new();
    assert!(requests.oldest().is_none());
    let first = request(1);
    assert!(requests.record(first));
    assert!(requests.record(request(2)));
    assert_eq!(requests.oldest(), Some(first.requested_at));
}

/// A connection ending gives its blocks back to the scheduler rather than losing them.
#[test]
fn ending_a_connection_gives_the_blocks_back() {
    let requests = Requests::new();
    assert!(requests.record(request(1)));
    assert!(requests.record(request(2)));
    assert_eq!(requests.clear(), 2);
    assert_eq!(requests.outstanding(), 0);
}
