// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a peer's service bits say it can do, and how long it gets to say anything at all.

use std::time::{Duration, Instant};

use bitcoin::p2p::ServiceFlags;
use bitmigo_consensus::params::BlockTime;

use super::{PeerDownload, can_serve_blocks, can_serve_witnesses, headers_timeout, is_limited};

/// What an unpruned Core node advertises (R4 §1.4), and what this node advertises back.
fn full_node() -> ServiceFlags {
    let mut services = ServiceFlags::NETWORK;
    services.add(ServiceFlags::WITNESS);
    services.add(ServiceFlags::NETWORK_LIMITED);
    services
}

/// A pruned node: the recent chain only.
fn pruned() -> ServiceFlags {
    let mut services = ServiceFlags::NETWORK_LIMITED;
    services.add(ServiceFlags::WITNESS);
    services
}

#[test]
fn a_full_node_can_serve_blocks_and_their_witnesses() {
    assert!(can_serve_blocks(full_node()));
    assert!(can_serve_witnesses(full_node()));
    assert!(!is_limited(full_node()));
}

#[test]
fn a_pruned_node_can_serve_blocks_but_only_the_recent_ones() {
    assert!(can_serve_blocks(pruned()));
    assert!(can_serve_witnesses(pruned()));
    assert!(is_limited(pruned()));
}

#[test]
fn a_peer_offering_nothing_is_asked_for_nothing() {
    assert!(!can_serve_blocks(ServiceFlags::NONE));
    assert!(!can_serve_witnesses(ServiceFlags::NONE));
    // Not limited either: "limited" is a claim about which blocks it has, and this peer has
    // made no claim at all.
    assert!(!is_limited(ServiceFlags::NONE));
}

#[test]
fn a_node_without_witness_is_no_use_whatever_else_it_offers() {
    assert!(can_serve_blocks(ServiceFlags::NETWORK));
    assert!(!can_serve_witnesses(ServiceFlags::NETWORK));
}

#[test]
fn a_peer_gets_a_quarter_of_an_hour_plus_a_millisecond_a_header() {
    let spacing = Duration::from_mins(10);
    let now = BlockTime::new(2_000_000_000);
    // Caught up: the base and nothing more.
    assert_eq!(headers_timeout(now, now, spacing), Duration::from_mins(15));
    // A thousand blocks behind: a thousand milliseconds more.
    let behind = BlockTime::new(now.get().saturating_sub(1000 * 600));
    assert_eq!(
        headers_timeout(behind, now, spacing),
        Duration::from_mins(15) + Duration::from_millis(1000),
    );
    // A clock that disagrees the other way costs nothing: the allowance is never negative.
    let ahead = BlockTime::new(now.get().saturating_add(10_000));
    assert_eq!(
        headers_timeout(ahead, now, spacing),
        Duration::from_mins(15)
    );
}

#[test]
fn a_row_belongs_to_one_connection_and_is_forgotten_with_it() {
    let first = Instant::now();
    let mut row = PeerDownload::default();
    assert!(
        row.describes(None),
        "an empty row is up to date about an empty slot"
    );
    assert!(!row.describes(Some(first)));

    row.reset(Some(first));
    row.sync_started = true;
    row.sendheaders_sent = true;
    assert!(row.describes(Some(first)));

    // The same slot, a different connection: everything the old peer was owed goes.
    let second = Instant::now();
    assert!(!row.describes(Some(second)));
    row.reset(Some(second));
    assert!(!row.sync_started);
    assert!(!row.sendheaders_sent);
    assert!(row.describes(Some(second)));
}
