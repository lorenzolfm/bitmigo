// SPDX-License-Identifier: MIT OR Apache-2.0

//! Anchors, the candidate queue and the netgroup rule. Nothing here touches the network:
//! the one function that would, [`super::Candidates::query_seeds`], is a DNS lookup and is
//! exercised by the regtest harness, which has no seeds.

use std::net::SocketAddr;

use bitmigo_consensus::params::{ChainParams, RegtestOverrides};

use super::{Candidates, MAX_ANCHORS, MAX_CANDIDATES, netgroup};
use crate::peer::Network;

fn address(last: u8, port: u16) -> SocketAddr {
    SocketAddr::from(([203, 0, 113, last], port))
}

/// A temporary directory outside the source tree, named after the test that asked for it.
fn scratch(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join("bitmigo-tests").join(name);
    let _removed = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn candidates(directory: &std::path::Path) -> Candidates {
    let network = Network::of(&ChainParams::regtest(RegtestOverrides::default()));
    Candidates::new(&network, directory)
}

#[test]
fn the_queue_refuses_duplicates_and_does_not_grow_past_its_bound() {
    let directory = scratch("candidates-bound");
    let table = candidates(&directory);

    assert!(table.offer(address(1, 8333)));
    assert!(!table.offer(address(1, 8333)));
    // The same host on another port is another peer.
    assert!(table.offer(address(1, 8334)));
    assert_eq!(table.len(), 2);

    for port in 0..u16::try_from(MAX_CANDIDATES).unwrap() {
        let _offered = table.offer(SocketAddr::from(([198, 51, 100, 1], port)));
    }
    assert_eq!(table.len(), MAX_CANDIDATES);
    assert!(!table.offer(address(9, 9999)));
}

/// The queue rotates rather than spinning on its first entry: an address that was just
/// dialled goes to the back.
#[test]
fn a_dialled_address_is_not_offered_again_straight_away() {
    let directory = scratch("candidates-rotate");
    let table = candidates(&directory);
    assert!(table.offer(address(1, 8333)));
    assert!(table.offer(address(2, 8333)));

    assert_eq!(table.next(), Some(address(1, 8333)));
    assert_eq!(table.next(), Some(address(2, 8333)));
    // Both are now recently tried, so a third call has nothing fresh to give — and both
    // are still on the queue, because a failed dial must not lose an address.
    assert_eq!(table.next(), None);
    assert_eq!(table.len(), 2);
}

#[test]
fn an_empty_table_has_nothing_to_dial() {
    let directory = scratch("candidates-empty");
    let table = candidates(&directory);
    assert_eq!(table.next(), None);
    assert_eq!(table.load_anchors(), 0);
}

/// The point of an anchor: it survives a restart, and it is dialled before anything a
/// stranger suggested.
#[test]
fn anchors_are_written_read_back_and_dialled_first() {
    let directory = scratch("anchors");
    let stopping = candidates(&directory);
    stopping
        .save_anchors(&[address(10, 18444), address(11, 18444)])
        .unwrap();

    let starting = candidates(&directory);
    assert!(starting.offer(address(99, 18444)));
    assert_eq!(starting.load_anchors(), 2);
    assert_eq!(starting.len(), 3);

    // Front of the queue, ahead of the address that was already there.
    let first = starting.next().unwrap();
    let second = starting.next().unwrap();
    assert!(first == address(10, 18444) || first == address(11, 18444));
    assert!(second == address(10, 18444) || second == address(11, 18444));
    assert_ne!(first, second);
    assert_eq!(starting.next(), Some(address(99, 18444)));
    // And nothing was lost by dialling: an anchor survives a failed connect too.
    assert_eq!(starting.len(), 3);
}

#[test]
fn a_missing_or_damaged_anchors_file_is_the_ordinary_case() {
    let directory = scratch("anchors-damaged");
    let table = candidates(&directory);
    assert_eq!(table.load_anchors(), 0);

    std::fs::write(directory.join("anchors"), "not an address\n\n").unwrap();
    assert_eq!(table.load_anchors(), 0);
    assert_eq!(table.len(), 0);
}

#[test]
#[should_panic(expected = "two anchors")]
fn more_anchors_than_core_keeps_is_a_programming_error() {
    let directory = scratch("anchors-too-many");
    let table = candidates(&directory);
    let too_many = vec![address(1, 1), address(2, 2), address(3, 3)];
    assert_eq!(MAX_ANCHORS, 2);
    let _refused = table.save_anchors(&too_many);
}

/// The one eclipse defence that costs nothing: a second address in the same /16 buys an
/// attacker no second outbound slot.
#[test]
fn addresses_in_the_same_block_share_a_netgroup() {
    assert_eq!(netgroup(address(1, 8333)), netgroup(address(200, 8333)));
    assert_ne!(
        netgroup(address(1, 8333)),
        netgroup(SocketAddr::from(([198, 51, 100, 1], 8333))),
    );
    // The port is not part of the group: two nodes behind one address are one attacker.
    assert_eq!(netgroup(address(1, 8333)), netgroup(address(1, 18444)));
}

#[test]
fn ipv6_is_grouped_by_its_first_four_bytes() {
    let one: SocketAddr = "[2001:db8:1::1]:8333".parse().unwrap();
    let two: SocketAddr = "[2001:db8:2::2]:8333".parse().unwrap();
    let other: SocketAddr = "[2a00:1450::1]:8333".parse().unwrap();
    assert_eq!(netgroup(one), netgroup(two));
    assert_ne!(netgroup(one), netgroup(other));
}
