// SPDX-License-Identifier: MIT OR Apache-2.0

//! The download path, driven over a real socket by a process that is not the node.
//!
//! The headers are bitcoind v31.1.0's own, mined on regtest and kept in
//! `tests/data/regtest-headers.hex`, so what this peer answers with is what a real peer
//! would answer with. Everything the node does with them — accepting them into the tree,
//! deciding which blocks it is missing, and asking for exactly those — happens in the
//! binary an operator would run.

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, ChildStdout, Command, Stdio};

use bitcoin::block::Header;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;

use common::{DataDir, PROTOCOL_VERSION, Peer, regtest_headers};

/// Core's `MAX_BLOCKS_IN_TRANSIT_PER_PEER`, which is what one peer is asked for at once.
const MAX_BLOCKS_IN_FLIGHT: usize = 16;

/// Start the node on a port the operating system picks, and wait until it says where.
fn start(data: &DataDir) -> (Child, BufReader<ChildStdout>, SocketAddr) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bitmigo"))
        .arg("127.0.0.1:0")
        .env("XDG_DATA_HOME", data.path())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the node starts");
    let stdout = child.stdout.take().expect("a piped stdout");
    let mut lines = BufReader::new(stdout);
    let mut line = String::new();
    lines.read_line(&mut line).expect("the node says something");
    let address = line
        .split_whitespace()
        .nth(3)
        .and_then(|field| field.trim_end_matches(',').parse().ok())
        .unwrap_or_else(|| panic!("no address in {line:?}"));
    (child, lines, address)
}

/// Stop the node however this test left it.
fn stop(child: &mut Child) {
    let _killed = child.kill();
    let _waited = child.wait();
}

/// Read the node's own account of itself until it says this, or a handful of lines pass.
fn waits_for(lines: &mut BufReader<ChildStdout>, wanted: &str) -> Option<String> {
    for _ in 0..8 {
        let mut line = String::new();
        if lines.read_line(&mut line).unwrap_or(0) == 0 {
            return None;
        }
        if line.contains(wanted) {
            return Some(line);
        }
    }
    None
}

/// The whole loop: `sendheaders`, `getheaders`, two hundred real headers, and a `getdata`
/// for the sixteen blocks that answer them.
#[test]
fn the_node_asks_for_headers_and_then_for_the_blocks_they_name() {
    let data = DataDir::new();
    let (mut child, _lines, address) = start(&data);
    let mut peer = Peer::connect(address);
    peer.handshake();

    // Announce with headers, please: one round trip per block instead of two.
    let announce = peer.recv_until(|message| matches!(message, NetworkMessage::SendHeaders));
    assert_eq!(announce, Some(NetworkMessage::SendHeaders));

    let asked = peer.recv_until(|message| matches!(message, NetworkMessage::GetHeaders(_)));
    let Some(NetworkMessage::GetHeaders(request)) = asked else {
        stop(&mut child);
        panic!("the node asks a peer it can reach for headers: {asked:?}");
    };
    let headers = regtest_headers();
    let genesis = headers.first().expect("the fixture starts at genesis");
    assert_eq!(
        request.locator_hashes,
        vec![genesis.block_hash()],
        "a node holding only genesis has only genesis to say",
    );
    assert_eq!(request.version, PROTOCOL_VERSION);

    // Everything above genesis, as bitcoind mined it.
    let above: Vec<Header> = headers.iter().skip(1).copied().collect();
    assert_eq!(above.len(), 200);
    peer.send(NetworkMessage::Headers(above.clone()));

    let asked = peer.recv_until(|message| matches!(message, NetworkMessage::GetData(_)));
    let Some(NetworkMessage::GetData(items)) = asked else {
        stop(&mut child);
        panic!("the node asks for the blocks it is missing: {asked:?}");
    };
    assert_eq!(
        items.len(),
        MAX_BLOCKS_IN_FLIGHT,
        "sixteen at a time from one peer, which is what bounds what it can send back",
    );
    let wanted: Vec<Inventory> = above
        .iter()
        .take(MAX_BLOCKS_IN_FLIGHT)
        .map(|header| Inventory::WitnessBlock(header.block_hash()))
        .collect();
    assert_eq!(
        items, wanted,
        "the first sixteen blocks above the tip, with their witnesses, lowest first",
    );
    stop(&mut child);
}

/// A block nobody asked for ends the connection, which is the rule the four-megabyte read
/// cap rests on: a peer may send a block that large only while it owes this node one.
#[test]
fn a_block_nobody_asked_for_ends_the_connection() {
    let data = DataDir::new();
    let (mut child, mut lines, address) = start(&data);
    let mut peer = Peer::connect(address);
    peer.handshake();
    assert!(
        peer.recv_until(|message| matches!(message, NetworkMessage::GetHeaders(_)))
            .is_some()
    );

    // A real block, correctly framed, and one this node never asked this peer for.
    let block = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    peer.send(NetworkMessage::Block(block));

    assert_eq!(peer.recv_until(|_| false), None, "the node shut the socket");
    let said = waits_for(&mut lines, "gone:").expect("the disconnect line");
    assert!(said.contains("unrequested block"), "{said:?}");
    assert!(said.contains("(misbehaving)"), "{said:?}");
    stop(&mut child);
}
