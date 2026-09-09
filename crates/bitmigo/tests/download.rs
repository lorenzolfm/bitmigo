// SPDX-License-Identifier: MIT OR Apache-2.0

//! The download path, driven over a real socket by a process that is not the node.
//!
//! The headers are bitcoind v31.1.0's own, mined on regtest and kept in
//! `tests/data/regtest-headers.hex`, so what this peer answers with is what a real peer
//! would answer with. Everything the node does with them — accepting them into the tree,
//! deciding which blocks it is missing, and asking for exactly those — happens in the
//! binary an operator would run.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, deserialize_partial, serialize};
use bitcoin::hashes::hex::FromHex;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};

/// The node runs on regtest until there are flags to say otherwise.
const MAGIC: Magic = Magic::REGTEST;

/// Core's `PROTOCOL_VERSION` at v31.1, which is what this node speaks.
const PROTOCOL_VERSION: u32 = 70_016;

/// Core's `MAX_BLOCKS_IN_TRANSIT_PER_PEER`, which is what one peer is asked for at once.
const MAX_BLOCKS_IN_FLIGHT: usize = 16;

/// Two hundred and one headers from a regtest chain bitcoind mined.
const BITCOIND_REGTEST_HEADERS: &str = include_str!("data/regtest-headers.hex");

/// How long a test waits for the node to answer. Everything here is loopback, but the chain
/// thread looks at its schedule four times a second.
const REPLY_LIMIT: Duration = Duration::from_secs(10);

/// Start the node on a port the operating system picks, and wait until it says where.
fn start() -> (Child, BufReader<ChildStdout>, SocketAddr) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bitmigo"))
        .arg("127.0.0.1:0")
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

/// The headers bitcoind mined, in height order.
fn regtest_headers() -> Vec<Header> {
    BITCOIND_REGTEST_HEADERS
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let bytes = Vec::<u8>::from_hex(line.trim()).expect("a hex header");
            assert_eq!(bytes.len(), 80, "a header is eighty bytes");
            deserialize(&bytes).expect("bitcoind wrote it")
        })
        .collect()
}

/// One peer, framing messages the way the wire does.
struct Peer {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Peer {
    fn connect(address: SocketAddr) -> Peer {
        let stream = TcpStream::connect(address).expect("the node accepts");
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("a read timeout");
        Peer {
            stream,
            buffer: Vec::new(),
        }
    }

    fn send(&mut self, message: NetworkMessage) {
        let frame = serialize(&RawNetworkMessage::new(MAGIC, message));
        self.stream.write_all(&frame).expect("the node is reading");
    }

    fn recv(&mut self) -> Option<NetworkMessage> {
        let deadline = Instant::now() + REPLY_LIMIT;
        loop {
            if let Ok((decoded, used)) = deserialize_partial::<RawNetworkMessage>(&self.buffer) {
                self.buffer.drain(..used);
                return Some(decoded.into_payload());
            }
            if Instant::now() > deadline {
                return None;
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => return None,
                Ok(read) => self.buffer.extend_from_slice(chunk.get(..read)?),
                Err(_timeout) => {}
            }
        }
    }

    /// Read until a message of interest arrives, answering the node's pings on the way.
    fn recv_until(&mut self, wanted: impl Fn(&NetworkMessage) -> bool) -> Option<NetworkMessage> {
        for _ in 0..16 {
            let message = self.recv()?;
            if wanted(&message) {
                return Some(message);
            }
            if let NetworkMessage::Ping(nonce) = message {
                self.send(NetworkMessage::Pong(nonce));
            }
        }
        None
    }

    /// The handshake, from the side that was dialled by nobody: this peer speaks first,
    /// exactly as an inbound connection to the node does.
    fn handshake(&mut self) {
        let address = Address::new(&"127.0.0.1:18444".parse().unwrap(), ServiceFlags::NONE);
        let mut services = ServiceFlags::NETWORK;
        services.add(ServiceFlags::WITNESS);
        self.send(NetworkMessage::Version(VersionMessage {
            version: PROTOCOL_VERSION,
            services,
            timestamp: 0,
            receiver: address.clone(),
            sender: address,
            nonce: 0x5a5a_5a5a_5a5a_5a5a,
            user_agent: "/bitmigo-test:0/".to_owned(),
            start_height: 200,
            relay: true,
        }));
        assert!(matches!(self.recv(), Some(NetworkMessage::Version(_))));
        assert_eq!(self.recv(), Some(NetworkMessage::Verack));
        self.send(NetworkMessage::Verack);
    }
}

/// The whole loop: `sendheaders`, `getheaders`, two hundred real headers, and a `getdata`
/// for the sixteen blocks that answer them.
#[test]
fn the_node_asks_for_headers_and_then_for_the_blocks_they_name() {
    let (mut child, _lines, address) = start();
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
    let (mut child, mut lines, address) = start();
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
