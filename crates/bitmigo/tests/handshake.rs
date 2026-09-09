// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node spoken to over a real socket by a process that is not it.
//!
//! Everything else about the peer module is tested a message at a time; this is the one
//! test that puts the whole path together — the listener taking a connection, a reader
//! thread framing what arrives, the handshake, and a writer thread getting the answer back
//! out — against the binary an operator would run.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::consensus::{deserialize_partial, serialize};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};

/// The node runs on regtest until there are flags to say otherwise.
const MAGIC: Magic = Magic::REGTEST;

/// Core's `PROTOCOL_VERSION` at v31.1, which is what this node speaks.
const PROTOCOL_VERSION: u32 = 70_016;

/// How long a test waits for the node to answer. Everything here is loopback.
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
    assert!(line.contains("listening on"), "{line:?}");
    (child, lines, address)
}

/// Stop the node however this test left it.
fn stop(child: &mut Child) {
    let _killed = child.kill();
    let _waited = child.wait();
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

    /// Read until a message arrives, or give up. Nothing is answered here, so a test that
    /// wants two messages asks twice.
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
}

/// A `version` from a peer that offers what this node wants of one it dialled — which it
/// does not need to, being inbound, but a real Core node would.
fn version() -> NetworkMessage {
    let address = Address::new(&"127.0.0.1:18444".parse().unwrap(), ServiceFlags::NONE);
    let mut services = ServiceFlags::NETWORK;
    services.add(ServiceFlags::WITNESS);
    NetworkMessage::Version(VersionMessage {
        version: PROTOCOL_VERSION,
        services,
        timestamp: 0,
        receiver: address.clone(),
        sender: address,
        nonce: 0x5a5a_5a5a_5a5a_5a5a,
        user_agent: "/bitmigo-test:0/".to_owned(),
        start_height: 0,
        relay: true,
    })
}

/// The whole handshake, and then a `ping` answered with a `pong`: the reader read, the
/// session decided, and the writer wrote.
#[test]
fn the_node_completes_a_handshake_and_answers_a_ping() {
    let (mut child, _lines, address) = start();
    let mut peer = Peer::connect(address);

    peer.send(version());
    let their_version = peer.recv().expect("a version back");
    let NetworkMessage::Version(said) = their_version else {
        stop(&mut child);
        panic!("expected a version, got {their_version:?}");
    };

    // The three statements this node makes about itself, seen from the wire.
    assert_eq!(said.version, PROTOCOL_VERSION);
    assert!(!said.relay, "fRelay = 0 is the mempool-less contract");
    assert!(said.services.has(ServiceFlags::NETWORK));
    assert!(said.services.has(ServiceFlags::WITNESS));
    assert!(said.services.has(ServiceFlags::NETWORK_LIMITED));
    assert!(!said.services.has(ServiceFlags::BLOOM));
    assert!(said.user_agent.starts_with("/bitmigo:"), "{said:?}");

    assert_eq!(peer.recv(), Some(NetworkMessage::Verack));
    peer.send(NetworkMessage::Verack);

    peer.send(NetworkMessage::Ping(0x0102_0304_0506_0708));
    assert_eq!(
        peer.recv(),
        Some(NetworkMessage::Pong(0x0102_0304_0506_0708)),
    );
    stop(&mut child);
}

/// A peer that asks a node with no mempool for its mempool is disconnected, not ignored.
/// The socket closing is how a test sees a verdict the node reached on its own thread.
#[test]
fn a_mempool_request_ends_the_connection() {
    let (mut child, mut lines, address) = start();
    let mut peer = Peer::connect(address);

    peer.send(version());
    assert!(matches!(peer.recv(), Some(NetworkMessage::Version(_))));
    assert_eq!(peer.recv(), Some(NetworkMessage::Verack));
    peer.send(NetworkMessage::Verack);
    peer.send(NetworkMessage::MemPool);

    // The read returns nothing more: the node shut the socket down.
    assert_eq!(peer.recv(), None);

    let said = waits_for(&mut lines, "gone:").expect("the disconnect line");
    assert!(
        said.contains("mempool request without NODE_BLOOM"),
        "{said:?}"
    );
    assert!(said.contains("(misbehaving)"), "{said:?}");
    stop(&mut child);
}

/// Another network's magic is refused before anything is decoded, which is the bound that
/// exists so a peer cannot pick this node's buffer size.
#[test]
fn a_message_for_another_network_is_refused() {
    let (mut child, mut lines, address) = start();
    let mut peer = Peer::connect(address);
    peer.stream
        .write_all(&serialize(&RawNetworkMessage::new(
            Magic::BITCOIN,
            NetworkMessage::Verack,
        )))
        .expect("the node is reading");

    assert_eq!(peer.recv(), None);
    let said = waits_for(&mut lines, "gone:").expect("the disconnect line");
    assert!(said.contains("wrong magic"), "{said:?}");
    // Not blamed on anybody: this is also what a Core node's BIP324 handshake looks like
    // to a node that speaks only v1, and it reconnects over v1 straight afterwards.
    assert!(!said.contains("(misbehaving)"), "{said:?}");
    stop(&mut child);
}

/// Two nodes, one dialling the other: the connector, the outbound half of the handshake and
/// the diversity rule that lets a loopback address through.
///
/// The inbound half is covered by every other test here; this is the only one that exercises
/// the side that speaks first.
#[test]
fn a_node_dials_the_peer_it_was_pointed_at() {
    let (mut listening, mut listening_says, address) = start();
    let (mut dialling, mut dialling_says, _address) = start_dialling(address);

    let dialled = waits_for(&mut dialling_says, "ready:").expect("the dialling node's line");
    assert!(dialled.contains("/bitmigo:"), "{dialled:?}");
    let accepted = waits_for(&mut listening_says, "ready:").expect("the listening node's line");
    assert!(accepted.contains("/bitmigo:"), "{accepted:?}");
    stop(&mut dialling);
    stop(&mut listening);
}

/// A node told where one other node is, which is bitcoind's `-addnode`.
fn start_dialling(peer: SocketAddr) -> (Child, BufReader<ChildStdout>, SocketAddr) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bitmigo"))
        .arg("127.0.0.1:0")
        .arg(peer.to_string())
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
    assert!(line.contains("listening on"), "{line:?}");
    (child, lines, address)
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
