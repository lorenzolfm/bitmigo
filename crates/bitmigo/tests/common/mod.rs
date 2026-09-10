// SPDX-License-Identifier: MIT OR Apache-2.0

//! What every test that runs the real binary needs: a data directory of its own, and a
//! peer that speaks the wire.
//!
//! The data directory is not a convenience. The node takes a lock on it for the life of
//! the process (BM-D4 decision 8), so two tests pointed at one directory would be two
//! bitmigos on one store — which is exactly what the lock exists to refuse. One directory
//! per test, removed with it.

#![allow(dead_code, reason = "each test binary uses the part of this it needs")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, deserialize_partial, serialize};
use bitcoin::hashes::hex::FromHex;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};

/// The node runs on regtest until there are flags to say otherwise.
pub const MAGIC: Magic = Magic::REGTEST;

/// Core's `PROTOCOL_VERSION` at v31.1, which is what this node speaks.
pub const PROTOCOL_VERSION: u32 = 70_016;

/// How long a test waits for the node to answer. Everything here is loopback, but the
/// chain thread looks at its schedule four times a second.
pub const REPLY_LIMIT: Duration = Duration::from_secs(10);

/// Two hundred and one headers from a regtest chain bitcoind v31.1.0 mined.
const BITCOIND_REGTEST_HEADERS: &str = include_str!("../data/regtest-headers.hex");

/// A directory the node can keep its store in, removed when the test ends.
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// One no other test is using.
    pub fn new() -> DataDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "bitmigo-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst),
        );
        let root = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&root).expect("a test data directory");
        DataDir { root }
    }

    /// What to put in `XDG_DATA_HOME`, which is where the node looks.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// The chain's own directory below it, which is what the node locks.
    pub fn chain(&self) -> PathBuf {
        self.root.join("bitmigo").join("regtest")
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.root) {
            eprintln!("test data directory {}: {error}", self.root.display());
        }
    }
}

/// The headers bitcoind mined, in height order.
pub fn regtest_headers() -> Vec<Header> {
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
pub struct Peer {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Peer {
    pub fn connect(address: SocketAddr) -> Peer {
        let stream = TcpStream::connect(address).expect("the node accepts");
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("a read timeout");
        Peer {
            stream,
            buffer: Vec::new(),
        }
    }

    pub fn send(&mut self, message: NetworkMessage) {
        let frame = serialize(&RawNetworkMessage::new(MAGIC, message));
        self.stream.write_all(&frame).expect("the node is reading");
    }

    pub fn recv(&mut self) -> Option<NetworkMessage> {
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
    pub fn recv_until(
        &mut self,
        wanted: impl Fn(&NetworkMessage) -> bool,
    ) -> Option<NetworkMessage> {
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
    pub fn handshake(&mut self) {
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
