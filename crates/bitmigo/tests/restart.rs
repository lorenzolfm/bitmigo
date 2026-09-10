// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ordinary restart: a node stopped the way an operator stops it, started again on the
//! same data directory, and picking up where it left off.
//!
//! The store's own tests prove the index round trip against bitcoind's blocks a piece at a
//! time. What only a process can show is the rest of it: that the layout is made and locked
//! at startup, that a second bitmigo on one directory is refused, that a clean stop commits
//! what the chain thread has, and that the next start replays it rather than asking a peer
//! for two hundred headers it already has.
//!
//! `kill -9` at seeded points belongs to BM-12, where the muhash oracle already is
//! (BM-D4 decision 6). This is the ordinary case.

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::p2p::message::NetworkMessage;

use common::{DataDir, Peer, regtest_headers};

/// How long a clean stop is allowed to take.
const STOP_LIMIT: Duration = Duration::from_secs(20);

/// Start the node on a port the operating system picks, in a data directory of its own.
///
/// Everything it says before it binds comes back with it: the index is replayed first, so
/// that a store this node cannot read stops it before it answers anybody, and what the
/// replay found is the line this test is about.
fn start(data: &DataDir) -> (Child, BufReader<ChildStdout>, SocketAddr, Vec<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bitmigo"))
        .arg("127.0.0.1:0")
        .env("XDG_DATA_HOME", data.path())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the node starts");
    let stdout = child.stdout.take().expect("a piped stdout");
    let mut lines = BufReader::new(stdout);
    let mut before = Vec::new();
    let mut line = String::new();
    while !line.contains("listening on") {
        line.clear();
        assert!(
            lines.read_line(&mut line).unwrap_or(0) > 0,
            "the node stopped before it listened: {before:?}",
        );
        before.push(line.clone());
    }
    let address = line
        .split_whitespace()
        .nth(3)
        .and_then(|field| field.trim_end_matches(',').parse().ok())
        .unwrap_or_else(|| panic!("no address in {line:?}"));
    (child, lines, address, before)
}

/// Stop the node the way an operator does, and wait for it to finish.
fn stop_cleanly(child: &mut Child) -> i32 {
    let pid = i32::try_from(child.id()).expect("a pid fits an int");
    #[allow(unsafe_code, reason = "no safe wrapper: signalling another process")]
    let sent = unsafe { libc::kill(pid, libc::SIGINT) };
    assert_eq!(sent, 0, "the node is still running");
    let deadline = Instant::now() + STOP_LIMIT;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("the node is waitable") {
            return status.code().unwrap_or(-1);
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("the node did not stop");
}

/// Give the node two hundred of bitcoind's headers, and wait until it acts on them.
fn feed_headers(address: SocketAddr) -> Peer {
    let mut peer = Peer::connect(address);
    peer.handshake();
    let asked = peer.recv_until(|message| matches!(message, NetworkMessage::GetHeaders(_)));
    assert!(
        matches!(asked, Some(NetworkMessage::GetHeaders(_))),
        "{asked:?}"
    );

    let headers = regtest_headers();
    let above: Vec<_> = headers.iter().skip(1).copied().collect();
    assert_eq!(above.len(), 200);
    peer.send(NetworkMessage::Headers(above));

    // The `getdata` is how a test sees that the headers went into the tree: the node only
    // asks for blocks it is missing, and it was missing none of these a moment ago.
    let asked = peer.recv_until(|message| matches!(message, NetworkMessage::GetData(_)));
    assert!(
        matches!(asked, Some(NetworkMessage::GetData(_))),
        "{asked:?}"
    );
    peer
}

#[test]
fn a_node_that_is_stopped_and_started_again_keeps_the_headers_it_had() {
    let data = DataDir::new();
    let headers = regtest_headers();
    // One below the best header, which is Core's rule and the node's: a locator that
    // starts at the best header lets a peer with the same chain answer with an empty
    // `headers`, and an empty answer says nothing.
    let below_tip = headers.get(199).expect("a fixture tip").block_hash();
    let genesis = headers
        .first()
        .expect("the fixture starts at genesis")
        .block_hash();

    let (mut child, _lines, address, _said) = start(&data);
    let peer = feed_headers(address);
    drop(peer);

    // A clean stop is what commits the index: the alternative is crash recovery, and an
    // operator's Ctrl-C should not be one.
    assert_eq!(stop_cleanly(&mut child), 0);

    // The layout BM-D4 decision 9 states, made at the first start and still there.
    let chain = data.chain();
    assert!(chain.join("LOCK").is_file());
    assert!(chain.join("blocks").is_dir());
    assert!(chain.join("index").join("journal.dat").is_file());
    assert!(chain.join("coins").is_dir());

    let (mut child, _lines, address, said) = start(&data);
    let loaded = said
        .iter()
        .find(|line| line.contains("block index:"))
        .unwrap_or_else(|| panic!("the node says what it read: {said:?}"));
    assert!(loaded.contains("200 records"), "{loaded:?}");
    assert!(loaded.contains("201 headers"), "{loaded:?}");
    // Nothing is connected, because there is no coin store yet: BM-D4's load rule with the
    // one term it has, and every block is connected again when there is one (BM-27).
    assert!(loaded.contains("0 connected"), "{loaded:?}");
    assert!(!loaded.contains("torn"), "{loaded:?}");

    // And the headers are not just counted, they are usable: the locator this node offers
    // a fresh peer starts at the tip it loaded rather than at genesis.
    let mut peer = Peer::connect(address);
    peer.handshake();
    let asked = peer.recv_until(|message| matches!(message, NetworkMessage::GetHeaders(_)));
    let Some(NetworkMessage::GetHeaders(request)) = asked else {
        stop_cleanly(&mut child);
        panic!("the node asks for headers from where it got to: {asked:?}");
    };
    assert_eq!(
        request.locator_hashes.first().copied(),
        Some(below_tip),
        "a node that reloaded two hundred headers asks from where it got to",
    );
    assert_ne!(
        request.locator_hashes.first().copied(),
        Some(genesis),
        "and not from genesis, which is what it would have had to do",
    );
    assert_eq!(stop_cleanly(&mut child), 0);
}

#[test]
fn a_second_bitmigo_on_one_data_directory_is_refused() {
    // Two processes on one store would corrupt the coin store, so this is not advice: the
    // second one says which directory and exits (BM-D4 decision 8).
    let data = DataDir::new();
    let (mut child, _lines, _address, _said) = start(&data);

    let second = Command::new(env!("CARGO_BIN_EXE_bitmigo"))
        .arg("127.0.0.1:0")
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("the second node runs");
    assert!(!second.status.success(), "the second bitmigo started");
    let said = String::from_utf8_lossy(&second.stderr);
    assert!(said.contains("another bitmigo is running"), "{said:?}");
    assert!(said.contains("regtest"), "{said:?}");
    // And it said so before binding a socket or answering anybody.
    assert!(
        String::from_utf8_lossy(&second.stdout).is_empty(),
        "the refusal comes before the node listens",
    );

    // The kernel drops the lock with the process, so the next start simply works.
    assert_eq!(stop_cleanly(&mut child), 0);
    let (mut again, _lines, _address, _said) = start(&data);
    assert_eq!(stop_cleanly(&mut again), 0);
}
