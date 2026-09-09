// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node stopped the way an operator stops it: a signal to a running process, with a peer
//! connected and a thread blocked in a read.
//!
//! These run the real binary, because the two things worth testing here are the two the
//! process boundary owns: that a handler reaches every thread, and that a second signal
//! leaves at once.

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// The inbound half of the node's slot table.
const INBOUND_SLOTS: usize = 22;

/// What the node exits with when it is asked to stop twice.
const EXIT_SECOND_SIGNAL: i32 = 2;

/// How long a clean stop is allowed to take. The node's own deadline for the threads that
/// hold nothing is five seconds, and nothing here should come close to it.
const STOP_LIMIT: Duration = Duration::from_secs(20);

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
    assert!(line.contains("69 threads"), "{line:?}");
    (child, lines, address)
}

/// Send a signal to the node, the way `kill` does.
fn signal(child: &Child, signum: i32) {
    assert!(try_signal(child, signum), "the node is still running");
}

/// Send a signal, saying whether it reached anything: a node that has already exited is not
/// an error when the point of the test is to keep asking.
fn try_signal(child: &Child, signum: i32) -> bool {
    let pid = i32::try_from(child.id()).expect("a pid fits an int");
    // The one call these tests make that `std` has no wrapper for.
    #[allow(unsafe_code, reason = "no safe wrapper: signalling another process")]
    let sent = unsafe { libc::kill(pid, signum) };
    sent == 0
}

/// Wait for the node to exit, bounded.
fn wait(child: &mut Child) -> Option<i32> {
    let deadline = Instant::now() + STOP_LIMIT;
    while Instant::now() < deadline {
        match child.try_wait().expect("the node is waitable") {
            Some(status) => return Some(status.code().unwrap_or(-1)),
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    None
}

#[test]
fn sigint_stops_a_node_with_a_peer_blocked_in_a_read() {
    let (mut child, mut lines, address) = start();

    // A peer that connects and then says nothing at all: its reader thread is inside a
    // blocking read, which is the state the shutdown has to be able to end.
    let peer = TcpStream::connect(address).expect("the node accepts");
    let mut announced = String::new();
    lines.read_line(&mut announced).expect("the node says so");
    assert!(announced.contains("peer 10 in from"), "{announced:?}");

    let asked = Instant::now();
    signal(&child, libc::SIGINT);
    let status = wait(&mut child);
    let took = asked.elapsed();

    assert_eq!(status, Some(0), "a clean stop");
    assert!(took < STOP_LIMIT, "{took:?}");

    let mut said = String::new();
    lines
        .get_mut()
        .read_to_string(&mut said)
        .expect("the rest of what it said");
    assert!(said.contains("stopping on SIGINT"), "{said:?}");
    assert!(said.contains("closed 1 peer connections"), "{said:?}");
    assert!(
        said.contains("0 bytes"),
        "the reader was in a read: {said:?}"
    );
    assert!(
        said.contains("stopped, 69 threads joined"),
        "every thread returned: {said:?}",
    );
    drop(peer);
}

#[test]
fn sigterm_stops_it_too() {
    let (mut child, mut lines, _address) = start();
    signal(&child, libc::SIGTERM);
    assert_eq!(wait(&mut child), Some(0));

    let mut said = String::new();
    lines
        .get_mut()
        .read_to_string(&mut said)
        .expect("the rest of what it said");
    assert!(said.contains("stopping on SIGTERM"), "{said:?}");
}

#[test]
fn a_second_signal_leaves_at_once() {
    let (mut child, _lines, address) = start();

    // A full inbound table, so the shutdown has thirty-two sockets and sixty-four threads to
    // get through rather than none: this is the long stop the escape hatch exists for.
    let mut peers = Vec::with_capacity(INBOUND_SLOTS);
    for _ in 0..INBOUND_SLOTS {
        peers.push(TcpStream::connect(address).expect("the node accepts"));
    }

    // An operator holding Ctrl-C down. The first signal starts the sequence; a standard
    // signal that arrives while the same one is still pending is dropped rather than
    // queued, so one extra `kill` is not enough to prove anything — asking until the node
    // is gone is what an impatient operator actually does.
    let mut asked = 0;
    let deadline = Instant::now() + STOP_LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the node is waitable") {
            break status.code().unwrap_or(-1);
        }
        assert!(Instant::now() < deadline, "the node never stopped");
        if try_signal(&child, libc::SIGINT) {
            asked += 1;
        }
    };

    assert!(asked >= 2, "asked {asked} times");
    assert_eq!(status, EXIT_SECOND_SIGNAL, "asked twice, left immediately");
    drop(peers.pop());
}
