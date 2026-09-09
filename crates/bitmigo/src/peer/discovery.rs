// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where to dial: anchors first, then whatever the network has told us, then DNS seeds.
//!
//! This is the minimum that keeps a node connected without being trivially eclipsed, and
//! it is deliberately not Core's address manager. Core's 1024/256/64 bucket geometry, its
//! secret bucketing key and its feeler connections all exist to make *gossiped* addresses
//! hard to poison; this node has ten outbound slots, remembers two anchors, and asks the
//! seeds when it cannot fill them. How much of the addrman is worth its weight is a
//! question the map still holds open, and answering it early would be guessing.
//!
//! What is not deferred is the one defence that costs nothing: **netgroup diversity**. Core
//! requires its non-feeler outbound connections to be in distinct netgroups, because an
//! attacker who owns one /16 must otherwise only fill a table to own a node's whole view of
//! the chain. [`netgroup`] is the cheap version of Core's `GetGroup` — the address's /16 or
//! /32 — and the connector refuses a candidate that shares one with a live connection.
//!
//! Anchors are Core's `anchors.dat` idea and not its format: two block-relay-only peers
//! written at a clean stop and dialled first at the next start, so that an attacker who
//! wants to eclipse this node has to survive a restart to do it. One address per line,
//! because a file a person can read is a file a person can fix.

use std::collections::VecDeque;
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::network::Network;
use crate::runtime::sync::lock;

/// Core's `MAX_BLOCK_RELAY_ONLY_ANCHORS`. Two, and the same two slots every time.
pub const MAX_ANCHORS: usize = 2;

/// How many addresses this node will hold on to. Core's addrman holds sixty-five thousand
/// because it gossips; this one dials ten peers and needs a queue, not a database.
pub const MAX_CANDIDATES: usize = 1024;

/// How many addresses one DNS seed may contribute, which is Core's `nMaxIPs`.
pub const MAX_ADDRESSES_PER_SEED: usize = 32;

/// Core's `SEED_OUTBOUND_CONNECTION_THRESHOLD`: below this many outbound connections, the
/// seeds are worth asking; at or above it they are not.
pub const SEED_OUTBOUND_THRESHOLD: usize = 2;

/// How many recently dialled addresses are remembered, so that a queue with two entries in
/// it does not become a tight reconnection loop.
const MAX_RECENT: usize = 256;

/// How long a dialled address waits before it is worth trying again, which is Core's own
/// ten minutes (`net.cpp: ThreadOpenConnections`). An address is kept rather than dropped
/// on a failed dial: this node has ten outbound slots and no failure counting, so throwing
/// candidates away would empty the queue and send it back to the DNS seeds. Counting
/// failures the way Core's addrman does is a decision the map still holds open.
const RETRY_INTERVAL: Duration = Duration::from_secs(600);

/// The name Core queries: `x<hex of NODE_NETWORK|NODE_WITNESS>.<seed>`, which asks the seed
/// for peers with those service bits (`net.cpp: ThreadDNSAddressSeed`).
const SEED_SERVICE_PREFIX: &str = "x9.";

/// The file anchors are written to, below the chain's data directory.
const ANCHORS_FILE: &str = "anchors";

/// Addresses worth dialling, in the order they are worth dialling in.
pub struct Candidates {
    seeds: &'static [&'static str],
    default_port: u16,
    anchors: PathBuf,
    queue: Mutex<VecDeque<SocketAddr>>,
    recent: Mutex<VecDeque<(SocketAddr, Instant)>>,
}

impl Candidates {
    /// An empty table for a chain, whose anchors live under `directory`.
    pub fn new(network: &Network, directory: &Path) -> Candidates {
        Candidates {
            seeds: network.seeds(),
            default_port: network.default_port(),
            anchors: directory.join(ANCHORS_FILE),
            queue: Mutex::new(VecDeque::with_capacity(MAX_CANDIDATES)),
            recent: Mutex::new(VecDeque::with_capacity(MAX_RECENT)),
        }
    }

    /// Read the anchors written at the last clean stop and put them at the front.
    ///
    /// Front, not back: an anchor is the one address this node has evidence about, and
    /// dialling it before anything a stranger suggested is the whole point of writing it
    /// down. A missing or unreadable file is the ordinary case on a first run.
    pub fn load_anchors(&self) -> usize {
        let Ok(text) = fs::read_to_string(&self.anchors) else {
            return 0;
        };
        let mut queue = lock(&self.queue);
        let mut loaded: usize = 0;
        for line in text.lines().take(MAX_ANCHORS) {
            if let Ok(address) = line.trim().parse::<SocketAddr>() {
                queue.push_front(address);
                loaded = loaded.saturating_add(1);
            }
        }
        loaded
    }

    /// Write the addresses that will be dialled first next time.
    ///
    /// Called at a clean stop, with the live block-relay-only connections. A failure is
    /// reported and nothing more: losing the anchors costs a slower, less certain start,
    /// never correctness.
    pub fn save_anchors(&self, addresses: &[SocketAddr]) -> std::io::Result<()> {
        assert!(addresses.len() <= MAX_ANCHORS, "two anchors, as Core keeps");
        if let Some(directory) = self.anchors.parent() {
            fs::create_dir_all(directory)?;
        }
        let mut text = String::new();
        for address in addresses {
            text.push_str(&address.to_string());
            text.push('\n');
        }
        fs::write(&self.anchors, text)
    }

    /// Offer an address for dialling later. Refuses duplicates and refuses to grow past the
    /// bound: a peer that gossips addresses cannot make this node hold more of them.
    pub fn offer(&self, address: SocketAddr) -> bool {
        let mut queue = lock(&self.queue);
        if queue.len() >= MAX_CANDIDATES || queue.contains(&address) {
            return false;
        }
        queue.push_back(address);
        true
    }

    /// The next address to dial.
    ///
    /// The queue is a ring: every address returned goes to the back and is remembered as
    /// recently tried, so a table of two entries rotates between them at Core's ten-minute
    /// interval rather than spinning on the first.
    pub fn next(&self) -> Option<SocketAddr> {
        let mut queue = lock(&self.queue);
        // Bounded by the queue: every address is either returned or moved to the back, so
        // at most one full pass happens before this gives up.
        for _ in 0..queue.len() {
            let address = queue.pop_front()?;
            queue.push_back(address);
            if self.recently_tried(address) {
                continue;
            }
            drop(queue);
            self.remember(address);
            return Some(address);
        }
        None
    }

    /// How many addresses are waiting.
    pub fn len(&self) -> usize {
        lock(&self.queue).len()
    }

    /// Ask the DNS seeds, and put what they answer on the queue.
    ///
    /// The one place this node performs a lookup, and it is worth being plain about the
    /// cost: a seed learns that somebody at this address started a node. Core makes the
    /// same trade and stops asking as soon as it has [`SEED_OUTBOUND_THRESHOLD`] outbound
    /// connections, which is why the connector calls this only when it cannot fill them.
    pub fn query_seeds(&self) -> usize {
        let mut found: usize = 0;
        for seed in self.seeds {
            let name = format!("{SEED_SERVICE_PREFIX}{seed}:{}", self.default_port);
            let Ok(addresses) = name.to_socket_addrs() else {
                continue;
            };
            for address in addresses.take(MAX_ADDRESSES_PER_SEED) {
                if self.offer(address) {
                    found = found.saturating_add(1);
                }
            }
        }
        found
    }

    fn recently_tried(&self, address: SocketAddr) -> bool {
        lock(&self.recent)
            .iter()
            .any(|(tried, at)| *tried == address && at.elapsed() < RETRY_INTERVAL)
    }

    fn remember(&self, address: SocketAddr) {
        let mut recent = lock(&self.recent);
        // Bounded twice: by age, so a long-running node forgets, and by count, so a short
        // one cannot be made to remember more than this whatever it dials.
        while recent
            .front()
            .is_some_and(|(_, at)| at.elapsed() >= RETRY_INTERVAL)
            || recent.len() >= MAX_RECENT
        {
            if recent.pop_front().is_none() {
                break;
            }
        }
        recent.push_back((address, Instant::now()));
    }
}

/// Core's `GetGroup`, without the `ASMap`: an address's /16 if it is IPv4, its /32 if it is
/// IPv6.
///
/// The point is not precision, it is that buying a second address in the same block buys an
/// attacker nothing. Core's version consults a routing-table map to do better; that map is
/// an operator-supplied file and a whole decision of its own.
pub fn netgroup(address: SocketAddr) -> [u8; 4] {
    match address.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            [
                octets.first().copied().unwrap_or(0),
                octets.get(1).copied().unwrap_or(0),
                0,
                0,
            ]
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            [
                octets.first().copied().unwrap_or(0),
                octets.get(1).copied().unwrap_or(0),
                octets.get(2).copied().unwrap_or(0),
                octets.get(3).copied().unwrap_or(0),
            ]
        }
    }
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
