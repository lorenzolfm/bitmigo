// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `version`/`verack` exchange, in Core's order and with Core's ordering rules.
//!
//! Three things about this node are settled here, and each is a whole design decision
//! compressed into one field of one message:
//!
//! - **`fRelay = 0`.** It is the entire mechanism a node without a mempool needs. Core then
//!   never queues a transaction inventory for us, never offers `sendtxrcncl`, and makes its
//!   own `feefilter` a no-op, because the structure that would hold the value is only
//!   allocated for a peer that asked for transactions (R4 §1.5). The BIP330 family can be
//!   left unimplemented rather than stubbed.
//! - **`NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED`.** What an unpruned Core node
//!   advertises, all three: the third is what makes this node acceptable to peers near the
//!   tip that are looking for limited peers, and BIP159 permits a full node to set both
//!   (R4 §1.4, §8.9).
//! - **Protocol version 70016**, Core's, not the `bitcoin` crate's 70001, which is below
//!   every feature gate from `SENDHEADERS_VERSION` up (R4 §6.3).
//!
//! What this node does *not* send is as deliberate. No `wtxidrelay`: wtxid relay is a
//! transaction-relay feature and this node has said it wants none. No `sendaddrv2`: it
//! speaks v1 to IPv4 and IPv6 peers and has nowhere to put a Tor or I2P address. No
//! `sendcmpct`: not sending it is what forbids any peer from ever requesting a compact
//! block from us (BIP152 §sendcmpct rule 7), which is a whole message family refused by
//! silence. All three are also the messages Core disconnects for if they arrive after
//! `verack`, so none of them can be sent late by accident.

use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_network::VersionMessage;

use super::{
    Disconnect, HANDSHAKE_TIMEOUT, MIN_PEER_PROTO_VERSION, PROTOCOL_VERSION, SlotKind, USER_AGENT,
};

/// What this node offers: exactly what an unpruned Core node offers, minus the two bits
/// that are about transactions (`NODE_BLOOM`) and the one that is about a transport this
/// node does not speak (`NODE_P2P_V2`).
pub fn local_services() -> ServiceFlags {
    let mut services = ServiceFlags::NETWORK;
    services.add(ServiceFlags::WITNESS);
    services.add(ServiceFlags::NETWORK_LIMITED);
    services
}

/// What this node requires of a peer it dialled: Core's `GetDesirableServiceFlags` in its
/// strict form. Core relaxes `NODE_NETWORK` to `NODE_NETWORK_LIMITED` for a node already
/// within 144 blocks of the tip; a node syncing an archive from genesis never is, so the
/// relaxation would be dead code here and is left out rather than written unreachable.
pub fn desirable_services() -> ServiceFlags {
    let mut services = ServiceFlags::NETWORK;
    services.add(ServiceFlags::WITNESS);
    services
}

/// How far through the exchange a connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Nothing has been heard yet. On an outbound connection this node has already sent its
    /// own `version`; on an inbound one it waits, exactly as Core does.
    AwaitingVersion,
    /// Their `version` arrived and this node has answered; only `verack` is missing.
    AwaitingVerack,
    /// Both sides are through. From here a message that belongs to the handshake is a
    /// disconnect rather than a nicety.
    Ready,
}

/// One connection's half of the exchange.
pub struct Handshake {
    kind: SlotKind,
    stage: Stage,
    /// The nonce this node put in its own `version`, and compares an inbound peer's to.
    nonce: u64,
    /// Who is on the other end, which is what this node addresses its `version` to.
    peer: SocketAddr,
    /// The height this node claims. Read once, when the connection is made: it is a
    /// courtesy, not a commitment, and Core treats it the same way.
    start_height: i32,
    started: Instant,
    peer_version: u32,
    peer_services: ServiceFlags,
    peer_user_agent: String,
}

impl Handshake {
    /// A fresh exchange for a connection of this kind.
    pub fn new(kind: SlotKind, nonce: u64, peer: SocketAddr, start_height: i32) -> Handshake {
        Handshake {
            kind,
            stage: Stage::AwaitingVersion,
            nonce,
            peer,
            start_height,
            started: Instant::now(),
            peer_version: 0,
            peer_services: ServiceFlags::NONE,
            peer_user_agent: String::new(),
        }
    }

    /// This node's own `version`.
    ///
    /// An outbound connection sends this before it has heard anything; an inbound one sends
    /// it in reply. Core's rule, and the reason is worth stating: the side that dialled
    /// knows what it dialled, and the side that accepted knows nothing until it is told.
    pub fn our_version(&self) -> NetworkMessage {
        let services = local_services();
        NetworkMessage::Version(VersionMessage {
            version: PROTOCOL_VERSION,
            services,
            timestamp: unix_seconds(),
            // Core fills the receiver's services with what it hopes for and its own
            // address with a placeholder; neither field is used by anything.
            receiver: Address::new(&self.peer, ServiceFlags::NONE),
            sender: Address::new(&unroutable(), services),
            nonce: self.nonce,
            user_agent: USER_AGENT.to_owned(),
            start_height: self.start_height,
            // The whole mempool-less contract, in one bool.
            relay: false,
        })
    }

    /// Take one message, and say what to send back.
    ///
    /// The replies are returned rather than sent so that this type stays a state machine:
    /// it has no socket, no queue and no clock beyond the one it was built with, which is
    /// what lets every rule below be a test rather than a connection.
    pub fn receive(&mut self, message: &NetworkMessage) -> Result<Vec<NetworkMessage>, Disconnect> {
        match (self.stage, message) {
            (Stage::AwaitingVersion, NetworkMessage::Version(version)) => self.version(version),
            (Stage::AwaitingVerack, NetworkMessage::Verack) => {
                self.stage = Stage::Ready;
                Ok(Vec::new())
            }
            // Two of the three negotiation messages, which Core accepts only between
            // `version` and `verack` and disconnects for afterwards (R4 §1.2, §8.7).
            (Stage::Ready, NetworkMessage::WtxidRelay | NetworkMessage::SendAddrV2) => {
                Err(Disconnect::NegotiationAfterVerack {
                    command: message.cmd(),
                })
            }
            // The third. BIP330: "Must not be sent if peer specified no support for
            // transaction relay (fRelay=0)", which this node always does — so it is a
            // disconnect at any stage, not only after `verack`. The `bitcoin` crate has no
            // variant for it, so it arrives as an unknown command.
            (_, NetworkMessage::Unknown { command, .. }) if command.as_ref() == "sendtxrcncl" => {
                Err(Disconnect::TransactionRelay)
            }
            // Everything else: a redundant `version`, a second `verack`, a `verack` before
            // the `version` that should precede it, or any other message this early.
            // Logged and ignored, exactly as Core does — nothing this node acts on can
            // arrive before the handshake is through anyway.
            _ => Ok(Vec::new()),
        }
    }

    /// Their `version`: the three rules that end a connection, then the reply.
    fn version(&mut self, version: &VersionMessage) -> Result<Vec<NetworkMessage>, Disconnect> {
        if version.version < MIN_PEER_PROTO_VERSION {
            return Err(Disconnect::ObsoleteVersion {
                version: version.version,
            });
        }
        // Our own nonce coming back means the connection is this node's socket talking to
        // itself. Core checks it on inbound connections only, where it is possible.
        if self.kind == SlotKind::Inbound && version.nonce == self.nonce && self.nonce != 0 {
            return Err(Disconnect::ConnectedToSelf);
        }
        // Only on a connection this node made: an inbound peer is not asked to be useful,
        // it is answered. Core's `ExpectServicesFromConn` is the same distinction.
        let wanted = desirable_services();
        if self.kind == SlotKind::Outbound && !version.services.has(wanted) {
            return Err(Disconnect::MissingServices {
                offered: version.services,
                wanted,
            });
        }

        self.peer_version = version.version;
        self.peer_services = version.services;
        self.peer_user_agent.clone_from(&version.user_agent);
        self.stage = Stage::AwaitingVerack;

        let mut replies = Vec::with_capacity(2);
        if self.kind == SlotKind::Inbound {
            // Core's order, and the side that accepted has not spoken yet: a peer given
            // only a `verack` waits forever for the `version` it needs to know what it is
            // talking to. The outbound case sent its `version` before it heard anything.
            replies.push(self.our_version());
        }
        replies.push(NetworkMessage::Verack);
        Ok(replies)
    }

    /// Whether the handshake has been going on too long. An anonymous peer holding a slot
    /// without having completed a handshake is the cheapest attack there is, so it has the
    /// shortest timeout in the module.
    pub fn timed_out(&self) -> bool {
        self.stage != Stage::Ready && self.started.elapsed() > HANDSHAKE_TIMEOUT
    }

    /// How far through the exchange this connection is.
    #[allow(
        dead_code,
        reason = "the session asks `is_ready`; the stage itself is evidence"
    )]
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Whether messages other than the handshake's own may now be acted on.
    pub fn is_ready(&self) -> bool {
        self.stage == Stage::Ready
    }

    /// What the peer said it offers. Meaningless before its `version` arrives.
    #[allow(
        dead_code,
        reason = "Core's `CanServeBlocks` and `CanServeWitnesses` read this; the scheduler \
                  that asks them is BM-23"
    )]
    pub fn peer_services(&self) -> ServiceFlags {
        self.peer_services
    }

    /// What protocol version the peer speaks.
    #[allow(
        dead_code,
        reason = "every feature gate in Core is a comparison against this"
    )]
    pub fn peer_version(&self) -> u32 {
        self.peer_version
    }

    /// What the peer calls itself. Logged, never acted on: it is a string an attacker
    /// chooses.
    pub fn peer_user_agent(&self) -> &str {
        &self.peer_user_agent
    }
}

/// A nonce for one connection.
///
/// It is not a secret and does not need a generator that behaves like one: its only job is
/// to be different from the nonce of every other connection this node has open, so that a
/// `version` carrying it back is this node's own socket and nothing else. A peer that
/// guessed one would win the right to have its own connection closed. `SplitMix64` over the
/// clock is enough for that, and is one function rather than a fourth dependency.
pub fn nonce() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0u128, |since| since.as_nanos())
        .to_le_bytes();
    let mut low = [0u8; 8];
    if let Some(head) = nanos.get(..8) {
        low.copy_from_slice(head);
    }
    let state = u64::from_le_bytes(low).wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut mixed = state ^ state.wrapping_shr(30);
    mixed = mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed ^= mixed.wrapping_shr(27);
    mixed = mixed.wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ mixed.wrapping_shr(31)
}

/// Seconds since the epoch, as `version` carries them.
fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The address this node puts in its own `version`.
///
/// Core sends what it believes its own address to be so that peers can gossip it; this node
/// does not gossip and has nothing useful to say, so it sends the unspecified address
/// rather than guess at one. A peer that wants to reach us knows where it is connected.
fn unroutable() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;
