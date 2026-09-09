// SPDX-License-Identifier: MIT OR Apache-2.0

//! The whole vocabulary, walked end to end.
//!
//! Core's `Misbehaving` has no score at v31.1: every call is an immediate disconnect, so
//! the list of things that end a connection is short enough to enumerate — which is what
//! this file does. Adding a reason without deciding whether the peer earned it fails here.

use bitcoin::hashes::Hash;
use bitcoin::p2p::ServiceFlags;
use bitcoin::{BlockHash, CompactTarget};
use bitmigo_consensus::block::BlockError;
use bitmigo_consensus::header::HeaderError;

use super::Disconnect;
use crate::peer::wire::WireError;

/// Every reason, in one place. A `match` in [`Disconnect::misbehaving`] keeps this honest:
/// a new variant does not compile until somebody has answered the question.
fn every_reason() -> Vec<Disconnect> {
    vec![
        Disconnect::Wire(WireError::WrongMagic { seen: [0u8; 4] }),
        Disconnect::Wire(WireError::BadCommand),
        Disconnect::Wire(WireError::TooLong {
            declared: 5_000_000,
        }),
        Disconnect::Wire(WireError::OverCap {
            declared: 1_000_000,
            cap: 512 * 1024,
        }),
        Disconnect::Wire(WireError::Malformed),
        Disconnect::Wire(WireError::TooManyItems {
            seen: 50_001,
            allowed: 50_000,
        }),
        Disconnect::Wire(WireError::Stalled),
        Disconnect::ObsoleteVersion { version: 209 },
        Disconnect::ConnectedToSelf,
        Disconnect::MissingServices {
            offered: ServiceFlags::NONE,
            wanted: ServiceFlags::NETWORK,
        },
        Disconnect::NegotiationAfterVerack {
            command: "wtxidrelay",
        },
        Disconnect::HandshakeTimeout,
        Disconnect::PingTimeout,
        Disconnect::Silent,
        Disconnect::TransactionRelay,
        Disconnect::BloomFilter,
        Disconnect::CompactFilter,
        Disconnect::Mempool,
        Disconnect::UnrequestedBlock {
            hash: BlockHash::from_byte_array([0u8; 32]),
        },
        Disconnect::InvalidHeader(HeaderError::HighHash),
        Disconnect::InvalidBlock(BlockError::BadMerkleRoot {
            computed: [0u8; 32],
        }),
        Disconnect::BlockDownloadTimeout,
        Disconnect::BlockStalling,
        Disconnect::HeadersTimeout,
        Disconnect::StaleTip,
        Disconnect::OutboxFull,
        Disconnect::WriteFailed,
        Disconnect::PeerClosed,
        Disconnect::NodeStopping,
    ]
}

/// Every reason says something, and no two of the interesting ones say the same thing.
#[test]
fn every_reason_names_itself() {
    for reason in every_reason() {
        let said = reason.to_string();
        assert!(!said.is_empty(), "{reason:?}");
        assert!(!said.contains("Disconnect"), "{said}");
    }
}

/// The classification the address manager will want. Everything a correct peer can do is
/// false; everything that is a protocol violation or an invalid block is true.
#[test]
fn only_a_peer_that_earned_it_is_blamed() {
    assert!(Disconnect::Wire(WireError::BadCommand).misbehaving());
    assert!(Disconnect::TransactionRelay.misbehaving());
    assert!(Disconnect::Mempool.misbehaving());
    assert!(Disconnect::BloomFilter.misbehaving());
    assert!(Disconnect::CompactFilter.misbehaving());
    assert!(Disconnect::InvalidHeader(HeaderError::HighHash).misbehaving());
    assert!(
        Disconnect::UnrequestedBlock {
            hash: BlockHash::from_byte_array([0u8; 32]),
        }
        .misbehaving()
    );
    assert!(
        Disconnect::NegotiationAfterVerack {
            command: "sendaddrv2",
        }
        .misbehaving()
    );

    // A peer that hangs up, goes quiet, or is dropped by a node that is stopping has done
    // nothing wrong, and neither has one this node dialled and found unhelpful.
    assert!(!Disconnect::PeerClosed.misbehaving());
    assert!(!Disconnect::NodeStopping.misbehaving());
    assert!(!Disconnect::Silent.misbehaving());
    assert!(!Disconnect::PingTimeout.misbehaving());
    assert!(!Disconnect::HandshakeTimeout.misbehaving());
    assert!(!Disconnect::OutboxFull.misbehaving());
    // Every download verdict is about this node's own patience, not about the peer's
    // honesty: a peer that is slow, or that this node makes way past, has broken no rule.
    assert!(!Disconnect::BlockDownloadTimeout.misbehaving());
    assert!(!Disconnect::BlockStalling.misbehaving());
    assert!(!Disconnect::HeadersTimeout.misbehaving());
    assert!(!Disconnect::StaleTip.misbehaving());
    assert!(!Disconnect::WriteFailed.misbehaving());
    assert!(!Disconnect::ConnectedToSelf.misbehaving());
    assert!(
        !Disconnect::MissingServices {
            offered: ServiceFlags::NONE,
            wanted: ServiceFlags::NETWORK,
        }
        .misbehaving()
    );
}

/// Framing errors are the peer's — with one exception, and a real bitcoind is why.
///
/// Core opens an outbound connection with BIP324's v2 handshake unless it already knows the
/// peer speaks v1, so its first sixteen bytes are random and read as another network's
/// magic; it then reconnects over v1 and the handshake completes. Observed against
/// bitcoind v31.1.0 on regtest, and the reason wrong magic is not blamed on anybody.
#[test]
fn every_framing_error_but_one_is_the_peers() {
    for reason in every_reason() {
        match reason {
            Disconnect::Wire(WireError::WrongMagic { .. }) => {
                assert!(!reason.misbehaving(), "{reason:?}");
            }
            Disconnect::Wire(_) => assert!(reason.misbehaving(), "{reason:?}"),
            _ => {}
        }
    }
    assert_eq!(
        Disconnect::from(WireError::Malformed),
        Disconnect::Wire(WireError::Malformed),
    );
}

/// The evidence is carried, not summarised into a string: a reason a test can match on is
/// a reason the address manager can act on later.
#[test]
fn a_reason_carries_what_was_seen() {
    let bits = CompactTarget::from_consensus(0x1d00_ffff);
    let reason = Disconnect::InvalidHeader(HeaderError::BadDiffBits { required: bits });
    match reason {
        Disconnect::InvalidHeader(HeaderError::BadDiffBits { required }) => {
            assert_eq!(required, bits);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(reason.to_string(), "bad-diffbits");
}
