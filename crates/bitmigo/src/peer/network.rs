// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node-side chain table: everything about a chain that consensus does not read.
//!
//! [`bitmigo_consensus::params::ChainParams`] holds what validation needs — genesis, the
//! proof-of-work limit, the buried heights, the block challenge — and deliberately nothing
//! else, so that a rule can be tested without a network around it. The four facts a chain
//! also carries are all about *finding and talking to* the chain rather than about
//! validating it: the message magic, the default port, the DNS seeds, and the minimum chain
//! work below which the node will not download blocks from a peer.
//!
//! The two tables are paired by the shared [`Chain`] enum, and [`Network::of`] takes the
//! params rather than the enum so that the pairing cannot be got wrong: signet's magic is
//! derived from the very challenge script the params carry, so a node cannot end up
//! speaking the default signet's magic to a custom signet.

use bitcoin::ScriptBuf;
use bitcoin::consensus::serialize;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::p2p::Magic;
use bitmigo_consensus::block::signet::default_challenge;
use bitmigo_consensus::params::{BlockChallenge, Chain, ChainParams};

/// Bitcoin Core v31.1 `kernel/chainparams.cpp: CMainParams`. Trailing dots included, as
/// Core writes them: the name is fully qualified, so a resolver adds no search domain.
const MAINNET_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be.",
    "dnsseed.bluematt.me.",
    "seed.bitcoin.jonasschnelli.ch.",
    "seed.btc.petertodd.net.",
    "seed.bitcoin.sprovoost.nl.",
    "dnsseed.emzy.de.",
    "seed.bitcoin.wiz.biz.",
    "seed.mainnet.achownodes.xyz.",
];

/// Core v31.1 `SigNetParams`, and only for the challenge BIP325 defines: a custom signet is
/// a private network whose participants tell each other where to connect.
const SIGNET_SEEDS: &[&str] = &[
    "seed.signet.bitcoin.sprovoost.nl.",
    "seed.signet.achownodes.xyz.",
];

/// Core v31.1 `CMainParams::nMinimumChainWork`,
/// `0000000000000000000000000000000000000001128750f82f4c366153a3a030`. **This value goes
/// stale between Core releases** and is a lower bound, not a rule: it only says which peers
/// are worth downloading from.
const MAINNET_MINIMUM_CHAIN_WORK: u128 = 0x0001_1287_50f8_2f4c_3661_53a3_a030;

/// Core v31.1 `SigNetParams::nMinimumChainWork` for the default challenge,
/// `00000000000000000000000000000000000000000000000000000b463ea0a4b8`. Core sets it to zero
/// for a custom signet, and so does [`Network::of`].
const SIGNET_MINIMUM_CHAIN_WORK: u128 = 0x0000_0b46_3ea0_a4b8;

/// What the node knows about a chain that the consensus crate does not.
///
/// Private fields and accessors, exactly as `ChainParams`: the table is data, and nothing
/// outside this module assembles a row of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    chain: Chain,
    magic: Magic,
    default_port: u16,
    seeds: &'static [&'static str],
    minimum_chain_work: u128,
    directory: &'static str,
}

impl Network {
    /// The row that goes with these chain parameters.
    ///
    /// Takes the parameters rather than the [`Chain`] so that the pairing cannot be got
    /// wrong: signet's magic is derived from the very challenge script the parameters
    /// carry, so a node can never end up speaking the default signet's magic to a custom
    /// one. The assertion is the pairing rule BM-D3 states, said where it is relied on.
    pub fn of(params: &ChainParams) -> Network {
        let network = match params.chain() {
            Chain::Mainnet => Network::mainnet(),
            Chain::Signet => Network::signet(&signet_challenge(params)),
            Chain::Regtest => Network::regtest(),
        };
        assert_eq!(
            network.chain,
            params.chain(),
            "one row per chain, and the same chain"
        );
        network
    }

    fn mainnet() -> Network {
        Network {
            chain: Chain::Mainnet,
            magic: Magic::BITCOIN,
            default_port: 8333,
            seeds: MAINNET_SEEDS,
            minimum_chain_work: MAINNET_MINIMUM_CHAIN_WORK,
            directory: "mainnet",
        }
    }

    /// The signet row, whose magic, seeds and minimum work all depend on the challenge:
    /// two signets with different challenges are different networks that must not be able
    /// to hear each other, and only the one BIP325 defines has public seeds.
    fn signet(challenge: &ScriptBuf) -> Network {
        let default = *challenge == default_challenge();
        Network {
            chain: Chain::Signet,
            magic: signet_magic(challenge),
            default_port: 38_333,
            seeds: if default { SIGNET_SEEDS } else { &[] },
            minimum_chain_work: if default {
                SIGNET_MINIMUM_CHAIN_WORK
            } else {
                0
            },
            directory: "signet",
        }
    }

    fn regtest() -> Network {
        Network {
            chain: Chain::Regtest,
            magic: Magic::REGTEST,
            default_port: 18_444,
            // Core clears the seeds and leaves one placeholder that resolves to nothing: a
            // regtest node is told where its peers are, or it has none.
            seeds: &[],
            minimum_chain_work: 0,
            directory: "regtest",
        }
    }

    /// Which chain this row is for.
    #[allow(
        dead_code,
        reason = "the pairing assertion is inside this module; the accessor is for the \
                  download scheduler, which asks which chain it is on"
    )]
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// The four bytes every message on this chain starts with.
    pub fn magic(&self) -> Magic {
        self.magic
    }

    /// The port a peer is assumed to listen on when an address does not say.
    pub fn default_port(&self) -> u16 {
        self.default_port
    }

    /// The DNS seeds, in Core's order. Empty on regtest and on a custom signet.
    pub fn seeds(&self) -> &'static [&'static str] {
        self.seeds
    }

    /// The work a peer's headers chain must claim before the node will ask it for blocks,
    /// big-endian so that it compares byte for byte against accumulated chain work.
    ///
    /// Held as a `u128` because it is one: mainnet's chain work is around 2^95 and the
    /// figure Core ships is smaller still, so the top sixteen bytes are zero and will stay
    /// zero for longer than this code will exist.
    pub fn minimum_chain_work(&self) -> [u8; 32] {
        let mut work = [0u8; 32];
        let low = self.minimum_chain_work.to_be_bytes();
        if let Some(bytes) = work.get_mut(16..32) {
            bytes.copy_from_slice(&low);
        }
        work
    }

    /// The subdirectory this chain's data lives in, below the node's data directory. Core
    /// spells mainnet's as the data directory itself; a subdirectory per chain is one rule
    /// rather than two.
    pub fn directory(&self) -> &'static str {
        self.directory
    }
}

/// The challenge signet parameters were built with.
///
/// `ChainParams::signet` asserts a challenge at construction, so the second arm is
/// unbuildable through the crate's own constructors. It answers with the challenge BIP325
/// defines rather than inventing a magic for a network that does not exist.
fn signet_challenge(params: &ChainParams) -> ScriptBuf {
    match params.block_challenge() {
        BlockChallenge::Signet(script) => script.clone(),
        BlockChallenge::None => default_challenge(),
    }
}

/// Core's `SigNetParams`: "message start is defined as the first 4 bytes of the sha256d of
/// the block script", where the script is hashed with its `CompactSize` length prefix.
fn signet_magic(challenge: &ScriptBuf) -> Magic {
    let digest = sha256d::Hash::hash(&serialize(challenge)).to_byte_array();
    let mut start = [0u8; 4];
    if let Some(head) = digest.get(..4) {
        start.copy_from_slice(head);
    }
    Magic::from_bytes(start)
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
