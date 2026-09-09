// SPDX-License-Identifier: MIT OR Apache-2.0

//! The table against Bitcoin Core v31.1's `kernel/chainparams.cpp`.

use bitcoin::ScriptBuf;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::p2p::Magic;
use bitmigo_consensus::block::signet::default_challenge;
use bitmigo_consensus::params::{Chain, ChainParams, RegtestOverrides};

use super::Network;

fn mainnet() -> Network {
    Network::of(&ChainParams::mainnet())
}

fn regtest() -> Network {
    Network::of(&ChainParams::regtest(RegtestOverrides::default()))
}

fn signet() -> Network {
    Network::of(&ChainParams::signet(default_challenge()))
}

#[test]
fn magic_and_port_are_cores() {
    assert_eq!(mainnet().magic(), Magic::BITCOIN);
    assert_eq!(mainnet().default_port(), 8333);
    assert_eq!(regtest().magic(), Magic::REGTEST);
    assert_eq!(regtest().default_port(), 18_444);
    assert_eq!(signet().default_port(), 38_333);
}

/// The one derivation in the table, checked against the constant the `bitcoin` crate ships
/// for the public signet: our sha256d of BIP325's challenge must be those four bytes.
#[test]
fn the_default_signet_magic_is_derived_not_copied() {
    assert_eq!(signet().magic(), Magic::SIGNET);
}

/// Two signets with different challenges are different networks. This is the property the
/// derivation exists for, and the reason `Network::of` takes the parameters.
#[test]
fn a_custom_signet_gets_its_own_magic_and_no_seeds() {
    let custom = ScriptBuf::builder().push_opcode(OP_RETURN).into_script();
    let network = Network::of(&ChainParams::signet(custom));

    assert_ne!(network.magic(), Magic::SIGNET);
    assert_eq!(network.chain(), Chain::Signet);
    // Core only lists seeds and a minimum chain work for the challenge BIP325 defines.
    assert!(network.seeds().is_empty());
    assert_eq!(network.minimum_chain_work(), [0u8; 32]);
}

#[test]
fn seeds_are_cores_in_cores_order() {
    assert_eq!(mainnet().seeds().len(), 8);
    assert_eq!(
        mainnet().seeds().first().copied(),
        Some("seed.bitcoin.sipa.be.")
    );
    assert_eq!(
        mainnet().seeds().last().copied(),
        Some("seed.mainnet.achownodes.xyz."),
    );
    assert_eq!(signet().seeds().len(), 2);
    // Core clears regtest's seeds and leaves a placeholder that resolves to nothing.
    assert!(regtest().seeds().is_empty());
}

#[test]
fn minimum_chain_work_is_big_endian_and_ordered() {
    let work = mainnet().minimum_chain_work();
    assert_eq!(work.get(..19), Some([0u8; 19].as_slice()));
    // 0x...01128750f82f4c366153a3a030: the first nonzero byte, then the last.
    assert_eq!(work.get(19).copied(), Some(0x01));
    assert_eq!(work.get(31).copied(), Some(0x30));
    // Big-endian bytes compare as the numbers do, which is why they are the accessor.
    assert!(mainnet().minimum_chain_work() > signet().minimum_chain_work());
    assert!(signet().minimum_chain_work() > regtest().minimum_chain_work());
    assert_eq!(regtest().minimum_chain_work(), [0u8; 32]);
}

#[test]
fn every_chain_has_its_own_directory() {
    assert_eq!(mainnet().directory(), "mainnet");
    assert_eq!(signet().directory(), "signet");
    assert_eq!(regtest().directory(), "regtest");
}
