// SPDX-License-Identifier: MIT OR Apache-2.0

//! bitmigo's consensus rules: script, transaction and block validation, and the chainstate
//! transitions they imply.
//!
//! This crate is pure. It takes bytes and state in and returns verdicts and new state out:
//! no filesystem, no network, no clock, no threads. That is what lets every rule be tested
//! against Bitcoin Core's vectors without a node around it, and what keeps the surface that
//! can disagree with the network small enough to read. The clippy configuration beside this
//! crate rejects the common ways of breaking that rule.
//!
//! Rules land one module at a time, each with its tests. [`params`] says what a chain is and
//! which rules apply to a block at a height; [`script`] is the script interpreter, from the
//! signature hashes up to `verify_script`.

// The purity tripwire in `clippy.toml` is a hard error here, not a warning like the rest of
// clippy: reaching for the disk or the network from consensus is a design bug, not style.
#![deny(clippy::disallowed_types, clippy::disallowed_methods)]

pub mod params;
pub mod script;

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use bitcoin::constants::genesis_block;

    /// The pinned `bitcoin` and `bitcoin_hashes` crates agree with the network on the one
    /// hash everything else hangs from. This is a wiring test: it proves the dependency
    /// versions this crate is built against hash a block the way mainnet does.
    #[test]
    fn genesis_block_hash_matches_mainnet() {
        let genesis = genesis_block(Network::Bitcoin);
        assert_eq!(genesis.txdata.len(), 1);
        assert_eq!(
            genesis.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        );
    }
}
