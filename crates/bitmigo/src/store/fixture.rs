// SPDX-License-Identifier: MIT OR Apache-2.0

//! bitcoind's own regtest chain, for the tests that have to be about real bytes.
//!
//! A store is only interesting against blocks somebody else serialised: an encoder tested
//! against its own output agrees with itself and nothing more. `regtest-blocks.hex` is a
//! hundred and six blocks mined by the system bitcoind v31.1.0, four of which carry real
//! spends across the four standard output types, so the coin encoder, the undo record and
//! the series all meet transactions this node did not make up.

use std::collections::HashMap;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{Block, OutPoint};
use bitmigo_consensus::params::Height;
use bitmigo_consensus::tx::{Coin, is_unspendable};

/// Blocks 0 to 105 of a regtest chain, one per line, hex.
const BLOCKS: &str = include_str!("../../tests/data/regtest-blocks.hex");

/// Every block's raw bytes, in height order, exactly as bitcoind serialised them.
pub fn raw() -> Vec<Vec<u8>> {
    BLOCKS
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| Vec::<u8>::from_hex(line).expect("bitcoind prints hex"))
        .collect()
}

/// The same, decoded.
pub fn blocks() -> Vec<Block> {
    raw()
        .iter()
        .map(|bytes| deserialize(bytes).expect("bitcoind's own block"))
        .collect()
}

/// Every coin the chain creates, by outpoint: what an input of a later block spends.
pub fn coins(blocks: &[Block]) -> HashMap<OutPoint, Coin> {
    let mut set = HashMap::new();
    for (height, block) in blocks.iter().enumerate() {
        let height = Height::new(u32::try_from(height).expect("a fixture height"));
        for (index, transaction) in block.txdata.iter().enumerate() {
            let txid = transaction.compute_txid();
            for (vout, output) in transaction.output.iter().enumerate() {
                if is_unspendable(&output.script_pubkey) {
                    continue;
                }
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).expect("a fixture index"),
                };
                set.insert(
                    outpoint,
                    Coin {
                        outpoint,
                        output: output.clone(),
                        height,
                        coinbase: index == 0,
                    },
                );
            }
        }
    }
    set
}

/// The coins one block spends, in block order: the delta's `spent` list.
///
/// An output created and spent inside the same block is in neither of the delta's lists,
/// so it is left out here too — the undo record restores what the block destroyed, and
/// something that never existed outside the block was not destroyed.
pub fn spent_by(block: &Block, coins: &HashMap<OutPoint, Coin>) -> Vec<Coin> {
    let own: Vec<_> = block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    block
        .txdata
        .iter()
        .skip(1)
        .flat_map(|transaction| transaction.input.iter())
        .filter(|input| !own.contains(&input.previous_output.txid))
        .map(|input| {
            coins
                .get(&input.previous_output)
                .cloned()
                .expect("the fixture chain spends only its own coins")
        })
        .collect()
}
