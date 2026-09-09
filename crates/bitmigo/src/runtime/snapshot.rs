// SPDX-License-Identifier: MIT OR Apache-2.0

//! The published snapshots: the only thing the control thread is allowed to read.
//!
//! Two threads own the node's state. The chain thread owns the header tree, the block index
//! and the download schedule; the validation thread owns the coin store, the tip and the
//! accumulator over the UTXO set. Neither is shared, and neither takes a lock to do its
//! work — which is the whole reason the node is laid out this way.
//!
//! An operator asking for `status` must not be able to reach into either. So each owner
//! publishes a small immutable summary of itself once per block, behind a mutex held for the
//! length of a copy, and the control thread answers from that. The answer can be one block
//! stale; a lock on the chainstate held while a socket is written to could be one flush long.

use std::sync::Mutex;

use bitcoin::BlockHash;
use bitmigo_consensus::params::{Chain, Height};

use crate::runtime::sync::lock;

/// A value one thread writes and others read, at most one copy old.
pub struct Published<T: Clone> {
    current: Mutex<T>,
}

impl<T: Clone> Published<T> {
    /// The value a reader sees before the owner has published anything.
    pub fn new(initial: T) -> Published<T> {
        Published {
            current: Mutex::new(initial),
        }
    }

    /// Replace the published value. Called by the owner, once per block.
    pub fn publish(&self, value: T) {
        *lock(&self.current) = value;
    }

    /// A copy of the last published value.
    pub fn read(&self) -> T {
        lock(&self.current).clone()
    }
}

/// What the chain thread publishes: where the node is, and what it is still fetching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusSnapshot {
    /// Which chain the node is on.
    pub chain: Chain,
    /// The most-work fully validated block, once there is one.
    pub tip: Option<BlockHash>,
    /// Its height.
    pub tip_height: Height,
    /// The most-work header accepted, which during a sync runs far ahead of the tip.
    pub header_height: Height,
    /// Blocks requested and not yet received.
    pub blocks_in_flight: usize,
    /// Peers with a completed handshake.
    pub peers: usize,
    /// Whether the node still considers itself behind.
    pub initial_block_download: bool,
    /// Messages waiting for the chain thread. A number that stays near the bound means the
    /// node is validation-bound and its peers are being throttled.
    pub queued_messages: usize,
    /// What those messages hold, in bytes: the bound that actually binds.
    pub queued_bytes: usize,
}

impl StatusSnapshot {
    /// The status of a node that has just started: genesis and nothing else.
    pub fn starting(chain: Chain) -> StatusSnapshot {
        StatusSnapshot {
            chain,
            tip: None,
            tip_height: Height::GENESIS,
            header_height: Height::GENESIS,
            blocks_in_flight: 0,
            peers: 0,
            initial_block_download: true,
            queued_messages: 0,
            queued_bytes: 0,
        }
    }
}

/// What the validation thread publishes: the summary of the UTXO set that the differential
/// harness compares against Bitcoin Core's `gettxoutsetinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoSetSnapshot {
    /// The block the set is the state after.
    pub best_block: Option<BlockHash>,
    /// Its height.
    pub height: Height,
    /// How many unspent outputs there are.
    pub txouts: u64,
    /// What they are worth, in satoshis.
    pub total_amount: u64,
    /// The rolling hash over the set, maintained block by block rather than recomputed.
    pub muhash: [u8; 32],
}

impl UtxoSetSnapshot {
    /// The empty set, before genesis is applied.
    pub fn empty() -> UtxoSetSnapshot {
        UtxoSetSnapshot {
            best_block: None,
            height: Height::GENESIS,
            txouts: 0,
            total_amount: 0,
            muhash: [0u8; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Published, StatusSnapshot, UtxoSetSnapshot};
    use bitmigo_consensus::params::{Chain, Height};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn a_reader_sees_the_initial_value_until_the_owner_publishes() {
        let published = Published::new(StatusSnapshot::starting(Chain::Regtest));
        assert_eq!(published.read().tip_height, Height::GENESIS);
        assert!(published.read().initial_block_download);

        let mut advanced = published.read();
        advanced.tip_height = Height::new(120);
        advanced.initial_block_download = false;
        published.publish(advanced);

        assert_eq!(published.read().tip_height, Height::new(120));
        assert!(!published.read().initial_block_download);
    }

    #[test]
    fn a_reader_never_touches_the_owners_state() {
        let published = Arc::new(Published::new(UtxoSetSnapshot::empty()));
        let owner = Arc::clone(&published);
        let writer = thread::spawn(move || {
            for height in 1..=200u32 {
                owner.publish(UtxoSetSnapshot {
                    best_block: None,
                    height: Height::new(height),
                    txouts: u64::from(height),
                    total_amount: u64::from(height) * 50 * 100_000_000,
                    muhash: [0u8; 32],
                });
            }
        });

        // Whatever the reader sees is a whole snapshot, never a half-written one.
        for _ in 0..200 {
            let seen = published.read();
            assert_eq!(seen.txouts, u64::from(seen.height.get()));
        }
        writer.join().unwrap();
        assert_eq!(published.read().height, Height::new(200));
    }
}
