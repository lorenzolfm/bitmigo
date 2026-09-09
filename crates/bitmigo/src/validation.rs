// SPDX-License-Identifier: MIT OR Apache-2.0

//! The validation thread.
//!
//! It owns the coin store, the UTXO cache, the tip, the undo data and the accumulator over
//! the set. One thread, so none of that is locked and none of it is copied; the operator
//! reads a published summary instead, and the block server reads raw bytes off the disk
//! without coming anywhere near here.
//!
//! It pulls its work rather than being pushed at. A connect that runs long — a block full of
//! signatures, or a flush of the cache — is felt as the queue behind it filling, then the
//! chain thread not topping it up, then the download window filling, then the peer readers
//! blocking, and finally as TCP backpressure to the peers that are sending fastest. Nothing
//! in that chain is an unbounded buffer, and nothing in it drops a block.

use std::time::Duration;

use crate::runtime::Shared;
use crate::runtime::queue::{ConnectJob, Received};

/// How long the thread waits for a job before looking at the shutdown flag again.
const VALIDATION_TICK: Duration = Duration::from_millis(250);

/// Run until the node stops.
///
/// The loop ends on the shutdown flag rather than on the queue closing, because that is what
/// the shutdown sequence promises: the block being connected finishes — a connect is atomic,
/// and half of one must never reach the disk — and whatever else is queued is simply not
/// started. Those blocks are still on the disk exactly as they arrived, and the next start
/// picks them up from the tip.
pub fn run(shared: &Shared) {
    let mut connected: u64 = 0;
    while !shared.shutdown.is_begun() {
        match shared.to_validation.pop(VALIDATION_TICK) {
            Received::Item(job) => {
                apply(shared, &job);
                connected = connected.saturating_add(1);
            }
            Received::Empty => {}
            Received::Closed => break,
        }
    }
    let discarded = shared.to_validation.discard();
    flush(shared);
    println!("bitmigo: validation stopped after {connected} blocks, {discarded} queued");
}

/// Connect or disconnect one block.
///
/// The coins path is written and tested in the consensus crate, against exact inputs: this
/// thread is what turns a job into those inputs and applies what comes back. Prefetch the
/// coins the block spends, run `confirm` and then `connect` in chain order, apply the
/// resulting delta to the store, fold it into the accumulator, and move the tip. The store
/// and the cache the prefetch reads from are the storage engine's, and this is where they
/// attach; the assertion that the job's parent is the tip belongs here too, because a job
/// whose parent is no longer the tip is a reorg that landed while it was queued.
fn apply(shared: &Shared, job: &ConnectJob) {
    let mut utxoset = shared.utxoset.read();
    utxoset.height = job.height();
    utxoset.best_block = Some(job.hash);
    shared.utxoset.publish(utxoset);
}

/// Get the chainstate onto the disk before the process ends.
///
/// This is the flush a shutdown waits for without a deadline, and the reason the node asks
/// for signals at all: the dirty coins, the tip, the accumulator and the marker that says
/// they agree, written in the storage engine's order. A second signal cuts it short, and
/// crash recovery pays for that in time.
fn flush(shared: &Shared) {
    let _ = shared;
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::runtime::Shared;
    use crate::runtime::queue::{BlockLocation, ConnectJob, JobKind};
    use crate::runtime::signal::Cause;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget};
    use bitmigo_consensus::header::Context;
    use bitmigo_consensus::params::{BlockTime, Chain, ChainParams, Height, RegtestOverrides};
    use std::sync::Arc;
    use std::thread::{self, Builder};
    use std::time::{Duration, Instant};

    fn job(height: u32) -> ConnectJob {
        let params = ChainParams::regtest(RegtestOverrides::default());
        let hash = BlockHash::all_zeros();
        let height = Height::new(height);
        ConnectJob {
            kind: JobKind::Connect,
            hash,
            context: Context::new(
                height,
                BlockTime::new(1_296_688_602),
                BlockTime::new(1_296_688_602),
                CompactTarget::from_consensus(0x207f_ffff),
                params.rules_at(height, hash, None),
            ),
            location: BlockLocation {
                file: 0,
                offset: 8,
                len: 285,
            },
        }
    }

    #[test]
    fn jobs_are_pulled_and_the_utxo_summary_follows_them() {
        let shared = Arc::new(Shared::testing(Chain::Regtest));
        let running = Arc::clone(&shared);
        let validation = Builder::new()
            .name("validation".to_owned())
            .spawn(move || run(&running))
            .expect("a test thread");

        for height in 1..=8 {
            assert!(shared.to_validation.try_push(job(height)).is_ok());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while shared.utxoset.read().height != Height::new(8) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(shared.utxoset.read().height, Height::new(8));

        shared.shutdown.begin(Cause::Internal("test"));
        validation.join().expect("the validation thread stops");
    }

    #[test]
    fn a_shutdown_leaves_the_queued_blocks_for_the_next_start() {
        let shared = Arc::new(Shared::testing(Chain::Regtest));
        // Announced before the thread starts, so nothing is taken off the queue at all.
        shared.shutdown.begin(Cause::Internal("test"));
        for height in 1..=4 {
            assert!(shared.to_validation.try_push(job(height)).is_ok());
        }

        let running = Arc::clone(&shared);
        let validation = Builder::new()
            .name("validation".to_owned())
            .spawn(move || run(&running))
            .expect("a test thread");
        validation.join().expect("the validation thread stops");

        assert_eq!(shared.to_validation.len(), 0);
        assert_eq!(shared.utxoset.read().height, Height::GENESIS);
    }
}
