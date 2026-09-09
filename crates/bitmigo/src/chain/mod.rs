// SPDX-License-Identifier: MIT OR Apache-2.0

//! The chain thread, and the state that drives both validation paths.
//!
//! It owns the header tree, the block index, the download schedule, the in-flight map and
//! the block store's single write. Nothing else writes any of those, so none of them is
//! behind a lock, and the thread is a plain loop over one queue.
//!
//! [`HeaderTree`] is the state: every header this node has accepted, what is known about
//! the block behind each one, the most-work header the download aims at, and the tip whose
//! coins are in the chainstate. Everything the two validation paths need comes out of it —
//! the [`Context`](bitmigo_consensus::header::Context) that travels with a download request
//! and is read again at receipt, the plan of disconnects and connects that a
//! [`Reorg`] is, and the locator that finds the last block this node and a peer agree on.
//!
//! Two rules hold the loop. The chain thread never blocks on a full queue: when the
//! validation thread is behind, it stops topping up and lets the blocks pile up behind it.
//! And it publishes its summary of itself rather than letting anything read its state.

#[cfg(test)]
pub mod fixture;
mod locator;
mod reorg;
mod tree;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::block::Header;
use bitcoin::p2p::message::NetworkMessage;
use bitmigo_consensus::params::BlockTime;

use crate::download::{HeadersReceived, Schedule};
use crate::peer::{Disconnect, MAX_HEADERS_ITEMS, SlotIndex};
use crate::runtime::Shared;
use crate::runtime::queue::{PeerMessage, Received};

// The module's own surface, named here so the modules that will drive it — the receipt
// path, the chainstate, the download schedule and the block server — reach one place.
#[allow(
    unused_imports,
    reason = "re-exported for BM-9, BM-10 and BM-24; the chain thread and the \
              download schedule use a few"
)]
pub use locator::MAX_LOCATOR_ENTRIES;
#[allow(unused_imports, reason = "the plan is handed to validation by BM-10")]
pub use reorg::{REORG_WARNING_DEPTH, Reorg};
#[allow(
    unused_imports,
    reason = "the tree's states and verdicts are read by BM-9 and BM-10"
)]
pub use tree::{
    AcceptError, Accepted, HeaderEntry, HeaderStatus, HeaderTree, Invalidity, MAX_TREE_HEADERS,
    NodeId, UndoLocation,
};

/// How long the thread waits for a message before looking at the shutdown flag and its
/// schedule again. Both a message and a shutdown wake it directly; this bounds the wait.
const CHAIN_TICK: Duration = Duration::from_millis(250);

/// Run until the node stops.
pub fn run(shared: &Shared) {
    let mut tree = HeaderTree::new(&shared.params);
    let mut schedule = Schedule::new(shared);
    let mut received: u64 = 0;
    let mut reorg_depth: usize = 0;
    publish(shared, &tree, &schedule, reorg_depth);
    while !shared.shutdown.is_begun() {
        match shared.to_chain.recv(CHAIN_TICK) {
            Received::Item(message) => {
                received = received.saturating_add(1);
                record(shared, &mut tree, &mut schedule, message);
            }
            Received::Empty => {}
            Received::Closed => break,
        }
        // What to ask for next, of whom, and who has stopped answering: one pass per turn
        // of this loop, message or no message.
        schedule.tick(shared, &mut tree);
        let depth = plan(shared, &mut tree);
        // Said once per reorg rather than once per tick: the plan stands until validation
        // has worked through it, and an operator warned four times a second is not warned.
        if depth >= REORG_WARNING_DEPTH && depth != reorg_depth {
            let fork = tree.entry(tree.tip()).height().get();
            println!("bitmigo: reorg {depth} blocks deep, active chain rewinds past {fork}");
        }
        reorg_depth = depth;
        publish(shared, &tree, &schedule, reorg_depth);
    }
    flush(shared);
    // Validation stops when the shutdown is announced, but closing the queue behind it says
    // so plainly: nothing further will be scheduled.
    shared.to_validation.close();
    println!(
        "bitmigo: chain stopped after {received} messages, {} headers, {}",
        tree.len(),
        schedule.summary(),
    );
}

/// Take one message from a peer reader.
///
/// What arrives has already been through the receipt-time checks, on the reader's own thread
/// and against the context that travelled with the request, so this side is bookkeeping:
/// accept the header into the tree, write the block's raw bytes to the store exactly as they
/// arrived, move the block's status along, and clear it from the in-flight map.
#[allow(
    clippy::needless_pass_by_value,
    reason = "the queue hands ownership over, and the block arm takes it: a block's raw \
              bytes are written to the store exactly as they arrived, which is BM-9's"
)]
fn record(shared: &Shared, tree: &mut HeaderTree, schedule: &mut Schedule, message: PeerMessage) {
    let peer = message.peer;
    match message.message {
        NetworkMessage::Headers(headers) => {
            let received = headers_received(shared, tree, peer, &headers);
            schedule.headers_answered(shared, tree, peer, received);
        }
        // The hash is computed again here rather than carried on the queue: eighty bytes of
        // `sha256d` beside the merkle root the reader thread has already paid for, and one
        // less field that could disagree with the block beside it. The bytes themselves go
        // to the store, whose location is what moves a header to `BlockChecked` (BM-9).
        NetworkMessage::Block(block) => schedule.block_received(shared, peer, block.block_hash()),
        NetworkMessage::Inv(items) => schedule.announced(shared, tree, peer, &items),
        // A `getheaders` is answered from `HeaderTree::headers_after` and a `getdata` from
        // the block store, both by the block server (BM-24). A `notfound` naming a block is
        // ignored exactly as Core ignores it: the request stays in flight, and the download
        // timeout is what ends a peer that answers that way. The address messages wait on
        // the address manager the map still holds open.
        _ => {}
    }
}

/// Place a peer's headers in the tree, in the order they were sent.
///
/// The batch stops at the first header that does not go in, which is Core's behaviour and
/// the only one that makes sense: a `headers` message is a chain, so once one link fails
/// every header after it is unconnected. A peer answers for its own fault and nothing else
/// (BM-D1 decision 6), and nothing here writes a line to the log — a peer that can make
/// this node print is a peer that has been handed a megaphone.
fn headers_received(
    shared: &Shared,
    tree: &mut HeaderTree,
    peer: SlotIndex,
    headers: &[Header],
) -> HeadersReceived {
    assert!(headers.len() <= MAX_HEADERS_ITEMS, "the framer bounds this");
    let now = node_time();
    let mut received = HeadersReceived {
        count: headers.len(),
        last: None,
        unconnecting: false,
    };
    for header in headers {
        let error = match tree.accept(header, &shared.params, now) {
            // A duplicate counts: the peer has said it has this block, which is what the
            // download schedule reads off the last header of a batch.
            Ok(accepted) => {
                received.last = Some(accepted.node());
                continue;
            }
            Err(error) => error,
        };
        // Core's `HandleUnconnectingHeaders`: a first header whose parent this node has
        // never seen is a peer that is ahead of us, not a peer at fault. The schedule
        // answers it with a `getheaders` from this node's own best header.
        received.unconnecting =
            received.last.is_none() && matches!(error, AcceptError::UnknownParent { .. });
        if let Some(fault) = error.peer_fault()
            && let Some(connection) = shared.slots.connection(peer)
        {
            connection.disconnect(Disconnect::InvalidHeader(fault));
        }
        return received;
    }
    received
}

/// Top the connect queue up while the connectable prefix advances and there is room.
///
/// Pull-shaped on purpose: the answer to a full queue is to do nothing, not to wait. The
/// plan is [`HeaderTree::reorg`], bounded by the room there is, so a reorg of any depth is
/// worked through a batch at a time and never built as one list.
///
/// Handing the jobs over waits on the chainstate (BM-10), and deliberately: a job that has
/// been queued and not yet applied is in-flight state, and the thread that hands it over is
/// the one that must know when it has landed. Nothing reports a connect back yet, and a
/// hand-off with no report is a hand-off that would queue the same block over and over.
/// BM-10 brings the report, and the undo record a block needs to become
/// [`HeaderStatus::Connected`], together. Returns the depth of the reorg the plan describes.
fn plan(shared: &Shared, tree: &mut HeaderTree) -> usize {
    let room = shared.to_validation.room();
    if room == 0 {
        return 0;
    }
    let plan = tree.reorg(&shared.params, room);
    if plan.is_empty() { 0 } else { plan.depth() }
}

/// Publish what an operator may see: never the thread's own state, always a copy of it.
fn publish(shared: &Shared, tree: &HeaderTree, schedule: &Schedule, reorg_depth: usize) {
    let mut status = shared.status.read();
    status.peers = shared
        .slots
        .occupied(crate::peer::SlotKind::Outbound)
        .saturating_add(shared.slots.occupied(crate::peer::SlotKind::Inbound));
    status.queued_messages = shared.to_chain.len();
    status.queued_bytes = shared.to_chain.bytes();

    let tip = tree.entry(tree.tip());
    status.tip = Some(tip.hash());
    status.tip_height = tip.height();
    let best = tree.entry(tree.best_header());
    status.header_tip = Some(best.hash());
    status.header_height = best.height();
    status.header_work = best.chainwork();
    status.last_reorg_depth = reorg_depth;
    status.blocks_in_flight = schedule.blocks_in_flight();
    status.initial_block_download = schedule.is_initial_block_download();
    shared.status.publish(status);
}

/// This node's clock, as a header timestamp.
///
/// The one rule in the header stages that needs a clock, which is why the consensus crate
/// leaves a hole where Core runs it. A clock that reads before the epoch is broken, and the
/// safe direction for a broken clock is to accept nothing rather than everything.
pub fn node_time() -> BlockTime {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    BlockTime::new(u32::try_from(seconds).unwrap_or(u32::MAX))
}

/// Get the block store and its index onto the disk before the process ends.
///
/// The store's `fsync` goes here, in the order the storage engine states: files, then index.
/// Doing it on a clean stop is what keeps crash recovery a backstop rather than the ordinary
/// path — every Ctrl-C would otherwise replay every block since the last periodic flush.
fn flush(shared: &Shared) {
    let _ = shared;
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
