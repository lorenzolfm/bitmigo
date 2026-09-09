// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's runtime: the thread table, the state the threads share, and the sequence that
//! takes the whole thing down without relying on crash recovery.
//!
//! Sixty-nine threads, all of them created before the first connection and none of them
//! spawned afterwards:
//!
//! ```text
//!                   ┌──────── 32 peer slots, preallocated at startup ─────────┐
//!  listener ─accept─┤  reader ×32                      writer ×32             │
//!  connector ─dial──┤  one blocking read               one blocking queue     │
//!                   └────────┬──────────────────────────────▲─────────────────┘
//!                            │ 32 MB / 1024 items           │ send jobs
//!                            │ READERS BLOCK when full ──▶ TCP backpressure, that peer only
//!                            ▼                              │
//!                   ┌────────────────────────────────────────┴──┐
//!                   │ chain: header tree, schedule, block store │
//!                   └────────┬──────────────────────────────────┘
//!                            │ 64 connect jobs, pulled — never blocks
//!                            ▼
//!                   ┌───────────────────────────────────────────┐
//!                   │ validation: coins, tip, undo, accumulator │
//!                   └────────┬──────────────────────────────────┘
//!                            │ one published snapshot each
//!                            ▼
//!                          control
//! ```
//!
//! Two threads own everything that persists: the chain thread is the block store's single
//! writer, and the validation thread is the only thread that touches the coins. They are two
//! threads and not one because connecting a block is the slow stage, and merging them would
//! stop block download for the length of every script verification.

pub mod queue;
pub mod signal;
pub mod snapshot;
pub mod supervisor;
pub mod sync;

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use bitmigo_consensus::params::Chain;

use crate::peer::{
    PEER_SLOTS, PEER_THREAD_STACK_BYTES, PeerSlots, READER_THREAD_PREFIX, SlotIndex,
    WRITER_THREAD_PREFIX,
};
use crate::runtime::queue::{ChainToValidation, PeerMessage, PeerToChain};
use crate::runtime::signal::{Cause, Shutdown, SignalPipe};
use crate::runtime::snapshot::{Published, StatusSnapshot, UtxoSetSnapshot};
use crate::runtime::supervisor::{DEFAULT_STACK_BYTES, ShutdownReport, Supervisor};
use crate::{chain, control, peer, validation};

/// The thread that accepts connections, and the one that owns the self-pipe.
pub const LISTENER_THREAD: &str = "listener";
/// The thread that dials them.
pub const CONNECTOR_THREAD: &str = "connector";
/// The thread that owns the header tree, the schedule and the block store's single write.
pub const CHAIN_THREAD: &str = "chain";
/// The thread that owns the chainstate. The one thread a shutdown waits for without a limit.
pub const VALIDATION_THREAD: &str = "validation";
/// The thread that answers the operator, from the published snapshots and nothing else.
pub const CONTROL_THREAD: &str = "control";

/// One row of the thread table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRow {
    /// The thread's name, or the prefix its instances are numbered under.
    pub name: &'static str,
    /// How many of them there are.
    pub count: usize,
    /// The stack each one gets.
    pub stack_bytes: usize,
}

/// Every thread the node runs. The whole concurrency model is readable from this table, and
/// so is its cost: the stacks multiplied by the counts, reserved at startup whether the node
/// has one peer or thirty-two.
pub const THREAD_TABLE: [ThreadRow; 7] = [
    ThreadRow {
        name: LISTENER_THREAD,
        count: 1,
        stack_bytes: DEFAULT_STACK_BYTES,
    },
    ThreadRow {
        name: CONNECTOR_THREAD,
        count: 1,
        stack_bytes: DEFAULT_STACK_BYTES,
    },
    ThreadRow {
        name: READER_THREAD_PREFIX,
        count: PEER_SLOTS,
        stack_bytes: PEER_THREAD_STACK_BYTES,
    },
    ThreadRow {
        name: WRITER_THREAD_PREFIX,
        count: PEER_SLOTS,
        stack_bytes: PEER_THREAD_STACK_BYTES,
    },
    ThreadRow {
        name: CHAIN_THREAD,
        count: 1,
        stack_bytes: DEFAULT_STACK_BYTES,
    },
    // Validation gets the script pool beside it once there is one; the pool's threads are
    // its own and join before each block ends, so they are not rows here.
    ThreadRow {
        name: VALIDATION_THREAD,
        count: 1,
        stack_bytes: DEFAULT_STACK_BYTES,
    },
    ThreadRow {
        name: CONTROL_THREAD,
        count: 1,
        stack_bytes: DEFAULT_STACK_BYTES,
    },
];

/// Threads at the peer cap: the five singletons and two per slot. Sixty-nine, and the number
/// does not move at runtime.
pub const THREAD_COUNT: usize = 5 + PEER_SLOTS + PEER_SLOTS;

const _: () = assert!(THREAD_COUNT == 69);

/// What the operator gives the node. The flags, the configuration file and the data
/// directory that will fill this in are the operator surface, which is not settled yet; the
/// defaults are regtest's, because that is the only chain the node can currently be pointed
/// at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Where to accept connections.
    pub listen: SocketAddr,
    /// Which chain.
    pub chain: Chain,
    /// How long the threads that hold no persistent state get to notice a shutdown.
    pub join_deadline: Duration,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen: SocketAddr::from(([127, 0, 0, 1], 18_444)),
            chain: Chain::Regtest,
            join_deadline: supervisor::JOIN_DEADLINE,
        }
    }
}

/// What the threads share. Everything here is either a bounded queue, a published snapshot,
/// or the slot table: there is no shared mutable node state, because each owner keeps its own
/// behind its own thread.
pub struct Shared {
    /// The node is stopping, and why.
    pub shutdown: Shutdown,
    /// The thirty-two connection slots.
    pub slots: PeerSlots,
    /// Peer readers to the chain thread. The only queue with a blocking send.
    pub to_chain: PeerToChain<PeerMessage>,
    /// The chain thread to the validation thread. Pulled, never pushed against a full queue.
    pub to_validation: ChainToValidation,
    /// The chain thread's summary of itself.
    pub status: Published<StatusSnapshot>,
    /// The validation thread's summary of the UTXO set.
    pub utxoset: Published<UtxoSetSnapshot>,
}

impl Shared {
    /// The shared state of a node that has just started.
    pub fn new(chain: Chain) -> Shared {
        Shared {
            shutdown: Shutdown::new(),
            slots: PeerSlots::new(),
            to_chain: PeerToChain::new(),
            to_validation: ChainToValidation::new(),
            status: Published::new(StatusSnapshot::starting(chain)),
            utxoset: Published::new(UtxoSetSnapshot::empty()),
        }
    }
}

/// A running node.
pub struct Runtime {
    shared: Arc<Shared>,
    supervisor: Supervisor,
    listen: SocketAddr,
}

impl Runtime {
    /// Bind the listening socket and start every thread in the table.
    ///
    /// The socket is bound before anything is spawned, so a node that cannot listen fails
    /// while it is still one thread and reports why. The self-pipe goes to the listener,
    /// which is the only thread that must wait on a descriptor and on a signal at once.
    pub fn start(config: &Config, pipe: SignalPipe) -> io::Result<Runtime> {
        assert_eq!(
            THREAD_TABLE.iter().map(|row| row.count).sum::<usize>(),
            THREAD_COUNT,
            "the table is the thread count",
        );
        let socket = TcpListener::bind(config.listen)?;
        let listen = socket.local_addr()?;
        let shared = Arc::new(Shared::new(config.chain));
        let mut supervisor = Supervisor::with_capacity(THREAD_COUNT);

        let listening = Arc::clone(&shared);
        supervisor.spawn(LISTENER_THREAD, DEFAULT_STACK_BYTES, move || {
            peer::listener(&listening, socket, &pipe);
        })?;

        let dialling = Arc::clone(&shared);
        supervisor.spawn(CONNECTOR_THREAD, DEFAULT_STACK_BYTES, move || {
            peer::connector(&dialling);
        })?;

        for index in 0..PEER_SLOTS {
            let slot = SlotIndex::from_position(index);
            let reading = Arc::clone(&shared);
            supervisor.spawn(
                &format!("{READER_THREAD_PREFIX}{slot}"),
                PEER_THREAD_STACK_BYTES,
                move || peer::reader(&reading, slot),
            )?;
        }
        for index in 0..PEER_SLOTS {
            let slot = SlotIndex::from_position(index);
            let writing = Arc::clone(&shared);
            supervisor.spawn(
                &format!("{WRITER_THREAD_PREFIX}{slot}"),
                PEER_THREAD_STACK_BYTES,
                move || peer::writer(&writing, slot),
            )?;
        }

        let charting = Arc::clone(&shared);
        supervisor.spawn(CHAIN_THREAD, DEFAULT_STACK_BYTES, move || {
            chain::run(&charting);
        })?;
        let validating = Arc::clone(&shared);
        supervisor.spawn(VALIDATION_THREAD, DEFAULT_STACK_BYTES, move || {
            validation::run(&validating);
        })?;
        let answering = Arc::clone(&shared);
        supervisor.spawn(CONTROL_THREAD, DEFAULT_STACK_BYTES, move || {
            control::run(&answering);
        })?;

        assert_eq!(supervisor.spawned(), THREAD_COUNT);
        Ok(Runtime {
            shared,
            supervisor,
            listen,
        })
    }

    /// Where the node is accepting connections, which is the requested address unless the
    /// operator asked for port zero.
    pub fn listen_address(&self) -> SocketAddr {
        self.listen
    }

    /// What the threads share, for the tests that drive the node without a process around
    /// it. Everything else reaches this through the thread it was handed to.
    #[cfg(test)]
    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Block until something asks the node to stop.
    pub fn wait(&self) -> Cause {
        self.shared.shutdown.wait()
    }

    /// Stop, in the one order that never relies on crash recovery.
    ///
    /// 1. The shutdown is announced — by the signal handler through the listener, or by a
    ///    thread that cannot continue. The listening socket closes as the listener returns
    ///    and the connector stops dialling.
    /// 2. `shutdown(Both)` reaches every peer socket, which is what ends the reads the peer
    ///    threads are blocked in. The read timeout behind it is only a backstop.
    /// 3. The queue to the chain thread closes, so the chain thread drains what is already
    ///    on it, flushes the block store and its index, and exits.
    /// 4. The validation thread finishes the block it is on — a connect is atomic — and
    ///    flushes the coins, the tip and the accumulator.
    /// 5. Everything but validation has [`Config::join_deadline`] to return. None of them
    ///    holds anything that has to reach the disk, so past that the node reports them and
    ///    goes; validation is waited for however long its flush takes, and the operator's
    ///    escape from a long flush is a second signal, which exits at once.
    pub fn shutdown(self, deadline: Duration) -> ShutdownReport {
        assert!(
            self.shared.shutdown.is_begun(),
            "a shutdown is announced before it is performed",
        );
        let live = self.shared.slots.shutdown_all();
        if live > 0 {
            println!("bitmigo: closed {live} peer connections");
        }
        self.shared.to_chain.close();
        self.supervisor.finish(VALIDATION_THREAD, deadline)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
