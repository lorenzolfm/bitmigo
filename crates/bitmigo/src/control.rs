// SPDX-License-Identifier: MIT OR Apache-2.0

//! The control thread.
//!
//! The operator's whole view of a running node, and deliberately the smallest thread in it.
//! What is settled here is what it may touch: the two published snapshots, and nothing else.
//! It never takes a lock either owner holds, never reads the header tree or the chainstate,
//! and cannot make a slow client into a slow node — the worst a client can do is read a copy
//! that is one block old.
//!
//! The Unix socket it answers on, the line-per-request protocol, and the `status` and
//! `utxoset` commands are the control module's own work. The socket file it creates is
//! removed here, on the way out, which is why the thread has a shutdown of its own to do.

use std::time::Duration;

use crate::runtime::Shared;

/// How long the thread sleeps between passes. A shutdown wakes it directly.
const CONTROL_TICK: Duration = Duration::from_millis(500);

/// Run until the node stops.
pub fn run(shared: &Shared) {
    while shared.shutdown.wait_timeout(CONTROL_TICK).is_none() {}

    // The last thing an operator watching the terminal sees is where the node got to, read
    // the same way a client would have read it.
    let status = shared.status.read();
    let utxoset = shared.utxoset.read();
    println!(
        "bitmigo: {:?} tip {} at height {}, {} unspent outputs",
        status.chain,
        status
            .tip
            .map_or_else(|| "none".to_owned(), |hash| hash.to_string()),
        utxoset.height.get(),
        utxoset.txouts,
    );
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::runtime::Shared;
    use crate::runtime::signal::Cause;
    use bitmigo_consensus::params::Chain;
    use std::sync::Arc;
    use std::thread::{self, Builder};
    use std::time::{Duration, Instant};

    #[test]
    fn the_control_thread_stops_when_the_node_does() {
        let shared = Arc::new(Shared::new(Chain::Regtest));
        let running = Arc::clone(&shared);
        let control = Builder::new()
            .name("control".to_owned())
            .spawn(move || run(&running))
            .expect("a test thread");

        thread::sleep(Duration::from_millis(20));
        let started = Instant::now();
        shared.shutdown.begin(Cause::Internal("test"));
        control.join().expect("the control thread stops");
        // Woken by the announcement, not by the tick behind it.
        assert!(started.elapsed() < Duration::from_millis(400));
    }
}
