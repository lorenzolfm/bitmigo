// SPDX-License-Identifier: MIT OR Apache-2.0

//! bitmigo: a full archival Bitcoin node with its own consensus implementation.
//!
//! The binary owns everything the consensus crate refuses to touch: the disk, the network,
//! the clock and the operator. What it owns first is the shape of the program — sixty-nine
//! threads created before the first connection, two bounded queues between them, two
//! published snapshots out of them, and a shutdown that gets the chainstate onto the disk
//! rather than leaving it to crash recovery.
//!
//! ```text
//! bitmigo [listen address]
//! ```
//!
//! The address defaults to regtest's port on the loopback. Flags, a configuration file, a
//! data directory and a choice of chain are the operator surface, and they are not settled
//! yet; this is the smallest thing that lets the node be started and stopped.

mod chain;
mod control;
mod peer;
mod runtime;
mod validation;

use std::io;
use std::process::ExitCode;

use crate::runtime::signal::SignalPipe;
use crate::runtime::{Config, Runtime, THREAD_COUNT};

fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bitmigo: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Start the node, wait for something to stop it, and stop it.
fn start() -> io::Result<()> {
    let config = configure(std::env::args().skip(1))?;

    // Before any thread exists: a handler that fires while the table is half-built would
    // have a self-pipe nobody is reading yet.
    let pipe = SignalPipe::install()?;
    let runtime = Runtime::start(&config, pipe)?;
    println!(
        "bitmigo: listening on {}, {THREAD_COUNT} threads",
        runtime.listen_address(),
    );

    let cause = runtime.wait();
    println!("bitmigo: stopping on {cause}");
    let report = runtime.shutdown(config.join_deadline);
    println!("bitmigo: stopped, {report}");
    Ok(())
}

/// Read the one argument there is.
fn configure(mut arguments: impl Iterator<Item = String>) -> io::Result<Config> {
    let mut config = Config::default();
    if let Some(listen) = arguments.next() {
        config.listen = listen.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not an address to listen on: {listen}"),
            )
        })?;
    }
    if let Some(unexpected) = arguments.next() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unexpected argument: {unexpected}"),
        ));
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::configure;
    use crate::runtime::Config;
    use std::net::SocketAddr;

    #[test]
    fn no_argument_is_the_default_address() {
        let config = configure(std::iter::empty()).unwrap();
        assert_eq!(config.listen, Config::default().listen);
    }

    #[test]
    fn one_argument_is_the_address_to_listen_on() {
        let config = configure(["127.0.0.1:0".to_owned()].into_iter()).unwrap();
        assert_eq!(config.listen, SocketAddr::from(([127, 0, 0, 1], 0)));
    }

    #[test]
    fn anything_else_is_refused_before_a_socket_is_bound() {
        assert!(configure(["not-an-address".to_owned()].into_iter()).is_err());
        assert!(configure(["127.0.0.1:0".to_owned(), "--flag".to_owned()].into_iter()).is_err());
    }
}
