// SPDX-License-Identifier: MIT OR Apache-2.0

//! bitmigo: a full archival Bitcoin node with its own consensus implementation.
//!
//! The binary owns everything the consensus crate refuses to touch: the disk, the network,
//! the clock and the operator. It does nothing yet.

fn main() {
    println!("bitmigo {}", env!("CARGO_PKG_VERSION"));
}
