# bitmigo

A full archival Bitcoin node in Rust with its own consensus implementation. The pitch is
safety and clarity of implementation, not features.

## Layout

- `crates/consensus` — `bitmigo-consensus`: the rules. Pure: no filesystem, network, clock or
  threads. Its `clippy.toml` rejects the common ways of breaking that.
- `crates/bitmigo` — the node binary: storage, peers, the operator surface.
- `docs/decisions/` — numbered decision records. A decision lives there, not in chat.

More crates only when a seam earns one.

## Conventions

- **TigerStyle throughout.** Safety, then performance, then developer experience. Bounded
  loops and queues, assertions on arguments and invariants (`assert!`, not `debug_assert!`,
  for anything cheap), explicit limits on peers, buffers, script sizes and stack depth,
  functions under 70 lines, lines under 100 columns. Comments say why.
- **Dependencies.** `bitcoin`, `bitcoin_hashes` and `secp256k1` are the only third-party
  crates, pinned exactly ([decision 0001](docs/decisions/0001-primitive-crates.md)). Any new
  crate, including dev and build dependencies, needs a recorded decision in `docs/decisions/`
  first. Never enable `bitcoin/bitcoinconsensus`.
- **Every source file starts with** `// SPDX-License-Identifier: MIT OR Apache-2.0`.
- **Toolchain:** the system `rustc`/`cargo` (1.98, edition 2024). No rustup, no flake needed.
- **Verify before handing over:** `cargo build`, `cargo test`, `cargo clippy --all-targets`
  and `cargo fmt --check`, all clean.

## Working here

- Show the diff and wait for approval; do not commit or push.
- The safety net for consensus code is differential testing against Bitcoin Core: its JSON
  test vectors, and side-by-side regtest runs against the system `bitcoind`.
