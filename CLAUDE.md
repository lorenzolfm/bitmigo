# bitmigo

A full archival Bitcoin node in Rust with its own consensus implementation. The pitch is
safety and clarity of implementation, not features.

## Layout

- `crates/consensus` — `bitmigo-consensus`: the rules. Pure: no filesystem, network, clock or
  threads. Its `clippy.toml` rejects the common ways of breaking that.
- `crates/bitmigo` — the node binary: storage, peers, the operator surface. Its `runtime`
  module owns the thread table, the two bounded queues between the threads, the published
  snapshots out of them, and the shutdown sequence.
- `crates/differential` — `bitmigo-differential`: not a default member. The one place a
  third-party oracle (Core 26's `libbitcoinconsensus`) is allowed; a seeded fuzzer that pits
  `verify_input` against it, and the `script_assets_test.json` runner. Run it with
  `cargo test -p bitmigo-differential`; the binary `bitmigo-differential fuzz` runs longer.
- `docs/decisions/` — numbered decision records. A decision lives there, not in chat.

More crates only when a seam earns one.

## Conventions

- **TigerStyle throughout.** Safety, then performance, then developer experience. Bounded
  loops and queues, assertions on arguments and invariants (`assert!`, not `debug_assert!`,
  for anything cheap), explicit limits on peers, buffers, script sizes and stack depth,
  functions under 70 lines, lines under 100 columns. Comments say why.
- **Dependencies.** `bitcoin`, `bitcoin_hashes` and `secp256k1` are the primitives the whole
  workspace links, pinned exactly ([decision 0001](docs/decisions/0001-primitive-crates.md)),
  and `libc` is a fourth for the node binary alone — signals, and nothing else
  ([decision 0004](docs/decisions/0004-libc.md)). `bitcoinconsensus` is a test oracle for
  `crates/differential` alone ([decision 0003](docs/decisions/0003-differential-oracle.md)).
  Any new crate, including dev and build dependencies, needs a recorded decision in
  `docs/decisions/` first. Never enable `bitcoin/bitcoinconsensus`.
- **`unsafe` is denied in the workspace and forbidden in every crate root but the node's.**
  The one module that lifts it is `bitmigo::runtime::signal`, with an `#[allow]` per call that
  names why; anything else that wants it needs a decision first.
- **Panics are prevented, not contained.** The release profile is `panic = "abort"` with
  `overflow-checks` on, and the modules that touch the wire deny `indexing_slicing`,
  `unwrap_used`, `expect_used`, `panic` and `arithmetic_side_effects` so that a parse path is
  a `Result` by construction. `assert!` stays: an assertion is a claim about our own
  invariants, not about what a peer sent.
- **Every source file starts with** `// SPDX-License-Identifier: MIT OR Apache-2.0`.
- **Toolchain:** the system `rustc`/`cargo` (1.98, edition 2024). No rustup, no flake needed.
- **Verify before handing over:** `cargo build`, `cargo test`, `cargo clippy --all-targets`
  and `cargo fmt --check`, all clean; the same three with `-p bitmigo-differential` when the
  change touches `script` or the differential crate.

## Working here

- Show the diff and wait for approval; do not commit or push.
- The safety net for consensus code is differential testing against Bitcoin Core: its JSON
  test vectors, and side-by-side regtest runs against the system `bitcoind`.
