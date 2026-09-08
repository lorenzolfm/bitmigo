# 0003 — Bitcoin Core's script verifier as a test-only oracle, in its own crate

**Status:** accepted, 2026-09-08.

## Decision

`crates/differential` (`bitmigo-differential`) depends on `bitcoinconsensus`, the Rust
binding that compiles Bitcoin Core 26.0's `libbitcoinconsensus` from its C++ sources, and
asks it the same questions it asks `bitmigo_consensus::script::verify_input`. The terms:

- **Version `0.106.0+26.0`, pinned exactly** in the workspace `Cargo.toml` (spelled
  `=0.106.0`, since cargo ignores build metadata in a requirement) and by `Cargo.lock`. It
  is the last release: Core removed `libbitcoinconsensus` in v28 (PR 29189), so the crate
  is frozen at Core 26.0's `script/interpreter.cpp`.
- **A dependency of `bitmigo-differential` only.** Never of `bitmigo-consensus` or
  `bitmigo`, and never through the `bitcoin` crate's `bitcoinconsensus` feature, which stays
  off (decision 0001). The differential crate is a workspace member but not a default
  member: `cargo build`, `cargo test` and `cargo clippy` at the root do not compile it, and
  `cargo test -p bitmigo-differential` runs it on demand. Nothing from it is linked into the
  node.
- **It adds no crate but itself.** Its one dependency is the build-time `cc` (1.4.5, with
  `shlex 2.0.1` and `find-msvc-tools 0.1.12` behind it), which `Cargo.lock` already carried:
  `secp256k1-sys` compiles libsecp256k1 with the same crate. No `libc`, no `jobserver`:
  `cc`'s parallel feature is off. The library brings its own copy of libsecp256k1
  (`external-secp` off); rust-secp256k1's symbols are prefixed, so the two do not collide,
  exactly as `bitcoin`'s own feature builds it.
- **The crate compares booleans.** `libbitcoinconsensus` reports only whether `VerifyScript`
  returned true; its other error codes (bad flags, wrong prevout count, undecodable
  transaction) mean the harness misused it and are assertions, never verdicts.

## Why

- **An oracle callable in-process is what makes fuzzing pay.** Core's JSON vectors cover
  what Core's authors thought to write down; a generator that builds a spend, signs it, damages
  one byte and asks both interpreters explores what nobody wrote down, at hundreds of cases per
  second. Running `bitcoind` per case would be four orders of magnitude slower and would test
  the node's transaction policy along with its scripts.
- **This is the only Rust binding to Core's verifier**, and Core's verifier is the network's
  definition of a valid script. The alternative, libbitcoinkernel, has no stable API and no
  Rust binding pinned to a release; delegating to it was declined at charting anyway.
- **A frozen Core 26 is still a correct script oracle.** No consensus change to script has
  activated since taproot (block 709,632, November 2021), and none is deployed. Core's
  `script/interpreter.cpp` between v26.0 and v31.1 changed only in type (a typed flags wrapper,
  spans); `docs/consensus-rules.md` §4 was inventoried against v31.1 and lists no rule the v26
  library lacks. The day a script softfork activates, this oracle is stale for that rule and
  this decision is reopened.
- **Test-only counts as a dependency** (decision 0001, Consequences). Isolating it in a
  non-default crate is how the pure crate's `cargo test` stays dependency-free and C++-free,
  and how a reader can see at a glance that nothing consensus links against Core.

## Consequences

- Building the differential crate needs a C++17 compiler on the path; the system `g++`
  (15.3) is enough. Compiling the library takes a minute or two once per profile.
- `crates/differential` is the one place a third-party consensus implementation may be
  named. A future fuzz target for headers, transactions or storage encoders either joins it
  or records its own decision; `cargo-fuzz` (nightly) would.
- The fuzzer's generator signs with rust-bitcoin's `SighashCache`, so rust-bitcoin is a
  third participant: a wrong digest there wastes a case (both interpreters reject) rather
  than misreporting one. BM-15 tested those digests against Core's `sighash.json`.
- `script_assets_test.json` is generated, not shipped (`docs/differential-testing.md` §1.6);
  the runner reads it from the path in `BITMIGO_SCRIPT_ASSETS` and skips with a message when
  the variable is unset, so the corpus never enters the repository.
