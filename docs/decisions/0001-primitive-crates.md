# 0001 — Three primitive crates, and nothing else

**Status:** accepted, 2026-09-07.

## Decision

bitmigo depends on exactly three third-party crates, pinned to exact versions in the
workspace `Cargo.toml`:

| Crate | Version | What it supplies |
|---|---|---|
| `bitcoin` | 0.32.102 | Block, transaction, script and header types; consensus serialization; network constants |
| `bitcoin_hashes` | 0.14.101 | SHA-256, double SHA-256, RIPEMD-160, tagged hashes |
| `secp256k1` | 0.29.1 | ECDSA and Schnorr signature verification over libsecp256k1 |

Everything else — the script interpreter, transaction and block validation, softfork
activation, chainstate, storage, networking — is written in this repository.

Adding a fourth crate needs a decision recorded in this directory before it appears in
`Cargo.toml`: what it costs (supply chain, build time, the surface it adds to consensus),
what the alternative is, and why the alternative loses.

## Why

- **Consensus is the product.** A node whose validation is somebody else's library has
  nothing to say about safety and clarity of implementation. The rules are the thing to read.
- **Primitives are not.** Hashing and curve arithmetic are where an independent
  implementation adds risk and no clarity. `bitcoin_hashes` and `secp256k1` are the crates
  Bitcoin Core's own test suite and most of the Rust ecosystem already exercise.
- **Every dependency is attack surface** for a program that decides which chain is valid.
  Fewer, pinned, and each one argued for.

## Consequences

- `bitcoin` is used with `default-features = false`. Its optional `bitcoinconsensus` feature
  wraps Core's script verifier and must never be enabled: that would be the delegation this
  decision refuses.
- The pins move only by an explicit bump commit that names what changed in the crate's API,
  because the rust-bitcoin crate split has reshuffled types between releases before.
- Test-only and build-only dependencies count. A fuzzing harness or benchmark that wants a
  crate records its decision the same way.
