# bitmigo

A full archival Bitcoin node in Rust with its own consensus implementation.

bitmigo validates every block from genesis with its own script interpreter and its own
chainstate, and follows the tip. It leans on the `bitcoin`, `bitcoin_hashes` and `secp256k1`
crates for types, serialization, hashing and signature verification, and on nothing else.
The rules themselves are written here, in a style meant to be read: bounded, asserted,
and small enough to fit on a screen.

**Status:** pre-alpha. The workspace builds and does nothing yet.

## Building

```sh
cargo build
cargo test
cargo clippy --all-targets
```

Rust 1.98 or newer.

## Layout

- `crates/consensus` — the rules, as a pure library with no I/O.
- `crates/bitmigo` — the node binary.
- `docs/decisions/` — why things are the way they are.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in this work by you shall be dual
licensed as above, without any additional terms or conditions.
