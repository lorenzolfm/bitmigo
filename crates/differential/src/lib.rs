// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential tests of bitmigo's script interpreter against Bitcoin Core's.
//!
//! This crate is the one place a third-party consensus oracle is allowed
//! (`docs/decisions/0003-differential-oracle.md`): it links `libbitcoinconsensus`, Core
//! 26.0's `VerifyScript` compiled from its C++ sources, and asks it and
//! `bitmigo_consensus::script::verify_input` the same questions. It is not a default
//! workspace member; `cargo test -p bitmigo-differential` runs it on demand, and the
//! `bitmigo-differential` binary runs the fuzzer for as long as asked.
//!
//! Two sources of questions. [`fuzz`] builds cases from a seed, signed spends two times in
//! three ([`templates`]) and unstructured scripts otherwise ([`generate`]), and compares
//! the two verdicts. [`assets`] replays Core's generated `script_assets_test.json` under
//! the 128-combination flag rule. Neither is part of the node; nothing here is linked into
//! it.

// The oracle's `unsafe` lives inside `bitcoinconsensus`; this crate writes none of its own.
#![forbid(unsafe_code)]

pub mod assets;
pub mod case;
pub mod fuzz;
pub mod generate;
pub mod json;
pub mod oracle;
pub mod prng;
pub mod templates;
