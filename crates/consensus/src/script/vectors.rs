// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test-only helpers for the `script` tests: the vendored vector files, a JSON reader small
//! enough to audit, a CSV splitter and a deterministic transaction generator.
//!
//! `serde` is not a dependency (decision 0001) and will not become one for three files of
//! arrays, strings and integers. The JSON reader below handles exactly the subset those files
//! use, iteratively with an explicit stack, and panics on anything else: a vector file that
//! stops parsing is a test failure, not an input to recover from.

#![allow(
    clippy::indexing_slicing,
    reason = "test-only code: an index out of bounds fails the test with a panic, as intended"
)]

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::hex::FromHex;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

/// Core's `src/test/data/sighash.json` at v31.1; see `tests/data/README.md`.
pub const CORE_SIGHASH_JSON: &str = include_str!("../../tests/data/sighash.json");
/// BIP340's `test-vectors.csv`; see `tests/data/README.md`.
pub const BIP340_TEST_VECTORS_CSV: &str = include_str!("../../tests/data/bip340-test-vectors.csv");
/// BIP341's `wallet-test-vectors.json`; see `tests/data/README.md`.
pub const BIP341_WALLET_TEST_VECTORS_JSON: &str =
    include_str!("../../tests/data/bip341-wallet-test-vectors.json");

/// The vector files nest six deep; anything past this is a broken file.
const JSON_DEPTH_MAX: usize = 16;

/// A JSON value, as far as the vector files need one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(i64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// A container under construction.
enum Frame {
    Array(Vec<Json>),
    Object {
        fields: Vec<(String, Json)>,
        key: Option<String>,
    },
}

impl Json {
    /// Parses one JSON document. Panics on malformed input or any construct the vector files
    /// do not use (floats, escapes beyond `\"`, `\\` and `\/`).
    pub fn parse(text: &str) -> Json {
        let bytes = text.as_bytes();
        let mut stack: Vec<Frame> = Vec::new();
        let mut position = skip_whitespace(bytes, 0);
        // Every step consumes at least one byte, so the byte count bounds the loop.
        for _ in 0..=bytes.len() {
            let (token, next) = read_token(bytes, position, &mut stack);
            assert!(next > position);
            position = skip_whitespace(bytes, next);
            let Some(value) = token else { continue };
            match stack.last_mut() {
                None => {
                    assert_eq!(position, bytes.len(), "bytes after the JSON value");
                    return value;
                }
                Some(Frame::Array(items)) => items.push(value),
                Some(Frame::Object { fields, key }) => {
                    fields.push((key.take().expect("a value follows its key"), value));
                }
            }
        }
        panic!("the JSON document did not terminate");
    }

    /// The field `key` of an object; panics if absent.
    pub fn get(&self, key: &str) -> &Json {
        let Json::Object(fields) = self else {
            panic!("not an object")
        };
        let field = fields.iter().find(|(name, _)| name == key);
        &field.unwrap_or_else(|| panic!("missing key {key}")).1
    }

    pub fn as_array(&self) -> &[Json] {
        let Json::Array(items) = self else {
            panic!("not an array")
        };
        items
    }

    pub fn as_str(&self) -> &str {
        let Json::Str(text) = self else {
            panic!("not a string")
        };
        text
    }

    pub fn as_i64(&self) -> i64 {
        let Json::Number(number) = self else {
            panic!("not a number")
        };
        *number
    }

    /// A hex string decoded.
    pub fn as_bytes(&self) -> Vec<u8> {
        Vec::<u8>::from_hex(self.as_str()).expect("a hex string")
    }
}

/// Reads one token at `position`. A container opener pushes a frame and yields nothing; a
/// closer pops its frame and yields the container; a string inside an object that has no
/// pending key becomes that key and yields nothing; everything else yields a value.
fn read_token(bytes: &[u8], position: usize, stack: &mut Vec<Frame>) -> (Option<Json>, usize) {
    let byte = *bytes.get(position).expect("unterminated JSON");
    match byte {
        b'[' => {
            stack.push(Frame::Array(Vec::new()));
            assert!(stack.len() <= JSON_DEPTH_MAX);
            (None, position + 1)
        }
        b'{' => {
            stack.push(Frame::Object {
                fields: Vec::new(),
                key: None,
            });
            assert!(stack.len() <= JSON_DEPTH_MAX);
            (None, position + 1)
        }
        b']' => match stack.pop() {
            Some(Frame::Array(items)) => (Some(Json::Array(items)), position + 1),
            _ => panic!("unbalanced ] at {position}"),
        },
        b'}' => match stack.pop() {
            Some(Frame::Object { fields, key: None }) => (Some(Json::Object(fields)), position + 1),
            _ => panic!("unbalanced }} at {position}"),
        },
        b',' | b':' => (None, position + 1),
        b'"' => {
            let (text, next) = read_string(bytes, position);
            match stack.last_mut() {
                Some(Frame::Object { key, .. }) if key.is_none() => {
                    *key = Some(text);
                    (None, next)
                }
                _ => (Some(Json::Str(text)), next),
            }
        }
        b't' => read_literal(bytes, position, b"true", Json::Bool(true)),
        b'f' => read_literal(bytes, position, b"false", Json::Bool(false)),
        b'n' => read_literal(bytes, position, b"null", Json::Null),
        b'-' | b'0'..=b'9' => read_number(bytes, position),
        other => panic!("unexpected byte {other:#04x} at {position}"),
    }
}

fn skip_whitespace(bytes: &[u8], mut position: usize) -> usize {
    // Bounded by the input length.
    while let Some(byte) = bytes.get(position) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        position += 1;
    }
    position
}

fn read_string(bytes: &[u8], position: usize) -> (String, usize) {
    assert_eq!(bytes.get(position), Some(&b'"'));
    let mut text = Vec::new();
    let mut cursor = position + 1;
    // Bounded by the input length.
    for _ in 0..bytes.len() {
        let byte = *bytes.get(cursor).expect("unterminated string");
        cursor += 1;
        match byte {
            b'"' => {
                return (
                    String::from_utf8(text).expect("the vectors are ASCII"),
                    cursor,
                );
            }
            b'\\' => {
                let escaped = *bytes.get(cursor).expect("unterminated escape");
                cursor += 1;
                assert!(matches!(escaped, b'"' | b'\\' | b'/'), "unsupported escape");
                text.push(escaped);
            }
            _ => text.push(byte),
        }
    }
    panic!("unterminated string at {position}");
}

fn read_literal(
    bytes: &[u8],
    position: usize,
    literal: &[u8],
    value: Json,
) -> (Option<Json>, usize) {
    let end = position + literal.len();
    assert_eq!(
        bytes.get(position..end),
        Some(literal),
        "bad literal at {position}"
    );
    (Some(value), end)
}

fn read_number(bytes: &[u8], position: usize) -> (Option<Json>, usize) {
    let mut end = position;
    if bytes.get(end) == Some(&b'-') {
        end += 1;
    }
    // Bounded by the input length.
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    let text = core::str::from_utf8(&bytes[position..end]).expect("ASCII digits");
    let number = text.parse::<i64>().expect("an integer");
    (Some(Json::Number(number)), end)
}

/// The rows of a header-first CSV with no quoting, split on commas.
pub fn csv_rows(text: &str) -> Vec<Vec<&str>> {
    text.lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(|line| line.split(',').collect())
        .collect()
}

/// `SplitMix64`: a deterministic generator with a one-word state, so a failing case is
/// reproducible from its seed.
pub struct Prng(u64);

impl Prng {
    pub fn new(seed: u64) -> Prng {
        Prng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() >> 32).expect("the top 32 bits fit")
    }

    /// A value in `0..bound`.
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0);
        self.next_u64() % bound
    }

    pub fn below_usize(&mut self, bound: usize) -> usize {
        usize::try_from(self.below(u64::try_from(bound).expect("fits"))).expect("fits")
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| u8::try_from(self.below(256)).expect("one byte"))
            .collect()
    }

    pub fn bytes_32(&mut self) -> [u8; 32] {
        self.bytes(32).try_into().expect("32 bytes")
    }
}

/// A transaction with 1 to 6 inputs and 0 to 6 outputs, random everywhere a signature hash
/// reads: version (1, 2 or arbitrary), lock time, outpoints, sequences, amounts, scripts.
pub fn random_transaction(prng: &mut Prng) -> Transaction {
    let version = match prng.below(3) {
        0 => 1,
        1 => 2,
        _ => i32::from_le_bytes(prng.next_u32().to_le_bytes()),
    };
    let input_count = prng.below_usize(6) + 1;
    let output_count = prng.below_usize(7);
    Transaction {
        version: Version(version),
        lock_time: LockTime::from_consensus(prng.next_u32()),
        input: (0..input_count)
            .map(|_| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(prng.bytes_32()),
                    vout: prng.next_u32(),
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(prng.next_u32()),
                witness: Witness::new(),
            })
            .collect(),
        output: (0..output_count).map(|_| random_tx_out(prng)).collect(),
    }
}

/// `count` spent outputs with random amounts and scripts of 0 to 40 bytes.
pub fn random_prevouts(prng: &mut Prng, count: usize) -> Vec<TxOut> {
    (0..count).map(|_| random_tx_out(prng)).collect()
}

fn random_tx_out(prng: &mut Prng) -> TxOut {
    let script_len = prng.below_usize(41);
    TxOut {
        value: Amount::from_sat(prng.below(21_000_000 * 100_000_000)),
        script_pubkey: ScriptBuf::from_bytes(prng.bytes(script_len)),
    }
}

/// A `scriptCode` of 0 to 11 operations that rust-bitcoin's oracle hashes the same way Core
/// does: complete pushes only, and no `OP_CODESEPARATOR`, which the oracle does not strip.
pub fn random_script_code(prng: &mut Prng) -> ScriptBuf {
    const PLAIN_OPCODES: [u8; 9] = [0x00, 0x63, 0x67, 0x68, 0x76, 0x87, 0x88, 0xa9, 0xac];
    let mut bytes = Vec::new();
    let op_count = prng.below(12);
    for _ in 0..op_count {
        match prng.below(4) {
            0 => {
                let len = prng.below_usize(75) + 1;
                bytes.push(u8::try_from(len).expect("at most 75"));
                bytes.extend(prng.bytes(len));
            }
            1 => {
                let len = prng.below_usize(120);
                bytes.push(0x4c);
                bytes.push(u8::try_from(len).expect("at most 119"));
                bytes.extend(prng.bytes(len));
            }
            2 => bytes.push(0x51 + u8::try_from(prng.below(16)).expect("OP_1..OP_16")),
            _ => bytes.push(PLAIN_OPCODES[prng.below_usize(PLAIN_OPCODES.len())]),
        }
    }
    ScriptBuf::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::Json;

    #[test]
    fn json_reader_handles_the_vector_shapes() {
        let json = Json::parse(
            r#" { "a": [1, -2, "x"], "b": {"c": true, "d": null, "e": "q\"z"}, "f": [] } "#,
        );
        assert_eq!(json.get("a").as_array().len(), 3);
        assert_eq!(json.get("a").as_array()[1].as_i64(), -2);
        assert_eq!(json.get("a").as_array()[2].as_str(), "x");
        assert_eq!(json.get("b").get("c"), &Json::Bool(true));
        assert_eq!(json.get("b").get("d"), &Json::Null);
        assert_eq!(json.get("b").get("e").as_str(), "q\"z");
        assert_eq!(json.get("f").as_array().len(), 0);
    }
}
