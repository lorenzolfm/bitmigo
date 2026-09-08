// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test-only helpers for the `script` tests: the vendored vector files, a JSON reader small
//! enough to audit, a CSV splitter, a deterministic transaction generator, and the pieces of
//! Core's test harness the script vectors need: `ParseScript`'s mini-language,
//! `ParseScriptFlags`, `ParseScriptError`, `AmountFromValue` and the crediting/spending
//! transaction pair `DoTest` builds.
//!
//! `serde` is not a dependency (decision 0001) and will not become one for six files of
//! arrays, strings and numbers. The JSON reader below handles exactly the subset those files
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

use super::num::ScriptNum;
use super::opcode::{OP_0, OP_1, OP_1NEGATE, PARSER_NAMES};
use super::reader::push_encoding;
use super::{ScriptError, ScriptFlags};

/// Core's `src/test/data/sighash.json` at v31.1; see `tests/data/README.md`.
pub const CORE_SIGHASH_JSON: &str = include_str!("../../tests/data/sighash.json");
/// Core's `src/test/data/script_tests.json` at v31.1; see `tests/data/README.md`.
pub const CORE_SCRIPT_TESTS_JSON: &str = include_str!("../../tests/data/script_tests.json");
/// Core's `src/test/data/tx_valid.json` at v31.1; see `tests/data/README.md`.
pub const CORE_TX_VALID_JSON: &str = include_str!("../../tests/data/tx_valid.json");
/// Core's `src/test/data/tx_invalid.json` at v31.1; see `tests/data/README.md`.
pub const CORE_TX_INVALID_JSON: &str = include_str!("../../tests/data/tx_invalid.json");
/// BIP340's `test-vectors.csv`; see `tests/data/README.md`.
pub const BIP340_TEST_VECTORS_CSV: &str = include_str!("../../tests/data/bip340-test-vectors.csv");
/// BIP341's `wallet-test-vectors.json`; see `tests/data/README.md`.
pub const BIP341_WALLET_TEST_VECTORS_JSON: &str =
    include_str!("../../tests/data/bip341-wallet-test-vectors.json");

/// The vector files nest six deep; anything past this is a broken file.
const JSON_DEPTH_MAX: usize = 16;

/// A JSON value, as far as the vector files need one. A number with a fraction or an
/// exponent is kept as text: the only ones are amounts in BTC, read by [`Json::as_satoshis`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(i64),
    Decimal(String),
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

    pub fn is_array(&self) -> bool {
        matches!(self, Json::Array(_))
    }

    /// Core's `AmountFromValue`: a number in BTC with at most eight decimals, in satoshis.
    /// The vectors write `0.00000001` and integers; exponents are not needed.
    pub fn as_satoshis(&self) -> u64 {
        const SATOSHIS_PER_BTC: u64 = 100_000_000;
        match self {
            Json::Number(btc) => u64::try_from(*btc).expect("non-negative") * SATOSHIS_PER_BTC,
            Json::Decimal(text) => {
                let (whole, fraction) = text.split_once('.').expect("a decimal point");
                assert!(fraction.len() <= 8, "more than eight decimals: {text}");
                assert!(fraction.bytes().all(|b| b.is_ascii_digit()), "{text}");
                let whole: u64 = whole.parse().expect("digits");
                let fraction: u64 = format!("{fraction:0<8}").parse().expect("digits");
                whole * SATOSHIS_PER_BTC + fraction
            }
            _ => panic!("not an amount"),
        }
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
    let mut decimal = false;
    // Bounded by the input length.
    while let Some(&byte) = bytes.get(end) {
        if byte.is_ascii_digit() {
            end += 1;
        } else if matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-') {
            decimal = true;
            end += 1;
        } else {
            break;
        }
    }
    let text = core::str::from_utf8(&bytes[position..end]).expect("ASCII digits");
    if decimal {
        return (Some(Json::Decimal(text.to_owned())), end);
    }
    let number = text.parse::<i64>().expect("an integer");
    (Some(Json::Number(number)), end)
}

/// Core's `ParseScript`: whitespace-separated tokens, each a decimal number pushed as a
/// script number, `0x`-prefixed hex inserted verbatim (how the vectors spell explicit push
/// opcodes and malformed data), a single-quoted string pushed as data, or an opcode name
/// with or without its `OP_` prefix.
pub fn parse_script(text: &str) -> Vec<u8> {
    let mut script = Vec::new();
    for word in text.split([' ', '\t', '\n']) {
        if word.is_empty() {
            continue;
        }
        let digits = word.strip_prefix('-').unwrap_or(word);
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            let number: i64 = word.parse().expect("fits i64");
            assert!(number.abs() <= 0xffff_ffff, "out of range: {word}");
            script.extend(push_int64(number));
        } else if let Some(hex) = word.strip_prefix("0x")
            && !hex.is_empty()
            && let Ok(raw) = Vec::<u8>::from_hex(hex)
        {
            script.extend(raw);
        } else if word.len() >= 2 && word.starts_with('\'') && word.ends_with('\'') {
            script.extend(push_encoding(&word.as_bytes()[1..word.len() - 1]));
        } else {
            let name = word.strip_prefix("OP_").unwrap_or(word);
            let (byte, _) = PARSER_NAMES
                .iter()
                .find(|(_, candidate)| candidate.strip_prefix("OP_") == Some(name))
                .unwrap_or_else(|| panic!("unknown opcode {word}"));
            script.push(*byte);
        }
    }
    script
}

/// Core's `CScript::push_int64`: the small-integer opcodes where they apply, otherwise a
/// push of the minimal script number.
pub fn push_int64(number: i64) -> Vec<u8> {
    match number {
        -1 => vec![OP_1NEGATE],
        0 => vec![OP_0],
        1..=16 => vec![OP_1 + u8::try_from(number - 1).expect("0..16")],
        _ => push_encoding(&ScriptNum::from_i64(number).encode()),
    }
}

/// The 21 `SCRIPT_VERIFY_*` names of `ScriptFlagNamesToEnum`, with the consensus flag each
/// maps to, or `None` for a policy flag the interpreter has no switch for.
const FLAG_NAMES: [(&str, Option<ScriptFlags>); 21] = [
    ("P2SH", Some(ScriptFlags::P2SH)),
    ("STRICTENC", None),
    ("DERSIG", Some(ScriptFlags::DERSIG)),
    ("LOW_S", None),
    ("NULLDUMMY", Some(ScriptFlags::NULLDUMMY)),
    ("SIGPUSHONLY", None),
    ("MINIMALDATA", None),
    ("DISCOURAGE_UPGRADABLE_NOPS", None),
    ("CLEANSTACK", None),
    ("MINIMALIF", None),
    ("NULLFAIL", None),
    (
        "CHECKLOCKTIMEVERIFY",
        Some(ScriptFlags::CHECKLOCKTIMEVERIFY),
    ),
    (
        "CHECKSEQUENCEVERIFY",
        Some(ScriptFlags::CHECKSEQUENCEVERIFY),
    ),
    ("WITNESS", Some(ScriptFlags::WITNESS)),
    ("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM", None),
    ("WITNESS_PUBKEYTYPE", None),
    ("CONST_SCRIPTCODE", None),
    ("TAPROOT", Some(ScriptFlags::TAPROOT)),
    ("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION", None),
    ("DISCOURAGE_OP_SUCCESS", None),
    ("DISCOURAGE_UPGRADABLE_PUBKEYTYPE", None),
];

/// A vector's flag list, split into the consensus flags and the policy names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedFlags {
    pub consensus: ScriptFlags,
    pub policy: Vec<&'static str>,
}

impl ParsedFlags {
    pub fn has_policy(&self, name: &str) -> bool {
        self.policy.contains(&name)
    }
}

/// Core's `ParseScriptFlags`: comma-separated names, empty or `NONE` for no flags.
pub fn parse_flags(text: &str) -> ParsedFlags {
    let mut parsed = ParsedFlags {
        consensus: ScriptFlags::NONE,
        policy: Vec::new(),
    };
    if text.is_empty() || text == "NONE" {
        return parsed;
    }
    for word in text.split(',') {
        let (name, flag) = FLAG_NAMES
            .iter()
            .find(|(name, _)| *name == word)
            .unwrap_or_else(|| panic!("unknown flag {word}"));
        match flag {
            Some(flag) => parsed.consensus = parsed.consensus.union(*flag),
            None => parsed.policy.push(name),
        }
    }
    parsed
}

/// The `scriptError` names of `script_tests.cpp` that name no consensus error: the checks
/// behind them are policy flags.
const POLICY_ERROR_NAMES: [&str; 11] = [
    "SIG_HASHTYPE",
    "MINIMALDATA",
    "SIG_HIGH_S",
    "PUBKEYTYPE",
    "MINIMALIF",
    "NULLFAIL",
    "DISCOURAGE_UPGRADABLE_NOPS",
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
    "WITNESS_PUBKEYTYPE",
    "OP_CODESEPARATOR",
    "SIG_FINDANDDELETE",
];

/// What a `script_tests.json` row expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expected {
    Ok,
    Consensus(ScriptError),
    Policy(&'static str),
}

/// Core's `ParseScriptError` over its 44 names, sorted into the three kinds above.
pub fn parse_script_error(name: &str) -> Expected {
    if name == "OK" {
        return Expected::Ok;
    }
    if let Some(policy) = POLICY_ERROR_NAMES
        .iter()
        .find(|candidate| **candidate == name)
    {
        return Expected::Policy(policy);
    }
    let error = ScriptError::ALL
        .iter()
        .find(|error| error.name() == name)
        .unwrap_or_else(|| panic!("unknown script error {name}"));
    Expected::Consensus(*error)
}

/// `BuildCreditingTransaction`: version 1, one null-prevout input with scriptSig `OP_0 OP_0`,
/// one output paying `amount` to `script_pubkey`.
pub fn crediting_transaction(script_pubkey: &[u8], amount: u64) -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![OP_0, OP_0]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        }],
    }
}

/// `BuildSpendingTransaction`: version 1, one input spending the crediting transaction's
/// output with `script_sig` and `witness`, one output of the same amount to an empty script.
pub fn spending_transaction(
    script_sig: &[u8],
    witness: Witness,
    credit: &Transaction,
) -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: credit.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: credit.output[0].value,
            script_pubkey: ScriptBuf::new(),
        }],
    }
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
    use super::super::ScriptFlags;
    use super::{Expected, Json, parse_flags, parse_script, parse_script_error};
    use crate::script::ScriptError;

    #[test]
    fn parse_script_follows_core_s_grammar() {
        assert_eq!(parse_script(""), Vec::<u8>::new());
        assert_eq!(parse_script("  1  2  "), vec![0x51, 0x52]);
        assert_eq!(
            parse_script("0 -1 16 17 -17 255 256"),
            vec![
                0x00, 0x4f, 0x60, 0x01, 0x11, 0x01, 0x91, 0x02, 0xff, 0x00, 0x02, 0x00, 0x01
            ]
        );
        assert_eq!(parse_script("0x4c 0x01 0xff"), vec![0x4c, 0x01, 0xff]);
        assert_eq!(parse_script("'Az' EQUAL"), vec![0x02, 0x41, 0x7a, 0x87]);
        assert_eq!(parse_script("'' DUP OP_DUP"), vec![0x00, 0x76, 0x76]);
        assert_eq!(parse_script("RESERVED VERIF NOP10"), vec![0x50, 0x65, 0xb9]);
        assert_eq!(parse_script("CHECKLOCKTIMEVERIFY"), vec![0xb1]);
        assert_eq!(
            parse_script("4294967295"),
            vec![0x05, 0xff, 0xff, 0xff, 0xff, 0x00]
        );
    }

    #[test]
    #[should_panic(expected = "unknown opcode")]
    fn parse_script_rejects_names_core_rejects() {
        let _ = parse_script("CHECKSIGADD");
    }

    #[test]
    fn parse_flags_splits_consensus_from_policy() {
        assert_eq!(parse_flags("").consensus, ScriptFlags::NONE);
        assert_eq!(parse_flags("NONE").consensus, ScriptFlags::NONE);
        let parsed = parse_flags("P2SH,STRICTENC,WITNESS,CLEANSTACK");
        assert_eq!(
            parsed.consensus,
            ScriptFlags::P2SH.union(ScriptFlags::WITNESS)
        );
        assert_eq!(parsed.policy, vec!["STRICTENC", "CLEANSTACK"]);
        assert!(parsed.has_policy("CLEANSTACK"));
        assert!(!parsed.has_policy("MINIMALIF"));
    }

    #[test]
    fn parse_script_error_knows_all_44_names() {
        assert_eq!(parse_script_error("OK"), Expected::Ok);
        assert_eq!(
            parse_script_error("EVAL_FALSE"),
            Expected::Consensus(ScriptError::EvalFalse)
        );
        assert_eq!(parse_script_error("NULLFAIL"), Expected::Policy("NULLFAIL"));
        assert_eq!(
            parse_script_error("TAPSCRIPT_EMPTY_PUBKEY"),
            Expected::Consensus(ScriptError::TapscriptEmptyPubkey)
        );
        let names = [
            "OK",
            "EVAL_FALSE",
            "OP_RETURN",
            "SCRIPT_SIZE",
            "PUSH_SIZE",
            "OP_COUNT",
            "STACK_SIZE",
            "SIG_COUNT",
            "PUBKEY_COUNT",
            "VERIFY",
            "EQUALVERIFY",
            "CHECKMULTISIGVERIFY",
            "CHECKSIGVERIFY",
            "NUMEQUALVERIFY",
            "BAD_OPCODE",
            "DISABLED_OPCODE",
            "INVALID_STACK_OPERATION",
            "INVALID_ALTSTACK_OPERATION",
            "UNBALANCED_CONDITIONAL",
            "NEGATIVE_LOCKTIME",
            "UNSATISFIED_LOCKTIME",
            "SIG_HASHTYPE",
            "SIG_DER",
            "MINIMALDATA",
            "SIG_PUSHONLY",
            "SIG_HIGH_S",
            "SIG_NULLDUMMY",
            "PUBKEYTYPE",
            "CLEANSTACK",
            "MINIMALIF",
            "NULLFAIL",
            "DISCOURAGE_UPGRADABLE_NOPS",
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            "WITNESS_PROGRAM_WRONG_LENGTH",
            "WITNESS_PROGRAM_WITNESS_EMPTY",
            "WITNESS_PROGRAM_MISMATCH",
            "WITNESS_MALLEATED",
            "WITNESS_MALLEATED_P2SH",
            "WITNESS_UNEXPECTED",
            "WITNESS_PUBKEYTYPE",
            "TAPSCRIPT_EMPTY_PUBKEY",
            "OP_CODESEPARATOR",
            "SIG_FINDANDDELETE",
            "SCRIPTNUM",
        ];
        assert_eq!(names.len(), 44);
        let mut consensus = 0;
        for name in names {
            match parse_script_error(name) {
                Expected::Ok | Expected::Policy(_) => {}
                Expected::Consensus(_) => consensus += 1,
            }
        }
        assert_eq!(consensus, 32);
    }

    #[test]
    fn amounts_read_as_satoshis() {
        assert_eq!(Json::Number(1).as_satoshis(), 100_000_000);
        assert_eq!(Json::Number(0).as_satoshis(), 0);
        assert_eq!(Json::Decimal("0.00000001".into()).as_satoshis(), 1);
        assert_eq!(Json::Decimal("1.5".into()).as_satoshis(), 150_000_000);
        let json = Json::parse("[0.00000001, 0]");
        assert_eq!(json.as_array()[0].as_satoshis(), 1);
        assert_eq!(json.as_array()[1].as_satoshis(), 0);
    }

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
