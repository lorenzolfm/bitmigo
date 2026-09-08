// SPDX-License-Identifier: MIT OR Apache-2.0

//! The digest a signature commits to: legacy, BIP143 (segwit v0) and BIP341 (taproot).
//!
//! Core computes these in `SignatureHash` and `SignatureHashSchnorr` (`script/interpreter.cpp`)
//! over a `PrecomputedTransactionData` built once per transaction. Here the precompute is
//! [`TxPrecomputed`], eager and immutable so that every input of a transaction can be verified
//! on any thread against the same `&TxPrecomputed`, and the three digests are pure functions of
//! the transaction, the input and what the script asked for. rust-bitcoin's `SighashCache` is
//! not used: it does not strip `OP_CODESEPARATOR` from a legacy `scriptCode`, it is lazy and
//! `&mut self`, and a digest this crate is judged on should read against the BIP text. It is
//! the test oracle instead, beside Core's `sighash.json` and the BIP vectors.
//!
//! Byte order: every `[u8; 32]` here is the hash function's output, the order libsecp256k1
//! consumes. Core's `uint256::GetHex` prints it reversed; the `sighash.json` test reverses.

use bitcoin::consensus::Encodable;
use bitcoin::consensus::encode::VarInt;
use bitcoin::hashes::{Hash, HashEngine, sha256, sha256d};
use bitcoin::sighash::TapSighash;
use bitcoin::{Amount, Script, Transaction, TxOut, Txid};

use super::ScriptError;
use super::opcode::OP_CODESEPARATOR;
use super::reader::{OpRead, read_op};

/// Taproot only: a 64-byte signature carries no hash type byte and means [`SIGHASH_ALL`].
pub const SIGHASH_DEFAULT: u8 = 0x00;
/// Commit to every output.
pub const SIGHASH_ALL: u8 = 0x01;
/// Commit to no output.
pub const SIGHASH_NONE: u8 = 0x02;
/// Commit to the output at the signed input's index only.
pub const SIGHASH_SINGLE: u8 = 0x03;
/// Commit to the signed input only, so that others may be added.
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
/// The first byte of a taproot annex (`script.h: ANNEX_TAG`).
pub const ANNEX_TAG: u8 = 0x50;

/// Legacy and v0 read the output mode from the low five bits (Core's `nHashType & 0x1f`), so
/// an undefined byte such as `0x21` behaves as `ALL` and is not an error (§4.7).
const LEGACY_OUTPUT_MASK: u32 = 0x1f;
/// Taproot reads it from the low two bits, after the whole byte has been range-checked.
const TAPROOT_OUTPUT_MASK: u8 = 0x03;
/// BIP341's epoch byte.
const TAPROOT_EPOCH: u8 = 0x00;
/// BIP342's `key_version`: the only value defined, for 32-byte keys.
const KEY_VERSION_0: u8 = 0x00;
/// Core's `uint256::ONE`, little-endian: what a legacy `SIGHASH_SINGLE` "hashes" to when the
/// input has no matching output. Any signature over this constant verifies (§4.7).
const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const ZERO_HASH: [u8; 32] = [0; 32];

/// Everything about a transaction that every one of its signature hashes shares: Core's
/// `PrecomputedTransactionData`, computed once, all of it, up front.
///
/// Core computes lazily what the witnesses suggest it will need; here the eight hashes cost
/// five passes over the inputs and outputs, a fraction of one signature verification, and in
/// exchange the value is immutable and `Sync`, so the node can verify a transaction's inputs
/// on as many threads as it likes against one `&TxPrecomputed`.
#[derive(Clone, Debug)]
pub struct TxPrecomputed {
    /// Which transaction the hashes were taken from, so a precompute cannot be used with
    /// another transaction by mistake.
    txid: Txid,
    input_count: usize,
    output_count: usize,
    /// BIP143, double SHA-256: Core's `hashPrevouts`, `hashSequence`, `hashOutputs`.
    hash_prevouts: [u8; 32],
    hash_sequence: [u8; 32],
    hash_outputs: [u8; 32],
    /// BIP341, single SHA-256: Core's `m_*_single_hash`.
    sha_prevouts: [u8; 32],
    sha_amounts: [u8; 32],
    sha_scriptpubkeys: [u8; 32],
    sha_sequences: [u8; 32],
    sha_outputs: [u8; 32],
}

const fn assert_sync<T: Sync>() {}
const _: () = assert_sync::<TxPrecomputed>();

impl TxPrecomputed {
    /// Hashes `tx` and the outputs it spends, one `TxOut` per input in input order.
    #[must_use]
    pub fn new(tx: &Transaction, prevouts: &[TxOut]) -> TxPrecomputed {
        assert!(!tx.input.is_empty());
        assert_eq!(prevouts.len(), tx.input.len());

        let sha_prevouts = sha256_each(tx.input.iter().map(|input| &input.previous_output));
        let sha_sequences = sha256_each(tx.input.iter().map(|input| &input.sequence));
        let sha_outputs = sha256_each(tx.output.iter());
        let sha_amounts = sha256_each(prevouts.iter().map(|prevout| &prevout.value));
        let sha_scriptpubkeys = sha256_each(prevouts.iter().map(|prevout| &prevout.script_pubkey));
        TxPrecomputed {
            txid: tx.compute_txid(),
            input_count: tx.input.len(),
            output_count: tx.output.len(),
            // BIP143's double hashes are BIP341's single hashes hashed once more, which is how
            // Core shares the first pass between the two (`SHA256Uint256`).
            hash_prevouts: sha256_once(&sha_prevouts),
            hash_sequence: sha256_once(&sha_sequences),
            hash_outputs: sha256_once(&sha_outputs),
            sha_prevouts,
            sha_amounts,
            sha_scriptpubkeys,
            sha_sequences,
            sha_outputs,
        }
    }

    /// The cheap half of "built for this transaction" always; the full check, which hashes
    /// the whole transaction again, only in debug builds, because it would cost as much as
    /// the digest it guards on every signature.
    pub(super) fn assert_built_for(&self, tx: &Transaction) {
        assert_eq!(tx.input.len(), self.input_count);
        assert_eq!(tx.output.len(), self.output_count);
        debug_assert_eq!(tx.compute_txid(), self.txid);
    }
}

/// The three legacy and v0 mode bits Core derives from `nHashType`.
#[derive(Clone, Copy, Debug)]
struct EcdsaHashMode {
    anyone_can_pay: bool,
    single: bool,
    none: bool,
}

impl EcdsaHashMode {
    fn from_hash_type(hash_type: u32) -> EcdsaHashMode {
        let output_mode = hash_type & LEGACY_OUTPUT_MASK;
        let mode = EcdsaHashMode {
            anyone_can_pay: hash_type & u32::from(SIGHASH_ANYONECANPAY) != 0,
            single: output_mode == u32::from(SIGHASH_SINGLE),
            none: output_mode == u32::from(SIGHASH_NONE),
        };
        assert!(!(mode.single && mode.none));
        mode
    }
}

/// The pre-segwit digest: Core's `SignatureHash` in its `BASE` branch, which serialises the
/// transaction through `CTransactionSignatureSerializer` with the signed input's `scriptSig`
/// replaced by `script_code`, the other inputs' blanked, and outputs and sequences dropped or
/// nulled as the mode says, then appends the hash type as four bytes (§4.7).
///
/// `hash_type` is the whole 32-bit value Core hashes. The interpreter passes the signature's
/// last byte widened; the vectors pass arbitrary integers. `FindAndDelete` is the caller's:
/// the `script_code` given here is hashed as it is, minus its `OP_CODESEPARATOR`s.
#[must_use]
pub fn legacy_sighash(
    tx: &Transaction,
    index: usize,
    script_code: &Script,
    hash_type: u32,
) -> [u8; 32] {
    assert!(index < tx.input.len());
    let mode = EcdsaHashMode::from_hash_type(hash_type);

    // The SIGHASH_SINGLE bug: with no output at the input's index, Core returns the constant
    // one instead of a hash, and every signature over it verifies. Consensus, forever.
    if mode.single && index >= tx.output.len() {
        return UINT256_ONE;
    }

    let mut engine = sha256d::Hash::engine();
    encode(&mut engine, &tx.version);

    if mode.anyone_can_pay {
        encode(&mut engine, &VarInt(1));
        legacy_encode_input(&mut engine, tx, index, index, script_code, mode);
    } else {
        encode(&mut engine, &VarInt(count_to_u64(tx.input.len())));
        // Bounded by the transaction's input count.
        for input_index in 0..tx.input.len() {
            legacy_encode_input(&mut engine, tx, index, input_index, script_code, mode);
        }
    }

    let output_count = if mode.none {
        0
    } else if mode.single {
        index + 1
    } else {
        tx.output.len()
    };
    assert!(output_count <= tx.output.len());
    encode(&mut engine, &VarInt(count_to_u64(output_count)));
    // Bounded by the transaction's output count.
    for (output_index, output) in tx.output.iter().take(output_count).enumerate() {
        if mode.single && output_index != index {
            // Other outputs are nulled, not dropped: value -1 and an empty script, so the
            // signer commits to their position but not their content.
            encode(&mut engine, &TxOut::NULL);
        } else {
            encode(&mut engine, output);
        }
    }

    encode(&mut engine, &tx.lock_time);
    encode(&mut engine, &hash_type);
    sha256d::Hash::from_engine(engine).to_byte_array()
}

/// One input of the legacy preimage: `CTransactionSignatureSerializer::SerializeInput`.
fn legacy_encode_input(
    engine: &mut sha256::HashEngine,
    tx: &Transaction,
    signed_index: usize,
    input_index: usize,
    script_code: &Script,
    mode: EcdsaHashMode,
) {
    let input = tx
        .input
        .get(input_index)
        .expect("input_index is below the input count");
    encode(engine, &input.previous_output);
    if input_index == signed_index {
        legacy_encode_script_code(engine, script_code);
    } else {
        // Every other input's scriptSig is blanked: an empty script is one zero length byte.
        encode(engine, &VarInt(0));
    }
    if input_index != signed_index && (mode.single || mode.none) {
        // Let the other inputs' sequences be changed by their owners.
        encode(engine, &0u32);
    } else {
        encode(engine, &input.sequence);
    }
}

/// `CTransactionSignatureSerializer::SerializeScriptCode`: the `scriptCode` with every
/// `OP_CODESEPARATOR` removed, which the witness v0 digest does *not* do (BIP143 keeps
/// them; `docs/consensus-rules.md` §4.7).
///
/// Two quirks are Core's and therefore consensus. The length prefix is computed from the
/// script's size minus the separator count before anything is written. And the bytes are
/// written up to where `GetScriptOp` stops, so a push that runs past the end of the script
/// loses its tail while the prefix still counts it.
fn legacy_encode_script_code(engine: &mut sha256::HashEngine, script_code: &Script) {
    let bytes = script_code.as_bytes();

    let mut separator_count: usize = 0;
    let mut position = 0;
    // Each `read_op` advances `position` by at least one byte, so the script's length bounds
    // both loops.
    while position < bytes.len() {
        match read_op(bytes, position) {
            OpRead::Op { opcode, next } => {
                assert!(next > position);
                if opcode == OP_CODESEPARATOR {
                    separator_count += 1;
                }
                position = next;
            }
            OpRead::Truncated { .. } => break,
        }
    }
    assert!(separator_count <= bytes.len());
    encode(engine, &VarInt(count_to_u64(bytes.len() - separator_count)));

    let mut segment_start = 0;
    let mut position = 0;
    while position < bytes.len() {
        match read_op(bytes, position) {
            OpRead::Op { opcode, next } => {
                assert!(next > position);
                if opcode == OP_CODESEPARATOR {
                    let segment = bytes
                        .get(segment_start..next - 1)
                        .expect("inside the script");
                    engine.input(segment);
                    segment_start = next;
                }
                position = next;
            }
            OpRead::Truncated { next } => {
                position = next;
                break;
            }
        }
    }
    if segment_start != bytes.len() {
        assert!(segment_start <= position);
        let segment = bytes
            .get(segment_start..position)
            .expect("inside the script");
        engine.input(segment);
    }
}

/// The segwit v0 digest: Core's `SignatureHash` in its `WITNESS_V0` branch, BIP143.
///
/// `script_code` is what BIP143 defines for the program (the P2WPKH template, or the witness
/// script from after the last executed `OP_CODESEPARATOR`) and is serialised as given;
/// `amount` is the value of the output being spent, which the digest commits to. `hash_type`
/// is the 32-bit value Core hashes, mode-selected like the legacy digest.
#[must_use]
pub fn segwit_v0_sighash(
    tx: &Transaction,
    index: usize,
    script_code: &Script,
    amount: Amount,
    hash_type: u32,
    precomputed: &TxPrecomputed,
) -> [u8; 32] {
    assert!(index < tx.input.len());
    precomputed.assert_built_for(tx);
    let mode = EcdsaHashMode::from_hash_type(hash_type);

    let hash_prevouts = if mode.anyone_can_pay {
        ZERO_HASH
    } else {
        precomputed.hash_prevouts
    };
    let hash_sequence = if mode.anyone_can_pay || mode.single || mode.none {
        ZERO_HASH
    } else {
        precomputed.hash_sequence
    };
    let hash_outputs = if mode.single {
        // BIP143 commits to zero where legacy has the "hash one" bug; the semantics match.
        match tx.output.get(index) {
            Some(output) => sha256d_each(core::iter::once(output)),
            None => ZERO_HASH,
        }
    } else if mode.none {
        ZERO_HASH
    } else {
        precomputed.hash_outputs
    };

    let input = tx.input.get(index).expect("index is below the input count");
    let mut engine = sha256d::Hash::engine();
    encode(&mut engine, &tx.version);
    engine.input(&hash_prevouts);
    engine.input(&hash_sequence);
    encode(&mut engine, &input.previous_output);
    encode(&mut engine, script_code);
    encode(&mut engine, &amount);
    encode(&mut engine, &input.sequence);
    engine.input(&hash_outputs);
    encode(&mut engine, &tx.lock_time);
    encode(&mut engine, &hash_type);
    sha256d::Hash::from_engine(engine).to_byte_array()
}

/// Which taproot spend a Schnorr signature belongs to: BIP341's `ext_flag`, carrying the
/// BIP342 fields when the flag is 1. A tapscript signature without a leaf hash cannot be
/// written down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaprootSpend {
    /// A signature over the output key itself: Core's `SigVersion::TAPROOT`.
    KeyPath,
    /// A signature checked inside a BIP342 leaf: Core's `SigVersion::TAPSCRIPT`.
    Tapscript {
        /// The tagged hash of the leaf being executed (`ExecData`'s `m_tapleaf_hash`).
        leaf_hash: [u8; 32],
        /// Opcode position of the last executed `OP_CODESEPARATOR`, `0xffff_ffff` if none.
        codesep_pos: u32,
    },
}

/// The taproot digest: Core's `SignatureHashSchnorr`, BIP341 with the BIP342 extension.
///
/// `hash_type` is the signature's trailing byte, or [`SIGHASH_DEFAULT`] for a 64-byte
/// signature. `annex` is the annex as removed from the witness, `0x50` prefix included.
///
/// # Errors
///
/// [`ScriptError::SchnorrSigHashtype`] when `hash_type` is outside the seven defined values,
/// or asks for `SINGLE` at an input with no output at its index: taproot has no "hash one"
/// fallback, it fails.
pub fn taproot_sighash(
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    hash_type: u8,
    spend: TaprootSpend,
    annex: Option<&[u8]>,
    precomputed: &TxPrecomputed,
) -> Result<[u8; 32], ScriptError> {
    assert!(index < tx.input.len());
    assert_eq!(prevouts.len(), tx.input.len());
    precomputed.assert_built_for(tx);
    if let Some(annex) = annex {
        assert_eq!(annex.first(), Some(&ANNEX_TAG));
    }

    let defined = hash_type <= SIGHASH_SINGLE || (0x81..=0x83).contains(&hash_type);
    if !defined {
        return Err(ScriptError::SchnorrSigHashtype);
    }
    let output_type = if hash_type == SIGHASH_DEFAULT {
        SIGHASH_ALL
    } else {
        hash_type & TAPROOT_OUTPUT_MASK
    };
    let anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY != 0;
    // Core discovers this half-way through serialising; failing first changes nothing.
    if output_type == SIGHASH_SINGLE && index >= tx.output.len() {
        return Err(ScriptError::SchnorrSigHashtype);
    }

    let mut engine = TapSighash::engine();
    engine.input(&[TAPROOT_EPOCH, hash_type]);
    encode(&mut engine, &tx.version);
    encode(&mut engine, &tx.lock_time);
    if !anyone_can_pay {
        engine.input(&precomputed.sha_prevouts);
        engine.input(&precomputed.sha_amounts);
        engine.input(&precomputed.sha_scriptpubkeys);
        engine.input(&precomputed.sha_sequences);
    }
    if output_type == SIGHASH_ALL {
        engine.input(&precomputed.sha_outputs);
    }

    taproot_encode_input(
        &mut engine,
        tx,
        index,
        prevouts,
        anyone_can_pay,
        spend,
        annex,
    );

    if output_type == SIGHASH_SINGLE {
        let output = tx
            .output
            .get(index)
            .expect("checked against the output count above");
        engine.input(&sha256_each(core::iter::once(output)));
    }
    if let TaprootSpend::Tapscript {
        leaf_hash,
        codesep_pos,
    } = spend
    {
        engine.input(&leaf_hash);
        engine.input(&[KEY_VERSION_0]);
        encode(&mut engine, &codesep_pos);
    }
    Ok(TapSighash::from_engine(engine).to_byte_array())
}

/// The "data about this input" section of BIP341: `spend_type`, then either the input in
/// full (`ANYONECANPAY`) or its index, then the annex hash if there is one.
fn taproot_encode_input(
    engine: &mut sha256::HashEngine,
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    anyone_can_pay: bool,
    spend: TaprootSpend,
    annex: Option<&[u8]>,
) {
    let ext_flag: u8 = match spend {
        TaprootSpend::KeyPath => 0,
        TaprootSpend::Tapscript { .. } => 1,
    };
    let spend_type = (ext_flag << 1) | u8::from(annex.is_some());
    assert!(spend_type <= 3);
    engine.input(&[spend_type]);

    if anyone_can_pay {
        let input = tx.input.get(index).expect("index is below the input count");
        let prevout = prevouts.get(index).expect("one prevout per input");
        encode(engine, &input.previous_output);
        encode(engine, prevout);
        encode(engine, &input.sequence);
    } else {
        encode(
            engine,
            &u32::try_from(index).expect("an input index fits u32"),
        );
    }

    if let Some(annex) = annex {
        let mut annex_engine = sha256::Hash::engine();
        encode(&mut annex_engine, &VarInt(count_to_u64(annex.len())));
        annex_engine.input(annex);
        engine.input(&sha256::Hash::from_engine(annex_engine).to_byte_array());
    }
}

/// Consensus-serialises `value` into a hash engine. An engine accepts every write, so the
/// `io::Result` is an invariant, not an error.
pub(super) fn encode<E: Encodable + ?Sized>(engine: &mut sha256::HashEngine, value: &E) {
    let written = value
        .consensus_encode(engine)
        .expect("a hash engine accepts every write");
    assert!(written > 0);
}

/// Single SHA-256 over the concatenated consensus serialisation of `items`.
fn sha256_each<'a, E, I>(items: I) -> [u8; 32]
where
    E: Encodable + 'a,
    I: Iterator<Item = &'a E>,
{
    let mut engine = sha256::Hash::engine();
    // Bounded by the transaction's input or output count.
    for item in items {
        encode(&mut engine, item);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Double SHA-256 over the concatenated consensus serialisation of `items`.
fn sha256d_each<'a, E, I>(items: I) -> [u8; 32]
where
    E: Encodable + 'a,
    I: Iterator<Item = &'a E>,
{
    sha256_once(&sha256_each(items))
}

fn sha256_once(bytes: &[u8; 32]) -> [u8; 32] {
    sha256::Hash::hash(bytes).to_byte_array()
}

pub(super) fn count_to_u64(count: usize) -> u64 {
    u64::try_from(count).expect("a count of transaction parts fits u64")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "a test that indexes out of bounds fails with a panic, which is what a failing \
                  test does anyway"
    )]

    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::{Hash, sha256d};
    use bitcoin::hex::{DisplayHex, FromHex};
    use bitcoin::sighash::{
        Annex, EcdsaSighashType, Prevouts, SighashCache, TapSighash, TapSighashType,
    };
    use bitcoin::taproot::TapLeafHash;
    use bitcoin::{
        Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    use super::super::vectors::{
        BIP341_WALLET_TEST_VECTORS_JSON, CORE_SIGHASH_JSON, Json, Prng, random_prevouts,
        random_script_code, random_transaction,
    };
    use super::{
        ANNEX_TAG, ScriptError, TaprootSpend, TxPrecomputed, UINT256_ONE, legacy_sighash,
        segwit_v0_sighash, taproot_sighash,
    };

    fn hex(text: &str) -> Vec<u8> {
        Vec::<u8>::from_hex(text).expect("valid hex")
    }

    fn hex_32(text: &str) -> [u8; 32] {
        <[u8; 32]>::from_hex(text).expect("32 bytes of hex")
    }

    fn tx(text: &str) -> Transaction {
        deserialize(&hex(text)).expect("a transaction")
    }

    /// A script serialised with its length prefix, as BIP143 prints `scriptCode`.
    fn prefixed_script(text: &str) -> ScriptBuf {
        deserialize(&hex(text)).expect("a length-prefixed script")
    }

    fn legacy_oracle(tx: &Transaction, index: usize, code: &Script, hash_type: u32) -> [u8; 32] {
        SighashCache::new(tx)
            .legacy_signature_hash(index, code, hash_type)
            .expect("index in range")
            .to_byte_array()
    }

    /// rust-bitcoin serialises the *normalised* hash type; Core serialises the raw 32-bit
    /// value. Everything before those four bytes agrees, because rust-bitcoin's masking
    /// (`& 0x9f`) selects the same mode Core's `& 0x1f` and `& 0x80` do.
    fn segwit_v0_oracle(
        tx: &Transaction,
        index: usize,
        code: &Script,
        amount: Amount,
        hash_type: u32,
    ) -> [u8; 32] {
        let mut preimage = Vec::new();
        SighashCache::new(tx)
            .segwit_v0_encode_signing_data_to(
                &mut preimage,
                index,
                code,
                amount,
                EcdsaSighashType::from_consensus(hash_type),
            )
            .expect("index in range");
        let type_position = preimage.len() - 4;
        preimage.truncate(type_position);
        preimage.extend_from_slice(&hash_type.to_le_bytes());
        sha256d::Hash::hash(&preimage).to_byte_array()
    }

    fn taproot_oracle(
        tx: &Transaction,
        index: usize,
        prevouts: &[TxOut],
        hash_type: u8,
        spend: TaprootSpend,
        annex: Option<&[u8]>,
    ) -> Option<[u8; 32]> {
        let leaf = match spend {
            TaprootSpend::KeyPath => None,
            TaprootSpend::Tapscript {
                leaf_hash,
                codesep_pos,
            } => Some((TapLeafHash::from_byte_array(leaf_hash), codesep_pos)),
        };
        let annex = annex.map(|bytes| Annex::new(bytes).expect("starts with 0x50"));
        let sighash_type = TapSighashType::from_consensus_u8(hash_type).expect("defined");
        SighashCache::new(tx)
            .taproot_signature_hash(index, &Prevouts::All(prevouts), annex, leaf, sighash_type)
            .ok()
            .map(TapSighash::to_byte_array)
    }

    /// Core's `sighash_tests.cpp: sighash_from_data`: 500 random transactions and scripts,
    /// arbitrary 32-bit hash types (negative included), the expected digest printed as
    /// `uint256::GetHex`, which is byte-reversed. Almost half the scripts contain
    /// `OP_CODESEPARATOR`, and the `SIGHASH_SINGLE` bug fires whenever the index is past the
    /// outputs, so this one file covers every legacy branch.
    #[test]
    fn legacy_matches_core_sighash_json() {
        let rows = Json::parse(CORE_SIGHASH_JSON);
        let mut checked = 0;
        for row in rows.as_array() {
            let row = row.as_array();
            if row.len() == 1 {
                continue; // The header comment.
            }
            assert_eq!(row.len(), 5);
            let tx = tx(row[0].as_str());
            let script_code = ScriptBuf::from_bytes(row[1].as_bytes());
            let index = usize::try_from(row[2].as_i64()).expect("a non-negative index");
            let hash_type = i32::try_from(row[3].as_i64()).expect("an int32");
            let hash_type = u32::from_le_bytes(hash_type.to_le_bytes());
            let mut expected = hex_32(row[4].as_str());
            expected.reverse();

            let digest = legacy_sighash(&tx, index, &script_code, hash_type);
            assert_eq!(digest, expected, "row {checked}: {}", row[1].as_str());
            checked += 1;
        }
        assert_eq!(checked, 500);
    }

    #[test]
    fn legacy_matches_rust_bitcoin_on_generated_transactions() {
        let mut prng = Prng::new(0x1e9a_c100);
        for _ in 0..200 {
            let tx = random_transaction(&mut prng);
            let script_code = random_script_code(&mut prng);
            for index in 0..tx.input.len() {
                for hash_type in [0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00, prng.next_u32()] {
                    let ours = legacy_sighash(&tx, index, &script_code, hash_type);
                    let oracle = legacy_oracle(&tx, index, &script_code, hash_type);
                    assert_eq!(ours, oracle, "index {index} type {hash_type:#x}");
                }
            }
        }
    }

    fn one_input_no_output() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        }
    }

    #[test]
    fn legacy_single_without_an_output_hashes_to_one() {
        let tx = one_input_no_output();
        let code = ScriptBuf::from_bytes(vec![0xac]);
        assert_eq!(legacy_sighash(&tx, 0, &code, 0x03), UINT256_ONE);
        assert_eq!(legacy_sighash(&tx, 0, &code, 0x83), UINT256_ONE);
        // Any byte whose low five bits are 3 is SINGLE.
        assert_eq!(legacy_sighash(&tx, 0, &code, 0x23), UINT256_ONE);
        assert_eq!(legacy_sighash(&tx, 0, &code, 0xffff_ff03), UINT256_ONE);
        // NONE and ALL are unaffected.
        assert_ne!(legacy_sighash(&tx, 0, &code, 0x01), UINT256_ONE);
        assert_ne!(legacy_sighash(&tx, 0, &code, 0x02), UINT256_ONE);
    }

    /// Stripping is invisible to rust-bitcoin, so the oracle is fed the script with its
    /// separators already removed and must agree with ours fed the original.
    #[test]
    fn legacy_strips_every_codeseparator() {
        let mut prng = Prng::new(0xc0de);
        let tx = random_transaction(&mut prng);
        let with = hex(
            "76ab a9 14 abababababababababababababababababababab ab 88 ac ab"
                .replace(' ', "")
                .as_str(),
        );
        let without = hex("76a91 4abababababababababababababababababababab88ac"
            .replace(' ', "")
            .as_str());
        let ours = legacy_sighash(&tx, 0, &ScriptBuf::from_bytes(with), 0x01);
        let oracle = legacy_oracle(&tx, 0, &ScriptBuf::from_bytes(without), 0x01);
        assert_eq!(ours, oracle);
    }

    /// Core writes the bytes up to where `GetScriptOp` stops, so `02 aa` (a two-byte push
    /// with one byte of data) is serialised as `02 02`: a length of two, one byte. The
    /// preimage is built by hand here because no oracle reproduces it.
    #[test]
    fn legacy_drops_the_tail_of_a_truncated_push_as_core_does() {
        let mut tx = one_input_no_output();
        tx.output.push(TxOut {
            value: Amount::from_sat(7),
            script_pubkey: ScriptBuf::new(),
        });
        let code = ScriptBuf::from_bytes(vec![0x02, 0xaa]);

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&1i32.to_le_bytes()); // version
        preimage.push(1); // one input
        preimage.extend_from_slice(&[0; 32]); // null outpoint hash
        preimage.extend_from_slice(&u32::MAX.to_le_bytes()); // null outpoint index
        preimage.extend_from_slice(&[0x02, 0x02]); // scriptCode: claimed length 2, one byte
        preimage.extend_from_slice(&u32::MAX.to_le_bytes()); // sequence
        preimage.push(1); // one output
        preimage.extend_from_slice(&7u64.to_le_bytes());
        preimage.push(0); // empty script
        preimage.extend_from_slice(&0u32.to_le_bytes()); // lock time
        preimage.extend_from_slice(&1u32.to_le_bytes()); // hash type
        let expected = sha256d::Hash::hash(&preimage).to_byte_array();

        assert_eq!(legacy_sighash(&tx, 0, &code, 0x01), expected);
        assert_ne!(legacy_oracle(&tx, 0, &code, 0x01), expected);
    }

    const P2WPKH: &str = concat!(
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000",
        "0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100",
        "000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d59",
        "88ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000",
    );
    const P2SH_P2WPKH: &str = concat!(
        "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000",
        "0000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388",
        "ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000",
    );
    const P2WSH: &str = concat!(
        "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000",
        "0000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000",
        "000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f7",
        "88ac00000000",
    );
    const NO_FIND_AND_DELETE: &str = concat!(
        "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc001000000",
        "0000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000",
        "000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b28",
        "88ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000",
    );
    const P2SH_P2WSH: &str = concat!(
        "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e010000",
        "0000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688",
        "acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000",
    );
    const MULTISIG_6_OF_6: &str = concat!(
        "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f",
        "0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57",
        "761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1e",
        "d1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9",
        "602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c196",
        "17681024306b56ae",
    );

    // (transaction, input, prefixed scriptCode, amount in sats, hash type, sigHash)
    const BIP143_EXAMPLES: [(&str, usize, &str, u64, u32, &str); 12] = [
        (
            P2WPKH,
            1,
            "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac",
            600_000_000,
            0x01,
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
        ),
        (
            P2SH_P2WPKH,
            0,
            "1976a91479091972186c449eb1ded22b78e40d009bdf008988ac",
            1_000_000_000,
            0x01,
            "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
        ),
        (
            P2WSH,
            1,
            concat!(
                "4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255",
                "a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac",
            ),
            4_900_000_000,
            0x03,
            "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391",
        ),
        (
            P2WSH,
            1,
            "23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac",
            4_900_000_000,
            0x03,
            "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47",
        ),
        (
            NO_FIND_AND_DELETE,
            0,
            "270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac",
            16_777_215,
            0x83,
            "e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a",
        ),
        (
            NO_FIND_AND_DELETE,
            1,
            "2468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac",
            16_777_215,
            0x83,
            "cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54",
        ),
        (
            P2SH_P2WSH,
            0,
            MULTISIG_6_OF_6,
            987_654_321,
            0x01,
            "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c",
        ),
        (
            P2SH_P2WSH,
            0,
            MULTISIG_6_OF_6,
            987_654_321,
            0x02,
            "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36",
        ),
        (
            P2SH_P2WSH,
            0,
            MULTISIG_6_OF_6,
            987_654_321,
            0x03,
            "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea",
        ),
        (
            P2SH_P2WSH,
            0,
            MULTISIG_6_OF_6,
            987_654_321,
            0x81,
            "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e",
        ),
        (
            P2SH_P2WSH,
            0,
            MULTISIG_6_OF_6,
            987_654_321,
            0x82,
            "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a",
        ),
        (
            P2SH_P2WSH,
            0,
            MULTISIG_6_OF_6,
            987_654_321,
            0x83,
            "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b",
        ),
    ];

    /// The five worked examples of BIP143, twelve digests: P2WPKH, P2SH-P2WPKH, P2WSH with
    /// an executed `OP_CODESEPARATOR` and `SINGLE` past the outputs, P2WSH with an unexecuted
    /// separator under `SINGLE|ANYONECANPAY`, and P2SH-P2WSH under all six hash types. The
    /// BIP prints `scriptCode` with its length prefix and hashes in natural byte order.
    #[test]
    fn segwit_v0_matches_bip143_examples() {
        for (tx_hex, index, code, amount, hash_type, expected) in BIP143_EXAMPLES {
            let tx = tx(tx_hex);
            // BIP143 has no spent outputs for the other inputs; the precompute does not
            // read them for v0, so any of the right count serve.
            let prevouts = vec![
                TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: ScriptBuf::new()
                };
                tx.input.len()
            ];
            let precomputed = TxPrecomputed::new(&tx, &prevouts);
            let digest = segwit_v0_sighash(
                &tx,
                index,
                &prefixed_script(code),
                Amount::from_sat(amount),
                hash_type,
                &precomputed,
            );
            assert_eq!(
                digest.to_lower_hex_string(),
                expected,
                "type {hash_type:#04x} index {index}"
            );
        }
    }

    #[test]
    fn segwit_v0_matches_rust_bitcoin_on_generated_transactions() {
        let mut prng = Prng::new(0x5e60);
        for _ in 0..200 {
            let tx = random_transaction(&mut prng);
            let prevouts = random_prevouts(&mut prng, tx.input.len());
            let precomputed = TxPrecomputed::new(&tx, &prevouts);
            let script_code = random_script_code(&mut prng);
            for (index, prevout) in prevouts.iter().enumerate() {
                let amount = prevout.value;
                for hash_type in [0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00, prng.next_u32()] {
                    let ours = segwit_v0_sighash(
                        &tx,
                        index,
                        &script_code,
                        amount,
                        hash_type,
                        &precomputed,
                    );
                    let oracle = segwit_v0_oracle(&tx, index, &script_code, amount, hash_type);
                    assert_eq!(ours, oracle, "index {index} type {hash_type:#x}");
                }
            }
        }
    }

    /// BIP341's `keyPathSpending` vector states the five single-SHA intermediates and the
    /// digest for seven inputs across all seven hash types, in natural byte order.
    #[test]
    fn taproot_matches_bip341_key_path_vectors() {
        let json = Json::parse(BIP341_WALLET_TEST_VECTORS_JSON);
        let case = &json.get("keyPathSpending").as_array()[0];
        let tx: Transaction =
            deserialize(&case.get("given").get("rawUnsignedTx").as_bytes()).expect("tx");
        let prevouts: Vec<TxOut> = case
            .get("given")
            .get("utxosSpent")
            .as_array()
            .iter()
            .map(|utxo| TxOut {
                value: Amount::from_sat(
                    u64::try_from(utxo.get("amountSats").as_i64()).expect("positive"),
                ),
                script_pubkey: ScriptBuf::from_bytes(utxo.get("scriptPubKey").as_bytes()),
            })
            .collect();
        assert_eq!(tx.input.len(), 9);
        let precomputed = TxPrecomputed::new(&tx, &prevouts);

        let intermediary = case.get("intermediary");
        let stated = |name: &str| hex_32(intermediary.get(name).as_str());
        assert_eq!(precomputed.sha_prevouts, stated("hashPrevouts"));
        assert_eq!(precomputed.sha_amounts, stated("hashAmounts"));
        assert_eq!(precomputed.sha_scriptpubkeys, stated("hashScriptPubkeys"));
        assert_eq!(precomputed.sha_sequences, stated("hashSequences"));
        assert_eq!(precomputed.sha_outputs, stated("hashOutputs"));

        let spends = case.get("inputSpending").as_array();
        assert_eq!(spends.len(), 7);
        for spend in spends {
            let index =
                usize::try_from(spend.get("given").get("txinIndex").as_i64()).expect("index");
            let hash_type =
                u8::try_from(spend.get("given").get("hashType").as_i64()).expect("a byte");
            let expected = hex_32(spend.get("intermediary").get("sigHash").as_str());
            let digest = taproot_sighash(
                &tx,
                index,
                &prevouts,
                hash_type,
                TaprootSpend::KeyPath,
                None,
                &precomputed,
            );
            assert_eq!(digest, Ok(expected), "input {index} type {hash_type:#04x}");
        }
    }

    #[test]
    fn taproot_matches_rust_bitcoin_on_generated_transactions() {
        let mut prng = Prng::new(0x7a9);
        for _ in 0..100 {
            let tx = random_transaction(&mut prng);
            let prevouts = random_prevouts(&mut prng, tx.input.len());
            let precomputed = TxPrecomputed::new(&tx, &prevouts);
            let annex_len = prng.below_usize(20) + 1;
            let mut annex = prng.bytes(annex_len);
            annex[0] = ANNEX_TAG;
            let tapscript = TaprootSpend::Tapscript {
                leaf_hash: prng.bytes_32(),
                codesep_pos: prng.next_u32(),
            };
            for index in 0..tx.input.len() {
                for hash_type in [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83] {
                    for spend in [TaprootSpend::KeyPath, tapscript] {
                        for annex in [None, Some(annex.as_slice())] {
                            let ours = taproot_sighash(
                                &tx,
                                index,
                                &prevouts,
                                hash_type,
                                spend,
                                annex,
                                &precomputed,
                            );
                            let oracle =
                                taproot_oracle(&tx, index, &prevouts, hash_type, spend, annex);
                            assert_eq!(
                                ours.ok(),
                                oracle,
                                "index {index} type {hash_type:#04x} {spend:?}"
                            );
                            // Both refuse SINGLE past the outputs, and only that.
                            let single_past_outputs =
                                hash_type & 0x03 == 0x03 && index >= tx.output.len();
                            assert_eq!(ours.is_err(), single_past_outputs);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn taproot_rejects_undefined_hash_types() {
        let mut prng = Prng::new(0xbad);
        let tx = random_transaction(&mut prng);
        let prevouts = random_prevouts(&mut prng, tx.input.len());
        let precomputed = TxPrecomputed::new(&tx, &prevouts);
        for hash_type in [0x04, 0x05, 0x10, 0x20, 0x7f, 0x80, 0x84, 0x90, 0xc1, 0xff] {
            let digest = taproot_sighash(
                &tx,
                0,
                &prevouts,
                hash_type,
                TaprootSpend::KeyPath,
                None,
                &precomputed,
            );
            assert_eq!(
                digest,
                Err(ScriptError::SchnorrSigHashtype),
                "type {hash_type:#04x}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn precompute_rejects_another_transaction() {
        let mut prng = Prng::new(0x1);
        let tx = random_transaction(&mut prng);
        let precomputed = TxPrecomputed::new(&tx, &random_prevouts(&mut prng, tx.input.len()));
        let mut other = tx.clone();
        other.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        });
        let _digest = segwit_v0_sighash(&other, 0, Script::new(), Amount::ZERO, 1, &precomputed);
    }
}
