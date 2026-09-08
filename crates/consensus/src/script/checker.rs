// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`TxSigChecker`]: the four questions a script asks about the transaction spending it.
//!
//! Core's `GenericTransactionSignatureChecker` answers them from a transaction, an input
//! index, the spent output's amount and a `PrecomputedTransactionData`. This one holds the
//! same, with every spent output instead of one amount because taproot commits to all of them,
//! and is a plain struct rather than a trait: the vectors and the differential fuzzer build the
//! crediting/spending transaction pair the way Core's `DoTest` does, so one concrete checker
//! serves them and the node alike (BM-D2 decision 3). The fields are private so that a
//! signature cache could be added inside if a mempool ever wanted one.

use std::sync::LazyLock;

use bitcoin::{Script, Transaction, TxOut};
use secp256k1::ecdsa::Signature as EcdsaSignature;
use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::{Message, PublicKey, Secp256k1, VerifyOnly, XOnlyPublicKey};

use super::sighash::{self, SIGHASH_DEFAULT, TaprootSpend, TxPrecomputed};
use super::{ScriptError, SigVersion};

/// libsecp256k1 verifies against a context. Core uses `secp256k1_context_static`; the Rust
/// binding exposes no static verifying context, so one is built on first use and shared by
/// every thread for the life of the process. This is the crate's one lazy allocation.
static SECP256K1: LazyLock<Secp256k1<VerifyOnly>> = LazyLock::new(Secp256k1::verification_only);

/// Lock times at or above this are Unix timestamps, below it block heights (BIP65).
pub const LOCKTIME_THRESHOLD: i64 = 500_000_000;
/// `CTxIn::SEQUENCE_FINAL`: an input that opts out of lock-time enforcement.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;
/// `CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG`: bit 31 set means no relative lock (BIP68).
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: i64 = 1 << 31;
/// `CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG`: bit 22 set means the lock is in 512-second units.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: i64 = 1 << 22;
/// `CTxIn::SEQUENCE_LOCKTIME_MASK`: the sixteen bits that carry the lock value.
pub const SEQUENCE_LOCKTIME_MASK: i64 = 0x0000_ffff;
/// The largest magnitude a five-byte `CScriptNum` holds: the operands of `CHECKLOCKTIMEVERIFY`
/// and `CHECKSEQUENCEVERIFY` are read with `nMaxNumSize = 5`.
const SCRIPTNUM_LOCKTIME_MAX: i64 = (1 << 39) - 1;
/// A Schnorr signature is 64 bytes, or 65 with a trailing hash type (BIP341).
const SCHNORR_SIGNATURE_LEN: usize = 64;

/// One transaction input's view of its transaction, for the interpreter to ask about.
#[derive(Clone, Copy, Debug)]
pub struct TxSigChecker<'a> {
    tx: &'a Transaction,
    index: usize,
    prevouts: &'a [TxOut],
    precomputed: &'a TxPrecomputed,
}

impl<'a> TxSigChecker<'a> {
    /// A checker for input `index` of `tx`, which spends `prevouts[index]`; `precomputed` must
    /// have been built from the same `tx` and `prevouts`.
    #[must_use]
    pub fn new(
        tx: &'a Transaction,
        index: usize,
        prevouts: &'a [TxOut],
        precomputed: &'a TxPrecomputed,
    ) -> TxSigChecker<'a> {
        assert!(index < tx.input.len());
        assert_eq!(prevouts.len(), tx.input.len());
        precomputed.assert_built_for(tx);
        TxSigChecker {
            tx,
            index,
            prevouts,
            precomputed,
        }
    }

    /// Core's `CheckECDSASignature`: does `signature` (DER plus a trailing hash type byte)
    /// by `pubkey` sign this input under `script_code`?
    ///
    /// Only a verdict comes back, as in Core. Encoding rules (`DERSIG`, `STRICTENC`) are the
    /// interpreter's to enforce before asking; this function parses what history accepted:
    /// lax DER, high S normalised, hybrid and uncompressed keys. An unparsable key or
    /// signature is a `false`, not a script error, exactly as `CPubKey::Verify` fails.
    #[must_use]
    pub fn check_ecdsa(
        &self,
        signature: &[u8],
        pubkey: &[u8],
        script_code: &Script,
        sig_version: SigVersion,
    ) -> bool {
        // Empty signatures fail encoding-free, which is how CHECKMULTISIG skips a key.
        let Some((&hash_type, signature_body)) = signature.split_last() else {
            return false;
        };
        let Ok(pubkey) = PublicKey::from_slice(pubkey) else {
            return false;
        };
        let digest = match sig_version {
            SigVersion::Base => {
                sighash::legacy_sighash(self.tx, self.index, script_code, u32::from(hash_type))
            }
            SigVersion::WitnessV0 => {
                let amount = self
                    .prevouts
                    .get(self.index)
                    .expect("asserted in `new`")
                    .value;
                sighash::segwit_v0_sighash(
                    self.tx,
                    self.index,
                    script_code,
                    amount,
                    u32::from(hash_type),
                    self.precomputed,
                )
            }
            SigVersion::Tapscript => unreachable!("tapscript signatures are Schnorr"),
        };
        ecdsa_verify(signature_body, &pubkey, &digest)
    }

    /// Core's `CheckSchnorrSignature`: does `signature` (64 bytes, or 65 with a hash type)
    /// by the x-only `pubkey` sign this input for the given spend?
    ///
    /// # Errors
    ///
    /// [`ScriptError::SchnorrSigSize`] for any other length, [`ScriptError::SchnorrSigHashtype`]
    /// for a 65th byte of `0x00` or a hash type the digest rejects, [`ScriptError::SchnorrSig`]
    /// when the well-formed signature does not verify. Tapscript treats an empty signature as
    /// a plain `false` before ever asking; every other caller sees `SchnorrSigSize`.
    pub fn check_schnorr(
        &self,
        signature: &[u8],
        pubkey: &[u8; 32],
        spend: TaprootSpend,
        annex: Option<&[u8]>,
    ) -> Result<(), ScriptError> {
        let hash_type = match signature.len() {
            SCHNORR_SIGNATURE_LEN => SIGHASH_DEFAULT,
            len if len == SCHNORR_SIGNATURE_LEN + 1 => {
                let Some((&hash_type, _)) = signature.split_last() else {
                    return Err(ScriptError::SchnorrSigSize);
                };
                // The default is spelled by absence; writing it out is a distinct encoding of
                // the same digest, which BIP341 forbids.
                if hash_type == SIGHASH_DEFAULT {
                    return Err(ScriptError::SchnorrSigHashtype);
                }
                hash_type
            }
            _ => return Err(ScriptError::SchnorrSigSize),
        };
        let Some(signature_body) = signature.first_chunk::<SCHNORR_SIGNATURE_LEN>() else {
            return Err(ScriptError::SchnorrSigSize);
        };
        let digest = sighash::taproot_sighash(
            self.tx,
            self.index,
            self.prevouts,
            hash_type,
            spend,
            annex,
            self.precomputed,
        )?;
        if schnorr_verify(signature_body, pubkey, &digest) {
            Ok(())
        } else {
            Err(ScriptError::SchnorrSig)
        }
    }

    /// Core's `CheckLockTime` (BIP65): is the transaction's `nLockTime` of the same kind as
    /// `lock_time` and at least it, with this input not final? The operand is a five-byte
    /// script number the interpreter has already rejected if negative.
    #[must_use]
    pub fn check_locktime(&self, lock_time: i64) -> bool {
        assert!(lock_time >= 0);
        assert!(lock_time <= SCRIPTNUM_LOCKTIME_MAX);
        let tx_lock_time = i64::from(self.tx.lock_time.to_consensus_u32());

        // Heights and timestamps do not compare; fail unless both are the same kind.
        let same_kind = (tx_lock_time < LOCKTIME_THRESHOLD) == (lock_time < LOCKTIME_THRESHOLD);
        if !same_kind {
            return false;
        }
        if lock_time > tx_lock_time {
            return false;
        }
        // A final input would let the transaction into a block before nLockTime, making the
        // opcode moot; the input being checked is enough to prove it is not.
        let sequence = self
            .tx
            .input
            .get(self.index)
            .expect("asserted in `new`")
            .sequence;
        if sequence.to_consensus_u32() == SEQUENCE_FINAL {
            return false;
        }
        true
    }

    /// Core's `CheckSequence` (BIP112): does this input's `nSequence` encode a relative lock of
    /// the same kind as `sequence` and at least it? The operand is a five-byte script number
    /// the interpreter has already rejected if negative.
    #[must_use]
    pub fn check_sequence(&self, sequence: i64) -> bool {
        assert!(sequence >= 0);
        assert!(sequence <= SCRIPTNUM_LOCKTIME_MAX);
        let input = self.tx.input.get(self.index).expect("asserted in `new`");
        let tx_sequence = i64::from(input.sequence.to_consensus_u32());

        // Relative locks exist from version 2 (BIP68); the field is signed, so negative
        // versions fail here too.
        if self.tx.version.0 < 2 {
            return false;
        }
        // The disable bit on the transaction's own field switches the check off, so an input
        // carrying it can never satisfy CHECKSEQUENCEVERIFY.
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return false;
        }

        let mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
        let tx_sequence_masked = tx_sequence & mask;
        let sequence_masked = sequence & mask;
        let same_kind = (tx_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
            == (sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG);
        if !same_kind {
            return false;
        }
        if sequence_masked > tx_sequence_masked {
            return false;
        }
        true
    }
}

/// `CPubKey::Verify`: parse the signature as lax DER, normalise a high S, verify.
fn ecdsa_verify(signature: &[u8], pubkey: &PublicKey, digest: &[u8; 32]) -> bool {
    let Ok(mut signature) = EcdsaSignature::from_der_lax(signature) else {
        return false;
    };
    // libsecp256k1 rejects high-S signatures; Bitcoin never has (LOW_S is policy, §4.7).
    signature.normalize_s();
    SECP256K1
        .verify_ecdsa(&Message::from_digest(*digest), &signature, pubkey)
        .is_ok()
}

/// `XOnlyPubKey::VerifySchnorr`: BIP340 verification of a 32-byte message. A key whose x is
/// not on the curve parses as invalid and the check is `false`, as in Core.
pub(super) fn schnorr_verify(signature: &[u8; 64], pubkey: &[u8; 32], digest: &[u8; 32]) -> bool {
    let Ok(pubkey) = XOnlyPublicKey::from_slice(pubkey) else {
        return false;
    };
    let signature = SchnorrSignature::from_slice(signature).expect("64 bytes always parses");
    SECP256K1
        .verify_schnorr(&signature, &Message::from_digest(*digest), &pubkey)
        .is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "a test that indexes out of bounds fails with a panic, which is what a failing \
                  test does anyway"
    )]

    use bitcoin::consensus::deserialize;
    use bitcoin::hex::FromHex;
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxOut};
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    use super::super::vectors::{
        BIP340_TEST_VECTORS_CSV, BIP341_WALLET_TEST_VECTORS_JSON, Json, Prng, csv_rows,
        random_prevouts, random_transaction,
    };
    use super::{TxSigChecker, schnorr_verify};
    use crate::script::sighash::{ANNEX_TAG, SIGHASH_ALL, TxPrecomputed, legacy_sighash};
    use crate::script::{ScriptError, SigVersion, TaprootSpend};

    fn hex(text: &str) -> Vec<u8> {
        Vec::<u8>::from_hex(text).expect("valid hex")
    }

    fn hex_32(text: &str) -> [u8; 32] {
        <[u8; 32]>::from_hex(text).expect("32 bytes of hex")
    }

    /// The BIP340 vectors with a 32-byte message are consensus: rows 0-14. Rows 15-18 sign
    /// messages of other lengths, which Bitcoin never does, and are skipped.
    #[test]
    fn schnorr_verify_matches_bip340_vectors() {
        let rows = csv_rows(BIP340_TEST_VECTORS_CSV);
        assert_eq!(rows.len(), 19);
        let mut checked = 0;
        for row in &rows {
            let (pubkey, message, signature, expected) = (row[2], row[4], row[5], row[6]);
            if message.len() != 64 {
                continue;
            }
            let signature: [u8; 64] = hex(signature).try_into().expect("64-byte signature");
            let verified = schnorr_verify(&signature, &hex_32(pubkey), &hex_32(message));
            assert_eq!(
                verified,
                expected == "TRUE",
                "BIP340 row {}: {}",
                row[0],
                row[7]
            );
            checked += 1;
        }
        assert_eq!(checked, 15);
    }

    struct KeyPathVectors {
        tx: Transaction,
        prevouts: Vec<TxOut>,
        spends: Vec<(usize, Vec<u8>)>,
    }

    /// BIP341's `keyPathSpending` vector: the transaction, its nine spent outputs and, per
    /// signed input, the witness signature. Hash types 0x00-0x03 and 0x81-0x83 all appear.
    fn bip341_key_path_vectors() -> KeyPathVectors {
        let json = Json::parse(BIP341_WALLET_TEST_VECTORS_JSON);
        let case = &json.get("keyPathSpending").as_array()[0];
        let tx = deserialize(&case.get("given").get("rawUnsignedTx").as_bytes()).expect("tx");
        let prevouts = case
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
        let spends = case
            .get("inputSpending")
            .as_array()
            .iter()
            .map(|spend| {
                let index = usize::try_from(spend.get("given").get("txinIndex").as_i64());
                let witness = spend.get("expected").get("witness").as_array();
                assert_eq!(witness.len(), 1);
                (index.expect("index"), witness[0].as_bytes())
            })
            .collect();
        KeyPathVectors {
            tx,
            prevouts,
            spends,
        }
    }

    #[test]
    fn check_schnorr_accepts_bip341_key_path_signatures() {
        let vectors = bip341_key_path_vectors();
        let precomputed = TxPrecomputed::new(&vectors.tx, &vectors.prevouts);
        assert_eq!(vectors.spends.len(), 7);
        for (index, signature) in &vectors.spends {
            let checker = TxSigChecker::new(&vectors.tx, *index, &vectors.prevouts, &precomputed);
            let program = vectors.prevouts[*index].script_pubkey.as_bytes();
            assert_eq!(program.len(), 34);
            let output_key: &[u8; 32] = program[2..].try_into().expect("32-byte program");

            let verdict = checker.check_schnorr(signature, output_key, TaprootSpend::KeyPath, None);
            assert_eq!(verdict, Ok(()), "input {index}");

            // The same signature does not survive a flipped bit, a different spend path, an
            // annex it did not commit to, or another input's key.
            let mut tampered = signature.clone();
            tampered[10] ^= 0x01;
            let verdict = checker.check_schnorr(&tampered, output_key, TaprootSpend::KeyPath, None);
            assert_eq!(verdict, Err(ScriptError::SchnorrSig));
            let tapscript = TaprootSpend::Tapscript {
                leaf_hash: [7; 32],
                codesep_pos: 0xffff_ffff,
            };
            let verdict = checker.check_schnorr(signature, output_key, tapscript, None);
            assert_eq!(verdict, Err(ScriptError::SchnorrSig));
            let annex = [ANNEX_TAG, 1, 2, 3];
            let verdict =
                checker.check_schnorr(signature, output_key, TaprootSpend::KeyPath, Some(&annex));
            assert_eq!(verdict, Err(ScriptError::SchnorrSig));
        }
    }

    #[test]
    fn check_schnorr_reports_malformed_signatures() {
        let vectors = bip341_key_path_vectors();
        let precomputed = TxPrecomputed::new(&vectors.tx, &vectors.prevouts);
        let checker = TxSigChecker::new(&vectors.tx, 0, &vectors.prevouts, &precomputed);
        let key = [2u8; 32];
        let key_path = TaprootSpend::KeyPath;

        for len in [0, 1, 63, 66, 100] {
            let verdict = checker.check_schnorr(&vec![0u8; len], &key, key_path, None);
            assert_eq!(verdict, Err(ScriptError::SchnorrSigSize), "length {len}");
        }
        // 65 bytes ending in the default type: the default must be spelled by absence.
        let mut explicit_default = vec![0u8; 65];
        explicit_default[64] = 0x00;
        let verdict = checker.check_schnorr(&explicit_default, &key, key_path, None);
        assert_eq!(verdict, Err(ScriptError::SchnorrSigHashtype));
        // 65 bytes with an undefined type.
        for hash_type in [0x04, 0x20, 0x80, 0x84, 0xff] {
            let mut undefined = vec![0u8; 65];
            undefined[64] = hash_type;
            let verdict = checker.check_schnorr(&undefined, &key, key_path, None);
            assert_eq!(
                verdict,
                Err(ScriptError::SchnorrSigHashtype),
                "type {hash_type:#04x}"
            );
        }
        // SINGLE at an input past the last output: the transaction has 9 inputs, 2 outputs.
        assert_eq!(vectors.tx.output.len(), 2);
        let checker = TxSigChecker::new(&vectors.tx, 5, &vectors.prevouts, &precomputed);
        let mut single = vec![0u8; 65];
        single[64] = 0x03;
        let verdict = checker.check_schnorr(&single, &key, key_path, None);
        assert_eq!(verdict, Err(ScriptError::SchnorrSigHashtype));
        // A key whose x coordinate is not on the curve is a failed check, not a panic.
        let not_on_curve =
            hex_32("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34");
        let verdict = checker.check_schnorr(&[0u8; 64], &not_on_curve, key_path, None);
        assert_eq!(verdict, Err(ScriptError::SchnorrSig));
    }

    /// A signing setup for the ECDSA tests: a random transaction, a key, and a checker on
    /// one input. The consensus crate never signs; the test-only `All` context does.
    struct Signer {
        secp: Secp256k1<secp256k1::All>,
        secret_key: SecretKey,
        pubkey: Vec<u8>,
        tx: Transaction,
        prevouts: Vec<TxOut>,
        script_code: ScriptBuf,
    }

    fn signer(seed: u64) -> Signer {
        let mut prng = Prng::new(seed);
        let tx = random_transaction(&mut prng);
        let prevouts = random_prevouts(&mut prng, tx.input.len());
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&prng.bytes_32()).expect("a random key is valid");
        let pubkey = secret_key.public_key(&secp).serialize().to_vec();
        let script_code = ScriptBuf::from_bytes(
            hex("76a914")
                .into_iter()
                .chain([0u8; 20])
                .chain(hex("88ac"))
                .collect(),
        );
        Signer {
            secp,
            secret_key,
            pubkey,
            tx,
            prevouts,
            script_code,
        }
    }

    impl Signer {
        /// A strict-DER signature with `hash_type` appended, over the legacy digest of `index`.
        fn sign_legacy(&self, index: usize, hash_type: u8) -> Vec<u8> {
            let digest = legacy_sighash(&self.tx, index, &self.script_code, u32::from(hash_type));
            let message = secp256k1::Message::from_digest(digest);
            let mut signature = self
                .secp
                .sign_ecdsa(&message, &self.secret_key)
                .serialize_der()
                .to_vec();
            signature.push(hash_type);
            signature
        }
    }

    #[test]
    fn check_ecdsa_verifies_legacy_and_witness_v0_signatures() {
        let signer = signer(1);
        let precomputed = TxPrecomputed::new(&signer.tx, &signer.prevouts);
        for index in 0..signer.tx.input.len() {
            let checker = TxSigChecker::new(&signer.tx, index, &signer.prevouts, &precomputed);
            for hash_type in [0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00, 0x45, 0xff] {
                let signature = signer.sign_legacy(index, hash_type);
                assert!(
                    checker.check_ecdsa(
                        &signature,
                        &signer.pubkey,
                        &signer.script_code,
                        SigVersion::Base
                    ),
                    "input {index} type {hash_type:#04x}"
                );
                // The same bytes under v0 hash a different preimage.
                assert!(!checker.check_ecdsa(
                    &signature,
                    &signer.pubkey,
                    &signer.script_code,
                    SigVersion::WitnessV0
                ));
                // Another hash type byte, another digest.
                let mut retyped = signature.clone();
                retyped[signature.len() - 1] ^= 0x10;
                assert!(!checker.check_ecdsa(
                    &retyped,
                    &signer.pubkey,
                    &signer.script_code,
                    SigVersion::Base
                ));
            }

            let digest = crate::script::sighash::segwit_v0_sighash(
                &signer.tx,
                index,
                &signer.script_code,
                signer.prevouts[index].value,
                u32::from(SIGHASH_ALL),
                &precomputed,
            );
            let message = secp256k1::Message::from_digest(digest);
            let mut signature = signer
                .secp
                .sign_ecdsa(&message, &signer.secret_key)
                .serialize_der()
                .to_vec();
            signature.push(SIGHASH_ALL);
            assert!(checker.check_ecdsa(
                &signature,
                &signer.pubkey,
                &signer.script_code,
                SigVersion::WitnessV0
            ));
            assert!(!checker.check_ecdsa(
                &signature,
                &signer.pubkey,
                &signer.script_code,
                SigVersion::Base
            ));
        }
    }

    /// `s -> n - s` over the curve order, big-endian: the other valid `s` for the same message.
    fn negate_scalar(scalar: &[u8; 32]) -> [u8; 32] {
        let order = secp256k1::constants::CURVE_ORDER;
        let mut result = [0u8; 32];
        let mut borrow: i16 = 0;
        for position in (0..32).rev() {
            let difference = i16::from(order[position]) - i16::from(scalar[position]) - borrow;
            let (byte, next_borrow) = if difference < 0 {
                (difference + 256, 1)
            } else {
                (difference, 0)
            };
            result[position] = u8::try_from(byte).expect("one byte");
            borrow = next_borrow;
        }
        assert_eq!(borrow, 0);
        result
    }

    #[test]
    fn check_ecdsa_accepts_what_history_accepted() {
        let signer = signer(2);
        let precomputed = TxPrecomputed::new(&signer.tx, &signer.prevouts);
        let checker = TxSigChecker::new(&signer.tx, 0, &signer.prevouts, &precomputed);
        let strict = signer.sign_legacy(0, SIGHASH_ALL);
        let body = &strict[..strict.len() - 1];

        // High S: flip s to n - s. Strict DER would reject it under LOW_S; consensus does not.
        let compact = secp256k1::ecdsa::Signature::from_der(body)
            .expect("strict DER")
            .serialize_compact();
        let mut high_s = compact;
        let s: [u8; 32] = compact[32..].try_into().expect("32 bytes");
        high_s[32..].copy_from_slice(&negate_scalar(&s));
        let mut high_s_der = secp256k1::ecdsa::Signature::from_compact(&high_s)
            .expect("compact")
            .serialize_der()
            .to_vec();
        high_s_der.push(SIGHASH_ALL);
        assert!(checker.check_ecdsa(
            &high_s_der,
            &signer.pubkey,
            &signer.script_code,
            SigVersion::Base
        ));

        // BER long-form length on the outer SEQUENCE: `30 81 len` instead of `30 len`.
        let mut long_form = vec![0x30, 0x81];
        long_form.extend_from_slice(&body[1..]);
        long_form.push(SIGHASH_ALL);
        assert!(secp256k1::ecdsa::Signature::from_der(&long_form[..long_form.len() - 1]).is_err());
        assert!(checker.check_ecdsa(
            &long_form,
            &signer.pubkey,
            &signer.script_code,
            SigVersion::Base
        ));

        // Uncompressed and hybrid keys: 0x04, and 0x06/0x07 with the parity of y.
        let uncompressed = signer
            .secret_key
            .public_key(&signer.secp)
            .serialize_uncompressed();
        assert!(checker.check_ecdsa(
            &strict,
            &uncompressed,
            &signer.script_code,
            SigVersion::Base
        ));
        let mut hybrid = uncompressed;
        hybrid[0] = if uncompressed[64].is_multiple_of(2) {
            0x06
        } else {
            0x07
        };
        assert!(checker.check_ecdsa(&strict, &hybrid, &signer.script_code, SigVersion::Base));
        // The wrong hybrid parity is an unparsable key: false, not a panic.
        hybrid[0] ^= 0x01;
        assert!(!checker.check_ecdsa(&strict, &hybrid, &signer.script_code, SigVersion::Base));
    }

    #[test]
    fn check_ecdsa_is_false_on_unparsable_input() {
        let signer = signer(3);
        let precomputed = TxPrecomputed::new(&signer.tx, &signer.prevouts);
        let checker = TxSigChecker::new(&signer.tx, 0, &signer.prevouts, &precomputed);
        let strict = signer.sign_legacy(0, SIGHASH_ALL);
        let code = &signer.script_code;

        assert!(!checker.check_ecdsa(&[], &signer.pubkey, code, SigVersion::Base));
        assert!(!checker.check_ecdsa(&[SIGHASH_ALL], &signer.pubkey, code, SigVersion::Base));
        assert!(!checker.check_ecdsa(
            &[0x30, 0x00, SIGHASH_ALL],
            &signer.pubkey,
            code,
            SigVersion::Base
        ));
        assert!(!checker.check_ecdsa(&strict, &[], code, SigVersion::Base));
        assert!(!checker.check_ecdsa(&strict, &[0x02], code, SigVersion::Base));
        let mut bad_prefix = signer.pubkey.clone();
        bad_prefix[0] = 0x05;
        assert!(!checker.check_ecdsa(&strict, &bad_prefix, code, SigVersion::Base));
        let mut other_key = signer.pubkey.clone();
        other_key[0] ^= 0x01;
        assert!(!checker.check_ecdsa(&strict, &other_key, code, SigVersion::Base));
        let mut wrong_code = code.to_bytes();
        wrong_code.push(0x51);
        assert!(!checker.check_ecdsa(
            &strict,
            &signer.pubkey,
            &ScriptBuf::from_bytes(wrong_code),
            SigVersion::Base
        ));
    }

    fn checker_with(
        tx: &mut Transaction,
        version: i32,
        lock_time: u32,
        sequence: u32,
    ) -> (Transaction, Vec<TxOut>) {
        tx.version = bitcoin::transaction::Version(version);
        tx.lock_time = bitcoin::absolute::LockTime::from_consensus(lock_time);
        tx.input[0].sequence = Sequence(sequence);
        let prevouts = random_prevouts(&mut Prng::new(9), tx.input.len());
        (tx.clone(), prevouts)
    }

    #[test]
    fn check_locktime_follows_bip65() {
        let mut prng = Prng::new(4);
        let mut base = random_transaction(&mut prng);
        let cases: [(u32, u32, i64, bool); 9] = [
            // (tx nLockTime, input nSequence, operand, expected)
            (100, 0xffff_fffe, 100, true),
            (100, 0xffff_fffe, 99, true),
            (100, 0xffff_fffe, 101, false),
            (100, 0xffff_fffe, 0, true),
            // A height operand against a timestamp lock, and the reverse: different kinds.
            (600_000_000, 0xffff_fffe, 100, false),
            (100, 0xffff_fffe, 600_000_000, false),
            (600_000_000, 0, 500_000_000, true),
            // A final input disables nLockTime, so the check fails.
            (100, 0xffff_ffff, 100, false),
            (0, 0, 0, true),
        ];
        for (lock_time, sequence, operand, expected) in cases {
            let (tx, prevouts) = checker_with(&mut base, 1, lock_time, sequence);
            let precomputed = TxPrecomputed::new(&tx, &prevouts);
            let checker = TxSigChecker::new(&tx, 0, &prevouts, &precomputed);
            assert_eq!(
                checker.check_locktime(operand),
                expected,
                "{lock_time} {sequence:#x} {operand}"
            );
        }
    }

    #[test]
    fn check_sequence_follows_bip112() {
        let mut prng = Prng::new(5);
        let mut base = random_transaction(&mut prng);
        let type_flag: u32 = 1 << 22;
        let type_flag_operand: i64 = 1 << 22;
        let cases: [(i32, u32, i64, bool); 12] = [
            // (tx version, input nSequence, operand, expected)
            (2, 10, 10, true),
            (2, 10, 9, true),
            (2, 10, 11, false),
            // Version 1 and negative versions have no relative locks.
            (1, 10, 10, false),
            (-1, 10, 10, false),
            // The disable flag on the input turns the check off.
            (2, 0x0a | (1 << 31), 0x0a, false),
            // Time-based against time-based, in 512-second units.
            (2, type_flag | 0x0a, type_flag_operand | 0x0a, true),
            (2, type_flag | 0x0a, type_flag_operand | 0x0b, false),
            // Kinds must match.
            (2, type_flag | 0x0a, 0x0a, false),
            (2, 0x0a, type_flag_operand | 0x0a, false),
            // Bits outside the mask are ignored on both sides.
            (2, 0x0a | (1 << 23), 0x0a | (1 << 25), true),
            (2, 0xffff | type_flag, (1 << 39) - 1 - (1 << 31), true),
        ];
        for (version, sequence, operand, expected) in cases {
            let (tx, prevouts) = checker_with(&mut base, version, 0, sequence);
            let precomputed = TxPrecomputed::new(&tx, &prevouts);
            let checker = TxSigChecker::new(&tx, 0, &prevouts, &precomputed);
            assert_eq!(
                checker.check_sequence(operand),
                expected,
                "{version} {sequence:#x} {operand:#x}"
            );
        }
    }

    /// A Schnorr signature this crate never makes, checked by the code it does run: closes
    /// the loop on the tapscript path, which BIP341's key-path vectors cannot exercise.
    #[test]
    fn check_schnorr_verifies_a_tapscript_signature() {
        let mut prng = Prng::new(6);
        let tx = random_transaction(&mut prng);
        let prevouts = random_prevouts(&mut prng, tx.input.len());
        let precomputed = TxPrecomputed::new(&tx, &prevouts);
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &prng.bytes_32()).expect("valid key");
        let (xonly, _parity) = keypair.x_only_public_key();
        let pubkey = xonly.serialize();
        let spend = TaprootSpend::Tapscript {
            leaf_hash: prng.bytes_32(),
            codesep_pos: 3,
        };
        let annex = [ANNEX_TAG, 0xaa, 0xbb];

        let checker = TxSigChecker::new(&tx, 0, &prevouts, &precomputed);
        for hash_type in [0x00, 0x01, 0x02, 0x81, 0x82] {
            let digest = crate::script::sighash::taproot_sighash(
                &tx,
                0,
                &prevouts,
                hash_type,
                spend,
                Some(&annex),
                &precomputed,
            )
            .expect("defined hash type");
            let message = secp256k1::Message::from_digest(digest);
            let mut signature = secp
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .serialize()
                .to_vec();
            if hash_type != 0x00 {
                signature.push(hash_type);
            }
            assert_eq!(
                checker.check_schnorr(&signature, &pubkey, spend, Some(&annex)),
                Ok(())
            );
            assert_eq!(
                checker.check_schnorr(&signature, &pubkey, spend, None),
                Err(ScriptError::SchnorrSig)
            );
            assert_eq!(
                checker.check_schnorr(&signature, &pubkey, TaprootSpend::KeyPath, Some(&annex)),
                Err(ScriptError::SchnorrSig)
            );
        }
    }
}
