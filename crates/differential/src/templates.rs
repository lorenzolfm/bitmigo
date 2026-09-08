// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed cases: spends built to succeed, then sometimes damaged in one place.
//!
//! An unstructured script almost never satisfies a `CHECKSIG`, so on its own the fuzzer
//! would compare the two interpreters on failure paths only. These templates produce the
//! spends the chain actually contains (pay-to-pubkey and its hash, bare and P2SH multisig,
//! P2WPKH and P2WSH natively and P2SH-wrapped, taproot key path and script path, hash
//! puzzles under every wrapper) with real signatures over the digests rust-bitcoin computes,
//! so that both interpreters reach the signature check and one of them saying no is a
//! finding. Then, with some probability, one byte is flipped, one item dropped or the flags
//! changed, so that the two disagree about a *nearly* valid spend if they ever will.
//!
//! rust-bitcoin signs; bitmigo and Core verify. If rust-bitcoin's digest were wrong both
//! would reject and the case would be wasted, not misreported; BM-15 already checked those
//! digests against Core's `sighash.json`.

use bitcoin::hashes::{Hash, hash160, ripemd160, sha1, sha256, sha256d};
use bitcoin::key::{Keypair, PublicKey, TapTweak, XOnlyPublicKey};
use bitcoin::secp256k1::{self, All, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Annex, EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Amount, Script, ScriptBuf};
use bitmigo_consensus::script::ScriptFlags;

use crate::case::{Case, MAX_MONEY};
use crate::generate::{p2sh, push_data, random_flags};
use crate::prng::Prng;

/// The ECDSA hash types every signer uses.
const ECDSA_HASH_TYPES: [u8; 6] = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83];
/// Hash types no signer uses but legacy verification accepts: masked to `ALL` for the
/// outputs, `ANYONECANPAY` bit still honoured. Witness v0 signers stay on the defined set,
/// because rust-bitcoin's BIP143 digest normalises the type before hashing and Core does not.
const ECDSA_ODD_HASH_TYPES: [u8; 4] = [0x00, 0x04, 0x7f, 0xff];
/// The Schnorr hash types; `0x00` is `SIGHASH_DEFAULT` and makes a 64-byte signature.
const SCHNORR_HASH_TYPES: [u8; 7] = [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83];
/// The order of secp256k1, for producing high-S signatures.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// A signing key in every form a script can name it.
struct Key {
    secret: SecretKey,
    keypair: Keypair,
    /// Compressed three times in four; an uncompressed key is consensus-valid everywhere
    /// but tapscript (where it does not fit), and policy-invalid under witness v0.
    public: PublicKey,
}

impl Key {
    fn random(secp: &Secp256k1<All>, prng: &mut Prng) -> Key {
        // A random 32-byte string is a valid secret key unless it is zero or at least the
        // curve order, odds below 2^-127: not worth a retry loop.
        let secret = SecretKey::from_slice(&prng.bytes_32()).expect("a valid secret key");
        let keypair = Keypair::from_secret_key(secp, &secret);
        let inner = secp256k1::PublicKey::from_secret_key(secp, &secret);
        let public = if prng.chance(3, 4) {
            PublicKey::new(inner)
        } else {
            PublicKey::new_uncompressed(inner)
        };
        Key {
            secret,
            keypair,
            public,
        }
    }

    fn x_only(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }
}

/// How the inner script reaches the interpreter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wrapper {
    /// The inner script is the scriptPubKey; legacy sighash over it.
    Bare,
    /// The inner script is a redeem script; legacy sighash over it.
    P2sh,
    /// The inner script is a witness script; BIP143 over it.
    P2wsh,
    /// A P2WSH program wrapped in P2SH.
    P2shP2wsh,
    /// The inner script is a `0x00 0x14 <hash160(key)>` program; BIP143 over the implied
    /// P2PKH script code.
    P2wpkh,
    /// A P2WPKH program wrapped in P2SH.
    P2shP2wpkh,
    /// The inner script is a tapscript leaf; BIP341 with the leaf hash.
    Tapscript,
}

impl Wrapper {
    /// A wrapper for a script that checks signatures with `CHECKSIG`-family opcodes.
    fn random_script_wrapper(prng: &mut Prng) -> Wrapper {
        *prng.pick(&[
            Wrapper::Bare,
            Wrapper::P2sh,
            Wrapper::P2wsh,
            Wrapper::P2shP2wsh,
            Wrapper::Tapscript,
        ])
    }

    fn is_tapscript(self) -> bool {
        self == Wrapper::Tapscript
    }
}

/// A spend under construction: inner script, wrapper, and the output that commits to it.
struct Spend {
    wrapper: Wrapper,
    inner: Vec<u8>,
    script_pubkey: Vec<u8>,
    /// The tree the taproot output commits to, for the control block.
    taproot: Option<TaprootSpendInfo>,
}

impl Spend {
    fn new(secp: &Secp256k1<All>, prng: &mut Prng, wrapper: Wrapper, inner: Vec<u8>) -> Spend {
        let mut taproot = None;
        let script_pubkey = match wrapper {
            Wrapper::Bare | Wrapper::P2wpkh => inner.clone(),
            Wrapper::P2sh | Wrapper::P2shP2wpkh => p2sh(&inner),
            Wrapper::P2wsh => p2wsh(&inner),
            Wrapper::P2shP2wsh => p2sh(&p2wsh(&inner)),
            Wrapper::Tapscript => {
                let internal = Key::random(secp, prng).x_only();
                let info = TaprootBuilder::new()
                    .add_leaf(0, ScriptBuf::from_bytes(inner.clone()))
                    .expect("one leaf at depth 0 is a complete tree")
                    .finalize(secp, internal)
                    .expect("a complete tree finalizes");
                let script_pubkey = ScriptBuf::new_p2tr_tweaked(info.output_key()).into_bytes();
                taproot = Some(info);
                script_pubkey
            }
        };
        Spend {
            wrapper,
            inner,
            script_pubkey,
            taproot,
        }
    }

    /// The case before its scriptSig and witness exist: what the signatures commit to.
    fn unsigned_case(&self, prng: &mut Prng) -> Case {
        let flags = if prng.chance(3, 4) {
            ScriptFlags::MANDATORY
        } else {
            random_flags(prng)
        };
        Case {
            flags,
            script_pubkey: self.script_pubkey.clone(),
            amount: prng.below(MAX_MONEY + 1),
            script_sig: Vec::new(),
            witness: Vec::new(),
        }
    }

    /// The digest a signature for input 0 of `case` commits to, under this wrapper.
    fn sighash(&self, case: &Case, hash_type: u8) -> [u8; 32] {
        let tx = case.spending_transaction();
        let mut cache = SighashCache::new(&tx);
        let inner = Script::from_bytes(&self.inner);
        let amount = Amount::from_sat(case.amount);
        match self.wrapper {
            Wrapper::Bare | Wrapper::P2sh => cache
                .legacy_signature_hash(0, inner, u32::from(hash_type))
                .expect("input 0 exists")
                .to_byte_array(),
            Wrapper::P2wsh | Wrapper::P2shP2wsh => cache
                .p2wsh_signature_hash(0, inner, amount, ecdsa_type(hash_type))
                .expect("input 0 exists")
                .to_byte_array(),
            Wrapper::P2wpkh | Wrapper::P2shP2wpkh => cache
                .p2wpkh_signature_hash(0, inner, amount, ecdsa_type(hash_type))
                .expect("input 0 exists and the program is P2WPKH")
                .to_byte_array(),
            Wrapper::Tapscript => {
                let leaf = TapLeafHash::from_script(inner, LeafVersion::TapScript);
                let prevouts = [case.prevout()];
                cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &Prevouts::All(&prevouts),
                        leaf,
                        schnorr_type(hash_type),
                    )
                    .expect("input 0 exists")
                    .to_byte_array()
            }
        }
    }

    /// Places the solving `items` (bottom first) where this wrapper reads them.
    fn solve(&self, mut case: Case, items: Vec<Vec<u8>>) -> Case {
        assert!(case.script_sig.is_empty());
        assert!(case.witness.is_empty());
        match self.wrapper {
            Wrapper::Bare => {
                for item in &items {
                    push_data(&mut case.script_sig, item);
                }
            }
            Wrapper::P2sh => {
                for item in &items {
                    push_data(&mut case.script_sig, item);
                }
                push_data(&mut case.script_sig, &self.inner);
            }
            Wrapper::P2wsh => {
                case.witness = items;
                case.witness.push(self.inner.clone());
            }
            Wrapper::P2shP2wsh => {
                push_data(&mut case.script_sig, &p2wsh(&self.inner));
                case.witness = items;
                case.witness.push(self.inner.clone());
            }
            Wrapper::P2wpkh => case.witness = items,
            Wrapper::P2shP2wpkh => {
                push_data(&mut case.script_sig, &self.inner);
                case.witness = items;
            }
            Wrapper::Tapscript => {
                let info = self.taproot.as_ref().expect("a tapscript spend has a tree");
                let leaf = (
                    ScriptBuf::from_bytes(self.inner.clone()),
                    LeafVersion::TapScript,
                );
                let control = info.control_block(&leaf).expect("the leaf is in the tree");
                case.witness = items;
                case.witness.push(self.inner.clone());
                case.witness.push(control.serialize());
            }
        }
        case
    }
}

/// `OP_0 <sha256(script)>`.
fn p2wsh(script: &[u8]) -> Vec<u8> {
    let mut program = vec![0x00, 0x20];
    program.extend(sha256::Hash::hash(script).to_byte_array());
    assert_eq!(program.len(), 34);
    program
}

/// `OP_0 <hash160(key)>`.
fn p2wpkh(key: &PublicKey) -> Vec<u8> {
    let mut program = vec![0x00, 0x14];
    program.extend(hash160::Hash::hash(&key.to_bytes()).to_byte_array());
    assert_eq!(program.len(), 22);
    program
}

/// `DUP HASH160 <hash160(key)> EQUALVERIFY CHECKSIG`.
fn p2pkh(key: &PublicKey) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend(hash160::Hash::hash(&key.to_bytes()).to_byte_array());
    script.extend([0x88, 0xac]);
    assert_eq!(script.len(), 25);
    script
}

fn ecdsa_type(hash_type: u8) -> EcdsaSighashType {
    assert!(
        ECDSA_HASH_TYPES.contains(&hash_type),
        "witness v0 signs defined types only"
    );
    EcdsaSighashType::from_consensus(u32::from(hash_type))
}

fn schnorr_type(hash_type: u8) -> TapSighashType {
    TapSighashType::from_consensus_u8(hash_type).expect("a defined Schnorr hash type")
}

/// A DER signature plus its hash type byte, as a script pushes it. One time in eight the S
/// value is replaced by its negation: consensus accepts high S (`LOW_S` is policy), and
/// bitmigo normalises it where Core's libsecp256k1 does not need to.
fn ecdsa_signature(
    secp: &Secp256k1<All>,
    prng: &mut Prng,
    key: &Key,
    digest: [u8; 32],
    hash_type: u8,
) -> Vec<u8> {
    let mut signature = secp.sign_ecdsa(&Message::from_digest(digest), &key.secret);
    if prng.chance(1, 8) {
        let mut compact = signature.serialize_compact();
        let (_, s) = compact.split_at_mut(32);
        let high_s = curve_order_minus(s.try_into().expect("32 bytes"));
        s.copy_from_slice(&high_s);
        signature = secp256k1::ecdsa::Signature::from_compact(&compact).expect("valid r and s");
    }
    let mut bytes = signature.serialize_der().to_vec();
    bytes.push(hash_type);
    assert!(bytes.len() >= 9);
    assert!(bytes.len() <= 74);
    bytes
}

/// `n - s` over 32 big-endian bytes, for `0 < s < n`.
fn curve_order_minus(s: [u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0i16;
    for ((out, n), s) in result.iter_mut().zip(CURVE_ORDER).zip(s).rev() {
        let difference = i16::from(n) - i16::from(s) - borrow;
        if difference < 0 {
            *out = u8::try_from(difference + 256).expect("in range");
            borrow = 1;
        } else {
            *out = u8::try_from(difference).expect("in range");
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0, "s < n");
    result
}

/// A BIP340 signature over `digest` by `keypair`, with the hash type byte appended unless it
/// is `SIGHASH_DEFAULT`.
fn schnorr_signature(
    secp: &Secp256k1<All>,
    keypair: &Keypair,
    digest: [u8; 32],
    hash_type: u8,
) -> Vec<u8> {
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), keypair);
    let mut bytes = signature.serialize().to_vec();
    if hash_type != 0x00 {
        bytes.push(hash_type);
    }
    assert!(bytes.len() == 64 || bytes.len() == 65);
    bytes
}

/// A hash type for the wrapper's signature scheme, occasionally undefined where legacy
/// verification tolerates that.
fn random_hash_type(prng: &mut Prng, wrapper: Wrapper) -> u8 {
    match wrapper {
        Wrapper::Tapscript => *prng.pick(&SCHNORR_HASH_TYPES),
        Wrapper::Bare | Wrapper::P2sh if prng.chance(1, 8) => *prng.pick(&ECDSA_ODD_HASH_TYPES),
        _ => *prng.pick(&ECDSA_HASH_TYPES),
    }
}

/// Signs `case` for input 0 under `spend`'s wrapper with `key`.
fn sign(secp: &Secp256k1<All>, prng: &mut Prng, spend: &Spend, case: &Case, key: &Key) -> Vec<u8> {
    let hash_type = random_hash_type(prng, spend.wrapper);
    let digest = spend.sighash(case, hash_type);
    if spend.wrapper.is_tapscript() {
        schnorr_signature(secp, &key.keypair, digest, hash_type)
    } else {
        ecdsa_signature(secp, prng, key, digest, hash_type)
    }
}

/// `<hash-op> <digest of preimage> EQUAL`, solved by the preimage, under any wrapper.
fn hash_puzzle(secp: &Secp256k1<All>, prng: &mut Prng) -> Case {
    let wrapper = Wrapper::random_script_wrapper(prng);
    let preimage_len = prng.below_usize(81);
    let preimage = prng.bytes(preimage_len);
    let (opcode, digest): (u8, Vec<u8>) = match prng.below(5) {
        0 => (
            0xa6,
            ripemd160::Hash::hash(&preimage).to_byte_array().to_vec(),
        ),
        1 => (0xa7, sha1::Hash::hash(&preimage).to_byte_array().to_vec()),
        2 => (0xa8, sha256::Hash::hash(&preimage).to_byte_array().to_vec()),
        3 => (
            0xa9,
            hash160::Hash::hash(&preimage).to_byte_array().to_vec(),
        ),
        _ => (
            0xaa,
            sha256d::Hash::hash(&preimage).to_byte_array().to_vec(),
        ),
    };
    let mut inner = vec![opcode];
    push_data(&mut inner, &digest);
    if wrapper == Wrapper::Bare && opcode == 0xa9 {
        // `HASH160 <20 bytes> EQUAL` is the P2SH pattern byte for byte: bare, under the
        // P2SH flag, the preimage would run as a redeem script. `EQUALVERIFY OP_1` keeps
        // the puzzle a puzzle; the unstructured generator still produces the P2SH lookalike.
        inner.extend([0x88, 0x51]);
    } else {
        inner.push(0x87);
    }
    let spend = Spend::new(secp, prng, wrapper, inner);
    let case = spend.unsigned_case(prng);
    spend.solve(case, vec![preimage])
}

/// `<key> CHECKSIG` under any wrapper: ECDSA with a full key, Schnorr with an x-only key
/// in tapscript.
fn check_sig(secp: &Secp256k1<All>, prng: &mut Prng) -> Case {
    let wrapper = Wrapper::random_script_wrapper(prng);
    let key = Key::random(secp, prng);
    let mut inner = Vec::new();
    if wrapper.is_tapscript() {
        push_data(&mut inner, &key.x_only().serialize());
    } else {
        push_data(&mut inner, &key.public.to_bytes());
    }
    inner.push(if prng.chance(1, 4) { 0xad } else { 0xac });
    if inner.ends_with(&[0xad]) {
        inner.push(0x51);
    }
    let spend = Spend::new(secp, prng, wrapper, inner);
    let case = spend.unsigned_case(prng);
    let signature = sign(secp, prng, &spend, &case, &key);
    spend.solve(case, vec![signature])
}

/// `OP_k <keys> OP_n CHECKMULTISIG` with `k` signatures in key order behind the dummy, or
/// in tapscript `<x1> CHECKSIG <x2> CHECKSIGADD OP_2 NUMEQUAL` with both signatures.
fn multisig(secp: &Secp256k1<All>, prng: &mut Prng) -> Case {
    let wrapper = Wrapper::random_script_wrapper(prng);
    let key_count = prng.below_usize(3) + 1;
    let keys: Vec<Key> = (0..key_count).map(|_| Key::random(secp, prng)).collect();
    let required = prng.below_usize(key_count) + 1;
    let mut inner = Vec::new();
    if wrapper.is_tapscript() {
        for (index, key) in keys.iter().enumerate() {
            push_data(&mut inner, &key.x_only().serialize());
            inner.push(if index == 0 { 0xac } else { 0xba });
        }
        inner.extend([0x50 + u8::try_from(key_count).expect("at most 3"), 0x9c]);
    } else {
        inner.push(0x50 + u8::try_from(required).expect("at most 3"));
        for key in &keys {
            push_data(&mut inner, &key.public.to_bytes());
        }
        inner.extend([0x50 + u8::try_from(key_count).expect("at most 3"), 0xae]);
    }
    let spend = Spend::new(secp, prng, wrapper, inner);
    let case = spend.unsigned_case(prng);
    let mut items = Vec::new();
    if wrapper.is_tapscript() {
        // The first CHECKSIG consumes the top of the stack: the last key's signature is
        // pushed first.
        for key in keys.iter().rev() {
            items.push(sign(secp, prng, &spend, &case, key));
        }
    } else {
        // The dummy is empty by consensus under NULLDUMMY and free otherwise.
        items.push(if prng.chance(1, 8) {
            vec![0x01]
        } else {
            Vec::new()
        });
        for key in keys.iter().take(required) {
            items.push(sign(secp, prng, &spend, &case, key));
        }
    }
    spend.solve(case, items)
}

/// The three pay-to-pubkey-hash forms: legacy, native v0 and P2SH-wrapped v0.
fn pay_to_pubkey_hash(secp: &Secp256k1<All>, prng: &mut Prng) -> Case {
    let key = Key::random(secp, prng);
    let (wrapper, inner) = match prng.below(3) {
        0 => (Wrapper::Bare, p2pkh(&key.public)),
        1 => (Wrapper::P2wpkh, p2wpkh(&key.public)),
        _ => (Wrapper::P2shP2wpkh, p2wpkh(&key.public)),
    };
    let spend = Spend::new(secp, prng, wrapper, inner);
    let case = spend.unsigned_case(prng);
    let signature = sign(secp, prng, &spend, &case, &key);
    spend.solve(case, vec![signature, key.public.to_bytes()])
}

/// A taproot key-path spend: the output key is the internal key tweaked with no tree, the
/// witness is the signature alone or followed by an annex.
fn taproot_key_path(secp: &Secp256k1<All>, prng: &mut Prng) -> Case {
    let key = Key::random(secp, prng);
    let tweaked = key.keypair.tap_tweak(secp, None).to_keypair();
    let script_pubkey = ScriptBuf::new_p2tr(secp, key.x_only(), None).into_bytes();
    assert_eq!(script_pubkey.len(), 34);
    let spend = Spend {
        wrapper: Wrapper::Tapscript,
        inner: Vec::new(),
        script_pubkey,
        taproot: None,
    };
    let mut case = spend.unsigned_case(prng);
    let annex = if prng.chance(1, 4) {
        let mut annex = vec![0x50];
        let len = prng.below_usize(40);
        annex.extend(prng.bytes(len));
        Some(annex)
    } else {
        None
    };
    let hash_type = *prng.pick(&SCHNORR_HASH_TYPES);
    let tx = case.spending_transaction();
    let prevouts = [case.prevout()];
    let digest = SighashCache::new(&tx)
        .taproot_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            annex
                .as_deref()
                .map(|bytes| Annex::new(bytes).expect("starts with 0x50")),
            None,
            schnorr_type(hash_type),
        )
        .expect("input 0 exists")
        .to_byte_array();
    case.witness
        .push(schnorr_signature(secp, &tweaked, digest, hash_type));
    if let Some(annex) = annex {
        case.witness.push(annex);
    }
    case
}

/// One damage to a solved case, chosen at random: a flipped byte in the scriptSig or a
/// witness item, a truncated or extended item, a dropped item, other flags, another amount.
fn mutate(prng: &mut Prng, case: &mut Case) {
    match prng.below(8) {
        0 | 1 if !case.script_sig.is_empty() => {
            let index = prng.below_usize(case.script_sig.len());
            let bit = 1 << prng.below(8);
            *case.script_sig.get_mut(index).expect("index < len") ^= bit;
        }
        2 | 3 if !case.witness.is_empty() => {
            let item = prng.below_usize(case.witness.len());
            let bytes = case.witness.get_mut(item).expect("item < len");
            if bytes.is_empty() {
                bytes.push(prng.next_u8());
            } else {
                let index = prng.below_usize(bytes.len());
                let bit = 1 << prng.below(8);
                *bytes.get_mut(index).expect("index < len") ^= bit;
            }
        }
        4 if !case.witness.is_empty() => {
            let item = prng.below_usize(case.witness.len());
            let bytes = case.witness.get_mut(item).expect("item < len");
            if prng.chance(1, 2) {
                bytes.pop();
            } else {
                bytes.push(prng.next_u8());
            }
        }
        5 if !case.witness.is_empty() => {
            let item = prng.below_usize(case.witness.len());
            case.witness.remove(item);
        }
        6 => case.amount = prng.below(MAX_MONEY + 1),
        _ => case.flags = random_flags(prng),
    }
}

/// One signed case, damaged one time in three.
pub fn signed_case(secp: &Secp256k1<All>, prng: &mut Prng) -> Case {
    let mut case = match prng.below(6) {
        0 => hash_puzzle(secp, prng),
        1 | 2 => check_sig(secp, prng),
        3 => multisig(secp, prng),
        4 => pay_to_pubkey_hash(secp, prng),
        _ => taproot_key_path(secp, prng),
    };
    if prng.chance(1, 3) {
        mutate(prng, &mut case);
    }
    case.assert_bounded();
    case
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index panic fails the test"
    )]

    use bitcoin::secp256k1::Secp256k1;
    use bitmigo_consensus::script::ScriptFlags;

    use super::{
        CURVE_ORDER, check_sig, curve_order_minus, hash_puzzle, multisig, pay_to_pubkey_hash,
        taproot_key_path,
    };
    use crate::prng::Prng;

    /// Every undamaged template must verify on both sides under `MANDATORY`: that is what
    /// makes a later disagreement a finding rather than a broken generator.
    #[test]
    fn undamaged_templates_verify_on_both_sides() {
        let secp = Secp256k1::new();
        let mut prng = Prng::new(2024);
        for _ in 0..40 {
            for template in [
                hash_puzzle,
                check_sig,
                multisig,
                pay_to_pubkey_hash,
                taproot_key_path,
            ] {
                let mut case = template(&secp, &mut prng);
                case.flags = ScriptFlags::MANDATORY;
                // The multisig template's one-in-eight non-empty dummy, `[0x01]`, sits
                // first in the scriptSig (pushed as `01 01`) or first in the witness, and
                // fails under NULLDUMMY by design. Dropping the flag never invalidates a
                // valid spend, so a lookalike from another template costs nothing.
                let dummy_in_script_sig = case.script_sig.starts_with(&[0x01, 0x01]);
                let dummy_in_witness = case.witness.first().is_some_and(|d| d == &[0x01]);
                if dummy_in_script_sig || dummy_in_witness {
                    case.flags = ScriptFlags::MANDATORY.difference(ScriptFlags::NULLDUMMY);
                }
                assert!(
                    case.oracle_verdict(),
                    "the oracle rejected a template:\n{case}"
                );
                assert!(
                    case.bitmigo_verdict(),
                    "bitmigo rejected a template:\n{case}"
                );
            }
        }
    }

    #[test]
    fn curve_order_minus_is_subtraction() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut expected = CURVE_ORDER;
        expected[31] = 0x40;
        assert_eq!(curve_order_minus(one), expected);
        assert_eq!(curve_order_minus(CURVE_ORDER), [0u8; 32]);
    }
}
