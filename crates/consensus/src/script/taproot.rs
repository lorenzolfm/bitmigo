// SPDX-License-Identifier: MIT OR Apache-2.0

//! The taproot commitment (BIP341): what a control block says, and whether the output key
//! agrees with it.
//!
//! A script-path spend presents a leaf script and a control block. The block names the leaf
//! version, the internal key, the parity of the output key and the Merkle path from the
//! leaf to the root of the tree. Verifying the spend means recomputing that root from the
//! leaf upward and checking that the output key is the internal key tweaked by it. The
//! hashes are tagged SHA256 under the tags `bitcoin::taproot` spells; the arithmetic is
//! libsecp256k1's `xonly_pubkey_tweak_add_check`, the call Core makes. Nothing here
//! executes a script: the verifier decides what to do with a commitment that holds.

use bitcoin::Witness;
use bitcoin::consensus::encode::VarInt;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::taproot::{TapLeafHash, TapNodeHash, TapTweakHash};
use secp256k1::{Parity, Scalar, XOnlyPublicKey};

use super::ScriptError;
use super::checker::SECP256K1;
use super::sighash::{count_to_u64, encode};

/// `TAPROOT_CONTROL_BASE_SIZE`: the leaf-version byte and the 32-byte internal key.
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// `TAPROOT_CONTROL_NODE_SIZE`: one node of the Merkle path.
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// `TAPROOT_CONTROL_MAX_NODE_COUNT`: the deepest leaf a control block can prove.
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
/// `TAPROOT_CONTROL_MAX_SIZE`: 4,129 bytes.
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;
/// `TAPROOT_LEAF_MASK`: the leaf version is the first control byte without its parity bit.
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// `TAPROOT_LEAF_TAPSCRIPT`: the one leaf version with defined semantics (BIP342).
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// `VALIDATION_WEIGHT_OFFSET`: the sigop budget a tapscript starts with, before the
/// serialized size of its witness is added.
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// A control block, parsed: the last witness item of a script-path spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlBlock<'a> {
    /// `c[0] & 0xfe`.
    pub leaf_version: u8,
    /// `c[0] & 1`: whether the output key's Y coordinate is odd.
    pub output_parity_odd: bool,
    /// `c[1..33]`: the internal key `p`, x-only.
    pub internal_key: &'a [u8; 32],
    /// `c[33..]`: the Merkle path from the leaf upward, 32 bytes per node.
    path: &'a [u8],
}

impl<'a> ControlBlock<'a> {
    /// Splits a control block into its fields.
    ///
    /// # Errors
    ///
    /// [`ScriptError::TaprootWrongControlSize`] unless the length is `33 + 32·m` with
    /// `m ≤ 128`.
    pub fn parse(bytes: &'a [u8]) -> Result<ControlBlock<'a>, ScriptError> {
        if bytes.len() < TAPROOT_CONTROL_BASE_SIZE {
            return Err(ScriptError::TaprootWrongControlSize);
        }
        if bytes.len() > TAPROOT_CONTROL_MAX_SIZE {
            return Err(ScriptError::TaprootWrongControlSize);
        }
        if !(bytes.len() - TAPROOT_CONTROL_BASE_SIZE).is_multiple_of(TAPROOT_CONTROL_NODE_SIZE) {
            return Err(ScriptError::TaprootWrongControlSize);
        }
        let (&first, rest) = bytes.split_first().expect("at least 33 bytes");
        let (internal_key, path) = rest.split_first_chunk::<32>().expect("at least 33 bytes");
        assert_eq!(path.len() % TAPROOT_CONTROL_NODE_SIZE, 0);
        Ok(ControlBlock {
            leaf_version: first & TAPROOT_LEAF_MASK,
            output_parity_odd: first & 1 == 1,
            internal_key,
            path,
        })
    }

    /// `m`: how many nodes the Merkle path holds.
    #[must_use]
    pub fn path_len(&self) -> usize {
        // Exact: the parser admitted only whole nodes.
        assert_eq!(self.path.len() % TAPROOT_CONTROL_NODE_SIZE, 0);
        self.path.len() / TAPROOT_CONTROL_NODE_SIZE
    }
}

/// Core's `ComputeTapleafHash`: `tagged("TapLeaf", version || compact_size(len) || script)`.
/// The version arrives with its parity bit already masked off.
#[must_use]
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    assert_eq!(leaf_version & 1, 0);
    let mut engine = TapLeafHash::engine();
    engine.input(&[leaf_version]);
    encode(&mut engine, &VarInt(count_to_u64(script.len())));
    engine.input(script);
    TapLeafHash::from_engine(engine).to_byte_array()
}

/// Core's `ComputeTaprootMerkleRoot`: from the leaf up the path, each step hashing the
/// pair in lexicographic order so that a tree has one root whichever side a node is on.
#[must_use]
pub fn taproot_merkle_root(control: &ControlBlock<'_>, leaf_hash: &[u8; 32]) -> [u8; 32] {
    assert!(control.path_len() <= TAPROOT_CONTROL_MAX_NODE_COUNT);
    let (siblings, remainder) = control.path.as_chunks::<TAPROOT_CONTROL_NODE_SIZE>();
    assert!(remainder.is_empty());
    let mut node = *leaf_hash;
    // Bounded by TAPROOT_CONTROL_MAX_NODE_COUNT: the parser capped the path.
    for sibling in siblings {
        let mut engine = TapNodeHash::engine();
        if node < *sibling {
            engine.input(&node);
            engine.input(sibling);
        } else {
            engine.input(sibling);
            engine.input(&node);
        }
        node = TapNodeHash::from_engine(engine).to_byte_array();
    }
    node
}

/// `XOnlyPubKey::ComputeTapTweakHash` with a Merkle root: `tagged("TapTweak", p || root)`.
#[must_use]
pub fn tap_tweak(internal_key: &[u8; 32], merkle_root: &[u8; 32]) -> [u8; 32] {
    let mut engine = TapTweakHash::engine();
    engine.input(internal_key);
    engine.input(merkle_root);
    TapTweakHash::from_engine(engine).to_byte_array()
}

/// Core's `VerifyTaprootCommitment`: is `output_key` the control block's internal key
/// tweaked by the root that `leaf_hash` and the block's path lead to, with the parity the
/// block claims? False for an internal or output key that is not an x coordinate on the
/// curve, or a tweak at or above the group order, exactly where libsecp256k1 says no.
#[must_use]
pub fn verify_taproot_commitment(
    control: &ControlBlock<'_>,
    output_key: &[u8; 32],
    leaf_hash: &[u8; 32],
) -> bool {
    let Ok(internal_key) = XOnlyPublicKey::from_slice(control.internal_key) else {
        return false;
    };
    let Ok(output_key) = XOnlyPublicKey::from_slice(output_key) else {
        return false;
    };
    let merkle_root = taproot_merkle_root(control, leaf_hash);
    let Ok(tweak) = Scalar::from_be_bytes(tap_tweak(control.internal_key, &merkle_root)) else {
        return false;
    };
    let parity = if control.output_parity_odd {
        Parity::Odd
    } else {
        Parity::Even
    };
    internal_key.tweak_add_check(&SECP256K1, &output_key, parity, tweak)
}

/// The sigop budget a tapscript starts with (BIP342): `VALIDATION_WEIGHT_OFFSET` plus the
/// serialized size of the whole witness, annex and control block included, because that is
/// what the spender paid weight for. Each signature checked costs 50 of it.
#[must_use]
pub fn validation_weight(witness: &Witness) -> i64 {
    let size = i64::try_from(witness_serialized_size(witness))
        .expect("a witness is far smaller than 2^63 bytes");
    assert!(size >= 1);
    VALIDATION_WEIGHT_OFFSET + size
}

/// `GetSerializeSize(witness.stack)`: the item count as a compact size, then each item as
/// its compact-size length and bytes.
#[must_use]
pub fn witness_serialized_size(witness: &Witness) -> usize {
    let mut size = VarInt(count_to_u64(witness.len())).size();
    // Bounded by the witness item count.
    for item in witness {
        size += VarInt(count_to_u64(item.len())).size();
        size += item.len();
    }
    assert!(size >= 1);
    size
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index out of bounds fails the test with a panic"
    )]

    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::hex::FromHex;
    use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash, TapTweakHash};
    use bitcoin::{Script, Witness};

    use super::super::vectors::{BIP341_WALLET_TEST_VECTORS_JSON, Json};
    use super::{
        ControlBlock, ScriptError, TAPROOT_CONTROL_MAX_SIZE, tap_tweak, tapleaf_hash,
        taproot_merkle_root, verify_taproot_commitment, witness_serialized_size,
    };

    fn hex_32(text: &str) -> [u8; 32] {
        <[u8; 32]>::from_hex(text).expect("32 hex bytes")
    }

    /// One leaf of a BIP341 vector's `scriptTree`, in the order `leafHashes` and
    /// `scriptPathControlBlocks` list them.
    struct Leaf {
        script: Vec<u8>,
        version: u8,
    }

    /// Flattens a `scriptTree` (a leaf object or a two-element array of subtrees) into its
    /// leaves in `id` order. Depth is the vectors' four at most; the work stack is bounded
    /// by that.
    fn leaves(tree: &Json) -> Vec<Leaf> {
        let mut leaves = Vec::new();
        let mut pending = vec![tree];
        // Bounded by the node count of the vector's tree, at most seven.
        while let Some(node) = pending.pop() {
            if node.is_array() {
                let branches = node.as_array();
                assert_eq!(branches.len(), 2);
                pending.push(&branches[1]);
                pending.push(&branches[0]);
            } else {
                leaves.push(Leaf {
                    script: node.get("script").as_bytes(),
                    version: u8::try_from(node.get("leafVersion").as_i64()).expect("a byte"),
                });
            }
        }
        assert!(leaves.len() <= 3);
        leaves
    }

    /// The BIP341 wallet vectors' seven `scriptPubKey` cases: leaf hashes, Merkle roots,
    /// tweaks and output keys recomputed from the given trees, and every published control
    /// block committing to its leaf under the published output key.
    #[test]
    fn bip341_script_trees_commit_to_their_leaves() {
        let vectors = Json::parse(BIP341_WALLET_TEST_VECTORS_JSON);
        let mut leaves_checked = 0;
        for case in vectors.get("scriptPubKey").as_array() {
            let internal_key = hex_32(case.get("given").get("internalPubkey").as_str());
            let output_key = hex_32(case.get("intermediary").get("tweakedPubkey").as_str());
            let tree = case.get("given").get("scriptTree");
            if matches!(tree, Json::Null) {
                continue;
            }
            let merkle_root = hex_32(case.get("intermediary").get("merkleRoot").as_str());
            assert_eq!(
                tap_tweak(&internal_key, &merkle_root),
                hex_32(case.get("intermediary").get("tweak").as_str())
            );
            let leaf_hashes = case.get("intermediary").get("leafHashes").as_array();
            let control_blocks = case
                .get("expected")
                .get("scriptPathControlBlocks")
                .as_array();
            let leaves = leaves(tree);
            assert_eq!(leaves.len(), leaf_hashes.len());
            assert_eq!(leaves.len(), control_blocks.len());
            for (id, leaf) in leaves.iter().enumerate() {
                let leaf_hash = tapleaf_hash(leaf.version, &leaf.script);
                assert_eq!(leaf_hash, hex_32(leaf_hashes[id].as_str()));
                let control_bytes = control_blocks[id].as_bytes();
                let control = ControlBlock::parse(&control_bytes).expect("a published block");
                assert_eq!(control.leaf_version, leaf.version);
                assert_eq!(control.internal_key, &internal_key);
                assert_eq!(taproot_merkle_root(&control, &leaf_hash), merkle_root);
                assert!(verify_taproot_commitment(&control, &output_key, &leaf_hash));
                // The wrong parity, the wrong output key, another leaf's hash, and a
                // damaged path node all break the commitment.
                let mut flipped = control;
                flipped.output_parity_odd = !control.output_parity_odd;
                assert!(!verify_taproot_commitment(
                    &flipped,
                    &output_key,
                    &leaf_hash
                ));
                assert!(!verify_taproot_commitment(
                    &control,
                    &internal_key,
                    &leaf_hash
                ));
                let mut other_leaf = leaf_hash;
                other_leaf[0] ^= 1;
                assert!(!verify_taproot_commitment(
                    &control,
                    &output_key,
                    &other_leaf
                ));
                if control.path_len() > 0 {
                    let mut damaged = control_bytes.clone();
                    damaged[33] ^= 1;
                    let damaged = ControlBlock::parse(&damaged).expect("same size");
                    assert!(!verify_taproot_commitment(
                        &damaged,
                        &output_key,
                        &leaf_hash
                    ));
                }
                leaves_checked += 1;
            }
        }
        assert_eq!(leaves_checked, 12);
    }

    /// The tagged hashes agree with rust-bitcoin's, which is the oracle BM-D2 named for
    /// hashing; `0x50` is the one even version rust-bitcoin refuses and this code does not.
    #[test]
    fn tagged_hashes_match_rust_bitcoin() {
        let script = [0x51, 0x20];
        let expected =
            TapLeafHash::from_script(Script::from_bytes(&script), LeafVersion::TapScript);
        assert_eq!(tapleaf_hash(0xc0, &script), expected.to_byte_array());
        assert!(LeafVersion::from_consensus(0x50).is_err());
        assert_ne!(tapleaf_hash(0x50, &script), tapleaf_hash(0xc0, &script));

        let a = tapleaf_hash(0xc0, &[0x51]);
        let b = tapleaf_hash(0xc0, &[0x52]);
        let mut control = vec![0xc0];
        control.extend([0x02; 32]);
        control.extend(b);
        let control = ControlBlock::parse(&control).expect("one node");
        let expected = TapNodeHash::from_node_hashes(
            TapNodeHash::from_byte_array(a),
            TapNodeHash::from_byte_array(b),
        );
        assert_eq!(taproot_merkle_root(&control, &a), expected.to_byte_array());
        // The same pair the other way round hashes to the same node.
        let mut swapped = vec![0xc0];
        swapped.extend([0x02; 32]);
        swapped.extend(a);
        let swapped = ControlBlock::parse(&swapped).expect("one node");
        assert_eq!(taproot_merkle_root(&swapped, &b), expected.to_byte_array());

        let internal = hex_32("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27");
        let key = secp256k1::XOnlyPublicKey::from_slice(&internal).expect("on the curve");
        let expected = TapTweakHash::from_key_and_tweak(key, Some(TapNodeHash::from_byte_array(a)));
        assert_eq!(tap_tweak(&internal, &a), expected.to_byte_array());
    }

    #[test]
    fn control_block_sizes() {
        for path_len in [0usize, 1, 2, 128] {
            let bytes = vec![0xc1; 33 + 32 * path_len];
            let control = ControlBlock::parse(&bytes).expect("a valid size");
            assert_eq!(control.path_len(), path_len);
            assert_eq!(control.leaf_version, 0xc0);
            assert!(control.output_parity_odd);
            assert_eq!(control.internal_key, &[0xc1; 32]);
        }
        assert_eq!(TAPROOT_CONTROL_MAX_SIZE, 4129);
        for len in [0usize, 32, 34, 64, 66, 33 + 32 * 129] {
            assert_eq!(
                ControlBlock::parse(&vec![0xc0; len]),
                Err(ScriptError::TaprootWrongControlSize),
                "{len}"
            );
        }
    }

    /// Off-curve keys and an overflowing tweak are refused rather than trusted.
    #[test]
    fn commitment_refuses_keys_off_the_curve() {
        let leaf_hash = tapleaf_hash(0xc0, &[0x51]);
        // x = 5 has no square root on secp256k1; x = 0 neither.
        let mut off_curve = [0u8; 32];
        off_curve[31] = 5;
        let on_curve = hex_32("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let mut control = vec![0xc0];
        control.extend(off_curve);
        let control = ControlBlock::parse(&control).expect("base size");
        assert!(!verify_taproot_commitment(&control, &on_curve, &leaf_hash));
        let mut control = vec![0xc0];
        control.extend(on_curve);
        let control = ControlBlock::parse(&control).expect("base size");
        assert!(!verify_taproot_commitment(&control, &off_curve, &leaf_hash));
        assert!(!verify_taproot_commitment(&control, &[0; 32], &leaf_hash));
    }

    #[test]
    fn witness_size_is_the_serialized_size() {
        let cases: [Vec<Vec<u8>>; 6] = [
            vec![],
            vec![vec![]],
            vec![vec![0x50]],
            vec![vec![1; 252], vec![2; 253]],
            vec![vec![3; 65535], vec![4; 65536]],
            vec![vec![]; 300],
        ];
        for items in cases {
            let witness = Witness::from_slice(&items);
            assert_eq!(witness_serialized_size(&witness), serialize(&witness).len());
        }
    }
}
