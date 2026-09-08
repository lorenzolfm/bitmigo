// SPDX-License-Identifier: MIT OR Apache-2.0

//! The block merkle tree, Core's `ComputeMerkleRoot` (§2.4), with its mutation detector.
//!
//! Bitcoin's tree duplicates the last hash of an odd level, so a transaction list with its
//! tail repeated hashes to the same root as the honest list (CVE-2012-2459). Core defends by
//! noticing whenever it is about to hash two equal siblings and reporting the block as
//! mutated instead of invalid, so that the honest block with the same header can still
//! arrive. The witness tree (`BlockWitnessMerkleRoot`) is the same computation without the
//! detector, because the transaction tree already refuses the shape.

use bitcoin::hashes::{Hash, sha256d};

/// A merkle tree over `u32::MAX` leaves has this many levels; a block's leaf count is
/// bounded far below that by its size, so the loop below can never need more.
const MERKLE_LEVELS_MAX: usize = 32;

/// What [`merkle_root`] found: the root and whether any level hashed two equal siblings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleRoot {
    /// The root, or all zeros for no leaves.
    pub root: [u8; 32],
    /// True when two equal hashes sat side by side at any level (CVE-2012-2459).
    pub mutated: bool,
}

/// Core's `ComputeMerkleRoot(hashes, &mutated)`. Takes the leaves by value: each level is
/// built from the one below and replaces it.
#[must_use]
pub fn merkle_root(leaves: Vec<[u8; 32]>) -> MerkleRoot {
    let leaf_count = leaves.len();
    let mut level = leaves;
    let mut mutated = false;
    for _ in 0..=MERKLE_LEVELS_MAX {
        if level.len() <= 1 {
            break;
        }
        // Core checks the pairs before duplicating an odd tail, so the duplicate itself is
        // never the reason.
        let (pairs, _odd_tail) = level.as_chunks::<2>();
        for [left, right] in pairs {
            if left == right {
                mutated = true;
            }
        }
        if level.len() % 2 == 1 {
            let last = *level.last().expect("len > 1");
            level.push(last);
        }
        assert_eq!(level.len() % 2, 0);
        let (pairs, no_tail) = level.as_chunks::<2>();
        assert!(no_tail.is_empty());
        let parents: Vec<[u8; 32]> = pairs
            .iter()
            .map(|[left, right]| {
                let mut preimage = [0u8; 64];
                preimage[..32].copy_from_slice(left);
                preimage[32..].copy_from_slice(right);
                sha256d::Hash::hash(&preimage).to_byte_array()
            })
            .collect();
        assert_eq!(parents.len() * 2, level.len());
        level = parents;
    }
    assert!(level.len() <= 1);
    // One leaf is its own root and can never have been mutated.
    if leaf_count <= 1 {
        assert!(!mutated);
    }
    MerkleRoot {
        root: level.first().copied().unwrap_or([0u8; 32]),
        mutated,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash, sha256d};
    use bitcoin::merkle_tree::calculate_root;

    use super::merkle_root;

    fn leaf(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// The rust-bitcoin tree is the oracle for the root itself, one to nine leaves.
    #[test]
    fn root_matches_rust_bitcoin_for_every_small_leaf_count() {
        for count in 1..=9u8 {
            let leaves: Vec<[u8; 32]> = (1..=count).map(leaf).collect();
            let expected = calculate_root(
                leaves
                    .iter()
                    .map(|bytes| sha256d::Hash::from_byte_array(*bytes)),
            )
            .unwrap();
            let found = merkle_root(leaves);
            assert_eq!(found.root, expected.to_byte_array(), "{count}");
            assert!(!found.mutated, "{count}");
        }
    }

    #[test]
    fn no_leaves_give_the_zero_root() {
        let found = merkle_root(Vec::new());
        assert_eq!(found.root, [0u8; 32]);
        assert!(!found.mutated);
    }

    /// Core's own example: `[1,2,3,4,5,6]` and `[1,2,3,4,5,6,5,6]` share a root, and the
    /// second is flagged. A three-leaf list with its last leaf repeated is the smallest case.
    #[test]
    fn a_repeated_tail_keeps_the_root_and_sets_mutated() {
        let honest: Vec<[u8; 32]> = (1..=6).map(leaf).collect();
        let mut forged = honest.clone();
        forged.extend_from_slice(&[leaf(5), leaf(6)]);
        let honest_root = merkle_root(honest);
        let forged_root = merkle_root(forged);
        assert_eq!(honest_root.root, forged_root.root);
        assert!(!honest_root.mutated);
        assert!(forged_root.mutated);

        let small = merkle_root(vec![leaf(1), leaf(2), leaf(3)]);
        let small_forged = merkle_root(vec![leaf(1), leaf(2), leaf(3), leaf(3)]);
        assert_eq!(small.root, small_forged.root);
        assert!(small_forged.mutated);
    }

    /// Equal siblings anywhere, not only at the tail, are a mutation.
    #[test]
    fn equal_siblings_in_the_middle_are_a_mutation() {
        let found = merkle_root(vec![leaf(1), leaf(2), leaf(3), leaf(3), leaf(4), leaf(5)]);
        assert!(found.mutated);
        // Equal hashes that are not siblings are fine: positions 1 and 2 sit in different
        // pairs.
        let found = merkle_root(vec![leaf(1), leaf(2), leaf(2), leaf(3)]);
        assert!(!found.mutated);
    }
}
