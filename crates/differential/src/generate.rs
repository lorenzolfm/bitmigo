// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unstructured cases: scripts drawn from the opcode table, witnesses drawn from bytes,
//! flags drawn from the lattice.
//!
//! These cases almost always fail, and that is their job: they walk the interpreter's error
//! paths, where a one-off in a limit or a missing `BAD_OPCODE` shows up as a disagreement
//! about *which* way a script fails, and the fuzzer compares the boolean, so they show up
//! as a disagreement about *whether* it does under some flag set. The draw is biased toward
//! pushes, conditionals, hashes and signature opcodes, the operations with the most rules
//! around them, and the scriptSig echoes data from the scriptPubKey so that `EQUAL` and the
//! hash comparisons sometimes hold. Signed spends that succeed are `templates`' job.

use bitcoin::hashes::{Hash, hash160, sha256};
use bitmigo_consensus::script::ScriptFlags;

use crate::case::{Case, MAX_MONEY, WITNESS_ITEMS_MAX};
use crate::prng::Prng;

/// The most operations one random script holds.
pub const OPS_MAX: usize = 48;
/// The longest data a random `PUSHDATA` carries: past `MAX_SCRIPT_ELEMENT_SIZE` (520) so
/// that `PUSH_SIZE` is reachable, and not much past, so that cases stay quick.
pub const PUSH_LEN_MAX: usize = 600;

/// The seven consensus flags, for walking the lattice.
pub const FLAGS: [ScriptFlags; 7] = [
    ScriptFlags::P2SH,
    ScriptFlags::DERSIG,
    ScriptFlags::NULLDUMMY,
    ScriptFlags::CHECKLOCKTIMEVERIFY,
    ScriptFlags::CHECKSEQUENCEVERIFY,
    ScriptFlags::WITNESS,
    ScriptFlags::TAPROOT,
];

/// Control flow: the rules around `IF` are where unexecuted branches still fail.
const FLOW_OPCODES: [u8; 8] = [0x63, 0x64, 0x67, 0x68, 0x69, 0x63, 0x64, 0x68];
/// The five hash opcodes.
const HASH_OPCODES: [u8; 5] = [0xa6, 0xa7, 0xa8, 0xa9, 0xaa];
/// Signature and time-lock opcodes, `CODESEPARATOR` and `CHECKSIGADD` included.
const SIGNATURE_OPCODES: [u8; 8] = [0xac, 0xad, 0xae, 0xaf, 0xab, 0xba, 0xb1, 0xb2];
/// Every enabled stack, arithmetic and no-op opcode.
const PLAIN_OPCODES: [u8; 55] = [
    0x61, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
    0x7a, 0x7b, 0x7c, 0x7d, 0x82, 0x87, 0x88, 0x8b, 0x8c, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x9a,
    0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xb0, 0xb3, 0xb4, 0xb5, 0xb6,
    0xb7, 0xb8, 0xb9, 0x87, 0x88, 0x76, 0x75,
];

/// A subset of `MANDATORY` honouring both implications: one quarter of the time all seven
/// flags, since that is what every block since taproot is verified under; otherwise each
/// flag with probability one half, then trimmed.
pub fn random_flags(prng: &mut Prng) -> ScriptFlags {
    if prng.chance(1, 4) {
        return ScriptFlags::MANDATORY;
    }
    let mut flags = ScriptFlags::NONE;
    for flag in FLAGS {
        if prng.chance(1, 2) {
            flags = flags.union(flag);
        }
    }
    honour_implications(flags)
}

/// Drops `WITNESS` without `P2SH` and `TAPROOT` without `WITNESS`: the two pairs Core's
/// `GetBlockScriptFlags` never produces and bitmigo's interpreter refuses.
#[must_use]
pub fn honour_implications(flags: ScriptFlags) -> ScriptFlags {
    let mut trimmed = flags;
    if !trimmed.contains(ScriptFlags::P2SH) {
        trimmed = trimmed.difference(ScriptFlags::WITNESS);
    }
    if !trimmed.contains(ScriptFlags::WITNESS) {
        trimmed = trimmed.difference(ScriptFlags::TAPROOT);
    }
    assert!(trimmed.is_subset_of(flags));
    trimmed
}

/// Appends a push of `data` to `script`, minimally encoded except that the empty push is
/// `OP_0` and one-byte pushes stay data pushes, as Core's `CScript << vector` does.
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    assert!(
        data.len() <= u16::MAX.into(),
        "no PUSHDATA4 in generated scripts"
    );
    let len = data.len();
    if len == 0 {
        script.push(0x00);
    } else if len <= 75 {
        script.push(u8::try_from(len).expect("at most 75"));
    } else if len <= 255 {
        script.push(0x4c);
        script.push(u8::try_from(len).expect("at most 255"));
    } else {
        script.push(0x4d);
        script.extend(u16::try_from(len).expect("at most 65535").to_le_bytes());
    }
    script.extend(data);
}

/// One random operation appended to `script`, drawn by class.
fn random_op(prng: &mut Prng, script: &mut Vec<u8>, pool: &[Vec<u8>]) {
    match prng.below(32) {
        0..=6 => {
            let len = prng.below_usize(76);
            push_data(script, &prng.bytes(len));
        }
        7 => {
            let len = if prng.chance(1, 4) {
                *prng.pick(&[519, 520, 521, PUSH_LEN_MAX])
            } else {
                prng.below_usize(PUSH_LEN_MAX + 1)
            };
            push_data(script, &prng.bytes(len));
        }
        8..=9 => {
            if pool.is_empty() {
                script.push(0x51);
            } else {
                push_data(script, prng.pick(pool));
            }
        }
        10..=12 => script.push(*prng.pick(&[0x00, 0x4f, 0x51, 0x52, 0x53, 0x60])),
        13..=16 => script.push(*prng.pick(&FLOW_OPCODES)),
        17..=19 => script.push(*prng.pick(&HASH_OPCODES)),
        20..=23 => script.push(*prng.pick(&SIGNATURE_OPCODES)),
        24..=28 => script.push(*prng.pick(&PLAIN_OPCODES)),
        _ => script.push(prng.next_u8()),
    }
}

/// A script of up to `ops_max` operations. `pool` holds data items the script may push
/// verbatim, so that a scriptSig can echo what its scriptPubKey compares against.
pub fn random_script(prng: &mut Prng, ops_max: usize, pool: &[Vec<u8>]) -> Vec<u8> {
    assert!(ops_max <= OPS_MAX);
    let op_count = prng.below_usize(ops_max + 1);
    let mut script = Vec::new();
    for _ in 0..op_count {
        random_op(prng, &mut script, pool);
    }
    script
}

/// The data items a script pushes, in order, read with the same length rules the
/// interpreter uses; a truncated push ends the walk. These are what the other side of an
/// `EQUAL` most profitably echoes.
#[must_use]
pub fn pushed_items(script: &[u8]) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    let mut position = 0;
    // Every step consumes at least one byte, so the script length bounds the loop.
    for _ in 0..script.len() {
        let Some(&opcode) = script.get(position) else {
            break;
        };
        let (len, header) = match opcode {
            0x01..=0x4b => (usize::from(opcode), 1),
            0x4c => (script.get(position + 1).map_or(0, |&b| usize::from(b)), 2),
            0x4d => {
                let low = script.get(position + 1).copied().unwrap_or(0);
                let high = script.get(position + 2).copied().unwrap_or(0);
                (usize::from(u16::from_le_bytes([low, high])), 3)
            }
            0x4e => break,
            _ => (0, 1),
        };
        let start = position + header;
        let end = start + len;
        if end > script.len() {
            break;
        }
        if len > 0 {
            items.push(script.get(start..end).expect("end <= len").to_vec());
        }
        position = end;
    }
    assert!(position <= script.len());
    items
}

/// A witness of up to eight items: random bytes, echoed pool items, and the sizes that
/// matter (empty, 1, 32, 33, 64, 65 bytes, and the 520-byte edge).
pub fn random_witness(prng: &mut Prng, pool: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let item_count = prng.below_usize(9);
    let mut witness = Vec::with_capacity(item_count);
    for _ in 0..item_count {
        let item = match prng.below(8) {
            0..=2 => {
                let len = prng.below_usize(81);
                prng.bytes(len)
            }
            3 => {
                let len = *prng.pick(&[0, 1, 32, 33, 64, 65, 520, 521]);
                prng.bytes(len)
            }
            4 => vec![*prng.pick(&[0x00, 0x01, 0x50, 0x51, 0x80, 0xc0, 0xc1])],
            _ if !pool.is_empty() => prng.pick(pool).clone(),
            _ => {
                let len = prng.below_usize(20);
                prng.bytes(len)
            }
        };
        witness.push(item);
    }
    assert!(witness.len() <= WITNESS_ITEMS_MAX);
    witness
}

/// The output-side shape of an unstructured case.
enum Shape {
    /// The random script is the scriptPubKey itself.
    Bare,
    /// The random script is a P2SH redeem script, pushed last in the scriptSig.
    P2sh,
    /// The random script is a P2WSH witness script, last in the witness.
    P2wsh,
    /// A witness program of a random version and length: v1 with 32 bytes is a taproot
    /// output nothing commits to, everything else is anyone-can-spend or malformed.
    WitnessProgram,
}

/// One unstructured case.
pub fn random_case(prng: &mut Prng) -> Case {
    let shape = match prng.below(8) {
        0..=3 => Shape::Bare,
        4..=5 => Shape::P2sh,
        6 => Shape::P2wsh,
        _ => Shape::WitnessProgram,
    };
    let inner = random_script(prng, OPS_MAX, &[]);
    let pool = pushed_items(&inner);
    let solve_ops = prng.below_usize(9);
    let mut script_sig = random_script(prng, solve_ops, &pool);
    let mut witness = if prng.chance(1, 3) {
        Vec::new()
    } else {
        random_witness(prng, &pool)
    };
    let script_pubkey = match shape {
        Shape::Bare => inner,
        Shape::P2sh => {
            push_data(&mut script_sig, &inner);
            p2sh(&inner)
        }
        Shape::P2wsh => {
            witness.push(inner.clone());
            let mut program = vec![0x00, 0x20];
            program.extend(sha256::Hash::hash(&inner).to_byte_array());
            program
        }
        Shape::WitnessProgram => {
            let version = *prng.pick(&[0x51, 0x51, 0x52, 0x60, 0x00]);
            let len = *prng.pick(&[32, 32, 20, 2, 40, 41, 1]);
            let mut program = vec![version];
            push_data(&mut program, &prng.bytes(len));
            program
        }
    };
    let amount = if prng.chance(1, 8) {
        *prng.pick(&[0, 1, MAX_MONEY])
    } else {
        prng.below(MAX_MONEY + 1)
    };
    Case {
        flags: random_flags(prng),
        script_pubkey,
        amount,
        script_sig,
        witness,
    }
}

/// `HASH160 <hash160(redeem)> EQUAL`.
#[must_use]
pub fn p2sh(redeem: &[u8]) -> Vec<u8> {
    let mut script = vec![0xa9, 0x14];
    script.extend(hash160::Hash::hash(redeem).to_byte_array());
    script.push(0x87);
    assert_eq!(script.len(), 23);
    script
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index out of bounds fails the test with a panic, as intended"
    )]

    use bitmigo_consensus::script::ScriptFlags;

    use super::{FLAGS, honour_implications, push_data, pushed_items, random_case, random_flags};
    use crate::prng::Prng;

    #[test]
    fn flags_honour_both_implications() {
        let mut prng = Prng::new(3);
        let mut seen_mandatory = false;
        for _ in 0..500 {
            let flags = random_flags(&mut prng);
            assert!(flags.is_subset_of(ScriptFlags::MANDATORY));
            if flags.contains(ScriptFlags::WITNESS) {
                assert!(flags.contains(ScriptFlags::P2SH));
            }
            if flags.contains(ScriptFlags::TAPROOT) {
                assert!(flags.contains(ScriptFlags::WITNESS));
            }
            seen_mandatory |= flags == ScriptFlags::MANDATORY;
        }
        assert!(seen_mandatory);
        let all_but_p2sh = FLAGS
            .iter()
            .skip(1)
            .fold(ScriptFlags::NONE, |a, f| a.union(*f));
        let trimmed = honour_implications(all_but_p2sh);
        assert!(!trimmed.contains(ScriptFlags::WITNESS));
        assert!(!trimmed.contains(ScriptFlags::TAPROOT));
        assert!(trimmed.contains(ScriptFlags::DERSIG));
    }

    #[test]
    fn push_encodings_match_core() {
        let mut script = Vec::new();
        push_data(&mut script, &[]);
        push_data(&mut script, &[7]);
        push_data(&mut script, &[1; 75]);
        push_data(&mut script, &[2; 76]);
        push_data(&mut script, &[3; 256]);
        assert_eq!(script[0], 0x00);
        assert_eq!(&script[1..3], &[0x01, 7]);
        assert_eq!(script[3], 75);
        assert_eq!(&script[79..81], &[0x4c, 76]);
        assert_eq!(&script[157..160], &[0x4d, 0x00, 0x01]);
        let items = pushed_items(&script);
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], vec![7]);
        assert_eq!(items[3].len(), 256);
    }

    #[test]
    fn pushed_items_stop_at_a_truncated_push() {
        assert_eq!(pushed_items(&[0x02, 0xaa]), Vec::<Vec<u8>>::new());
        assert_eq!(pushed_items(&[0x01, 0xaa, 0x4c]), vec![vec![0xaa]]);
        assert!(pushed_items(&[0x4e, 1, 0, 0, 0, 9]).is_empty());
    }

    #[test]
    fn random_cases_are_bounded_and_both_shapes_appear() {
        let mut prng = Prng::new(11);
        let mut with_witness = 0;
        for _ in 0..300 {
            let case = random_case(&mut prng);
            case.assert_bounded();
            with_witness += usize::from(!case.witness.is_empty());
        }
        assert!(with_witness > 100);
    }
}
