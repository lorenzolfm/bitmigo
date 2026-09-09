// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for BIP325: the signet chain's own blocks as the positive oracle, one mutation of a
//! real block per way a solution can be wrong, and a round trip that signs a block under a
//! challenge of our own.
//!
//! The negative cases go through [`check_signet_solution`] rather than `check_block`, because
//! editing a block's coinbase moves its merkle root and therefore its hash: signet's target
//! admits about one hash in two million, so a mutated block cannot be re-mined in a test the
//! way a regtest one can. `check_block` is exercised on the unmutated blocks, where the proof
//! of work is bitcoind's.

#![allow(
    clippy::indexing_slicing,
    reason = "test fixtures index arrays and vectors whose lengths the tests assert"
)]

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::script::Builder;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Block, BlockHash, CompactTarget, Script, ScriptBuf, TxOut};
use secp256k1::{Message, Secp256k1, SecretKey};

use super::{
    BLOCK_SCRIPT_FLAGS, Cursor, DEFAULT_CHALLENGE, DEFAULT_CHALLENGE_HEX, SIGNET_HEADER,
    SignetError, check_signet_solution, default_block_challenge, default_challenge,
    fetch_and_clear_commitment_section, parse_solution, signet_txs,
};
use crate::block::{
    BlockError, WITNESS_COMMITMENT_SIZE_MIN, check_block, witness_commitment_index,
};
use crate::params::{BlockChallenge, Chain, ChainParams, Height, ScriptFlags};
use crate::script::{ScriptError, push_encoding, vectors::Json};

/// Four blocks of the signet BIP325 defines, taken from a synced `bitcoind -signet` v31.1.0
/// (`tests/data/README.md`): genesis, the first two blocks, and one 15-transaction block so
/// that the modified merkle root has real siblings and an odd level to duplicate.
const SIGNET_BLOCKS_JSON: &str = include_str!("../../../tests/data/signet-blocks.json");

struct Fixture {
    height: u32,
    hash: BlockHash,
    block: Block,
}

fn fixture() -> Vec<Fixture> {
    let rows = Json::parse(SIGNET_BLOCKS_JSON);
    let blocks: Vec<Fixture> = rows
        .as_array()
        .iter()
        .map(|row| Fixture {
            height: u32::try_from(row.get("height").as_i64()).unwrap(),
            hash: row.get("hash").as_str().parse().unwrap(),
            block: deserialize(&row.get("block").as_bytes()).unwrap(),
        })
        .collect();
    assert_eq!(blocks.len(), 4);
    blocks
}

fn signet() -> ChainParams {
    ChainParams::signet(default_challenge())
}

/// The one block of the fixture that has more than a coinbase.
fn crowded_block() -> Block {
    let block = fixture().pop().unwrap().block;
    assert_eq!(block.txdata.len(), 15);
    block
}

/// The commitment output of `block`'s coinbase, and its script.
fn commitment(block: &Block) -> (usize, &[u8]) {
    let coinbase = &block.txdata[0];
    let index = witness_commitment_index(coinbase).unwrap();
    (index, coinbase.output[index].script_pubkey.as_bytes())
}

/// Replaces the signet section of `block`'s coinbase commitment output with `solution`, or
/// removes it when `solution` is `None`.
///
/// Every fixture block's commitment script is BIP141's 38 bytes followed by exactly one
/// signet push, so the script Core leaves behind is those 38 bytes plus a push of the four
/// header bytes: the assertion below pins that shape, and the 38 bytes are the base a new
/// section is appended to. `the_fixture_helpers_are_faithful` checks the round trip.
fn set_solution(block: &mut Block, solution: Option<&[u8]>) {
    let (index, script) = commitment(block);
    let cleared = fetch_and_clear_commitment_section(Script::from_bytes(script)).unwrap();
    let base = cleared.replacement.as_bytes();
    assert_eq!(
        base.len(),
        WITNESS_COMMITMENT_SIZE_MIN + 1 + SIGNET_HEADER.len(),
    );
    let mut rewritten = base[..WITNESS_COMMITMENT_SIZE_MIN].to_vec();
    if let Some(solution) = solution {
        let mut push = SIGNET_HEADER.to_vec();
        push.extend_from_slice(solution);
        rewritten.extend_from_slice(&push_encoding(&push));
    }
    block.txdata[0].output[index].script_pubkey = ScriptBuf::from_bytes(rewritten);
}

/// The signet section of `block`'s coinbase commitment output: the solution bytes as mined.
fn solution_of(block: &Block) -> Vec<u8> {
    let (_, script) = commitment(block);
    fetch_and_clear_commitment_section(Script::from_bytes(script))
        .unwrap()
        .solution
}

/// The two helpers above rewrite a real block's commitment output, so they have to leave a
/// block that still verifies when the solution they put back is the mined one.
#[test]
fn the_fixture_helpers_are_faithful() {
    let mut block = crowded_block();
    let solution = solution_of(&block);
    // The mined push needs `OP_PUSHDATA1`, so this also covers the non-direct encoding.
    assert!(solution.len() + SIGNET_HEADER.len() > 75);
    set_solution(&mut block, Some(&solution));
    assert_eq!(check_signet_solution(&block, &default_challenge()), Ok(()));
    assert_eq!(solution_of(&block), solution);
}

// ---------------------------------------------------------------- chain parameters

#[test]
fn default_challenge_is_cores() {
    assert_eq!(DEFAULT_CHALLENGE_HEX.len(), 2 * DEFAULT_CHALLENGE.len());
    assert_eq!(DEFAULT_CHALLENGE.len(), 71);
    let challenge = default_challenge();
    assert_eq!(challenge.to_hex_string(), DEFAULT_CHALLENGE_HEX);
    // `OP_1 <33> <33> OP_2 OP_CHECKMULTISIG`: the 1-of-2 of BIP325's two signers.
    assert_eq!(challenge.as_bytes()[0], 0x51);
    assert_eq!(challenge.as_bytes()[1], 33);
    assert_eq!(challenge.as_bytes()[35], 33);
    assert_eq!(challenge.as_bytes()[69], 0x52);
    assert_eq!(challenge.as_bytes()[70], 0xae);
    assert_eq!(default_block_challenge(), BlockChallenge::Signet(challenge));
}

#[test]
fn signet_params_match_core() {
    let params = signet();
    assert_eq!(params.chain(), Chain::Signet);
    assert_eq!(
        params.genesis_hash().to_string(),
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    );
    assert_eq!(
        params.pow_limit().to_compact_lossy(),
        CompactTarget::from_consensus(0x1e03_77ae),
    );
    assert_eq!(params.pow_target_timespan(), 1_209_600);
    assert_eq!(params.pow_target_spacing(), 600);
    assert_eq!(params.difficulty_adjustment_interval(), 2016);
    assert!(!params.no_retargeting());
    assert!(!params.allow_min_difficulty());
    assert!(!params.enforce_bip94());
    assert_eq!(params.halving_interval(), 210_000);
    assert_eq!(params.bip34_height(), Height::new(1));
    assert_eq!(params.block_challenge(), &default_block_challenge());
}

/// Every buried deployment is at height 1, so block 1 already runs under every rule and
/// taproot is on from genesis (§5.2).
#[test]
fn every_deployment_is_buried_at_height_one() {
    let params = signet();
    let genesis = params.genesis_hash();
    let rules = params.rules_at(Height::new(1), genesis, None);
    assert!(rules.bip34_active());
    assert!(rules.csv_active());
    assert!(rules.segwit_active());
    assert_eq!(rules.script_flags(), ScriptFlags::MANDATORY);

    let rules = params.rules_at(Height::GENESIS, genesis, None);
    assert!(!rules.bip34_active());
    assert!(!rules.segwit_active());
    // Signet's BIP34 block has no hash, so the BIP30 scan never stops (§2.5).
    assert!(rules.bip30_check_required());
}

#[test]
fn mainnet_and_regtest_carry_no_challenge() {
    assert_eq!(
        ChainParams::mainnet().block_challenge(),
        &BlockChallenge::None
    );
    let regtest = ChainParams::regtest(crate::params::RegtestOverrides::default());
    assert_eq!(regtest.block_challenge(), &BlockChallenge::None);
}

// ---------------------------------------------------------------- the real chain

/// bitcoind's own signet blocks pass the whole of `check_block`, solution included. This is
/// the oracle: agreement with the chain Core validates.
#[test]
fn signet_blocks_pass_check_block() {
    let params = signet();
    for row in fixture() {
        assert_eq!(row.block.block_hash(), row.hash, "height {}", row.height);
        assert_eq!(
            check_block(&row.block, &params),
            Ok(()),
            "height {}",
            row.height
        );
    }
}

/// The same blocks, through the solution check alone, so the verdict cannot be coming from
/// somewhere else in `check_block`. Genesis is not among them: it is the exempt one.
#[test]
fn signet_blocks_carry_a_valid_solution() {
    let challenge = default_challenge();
    for row in fixture().iter().skip(1) {
        assert!(row.height > 0);
        assert_eq!(
            check_signet_solution(&row.block, &challenge),
            Ok(()),
            "height {}",
            row.height,
        );
        // A mined solution is a scriptSig and no witness: the challenge is bare multisig.
        let txs = signet_txs(&row.block, &challenge).unwrap();
        assert!(!txs.to_sign.input[0].script_sig.is_empty());
        assert!(txs.to_sign.input[0].witness.is_empty());
        assert_eq!(
            txs.spent_output(),
            &TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: challenge.clone()
            }
        );
    }
}

/// Genesis has no solution to check and Core says so before building anything, so it passes
/// under a challenge nothing could satisfy.
#[test]
fn genesis_is_exempt_from_the_challenge() {
    let genesis = &fixture()[0];
    assert_eq!(genesis.height, 0);
    let params = ChainParams::signet(ScriptBuf::from_bytes(vec![0x00]));
    assert_eq!(check_block(&genesis.block, &params), Ok(()));
    // Without the exemption it would fail: genesis has no witness commitment at all.
    assert_eq!(
        check_signet_solution(&genesis.block, &default_challenge()),
        Err(SignetError::NoWitnessCommitment),
    );
}

/// Mainnet's parameters take the `None` arm, so a mainnet block never looks for a solution.
/// Its genesis passes `check_block` as it did before signet existed.
#[test]
fn mainnet_takes_the_none_arm() {
    let params = ChainParams::mainnet();
    assert_eq!(check_block(params.genesis(), &params), Ok(()));
}

// ---------------------------------------------------------------- one mutation per rule

#[test]
fn a_stripped_solution_is_rejected() {
    let mut block = crowded_block();
    set_solution(&mut block, None);
    // No section at all: the solution is an empty scriptSig, which leaves the multisig
    // reaching past the bottom of the stack.
    let error = check_signet_solution(&block, &default_challenge()).unwrap_err();
    assert_eq!(
        error,
        SignetError::Script(ScriptError::InvalidStackOperation)
    );
    assert_eq!(error.to_string(), "bad-signet-blksig");
}

#[test]
fn a_forged_solution_is_rejected() {
    let mut block = crowded_block();
    let mut solution = solution_of(&block);
    // The last three bytes of a mined solution are the end of `S`, the sighash byte and the
    // witness item count; flipping the low bit of `S` keeps the DER encoding and the
    // framing valid, so this reaches the interpreter rather than the deserializer.
    let in_s = solution.len() - 3;
    solution[in_s] ^= 1;
    set_solution(&mut block, Some(&solution));
    let error = check_signet_solution(&block, &default_challenge()).unwrap_err();
    assert!(matches!(error, SignetError::Script(_)), "{error:?}");
}

#[test]
fn the_wrong_challenge_rejects_a_real_block() {
    let block = crowded_block();
    // The default challenge with its two public keys swapped: same shape, wrong keys.
    let mut bytes = DEFAULT_CHALLENGE;
    let (first, second) = (bytes[2..35].to_vec(), bytes[36..69].to_vec());
    bytes[2..35].copy_from_slice(&second);
    bytes[36..69].copy_from_slice(&first);
    let wrong = ScriptBuf::from_bytes(bytes.to_vec());
    assert_ne!(wrong, default_challenge());

    let error = check_signet_solution(&block, &wrong).unwrap_err();
    assert!(matches!(error, SignetError::Script(_)), "{error:?}");
    // Through `check_block`, the reason is the block's.
    let params = ChainParams::signet(wrong);
    assert_eq!(
        check_block(&block, &params).unwrap_err().to_string(),
        "bad-signet-blksig",
    );
}

/// The solution commits to the block's version, previous hash, merkle root and time; the
/// nonce is left out on purpose, so a signed block can be re-mined.
#[test]
fn the_solution_commits_to_the_header_but_not_the_nonce() {
    let challenge = default_challenge();
    let block = crowded_block();
    let mut wrong_version = block.clone();
    wrong_version.header.version = bitcoin::block::Version::from_consensus(4);
    assert!(check_signet_solution(&wrong_version, &challenge).is_err());

    let mut wrong_time = block.clone();
    wrong_time.header.time += 1;
    assert!(check_signet_solution(&wrong_time, &challenge).is_err());

    let mut wrong_parent = block.clone();
    wrong_parent.header.prev_blockhash = BlockHash::all_zeros();
    assert!(check_signet_solution(&wrong_parent, &challenge).is_err());

    let mut renonced = block.clone();
    renonced.header.nonce ^= 0xffff_ffff;
    assert_eq!(check_signet_solution(&renonced, &challenge), Ok(()));
}

/// Every transaction in the block is committed to through the modified merkle root, siblings
/// of the coinbase included.
#[test]
fn the_solution_commits_to_every_transaction() {
    let mut block = crowded_block();
    block.txdata.pop();
    assert_eq!(block.txdata.len(), 14);
    assert!(check_signet_solution(&block, &default_challenge()).is_err());
}

#[test]
fn a_block_with_no_witness_commitment_is_rejected() {
    let mut block = crowded_block();
    let (index, _) = commitment(&block);
    block.txdata[0].output.remove(index);
    assert_eq!(
        check_signet_solution(&block, &default_challenge()),
        Err(SignetError::NoWitnessCommitment),
    );
}

/// Core builds the two transactions before the size limits run, so a block with no
/// transactions at all reaches this code.
#[test]
fn a_block_with_no_coinbase_is_rejected() {
    let mut block = crowded_block();
    block.txdata.clear();
    assert_eq!(
        check_signet_solution(&block, &default_challenge()),
        Err(SignetError::CoinbaseMissing),
    );
    // And through `check_block`, before `bad-blk-length` gets a chance.
    let error = check_block(&block, &signet()).unwrap_err();
    assert_eq!(error, BlockError::Signet(SignetError::CoinbaseMissing));
}

#[test]
fn extraneous_solution_data_is_rejected() {
    let mut block = crowded_block();
    let mut solution = solution_of(&block);
    solution.push(0x00);
    set_solution(&mut block, Some(&solution));
    assert_eq!(
        check_signet_solution(&block, &default_challenge()),
        Err(SignetError::ExtraneousSolutionData { extra: 1 }),
    );
}

#[test]
fn a_truncated_solution_is_rejected() {
    let mut block = crowded_block();
    let solution = solution_of(&block);
    for keep in [1, solution.len() / 2, solution.len() - 1] {
        set_solution(&mut block, Some(&solution[..keep]));
        assert_eq!(
            check_signet_solution(&block, &default_challenge()),
            Err(SignetError::MalformedSolution),
            "{keep} bytes kept",
        );
    }
}

/// Core allows a commitment output with no signet section, so that a challenge anyone can
/// satisfy needs no solution at all.
#[test]
fn a_trivial_challenge_needs_no_solution() {
    let mut block = crowded_block();
    set_solution(&mut block, None);
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    assert_eq!(check_signet_solution(&block, &op_true), Ok(()));

    // A section that is present is still parsed, trivial challenge or not.
    let mut with_junk = crowded_block();
    set_solution(&mut with_junk, Some(&[0x05]));
    assert_eq!(
        check_signet_solution(&with_junk, &op_true),
        Err(SignetError::MalformedSolution),
    );
}

// ---------------------------------------------------------------- signing a block

/// The other direction: sign a block under a challenge of our own and check that the
/// solution we assemble satisfies it, then that one changed byte does not. This exercises
/// the `to_spend` and `to_sign` layout end to end, with rust-bitcoin's `SighashCache` as the
/// oracle for the digest.
#[test]
fn a_block_signed_under_our_own_challenge_passes() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[0x2b; 32]).unwrap();
    let public = secret.public_key(&secp);
    let challenge = Builder::new()
        .push_slice(public.serialize())
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script();

    // A solution of an empty scriptSig and an empty witness stack: enough for `signet_txs`
    // to parse, and the section is stripped to its four header bytes either way, so the
    // modified coinbase — and therefore the digest — is the same as with the real one.
    let mut block = crowded_block();
    set_solution(&mut block, Some(&[0x00, 0x00]));
    let txs = signet_txs(&block, &challenge).unwrap();
    let digest = SighashCache::new(&txs.to_sign)
        .legacy_signature_hash(0, &challenge, EcdsaSighashType::All.to_u32())
        .unwrap();
    let signature = secp.sign_ecdsa(&Message::from_digest(digest.to_byte_array()), &secret);

    let mut script_sig = signature.serialize_der().to_vec();
    script_sig.push(EcdsaSighashType::All.to_u32().try_into().unwrap());
    let script_sig = Builder::new()
        .push_slice(<&bitcoin::script::PushBytes>::try_from(script_sig.as_slice()).unwrap())
        .into_script();

    let mut solution = vec![u8::try_from(script_sig.len()).unwrap()];
    solution.extend_from_slice(script_sig.as_bytes());
    // No witness items.
    solution.push(0x00);

    set_solution(&mut block, Some(&solution));
    assert_eq!(check_signet_solution(&block, &challenge), Ok(()));

    // One byte of the signature, and it is no longer a solution.
    let last = solution.len() - 2;
    solution[last] ^= 0x08;
    set_solution(&mut block, Some(&solution));
    assert!(check_signet_solution(&block, &challenge).is_err());
}

/// The solution is verified under exactly Core's four flags, at every height: no CLTV, no
/// CSV, and no taproot, so a v1 witness program in a challenge is anyone-can-spend.
#[test]
fn the_solution_runs_under_cores_four_flags() {
    assert_eq!(
        BLOCK_SCRIPT_FLAGS,
        ScriptFlags::P2SH
            .union(ScriptFlags::WITNESS)
            .union(ScriptFlags::DERSIG)
            .union(ScriptFlags::NULLDUMMY),
    );
    assert!(!BLOCK_SCRIPT_FLAGS.contains(ScriptFlags::TAPROOT));
    assert!(!BLOCK_SCRIPT_FLAGS.contains(ScriptFlags::CHECKLOCKTIMEVERIFY));
    assert!(!BLOCK_SCRIPT_FLAGS.contains(ScriptFlags::CHECKSEQUENCEVERIFY));
}

// ---------------------------------------------------------------- the two parsers

/// Only the first push carrying the header *and* some data counts, and the header stays
/// behind in the rewritten script.
#[test]
fn only_the_first_signet_push_is_taken() {
    let script = ScriptBuf::from_bytes(
        [
            &[0x6a][..],
            &[0x05, 0xec, 0xc7, 0xda, 0xa2, 0x41][..],
            &[0x05, 0xec, 0xc7, 0xda, 0xa2, 0x42][..],
        ]
        .concat(),
    );
    let cleared = fetch_and_clear_commitment_section(&script).unwrap();
    assert_eq!(cleared.solution, vec![0x41]);
    assert_eq!(
        cleared.replacement.as_bytes(),
        [
            &[0x6a][..],
            &[0x04, 0xec, 0xc7, 0xda, 0xa2][..],
            &[0x05, 0xec, 0xc7, 0xda, 0xa2, 0x42][..],
        ]
        .concat(),
    );
}

/// A push of exactly the header carries no data, so it is not a section.
#[test]
fn a_header_with_no_data_is_not_a_section() {
    let script = ScriptBuf::from_bytes(vec![0x04, 0xec, 0xc7, 0xda, 0xa2]);
    assert!(fetch_and_clear_commitment_section(&script).is_none());
}

/// Rewriting re-serializes every push minimally, so a non-minimal push elsewhere in the
/// commitment script changes the modified coinbase and therefore the digest.
#[test]
fn the_rewrite_makes_every_push_minimal() {
    // `OP_PUSHDATA1 1 0x41` is a non-minimal encoding of the one-byte push `0x01 0x41`.
    let script = ScriptBuf::from_bytes(vec![0x4c, 0x01, 0x41, 0x05, 0xec, 0xc7, 0xda, 0xa2, 0x42]);
    let cleared = fetch_and_clear_commitment_section(&script).unwrap();
    assert_eq!(cleared.solution, vec![0x42]);
    assert_eq!(
        cleared.replacement.as_bytes(),
        [0x01, 0x41, 0x04, 0xec, 0xc7, 0xda, 0xa2],
    );
}

/// Core's script walk stops at a push that runs past the end of the script and keeps only
/// what it read, so the tail is dropped from the rewritten script.
#[test]
fn a_truncated_push_drops_the_tail() {
    let script = ScriptBuf::from_bytes(vec![
        0x05, 0xec, 0xc7, 0xda, 0xa2, 0x42, // the section
        0x51, // OP_1
        0x10, 0x00, // a 16-byte push with 1 byte of data
    ]);
    let cleared = fetch_and_clear_commitment_section(&script).unwrap();
    assert_eq!(cleared.solution, vec![0x42]);
    assert_eq!(
        cleared.replacement.as_bytes(),
        [0x04, 0xec, 0xc7, 0xda, 0xa2, 0x51],
    );
}

/// An empty push is written back as its opcode byte, which for `OP_PUSHDATA1` leaves a
/// truncated push in the rewritten script. Core does exactly this.
#[test]
fn an_empty_push_is_written_back_as_its_opcode() {
    let script = ScriptBuf::from_bytes(vec![
        0x00, // OP_0
        0x4c, 0x00, // OP_PUSHDATA1 of nothing
        0x05, 0xec, 0xc7, 0xda, 0xa2, 0x42,
    ]);
    let cleared = fetch_and_clear_commitment_section(&script).unwrap();
    assert_eq!(
        cleared.replacement.as_bytes(),
        [0x00, 0x4c, 0x04, 0xec, 0xc7, 0xda, 0xa2],
    );
}

#[test]
fn a_solution_round_trips_through_the_parser() {
    // scriptSig `OP_1`, then two witness items.
    let solution = [
        &[0x01, 0x51][..],
        &[0x02][..],
        &[0x03, 0xaa, 0xbb, 0xcc][..],
        &[0x00][..],
    ]
    .concat();
    let (script_sig, witness) = parse_solution(&solution).unwrap();
    assert_eq!(script_sig.as_bytes(), [0x51]);
    assert_eq!(witness.len(), 2);
    assert_eq!(witness.nth(0).unwrap(), [0xaa, 0xbb, 0xcc]);
    assert!(witness.nth(1).unwrap().is_empty());
}

#[test]
fn an_empty_solution_is_not_a_solution() {
    assert_eq!(parse_solution(&[]), Err(SignetError::MalformedSolution));
    // A scriptSig and nothing where the stack count should be.
    assert_eq!(parse_solution(&[0x00]), Err(SignetError::MalformedSolution));
    // The shortest well-formed one: no scriptSig, no witness items.
    assert_eq!(
        parse_solution(&[0x00, 0x00]),
        Ok((ScriptBuf::new(), bitcoin::Witness::new())),
    );
}

/// A witness item count larger than the bytes left cannot be satisfied, and must not be
/// allocated for either.
#[test]
fn an_impossible_witness_count_is_rejected() {
    assert_eq!(
        parse_solution(&[0x00, 0xfd, 0xff, 0xff]),
        Err(SignetError::MalformedSolution),
    );
}

/// Core's `ReadCompactSize` rejects any encoding longer than the value needs.
#[test]
fn compact_sizes_must_be_canonical() {
    let read = |bytes: &[u8]| Cursor::new(bytes).read_compact_size();
    assert_eq!(read(&[0x00]), Ok(0));
    assert_eq!(read(&[0xfc]), Ok(252));
    assert_eq!(read(&[0xfd, 0xfd, 0x00]), Ok(253));
    assert_eq!(read(&[0xfd, 0x00, 0x01]), Ok(256));
    assert_eq!(read(&[0xfe, 0x00, 0x00, 0x01, 0x00]), Ok(0x1_0000));

    // 253 encoded in three bytes, and 0x10000 in five: both non-canonical.
    assert_eq!(
        read(&[0xfd, 0xfc, 0x00]),
        Err(SignetError::MalformedSolution)
    );
    assert_eq!(
        read(&[0xfe, 0xff, 0xff, 0x00, 0x00]),
        Err(SignetError::MalformedSolution),
    );
    assert_eq!(
        read(&[0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
        Err(SignetError::MalformedSolution),
    );
    // Above `MAX_SIZE`.
    assert_eq!(
        read(&[0xfe, 0x00, 0x00, 0x00, 0x03]),
        Err(SignetError::MalformedSolution),
    );
    // And a size field that runs off the end.
    assert_eq!(read(&[0xfd, 0x01]), Err(SignetError::MalformedSolution));
}
