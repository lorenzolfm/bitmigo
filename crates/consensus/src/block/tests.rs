// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the two block stages: bitcoind's own regtest blocks as the oracle for the
//! positive path, and one mutation of a real block per rule for the negative one.

#![allow(
    clippy::indexing_slicing,
    reason = "test fixtures index arrays and vectors whose lengths the tests assert"
)]

use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use super::{
    BlockError, WITNESS_COMMITMENT_SIZE_MIN, accept_block, check_block, height_script,
    witness_commitment_index, witness_root,
};
use crate::header::{Context, HeaderError, check_header};
use crate::params::{BlockTime, ChainParams, Height, RegtestOverrides};
use crate::script::vectors::Json;
use crate::tx::{MAX_BLOCK_WEIGHT, MAX_MONEY, TxError};

/// Seven regtest blocks mined by bitcoind v31.1.0 (`tests/data/README.md`): genesis, two
/// coinbase-only blocks, and three blocks after maturity that spend coins with and without
/// witnesses, then one more coinbase-only block.
const REGTEST_BLOCKS_JSON: &str = include_str!("../../tests/data/regtest-blocks.json");

struct Fixture {
    height: u32,
    hash: BlockHash,
    block: Block,
    previous_time: BlockTime,
    previous_median_time_past: BlockTime,
}

fn fixture() -> Vec<Fixture> {
    let rows = Json::parse(REGTEST_BLOCKS_JSON);
    rows.as_array()
        .iter()
        .map(|row| {
            let height = u32::try_from(row.get("height").as_i64()).unwrap();
            let time = |key: &str| BlockTime::new(u32::try_from(row.get(key).as_i64()).unwrap());
            Fixture {
                height,
                hash: row.get("hash").as_str().parse().unwrap(),
                block: deserialize(&row.get("block").as_bytes()).unwrap(),
                previous_time: if height > 0 {
                    time("previous_time")
                } else {
                    time("time")
                },
                previous_median_time_past: if height > 0 {
                    time("previous_mediantime")
                } else {
                    time("mediantime")
                },
            }
        })
        .collect()
}

fn regtest() -> ChainParams {
    ChainParams::regtest(RegtestOverrides::default())
}

/// The context the node would build for `row`'s block on `params`, at `height`.
fn context_at(params: &ChainParams, row: &Fixture, height: u32) -> Context {
    let height = Height::new(height);
    Context::new(
        height,
        row.previous_median_time_past,
        row.previous_time,
        row.block.header.bits,
        params.rules_at(height, row.block.block_hash(), None),
    )
}

fn context(params: &ChainParams, row: &Fixture) -> Context {
    context_at(params, row, row.height)
}

/// Regtest's target lets about half of all hashes through, so a mutated header needs a
/// few nonces before it passes `check_header` again.
fn mine(block: &mut Block, params: &ChainParams) {
    for nonce in 0..10_000u32 {
        block.header.nonce = nonce;
        if check_header(&block.header, params).is_ok() {
            return;
        }
    }
    panic!("no nonce found in 10,000 tries");
}

/// Rewrites the header's merkle root from the transactions, using rust-bitcoin's tree as
/// the oracle, and mines the header.
fn seal(block: &mut Block, params: &ChainParams) {
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    mine(block, params);
}

/// Rewrites the coinbase's witness commitment from the transactions, with rust-bitcoin as
/// the oracle for both the witness root and the commitment hash.
fn recommit(block: &mut Block) {
    let position = witness_commitment_index(&block.txdata[0]).unwrap();
    let nonce = block.txdata[0].input[0].witness.nth(0).unwrap().to_vec();
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &nonce);
    let script = block.txdata[0].output[position].script_pubkey.to_bytes();
    let mut rewritten = script[..6].to_vec();
    rewritten.extend_from_slice(commitment.as_byte_array());
    rewritten.extend_from_slice(&script[WITNESS_COMMITMENT_SIZE_MIN..]);
    block.txdata[0].output[position].script_pubkey = ScriptBuf::from_bytes(rewritten);
}

#[test]
fn fixture_is_the_regtest_chain_bitcoind_mined() {
    let rows = fixture();
    let params = regtest();
    assert_eq!(rows.len(), 7);
    let heights: Vec<u32> = rows.iter().map(|row| row.height).collect();
    assert_eq!(heights, [0, 1, 2, 102, 103, 104, 105]);
    let tx_counts: Vec<usize> = rows.iter().map(|row| row.block.txdata.len()).collect();
    assert_eq!(tx_counts, [1, 1, 1, 4, 2, 3, 1]);
    assert_eq!(rows[0].block, *params.genesis());
    for row in &rows {
        assert_eq!(row.block.block_hash(), row.hash, "{}", row.height);
    }
    // Block 104 is the interesting one: two lock-timed witness spends and one legacy spend.
    let block_104 = &rows[5].block;
    assert_eq!(block_104.txdata[1].lock_time, LockTime::from_consensus(103));
    assert!(
        block_104.txdata[1]
            .input
            .iter()
            .all(|input| !input.witness.is_empty())
    );
    assert_eq!(block_104.txdata[2].lock_time, LockTime::ZERO);
    assert!(
        block_104.txdata[2]
            .input
            .iter()
            .all(|input| input.witness.is_empty())
    );
}

/// Every bitcoind block passes both stages with the context the node would build. The
/// commitment position and both merkle roots agree with rust-bitcoin along the way.
#[test]
fn bitcoind_blocks_pass_check_and_accept() {
    let rows = fixture();
    let params = regtest();
    for row in &rows {
        let block = &row.block;
        assert_eq!(check_block(block, &params), Ok(()), "{}", row.height);
        assert_eq!(
            super::merkle_root(
                block
                    .txdata
                    .iter()
                    .map(|tx| tx.compute_txid().to_byte_array())
                    .collect()
            )
            .root,
            block.compute_merkle_root().unwrap().to_byte_array()
        );
        assert_eq!(
            witness_root(block),
            block.witness_root().unwrap().to_byte_array()
        );
        if row.height == 0 {
            assert_eq!(witness_commitment_index(&block.txdata[0]), None);
            continue;
        }
        assert!(witness_commitment_index(&block.txdata[0]).is_some());
        assert!(block.check_witness_commitment());
        let context = context(&params, row);
        assert_eq!(accept_block(block, &context), Ok(()), "{}", row.height);
    }
}

#[test]
fn genesis_blocks_pass_check_block() {
    let mainnet = ChainParams::mainnet();
    assert_eq!(check_block(mainnet.genesis(), &mainnet), Ok(()));
    let regtest = regtest();
    assert_eq!(check_block(regtest.genesis(), &regtest), Ok(()));
}

#[test]
fn check_block_refuses_a_header_that_fails_proof_of_work() {
    let params = ChainParams::mainnet();
    let mut block = params.genesis().clone();
    block.header.nonce += 1;
    assert_eq!(
        check_block(&block, &params),
        Err(BlockError::Header(HeaderError::HighHash))
    );
}

#[test]
fn check_block_refuses_a_wrong_merkle_root() {
    let params = regtest();
    let mut block = fixture()[3].block.clone();
    let honest = block.header.merkle_root.to_byte_array();
    let mut forged = honest;
    forged[0] ^= 0x01;
    block.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(forged);
    mine(&mut block, &params);
    assert_eq!(
        check_block(&block, &params),
        Err(BlockError::BadMerkleRoot { computed: honest })
    );
}

/// Block 104 has three transactions; repeating the last one leaves the root unchanged, so
/// only the mutation detector stands between the forged block and the honest header.
#[test]
fn check_block_refuses_a_repeated_tail_with_the_honest_root() {
    let params = regtest();
    let mut block = fixture()[5].block.clone();
    let last = block.txdata[2].clone();
    block.txdata.push(last);
    assert_eq!(
        block.compute_merkle_root().unwrap(),
        block.header.merkle_root
    );
    assert_eq!(
        check_block(&block, &params),
        Err(BlockError::DuplicateTransactions)
    );
}

/// An empty block hashes to the zero root, so the header must claim that root to get past
/// the merkle check and reach the length rule.
#[test]
fn check_block_refuses_an_empty_transaction_list() {
    let params = regtest();
    let mut block = fixture()[6].block.clone();
    block.txdata.clear();
    block.header.merkle_root = bitcoin::TxMerkleNode::all_zeros();
    mine(&mut block, &params);
    assert_eq!(
        check_block(&block, &params),
        Err(BlockError::BadLength {
            tx_count: 0,
            base_size: 81
        })
    );
}

#[test]
fn check_block_refuses_a_missing_or_repeated_coinbase() {
    let params = regtest();
    let rows = fixture();
    let mut block = rows[3].block.clone();
    block.txdata.remove(0);
    seal(&mut block, &params);
    assert_eq!(
        check_block(&block, &params),
        Err(BlockError::CoinbaseMissing)
    );

    let mut block = rows[3].block.clone();
    block.txdata.push(rows[4].block.txdata[0].clone());
    seal(&mut block, &params);
    assert_eq!(
        check_block(&block, &params),
        Err(BlockError::CoinbaseMultiple { index: 4 })
    );
}

#[test]
fn check_block_reports_a_failing_transaction_with_its_index() {
    let params = regtest();
    let mut block = fixture()[3].block.clone();
    block.txdata[2].output[0].value = Amount::from_sat(MAX_MONEY + 1);
    seal(&mut block, &params);
    assert_eq!(
        check_block(&block, &params),
        Err(BlockError::Transaction {
            index: 2,
            error: TxError::VoutTooLarge { index: 0 }
        })
    );
}

/// 20,000 legacy sigops cost exactly the budget; one more is over it.
#[test]
fn check_block_enforces_the_legacy_sigop_budget() {
    const OP_CHECKSIG: u8 = 0xac;
    let params = regtest();
    let mut block = fixture()[6].block.clone();
    block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![OP_CHECKSIG; 20_000]);
    seal(&mut block, &params);
    assert_eq!(check_block(&block, &params), Ok(()));
    block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![OP_CHECKSIG; 20_001]);
    seal(&mut block, &params);
    assert_eq!(
        check_block(&block, &params),
        Err(BlockError::BadSigOps { count: 20_001 })
    );
}

/// Block 104's coinbase carries `nLockTime = 103`, final at 104 and not at 103.
#[test]
fn accept_block_refuses_a_non_final_transaction() {
    let params = regtest();
    let rows = fixture();
    let row = &rows[5];
    assert_eq!(row.block.txdata[0].lock_time, LockTime::from_consensus(103));
    assert_eq!(
        accept_block(&row.block, &context_at(&params, row, 104)),
        Ok(())
    );
    assert_eq!(
        accept_block(&row.block, &context_at(&params, row, 103)),
        Err(BlockError::NonFinal { index: 0 })
    );
}

/// Before CSV the cutoff for a time lock is the block's own time, not the median.
#[test]
fn accept_block_uses_the_block_time_as_cutoff_before_csv() {
    let rows = fixture();
    let row = &rows[6];
    let mut block = row.block.clone();
    // A time lock one second below the block's time: final against the block time, not
    // against the earlier median time past.
    let lock = block.header.time - 1;
    assert!(lock >= row.previous_median_time_past.get());
    block.txdata[0].lock_time = LockTime::from_consensus(lock);
    block.txdata[0].input[0].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
    let late_csv = ChainParams::regtest(RegtestOverrides {
        csv: Some(Height::new(1_000)),
        ..RegtestOverrides::default()
    });
    seal(&mut block, &late_csv);
    let row = Fixture {
        block: block.clone(),
        ..*row
    };
    assert!(!context(&late_csv, &row).rules().csv_active());
    assert_eq!(accept_block(&block, &context(&late_csv, &row)), Ok(()));
    let params = regtest();
    assert!(context(&params, &row).rules().csv_active());
    assert_eq!(
        accept_block(&block, &context(&params, &row)),
        Err(BlockError::NonFinal { index: 0 })
    );
}

#[test]
fn accept_block_enforces_the_bip34_height() {
    let params = regtest();
    let rows = fixture();
    let row = &rows[5];
    assert_eq!(
        accept_block(&row.block, &context_at(&params, row, 105)),
        Err(BlockError::BadCoinbaseHeight {
            expected: Height::new(105)
        })
    );
    // With BIP34 not yet active the height is not looked for.
    let late = ChainParams::regtest(RegtestOverrides {
        bip34: Some(Height::new(1_000)),
        ..RegtestOverrides::default()
    });
    assert_eq!(
        accept_block(&row.block, &context_at(&late, row, 105)),
        Ok(())
    );
}

/// `CScript() << height` for the heights that pick each encoding, against rust-bitcoin's
/// builder for the same integers.
#[test]
fn height_script_is_cores_push_of_the_height() {
    let cases: [(u32, &[u8]); 8] = [
        (1, &[0x51]),
        (16, &[0x60]),
        (17, &[0x01, 0x11]),
        (102, &[0x01, 0x66]),
        (127, &[0x01, 0x7f]),
        (128, &[0x02, 0x80, 0x00]),
        (227_931, &[0x03, 0x5b, 0x7a, 0x03]),
        (0x7fff_ffff, &[0x04, 0xff, 0xff, 0xff, 0x7f]),
    ];
    for (height, expected) in cases {
        let script = height_script(Height::new(height));
        assert_eq!(script, expected, "{height}");
        let oracle = Builder::new().push_int(i64::from(height)).into_script();
        assert_eq!(script, oracle.as_bytes(), "{height}");
    }
}

#[test]
fn accept_block_pins_the_coinbase_witness_and_the_commitment() {
    let params = regtest();
    let rows = fixture();
    let row = &rows[3];
    let context = context(&params, row);

    let mut block = row.block.clone();
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0u8; 31]]);
    assert_eq!(check_block(&block, &params), Ok(()));
    assert_eq!(
        accept_block(&block, &context),
        Err(BlockError::WitnessNonceSize)
    );
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0u8; 32], [0u8; 32]]);
    assert_eq!(
        accept_block(&block, &context),
        Err(BlockError::WitnessNonceSize)
    );

    // A different reserved value changes the commitment the script would need.
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0x42u8; 32]]);
    assert_eq!(
        accept_block(&block, &context),
        Err(BlockError::WitnessMerkleMismatch)
    );
    recommit(&mut block);
    assert_eq!(accept_block(&block, &context), Ok(()));

    // A witness swapped between transactions leaves every txid alone and breaks the tree.
    let mut block = row.block.clone();
    let witness = block.txdata[1].input[0].witness.clone();
    block.txdata[1].input[0].witness = block.txdata[2].input[0].witness.clone();
    block.txdata[2].input[0].witness = witness;
    assert_eq!(
        block.header.merkle_root,
        block.compute_merkle_root().unwrap()
    );
    assert_eq!(
        accept_block(&block, &context),
        Err(BlockError::WitnessMerkleMismatch)
    );
}

#[test]
fn accept_block_refuses_witnesses_nobody_committed_to() {
    let rows = fixture();
    let row = &rows[3];

    // Segwit not active: the coinbase's own reserved value is already unexpected.
    let late = ChainParams::regtest(RegtestOverrides {
        segwit: Some(Height::new(1_000)),
        ..RegtestOverrides::default()
    });
    assert_eq!(
        accept_block(&row.block, &context(&late, row)),
        Err(BlockError::UnexpectedWitness { index: 0 })
    );
    let mut stripped = row.block.clone();
    stripped.txdata[0].input[0].witness = Witness::new();
    assert_eq!(
        accept_block(&stripped, &context(&late, row)),
        Err(BlockError::UnexpectedWitness { index: 1 })
    );

    // Segwit active but no commitment output: the same rule.
    let params = regtest();
    let mut uncommitted = row.block.clone();
    let position = witness_commitment_index(&uncommitted.txdata[0]).unwrap();
    uncommitted.txdata[0].output.remove(position);
    uncommitted.txdata[0].input[0].witness = Witness::new();
    seal(&mut uncommitted, &params);
    let row = Fixture {
        block: uncommitted.clone(),
        ..*row
    };
    assert_eq!(check_block(&uncommitted, &params), Ok(()));
    assert_eq!(
        accept_block(&uncommitted, &context(&params, &row)),
        Err(BlockError::UnexpectedWitness { index: 1 })
    );
}

/// A block with no witness anywhere needs no commitment, segwit or not.
#[test]
fn accept_block_allows_a_witnessless_block_without_a_commitment() {
    let params = regtest();
    let rows = fixture();
    let mut block = rows[6].block.clone();
    let position = witness_commitment_index(&block.txdata[0]).unwrap();
    block.txdata[0].output.remove(position);
    block.txdata[0].input[0].witness = Witness::new();
    seal(&mut block, &params);
    let row = Fixture {
        block: block.clone(),
        ..rows[6]
    };
    assert_eq!(check_block(&block, &params), Ok(()));
    assert_eq!(accept_block(&block, &context(&params, &row)), Ok(()));
}

/// Block 105 plus one transaction whose witness carries `item_size` bytes.
fn block_with_heavy_witness(params: &ChainParams, item_size: usize) -> (Block, Fixture) {
    let rows = fixture();
    let mut block = rows[6].block.clone();
    block.txdata.push(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0u8; item_size]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    });
    recommit(&mut block);
    seal(&mut block, params);
    let row = Fixture {
        block: block.clone(),
        ..rows[6]
    };
    (block, row)
}

/// The weight limit is the last rule, after the witness is pinned; the base size stays
/// small, so only `accept_block` can see the excess.
#[test]
fn accept_block_enforces_the_block_weight() {
    let params = regtest();
    let (block, row) = block_with_heavy_witness(&params, 3_999_000);
    let weight = block.weight().to_wu();
    assert!(weight > MAX_BLOCK_WEIGHT);
    assert_eq!(check_block(&block, &params), Ok(()));
    assert_eq!(
        accept_block(&block, &context(&params, &row)),
        Err(BlockError::BadWeight { weight })
    );
    let (block, row) = block_with_heavy_witness(&params, 3_990_000);
    assert!(block.weight().to_wu() <= MAX_BLOCK_WEIGHT);
    assert_eq!(check_block(&block, &params), Ok(()));
    assert_eq!(accept_block(&block, &context(&params, &row)), Ok(()));
}

#[test]
fn witness_commitment_index_takes_the_last_matching_output() {
    let mut coinbase = fixture()[3].block.txdata[0].clone();
    let position = witness_commitment_index(&coinbase).unwrap();
    let commitment = coinbase.output[position].clone();
    coinbase.output.push(commitment.clone());
    assert_eq!(witness_commitment_index(&coinbase), Some(position + 1));
    // Too short, or the wrong header: not a commitment.
    let mut short = commitment.clone();
    short.script_pubkey = ScriptBuf::from_bytes(commitment.script_pubkey.to_bytes()[..37].to_vec());
    coinbase.output.push(short);
    assert_eq!(witness_commitment_index(&coinbase), Some(position + 1));
    let mut wrong = commitment.clone();
    let mut bytes = commitment.script_pubkey.to_bytes();
    bytes[5] = 0xee;
    wrong.script_pubkey = ScriptBuf::from_bytes(bytes);
    coinbase.output.push(wrong);
    assert_eq!(witness_commitment_index(&coinbase), Some(position + 1));
}

#[test]
#[should_panic(expected = "is_coinbase")]
fn accept_block_before_check_block_is_a_bug() {
    let params = regtest();
    let rows = fixture();
    let mut block = rows[3].block.clone();
    block.txdata.remove(0);
    let _unreachable = accept_block(&block, &context(&params, &rows[3]));
}

#[test]
fn errors_display_cores_reject_reasons() {
    let cases = [
        (BlockError::Header(HeaderError::HighHash), "high-hash"),
        (
            BlockError::BadMerkleRoot { computed: [0; 32] },
            "bad-txnmrklroot",
        ),
        (BlockError::DuplicateTransactions, "bad-txns-duplicate"),
        (
            BlockError::BadLength {
                tx_count: 0,
                base_size: 0,
            },
            "bad-blk-length",
        ),
        (BlockError::CoinbaseMissing, "bad-cb-missing"),
        (BlockError::CoinbaseMultiple { index: 1 }, "bad-cb-multiple"),
        (
            BlockError::Transaction {
                index: 0,
                error: TxError::VinEmpty,
            },
            "bad-txns-vin-empty",
        ),
        (BlockError::BadSigOps { count: 0 }, "bad-blk-sigops"),
        (BlockError::NonFinal { index: 0 }, "bad-txns-nonfinal"),
        (
            BlockError::BadCoinbaseHeight {
                expected: Height::new(1),
            },
            "bad-cb-height",
        ),
        (BlockError::WitnessNonceSize, "bad-witness-nonce-size"),
        (
            BlockError::WitnessMerkleMismatch,
            "bad-witness-merkle-match",
        ),
        (
            BlockError::UnexpectedWitness { index: 0 },
            "unexpected-witness",
        ),
        (BlockError::BadWeight { weight: 0 }, "bad-blk-weight"),
    ];
    for (error, reason) in cases {
        assert_eq!(error.to_string(), reason);
    }
}
