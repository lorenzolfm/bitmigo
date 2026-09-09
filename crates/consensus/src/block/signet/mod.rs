// SPDX-License-Identifier: MIT OR Apache-2.0

//! BIP325 signet: the extra thing a signet block must prove.
//!
//! A signet block carries a signature over itself, and the chain's [`BlockChallenge`] is the
//! script that signature must satisfy. Core checks it in `signet.cpp` from inside
//! `CheckBlock`, before the merkle root, so it is context-free and runs at receipt with the
//! rest of `check_block` (§2.8). The whole of BIP325 is here.
//!
//! The construction is a spend of an output nobody can create, so the interpreter can be
//! reused unchanged. [`signet_txs`] builds Core's two transactions:
//!
//! - `to_spend` pays zero to the challenge, and commits in its `scriptSig` to the block's
//!   version, previous hash, **modified** merkle root and time. The nonce is not committed
//!   to, so a block can be re-mined without a new signature.
//! - `to_sign` spends `to_spend`'s output with the solution the coinbase carries, and pays
//!   zero to `OP_RETURN`.
//!
//! "Modified" is the subtle half. The solution lives in the coinbase's witness commitment
//! output, after the four bytes [`SIGNET_HEADER`], so the coinbase the block commits to
//! already contains the signature. [`fetch_and_clear_commitment_section`] is Core's
//! `FetchAndClearCommitmentSection`: it rewrites that output with the signature removed and
//! the header kept, and the merkle root is taken over *that* coinbase. Two consequences are
//! consensus and easy to get wrong. Rewriting re-serializes every push in the commitment
//! script minimally, so a non-minimal push in it changes the root. And Core's script walk
//! stops at a truncated push and keeps only what it read, so the rewritten script is
//! shorter than the original in that case.
//!
//! A block whose commitment output has no signet section is not an error: Core allows it so
//! that a trivial challenge such as `OP_TRUE` needs no solution. Missing the witness
//! commitment output altogether is an error, because there would be nowhere to put one.

use bitcoin::absolute::LockTime;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use core::fmt;

use super::{merkle_root, witness_commitment_index};
use crate::params::{BlockChallenge, hex_bytes};
use crate::script::{
    OP_0, OP_RETURN, Reader, ScriptError, ScriptFlags, TxPrecomputed, push_encoding, verify_input,
};

/// Core's `SIGNET_HEADER`: the four bytes that mark the signet section of the witness
/// commitment output.
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// Core's `BLOCK_SCRIPT_VERIFY_FLAGS`: the solution is verified under these four flags at
/// every height, whatever the block's own script flags are (§4.2).
pub const BLOCK_SCRIPT_FLAGS: ScriptFlags = ScriptFlags::P2SH
    .union(ScriptFlags::WITNESS)
    .union(ScriptFlags::DERSIG)
    .union(ScriptFlags::NULLDUMMY);

/// The default challenge as `kernel/chainparams.cpp` writes it (§5.5): the 1-of-2 multisig
/// `OP_1 <03ad5e0e…be430> <0359ef50…2e6c4> OP_2 OP_CHECKMULTISIG` of the two signers who
/// mine the signet BIP325 defines.
pub const DEFAULT_CHALLENGE_HEX: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489\
                                         abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2\
                                         463c9540ce96883fe3b278760f048f5189f2e6c452ae";

/// [`DEFAULT_CHALLENGE_HEX`] as bytes, parsed at compile time.
pub const DEFAULT_CHALLENGE: [u8; 71] = hex_bytes(DEFAULT_CHALLENGE_HEX);

/// The bytes `to_spend`'s `scriptSig` commits to: version, previous hash, modified merkle
/// root, time. Not the nonce, so re-mining a signed block needs no new signature.
const BLOCK_DATA_SIZE: usize = 4 + 32 + 32 + 4;

/// Core's `MAX_SIZE`, the ceiling `ReadCompactSize` puts on any serialized length.
const MAX_SERIALIZED_SIZE: u64 = 0x0200_0000;

/// The challenge the signet BIP325 defines, as a script.
#[must_use]
pub fn default_challenge() -> ScriptBuf {
    ScriptBuf::from_bytes(DEFAULT_CHALLENGE.to_vec())
}

/// The default signet's [`BlockChallenge`], ready for
/// [`crate::params::ChainParams::signet`].
#[must_use]
pub fn default_block_challenge() -> BlockChallenge {
    BlockChallenge::Signet(default_challenge())
}

/// Why a signet block's solution was refused. `Display` is Core's one reject reason for all
/// of them, `bad-signet-blksig`; the variants are the evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignetError {
    /// The block has no transactions, so there is no coinbase to read a solution from.
    /// Reachable because Core runs this check before the size limits.
    CoinbaseMissing,
    /// The coinbase carries no witness commitment output, which is the only place a signet
    /// solution can live.
    NoWitnessCommitment,
    /// The solution bytes are not a `scriptSig` followed by a witness stack.
    MalformedSolution,
    /// Bytes left over after the witness stack: Core's "extraneous data encountered".
    ExtraneousSolutionData {
        /// How many.
        extra: usize,
    },
    /// The solution does not satisfy the challenge.
    Script(ScriptError),
}

impl fmt::Display for SignetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bad-signet-blksig")
    }
}

impl std::error::Error for SignetError {}

/// Core's `SignetTxs`: the pair of transactions a signet block's signature is taken over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignetTxs {
    /// `m_to_spend`: pays zero to the challenge, and commits to the block.
    pub to_spend: Transaction,
    /// `m_to_sign`: spends that output with the block's solution.
    pub to_sign: Transaction,
}

impl SignetTxs {
    /// The one output `to_sign` spends, which is the only prevout the interpreter needs.
    #[must_use]
    pub fn spent_output(&self) -> &TxOut {
        self.to_spend
            .output
            .first()
            .expect("to_spend has one output")
    }
}

/// Core's `CheckSignetBlockSolution`, minus its genesis exemption: only the caller knows the
/// chain's genesis hash, so [`super::check_block`] makes that test.
///
/// Core also runs this only when it is checking proof of work, which is its way of skipping
/// the solution while assembling a block. Nothing here ever skips proof of work, so there is
/// no such condition.
///
/// # Errors
///
/// [`SignetError`], whether the solution could not be parsed or did not satisfy `challenge`.
///
/// # Panics
///
/// If `challenge` is empty. [`crate::params::ChainParams::signet`] cannot hold one.
pub fn check_signet_solution(block: &Block, challenge: &Script) -> Result<(), SignetError> {
    assert!(!challenge.is_empty());
    let txs = signet_txs(block, challenge)?;
    let prevouts = [txs.spent_output().clone()];
    let precomputed = TxPrecomputed::new(&txs.to_sign, &prevouts);
    verify_input(&txs.to_sign, 0, &prevouts, &precomputed, BLOCK_SCRIPT_FLAGS)
        .map_err(SignetError::Script)
}

/// Core's `SignetTxs::Create`: the two transactions `block`'s solution is a spend of, under
/// `challenge`.
///
/// # Errors
///
/// [`SignetError`] where Core returns `std::nullopt`: no coinbase, no witness commitment, or
/// a solution section that does not deserialize.
pub fn signet_txs(block: &Block, challenge: &Script) -> Result<SignetTxs, SignetError> {
    let coinbase = block
        .txdata
        .first()
        .ok_or(SignetError::CoinbaseMissing)?
        .clone();
    let commitment_index =
        witness_commitment_index(&coinbase).ok_or(SignetError::NoWitnessCommitment)?;

    // The block commits to the coinbase with its own signature taken back out.
    let mut modified = coinbase;
    let commitment = modified
        .output
        .get_mut(commitment_index)
        .expect("an index witness_commitment_index returned");
    let solution = fetch_and_clear_commitment_section(&commitment.script_pubkey).map(|cleared| {
        commitment.script_pubkey = cleared.replacement;
        cleared.solution
    });

    let to_spend = to_spend_tx(challenge, &block_data(&block.header, &modified, block));
    // No section at all is allowed, so that a trivial challenge needs no solution.
    let (script_sig, witness) = match solution {
        Some(bytes) => parse_solution(&bytes)?,
        None => (ScriptBuf::new(), Witness::new()),
    };
    let to_sign = to_sign_tx(to_spend.compute_txid(), script_sig, witness);
    Ok(SignetTxs { to_spend, to_sign })
}

/// The commitment script with its signet section removed, and the section's bytes.
#[derive(Clone, Debug)]
struct Cleared {
    replacement: ScriptBuf,
    solution: Vec<u8>,
}

/// Core's `FetchAndClearCommitmentSection`. `None` when the script carries no signet
/// section, which leaves the coinbase untouched.
fn fetch_and_clear_commitment_section(commitment: &Script) -> Option<Cleared> {
    let mut reader = Reader::new(commitment.as_bytes());
    let mut replacement: Vec<u8> = Vec::with_capacity(commitment.len());
    let mut solution: Vec<u8> = Vec::new();
    let mut found = false;
    // Bounded by the script: every step of the reader consumes at least one byte.
    while let Some(op) = reader.next_op() {
        // `GetOp` returning false ends Core's loop, so the tail of a script with a truncated
        // push is dropped from the replacement.
        let Ok(op) = op else { break };
        if op.push.is_empty() {
            // Core writes the opcode byte back, which for an empty `OP_PUSHDATA1` push is
            // the single byte `0x4c`: a truncated push in the rewritten script.
            replacement.push(op.opcode.byte());
            continue;
        }
        let mut push = op.push;
        if !found
            && push.len() > SIGNET_HEADER.len()
            && push.starts_with(&SIGNET_HEADER)
            && let Some((header, section)) = push.split_at_checked(SIGNET_HEADER.len())
        {
            // A push counts only if it carries the header *and* some data, and only the
            // first such push does.
            solution.extend_from_slice(section);
            push = header;
            found = true;
        }
        // Core's `CScript() << pushdata`: the shortest push, so a non-minimal one in the
        // original script does not survive into the modified coinbase.
        replacement.extend_from_slice(&push_encoding(push));
    }
    found.then(|| Cleared {
        replacement: ScriptBuf::from_bytes(replacement),
        solution,
    })
}

/// Core's `ComputeModifiedMerkleRoot`: the block's transaction ids with the coinbase's
/// replaced by the modified one's. No mutation check, as Core has none here.
fn modified_merkle_root(modified_coinbase: &Transaction, block: &Block) -> [u8; 32] {
    assert!(!block.txdata.is_empty());
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(block.txdata.len());
    leaves.push(modified_coinbase.compute_txid().to_byte_array());
    for tx in block.txdata.iter().skip(1) {
        leaves.push(tx.compute_txid().to_byte_array());
    }
    assert_eq!(leaves.len(), block.txdata.len());
    merkle_root(leaves).root
}

/// The 72 bytes `to_spend` commits to, in Core's order.
fn block_data(header: &Header, modified_coinbase: &Transaction, block: &Block) -> Vec<u8> {
    let mut data = Vec::with_capacity(BLOCK_DATA_SIZE);
    data.extend_from_slice(&header.version.to_consensus().to_le_bytes());
    data.extend_from_slice(&header.prev_blockhash.to_byte_array());
    data.extend_from_slice(&modified_merkle_root(modified_coinbase, block));
    data.extend_from_slice(&header.time.to_le_bytes());
    assert_eq!(data.len(), BLOCK_DATA_SIZE);
    data
}

/// `m_to_spend`: one input spending nothing, `scriptSig` `OP_0 <block_data>`, one output of
/// zero paying the challenge. Its outpoint is null, so no chain can contain it.
fn to_spend_tx(challenge: &Script, block_data: &[u8]) -> Transaction {
    assert_eq!(block_data.len(), BLOCK_DATA_SIZE);
    let mut script_sig = vec![OP_0];
    script_sig.extend_from_slice(&push_encoding(block_data));
    Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence(0),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: challenge.to_owned(),
        }],
    }
}

/// `m_to_sign`: the solution spending `to_spend`'s only output, paying zero to `OP_RETURN`.
fn to_sign_tx(to_spend: Txid, script_sig: ScriptBuf, witness: Witness) -> Transaction {
    Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: to_spend,
                vout: 0,
            },
            script_sig,
            sequence: Sequence(0),
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![OP_RETURN]),
        }],
    }
}

/// Core's `SpanReader v{signet_solution}; v >> scriptSig; v >> scriptWitness.stack;` and the
/// "extraneous data encountered" check that follows it.
fn parse_solution(solution: &[u8]) -> Result<(ScriptBuf, Witness), SignetError> {
    let mut cursor = Cursor::new(solution);
    let script_sig = ScriptBuf::from_bytes(cursor.read_bytes()?.to_vec());

    let count = cursor.read_compact_size()?;
    let count = usize::try_from(count).map_err(|_| SignetError::MalformedSolution)?;
    // Every item costs at least its own length byte, so the bytes left bound the loop: this
    // is where Core would run out of stream instead.
    if count > cursor.remaining() {
        return Err(SignetError::MalformedSolution);
    }
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(cursor.read_bytes()?.to_vec());
    }
    assert_eq!(items.len(), count);

    let extra = cursor.remaining();
    if extra > 0 {
        return Err(SignetError::ExtraneousSolutionData { extra });
    }
    Ok((script_sig, Witness::from_slice(&items)))
}

/// A bounded cursor over the solution bytes: Core's `SpanReader`, with only the two things a
/// solution is made of.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Cursor<'a> {
        Cursor { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        assert!(self.position <= self.bytes.len());
        self.bytes.len() - self.position
    }

    /// The next `count` bytes, or [`SignetError::MalformedSolution`] where Core's stream
    /// would throw "end of data".
    fn take(&mut self, count: usize) -> Result<&'a [u8], SignetError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(SignetError::MalformedSolution)?;
        let taken = self
            .bytes
            .get(self.position..end)
            .ok_or(SignetError::MalformedSolution)?;
        self.position = end;
        assert!(self.position <= self.bytes.len());
        Ok(taken)
    }

    /// Core's `ReadCompactSize` with its range check: the shortest encoding of the value
    /// only, and nothing above [`MAX_SERIALIZED_SIZE`].
    fn read_compact_size(&mut self) -> Result<u64, SignetError> {
        let first = *self.take(1)?.first().expect("one byte");
        let value = match first {
            0..=252 => u64::from(first),
            253 => {
                let value = u64::from(u16::from_le_bytes(self.take_array::<2>()?));
                // "non-canonical ReadCompactSize()": a value that fits a shorter encoding.
                if value < 253 {
                    return Err(SignetError::MalformedSolution);
                }
                value
            }
            254 => {
                let value = u64::from(u32::from_le_bytes(self.take_array::<4>()?));
                if value < 0x1_0000 {
                    return Err(SignetError::MalformedSolution);
                }
                value
            }
            _ => {
                let value = u64::from_le_bytes(self.take_array::<8>()?);
                if value < 0x1_0000_0000 {
                    return Err(SignetError::MalformedSolution);
                }
                value
            }
        };
        if value > MAX_SERIALIZED_SIZE {
            return Err(SignetError::MalformedSolution);
        }
        Ok(value)
    }

    /// A `CompactSize` length followed by that many bytes: how Core serializes a `CScript`
    /// and each witness item.
    fn read_bytes(&mut self) -> Result<&'a [u8], SignetError> {
        let len = self.read_compact_size()?;
        let len = usize::try_from(len).map_err(|_| SignetError::MalformedSolution)?;
        self.take(len)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], SignetError> {
        let bytes = self.take(N)?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }
}

#[cfg(test)]
mod tests;
