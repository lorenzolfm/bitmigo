# Consensus rules an independent node must agree with Bitcoin Core about

- Core tag read: `v31.1` (the installed `bitcoind --version` reports `v31.1.0`).
- BIP texts read from `github.com/bitcoin/bips` `master` on the same date.
- Date: 2026-09-07.

How to read this document. Every section is one or more tables; every row names the single
source that owns the rule. Core sources are written `file: Symbol`, always relative to `src/` at
tag `v31.1` (so `validation.cpp: ConnectBlock` means `src/validation.cpp`, function
`ConnectBlock`, at that tag). BIPs are written `[BIP141]` and link to the text in the bips
repository at the end of the file. The `C/P` column says **C** for a consensus rule (a block that
breaks it is invalid) and **P** for policy (a mempool or relay rule that a block need not obey;
this node has no mempool, so policy stays out of consensus code). Where a claim could not be
confirmed from a primary source the row says so with the word "unverified". Heights and hashes
that Core does not spell out were resolved against chain data (marked "chain data"). A number
in square brackets inside a row, such as `[1]`, points to a note below the table.

## 1. Header rules

### 1.1 Proof of work and target encoding

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Hash meets target | `SHA256d(header)` as a 256-bit LE integer must be `<= target(nBits)` | C | `pow.cpp: CheckProofOfWorkImpl` |
| nBits decoding | size = `nBits >> 24`, word = `nBits & 0x007fffff`; size `<= 3` shifts word right by `8*(3-size)`, else left by `8*(size-3)` | C | `arith_uint256.cpp: SetCompact` |
| Negative target rejected | word `!= 0` and bit `0x00800000` set | C | `pow.cpp: DeriveTarget` |
| Overflow rejected | word `!= 0` and (size `> 34`, or word `> 0xff` and size `> 33`, or word `> 0xffff` and size `> 32`) | C | `arith_uint256.cpp: SetCompact` |
| Zero target rejected | decoded target `== 0` | C | `pow.cpp: DeriveTarget` |
| Above powLimit rejected | decoded target `> powLimit` of the chain | C | `pow.cpp: DeriveTarget` |
| powLimit main, testnet3, testnet4 | `00000000ffff…ffff` (compact `0x1d00ffff`) | C | `kernel/chainparams.cpp: CMainParams` etc. |
| powLimit signet | `00000377ae00…0000` (compact `0x1e0377ae`) | C | `kernel/chainparams.cpp: SigNetParams` |
| powLimit regtest | `7fffff…ffff` (compact `0x207fffff`) | C | `kernel/chainparams.cpp: CRegTestParams` |
| nBits must be canonical | `block.nBits` must equal `GetNextWorkRequired` exactly, so it is the `GetCompact` re-encoding of the computed target (mantissa with sign bit clear, no non-canonical encodings) | C | `validation.cpp: ContextualCheckBlockHeader` ("bad-diffbits"); `arith_uint256.cpp: GetCompact` |
| Chain work per block | `(~target / (target + 1)) + 1`; invalid nBits counts as 0 | C [1] | `chain.cpp: GetBitsProof` |
| Anti-DoS transition bound | `PermittedDifficultyTransition` (headers pre-sync) is not a validity rule | P | `pow.cpp: PermittedDifficultyTransition`; `headerssync.cpp` |

[1] Chain work is not checked per block, but it selects the best chain; two nodes that disagree
on `GetBitsProof` would follow different tips.

### 1.2 Difficulty retarget

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Interval | `nPowTargetTimespan / nPowTargetSpacing` = `1209600 / 600` = 2016 blocks (regtest: `86400 / 600` = 144) | C | `consensus/params.h: DifficultyAdjustmentInterval`; chainparams |
| When to retarget | only when `(prev.height + 1) % 2016 == 0`; otherwise `nBits = prev.nBits` | C | `pow.cpp: GetNextWorkRequired` |
| Off-by-one window | first block of the window is `prev.height - (2016 - 1)`; the measured timespan spans 2015 block intervals, not 2016. Must be preserved | C | `pow.cpp: GetNextWorkRequired` |
| Actual timespan | `prev.nTime - first.nTime` (signed 64-bit) | C | `pow.cpp: CalculateNextWorkRequired` |
| 4x clamp | clamp to `[timespan/4, timespan*4]` = `[302400, 4838400]` s | C | `pow.cpp: CalculateNextWorkRequired` |
| New target | `target(prev.nBits) * actual / 1209600` in 256-bit integer arithmetic, then cap at powLimit, then `GetCompact` | C | `pow.cpp: CalculateNextWorkRequired` |
| Precision loss is normative | the multiply happens on the 256-bit target decoded from nBits (already truncated to 3 bytes of mantissa) and the result is re-truncated by `GetCompact` | C | `pow.cpp: CalculateNextWorkRequired` |
| fPowNoRetargeting | regtest only: `nBits = prev.nBits` always at retarget boundaries | C | `pow.cpp: CalculateNextWorkRequired`; `CRegTestParams` |
| fPowAllowMinDifficultyBlocks (1) | testnet3, testnet4, regtest: off a retarget boundary, if `block.nTime > prev.nTime + 2*600` the block MUST use `powLimit` compact (a normal-difficulty block is invalid there) | C | `pow.cpp: GetNextWorkRequired` |
| fPowAllowMinDifficultyBlocks (2) | otherwise walk back over blocks with `nBits == powLimit` and `height % 2016 != 0` and use the first other `nBits` found | C | `pow.cpp: GetNextWorkRequired` |
| BIP94 base target | `enforce_BIP94` (testnet4; regtest with `-test=bip94`): retarget multiplies the target of the FIRST block of the period, not the last | C | `pow.cpp: CalculateNextWorkRequired`; [BIP94] |
| BIP94 timewarp | `enforce_BIP94`: a block with `height % 2016 == 0` must have `nTime >= prev.nTime - 600` (`MAX_TIMEWARP`) | C | `validation.cpp: ContextualCheckBlockHeader`; `consensus/consensus.h: MAX_TIMEWARP`; [BIP94] |
| Mainnet has no timewarp rule | `enforce_BIP94 = false` on main, testnet3, signet | C | `kernel/chainparams.cpp` |

### 1.3 Timestamps

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Median-time-past | median of the `nTime` of the last 11 blocks (fewer near genesis): sort, take index `n/2` | C | `chain.h: CBlockIndex::GetMedianTimePast`, `nMedianTimeSpan = 11` |
| Not too old | `block.nTime > MTP(prev)` strictly ("time-too-old") | C | `validation.cpp: ContextualCheckBlockHeader` |
| Not too new | `block.nTime <= now + 7200` (`MAX_FUTURE_BLOCK_TIME = 2h`), where `now` is the local `NodeClock` (system clock; no peer time adjustment) | C [2] | `validation.cpp: ContextualCheckBlockHeader`; `chain.h: MAX_FUTURE_BLOCK_TIME` |
| Future-time failures are not permanent | result `BLOCK_TIME_FUTURE`: the header is rejected before it enters the block index (nothing is marked invalid) and the peer is not punished; the same header can be accepted later | C | `validation.cpp: AcceptBlockHeader`; `consensus/validation.h: BLOCK_TIME_FUTURE`; `net_processing.cpp: MaybePunishNodeForBlock` |
| Not re-checked on connect | `ConnectBlock` does not re-run the header contextual checks | – | comment in `validation.cpp: ConnectBlock` |

[2] This is the one rule that depends on a clock. It is a validity rule for a block *at the time
it is received*; a block that was once too new becomes valid as time passes.

### 1.4 Version

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| nVersion < 2 rejected | once the block height `>= BIP34Height` | C | `validation.cpp: ContextualCheckBlockHeader`; [BIP34]; [BIP90] |
| nVersion < 3 rejected | once height `>= BIP66Height` | C | same; [BIP66] |
| nVersion < 4 rejected | once height `>= BIP65Height` | C | same; [BIP65] |
| Signed comparison | `nVersion` is `int32_t`; every negative version is `< 2` and therefore invalid after BIP34 | C | `validation.cpp: ContextualCheckBlockHeader`; [BIP9] |
| Otherwise free | no other bit of `nVersion` is consensus; versionbits signalling is read but never required | C | `versionbits.cpp`; section 5 |
| Old 750/1000 supermajority rule | replaced by fixed heights (BIP90); the 75% rule is gone | C | [BIP90] |

### 1.5 Genesis blocks

All genesis coinbases use `scriptSig = <0x1d00ffff as 4-byte push> <CScriptNum 4> <message>` and
one 50 BTC output. The genesis coinbase output is never added to the UTXO set: `ConnectBlock`
returns before connecting genesis transactions (`validation.cpp: ConnectBlock`, "Special case for
the genesis block").

| Chain | nTime / nNonce / nBits / nVersion | Block hash | Source |
| --- | --- | --- | --- |
| main | 1231006505 / 2083236893 / 0x1d00ffff / 1 | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` | `kernel/chainparams.cpp: CMainParams` |
| testnet3 | 1296688602 / 414098458 / 0x1d00ffff / 1 | `000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943` | `CTestNetParams` |
| testnet4 | 1714777860 / 393743547 / 0x1d00ffff / 1 | `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043` | `CTestNet4Params` |
| signet | 1598918400 / 52613770 / 0x1e0377ae / 1 | `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6` | `SigNetParams`; [BIP325] |
| regtest | 1296688602 / 2 / 0x207fffff / 1 | `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206` | `CRegTestParams` |

| Field | main, testnet3, signet, regtest | testnet4 | Source |
| --- | --- | --- | --- |
| Coinbase message | `The Times 03/Jan/2009 Chancellor on brink of second bailout for banks` | `03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e` | `kernel/chainparams.cpp: CreateGenesisBlock` |
| Output script | push of the 65-byte key `04678afd…11d5f` then `OP_CHECKSIG` | push of 33 zero bytes then `OP_CHECKSIG` | same |
| Merkle root | `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b` | `7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e` | same (asserted) |

### 1.6 Context-free versus contextual header checks

| Check | Context needed | Function | Source |
| --- | --- | --- | --- |
| PoW against own nBits | none | `CheckBlockHeader` | `validation.cpp: CheckBlockHeader` |
| nBits equals required work | previous headers | `ContextualCheckBlockHeader` | `validation.cpp` |
| nTime > MTP(prev) | previous 11 headers | `ContextualCheckBlockHeader` | `validation.cpp` |
| BIP94 timewarp | prev header | `ContextualCheckBlockHeader` | `validation.cpp` |
| nTime <= now + 2h | local clock | `ContextualCheckBlockHeader` | `validation.cpp` |
| version floor | height | `ContextualCheckBlockHeader` | `validation.cpp` |
| prev header known and not invalid | block index | `AcceptBlockHeader` | `validation.cpp: AcceptBlockHeader` |
| Checkpoints | none: removed in this release | – | `init.cpp` ("Checkpoints were removed") |

## 2. Block rules

### 2.1 Size and weight

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Weight definition | `weight = base_size * 3 + total_size` (`WITNESS_SCALE_FACTOR = 4`) | C | `consensus/validation.h: GetBlockWeight`; [BIP141] |
| MAX_BLOCK_WEIGHT | block weight `<= 4,000,000` (checked after the witness commitment) | C | `validation.cpp: ContextualCheckBlock`; `consensus/consensus.h` |
| Base size | `base_size * 4 <= 4,000,000`, i.e. non-witness serialization `<= 1,000,000` bytes | C | `validation.cpp: CheckBlock` ("bad-blk-length") |
| Transaction count | `vtx.size() * 4 <= 4,000,000` and `vtx` non-empty | C | `validation.cpp: CheckBlock` |
| Per-tx base size | non-witness size of each tx `* 4 <= 4,000,000` | C | `consensus/tx_check.cpp: CheckTransaction` ("bad-txns-oversize") |
| MAX_BLOCK_SERIALIZED_SIZE | 4,000,000, "only for buffer size limits" (block file reading, net); not a validity rule | – | `consensus/consensus.h`; `validation.cpp: LoadExternalBlockFile` |
| MIN_TRANSACTION_WEIGHT etc. | 240 and 40; used only for P2P message bounds (merkleblock, compact blocks) | – | `consensus/consensus.h`; `merkleblock.cpp`; `blockencodings.cpp` |

### 2.2 Signature operation counting

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| MAX_BLOCK_SIGOPS_COST | running total `<= 80,000` per block, checked after each tx | C | `validation.cpp: ConnectBlock` ("bad-blk-sigops"); `consensus/consensus.h` |
| Context-free pre-check | `sum(legacy sigops) * 4 <= 80,000` in `CheckBlock` (underestimate, no P2SH or witness) | C | `validation.cpp: CheckBlock` |
| Legacy count | every `scriptSig` and `scriptPubKey` of every tx incl. coinbase; `CHECKSIG(VERIFY)` = 1, `CHECKMULTISIG(VERIFY)` = 20 (inaccurate mode); scanned without executing, stops at a parse error | C | `consensus/tx_verify.cpp: GetLegacySigOpCount`; `script.cpp: CScript::GetSigOpCount(bool)` |
| P2SH count | for each non-coinbase input whose prevout is P2SH: the last push of the scriptSig is parsed as a script and counted in accurate mode (`OP_1..OP_16 CHECKMULTISIG` = n, else 20); a scriptSig with any non-push opcode counts 0 | C | `consensus/tx_verify.cpp: GetP2SHSigOpCount`; `script.cpp: GetSigOpCount(const CScript&)` |
| Scale factor | `(legacy + P2SH) * 4` | C | `consensus/tx_verify.cpp: GetTransactionSigOpCost` |
| Witness count | P2WPKH = 1; P2WSH = accurate count of the witnessScript (last witness item); any other version/program = 0; not scaled; P2SH-wrapped programs found via the scriptSig's last push (push-only scriptSig required) | C | `script/interpreter.cpp: WitnessSigOps`, `CountWitnessSigOps`; [BIP141] |
| Taproot | 0 block sigops; tapscript has a per-input budget instead (section 4.6) | C | `script/interpreter.cpp: WitnessSigOps`; [BIP342] |
| Coinbase | only legacy sigops are counted for the coinbase | C | `consensus/tx_verify.cpp: GetTransactionSigOpCost` |
| Flags gate | P2SH and witness counts are gated on `SCRIPT_VERIFY_P2SH` / `SCRIPT_VERIFY_WITNESS`, which Core sets for every block except two exception blocks (section 4.2) | C | `validation.cpp: GetBlockScriptFlags` |

### 2.3 Coinbase structure and maturity

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Definition | exactly one input whose prevout is null (`hash = 0`, `n = 0xffffffff`) | C | `primitives/transaction.h: IsCoinBase`, `COutPoint::NULL_INDEX` |
| Position | `vtx[0]` must be a coinbase; no other tx may be | C | `validation.cpp: CheckBlock` ("bad-cb-missing", "bad-cb-multiple") |
| scriptSig length | `2 <= size <= 100` bytes | C | `consensus/tx_check.cpp: CheckTransaction` ("bad-cb-length") |
| scriptSig not executed | the coinbase scriptSig is never run; only the BIP34 prefix is inspected | C | `validation.cpp: ConnectBlock` (`CheckInputScripts` skips coinbase) |
| BIP34 height | after `BIP34Height`, scriptSig must START with `CScript() << height` (prefix match; extra bytes allowed) | C | `validation.cpp: ContextualCheckBlock` ("bad-cb-height"); [BIP34] |
| Height serialization | heights 1..16 serialize as the single byte `OP_1..OP_16` (0x51..0x60); other values as a minimal `CScriptNum` push (`0x03 <3 bytes LE>` for current mainnet heights) | C | `script.h: CScript::push_int64`, `CScriptNum::serialize` |
| Value | `sum(vout) <= subsidy(height) + fees` | C | `validation.cpp: ConnectBlock` ("bad-cb-amount") |
| Witness | if a commitment exists, `vin[0].scriptWitness` must be exactly one 32-byte item (the witness reserved value); its content is free | C | `validation.cpp: CheckWitnessMalleation` ("bad-witness-nonce-size") |
| Also a transaction | the coinbase passes `CheckTransaction` and `IsFinalTx` like any tx | C | `validation.cpp: CheckBlock`, `ContextualCheckBlock` |
| COINBASE_MATURITY | an output of a coinbase at height `h` is spendable at height `>= h + 100` (`spend_height - h >= 100`) | C | `consensus/tx_verify.cpp: CheckTxInputs`; `consensus/consensus.h` |

### 2.4 Merkle root and CVE-2012-2459

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Construction | leaves are txids (SHA256d); pair-wise SHA256d; an odd level duplicates its last hash | C | `consensus/merkle.cpp: ComputeMerkleRoot` |
| Header must match | `hashMerkleRoot == root` ("bad-txnmrklroot", `BLOCK_MUTATED`) | C | `validation.cpp: CheckMerkleRoot` |
| Duplicate detection | if at any level two adjacent hashes at positions `(2k, 2k+1)` are equal, the block is rejected ("bad-txns-duplicate", `BLOCK_MUTATED`) even though the root matches | C | `consensus/merkle.cpp: ComputeMerkleRoot(mutated)`; `validation.cpp: CheckMerkleRoot` |
| Not marked permanently invalid | `BLOCK_MUTATED` failures do not mark the header invalid (the honest block with that header may still arrive) | C | `validation.cpp: CheckMerkleRoot`; comment in `merkle.cpp` |
| 64-byte tx heuristic | `IsBlockMutated` also treats a coinbase-less block with a 64-byte tx as mutated; Core states this is not a consensus change | P | `validation.cpp: IsBlockMutated` |

### 2.5 BIP34 height and BIP30 duplicate transactions

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| BIP30 rule | no transaction in the block may have an unspent output already in the UTXO set (`HaveCoin(txid, o)` for every output index) | C | `validation.cpp: ConnectBlock` ("bad-txns-BIP30"); [BIP30] |
| Historical scope | originally blocks with `nTime` after 2012-03-15 00:00 UTC; now every block except the two exceptions | C | [BIP30]; comment in `ConnectBlock` |
| Exceptions | height 91842 hash `00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec` and height 91880 hash `00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721` | C | `validation.cpp: IsBIP30Repeat` |
| What the exceptions did | their coinbases duplicate the coinbases of blocks 91722 (`…2574dd08e`) and 91812 (`…9306f2f`); the earlier coins are overwritten, so only one UTXO survives per pair and the earlier one is "unspendable" | C | `validation.cpp: IsBIP30Unspendable`; `coins.cpp: AddCoins` ("Coinbase transactions can always be overwritten") |
| Overwrite semantics | when adding coinbase outputs Core allows overwriting an existing coin (replacing it, so the coin's height becomes the new block's height) | C | `coins.cpp: AddCoins` |
| Skip after BIP34 | Core skips the BIP30 scan once the chain contains `BIP34Hash` at `BIP34Height` (mainnet `000000000000024b89…0808b8` at 227931), because a height-prefixed coinbase cannot duplicate an earlier one | C (optimisation) | `validation.cpp: ConnectBlock` |
| Resume at 1,983,702 | pre-BIP34 coinbases exist whose "indicated height" is a later height (lowest: 209,921, 490,897, 1,983,702); Core re-enables the BIP30 scan for every block at height `>= 1,983,702` (`BIP34_IMPLIES_BIP30_LIMIT`) | C | `validation.cpp: ConnectBlock` |
| Block 490,897 | block 176,684 indicated height 490,897; its coinbase was spent in block 185,956 (tx `d4f7fbbf…8781`) so no violation is possible; Core comment records this analysis | C | comment in `validation.cpp: ConnectBlock` |
| Equivalent simpler rule | always running the BIP30 scan (except at 91842/91880) is consensus-equivalent on any chain and is what the rule literally says | C | [BIP30] |

### 2.6 Witness commitment (BIP141)

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Location | a coinbase output whose `scriptPubKey` is `>= 38` bytes and starts `6a 24 aa 21 a9 ed`; if several match, the LAST (highest index) is the commitment | C | `consensus/validation.h: GetWitnessCommitmentIndex`, `MINIMUM_WITNESS_COMMITMENT = 38`; [BIP141] |
| Commitment value | bytes 6..38 must equal `SHA256d(witness_root || witness_reserved_value)` | C | `validation.cpp: CheckWitnessMalleation` ("bad-witness-merkle-match") |
| Witness root | Merkle root over `wtxid`s with the coinbase leaf = 32 zero bytes; same odd-duplication rule, no mutation check | C | `consensus/merkle.cpp: BlockWitnessMerkleRoot` |
| Witness reserved value | `vtx[0].vin[0].scriptWitness.stack` must be exactly one 32-byte item | C | `validation.cpp: CheckWitnessMalleation` |
| Optional when no witness | when segwit is active and no commitment is present, no transaction may carry witness data ("unexpected-witness") | C | `validation.cpp: CheckWitnessMalleation`; [BIP141] |
| Before segwit | the commitment is not looked for; every tx must have empty witness | C | `validation.cpp: ContextualCheckBlock` (`expect_witness_commitment = false`) |
| Extra bytes after the commitment | allowed; the script only needs `>= 38` bytes (signet puts its solution there) | C | `consensus/validation.h: GetWitnessCommitmentIndex`; [BIP325] |
| wtxid | `SHA256d` of the tx with witness; equals txid when no input has a witness | C | `primitives/transaction.h: GetWitnessHash`; [BIP141] |

### 2.7 Block subsidy

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Schedule | `50 * COIN >> (height / nSubsidyHalvingInterval)` | C | `validation.cpp: GetBlockSubsidy` |
| Interval | 210,000 (main, testnet3, testnet4, signet); 150 (regtest) | C | `kernel/chainparams.cpp` |
| 64 halvings | if `halvings >= 64` the subsidy is 0 (avoids undefined shift) | C | `validation.cpp: GetBlockSubsidy` |
| COIN, MAX_MONEY | `COIN = 100,000,000`; `MAX_MONEY = 21,000,000 * COIN` | C | `consensus/amount.h` |

### 2.8 Which checks run where

| Stage | Checks | Context | Source |
| --- | --- | --- | --- |
| `CheckBlockHeader` | PoW | none | `validation.cpp` |
| `CheckBlock` | header PoW; signet solution; merkle root and mutation; `vtx` non-empty; tx count and base size; first tx coinbase, no other coinbase; `CheckTransaction` for each tx; legacy sigops `* 4 <= 80,000` | none | `validation.cpp: CheckBlock` |
| `ContextualCheckBlockHeader` | nBits; MTP; BIP94; future time; version floor | headers | `validation.cpp` |
| `ContextualCheckBlock` | every tx `IsFinalTx` (BIP113 cutoff once CSV active); BIP34 height; witness commitment / no unexpected witness; weight `<= 4,000,000` | headers | `validation.cpp` |
| `ConnectBlock` | BIP30; per tx: inputs exist and unspent, maturity, money ranges, fee `>= 0`, BIP68, sigop cost, scripts; accumulated fees in range; coinbase value | UTXO set | `validation.cpp: ConnectBlock` |
| Signet | `CheckSignetBlockSolution` inside `CheckBlock` (genesis exempt): solution parsed from the witness commitment output after header `ec c7 da a2`; `to_spend`/`to_sign` per BIP325; verified with `P2SH | WITNESS | DERSIG | NULLDUMMY` | none | `signet.cpp: CheckSignetBlockSolution`, `SignetTxs::Create`; [BIP325] |

## 3. Transaction rules

### 3.1 Consensus

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Non-empty vin, vout | "bad-txns-vin-empty", "bad-txns-vout-empty" | C | `consensus/tx_check.cpp: CheckTransaction` |
| Size | base (non-witness) size `* 4 <= 4,000,000` | C | `consensus/tx_check.cpp: CheckTransaction` |
| Output range | each `nValue` in `[0, MAX_MONEY]`; running sum in `[0, MAX_MONEY]` (CVE-2010-5139) | C | `consensus/tx_check.cpp: CheckTransaction`; `consensus/amount.h: MoneyRange` |
| No duplicate inputs | all `prevout`s distinct (CVE-2018-17144) | C | `consensus/tx_check.cpp: CheckTransaction` |
| Non-coinbase prevouts | no input may have a null prevout | C | `consensus/tx_check.cpp: CheckTransaction` ("bad-txns-prevout-null") |
| Inputs exist and unspent | every prevout must be an unspent coin in the view (including coins created earlier in the same block) | C | `consensus/tx_verify.cpp: CheckTxInputs` ("bad-txns-inputs-missingorspent") |
| Immature coinbase | see 2.3 | C | `consensus/tx_verify.cpp: CheckTxInputs` |
| Input range | each input value and the running sum in `MoneyRange` | C | `consensus/tx_verify.cpp: CheckTxInputs` |
| Fee non-negative | `sum(in) >= sum(out)`; fee in `MoneyRange`; block fee total in `MoneyRange` | C | `consensus/tx_verify.cpp: CheckTxInputs`; `validation.cpp: ConnectBlock` |
| nLockTime = 0 | final | C | `consensus/tx_verify.cpp: IsFinalTx` |
| nLockTime < 500,000,000 | interpreted as height; final if `nLockTime < block height` | C | `consensus/tx_verify.cpp: IsFinalTx`; `script.h: LOCKTIME_THRESHOLD` |
| nLockTime >= 500,000,000 | interpreted as time; final if `nLockTime < cutoff` | C | `consensus/tx_verify.cpp: IsFinalTx` |
| Cutoff (BIP113) | `MTP(prev)` once CSV is active, else the block's own `nTime` | C | `validation.cpp: ContextualCheckBlock`; [BIP113] |
| Final-sequence bypass | if every input has `nSequence == 0xffffffff` the lock time is ignored | C | `consensus/tx_verify.cpp: IsFinalTx` |
| BIP68 applies when | `tx.version >= 2` (unsigned compare; `version` is `uint32_t`) and CSV is active | C | `consensus/tx_verify.cpp: CalculateSequenceLocks`; `primitives/transaction.h`; [BIP68] |
| BIP68 disable flag | bit 31 set: no relative lock | C | `primitives/transaction.h: SEQUENCE_LOCKTIME_DISABLE_FLAG` |
| BIP68 type flag | bit 22: set = time-based (units of 512 s, `<< 9`); clear = blocks | C | `SEQUENCE_LOCKTIME_TYPE_FLAG`, `SEQUENCE_LOCKTIME_GRANULARITY` |
| BIP68 mask | low 16 bits `0x0000ffff` carry the value | C | `SEQUENCE_LOCKTIME_MASK` |
| BIP68 height lock | satisfied when `block.height > coin.height + n - 1` | C | `consensus/tx_verify.cpp: CalculateSequenceLocks`, `EvaluateSequenceLocks` |
| BIP68 time lock | satisfied when `MTP(prev) > MTP(ancestor at coin.height - 1) + n*512 - 1` | C | same |
| BIP68 same-block parents | coins created in the same block have `height = this height`, so any `n >= 1` height lock fails | C | `validation.cpp: ConnectBlock` (prevheights from view) |
| Witness on non-witness input | any witness on an input whose script is not a witness program (native or P2SH-wrapped) fails (`SCRIPT_ERR_WITNESS_UNEXPECTED`) | C | `script/interpreter.cpp: VerifyScript` |
| Witness stripping | detected by the commitment (2.6); a segwit block's witnesses are committed to by the coinbase | C | `validation.cpp: CheckWitnessMalleation` |
| Version field | any `uint32_t` value is valid by consensus | C | `primitives/transaction.h`; `policy/policy.cpp: IsStandardTx` (policy 1..3) |
| Script validity | every non-coinbase input runs `VerifyScript` with the block's flags (section 4) | C | `validation.cpp: CheckInputScripts`, `CScriptCheck` |

### 3.2 Policy only (not consensus)

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Dust | `DUST_RELAY_TX_FEE = 3000` sat/kvB, `IsDust` | P | `policy/policy.h` |
| Min relay fee | `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB; `DEFAULT_INCREMENTAL_RELAY_FEE = 100` | P | `policy/policy.h` |
| MAX_STANDARD_TX_WEIGHT | 400,000 | P | `policy/policy.h` |
| MIN_STANDARD_TX_NONWITNESS_SIZE | 65 bytes | P | `policy/policy.h` |
| Standard versions | `TX_MIN_STANDARD_VERSION = 1`, `TX_MAX_STANDARD_VERSION = 3` | P | `policy/policy.h`; `policy/policy.cpp: IsStandardTx` |
| Standard output types | `IsStandard`: P2PK, P2PKH, P2SH, bare multisig (if `-permitbaremultisig`), `OP_RETURN` up to `-datacarriersize` (default `MAX_OP_RETURN_RELAY = 100,000` vbytes), witness programs | P | `policy/policy.h`, `policy.cpp: IsStandardTx` |
| Standard inputs | `AreInputsStandard`; `MAX_P2SH_SIGOPS = 15`; `MAX_STANDARD_SCRIPTSIG_SIZE = 1650` | P | `policy/policy.h` |
| Sigops per tx | `MAX_STANDARD_TX_SIGOPS_COST = 16,000`; `MAX_TX_LEGACY_SIGOPS = 2,500`; `-bytespersigop = 20` | P | `policy/policy.h` |
| P2WSH limits | `MAX_STANDARD_P2WSH_STACK_ITEMS = 100`, item size 80, script size 3,600 | P | `policy/policy.h`; `IsWitnessStandard` |
| Tapscript limits | `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80`; annex non-standard | P | `policy/policy.h`; `IsWitnessStandard` |
| Unknown witness versions | non-standard (`SpendsNonAnchorWitnessProg`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`) except P2A | P | `policy/policy.h`; `script/interpreter.h` |
| Script flags | `STANDARD_NOT_MANDATORY_VERIFY_FLAGS` (section 4.2) | P | `policy/policy.h` |
| Mempool shape | ancestor/descendant/cluster limits, RBF, package rules | P | `policy/policy.h`; `validation.cpp: MemPoolAccept` |
| Multi-A key count | `MAX_PUBKEYS_PER_MULTI_A = 999` is a descriptor limit, not a script rule | P | `script/script.h` |

## 4. Script

### 4.1 Opcodes

Execution model: `EvalScript` walks the script; pushes go on the stack when executed; an opcode
in `OP_IF..OP_ENDIF` (0x63..0x68) is always dispatched, other opcodes only when executed. Unknown
or reserved opcodes fail only when dispatched. Disabled opcodes fail while parsing, even in an
unexecuted branch. `SigVersion` is `BASE` (bare and P2SH), `WITNESS_V0`, `TAPSCRIPT`.

| Opcode(s) | Legacy / v0 status | Tapscript status | Source |
| --- | --- | --- | --- |
| `0x00..0x4e` pushes (`OP_0`, direct, `PUSHDATA1/2/4`) | push; item `<= 520` bytes; parse failure = script fails | same | `interpreter.cpp: EvalScript`; `script.cpp: GetScriptOp` |
| `0x4f OP_1NEGATE`, `0x51..0x60 OP_1..OP_16` | push number | same | `EvalScript` |
| `0x50 OP_RESERVED` | fails if executed; does not count toward the 201 limit | `OP_SUCCESS80` | `EvalScript` (default case); `script.cpp: IsOpSuccess` |
| `0x61 OP_NOP` | no-op (counts) | same | `EvalScript` |
| `0x62 OP_VER` | fails if executed | `OP_SUCCESS98` | `EvalScript`; `IsOpSuccess` |
| `0x63 OP_IF`, `0x64 OP_NOTIF` | conditional; v0: `MINIMALIF` is policy | argument must be `[]` or `[0x01]` (consensus) | `EvalScript` |
| `0x65 OP_VERIF`, `0x66 OP_VERNOTIF` | fail even when NOT executed (dispatched as part of the IF range) | same (not `OP_SUCCESS`) | `EvalScript` (`OP_IF <= opcode <= OP_ENDIF` dispatch) |
| `0x67 OP_ELSE`, `0x68 OP_ENDIF` | must be balanced; unbalanced at end = fail | same | `EvalScript` |
| `0x69 OP_VERIFY` | fail on false | same | `EvalScript` |
| `0x6a OP_RETURN` | fails if executed | same | `EvalScript` |
| `0x6b..0x7d` stack ops (`TOALTSTACK` .. `TUCK`) | enabled | same | `EvalScript` |
| `0x7e OP_CAT`, `0x7f OP_SUBSTR`, `0x80 OP_LEFT`, `0x81 OP_RIGHT` | disabled: fail even if unexecuted (CVE-2010-5137) | `OP_SUCCESS126..129` | `EvalScript`; `IsOpSuccess` |
| `0x82 OP_SIZE` | enabled | same | `EvalScript` |
| `0x83 OP_INVERT`, `0x84 OP_AND`, `0x85 OP_OR`, `0x86 OP_XOR` | disabled (as above) | `OP_SUCCESS131..134` | same |
| `0x87 OP_EQUAL`, `0x88 OP_EQUALVERIFY` | enabled | same | `EvalScript` |
| `0x89 OP_RESERVED1`, `0x8a OP_RESERVED2` | fail if executed | `OP_SUCCESS137..138` | same |
| `0x8b OP_1ADD`, `0x8c OP_1SUB` | enabled, 4-byte operands | same | `EvalScript` |
| `0x8d OP_2MUL`, `0x8e OP_2DIV` | disabled (as above) | `OP_SUCCESS141..142` | same |
| `0x8f..0x94` (`NEGATE`, `ABS`, `NOT`, `0NOTEQUAL`, `ADD`, `SUB`) | enabled | same | `EvalScript` |
| `0x95 OP_MUL`, `0x96 OP_DIV`, `0x97 OP_MOD`, `0x98 OP_LSHIFT`, `0x99 OP_RSHIFT` | disabled (as above) | `OP_SUCCESS149..153` | same |
| `0x9a..0xa5` (`BOOLAND` .. `WITHIN`) | enabled | same | `EvalScript` |
| `0xa6..0xaa` (`RIPEMD160`, `SHA1`, `SHA256`, `HASH160`, `HASH256`) | enabled | same | `EvalScript` |
| `0xab OP_CODESEPARATOR` | BASE: scriptCode starts after the last executed one, and `FindAndDelete` applies; v0: scriptCode starts after the last executed one, no `FindAndDelete`; `CONST_SCRIPTCODE` (policy) rejects it in BASE even unexecuted | records `codesep_pos` (opcode index) for the sighash; tapleaf hash is unaffected | `EvalScript`; `SignatureHash`; `SignatureHashSchnorr`; [BIP143]; [BIP342] |
| `0xac OP_CHECKSIG`, `0xad OP_CHECKSIGVERIFY` | ECDSA over BIP143 (v0) or legacy sighash | BIP340 Schnorr, 32-byte keys, budget (4.6) | `EvalChecksigPreTapscript`; `EvalChecksigTapscript` |
| `0xae OP_CHECKMULTISIG`, `0xaf OP_CHECKMULTISIGVERIFY` | `n <= 20` keys, `m <= n`; adds `n` to the op count; consumes one extra "dummy" element; `NULLDUMMY` (dummy must be empty) is consensus since segwit activation | fail if executed (`SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`) | `EvalScript`; `GetBlockScriptFlags`; [BIP147]; [BIP342] |
| `0xb0 OP_NOP1`, `0xb3..0xb9 OP_NOP4..OP_NOP10` | no-op; `DISCOURAGE_UPGRADABLE_NOPS` is policy | same | `EvalScript` |
| `0xb1 OP_CHECKLOCKTIMEVERIFY` (`NOP2`) | NOP before BIP65; after: 5-byte operand, `>= 0`, same type as `nLockTime`, `<= nLockTime`, input `nSequence != 0xffffffff`; leaves operand on stack | same | `EvalScript`; `CheckLockTime`; [BIP65] |
| `0xb2 OP_CHECKSEQUENCEVERIFY` (`NOP3`) | NOP before CSV; after: 5-byte operand, `>= 0`; if operand bit 31 set = NOP; else `tx.version >= 2` as `uint32_t` (a negative version passes; `tx_valid.json` has one), input bit 31 clear, same type (bit 22), masked operand `<=` masked input | same | `EvalScript`; `CheckSequence`; [BIP112] |
| `0xba OP_CHECKSIGADD` | fails if executed (`BAD_OPCODE`) | `(sig n pubkey -- n+success)` | `EvalScript`; [BIP342] |
| `0xbb..0xfe` | fail if executed | `OP_SUCCESS187..254` | `EvalScript`; `IsOpSuccess` |
| `0xff OP_INVALIDOPCODE` | fail if executed | fail if executed (255 is not `OP_SUCCESS`) | `EvalScript`; `IsOpSuccess` |
| Numeric operands | `CScriptNum` accepts `<= 4` bytes (5 for CLTV/CSV); results may exceed 4 bytes but then fail as operands; `MINIMALDATA` (minimal encoding) is policy | same | `script.h: CScriptNum` |
| Truthiness | `CastToBool`: any non-zero byte is true except negative zero (`0x80` last byte with all others zero) | same | `interpreter.cpp: CastToBool` |

### 4.2 Verification flags Core applies per block

`GetBlockScriptFlags` is the only source of block-level script flags.

| Flag | When applied to a block | C/P | Source |
| --- | --- | --- | --- |
| `SCRIPT_VERIFY_P2SH` | every block, except the exception blocks below (Core does not implement the BIP16 timestamp rule; "only one historical block violated the P2SH rules") | C | `validation.cpp: GetBlockScriptFlags`; [BIP16] |
| `SCRIPT_VERIFY_WITNESS` | every block except the exception blocks (witness data cannot appear pre-segwit anyway, see 2.6) | C | `GetBlockScriptFlags` |
| `SCRIPT_VERIFY_TAPROOT` | every block except the exception blocks; the taproot versionbits deployment is NOT consulted for validation (only by RPC) | C | `GetBlockScriptFlags`; `rpc/blockchain.cpp` (sole other use of `DEPLOYMENT_TAPROOT`) |
| `SCRIPT_VERIFY_DERSIG` | height `>= BIP66Height` | C | `GetBlockScriptFlags`; [BIP66] |
| `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` | height `>= BIP65Height` | C | `GetBlockScriptFlags`; [BIP65] |
| `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` | height `>= CSVHeight` | C | `GetBlockScriptFlags`; [BIP112] |
| `SCRIPT_VERIFY_NULLDUMMY` | height `>= SegwitHeight` | C | `GetBlockScriptFlags`; [BIP147] |
| Exception: mainnet block 170060 | hash `00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22` gets `SCRIPT_VERIFY_NONE` (the BIP16 violation); height via chain data | C | `kernel/chainparams.cpp: CMainParams` (`script_flag_exceptions`) |
| Exception: mainnet block 692261 | hash `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad` gets `P2SH | WITNESS` only (a pre-activation taproot-rule violation); height via chain data | C | `kernel/chainparams.cpp: CMainParams` |
| Exception: testnet3 block 394 | hash `00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105` gets `SCRIPT_VERIFY_NONE`; height via chain data | C | `kernel/chainparams.cpp: CTestNetParams` |
| Mandatory set (relay) | `P2SH | DERSIG | NULLDUMMY | CLTV | CSV | WITNESS | TAPROOT` | – | `policy/policy.h: MANDATORY_SCRIPT_VERIFY_FLAGS` |
| Standard-not-mandatory | `STRICTENC`, `MINIMALDATA`, `DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, `MINIMALIF`, `NULLFAIL`, `LOW_S`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`, `WITNESS_PUBKEYTYPE`, `CONST_SCRIPTCODE`, `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`, `DISCOURAGE_OP_SUCCESS`, `DISCOURAGE_UPGRADABLE_PUBKEYTYPE` | P | `policy/policy.h: STANDARD_NOT_MANDATORY_VERIFY_FLAGS` |
| `SCRIPT_VERIFY_SIGPUSHONLY` | defined, used by neither block validation nor standardness | – | `script/interpreter.h` |
| Signet block solution | verified with `P2SH | WITNESS | DERSIG | NULLDUMMY` regardless of height | C (signet) | `signet.cpp: BLOCK_SCRIPT_VERIFY_FLAGS` |

Consequence for an implementer: on the mainnet chain, "P2SH/segwit/taproot script rules from
genesis except the listed blocks" and "P2SH from timestamp 1333238400, segwit from 481824,
taproot from 709632" accept the same blocks. Core's form is stricter on hypothetical forks; the
listed exception blocks are the only places where the two differ on the real chain.

### 4.3 Limits

| Limit | Value | Applies to | Source |
| --- | --- | --- | --- |
| `MAX_SCRIPT_SIZE` | 10,000 bytes | BASE and WITNESS_V0 scripts being executed (scriptSig, scriptPubKey, redeemScript, witnessScript); not tapscript | `interpreter.cpp: EvalScript`; `script.h`; [BIP342] |
| `MAX_SCRIPT_ELEMENT_SIZE` | 520 bytes | every push; every witness stack item (v0 and tapscript initial stack); bypassed only by `OP_SUCCESS` | `EvalScript`; `ExecuteWitnessScript` |
| `MAX_STACK_SIZE` | 1,000 | `stack + altstack` after every executed opcode, all versions; tapscript also checks the initial stack | `EvalScript`; `ExecuteWitnessScript`; [BIP342] |
| `MAX_OPS_PER_SCRIPT` | 201 | BASE and v0: every opcode `> OP_16` (0x60) counts, executed or not; pushes and `OP_RESERVED` do not; `CHECKMULTISIG` adds its key count; not tapscript | `EvalScript` |
| `MAX_PUBKEYS_PER_MULTISIG` | 20 | `CHECKMULTISIG(VERIFY)` key count | `EvalScript`; `script.h` |
| Signature count | `0 <= m <= n` | `CHECKMULTISIG(VERIFY)` | `EvalScript` |
| `CScriptNum` size | 4 bytes (5 for CLTV/CSV operands) | numeric operands | `script.h: CScriptNum::nDefaultMaxNumSize` |
| Tapscript sigop budget | `50 + serialized size of the input's witness` (compact-size prefixes included); `-50` per checksig with a non-empty signature | tapscript only | `VerifyWitnessProgram`; `EvalChecksigTapscript`; `script.h: VALIDATION_WEIGHT_*`; [BIP342] |
| Control block | `33 + 32*m` bytes, `0 <= m <= 128` (max 4,129) | taproot script path | `interpreter.h: TAPROOT_CONTROL_*`; [BIP341] |
| Witness program length | 2..40 bytes | witness program detection | `script.cpp: IsWitnessProgram`; [BIP141] |
| Block sigops | 80,000 (2.2) | block | `consensus/consensus.h` |

### 4.4 P2SH (BIP16)

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Pattern | exactly 23 bytes: `OP_HASH160 0x14 <20 bytes> OP_EQUAL` | C | `script.cpp: IsPayToScriptHash`; [BIP16] |
| Push-only scriptSig | any non-push opcode in the scriptSig fails (`SIG_PUSHONLY`) | C | `interpreter.cpp: VerifyScript`; [BIP16] |
| Evaluation order | run scriptSig, copy the stack, run scriptPubKey, require true; then restore the copy, pop the last element as the redeemScript, run it with the remaining stack, require non-empty stack with true top | C | `VerifyScript` |
| redeemScript size | limited to 520 bytes by the push limit | C | `EvalScript`; [BIP16] |
| P2SH inside P2SH | the redeemScript is run as `SigVersion::BASE` with no further P2SH recursion | C | `VerifyScript` |
| Timestamp rule | BIP16 says enforce for blocks with `nTime >= 1333238400`; Core applies P2SH always except block 170060 (4.2) | C | [BIP16]; `GetBlockScriptFlags` |
| CLEANSTACK | exactly one stack element left after P2SH evaluation: policy | P | `VerifyScript`; `interpreter.h` |

### 4.5 Segregated witness v0 (BIP141, BIP143)

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Witness program | scriptPubKey (or redeemScript) of 4..42 bytes: `OP_0` or `OP_1..OP_16`, then one direct push whose length byte `+ 2 == script size` | C | `script.cpp: IsWitnessProgram`; [BIP141] |
| Native program: scriptSig | must be exactly empty (`SCRIPT_ERR_WITNESS_MALLEATED`) | C | `VerifyScript` |
| P2SH-wrapped program | scriptSig must be exactly one push of the redeemScript (`WITNESS_MALLEATED_P2SH`) | C | `VerifyScript` |
| v0, 20-byte program (P2WPKH) | witness must have exactly 2 items; executes `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` as `WITNESS_V0` | C | `VerifyWitnessProgram` |
| v0, 32-byte program (P2WSH) | witness non-empty; last item is the witnessScript; `SHA256(witnessScript) == program`; execute with the remaining items as the stack | C | `VerifyWitnessProgram` |
| v0, other length | fails (`WITNESS_PROGRAM_WRONG_LENGTH`) | C | `VerifyWitnessProgram`; [BIP141] |
| Witness items | each `<= 520` bytes; witnessScript `<= 10,000` bytes (via `EvalScript`) | C | `ExecuteWitnessScript`; `EvalScript` |
| Implicit cleanstack | exactly one element left and it is true | C | `ExecuteWitnessScript` |
| Versions 1..16 (not taproot, not P2A) | succeed without looking at the witness ("anyone can spend"); `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` is policy | C / P | `VerifyWitnessProgram`; [BIP141] |
| v1 32-byte inside P2SH | treated as an unknown program (success), not as taproot | C | `VerifyWitnessProgram` (`!is_p2sh`) |
| P2A | v1 with program `4e73` (2 bytes), not P2SH: always true, even under the discourage flag (a policy carve-out, consensus unchanged) | C / P | `script.cpp: IsPayToAnchor`; `VerifyWitnessProgram` |
| Compressed keys only | `WITNESS_PUBKEYTYPE`: policy | P | `CheckPubKeyEncoding` |
| MINIMALIF in v0 | policy | P | `EvalScript` |
| BIP143 digest | `SHA256d(version || hashPrevouts || hashSequence || outpoint || scriptCode || amount || nSequence || hashOutputs || nLockTime || hashtype(4 bytes LE))` | C | `SignatureHash` (`WITNESS_V0` branch); [BIP143] |
| hashPrevouts | `SHA256d(all outpoints)` unless `ANYONECANPAY` (then 32 zero bytes) | C | `SignatureHash`; [BIP143] |
| hashSequence | `SHA256d(all nSequence)` unless `ANYONECANPAY`, `SINGLE` or `NONE` (then zero) | C | same |
| hashOutputs | `SHA256d(all outputs)` for ALL; `SHA256d(vout[nIn])` for SINGLE with `nIn < vout.size()`; else zero (BIP143 uses zero where legacy uses the "1" hash) | C | same |
| scriptCode | P2WPKH: `1976a914{20}88ac`; P2WSH: witnessScript from after the last EXECUTED `OP_CODESEPARATOR`; no `FindAndDelete` | C | `EvalChecksigPreTapscript`; [BIP143] |
| Amount | the spent output's value is part of the digest; a missing amount is a validation failure | C | `CheckECDSASignature` |

### 4.6 Taproot (BIP340, BIP341, BIP342)

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Trigger | witness version 1, 32-byte program, not P2SH-wrapped, `SCRIPT_VERIFY_TAPROOT` set | C | `VerifyWitnessProgram`; [BIP341] |
| Empty witness | fails | C | `VerifyWitnessProgram` |
| Annex | if `>= 2` items and the last starts with `0x50`, it is removed; `sha_annex = SHA256(compact_size(len) || annex)` enters the sighash; non-standard by policy | C | `VerifyWitnessProgram`; `script.h: ANNEX_TAG`; [BIP341] |
| Key path | exactly one item left: a Schnorr signature over the output key `q` (the program) | C | `VerifyWitnessProgram`; `CheckSchnorrSignature` |
| Signature length | 64 bytes (`SIGHASH_DEFAULT`) or 65 bytes with a trailing hash type that must not be `0x00` | C | `CheckSchnorrSignature`; [BIP341] |
| hash_type set | `{0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}`; anything else fails | C | `SignatureHashSchnorr`; [BIP341] |
| Sighash | `SHA256(tag "TapSighash") ` over `0x00 (epoch) || hash_type || version || nLockTime || [sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences unless ANYONECANPAY] || [sha_outputs if ALL/DEFAULT] || spend_type || (outpoint, spent output, nSequence if ANYONECANPAY else input index u32) || [sha_annex] || [sha_single_output if SINGLE] || [tapleaf_hash, key_version=0x00, codesep_pos u32 if tapscript]`; all sub-hashes single SHA256 | C | `SignatureHashSchnorr`; `PrecomputedTransactionData::Init`; [BIP341] |
| spend_type | `ext_flag * 2 + annex_present`; `ext_flag = 0` key path, `1` tapscript | C | `SignatureHashSchnorr` |
| SINGLE without output | `nIn >= vout.size()` with SINGLE fails (no "hash 1" fallback) | C | `SignatureHashSchnorr` |
| Script path | last item = control block `c`, previous = script `s`; `len(c) = 33 + 32m`, `m <= 128` | C | `VerifyWitnessProgram` |
| Leaf version | `v = c[0] & 0xfe`; tapleaf hash `tagged("TapLeaf", v || compact_size(len(s)) || s)` | C | `ComputeTapleafHash` |
| Merkle path | `tagged("TapBranch", min(a,b) || max(a,b))` lexicographically, up the path | C | `ComputeTapbranchHash`, `ComputeTaprootMerkleRoot` |
| Commitment | `q == p + tagged("TapTweak", p || root) * G` with Y parity `c[0] & 1`; `p` is `c[1..33]` | C | `VerifyTaprootCommitment`; `pubkey.cpp: XOnlyPubKey::CheckTapTweak` |
| Unknown leaf version | any `v != 0xc0` succeeds without executing; `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` is policy | C / P | `VerifyWitnessProgram`; [BIP341] |
| Tapscript = leaf 0xc0 | the script is executed as `SigVersion::TAPSCRIPT` | C | `VerifyWitnessProgram`; [BIP342] |
| OP_SUCCESSx first | the script is parsed before execution; any `OP_SUCCESSx` (4.1) makes the spend valid unconditionally, even with an unparsable tail, oversized stack items or unbalanced IFs; a parse error before finding one fails | C | `ExecuteWitnessScript`; [BIP342] |
| Initial stack | `<= 1,000` items and each item `<= 520` bytes (checked after the `OP_SUCCESS` scan) | C | `ExecuteWitnessScript` |
| Result | exactly one true element | C | `ExecuteWitnessScript` |
| No 10,000-byte / 201-op limits | script size and op count are not limited in tapscript | C | `EvalScript`; [BIP342] |
| Sigop budget | `50 + GetSerializeSize(witness.stack)`; each `CHECKSIG/CHECKSIGVERIFY/CHECKSIGADD` with a non-empty signature subtracts 50 BEFORE any other check; below 0 fails | C | `EvalChecksigTapscript`; `VerifyWitnessProgram` |
| Public key rules | empty key: fail; 32-byte key: BIP340 verify (only if the signature is non-empty; a bad signature fails the script); any other length: "unknown type", treated as success without verification (`DISCOURAGE_UPGRADABLE_PUBKEYTYPE` is policy) | C / P | `EvalChecksigTapscript`; [BIP342] |
| Empty signature | pushes false (CHECKSIG) / `n` (CHECKSIGADD) / fails (CHECKSIGVERIFY); no budget cost | C | `EvalChecksigTapscript`; `EvalScript` |
| CHECKSIGADD | `(sig n pubkey -- n + 1 or n)`; `n` is a `CScriptNum` | C | `EvalScript`; [BIP342] |
| CHECKMULTISIG(VERIFY) | fail if executed | C | `EvalScript` |
| MINIMALIF | consensus: `OP_IF/OP_NOTIF` argument must be `[]` or `[0x01]` | C | `EvalScript`; [BIP342] |
| codesep_pos | opcode index (pushes count as one, unexecuted branches count) of the last executed `OP_CODESEPARATOR`, `0xffffffff` if none | C | `EvalScript`; [BIP342] |
| BIP340 verification | x-only 32-byte key with even Y; signature `(r, s)`; `s*G = R + tagged("BIP0340/challenge", r || pk || m) * P`; `lift_x` fails for `x >= p` or non-residue | C | `pubkey.cpp: XOnlyPubKey::VerifySchnorr` (libsecp256k1); [BIP340] |

### 4.7 Signature encoding, pubkey encoding and legacy sighash

| Rule | Detail | C/P | Source |
| --- | --- | --- | --- |
| Hash type byte | the last byte of the ECDSA signature; removed before verification | C | `CheckECDSASignature` |
| Undefined hash types | any byte is consensus-valid in legacy/v0; `& 0x1f` selects NONE (2) / SINGLE (3), else behaves as ALL; `0x80` = ANYONECANPAY. `STRICTENC` (policy) restricts to 1..3 plus 0x80 | C / P | `CTransactionSignatureSerializer`; `IsDefinedHashtypeSignature` |
| Legacy sighash | `SHA256d(serialized tx with scriptSigs blanked except `scriptCode` at `nIn`; for NONE no outputs and other inputs' `nSequence = 0`; for SINGLE outputs `0..nIn` with the others blanked (`nValue = -1`, empty script) and other `nSequence = 0`; for ANYONECANPAY only input `nIn`) || hashtype u32 LE)` | C | `SignatureHash` (BASE branch); `CTransactionSignatureSerializer` |
| SIGHASH_SINGLE bug | BASE: if `nIn >= vout.size()` the "hash" is the value 1 (`uint256::ONE`) and any signature over that constant verifies | C | `SignatureHash` |
| OP_CODESEPARATOR in scriptCode | BASE only: the serialized scriptCode has all `OP_CODESEPARATOR`s removed. The `WITNESS_V0` branch of `SignatureHash` serializes the scriptCode as is, separators included (4.5) | C | `CTransactionSignatureSerializer::SerializeScriptCode`; `SignatureHash` (`WITNESS_V0` branch); [BIP143] |
| FindAndDelete | BASE only: every occurrence of the exact signature push is removed from scriptCode before hashing; `CONST_SCRIPTCODE` (policy) rejects when anything was found | C / P | `EvalChecksigPreTapscript`; `interpreter.cpp: FindAndDelete` |
| Empty signature | always passes encoding checks and always fails verification (used to skip keys in multisig) | C | `CheckSignatureEncoding` |
| Strict DER (BIP66) | with `DERSIG`: 9..73 bytes, `0x30 len 0x02 lenR R 0x02 lenS S hashtype`, no negative or padded R/S, lengths consistent | C | `IsValidSignatureEncoding`; [BIP66] |
| Pre-BIP66 parsing | without `DERSIG` Core parses signatures with `ecdsa_signature_parse_der_lax` (tolerates BER-style length forms, leading zeros, trailing garbage) and normalizes high S. An independent node must accept the same set to validate blocks below 363725 | C | `pubkey.cpp: CPubKey::Verify`, `ecdsa_signature_parse_der_lax` |
| LOW_S | policy only; high-S signatures are consensus-valid (normalized before verifying) | P | `CheckSignatureEncoding`; `CPubKey::Verify` |
| NULLFAIL | policy: a failed check must have an empty signature | P | `EvalChecksigPreTapscript`; `EvalScript` |
| Pubkey validity | accepted headers: `0x02/0x03` (33 bytes), `0x04/0x06/0x07` (65 bytes, hybrid included); an unparsable key makes the check false (not a script failure). `STRICTENC` (policy) rejects hybrid and odd sizes | C / P | `pubkey.h: CPubKey::GetLen`, `IsValid`; `CPubKey::Verify`; `IsCompressedOrUncompressedPubKey` |
| CHECKMULTISIG order | keys and signatures are matched in order; on a mismatch the key pointer advances; failure once `sigs left > keys left` | C | `EvalScript` |
| NULLDUMMY | consensus since `SegwitHeight`: the dummy element must be empty | C | `EvalScript`; `GetBlockScriptFlags`; [BIP147] |

## 5. Softfork activation

### 5.1 Mechanisms

| Mechanism | Detail | Source |
| --- | --- | --- |
| Buried deployment | a fixed height per chain; active for a block when `block.height >= height` (`DeploymentActiveAt`) and for the next block when `prev.height + 1 >= height` (`DeploymentActiveAfter`) | `deploymentstatus.h`; `consensus/params.h: BuriedDeployment`; [BIP90] |
| Buried set | BIP34 (`DEPLOYMENT_HEIGHTINCB`), BIP65 (`CLTV`), BIP66 (`DERSIG`), CSV (BIP68/112/113), SEGWIT (BIP141/143/147) | `consensus/params.h` |
| Versionbits (BIP9 as modified by BIP341) | `DEPLOYMENT_TESTDUMMY`, `DEPLOYMENT_TAPROOT`; state per period from `bit`, `nStartTime`, `nTimeout`, `min_activation_height`, `period`, `threshold` | `consensus/params.h: BIP9Deployment`; `versionbits.cpp: GetStateFor`; [BIP9]; [BIP341] |
| Taproot in validation | the taproot versionbits state is not consulted by validation (4.2); it only feeds `getdeploymentinfo`. Consensus-wise Core behaves as "taproot rules always on except block 692261" | `validation.cpp: GetBlockScriptFlags`; `rpc/blockchain.cpp` |
| Special start times | `ALWAYS_ACTIVE = -1` (state ACTIVE from genesis), `NEVER_ACTIVE = -2` (state FAILED); `NO_TIMEOUT = INT64_MAX` | `consensus/params.h: BIP9Deployment` |

### 5.2 Buried deployment heights per chain

| Chain | BIP34 (hash) | BIP66 | BIP65 | CSV | SegWit | Source |
| --- | --- | --- | --- | --- | --- | --- |
| main | 227931 (`000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8`) | 363725 | 388381 | 419328 | 481824 | `kernel/chainparams.cpp: CMainParams`; [BIP90] |
| testnet3 | 21111 (`0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8`) | 330776 | 581885 | 770112 | 834624 | `CTestNetParams` |
| testnet4 | 1 (no hash) | 1 | 1 | 1 | 1 | `CTestNet4Params` |
| signet | 1 (no hash) | 1 | 1 | 1 | 1 | `SigNetParams` |
| regtest | 1 (no hash) | 1 | 1 | 1 | 0 | `CRegTestParams` (overridable) |

Block hashes Core records in comments for the mainnet heights: BIP66 `…8b50931`, BIP65
`…c4735f0`, CSV `…716b5b5`, SegWit `…167f9893` (`kernel/chainparams.cpp: CMainParams`). Original
BIP9 parameters, for the record: CSV bit 0, start 1462060800, timeout 1493596800 ([BIP68]);
SegWit bit 1, start 1479168000, timeout 1510704000 ([BIP141], [BIP147]).

### 5.3 Versionbits deployments per chain

| Chain | Deployment | bit | nStartTime | nTimeout | min_activation_height | period / threshold | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| main | taproot | 2 | 1619222400 (2021-04-24) | 1628640000 (2021-08-11) | 709632 | 2016 / 1815 (90%) | `CMainParams`; [BIP341] |
| main | testdummy | 28 | NEVER_ACTIVE | NO_TIMEOUT | 0 | 2016 / 1815 | `CMainParams` |
| testnet3 | taproot | 2 | 1619222400 | 1628640000 | 0 | 2016 / 1512 (75%) | `CTestNetParams`; [BIP341] |
| testnet3 | testdummy | 28 | NEVER_ACTIVE | NO_TIMEOUT | 0 | 2016 / 1512 | `CTestNetParams` |
| testnet4 | taproot | 2 | ALWAYS_ACTIVE | NO_TIMEOUT | 0 | 2016 / 1512 | `CTestNet4Params` |
| testnet4 | testdummy | 28 | NEVER_ACTIVE | NO_TIMEOUT | 0 | 2016 / 1512 | `CTestNet4Params` |
| signet | taproot | 2 | ALWAYS_ACTIVE | NO_TIMEOUT | 0 | 2016 / 1815 | `SigNetParams` |
| signet | testdummy | 28 | NEVER_ACTIVE | NO_TIMEOUT | 0 | 2016 / 1815 | `SigNetParams` |
| regtest | taproot | 2 | ALWAYS_ACTIVE | NO_TIMEOUT | 0 | 144 / 108 (75%) | `CRegTestParams` |
| regtest | testdummy | 28 | 0 | NO_TIMEOUT | 0 | 144 / 108 | `CRegTestParams` |

BIP341 records that taproot activated at height 709632 on mainnet and 2011968 on testnet3.
Because Core's validation applies `SCRIPT_VERIFY_TAPROOT` from genesis (4.2), these heights do
not appear anywhere in Core's validation path.

### 5.4 BIP9 state machine as implemented

| Rule | Detail | Source |
| --- | --- | --- |
| Period alignment | a block's state equals the state of the first block of its period; computed from the `pindexPrev` whose height is `period*k - 1` | `versionbits.cpp: GetStateFor` |
| DEFINED -> STARTED | `MTP(pindexPrev) >= nStartTime` | same; [BIP9] |
| STARTED -> LOCKED_IN | count of the last `period` blocks with `(nVersion & 0xE0000000) == 0x20000000` and bit set `>= threshold`; checked BEFORE the timeout (BIP341 order, opposite of original BIP9) | `versionbits.cpp: GetStateFor`; `VersionBitsConditionChecker::Condition`; [BIP341] |
| STARTED -> FAILED | not locked in and `MTP(pindexPrev) >= nTimeout` | same |
| LOCKED_IN -> ACTIVE | at the next period boundary once `pindexPrev.height + 1 >= min_activation_height`; otherwise stays LOCKED_IN | same; [BIP341] |
| Terminal | ACTIVE and FAILED never change | same |
| Thresholds | BIP9 text: 1916 of 2016 (95%) mainnet, 1512 (75%) testnet; BIP341 lowered taproot to 1815 (90%); Core stores per-deployment | [BIP9]; [BIP341]; `consensus/params.h` |
| Top bits | `VERSIONBITS_TOP_BITS = 0x20000000`, `VERSIONBITS_TOP_MASK = 0xE0000000`, 29 usable bits; `VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4` | `versionbits.h` |
| Unknown-bit warnings | `CheckUnknownActivations` (period 2016, threshold 1815 on main; `period*3/4` on test chains; ignores heights below `MinBIP9WarningHeight`) only logs; not consensus | `versionbits.cpp: WarningBitsConditionChecker`; `consensus/params.h: MinBIP9WarningHeight` |
| Miner version | `ComputeBlockVersion` sets top bits plus bits of STARTED/LOCKED_IN deployments; not consensus | `versionbits.cpp: ComputeBlockVersion` |

### 5.5 Regtest knobs

| Option | Effect | Source |
| --- | --- | --- |
| `-testactivationheight=name@height` | sets a buried height; names `segwit`, `bip34`, `dersig`, `cltv`, `csv` | `chainparams.cpp: ReadRegTestArgs`; `deploymentinfo.cpp: GetBuriedDeployment` |
| Default regtest heights | BIP34, BIP65, BIP66, CSV = 1; SegWit = 0 | `kernel/chainparams.cpp: CRegTestParams` |
| `-vbparams=deployment:start:end[:min_activation_height]` | overrides `nStartTime`, `nTimeout`, `min_activation_height` for `testdummy` or `taproot`; bit, period, threshold stay fixed | `chainparams.cpp: ReadRegTestArgs`; `deploymentinfo.cpp: VersionBitsDeploymentInfo` |
| `-test=bip94` | enables `enforce_BIP94` on regtest | `chainparams.cpp: ReadRegTestArgs` |
| `-signetchallenge=<hex>` | custom signet challenge; also changes the message start bytes (`SHA256d(serialized challenge)[0..4]`) and clears `nMinimumChainWork` / `defaultAssumeValid` | `chainparams.cpp: ReadSigNetArgs`; `kernel/chainparams.cpp: SigNetParams` |
| Default signet challenge | `512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae` (1-of-2 multisig) | `kernel/chainparams.cpp: SigNetParams` |

## 6. Historical quirks

| Quirk | What must be reproduced | C/P | Source |
| --- | --- | --- | --- |
| BIP30 exception blocks | 91842 and 91880 skip the duplicate check; their coinbases overwrite those of 91722 and 91812 (2.5) | C | `validation.cpp: IsBIP30Repeat`, `IsBIP30Unspendable`; [BIP30] |
| BIP34 mismatched heights | blocks before 227931 with `nVersion = 2` need not carry a height, and pre-BIP34 coinbases with "indicated heights" above their real height exist (lowest 209,921; 490,897; 1,983,702); hence the BIP30 scan resumes at 1,983,702 | C | comment in `validation.cpp: ConnectBlock` |
| BIP34Hash | Core keys the BIP30 skip on the presence of block `000000000000024b89…0808b8` at height 227931, not on the height alone | C | `validation.cpp: ConnectBlock`; `CMainParams: BIP34Hash` |
| Last v1 block | BIP34 records block 227,835 as the last version-1 block | – | [BIP34] |
| P2SH exception block | mainnet block 170060 `00000000000002dc…4f9c22` (nTime 1331137983 < 1333238400) contains the one transaction that violates P2SH; BIP16 cites tx `6a26d2ec…6192` | C | `CMainParams: script_flag_exceptions`; [BIP16]; height and time via chain data |
| Taproot exception block | mainnet block 692261 `0000000000000000000f14…e395ad` (nTime 1627028660, before activation at 709632) violates taproot rules; Core comment: "only one historical block violated the TAPROOT rules on mainnet". Which transaction: unverified from a primary source | C | `validation.cpp: GetBlockScriptFlags`; `CMainParams`; height via chain data |
| Testnet3 P2SH exception | block 394 `00000000dd30457c…2b105` | C | `CTestNetParams: script_flag_exceptions`; height via chain data |
| P2SH sigop counting | P2SH sigops are only added when `SCRIPT_VERIFY_P2SH` is in the block's flags, so the exception blocks count only legacy sigops | C | `consensus/tx_verify.cpp: GetTransactionSigOpCost` |
| Value overflow, block 74638 | the 2010 overflow block `0000000000790ab3…a7ec1c` is NOT on the canonical chain (height 74638 is `000000000069e1affe7161ab4bcbeacebb4ddf155b50e807f42de971b688a09b`); Core's only primary trace is the CVE-2010-5139 reference on the output-sum check. The narrative of the incident is secondary-source only | C | `consensus/tx_check.cpp: CheckTransaction`; chain data |
| Checkpoints | removed; `-checkpoints` is a hidden option that only warns. Nothing about checkpoints is consensus | – | `init.cpp` ("Checkpoints were removed") |
| nMinimumChainWork | main `0000…01128750f82f4c366153a3a030`; testnet3 `…17dde1c649f3708d14b6`; testnet4 `…09a0fe15d0177d086304`; signet `…0b463ea0a4b8`; regtest 0. Used to refuse to sync from peers with less work and as one assumevalid precondition; not a validity rule | P | `kernel/chainparams.cpp`; `validation.cpp: ConnectBlock`; `init.cpp: -minimumchainwork` |
| defaultAssumeValid | main `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac` (height 938343); testnet3 `000000007a61e423…5b67f4` (4842348); testnet4 `0000000002368b1e…bf7cf8a` (123613); signet `00000008414aab61…f5c329` (293175); regtest none | P | `kernel/chainparams.cpp` (heights in comments) |
| assumevalid semantics | script checks are skipped for a block iff: the assumevalid hash is a known header; the block is an ancestor of it; the block is in the best-header chain; best header chainwork `>= nMinimumChainWork`; and the work between the block and the best header exceeds two weeks at the tip's difficulty (`GetBlockProofEquivalentTime > 1209600`). Everything except scripts (merkle, sigops, amounts, BIP30, BIP68) is still checked | P | `validation.cpp: ConnectBlock` (`script_check_reason`); `chain.cpp: GetBlockProofEquivalentTime` |
| assumeutxo (mainnet) | height 840000 `hash_serialized a2a5521b…768f96`, chain tx 991032194, block `0000…1cda83a5`; 880000 `dbd19098…adcea9`, 1145604538, `…5cca2880`; 910000 `4daf8a17…2f1568`, 1226586151, `…194a821`; 935000 `e4b90ef9…025050`, 1305397408, `…6f0fb5ee` | P | `kernel/chainparams.cpp: CMainParams: m_assumeutxo_data` |
| assumeutxo (testnet3) | 2500000 `f8415849…71be7`, 66484552, `…d73206f`; 4840000 `ce6bb677…8db2a`, 536078574, `…f0d64786` | P | `CTestNetParams` |
| assumeutxo (testnet4) | 90000 `784fb5e9…f8b9b5`, 11347043, `…2df2dbe3b`; 120000 `10b05d05…4794b0`, 14141057, `…cbce01dc8` | P | `CTestNet4Params` |
| assumeutxo (signet) | 160000 `fe0a4430…df928a`, 2289496, `…0353a62c`; 290000 `97267e00…d14545`, 28547497, `…d5c9ac0` | P | `SigNetParams` |
| assumeutxo (regtest) | 110 `b952555c…141327` (111 tx); 200 `17dcc016…81d13a` (201); 299 `d2b051ff…1a63e2` (334) | P | `CRegTestParams` |
| assumeutxo semantics | a loaded snapshot must reproduce `hash_serialized` exactly (`CoinStatsHashType::HASH_SERIALIZED`) and sets `m_chain_tx_count` from the table; the background chain later re-validates | P | `validation.cpp: PopulateAndValidateSnapshot` (lines around `au_data.hash_serialized`) |
| chainTxData | `nTime`, `tx_count`, `dTxRate` are progress-estimation constants only | – | `kernel/chainparams.cpp` |
| Witness commitment only with witness data | 2.6: absent commitment is valid only when no tx has a witness | C | `validation.cpp: CheckWitnessMalleation`; [BIP141] |
| NULLDUMMY since segwit | 4.7 | C | `GetBlockScriptFlags`; [BIP147] |
| Genesis output unspendable | 1.5 | C | `validation.cpp: ConnectBlock` |
| Lax DER before BIP66 | 4.7 | C | `pubkey.cpp: ecdsa_signature_parse_der_lax` |
| OP_VERIF / OP_VERNOTIF | fail even unexecuted (4.1) | C | `interpreter.cpp: EvalScript` |

## 7. The UTXO set hash

`gettxoutsetinfo` offers `hash_serialized_3` (default), `muhash` and `none`
(`rpc/blockchain.cpp: gettxoutsetinfo`). Both hashes are computed by `kernel/coinstats.cpp` over
the same per-coin serialization.

| Element | Detail | Source |
| --- | --- | --- |
| Per-coin record | `outpoint || uint32((height << 1) | coinbase) || CTxOut` | `kernel/coinstats.cpp: TxOutSer` |
| outpoint | 32-byte txid (internal byte order, as hashed) then `n` as u32 LE | `primitives/transaction.h: COutPoint` serialization |
| height/coinbase word | `(nHeight << 1) + fCoinBase` as u32 LE (`nHeight` is 31 bits) | `TxOutSer`; `coins.h: Coin` |
| CTxOut | `nValue` i64 LE then `scriptPubKey` as compact-size length plus bytes (plain, not the compressed on-disk form) | `primitives/transaction.h: CTxOut` serialization |
| `hash_serialized_3` | one `HashWriter` (SHA256d, no prefix) fed every record in iteration order; result = `SHA256d(concatenation)` | `kernel/coinstats.cpp: ApplyCoinHash(HashWriter&)`, `FinalizeHash` |
| Iteration order | database cursor order: key `'C' || txid (32 bytes) || VARINT(n)`, so txids ascending by their serialized bytes; within a txid Core groups outputs in a `std::map<uint32_t, Coin>` (ascending `n`) | `txdb.cpp: CoinEntry`; `kernel/coinstats.cpp: ComputeUTXOStats` |
| `muhash` | each record `r` maps to `Num3072(ChaCha20(key = SHA256(r)) keystream, 384 bytes)`; the set hash is the product of all elements mod `2^3072 - 1103717`; final `SHA256(384-byte LE encoding)`; order-independent | `crypto/muhash.cpp: MuHash3072::ToNum3072`, `Finalize`; `kernel/coinstats.cpp: ApplyCoinHash(MuHash3072&)` |
| What is excluded | spent outputs; the genesis coinbase output (never added); outputs whose scriptPubKey `IsUnspendable()` (starts with `OP_RETURN`, or longer than 10000 bytes) are never added to the set; the overwritten coinbase outputs of 91722 and 91812 exist only under the heights 91842 and 91880 | `validation.cpp: ConnectBlock`; `coins.cpp: CCoinsViewCache::AddCoin`; `script/script.h: IsUnspendable`; `IsBIP30Unspendable` |
| Stats also reported | `nTransactions`, `nTransactionOutputs`, `nBogoSize` (`32 + 4 + 4 + 8 + 2 + script length` per coin), `total_amount` | `kernel/coinstats.cpp: ApplyStats`, `GetBogoSize` |
| assumeutxo uses | `hash_serialized` (the `hash_serialized_3` algorithm) is what the `m_assumeutxo_data` table commits to | `validation.cpp: PopulateAndValidateSnapshot`; `kernel/coinstats.h: CoinStatsHashType` |
| Caveat on the "_3" | the RPC name is `hash_serialized_3`; the kernel enum is `HASH_SERIALIZED`. Whether the "3" reflects the format above versus earlier variants was not traced to a source: unverified | `rpc/blockchain.cpp` |

## References

[BIP9]: https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
[BIP16]: https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
[BIP30]: https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
[BIP34]: https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
[BIP65]: https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
[BIP66]: https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
[BIP68]: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
[BIP90]: https://github.com/bitcoin/bips/blob/master/bip-0090.mediawiki
[BIP94]: https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki
[BIP112]: https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
[BIP113]: https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki
[BIP141]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
[BIP143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
[BIP144]: https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
[BIP147]: https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
[BIP325]: https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki
[BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[BIP341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
[BIP342]: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki

BIP144 defines the witness serialization used on the wire and on disk (marker `0x00`, flag
`0x01`); it is a serialization format, not a validity rule, and is listed for completeness.
Core source: https://github.com/bitcoin/bitcoin/tree/v31.1/src
