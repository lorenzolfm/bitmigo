# Differential testing against Bitcoin Core: vectors, the UTXO-set hash, checkpoints, harness

- Core tag read: `v31.1` (the installed `bitcoind --version` reports `v31.1.0`; `bitcoin-cli`
  is installed alongside).
- BIP texts read from `github.com/bitcoin/bips` `master` on the same date.
- Floresta read from the `master` worktree at `c0457dc` (2026-09-01); utreexod at `22c9737e`
  (2026-05-20). Both read-only.
- Date: 2026-09-08.

How to read this document. It goes one level below `docs/consensus-rules.md`: where that file
says which rule Core enforces, this one says how to prove that this node enforces the same
rule, and what oracle to compare against. Core sources are written `file: Symbol`, always
relative to `src/` at tag `v31.1` (so `test/script_tests.cpp: DoTest` means
`src/test/script_tests.cpp`, function `DoTest`); functional-test sources are written with
their full path under `test/functional/`. BIPs are written `[BIP141]` and link to the text at
the end. Where a claim could not be confirmed from a primary source the row or sentence says
so with the word "unverified". Section 7 of `docs/consensus-rules.md` already tables the
per-coin serialization of the UTXO hash; section 2 here verifies it against source rather than
restating it. Section 4.3 is a recommendation, not a finding, and is marked as such.

## 1. Test vectors

### 1.1 Inventory of `src/test/data/` at v31.1

The directory holds exactly eleven files (GitHub contents API, `ref=v31.1`). All JSON files
are compiled into the unit-test binary as string constants (`test/CMakeLists.txt:
target_json_data_sources`), read with `test/util/json.cpp: read_json`, which asserts the
document is a JSON array. Every harness skips rows that are a single string (comments); the
exact rule per file is given below.

| File | Bytes | What it tests | Harness | Consensus-relevant? |
| --- | --- | --- | --- | --- |
| `README.md` | 291 | says the data files are MIT-licensed, "see the accompanying file COPYING" | none | no |
| `script_tests.json` | 219772 | `VerifyScript` on (scriptSig, scriptPubKey, witness, amount, flags) → expected `ScriptError` | `test/script_tests.cpp: script_json_test` | yes (core of it) |
| `tx_valid.json` | 86526 | whole transactions whose inputs must verify under all flags except those listed | `test/transaction_tests.cpp: tx_valid` | yes |
| `tx_invalid.json` | 53412 | whole transactions that must fail under the listed flags, or fail `CheckTransaction` | `test/transaction_tests.cpp: tx_invalid` | yes |
| `sighash.json` | 210483 | legacy `SignatureHash` (SigVersion::BASE) on random transactions | `test/sighash_tests.cpp: sighash_from_data` | yes |
| `bip341_wallet_vectors.json` | 29296 | taproot tweak, script-tree Merkle root, BIP341 sighash and key-path signatures; byte-identical to `bip-0341/wallet-test-vectors.json` in the bips repo | `test/script_tests.cpp: bip341_keypath_test_vectors` | yes (sighash, tweak, control block) |
| `blockfilters.json` | 17816 | BIP158 basic filter bytes and filter headers for ten testnet3 blocks | `test/blockfilter_tests.cpp: blockfilters_json_test` | no (index, not consensus) |
| `base58_encode_decode.json` | 2125 | raw base58 encode/decode pairs | `test/base58_tests.cpp: base58_EncodeBase58`, `base58_DecodeBase58` | no |
| `key_io_valid.json` | 17149 | address/WIF strings → expected scriptPubKey or key bytes, per chain | `test/key_io_tests.cpp: key_io_valid_parse`, `key_io_valid_gen` | no (address encoding) |
| `key_io_invalid.json` | 5193 | strings that must decode as neither address nor key on any chain | `test/key_io_tests.cpp: key_io_invalid` | no |
| `asmap.raw` | 59 | a 59-byte mock ASN map (`250.0.0.0/8 → AS1000`, `101.N.0.0/16 → ASN`) for addrman bucketing tests | `test/addrman_tests.cpp` (embedded as `test::data::asmap`) | no |

Not in the repository but consumed by the unit tests: `script_assets_test.json`, read from
`$DIR_UNIT_TEST_DATA` by `test/script_assets_tests.cpp: script_assets_test` (section 1.6).
Note that at v31.1 this test lives in its own file `test/script_assets_tests.cpp`, not in
`script_tests.cpp`.

### 1.2 License

`src/test/data/README.md` states: "The data files in this directory are distributed under
the MIT software license, see the accompanying file COPYING". There is no separate `LICENSE`
file in the directory (404 at v31.1) and the JSON files carry no header. `COPYING` at the
repository root is the MIT license. Copying the vectors into this repository requires only
the MIT notice.

### 1.3 `script_tests.json`

Row shape (`test/script_tests.cpp: script_json_test`, and the file's own first row):

```
[[wit..., amount]?, scriptSig, scriptPubKey, flags, expected_scripterror, ...comments]
```

| Element | Detail | Source |
| --- | --- | --- |
| Comment rows | a row with exactly one element is skipped; a row with fewer than 4 elements (after the optional witness) that is not 1 element is a "Bad test" error | `script_json_test`: `if (test.size() < 4 + pos)` |
| Witness array | optional first element, an array; every element but the last is a hex witness stack item; the last is the amount in BTC as a JSON number, parsed by `AmountFromValue` (so `0.00000001` = 1 satoshi); 113 of 1222 rows carry one | `script_json_test`; `rpc/util.cpp: AmountFromValue` |
| `#SCRIPT#` prefix | a witness element starting with `#SCRIPT#` is parsed by `ParseScript` (the mini-language below) and pushed as bytes; used for tapscript leaves (5 rows) | `script_json_test` |
| `#CONTROLBLOCK#` | the framework builds a single-leaf taproot tree (leaf = previous witness element, version `0xc0`), internal key = `key0` = secp256k1 private key `1` uncompressed (`vchKey0` = 31 zero bytes then `0x01`), and pushes the control block (5 rows) | `script_json_test`; `script_tests.cpp: KeyData`, `vchKey0` |
| `0x51 0x20 #TAPROOTOUTPUT#` | as scriptPubKey: `OP_1 <32-byte output key>` from that same tree (5 rows) | `script_json_test` |
| scriptSig, scriptPubKey | strings in the mini-language | `core_io.cpp: ParseScript` |
| flags | comma-separated names from section 1.7; empty string or `NONE` means no flags | `test/transaction_tests.cpp: ParseScriptFlags` |
| expected_scripterror | one of the names in section 1.8 | `script_tests.cpp: ParseScriptError` |
| Extra elements | anything after the fifth (or sixth with witness) element is ignored: free-form comments | `script_json_test` |

The mini-language (`core_io.cpp: ParseScript`), whitespace-separated tokens in order of the
checks:

| Token | Meaning | Source |
| --- | --- | --- |
| decimal integer, optional leading `-`, in `-0xFFFFFFFF..0xFFFFFFFF` | pushed as a script number (`CScript << int64_t`: `OP_0`, `OP_1..OP_16`, `OP_1NEGATE` or a minimal `CScriptNum` push); out of range throws | `ParseScript` |
| `0x` + hex | raw bytes inserted verbatim, NOT pushed (this is how tests write explicit push opcodes and malformed data) | `ParseScript` |
| `'...'` single-quoted | the bytes between the quotes are pushed as data; no spaces inside | `ParseScript` |
| anything else | an opcode name, with or without the `OP_` prefix (`OP_ADD` and `ADD`); every name that `GetOpName` returns except `OP_UNKNOWN`, plus `OP_RESERVED`; unknown names throw | `core_io.cpp: OpCodeParser` |

What the harness does with a row (`test/script_tests.cpp: DoTest`):

| Step | Detail | Source |
| --- | --- | --- |
| Crediting tx | version 1, nLockTime 0, one input with null prevout, scriptSig `OP_0 OP_0`, nSequence `0xffffffff`, one output `(amount, scriptPubKey)` | `test/util/transaction_utils.cpp: BuildCreditingTransaction` |
| Spending tx | version 1, nLockTime 0, one input `(credit txid, 0)` with the scriptSig and witness, nSequence `0xffffffff`, one output `(amount, empty script)` | `BuildSpendingTransaction` |
| Flag fix-up | if `CLEANSTACK` is set, `P2SH` and `WITNESS` are added before running | `DoTest` |
| Main check | `VerifyScript(scriptSig, scriptPubKey, &witness, flags, checker(spend, 0, amount))` must return `expected == OK`, and the returned `ScriptError` must equal the expected one exactly | `DoTest` |
| Monotonicity check | 256 times: draw 21 random bits; for an expected-OK row remove those bits from the flags, for an expected-error row add them; skip combinations where `CLEANSTACK` lacks `P2SH|WITNESS` or `WITNESS` lacks `P2SH`; the boolean result must not change (the error code is not checked here) | `DoTest`, `MAX_SCRIPT_VERIFY_FLAGS_BITS` |
| `UPDATE_JSON_TESTS` | a `#define` at the top of `script_tests.cpp` that makes `script_build` regenerate the JSON from the C++ `TestBuilder` list; it is a generator for the file, not a consumer | `script_tests.cpp: script_build`, line 39 |

Counts (computed from the file): 1273 rows, 51 comment rows, 1222 test rows, 113 with a
witness array, 675 expecting `OK`. Flag names that actually occur: (none), `P2SH`,
`STRICTENC`, `DERSIG`, `LOW_S`, `NULLDUMMY`, `SIGPUSHONLY`, `MINIMALDATA`,
`DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, `CHECKSEQUENCEVERIFY`, `WITNESS`,
`DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`, `MINIMALIF`, `NULLFAIL`, `WITNESS_PUBKEYTYPE`,
`TAPROOT`. `CHECKLOCKTIMEVERIFY` and `CONST_SCRIPTCODE` never occur as flags in this file.
Error names that occur: `OK`, `EVAL_FALSE`, `OP_RETURN`, `SCRIPT_SIZE`, `PUSH_SIZE`,
`OP_COUNT`, `STACK_SIZE`, `SIG_COUNT`, `PUBKEY_COUNT`, `VERIFY`, `EQUALVERIFY`,
`NUMEQUALVERIFY`, `BAD_OPCODE`, `DISABLED_OPCODE`, `INVALID_STACK_OPERATION`,
`INVALID_ALTSTACK_OPERATION`, `UNBALANCED_CONDITIONAL`, `NEGATIVE_LOCKTIME`,
`UNSATISFIED_LOCKTIME`, `SIG_HASHTYPE`, `SIG_DER`, `MINIMALDATA`, `SIG_PUSHONLY`,
`SIG_HIGH_S`, `SIG_NULLDUMMY`, `PUBKEYTYPE`, `CLEANSTACK`, `MINIMALIF`, `NULLFAIL`,
`DISCOURAGE_UPGRADABLE_NOPS`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`,
`WITNESS_PROGRAM_WRONG_LENGTH`, `WITNESS_PROGRAM_WITNESS_EMPTY`, `WITNESS_PROGRAM_MISMATCH`,
`WITNESS_MALLEATED`, `WITNESS_MALLEATED_P2SH`, `WITNESS_UNEXPECTED`, `WITNESS_PUBKEYTYPE`,
`TAPSCRIPT_EMPTY_PUBKEY`, `SCRIPTNUM`.

utreexod carries a copy at `txscript/data/script_tests.json` (214290 bytes) that differs from
Core's v31.1 file from byte 7642 on; use Core's, not that one.

### 1.4 `tx_valid.json` and `tx_invalid.json`

Row shape (both files' leading comments; `test/transaction_tests.cpp: tx_valid`, `tx_invalid`):

```
[[[prevout hash, prevout index, prevout scriptPubKey, amount?], [input 2], ...],
 serializedTransaction, verifyFlags]
```

| Element | Detail | Source |
| --- | --- | --- |
| Comment rows | a row whose first element is not an array is skipped (`if (test[0].isArray())`); a 3-element check then applies | `tx_valid`, `tx_invalid` |
| Prevout entry | `[txid hex (display order), n, scriptPubKey in the mini-language, amount in satoshis as a JSON integer?]`; 3 or 4 elements; the amount defaults to 0 when absent (81 of 176 inputs in `tx_valid`, 29 of 110 in `tx_invalid` carry one) | `tx_valid`; `CheckTxScripts` |
| Transaction | hex, deserialized with `TX_WITH_WITNESS` (so witness-bearing serializations are allowed) | `tx_valid` |
| `CheckTransaction` | run first with `consensus/tx_check.cpp: CheckTransaction`; in `tx_valid` it must pass; in `tx_invalid`, if it fails the flags string must be exactly `BADTX` and the row ends there (9 such rows) | `tx_valid`, `tx_invalid` |
| **`tx_valid` flags = flags to EXCLUDE** | the third element lists the flags under which the transaction is NOT required to pass; the harness runs every input with `~verify_flags` (every known flag except the listed ones) and expects success | `tx_valid`: `CheckTxScripts(..., ~verify_flags, ..., expect_valid=true)` |
| `tx_valid` maximality | for each listed flag `f` (via `ExcludeIndividualFlags`), running with `~(verify_flags without f)`, i.e. re-enabling `f`, must FAIL ("Too many flags unset"); so the listed set is exactly the set of flags the transaction violates, and an implementation that does not implement a listed policy flag will see this maximality check fail, not the main check | `tx_valid`; `ExcludeIndividualFlags` |
| `tx_valid` monotonicity | removing any single flag, or a random subset, from `~verify_flags` must still pass | `tx_valid`; `TrimFlags` |
| `tx_invalid` flags = flags to APPLY | run with exactly the listed flags, expect at least one input to fail; adding any single flag or random superset must still fail; removing any single listed flag (`ExcludeIndividualFlags`) must make it PASS ("Too many flags set"), so here too the list is minimal | `tx_invalid`; `FillFlags` |
| Flag-combination validity | `TrimFlags` drops `WITNESS` without `P2SH` and `CLEANSTACK` without `WITNESS`; `FillFlags` adds them; a row whose flags are not already "filled" is a "Bad test flags" error | `TrimFlags`, `FillFlags`, `IsValidFlagCombination` |
| Per-input evaluation | `VerifyScript(scriptSig, prevout script, &witness, flags, TransactionSignatureChecker(tx, i, amount, txdata))`, inputs in order, stopping at the first failure | `CheckTxScripts` |

Counts: `tx_valid` has 121 test rows (129 comment rows); flags that occur: `NONE`, `LOW_S`,
`CLEANSTACK`, `CONST_SCRIPTCODE`, `STRICTENC`, `DERSIG`, `SIGPUSHONLY`, `MINIMALDATA`,
`NULLDUMMY`, `NULLFAIL`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`. `tx_invalid` has 93 test
rows (108 comment rows); flags that occur: `NONE`, `BADTX`, `P2SH`, `CHECKLOCKTIMEVERIFY`,
`CHECKSEQUENCEVERIFY`, `WITNESS`, `CONST_SCRIPTCODE`, `NULLDUMMY`, `DERSIG`,
`DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`.

The trap, stated once more: in `tx_valid.json` a flag list such as `"DERSIG,LOW_S,STRICTENC"`
means "this transaction is valid under every flag except those three, and invalid once any of
them is enabled". `"NONE"` means "valid under all flags".

### 1.5 The smaller files

| File | Row shape and semantics | Source |
| --- | --- | --- |
| `sighash.json` | `[raw_transaction hex, scriptCode hex, input_index, hashType (int32, may be any value incl. negative or > 0xff), expected sighash hex]`; 500 rows plus one header comment; the harness deserializes with `TX_WITH_WITNESS`, requires `CheckTransaction` to pass, then checks `SignatureHash(scriptCode, tx, nIn, nHashType, 0, SigVersion::BASE).GetHex()`; the expected string is `uint256::GetHex()`, i.e. the hash bytes reversed. Legacy sighash only; covers the `SIGHASH_SINGLE` bug (input index ≥ outputs returns the "one" hash) because the transactions are random | `test/sighash_tests.cpp: sighash_from_data` |
| `base58_encode_decode.json` | `[hex bytes, base58 string]`, 21 rows; encode must produce the string, decode must produce the bytes | `test/base58_tests.cpp` |
| `key_io_valid.json` | `[string, expected hex payload, {chain, isPrivkey, isCompressed?, tryCaseFlip?}]`, 70 rows over `main`, `testnet4`, `signet`, `regtest` (no testnet3 rows); for a public entry the payload is the scriptPubKey and a case-flipped copy must decode iff `tryCaseFlip` (bech32); for a private entry the payload is the 32-byte key and `isCompressed` must match; each must be invalid as the other kind | `test/key_io_tests.cpp: key_io_valid_parse` |
| `key_io_invalid.json` | `[string]`, 70 rows; must decode as neither destination nor secret on main, testnet3, signet and regtest | `key_io_tests.cpp: key_io_invalid` |
| `bip341_wallet_vectors.json` | object `{version, scriptPubKey[7], keyPathSpending[1]}`; `scriptPubKey[i]` = `{given: {internalPubkey, scriptTree}, intermediary: {merkleRoot, tweak, tweakedPubkey}, expected: {scriptPubKey, bip350Address}}`; `keyPathSpending[0]` = `{given: {rawUnsignedTx, utxosSpent[{scriptPubKey, amountSats}]}, intermediary: {hashAmounts, hashOutputs, hashPrevouts, hashScriptPubkeys, hashSequences}, inputSpending[{given: {txinIndex, internalPrivkey, merkleRoot, hashType}, intermediary: {internalPubkey, tweak, tweakedPrivkey, sigMsg, precomputedUsed, sigHash}, expected: {witness}}], auxiliary: {fullySignedTx}}`; Core checks the five intermediate hashes, the tweak, `sigHash == SHA256(TapSighash tag, sigMsg)` and the produced signature | `test/script_tests.cpp: bip341_keypath_test_vectors`; [BIP341] |
| `blockfilters.json` | header comment then `[height, block hash, block hex, [prevout scriptPubKeys hex], previous basic header, basic filter hex, basic header, notes?]`, 10 rows at testnet3 heights 0, 2, 3, 15007, 49291, 180480, 926485, 987876, 1263442, 1414221 (the [BIP158] vectors); prevout scripts are fed in as undo data with amount 0 | `test/blockfilter_tests.cpp: blockfilters_json_test` |
| `asmap.raw` | binary asmap; only `addrman_tests.cpp` bucket tests use it | `test/addrman_tests.cpp` |

### 1.6 `script_assets_test.json` (generated, not shipped)

| Element | Detail | Source |
| --- | --- | --- |
| Where the test looks | `$DIR_UNIT_TEST_DATA/script_assets_test.json`; if the variable or file is missing the test prints a warning and returns (CTest treats "skipping script_assets_test" as SKIP) | `test/script_assets_tests.cpp: script_assets_test`; `test/CMakeLists.txt` |
| How it is produced | `TEST_DUMP_DIR=<dir> test/functional/feature_taproot.py --dumptests`, repeated (Core's comment says ten times; each run is randomized), then optionally minimized with the libFuzzer target `script_assets_test_minimizer`; finally `(echo '['; cat dump-min/* \| head -c -2; echo ']') > script_assets_test.json`. Each dump is written to `$TEST_DUMP_DIR/<x>/<sha1>` where `<x>` is the first hex digit of the SHA-1 of the record, and each record ends with `",\n"`, which is why the last two bytes are stripped before closing the array | `test/fuzz/script_assets_test_minimizer.cpp` header comment; `feature_taproot.py: dump_json_test` |
| Record | JSON object `{tx, prevouts[], index, flags, comment, final?, success?, failure?}`; `tx` is the transaction hex WITHOUT witness (`TX_NO_WITNESS` on read); `prevouts` are serialized `CTxOut`s (8-byte LE value, compact-size-prefixed script), one per input; `index` is the input under test; `success`/`failure` are `{scriptSig hex, witness: [hex...]}` | `script_assets_tests.cpp: AssetTest`; `dump_json_test` |
| `flags` | `"P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY"` for spenders whose comment starts with `legacy/` or `inactive/`, otherwise the same plus `,TAPROOT`; consensus flags only, never policy | `feature_taproot.py: LEGACY_FLAGS`, `TAPROOT_FLAGS` |
| `final` | present and `true` when the spender is standard; means "valid under every consensus flag combination" | `dump_json_test` |
| Semantics | over all 128 combinations of the 7 consensus flags minus the invalid ones (`WITNESS` needs `P2SH`, `TAPROOT` needs `WITNESS`; `ALL_CONSENSUS_FLAGS`): `success` must verify under every combination that is a subset of `flags` (all combinations if `final`); `failure` must fail under every combination that is a superset of `flags`. Verification uses a `CachingTransactionSignatureChecker` with `PrecomputedTransactionData` over all prevouts, i.e. full BIP341 sighash context | `AssetTest`, `AllConsensusFlags` |
| Size | 2,808 records per run at v31.1 (one per spender per input-count pass), with no overlap between runs because every record carries fresh random keys: ten runs gave 28,080 records, 90 MB (24 MB gzip, 13 MB xz), 636 distinct comments, 7,254 `final`, 24,900 with a `failure`; it is the single richest taproot/tapscript consensus corpus Core has, too large to vendor. Producing it needs Core's Python framework and a `bitcoind` with wallet, not a Core build: the framework reads only `BUILDDIR`, `EXEEXT`, `CLIENT_BUGREPORT` and the `[components]` booleans from `config.ini`, so when `cmake -B build` stops on a missing dependency, fill `test/config.ini.in` by hand with `ENABLE_WALLET=true`, symlink the installed binaries into `BUILDDIR/bin`, and run `TEST_DUMP_DIR=<dir> test/functional/feature_taproot.py --dumptests --configfile build/test/config.ini` (43 s per run, parallel runs are safe since ports derive from the PID; assemble with `find <dir> -type f \| sort \| xargs cat`, a glob overflows the argument list). The runner in `crates/differential` reads the assembled file from `BITMIGO_SCRIPT_ASSETS`; on the corpus generated 2026-09-08 it made 1,786,880 success and 26,180 failure checks, all as Core expects | `feature_taproot.py: dump_json_test`, `skip_test_if_missing_module`; `test/config.ini.in`; `test_framework.py: is_wallet_compiled`; `util.py: get_binary_paths` |

### 1.7 Flag names, bits, and which are consensus

`script_verify_flags` at v31.1 is a typed wrapper; the enum value is the bit index, and
`MAX_SCRIPT_VERIFY_FLAGS_BITS` = 21 (`script/interpreter.h`). Names are the enum names minus
`SCRIPT_VERIFY_` (`script/interpreter.cpp: ScriptFlagNamesToEnum`); the same map serves the
JSON vectors, `GetScriptFlagNames`, and `getblock`/`getdeploymentinfo` output. The consensus
set is what `validation.cpp: GetBlockScriptFlags` can return: `P2SH | WITNESS | TAPROOT`
always (except for two exception blocks, section 3 of `consensus-rules.md`), plus `DERSIG`,
`CHECKLOCKTIMEVERIFY`, `CHECKSEQUENCEVERIFY`, `NULLDUMMY` once their deployments are active.
That set equals `policy/policy.h: MANDATORY_SCRIPT_VERIFY_FLAGS`.

| Bit | Name | Consensus? | What it changes | Source |
| --- | --- | --- | --- | --- |
| 0 | `P2SH` | C | evaluate BIP16 redeem scripts | `interpreter.h`; `GetBlockScriptFlags` |
| 1 | `STRICTENC` | P | non-strict-DER sig, undefined hashtype, or malformed pubkey fails instead of returning false; "not used or intended as a consensus rule" | `interpreter.h` comment |
| 2 | `DERSIG` | C (BIP66) | non-DER signature fails | `GetBlockScriptFlags` |
| 3 | `LOW_S` | P | high-S fails | `policy.h: STANDARD_SCRIPT_VERIFY_FLAGS` |
| 4 | `NULLDUMMY` | C (BIP147, since segwit) | CHECKMULTISIG dummy must be empty | `GetBlockScriptFlags` |
| 5 | `SIGPUSHONLY` | P | scriptSig must be push-only; not even in `STANDARD_SCRIPT_VERIFY_FLAGS`, only vectors use it | `policy.h` |
| 6 | `MINIMALDATA` | P | minimal pushes and minimal numbers | `policy.h` |
| 7 | `DISCOURAGE_UPGRADABLE_NOPS` | P | executed NOP1-10 fail; "will never be a mandatory flag" | `interpreter.h` comment |
| 8 | `CLEANSTACK` | P | exactly one stack element must remain; requires `P2SH` and `WITNESS`; witness v0 and tapscript enforce the equivalent by consensus regardless of the flag | `interpreter.h`; `DoTest` |
| 9 | `CHECKLOCKTIMEVERIFY` | C (BIP65) | | `GetBlockScriptFlags` |
| 10 | `CHECKSEQUENCEVERIFY` | C (BIP112) | | `GetBlockScriptFlags` |
| 11 | `WITNESS` | C (BIP141) | requires `P2SH` | `GetBlockScriptFlags`; `TrimFlags` |
| 12 | `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` | P | witness v1-v16 spends fail (v1 only when `TAPROOT` is off) | `policy.h` |
| 13 | `MINIMALIF` | P for witness v0; tapscript enforces the same rule by consensus without the flag | `interpreter.h` comment |
| 14 | `NULLFAIL` | P | failed CHECK(MULTI)SIG must have empty signatures (in tapscript this is consensus regardless) | `policy.h` |
| 15 | `WITNESS_PUBKEYTYPE` | P | witness v0 pubkeys must be compressed | `policy.h` |
| 16 | `CONST_SCRIPTCODE` | P | OP_CODESEPARATOR and FindAndDelete fail in non-segwit scripts | `policy.h` |
| 17 | `TAPROOT` | C (BIP341/342) | requires `WITNESS` | `GetBlockScriptFlags`; `AllConsensusFlags` |
| 18 | `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` | P | unknown leaf versions fail | `policy.h` |
| 19 | `DISCOURAGE_OP_SUCCESS` | P | OP_SUCCESSx fails | `policy.h` |
| 20 | `DISCOURAGE_UPGRADABLE_PUBKEYTYPE` | P | unknown tapscript pubkey lengths fail | `policy.h` |

How a consensus-only implementation should consume rows that carry policy flags. The
implementation has no policy switches, so a vector's policy flags cannot be honoured. The
exact behaviour of the harness makes the correct reduction mechanical:

1. `script_tests.json`: strip the policy flags from `flags`. If `expected_scripterror` is
   `OK`, the row must still pass (that is precisely the "removing flags from a passing test
   does not change the result" property `DoTest` already asserts). If the expected error is a
   policy-only error (`MINIMALDATA`, `SIG_PUSHONLY`, `SIG_HIGH_S`, `PUBKEYTYPE` under
   `STRICTENC`, `CLEANSTACK`, `MINIMALIF` outside tapscript, `NULLFAIL` outside tapscript,
   `DISCOURAGE_*`, `WITNESS_PUBKEYTYPE`, `OP_CODESEPARATOR`, `SIG_FINDANDDELETE`) the row
   can only assert that the script passes or fails for some other reason once the flag is
   gone; the safe rule is: keep the row as a MUST-PASS if the error was produced purely by a
   stripped flag, otherwise skip it and count it. Rows that expect a consensus error under
   consensus-only flags (`P2SH`, `DERSIG`, `NULLDUMMY`, `CHECKLOCKTIMEVERIFY`,
   `CHECKSEQUENCEVERIFY`, `WITNESS`, `TAPROOT`, or none) are the ones that carry weight; all
   rows with an empty flag list or `P2SH,STRICTENC` (914 rows carry `P2SH`, 775 carry
   `STRICTENC`) reduce to `P2SH` or none. Important: `STRICTENC` also enables pubkey-encoding
   checks in `CheckPubKeyEncoding`; with it stripped, a row that expected `PUBKEYTYPE` will
   evaluate the signature against a malformed key and simply get `EVAL_FALSE` or `OK`
   depending on the script, so such rows must not be kept as MUST-FAIL.
2. `tx_valid.json`: the excluded-flags list must be intersected with the consensus set.
   Run with (consensus set minus listed consensus flags) and expect success. Do not attempt
   the maximality check for policy flags (there is nothing to re-enable). Rows whose only
   excluded flags are policy (`LOW_S`, `CLEANSTACK`, `CONST_SCRIPTCODE`, `STRICTENC`,
   `SIGPUSHONLY`, `MINIMALDATA`, `NULLFAIL`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`) are
   MUST-PASS under full consensus flags; that is 121 rows of full-transaction evidence.
3. `tx_invalid.json`: rows whose flag list contains only consensus flags (or `NONE`, or
   `BADTX`) are MUST-FAIL under exactly those flags (and, by the harness's own superset
   property, under the full consensus set). Rows whose list contains a policy flag
   (`CONST_SCRIPTCODE`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`, 14 rows) must be skipped:
   by the minimality property they PASS once that flag is removed.
4. `script_assets_test.json` carries consensus flags only; every record applies unchanged,
   and the subset/superset rule of section 1.6 should be run in full (128 combinations).

The activation-dependent flags (`DERSIG`, CLTV, CSV, `NULLDUMMY`) are always-on from the
vectors' point of view; on a real chain the implementation must pick them by height as
`consensus-rules.md` section 3 describes.

### 1.8 `scriptError` names

`test/script_tests.cpp: script_errors[]` maps 44 names to `script/script_error.h:
ScriptError_t`; the name is the enum name minus `SCRIPT_ERR_`, with two exceptions:
`SIG_NULLFAIL` is spelled `NULLFAIL`, and `UNKNOWN_ERROR` has no name (the parser returns it
for an unrecognized string and reports an error). The full list at v31.1: `OK`, `EVAL_FALSE`,
`OP_RETURN`, `SCRIPT_SIZE`, `PUSH_SIZE`, `OP_COUNT`, `STACK_SIZE`, `SIG_COUNT`,
`PUBKEY_COUNT`, `VERIFY`, `EQUALVERIFY`, `CHECKMULTISIGVERIFY`, `CHECKSIGVERIFY`,
`NUMEQUALVERIFY`, `BAD_OPCODE`, `DISABLED_OPCODE`, `INVALID_STACK_OPERATION`,
`INVALID_ALTSTACK_OPERATION`, `UNBALANCED_CONDITIONAL`, `NEGATIVE_LOCKTIME`,
`UNSATISFIED_LOCKTIME`, `SIG_HASHTYPE`, `SIG_DER`, `MINIMALDATA`, `SIG_PUSHONLY`,
`SIG_HIGH_S`, `SIG_NULLDUMMY`, `PUBKEYTYPE`, `CLEANSTACK`, `MINIMALIF`, `NULLFAIL`,
`DISCOURAGE_UPGRADABLE_NOPS`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`,
`WITNESS_PROGRAM_WRONG_LENGTH`, `WITNESS_PROGRAM_WITNESS_EMPTY`, `WITNESS_PROGRAM_MISMATCH`,
`WITNESS_MALLEATED`, `WITNESS_MALLEATED_P2SH`, `WITNESS_UNEXPECTED`, `WITNESS_PUBKEYTYPE`,
`TAPSCRIPT_EMPTY_PUBKEY`, `OP_CODESEPARATOR`, `SIG_FINDANDDELETE`, `SCRIPTNUM`.

The `ScriptError_t` enum has more members than the table (`SCHNORR_SIG_SIZE`,
`SCHNORR_SIG_HASHTYPE`, `SCHNORR_SIG`, `TAPROOT_WRONG_CONTROL_SIZE`,
`TAPSCRIPT_VALIDATION_WEIGHT`, `TAPSCRIPT_CHECKMULTISIG`, `TAPSCRIPT_MINIMALIF`,
`DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`, `DISCOURAGE_OP_SUCCESS`,
`DISCOURAGE_UPGRADABLE_PUBKEYTYPE`); those never appear in `script_tests.json` and
`FormatScriptError` would flag them as unknown. A bitmigo error enum needs at least the 44
named values to consume the vectors; matching Core's error code, not only the boolean, is
what `DoTest` checks, and is worth mirroring so that a mismatch points at the exact rule.

### 1.9 Vectors outside Core

| Vector | Format | Use | Source |
| --- | --- | --- | --- |
| BIP340 `test-vectors.csv` | CSV, header `index,secret key,public key,aux_rand,message,signature,verification result,comment`; 19 data rows; rows 0-3 have a secret key (signing + verification), later rows verify only (`TRUE`/`FALSE`) and exercise bad keys, bad `R`, high `s`, and messages of 0, 17 and 100 bytes | Schnorr signing and verification; this node only verifies, so the `verification result` column is the oracle | [BIP340] `bip-0340/test-vectors.csv` |
| BIP341 `wallet-test-vectors.json` | identical bytes to Core's `bip341_wallet_vectors.json` (verified with a byte comparison) | section 1.5 | [BIP341] |
| BIP143 worked examples | five sections in the BIP text (`Native P2WPKH`, `P2SH-P2WPKH`, `Native P2WSH`, `P2SH-P2WSH`, `No FindAndDelete`) each giving the unsigned tx, the `hashPrevouts`/`hashSequence`/`hashOutputs` intermediates, the sighash preimage, and the signed tx; not machine-readable, must be transcribed | segwit v0 sighash | [BIP143] |
| BIP174 | irrelevant (PSBT) | | |

## 2. The UTXO-set hash

### 2.1 The RPC surface

| Element | Detail | Source |
| --- | --- | --- |
| `gettxoutsetinfo hash_type hash_or_height use_index` | `hash_type` ∈ {`hash_serialized_3` (default), `muhash`, `none`}; anything else is `RPC_INVALID_PARAMETER`; `use_index` defaults to true | `rpc/blockchain.cpp: gettxoutsetinfo`, `ParseHashType` |
| `hash_or_height` | requires `-coinstatsindex`; refused for `hash_serialized_3` ("cannot be queried for a specific block") and refused with `use_index=false`; so historical queries exist only for `muhash` and `none` | `gettxoutsetinfo` |
| Flush first | the RPC calls `active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false)` unconditionally before reading, so the value is over the fully written `CCoinsViewDB` and includes every connected block; no `-txindex` is involved | `gettxoutsetinfo`; `GetUTXOStats` |
| Index path | when the index exists, is requested, and `hash_type` is `muhash` or `none`, the answer comes from `CoinStatsIndex::LookUpStats` for the given block (or the DB's best block), after `BlockUntilSyncedToCurrentChain`; otherwise `kernel::ComputeUTXOStats` scans the DB cursor | `GetUTXOStats` |
| Result, always | `height`, `bestblock`, `txouts`, `bogosize`, `total_amount` (string BTC), plus `hash_serialized_3` or `muhash` when requested | `gettxoutsetinfo` |
| Result, scan only | `transactions` (distinct txids with unspent outputs), `disk_size` | `gettxoutsetinfo`: `if (!stats.index_used)` |
| Result, index only | `total_unspendable_amount` and `block_info{prevout_spent, coinbase, new_outputs_ex_coinbase, unspendable, unspendables{genesis_block, bip30, scripts, unclaimed_rewards}}`, computed as the difference between this block's and the previous block's cumulative index values | `gettxoutsetinfo` |
| Regtest immediately after a block | `generate*`/`submitblock` return after `ActivateBestChain`, so a following `gettxoutsetinfo` sees the new tip; with `-coinstatsindex=1` the `muhash` answer additionally waits for the index thread to catch up (`BlockUntilSyncedToCurrentChain`) | `gettxoutsetinfo`; `index/base.cpp` (unverified beyond the call site) |

### 2.2 The kernel computation, verified against section 7 of `consensus-rules.md`

The kernel path at v31.1 is `kernel/coinstats.cpp` (there is no `node/coinstats.cpp`). Every
row of section 7 was checked; all agree with source. The exact function bodies, for the
record:

```
TxOutSer(ss, outpoint, coin):
    ss << outpoint                                              // 32-byte txid, u32 LE n
    ss << static_cast<uint32_t>((coin.nHeight << 1) + coin.fCoinBase)   // u32 LE, NOT VARINT
    ss << coin.out                                              // i64 LE value, compact-size script
ApplyHash(hash_obj, txid, outputs):
    for (n, coin) in outputs, ascending n:  ApplyCoinHash(hash_obj, COutPoint(txid, n), coin)
FinalizeHash(HashWriter):  stats.hashSerialized = ss.GetHash()  // SHA256d of the concatenation
FinalizeHash(MuHash3072):  muhash.Finalize(out)
```

Points that section 7 leaves implicit and that matter for an implementation:

| Point | Detail | Source |
| --- | --- | --- |
| No prefix, no per-txid framing | `hash_serialized_3` is `SHA256d` of the bare concatenation of `TxOutSer` records; the `std::map<uint32_t, Coin>` grouping in `ComputeUTXOStats` only sorts outputs of one txid by `n` and feeds `ApplyStats`; it adds no bytes | `kernel/coinstats.cpp: ComputeUTXOStats`, `ApplyHash` |
| Height word | `uint32_t`, not `VARINT`; this is the on-the-wire difference from the coin's disk serialization (`coins.h: Coin::Serialize` uses `VARINT(nHeight * 2 + fCoinBase)` and `TxOutCompression`) | `TxOutSer`; `coins.h` |
| Same bytes for both hashes | muhash inserts exactly the `TxOutSer` bytes of a coin; so one serializer serves both | `ApplyCoinHash(MuHash3072&)`, `RemoveCoinHash` |
| Unspendable outputs are absent | `CCoinsViewCache::AddCoin` returns early when `scriptPubKey.IsUnspendable()` (starts with `OP_RETURN`, or longer than `MAX_SCRIPT_SIZE` = 10000); such outputs never enter the set and therefore neither hash. Section 7's "what is excluded" row omits this; it is the one addition to make there | `coins.cpp: CCoinsViewCache::AddCoin`; `script/script.h: IsUnspendable` |
| Genesis | `ConnectBlock` returns before touching coins for the genesis block; its output is never in the set | `validation.cpp: ConnectBlock` ("Special case for the genesis block") |
| Iteration order | LevelDB key `'C' ‖ txid (32 bytes, internal order) ‖ VARINT(n)`; the cursor is lexicographic, so txids ascend by internal byte order and, within a txid, by `n` (the map re-sorts `n` numerically, which coincides with VARINT order) | `txdb.cpp: CoinEntry`; `ComputeUTXOStats` |
| Stats | `nTransactions` counts txids, `nTransactionOutputs` coins, `nBogoSize` = Σ(32+4+4+8+2+script length), `total_amount` = Σ value with overflow detection (`CheckedAdd`) | `ApplyStats`, `GetBogoSize` |

### 2.3 Why `hash_serialized_3`

| Element | Detail | Source |
| --- | --- | --- |
| Change | `hash_serialized_2` removed, `hash_serialized_3` added, in v26.0 by PR #28685 ("coinstats, assumeutxo: fix hash_serialized2 calculation", merged 2023-10-23), closing issue #28675 | `doc/release-notes/release-notes-26.0.md` (line 73-75); GitHub PR #28685 |
| The bug | the old `ApplyHash(HashWriter&)` wrote `VARINT(it->second.nHeight * 2 + it->second.fCoinBase ? 1u : 0u)`; operator precedence made it `VARINT((height*2 + coinbase) ? 1 : 0)`, i.e. always `VARINT(1)` for any coin above height 0, so the hash did not commit to heights or coinbase flags at all (found by theStack in #28675; introduced in #12737) | issue #28675 comment; PR #28685 diff of `kernel/coinstats.cpp` |
| The old format | per txid: `txid ‖ VARINT(height/coinbase word of the first output) ‖ for each output: VARINT(n+1) ‖ scriptPubKey ‖ VARINT(value) ‖ then VARINT(0)`, SHA256d over the whole; entirely different framing from `_3` | PR #28685 diff (removed code) |
| The fix | `_3` reuses `TxOutSer` (the muhash record) for the `HashWriter` path, so the two hash types now consume identical bytes | PR #28685 diff |
| Consequence | any `hash_serialized_2` value published before 26.0 (older assumeutxo params, blog posts) is not comparable; `_3` values are stable since v26.0 | same |
| `hash_serialized` → `_2` | not traced to a release note or PR at v31.1: unverified | |

### 2.4 `MuHash3072`

| Element | Detail | Source |
| --- | --- | --- |
| Element hash | `ToNum3072(in)`: `key = SHA256(in)` (single SHA256 of the raw record bytes, no length prefix; `HashWriter << span` writes bytes verbatim), then `ChaCha20Aligned{key}` (nonce 0, block counter 0) produces a 384-byte keystream, read as a little-endian 3072-bit integer (`Num3072` reads limbs with `ReadLE64`) | `crypto/muhash.cpp: MuHash3072::ToNum3072`; `Num3072::Num3072(const unsigned char(&)[384])`; `crypto/chacha20.h: ChaCha20Aligned` |
| Group | multiplication modulo `2^3072 - 1103717` (`MAX_PRIME_DIFF = 1103717`); `Num3072` keeps limbs, reduces lazily (`IsOverflow`/`FullReduce`) | `crypto/muhash.cpp` |
| Set state | two `Num3072`: `m_numerator` (product of inserted elements) and `m_denominator` (product of removed elements); `Insert` multiplies the numerator, `Remove` multiplies the denominator; no inversion until needed | `crypto/muhash.h: MuHash3072`; `Insert`, `Remove` |
| Finalize | `m_numerator.Divide(m_denominator)` (one modular inverse), denominator reset to 1, then `out = SHA256(384-byte LE encoding of the numerator)`; does not change the set's value | `MuHash3072::Finalize` |
| Serialization | `SERIALIZE_METHODS` writes numerator then denominator, each as 384 raw LE bytes (768 bytes total); this is what `coinstatsindex` stores under key `'M'` | `muhash.h: SERIALIZE_METHODS(MuHash3072)`; `index/coinstatsindex.cpp: DB_MUHASH` |
| Combination | `operator*=` and `operator/=` combine two sets, so per-block deltas can be computed in parallel and merged | `muhash.h` |
| Order independence | multiplication commutes, so the result is independent of insertion order and of removal timing; removing an element never inserted yields a wrong (non-detectable) state, so the caller must keep exact set semantics | `muhash.h` header comment |

### 2.5 `coinstatsindex`

| Element | Detail | Source |
| --- | --- | --- |
| What it stores | per block, under the height key, `pair<block hash, DBVal>`; `DBVal` = `{muhash (finalized uint256), transaction_output_count, bogo_size, total_amount, total_subsidy, total_prevout_spent_amount (uint256), total_new_outputs_ex_coinbase_amount (uint256), total_coinbase_amount (uint256), total_unspendables_genesis_block, _bip30, _scripts, _unclaimed_rewards}`; plus one running `MuHash3072` state under `DB_MUHASH` (`'M'`), committed in the same batch as the best-block marker | `index/coinstatsindex.cpp: DBVal`, `CustomCommit` |
| Per block, forward | for each tx: skip the whole coinbase of blocks 91722 and 91812 (`IsBIP30Unspendable`, adding the subsidy to `bip30`); for each output: if `IsUnspendable` add value to `scripts` and skip, else `ApplyCoinHash(m_muhash, {txid, j}, Coin{out, height, is_coinbase})`; for each non-coinbase tx, for each input `j`: `RemoveCoinHash(m_muhash, prevout, undo.vprevout[j])` where the `Coin` (with its original height/coinbase flag) comes from the block's undo data; then unclaimed rewards = (Σ prevouts spent + Σ subsidy) − (Σ new outputs + Σ coinbase outputs + unspendables) | `CustomAppend` |
| Genesis | height 0 adds nothing to the set; its subsidy goes to `unspendables.genesis_block` | `CustomAppend` (`else` branch) |
| Reorg | `CustomRemove` → `RevertBlock`: remove the block's created coins, re-add the spent ones from undo data, then assert the rolled-back finalized muhash equals the stored value of the parent | `RevertBlock` |
| Lookup | `LookUpStats(block_index)` reads the stored `DBVal`; `hashSerialized` is filled with the stored `muhash`; `index_used = true`; `nTransactions` and `nDiskSize` are not available | `LookUpStats` |
| BIP30 subtlety | because the index skips the 91722 and 91812 coinbases at those heights and adds the duplicates at 91842 and 91880, `gettxoutsetinfo muhash <h>` for 91722 ≤ h < 91842 (and 91812 ≤ h < 91880) describes a set WITHOUT those coins, whereas a node's live UTXO set at that time contained them (they were overwritten later by `AddCoin(..., possible_overwrite=true)`). Outside those two windows the index and a live set agree; at the tip they always agree | `CustomAppend`; `validation.cpp: IsBIP30Unspendable`, `IsBIP30Repeat`; `coins.cpp: AddCoin` |

### 2.6 What bitmigo should maintain, and what to compare against

Conclusions from the above, each following from a cited row:

- `muhash` is incrementally maintainable: insert the `TxOutSer` record on coin creation
  (skipping unspendable outputs), remove it on spend using the spent coin's ORIGINAL height
  and coinbase flag, finalize whenever a comparison is wanted (2.4, 2.5). The cost per coin is
  one SHA256, one ChaCha20 keystream of 384 bytes, and one 3072-bit modular multiplication;
  one modular inverse per finalize.
- `hash_serialized_3` is not incrementally maintainable: it is a SHA256d over a specific
  total order of the whole set (2.2), so any change forces a full re-serialization in
  database order. It is what assumeutxo commits to (section 3), so it is still needed at
  checkpoint heights, but only as a batch scan.
- Therefore: maintain `muhash` live and compare it at every block on regtest and signet; run
  the `hash_serialized_3` scan only at assumeutxo heights and at milestones. Both hashes are
  functions of the same record bytes, so one serializer and one "exclusion" rule serve both.
- The Core command that yields the comparable value at an arbitrary height is
  `bitcoin-cli -coinstatsindex ... gettxoutsetinfo muhash <height-or-hash> true`, which
  requires the node to run with `-coinstatsindex=1` (2.1). At the tip, `gettxoutsetinfo
  muhash` without the index (or `use_index=false`) scans the DB and must give the same value
  as the index (Core's own tests assert this). For `hash_serialized_3` only the tip is
  available, from a scan.
- The mainnet cost of a `hash_serialized_3` scan: Core's own help text says only "this call
  may take some time if you are not using coinstatsindex"; no timing figure was found in the
  release notes or the assumeutxo design doc at v31.1: unverified.

### 2.7 Regtest oracle checklist

| Check | Detail | Source |
| --- | --- | --- |
| No `-txindex` needed | neither the scan nor the index reads the transaction index | `GetUTXOStats`; `CoinStatsIndex::CustomAppend` (uses `block.data` and `block.undo_data`) |
| Cache is flushed | `ForceFlushStateToDisk(false)` before every scan, so the value covers every connected block and no cached-only state is missing | `gettxoutsetinfo` |
| `bestblock` in the answer | compare it with bitmigo's tip hash before comparing hashes; a mismatch there is a sync problem, not a hash problem | `gettxoutsetinfo` result |
| `txouts`, `total_amount`, `bogosize` | cheap secondary invariants to compare before the hash: they localize a mismatch to "missing/extra coin", "wrong value" or "wrong script length" | `ApplyStats` |
| `hash_serialized_3` after the first mismatch | `dumptxoutset <path> latest` gives the full set to diff (section 3.3) | `rpc/blockchain.cpp: dumptxoutset` |

## 3. Assumeutxo snapshots as intermediate checkpoints

### 3.1 The committed values at v31.1 (`kernel/chainparams.cpp: m_assumeutxo_data`)

| Chain | Height | `hash_serialized` | `m_chain_tx_count` | Block hash |
| --- | --- | --- | --- | --- |
| mainnet | 840000 | `a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96` | 991032194 | `0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5` |
| mainnet | 880000 | `dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9` | 1145604538 | `000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880` |
| mainnet | 910000 | `4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568` | 1226586151 | `0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821` |
| mainnet | 935000 | `e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050` | 1305397408 | `0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee` |
| testnet3 | 2500000 | `f841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7` | 66484552 | `0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f` |
| testnet3 | 4840000 | `ce6bb677bb2ee9789c4a1c9d73e6683c53fc20e8fdbedbdaaf468982a0c8db2a` | 536078574 | `00000000000000f4971a7fb37fbdff89315b69a2e1920c467654a382f0d64786` |
| testnet4 | 90000 | `784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5` | 11347043 | `0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b` |
| testnet4 | 120000 | `10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0` | 14141057 | `000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8` |
| signet | 160000 | `fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a` | 2289496 | `0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c` |
| signet | 290000 | `97267e000b4b876800167e71b9123f1529d13b14308abec2888bbd2160d14545` | 28547497 | `0000000577f2741bb30cd9d39d6d71b023afbeb9764f6260786a97969d5c9ac0` |
| regtest | 110 | `b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327` | 111 | `6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397` |
| regtest | 200 | `17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a` | 201 | `385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9` |
| regtest | 299 | `d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2` | 334 | `7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2` |

Source for every row: `kernel/chainparams.cpp` lines 166-189 (`CMainParams`), 287-298
(`CTestNetParams`, testnet3), 400-411 (`CTestNet4Params`), 521-532 (signet), 646-665
(`CRegTestParams`). The struct is `kernel/chainparams.h: AssumeutxoData {height,
hash_serialized, m_chain_tx_count, blockhash}`.

### 3.2 What they commit to, and the caveats

| Element | Detail | Source |
| --- | --- | --- |
| Hash type | `PopulateAndValidateSnapshot` loads the coins, flushes, then runs `ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, ...)` and requires `AssumeutxoHash{hashSerialized} == au_data.hash_serialized`; so every value above is a `hash_serialized_3` (2.2) | `validation.cpp: PopulateAndValidateSnapshot`; `kernel/chainparams.h: AssumeutxoHash` |
| Which set | the set AFTER connecting the block at `height` (the snapshot's `m_base_blockhash` is that block; `dumptxoutset` writes the set whose `bestblock` is the base block) | `rpc/blockchain.cpp: PrepareUTXOSnapshot`, `WriteUTXOSnapshot` |
| Nothing extra | the hash is over the coins only; block hash, height and coin count are in the snapshot header but not in the hash | `ComputeUTXOStats`; `node/utxo_snapshot.h` |
| Regtest rows are not free | the three regtest entries are for Core's own tests: height 110 for unit tests, 200 for the `utxo_snapshot` fuzz target, 299 for `feature_assumeutxo.py`, whose chain is the framework's cached 199-block chain (mined to the framework's deterministic keys and a P2TR `OP_TRUE` address with mocktime) plus 100 blocks with `MiniWallet` self-transfers; a different regtest chain has a different set. They are usable only if the same chain is reproduced, i.e. by running that test | `kernel/chainparams.cpp` comments at lines 647-661; `feature_assumeutxo.py: set_test_params`, `run_test`; `test_framework.py: _initialize_chain` |
| Mainnet/testnet/signet rows | are genuine checkpoints: an implementation that has connected block `height` can serialize its set in database order (2.2) and compare; agreement proves the whole history of coin creation and spending up to that block, and disagreement can be diffed with a `dumptxoutset` from Core at the same height (`dumptxoutset utxo.dat rollback=<height>`) | 3.3 |
| Nothing published | Core does not ship snapshot files; users produce them with `dumptxoutset` (the `loadtxoutset` help says snapshots "are typically obtained from third-party sources") | `rpc/blockchain.cpp: loadtxoutset` help text |

### 3.3 `dumptxoutset` and the snapshot file format (a diffable oracle)

| Element | Detail | Source |
| --- | --- | --- |
| RPC | `dumptxoutset <path> <type> {rollback}`; `type` ∈ {`latest`, `rollback`}; `rollback=<height or hash>` makes the node temporarily invalidate blocks down to that height, dump, then reconsider; network activity is suspended meanwhile; the file is written to `<path>.incomplete` then renamed; refuses to overwrite | `rpc/blockchain.cpp: dumptxoutset` |
| Result | `{coins_written, base_hash, base_height, path, txoutset_hash (hash_serialized_3), nchaintx}` | `WriteUTXOSnapshot` |
| Header | `SnapshotMetadata`: magic `"utxo\xff"` (5 bytes), `uint16 VERSION = 2`, 4-byte network magic (`pchMessageStart`), `uint256 m_base_blockhash`, `uint64 m_coins_count` | `node/utxo_snapshot.h: SNAPSHOT_MAGIC_BYTES`, `SnapshotMetadata::Serialize` |
| Body | for each txid in DB cursor order: `txid (32 bytes)`, `CompactSize(number of coins)`, then per coin `CompactSize(n)`, `Coin` | `WriteUTXOSnapshot: write_coins_to_file` |
| `Coin` | `VARINT((nHeight << 1) | fCoinBase)` then `TxOutCompression`: `VARINT(CompressAmount(nValue))` and a compressed script | `coins.h: Coin::Serialize`; `compressor.h: TxOutCompression` |
| `CompressAmount` | 0 → 0; else strip trailing decimal zeros (`e` ≤ 9): if `e < 9`, `1 + (n/10*9 + n%10 - 1)*10 + e`; else `1 + (n-1)*10 + 9` | `compressor.cpp: CompressAmount` |
| Script compression | `VARINT(nSize)`: 0 = P2PKH (`0x00` + 20-byte hash), 1 = P2SH (`0x01` + 20 bytes), 2/3 = P2PK compressed (`0x02`/`0x03` + 32 bytes), 4/5 = P2PK uncompressed (parity in the low bit, 32-byte x); otherwise `nSize - 6` is the raw script length followed by the raw bytes; on read a script longer than 10000 is replaced by `OP_RETURN` | `compressor.h: ScriptCompression`; `compressor.cpp: CompressScript`, `GetSpecialScriptSize` |
| Use | parse the file into (outpoint → coin), diff against bitmigo's set; because the file is in the same cursor order as the hash, the first differing coin also tells which prefix of the `hash_serialized_3` stream diverged | 2.2 |

## 4. The regtest harness shape

### 4.1 Core's functional-test framework (`test/functional/test_framework/`)

| Piece | Detail | Source |
| --- | --- | --- |
| Test class | subclass `BitcoinTestFramework`; override `set_test_params` (`num_nodes`, `setup_clean_chain`, `extra_args` per node), optionally `setup_chain`/`setup_network`/`setup_nodes`, and `run_test`; `main()` parses options, builds the chain, starts nodes, runs, tears down | `test_framework.py: BitcoinTestFramework` |
| Chain cache | unless `setup_clean_chain`, node 0 mines a 199-block chain once into `--cachedir` (8 rounds of 25/24 blocks to three deterministic addresses and a P2TR `OP_TRUE` address, under mocktime), then `chainstate`, `blocks`, `indexes` are copied into every node's datadir and a 200th block is generated at the current time | `test_framework.py: _initialize_chain`, `setup_nodes` |
| Datadir | `<tmpdir>/node<i>/` with a `bitcoin.conf` containing `regtest=1`, `[regtest]`, `port=`, `rpcport=`, `server=1`, `discover=0`, `dnsseed=0`, `fixedseeds=0`, `listenonion=0`, `connect=0` (unless autoconnect is wanted), `peertimeout=999999999`, `rpcservertimeout=99000`, `fallbackfee`, `keypool=1` etc.; `stdout/` and `stderr/` subdirectories | `util.py: initialize_datadir`, `write_config` |
| Ports | `p2p_port(n) = PORT_MIN + n + (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)` with `PORT_MIN` 11000 (env `TEST_RUNNER_PORT_MIN`), `PORT_RANGE` 5000, `MAX_NODES` 12; `rpc_port(n) = p2p_port(n) + 5000`; `tor_port(n) = p2p_port(n) + 10000`; `PortSeed.n` is `--portseed`, default the test's PID | `util.py` |
| Launch | `TestNode.start` runs `binaries.node_argv() + [-datadir=..., -logtimemicros, -debug, -debugexclude=libevent/leveldb/rand, -uacomment=testnode<i>, -disablewallet (unless wallet), -logthreadnames, -logsourcelocations, -loglevel=trace, -nologratelimit, -v2transport=0/1] + extra_args`, plus `-bind=0.0.0.0:<p2p> -bind=127.0.0.1:<tor>=onion` when listening; stdout/stderr go to temp files; `wait_for_rpc_connection` polls the cookie-authenticated RPC four times a second until `getblockchaininfo` answers | `test_node.py: TestNode.__init__`, `start`, `wait_for_rpc_connection` |
| Binary location | from `config.ini` (`BUILDDIR/bin/bitcoind`), overridable per binary by environment: `BITCOIND`, `BITCOINCLI`, `BITCOINUTIL`, `BITCOINTX`, `BITCOINWALLET`, `BITCOINCHAINSTATE`, `BITCOIN_BENCH`, `BITCOIN_BIN`; `BITCOIN_CMD` switches to the `bitcoin` wrapper; `versions=[...]` in `add_nodes` selects previous-release binaries from `--previous-releases` | `util.py: get_binary_paths`, `Binaries`; `test_framework.py: add_nodes` |
| Foreign binary | there is no notion of a non-Core node: `TestNode` assumes Core's RPC (`getblockchaininfo`, `getpeerinfo` with `subver`/`bytesrecv_per_msg`, `addnode`), the cookie file, and Core's debug log; `BITCOIND` can only point at another `bitcoind` build. Since bitmigo has no RPC by design, it cannot be a `TestNode` | `test_node.py`; `test_framework.py: connect_nodes` |
| Connect | `connect_nodes(a, b)`: `addnode 127.0.0.1:<p2p_port(b)> onetry` from `a`, then wait until both `getpeerinfo`s show the other's `subversion` and each has received a `pong` | `test_framework.py: connect_nodes` |
| Sync | `sync_blocks`: poll `getbestblockhash` on every node until equal, asserting each has ≥ 1 peer; `sync_all` = `sync_blocks` + `sync_mempools` | `test_framework.py: sync_blocks` |
| Mining | `self.generate(node, n)`, `generatetoaddress`, `generateblock(output=..., transactions=[...])`, `generatetodescriptor`, all followed by `sync_all` unless `sync_fun=self.no_op`; `invalidateblock`/`reconsiderblock` RPCs for reorgs; `submitblock(hex)` returns `None` on acceptance or the rejection reason string (e.g. `bad-txnmrklroot`, `bad-witness-merkle-match`) | `test_framework.py: generate*`; `p2p_segwit.py` lines 826-986 |
| Python peer | `P2PInterface` (asyncio, one `NetworkThread`): `peer_connect`, `send_without_ping`, `send_and_ping`, `sync_with_ping`, `wait_for_verack/block/header/getdata/getheaders/inv/tx/disconnect`, `on_*` overridable handlers; `node.add_p2p_connection(P2PInterface())` makes the node accept an inbound peer; `add_outbound_p2p_connection` makes the node dial the Python peer | `p2p.py: P2PInterface`; `test_node.py: add_p2p_connection` |
| Crafted blocks | `P2PDataStore.send_blocks_and_test(blocks, node, success, reject_reason, force_send, expect_disconnect)`: stores blocks, sends `headers` for them (or full `block` messages if `force_send`), answers the node's `getheaders`/`getdata` from its store, waits for `getdata` of the last block, then asserts `getbestblockhash` equals (or not) the last block and that `reject_reason` appears in `debug.log` | `p2p.py: P2PDataStore` |
| Block construction | `blocktools.py: create_block(hashprev, coinbase, ntime, version, tmpl, txlist)`, `create_coinbase(height, pubkey, script_pubkey, extra_output_script, fees, nValue, halving_period)` (BIP34 height push), `add_witness_commitment(block, nonce)`, `block.solve()` (regtest PoW, `REGTEST_N_BITS = 0x207fffff`); serialization classes `CBlock`, `CBlockHeader`, `CTransaction`, `CTxIn`, `CTxOut`, `CScriptWitness`, `COutPoint` and every `msg_*` type in `messages.py`; `script.py` is a `CScript` builder | `blocktools.py`; `messages.py`; `script.py` |
| Tests worth mirroring | `feature_block.py` (one node, `P2PDataStore`, ~130 hand-built invalid blocks: sigops, size, coinbase, timestamps, BIP34/66/65, duplicate inputs, ...; `-testactivationheight=bip34@2`), `p2p_segwit.py` (two nodes with `-testactivationheight=segwit@<h>` and `-acceptnonstdtxn` 1/0; witness commitment, malleation, BIP143), `feature_taproot.py` (one node; thousands of randomized spenders via `submitblock`, also the source of `script_assets_test.json`), `feature_assumeutxo.py` (four nodes; snapshot dump/load; also shows `-coinstatsindex=1` usage) | the files named |
| Activation knobs | regtest defaults: `BIP34Height`, `BIP65Height`, `BIP66Height`, `CSVHeight` = 1, `SegwitHeight` = 0, taproot `ALWAYS_ACTIVE` with `min_activation_height` 0, so every rule is on from the first block; `-testactivationheight=<name>@<height>` (`segwit`, `bip34`, `bip66`, `bip65`, `csv`) and `-vbparams=<deployment>:<start>:<end>[:<min_activation_height>]` move them, which is how `feature_block.py` and `p2p_segwit.py` test pre- and post-activation behaviour | `kernel/chainparams.cpp: CRegTestParams`; `chainparams.cpp: ReadRegTestArgs` (the `-testactivationheight` / `-vbparams` parser); `p2p_segwit.py` line 222 |

The two ways to drive a heterogeneous pair through the same blocks, using only what the
framework already offers:

- (a) Peer sync: bitmigo dials the Core node's `p2p_port(0)` (Core is started with
  `connect=0` but still listens; `-whitelist=noban@127.0.0.1` avoids bans while bitmigo's
  behaviour is immature). Core mines with `generate*`; bitmigo syncs over the wire; the
  harness then compares `getbestblockhash` / `gettxoutsetinfo muhash` from Core against
  bitmigo's own reporting channel. This exercises bitmigo's header/block download as well as
  validation.
- (b) Same bytes to both: build blocks with `blocktools.py` (or fetch them from Core with
  `getblock <hash> 0`), push them to Core with `submitblock` or `P2PDataStore`, and to
  bitmigo through whatever ingestion surface it has (a raw-block file, a stdin feed, or a
  Python `P2PInterface` acting as a peer that serves `headers`/`block` to bitmigo). This is
  what `feature_block.py` does for Core alone, and it is the only way to deliver deliberately
  invalid blocks, since Core will not relay them.

### 4.2 Floresta's functional tests (nearest prior art: a Rust node beside reference nodes)

Location: `tests/` in the Floresta repository (worktree `master`). Layout and shape:

| Piece | Detail | Source |
| --- | --- | --- |
| Runner | `pytest` with `pytest-xdist` (`-n 4 --dist=loadscope`, `-x`, `--strict-markers`); `python_files = ["*/*.py"]`, so every `.py` one directory below `tests/` is a test module; markers `example`, `florestad`, `rpc`, `p2p`, `expensive` (the last only with `--run-expensive`) | `pyproject.toml: [tool.pytest.ini_options]`; `tests/conftest.py: pytest_addoption` |
| Directories | `tests/example/` (`bitcoin.py`, `utreexod.py`, `electrum.py`, `functional.py`, `integration.py`), `tests/florestad/`, `tests/floresta-cli/` (one file per RPC), `tests/p2p/`, `tests/expensive/`, `tests/test_framework/` (the library, MIT, adapted from Core's), `tests/bitcoin_hashes/<version>` (SHA256SUMS for prebuilt Core tarballs) | directory listing |
| Binaries | `tests/prepare.sh` builds `florestad` with cargo (symlinked into `$FLORESTA_TEMP_DIR/binaries/`, default `/tmp/floresta-func-tests`), clones and `go build`s `utreexod`, and obtains `bitcoind` by (1) `BITCOIND_EXE` if set, (2) downloading the release tarball for `BITCOIN_REVISION` (default `30.2`) from bitcoincore.org and checking it against `tests/bitcoin_hashes/`, (3) building from source with cmake; `tests/run.sh` wipes `$FLORESTA_TEMP_DIR/data` and runs `uv run pytest` | `tests/prepare.sh`; `tests/run.sh` |
| Environment check | a session-scoped autouse fixture fails fast unless `FLORESTA_TEMP_DIR` exists and holds `binaries/florestad`, `binaries/utreexod`, `binaries/bitcoind` | `conftest.py: validate_and_check_environment` |
| Node class hierarchy | `NodeType` enum {`BITCOIND`, `FLORESTAD`, `UTREEXOD`}; `Node(variant, rpc_config, p2p_config, extra_args, electrum_config, targetdir, data_dir, tls, log)` composes a `daemon` (`BitcoinDaemon` / `FlorestaDaemon` / `UtreexoDaemon`, all `BaseDaemon`), an `rpc` (`BitcoinRPC` / `FlorestaRPC` / `UtreexoRPC`, all `BaseRPC`, JSON-RPC over HTTP with `requests`) and, except for bitcoind, an `ElectrumClient` | `test_framework/node.py`; `test_framework/daemon/*.py`; `test_framework/rpc/*.py` |
| Launch args | bitcoind: `-chain=regtest -datadir=<d> -rpcuser=test -rpcpassword=test -rpcport=<p> -rpcbind=127.0.0.1 -rpcthreads=1 -port=<p> -bind=127.0.0.1 + extra_args`; florestad: `--network=regtest --data-dir=<d> --rpc-address=127.0.0.1:<p> --electrum-address=...` and NO p2p listen flag ("the p2p port is not configurable in floresta"); utreexod: `--regtest --datadir=<d> --rpcuser/--rpcpass/--rpclisten --utreexoproofindex --listen=127.0.0.1:<p> --electrumlisteners=...`; `BaseDaemon.start` runs `Popen([binary] + settings())`, stdout to a per-daemon log file, sleeps one second and fails if the process died | `daemon/bitcoin.py`, `daemon/floresta.py`, `daemon/utreexo.py`, `daemon/base.py: start` |
| Ports and dirs | every port is random in `[2000, 65535]` (`Utility.get_random_port`, checked free); datadirs are `$FLORESTA_TEMP_DIR/data/<test name>/<variant><k>`; logs `$FLORESTA_TEMP_DIR/logs/<test name>/`; `run_node` retries up to three times, regenerating ports on failure (`Node.update_configs`), then waits on the RPC socket and calls `getblockchaininfo` | `test_framework/util.py: Utility`; `__init__.py: create_data_dir_for_daemon`, `run_node` |
| Fixtures | `node_manager` (a `FlorestaTestFramework` per test, stopped afterwards), `florestad_node`, `bitcoind_node`, `utreexod_node` (with `--miningaddr`, `--utreexoproofindex`, `--prune=0`), pairs `florestad_utreexod`, `florestad_bitcoind`, and a factory `florestad_bitcoind_utreexod_with_chain(blocks=100, ...)` that mines on utreexod (or `generatetoaddress` on bitcoind), then connects florestad→utreexod, bitcoind→utreexod, florestad→bitcoind with `time.sleep` pauses; class-scoped `shared_*` variants exist | `conftest.py` |
| Connecting | `connect_nodes(a, b)`: since florestad does not listen, the florestad side always dials (`addnode <host:port> add`); then `wait_for_peers_connections` polls `getpeerinfo` on both and matches by user-agent substring (`Floresta`, `utreexod`, `Satoshi`) and address (`subver`/`addr` on Core and utreexod, `user_agent`/`address` on florestad) | `__init__.py: connect_nodes`, `check_connection`; `node.py: is_peer_connected`, `get_connection_info` |
| Waiting for sync | `wait_for_sync_nodes(is_finished_ibd)`: poll until every node's `getblockcount` equals node 0's and, for florestad, `getblockchaininfo().initialblockdownload` is false; generic `wait_until(predicate, timeout=30, interval=0.5)` | `__init__.py: check_sync_nodes`, `wait_for_sync_nodes`; `util.py: wait_until` |
| Cross-node comparison | direct RPC equality: e.g. after a reorg on utreexod (`invalidateblock` then `generate`), assert `florestad.getblockchaininfo().bestblockhash == utreexod.getblockchaininfo().bestblockhash` and `florestad headers == utreexod blocks`; `util.py: compare_fields(candidate, reference, ignore_fields)` compares JSON structures recursively with the reference defining the required keys (used to check florestad's RPC output shape against Core's) | `tests/florestad/reorg_chain.py`; `test_framework/util.py: compare_fields` |
| Wire-level tricks | a port of Core's `p2p.py` (`P2PInterface`, `NetworkThread`, v1 and BIP324 v2 transport in `v2_p2p.py`) and `messages.py`; `FlorestaTestFramework.add_p2p_connection(node, p2p_conn, p2p_idx, connection_type, ...)` makes a daemon dial a Python peer (`addnode ... onetry`), used by `tests/p2p/` to feed headers, addrs and malformed messages; `create_msg_random` builds oversized/garbage messages | `test_framework/p2p.py`; `__init__.py: add_p2p_connection`, `create_msg_random` |
| What it does not do | no UTXO-set hash comparison (florestad is a utreexo node; it exposes `getroots`, the accumulator roots, instead), no reuse of Core's Python framework as a dependency (copied and adapted), no attempt to make florestad a Core `TestNode` | `rpc/floresta.py: get_roots`; `test_framework/README.md` |

### 4.3 Recommendation (not a finding)

Copy Floresta's shape, not Core's: a small pytest suite in this repository with a
`Node` abstraction over two daemons (`bitcoind`, `bitmigo`), per-test datadirs under a temp
root, random free ports, and fixtures that start a pair and connect them (bitmigo dials
Core's `-port`; Core runs `-regtest -server -connect=0 -listen=1 -coinstatsindex=1
-whitelist=noban@127.0.0.1`). Point at the installed binary with `BITCOIND` rather than
building Core. For the block source, use both paths of 4.1: Core's `generate*` for
"happy" chains, and Core's `test_framework` `blocktools.py`/`P2PDataStore` (vendored under the
MIT notice, as Floresta did) as a Python peer that serves crafted or invalid blocks to both
daemons. The comparison endpoint on the bitmigo side should be whatever operator surface the
node grows (a status file, a Unix socket, or a CLI subcommand) and must report at least
`bestblockhash`, `height`, `txouts`, `total_amount` and the finalized `muhash`; the harness
asserts them equal to `gettxoutsetinfo muhash <height> true` after each block, and runs the
`hash_serialized_3` comparison only at the end of a run. Keep the vectors of section 1 as
unit tests inside the consensus crate, with the flag reduction of 1.7 encoded once.

## References

- [BIP143] Segregated Witness transaction signature verification —
  https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
- [BIP158] Compact Block Filters for Light Clients —
  https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
- [BIP340] Schnorr Signatures for secp256k1, test vectors at `bip-0340/test-vectors.csv` —
  https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- [BIP341] Taproot: SegWit version 1 spending rules, vectors at
  `bip-0341/wallet-test-vectors.json` —
  https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- Bitcoin Core v31.1 sources — https://github.com/bitcoin/bitcoin/tree/v31.1
- Bitcoin Core PR #28685 "coinstats, assumeutxo: fix hash_serialized2 calculation" —
  https://github.com/bitcoin/bitcoin/pull/28685
- Bitcoin Core issue #28675 "Assumeutxo: Altered txoutset dump is still valid" —
  https://github.com/bitcoin/bitcoin/issues/28675
- Bitcoin Core `doc/release-notes/release-notes-26.0.md`, RPC section.
- Floresta functional tests — `tests/` in https://github.com/getfloresta/floresta (read at
  `c0457dc`).
- `docs/consensus-rules.md` in this repository, sections 3 and 7.
