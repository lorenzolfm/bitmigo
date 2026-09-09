# 0002 — Chain parameters: every deployment buried, exceptions by hash

**Status:** accepted, 2026-09-08.

## Decision

`bitmigo_consensus::params` answers "which rules apply to this block" with one function,
`ChainParams::rules_at(height, hash, bip34_ancestor) -> Rules`, over a table of constants per
chain. The table has this shape and no other:

- **Every softfork is a buried height.** BIP34, BIP66, BIP65, CSV and SegWit each have one
  height per chain. P2SH, WITNESS and TAPROOT have none: they apply from genesis, minus a
  per-block **exception list keyed by block hash** (mainnet blocks 170060 and 692261). There
  is no BIP9 versionbits state machine and no `-vbparams`.
- **`ChainParams` has private fields and named constructors** (`mainnet()`, `signet(challenge)`
  and `regtest(overrides)`), and holds only what validation reads:
  genesis, `powLimit`, retarget parameters, halving interval, buried heights, the BIP34 block
  hash, the exception lists. Network magic, ports, seeds and minimum chain work are the node's.
- **`Height` and `BlockTime` are newtypes** with no `From<u32>` and only the arithmetic the
  rules need; timespans are `i64`.
- **Regtest's knobs are Core's**, spelled Core's way: `-testactivationheight=name@height` for
  the five buried heights and `-test=bip94`, parsed by a pure function that fails with Core's
  messages.
- **Three chains**: mainnet, signet, regtest. **No checkpoints.**

## Why

- **It is what Core validates.** Core's `GetBlockScriptFlags` never reads the versionbits
  state; taproot's deployment record feeds only RPC. Mirroring the state machine would add a
  second source of truth for a fact the chain has already settled. A future softfork is new
  rule code and a new height, in Core and here alike.
- **Exceptions only relax.** Keying them by hash, as Core does, means a fork block at the same
  height gets the full rule set, and the constructor can assert that every exception is a
  subset of the always-on flags. A height-keyed list could not say that.
- **Unwritable wrong chains.** With no taproot height, "taproot before segwit" cannot be
  expressed. With private fields, a `ChainParams` that skipped the genesis assertion cannot
  exist. With distinct newtypes, a height cannot be compared with a timestamp.
- **The harness passes one command line to both nodes.** Accepting Core's spelling and Core's
  error text is what lets a regtest scenario be described once.
- **Checkpoints are a rule Core no longer has**, and a node that carries one Core lacks can
  disagree with it. Minimum chain work is a download-time defence, not a validity rule, so it
  lives node-side.

## Consequences

- `Rules` is the only way a contextual check learns about activations; nothing outside
  `params` compares a height to a deployment constant.
- The BIP30 window is part of `Rules`: `bip30_check_required` is false only for the two 2010
  repeat blocks and, on mainnet, from the block after the BIP34 block until height 1,983,702
  (`BIP34_IMPLIES_BIP30_LIMIT`). The node reports the hash of the ancestor at the BIP34
  height; the crate compares it, so a node cannot assert a match.
- The script flag type is the interpreter's `script::ScriptFlags`, re-exported by `params`
  because `Rules` produces it.
- Signet is the one chain whose `ChainParams` carries a `BlockChallenge`. The rule it implies
  is a block rule, so it lives in `block::signet`; `check_block` matches on the challenge and
  mainnet and regtest take the `None` arm.
- Testnet3 and testnet4 are data, not design: adding one is a constructor and a table row,
  with the testnet3 exception block 394 joining the exception list.
