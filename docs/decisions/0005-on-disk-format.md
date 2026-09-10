# 0005 — The on-disk format: two flat-file series, an append-only index, one ordering rule

**Status:** accepted, 2026-09-10.

## Decision

The node's store is three things under one lock, and the coin store joins them beside these:

```text
$XDG_DATA_HOME/bitmigo/<chain>/
├── LOCK          held for the process's life, std File::try_lock
├── anchors.dat
├── blocks/       blk00000.dat …, undo00000.dat …
├── index/        journal.dat
└── coins/
```

- **`<chain>` is in the path for every chain**, mainnet included. Core puts mainnet at the
  datadir root and hangs the others beneath it, and every path-building call site then has to
  know about the asymmetry.
- **Two independent flat-file series, one writer thread each** — the chain thread writes
  blocks, the validation thread writes undo records. Core mirrors `rev*.dat` onto `blk*.dat`
  only so that pruning can delete both together; bitmigo never prunes, and mirroring would
  make validation follow the chain thread's file cursor.
- **Framing is Core's minus the obfuscation.** A block record is `magic(4) ‖ len(u32 LE) ‖
  raw bytes`; an undo record is `magic(4) ‖ len(u32 LE) ‖ record ‖ SHA256d(previous block
  hash ‖ record)`. The location names the **body**, so serving a block is one `pread(len)`
  with no copy and no reserialisation. Blocks carry no checksum — a block is self-verifying
  against its own hash — and undo records do, because nothing else can vouch for them. No XOR
  key: Core's would force a copy-and-unmask on every block served.
- **128 MiB per file, plain append, no preallocation.** A record that would take a non-empty
  file past the threshold rolls to the next one; a record larger than the threshold gets a
  file of its own, because consensus permits a quarter-gigabyte undo record.
- **The undo record is what the block cannot say.** `spent` and `overwritten` from the
  `BlockDelta`, and not `created`, which is a pure function of a block whose bytes are on the
  disk for ever. Each spent coin carries the **index of the input it belongs to**, and each
  overwritten coin its outpoint. Coins are written under Core's amount and script compression
  (`compressor.cpp`), with the uncompressed-P2PK templates 4 and 5 refused rather than
  written.
- **The block index is one append-only journal, rewritten whole** past twice its live entry
  count. Per entry: the 80-byte header and what is known about the block behind it, under a
  four-byte `SHA256d` checksum. Height, chain work, the parent link and the skip pointer are
  recomputed at load. A **format version and the chain's genesis hash** sit in its file
  header.
- **The journal records what the node has, not what it concluded.** A refusal by
  `accept_header` and an inherited refusal are both re-derived exactly by the replay, so
  neither is written down. A refusal by one of the four stages that need the block is kept as
  its **stage and not its reason**.
- **One ordering rule, applied three times: a record that names bytes is committed only after
  those bytes are durable.** Files → index → coins. The middle step crosses a thread
  boundary, so it is kept structurally instead of by a handshake: **the chain thread never
  hands validation a block the index has not committed.**
- **The datadir lock is `std::fs::File::try_lock`**, stabilised in Rust 1.89. No `libc`, so
  [decision 0004](0004-libc.md) stays scoped to signals.

## Why

- **Byte-identical serving.** R4 §8.6: a peer must get back the bytes it would get from any
  other node. A store that normalised on write, or masked with an XOR key, could not serve by
  `pread`, and every design that reserialises is one bug away from a different block.
- **The undo record must round-trip a coin exactly.** A coin put back has to serialize
  identically to the one taken out, or this node's UTXO-set hash leaves every other node's
  behind. That is why the coin encoder is one encoder for the whole node, and why a script
  it does not recognise is stored verbatim rather than nearly.
- **An input index, not an outpoint, and not nothing.** Core writes nothing and recovers the
  pairing by position, which means the same "was this spend in-block" filter has to run
  identically on the connect and the disconnect path, and a disagreement between them stays
  silent until a hash diverges. Writing the outpoint out in full would be about 97 GB over a
  mainnet history. The index is two or three bytes, about 8 GB, and makes the record
  self-describing against the block: the decoder refuses indices that do not ascend or that
  name no input.
- **A stage, not a reason.** `Invalidity` wraps four consensus error enums; a codec for all
  of them would be several hundred lines for values whose job is to produce a line of text,
  and a new error variant would silently become an index-format change. What has to survive a
  restart is that the block is never built on again, and a byte says that.
- **The marker is the truth.** Persisted status is a hint: a crash between the index write
  and the coins write leaves headers claiming `Connected` for blocks the on-disk set does not
  include. The loader takes the coin store's marker as the tip and demotes everything above
  it. Demoting costs a reconnect and never a re-download; believing the index is not safe.
- **A batch, not an `fsync` per block.** Making the ordering structural means the chain
  thread commits before it hands work over, which during a sync is one `fsync` per thousand
  headers rather than one per block, and near the tip is one every minute at worst.

## Consequences

- Bytes that are durable but unnamed are dead space. An archival node that never deletes has
  nowhere to put a reclaim, and Core behaves the same way.
- A torn tail record is discarded and the blocks it named are downloaded again. That is the
  only shape a partial write can take, because a record is never named by anything until the
  batch it is in has been `fsync`ed.
- A block that was refused after its bytes were written keeps those bytes for ever: the
  header tree's `Invalid` state carries no location, so nothing can find them again.
- Power loss is implemented but unproven. `kill -9` is process death and the page cache
  survives it; the `fsync` ordering that would also survive power loss is Core's own
  discipline and is written, but a device-mapper harness to prove it would need its own
  decision. The `kill -9` matrix itself belongs with the regtest differential harness, where
  the muhash oracle already is.
- `blocks/` is a directory of its own so that an operator can symlink it onto another disk
  today with no flag at all. What a `-blocksdir` equivalent should look like is the operator
  surface's question.
- Two bitmigos on one data directory is refused before a socket is bound. The kernel drops
  the lock with the process, so there is no stale-lockfile case — which is exactly the case a
  store designed around `kill -9` would otherwise meet on every restart.
