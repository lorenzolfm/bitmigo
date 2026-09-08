# Storage layouts of Bitcoin Core, btcd and Floresta, and what an archival node must answer

- Core tag read: `v31.1` (commit `9be056a8`, "Finalise 31.1"), shallow-cloned and grepped; the
  installed `bitcoind --version` reports `v31.1.0`.
- btcd read from `master` at `05585e03` (2026-07-24, "version-bump-v0.26.2"), fetched file by
  file from raw.githubusercontent.com.
- utreexod read at `22c9737e` (2026-05-20); Floresta read from the `master` worktree at
  `c0457dc` (2026-09-01). Both on disk, read-only.
- Bitcoin Core GitHub PRs #34677 and #35465 and `doc/release-notes/release-notes-31.0.md`
  from `master` were read for the size figures and the dbcache change; they are cited by number.
- Date: 2026-09-08.

How to read this document. It describes what the three reference implementations write to
disk and keep in memory, and, for each structure, which question of a running node it exists to
answer. Core sources are written `file: Symbol`, always relative to `src/` at tag `v31.1` (so
`txdb.cpp: CCoinsViewDB::BatchWrite` means `src/txdb.cpp`); btcd sources are written with their
path under the repository root (`blockchain/chainio.go: dbPutBestState`); Floresta sources are
under `crates/floresta-chain/src/`. Byte layouts are given as Core writes them; `VARINT` is
Core's MSB-base-128 varint with the "minus one per continuation" offset (`serialize.h`), which
btcd calls a VLQ and documents identically. Where a claim could not be confirmed from a primary
source the sentence says so with the word "unverified". Sections 1 to 5 are findings; section 6
is a list of observations for an implementer and decides nothing.

## 1. The UTXO set

### 1.1 Core on disk: `chainstate/`

| Element | Detail | Source |
| --- | --- | --- |
| Store | one LevelDB at `<datadir>/chainstate/`, opened with `obfuscate = true`; the whole value of every record is XORed with a random 8-byte key stored under the null-prefixed key `\0obfuscate_key` | `doc/files.md`; `validation.cpp: Chainstate::InitCoinsDB`; `dbwrapper.h: CDBWrapper::OBFUSCATION_KEY`; `dbwrapper.cpp: CDBWrapper::CDBWrapper` |
| Coin key | `'C' ‖ txid (32 bytes, internal byte order) ‖ VARINT(n)`; the prefix byte is `DB_COIN` | `txdb.cpp: CoinEntry`, `DB_COIN` |
| Coin value | `VARINT(height * 2 + coinbase) ‖ VARINT(CompressAmount(value)) ‖ compressed script`; `Serialize` asserts the coin is not spent, so the DB never holds a spent coin and `GetCoin` re-asserts that on read | `coins.h: Coin::Serialize`; `txdb.cpp: CCoinsViewDB::GetCoin` |
| Height word | `nHeight` is a 31-bit bitfield, `fCoinBase` 1 bit; the pair packs into one `uint32_t` | `coins.h: Coin` |
| Amount compression | 0 → 0; else strip up to 9 trailing decimal zeros into `e`; if `e < 9` take the last digit `d` (1..9), drop it, output `1 + 10*(9*n + d - 1) + e`; if `e == 9` output `1 + 10*(n-1) + 9`; the varint of that is at most as long as the varint of the amount and usually 2-4 bytes | `compressor.cpp: CompressAmount`, `DecompressAmount` |
| Script templates | a leading `VARINT(nSize)`; `nSize < 6` selects a special form: `0` = P2PKH (20 bytes follow), `1` = P2SH (20 bytes), `2`/`3` = P2PK with a compressed key whose first byte is `nSize` (32 bytes follow), `4`/`5` = P2PK with an uncompressed key, stored as the x coordinate plus the parity in the low bit of `nSize` (32 bytes follow, decompressed with `CPubKey::Decompress`); otherwise `nSize - 6` is the raw script length and the script follows verbatim | `compressor.h: ScriptCompression`, `nSpecialScripts`; `compressor.cpp: CompressScript`, `DecompressScript`, `GetSpecialScriptSize` |
| Template matching is strict | P2PK is only compressed when the pushed key is 33 bytes starting `02`/`03`, or 65 bytes starting `04` and `IsFullyValid()`; anything else is stored raw | `compressor.cpp: IsToPubKey` |
| Oversized script on read | if `nSize - 6 > MAX_SCRIPT_SIZE` the bytes are skipped and the script becomes a bare `OP_RETURN` | `compressor.h: ScriptCompression::Unser` |
| Best block | key `'B'` (`DB_BEST_BLOCK`) → `uint256` hash of the block the on-disk set corresponds to; absent while a flush is in progress (see 1.3) | `txdb.cpp: DB_BEST_BLOCK`, `GetBestBlock` |
| Head blocks | key `'H'` (`DB_HEAD_BLOCKS`) → `std::vector<uint256>` of exactly two hashes `[new_tip, old_tip]`, present only during a flush | `txdb.cpp: DB_HEAD_BLOCKS`, `GetHeadBlocks` |
| Legacy key | `'c'` (`DB_COINS`, per-txid records) was retired in v0.15; `NeedsUpgrade` refuses a DB that still has one | `txdb.cpp: NeedsUpgrade` |
| LevelDB options | block cache = `cache_bytes / 2`, write buffer = `cache_bytes / 4`, 10-bit bloom filter, no compression, `paranoid_checks`, 32 MiB SST files, `max_open_files = 64` on platforms where LevelDB's default of 1000 would mmap too much | `dbwrapper.cpp: GetOptions`, `SetMaxOpenFiles`; `dbwrapper.h: DBWRAPPER_MAX_FILE_SIZE` |
| Cursor order | a full scan is `Seek('C')` then `Next()` while the key prefix is still `'C'`; LevelDB is lexicographic, so txids ascend by internal byte order and outputs within a txid ascend by `n` (VARINT preserves numeric order) | `txdb.cpp: CCoinsViewDB::Cursor`, `CCoinsViewDBCursor::Next` |
| Size estimate | `EstimateSize` asks LevelDB for the byte range `['C', 'D')` | `txdb.cpp: CCoinsViewDB::EstimateSize` |

### 1.2 Core in memory: `CCoinsViewCache`

Core layers views: `CCoinsViewDB` (LevelDB) → `CCoinsViewErrorCatcher` → `CCoinsViewCache`
(`m_cacheview`, "CoinsTip", the big dbcache-bounded map) → `CoinsViewOverlay`
(`m_connect_block_view`, a one-block scratch view). The overlay fetches misses with `PeekCoin`
so that a failed `ConnectBlock` cannot pollute the parent, and is reset by a guard after every
block; on success it is flushed down into `CoinsTip` (`validation.h: CoinsViews`,
`validation.cpp: CoinsViews::InitCache`, `Chainstate::ConnectTip`; `coins.h: CoinsViewOverlay`).

| Element | Detail | Source |
| --- | --- | --- |
| Map | `std::unordered_map<COutPoint, CCoinsCacheEntry, SaltedOutpointHasher>` with a pool allocator sized for the node; the salt is random unless the cache is built `deterministic` | `coins.h: CCoinsMap`; `coins.cpp: CCoinsViewCache::CCoinsViewCache` |
| Entry flags | `DIRTY` = may differ from the parent; `FRESH` = the parent has no unspent version of this coin. Of the 8 (spent, dirty, fresh) combinations only four are legal: unspent+FRESH+DIRTY (new coin), unspent+DIRTY (changed during a reorg), unspent+clean (fetched from parent), spent+DIRTY+not FRESH (spentness must reach the parent) | `coins.h: CCoinsCacheEntry` (comment block) |
| Why FRESH | "If a FRESH coin in the cache is later spent, it can be deleted entirely and doesn't ever need to be flushed to the parent. This is a performance optimization." Misapplying FRESH to a coin that exists unspent in the parent "will cause a consensus failure, since it might not be deleted from the parent when this cache is flushed" | `coins.h: CCoinsCacheEntry::Flags` |
| Why DIRTY | "Failure to mark a coin as DIRTY when it is potentially different from the parent cache will cause a consensus failure" | same |
| Flagged-entry list | every DIRTY or FRESH entry is threaded into a circular doubly linked list through a sentinel pair (`m_prev`/`m_next` inside the entry), so a flush walks only flagged entries instead of the whole map; `SetClean` unlinks | `coins.h: CCoinsCacheEntry::AddFlags`, `SetClean`, `CCoinsViewCache::m_sentinel` |
| `AddCoin` | refuses to overwrite an unspent coin unless `possible_overwrite`; marks FRESH only when the slot was absent or was a spent-and-not-DIRTY entry, because a spent DIRTY entry means spentness has not reached the parent yet ("Re-adding a spent coin can happen in the case of a re-org"); unspendable scripts are never added | `coins.cpp: CCoinsViewCache::AddCoin` |
| `AddCoins` | coinbase outputs are always added with `possible_overwrite = true` "to correctly deal with the pre-BIP30 occurrences of duplicate coinbase transactions" | `coins.cpp: AddCoins` |
| `SpendCoin` | moves the coin out (into the undo record), then erases the entry if FRESH, else clears it and marks DIRTY | `coins.cpp: CCoinsViewCache::SpendCoin` |
| Child→parent write | `BatchWrite` into a parent cache: FRESH+spent children vanish; new entries move up and inherit FRESH only if the child was FRESH; a FRESH child meeting an unspent parent throws `"FRESH flag misapplied"`; a spent child meeting a FRESH parent deletes the parent entry | `coins.cpp: CCoinsViewCache::BatchWrite` |
| Memory accounting | `DynamicMemoryUsage()` = map overhead + Σ script allocations (`cachedCoinsUsage`), maintained on every add/spend/uncache; `m_dirty_count` is kept alongside | `coins.cpp: CCoinsViewCache::DynamicMemoryUsage`, `SanityCheck` |
| Cache budget | `-dbcache` bytes are split: block-tree LevelDB `min(total/8, 2 MiB)`, then coins LevelDB `min(rest/2, 8 MiB)`, the rest to the in-memory coins cache; optional indexes take up to `total/8` each first | `kernel/caches.h: CacheSizes`; `node/caches.cpp: CalculateCacheSizes` |
| `-dbcache` default | `DEFAULT_KERNEL_CACHE = 450 MiB`, raised to `HIGH_DEFAULT_DBCACHE = 1024 MiB` on 64-bit systems with `>= 4096 MiB` detected RAM; minimum 4 MiB; capped at 1024 MiB on 32-bit. The raise shipped in 31.0 (#34692) | `kernel/caches.h`; `node/caches.cpp: GetDefaultDBCache`, `CalculateDbCacheBytes`; `node/caches.h: MIN_DB_CACHE`; `release-notes-31.0.md` |
| Size states | total space = coins budget + unused mempool budget; usage above that is `CRITICAL`; above `max(90 % of it, it - 10 MiB)` is `LARGE` | `validation.cpp: Chainstate::GetCoinsCacheSizeState`; `validation.h: LargeCoinsCacheThreshold` |

### 1.3 Flushing, the dirty marker, and crash recovery

| Element | Detail | Source |
| --- | --- | --- |
| Modes | `IF_NEEDED` (after every connect/disconnect; writes only when `CRITICAL`), `PERIODIC` (writes when `LARGE` or when the randomized 50-70 min timer fires), `FORCE_FLUSH` (write and empty), `FORCE_SYNC` (write, keep cache), `NONE` (prune bookkeeping only) | `validation.h: FlushStateMode`; `validation.cpp: FlushStateToDisk`, `DATABASE_WRITE_INTERVAL_MIN/MAX` |
| Flush vs Sync | `empty_cache = FORCE_FLUSH ‖ LARGE ‖ CRITICAL`; when true `CoinsTip().Flush()` (erase everything, reallocate the map), otherwise `CoinsTip().Sync()` (write dirty entries, keep unspent ones, erase spent ones). The periodic timer therefore no longer empties the cache | `validation.cpp: FlushStateToDisk`; `coins.cpp: CCoinsViewCache::Flush`, `Sync`; `coins.h: CoinsViewCacheCursor` |
| Cursor contract | the same `CoinsViewCacheCursor` serves both; `NextAndMaybeErase` clears flags (Sync) or leaves erasure to the caller (Flush); `WillErase` lets the receiver move instead of copy | `coins.h: CoinsViewCacheCursor` |
| Order inside one flush | block/undo files are fsynced first, then the block index and file info are written to `blocks/index/` with `sync = true`, then pruned files are unlinked, then the coins are written | `validation.cpp: FlushStateToDisk` ("write block and undo data to disk", "write block index to disk"); `node/blockstorage.cpp: BlockTreeDB::WriteBatchSync` |
| Disk-space guard | before writing coins Core requires `48 * 2 * 2 * dirty_count` free bytes: 48 bytes per entry, written twice by LevelDB (log and table), times a safety factor of 2 | `validation.cpp: FlushStateToDisk` (comment) |
| `BatchWrite` | the first LevelDB batch erases `'B'` and writes `'H' = [new_tip, old_tip]`; dirty entries are then written (`Erase` for spent, `Write` for unspent) in batches of `-dbbatchsize` (default `DEFAULT_DB_CACHE_BATCH = 32 MiB`); the final batch erases `'H'` and writes `'B' = new_tip` | `txdb.cpp: CCoinsViewDB::BatchWrite`; `txdb.h: CoinsViewOptions`; `kernel/caches.h: DEFAULT_DB_CACHE_BATCH` |
| Why two hashes | "mark the database as being in the middle of a transition from old_tip to hashBlock. A vector is used for future extensibility, as we may want to support interrupting after partial writes from multiple independent reorgs" | `txdb.cpp: CCoinsViewDB::BatchWrite` (comment) |
| Resuming a flush | if `'B'` is absent and `'H'` has two entries, the new flush must target `H[0]` (asserted) and treats `H[1]` as the old tip | same |
| Crash test hook | `-dbcrashratio` makes `BatchWrite` `_Exit(0)` after a partial batch with probability `1/ratio` | `txdb.cpp: BatchWrite`; `txdb.h: CoinsViewOptions::simulate_crash_ratio` |
| Recovery | at startup `ReplayBlocks` reads `'H'`; if present it finds the fork between `H[1]` (old tip, may be null on a first flush) and `H[0]`, disconnects from the old tip down to the fork using `rev*.dat` (never disconnecting genesis), then rolls forward with `RollforwardBlock` (spend inputs, `AddCoins` with `check_for_overwrite = true` because every addition may be a re-write of an already flushed coin), and finally `Flush`es with best block `H[0]` | `validation.cpp: Chainstate::ReplayBlocks`, `RollforwardBlock` |
| Why replay works | a partially written batch leaves some coins at the old state and some at the new; re-applying every block from the fork to `H[0]` is idempotent for `AddCoin(possible_overwrite)` and `SpendCoin` (no-op if absent), so the result is the new state regardless of where the crash fell | `validation.cpp: RollforwardBlock`; `coins.cpp: SpendCoin` |
| Tip after load | `LoadChainTip` sets `m_chain` to the block whose hash is `'B'`, and renumbers that chain's `nSequenceId` so it wins ties over reboots | `validation.cpp: Chainstate::LoadChainTip` |
| Compaction | after a full flush outside IBD, with probability `1/320` per flush (about fortnightly with hourly flushes), a background `CompactFull` of the chainstate is started; added by #35465 and backported to 31.1 | `validation.cpp: ShouldCompactChainstate`; `txdb.cpp: CCoinsViewDB::CompactFull`; PR #35465 |

### 1.4 btcd

btcd stores everything in one `ffldb` database: LevelDB for metadata buckets, flat files for
blocks (section 2.4). The UTXO layer lives in the metadata bucket `utxosetv2`
(`blockchain/chainio.go: utxoSetBucketName`).

| Element | Detail | Source |
| --- | --- | --- |
| Key | `hash (32) ‖ VLQ(index)`; the comment notes the MSB VLQ keeps byte-wise iteration in numeric order | `blockchain/chainio.go` ("The unspent transaction output (utxo) set") |
| Value | `VLQ(header code) ‖ VLQ(compressed amount) ‖ compressed script`, header code `height << 1 ‖ coinbase`; described as "a slightly modified version of the format used in Bitcoin Core" | same |
| Script templates | the same six: `cstPayToPubKeyHash = 0`, `cstPayToScriptHash = 1`, `cstPayToPubKeyComp2/3`, `cstPayToPubKeyUncomp4/5`, `numSpecialScripts = 6`; VLQ is documented with worked encodings (0-127 one byte, 128-16511 two bytes) | `blockchain/compress.go` |
| Best state | metadata key `chainstate` → `hash (32) ‖ height u32 LE ‖ total txns u64 LE ‖ work-sum length u32 LE ‖ work-sum big-endian bytes`; rewritten on every connect and disconnect | `blockchain/chainio.go: bestChainState`, `serializeBestChainState` |
| Cache | `utxoCache` (added in the 2023 utxocache work) holds `map[OutPoint]*UtxoEntry` slices bounded by `maxTotalMemoryUsage`; an entry carries `modified`/`fresh` flags with the same meaning as Core's DIRTY/FRESH ("If an entry is fresh, we will always have it in the cache") | `blockchain/utxocache.go: utxoCache`, `addTxIn` |
| Flush modes | `FlushRequired`, `FlushPeriodic` (every 5 min after IBD), `FlushIfNeeded` (only when memory is at the limit, skipped if already flushed at this tip) | `blockchain/utxocache.go: FlushMode`, `utxoFlushPeriodicInterval`, `flush` |
| Consistency marker | `writeCache` deletes spent/nil entries, puts modified ones, then writes metadata key `utxostateconsistency = best block hash` in the same DB transaction, so the marker names the block up to which the on-disk set is complete | `blockchain/utxocache.go: writeCache`; `blockchain/chainio.go: dbPutUtxoStateConsistency` |
| Recovery | `InitConsistentState` compares the marker with the best-chain tip; if behind, it replays forward from the marker block to the tip through the cache, flushing as needed. It never disconnects, because "the cache is flushed before the reorganization begins and the utxo set at each block disconnect is written atomically" | `blockchain/utxocache.go: InitConsistentState` |
| Connect ordering | `connectBlock`: flush dirty block-index nodes, then one DB transaction writes best state, hash↔height index, spend journal (and prunes); after commit `flush(FlushIfNeeded)` in a second transaction | `blockchain/chain.go: connectBlock` |
| Disconnect ordering | `disconnectBlock`: one transaction writes best state, removes the height index entry, `flush(FlushRequired)` of the cache, then `dbPutUtxoView` (restore spent, remove created), then removes the spend-journal entry | `blockchain/chain.go: disconnectBlock` |

### 1.5 Floresta

Floresta keeps no UTXO set. Its chain state is a utreexo `Stump` (the accumulator roots and a
leaf count); block inputs are proven against it with per-block proofs supplied by peers, and
the accumulator after each block is serialized and stored per height
(`pruned_utreexo/chain_state.rs: update_view`; `chainstore.rs: ChainStore::save_roots_for_block`,
`load_roots_for_block`). A reorg reloads the roots stored for the fork height rather than
unspending anything (`chain_state.rs: reorg_acc`, `reorg`). The worst-case accumulator is
bounded at 64 roots × 32 bytes + 8 bytes = 2056 bytes (`flat_chain_store.rs:
MAX_ACCUMULATOR_SIZE`). Script verification, when the `bitcoinkernel` feature is on, calls
`bitcoinkernel::verify` per input with flags derived from the height; nothing else from
libbitcoinkernel is used (`pruned_utreexo/consensus.rs: verify_transaction`;
`chainparams.rs: get_validation_flags`; `Cargo.toml: bitcoinkernel = "=0.3.0"`).

This does not transfer to an archival node because such a node must answer "what does this
outpoint hold" for arbitrary outpoints without a peer-supplied proof, and must serve undo data
and blocks it validated itself; an accumulator answers only "is this (outpoint, data) pair
in the set, given a proof".

## 2. Blocks and undo data

### 2.1 Core block files `blk*.dat`

| Element | Detail | Source |
| --- | --- | --- |
| Files | `<blocksdir>/blkNNNNN.dat`, 5-digit sequence, 128 MiB max (`MAX_BLOCKFILE_SIZE = 0x8000000`), preallocated in 16 MiB chunks (`BLOCKFILE_CHUNK_SIZE`); undo files `revNNNNN.dat` preallocated in 1 MiB chunks (`UNDOFILE_CHUNK_SIZE`) | `node/blockstorage.h`; `doc/files.md` |
| Record framing | `message start (4) ‖ size (u32 LE) ‖ block serialized with witness`; `STORAGE_HEADER_BYTES = 8`; the index stores the position of the block body, so a read seeks to `nDataPos - 8`, checks the magic and rejects `size > MAX_SIZE` | `node/blockstorage.cpp: BlockManager::WriteBlock`, `ReadRawBlock`; `node/blockstorage.h: STORAGE_HEADER_BYTES` |
| XOR | since 28.0 every byte of `blk*`/`rev*` is XORed with the 8-byte key in `<blocksdir>/xor.dat` (all zero when `-blocksxor=0`, and then the key cannot be enabled later); the key is created only on a first run | `node/blockstorage.cpp: InitBlocksdirXorKey`; `kernel/blockmanager_opts.h: DEFAULT_XOR_BLOCKSDIR`; `release-notes-28.0.md` |
| Read checks | `ReadBlock` verifies the header PoW and, when a hash is expected, that the hash matches the index entry | `node/blockstorage.cpp: BlockManager::ReadBlock` |
| Placement | `FindNextBlockPos` appends at `m_blockfile_info[nFile].nSize`; when the record would not fit it moves to `MaxBlockfileNum() + 1`, flushes and truncates ("finalizes") the previous file, and records the new cursor; blocks are written in download order, so heights within a file are not sorted | `node/blockstorage.cpp: BlockManager::FindNextBlockPos`, `FlushBlockFile`; `flatfile.cpp: FlatFileSeq::Flush` |
| Two cursors | one cursor for `NORMAL` files and one for `ASSUMED` files (blocks at or above the assumeutxo snapshot height), so background validation and tip-following write to different files | `node/blockstorage.h: BlockfileCursor`, `BlockfileType`; `node/blockstorage.cpp: BlockfileTypeForHeight` |
| Written on receipt | `AcceptBlock` writes the block (`WriteBlock`) and calls `ReceivedBlockTransactions` before any validation beyond `CheckBlock`; connection happens later in `ActivateBestChain`. Invalid-but-well-formed blocks therefore also occupy `blk*` space | `validation.cpp: ChainstateManager::AcceptBlock` ("Write block to history file"), `ReceivedBlockTransactions` |
| Per-file bookkeeping | `CBlockFileInfo{nBlocks, nSize, nUndoSize, nHeightFirst, nHeightLast, nTimeFirst, nTimeLast}`, all VARINT, kept in `m_blockfile_info` and written under `'f' ‖ int nFile` (`DB_BLOCK_FILES`); the highest file number is under `'l'` (`DB_LAST_BLOCK`) | `node/blockstorage.h: CBlockFileInfo`; `node/blockstorage.cpp: DB_BLOCK_FILES`, `DB_LAST_BLOCK`, `WriteBatchSync` |
| Positions | `FlatFilePos{nFile: i32, nPos: u32}`, serialized as `VARINT(nFile) ‖ VARINT(nPos)`; `nFile == -1` is null | `flatfile.h: FlatFilePos` |
| Preallocation | `Allocate` grows the file to the next multiple of the chunk size, after checking free space; the zero-filled tail is cut off by `Flush(finalize = true)` | `flatfile.cpp: FlatFileSeq::Allocate`, `Flush` |
| File fsync policy | `FlushChainstateBlockFile` (called from every state flush) fsyncs only the file the active cursor points at; a file is fsynced-and-truncated once when it is left | `node/blockstorage.cpp: FlushChainstateBlockFile`, `FlushBlockFile` |

### 2.2 Core undo files `rev*.dat`

| Element | Detail | Source |
| --- | --- | --- |
| Record | `message start (4) ‖ size (u32) ‖ CBlockUndo ‖ SHA256d(prev block hash ‖ CBlockUndo)` (32 bytes); `UNDO_DATA_DISK_OVERHEAD = 8 + 32` | `node/blockstorage.cpp: BlockManager::WriteBlockUndo`; `node/blockstorage.h: UNDO_DATA_DISK_OVERHEAD` |
| Checksum use | on read a `HashVerifier` folds the previous block hash then the bytes as they are deserialized and compares with the trailer; the comment says reserializing could lose data, hence hashing the raw stream | `node/blockstorage.cpp: BlockManager::ReadBlockUndo` |
| `CBlockUndo` | `vector<CTxUndo>` for every transaction except the coinbase (so `vtxundo.size() + 1 == vtx.size()`) | `undo.h: CBlockUndo`; `validation.cpp: DisconnectBlock` |
| `CTxUndo` | `vector<Coin>` with one entry per input, in input order, each the coin that input spent | `undo.h: CTxUndo`; `validation.cpp: UpdateCoins` |
| Per-input bytes | `VARINT(height * 2 + coinbase)`, then a single `0x00` byte if `height > 0` (a legacy "transaction version" slot kept for compatibility), then the compressed `CTxOut` (same amount and script compression as the chainstate) | `undo.h: TxInUndoFormatter` |
| Same file as the block | undo goes into `rev` with the same number as the `blk` file that holds the block (`FindUndoPos(state, block.nFile, ...)`) | `node/blockstorage.cpp: BlockManager::WriteBlockUndo`, `FindUndoPos` |
| When written | at the end of `ConnectBlock`, after all script checks and before `RaiseValidity(BLOCK_VALID_SCRIPTS)`; skipped when `fJustCheck`. So undo exists exactly for blocks that were connected at least once | `validation.cpp: Chainstate::ConnectBlock` |
| Index update | `block.nUndoPos = pos`, `nStatus \|= BLOCK_HAVE_UNDO`, block marked dirty in the index; `CheckBlockIndex` asserts `HAVE_UNDO ⇒ HAVE_DATA` | `node/blockstorage.cpp: WriteBlockUndo`; `validation.cpp: CheckBlockIndex` |
| Why on connect | the undo record is a by-product of applying the block: `UpdateCoins` moves each spent coin out of the cache into `txundo.vprevout` as it spends it, so the data is only available at connect time; a later flush no longer has the spent coins | `validation.cpp: UpdateCoins`; `coins.cpp: SpendCoin(moveto)` |
| Undo-file trimming | `BlockfileCursor::undo_height` tracks the highest block whose undo was written into the current file; undo files are truncated when their block file is finalized and the two heights agree, "a heuristic" the comment admits can trim early or late | `node/blockstorage.h: BlockfileCursor` (comment); `node/blockstorage.cpp: FindNextBlockPos`, `WriteBlockUndo` |
| Availability query | `CheckBlockDataAvailability(upper, lower, status)` walks `pprev` from `upper` while the status mask holds and reports whether it reaches `lower`; the genesis block never has undo, so a `HAVE_UNDO` query down to height 0 is satisfied by `HAVE_DATA` at height 1 | `node/blockstorage.cpp: BlockManager::CheckBlockDataAvailability`, `GetFirstBlock` |
| Pruning | a pruned file clears `HAVE_DATA`, `HAVE_UNDO`, `nFile/nDataPos/nUndoPos` on every index entry in it and resets its `CBlockFileInfo`; `MIN_BLOCKS_TO_KEEP = 288` blocks below the tip are never pruned | `node/blockstorage.cpp: PruneOneBlockFile`; `validation.h: MIN_BLOCKS_TO_KEEP` |

### 2.3 What `DisconnectBlock` needs, and why the record is exactly that

| Step | What it reads | Source |
| --- | --- | --- |
| Read undo | `ReadBlockUndo`; fails if the count mismatches the block | `validation.cpp: DisconnectBlock` |
| Remove created outputs | for every spendable output, `SpendCoin` and check the removed coin equals `(txout, height, coinbase)` from the block; mismatch sets `fClean = false` unless it is one of the two BIP30 duplicate-coinbase blocks (91722, 91812) | same |
| Restore inputs | in reverse transaction and input order, `ApplyTxInUndo`: if the coin already exists unspent, `fClean = false` and the add is an overwrite; if the undo record has `nHeight == 0` (pre-0.15 records only carried metadata on the last spend of a txid) the height/coinbase are copied from another unspent output of the same txid via `AccessByTxid`, else `DISCONNECT_FAILED` | `validation.cpp: ApplyTxInUndo`, `AccessByTxid` |
| Result | `DISCONNECT_OK` / `DISCONNECT_UNCLEAN` (state was inconsistent but repaired) / `DISCONNECT_FAILED`; `DisconnectTip` accepts only `OK`, `ReplayBlocks` accepts anything but `FAILED` | `validation.cpp: DisconnectTip`, `ReplayBlocks` |
| Why those four fields | the coin re-created must serialize identically to the one that was spent (script, amount, height, coinbase flag), otherwise the chainstate and every UTXO-set hash diverge from a node that never saw the fork; height and coinbase are needed again for maturity and BIP30 checks when the block is re-connected | `coins.h: Coin::Serialize`; `kernel/coinstats.cpp: TxOutSer` (see `docs/differential-testing.md` §2) |

### 2.4 btcd: `ffldb` flat files and the spend journal

| Element | Detail | Source |
| --- | --- | --- |
| Block files | `<db>/blocks/NNNNNNNNN.fdb` (9 digits), 512 MiB max, `maxOpenFiles = 25` read handles | `database/ffldb/blockio.go: blockFilenameTemplate`, `maxBlockFileSize` |
| Record | `network (4) ‖ block length (4) ‖ serialized block ‖ CRC-32C checksum (4)` | `database/ffldb/blockio.go: writeBlock` ("Format: ..."), `castagnoli` |
| Location index | LevelDB bucket `ffldb-blockidx`, key = block hash, value = `file u32 ‖ offset u32 ‖ length u32` (12 bytes) followed by the 80-byte header, "since they are so commonly needed"; the write cursor is persisted under `ffldb-writeloc` | `database/ffldb/db.go: blockIdxBucketName`, `writeLocKeyName`, `blockHdrOffset`, `writePendingAndCommit`; `blockio.go: serializeBlockLoc` |
| Commit order | file deletions first ("we can't undo deletions of files"), then blocks appended to the flat file (with rollback of the write cursor on failure), then the LevelDB batch for index and metadata | `database/ffldb/db.go: writePendingAndCommit` |
| Spend journal | bucket `spendjournal`, key = block hash, value = the spent outputs of the whole block in reverse spend order, each `VLQ(header code) ‖ 0x00 reserved ‖ compressed txout`; not self-describing: the number of entries comes from the block's inputs | `blockchain/chainio.go` ("The transaction spend journal"), `dbPutSpendJournalEntry`, `dbFetchSpendJournalEntry` |
| Why reverse | "later transactions are allowed to spend outputs from earlier ones in the same block", so unspending walks backwards | same (comment) |
| Why a journal | "the spent transaction outputs must be resurrected from somewhere ... this is the most straight forward method that does not require having a transaction index and unpruned blockchain" | same (comment) |
| Pruning | `dbTx.PruneBlocks(target)` deletes whole `.fdb` files; the spend journals of the deleted blocks are removed in the same transaction and a UTXO flush is forced if a deleted block is past the last flush | `blockchain/chain.go: connectBlock`; `blockchain/utxocache.go: flushNeededAfterPrune` |

utreexod keeps this whole layer: it still defaults to `ffldb`, still writes `spendjournal`
entries in `connectBlock`, and adds a `utreexostate` bucket plus a pebble-backed
`NodesBackEnd` (each accumulator node serialized as three 32-byte hashes and a 4-byte
add-index with a "remember" bit) for the accumulator (`utreexod config.go: defaultDbType`;
`blockchain/chain.go: connectBlock`; `blockchain/chainio.go: utreexoStateBucketName`;
`blockchain/utreexoio.go: serializeNode`). A node runs either `utxoCache` or `utreexoView`,
never both (`blockchain/chain.go: BlockChain` fields, comment).

### 2.5 Floresta

Floresta stores no blocks and no undo data. `get_block` is `unimplemented!("This chainstate
doesn't hold full blocks")`; `connect_block` consumes the block and its utreexo proof, updates
the accumulator and header state, and drops the block (`pruned_utreexo/chain_state.rs:
get_block`, `connect_block`). What it persists per block is the header with its state tag and
the post-block accumulator (section 3.7).

## 3. The block index and the header tree

### 3.1 Core in memory: `CBlockIndex`

| Field | Meaning | Source |
| --- | --- | --- |
| `phashBlock` | pointer to the key of this entry in `m_block_index` (an `unordered_map<uint256, CBlockIndex>`); entries are never removed while running | `chain.h: CBlockIndex`; `node/blockstorage.h: BlockMap` |
| `pprev`, `pskip` | parent, and a skip-list pointer to an ancestor chosen by `GetSkipHeight` so that `GetAncestor(h)` is `O(log n)` ("max 110 steps to go back up to 2**18 blocks") | `chain.cpp: GetSkipHeight`, `CBlockIndex::GetAncestor`, `BuildSkip` |
| `nHeight`, `nChainWork`, `nTimeMax` | height; cumulative `GetBlockProof`; running max of `nTime` | `node/blockstorage.cpp: AddToBlockIndex`, `LoadBlockIndex` |
| `nFile`, `nDataPos`, `nUndoPos` | flat-file locations, valid only when the corresponding `HAVE_*` bit is set | `chain.h: CBlockIndex::GetBlockPos`, `GetUndoPos` |
| `nTx`, `m_chain_tx_count` | transaction count of this block (set when the block's transactions were received, i.e. `VALID_TRANSACTIONS`); cumulative count from genesis or the snapshot base, `0` meaning "some ancestor's transactions were never received" (`HaveNumChainTxs`) | `chain.h: BlockStatus` (comment on `BLOCK_VALID_TRANSACTIONS`), `HaveNumChainTxs` |
| `nStatus` | validity level `VALID_TREE = 2` (headers), `VALID_TRANSACTIONS = 3`, `VALID_CHAIN = 4`, `VALID_SCRIPTS = 5` in the low 3 bits; `HAVE_DATA = 8`, `HAVE_UNDO = 16`, `FAILED_VALID = 32`, `FAILED_CHILD = 64` (now unused: descendants get `FAILED_VALID` directly), `OPT_WITNESS = 128`, `STATUS_RESERVED = 256` (former assumeutxo marker, unused) | `chain.h: BlockStatus` |
| `nSequenceId` | insertion order used as the tie-breaker among equal-work candidates; `SEQ_ID_INIT_FROM_DISK = 1` for loaded entries, `0` for the loaded active chain (so it wins), negative for `preciousblock` | `chain.h: SEQ_ID_*`; `node/blockstorage.cpp: CBlockIndexWorkComparator` |
| `IsValid(level)` | false if `FAILED_VALID`; else compares the low bits; `RaiseValidity` never lowers | `chain.h: CBlockIndex::IsValid`, `RaiseValidity` |

### 3.2 Core on disk: `blocks/index/`

| Element | Detail | Source |
| --- | --- | --- |
| Store | LevelDB at `<datadir>/blocks/index/` (not moved by `-blocksdir`), class `BlockTreeDB`, budget `min(dbcache/8, 2 MiB)`; obfuscation is not enabled for it at v31.1 (only the chainstate passes `obfuscate = true`): unverified beyond that grep | `doc/files.md`; `node/blockstorage.h: BlockTreeDB`; `validation.cpp: InitCoinsDB` |
| Index entry | key `'b' ‖ block hash`; value `CDiskBlockIndex`: `VARINT(259900)` (a dummy version), `VARINT(nHeight)`, `VARINT(nStatus)`, `VARINT(nTx)`, then `VARINT(nFile)` if `HAVE_DATA \| HAVE_UNDO`, `VARINT(nDataPos)` if `HAVE_DATA`, `VARINT(nUndoPos)` if `HAVE_UNDO`, then the raw 80-byte header fields (`nVersion`, `hashPrev`, `hashMerkleRoot`, `nTime`, `nBits`, `nNonce`) | `node/blockstorage.cpp: DB_BLOCK_INDEX`; `chain.h: CDiskBlockIndex` |
| Not stored | `nChainWork`, `m_chain_tx_count`, `nTimeMax`, `pskip`, `nSequenceId` are recomputed at load | `node/blockstorage.cpp: LoadBlockIndex` |
| Headers are persisted | `AddToBlockIndex` puts every accepted header into `m_dirty_blockindex`, so header-only entries (no `HAVE_DATA`, `nTx = 0`) reach disk at the next flush | `node/blockstorage.cpp: AddToBlockIndex` |
| Other keys | `'f' ‖ nFile` → `CBlockFileInfo`; `'l'` → last file; `'R'` → reindex in progress; `'F' ‖ name` → flags (`"prunedblockfiles"`, formerly `"txindex"`) | `node/blockstorage.cpp: DB_*`, `BlockTreeDB::WriteFlag`, `WriteReindexing` |
| Load of file info | `LoadBlockIndexDB` reads `'l'`, then `'f'` for every file up to it and beyond it until a miss, opens every `blk` file that some `HAVE_DATA` entry references (failing startup if one is missing), and seeds the two write cursors from each file's `nHeightLast`; `"prunedblockfiles"` and `'R'` are read last | `node/blockstorage.cpp: BlockManager::LoadBlockIndexDB` |
| Reindex flag | `'R'` is written when the index is wiped (`-reindex`), which also sets `m_blockfiles_indexed = false`; `ImportBlocks` then rescans every `blkNNNNN.dat` that exists on disk, in order; with `-prune` the `rev` files and any non-contiguous `blk` files are deleted first | `node/blockstorage.cpp: BlockManager::BlockManager`, `ImportBlocks`, `CleanupBlockRevFiles`, `BlockTreeDB::WriteReindexing` |
| Write | `WriteBatchSync` writes dirty file infos, last file, and dirty index entries in one batch with `sync = true` | `node/blockstorage.cpp: BlockTreeDB::WriteBatchSync`, `BlockManager::WriteBlockIndexDB` |

### 3.3 Load, candidates, and best-chain selection

| Step | Detail | Source |
| --- | --- | --- |
| `LoadBlockIndexGuts` | cursor from `('b', 0)`; each row creates (or finds) the entry by its computed hash, links `pprev` by `hashPrev` (creating a placeholder if unseen), copies the disk fields, and re-checks the header PoW | `node/blockstorage.cpp: BlockTreeDB::LoadBlockIndexGuts` |
| `LoadBlockIndex` | sorts by height; refuses a gap ("block index is non-contiguous"); recomputes `nChainWork`, `nTimeMax`, `m_chain_tx_count` (or inserts into `m_blocks_unlinked` when the parent's is unknown), converts stale `FAILED_CHILD` into `FAILED_VALID`, propagates `FAILED_VALID` to children, builds `pskip`; sets `m_chain_tx_count` of the snapshot base from chainparams | `node/blockstorage.cpp: BlockManager::LoadBlockIndex` |
| `ReceivedBlockTransactions` | on receipt of a block's transactions: `nTx = vtx.size()`, `nFile/nDataPos`, `nUndoPos = 0`, `HAVE_DATA`, `OPT_WITNESS` if segwit is active, `RaiseValidity(VALID_TRANSACTIONS)`, mark dirty; if the parent has chain-tx data, assign `m_chain_tx_count` and a fresh `nSequenceId`, offer the block to every chainstate's candidate set, and repeat for descendants waiting in `m_blocks_unlinked`; otherwise park the block in `m_blocks_unlinked` under its parent | `validation.cpp: ChainstateManager::ReceivedBlockTransactions` |
| `m_blocks_unlinked` | `multimap<parent, child>` of blocks with data whose parent has no data yet; drained by `ReceivedBlockTransactions` when the parent's data arrives | `node/blockstorage.h: m_blocks_unlinked`; `validation.cpp: ReceivedBlockTransactions` |
| `m_best_header`, `m_best_invalid` | the most-work `VALID_TREE` header (compared with `CBlockIndexWorkComparator`) and the most-work `FAILED_VALID` block, both derived at load | `validation.cpp: ChainstateManager::LoadBlockIndex` |
| `setBlockIndexCandidates` | "all CBlockIndex entries that have as much work as our current tip or more, and transaction data needed to be validated"; may include failed or pruned entries; ordered by `CBlockIndexWorkComparator` (work, then `nSequenceId`, then pointer) | `validation.h: setBlockIndexCandidates`; `node/blockstorage.cpp: CBlockIndexWorkComparator` |
| Adding candidates | `TryAddBlockIndexCandidate` inserts only entries not below the tip, and only ancestors of the target block for a historical chainstate | `validation.cpp: Chainstate::TryAddBlockIndexCandidate` |
| `FindMostWorkChain` | takes the best candidate, walks back to the active chain; if it meets `FAILED_VALID` it marks the whole path failed (and `m_best_invalid`), if it meets missing data it moves the path into `m_blocks_unlinked`; either way the candidates are erased and the loop retries | `validation.cpp: Chainstate::FindMostWorkChain` |
| `ActivateBestChainStep` | `pindexFork = m_chain.FindFork(most_work)`; disconnect the tip until it equals the fork; then connect in batches of 32 blocks toward the target, stopping early as soon as the tip has more work than the old tip; `PruneBlockIndexCandidates` after every connect removes candidates worse than the tip but never the tip itself ("we may need to return to it later in case a reorganization to a better block fails") | `validation.cpp: Chainstate::ActivateBestChainStep`, `PruneBlockIndexCandidates` |
| `CChain` | `vector<CBlockIndex*>` indexed by height; `SetTip` rewrites the vector down to the first entry that already matches; `Contains` is `vChain[h] == p`; `FindFork` walks `pprev` from the other tip's ancestor at `Height()` until `Contains` | `chain.h: CChain`; `chain.cpp: CChain::SetTip`, `FindFork` |
| Fork of two arbitrary tips | `LastCommonAncestor` equalizes heights with `GetAncestor` then jumps by `pskip` while the skips agree, relying on equal-height blocks having equal-height skips | `chain.cpp: LastCommonAncestor` |
| Locator | `LocatorEntries`: hashes walking back with step 1 for the first 10 entries then doubling, via `GetAncestor`, always ending at genesis; `have.reserve(32)` | `chain.cpp: LocatorEntries`, `GetLocator` |
| `InvalidateBlock` | disconnects to below the block, marks it and its descendants `FAILED_VALID` (dirty), erases them from the candidates, re-adds every `VALID_TRANSACTIONS` entry with chain-tx data that is not worse than the tip; there is no `m_failed_blocks` set at v31.1 (the name does not occur in `src/`; it existed through 0.18 per its release notes) | `validation.cpp: Chainstate::InvalidateBlock`; `release-notes-0.18.0.md` |

### 3.4 Invariants `CheckBlockIndex` asserts

Run with `-checkblockindex` (default on regtest), it rebuilds forward pointers for the whole
tree and depth-first walks it (`validation.cpp: ChainstateManager::CheckBlockIndex`). The
asserted invariants, in its own words where short:

- `forward.size() + best_hdr_chain.Height() + 1 == m_block_index.size()`; genesis hash matches.
- If never pruned, `HAVE_DATA ⇔ nTx > 0`; if pruned, `HAVE_DATA ⇒ nTx > 0`.
- `HAVE_UNDO ⇒ HAVE_DATA`. `VALID_TRANSACTIONS ⇔ nTx > 0` ("pruning-independent").
- `HaveNumChainTxs()` ⇔ no ancestor (back to genesis or the snapshot base) lacks
  `VALID_TRANSACTIONS`.
- `nHeight` consistent; `nChainWork >= pprev->nChainWork`; `pskip` points back for
  height ≥ 2.
- Every entry is at least `VALID_TREE`; `TREE`/`CHAIN`/`SCRIPTS` valid implies all parents are.
- `FAILED_VALID` is set on a block iff it or an ancestor is invalid.
- `m_chain_tx_count == nTx + pprev->m_chain_tx_count` when both are known; otherwise it is
  non-zero only for the snapshot base.
- No block has more work than `m_best_header` unless it is `FAILED_VALID`.
- A block not worse than the tip with all ancestors' data is in `setBlockIndexCandidates`;
  a block worse than the tip, or with a never-received ancestor, is not.
- A block with data whose parent never had data, and no invalid parent, is in
  `m_blocks_unlinked`.

### 3.5 Crash windows and the write ordering that covers them

| Window | What is on disk | Recovery | Source |
| --- | --- | --- | --- |
| Block written, index not yet | `blk*` has the record; `blocks/index` does not know the position | the record is orphaned space; a `-reindex` rescans files (`ImportBlocks` reads every `blk` file); nothing else refers to it | `validation.cpp: AcceptBlock`; `node/blockstorage.cpp: ImportBlocks` |
| Block connected, chainstate flushed, index not yet | cannot happen in that order: each `FlushStateToDisk` writes block files, then the index (sync), then the coins; `ConnectTip` only flushes the one-block view into the in-memory cache | none needed | `validation.cpp: FlushStateToDisk`, `ConnectTip` |
| Index written, chainstate not yet | index says `VALID_SCRIPTS` + `HAVE_UNDO` for blocks the on-disk coins do not include; `'B'` still names the older tip | `LoadChainTip` starts from `'B'`; the newer blocks are simply candidates and get reconnected from `blk*` | `validation.cpp: LoadChainTip`, `FindMostWorkChain` |
| Crash during the coins batch | `'B'` absent, `'H' = [new, old]`, coins partly new | `ReplayBlocks` (section 1.3) | `validation.cpp: ReplayBlocks` |
| Undo written, index not flushed | `rev*` has a record the index does not point at (`nUndoPos` lost) | the block is re-connected and `WriteBlockUndo` writes a fresh record (`GetUndoPos().IsNull()`); the old bytes are dead space unless the file was truncated at finalize | `node/blockstorage.cpp: WriteBlockUndo` |
| Preallocated tail | files carry zero-filled chunk padding until finalized | `FlatFileSeq::Flush(finalize)` truncates; readers never look past index positions | `flatfile.cpp: FlatFileSeq::Allocate`, `Flush` |

### 3.6 btcd

| Element | Detail | Source |
| --- | --- | --- |
| In memory | `blockIndex` map of `*blockNode` with `parent`, `height`, `workSum`, header fields and a `blockStatus` byte: `statusDataStored = 1`, `statusValid = 2`, `statusValidateFailed = 4`, `statusInvalidAncestor = 8`, `statusHeaderStored = 16` | `blockchain/blockindex.go: blockStatus` |
| Header tree on disk | bucket `blockheaderidx`, key = `height (u32 big-endian) ‖ hash`, value = `80-byte header ‖ status byte`; big-endian height so a cursor yields headers in height order; header-only nodes are skipped at flush "for backwards compatibility" (they are re-derived on load) | `blockchain/chainio.go: blockIndexKey`, `dbStoreBlockNode`; `blockchain/blockindex.go: flushToDB` |
| Main-chain maps | bucket `hashidx` (hash → u32 height) and `heightidx` (u32 height → hash), rewritten on every connect/disconnect | `blockchain/chainio.go` ("The block index consists of two buckets"), `dbPutBlockIndex`, `dbRemoveBlockIndex` |
| Best state | metadata key `chainstate` (section 1.4); at load, all headers are read in height order and the ancestors of the stored tip are upgraded to `statusValid` "as all the block before the current tip are valid by definition" | `blockchain/chainio.go: initChainState` |
| Reorg | `reorganizeChain(detach, attach)`: validate the whole path on a scratch view first; disconnect each block (loading its spend journal into the view), then connect the new blocks through the cache; "If we suddenly crash here, we are able to recover as well" because the consistency marker was written by the forced flush on disconnect | `blockchain/chain.go: reorganizeChain`, `disconnectBlock` |

### 3.7 Floresta

| Element | Detail | Source |
| --- | --- | --- |
| Header states | `DiskBlockHeader` = tag byte ‖ 80-byte header ‖ optional u32 height: `0x00 FullyValid(h)`, `0x01 Orphan`, `0x02 HeadersOnly(h)`, `0x03 InFork(h)`, `0x04 InvalidChain`, `0x05 AssumedValid(h)` | `pruned_utreexo/chainstore.rs: DiskBlockHeader`, `Encodable` impl |
| Best chain | `BestChain{best_block, depth, validation_index, alternative_tips}`; `validation_index` is the last block whose transactions were validated, distinct from the most-work header tip; saved by `flush` | `chainstore.rs: BestChain`; `chain_state.rs: flush` |
| `FlatChainStore` (the only store at `c0457dc`; no `KvChainStore` remains) | five files under the datadir: `headers.bin` (mmap, one `HashedDiskHeader` per main-chain height, so `pos(h) = h * size_of`), `fork_headers.bin` (same records for fork blocks), `blocks_index.bin` (open-addressing hash map, hash → u32 height, 4 bytes per bucket, sized so the load factor stays low), `accumulators.bin` (append-only roots per block, located by `acc_pos/acc_len` in the header record), `metadata.bin` (`Metadata`: magic `"flst"`, version 1, the `BestChain` fields with `alternative_tips: [BlockHash; 64]`, file sizes, index occupancy/capacity, and a checksum for corruption detection) | `pruned_utreexo/flat_chain_store.rs` (module comment), `FlatChainStore`, `Metadata`, `HashedDiskHeader`, `FLAT_CHAINSTORE_MAGIC` |
| Record size | `HashedDiskHeader` = `DiskBlockHeader` + hash + `acc_pos: u32` + `acc_len: u32`; the module comment budgets 124 bytes per record and 310 MiB for 2.5 M headers | same |
| Kernel | `bitcoinkernel` is used only for script verification (section 1.5); headers, best chain and the accumulator are Floresta's own | `pruned_utreexo/consensus.rs`; `partial_chain.rs` |

## 4. Sizes today

| Quantity | Value | As of | Source |
| --- | --- | --- | --- |
| `m_assumed_blockchain_size` (mainnet) | 856 GB ("minimum free space needed for data directory") | v31.1 | `kernel/chainparams.cpp: CMainParams`; `kernel/chainparams.h` |
| `m_assumed_chain_state_size` (mainnet) | 14 GB | v31.1 | same |
| Same for testnet3 / testnet4 / signet | 245 / 19, 31 / 2, 24 / 4 GB | v31.1 | `kernel/chainparams.cpp` |
| Highest mainnet assumeutxo entry | height 935,000, block `0000...f0fb5ee`, `hash_serialized_3 = e4b90ef9...6025050`, `m_chain_tx_count = 1,305,397,408` | v31.1 | `kernel/chainparams.cpp: CMainParams::m_assumeutxo_data` |
| Coins in that snapshot | `txouts = 164,241,311`, `disk_size = 13,290,295,029` bytes, `transactions = 113,879,165`, `bogosize = 12,870,854,130`, `total_amount = 19,984,148.03206779` (author's `gettxoutsetinfo` output in the PR that added the entry; not in `src/`) | 2026-02 | GitHub PR #34677 |
| Snapshot header | `"utxo\xff" ‖ u16 version 2 ‖ 4-byte network magic ‖ base block hash ‖ u64 coins_count`, followed by the coins | v31.1 | `node/utxo_snapshot.h: SnapshotMetadata`, `SNAPSHOT_MAGIC_BYTES` |
| `chainTxData` | 1,315,805,869 transactions at block `...ba5ac` (height 938,343), `nTime 1772055173` | v31.1 | `kernel/chainparams.cpp: CMainParams::chainTxData` |
| Chainstate on disk, more recent | "12GB" after IBD to 952,425 with compaction, "15GB" without; "~10.6 GB" after a manual full compaction (contributor measurements in the compaction PR) | 2026-06-05 | GitHub PR #35465 (andrewtoth) |
| UTXO count, independent | 173,190,861 coins, "11 GB on disk", at height 892,385 | 2025-04-14 | research.mempool.space, "UTXO Set Report" (2025-05-18) |
| Current UTXO count | no figure later than PR #34677 (164.2 M at 935,000) was found from a first-party source; unverified for September 2026 | — | — |
| Chain height and blocks total | height 966,055; `blockchain_size = 767,204,310,480` bytes (Blockchair's own accounting of block bytes, not a `blocks/` directory measurement) | 2026-09-08 | `api.blockchair.com/bitcoin/stats` |
| `rev*.dat` total | no primary or first-party figure found; unverified | — | — |
| `blocks/index/` size | no primary or first-party figure found; unverified. The on-disk entry is at most ~100 bytes (80-byte header plus a handful of varints), so ~1 M entries is on the order of 100 MB before LevelDB overhead | — | derived from `chain.h: CDiskBlockIndex` |
| Contrib tooling | `contrib/utxo-tools/utxo_to_sqlite.py` converts a snapshot to SQLite; there is no `contrib/assumeutxo/` directory at v31.1 | v31.1 | repository tree |

## 5. What the archival node must be able to answer

Access pattern abbreviations: R = random, S = sequential; r = read, w = write. "IBD" and
"steady" say how often the question is asked during initial block download and while
following the tip. The last column names the Core structure that answers it today.

| Question | Pattern | IBD | Steady | Core structure today | Source |
| --- | --- | --- | --- | --- | --- |
| Give me block by hash (serve `getdata`, RPC, reorg, reindex) | R r; S w on receipt | every block written once; rarely read back except at connect (`ConnectTip` reads from disk unless the block was just received) | reads from peers' requests, roughly recent blocks | `m_block_index` → `nFile/nDataPos` → `blk*.dat` | `validation.cpp: ConnectTip`; `node/blockstorage.cpp: ReadBlock` |
| Give me the undo record for block N | S w at connect; R r on disconnect | written per connected block; never read | read only on reorg, replay, or `-reindex-chainstate` | `nUndoPos` → `rev*.dat` | `node/blockstorage.cpp: WriteBlockUndo`, `ReadBlockUndo` |
| Is this outpoint unspent, and what does it hold | R r, very hot | thousands per block, mostly recent coins | same, lower rate | `CCoinsViewCache` over `chainstate/` (`'C'` key) | `coins.cpp: FetchCoin`; `txdb.cpp: GetCoin` |
| Spend and create the outpoints of a block, atomically | R w, batched | every block | every block | in-memory cache marks DIRTY/FRESH; durability by `BatchWrite` with `'H'` marker | `coins.cpp: SpendCoin`, `AddCoin`; `txdb.cpp: BatchWrite` |
| Undo a block's outpoint changes | R w | never | reorgs only | `DisconnectBlock` + `CBlockUndo` | `validation.cpp: DisconnectBlock` |
| What is the best validated block (chainstate tip) | point r | constantly | constantly | `m_chain.Tip()`, persisted as `'B'` | `validation.cpp: LoadChainTip`; `txdb.cpp: GetBestBlock` |
| What is the best header (most work, TREE-valid) | point r | constantly during headers sync | per header | `m_best_header` | `validation.cpp: ChainstateManager::LoadBlockIndex` |
| Which headers do I have, and what is each one's status | R r/w by hash; S r at load | every header written; whole index read at start | per header/block | `m_block_index` + `nStatus`, persisted as `'b'` rows | `node/blockstorage.cpp: LoadBlockIndexGuts`, `AddToBlockIndex` |
| Which blocks do I still lack (download scheduling) | walk from tip along the best header chain | constantly | after a gap | `nStatus & HAVE_DATA` along `m_best_header` ancestry; `m_blocks_unlinked` for out-of-order arrivals | `validation.cpp: FindMostWorkChain`; `node/blockstorage.h: m_blocks_unlinked` |
| Which candidates could become the tip | ordered set r/w | per block | per block | `setBlockIndexCandidates` | `validation.h: setBlockIndexCandidates` |
| Find the fork point between two tips | pointer walk, `O(log n)` | rare | per reorg | `CChain::FindFork`, `LastCommonAncestor` via `pskip` | `chain.cpp: FindFork`, `LastCommonAncestor` |
| Which block locator to send a peer | ~32 ancestor lookups | per `getheaders` | per `getheaders` | `GetLocator` over `pskip` | `chain.cpp: LocatorEntries` |
| Block at height h on the active chain | array index | per block | per RPC/`getblocks` | `CChain::operator[]` | `chain.h: CChain` |
| Where does the next block/undo record go, how full is each file | point r/w | per block | per block | `m_blockfile_info`, `m_blockfile_cursors`, persisted as `'f'`/`'l'` | `node/blockstorage.cpp: FindNextBlockPos` |
| Have I flushed consistently; where to resume after a crash | point r at start | at start | at start | `'B'` / `'H'`, `ReplayBlocks` | `validation.cpp: ReplayBlocks` |
| UTXO-set hash accumulator state (muhash) | point r/w | per block if maintained incrementally | per block | not a validation structure; `CoinStatsIndex` keeps a per-block `MuHash3072` in `indexes/coinstatsindex/` when `-coinstatsindex` is on; otherwise `gettxoutsetinfo` scans the cursor | `index/coinstatsindex.cpp` (unverified beyond the file name; see `docs/differential-testing.md` §2) |
| Is the whole index consistent | full-tree walk | debug only | debug only | `CheckBlockIndex` | `validation.cpp: CheckBlockIndex` |

## 6. Observations (not decisions)

These are things the sources above make apparent; none of them chooses a design.

1. Both full-node implementations separate "bytes that are only ever appended and read by
   position" (blocks, undo) from "keyed state that is rewritten" (coins, index). Core uses
   flat files plus LevelDB; btcd uses flat files plus LevelDB buckets in one database.
2. Every layout stores the same coin tuple: `(height, coinbase, amount, script)`, and every
   undo record stores the same tuple again per spent input. The chainstate hash formats in
   `docs/differential-testing.md` §2 are built from the same tuple.
3. Undo data is a by-product of connecting a block, which is why both Core and btcd write it
   at connect time in validation order, not in download order.
4. Crash safety in both nodes rests on one marker written in the same batch as the coin
   writes (`'H'`/`'B'` in Core, `utxostateconsistency` in btcd) plus the ability to re-apply
   blocks from disk idempotently. Neither node journals the coin writes themselves.
5. Core's index is written before the coins in each flush, and the index may legitimately be
   ahead of the coins after a crash; Core's load path tolerates that, but not the reverse.
6. The block index is small (about 1 M entries) and is loaded whole at start in both nodes;
   its persisted form omits everything that can be recomputed by one height-ordered pass.
7. Floresta's layout answers the questions of a pruned utreexo client (header status, best
   chain, accumulator per height) and none of the block-serving or outpoint-lookup rows in
   section 5; utreexod keeps btcd's full layout beside the accumulator rather than replacing
   it.
8. The one figure an implementer will most want and that this document could not source for
   September 2026 is the live UTXO count; the latest first-party number is 164.2 M coins at
   height 935,000 (PR #34677), with 12-15 GB on disk at 952,425 (PR #35465).

## References

- Bitcoin Core v31.1 sources — https://github.com/bitcoin/bitcoin/tree/v31.1/src
- Bitcoin Core `doc/files.md` at v31.1 — https://github.com/bitcoin/bitcoin/blob/v31.1/doc/files.md
- Bitcoin Core `doc/release-notes/release-notes-28.0.md` (blocksdir XOR) —
  https://github.com/bitcoin/bitcoin/blob/v31.1/doc/release-notes/release-notes-28.0.md
- Bitcoin Core `doc/release-notes/release-notes-31.0.md` (dbcache default, #34692) —
  https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-31.0.md
- Bitcoin Core PR #34677 "kernel: Chainparams and headerssync updates pre-31.0" (assumeutxo
  935,000 entry and its `gettxoutsetinfo` output) — https://github.com/bitcoin/bitcoin/pull/34677
- Bitcoin Core PR #35465 "coins: compact chainstate regularly" —
  https://github.com/bitcoin/bitcoin/pull/35465
- btcd `master` at `05585e03` —
  https://github.com/btcsuite/btcd/tree/05585e037ba0690572208dbc46d121a49cc0c4c9
  (`blockchain/chainio.go`, `blockchain/utxocache.go`, `blockchain/chain.go`,
  `blockchain/blockindex.go`, `blockchain/compress.go`, `database/ffldb/{db,blockio}.go`)
- utreexod at `22c9737e` — https://github.com/utreexo/utreexod (read on disk)
- Floresta at `c0457dc` — https://github.com/getfloresta/floresta (read on disk;
  `crates/floresta-chain/src/pruned_utreexo/{chainstore,flat_chain_store,chain_state}.rs`)
- mempool research, "UTXO Set Report" (2025-05-18) — https://research.mempool.space/utxo-set-report/
- Blockchair stats API (2026-09-08) — https://api.blockchair.com/bitcoin/stats
- `docs/consensus-rules.md` §7 and `docs/differential-testing.md` §2 in this repository.
