# The minimum p2p surface for headers-first IBD and for serving blocks

- Core tag read: `v31.1` (commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`, "Merge
  bitcoin/bitcoin#35666: [31.x] Finalise 31.1", 2026-07-06), full checkout on disk, read-only.
  The installed `bitcoind --version` reports `v31.1.0`.
- BIP texts read from `github.com/bitcoin/bips` `master` on the same date: 31, 35, 37, 61, 111,
  130, 133, 144, 152, 155, 157, 158, 159, 324, 330, 339.
- The `bitcoin` Rust crate read at the version this repository pins, `0.32.102`, from the local
  cargo registry (`src/p2p/`, `src/network.rs`, `src/consensus/encode.rs`).
- Scope: headers-first initial block download, block download, and serving blocks and headers to
  peers. Mempool and transaction relay are deliberately out of scope; the transaction-facing
  parts of Core are described only where a node without a mempool has to say something about
  them on the wire.
- Date: 2026-09-08.

How to read this document. Every claim carries a source. Core sources are written
`file: Symbol`, always relative to `src/` at tag `v31.1` (so `net_processing.cpp:
FindNextBlocksToDownload` means `src/net_processing.cpp`, that function); Core documentation is
cited by its path under the repository root (`doc/bips.md`). Crate items are written
`p2p/message.rs: NetworkMessage`, relative to `bitcoin-0.32.102/src/`. BIPs are written
`BIP155 §Specification`. Numeric constants are quoted with the symbol name Core gives them, and
with Core's own spelling of the value. Note that `src/version.h` no longer exists at v31.1: the
protocol version constants moved to `src/node/protocol_version.h`. Sections 1 to 6 are findings,
section 7 is the message inventory, section 8 lists observations and decides nothing. Where a
claim could not be confirmed from a primary source the sentence says so with the word
"unverified".

## 1. The handshake

### 1.1 Protocol versions

| Symbol | Value | Meaning | Source |
| --- | --- | --- | --- |
| `PROTOCOL_VERSION` | 70016 | version Core advertises in its own `version` message | `node/protocol_version.h`; `net_processing.cpp: PushNodeVersion` |
| `INIT_PROTO_VERSION` | 209 | "initial proto version, to be increased after version/verack negotiation" | `node/protocol_version.h` |
| `MIN_PEER_PROTO_VERSION` | 31800 | "disconnect from peers older than this proto version" | `node/protocol_version.h` |
| `BIP0031_VERSION` | 60000 | `pong` and the `ping` nonce are enabled for all versions AFTER this one | `node/protocol_version.h`; BIP31 §Specification |
| `SENDHEADERS_VERSION` | 70012 | `sendheaders` and header-based block announcement | `node/protocol_version.h`; BIP130 §Specification |
| `FEEFILTER_VERSION` | 70013 | `feefilter` | `node/protocol_version.h`; BIP133 §Specification |
| `SHORT_IDS_BLOCKS_VERSION` | 70014 | compact blocks (`sendcmpct`) | `node/protocol_version.h`; BIP152 §sendcmpct |
| `INVALID_CB_NO_BAN_VERSION` | 70015 | not banning for invalid compact blocks | `node/protocol_version.h` |
| `WTXID_RELAY_VERSION` | 70016 | `wtxidrelay`, and the gate Core also uses for `sendaddrv2` | `node/protocol_version.h`; BIP339 §Specification |

`CBlockLocator::DUMMY_VERSION` is hard-coded to 70016 and is documented as never used
(`primitives/block.h: CBlockLocator`).

### 1.2 Ordering rules Core enforces

| Situation | What Core does | Source |
| --- | --- | --- |
| Any message before `version` | logged and ignored, connection kept (`"non-version message before version handshake"`) | `net_processing.cpp: ProcessMessage` |
| Second `version` | logged and ignored (`"redundant version message"`), connection kept | `net_processing.cpp: ProcessMessage` |
| `nVersion < MIN_PEER_PROTO_VERSION` | disconnect | `net_processing.cpp: ProcessMessage` |
| Peer lacks desired services on an outbound (`ExpectServicesFromConn()` is true for OUTBOUND_FULL_RELAY, BLOCK_RELAY, ADDR_FETCH) | disconnect | `net.h: CNode::ExpectServicesFromConn`; `net_processing.cpp: ProcessMessage` |
| Inbound whose `nNonce` matches one of ours | disconnect ("connected to self") | `net_processing.cpp: ProcessMessage`; `net.cpp: CConnman::CheckIncomingNonce` |
| Second `verack` | logged and ignored | `net_processing.cpp: ProcessMessage` |
| Any non-negotiation message between `version` and `verack` | logged and ignored (`"Unsupported message ... prior to verack"`) | `net_processing.cpp: ProcessMessage` |
| `wtxidrelay`, `sendaddrv2` or `sendtxrcncl` after `verack` | disconnect | `net_processing.cpp: ProcessMessage`; BIP339 §Specification; BIP155 §Specification; BIP330 §sendtxrcncl |
| `sendheaders` or `sendcmpct` at any time | accepted, no timing rule | `net_processing.cpp: ProcessMessage` |
| Unknown message type | logged and ignored, "for extensibility" | `net_processing.cpp: ProcessMessage` |

Who speaks first: for an outbound connection Core sends `version` from its own send loop
(`net_processing.cpp: SendMessages`, guarded by `Peer::m_outbound_version_message_sent`); for an
inbound connection Core waits for the peer's `version` and replies with its own
(`net_processing.cpp: ProcessMessage`, `PushNodeVersion`).

Timeouts. `DEFAULT_PEER_CONNECT_TIMEOUT = 60` seconds (`-peertimeout`): if nothing was sent or
received in that window the peer is dropped, and once that window has passed a connection that
still has `fSuccessfullyConnected == false` is dropped as a "version handshake timeout"
(`net.h: DEFAULT_PEER_CONNECT_TIMEOUT`; `net.cpp: CConnman::InactivityCheck`,
`ShouldRunInactivityChecks`). After the handshake, `TIMEOUT_INTERVAL{20}` minutes of no send or
no receive is a disconnect (`net.h: TIMEOUT_INTERVAL`; `net.cpp: CConnman::InactivityCheck`).

### 1.3 Messages Core sends during the handshake, in order

On receiving `version` (all in `net_processing.cpp: ProcessMessage`):
`wtxidrelay` if the greatest common version is at least `WTXID_RELAY_VERSION`; `sendaddrv2` if
the greatest common version is at least 70016 (Core's comment: BIP155 defines the messages for
all versions, but "some implementations reject messages they don't know", so it is withheld from
older peers); `sendtxrcncl` only when `-txreconciliation` is on, which it is not by default
(`net_processing.h: DEFAULT_TXRECONCILIATION_ENABLE{false}`); then `verack`.

On receiving `verack`: `sendcmpct` with `high_bandwidth=false` and
`version=CMPCTBLOCKS_VERSION{2}`, if the common version is at least
`SHORT_IDS_BLOCKS_VERSION`, sent even to non-`NODE_NETWORK` peers "because they may wish to
request compact blocks from us" (`net_processing.cpp: ProcessMessage`).

`sendheaders` is not part of the handshake in Core v31.1. It is sent later from
`net_processing.cpp: MaybeSendSendHeaders`, and only once `state.pindexBestKnownBlock` exists and
has more work than `MinimumChainWork()`, because "receiving headers announcements for new blocks
while trying to sync their headers chain is problematic".

Also on receiving `version`, for outbound peers only, Core sends `getaddr` once and grants the
peer an extra `MAX_ADDR_TO_SEND` addr-processing tokens (`net_processing.cpp: ProcessMessage`,
`Peer::m_getaddr_sent`).

### 1.4 Service bits

`GetDesirableServiceFlags(services)` returns `NODE_NETWORK | NODE_WITNESS`, except that a peer
already advertising `NODE_NETWORK_LIMITED` is acceptable as
`NODE_NETWORK_LIMITED | NODE_WITNESS` when `ApproximateBestBlockDepth() <
NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS` (144). `HasAllDesirableServiceFlags` is
`!(GetDesirableServiceFlags(services) & ~services)`
(`net_processing.cpp: PeerManagerImpl::GetDesirableServiceFlags`, `HasAllDesirableServiceFlags`;
`net_processing.cpp: NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS`).

An unpruned Core node advertises `NODE_NETWORK_LIMITED | NODE_WITNESS` from the start and ORs in
`NODE_NETWORK` once it knows it can serve historical blocks; `NODE_P2P_V2` is added when
`-v2transport` is on (default true), `NODE_COMPACT_FILTERS` with `-peerblockfilters`, `NODE_BLOOM`
with `-peerbloomfilters` (`init.cpp: g_local_services`). So a full archival node's steady-state
flags are `NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED`, plus `NODE_P2P_V2` if it speaks
BIP324. BIP159 §Specification says the reverse is forbidden: a pruned peer must not set
`NODE_NETWORK`, but a full node may set both.

Per-peer predicates used during sync (all `net_processing.cpp`):

| Predicate | Definition | Source |
| --- | --- | --- |
| `CanServeBlocks(peer)` | `m_their_services & (NODE_NETWORK\|NODE_NETWORK_LIMITED)` | `net_processing.cpp: CanServeBlocks` |
| `IsLimitedPeer(peer)` | `NODE_NETWORK_LIMITED` set and `NODE_NETWORK` unset | `net_processing.cpp: IsLimitedPeer` |
| `CanServeWitnesses(peer)` | `m_their_services & NODE_WITNESS` | `net_processing.cpp: CanServeWitnesses` |
| `MayHaveUsefulAddressDB(services)` | `NODE_NETWORK` or `NODE_NETWORK_LIMITED`; used to accept feelers and to decide which gossiped addresses are worth storing | `protocol.h: MayHaveUsefulAddressDB`; `net_processing.cpp: ProcessMessage` (addr) |
| `SeedsServiceFlags()` | `NODE_NETWORK \| NODE_WITNESS`; the bits encoded into the `x<hex>.` DNS seed subdomain | `protocol.h: SeedsServiceFlags`; `net.cpp: ThreadDNSAddressSeed` |

`fPreferredDownload` is set at `version` time as `(!inbound || NoBan) && !addrfetch &&
CanServeBlocks(peer)` (`net_processing.cpp: ProcessMessage`). Witness data is required
transitively: `FindNextBlocks` returns early for a peer that cannot serve witnesses as soon as
the walk reaches a block at which segwit is active (`net_processing.cpp: FindNextBlocks`), so a
peer without `NODE_WITNESS` is useless for post-481824 mainnet block download.

### 1.5 `fRelay`, `feefilter` and a node with no mempool

The `version` message's trailing `fRelay` bool comes from BIP37. Core allocates its per-peer
`TxRelay` structure only if the connection is not block-relay-only, not a feeler, and either the
peer set `fRelay=true` or we offer `NODE_BLOOM` (`net_processing.cpp: ProcessMessage`). When the
structure is absent, Core never queues transaction `inv`s for that peer
(`net_processing.cpp: SendMessages`, `InitiateTxBroadcastToAll`) and answers no `getdata` for
transactions (`net_processing.cpp: ProcessGetData` returns early when `tx_relay == nullptr`).
Core itself sets `my_tx_relay = !RejectIncomingTxs(pnode)`, which is false for block-relay-only
and feeler connections and under `-blocksonly` (`net_processing.cpp: PushNodeVersion`,
`RejectIncomingTxs`).

Consequences for a node without a mempool: advertising `fRelay=0` is sufficient and is the
mechanism Core itself uses. Core will then also not offer us `sendtxrcncl` (it requires
`tx_relay->m_relay_txs`), and if we send `sendtxrcncl` anyway Core disconnects us
("sendtxrcncl received which indicated no tx relay to us"). BIP330 §sendtxrcncl says the same:
"Must not be sent if peer specified no support for transaction relay (fRelay=0)".

`feefilter` (BIP133) is the other polite refusal, and Core does send one with a filter of
`MAX_MONEY` while it is in IBD (`net_processing.cpp: MaybeSendFeefilter`). But Core's `feefilter`
handler stores the value inside `TxRelay`, which does not exist for a peer that sent `fRelay=0`
(`net_processing.cpp: ProcessMessage`), so sending `feefilter` after `fRelay=0` is a no-op on
Core's side. It is redundant, not harmful.

Sending us a transaction after we said `fRelay=0` is not something Core does; conversely, if a
peer sends transactions or transaction `inv`s to a Core node that declared no relay, Core
disconnects it ("transaction sent in violation of protocol", "inv sent in violation of
protocol"), which is the behaviour to mirror (`net_processing.cpp: ProcessMessage`).

### 1.6 Ping and pong

`PING_INTERVAL{2min}` between automatic pings; a ping is only sent when no ping is outstanding.
If a ping is outstanding for longer than `TIMEOUT_INTERVAL{20}` minutes the peer is disconnected
("ping timeout"). The nonce is a nonzero `rand64()`, and the `ping` carries it only when the
common version is greater than `BIP0031_VERSION`. On receiving `ping`, Core echoes the nonce back
as `pong` under the same version condition. Unsolicited pongs, nonce mismatches and short
payloads are logged, never punished. (`net_processing.cpp: PING_INTERVAL`, `MaybeSendPing`,
`ProcessMessage`; `net.h: TIMEOUT_INTERVAL`; BIP31 §Specification.)

## 2. Headers-first sync

### 2.1 `getheaders` and `headers`

`MAX_HEADERS_RESULTS = 2000`, and its comment is a protocol statement: "We rely on the assumption
that if a peer sends less than this number, we reached its tip. Changing this value is a protocol
upgrade." It is the default of the runtime option `max_headers_result`
(`net_processing.h: MAX_HEADERS_RESULTS`, `PeerManager::Options::max_headers_result`).

The locator is exponential: entries are the tip, then the ancestors at `height - step`, with
`step` doubling once more than 10 entries have been pushed, always terminating at genesis
(`chain.cpp: LocatorEntries`, `GetLocator`). The receiving side rejects a locator with more than
`MAX_LOCATOR_SZ = 101` entries by disconnecting (`net_processing.cpp: MAX_LOCATOR_SZ`,
`ProcessMessage`). A locator of 101 entries covers roughly 2^90 blocks, so the bound is never
binding for an honest peer.

Rate limit on our side: `MaybeSendGetHeaders` refuses to emit a new `getheaders` while one has
been outstanding for less than `HEADERS_RESPONSE_TIME{2min}`; the timestamp is cleared whenever a
connecting `headers` message arrives, including an empty one
(`net_processing.cpp: MaybeSendGetHeaders`, `ProcessHeadersMessage`).

### 2.2 Choosing the sync peer

Core keeps `nSyncStarted`, the number of peers with `CNodeState::fSyncStarted`. A new sync is
started only if `nSyncStarted == 0 && sync_blocks_and_headers_from_peer`, or if
`m_best_header->Time()` is within 24 hours of now, in which case any eligible peer may be added.
`sync_blocks_and_headers_from_peer` is true for a `fPreferredDownload` peer, and for an inbound
peer only when `m_num_preferred_download_peers == 0 || mapBlocksInFlight.empty()`. The initial
`getheaders` starts one block below `m_best_header` so that a synced peer cannot answer with an
empty `headers`. (`net_processing.cpp: SendMessages`.)

Timeout: `peer.m_headers_sync_timeout = now + HEADERS_DOWNLOAD_TIMEOUT_BASE{15min} +
HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER{1ms} * (seconds since m_best_header) / nPowTargetSpacing`.
The peer is disconnected on expiry only if it is our only sync peer and we have at least one
other preferred-download peer to try (`net_processing.cpp: SendMessages`,
`HEADERS_DOWNLOAD_TIMEOUT_BASE`, `HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER`).

### 2.3 Anti-DoS for low-work headers

`GetAntiDoSWorkThreshold()` is `max(tip->nChainWork - min(144 * GetBlockProof(tip),
tip->nChainWork), MinimumChainWork())`: the 144-block buffer lets near-tip forks through
(`net_processing.cpp: GetAntiDoSWorkThreshold`). `nMinimumChainWork` per chain is in
`kernel/chainparams.cpp: consensus.nMinimumChainWork` (mainnet
`0000000000000000000000000000000000000001128750f82f4c366153a3a030`; regtest and the default
signet are zero).

`ProcessHeadersMessage` runs, in order: `CheckHeadersPoW` (valid proof-of-work, then continuity;
either failure is `Misbehaving`), continuation of an existing presync, lookup of
`headers[0].hashPrevBlock`, and, if that lookup fails, `HandleUnconnectingHeaders`. Anti-DoS
checks are skipped when the last header is already an ancestor of `m_best_header` or of the tip
(`IsAncestorOfBestHeaderOrTip`) or when the peer has `NetPermissionFlags::NoBan`. Otherwise
`TryLowWorkHeadersSync` decides. (`net_processing.cpp: ProcessHeadersMessage`, `CheckHeadersPoW`,
`CheckHeadersAreContinuous`, `IsAncestorOfBestHeaderOrTip`.)

There is no `MAX_UNCONNECTING_HEADERS_MSGS` in v31.1 and no `Misbehaving` for unconnecting
headers: `HandleUnconnectingHeaders` now only sends a `getheaders` from `m_best_header` and calls
`UpdateBlockAvailability` with the last header's hash, so that the peer can later be used to
download those blocks (`net_processing.cpp: HandleUnconnectingHeaders`). `Misbehaving` itself no
longer carries a score; one call sets `Peer::m_should_discourage` and the next
`MaybeDiscourageAndDisconnect` disconnects and discourages, unless the peer has NoBan, is a
manual connection, or is local (`net_processing.cpp: Misbehaving`,
`MaybeDiscourageAndDisconnect`).

### 2.4 Headers presync (the download-twice mechanism)

`HeadersSyncState` (`headerssync.h`, `headerssync.cpp`) has three states: `PRESYNC`,
`REDOWNLOAD`, `FINAL`. It is created by `TryLowWorkHeadersSync` only when the claimed work of the
received chain is below the threshold AND the `headers` message was full, that is exactly
`max_headers_result` entries; a short low-work message is simply ignored
(`net_processing.cpp: TryLowWorkHeadersSync`).

- PRESYNC: each header is checked for continuity and for `PermittedDifficultyTransition`; work is
  accumulated; at every height `h` with `h % commitment_period == m_commit_offset` one bit,
  `m_hasher(hash) & 1`, is pushed into a `bitdeque`. `m_commit_offset` is
  `FastRandomContext().randrange(commitment_period)`, so an attacker cannot know which heights
  are committed. (`headerssync.cpp: ValidateAndProcessSingleHeader`, `HeadersSyncState`
  constructor.)
- `m_max_commitments = 6 * max_seconds_since_start / commitment_period`, where
  `max_seconds_since_start` is the time from the fork point's median-time-past to now plus
  `MAX_FUTURE_BLOCK_TIME`; 6 blocks per second is the fastest rate the MTP rule allows. Exceeding
  it aborts the sync. (`headerssync.cpp: HeadersSyncState::HeadersSyncState`,
  `ValidateAndProcessSingleHeader`.)
- Once accumulated work reaches `m_minimum_required_work`, the state flips to REDOWNLOAD and the
  peer is asked for the same headers again from the fork point.
- REDOWNLOAD: headers are re-received, difficulty transitions re-checked, and at every committed
  height the stored bit must match. Headers leave the buffer into the block index only once more
  than `redownload_buffer_size` are queued, or once the target work has been reached.
  (`headerssync.cpp: ValidateAndStoreRedownloadedHeader`, `PopHeadersReadyForAcceptance`.)

The parameters live in the chain params, generated by `headerssync-params.py` on 2026-02-25
(`kernel/chainparams.h: HeadersSyncParams`; `kernel/chainparams.cpp`):

| Chain | `commitment_period` | `redownload_buffer_size` | commitments buffered |
| --- | --- | --- | --- |
| main | 641 | 15218 | ~23.7 |
| testnet3 | 606 | 16092 | ~26.6 |
| testnet4 | 620 | 15724 | ~25.4 |
| signet | 673 | 14460 | ~21.5 |
| regtest | 275 | 7017 | ~25.5 (copied from testnet4) |

`sizeof(CompressedHeader) == 48` is a static assertion, because the memory analysis behind those
numbers assumes it (`headerssync.cpp`).

Answer to the specific question: presync is purely a local defence of the syncing node. The
locator it emits is an ordinary `CBlockLocator` (the last received or last redownloaded hash,
followed by the normal exponential locator from the fork point), and the only wire effect on the
serving side is that the same range of `getheaders` requests arrives twice
(`headerssync.cpp: NextHeadersRequestLocator`). A peer being synced from observes nothing but
repeated `getheaders`/`headers` round trips, and must serve the second pass identically to the
first: `ValidateAndStoreRedownloadedHeader` aborts the sync on any commitment mismatch. A node
that only serves headers, and a node that syncs from honest peers, need implement no part of
presync; a node that wants Core's memory bound during its own IBD does.

### 2.5 Following the tip

Announcement of new blocks is by `headers` when the peer sent `sendheaders`, by `cmpctblock` when
the peer requested high-bandwidth mode, and by `inv` otherwise. Core falls back to `inv` when the
peer prefers neither, when more than `MAX_BLOCKS_TO_ANNOUNCE = 8` blocks are queued, when a
queued block is no longer on the active chain, or when the queued blocks do not connect to each
other. The `inv` fallback announces only the tip. (`net_processing.cpp: SendMessages`,
`MAX_BLOCKS_TO_ANNOUNCE`.)

On receiving a block `inv` for something unknown, Core sends a `getheaders` from `m_best_header`
rather than a `getdata`, with a guard that at most one new peer per new block is added to headers
sync before sync has started (`Peer::m_inv_triggered_getheaders_before_sync`,
`m_last_block_inv_triggering_headers_sync`) (`net_processing.cpp: ProcessMessage`).

`getblocks` is answered but never sent by Core v31.1: the only reference outside the handler is
the BIP324 short-message table (`net_processing.cpp: ProcessMessage`; `net.cpp:
V2_MESSAGE_IDS`). Its reply is at most 500 block hashes in an `inv`, with a continuation hash so
the peer asks again (`net_processing.cpp: ProcessMessage`). Legacy `getblocks`-driven sync is not
needed to reach the tip today.

## 3. Block download

### 3.1 The bounds

| Symbol | Value | Meaning | Source |
| --- | --- | --- | --- |
| `MAX_BLOCKS_IN_TRANSIT_PER_PEER` | 16 | blocks requestable at once from one peer | `net_processing.cpp` |
| `BLOCK_DOWNLOAD_WINDOW` | 1024 | how far past `pindexLastCommonBlock` we will fetch | `net_processing.cpp` |
| `BLOCK_DOWNLOAD_TIMEOUT_BASE` | 1 | in multiples of `nPowTargetSpacing` (10 min) | `net_processing.cpp` |
| `BLOCK_DOWNLOAD_TIMEOUT_PER_PEER` | 0.5 | extra multiple per other peer we are downloading from | `net_processing.cpp` |
| `BLOCK_STALLING_TIMEOUT_DEFAULT` | 2s | stalling window, adaptive | `net_processing.cpp` |
| `BLOCK_STALLING_TIMEOUT_MAX` | 64s | cap on the adaptive stalling window | `net_processing.cpp` |
| `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK` | 3 | the only path by which one block is in flight from several peers | `net_processing.h` |
| `MAX_CMPCTBLOCK_DEPTH` | 5 | serve `cmpctblock` only this close to the tip | `net_processing.cpp` |
| `MAX_BLOCKTXN_DEPTH` | 10 | answer `getblocktxn` only this close to the tip | `net_processing.cpp` |
| `MAX_PROTOCOL_MESSAGE_LENGTH` | `4 * 1000 * 1000` | "no message over 4 MB is currently acceptable" | `net.h` |
| `MAX_SIZE` | `0x02000000` | serialization vector limit, also checked on the header | `serialize.h`; `net.cpp: V1Transport::readHeader` |
| `DEFAULT_MAXRECEIVEBUFFER` | `5 * 1000` | kB, times 1000 in `init.cpp`, so 5 MB of queued received messages | `net.h`; `init.cpp` |
| `DEFAULT_MAXSENDBUFFER` | `1 * 1000` | kB, times 1000, so 1 MB of queued outgoing bytes | `net.h`; `init.cpp` |

`fPauseRecv` is set whenever the per-peer processing queue exceeds `m_recv_flood_size`, and
cleared as messages are polled; `fPauseSend` when queued send memory exceeds
`nSendBufferMaxSize` (`net.cpp: CNode::AddReceivedMessage`, `CNode::PollMessage`,
`CConnman::PushMessage`). `ProcessGetData` stops as soon as `fPauseSend` is set, and processes at
most one block item per call (`net_processing.cpp: ProcessGetData`).

### 3.2 Selection

`FindNextBlocksToDownload` returns early if the peer's best known block is null, has less work
than our tip, or has less work than `MinimumChainWork()`. It then sets `pindexLastCommonBlock` to
the fork point between the peer's best known block and our tip (unless an existing value has more
work and is still an ancestor of the peer's best block), and walks forward with
`nWindowEnd = pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW`
(`net_processing.cpp: FindNextBlocksToDownload`).

`FindNextBlocks` walks in batches of at least 128 ancestors, skipping blocks we already have and
blocks already in flight, and stops when `count` blocks have been collected. It bails out
entirely on a block that fails `IsValid(BLOCK_VALID_TREE)` and on the first segwit-active block
when the peer cannot serve witnesses. For a limited peer it skips blocks deeper than
`NODE_NETWORK_LIMITED_MIN_BLOCKS - 2` below the peer's tip. When it reaches the end of the window
having collected nothing, and the first in-flight block it saw belongs to another peer, that peer
is recorded as `nodeStaller` (`net_processing.cpp: FindNextBlocks`).

### 3.3 Stalling and timeouts

Stalling means exactly this: the download window cannot move because the block at its left edge
is in flight from someone else, and we could fetch more "if the window were 1 larger". Core marks
that peer with `m_stalling_since` only when our own in-flight list for the requesting peer is
empty, and disconnects it once `m_stalling_since` is older than the current stalling timeout. On
each such disconnect the shared timeout doubles, capped at `BLOCK_STALLING_TIMEOUT_MAX`, "so that
we don't disconnect multiple peers if our own bandwidth is insufficient"; it decays by a factor
of 0.85 per connected block back to `BLOCK_STALLING_TIMEOUT_DEFAULT`
(`net_processing.cpp: SendMessages`, `PeerManagerImpl::BlockConnected`,
`m_block_stalling_timeout`).

Separately, if the oldest block in flight from a peer has been in flight for longer than
`nPowTargetSpacing * (BLOCK_DOWNLOAD_TIMEOUT_BASE + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER *
nOtherPeersWithValidatedDownloads)`, the peer is disconnected ("Timeout downloading block"). Only
validated in-flight blocks are counted, "so peers can't advertise non-existing block hashes to
unreasonably increase our timeout" (`net_processing.cpp: SendMessages`).

### 3.4 Who is asked

The `getdata` block loop runs only when `CanServeBlocks(peer)` and
`(sync_blocks_and_headers_from_peer && !IsLimitedPeer(peer)) || !IsInitialBlockDownload()` and
`vBlocksInFlight.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER` (`net_processing.cpp: SendMessages`).
During IBD that restricts requests to preferred-download peers, which are outbound or NoBan; an
inbound peer is only used when there are no preferred-download peers at all, or nothing is in
flight anywhere (section 2.2). Out of IBD, Core downloads from every peer that can serve blocks.

Each requested inventory is `MSG_BLOCK | GetFetchFlags(peer)`, and `GetFetchFlags` adds
`MSG_WITNESS_FLAG` when the peer has `NODE_WITNESS`, giving `MSG_WITNESS_BLOCK = MSG_BLOCK |
(1 << 30) = 0x40000002` (`net_processing.cpp: GetFetchFlags`; `protocol.h: MSG_WITNESS_FLAG`,
`GetDataMsg`; BIP144 §Relay).

Duplicate requests: `BlockRequested` inserts into the multimap `mapBlocksInFlight` and
`Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK)`. Plain block
download never asks two peers for the same block, because `FindNextBlocks` skips anything already
in flight; only the compact-block path allows up to 3
(`net_processing.cpp: BlockRequested`, `RemoveBlockRequest`, `ProcessMessage` for `cmpctblock`).

Stale tip: every `STALE_CHECK_INTERVAL{10min}` Core checks `TipMayBeStale()` (no tip update for
`3 * nPowTargetSpacing` and nothing in flight) and, if stale, sets `SetTryNewOutboundPeer(true)`,
allowing one extra full-relay outbound above the normal maximum. Extra peers are pruned every
`EXTRA_PEER_CHECK_INTERVAL{45s}` and an eviction candidate must have been connected for
`MINIMUM_CONNECT_TIME{30s}`. (`net_processing.cpp: CheckForStaleTipAndEvictPeers`,
`TipMayBeStale`, `EvictExtraOutboundPeers`.)

`nMaxOutboundLimit` comes from `-maxuploadtarget`, `DEFAULT_MAX_UPLOAD_TARGET{"0M"}`, that is
unlimited by default, measured over `MAX_UPLOAD_TIMEFRAME{60 * 60 * 24}` seconds
(`net.h: DEFAULT_MAX_UPLOAD_TARGET`; `net.cpp: MAX_UPLOAD_TIMEFRAME`,
`CConnman::OutboundTargetReached`).

### 3.5 What a bounded scheduler must track

Per peer: an ordered in-flight list bounded at 16 entries, the time the current batch started
(`m_downloading_since`, reset to now whenever the head of the list is received), a stalling-since
timestamp, the peer's best known block, and the last common block. Globally: a multimap from
block hash to (peer, iterator) with at most 3 entries per hash, a count of peers currently
downloading, and one shared adaptive stalling timeout in [2s, 64s]. The download window is 1024
blocks ahead of the last common block; the walk batch is at least 128 headers. All of these are
in `net_processing.cpp: CNodeState`, `QueuedBlock`, `BlockDownloadMap mapBlocksInFlight`,
`m_peers_downloading_from`, `m_block_stalling_timeout`.

## 4. What it takes to serve

### 4.1 Must answer

`getheaders` (`net_processing.cpp: ProcessMessage`). Disconnect if the locator exceeds
`MAX_LOCATOR_SZ`. Ignore while reindexing. If our own tip has less work than
`MinimumChainWork()`, reply with an empty `headers` rather than nothing, "to tell the peer to go
away but not treat us as unresponsive". With a null locator, look up `hashStop` directly and
apply `BlockRequestAllowed`. Otherwise find the fork point with `FindForkInGlobalIndex` and walk
forward, sending at most `max_headers_result` headers, stopping early at `hashStop`. Headers are
serialized as `CBlock` so that each carries the trailing `0x00` transaction count. An unknown
locator degrades to the genesis block, which is always in every locator, so the walk always has a
starting point.

`getdata` for `MSG_BLOCK` / `MSG_WITNESS_BLOCK` (`net_processing.cpp: ProcessGetBlockData`). The
refusals, in the order Core applies them: unknown hash, `BlockRequestAllowed` false, outbound
target reached for a block older than `HISTORICAL_BLOCK_AGE = 7 * 24 * 60 * 60` seconds
(disconnect), `NODE_NETWORK_LIMITED` set without `NODE_NETWORK` and depth greater than
`NODE_NETWORK_LIMITED_MIN_BLOCKS = 288` plus a 2-block race buffer (disconnect), block data not
on disk. `BlockRequestAllowed` allows any block on the active chain, and off-chain blocks only if
fully validated and within `STALE_RELAY_AGE_LIMIT = 30 * 24 * 60 * 60` seconds of the best header
by both timestamp and equivalent-work time (`net_processing.cpp: BlockRequestAllowed`,
`STALE_RELAY_AGE_LIMIT`, `HISTORICAL_BLOCK_AGE`, `NODE_NETWORK_LIMITED_MIN_BLOCKS`;
`validation.h: MIN_BLOCKS_TO_KEEP = 288`). For `MSG_WITNESS_BLOCK` Core takes a fast path and
copies raw bytes from disk, because "the network format matches the format on disk"
(`net_processing.cpp: ProcessGetBlockData`; `node/blockstorage.cpp: BlockManager::ReadRawBlock`).

`getdata` size: more than `MAX_INV_SZ = 50000` entries is `Misbehaving`. `MAX_GETDATA_SZ = 1000`
is explicitly a send-side batching limit, "Not used in processing incoming GETDATA for
compatibility" (`net_processing.cpp: MAX_INV_SZ`, `MAX_GETDATA_SZ`, `ProcessMessage`).

`ping` must be answered with `pong` echoing the nonce (section 1.6). A peer that does not is
disconnected after 20 minutes.

`getaddr`: answered only on inbound connections, and only once per connection
(`Peer::m_getaddr_recvd`), with up to `MAX_ADDR_TO_SEND{1000}` addresses capped at
`MAX_PCT_ADDR_TO_SEND{23}` percent of the addrman (`net_processing.cpp: ProcessMessage`).

`addr` / `addrv2`: accepted, rate limited (section 5.3). `notfound`: parsed, used only to cancel
transaction requests (`net_processing.cpp: ProcessMessage`).

### 4.2 May be ignored or refused

| Message | Core v31.1 behaviour | Source |
| --- | --- | --- |
| `tx`, transaction `inv` | disconnect if we declared no tx relay; otherwise mempool logic | `net_processing.cpp: ProcessMessage`, `RejectIncomingTxs` |
| `mempool` | disconnect unless we advertise `NODE_BLOOM` or the peer has the Mempool permission | `net_processing.cpp: ProcessMessage`; BIP35 §Specification; BIP111 §Specification |
| `filterload`, `filteradd`, `filterclear` | disconnect if `NODE_BLOOM` is not in our own offered services | `net_processing.cpp: ProcessMessage` |
| `getcfilters`, `getcfheaders`, `getcfcheckpt` | disconnect if `NODE_COMPACT_FILTERS` is not offered. BIP157 only says a node "SHOULD NOT respond"; Core is stricter | `net_processing.cpp: PrepareBlockFilterRequest`; BIP157 §getcfilters |
| `sendcmpct` | recorded; a version other than 2 is ignored outright | `net_processing.cpp: ProcessMessage`, `CMPCTBLOCKS_VERSION{2}` |
| `cmpctblock`, `getblocktxn`, `blocktxn` | full BIP152 machinery, but never entered if we never send `sendcmpct`: BIP152 forbids requesting `MSG_CMPCT_BLOCK` from a peer that has not sent one | BIP152 §sendcmpct, §MSG_CMPCT_BLOCK; `net_processing.cpp: ProcessMessage` |
| `merkleblock` | only produced for `MSG_FILTERED_BLOCK` when a bloom filter is loaded | `net_processing.cpp: ProcessGetBlockData` |
| unknown command | logged and ignored | `net_processing.cpp: ProcessMessage` |
| `reject` | does not exist in v31.1: not in `NetMsgType`, removed in v0.20.0 (PR #15437) | `protocol.h: ALL_NET_MESSAGE_TYPES`; `doc/bips.md` (BIP 61 row); `doc/release-notes/release-notes-0.20.0.md` |

A syncing bitcoind never requires compact blocks from us. If we never send `sendcmpct`, it will
not request `MSG_CMPCT_BLOCK` from us (BIP152 §sendcmpct, rule 7), and its own low-bandwidth
`sendcmpct(0, 2)` to us is a statement about what it is willing to serve, which we may ignore.

### 4.3 What Core does to a slow or wrong peer

Block download timeout and stalling disconnect (section 3.3). `notfound` for a block is not
special-cased: only transaction inventories are extracted
(`net_processing.cpp: ProcessMessage`). An unrequested block is still processed if it has enough
claimed work (`min_pow_checked` is set when `prev_block->nChainWork + GetBlockProof(block) >=
GetAntiDoSWorkThreshold()`), but `forceProcessing` is only true for a block we requested
(`net_processing.cpp: ProcessMessage`). A mutated block is `Misbehaving`, which in v31.1 means
immediate discourage and disconnect (`net_processing.cpp: ProcessMessage`, `IsBlockMutated`,
`Misbehaving`). Invalid headers and blocks go through `MaybePunishNodeForBlock`
(`net_processing.cpp: MaybePunishNodeForBlock`). An outbound peer whose best known block never
reaches our tip's work within `CHAIN_SYNC_TIMEOUT{20min}` plus one `HEADERS_RESPONSE_TIME{2min}`
grace `getheaders` is disconnected, unless it is among the
`MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT = 4` protected peers
(`net_processing.cpp: ConsiderEviction`).

### 4.4 What a syncing bitcoind needs from us as the inbound side

It needs, at minimum: our `version` with `NODE_NETWORK | NODE_WITNESS`
(`HasAllDesirableServiceFlags` is only enforced on its outbound side, but the flags also gate
`CanServeBlocks` and
`CanServeWitnesses` in every direction), our `verack`, answers to `getheaders`, answers to
`getdata` for `MSG_WITNESS_BLOCK`, and `pong` for its `ping`
(`net_processing.cpp: ProcessMessage`, `CanServeBlocks`, `CanServeWitnesses`, `MaybeSendPing`).

It does not need `addr` from us: address relay is set up lazily, `getaddr` is only sent on its
outbound connections, and no code path punishes a peer for silence on addresses
(`net_processing.cpp: SetupAddressRelay`, `ProcessMessage` for `getaddr`). It does not need
`sendheaders` from us either; `sendheaders` is what we send to ask the peer to announce with
headers, and Core sends it on its own schedule (`net_processing.cpp: MaybeSendSendHeaders`).
Announcing new blocks to it by plain `inv` is sufficient and is the path Core itself falls back
to (section 2.5). It does not need `sendcmpct` from us (section 4.2). It will not accept
`wtxidrelay`, `sendaddrv2` or `sendtxrcncl` after our `verack`, so those either go between
`version` and `verack` or not at all (section 1.2).

## 5. Peer discovery

### 5.1 Seeds

DNS seeds per chain (`kernel/chainparams.cpp: vSeeds`):

| Chain | Seeds | Source |
| --- | --- | --- |
| main | `seed.bitcoin.sipa.be.`, `dnsseed.bluematt.me.`, `seed.bitcoin.jonasschnelli.ch.`, `seed.btc.petertodd.net.`, `seed.bitcoin.sprovoost.nl.`, `dnsseed.emzy.de.`, `seed.bitcoin.wiz.biz.`, `seed.mainnet.achownodes.xyz.` | `kernel/chainparams.cpp: CMainParams` |
| testnet3 | `testnet-seed.bitcoin.jonasschnelli.ch.`, `seed.tbtc.petertodd.net.`, `seed.testnet.bitcoin.sprovoost.nl.`, `testnet-seed.bluematt.me.`, `seed.testnet.achownodes.xyz.` | `kernel/chainparams.cpp: CTestNetParams` |
| testnet4 | `seed.testnet4.bitcoin.sprovoost.nl.`, `seed.testnet4.wiz.biz.` | `kernel/chainparams.cpp: CTestNet4Params` |
| signet (default challenge only) | `seed.signet.bitcoin.sprovoost.nl.`, `seed.signet.achownodes.xyz.` | `kernel/chainparams.cpp: SigNetParams` |
| regtest | `vSeeds.clear()` then the single placeholder `dummySeed.invalid.` | `kernel/chainparams.cpp: CRegTestParams` |

Default ports and magic: main 8333 / `f9beb4d9`, testnet3 18333 / `0b110907`, testnet4 48333 /
`1c163f28`, regtest 18444 (`nDefaultPort` at `kernel/chainparams.cpp: CRegTestParams`) /
`fabfb5da`, signet 38333 with the magic derived as the first 4 bytes of the hash of the challenge
(`kernel/chainparams.cpp: pchMessageStart`, `nDefaultPort`, `SigNetParams`).

The hardcoded fallback list is `src/chainparamsseeds.h`, "AUTOGENERATED by
contrib/seeds/generate-seeds.py", where "Each line contains a BIP155 serialized (networkID, addr,
port) tuple" (`chainparamsseeds.h`). Fixed seeds are only added after 60 seconds with an empty
addrman for at least one reachable network, or immediately if `-dnsseed=0` and neither `-addnode`
nor `-seednode` was given (`net.cpp: ThreadOpenConnections`).

`ThreadDNSAddressSeed` (`net.cpp`): if `-seednode` was given, wait up to a `SEEDNODE_TIMEOUT` of
30 seconds for `SEED_OUTBOUND_CONNECTION_THRESHOLD = 2` full outbound connections before touching
DNS. Query all seeds at once when `-forcednsseed` or when the addrman is empty; otherwise query
`DNSSEEDS_TO_QUERY_AT_ONCE = 3` at a time, waiting `DNSSEEDS_DELAY_FEW_PEERS{11}` seconds between
groups, or `DNSSEEDS_DELAY_MANY_PEERS{5}` minutes when the addrman holds at least
`DNSSEEDS_DELAY_PEER_THRESHOLD = 1000` addresses, waking early to check the outbound count. Each
seed is queried as `x<hex of SeedsServiceFlags()>.<seed>`, capped at `nMaxIPs = 32` results, and
each result is given a random age between 3 and 7 days (`net.cpp: ThreadDNSAddressSeed`).

### 5.2 Addrman

| Element | Value | Source |
| --- | --- | --- |
| new buckets | `ADDRMAN_NEW_BUCKET_COUNT{1 << 10}` = 1024 | `addrman_impl.h` |
| tried buckets | `ADDRMAN_TRIED_BUCKET_COUNT{1 << 8}` = 256 | `addrman_impl.h` |
| bucket size | `ADDRMAN_BUCKET_SIZE{1 << 6}` = 64 | `addrman_impl.h` |
| new buckets per source group | `ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP{64}` | `addrman.cpp` |
| tried buckets per netgroup | `ADDRMAN_TRIED_BUCKETS_PER_GROUP{8}` | `addrman.cpp` |
| new buckets an address may occupy | `ADDRMAN_NEW_BUCKETS_PER_ADDRESS{8}` | `addrman.cpp` |
| terrible-entry rules | `ADDRMAN_HORIZON{30 * 24h}`, `ADDRMAN_RETRIES{3}`, `ADDRMAN_MAX_FAILURES{10}`, `ADDRMAN_MIN_FAIL{7 * 24h}`, `ADDRMAN_REPLACEMENT{4h}` | `addrman.cpp: AddrInfo::IsTerrible` |
| tried collision set | `ADDRMAN_SET_TRIED_COLLISION_SIZE{10}`, `ADDRMAN_TEST_WINDOW{40min}` | `addrman.cpp` |
| on-disk file | `peers.dat`, `Format::V4_MULTIPORT` | `addrman_impl.h: AddrManImpl::FILE_FORMAT` |

Bucketing is keyed by a secret `nKey`: the tried bucket is
`H(nKey, netgroup(addr), H(nKey, addr.key) % 8) % 256`, the new bucket is
`H(nKey, netgroup(src), H(nKey, netgroup(addr), netgroup(src)) % 64) % 1024`, and the position
inside a bucket is `H(nKey, 'N' or 'K', bucket, addr.key) % 64`
(`addrman.cpp: AddrInfo::GetTriedBucket`, `GetNewBucket`, `GetBucketPosition`).

### 5.3 Address relay bounds

`MAX_ADDR_TO_SEND{1000}` per `addr` message, and more than that from a peer is `Misbehaving`
(BIP155 §Specification says the same: "One message can contain up to 1,000 addresses. Clients
SHOULD reject messages with more addresses"). Incoming addresses are shuffled and metered by a
token bucket that refills at `MAX_ADDR_RATE_PER_SECOND{0.1}` per second up to
`MAX_ADDR_PROCESSING_TOKEN_BUCKET{MAX_ADDR_TO_SEND}`, with a one-off top-up of
`MAX_ADDR_TO_SEND` after we send `getaddr`. An address with a timestamp older than 100000000
seconds or more than 10 minutes in the future is rewritten to 5 days ago. Only addresses under 10
minutes old, in messages of at most 10 entries, and only when we did not just send `getaddr`, are
gossiped onward, to a small deterministic set of peers rotated every
`ROTATE_ADDR_RELAY_DEST_INTERVAL{24h}`. Outgoing `addr` is sent on an exponential schedule with
mean `AVG_ADDRESS_BROADCAST_INTERVAL{30s}`, and our own address is re-announced with mean
`AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL{24h}` via `Peer::m_next_local_addr_send`, never during IBD.
(`net_processing.cpp: MAX_ADDR_TO_SEND`, `MAX_ADDR_RATE_PER_SECOND`,
`MAX_ADDR_PROCESSING_TOKEN_BUCKET`, `ProcessMessage` for `addr`, `RelayAddress`, `MaybeSendAddr`.)

### 5.4 Connection slots and eclipse defences

| Symbol | Value | Source |
| --- | --- | --- |
| `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS` | 8 | `net.h` |
| `MAX_BLOCK_RELAY_ONLY_CONNECTIONS` | 2 | `net.h` |
| `MAX_FEELER_CONNECTIONS` | 1, on a `FEELER_INTERVAL` of 2 minutes | `net.h` |
| `MAX_ADDNODE_CONNECTIONS` | 8 | `net.h` |
| `DEFAULT_MAX_PEER_CONNECTIONS` | 125 | `net.h` |
| inbound slots | `m_max_inbound = max(0, m_max_automatic_connections - (full_relay + block_relay + feeler))`, so 114 at the default | `net.h: CConnman::Init` |
| anchors | `MAX_BLOCK_RELAY_ONLY_ANCHORS = 2`, persisted in `anchors.dat`, tried first and highest priority on restart | `net.cpp: MAX_BLOCK_RELAY_ONLY_ANCHORS`, `ANCHORS_DATABASE_FILENAME`, `ThreadOpenConnections` |

Diversity rules in `net.cpp: ThreadOpenConnections`: non-feeler IPv4/IPv6 outbound connections
must be in distinct netgroups (`m_netgroupman.GetGroup`, ASMap-aware); at most 100 addrman
candidates are tried per pass; addresses tried within the last 10 minutes are skipped for the
first 30 attempts; bad ports (`doc/p2p-bad-ports.md`) are skipped for the first 50; non-feelers
must satisfy `HasAllDesirableServiceFlags`, feelers only `MayHaveUsefulAddressDB`; one extra
outbound per reachable network is opened on an `EXTRA_NETWORK_PEER_INTERVAL` schedule.

Inbound eviction (`node/eviction.cpp: SelectNodeToEvict`) protects, in order, NoBan peers,
outbound peers, 4 peers by keyed netgroup, 8 by lowest minimum ping, 4 by most recent novel
transaction, 8 non-tx-relay peers by most recent novel block, 4 by most recent novel block, then
`ProtectEvictionCandidatesByRatio` protects half the remainder by longest uptime, reserving up to
half of those protected slots for CJDNS, I2P, localhost and onion peers.

Minimum that keeps a fresh node connected without being trivially eclipsed, in Core's numbers: 8
full-relay outbound plus 2 block-relay-only, all in distinct netgroups; 2 block-relay-only
anchors persisted across restarts; 1 feeler every 2 minutes to test-before-evict addrman
collisions; a secret-keyed addrman with the 1024/256/64 bucket geometry so that a single source
group can only reach 64 new buckets; and DNS seeds queried 3 at a time only when the addrman
cannot supply 2 outbound connections.

## 6. Transport

### 6.1 v1 framing

`CMessageHeader` is 4 bytes of message start (magic), a 12-byte message type padded with zeros,
a 4-byte little-endian length and a 4-byte checksum, `HEADER_SIZE` in total
(`protocol.h: CMessageHeader`). On receive Core rejects a wrong magic, a size greater than
`MAX_SIZE` or `MAX_PROTOCOL_MESSAGE_LENGTH`, a checksum that is not the first 4 bytes of
double-SHA256 over the payload, and a message type containing bytes outside `[0x20, 0x7E]` or
non-zero bytes after the first zero. Payload buffers grow at most 256 KiB at a time.
(`net.cpp: V1Transport::readHeader`, `readData`, `GetReceivedMessage`;
`protocol.cpp: CMessageHeader::IsMessageTypeValid`.)

### 6.2 Is v1 alone enough today

Yes, on the evidence in the tree. `-v2transport` defaults to true
(`net.h: DEFAULT_V2_TRANSPORT{true}`) and has since v27.0 ("BIP324 v2 transport is now enabled by
default", `doc/release-notes/release-notes-27.0.md`), but:

- Inbound connections are accepted with a transport that auto-detects: "The V2Transport
  transparently falls back to V1 behavior when an incoming V1 connection is detected, so use it
  whenever we signal NODE_P2P_V2" (`net.cpp: CConnman::CreateNodeFromAcceptedSocket`). The
  detection is the BIP324 rule: a responder that sees the 16 bytes of magic followed by
  `version\x00\x00\x00\x00\x00` treats the connection as v1 (BIP324 §Specification;
  `net.cpp: V2Transport`, `V1_PREFIX_LEN{16}`).
- Outbound, Core only attempts v2 when both sides advertise `NODE_P2P_V2`
  (`addrConnect.nServices & GetLocalServices() & NODE_P2P_V2`,
  `net.cpp: ThreadOpenConnections`), and on failure it queues a reconnection with
  `use_v2transport = false` ("retrying with v1 transport protocol")
  (`net.cpp: CConnman::DisconnectNodes`, `V2Transport::ShouldReconnectV1`,
  `CConnman::PerformReconnections`).
- There is no deprecation of v1 anywhere in `src/` or `doc/` at v31.1; the only statement found
  is v26.0's "v1 transport protocol remains fully supported"
  (`doc/release-notes/release-notes-26.0.md`).

A v1-only node will therefore be dialled by Core over v1 (Core will not even try v2 unless we
advertise `NODE_P2P_V2`), and will be accepted inbound by Core. The cost of v1-only is a
narrower slice of the network for our own outbound connections, since some nodes may prefer or
require v2; that preference could not be quantified from a primary source, so it is unverified.

### 6.3 What the `bitcoin` crate 0.32.102 provides

| Item | State at 0.32.102 | Source |
| --- | --- | --- |
| Framing | `RawNetworkMessage` = magic, `CommandString` (12 bytes, trailing zeros trimmed on decode), `CheckedData` (length + 4-byte checksum + payload). The checksum IS verified on decode | `p2p/message.rs: RawNetworkMessage`, `CommandString`; `consensus/encode.rs: CheckedData` |
| Size limits | `MAX_MSG_SIZE = 5_000_000` applied by `consensus_decode` via `Read::take`; `MAX_VEC_SIZE = 4_000_000` for vectors. Neither matches Core's `MAX_PROTOCOL_MESSAGE_LENGTH = 4_000_000`, and `MAX_INV_SIZE = 50_000` is documented as "not currently enforced by this implementation" | `p2p/message.rs: MAX_MSG_SIZE`, `MAX_INV_SIZE`; `consensus/encode.rs: MAX_VEC_SIZE` |
| Unknown commands | decoded into `NetworkMessage::Unknown { command, payload }` rather than an error | `p2p/message.rs: NetworkMessage::Unknown` |
| Missing variants | no `sendtxrcncl`, `reqrecon`, `sketch`, `reqsketchext`, `reconcildiff`; these arrive as `Unknown`. Legacy `Alert` and `Reject` variants exist although Core removed `reject` | `p2p/message.rs: NetworkMessage` |
| Trailing bytes | a decoded payload with leftover bytes is an error ("extra bytes after network message payload") | `p2p/message.rs` |
| `headers` | `HeaderDeserializationWrapper` enforces the `0x00` transaction count after each header | `p2p/message.rs: HeaderDeserializationWrapper` |
| `Inventory` | has `Block`, `WitnessBlock`, `CompactBlock`, `Transaction`, `WitnessTransaction`, `WTx`, `Error`, and `Unknown { inv_type, hash }` | `p2p/message_blockdata.rs: Inventory` |
| `getheaders`/`getblocks` | `GetHeadersMessage { version, locator_hashes, stop_hash }`, constructed with the crate's own `PROTOCOL_VERSION` | `p2p/message_blockdata.rs: GetHeadersMessage`, `GetBlocksMessage` |
| `PROTOCOL_VERSION` | 70001 in the crate, against Core's 70016; a node using the crate's constant would be below every feature gate from `SENDHEADERS_VERSION` up | `p2p/mod.rs: PROTOCOL_VERSION`; `node/protocol_version.h` |
| `ServiceFlags` | `NONE`, `NETWORK`, `GETUTXO`, `BLOOM`, `WITNESS`, `COMPACT_FILTERS`, `NETWORK_LIMITED`, `P2P_V2` | `p2p/mod.rs: ServiceFlags` |
| `VersionMessage` | all nine fields including `relay` | `p2p/message_network.rs: VersionMessage` |
| Addresses | `Address { services, address: [u16; 8], port }`, `AddrV2` (with the 512-byte cap from BIP155 enforced), `AddrV2Message { time, services, addr, port }` | `p2p/address.rs` |
| `Magic` | `BITCOIN`, `TESTNET3`, `TESTNET4`, `SIGNET`, `REGTEST` constants matching Core's `pchMessageStart` | `p2p/mod.rs: Magic`; `kernel/chainparams.cpp` |
| BIP324 | absent. The only occurrence of "BIP324" in the crate is the doc comment on `ServiceFlags::P2P_V2` | `p2p/mod.rs` |

So the crate supplies v1 framing, the message enum and the wire types, and does not supply: the
v2 transport, Core's message-length bound, any inv or locator count enforcement, the current
protocol version constant, or the `sendtxrcncl` family. Those are what bitmigo would write
itself.

## 7. The minimum inventory

Every message type Core v31.1 knows, in the order of `protocol.h: ALL_NET_MESSAGE_TYPES`.
"Direction" is from bitmigo's point of view. The verdict column is a description of what the
surface in sections 1 to 6 requires, not a decision.

| Message | Direction | Verdict | Why | Source |
| --- | --- | --- | --- | --- |
| `version` | both | must SEND and ANSWER | no other message is processed before it | `net_processing.cpp: PushNodeVersion`, `ProcessMessage` |
| `verack` | both | must SEND and ANSWER | nothing but negotiation messages is processed before `fSuccessfullyConnected` | `net_processing.cpp: ProcessMessage` |
| `addr` | both | must ANSWER (parse and store); SEND on `getaddr` from an inbound peer | addrman needs feeding; a peer that never answers `getaddr` is not punished | `net_processing.cpp: ProcessMessage`, `MaybeSendAddr` |
| `addrv2` | both | may IGNORE unless we sent `sendaddrv2`; must ANSWER if we did | only sent to peers that signalled support | BIP155 §Specification; `net_processing.cpp: ProcessMessage` |
| `sendaddrv2` | both | may IGNORE (then peers use `addr`) | strictly an upgrade for Tor v3, I2P and CJDNS addresses | BIP155 §Specification |
| `inv` | both | must ANSWER for block invs; SEND for block announcement | the fallback announcement path, and how a lagging peer learns of a new tip | `net_processing.cpp: ProcessMessage`, `SendMessages` |
| `getdata` | both | must SEND (`MSG_WITNESS_BLOCK`) and must ANSWER (`MSG_BLOCK`, `MSG_WITNESS_BLOCK`) | the only way blocks move | `net_processing.cpp: SendMessages`, `ProcessGetBlockData` |
| `merkleblock` | send | never | BIP37 output, requires `NODE_BLOOM` | `net_processing.cpp: ProcessGetBlockData` |
| `getblocks` | both | may IGNORE | Core never sends it; only the handler exists | `net_processing.cpp: ProcessMessage` |
| `getheaders` | both | must SEND and must ANSWER | the whole of headers-first sync in both roles | `net_processing.cpp: MaybeSendGetHeaders`, `ProcessMessage` |
| `tx` | both | never | no mempool; Core disconnects a peer that sends tx after `fRelay=0` | `net_processing.cpp: RejectIncomingTxs` |
| `headers` | both | must SEND and must ANSWER | reply to `getheaders`; also the BIP130 announcement path | `net_processing.cpp: ProcessHeadersMessage`, `SendMessages` |
| `block` | both | must SEND and must ANSWER | reply to `getdata` in both roles | `net_processing.cpp: ProcessGetBlockData`, `ProcessMessage` |
| `getaddr` | both | must ANSWER (inbound only, once); SEND once per outbound | Core ignores `getaddr` from its outbound peers to resist fingerprinting | `net_processing.cpp: ProcessMessage` |
| `mempool` | recv | never (refuse) | BIP35, gated on `NODE_BLOOM`, which an archival node without a mempool cannot offer | BIP35 §Specification; BIP111 §Specification; `net_processing.cpp: ProcessMessage` |
| `ping` | both | must SEND and must ANSWER | 20-minute disconnect on an unanswered ping in both directions | `net_processing.cpp: MaybeSendPing`, `ProcessMessage` |
| `pong` | both | must SEND and must ANSWER | same | `net_processing.cpp: ProcessMessage` |
| `notfound` | both | may IGNORE on receive; SEND only for tx | Core extracts only transaction invs from it | `net_processing.cpp: ProcessMessage`, `ProcessGetData` |
| `filterload` | recv | never (refuse) | BIP37; Core disconnects when `NODE_BLOOM` is unset | BIP111 §Specification; `net_processing.cpp: ProcessMessage` |
| `filteradd` | recv | never (refuse) | same | `net_processing.cpp: ProcessMessage` |
| `filterclear` | recv | never (refuse) | same | `net_processing.cpp: ProcessMessage` |
| `sendheaders` | both | should SEND; may IGNORE on receive | sending it gets header announcements instead of inv round trips; ignoring it just means we announce by inv | BIP130 §Specification; `net_processing.cpp: MaybeSendSendHeaders`, `ProcessMessage` |
| `feefilter` | both | may IGNORE | redundant once `fRelay=0`: Core's handler needs a `TxRelay` that does not exist | BIP133 §Specification; `net_processing.cpp: ProcessMessage` |
| `sendcmpct` | both | may IGNORE | not sending it means no peer may request `MSG_CMPCT_BLOCK` from us | BIP152 §sendcmpct; `net_processing.cpp: ProcessMessage` |
| `cmpctblock` | both | never | only reachable if we send `sendcmpct` | BIP152 §MSG_CMPCT_BLOCK |
| `getblocktxn` | both | never | same | BIP152; `net_processing.cpp: ProcessMessage` |
| `blocktxn` | both | never | same | BIP152; `net_processing.cpp: ProcessMessage` |
| `getcfilters` | recv | never (refuse) | requires `NODE_COMPACT_FILTERS` and a filter index | BIP157 §getcfilters; `net_processing.cpp: PrepareBlockFilterRequest` |
| `cfilter` | send | never | same | BIP157 §cfilter |
| `getcfheaders` | recv | never (refuse) | same | BIP157 §getcfheaders |
| `cfheaders` | send | never | same | BIP157 §cfheaders |
| `getcfcheckpt` | recv | never (refuse) | same | BIP157 §getcfcheckpt |
| `cfcheckpt` | send | never | same | BIP157 §cfcheckpt |
| `wtxidrelay` | both | may IGNORE; never SEND | wtxid relay is a transaction-relay feature | BIP339 §Specification; `net_processing.cpp: ProcessMessage` |
| `sendtxrcncl` | both | never | forbidden after `fRelay=0`, and Core disconnects for it | BIP330 §sendtxrcncl; `net_processing.cpp: ProcessMessage` |

Not in `ALL_NET_MESSAGE_TYPES` and therefore unknown to Core v31.1: `reject` (BIP61, removed in
v0.20.0), `alert` (Core still emits one hardcoded final alert to peers with a common version at
or below 70012, but has no handler), and the Erlay data messages `reqrecon`, `sketch`,
`reqsketchext`, `reconcildiff` from BIP330 (`protocol.h: ALL_NET_MESSAGE_TYPES`;
`net_processing.cpp: ProcessMessage`; `doc/bips.md`).

## 8. Observations (not decisions)

These are things the sources above make apparent; none of them chooses a design.

1. The whole IBD surface is 10 message types: `version`, `verack`, `ping`, `pong`, `getheaders`,
   `headers`, `getdata`, `block`, `inv`, `addr`. Serving adds `getaddr` and, for politeness,
   `notfound`. Everything else in section 7 is either refused or ignored.
2. Two constants are protocol, not policy: `MAX_HEADERS_RESULTS = 2000` (its own comment says
   changing it is a protocol upgrade) and `MSG_WITNESS_BLOCK = 0x40000002`. Everything else in
   sections 2 and 3 is one node's local choice, which means differential testing against Core
   will not catch a divergence in them; only the behaviour they produce is observable.
3. `fRelay = 0` in `version` is the entire mechanism a mempool-less node needs. It suppresses
   transaction invs from Core, suppresses `sendtxrcncl`, makes `feefilter` a no-op, and makes
   `getdata` for transactions unanswerable. It also forecloses `sendtxrcncl`, so the BIP330
   message family can be left unimplemented rather than stubbed.
4. Presync is asymmetric: it costs the syncing node a second pass over the headers and a
   `bitdeque` of one bit per 641 headers, and costs the serving node a second identical
   `getheaders` walk. A serving node must therefore be deterministic over the same locator range,
   which is a constraint on how the header index answers `getheaders`, not on the network code.
5. Concurrency shape implied by section 3: one shared multimap of in-flight block hashes with a
   per-hash cap, one shared adaptive timeout, one shared "peers currently downloading" counter,
   and per-peer ordered queues. Core holds `cs_main` for all of the shared parts and processes
   one peer's messages at a time under `g_msgproc_mutex`. The blocking bound, 16 blocks per peer
   over 1024 blocks of window, means at most 64 peers can be usefully downloading at once during
   IBD before the window becomes the binding constraint.
6. Validation-pipeline shape implied by section 4: blocks arrive out of order within a 1024-block
   window but must be served back in a form byte-identical to what was received, since Core's own
   fast path for `MSG_WITNESS_BLOCK` reads raw bytes from disk without reserializing. Any storage
   layer that normalizes a block on write breaks that path.
7. Core disconnects rather than ignores in four places a peer will hit by accident: locator
   longer than 101 entries, `filter*` without `NODE_BLOOM`, `getcf*` without
   `NODE_COMPACT_FILTERS`, and negotiation messages after `verack`. Three of those are stricter
   than the corresponding BIP, which says only "SHOULD NOT respond" or "MUST be ignored".
8. `Misbehaving` in v31.1 has no score: every call is an immediate discourage. There is no
   partial credit, so anything that calls it is effectively a protocol violation, and the list of
   callers is short enough to enumerate as a test matrix.
9. The service bits an unpruned Core node sets are `NODE_NETWORK | NODE_WITNESS |
   NODE_NETWORK_LIMITED`, not just the first two. Advertising `NODE_NETWORK_LIMITED` as well is
   what makes a node acceptable to peers close to the tip that are looking for limited peers.
10. The crate at 0.32.102 gives correct v1 framing with checksum verification, but its
    `MAX_MSG_SIZE = 5_000_000` is larger than Core's `MAX_PROTOCOL_MESSAGE_LENGTH = 4_000_000`,
    and it enforces no inv or locator counts. Any bounded-queue discipline has to be imposed
    above the crate, not assumed from it.
11. `getblocks` is dead weight on the sending side (Core never emits it) but is still answered by
    Core; a node that never answers it is indistinguishable from Core in practice, but a node
    that never sends it is exactly Core.
12. What could not be verified from a primary source: the share of the reachable mainnet network
    that would refuse a v1-only inbound connection today. Core v31.1 accepts v1 inbound and falls
    back to v1 outbound, and no deprecation appears in its tree, but the behaviour of other
    implementations and of the wider network is unverified here.

## References

- Bitcoin Core v31.1 sources, at commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`:
  https://github.com/bitcoin/bitcoin/tree/9be056a8a72b624dae9623b2f7bded92c2a21c91/src
  (`net.cpp`, `net.h`, `net_processing.cpp`, `net_processing.h`, `protocol.h`, `protocol.cpp`,
  `headerssync.cpp`, `headerssync.h`, `addrman.cpp`, `addrman_impl.h`, `chain.cpp`,
  `node/protocol_version.h`, `node/eviction.cpp`, `kernel/chainparams.cpp`,
  `kernel/chainparams.h`, `chainparamsseeds.h`, `init.cpp`, `serialize.h`, `validation.h`,
  `primitives/block.h`)
- Bitcoin Core `doc/bips.md` at v31.1 (BIP 61 removal history):
  https://github.com/bitcoin/bitcoin/blob/v31.1/doc/bips.md
- Bitcoin Core `doc/p2p-bad-ports.md` at v31.1:
  https://github.com/bitcoin/bitcoin/blob/v31.1/doc/p2p-bad-ports.md
- Bitcoin Core `doc/release-notes/release-notes-0.20.0.md` (BIP61 reject removal, PR #15437)
- Bitcoin Core `doc/release-notes/release-notes-26.0.md` (BIP324 added, opt-in; "v1 transport
  protocol remains fully supported")
- Bitcoin Core `doc/release-notes/release-notes-27.0.md` (v2 transport on by default, PR #29347;
  v1 retry after a failed v2 attempt)
- [BIP31] Pong message: https://github.com/bitcoin/bips/blob/master/bip-0031.mediawiki
- [BIP35] mempool message: https://github.com/bitcoin/bips/blob/master/bip-0035.mediawiki
- [BIP37] Connection Bloom filtering:
  https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
- [BIP61] Reject P2P message: https://github.com/bitcoin/bips/blob/master/bip-0061.mediawiki
- [BIP111] NODE_BLOOM service bit: https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki
- [BIP130] sendheaders message: https://github.com/bitcoin/bips/blob/master/bip-0130.mediawiki
- [BIP133] feefilter message: https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki
- [BIP144] Segregated Witness (peer services):
  https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
- [BIP152] Compact Block Relay: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
- [BIP155] addrv2 message: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
- [BIP157] Client Side Block Filtering:
  https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
- [BIP158] Compact Block Filters for Light Clients:
  https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
- [BIP159] NODE_NETWORK_LIMITED service bit:
  https://github.com/bitcoin/bips/blob/master/bip-0159.mediawiki
- [BIP324] Version 2 P2P Encrypted Transport Protocol:
  https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
- [BIP330] Transaction announcements reconciliation:
  https://github.com/bitcoin/bips/blob/master/bip-0330.mediawiki
- [BIP339] WTXID-based transaction relay:
  https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki
- `bitcoin` Rust crate 0.32.102: https://docs.rs/bitcoin/0.32.102 (read from the local cargo
  registry: `src/p2p/{mod,message,message_network,message_blockdata,address,message_bloom,
  message_compact_blocks,message_filter}.rs`, `src/network.rs`, `src/consensus/encode.rs`)
- `docs/consensus-rules.md`, `docs/storage-layouts.md` and `docs/differential-testing.md` in this
  repository.
