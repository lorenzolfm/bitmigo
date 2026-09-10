# Test data

## `regtest-headers.hex`

Two hundred and one headers of a regtest chain mined by the system **bitcoind v31.1.0**, from
genesis to height 200. One 80-byte header per line, hex, exactly as `getblockheader <hash>
false` returns it, in height order.

Regenerate with a throwaway datadir:

```sh
bitcoind -regtest -datadir=$DIR -daemon
CLI="bitcoin-cli -regtest -datadir=$DIR"
$CLI createwallet w
$CLI generatetoaddress 200 "$($CLI -rpcwallet=w getnewaddress)"
for h in $(seq 0 200); do $CLI getblockheader "$($CLI getblockhash $h)" false; done > regtest-headers.hex
```

Why 200: regtest's difficulty adjustment interval is 144 blocks
(`pow_target_timespan / pow_target_spacing` = one day over ten minutes), so a chain this long
crosses one period boundary. The header tree assembles each block's `Context` — median time
past over the last eleven timestamps, and the required `nBits` over the whole difficulty
period it walks — and `accept_header` refuses any header whose `nBits` is not exactly what
that walk produced. Every header on this chain going into the tree is therefore an agreement
with Core's own `GetNextWorkRequired` and `GetMedianTimePast`, at the boundary included.

## `regtest-blocks.hex`

A hundred and six whole blocks of a regtest chain mined by the system **bitcoind v31.1.0**,
from genesis to height 105, one block per line, hex, exactly as `getblock <hash> 0` returns
it, in height order.

Regenerate with a throwaway datadir:

```sh
bitcoind -regtest -datadir=$DIR -daemon -fallbackfee=0.0002
CLI="bitcoin-cli -regtest -datadir=$DIR -rpcwallet=w"
bitcoin-cli -regtest -datadir=$DIR createwallet w
L=$($CLI getnewaddress "" legacy); S=$($CLI getnewaddress "" p2sh-segwit)
W=$($CLI getnewaddress "" bech32); T=$($CLI getnewaddress "" bech32m)
$CLI generatetoaddress 101 "$L"
$CLI sendmany "" "{\"$L\":1,\"$S\":2,\"$W\":3,\"$T\":4}"; $CLI sendtoaddress "$L" 5
$CLI generatetoaddress 1 "$L"
$CLI sendmany "" "{\"$W\":1.5,\"$T\":2.5,\"$L\":0.5}"
$CLI sendtoaddress "$S" 6; $CLI sendtoaddress "$T" 7
$CLI generatetoaddress 1 "$L"
$CLI sendtoaddress "$W" 8
$CLI generatetoaddress 2 "$L"
N="bitcoin-cli -regtest -datadir=$DIR"
for h in $(seq 0 105); do $N getblock "$($N getblockhash $h)" 0; done > regtest-blocks.hex
```

Why a hundred and six, and why with spends: a coinbase matures after a hundred blocks, so a
regtest chain has to be that long before anything can be spent at all. Blocks 102, 103 and
104 then spend across the four standard output types — P2PKH, P2SH, P2WPKH and P2TR — which
is what makes the store's tests be about coins somebody else serialised. The coin encoder
round-trips every coin the chain creates, the undo record is built from the spends and paired
back with the inputs they came from, and the whole chain is written into a store, closed,
opened again and read back byte for byte.
