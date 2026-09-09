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
