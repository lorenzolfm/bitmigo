# Vendored test vectors

Files copied verbatim from their upstream repositories. They are read by the unit tests of
`bitmigo-consensus` (`include_str!` from `src/script/vectors.rs`) and are never shipped in a
binary. Re-fetch them from the revision below before diffing; do not hand-edit.

| File | Upstream | Revision | Licence | SHA-256 |
| --- | --- | --- | --- | --- |
| `sighash.json` | `bitcoin/bitcoin`, `src/test/data/sighash.json` | tag `v31.1` | MIT | `52cf23c2076e7f129c71d5508631d3e5ae3be1b1cb0585c0e23bbb4bb373e924` |
| `bip340-test-vectors.csv` | `bitcoin/bips`, `bip-0340/test-vectors.csv` | `09e21036a4001fe6c9ba65c1d3a39b737768132f` (2026-09-03) | BSD-2-Clause OR MIT OR CC0-1.0 (BIP340 `License-Code`) | `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` |
| `bip341-wallet-test-vectors.json` | `bitcoin/bips`, `bip-0341/wallet-test-vectors.json` | `09e21036a4001fe6c9ba65c1d3a39b737768132f` (2026-09-03) | BSD-3-Clause (BIP341 `License`) | `403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f` |

## Bitcoin Core (`sighash.json`)

`src/test/data/README.md` in Bitcoin Core states that the data files in that directory are
distributed under the MIT software license, see the accompanying file `COPYING`
(`docs/differential-testing.md` §1.2). That licence:

```
Copyright (c) 2009-2025 The Bitcoin Core developers
Copyright (c) 2009-2025 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## BIPs (`bip340-test-vectors.csv`, `bip341-wallet-test-vectors.json`)

BIP340 (Pieter Wuille, Jonas Nick, Tim Ruffing) is licensed BSD-2-Clause, and its code and
test vectors additionally under MIT or CC0-1.0 at the user's choice; the MIT text above
applies. BIP341 (Pieter Wuille, Jonas Nick, Anthony Towns) is licensed BSD-3-Clause:

```
Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of
   conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of
   conditions and the following disclaimer in the documentation and/or other materials
   provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used
   to endorse or promote products derived from this software without specific prior written
   permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
