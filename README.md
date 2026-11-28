silentwire
==========

[![CI](https://github.com/Yudis-bit/silentwire/actions/workflows/ci.yml/badge.svg)](https://github.com/Yudis-bit/silentwire/actions)
[![crates.io](https://img.shields.io/crates/v/silentwire.svg)](https://crates.io/crates/silentwire)
[![docs.rs](https://docs.rs/silentwire/badge.svg)](https://docs.rs/silentwire)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

BIP-352 Silent Payments scanning, sending, address coding, and BIP-374/375
helpers in Rust.

```sh
cargo add silentwire
cargo add bdk-silentwire
```

```rust
let mut scanner = silentwire::ScanContext::new();
let matches = scanner.scan_transaction(&scan_key, &spend_pubkey, &tweak, &outputs)?;
for payment in matches { println!("{}", payment.output_index); }
```

`scan_key` is a canonical, nonzero 32-byte scalar. `spend_pubkey` and `tweak`
are compressed 33-byte secp256k1 points. The tweak is `T = h * A_sum`, where
`h` is `BIP0352/Inputs` over the lowest input outpoint and the aggregated
eligible input key. Passing `A_sum` alone omits the input hash.
`PreparedTransaction` and `bdk-silentwire` build `T` from eligible inputs with
opcode-aware P2PKH push parsing, BIP-141 nested P2SH-P2WPKH direct-push and
HASH160 checks, and 2-element P2WPKH / nested witness pubkey HASH160 checks.

`output_index` gives the position in the supplied output slice and
`derivation_index` records `k`. Matches also carry `taproot_pubkey`,
`tweak_scalar`, and an optional label index. `scan_block` pairs each
transaction tweak with its own outputs and returns `BlockPaymentMatch` with
`transaction_index` intact. `bdk-silentwire` maps compact Taproot positions
back to transaction vouts, skips coinbase transactions, chunks blocks beyond
`MAX_BATCH` (4,096), and decodes bounded canonical CompactSize streams.

Allocation and arithmetic
-------------------------

`ScanContext` takes 536 bytes on x86_64 (`align = 8`). `scan_transaction_into`
and `scan_block_into` write into caller-owned slices with zero heap allocations
and erase any written prefix on `Error::ScratchTooSmall`.

`GlvScalar` decomposes `b_scan` once and folds both half-scalar signs into the
signed radix-16 digits so per-base tables carry no secret state. Each base
computes `[2..8]*P` with Jacobian `3M + 4S` doublings and `7M + 4S`
`madd-2007-bl` additions, deriving `phi(j*P) = (beta * x_j, y_j)` on the fly.
Up to 32 transactions (224 precomp points) normalize in one branchless
`MontgomeryBatchInverter` pass. Evaluation runs 128 Jacobian doublings and 65
complete Brier-Joye (`7M + 5S`) mixed additions, then batch-normalizes all 32
shared secrets in a second pass.

Generator multiplication `t_k * G` splits the scalar into 43 signed 6-bit
windows (`d_i in [-31, 32]`) over 32 entries per window with `u64`
conditional selection, `7M + 4S` mixed additions, and zero online doublings.
The static table takes 88,064 bytes in read-only storage. Compile-time SHA-256
midstates handle `BIP0352/{SharedSecret,Inputs,Label}` and
`BIP0374/{aux,nonce,challenge}`, cutting single-block tagged hashes from three
compressions to one.

When tracking at most `ADAPTIVE_LABEL_THRESHOLD` (8) labels, output matching
checks `Z != 0` and `X == x_out * Z^2 (mod p)` directly in Jacobian coordinates
with zero inversions and canonical `x_out < p` checks. Beyond 8 labels, the
scanner switches to `O(1)` subtractive lookup (`+-P_tx - P_0`) against a sorted
label table with batched normalization.

Protocol support and safety boundaries
--------------------------------------

`address` implements `no_std + alloc` Bech32m encoding and decoding for `sp`
and `tsp` addresses up to 1023 characters, requiring exact 66-byte payloads on
`v0`, preserving trailing `extension_data` on `v1..=v30`, and rejecting `v31`
or Bech32 checksums. `sender::create_outputs_checked` orders `OwnVerified`
recipients ahead of `External` entries sharing a scan key so self-change stays
recoverable, while rejecting distinct external parties colliding on a scan key
with `Error::ScanKeyCollision`. `bip374` implements `no_std` BIP-374 v0.3.1
DLEQ prove/verify (with fault-injection self-verification), BIP-375 share
aggregation with canonical lexicographical `B_spend` ordering, and change
shadowing checks (`Error::ChangeOrderShadowing`).

`HardenedMultiplier` splits the scalar through two independent additive blinds
held in `Zeroizing`, rejects degenerate blinds (`b1 == b2`, `b1 == -b2`,
`b1 + b2 == s`, or equal to `0`/`s`) and quadratic twist points, and
cross-checks both paths in constant time. `EmbeddedStaticScanner` compiles with
`--no-default-features` without `alloc`, keeps fixed compile-time arrays (4,480
bytes for `<16, 64, 8>` and 5,952 bytes for `<32, 64, 8>` on x86_64), derives
the `m = 0` change label automatically, isolates output ranges per tweak,
tracks source transaction indices and consumed vouts, wipes matches on `Drop`,
and parses Taproot x-only outputs on the fly without stack-buffered field
arrays.

`silentwire`, `bdk-silentwire`, and `silentwire-cli` forbid unsafe Rust. Only
`silentwire-ffi` uses `unsafe` for the C ABI and Valgrind declassification
hooks. Constant-time control flow and memory access across all five C ABI entry
points (six scenarios covering Mode A/B labels, batched GLV, dual-blinded
multiplication with tainted blinds, and BIP-374 DLEQ proving with tainted
`aux_rand`) pass Valgrind 3.27.1 (`tests/ctime.c`: exit 0, `0 errors from 0
contexts`, with `--negative-control` exiting 42). Valgrind checks compiled
x86_64 binaries for secret-dependent branches and addresses only. Physical DPA
or EMA resistance depends on target silicon, and whole-program Cortex-M4 SRAM
bounds require target linker maps and call-graph stack analysis.

Benchmarks
----------

On Intel Core i7-8550U pinned to `taskset -c 2` (release `lto = "fat"`),
`scripts/bench_vs_secp256k1.c` compares `silentwire_scan_batch_glv` against
locally built `bitcoin-core/secp256k1` (`82ff827`, `-O2`, `USE_ASM_X86_64=1`,
`COMB_BLOCKS=43`, `COMB_TEETH=6`, `ENABLE_MODULE_SILENTPAYMENTS=ON`):

```
workload (taskset -c 2)          libsecp256k1   silentwire    ratio  digest parity
1,000 txs (2,501 outs, m=0)      99.25 us/tx    99.28 us/tx   1.00x  PASS (7e1a4dde...)
1,000 txs (2,501 outs, no lbl)   91.45 us/tx    95.31 us/tx   0.96x  PASS (6ad7d9fb...)
4,000 txs (10,001 outs, m=0)     92.67 us/tx    97.64 us/tx   0.95x  PASS (1edac1c9...)
```

In this harness `libsecp256k1` receives pre-parsed uncompressed
`secp256k1_silentpayments_prevouts_summary` structs, while
`silentwire_scan_batch_glv` also decompresses every 33-byte tweak via `sqrt()`
inside the timed region.

Workspace and verification
--------------------------

The workspace has four crates: `silentwire`, `bdk-silentwire`, `silentwire-ffi`,
and `silentwire-cli`. C and C++ callers include `bindings/include/silentwire.h`
(checked with `cc -std=c11 -pedantic -Werror` and `c++ -std=c++17 -Werror`).

```sh
cargo fmt --all --check
cargo check --workspace --offline --locked
cargo check -p silentwire --no-default-features --offline --locked
cargo check -p silentwire --no-default-features --features alloc --offline --locked
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --workspace --release --offline --locked
make ffi
make bench
```

`tests/official_vectors.rs` runs 34 sending and 36 receiving BIP-352 test
vectors (29 sending / 30 receiving from `bitcoin/bips` `fdcd802` plus 5 sending
/ 6 receiving `K_max` and label edge cases from `bitcoin/bips#2330`).
`tests/bip374_vectors.rs` runs all 14 generate and 17 verify official BIP-374
v0.3.1 test vectors from `bitcoin/bips/bip-0374`. `tests/differential_fuzz.rs`
replays 100,000 deterministic transactions against independent `k256` derivation.
Details on formulas and static footprints are in
`doc/MATHEMATICAL_SPECIFICATION.md` and `doc/HARDWARE_WALLET_SRAM.md`.

License
-------

MIT OR Apache-2.0. See `NOTICE` for curve formula attributions.
