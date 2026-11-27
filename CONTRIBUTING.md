Contributing to silentwire
==========================

`silentwire`, `bdk-silentwire`, and `silentwire-cli` enforce
`#![forbid(unsafe_code)]`. `unsafe` is restricted to `crates/silentwire-ffi`
with explicit safety invariants on every block. Changes to curve arithmetic,
script parsing, or BIP-352/374/375 derivation need differential tests or
explicit failure vectors.

Run the local checks before sending a patch:

```sh
cargo fmt --all --check
cargo check --workspace --offline --locked
cargo check -p silentwire --no-default-features --offline --locked
cargo check -p silentwire --no-default-features --features alloc --offline --locked
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --workspace --release --offline --locked
make ffi
```

Use imperative 50/72 commit subjects with a short scope prefix (`silentwire:`,
`bdk:`, `ffi:`, `cli:`, `doc:`, `test:`) and explain the reason for the change
in the commit body.
