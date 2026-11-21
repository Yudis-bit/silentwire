Hardware wallet SRAM constraints in silentwire
==============================================

This document records static arena sizing and embedded verification boundaries
for `EmbeddedStaticScanner` and `ScanContext`.

Target environment
------------------

Constrained hardware signers such as ARM Cortex-M4 devices forbid heap
allocation in bare-metal scanning paths and reserve bounded static SRAM
budgets, commonly at most 16 KiB for dedicated scanning buffers.

`EmbeddedStaticScanner` layout
------------------------------

`EmbeddedStaticScanner<MAX_TWEAKS, MAX_OUTPUTS, MAX_MATCHES>` stores all state
in compile-time fixed arrays and precomputes the mandatory BIP-352 change label
(`m = 0`) alongside the unlabeled spend key:

    pub struct EmbeddedStaticScanner<
        const MAX_TWEAKS: usize,
        const MAX_OUTPUTS: usize,
        const MAX_MATCHES: usize,
    > {
        scan_scalar: Zeroizing<Scalar>,
        spend_affine: Affine,
        change_point: Affine,
        change_label: Zeroizing<Scalar>,
        tweaks: [AffinePoint; MAX_TWEAKS],
        tweak_output_ranges: [(u16, u16); MAX_TWEAKS],
        tweak_count: usize,
        outputs: [[u8; 32]; MAX_OUTPUTS],
        output_count: usize,
        matches: [SilentPaymentMatch; MAX_MATCHES],
        match_count: usize,
    }

Observed host x86_64 static footprints
--------------------------------------

Measured via `core::mem::size_of` on Linux x86_64 (`tests/embedded.rs` and
`tests/scan_context.rs`):

    ScanContext:                             536 bytes (align 8, 0 heap allocs on *_into paths)
    EmbeddedStaticScanner<16, 64, 8>:      4,712 bytes
    EmbeddedStaticScanner<32, 64, 8>:      6,440 bytes

The read-only comb table (`comb_table.rs`) occupies 88,064 bytes and is meant
for flash or `.rodata` rather than SRAM.

Scanning invariants
-------------------

Candidate tweaks are checked against the secp256k1 curve equation before
insertion so off-curve and quadratic twist points fail closed. Each `add_tweak`
call opens an isolated `(start, len)` range so outputs from one transaction
never match against another tweak.

`scan()` and streaming `scan_tx()` evaluate both unlabeled (`B_spend`) and
mandatory `m = 0` change (`B_spend + L_0`) candidates using `comb` and
zero-inversion Jacobian x-matching (`X == x_out * Z^2 (mod p)`, `Z != 0`).
Per-transaction `consumed` tracking prevents matching the same output across
multiple `k` values. Temporary shared secret and tweak scalar buffers stay in
`Zeroizing`, and `clear()` erases buffered matches.

Scope boundary
--------------

Host `size_of` numbers confirm struct arena geometry only. Proving a
whole-program <= 16 KiB SRAM bound on a bare-metal target such as
`thumbv7em-none-eabihf` requires compiling the target firmware ELF and checking
`.data`, `.bss`, and worst-case call-graph stack usage (including interrupt
frames and `k256` field temporaries) from linker maps and target stack-usage
data.
