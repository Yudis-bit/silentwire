Mathematical specification of silentwire
========================================

This document specifies the algebraic formulations and execution invariants
implemented in silentwire for BIP-352 Silent Payments and BIP-374/375.

secp256k1 curve parameters
--------------------------

The engine operates over the prime field F_p and elliptic curve group E(F_p):

    p = 2^256 - 2^32 - 977
      = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Curve equation:

    y^2 = x^3 + 7 (mod p)

Generator point G = (G_x, G_y):

    G_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    G_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

Theorem 1: Fused cross-transaction GLV endomorphism
---------------------------------------------------

secp256k1 has j-invariant 0 and admits an efficiently computable endomorphism
phi over F_p:

    phi(x, y) = (beta * x, y) = lambda * (x, y)

with beta^3 = 1 (mod p) and lambda^3 = 1 (mod n):

    beta   = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
    lambda = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72

Babai rounding splits any scan scalar k in [1, n - 1] into two signed
half-scalars k = r1 + r2 * lambda (mod n) with |r1|, |r2| < 2^128. Absolute
values are computed branchlessly as min(r, n - r) in four little-endian u64
limbs, then recoded into 33 signed radix-16 digits d1[0..33], d2[0..33] in
[-8, 8] with the signs of r1 and r2 folded directly into the digits.

Because signs live in the digits rather than the base table, per-base
precomputation is independent of the secret scalar:

    T_P = [1*P, 2*P, 3*P, 4*P, 5*P, 6*P, 7*P, 8*P]

Only the 7 non-unit multiples [2..8]*P are built (4 Jacobian doublings at
3M + 4S and 3 distinct mixed additions at 7M + 4S). Across a chunk of up to
32 transaction tweaks, all 32 * 7 = 224 Jacobian points normalize in one
branchless MontgomeryBatchInverter call. The endomorphism table entries are
evaluated on the fly via phi(j*P) = (beta * x_j, y_j) with zero extra group
additions or inversions.

Online evaluation runs 128 Jacobian doublings (3M + 4S) and 66 complete
Brier-Joye Jacobian+Affine mixed additions (7M + 5S, scaled by s = 2 to avoid
halving, handling infinity, doubling, inverses, and endomorphism pairs
y1 = -y2, x1 != x2 without branches). All 32 resulting shared secrets normalize
in one second branchless MontgomeryBatchInverter call.

Theorem 2: Signed 6-bit fixed-base comb table
---------------------------------------------

Candidate outputs derive from P_k = B_spend + t_k * G with fixed generator G.
A 256-bit scalar t_k is split into 43 windows of 6 bits (43 * 6 = 258 bits)
and recoded branchlessly into signed digits d_i in [-31, 32]:

    if raw > 32: digit = raw - 64, carry = 1
    else:        digit = raw,      carry = 0

On window 42, raw <= 15 + 1 = 16 <= 32, so carry-out is identically zero for
all canonical scalars t_k in [1, n - 1]. Each window stores 32 affine points
T[i][j] = (j + 1) * 2^(6*i) * G as 4-limb u64 coordinate pairs:

    43 * 32 * 64 bytes = 88,064 bytes

Table selection uses u64::conditional_select across all 32 entries per window,
followed by conditional y-negation for negative digits. At every window i, the
running partial sum S_i = sum_{j=0}^{i-1} d_j * 2^(6*j) satisfies
|S_i| < 0.51 * 2^(6*i) < |T_i| and S_i != +-T_i (mod n) for all t_k in
[1, n - 1], so comb accumulation uses branchless madd-2007-bl mixed addition
(7M + 4S) with zero explicit doublings.

Theorem 3: Zero-inversion Jacobian x-match and adaptive labels
--------------------------------------------------------------

For a Jacobian candidate point C = (X : Y : Z) representing affine x = X / Z^2
and a Taproot output x-only key x_out:

    x(C) == x_out  <=>  Z != 0  AND  x_out < p  AND  X - x_out * Z^2 == 0 (mod p)

Precomputing Z^2 once per candidate tests each output in 1 field multiplication
and 0 modular inversions. Non-canonical values x_out >= p are rejected prior to
matching, and Z == 0 (infinity) unconditionally returns false even for
x_out == 0.

When the wallet tracks L <= 8 labels (ADAPTIVE_LABEL_THRESHOLD), the scanner
evaluates each variant P_k + L_m in Mode A using zero-inversion Jacobian
matching. When L > 8, the scanner switches to Mode B (O(1) subtractive lookup).
It checks unlabeled P_0 via Jacobian x-match, lifts remaining candidate outputs
to +-P_tx, computes +-P_tx - P_0 with batched normalization, and runs binary
search over the sorted precomputed label table.

Theorem 4: Branchless in-place Montgomery batch inversion
---------------------------------------------------------

Converting N Jacobian points (X : Y : Z) to affine requires Z_i^-1 (mod p).
Montgomery batch inversion replaces N inversions with 1 field inversion and
3(N - 1) field multiplications in caller-provided scratch buffers:

    c_0 = 1
    c_i = c_{i-1} * select(Z_i, 1, Z_i == 0)
    inv = (c_N)^-1 (mod p)

Walking backwards from N - 1 to 0 recovers Z_i^-1 for nonzero Z_i and restores
0 for Z_i == 0 via masked conditional selection without division by zero or
heap allocation.

Theorem 5: Precomputed tagged-hash SHA-256 midstates
----------------------------------------------------

Every BIP-352 and BIP-374 tagged hash begins with SHA256(tag) || SHA256(tag),
which fills one 64-byte SHA-256 block. Starting from the precomputed chaining
state `[u32; 8]` reduces single-block payloads (37-byte BIP0352/SharedSecret and
36-byte BIP0352/Label) from three compressions to one.

Theorem 6: 64-byte aligned fail-safe candidate filter
-----------------------------------------------------

Each filter bucket stores eight 64-bit fingerprint tags (64 bytes, 64-byte
aligned). Candidate relocation uses the XOR involution
alt(b, tag) = b XOR mask(tag) (mod M). If eviction reaches the depth bound, a
persistent saturation flag forces contains(tag) = true, preserving identically
zero false negatives under adversarial input distributions.

Theorem 7: Dual independent additive blinding (HardenedMultiplier)
------------------------------------------------------------------

Given secret scalar s and two distinct nonzero blinds b1 != b2 (with
b1 != s, b2 != s, b1 != -b2, and b1 + b2 != s):

    s1 = s - b1 (mod n),  P1 = s1 * B + b1 * B
    s2 = s - b2 (mod n),  P2 = s2 * B + b2 * B

Both paths evaluate via GlvScalar::multiply_single_affine without ever invoking
a point multiplication directly on s. Split scalars are held in Zeroizing
wrappers, both resulting points are verified on y^2 = x^3 + 7 (mod p), and
P1 == P2 is verified in constant time before returning P1.

Architectural and verification boundaries
-----------------------------------------

Constant-time control flow and memory access across all C ABI entry points are
verified on Linux x86_64 using Valgrind 3.27.1 (tests/ctime.c, 0 errors from
0 contexts, plus an active exit-42 negative control). Physical side-channel
resistance (DPA/EMA) depends on target silicon and requires oscilloscope
measurement. Embedded SRAM bounds on bare-metal microcontrollers (such as ARM
Cortex-M4) require whole-program linker section maps and call-graph stack
analysis beyond host sizeof checks.
