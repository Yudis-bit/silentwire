use crate::{
    coordinates::{batch_normalize_jacobian, beta_fe, Affine, JacobianPoint},
    Error, MAX_BATCH,
};
use k256::elliptic_curve::{point::BatchNormalize, scalar::IsHigh, PrimeField};
use k256::{AffinePoint, FieldElement, ProjectivePoint, Scalar};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

pub const WINDOW_BITS: usize = 5;
pub const TABLE_SIZE: usize = 1 << WINDOW_BITS;
pub const WINDOWS: usize = 256_usize.div_ceil(WINDOW_BITS);
pub const ROLLING_BASES: usize = 4;
pub const GLV_TABLE_SIZE: usize = 16;
pub const GLV_WINDOWS: usize = 33;
pub const GLV_FUSED_BASES: usize = 32;
const GLV_HALF_TABLE: usize = 8;
const GLV_NORM_PER_BASE: usize = GLV_HALF_TABLE - 1;

/// secp256k1 group order `n` in four little-endian `u64` limbs.
const ORDER_LE: [u64; 4] = [
    0xbfd2_5e8c_d036_4141,
    0xbaae_dce6_af48_a03b,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
];

const MINUS_LAMBDA_BYTES: [u8; 32] = [
    0xac, 0x9c, 0x52, 0xb3, 0x3f, 0xa3, 0xcf, 0x1f, 0x5a, 0xd9, 0xe3, 0xfd, 0x77, 0xed, 0x9b, 0xa4,
    0xa8, 0x80, 0xb9, 0xfc, 0x8e, 0xc7, 0x39, 0xc2, 0xe0, 0xcf, 0xc8, 0x10, 0xb5, 0x12, 0x83, 0xcf,
];
const MINUS_B1_BYTES: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc3,
];
const MINUS_B2_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0x8a, 0x28, 0x0a, 0xc5, 0x07, 0x74, 0x34, 0x6d, 0xd7, 0x65, 0xcd, 0xa8, 0x3d, 0xb1, 0x56, 0x2c,
];
const G1_BYTES: [u8; 32] = [
    0x30, 0x86, 0xd2, 0x21, 0xa7, 0xd4, 0x6b, 0xcd, 0xe8, 0x6c, 0x90, 0xe4, 0x92, 0x84, 0xeb, 0x15,
    0x3d, 0xaa, 0x8a, 0x14, 0x71, 0xe8, 0xca, 0x7f, 0xe8, 0x93, 0x20, 0x9a, 0x45, 0xdb, 0xb0, 0x31,
];
const G2_BYTES: [u8; 32] = [
    0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc4,
    0x22, 0x12, 0x08, 0xac, 0x9d, 0xf5, 0x06, 0xc6, 0x15, 0x71, 0xb4, 0xae, 0x8a, 0xc4, 0x7f, 0x71,
];

fn mul_shift_384(k_bytes: &[u8; 32], g_bytes: &[u8; 32]) -> u128 {
    let mut k_limbs = [0u64; 4];
    let mut g_limbs = [0u64; 4];
    for i in 0..4 {
        k_limbs[i] = u64::from_le_bytes(k_bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        g_limbs[i] = u64::from_le_bytes(g_bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    let mut p = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let total = (p[i + j] as u128) + (k_limbs[i] as u128) * (g_limbs[j] as u128) + carry;
            p[i + j] = total as u64;
            carry = total >> 64;
        }
        for limb in p.iter_mut().skip(i + 4) {
            let total = (*limb as u128) + carry;
            *limb = total as u64;
            carry = total >> 64;
        }
    }
    ((p[6] as u128) | ((p[7] as u128) << 64)) + u128::from(p[5] >> 63)
}

/// Branchless conversion of `u128` into `Scalar` without `Option::unwrap()`.
#[inline]
fn scalar_from_u128(val: u128) -> Scalar {
    let two_pow_32 = Scalar::from(1u64 << 32);
    let two_pow_64 = two_pow_32 * two_pow_32;
    let hi = Scalar::from((val >> 64) as u64);
    let lo = Scalar::from(val as u64);
    hi * two_pow_64 + lo
}

/// Branchless computation of `min(s, n - s)` big-endian bytes without calling
/// `k256::Scalar::neg` (whose `crypto_bigint::neg_mod` can emit a secret-dependent
/// zero check under LLVM optimization).
fn abs_scalar_bytes(s: &Scalar, is_high: Choice) -> Zeroizing<[u8; 32]> {
    let raw = Zeroizing::new(<[u8; 32]>::from(s.to_bytes()));
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[3 - i] = u64::from_be_bytes(raw[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    let mut neg_limbs = [0u64; 4];
    let mut borrow = 0u128;
    for i in 0..4 {
        let diff = (ORDER_LE[i] as u128)
            .wrapping_sub(limbs[i] as u128)
            .wrapping_sub(borrow);
        neg_limbs[i] = diff as u64;
        borrow = (diff >> 127) & 1;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for i in 0..4 {
        let chosen = u64::conditional_select(&limbs[3 - i], &neg_limbs[3 - i], is_high);
        out[i * 8..(i + 1) * 8].copy_from_slice(&chosen.to_be_bytes());
    }
    limbs.zeroize();
    neg_limbs.zeroize();
    out
}

fn decompose(k: &Scalar) -> (Scalar, Scalar) {
    let k_bytes = Zeroizing::new(<[u8; 32]>::from(k.to_bytes()));
    let mut k_le = Zeroizing::new(*k_bytes);
    k_le.reverse();
    let mut g1_le = G1_BYTES;
    g1_le.reverse();
    let mut g2_le = G2_BYTES;
    g2_le.reverse();
    let c1_num = mul_shift_384(&k_le, &g1_le);
    let c2_num = mul_shift_384(&k_le, &g2_le);
    let c1 = scalar_from_u128(c1_num);
    let c2 = scalar_from_u128(c2_num);
    let minus_b1 = Option::<Scalar>::from(Scalar::from_repr(MINUS_B1_BYTES.into())).unwrap();
    let minus_b2 = Option::<Scalar>::from(Scalar::from_repr(MINUS_B2_BYTES.into())).unwrap();
    let minus_lam = Option::<Scalar>::from(Scalar::from_repr(MINUS_LAMBDA_BYTES.into())).unwrap();
    let r2 = c1 * minus_b1 + c2 * minus_b2;
    let r1 = *k + r2 * minus_lam;
    (r1, r2)
}

fn radix16_signed_from_bytes(bytes: &[u8; 32], negate: Choice) -> [i8; GLV_WINDOWS] {
    let mut out = [0i8; GLV_WINDOWS];
    for i in 0..16 {
        out[2 * i] = (bytes[31 - i] & 0xf) as i8;
        out[2 * i + 1] = ((bytes[31 - i] >> 4) & 0xf) as i8;
    }
    out[32] = (bytes[15] & 0xf) as i8;
    for i in 0..GLV_WINDOWS - 1 {
        let carry = (out[i] + 8) >> 4;
        out[i] -= carry << 4;
        out[i + 1] += carry;
    }
    // Fold sign into digits so the precomputation table remains 100% public.
    let neg_mask = -(negate.unwrap_u8() as i8);
    for d in &mut out {
        *d = (*d ^ neg_mask).wrapping_sub(neg_mask);
    }
    out
}

#[inline]
fn select_affine8_coord(table: &[Affine; GLV_HALF_TABLE], x: i8) -> Affine {
    let xmask = x >> 7;
    let xabs = ((x + xmask) ^ xmask) as u8;
    let mut selected = Affine::identity();
    for (idx, entry) in table.iter().enumerate() {
        selected = Affine::conditional_select(&selected, entry, xabs.ct_eq(&((idx + 1) as u8)));
    }
    let neg_mask = Choice::from((xmask & 1) as u8);
    Affine::conditional_select(&selected, &selected.negate(), neg_mask)
}

/// Fills `[2*P, 3*P, ..., 8*P]` in Jacobian coordinates using `3M + 4S` doublings
/// and `7M + 4S` `add_mixed_distinct` (skipping `1*P` which already has `Z = 1`).
/// On prime-order secp256k1, `2P, 4P, 6P` are guaranteed `!= ±P` for any `P != ∞`.
#[inline]
fn fill_seven_jacobian(dst: &mut [JacobianPoint], base: &Affine) {
    let p1 = JacobianPoint::from_affine(base);
    let p2 = p1.double();
    let p3 = p2.add_mixed_distinct(base);
    let p4 = p2.double();
    let p5 = p4.add_mixed_distinct(base);
    let p6 = p3.double();
    let p7 = p6.add_mixed_distinct(base);
    let p8 = p4.double();
    dst[0] = p2;
    dst[1] = p3;
    dst[2] = p4;
    dst[3] = p5;
    dst[4] = p6;
    dst[5] = p7;
    dst[6] = p8;
}

/// Zero-allocation batch normalization of `k256::ProjectivePoint` values (used for
/// Mode B subtractive diffs where values are public/declassified).
pub(crate) fn batch_normalize_projective_into(src: &[ProjectivePoint], dst: &mut [AffinePoint]) {
    debug_assert_eq!(src.len(), dst.len());
    let mut offset = 0usize;
    while offset < src.len() {
        let rem = src.len() - offset;
        if rem == 1 {
            dst[offset] = src[offset].to_affine();
            offset += 1;
        } else if rem <= 16 {
            let mut buf = [ProjectivePoint::GENERATOR; 16];
            buf[..rem].copy_from_slice(&src[offset..offset + rem]);
            let norm = ProjectivePoint::batch_normalize(&buf);
            dst[offset..offset + rem].copy_from_slice(&norm[..rem]);
            offset += rem;
        } else {
            let take = rem.min(64);
            let mut buf = [ProjectivePoint::GENERATOR; 64];
            buf[..take].copy_from_slice(&src[offset..offset + take]);
            let norm = ProjectivePoint::batch_normalize(&buf);
            dst[offset..offset + take].copy_from_slice(&norm[..take]);
            offset += take;
        }
    }
}

#[derive(Clone)]
pub struct GlvScalar {
    d1: [i8; GLV_WINDOWS],
    d2: [i8; GLV_WINDOWS],
}

impl Drop for GlvScalar {
    fn drop(&mut self) {
        self.d1.zeroize();
        self.d2.zeroize();
    }
}

impl GlvScalar {
    /// Constant-time GLV decomposition and signed radix-16 recoding with signs
    /// absorbed into `d1`/`d2` so base-point tables require zero secret data.
    pub fn new(scalar: &Scalar) -> Self {
        let (r1, r2) = decompose(scalar);
        let sign1 = r1.is_high();
        let sign2 = r2.is_high();
        let b1 = abs_scalar_bytes(&r1, sign1);
        let b2 = abs_scalar_bytes(&r2, sign2);
        let d1 = radix16_signed_from_bytes(&b1, sign1);
        let d2 = radix16_signed_from_bytes(&b2, sign2);
        Self { d1, d2 }
    }

    /// Evaluates `self * P` for one internal `Affine` base using an 8-point public
    /// table (`phi(j*P) = (beta*x_j, y_j)`), normalizing only the 7 non-unit
    /// multiples `[2..8]*P`, with complete Jacobian `3M + 4S` doublings and
    /// `7M + 5S` complete mixed additions.
    pub(crate) fn multiply_single_affine(&self, base: &Affine) -> JacobianPoint {
        let mut proj = [JacobianPoint::IDENTITY; GLV_NORM_PER_BASE];
        fill_seven_jacobian(&mut proj, base);
        let mut tab = [Affine::identity(); GLV_HALF_TABLE];
        tab[0] = *base;
        let mut zs = [FieldElement::ZERO; GLV_NORM_PER_BASE];
        let mut scratch = [FieldElement::ZERO; GLV_NORM_PER_BASE];
        batch_normalize_jacobian(&proj, &mut tab[1..], &mut zs, &mut scratch)
            .expect("7-entry scratch always suffices");
        self.eval_table(&tab)
    }

    #[inline]
    fn eval_table(&self, tab: &[Affine; GLV_HALF_TABLE]) -> JacobianPoint {
        let beta = beta_fe();
        let p1_top = select_affine8_coord(tab, self.d1[32]);
        let p2_top = select_affine8_coord(tab, self.d2[32]).endomorphism(&beta);
        let mut acc = JacobianPoint::from_affine(&p1_top).add_mixed(&p2_top);
        for i in (0..32).rev() {
            acc = acc.double().double().double().double();
            let q1 = select_affine8_coord(tab, self.d1[i]);
            let q2 = select_affine8_coord(tab, self.d2[i]).endomorphism(&beta);
            acc = acc.add_mixed(&q1).add_mixed(&q2);
        }
        acc
    }

    /// Fused cross-transaction GLV multiplication in chunks of up to 32 bases.
    /// Builds 7 non-unit Jacobian multiples `[2..8]*P_i` per base, batch-normalizes
    /// up to 224 precomp points via `MontgomeryBatchInverter`, derives `phi(j*P_i)`
    /// via `beta * x_j`, and batch-normalizes the resulting shared secrets without
    /// heap allocations.
    pub(crate) fn multiply_affine_batch_to_affine(
        &self,
        bases: &[Affine],
        out: &mut [Affine],
    ) -> Result<(), Error> {
        if bases.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if out.len() != bases.len() {
            return Err(Error::ScratchTooSmall);
        }
        let mut jac_out = [JacobianPoint::IDENTITY; GLV_FUSED_BASES];
        let mut proj_buf = [JacobianPoint::IDENTITY; GLV_FUSED_BASES * GLV_NORM_PER_BASE];
        let mut aff_buf = [Affine::identity(); GLV_FUSED_BASES * GLV_NORM_PER_BASE];
        let mut zs = [FieldElement::ZERO; GLV_FUSED_BASES * GLV_NORM_PER_BASE];
        let mut scratch = [FieldElement::ZERO; GLV_FUSED_BASES * GLV_NORM_PER_BASE];

        for (base_chunk, out_chunk) in bases
            .chunks(GLV_FUSED_BASES)
            .zip(out.chunks_mut(GLV_FUSED_BASES))
        {
            let count = base_chunk.len();
            let total_pts = count * GLV_NORM_PER_BASE;
            for (idx, base) in base_chunk.iter().enumerate() {
                let off = idx * GLV_NORM_PER_BASE;
                fill_seven_jacobian(&mut proj_buf[off..off + GLV_NORM_PER_BASE], base);
            }
            batch_normalize_jacobian(
                &proj_buf[..total_pts],
                &mut aff_buf[..total_pts],
                &mut zs[..total_pts],
                &mut scratch[..total_pts],
            )?;
            let mut tab = [Affine::identity(); GLV_HALF_TABLE];
            for (idx, jac_slot) in jac_out[..count].iter_mut().enumerate() {
                let off = idx * GLV_NORM_PER_BASE;
                tab[0] = base_chunk[idx];
                tab[1..].copy_from_slice(&aff_buf[off..off + GLV_NORM_PER_BASE]);
                *jac_slot = self.eval_table(&tab);
            }
            batch_normalize_jacobian(
                &jac_out[..count],
                out_chunk,
                &mut zs[..count],
                &mut scratch[..count],
            )?;
        }
        jac_out.iter_mut().for_each(|p| {
            p.x.zeroize();
            p.y.zeroize();
            p.z.zeroize();
        });
        zs.zeroize();
        scratch.zeroize();
        Ok(())
    }

    pub fn multiply_rolling_into(
        &self,
        bases: &[ProjectivePoint],
        output: &mut [ProjectivePoint],
        tables: &mut [AffinePoint],
    ) -> Result<(), Error> {
        if bases.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if output.len() != bases.len()
            || tables.len() < bases.len().min(ROLLING_BASES) * GLV_TABLE_SIZE
        {
            return Err(Error::ScratchTooSmall);
        }
        let tile = (tables.len() / GLV_TABLE_SIZE).clamp(1, GLV_FUSED_BASES);
        for (chunk, out) in bases.chunks(tile).zip(output.chunks_mut(tile)) {
            self.multiply_into(chunk, out, tables)?;
        }
        Ok(())
    }

    /// Fused cross-base GLV multiplication on `k256::ProjectivePoint` slices using
    /// the Jacobian 8-point `phi(j*P)` engine and branchless Montgomery batching.
    pub fn multiply_into(
        &self,
        bases: &[ProjectivePoint],
        output: &mut [ProjectivePoint],
        tables: &mut [AffinePoint],
    ) -> Result<(), Error> {
        if bases.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if output.len() != bases.len() || tables.len() < bases.len() * GLV_TABLE_SIZE {
            return Err(Error::ScratchTooSmall);
        }
        let mut aff_bases = [AffinePoint::IDENTITY; GLV_FUSED_BASES];
        let mut coord_bases = [Affine::identity(); GLV_FUSED_BASES];
        let mut coord_out = [Affine::identity(); GLV_FUSED_BASES];

        for (base_chunk, out_chunk) in bases
            .chunks(GLV_FUSED_BASES)
            .zip(output.chunks_mut(GLV_FUSED_BASES))
        {
            let count = base_chunk.len();
            batch_normalize_projective_into(base_chunk, &mut aff_bases[..count]);
            for i in 0..count {
                coord_bases[i] = Affine::from_k256(&aff_bases[i]);
            }
            self.multiply_affine_batch_to_affine(&coord_bases[..count], &mut coord_out[..count])?;
            for i in 0..count {
                out_chunk[i] = ProjectivePoint::from(coord_out[i].to_k256());
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SharedScalar {
    digits: [u8; WINDOWS],
}

impl Drop for SharedScalar {
    fn drop(&mut self) {
        self.digits.zeroize();
    }
}

impl SharedScalar {
    pub fn new(scalar: &Scalar) -> Self {
        let bytes = Zeroizing::new(<[u8; 32]>::from(scalar.to_bytes()));
        let mut digits = [0; WINDOWS];
        for (window, digit) in digits.iter_mut().enumerate() {
            for bit in 0..WINDOW_BITS {
                let position = window * WINDOW_BITS + bit;
                if position < 256 {
                    *digit |= ((bytes[31 - position / 8] >> (position % 8)) & 1) << bit;
                }
            }
        }
        Self { digits }
    }

    pub fn multiply_rolling_into(
        &self,
        bases: &[ProjectivePoint],
        output: &mut [ProjectivePoint],
        tables: &mut [ProjectivePoint],
    ) -> Result<(), Error> {
        if bases.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if output.len() != bases.len() || tables.len() < bases.len().min(ROLLING_BASES) * TABLE_SIZE
        {
            return Err(Error::ScratchTooSmall);
        }
        for (chunk, out) in bases
            .chunks(ROLLING_BASES)
            .zip(output.chunks_mut(ROLLING_BASES))
        {
            self.multiply_into(chunk, out, tables)?;
        }
        Ok(())
    }

    pub fn multiply_rolling_mixed_into(
        &self,
        bases: &[ProjectivePoint],
        output: &mut [ProjectivePoint],
        tables: &mut [AffinePoint],
    ) -> Result<(), Error> {
        if bases.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if output.len() != bases.len() || tables.len() < bases.len().min(ROLLING_BASES) * TABLE_SIZE
        {
            return Err(Error::ScratchTooSmall);
        }
        for (chunk, out) in bases
            .chunks(ROLLING_BASES)
            .zip(output.chunks_mut(ROLLING_BASES))
        {
            self.multiply_mixed_into(chunk, out, tables)?;
        }
        Ok(())
    }

    pub fn multiply_into(
        &self,
        bases: &[ProjectivePoint],
        output: &mut [ProjectivePoint],
        tables: &mut [ProjectivePoint],
    ) -> Result<(), Error> {
        if bases.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if output.len() != bases.len() || tables.len() < bases.len() * TABLE_SIZE {
            return Err(Error::ScratchTooSmall);
        }
        for (base, table) in bases.iter().zip(tables.as_chunks_mut::<TABLE_SIZE>().0) {
            table[0] = ProjectivePoint::IDENTITY;
            for j in 1..TABLE_SIZE {
                table[j] = table[j - 1] + base;
            }
        }
        output.fill(ProjectivePoint::IDENTITY);
        for digit in self.digits.iter().rev() {
            for (result, table) in output.iter_mut().zip(tables.as_chunks::<TABLE_SIZE>().0) {
                for _ in 0..WINDOW_BITS {
                    *result = result.double();
                }
                let mut selected = ProjectivePoint::IDENTITY;
                for (index, candidate) in table.iter().enumerate() {
                    selected = ProjectivePoint::conditional_select(
                        &selected,
                        candidate,
                        (index as u8).ct_eq(digit),
                    );
                }
                *result += selected;
            }
        }
        Ok(())
    }

    pub fn multiply_mixed_into(
        &self,
        bases: &[ProjectivePoint],
        output: &mut [ProjectivePoint],
        tables: &mut [AffinePoint],
    ) -> Result<(), Error> {
        if bases.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if output.len() != bases.len() || tables.len() < bases.len() * TABLE_SIZE {
            return Err(Error::ScratchTooSmall);
        }
        for (base, table) in bases.iter().zip(tables.as_chunks_mut::<TABLE_SIZE>().0) {
            let is_id = base.ct_eq(&ProjectivePoint::IDENTITY);
            let safe_base =
                ProjectivePoint::conditional_select(base, &ProjectivePoint::GENERATOR, is_id);
            let mut proj = [ProjectivePoint::IDENTITY; TABLE_SIZE - 1];
            proj[0] = safe_base;
            for j in 1..TABLE_SIZE - 1 {
                proj[j] = proj[j - 1] + safe_base;
            }
            let affines: [AffinePoint; TABLE_SIZE - 1] = ProjectivePoint::batch_normalize(&proj);
            table[0] = AffinePoint::IDENTITY;
            for (dst, src) in table[1..].iter_mut().zip(&affines) {
                *dst = AffinePoint::conditional_select(src, &AffinePoint::IDENTITY, is_id);
            }
        }
        output.fill(ProjectivePoint::IDENTITY);
        for digit in self.digits.iter().rev() {
            for (result, table) in output.iter_mut().zip(tables.as_chunks::<TABLE_SIZE>().0) {
                for _ in 0..WINDOW_BITS {
                    *result = result.double();
                }
                let mut selected = AffinePoint::IDENTITY;
                for (index, candidate) in table.iter().enumerate() {
                    selected = AffinePoint::conditional_select(
                        &selected,
                        candidate,
                        (index as u8).ct_eq(digit),
                    );
                }
                *result += selected;
            }
        }
        Ok(())
    }
}
