use crate::{coordinates::Affine, point, scalar, ssmb::GlvScalar, tagged_hash, Error};
use k256::elliptic_curve::Group;
use k256::{AffinePoint, FieldElement, ProjectivePoint, Scalar};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Checks if an x-coordinate lies on the secp256k1 quadratic twist:
/// `E_twist: y^2 = (x^3 + 7) * d (mod p)` where `d` is a quadratic non-residue.
/// If `x^3 + 7` is not a quadratic residue in `F_p`, `(x, y)` lies on the twist.
pub fn is_on_quadratic_twist(x_bytes: &[u8; 32]) -> bool {
    let x_opt: Option<FieldElement> = Option::from(FieldElement::from_bytes(x_bytes.into()));
    let Some(x) = x_opt else {
        return false;
    };
    let seven = FieldElement::from(7u64);
    let rhs = x.square() * x + seven;
    bool::from(rhs.sqrt().is_none())
}

/// Audits a compressed 33-byte candidate tweak point against twist leakage
/// and standard SEC1 curve validation in a single decompression pass.
/// Rejects fail-closed on twist points, non-canonical coordinates, and infinity.
pub fn audit_candidate_tweak(bytes: &[u8; 33]) -> Result<AffinePoint, Error> {
    point(bytes)
}

fn derive_independent_blind(blinding_scalar: &Scalar) -> Result<Zeroizing<Scalar>, Error> {
    let blind_bytes = Zeroizing::new(<[u8; 32]>::from(blinding_scalar.to_bytes()));
    let derived = Zeroizing::new(tagged_hash(
        b"silentwire/dpa-split-2",
        &[blind_bytes.as_ref()],
    ));
    Ok(Zeroizing::new(scalar(*derived)?))
}

#[inline]
fn ct_mul_add_split(base: &Affine, sa: &Scalar, sb: &Scalar) -> Affine {
    let qa = GlvScalar::new(sa).multiply_single_affine(base).to_affine();
    let qb = GlvScalar::new(sb).multiply_single_affine(base);
    qb.add_mixed(&qa).to_affine()
}

/// Scalar multiplication with dual independent additive scalar blinding and
/// constant-time fault cross-checking (never performs an unblinded multiplication
/// by `secret_scalar`).
pub struct HardenedMultiplier;

impl HardenedMultiplier {
    /// Computes `Q = secret_scalar * base_point` using two independent blinded
    /// additive splits (`s = s1 + s2` and `s = s3 + s4`, `s1 != s3`, `s1 != -s3`,
    /// `s1 + s3 != s`), deriving the second blinding scalar via domain-separated
    /// hashing of `blinding_scalar`.
    pub fn multiply_hardened(
        secret_scalar: &Scalar,
        base_point: &ProjectivePoint,
        blinding_scalar: &Scalar,
    ) -> Result<AffinePoint, Error> {
        if bool::from(secret_scalar.is_zero()) {
            return Err(Error::InvalidScalar);
        }
        if bool::from(base_point.is_identity()) {
            return Err(Error::InvalidPoint);
        }
        if bool::from(blinding_scalar.is_zero()) || *blinding_scalar == *secret_scalar {
            return Err(Error::InvalidScalar);
        }

        let blinding_alt = derive_independent_blind(blinding_scalar)?;
        Self::multiply_hardened_dual(secret_scalar, base_point, blinding_scalar, &blinding_alt)
    }

    /// Computes `Q = secret_scalar * base_point` using two explicit caller-supplied
    /// independent blinding scalars `blinding_1` and `blinding_2`.
    pub fn multiply_hardened_dual(
        secret_scalar: &Scalar,
        base_point: &ProjectivePoint,
        blinding_1: &Scalar,
        blinding_2: &Scalar,
    ) -> Result<AffinePoint, Error> {
        let base_aff = base_point.to_affine();
        let enc = Zeroizing::new(Self::multiply_dual_with_declassify(
            secret_scalar,
            &base_aff,
            blinding_1,
            blinding_2,
            None,
        )?);
        point(enc.as_ref())
    }

    /// Constant-time dual-blinded multiplication with an explicit declassification
    /// hook for public guard predicates and final output points (used by FFI tests).
    pub fn multiply_dual_with_declassify(
        secret_scalar: &Scalar,
        base_point: &AffinePoint,
        blinding_1: &Scalar,
        blinding_2: &Scalar,
        declassify: Option<fn(*const u8, usize)>,
    ) -> Result<[u8; 33], Error> {
        let base_coord = Affine::from_k256(base_point);
        if bool::from(!base_coord.is_on_curve()) {
            return Err(Error::InvalidPoint);
        }
        let blind_sum = Zeroizing::new(*blinding_1 + *blinding_2);
        let invalid = (secret_scalar.is_zero()
            | blinding_1.is_zero()
            | blinding_2.is_zero()
            | blinding_1.ct_eq(blinding_2)
            | blinding_1.ct_eq(secret_scalar)
            | blinding_2.ct_eq(secret_scalar)
            | blind_sum.is_zero()
            | blind_sum.ct_eq(secret_scalar))
        .unwrap_u8();
        if let Some(f) = declassify {
            f(&invalid as *const u8, 1);
        }
        if invalid != 0 {
            return Err(Error::InvalidScalar);
        }

        let s1 = Zeroizing::new(*blinding_1);
        let s2 = Zeroizing::new(*secret_scalar - *s1);
        let s3 = Zeroizing::new(*blinding_2);
        let s4 = Zeroizing::new(*secret_scalar - *s3);

        let mut q_coord = ct_mul_add_split(&base_coord, &s1, &s2);
        let mut check_coord = ct_mul_add_split(&base_coord, &s3, &s4);
        let valid_curve = (q_coord.is_on_curve() & check_coord.is_on_curve()).unwrap_u8();
        if let Some(f) = declassify {
            f(&valid_curve as *const u8, 1);
            f(
                (&q_coord as *const Affine).cast(),
                core::mem::size_of::<Affine>(),
            );
            f(
                (&check_coord as *const Affine).cast(),
                core::mem::size_of::<Affine>(),
            );
        }
        if valid_curve == 0 {
            q_coord.zeroize_coords();
            check_coord.zeroize_coords();
            return Err(Error::InvalidPoint);
        }
        let enc = q_coord.to_compressed_bytes()?;
        let check_enc = Zeroizing::new(check_coord.to_compressed_bytes()?);
        q_coord.zeroize_coords();
        check_coord.zeroize_coords();
        if bool::from(!enc.ct_eq(check_enc.as_slice())) {
            return Err(Error::InvalidPoint);
        }
        Ok(enc)
    }
}
