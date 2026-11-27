// Constant-time Jacobian formulas (a = 0) follow Brier & Joye (PKC 2002) as
// formulated in libsecp256k1 (MIT), scaled by Z' = 2*M*Z to avoid halving, and
// standard a = 0 doubling (3M + 4S). Homogeneous mixed addition for batch
// tests follows k256 0.13.4 (Renes-Costello-Batina 2015, Algorithm 8).

use crate::batch::MontgomeryBatchInverter;
use crate::Error;
use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, FieldElement,
};
use subtle::{Choice, ConditionallySelectable};

/// Cube root of unity `beta` in `F_p` for the secp256k1 GLV endomorphism
/// `phi(x, y) = (beta * x, y) = lambda * (x, y)`.
const BETA_BYTES: [u8; 32] = [
    0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10, 0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
    0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95, 0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
];

#[inline]
pub(crate) fn beta_fe() -> FieldElement {
    FieldElement::from_bytes((&BETA_BYTES).into()).unwrap_or(FieldElement::ONE)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Affine {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) infinity: Choice,
}

impl Affine {
    pub(crate) fn identity() -> Self {
        Self {
            x: FieldElement::ZERO,
            y: FieldElement::ZERO,
            infinity: Choice::from(1),
        }
    }

    pub(crate) fn from_k256(point: &AffinePoint) -> Self {
        let encoded = point.to_encoded_point(false);
        if encoded.as_bytes().len() != 65 {
            return Self::identity();
        }
        Self {
            x: FieldElement::from_bytes(encoded.x().expect("uncompressed x"))
                .unwrap_or(FieldElement::ZERO),
            y: FieldElement::from_bytes(encoded.y().expect("uncompressed y"))
                .unwrap_or(FieldElement::ZERO),
            infinity: Choice::from(0),
        }
    }

    #[inline]
    pub(crate) fn negate(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.negate(1).normalize_weak(),
            infinity: self.infinity,
        }
    }

    #[inline]
    pub(crate) fn endomorphism(&self, beta: &FieldElement) -> Self {
        Self {
            x: self.x.mul(beta).normalize_weak(),
            y: self.y,
            infinity: self.infinity,
        }
    }

    pub(crate) fn to_k256(self) -> AffinePoint {
        let x = self.x.normalize().to_bytes();
        let y = self.y.normalize().to_bytes();
        let encoded = k256::EncodedPoint::from_affine_coordinates(&x, &y, false);
        let point = AffinePoint::from_encoded_point(&encoded).unwrap_or(AffinePoint::IDENTITY);
        AffinePoint::conditional_select(&point, &AffinePoint::IDENTITY, self.infinity)
    }

    pub(crate) fn to_compressed_bytes(self) -> Result<[u8; 33], Error> {
        if bool::from(self.infinity) {
            return Err(Error::InvalidPoint);
        }
        let x_norm = self.x.normalize();
        let y_norm = self.y.normalize();
        let mut out = [0u8; 33];
        out[0] = if bool::from(y_norm.is_odd()) {
            0x03
        } else {
            0x02
        };
        out[1..].copy_from_slice(&x_norm.to_bytes());
        Ok(out)
    }

    #[inline]
    pub(crate) fn is_on_curve(&self) -> Choice {
        let lhs = self.y.square();
        let rhs = self.x.square().mul(&self.x) + FieldElement::from(7u64);
        let diff = lhs + rhs.negate(2);
        !self.infinity & diff.normalizes_to_zero()
    }

    #[inline]
    pub(crate) fn zeroize_coords(&mut self) {
        use zeroize::Zeroize;
        self.x.zeroize();
        self.y.zeroize();
        self.infinity = Choice::from(1);
    }
}

impl ConditionallySelectable for Affine {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

/// Parses an x-only 32-byte Taproot public key into a canonical `FieldElement`.
/// Returns `None` for any non-canonical value `x >= p`.
#[inline]
pub(crate) fn parse_x_only(bytes: &[u8; 32]) -> Option<FieldElement> {
    Option::from(FieldElement::from_bytes(bytes.into()))
}

/// Lifts a canonical x-only 32-byte coordinate to the even-`y` secp256k1 point.
/// Returns `None` for `x >= p` or any off-curve / quadratic twist x-coordinate.
#[cfg(any(feature = "alloc", test))]
#[inline]
pub(crate) fn lift_x_k256(x_bytes: &[u8; 32]) -> Option<AffinePoint> {
    let mut encoded = [0u8; 33];
    encoded[0] = 0x02;
    encoded[1..].copy_from_slice(x_bytes);
    let ep = k256::EncodedPoint::from_bytes(encoded).ok()?;
    Option::from(AffinePoint::from_encoded_point(&ep))
}

/// Constant-time Jacobian coordinates `(X : Y : Z)` with `x = X / Z^2`, `y = Y / Z^3`.
/// Point at infinity is uniquely represented by `Z == 0`.
/// Invariant: `x`, `y`, `z` always have magnitude `<= 1` after every operation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct JacobianPoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
}

impl JacobianPoint {
    pub(crate) const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    #[inline]
    pub(crate) fn from_affine(p: &Affine) -> Self {
        let z =
            FieldElement::conditional_select(&FieldElement::ONE, &FieldElement::ZERO, p.infinity);
        Self {
            x: FieldElement::conditional_select(&p.x, &FieldElement::ZERO, p.infinity),
            y: FieldElement::conditional_select(&p.y, &FieldElement::ONE, p.infinity),
            z,
        }
    }

    /// Constant-time Jacobian doubling for `a = 0` (`y^2 = x^3 + 7`): `3M + 4S`.
    /// Preserves `Z == 0` when `self` is the point at infinity.
    #[inline]
    pub(crate) fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = self.x.mul(&b).mul_single(4);
        let e = a.mul_single(3);
        let x3 = (e.square() + d.double().negate(8)).normalize_weak();
        let y3 = (e.mul(&(d + x3.negate(1))) + c.mul_single(8).negate(8)).normalize_weak();
        let z3 = self.y.mul(&self.z).double().normalize_weak();
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete, branchless, constant-time unified Jacobian + Affine addition (`7M + 5S`).
    ///
    /// Handles all edge cases (`self == ∞`, `other == ∞`, `self == other`,
    /// `self == -other`, and endomorphism pairs `y1 == -y2, x1 != x2`) without branches.
    #[inline]
    pub(crate) fn add_mixed(&self, other: &Affine) -> Self {
        let zz = self.z.square();
        let u1 = self.x;
        let u2 = other.x.mul(&zz);
        let s1 = self.y;
        let s2 = other.y.mul(&zz).mul(&self.z);

        let t = u1 + u2;
        let m = s1 + s2;
        let neg_u2 = u2.negate(1);
        let rr = (t.square() + u1.mul(&neg_u2)).normalize_weak();
        let degenerate = m.normalizes_to_zero();

        let rr_alt_base = s1.double();
        let m_alt_base = u1 + neg_u2;
        let rr_alt = FieldElement::conditional_select(&rr, &rr_alt_base, degenerate);
        let m_alt = FieldElement::conditional_select(&m, &m_alt_base, degenerate);

        let n = m_alt.square();
        let q = t.negate(2).mul(&n);
        let n4 = n.square();
        let n_term = FieldElement::conditional_select(&n4, &m, degenerate);

        let x3_raw = rr_alt.square() + q;
        let z3_raw = self.z.mul(&m_alt);
        let y3_twice = (rr_alt.mul(&(x3_raw.double() + q)) + n_term).negate(3);

        // Scale Jacobian representation by s = 2: (4*X3, 4*(2*Y3), 2*Z3) avoids halving.
        let computed = Self {
            x: x3_raw.mul_single(4).normalize_weak(),
            y: y3_twice.mul_single(4).normalize_weak(),
            z: z3_raw.double().normalize_weak(),
        };

        let self_inf = self.z.normalizes_to_zero();
        let from_other = Self {
            x: other.x,
            y: other.y,
            z: FieldElement::ONE,
        };
        let with_self_inf = Self::conditional_select(&computed, &from_other, self_inf);
        Self::conditional_select(&with_self_inf, self, other.infinity)
    }

    /// Constant-time Jacobian + Affine mixed addition (`7M + 4S`, `madd-2007-bl`)
    /// for provably distinct non-inverse points (`P != ±Q` whenever neither is `∞`).
    ///
    /// Handles `self == ∞` and `other == ∞` branchlessly. Used in fixed-base comb
    /// evaluation (where `|S_i| < 0.51 * 2^(6i) < |T_i|` proves `S_i ≢ ±T_i (mod n)`)
    /// and small multiple table construction (`2P+P, 4P+P, 6P+P` on prime-order `n`).
    #[inline]
    pub(crate) fn add_mixed_distinct(&self, other: &Affine) -> Self {
        let z1z1 = self.z.square();
        let u2 = other.x.mul(&z1z1);
        let s2 = other.y.mul(&self.z).mul(&z1z1);
        let h = u2 + self.x.negate(1);
        let hh = h.square();
        let i = hh.mul_single(4);
        let j = h.mul(&i);
        let r = (s2 + self.y.negate(1)).double();
        let v = self.x.mul(&i);

        let x3 = (r.square() + j.negate(1) + v.double().negate(2)).normalize_weak();
        let y3 = (r.mul(&(v + x3.negate(1))) + self.y.mul(&j).double().negate(2)).normalize_weak();
        let z3 = ((self.z + h).square() + z1z1.negate(1) + hh.negate(1)).normalize_weak();

        let computed = Self {
            x: x3,
            y: y3,
            z: z3,
        };
        let self_inf = self.z.normalizes_to_zero();
        let from_other = Self {
            x: other.x,
            y: other.y,
            z: FieldElement::ONE,
        };
        let with_self_inf = Self::conditional_select(&computed, &from_other, self_inf);
        Self::conditional_select(&with_self_inf, self, other.infinity)
    }

    /// Precomputes `Z^2` for zero-inversion x-coordinate matching across multiple outputs.
    #[inline]
    pub(crate) fn match_z2(&self) -> (FieldElement, Choice) {
        (self.z.square(), !self.z.normalizes_to_zero())
    }

    /// Zero-inversion Jacobian x-coordinate match using precomputed `(Z^2, Z != 0)`:
    /// checks `Z != 0` and `X == x_out * Z^2 (mod p)`.
    #[inline]
    pub(crate) fn matches_x_precomputed(
        &self,
        z2: &FieldElement,
        non_infinity: Choice,
        x_out: &FieldElement,
    ) -> Choice {
        let diff = self.x + x_out.mul(z2).negate(1);
        non_infinity & diff.normalizes_to_zero()
    }

    /// Zero-inversion Jacobian x-coordinate match:
    /// checks `Z != 0` and `X == x_out * Z^2 (mod p)`.
    #[cfg(test)]
    #[inline]
    pub(crate) fn matches_x(&self, x_out: &FieldElement) -> Choice {
        let (z2, non_infinity) = self.match_z2();
        self.matches_x_precomputed(&z2, non_infinity, x_out)
    }

    pub(crate) fn to_affine(self) -> Affine {
        let zero = self.z.normalizes_to_zero();
        let zi = self.z.invert().unwrap_or(FieldElement::ONE);
        let z2 = zi.square();
        let z3 = z2.mul(&zi);
        let aff = Affine {
            x: self.x.mul(&z2).normalize_weak(),
            y: self.y.mul(&z3).normalize_weak(),
            infinity: Choice::from(0),
        };
        Affine::conditional_select(&aff, &Affine::identity(), zero)
    }

    pub(crate) fn to_k256(self) -> AffinePoint {
        self.to_affine().to_k256()
    }
}

impl ConditionallySelectable for JacobianPoint {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

/// Branchless, zero-allocation Montgomery batch normalization of Jacobian points
/// using `MontgomeryBatchInverter`. Preserves points at infinity (`Z == 0`).
pub(crate) fn batch_normalize_jacobian(
    points: &[JacobianPoint],
    out: &mut [Affine],
    zs: &mut [FieldElement],
    scratch: &mut [FieldElement],
) -> Result<(), Error> {
    let n = points.len();
    if out.len() < n || zs.len() < n || scratch.len() < n {
        return Err(Error::ScratchTooSmall);
    }
    if n == 0 {
        return Ok(());
    }
    for i in 0..n {
        zs[i] = points[i].z;
    }
    MontgomeryBatchInverter::invert(&mut zs[..n], &mut scratch[..n])?;
    for i in 0..n {
        let zero = points[i].z.normalizes_to_zero();
        let zi = zs[i];
        let z2 = zi.square();
        let z3 = z2.mul(&zi);
        let aff = Affine {
            x: points[i].x.mul(&z2).normalize_weak(),
            y: points[i].y.mul(&z3).normalize_weak(),
            infinity: Choice::from(0),
        };
        out[i] = Affine::conditional_select(&aff, &Affine::identity(), zero);
    }
    Ok(())
}

/// Homogeneous projective point `(X : Y : Z)` with `x = X / Z`, `y = Y / Z`
/// retained for batch normalization tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectivePoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
}

#[cfg(test)]
impl ProjectivePoint {
    pub(crate) const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    pub(crate) fn add_mixed(&self, other: &Affine) -> Self {
        let xx = self.x * other.x;
        let yy = self.y * other.y;
        let xy = (self.x + self.y) * (other.x + other.y) + (xx + yy).negate(2);
        let yz = other.y * self.z + self.y;
        let xz = other.x * self.z + self.x;
        let bz = self.z.mul_single(7);
        let bz3 = (bz.double() + bz).normalize_weak();
        let minus = yy + bz3.negate(1);
        let plus = yy + bz3;
        let byz = yz.mul_single(7).normalize_weak();
        let byz3 = (byz.double() + byz).normalize_weak();
        let xx3 = xx.double() + xx;
        let bxx9 = (xx3.double() + xx3)
            .normalize_weak()
            .mul_single(7)
            .normalize_weak();
        let result = Self {
            x: (xy * minus + (byz3 * xz).negate(1)).normalize_weak(),
            y: (plus * minus + bxx9 * xz).normalize_weak(),
            z: (yz * plus + xx3 * xy).normalize_weak(),
        };
        Self::conditional_select(&result, self, other.infinity)
    }

    pub(crate) fn to_k256(self) -> AffinePoint {
        let inverse = self.z.invert().unwrap_or(FieldElement::ONE);
        let x = (self.x * inverse).normalize().to_bytes();
        let y = (self.y * inverse).normalize().to_bytes();
        let encoded = k256::EncodedPoint::from_affine_coordinates(&x, &y, false);
        let point = AffinePoint::from_encoded_point(&encoded).unwrap_or(AffinePoint::IDENTITY);
        AffinePoint::conditional_select(&point, &AffinePoint::IDENTITY, self.z.normalizes_to_zero())
    }
}

#[cfg(test)]
impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Scalar;

    #[test]
    fn jacobian_complete_add_double_endomorphism_and_matches_x() {
        let beta = beta_fe();
        // beta^3 == 1 (mod p).
        let beta3 = (beta.square() * beta).normalize();
        assert_eq!(beta3.to_bytes(), FieldElement::ONE.to_bytes());

        let g_aff = Affine::from_k256(&AffinePoint::GENERATOR);
        let g_jac = JacobianPoint::from_affine(&g_aff);

        // Doubling matches 2*G.
        let g2_expected = (k256::ProjectivePoint::GENERATOR * Scalar::from(2u64)).to_affine();
        assert_eq!(g_jac.double().to_k256(), g2_expected);
        assert_eq!(g_jac.add_mixed(&g_aff).to_k256(), g2_expected);

        // Identity handling: inf + G = G, G + inf = G, double(inf) = inf.
        assert_eq!(
            JacobianPoint::IDENTITY.add_mixed(&g_aff).to_k256(),
            AffinePoint::GENERATOR
        );
        assert_eq!(
            g_jac.add_mixed(&Affine::identity()).to_k256(),
            AffinePoint::GENERATOR
        );
        assert_eq!(
            JacobianPoint::IDENTITY.double().to_k256(),
            AffinePoint::IDENTITY
        );

        // Inverse: G + (-G) = inf.
        let neg_g = g_aff.negate();
        assert_eq!(g_jac.add_mixed(&neg_g).to_k256(), AffinePoint::IDENTITY);

        // Endomorphism degenerate branch: y1 == -y2, x1 != x2 (G + (-phi(G))).
        let phi_g = g_aff.endomorphism(&beta);
        let neg_phi_g = phi_g.negate();
        let expected_deg = (k256::ProjectivePoint::GENERATOR
            + (-k256::ProjectivePoint::GENERATOR.endomorphism()))
        .to_affine();
        assert_eq!(g_jac.add_mixed(&neg_phi_g).to_k256(), expected_deg);
        // Same branch with non-trivial Z (2*G + (-phi(2*G))).
        let g2_jac = g_jac.double();
        let neg_phi_g2 = Affine::from_k256(&g2_expected).endomorphism(&beta).negate();
        let expected_deg2 = (k256::ProjectivePoint::from(g2_expected)
            + (-k256::ProjectivePoint::from(g2_expected).endomorphism()))
        .to_affine();
        assert_eq!(g2_jac.add_mixed(&neg_phi_g2).to_k256(), expected_deg2);

        // Zero-inversion matches_x with nontrivial Z, infinity, and x >= p.
        let g3 = g2_jac.add_mixed(&g_aff);
        let g3_distinct = g2_jac.add_mixed_distinct(&g_aff);
        let g3_expected = (k256::ProjectivePoint::GENERATOR * Scalar::from(3u64)).to_affine();
        assert_eq!(g3.to_k256(), g3_expected);
        assert_eq!(g3_distinct.to_k256(), g3_expected);
        assert_eq!(
            JacobianPoint::IDENTITY.add_mixed_distinct(&g_aff).to_k256(),
            AffinePoint::GENERATOR
        );
        assert_eq!(
            g2_jac.add_mixed_distinct(&Affine::identity()).to_k256(),
            g2_expected
        );
        let g3_x_bytes: [u8; 32] = g3_expected.to_encoded_point(true).as_bytes()[1..33]
            .try_into()
            .unwrap();
        let g3_x = parse_x_only(&g3_x_bytes).unwrap();
        assert!(bool::from(g3.matches_x(&g3_x)));
        assert!(!bool::from(
            g3.matches_x(&(g3_x + FieldElement::ONE).normalize())
        ));
        assert!(!bool::from(JacobianPoint::IDENTITY.matches_x(&g3_x)));
        assert!(!bool::from(
            JacobianPoint::IDENTITY.matches_x(&FieldElement::ZERO)
        ));

        let p_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xff, 0xff, 0xfc, 0x2f,
        ];
        assert!(parse_x_only(&p_bytes).is_none());
        assert!(parse_x_only(&[0xff; 32]).is_none());
        assert!(lift_x_k256(&p_bytes).is_none());
        assert!(lift_x_k256(&[0u8; 32]).is_none());
    }
}
