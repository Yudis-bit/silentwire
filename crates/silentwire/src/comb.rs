use crate::coordinates::{Affine, JacobianPoint};
use k256::{FieldElement, Scalar};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

#[path = "comb_table.rs"]
mod table;

pub(crate) const WINDOWS: usize = 43;
pub(crate) const WINDOW_BITS: usize = 6;
pub(crate) const ENTRIES: usize = 32;

#[inline(always)]
fn words_to_field_element(words: &[u64; 4]) -> FieldElement {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&words[0].to_be_bytes());
    bytes[8..16].copy_from_slice(&words[1].to_be_bytes());
    bytes[16..24].copy_from_slice(&words[2].to_be_bytes());
    bytes[24..32].copy_from_slice(&words[3].to_be_bytes());
    FieldElement::from_bytes((&bytes).into()).unwrap_or(FieldElement::ZERO)
}

/// Constant-time fixed-base generator multiplication using signed 6-bit windows
/// (`d_i in [-31, 32]`), word-level (`u64`) table selection, and Jacobian
/// mixed addition (`7M + 4S`, `madd-2007-bl`).
///
/// Signed recoding halves the precomputed table from 63 to 32 entries per
/// window (88,064 bytes total), guarantees carry-out == 0 on window 42 since
/// the top four scalar bits satisfy `raw <= 15 + 1 = 16 <= 32`, and guarantees
/// `S_i ≢ ±T_i (mod n)` at every step for all `scalar in [1, n - 1]`.
pub(crate) fn multiply_projective(scalar: &Scalar) -> JacobianPoint {
    let bytes = Zeroizing::new(<[u8; 32]>::from(scalar.to_bytes()));
    let mut x_words = Zeroizing::new([0u64; 4]);
    let mut y_words = Zeroizing::new([0u64; 4]);
    let mut result = JacobianPoint::IDENTITY;
    let mut carry = 0i8;

    for window in 0..WINDOWS {
        let bit = window * WINDOW_BITS;
        let at = 31 - bit / 8;
        let mut word = u16::from(bytes[at]);
        if at > 0 {
            word |= u16::from(bytes[at - 1]) << 8;
        }
        let raw = (((word >> (bit % 8)) & 63) as i8) + carry;
        // Branchless signed recoding: if raw > 32, digit = raw - 64 and carry = 1.
        let borrow = ((32 - raw) >> 7) & 1;
        let digit = raw - (borrow << 6);
        carry = borrow;

        // Branchless abs(digit) in [0..=32] and sign choice (1 iff digit < 0).
        let sign_mask = digit >> 7;
        let abs_digit = ((digit + sign_mask) ^ sign_mask) as u8;
        let neg_choice = Choice::from((sign_mask & 1) as u8);

        let mut xw = [0u64; 4];
        let mut yw = [0u64; 4];
        for (index, (tx, ty)) in table::POINTS[window].iter().take(ENTRIES).enumerate() {
            let select = abs_digit.ct_eq(&((index + 1) as u8));
            xw[0] = u64::conditional_select(&xw[0], &tx[0], select);
            xw[1] = u64::conditional_select(&xw[1], &tx[1], select);
            xw[2] = u64::conditional_select(&xw[2], &tx[2], select);
            xw[3] = u64::conditional_select(&xw[3], &tx[3], select);
            yw[0] = u64::conditional_select(&yw[0], &ty[0], select);
            yw[1] = u64::conditional_select(&yw[1], &ty[1], select);
            yw[2] = u64::conditional_select(&yw[2], &ty[2], select);
            yw[3] = u64::conditional_select(&yw[3], &ty[3], select);
        }
        *x_words = xw;
        *y_words = yw;

        let x = words_to_field_element(&x_words);
        let y_pos = words_to_field_element(&y_words);
        let y =
            FieldElement::conditional_select(&y_pos, &y_pos.negate(1).normalize_weak(), neg_choice);

        let point = Affine {
            x,
            y,
            infinity: abs_digit.ct_eq(&0),
        };
        result = result.add_mixed_distinct(&point);
    }
    result
}

pub(crate) fn multiply_generator(scalar: &Scalar) -> k256::ProjectivePoint {
    k256::ProjectivePoint::from(multiply_projective(scalar).to_k256())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::{sec1::FromEncodedPoint, PrimeField};
    use k256::AffinePoint;

    #[test]
    fn every_table_entry_matches_independent_group_multiplication() {
        let mut base = k256::ProjectivePoint::GENERATOR;
        for row in &table::POINTS {
            for (index, (xw, yw)) in row.iter().enumerate() {
                let x = words_to_field_element(xw).normalize().to_bytes();
                let y = words_to_field_element(yw).normalize().to_bytes();
                let encoded = k256::EncodedPoint::from_affine_coordinates(&x, &y, false);
                let point =
                    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)).unwrap();
                assert_eq!(point, (base * Scalar::from((index + 1) as u64)).to_affine());
            }
            for _ in 0..6 {
                base = base.double();
            }
        }
    }

    #[test]
    fn comb_covers_zero_top_bits_and_every_six_bit_digit() {
        for bit in 0..256 {
            let mut encoded = [0u8; 32];
            encoded[31 - bit / 8] = 1 << (bit % 8);
            let scalar = Option::<Scalar>::from(Scalar::from_repr(encoded.into())).unwrap();
            assert_eq!(
                multiply_generator(&scalar),
                k256::ProjectivePoint::GENERATOR * scalar
            );
        }
        for pattern in [0xffu8, 0x7f, 0x3f, 0x55, 0xaa, 0x80] {
            let mut bytes = [pattern; 32];
            bytes[0] &= 0x7f;
            if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(bytes.into())) {
                assert_eq!(multiply_generator(&s), k256::ProjectivePoint::GENERATOR * s);
            }
        }
        for value in [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::from(32u64),
            Scalar::from(33u64),
            Scalar::from(63u64),
            Scalar::from(64u64),
            -Scalar::ONE,
            -Scalar::from(32u64),
        ] {
            assert_eq!(
                multiply_generator(&value),
                k256::ProjectivePoint::GENERATOR * value
            );
        }
    }
}
