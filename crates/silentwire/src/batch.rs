use crate::{Error, MAX_BATCH};
use k256::FieldElement;
use subtle::ConditionallySelectable;

pub struct MontgomeryBatchInverter;

impl MontgomeryBatchInverter {
    pub fn invert(values: &mut [FieldElement], scratch: &mut [FieldElement]) -> Result<(), Error> {
        if values.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if scratch.len() < values.len() {
            return Err(Error::ScratchTooSmall);
        }
        if values.is_empty() {
            return Ok(());
        }
        let first = values[0];
        let mut product = FieldElement::conditional_select(
            &first,
            &FieldElement::ONE,
            first.normalizes_to_zero(),
        );
        scratch[0] = product;
        for (value, prefix) in values.iter().skip(1).zip(scratch.iter_mut().skip(1)) {
            let factor = FieldElement::conditional_select(
                value,
                &FieldElement::ONE,
                value.normalizes_to_zero(),
            );
            product = product.mul(&factor);
            *prefix = product;
        }
        let mut suffix = product.invert().unwrap_or(FieldElement::ONE);
        for i in (1..values.len()).rev() {
            let value = &mut values[i];
            let zero = value.normalizes_to_zero();
            let factor = FieldElement::conditional_select(value, &FieldElement::ONE, zero);
            let inverse = scratch[i - 1].mul(&suffix);
            suffix = suffix.mul(&factor);
            *value = FieldElement::conditional_select(&inverse, &FieldElement::ZERO, zero);
        }
        values[0] = FieldElement::conditional_select(
            &suffix,
            &FieldElement::ZERO,
            first.normalizes_to_zero(),
        );
        Ok(())
    }
}

/// Normalize internal homogeneous points using one inversion and N prefixes.
/// Coordinates stay private to the engine and never expose k256 layout.
#[cfg(test)]
pub(crate) fn normalize_in_place(
    points: &mut [crate::coordinates::ProjectivePoint],
    prefixes: &mut [FieldElement],
) -> Result<(), Error> {
    use crate::coordinates::ProjectivePoint;
    if points.len() > MAX_BATCH {
        return Err(Error::BatchTooLarge);
    }
    if prefixes.len() < points.len() {
        return Err(Error::ScratchTooSmall);
    }
    if points.is_empty() {
        return Ok(());
    }
    let masked = |z: &FieldElement| {
        FieldElement::conditional_select(z, &FieldElement::ONE, z.normalizes_to_zero())
    };
    let mut product = masked(&points[0].z);
    prefixes[0] = product;
    for i in 1..points.len() {
        product = product.mul(&masked(&points[i].z));
        prefixes[i] = product;
    }
    let mut inverse = product.invert().unwrap_or(FieldElement::ONE);
    for i in (0..points.len()).rev() {
        let z = points[i].z;
        let zi = if i == 0 {
            inverse
        } else {
            prefixes[i - 1].mul(&inverse)
        };
        if i > 0 {
            inverse = inverse.mul(&masked(&z));
        }
        let normalized = ProjectivePoint {
            x: points[i].x.mul(&zi).normalize(),
            y: points[i].y.mul(&zi).normalize(),
            z: FieldElement::ONE,
        };
        points[i] = ProjectivePoint::conditional_select(
            &normalized,
            &ProjectivePoint::IDENTITY,
            z.normalizes_to_zero(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinates::{Affine, ProjectivePoint};
    #[test]
    fn homogeneous_normalization_handles_zero_mixed_and_capacity() {
        let base = Affine::from_k256(&k256::AffinePoint::GENERATOR);
        let mut points = [ProjectivePoint::IDENTITY; 16];
        let mut expected = [k256::AffinePoint::IDENTITY; 16];
        for i in 1..16 {
            let point = ProjectivePoint::IDENTITY.add_mixed(&base);
            let scale = FieldElement::from((i + 1) as u64);
            points[i] = ProjectivePoint {
                x: point.x * scale,
                y: point.y * scale,
                z: point.z * scale,
            };
            expected[i] = k256::AffinePoint::GENERATOR;
        }
        let before = points;
        assert_eq!(
            normalize_in_place(&mut points, &mut [FieldElement::ZERO; 15]),
            Err(Error::ScratchTooSmall)
        );
        for (a, b) in points.iter().zip(before) {
            assert_eq!(a.to_k256(), b.to_k256());
        }
        normalize_in_place(&mut points, &mut [FieldElement::ZERO; 16]).unwrap();
        for (point, expected) in points.iter().zip(expected) {
            assert_eq!(point.to_k256(), expected);
        }
        let mut zeros = [ProjectivePoint::IDENTITY; 16];
        normalize_in_place(&mut zeros, &mut [FieldElement::ZERO; 16]).unwrap();
        assert!(zeros
            .iter()
            .all(|point| bool::from(point.z.normalizes_to_zero())));
        normalize_in_place(&mut [], &mut []).unwrap();
    }
}
