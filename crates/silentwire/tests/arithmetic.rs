use silentwire::k256::{AffinePoint, FieldElement, ProjectivePoint, Scalar};
use silentwire::{
    batch::MontgomeryBatchInverter,
    matcher::CuckooFilter,
    ssmb::{GlvScalar, SharedScalar, GLV_TABLE_SIZE, TABLE_SIZE},
    Error,
};

fn field(value: u64) -> FieldElement {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Option::from(FieldElement::from_bytes(&bytes.into())).unwrap()
}

#[test]
fn inversion_zero_boundaries_and_scratch_atomicity() {
    for size in [0, 1, 2, 17, 4096] {
        let original: Vec<_> = (0..size).map(|i| field((i % 19) as u64)).collect();
        let mut values = original.clone();
        let mut scratch = vec![FieldElement::ZERO; size];
        MontgomeryBatchInverter::invert(&mut values, &mut scratch).unwrap();
        for (i, (value, original)) in values.iter().zip(original).enumerate() {
            let expected = original.invert().unwrap_or(FieldElement::ZERO);
            assert_eq!(
                value.normalize().to_bytes(),
                expected.normalize().to_bytes(),
                "index {i}"
            );
        }
    }
    let mut values = [field(3), field(7)];
    assert_eq!(
        MontgomeryBatchInverter::invert(&mut values, &mut []),
        Err(Error::ScratchTooSmall)
    );
    assert_eq!(values[0].to_bytes(), field(3).to_bytes());
    assert_eq!(
        MontgomeryBatchInverter::invert(&mut vec![field(1); 4097], &mut []),
        Err(Error::BatchTooLarge)
    );
}

#[test]
fn shared_scalar_reconstructs_even_digits_and_top_bits() {
    let bases = [
        ProjectivePoint::IDENTITY,
        ProjectivePoint::GENERATOR,
        ProjectivePoint::GENERATOR * Scalar::from(17u64),
        -ProjectivePoint::GENERATOR,
    ];
    for scalar in [
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::from(16u64),
        Scalar::from(31u64),
        Scalar::from(32u64),
        Scalar::from(256u64),
        -Scalar::ONE,
    ] {
        let schedule = SharedScalar::new(&scalar);
        let mut output = [ProjectivePoint::IDENTITY; 4];
        schedule
            .multiply_into(
                &bases,
                &mut output,
                &mut vec![ProjectivePoint::IDENTITY; 4 * TABLE_SIZE],
            )
            .unwrap();
        for i in 0..4 {
            assert_eq!(output[i], bases[i] * scalar);
        }
    }
    let mut unchanged = [ProjectivePoint::GENERATOR];
    let schedule = SharedScalar::new(&Scalar::ONE);
    assert_eq!(
        schedule.multiply_into(&bases[..1], &mut unchanged, &mut []),
        Err(Error::ScratchTooSmall)
    );
    assert_eq!(unchanged[0], ProjectivePoint::GENERATOR);
    schedule.multiply_into(&[], &mut [], &mut []).unwrap();
}

#[test]
fn shared_scalar_handles_the_maximum_batch() {
    let bases: Vec<_> = (0..4096)
        .map(|i| match i % 3 {
            0 => ProjectivePoint::IDENTITY,
            1 => ProjectivePoint::GENERATOR,
            _ => -ProjectivePoint::GENERATOR,
        })
        .collect();
    let scalar = -Scalar::ONE;
    let mut output = vec![ProjectivePoint::IDENTITY; bases.len()];
    SharedScalar::new(&scalar)
        .multiply_into(
            &bases,
            &mut output,
            &mut vec![ProjectivePoint::IDENTITY; bases.len() * TABLE_SIZE],
        )
        .unwrap();
    for (base, result) in bases.iter().zip(&output) {
        assert_eq!(*result, -*base);
    }
    let mut rolling = vec![ProjectivePoint::IDENTITY; bases.len()];
    SharedScalar::new(&scalar)
        .multiply_rolling_into(
            &bases,
            &mut rolling,
            &mut vec![ProjectivePoint::IDENTITY; 4 * TABLE_SIZE],
        )
        .unwrap();
    assert_eq!(rolling, output);
    let mut tail = vec![ProjectivePoint::IDENTITY; 7];
    SharedScalar::new(&scalar)
        .multiply_rolling_into(
            &bases[..7],
            &mut tail,
            &mut vec![ProjectivePoint::IDENTITY; 4 * TABLE_SIZE],
        )
        .unwrap();
    assert_eq!(tail, output[..7]);
    assert_eq!(
        SharedScalar::new(&scalar).multiply_into(
            &vec![ProjectivePoint::IDENTITY; 4097],
            &mut [],
            &mut []
        ),
        Err(Error::BatchTooLarge)
    );
}

#[test]
fn cuckoo_saturation_cannot_drop_a_key() {
    assert!(core::mem::size_of::<CuckooFilter>() < 8192);
    assert_eq!(core::mem::align_of::<CuckooFilter>(), 64);
    let mut filter = CuckooFilter::default();
    let keys: Vec<[u8; 32]> = (0..10000u64)
        .map(|i| {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&i.to_le_bytes());
            key
        })
        .collect();
    for key in &keys {
        filter.insert(key);
    }
    assert!(filter.saturated());
    for key in &keys {
        assert!(filter.may_contain(key));
    }
}

#[test]
fn cuckoo_dual_bucket_query_accuracy() {
    let mut filter = CuckooFilter::default();
    let mut inserted = Vec::new();
    for i in 0..100u64 {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(i * 7919).to_le_bytes());
        key[31] = (i % 256) as u8;
        filter.insert(&key);
        inserted.push(key);
    }
    assert!(!filter.saturated());
    for key in &inserted {
        assert!(filter.may_contain(key));
    }
    let mut absent_count = 0;
    for i in 1000..2000u64 {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(i * 104729).to_le_bytes());
        key[30] = 0xee;
        if !filter.may_contain(&key) {
            absent_count += 1;
        }
    }
    assert!(absent_count > 950);
}

#[test]
fn shared_scalar_mixed_addition_parity() {
    let bases = [
        ProjectivePoint::IDENTITY,
        ProjectivePoint::GENERATOR,
        ProjectivePoint::GENERATOR * Scalar::from(42u64),
        -ProjectivePoint::GENERATOR,
    ];
    let scalar = Scalar::from(0xdeadbeefcafebabeu64);
    let schedule = SharedScalar::new(&scalar);
    let mut proj_out = [ProjectivePoint::IDENTITY; 4];
    let mut proj_scratch = [ProjectivePoint::IDENTITY; 4 * TABLE_SIZE];
    schedule
        .multiply_into(&bases, &mut proj_out, &mut proj_scratch)
        .unwrap();

    let mut mixed_out = [ProjectivePoint::IDENTITY; 4];
    let mut mixed_scratch = [AffinePoint::IDENTITY; 4 * TABLE_SIZE];
    schedule
        .multiply_mixed_into(&bases, &mut mixed_out, &mut mixed_scratch)
        .unwrap();
    assert_eq!(proj_out, mixed_out);

    let mut rolling_mixed = [ProjectivePoint::IDENTITY; 4];
    let mut rolling_scratch = [AffinePoint::IDENTITY; 4 * TABLE_SIZE];
    schedule
        .multiply_rolling_mixed_into(&bases, &mut rolling_mixed, &mut rolling_scratch)
        .unwrap();
    assert_eq!(proj_out, rolling_mixed);
}

#[test]
fn glv_scalar_matches_scalar_multiplication_and_shared_scalar() {
    let bases = [
        ProjectivePoint::IDENTITY,
        ProjectivePoint::GENERATOR,
        ProjectivePoint::GENERATOR * Scalar::from(42u64),
        -ProjectivePoint::GENERATOR,
    ];
    for scalar in [
        Scalar::from(1u64),
        Scalar::from(17u64),
        Scalar::from(0xdeadbeefcafebabeu64),
        -Scalar::ONE,
    ] {
        let glv = GlvScalar::new(&scalar);
        let mut glv_out = [ProjectivePoint::IDENTITY; 4];
        let mut glv_scratch = [AffinePoint::IDENTITY; 4 * GLV_TABLE_SIZE];
        glv.multiply_into(&bases, &mut glv_out, &mut glv_scratch)
            .unwrap();

        for i in 0..4 {
            assert_eq!(glv_out[i], bases[i] * scalar, "base {i}");
        }

        let mut rolling_out = [ProjectivePoint::IDENTITY; 4];
        let mut rolling_scratch = [AffinePoint::IDENTITY; 4 * GLV_TABLE_SIZE];
        glv.multiply_rolling_into(&bases, &mut rolling_out, &mut rolling_scratch)
            .unwrap();
        assert_eq!(glv_out, rolling_out);
    }
}
