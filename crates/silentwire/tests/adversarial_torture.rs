use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, FieldElement, ProjectivePoint, Scalar};
use silentwire::{
    batch::MontgomeryBatchInverter, compressed, input::PreparedTransaction, matcher::CuckooFilter,
    scalar, tagged_hash, ScanContext, SpScannerNaive,
};
use subtle::ConstantTimeEq;

#[test]
fn glv_decomposition_boundary_torture() {
    let minus_lambda_bytes: [u8; 32] = [
        0xac, 0x9c, 0x52, 0xb3, 0x3f, 0xa3, 0xcf, 0x1f, 0x5a, 0xd9, 0xe3, 0xfd, 0x77, 0xed, 0x9b,
        0xa4, 0xa8, 0x80, 0xb9, 0xfc, 0x8e, 0xc7, 0x39, 0xc2, 0xe0, 0xcf, 0xc8, 0x10, 0xb5, 0x12,
        0x83, 0xcf,
    ];
    let _minus_lambda = Scalar::from_repr(minus_lambda_bytes.into()).unwrap();

    // Boundary scalars including 1, 2, 3, -1, -2, and alternating bit patterns.
    let test_scalars = [
        Scalar::ONE,
        Scalar::from(2u64),
        Scalar::from(3u64),
        Scalar::from(0xdeadbeef_u64),
        -Scalar::ONE,
        -Scalar::from(2u64),
        Scalar::from_repr([0x7f; 32].into()).unwrap(),
        Scalar::from_repr([0x55; 32].into()).unwrap(),
        Scalar::from_repr([0xaa; 32].into()).unwrap(),
    ];

    let base = ProjectivePoint::GENERATOR;
    for (i, &k) in test_scalars.iter().enumerate() {
        let glv = silentwire::ssmb::GlvScalar::new(&k);
        let mut out = [ProjectivePoint::IDENTITY];
        let mut scratch = [AffinePoint::IDENTITY; silentwire::ssmb::GLV_TABLE_SIZE];
        glv.multiply_into(&[base], &mut out, &mut scratch)
            .expect("GLV mult should succeed");

        let reference = base * k;
        assert_eq!(
            out[0].to_affine(),
            reference.to_affine(),
            "GLV multiplication mismatch for scalar index {i}"
        );
    }
}

#[test]
fn montgomery_batch_torture_all_zeros_and_sparse_patterns() {
    let mut zeros = [FieldElement::ZERO; 16];
    let mut scratch = [FieldElement::ZERO; 16];
    MontgomeryBatchInverter::invert(&mut zeros, &mut scratch).unwrap();
    for (i, z) in zeros.iter().enumerate() {
        assert!(
            bool::from(z.normalizes_to_zero()),
            "Expected 0 at index {i}, got non-zero"
        );
    }

    let mut checker = [FieldElement::ZERO; 32];
    let mut scratch32 = [FieldElement::ZERO; 32];
    for (i, elem) in checker.iter_mut().enumerate() {
        if i % 2 == 1 {
            let mut b = [0u8; 32];
            b[31] = (i as u8) + 1;
            *elem = FieldElement::from_bytes(&b.into()).unwrap();
        }
    }
    let original = checker;
    MontgomeryBatchInverter::invert(&mut checker, &mut scratch32).unwrap();
    for i in 0..32 {
        if i % 2 == 0 {
            assert!(bool::from(checker[i].normalizes_to_zero()));
        } else {
            let prod = original[i].mul(&checker[i]).normalize();
            assert!(
                bool::from(prod.ct_eq(&FieldElement::ONE)),
                "Inverse mismatch at checker index {i}"
            );
        }
    }

    let mut sparse = [FieldElement::ZERO; 64];
    let mut scratch64 = [FieldElement::ZERO; 64];
    let target_val = FieldElement::from_bytes(&[0x42; 32].into()).unwrap();
    sparse[37] = target_val;
    MontgomeryBatchInverter::invert(&mut sparse, &mut scratch64).unwrap();
    assert!(bool::from(
        sparse[37]
            .mul(&target_val)
            .normalize()
            .ct_eq(&FieldElement::ONE)
    ));
    for (i, val) in sparse.iter().enumerate() {
        if i != 37 {
            assert!(bool::from(val.normalizes_to_zero()));
        }
    }
}

#[test]
fn cuckoo_saturation_guarantees_zero_false_negatives() {
    let mut filter = CuckooFilter::default();
    let mut keys = Vec::with_capacity(3000);

    // Insert 3000 distinct keys to trigger eviction cascades and saturation.
    for i in 0..3000u32 {
        let mut key = [0u8; 32];
        key[0..4].copy_from_slice(&i.to_le_bytes());
        key[4..8].copy_from_slice(&(!i).to_le_bytes());
        filter.insert(&key);
        keys.push(key);
    }

    assert!(
        filter.saturated(),
        "Filter must saturate under 3000 keys (capacity 2048)"
    );

    // Once saturated, may_contain must always return true.
    for (i, key) in keys.iter().enumerate() {
        assert!(
            filter.may_contain(key),
            "Saturated filter dropped key at index {i}"
        );
    }

    // Clearing restores normal non-saturated state.
    filter.clear();
    assert!(!filter.saturated());
    assert!(!filter.may_contain(&keys[0]));
}

#[test]
fn scan_context_stress_dynamic_shape_reentrancy() {
    let scan = scalar([0x33; 32]).unwrap();
    let spend = ProjectivePoint::GENERATOR * Scalar::from(999u64);
    let scanner = SpScannerNaive::new(
        scan.to_bytes().into(),
        compressed(&spend.to_affine()).unwrap(),
        &[1, 2, 3],
    )
    .unwrap();

    let prepared = PreparedTransaction {
        aggregate: ProjectivePoint::GENERATOR.to_affine(),
        input_hash: Scalar::ONE,
        tweak: ProjectivePoint::GENERATOR * Scalar::from(12345u64),
    };
    let shared = compressed(&scanner.shared_secret(&prepared)).unwrap();
    let tweak0 = scalar(tagged_hash(
        b"BIP0352/SharedSecret",
        &[&shared, &0u32.to_be_bytes()],
    ))
    .unwrap();
    let match_pub: [u8; 32] =
        compressed(&(spend + ProjectivePoint::GENERATOR * tweak0).to_affine()).unwrap()[1..]
            .try_into()
            .unwrap();

    let mut ctx = ScanContext::with_capacity(16, 4);

    // Re-entrancy across changing batch sizes: 1, 4, 0, 7, 2, 0, 1.
    let sizes = [1, 4, 0, 7, 2, 0, 1];
    for &size in &sizes {
        let txs: Vec<PreparedTransaction> = (0..size).map(|_| prepared.clone()).collect();
        let outs_data: Vec<[u8; 32]> = (0..size)
            .map(|i| if i == 0 { match_pub } else { [0xff; 32] })
            .collect();
        let outs_slices: Vec<[[u8; 32]; 1]> = outs_data.iter().map(|&k| [k]).collect();
        let outs_refs: Vec<&[[u8; 32]]> = outs_slices.iter().map(|s| s.as_slice()).collect();

        scanner.scan_batch_into(&txs, &outs_refs, &mut ctx).unwrap();

        assert_eq!(ctx.results().len(), size);
        if size > 0 {
            assert_eq!(ctx.results()[0].len(), 1);
            assert_eq!(ctx.results()[0][0].taproot_pubkey, match_pub);
            for r in &ctx.results()[1..] {
                assert!(r.is_empty());
            }
        }
    }
}
