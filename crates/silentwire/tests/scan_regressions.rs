use silentwire::{
    compressed,
    input::PreparedTransaction,
    k256::{ProjectivePoint, Scalar},
    scalar, tagged_hash, SpScannerNaive,
};

#[test]
fn missing_k_stops_scanning_and_empty_batches_are_valid() {
    let scan = scalar([1; 32]).unwrap();
    let spend = ProjectivePoint::GENERATOR * Scalar::from(31u64);
    let scanner = SpScannerNaive::new(
        scan.to_bytes().into(),
        compressed(&spend.to_affine()).unwrap(),
        &[],
    )
    .unwrap();
    let prepared = PreparedTransaction {
        aggregate: ProjectivePoint::GENERATOR.to_affine(),
        input_hash: Scalar::ONE,
        tweak: ProjectivePoint::GENERATOR,
    };
    let shared = compressed(&scanner.shared_secret(&prepared)).unwrap();
    let keys: Vec<[u8; 32]> = [2u32, 0]
        .iter()
        .map(|k| {
            let tweak = scalar(tagged_hash(
                b"BIP0352/SharedSecret",
                &[&shared, &k.to_be_bytes()],
            ))
            .unwrap();
            compressed(&(spend + ProjectivePoint::GENERATOR * tweak).to_affine()).unwrap()[1..]
                .try_into()
                .unwrap()
        })
        .collect();
    let found = scanner.scan_prepared(&prepared, &keys).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].output_index, 1);
    assert_eq!(found[0].derivation_index, 0);
    assert!(scanner.scan_batch(&[], &[]).unwrap().is_empty());
}

#[test]
fn scan_context_reuse_preserves_matches_and_clears_state() {
    use silentwire::ScanContext;

    let scan = scalar([7; 32]).unwrap();
    let spend = ProjectivePoint::GENERATOR * Scalar::from(42u64);
    let scanner = SpScannerNaive::new(
        scan.to_bytes().into(),
        compressed(&spend.to_affine()).unwrap(),
        &[100, 200],
    )
    .unwrap();
    let prepared = PreparedTransaction {
        aggregate: ProjectivePoint::GENERATOR.to_affine(),
        input_hash: Scalar::ONE,
        tweak: ProjectivePoint::GENERATOR * Scalar::from(5u64),
    };
    let shared = compressed(&scanner.shared_secret(&prepared)).unwrap();
    let tweak0 = scalar(tagged_hash(
        b"BIP0352/SharedSecret",
        &[&shared, &0u32.to_be_bytes()],
    ))
    .unwrap();
    let match_key: [u8; 32] =
        compressed(&(spend + ProjectivePoint::GENERATOR * tweak0).to_affine()).unwrap()[1..]
            .try_into()
            .unwrap();

    let txs = [prepared.clone(), prepared.clone()];
    let outputs1 = [match_key, [0xaa; 32]];
    let outputs2 = [[0xbb; 32]];
    let outputs_refs: [&[[u8; 32]]; 2] = [&outputs1, &outputs2];

    let mut ctx = ScanContext::with_capacity(4, 3);
    scanner
        .scan_batch_into(&txs, &outputs_refs, &mut ctx)
        .unwrap();

    assert_eq!(ctx.results().len(), 2);
    assert_eq!(ctx.results()[0].len(), 1);
    assert_eq!(ctx.results()[0][0].derivation_index, 0);
    assert_eq!(ctx.results()[0][0].output_index, 0);
    assert!(ctx.results()[1].is_empty());

    // Second batch with 0 matches to verify no leftover state
    let empty_outputs: [&[[u8; 32]]; 1] = [&outputs2];
    scanner
        .scan_batch_into(&txs[..1], &empty_outputs, &mut ctx)
        .unwrap();
    assert_eq!(ctx.results().len(), 1);
    assert!(ctx.results()[0].is_empty());
    assert!(ctx.results_capacity() >= 2);
}
