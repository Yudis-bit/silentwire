mod support;

#[test]
fn replay_100000_transactions_against_independent_derivation() {
    let mut context = silentwire::ScanContext::new();
    for index in 0..100000 {
        let case = support::case(352, index);
        // Keep the serialized provenance consumed by the external reference replay.
        assert_eq!(case.outpoint.len(), 36);
        assert_eq!(
            silentwire::tagged_hash(b"BIP0352/Inputs", &[&case.outpoint, &case.aggregate]),
            case.input_hash
        );
        support::scan(&mut context, &case);
    }
}
