use silentwire::{
    compressed,
    input::PreparedTransaction,
    k256::{elliptic_curve::ops::MulByGenerator, ProjectivePoint},
    scalar,
    sender::{aggregate_secret, create_outputs, Recipient, SenderInput},
    tagged_hash, SpScannerNaive,
};

#[test]
fn differential_scanning_parity_across_engines() {
    let scan_priv = scalar([0x42; 32]).unwrap();
    let spend_priv = scalar([0x55; 32]).unwrap();
    let spend_pub = (ProjectivePoint::GENERATOR * spend_priv).to_affine();
    let spend_pub_bytes = compressed(&spend_pub).unwrap();

    let labels = [10u32, 20u32];
    let scanner_unlabeled =
        SpScannerNaive::new(scan_priv.to_bytes().into(), spend_pub_bytes, &[]).unwrap();
    let scanner_labeled =
        SpScannerNaive::new(scan_priv.to_bytes().into(), spend_pub_bytes, &labels).unwrap();

    let tx_count = 16;
    let mut transactions = Vec::with_capacity(tx_count);
    let mut all_outputs = Vec::with_capacity(tx_count);

    for i in 0..tx_count {
        let input_bytes = [((i + 1) * 3) as u8; 32];
        let sender_input = SenderInput {
            secret: input_bytes,
            is_taproot: false,
        };
        let outpoint = [i as u8; 36];

        let mut recipients = Vec::new();
        if i % 3 == 0 {
            recipients.push(Recipient {
                scan: (ProjectivePoint::GENERATOR * scan_priv).to_affine(),
                spend: spend_pub,
            });
        }
        if i % 4 == 0 {
            let label_tweak = scalar(tagged_hash(
                b"BIP0352/Label",
                &[&scan_priv.to_bytes(), &10u32.to_be_bytes()],
            ))
            .unwrap();
            let labeled_spend = (ProjectivePoint::from(spend_pub)
                + ProjectivePoint::GENERATOR * label_tweak)
                .to_affine();
            recipients.push(Recipient {
                scan: (ProjectivePoint::GENERATOR * scan_priv).to_affine(),
                spend: labeled_spend,
            });
        }

        let dummy_priv = scalar([0xdd; 32]).unwrap();
        let dummy_pub = (ProjectivePoint::GENERATOR * dummy_priv).to_affine();
        recipients.push(Recipient {
            scan: dummy_pub,
            spend: dummy_pub,
        });

        let outputs = create_outputs(&[sender_input], &[outpoint], &recipients).unwrap();

        let sum = aggregate_secret(&[sender_input]).unwrap();
        let aggregate = ProjectivePoint::mul_by_generator(&sum).to_affine();
        let input_hash = scalar(tagged_hash(
            b"BIP0352/Inputs",
            &[&outpoint, &compressed(&aggregate).unwrap()],
        ))
        .unwrap();
        let tweak = ProjectivePoint::from(aggregate) * input_hash;

        transactions.push(PreparedTransaction {
            aggregate,
            input_hash,
            tweak,
        });
        all_outputs.push(outputs);
    }

    let output_slices: Vec<&[[u8; 32]]> = all_outputs.iter().map(Vec::as_slice).collect();

    for scanner in [&scanner_unlabeled, &scanner_labeled] {
        let mut sequential = Vec::new();
        let mut single_glv = Vec::new();

        for (tx, outputs) in transactions.iter().zip(&all_outputs) {
            let seq_matches = scanner.scan_prepared(tx, outputs).unwrap();
            let glv_matches = scanner.scan_prepared_glv(tx, outputs).unwrap();
            assert_eq!(seq_matches, glv_matches);
            sequential.push(seq_matches);
            single_glv.push(glv_matches);
        }

        let batch_glv = scanner
            .scan_batch_glv(&transactions, &output_slices)
            .unwrap();

        assert_eq!(sequential, single_glv);
        assert_eq!(sequential, batch_glv);

        let total_matches: usize = batch_glv.iter().map(Vec::len).sum();
        assert!(total_matches > 0);
    }
}
