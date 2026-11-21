use silentwire::k256::elliptic_curve::sec1::ToEncodedPoint;
use silentwire::k256::{AffinePoint, ProjectivePoint};
use silentwire::{compressed, scalar, tagged_hash, EmbeddedStaticScanner, Error};

#[test]
fn embedded_static_scanner_memory_footprint() {
    let footprint_16 = EmbeddedStaticScanner::<16, 64, 8>::memory_footprint();
    let footprint_32 = EmbeddedStaticScanner::<32, 64, 8>::memory_footprint();
    println!(
        "host EmbeddedStaticScanner<16,64,8> bytes={footprint_16}, <32,64,8> bytes={footprint_32}"
    );
    assert!(
        footprint_16 < 16 * 1024,
        "Footprint {footprint_16} bytes exceeds 16KB budget"
    );
    assert!(
        footprint_32 < 16 * 1024,
        "Footprint {footprint_32} bytes exceeds 16KB budget"
    );
}

#[test]
fn embedded_static_scanner_exact_match_change_isolation_and_twist_rejection() {
    let scan_priv = [
        0x0f, 0x69, 0x4e, 0x06, 0x80, 0x28, 0xa7, 0x17, 0xf8, 0xaf, 0x6b, 0x94, 0x11, 0xf9, 0xa1,
        0x33, 0xdd, 0x35, 0x65, 0x25, 0x87, 0x14, 0xcc, 0x22, 0x65, 0x94, 0xb3, 0x4d, 0xb9, 0x0c,
        0x1f, 0x2c,
    ];
    let spend_pub = [
        0x02, 0x5c, 0xc9, 0x85, 0x6d, 0x6f, 0x83, 0x75, 0x35, 0x0e, 0x12, 0x39, 0x78, 0xda, 0xac,
        0x20, 0x0c, 0x26, 0x0c, 0xb5, 0xb5, 0xae, 0x83, 0x10, 0x6c, 0xab, 0x90, 0x48, 0x4d, 0xcd,
        0x8f, 0xcf, 0x36,
    ];
    let tweak = [
        0x02, 0x4a, 0xc2, 0x53, 0xc2, 0x16, 0x53, 0x2e, 0x96, 0x19, 0x88, 0xe2, 0xa8, 0xce, 0x26,
        0x6a, 0x44, 0x7c, 0x89, 0x4c, 0x78, 0x1e, 0x52, 0xef, 0x6c, 0xee, 0x90, 0x23, 0x61, 0xdb,
        0x96, 0x00, 0x04,
    ];
    let expected_out = [
        0x3e, 0x9f, 0xce, 0x73, 0xd4, 0xe7, 0x7a, 0x48, 0x09, 0x90, 0x8e, 0x3c, 0x3a, 0x2e, 0x54,
        0xee, 0x14, 0x7b, 0x93, 0x12, 0xdc, 0x50, 0x44, 0xa1, 0x93, 0xd1, 0xfc, 0x85, 0xde, 0x46,
        0xe3, 0xc1,
    ];
    let expected_tweak = [
        0xf4, 0x38, 0xb4, 0x01, 0x79, 0xa3, 0xc4, 0x26, 0x2d, 0xe1, 0x29, 0x86, 0xc0, 0xe6, 0xcc,
        0xe0, 0x63, 0x40, 0x07, 0xcd, 0xc7, 0x9c, 0x1d, 0xcd, 0x3e, 0x20, 0xb9, 0xeb, 0xc2, 0xe7,
        0xee, 0xf6,
    ];

    // Also compute a mandatory m = 0 change output at k = 1 for the same tweak.
    let scan_sc = scalar(scan_priv).unwrap();
    let spend_pt = silentwire::point(&spend_pub).unwrap();
    let tweak_pt = silentwire::point(&tweak).unwrap();
    let shared = compressed(&(ProjectivePoint::from(tweak_pt) * scan_sc).to_affine()).unwrap();
    let t1 = scalar(tagged_hash(
        b"BIP0352/SharedSecret",
        &[&shared, &1u32.to_be_bytes()],
    ))
    .unwrap();
    let label0 = scalar(tagged_hash(
        b"BIP0352/Label",
        &[&scan_priv, &0u32.to_be_bytes()],
    ))
    .unwrap();
    let change_k1_enc = compressed(
        &(ProjectivePoint::from(spend_pt) + ProjectivePoint::GENERATOR * (t1 + label0)).to_affine(),
    )
    .unwrap();
    let mut change_k1 = [0u8; 32];
    change_k1.copy_from_slice(&change_k1_enc[1..33]);

    let mut scanner =
        EmbeddedStaticScanner::<8, 16, 4>::new(scan_priv, spend_pub).expect("valid init");

    // Tx 0: unlabeled k = 0 at vout 1, m = 0 change k = 1 at vout 2
    scanner.add_tweak(&tweak).expect("valid tweak add");
    scanner.add_output(&[0x11; 32]).expect("dummy 1");
    scanner.add_output(&expected_out).expect("real output");
    scanner.add_output(&change_k1).expect("change m=0 output");

    // Tx 1 uses a different tweak and must not cross-match Tx 0 outputs.
    let gen_bytes: [u8; 33] = AffinePoint::GENERATOR
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    scanner.add_tweak(&gen_bytes).expect("second tweak");
    scanner.add_output(&[0x22; 32]).expect("tx1 dummy");

    let matches = scanner.scan().expect("successful scan");
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].output_index, 1);
    assert_eq!(matches[0].derivation_index, 0);
    assert_eq!(matches[0].label, None);
    assert_eq!(matches[0].taproot_pubkey, expected_out);
    assert_eq!(matches[0].tweak_scalar, expected_tweak);

    assert_eq!(matches[1].output_index, 2);
    assert_eq!(matches[1].derivation_index, 1);
    assert_eq!(matches[1].label, Some(0));
    assert_eq!(matches[1].taproot_pubkey, change_k1);
    assert_eq!(
        matches[1].tweak_scalar,
        <[u8; 32]>::from((t1 + label0).to_bytes())
    );

    // Streaming scan_tx recovers both outputs without touching internal tweak buffer
    let stream_matches = scanner
        .scan_tx(&tweak, &[change_k1, expected_out])
        .expect("scan_tx");
    assert_eq!(stream_matches.len(), 2);
    assert_eq!(stream_matches[0].derivation_index, 0);
    assert_eq!(stream_matches[0].output_index, 1);
    assert_eq!(stream_matches[1].derivation_index, 1);
    assert_eq!(stream_matches[1].label, Some(0));
    assert_eq!(stream_matches[1].output_index, 0);

    // Reject quadratic twist point
    let mut twist_point = [0u8; 33];
    twist_point[0] = 0x02;
    assert_eq!(scanner.add_tweak(&twist_point), Err(Error::InvalidPoint));

    scanner.clear();
    let empty_matches = scanner.scan().expect("empty scan");
    assert_eq!(empty_matches.len(), 0);
}

#[test]
fn embedded_static_scanner_capacity_bounds() {
    let spend_aff = AffinePoint::GENERATOR;
    let spend_pub: [u8; 33] = spend_aff
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let scan_priv = [0x42; 32];

    let mut scanner =
        EmbeddedStaticScanner::<2, 2, 2>::new(scan_priv, spend_pub).expect("valid init");

    let tweak: [u8; 33] = spend_aff
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    assert!(scanner.add_tweak(&tweak).is_ok());
    assert!(scanner.add_tweak(&tweak).is_ok());
    assert_eq!(scanner.add_tweak(&tweak), Err(Error::BatchTooLarge));

    assert!(scanner.add_output(&[0xaa; 32]).is_ok());
    assert!(scanner.add_output(&[0xbb; 32]).is_ok());
    assert_eq!(scanner.add_output(&[0xcc; 32]), Err(Error::BatchTooLarge));
}
