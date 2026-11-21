use bdk_silentwire::ctis::{CompactTweakBlock, CtisError};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use silentwire::k256::elliptic_curve::sec1::ToEncodedPoint;
use silentwire::k256::AffinePoint;
use silentwire::SpScannerNaive;

#[test]
fn ctis_encode_decode_roundtrip() {
    let block_hash = BlockHash::from_byte_array([0x42; 32]);
    let height = 840_000;

    let gen_affine = AffinePoint::GENERATOR;
    let gen_bytes: [u8; 33] = gen_affine
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    let candidate_tweaks = vec![gen_bytes, gen_bytes];
    let gcs_filter_bytes = vec![0x01, 0x02, 0x03, 0x04];

    let block = CompactTweakBlock::new(height, block_hash, candidate_tweaks, gcs_filter_bytes);
    let encoded = block.encode();

    // 4 height + 32 hash + 1 count + 66 tweaks + 1 filter len + 4 filter = 108 bytes.
    assert_eq!(encoded.len(), 4 + 32 + 1 + 66 + 1 + 4);

    let decoded = CompactTweakBlock::decode(&encoded).expect("valid CTIS decode");
    assert_eq!(decoded, block);
}

#[test]
fn ctis_twist_point_rejection() {
    let block_hash = BlockHash::from_byte_array([0x55; 32]);
    let height = 800_000;

    let mut twist_point = [0u8; 33];
    twist_point[0] = 0x02; // x = 0 is on the quadratic twist

    let block = CompactTweakBlock::new(height, block_hash, vec![twist_point], Vec::new());
    assert_eq!(
        block.validate_points(),
        Err(CtisError::TwistPointDetected(0))
    );
}

#[test]
fn ctis_malformed_point_rejection() {
    let block_hash = BlockHash::from_byte_array([0x77; 32]);
    let height = 800_001;

    let mut invalid_prefix_point = [0u8; 33];
    invalid_prefix_point[0] = 0x04; // uncompressed prefix invalid in CTIS

    let block = CompactTweakBlock::new(height, block_hash, vec![invalid_prefix_point], Vec::new());
    assert_eq!(block.validate_points(), Err(CtisError::MalformedPoint(0)));
}

#[test]
fn ctis_candidate_scanning_integration() {
    let scan_priv = [0x11; 32];
    let spend_affine = AffinePoint::GENERATOR;
    let spend_bytes: [u8; 33] = spend_affine
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    let scanner = SpScannerNaive::new(scan_priv, spend_bytes, &[]).expect("valid scanner");

    let tweak_affine = AffinePoint::GENERATOR;
    let tweak_bytes: [u8; 33] = tweak_affine
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    let block_hash = BlockHash::from_byte_array([0x33; 32]);
    let block = CompactTweakBlock::new(820_000, block_hash, vec![tweak_bytes], Vec::new());

    // Derive the expected output script from the shared secret directly.
    let shared = scanner.shared_secret_from_tweak(&tweak_affine);
    let candidate_scripts = scanner
        .derive_candidate_scripts_for_shared(&shared, 1)
        .expect("valid candidate scripts");
    assert!(!candidate_scripts.is_empty());

    let target_outpoint: [u8; 32] = candidate_scripts[0][2..34].try_into().unwrap();
    let tx_outputs = [target_outpoint];
    let outputs_per_tweak: Vec<&[[u8; 32]]> = vec![&tx_outputs];

    let matches = block
        .scan_candidates(&scanner, &outputs_per_tweak)
        .expect("successful candidate scan");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].len(), 1);
    assert_eq!(matches[0][0].taproot_pubkey, target_outpoint);
}

#[test]
fn ctis_decode_rejects_oversized_compactsize_non_minimal_and_trailing_bytes() {
    // 41-byte packet claiming tweaks_count = u32::MAX must fail without allocating.
    let mut oom_u32 = vec![0u8; 36];
    oom_u32.push(0xfe);
    oom_u32.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        CompactTweakBlock::decode(&oom_u32),
        Err(CtisError::UnexpectedEof)
    );

    // 45-byte packet claiming tweaks_count = u64::MAX.
    let mut oom_u64 = vec![0u8; 36];
    oom_u64.push(0xff);
    oom_u64.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        CompactTweakBlock::decode(&oom_u64),
        Err(CtisError::UnexpectedEof)
    );

    // Oversized filter_len = u32::MAX after 0 tweaks tests checked cursor addition.
    let mut oom_filter = vec![0u8; 36];
    oom_filter.push(0x00); // 0 tweaks
    oom_filter.push(0xfe);
    oom_filter.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        CompactTweakBlock::decode(&oom_filter),
        Err(CtisError::UnexpectedEof)
    );

    // Non-minimal CompactSize encoding (0xfd 0x01 0x00 for value 1).
    let mut non_minimal = vec![0u8; 36];
    non_minimal.extend_from_slice(&[0xfd, 0x01, 0x00]);
    non_minimal.extend_from_slice(&[0x02; 33]);
    non_minimal.push(0x00);
    assert_eq!(
        CompactTweakBlock::decode(&non_minimal),
        Err(CtisError::MalformedCompactSize)
    );

    // Trailing garbage byte after filter payload.
    let mut trailing = vec![0u8; 36];
    trailing.push(0x00); // 0 tweaks
    trailing.push(0x00); // 0 filter bytes
    trailing.push(0xff); // unexpected trailing byte
    assert_eq!(
        CompactTweakBlock::decode(&trailing),
        Err(CtisError::UnexpectedEof)
    );
}
