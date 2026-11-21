use bitcoin_hashes::{hash160, Hash};
use silentwire::{
    compressed,
    input::{extract_key, PreparedTransaction, ValidatedInput},
    k256::{AffinePoint, ProjectivePoint, Scalar},
    scalar,
    ssmb::{GlvScalar, GLV_TABLE_SIZE},
    tagged_hash, SpScannerNaive, ADAPTIVE_LABEL_THRESHOLD,
};

#[test]
fn p2pkh_push_boundary_and_p2sh_p2wpkh_consensus_checks() {
    let pubkey_aff = (ProjectivePoint::GENERATOR * Scalar::from(42u64)).to_affine();
    let pubkey = compressed(&pubkey_aff).unwrap();
    let pk_hash = *hash160::Hash::hash(&pubkey).as_byte_array();

    // Standard P2PKH scriptPubKey
    let mut p2pkh_spk = vec![0x76, 0xa9, 0x14];
    p2pkh_spk.extend_from_slice(&pk_hash);
    p2pkh_spk.extend_from_slice(&[0x88, 0xac]);

    // 1. Crafted malleated trap: 33-byte pubkey bytes embedded INSIDE a 40-byte push
    //    (not a standalone 33-byte push item). Opcode-aware parsing MUST reject it.
    let mut trapped_sig = vec![40u8, 0xaa, 0xbb, 0xcc];
    trapped_sig.extend_from_slice(&pubkey);
    trapped_sig.extend_from_slice(&[0xdd, 0xee, 0xff, 0x11]);
    let trapped_in = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &p2pkh_spk,
        script_sig: &trapped_sig,
        witness: &[],
    };
    assert_eq!(extract_key(&trapped_in).unwrap(), None);

    // 2. Valid legacy P2PKH using OP_PUSHDATA1 (0x4c 0x21 <33B pubkey>)
    let mut pushdata1_sig = vec![0x01, 0x01, 0x4c, 0x21];
    pushdata1_sig.extend_from_slice(&pubkey);
    let pd1_in = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &p2pkh_spk,
        script_sig: &pushdata1_sig,
        witness: &[],
    };
    assert_eq!(extract_key(&pd1_in).unwrap(), Some(pubkey_aff));

    // 3. Valid malleated P2PKH with <dummy> OP_DROP <sig> <pubkey>
    let mut malleated_sig = vec![0x01, 0x00, 0x75, 0x02, 0x30, 0x00, 0x21];
    malleated_sig.extend_from_slice(&pubkey);
    let mal_in = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &p2pkh_spk,
        script_sig: &malleated_sig,
        witness: &[],
    };
    assert_eq!(extract_key(&mal_in).unwrap(), Some(pubkey_aff));

    // 4. P2SH-P2WPKH: valid direct push + matching HASH160 + witness len 2
    let mut redeem = vec![0x00, 0x14];
    redeem.extend_from_slice(&pk_hash);
    let redeem_hash = *hash160::Hash::hash(&redeem).as_byte_array();
    let mut p2sh_spk = vec![0xa9, 0x14];
    p2sh_spk.extend_from_slice(&redeem_hash);
    p2sh_spk.push(0x87);

    let mut direct_push_sig = vec![0x16];
    direct_push_sig.extend_from_slice(&redeem);
    let sig_dummy: &[u8] = &[0x30, 0x01];
    let pk_slice: &[u8] = &pubkey;
    let valid_nested = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &p2sh_spk,
        script_sig: &direct_push_sig,
        witness: &[sig_dummy, pk_slice],
    };
    assert_eq!(extract_key(&valid_nested).unwrap(), Some(pubkey_aff));

    // 5. P2SH-P2WPKH with WRONG redeem HASH160 MUST return None
    let mut wrong_spk = p2sh_spk.clone();
    wrong_spk[2] ^= 0xff;
    let bad_hash_nested = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &wrong_spk,
        script_sig: &direct_push_sig,
        witness: &[sig_dummy, pk_slice],
    };
    assert_eq!(extract_key(&bad_hash_nested).unwrap(), None);

    // 6. P2SH-P2WPKH with OP_PUSHDATA1 (non-minimal, BIP-141 invalid) MUST return None
    let mut pd1_nested_sig = vec![0x4c, 0x16];
    pd1_nested_sig.extend_from_slice(&redeem);
    let pd1_nested = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &p2sh_spk,
        script_sig: &pd1_nested_sig,
        witness: &[sig_dummy, pk_slice],
    };
    assert_eq!(extract_key(&pd1_nested).unwrap(), None);

    // 7. P2SH-P2WPKH and P2WPKH with witness.len() != 2 MUST return None
    let bad_wit_nested = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &p2sh_spk,
        script_sig: &direct_push_sig,
        witness: &[pk_slice],
    };
    assert_eq!(extract_key(&bad_wit_nested).unwrap(), None);

    let bad_wit_3 = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &redeem,
        script_sig: &[],
        witness: &[sig_dummy, sig_dummy, pk_slice],
    };
    assert_eq!(extract_key(&bad_wit_3).unwrap(), None);
}

#[test]
fn adaptive_label_mode_a_and_mode_b_exact_parity() {
    let scan_priv = [0x29u8; 32];
    let spend_priv = [0x37u8; 32];
    let scan_sc = scalar(scan_priv).unwrap();
    let spend_sc = scalar(spend_priv).unwrap();
    let spend_pt = (ProjectivePoint::GENERATOR * spend_sc).to_affine();
    let spend_pub = compressed(&spend_pt).unwrap();

    let tweak_pt = (ProjectivePoint::GENERATOR * Scalar::from(99991u64)).to_affine();
    let prepared = PreparedTransaction {
        aggregate: tweak_pt,
        input_hash: Scalar::ONE,
        tweak: ProjectivePoint::from(tweak_pt),
    };
    let shared_aff = (ProjectivePoint::from(tweak_pt) * scan_sc).to_affine();
    let shared_bytes = compressed(&shared_aff).unwrap();

    // Cover both sides of ADAPTIVE_LABEL_THRESHOLD (8): Mode A (1, 8) and Mode B (9, 32).
    assert_eq!(ADAPTIVE_LABEL_THRESHOLD, 8);
    for label_count in [1u32, 8, 9, 32] {
        let labels: Vec<u32> = (0..label_count).collect();
        let scanner = SpScannerNaive::new(scan_priv, spend_pub, &labels).unwrap();

        // Build outputs: k=0 unlabeled, k=1 change (m=0), k=2 last label (m=label_count-1),
        // plus twist decoy (x=0) and non-canonical x >= p decoy (0xff..ff).
        let mut expected_outputs = Vec::new();
        let specs: &[(u32, Option<u32>)] = &[(0, None), (1, Some(0)), (2, Some(label_count - 1))];
        for &(k, lbl) in specs {
            let tk = scalar(tagged_hash(
                b"BIP0352/SharedSecret",
                &[&shared_bytes, &k.to_be_bytes()],
            ))
            .unwrap();
            let mut total_tweak = tk;
            if let Some(m) = lbl {
                let lm = scalar(tagged_hash(
                    b"BIP0352/Label",
                    &[&scan_priv, &m.to_be_bytes()],
                ))
                .unwrap();
                total_tweak += lm;
            }
            let out_enc = compressed(
                &(ProjectivePoint::from(spend_pt) + ProjectivePoint::GENERATOR * total_tweak)
                    .to_affine(),
            )
            .unwrap();
            let mut x_only = [0u8; 32];
            x_only.copy_from_slice(&out_enc[1..33]);
            expected_outputs.push((k, lbl, x_only, <[u8; 32]>::from(total_tweak.to_bytes())));
        }

        // Permuted vout layout with twist + non-canonical decoys interleaved.
        let tx_outputs = [
            [0x00u8; 32],          // vout 0: quadratic twist decoy
            expected_outputs[2].2, // vout 1: k = 2 labeled
            [0xffu8; 32],          // vout 2: non-canonical x >= p decoy
            expected_outputs[0].2, // vout 3: k = 0 unlabeled
            expected_outputs[1].2, // vout 4: k = 1 change m = 0
        ];

        let single = scanner.scan_prepared_glv(&prepared, &tx_outputs).unwrap();
        let batch = scanner
            .scan_batch_glv(std::slice::from_ref(&prepared), &[tx_outputs.as_slice()])
            .unwrap();
        assert_eq!(
            single, batch[0],
            "single vs batch mismatch for L={label_count}"
        );
        assert_eq!(single.len(), 3, "missing matches for L={label_count}");

        assert_eq!(single[0].derivation_index, 0);
        assert_eq!(single[0].output_index, 3);
        assert_eq!(single[0].label, None);
        assert_eq!(single[0].tweak_scalar, expected_outputs[0].3);

        assert_eq!(single[1].derivation_index, 1);
        assert_eq!(single[1].output_index, 4);
        assert_eq!(single[1].label, Some(0));
        assert_eq!(single[1].tweak_scalar, expected_outputs[1].3);

        assert_eq!(single[2].derivation_index, 2);
        assert_eq!(single[2].output_index, 1);
        assert_eq!(single[2].label, Some(label_count - 1));
        assert_eq!(single[2].tweak_scalar, expected_outputs[2].3);
    }
}

#[test]
fn fused_glv_batch_matches_scalar_mul_with_identity_points() {
    let k = Scalar::from(0x0123_4567_89ab_cdef_u64).invert().unwrap();
    let glv = GlvScalar::new(&k);
    for count in [1usize, 2, 4, 5, 16, 17, 64, 65, 130] {
        let bases: Vec<ProjectivePoint> = (0..count)
            .map(|i| {
                if i % 11 == 0 {
                    ProjectivePoint::IDENTITY
                } else {
                    ProjectivePoint::GENERATOR * Scalar::from((i + 3) as u64)
                }
            })
            .collect();
        let mut out = vec![ProjectivePoint::IDENTITY; count];
        let mut tables = vec![AffinePoint::IDENTITY; count * GLV_TABLE_SIZE];
        glv.multiply_into(&bases, &mut out, &mut tables).unwrap();
        for (i, (got, base)) in out.iter().zip(&bases).enumerate() {
            let expected = *base * k;
            assert_eq!(
                got.to_affine(),
                expected.to_affine(),
                "fused GLV mismatch at count={count}, idx={i}"
            );
        }
    }
}
