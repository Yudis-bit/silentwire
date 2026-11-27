//! Official BIP-374 v0.3.1 DLEQ test vectors (`bitcoin/bips/bip-0374`)
//! and BIP-375 canonical ordering regression tests.

use silentwire::{
    bip374::{derive_bip375_outputs, dleq_prove, dleq_verify, Bip375SignerShare},
    compressed,
    k256::{AffinePoint, ProjectivePoint, Scalar},
    point, scalar, Error,
};

fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s)
        .expect("valid hex")
        .try_into()
        .expect("exact length")
}

fn opt_msg(s: &str) -> Option<[u8; 32]> {
    if s.is_empty() {
        None
    } else {
        Some(decode_hex::<32>(s))
    }
}

fn parse_point_or_infinity(s: &str) -> AffinePoint {
    if s == "INFINITY" {
        AffinePoint::IDENTITY
    } else {
        point(&hex::decode(s).expect("valid point hex")).expect("valid point")
    }
}

#[test]
fn bip374_all_14_official_generate_vectors() {
    let csv = include_str!("fixtures/bip374_generate_proof.csv");
    let mut count = 0usize;
    for line in csv.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        assert_eq!(cols.len(), 8, "unexpected CSV row: {line}");
        let idx = cols[0];
        let g = parse_point_or_infinity(cols[1]);
        let a_bytes = decode_hex::<32>(cols[2]);
        let b = parse_point_or_infinity(cols[3]);
        let r = decode_hex::<32>(cols[4]);
        let m = opt_msg(cols[5]);
        let expected = cols[6];
        let comment = cols[7];

        let m_slice = m.as_ref().map(|x| x.as_slice());
        let g_opt = if g == AffinePoint::GENERATOR {
            None
        } else {
            Some(&g)
        };

        if expected == "INVALID" {
            let res = scalar(a_bytes).and_then(|a| dleq_prove(&a, &b, &r, g_opt, m_slice));
            assert!(res.is_err(), "vector {idx} ({comment}) must fail");
        } else {
            let a = scalar(a_bytes).expect("valid scalar");
            let proof = dleq_prove(&a, &b, &r, g_opt, m_slice)
                .unwrap_or_else(|e| panic!("vector {idx} ({comment}) failed: {e:?}"));
            assert_eq!(
                hex::encode(proof),
                expected,
                "proof mismatch on vector {idx} ({comment})"
            );
            // Passing explicit Some(&G) must produce the exact same proof.
            let proof_explicit_g = dleq_prove(&a, &b, &r, Some(&g), m_slice).unwrap();
            assert_eq!(proof_explicit_g, proof);
        }
        count += 1;
    }
    assert_eq!(count, 14);
}

#[test]
fn bip374_all_17_official_verify_vectors() {
    let csv = include_str!("fixtures/bip374_verify_proof.csv");
    let mut count = 0usize;
    for line in csv.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        assert_eq!(cols.len(), 9, "unexpected CSV row: {line}");
        let idx = cols[0];
        let g = parse_point_or_infinity(cols[1]);
        let a = parse_point_or_infinity(cols[2]);
        let b = parse_point_or_infinity(cols[3]);
        let c = parse_point_or_infinity(cols[4]);
        let proof = decode_hex::<64>(cols[5]);
        let m = opt_msg(cols[6]);
        let expected_ok = match cols[7] {
            "TRUE" => true,
            "FALSE" => false,
            other => panic!("unexpected verdict {other}"),
        };
        let comment = cols[8];

        let g_opt = if g == AffinePoint::GENERATOR {
            None
        } else {
            Some(&g)
        };
        let ok = dleq_verify(&a, &b, &c, &proof, g_opt, m.as_ref().map(|x| x.as_slice())).is_ok();
        assert_eq!(
            ok, expected_ok,
            "verify mismatch on vector {idx} ({comment})"
        );
        count += 1;
    }
    assert_eq!(count, 17);
}

#[test]
fn bip375_outputs_sort_lexicographically_and_break_ties_by_index() {
    let scan = (ProjectivePoint::GENERATOR * Scalar::from(77u64)).to_affine();
    let p1 = (ProjectivePoint::GENERATOR * Scalar::from(100u64)).to_affine();
    let p2 = (ProjectivePoint::GENERATOR * Scalar::from(101u64)).to_affine();
    let (sp_lo, sp_hi) = if compressed(&p1).unwrap() < compressed(&p2).unwrap() {
        (p1, p2)
    } else {
        (p2, p1)
    };

    let a1 = Scalar::from(555u64);
    let share = Bip375SignerShare {
        input_pubkey: (ProjectivePoint::GENERATOR * a1).to_affine(),
        ecdh_share: (ProjectivePoint::from(scan) * a1).to_affine(),
        dleq_proof: dleq_prove(&a1, &scan, &[0x11u8; 32], None, None).unwrap(),
    };

    // Empty slices and identity points fail closed with InvalidPoint.
    assert_eq!(
        derive_bip375_outputs(&[], &scan, &[0u8; 36], &[sp_lo]),
        Err(Error::InvalidPoint)
    );
    assert_eq!(
        derive_bip375_outputs(&[share], &scan, &[0u8; 36], &[]),
        Err(Error::InvalidPoint)
    );
    assert_eq!(
        derive_bip375_outputs(&[share], &scan, &[0u8; 36], &[AffinePoint::IDENTITY]),
        Err(Error::InvalidPoint)
    );

    // Identical spend keys get consecutive k values in ascending output index order.
    let dup = derive_bip375_outputs(&[share], &scan, &[0u8; 36], &[sp_hi, sp_lo, sp_hi]).unwrap();
    assert_eq!(dup.len(), 3);
    assert_ne!(dup[0], dup[2]);
    // sp_lo receives k=0, first sp_hi receives k=1, second sp_hi receives k=2.
    let canonical =
        derive_bip375_outputs(&[share], &scan, &[0u8; 36], &[sp_lo, sp_hi, sp_hi]).unwrap();
    assert_eq!(dup[1], canonical[0]);
    assert_eq!(dup[0], canonical[1]);
    assert_eq!(dup[2], canonical[2]);
}
