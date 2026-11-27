use silentwire::k256::elliptic_curve::sec1::ToEncodedPoint;
use silentwire::k256::{AffinePoint, ProjectivePoint, Scalar};
use silentwire::{audit_candidate_tweak, is_on_quadratic_twist, Error, HardenedMultiplier};

#[test]
fn twist_rejection_identifies_twist_and_curve_points() {
    let x_twist = [0u8; 32];
    assert!(is_on_quadratic_twist(&x_twist));

    let mut twist_candidate = [0u8; 33];
    twist_candidate[0] = 0x02;
    assert_eq!(
        audit_candidate_tweak(&twist_candidate),
        Err(Error::InvalidPoint)
    );

    let gen_affine = AffinePoint::GENERATOR;
    let gen_enc = gen_affine.to_encoded_point(true);
    let gen_bytes: [u8; 33] = gen_enc.as_bytes().try_into().unwrap();
    let gen_x: [u8; 32] = gen_bytes[1..33].try_into().unwrap();

    assert!(!is_on_quadratic_twist(&gen_x));
    let parsed_gen = audit_candidate_tweak(&gen_bytes).expect("generator is valid");
    assert_eq!(parsed_gen, gen_affine);
}

#[test]
fn hardened_multiplication_parity_blinding_and_degenerate_guards() {
    let secret = Scalar::from(0x13374269u64);
    let blinding1 = Scalar::from(0xDEADBEEFu64);
    let blinding2 = Scalar::from(0xCAFEBABE9999u64);
    let base = ProjectivePoint::GENERATOR;

    let q1 = HardenedMultiplier::multiply_hardened(&secret, &base, &blinding1).unwrap();
    let q2 = HardenedMultiplier::multiply_hardened(&secret, &base, &blinding2).unwrap();
    let q_dual =
        HardenedMultiplier::multiply_hardened_dual(&secret, &base, &blinding1, &blinding2).unwrap();
    let expected = (base * secret).to_affine();

    assert_eq!(q1, expected);
    assert_eq!(q2, expected);
    assert_eq!(q_dual, expected);

    // Zero scalar, zero blinding, identity point, or collapsed splits fail closed
    assert_eq!(
        HardenedMultiplier::multiply_hardened(&Scalar::ZERO, &base, &blinding1),
        Err(Error::InvalidScalar)
    );
    assert_eq!(
        HardenedMultiplier::multiply_hardened(&secret, &base, &Scalar::ZERO),
        Err(Error::InvalidScalar)
    );
    assert_eq!(
        HardenedMultiplier::multiply_hardened(&secret, &base, &secret),
        Err(Error::InvalidScalar)
    );
    assert_eq!(
        HardenedMultiplier::multiply_hardened(&secret, &ProjectivePoint::IDENTITY, &blinding1),
        Err(Error::InvalidPoint)
    );
    assert_eq!(
        HardenedMultiplier::multiply_hardened_dual(&secret, &base, &blinding1, &blinding1),
        Err(Error::InvalidScalar)
    );
    assert_eq!(
        HardenedMultiplier::multiply_hardened_dual(&secret, &base, &blinding1, &secret),
        Err(Error::InvalidScalar)
    );
    // Spec Theorem 7: reject b1 == -b2 and b1 + b2 == secret (swapped identical splits)
    assert_eq!(
        HardenedMultiplier::multiply_hardened_dual(&secret, &base, &blinding1, &(-blinding1)),
        Err(Error::InvalidScalar)
    );
    assert_eq!(
        HardenedMultiplier::multiply_hardened_dual(
            &secret,
            &base,
            &blinding1,
            &(secret - blinding1)
        ),
        Err(Error::InvalidScalar)
    );
}
