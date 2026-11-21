use silentwire::k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use silentwire::{compressed, scalar, tagged_hash, ScanContext, SilentPaymentMatch};

pub struct Case {
    pub scan: [u8; 32],
    pub spend: [u8; 33],
    pub aggregate: [u8; 33],
    pub outpoint: [u8; 36],
    pub input_hash: [u8; 32],
    pub tweak: [u8; 33],
    pub outputs: Vec<[u8; 32]>,
    pub expected: Vec<SilentPaymentMatch>,
}

fn key(seed: u32, index: u32, domain: u8) -> Scalar {
    let bytes = tagged_hash(
        b"Silentwire/Sentinel",
        &[&seed.to_be_bytes(), &index.to_be_bytes(), &[domain]],
    );
    scalar(bytes).expect("deterministic corpus uses canonical nonzero scalars")
}

pub fn case(seed: u32, index: u32) -> Case {
    let count = match index % 8 {
        0 => 0,
        1 => 2,
        _ => 1,
    };
    case_with_count(seed, index, count)
}

pub fn case_with_count(seed: u32, index: u32, count: u32) -> Case {
    let scan = key(seed, index, 0);
    let spend_point = ProjectivePoint::GENERATOR * key(seed, index, 1);
    let aggregate_point = ProjectivePoint::GENERATOR * key(seed, index, 2);
    let aggregate = compressed(&aggregate_point.to_affine()).unwrap();
    let mut outpoint = [0; 36];
    outpoint[..32].copy_from_slice(&tagged_hash(
        b"Silentwire/Outpoint",
        &[&seed.to_be_bytes(), &index.to_be_bytes()],
    ));
    outpoint[32..].copy_from_slice(&(index % 19).to_le_bytes());
    let input_hash = tagged_hash(b"BIP0352/Inputs", &[&outpoint, &aggregate]);
    let tweak_point = aggregate_point * scalar(input_hash).unwrap();
    let shared = compressed(&(tweak_point * scan).to_affine()).unwrap();
    let dummy = ProjectivePoint::GENERATOR * key(seed, index, 3);
    let mut outputs = vec![<[u8; 32]>::from(
        *dummy.to_affine().to_encoded_point(true).x().unwrap(),
    )];
    let mut expected = Vec::new();
    for k in 0u32..count {
        let t = scalar(tagged_hash(
            b"BIP0352/SharedSecret",
            &[&shared, &k.to_be_bytes()],
        ))
        .unwrap();
        // Independent k256 fixed-base path bypassing the comb and batch code.
        let point = (spend_point + ProjectivePoint::GENERATOR * t).to_affine();
        let x: [u8; 32] = (*point.to_encoded_point(true).x().unwrap()).into();
        outputs.push(x);
        expected.push(SilentPaymentMatch {
            output_index: outputs.len() as u32 - 1,
            derivation_index: k,
            taproot_pubkey: x,
            tweak_scalar: t.to_bytes().into(),
            label: None,
        });
    }
    if index % 2 == 1 {
        outputs.reverse();
        for item in &mut expected {
            item.output_index = outputs.len() as u32 - 1 - item.output_index;
        }
    }
    Case {
        scan: scan.to_bytes().into(),
        spend: compressed(&spend_point.to_affine()).unwrap(),
        aggregate,
        outpoint,
        input_hash,
        tweak: compressed(&tweak_point.to_affine()).unwrap(),
        outputs,
        expected,
    }
}

pub fn scan(context: &mut ScanContext, case: &Case) -> Vec<SilentPaymentMatch> {
    let found = context
        .scan_transaction(&case.scan, &case.spend, &case.tweak, &case.outputs)
        .unwrap();
    assert_eq!(found, case.expected);
    found
}
