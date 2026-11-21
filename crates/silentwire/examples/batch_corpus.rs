use silentwire::{batch::MontgomeryBatchInverter, k256::FieldElement};

fn main() {
    let original: Vec<_> = (0..4096u64)
        .map(|i| {
            let mut bytes =
                silentwire::tagged_hash(b"silentwire/differential", &[&i.to_be_bytes()]);
            if i.is_multiple_of(17) {
                bytes = [0; 32];
            } else if i.is_multiple_of(19) {
                bytes =
                    hex::decode("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")
                        .unwrap()
                        .try_into()
                        .unwrap();
            }
            Option::<FieldElement>::from(FieldElement::from_bytes(&bytes.into())).unwrap()
        })
        .collect();
    let mut values = original.clone();
    MontgomeryBatchInverter::invert(&mut values, &mut vec![FieldElement::ZERO; 4096]).unwrap();
    let encoded: Vec<String> = original.iter().map(|v| hex::encode(v.to_bytes())).collect();
    let inverses: Vec<String> = values
        .iter()
        .map(|v| hex::encode(v.normalize().to_bytes()))
        .collect();
    println!(
        "{}",
        serde_json::json!({"zHex": encoded, "inverseHex": inverses})
    );
}
