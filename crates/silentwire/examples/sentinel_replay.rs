#[path = "../tests/support/mod.rs"]
mod support;

use serde_json::json;
use silentwire::{ScanContext, SilentPaymentMatch};
use std::io::{self, BufWriter, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 || args[1] != "--cases" || args[3] != "--seed" {
        return Err("usage: sentinel_replay --cases N --seed U32".into());
    }
    let cases: u32 = args[2].parse()?;
    let seed: u32 = args[4].parse()?;
    if !(1..=100000).contains(&cases) {
        return Err("cases outside 1..100000".into());
    }
    let mut stdout = BufWriter::new(io::stdout().lock());
    let mut context = ScanContext::new();
    for index in 0..cases {
        let case = support::case(seed, index);
        let found = support::scan(&mut context, &case);
        writeln!(
            stdout,
            "{}",
            json!({"index":index,"scan":hex::encode(case.scan),"spend":hex::encode(case.spend),"aggregate":hex::encode(case.aggregate),"outpoint":hex::encode(case.outpoint),"input_hash":hex::encode(case.input_hash),"tweak":hex::encode(case.tweak),"outputs":case.outputs.iter().map(hex::encode).collect::<Vec<_>>(),"matches":found.iter().map(|m| json!({"pub_key":hex::encode(m.taproot_pubkey),"priv_key_tweak":hex::encode(m.tweak_scalar),"output_index":m.output_index,"derivation_index":m.derivation_index})).collect::<Vec<_>>() })
        )?;
    }
    let case = support::case(seed, 0);
    let mut buffer = [SilentPaymentMatch::default(); 3];
    let mut infinity = [0u8; 33];
    let invalid_infinity = context
        .scan_transaction_into(
            &case.scan,
            &case.spend,
            &infinity,
            &case.outputs,
            &mut buffer,
        )
        .is_err();
    infinity[0] = 2; // x=0 has no square root for x^3 + 7 on secp256k1.
    let invalid_twist = context
        .scan_transaction_into(
            &case.scan,
            &case.spend,
            &infinity,
            &case.outputs,
            &mut buffer,
        )
        .is_err();
    let order: [u8; 32] =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?
            .try_into()
            .unwrap();
    let invalid_scalar = context
        .scan_transaction_into(&order, &case.spend, &case.tweak, &case.outputs, &mut buffer)
        .is_err();
    let parity_case = support::case(seed, 1);
    let original = support::scan(&mut context, &parity_case);
    let mut negated = parity_case.outputs.clone();
    // SEC1 signs change but the Taproot x-only encoding remains equal.
    for output in &mut negated {
        let mut sec = [0u8; 33];
        sec[0] = 2;
        sec[1..].copy_from_slice(output);
        let point = silentwire::point(&sec)?;
        use silentwire::k256::elliptic_curve::sec1::ToEncodedPoint;
        *output = (*(-point).to_encoded_point(true).x().unwrap()).into();
    }
    let parity_equal = context.scan_transaction(
        &parity_case.scan,
        &parity_case.spend,
        &parity_case.tweak,
        &negated,
    )? == original;
    assert!(invalid_infinity && invalid_twist && invalid_scalar && parity_equal);
    writeln!(
        stdout,
        "{}",
        json!({"boundary":true,"infinityRejected":invalid_infinity,"twistRejected":invalid_twist,"scalarNRejected":invalid_scalar,"parityEqual":parity_equal})
    )?;
    Ok(())
}
