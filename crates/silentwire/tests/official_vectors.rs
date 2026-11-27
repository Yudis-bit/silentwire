use serde_json::Value;
use silentwire::{
    compressed,
    input::{extract_key, prepare, ValidatedInput},
    point, scalar,
    sender::{aggregate_secret, create_outputs, Recipient, SenderInput},
    SpScannerNaive,
};

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn fixed<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().ok().unwrap()
}

struct OwnedInput {
    outpoint: [u8; 36],
    prevout: Vec<u8>,
    sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
}

fn compact(raw: &[u8], cursor: &mut usize) -> usize {
    let prefix = raw[*cursor];
    *cursor += 1;
    let width = match prefix {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        _ => return usize::from(prefix),
    };
    let mut n = 0usize;
    for i in 0..width {
        n |= usize::from(raw[*cursor + i]) << (8 * i);
    }
    *cursor += width;
    n
}

fn owned(v: &Value) -> OwnedInput {
    let mut outpoint = [0; 36];
    let mut txid = bytes(&v["txid"]);
    txid.reverse();
    outpoint[..32].copy_from_slice(&txid);
    outpoint[32..].copy_from_slice(&(v["vout"].as_u64().unwrap() as u32).to_le_bytes());
    let raw = bytes(&v["txinwitness"]);
    let mut cursor = 0;
    let mut witness = Vec::new();
    if !raw.is_empty() {
        let count = compact(&raw, &mut cursor);
        for _ in 0..count {
            let size = compact(&raw, &mut cursor);
            witness.push(raw[cursor..cursor + size].to_vec());
            cursor += size;
        }
    }
    assert_eq!(cursor, raw.len());
    OwnedInput {
        outpoint,
        prevout: bytes(&v["prevout"]["scriptPubKey"]["hex"]),
        sig: bytes(&v["scriptSig"]),
        witness,
    }
}

fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/send_and_receive_test_vectors.json")).unwrap()
}

#[test]
fn all_36_official_receiving_cases() {
    let mut count = 0;
    for case in vectors() {
        for test in case["receiving"].as_array().unwrap() {
            let given = &test["given"];
            let expected = &test["expected"];
            let owned: Vec<OwnedInput> =
                given["vin"].as_array().unwrap().iter().map(owned).collect();
            let stacks: Vec<Vec<&[u8]>> = owned
                .iter()
                .map(|i| i.witness.iter().map(Vec::as_slice).collect())
                .collect();
            let inputs: Vec<_> = owned
                .iter()
                .zip(&stacks)
                .map(|(i, stack)| ValidatedInput {
                    outpoint: i.outpoint,
                    prevout_script: &i.prevout,
                    script_sig: &i.sig,
                    witness: stack,
                })
                .collect();
            let scan = fixed(&given["key_material"]["scan_priv_key"]);
            let spend = scalar(fixed(&given["key_material"]["spend_priv_key"])).unwrap();
            let spend =
                compressed(&(silentwire::k256::ProjectivePoint::GENERATOR * spend).to_affine())
                    .unwrap();
            let labels: Vec<u32> = given["labels"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_u64().unwrap() as u32)
                .collect();
            let scanner = SpScannerNaive::new(scan, spend, &labels).unwrap();
            let outputs: Vec<[u8; 32]> = given["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(fixed)
                .collect();
            let prepared = prepare(&inputs).unwrap();
            let found = if let Some(prepared) = prepared {
                assert_eq!(
                    hex::encode(compressed(&prepared.aggregate).unwrap()),
                    expected["input_pub_key_sum"].as_str().unwrap(),
                    "{}",
                    case["comment"]
                );
                assert_eq!(
                    hex::encode(compressed(&prepared.tweak.to_affine()).unwrap()),
                    expected["tweak"].as_str().unwrap()
                );
                assert_eq!(
                    hex::encode(compressed(&scanner.shared_secret(&prepared)).unwrap()),
                    expected["shared_secret"].as_str().unwrap()
                );
                let serial = scanner.scan_prepared(&prepared, &outputs).unwrap();
                let mut batch = scanner
                    .scan_batch(core::slice::from_ref(&prepared), &[&outputs])
                    .unwrap();
                assert!(
                    serial == batch.remove(0),
                    "serial/batch mismatch: {}",
                    case["comment"]
                );
                serial
            } else {
                Vec::new()
            };
            if let Some(n) = expected["n_outputs"].as_u64() {
                assert_eq!(found.len(), n as usize);
            } else {
                let mut observed: Vec<_> = found
                    .iter()
                    .map(|m| (hex::encode(m.taproot_pubkey), hex::encode(m.tweak_scalar)))
                    .collect();
                let mut wanted: Vec<_> = expected["outputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| {
                        (
                            o["pub_key"].as_str().unwrap().to_owned(),
                            o["priv_key_tweak"].as_str().unwrap().to_owned(),
                        )
                    })
                    .collect();
                observed.sort();
                wanted.sort();
                assert_eq!(observed, wanted, "{}", case["comment"]);
            }
            for m in found {
                assert_eq!(outputs[m.output_index as usize], m.taproot_pubkey);
            }
            count += 1;
        }
    }
    assert_eq!(count, 36);
}

#[test]
fn all_34_official_sending_cases() {
    let mut count = 0;
    for case in vectors() {
        for test in case["sending"].as_array().unwrap() {
            let given = &test["given"];
            let expected = &test["expected"];
            let vins = given["vin"].as_array().unwrap();
            let owned: Vec<_> = vins.iter().map(owned).collect();
            let mut secrets = Vec::new();
            let mut keys = Vec::new();
            for (v, i) in vins.iter().zip(&owned) {
                let witness: Vec<&[u8]> = i.witness.iter().map(Vec::as_slice).collect();
                let input = ValidatedInput {
                    outpoint: i.outpoint,
                    prevout_script: &i.prevout,
                    script_sig: &i.sig,
                    witness: &witness,
                };
                if let Some(key) = extract_key(&input).unwrap() {
                    keys.push(hex::encode(compressed(&key).unwrap()));
                    secrets.push(SenderInput {
                        secret: fixed(&v["private_key"]),
                        is_taproot: silentwire::p2tr_key(&i.prevout).is_some(),
                    });
                }
            }
            let wanted: Vec<_> = expected["input_pub_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(keys, wanted, "{}", case["comment"]);
            if !expected["input_private_key_sum"].is_null() && !secrets.is_empty() {
                assert_eq!(
                    hex::encode(aggregate_secret(&secrets).unwrap().to_bytes()),
                    expected["input_private_key_sum"].as_str().unwrap()
                );
            }
            let outpoints: Vec<_> = owned.iter().map(|i| i.outpoint).collect();
            let mut recipients = Vec::new();
            for r in given["recipients"].as_array().unwrap() {
                for _ in 0..r["count"].as_u64().unwrap_or(1) {
                    recipients.push(Recipient {
                        scan: point(&bytes(&r["scan_pub_key"])).unwrap(),
                        spend: point(&bytes(&r["spend_pub_key"])).unwrap(),
                    });
                }
            }
            let max_group = recipients
                .iter()
                .map(|r| recipients.iter().filter(|o| o.scan == r.scan).count())
                .max()
                .unwrap_or(0);
            let outputs_res = create_outputs(&secrets, &outpoints, &recipients);
            let mut outputs: Vec<_> = if max_group > silentwire::K_MAX as usize {
                assert_eq!(
                    outputs_res,
                    Err(silentwire::Error::BatchTooLarge),
                    "exceeding K_MAX must fail closed: {}",
                    case["comment"]
                );
                Vec::new()
            } else {
                outputs_res.unwrap().iter().map(hex::encode).collect()
            };
            outputs.sort();
            assert!(
                expected["outputs"].as_array().unwrap().iter().any(|set| {
                    let mut set: Vec<_> = set
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect();
                    set.sort();
                    set == outputs
                }),
                "{}",
                case["comment"]
            );
            count += 1;
        }
    }
    assert_eq!(count, 34);
}

#[test]
fn rejects_spoofed_witness_pubkey_in_p2wpkh_and_nested_p2sh_p2wpkh() {
    use bitcoin_hashes::{hash160, Hash};
    use silentwire::k256::{ProjectivePoint, Scalar};

    let real_pk =
        compressed(&(ProjectivePoint::GENERATOR * Scalar::from(17u64)).to_affine()).unwrap();
    let spoof_pk =
        compressed(&(ProjectivePoint::GENERATOR * Scalar::from(19u64)).to_affine()).unwrap();
    let real_hash = hash160::Hash::hash(&real_pk);

    // Native P2WPKH: 0x00 0x14 <20-byte hash160(real_pk)>
    let mut wpkh_spk = vec![0x00u8, 0x14];
    wpkh_spk.extend_from_slice(real_hash.as_byte_array());

    let valid_wpkh = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &wpkh_spk,
        script_sig: &[],
        witness: &[b"sig", &real_pk],
    };
    assert_eq!(
        extract_key(&valid_wpkh).unwrap(),
        Some(point(&real_pk).unwrap())
    );

    let spoofed_wpkh = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &wpkh_spk,
        script_sig: &[],
        witness: &[b"sig", &spoof_pk],
    };
    assert_eq!(extract_key(&spoofed_wpkh).unwrap(), None);

    // Nested P2SH-P2WPKH: scriptSig = [0x16, 0x00, 0x14, hash160(real_pk)]
    let mut redeem = vec![0x00u8, 0x14];
    redeem.extend_from_slice(real_hash.as_byte_array());
    let redeem_hash = hash160::Hash::hash(&redeem);
    let mut p2sh_spk = vec![0xa9u8, 0x14];
    p2sh_spk.extend_from_slice(redeem_hash.as_byte_array());
    p2sh_spk.push(0x87);
    let mut script_sig = vec![0x16u8];
    script_sig.extend_from_slice(&redeem);

    let valid_nested = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &p2sh_spk,
        script_sig: &script_sig,
        witness: &[b"sig", &real_pk],
    };
    assert_eq!(
        extract_key(&valid_nested).unwrap(),
        Some(point(&real_pk).unwrap())
    );

    let spoofed_nested = ValidatedInput {
        outpoint: [0u8; 36],
        prevout_script: &p2sh_spk,
        script_sig: &script_sig,
        witness: &[b"sig", &spoof_pk],
    };
    assert_eq!(extract_key(&spoofed_nested).unwrap(), None);
}
