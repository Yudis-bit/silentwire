#![forbid(unsafe_code)]

use bdk_silentwire::{
    bitcoin::{OutPoint, ScriptBuf, TxOut, Txid},
    BlkStreamScanner, PrevoutProvider,
};
use core::str::FromStr;
use serde_json::Value;
use silentwire::{
    batch::MontgomeryBatchInverter,
    compressed,
    input::{extract_key, prepare, ValidatedInput},
    k256::{FieldElement, ProjectivePoint, Scalar},
    matcher::CuckooFilter,
    point, scalar,
    sender::{aggregate_secret, create_outputs, Recipient, SenderInput},
    ssmb::{GlvScalar, GLV_TABLE_SIZE, ROLLING_BASES},
    ScanContext, SpScannerNaive,
};
use std::{collections::BTreeMap, fs, hint::black_box, time::Instant};

struct MapPrevouts(BTreeMap<OutPoint, TxOut>);

impl PrevoutProvider for MapPrevouts {
    fn prevout(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.0.get(outpoint)
    }
}

fn load_prevouts(path: &str) -> Result<MapPrevouts, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let val: Value = serde_json::from_str(&text)?;
    let mut map = BTreeMap::new();
    if let Some(arr) = val.as_array() {
        for item in arr {
            let txid = Txid::from_str(item["txid"].as_str().unwrap_or_default())?;
            let vout = item["vout"].as_u64().unwrap_or_default() as u32;
            let script_hex = item["script_pubkey"].as_str().unwrap_or_default();
            let value_sats = item["value"].as_u64().unwrap_or_default();
            map.insert(
                OutPoint { txid, vout },
                TxOut {
                    value: bdk_silentwire::bitcoin::Amount::from_sat(value_sats),
                    script_pubkey: ScriptBuf::from_bytes(hex::decode(script_hex)?),
                },
            );
        }
    }
    Ok(MapPrevouts(map))
}

fn run_scan_blk(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut blk_path = None;
    let mut scan_priv = None;
    let mut spend_pub = None;
    let mut prevouts_path = None;
    let mut thread_count = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--blk" => {
                i += 1;
                blk_path = args.get(i).cloned();
            }
            "--scan-priv" => {
                i += 1;
                scan_priv = args.get(i).cloned();
            }
            "--spend-pub" => {
                i += 1;
                spend_pub = args.get(i).cloned();
            }
            "--prevouts" => {
                i += 1;
                prevouts_path = args.get(i).cloned();
            }
            "--threads" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    thread_count = val.parse::<usize>().ok();
                }
            }
            _ => {}
        }
        i += 1;
    }

    let blk_path = blk_path.ok_or("Missing required --blk <path>")?;
    let scan_priv_hex = scan_priv.ok_or("Missing required --scan-priv <hex>")?;
    let spend_pub_hex = spend_pub.ok_or("Missing required --spend-pub <hex>")?;

    let scan_bytes: [u8; 32] = hex::decode(scan_priv_hex)?
        .try_into()
        .map_err(|_| "Invalid scan key")?;
    let spend_bytes: [u8; 33] = hex::decode(spend_pub_hex)?
        .try_into()
        .map_err(|_| "Invalid spend pubkey")?;
    let scanner = SpScannerNaive::new(scan_bytes, spend_bytes, &[])?;

    let prevouts = match prevouts_path {
        Some(ref p) => load_prevouts(p)?,
        None => MapPrevouts(BTreeMap::new()),
    };

    let threads = thread_count.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });

    let data = fs::read(&blk_path)?;
    let started = Instant::now();
    let blk_stream = BlkStreamScanner::new(&data);
    let results = blk_stream.scan_blocks_parallel(&scanner, &prevouts, threads)?;
    let elapsed = started.elapsed();

    let mut match_count = 0;
    for (header, matches) in &results {
        match_count += matches.len();
        for m in matches {
            println!(
                "match,{},{},{},{}",
                header.block_hash(),
                m.txid,
                m.payment.output_index,
                hex::encode(m.payment.taproot_pubkey)
            );
        }
    }

    let mb = data.len() as f64 / 1_000_000.0;
    let sec = elapsed.as_secs_f64();
    println!(
        "summary,blocks={},matches={},bytes={},seconds={:.4},speed_mbs={:.2},threads={}",
        results.len(),
        match_count,
        data.len(),
        sec,
        mb / sec,
        threads
    );
    Ok(())
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
    OwnedInput {
        outpoint,
        prevout: bytes(&v["prevout"]["scriptPubKey"]["hex"]),
        sig: bytes(&v["scriptSig"]),
        witness,
    }
}

fn run_verify_vectors(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let cases: Vec<Value> = serde_json::from_str(&content)?;
    let mut sending_count = 0;
    let mut receiving_count = 0;

    for case in &cases {
        if let Some(sending_tests) = case["sending"].as_array() {
            for test in sending_tests {
                let given = &test["given"];
                let expected = &test["expected"];
                let vins = given["vin"].as_array().unwrap();
                let owned_inputs: Vec<_> = vins.iter().map(owned).collect();
                let mut secrets = Vec::new();
                for (v, i) in vins.iter().zip(&owned_inputs) {
                    let witness: Vec<&[u8]> = i.witness.iter().map(Vec::as_slice).collect();
                    let input = ValidatedInput {
                        outpoint: i.outpoint,
                        prevout_script: &i.prevout,
                        script_sig: &i.sig,
                        witness: &witness,
                    };
                    if extract_key(&input)?.is_some() {
                        secrets.push(SenderInput {
                            secret: fixed(&v["private_key"]),
                            is_taproot: silentwire::p2tr_key(&i.prevout).is_some(),
                        });
                    }
                }
                if !expected["input_private_key_sum"].is_null() && !secrets.is_empty() {
                    assert_eq!(
                        hex::encode(aggregate_secret(&secrets)?.to_bytes()),
                        expected["input_private_key_sum"].as_str().unwrap()
                    );
                }
                let outpoints: Vec<_> = owned_inputs.iter().map(|i| i.outpoint).collect();
                let mut recipients = Vec::new();
                for r in given["recipients"].as_array().unwrap() {
                    for _ in 0..r["count"].as_u64().unwrap_or(1) {
                        recipients.push(Recipient {
                            scan: point(&bytes(&r["scan_pub_key"]))?,
                            spend: point(&bytes(&r["spend_pub_key"]))?,
                        });
                    }
                }
                let mut outputs: Vec<_> = create_outputs(&secrets, &outpoints, &recipients)?
                    .iter()
                    .map(hex::encode)
                    .collect();
                outputs.sort();
                assert!(expected["outputs"].as_array().unwrap().iter().any(|set| {
                    let mut s: Vec<_> = set
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect();
                    s.sort();
                    s == outputs
                }));
                sending_count += 1;
            }
        }

        if let Some(receiving_tests) = case["receiving"].as_array() {
            for test in receiving_tests {
                let given = &test["given"];
                let expected = &test["expected"];
                let owned_inputs: Vec<OwnedInput> =
                    given["vin"].as_array().unwrap().iter().map(owned).collect();
                let stacks: Vec<Vec<&[u8]>> = owned_inputs
                    .iter()
                    .map(|i| i.witness.iter().map(Vec::as_slice).collect())
                    .collect();
                let inputs: Vec<_> = owned_inputs
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
                let spend = scalar(fixed(&given["key_material"]["spend_priv_key"]))?;
                let spend_pub = compressed(&(ProjectivePoint::GENERATOR * spend).to_affine())?;
                let labels: Vec<u32> = given["labels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m.as_u64().unwrap() as u32)
                    .collect();
                let scanner = SpScannerNaive::new(scan, spend_pub, &labels)?;
                let outputs: Vec<[u8; 32]> = given["outputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(fixed)
                    .collect();

                let prepared = prepare(&inputs)?;
                let found = if let Some(prepared) = prepared {
                    assert_eq!(
                        hex::encode(compressed(&prepared.aggregate)?),
                        expected["input_pub_key_sum"].as_str().unwrap()
                    );
                    assert_eq!(
                        hex::encode(compressed(&prepared.tweak.to_affine())?),
                        expected["tweak"].as_str().unwrap()
                    );
                    assert_eq!(
                        hex::encode(compressed(&scanner.shared_secret(&prepared))?),
                        expected["shared_secret"].as_str().unwrap()
                    );
                    scanner.scan_prepared_glv(&prepared, &outputs)?
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
                    assert_eq!(observed, wanted);
                }
                for m in found {
                    assert_eq!(outputs[m.output_index as usize], m.taproot_pubkey);
                }
                receiving_count += 1;
            }
        }
    }

    println!("verified_vectors,sending={sending_count},receiving={receiving_count},verdict=PASS");
    Ok(())
}

fn run_bench() -> Result<(), Box<dyn std::error::Error>> {
    println!("workload,count,elapsed_ns,us_per_unit");
    let scalar_val = Scalar::from(0x123456789abcdefu64).invert().unwrap();
    let glv = GlvScalar::new(&scalar_val);
    for size in [4usize, 100, 1000] {
        let bases: Vec<_> = (1..=size)
            .map(|i| ProjectivePoint::GENERATOR * Scalar::from(i as u64))
            .collect();
        let mut glv_out = vec![ProjectivePoint::IDENTITY; size];
        let mut glv_tables =
            vec![silentwire::k256::AffinePoint::IDENTITY; size.min(ROLLING_BASES) * GLV_TABLE_SIZE];
        let started = Instant::now();
        glv.multiply_rolling_into(black_box(&bases), &mut glv_out, &mut glv_tables)
            .unwrap();
        let elapsed = started.elapsed().as_nanos();
        let per_unit = (elapsed as f64 / 1000.0) / size as f64;
        println!("glv_rolling_bench,{size},{elapsed},{per_unit:.2}");
    }

    let mut filter = CuckooFilter::default();
    for i in 0..100u64 {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(i * 7919).to_le_bytes());
        filter.insert(&key);
    }
    let started = Instant::now();
    let mut hits = 0;
    for i in 0..1000u64 {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(i * 7919).to_le_bytes());
        if filter.may_contain(&key) {
            hits += 1;
        }
    }
    let filter_ns = started.elapsed().as_nanos();
    println!(
        "cuckoo_dual_lookup_bench,1000_queries,{filter_ns},{:.3},hits={hits}",
        (filter_ns as f64 / 1000.0) / 1000.0
    );

    let mut values: Vec<FieldElement> = (1..=1000)
        .map(|i| {
            let mut bytes = [0; 32];
            bytes[24..].copy_from_slice(&(i as u64).to_be_bytes());
            Option::from(FieldElement::from_bytes(&bytes.into())).unwrap()
        })
        .collect();
    let mut scratch = vec![FieldElement::ZERO; 1000];
    let started = Instant::now();
    MontgomeryBatchInverter::invert(black_box(&mut values), &mut scratch).unwrap();
    let inv_ns = started.elapsed().as_nanos();
    println!(
        "batch_inversion_bench,1000_elements,{inv_ns},{:.3}",
        (inv_ns as f64 / 1000.0) / 1000.0
    );

    // Simulated block benchmark comparing reference naive vs silentwire batching
    run_compare(&[])?;
    Ok(())
}

fn run_compare(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use silentwire::input::PreparedTransaction;

    let mut tx_count = 1000usize;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--txs" {
            i += 1;
            if let Some(val) = args.get(i) {
                if let Ok(n) = val.parse::<usize>() {
                    tx_count = n;
                }
            }
        }
        i += 1;
    }

    let scan_priv = [0x42u8; 32];
    let spend_priv = [0x69u8; 32];
    let scan_scalar = scalar(scan_priv)?;
    let spend_scalar = scalar(spend_priv)?;
    let spend_pub_aff = (ProjectivePoint::GENERATOR * spend_scalar).to_affine();
    let spend_pub_bytes = compressed(&spend_pub_aff)?;
    let spend_pub_proj = ProjectivePoint::from(spend_pub_aff);
    let scanner = SpScannerNaive::new(scan_priv, spend_pub_bytes, &[])?;

    let target_tx_idx = tx_count * 777 / 1000;
    let recipient = Recipient {
        scan: (ProjectivePoint::GENERATOR * scan_scalar).to_affine(),
        spend: spend_pub_aff,
    };

    let mut transactions = Vec::with_capacity(tx_count);
    let mut outputs_storage: Vec<Vec<[u8; 32]>> = Vec::with_capacity(tx_count);

    for tx_idx in 0..tx_count {
        let raw_sec = Scalar::from((tx_idx + 1) as u64 * 424242 + 7);
        let raw_aff = (ProjectivePoint::GENERATOR * raw_sec).to_affine();
        let is_even = compressed(&raw_aff)?[0] == 0x02;
        let sec = if is_even { raw_sec } else { -raw_sec };
        let agg_aff = (ProjectivePoint::GENERATOR * sec).to_affine();
        let mut outpoint = [0u8; 36];
        outpoint[..4].copy_from_slice(&(tx_idx as u32).to_le_bytes());
        let input_hash = scalar(silentwire::tagged_hash(
            b"BIP0352/Inputs",
            &[&outpoint, &compressed(&agg_aff)?],
        ))?;

        let tweak = ProjectivePoint::from(agg_aff) * input_hash;
        transactions.push(PreparedTransaction {
            aggregate: agg_aff,
            input_hash,
            tweak,
        });

        let mut tx_outputs = Vec::new();
        if tx_idx == target_tx_idx {
            let secret_input = SenderInput {
                secret: sec.to_bytes().into(),
                is_taproot: true,
            };
            let sp_outs = create_outputs(&[secret_input], &[outpoint], &[recipient])?;
            for out in sp_outs {
                tx_outputs.push(out);
            }
            tx_outputs.push([0xee; 32]);
        } else {
            let count = if tx_idx % 2 == 0 { 2 } else { 3 };
            for o in 0..count {
                let mut fake_out = [0u8; 32];
                fake_out[..4].copy_from_slice(&(tx_idx as u32).to_le_bytes());
                fake_out[4..8].copy_from_slice(&(o as u32).to_le_bytes());
                fake_out[8] = 0xcc;
                tx_outputs.push(fake_out);
            }
        }
        outputs_storage.push(tx_outputs);
    }

    let outputs_slices: Vec<&[[u8; 32]]> = outputs_storage.iter().map(|v| v.as_slice()).collect();
    let total_outputs: usize = outputs_storage.iter().map(|v| v.len()).sum();

    println!("benchmark,workload=bip352_comparison,transactions={tx_count},outputs={total_outputs},target_tx_index={target_tx_idx}");

    // Reference naive scanning
    let started_naive = Instant::now();

    let mut naive_matches = Vec::new();
    for (tx_idx, tx) in transactions.iter().enumerate() {
        let tx_outs = outputs_slices[tx_idx];
        if tx_outs.is_empty() {
            continue;
        }
        let shared_proj = tx.tweak * scan_scalar;
        let shared_aff = shared_proj.to_affine();
        let encoded = match compressed(&shared_aff) {
            Ok(enc) => enc,
            Err(_) => continue,
        };

        let mut k = 0u32;
        while let Ok(tweak_scalar) = scalar(silentwire::tagged_hash(
            b"BIP0352/SharedSecret",
            &[&encoded, &k.to_be_bytes()],
        )) {
            let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
            let cand_proj = tweak_point + spend_pub_proj;
            let cand_aff = cand_proj.to_affine();
            let Ok(cand_bytes) = compressed(&cand_aff) else {
                break;
            };
            let Ok(cand_x) = cand_bytes[1..33].try_into() else {
                break;
            };

            let mut hit = false;
            for (vout, out) in tx_outs.iter().enumerate() {
                if *out == cand_x {
                    naive_matches.push((tx_idx, vout, cand_x, tweak_scalar.to_bytes().into()));
                    hit = true;
                    break;
                }
            }
            if !hit {
                break;
            }
            k += 1;
        }
    }
    let elapsed_naive = started_naive.elapsed();
    let sec_naive = elapsed_naive.as_secs_f64();
    let outs_sec_naive = total_outputs as f64 / sec_naive;
    let us_per_tx_naive = (sec_naive * 1_000_000.0) / tx_count as f64;

    // Optimized scanning with ScanContext
    let mut ctx = ScanContext::default();

    let started_fast = Instant::now();

    scanner.scan_batch_into(&transactions, &outputs_slices, &mut ctx)?;

    let elapsed_fast = started_fast.elapsed();
    let sec_fast = elapsed_fast.as_secs_f64();
    let outs_sec_fast = total_outputs as f64 / sec_fast;
    let us_per_tx_fast = (sec_fast * 1_000_000.0) / tx_count as f64;

    let mut fast_matches = Vec::new();
    for (tx_idx, list) in ctx.results().iter().enumerate() {
        for m in list {
            fast_matches.push((
                tx_idx,
                m.output_index as usize,
                m.taproot_pubkey,
                m.tweak_scalar,
            ));
        }
    }

    assert_eq!(naive_matches.len(), fast_matches.len());
    assert_eq!(naive_matches, fast_matches);
    assert_eq!(naive_matches.len(), 1);

    let speedup_time = sec_naive / sec_fast;
    let time_reduction_pct = (1.0 - (sec_fast / sec_naive)) * 100.0;

    println!(
        "reference_naive,latency_ms={:.3},us_per_tx={:.2},throughput_outs_per_sec={:.1},matches={}",
        sec_naive * 1000.0,
        us_per_tx_naive,
        outs_sec_naive,
        naive_matches.len()
    );
    println!(
        "silentwire_fast,latency_ms={:.3},us_per_tx={:.2},throughput_outs_per_sec={:.1},matches={}",
        sec_fast * 1000.0,
        us_per_tx_fast,
        outs_sec_fast,
        fast_matches.len()
    );
    println!(
        "comparison,speedup_time={:.2}x,time_reduction_pct={:.1}%,consensus_parity=PASS",
        speedup_time, time_reduction_pct
    );
    for (tx_idx, vout, pubkey, tweak) in &fast_matches {
        println!(
            "match,tx_index={tx_idx},vout={vout},pubkey={},tweak_scalar={}",
            hex::encode(pubkey),
            hex::encode(tweak)
        );
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(|s| s.as_str()).unwrap_or("help");
    match command {
        "scan-blk" => run_scan_blk(&args[1..])?,
        "verify-vectors" => {
            let path = args
                .get(1)
                .map(|s| s.as_str())
                .unwrap_or("test-vectors/send_and_receive_test_vectors.json");
            run_verify_vectors(path)?;
        }
        "compare" => run_compare(&args[1..])?,
        "bench" => run_bench()?,
        _ => {
            println!("Usage: silentwire-cli <command> [options]");
            println!("Commands:");
            println!("  scan-blk        --blk <file> --scan-priv <hex> --spend-pub <hex> [--prevouts <file>] [--threads <n>]");
            println!("  verify-vectors  [<vector-json>]");
            println!("  compare         [--txs <count>]");
            println!("  bench");
        }
    }
    Ok(())
}
