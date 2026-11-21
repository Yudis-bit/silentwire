use silentwire::{
    batch::MontgomeryBatchInverter,
    input::PreparedTransaction,
    k256::{FieldElement, ProjectivePoint, Scalar},
    scalar,
    sender::{create_outputs, Recipient, SenderInput},
    ssmb::{GlvScalar, SharedScalar, GLV_TABLE_SIZE, ROLLING_BASES, TABLE_SIZE},
    SpScannerNaive,
};
use std::{hint::black_box, time::Instant};

fn main() {
    println!(
        "projective_point_bytes,{}",
        core::mem::size_of::<ProjectivePoint>()
    );
    println!(
        "glv_rolling_table_bytes,{}",
        ROLLING_BASES * GLV_TABLE_SIZE * core::mem::size_of::<silentwire::k256::AffinePoint>()
    );
    println!("workload,count,serial_ns,shared_schedule_ns,rolling_schedule_ns,glv_rolling_ns,us_per_point,serial_over_glv");
    let scalar_val = Scalar::from(0x123456789abcdefu64).invert().unwrap();
    let glv = GlvScalar::new(&scalar_val);
    for size in [1usize, 4, 16, 100, 1000, 2000] {
        let bases: Vec<_> = (1..=size)
            .map(|i| ProjectivePoint::GENERATOR * Scalar::from(i as u64))
            .collect();
        let mut output = vec![ProjectivePoint::IDENTITY; size];
        let mut tables = vec![ProjectivePoint::IDENTITY; size * TABLE_SIZE];
        let mut rolling = vec![ProjectivePoint::IDENTITY; size];
        let mut rolling_tables =
            vec![ProjectivePoint::IDENTITY; size.min(ROLLING_BASES) * TABLE_SIZE];
        let mut glv_out = vec![ProjectivePoint::IDENTITY; size];
        let mut glv_tables =
            vec![silentwire::k256::AffinePoint::IDENTITY; size.min(ROLLING_BASES) * GLV_TABLE_SIZE];
        let mut serial = vec![ProjectivePoint::IDENTITY; size];
        let schedule = SharedScalar::new(&scalar_val);
        let started = Instant::now();
        for (result, base) in serial.iter_mut().zip(&bases) {
            *result = black_box(base) * black_box(&scalar_val);
        }
        let serial_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        schedule
            .multiply_into(black_box(&bases), &mut output, &mut tables)
            .unwrap();
        let shared_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        schedule
            .multiply_rolling_into(black_box(&bases), &mut rolling, &mut rolling_tables)
            .unwrap();
        let rolling_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        glv.multiply_rolling_into(black_box(&bases), &mut glv_out, &mut glv_tables)
            .unwrap();
        let glv_ns = started.elapsed().as_nanos();
        let us_per_point = (glv_ns as f64 / 1000.0) / size as f64;
        assert_eq!(serial, output);
        assert_eq!(serial, rolling);
        assert_eq!(serial, glv_out);
        black_box(output);
        println!(
            "synthetic_scalar_multiply,{size},{serial_ns},{shared_ns},{rolling_ns},{glv_ns},{us_per_point:.2},{:.2}",
            serial_ns as f64 / glv_ns as f64
        );
    }
    println!("workload,count,individual_inverse_ns,batch_inverse_ns,us_per_inverse,individual_over_batch");
    for size in [1usize, 4, 100, 1000, 2000, 4096] {
        let values: Vec<FieldElement> = (1..=size)
            .map(|i| {
                let mut bytes = [0; 32];
                bytes[24..].copy_from_slice(&(i as u64).to_be_bytes());
                Option::from(FieldElement::from_bytes(&bytes.into())).unwrap()
            })
            .collect();
        let mut batch = values.clone();
        let mut scratch = vec![FieldElement::ZERO; size];
        let mut individual = vec![FieldElement::ZERO; size];
        let started = Instant::now();
        for (result, value) in individual.iter_mut().zip(&values) {
            *result = black_box(value).invert().unwrap();
        }
        let individual_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        MontgomeryBatchInverter::invert(black_box(&mut batch), &mut scratch).unwrap();
        let batch_ns = started.elapsed().as_nanos();
        let us_per_inverse = (batch_ns as f64 / 1000.0) / size as f64;
        for (a, b) in individual.iter().zip(batch) {
            assert_eq!(a.normalize().to_bytes(), b.normalize().to_bytes());
        }
        println!(
            "synthetic_field_inverse,{size},{individual_ns},{batch_ns},{us_per_inverse:.3},{:.2}",
            individual_ns as f64 / batch_ns as f64
        );
    }

    println!("workload,txs,outputs,matches,total_ms,us_per_tx,outputs_per_sec");
    benchmark_full_block_scan();
}

fn benchmark_full_block_scan() {
    let scan_priv = [0x55u8; 32];
    let spend_priv = [0x77u8; 32];
    let scan_scalar = scalar(scan_priv).unwrap();
    let spend_scalar = scalar(spend_priv).unwrap();
    let spend_pub_aff = (ProjectivePoint::GENERATOR * spend_scalar).to_affine();
    let spend_pub_bytes = silentwire::compressed(&spend_pub_aff).unwrap();
    let scanner = SpScannerNaive::new(scan_priv, spend_pub_bytes, &[]).unwrap();

    let tx_count = 1000;
    let mut transactions = Vec::with_capacity(tx_count);
    let mut outputs_storage: Vec<Vec<[u8; 32]>> = Vec::with_capacity(tx_count);

    let target_tx_idx = 420;
    let recipient = Recipient {
        scan: (ProjectivePoint::GENERATOR * scan_scalar).to_affine(),
        spend: spend_pub_aff,
    };

    for tx_idx in 0..tx_count {
        let sec = Scalar::from((tx_idx + 1) as u64 * 31337 + 1);
        let agg_aff = (ProjectivePoint::GENERATOR * sec).to_affine();
        let mut outpoint = [0u8; 36];
        outpoint[..4].copy_from_slice(&(tx_idx as u32).to_le_bytes());
        let input_hash = scalar(silentwire::tagged_hash(
            b"BIP0352/Inputs",
            &[&outpoint, &silentwire::compressed(&agg_aff).unwrap()],
        ))
        .unwrap();

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
            let sp_outs =
                create_outputs(&[secret_input], &[outpoint], &[recipient]).expect("valid creation");
            for out in sp_outs {
                tx_outputs.push(out);
            }
            tx_outputs.push([0xaa; 32]);
        } else {
            let count = if tx_idx % 2 == 0 { 2 } else { 3 };
            for o in 0..count {
                let mut fake_out = [0u8; 32];
                fake_out[..4].copy_from_slice(&(tx_idx as u32).to_le_bytes());
                fake_out[4..8].copy_from_slice(&(o as u32).to_le_bytes());
                fake_out[8] = 0xbb;
                tx_outputs.push(fake_out);
            }
        }
        outputs_storage.push(tx_outputs);
    }

    let outputs_slices: Vec<&[[u8; 32]]> = outputs_storage.iter().map(|v| v.as_slice()).collect();
    let total_outputs: usize = outputs_storage.iter().map(|v| v.len()).sum();

    let started = Instant::now();
    let matches = scanner
        .scan_batch(&transactions, &outputs_slices)
        .expect("batch scan valid");
    let elapsed = started.elapsed();

    let total_matches: usize = matches.iter().map(|m| m.len()).sum();
    let elapsed_sec = elapsed.as_secs_f64();
    let outputs_per_sec = total_outputs as f64 / elapsed_sec;
    let us_per_tx = (elapsed_sec * 1_000_000.0) / tx_count as f64;

    assert_eq!(total_matches, 1);
    println!(
        "full_block_scan_bench,{},{},{},{:.2},{:.2},{:.0}",
        tx_count,
        total_outputs,
        total_matches,
        elapsed_sec * 1000.0,
        us_per_tx,
        outputs_per_sec
    );
}
