use bdk_silentwire::{
    derive_spending_key, PrevoutProvider, ScanError, SpScanner, SpWalletTracker,
    StreamingBlockScanner,
};
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute, blockdata::constants::genesis_block, transaction, Amount, Block, Network, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use serde_json::Value;
use silentwire::{compressed, k256::ProjectivePoint, scalar, SpScannerNaive};
use std::{collections::BTreeMap, str::FromStr};

struct Prevouts(BTreeMap<OutPoint, TxOut>);
impl PrevoutProvider for Prevouts {
    fn prevout(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.0.get(outpoint)
    }
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
    let mut n = 0;
    for i in 0..width {
        n |= usize::from(raw[*cursor + i]) << (8 * i);
    }
    *cursor += width;
    n
}

fn fixture() -> (Block, Prevouts, SpScanner, Vec<u8>) {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/send_and_receive_test_vectors.json")).unwrap();
    let given = &cases[0]["receiving"][0]["given"];
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        }],
    };
    let mut prevouts = Prevouts(BTreeMap::new());
    for vin in given["vin"].as_array().unwrap() {
        let outpoint = OutPoint {
            txid: Txid::from_str(vin["txid"].as_str().unwrap()).unwrap(),
            vout: vin["vout"].as_u64().unwrap() as u32,
        };
        let raw = hex::decode(vin["txinwitness"].as_str().unwrap()).unwrap();
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
        tx.input.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::from_bytes(
                hex::decode(vin["scriptSig"].as_str().unwrap()).unwrap(),
            ),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&witness),
        });
        prevouts.0.insert(
            outpoint,
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(
                    hex::decode(vin["prevout"]["scriptPubKey"]["hex"].as_str().unwrap()).unwrap(),
                ),
            },
        );
    }
    let output = hex::decode(given["outputs"][0].as_str().unwrap()).unwrap();
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&output);
    tx.output.push(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    let scan = hex::decode(given["key_material"]["scan_priv_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let spend = scalar(
        hex::decode(given["key_material"]["spend_priv_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let receiver = SpScannerNaive::new(
        scan,
        compressed(&(ProjectivePoint::GENERATOR * spend).to_affine()).unwrap(),
        &[],
    )
    .unwrap();
    let header = genesis_block(Network::Bitcoin).header;
    (
        Block {
            header,
            txdata: vec![tx],
        },
        prevouts,
        SpScanner::new(receiver),
        output,
    )
}

#[test]
fn preserves_vout_and_chain_identity_even_for_dust() {
    let (block, prevouts, scanner, output) = fixture();
    let found = scanner.scan_block(&block, &prevouts).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].payment.output_index, 1);
    assert_eq!(found[0].payment.taproot_pubkey.as_slice(), output);
    assert_eq!(found[0].block_hash, block.block_hash());
    assert_eq!(found[0].txid, block.txdata[0].compute_txid());
}

#[test]
fn rejects_missing_prevouts_and_skips_future_witness_versions() {
    let (block, mut prevouts, scanner, _) = fixture();
    let outpoint = block.txdata[0].input[0].previous_output;
    let removed = prevouts.0.remove(&outpoint).unwrap();
    assert!(
        matches!(scanner.scan_block(&block, &prevouts), Err(ScanError::MissingPrevout(x)) if x == outpoint)
    );
    let mut script = vec![0x52, 32];
    script.extend_from_slice(&[1; 32]);
    prevouts.0.insert(
        outpoint,
        TxOut {
            script_pubkey: ScriptBuf::from_bytes(script),
            ..removed
        },
    );
    assert!(scanner.scan_block(&block, &prevouts).unwrap().is_empty());
}

#[test]
fn tracker_applies_blocks_detects_reorgs_and_rolls_back() {
    let (block, prevouts, scanner, output) = fixture();
    let mut tracker = SpWalletTracker::new(scanner);
    assert_eq!(tracker.tip(), None);
    assert!(tracker.payments().is_empty());

    let found = tracker.apply_block(100, &block, &prevouts).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].height, 100);
    assert_eq!(found[0].payment.taproot_pubkey.as_slice(), output);
    assert_eq!(tracker.tip().unwrap().height, 100);
    assert_eq!(tracker.tip().unwrap().block_hash, block.block_hash());
    assert_eq!(tracker.payments().len(), 1);

    let mut mismatched = block.clone();
    mismatched.header.prev_blockhash = bitcoin::BlockHash::from_byte_array([0; 32]);
    assert!(matches!(
        tracker.apply_block(101, &mismatched, &prevouts),
        Err(ScanError::ReorganizationDetected { expected, actual })
            if expected == block.block_hash() && actual == bitcoin::BlockHash::from_byte_array([0; 32])
    ));

    let mut chained = block.clone();
    chained.header.prev_blockhash = block.block_hash();
    chained.header.time += 600;
    let found2 = tracker.apply_block(101, &chained, &prevouts).unwrap();
    assert_eq!(found2.len(), 1);
    assert_eq!(tracker.tip().unwrap().height, 101);
    assert_eq!(tracker.payments().len(), 2);

    let orphaned = tracker.rollback_to(100);
    assert_eq!(orphaned.len(), 1);
    assert_eq!(orphaned[0].height, 101);
    assert_eq!(tracker.tip().unwrap().height, 100);
    assert_eq!(tracker.payments().len(), 1);
    assert_eq!(tracker.payments()[0].height, 100);
}

#[test]
fn spending_key_derivation_signs_for_detected_output() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/send_and_receive_test_vectors.json")).unwrap();
    let given = &cases[0]["receiving"][0]["given"];
    let (block, prevouts, scanner, _) = fixture();
    let matches = scanner.scan_block(&block, &prevouts).unwrap();
    assert_eq!(matches.len(), 1);

    let spend_priv: [u8; 32] =
        hex::decode(given["key_material"]["spend_priv_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let derived = derive_spending_key(spend_priv, matches[0].payment.tweak_scalar).unwrap();
    let derived_scalar = scalar(derived).unwrap();
    let derived_pub =
        compressed(&(ProjectivePoint::GENERATOR * derived_scalar).to_affine()).unwrap();
    assert_eq!(
        &derived_pub[1..],
        matches[0].payment.taproot_pubkey.as_slice()
    );
}

#[test]
fn streaming_raw_block_scanner_matches_in_memory_scan() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/send_and_receive_test_vectors.json")).unwrap();
    let given = &cases[0]["receiving"][0]["given"];
    let (block, prevouts, scanner, output) = fixture();
    let in_memory_matches = scanner.scan_block(&block, &prevouts).unwrap();

    let scan = hex::decode(given["key_material"]["scan_priv_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let spend = scalar(
        hex::decode(given["key_material"]["spend_priv_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let receiver = SpScannerNaive::new(
        scan,
        compressed(&(ProjectivePoint::GENERATOR * spend).to_affine()).unwrap(),
        &[],
    )
    .unwrap();

    let raw = bitcoin::consensus::serialize(&block);
    let streaming = StreamingBlockScanner::new(&raw);
    let (header, matches) = streaming.scan(&receiver, &prevouts).unwrap();

    assert_eq!(header, block.header);
    assert_eq!(matches.len(), in_memory_matches.len());
    assert_eq!(matches[0].block_hash, in_memory_matches[0].block_hash);
    assert_eq!(matches[0].txid, in_memory_matches[0].txid);
    assert_eq!(
        matches[0].payment.output_index,
        in_memory_matches[0].payment.output_index
    );
    assert_eq!(
        matches[0].payment.taproot_pubkey.as_slice(),
        output.as_slice()
    );
    assert_eq!(
        matches[0].payment.tweak_scalar,
        in_memory_matches[0].payment.tweak_scalar
    );

    let (header_batch, matches_batch) = streaming.scan_batch(&receiver, &prevouts).unwrap();
    assert_eq!(header_batch, block.header);
    assert_eq!(matches_batch, matches);
}

#[test]
fn blk_file_scanner_parses_framed_blocks() {
    use bdk_silentwire::{BlkStreamScanner, MAINNET_MAGIC};
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/send_and_receive_test_vectors.json")).unwrap();
    let given = &cases[0]["receiving"][0]["given"];
    let (block, prevouts, _, output) = fixture();

    let scan = hex::decode(given["key_material"]["scan_priv_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let spend = scalar(
        hex::decode(given["key_material"]["spend_priv_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let receiver = SpScannerNaive::new(
        scan,
        compressed(&(ProjectivePoint::GENERATOR * spend).to_affine()).unwrap(),
        &[],
    )
    .unwrap();

    let raw_block = bitcoin::consensus::serialize(&block);
    let mut blk_data = Vec::new();
    blk_data.extend_from_slice(&MAINNET_MAGIC);
    blk_data.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());
    blk_data.extend_from_slice(&raw_block);

    blk_data.extend_from_slice(&MAINNET_MAGIC);
    blk_data.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());
    blk_data.extend_from_slice(&raw_block);

    let blk_scanner = BlkStreamScanner::new(&blk_data);
    let results = blk_scanner.scan_blocks(&receiver, &prevouts).unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, block.header);
    assert_eq!(results[1].0, block.header);
    assert_eq!(results[0].1.len(), 1);
    assert_eq!(results[1].1.len(), 1);
    assert_eq!(
        results[0].1[0].payment.taproot_pubkey.as_slice(),
        output.as_slice()
    );
    assert_eq!(
        results[1].1[0].payment.taproot_pubkey.as_slice(),
        output.as_slice()
    );
}

#[test]
fn blk_file_scanner_parallel_matches_sequential() {
    use bdk_silentwire::{BlkStreamScanner, MAINNET_MAGIC};
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/send_and_receive_test_vectors.json")).unwrap();
    let given = &cases[0]["receiving"][0]["given"];
    let (block, prevouts, _, output) = fixture();

    let scan = hex::decode(given["key_material"]["scan_priv_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let spend = scalar(
        hex::decode(given["key_material"]["spend_priv_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let receiver = SpScannerNaive::new(
        scan,
        compressed(&(ProjectivePoint::GENERATOR * spend).to_affine()).unwrap(),
        &[],
    )
    .unwrap();

    let raw_block = bitcoin::consensus::serialize(&block);
    let mut blk_data = Vec::new();
    for _ in 0..4 {
        blk_data.extend_from_slice(&MAINNET_MAGIC);
        blk_data.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());
        blk_data.extend_from_slice(&raw_block);
    }

    let blk_scanner = BlkStreamScanner::new(&blk_data);
    let sequential = blk_scanner.scan_blocks(&receiver, &prevouts).unwrap();
    let parallel_2 = blk_scanner
        .scan_blocks_parallel(&receiver, &prevouts, 2)
        .unwrap();
    let parallel_4 = blk_scanner
        .scan_blocks_parallel(&receiver, &prevouts, 4)
        .unwrap();

    assert_eq!(sequential.len(), 4);
    assert_eq!(sequential, parallel_2);
    assert_eq!(sequential, parallel_4);
    for (_, matches) in &parallel_4 {
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].payment.taproot_pubkey.as_slice(),
            output.as_slice()
        );
    }
}

#[test]
fn bip158_filter_prefilter_matches_silent_payment_block() {
    use bdk_silentwire::SpFilterMatcher;
    use bitcoin::bip158::BlockFilter;
    use bitcoin::consensus::serialize;
    use silentwire::input::{prepare, ValidatedInput};

    let (block, prevouts, _, _output) = fixture();
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/send_and_receive_test_vectors.json")).unwrap();
    let given = &cases[0]["receiving"][0]["given"];
    let scan: [u8; 32] = hex::decode(given["key_material"]["scan_priv_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let spend = scalar(
        hex::decode(given["key_material"]["spend_priv_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let receiver = SpScannerNaive::new(
        scan,
        compressed(&(ProjectivePoint::GENERATOR * spend).to_affine()).unwrap(),
        &[],
    )
    .unwrap();

    let filter = BlockFilter::new_script_filter(&block, |op| {
        Ok::<_, bitcoin::bip158::Error>(prevouts.prevout(op).unwrap().script_pubkey.clone())
    })
    .unwrap();

    let tx = &block.txdata[0];
    let witnesses: Vec<Vec<&[u8]>> = tx
        .input
        .iter()
        .map(|i| i.witness.iter().collect())
        .collect();
    let mut inputs = Vec::new();
    for (input, witness) in tx.input.iter().zip(witnesses.iter()) {
        let prevout = prevouts.prevout(&input.previous_output).unwrap();
        let outpoint = serialize(&input.previous_output).try_into().unwrap();
        inputs.push(ValidatedInput {
            outpoint,
            prevout_script: prevout.script_pubkey.as_bytes(),
            script_sig: input.script_sig.as_bytes(),
            witness,
        });
    }
    let prepared = prepare(&inputs).unwrap().unwrap();

    let matched = SpFilterMatcher::matches_block_filter(
        &filter,
        &block.block_hash(),
        &receiver,
        core::slice::from_ref(&prepared),
        1,
    )
    .unwrap();
    assert!(matched);

    let dummy_receiver = SpScannerNaive::new(
        [0x99; 32],
        compressed(&(ProjectivePoint::GENERATOR * scalar([0x88; 32]).unwrap()).to_affine())
            .unwrap(),
        &[],
    )
    .unwrap();
    let dummy_matched = SpFilterMatcher::matches_block_filter(
        &filter,
        &block.block_hash(),
        &dummy_receiver,
        core::slice::from_ref(&prepared),
        1,
    )
    .unwrap();
    assert!(!dummy_matched);
}

#[test]
fn differential_fast_gcs_matches_rust_bitcoin_block_filter() {
    use bdk_silentwire::filter::FastGcsFilterMatcher;
    use bitcoin::bip158::BlockFilter;

    let (block, prevouts, _, _) = fixture();
    let block_hash = block.block_hash();
    let filter = BlockFilter::new_script_filter(&block, |op| {
        Ok::<_, bitcoin::bip158::Error>(prevouts.prevout(op).unwrap().script_pubkey.clone())
    })
    .unwrap();

    for tx in &block.txdata {
        for out in &tx.output {
            let script = out.script_pubkey.as_bytes();
            let query = [script];
            let reference = filter
                .match_any(&block_hash, query.iter().copied())
                .unwrap();
            let fast =
                FastGcsFilterMatcher::match_any_raw(&filter.content, &block_hash, query).unwrap();
            assert_eq!(
                reference, fast,
                "Disagreement on present script: {reference} vs {fast}"
            );
            if !out.script_pubkey.is_op_return() && !out.script_pubkey.is_empty() {
                assert!(fast);
            }
        }
    }

    for i in 0..100u8 {
        let dummy = [i, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
        let query = [dummy.as_slice()];
        let reference = filter
            .match_any(&block_hash, query.iter().copied())
            .unwrap();
        let fast =
            FastGcsFilterMatcher::match_any_raw(&filter.content, &block_hash, query).unwrap();
        assert_eq!(
            reference, fast,
            "Disagreement on absent script {i}: {reference} vs {fast}"
        );
    }
}

#[test]
fn gcs_adversarial_malformed_bitstreams_fail_closed() {
    use bdk_silentwire::filter::{FastGcsBitReader, FastGcsFilterMatcher};
    use bitcoin::BlockHash;

    let block_hash = BlockHash::from_byte_array([0x11; 32]);
    let query = [&[0x51, 0x20, 0xaa][..]];

    let truncated = [0x01, 0xff];
    assert!(FastGcsFilterMatcher::match_any_raw(&truncated, &block_hash, query).is_err());

    let all_ones = [0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(FastGcsFilterMatcher::match_any_raw(&all_ones, &block_hash, query).is_err());

    let mut reader = FastGcsBitReader::new(&[]);
    assert_eq!(reader.decode_golomb_rice_p19(), None);

    let zero_elems = [0x00];
    assert_eq!(
        FastGcsFilterMatcher::match_any_raw(&zero_elems, &block_hash, query),
        Ok(false)
    );

    let overflow_n = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00,
    ];
    assert!(FastGcsFilterMatcher::match_any_raw(&overflow_n, &block_hash, query).is_err());
}

#[test]
fn from_secp_keys_and_scan_block_batch_matches() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/send_and_receive_test_vectors.json")).unwrap();
    let given = &cases[0]["receiving"][0]["given"];
    let (block, prevouts, scanner, output) = fixture();

    let scan_bytes: [u8; 32] =
        hex::decode(given["key_material"]["scan_priv_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let spend_bytes: [u8; 32] =
        hex::decode(given["key_material"]["spend_priv_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();

    let secp_scan_sk = bitcoin::secp256k1::SecretKey::from_slice(&scan_bytes).unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let secp_spend_sk = bitcoin::secp256k1::SecretKey::from_slice(&spend_bytes).unwrap();
    let secp_spend_pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secp_spend_sk);

    let secp_scanner = SpScanner::from_secp_keys(&secp_scan_sk, &secp_spend_pk, &[]).unwrap();
    let matches_sequential = secp_scanner.scan_block(&block, &prevouts).unwrap();
    let matches_batch = secp_scanner.scan_block_batch(&block, &prevouts).unwrap();

    assert_eq!(matches_sequential.len(), 1);
    assert_eq!(matches_sequential, matches_batch);
    assert_eq!(
        matches_batch[0].payment.taproot_pubkey.as_slice(),
        output.as_slice()
    );

    let reference_matches = scanner.scan_block(&block, &prevouts).unwrap();
    assert_eq!(matches_batch, reference_matches);
}
