use crate::{compressed, hash::tagged_hash_inputs, point, scalar, Error};
use bitcoin_hashes::{hash160, Hash};
use k256::{elliptic_curve::group::Group, AffinePoint, ProjectivePoint, Scalar};

const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub struct ValidatedInput<'a> {
    pub outpoint: [u8; 36],
    pub prevout_script: &'a [u8],
    pub script_sig: &'a [u8],
    pub witness: &'a [&'a [u8]],
}

pub fn spends_future_witness(script: &[u8]) -> bool {
    (4..=42).contains(&script.len())
        && (0x52..=0x60).contains(&script[0])
        && usize::from(script[1]) == script.len() - 2
}

/// Parses complete Bitcoin Script push operations in `script_sig` without
/// scanning across opcode boundaries, returning the last pushed 33-byte
/// compressed public key whose `HASH160` matches `expected_hash`.
///
/// Legacy P2PKH scriptSigs can carry third-party malleated non-push opcodes
/// such as `<dummy> OP_DROP <sig> <pubkey>`. Non-push single-byte opcodes step
/// cleanly without slicing inside pushed payload bytes.
fn extract_p2pkh_push_pubkey(script_sig: &[u8], expected_hash: &[u8]) -> Option<AffinePoint> {
    let mut cursor = 0usize;
    let mut matched: Option<AffinePoint> = None;

    while cursor < script_sig.len() {
        let opcode = script_sig[cursor];
        cursor += 1;
        let push_len = match opcode {
            0x01..=0x4b => usize::from(opcode),
            0x4c => {
                let end = cursor.checked_add(1)?;
                if end > script_sig.len() {
                    return None;
                }
                let n = usize::from(script_sig[cursor]);
                cursor = end;
                n
            }
            0x4d => {
                let end = cursor.checked_add(2)?;
                if end > script_sig.len() {
                    return None;
                }
                let n = usize::from(u16::from_le_bytes([
                    script_sig[cursor],
                    script_sig[cursor + 1],
                ]));
                cursor = end;
                n
            }
            0x4e => {
                let end = cursor.checked_add(4)?;
                if end > script_sig.len() {
                    return None;
                }
                let n = usize::try_from(u32::from_le_bytes([
                    script_sig[cursor],
                    script_sig[cursor + 1],
                    script_sig[cursor + 2],
                    script_sig[cursor + 3],
                ]))
                .ok()?;
                cursor = end;
                n
            }
            _ => continue,
        };
        let data_end = cursor.checked_add(push_len)?;
        if data_end > script_sig.len() {
            return None;
        }
        let pushed = &script_sig[cursor..data_end];
        cursor = data_end;
        if pushed.len() == 33 && hash160::Hash::hash(pushed).as_byte_array()[..] == *expected_hash {
            if let Ok(key) = point(pushed) {
                matched = Some(key);
            }
        }
    }

    matched
}

pub fn extract_key(input: &ValidatedInput<'_>) -> Result<Option<AffinePoint>, Error> {
    let script = input.prevout_script;
    if script.len() == 25 && script[..3] == [0x76, 0xa9, 0x14] && script[23..] == [0x88, 0xac] {
        return Ok(extract_p2pkh_push_pubkey(input.script_sig, &script[3..23]));
    }
    let p2wpkh = script.len() == 22 && script[..2] == [0, 20];
    // BIP-141 requires nested P2SH-P2WPKH scriptSig to be the exact 23-byte
    // direct push [0x16, 0x00, 0x14, <20-byte-hash>] matching HASH160(redeem).
    let nested = script.len() == 23
        && script[..2] == [0xa9, 20]
        && script[22] == 0x87
        && input.script_sig.len() == 23
        && input.script_sig[..3] == [22, 0, 20]
        && hash160::Hash::hash(&input.script_sig[1..]).as_byte_array()[..] == script[2..22];
    if p2wpkh || nested {
        if input.witness.len() != 2 {
            return Ok(None);
        }
        return Ok(input.witness.last().and_then(|key| point(key).ok()));
    }
    if let Some(x) = crate::p2tr_key(script) {
        let mut witness = input.witness;
        if witness.len() > 1
            && witness
                .last()
                .is_some_and(|item| item.first() == Some(&0x50))
        {
            witness = &witness[..witness.len() - 1];
        }
        if witness.is_empty() {
            return Err(Error::InvalidWitness);
        }
        if witness.len() > 1 {
            let control = witness[witness.len() - 1];
            if !(33..=4129).contains(&control.len()) || !(control.len() - 33).is_multiple_of(32) {
                return Err(Error::InvalidWitness);
            }
            if control[1..33] == NUMS_H {
                return Ok(None);
            }
        }
        let mut encoded = [2; 33];
        encoded[1..].copy_from_slice(x);
        return point(&encoded).map(Some);
    }
    Ok(None)
}

#[derive(Clone)]
pub struct PreparedTransaction {
    pub aggregate: AffinePoint,
    pub input_hash: Scalar,
    pub tweak: ProjectivePoint,
}

pub fn prepare(inputs: &[ValidatedInput<'_>]) -> Result<Option<PreparedTransaction>, Error> {
    if inputs.is_empty()
        || inputs
            .iter()
            .any(|i| spends_future_witness(i.prevout_script))
    {
        return Ok(None);
    }
    let mut sum = ProjectivePoint::IDENTITY;
    for input in inputs {
        if let Some(key) = extract_key(input)? {
            sum += key;
        }
    }
    if bool::from(sum.is_identity()) {
        return Ok(None);
    }
    let aggregate = sum.to_affine();
    let lowest = inputs
        .iter()
        .map(|i| &i.outpoint)
        .min()
        .ok_or(Error::InvalidPoint)?;
    let agg_bytes = compressed(&aggregate)?;
    let input_hash = scalar(tagged_hash_inputs(lowest, &agg_bytes))?;
    Ok(Some(PreparedTransaction {
        aggregate,
        input_hash,
        tweak: sum * input_hash,
    }))
}
