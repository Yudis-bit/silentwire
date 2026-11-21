#![allow(deprecated)]
//! Compile-time SHA-256 midstates for BIP-352 and BIP-374 tagged hashes.
//!
//! Because `SHA256(tag) || SHA256(tag)` is exactly 64 bytes (one SHA-256 block),
//! starting from the precomputed midstate reduces single-block payloads such as
//! `BIP0352/SharedSecret` (37 bytes) and `BIP0352/Label` (36 bytes) from three
//! SHA-256 block compressions to one.

use sha2::digest::generic_array::GenericArray;

pub(crate) const MIDSTATE_SHARED_SECRET: [u32; 8] = [
    0x8883_1537,
    0x5127_079b,
    0x69c2_137b,
    0xab03_03e6,
    0x98fa_21fa,
    0x4a88_8523,
    0xbd99_daab,
    0xf25e_5e0a,
];

pub(crate) const MIDSTATE_INPUTS: [u32; 8] = [
    0xd414_3ffc,
    0x012e_a4b5,
    0x36e2_1c8f,
    0xf7ec_7b54,
    0x4dd4_e2ac,
    0x9bca_a0a4,
    0xe244_899b,
    0xcd06_903e,
];

pub(crate) const MIDSTATE_LABEL: [u32; 8] = [
    0x26b9_5d63,
    0x8bf1_b740,
    0x10a5_986f,
    0x06a3_87a5,
    0x2d1c_1c30,
    0xd035_951a,
    0x2d7f_0f96,
    0x29e3_e0db,
];

pub(crate) const MIDSTATE_BIP374_AUX: [u32; 8] = [
    0x4847_9343,
    0xa9eb_648c,
    0x5895_2fe4,
    0x4772_d3b2,
    0x977a_b0a0,
    0xcb8e_2740,
    0x60bb_4b81,
    0x68a4_1b66,
];

pub(crate) const MIDSTATE_BIP374_NONCE: [u32; 8] = [
    0xa810_fc87,
    0x3b4a_4d2a,
    0xe302_cfb4,
    0x322d_f1a0,
    0xd2e7_fb82,
    0x7808_570d,
    0x9c33_e0cd,
    0x2dfb_f7f6,
];

pub(crate) const MIDSTATE_BIP374_CHALLENGE: [u32; 8] = [
    0x24f1_c9c7,
    0xd153_8c75,
    0xc987_4ae8,
    0x6566_de76,
    0x4878_43c9,
    0xc13d_8026,
    0x39a2_f3ef,
    0x2ad0_fcb3,
];

#[inline(always)]
fn finalize_state(state: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Computes `tagged_hash("BIP0352/SharedSecret", &[shared_compressed, &k.to_be_bytes()])`
/// in a single SHA-256 compression block.
#[inline]
pub(crate) fn tagged_hash_shared_secret(shared_compressed: &[u8; 33], k: u32) -> [u8; 32] {
    let mut state = MIDSTATE_SHARED_SECRET;
    let mut block = [0u8; 64];
    block[..33].copy_from_slice(shared_compressed);
    block[33..37].copy_from_slice(&k.to_be_bytes());
    block[37] = 0x80;
    // Total message length = 64 (tag prefix) + 37 (payload) = 101 bytes = 808 bits.
    block[56..64].copy_from_slice(&(101u64 * 8).to_be_bytes());
    sha2::compress256(
        &mut state,
        core::slice::from_ref(GenericArray::from_slice(&block)),
    );
    finalize_state(state)
}

/// Computes `tagged_hash("BIP0352/Label", &[scan_privkey, &m.to_be_bytes()])`
/// in a single SHA-256 compression block.
#[inline]
pub(crate) fn tagged_hash_label(scan_privkey: &[u8; 32], m: u32) -> [u8; 32] {
    let mut state = MIDSTATE_LABEL;
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(scan_privkey);
    block[32..36].copy_from_slice(&m.to_be_bytes());
    block[36] = 0x80;
    // Total message length = 64 + 36 = 100 bytes = 800 bits.
    block[56..64].copy_from_slice(&(100u64 * 8).to_be_bytes());
    sha2::compress256(
        &mut state,
        core::slice::from_ref(GenericArray::from_slice(&block)),
    );
    finalize_state(state)
}

/// Computes `tagged_hash("BIP0352/Inputs", &[outpoint, aggregate_compressed])`
/// starting from the precomputed midstate (2 blocks instead of 4).
#[inline]
pub(crate) fn tagged_hash_inputs(outpoint: &[u8; 36], aggregate_compressed: &[u8; 33]) -> [u8; 32] {
    let mut state = MIDSTATE_INPUTS;
    let mut blocks = [[0u8; 64]; 2];
    blocks[0][..36].copy_from_slice(outpoint);
    blocks[0][36..64].copy_from_slice(&aggregate_compressed[..28]);
    blocks[1][..5].copy_from_slice(&aggregate_compressed[28..33]);
    blocks[1][5] = 0x80;
    // Total message length = 64 + 69 = 133 bytes = 1064 bits.
    blocks[1][56..64].copy_from_slice(&(133u64 * 8).to_be_bytes());
    let arr = [
        *GenericArray::from_slice(&blocks[0]),
        *GenericArray::from_slice(&blocks[1]),
    ];
    sha2::compress256(&mut state, &arr);
    finalize_state(state)
}

/// Streams arbitrary parts into a precomputed 64-byte tagged-hash midstate.
pub(crate) fn tagged_hash_midstate(midstate: [u32; 8], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = midstate;
    let mut block = [0u8; 64];
    let mut filled = 0usize;
    let mut total_bytes: u64 = 64;

    for part in parts {
        let mut slice = *part;
        total_bytes = total_bytes.wrapping_add(slice.len() as u64);
        if filled > 0 {
            let take = (64 - filled).min(slice.len());
            block[filled..filled + take].copy_from_slice(&slice[..take]);
            filled += take;
            slice = &slice[take..];
            if filled == 64 {
                sha2::compress256(
                    &mut state,
                    core::slice::from_ref(GenericArray::from_slice(&block)),
                );
                filled = 0;
            }
        }
        while slice.len() >= 64 {
            sha2::compress256(
                &mut state,
                core::slice::from_ref(GenericArray::from_slice(&slice[..64])),
            );
            slice = &slice[64..];
        }
        if !slice.is_empty() {
            block[..slice.len()].copy_from_slice(slice);
            filled = slice.len();
        }
    }

    block[filled] = 0x80;
    for byte in &mut block[filled + 1..] {
        *byte = 0;
    }
    if filled >= 56 {
        sha2::compress256(
            &mut state,
            core::slice::from_ref(GenericArray::from_slice(&block)),
        );
        block = [0u8; 64];
    }
    block[56..64].copy_from_slice(&(total_bytes * 8).to_be_bytes());
    sha2::compress256(
        &mut state,
        core::slice::from_ref(GenericArray::from_slice(&block)),
    );
    finalize_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagged_hash;

    #[test]
    fn midstates_match_reference_tagged_hash() {
        let shared = [0x02u8; 33];
        assert_eq!(
            tagged_hash_shared_secret(&shared, 0),
            tagged_hash(b"BIP0352/SharedSecret", &[&shared, &0u32.to_be_bytes()])
        );
        assert_eq!(
            tagged_hash_shared_secret(&shared, 2322),
            tagged_hash(b"BIP0352/SharedSecret", &[&shared, &2322u32.to_be_bytes()])
        );

        let scan = [0x42u8; 32];
        assert_eq!(
            tagged_hash_label(&scan, 0),
            tagged_hash(b"BIP0352/Label", &[&scan, &0u32.to_be_bytes()])
        );
        assert_eq!(
            tagged_hash_label(&scan, 999),
            tagged_hash(b"BIP0352/Label", &[&scan, &999u32.to_be_bytes()])
        );

        let outpoint = [0x11u8; 36];
        let agg = [0x03u8; 33];
        assert_eq!(
            tagged_hash_inputs(&outpoint, &agg),
            tagged_hash(b"BIP0352/Inputs", &[&outpoint, &agg])
        );

        for (tag, mid) in [
            (b"BIP0374/aux".as_slice(), MIDSTATE_BIP374_AUX),
            (b"BIP0374/nonce".as_slice(), MIDSTATE_BIP374_NONCE),
            (b"BIP0374/challenge".as_slice(), MIDSTATE_BIP374_CHALLENGE),
        ] {
            for len in [0usize, 1, 32, 55, 56, 63, 64, 65, 128, 199] {
                let msg = alloc::vec![0xab; len];
                assert_eq!(
                    tagged_hash_midstate(mid, &[&msg]),
                    tagged_hash(tag, &[&msg]),
                    "mismatch for len {len}"
                );
            }
        }
    }
}
