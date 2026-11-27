//! `no_std` BIP-374 v0.3.1 Discrete Log Equality (DLEQ) proofs and BIP-375
//! collaborative PSBT share verification + self-change collision guard.

use crate::{
    comb, compressed,
    coordinates::Affine,
    hash::{
        tagged_hash_midstate, MIDSTATE_BIP374_AUX, MIDSTATE_BIP374_CHALLENGE, MIDSTATE_BIP374_NONCE,
    },
    ssmb::GlvScalar,
    Error,
};
#[cfg(feature = "alloc")]
use crate::{
    hash::{tagged_hash_inputs, tagged_hash_shared_secret},
    scalar,
    sender::{ProvenancedRecipient, RecipientOrigin},
    K_MAX,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use k256::elliptic_curve::{group::prime::PrimeCurveAffine, ops::Reduce, Group, PrimeField};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

fn dleq_challenge(
    a_bytes: &[u8; 33],
    b_bytes: &[u8; 33],
    c_bytes: &[u8; 33],
    g_bytes: &[u8; 33],
    r1_bytes: &[u8; 33],
    r2_bytes: &[u8; 33],
    msg: Option<&[u8]>,
) -> Result<Scalar, Error> {
    let digest = match msg {
        Some(m) => {
            if m.len() != 32 {
                return Err(Error::InvalidProof);
            }
            tagged_hash_midstate(
                MIDSTATE_BIP374_CHALLENGE,
                &[a_bytes, b_bytes, c_bytes, g_bytes, r1_bytes, r2_bytes, m],
            )
        }
        None => tagged_hash_midstate(
            MIDSTATE_BIP374_CHALLENGE,
            &[a_bytes, b_bytes, c_bytes, g_bytes, r1_bytes, r2_bytes],
        ),
    };
    Ok(<Scalar as Reduce<U256>>::reduce_bytes((&digest).into()))
}

/// Generates a 64-byte BIP-374 v0.3.1 DLEQ proof `(e || s)` proving
/// `log_G(A) == log_B(C)` where `A = a * G` and `C = a * B`.
///
/// When `msg` is `Some`, BIP-374 requires an exact 32-byte message.
pub fn dleq_prove(
    secret_a: &Scalar,
    b_point: &AffinePoint,
    aux_rand: &[u8; 32],
    g_point: Option<&AffinePoint>,
    msg: Option<&[u8]>,
) -> Result<[u8; 64], Error> {
    dleq_prove_with_declassify(secret_a, b_point, aux_rand, g_point, msg, None)
}

/// Variant of `dleq_prove` with an explicit declassification hook for public wire
/// outputs (`A`, `C`, `R1`, `R2`, `proof`, and non-zero predicates), keeping
/// `secret_a`, `aux_rand`, and the ephemeral nonce `k` secret across all group
/// multiplications and `s = k + e*a`.
pub fn dleq_prove_with_declassify(
    secret_a: &Scalar,
    b_point: &AffinePoint,
    aux_rand: &[u8; 32],
    g_point: Option<&AffinePoint>,
    msg: Option<&[u8]>,
    declassify: Option<fn(*const u8, usize)>,
) -> Result<[u8; 64], Error> {
    if let Some(m) = msg {
        if m.len() != 32 {
            return Err(Error::InvalidProof);
        }
    }
    let a_zero = secret_a.is_zero().unwrap_u8();
    if let Some(f) = declassify {
        f(&a_zero as *const u8, 1);
    }
    if a_zero != 0 {
        return Err(Error::InvalidScalar);
    }
    let g_aff = g_point.copied().unwrap_or(AffinePoint::GENERATOR);
    if bool::from(g_aff.is_identity()) || bool::from(b_point.is_identity()) {
        return Err(Error::InvalidPoint);
    }
    let g_coord = Affine::from_k256(&g_aff);
    let b_coord = Affine::from_k256(b_point);

    let a_coord = if g_point.is_none() {
        comb::multiply_projective(secret_a).to_affine()
    } else {
        GlvScalar::new(secret_a)
            .multiply_single_affine(&g_coord)
            .to_affine()
    };
    let c_coord = GlvScalar::new(secret_a)
        .multiply_single_affine(&b_coord)
        .to_affine();
    if let Some(f) = declassify {
        f(
            (&a_coord as *const Affine).cast(),
            core::mem::size_of::<Affine>(),
        );
        f(
            (&c_coord as *const Affine).cast(),
            core::mem::size_of::<Affine>(),
        );
    }
    let a_bytes = a_coord.to_compressed_bytes()?;
    let b_bytes = compressed(b_point)?;
    let c_bytes = c_coord.to_compressed_bytes()?;
    let g_bytes = compressed(&g_aff)?;

    // t = a XOR tagged_hash("BIP0374/aux", aux_rand)
    let aux_hash = Zeroizing::new(tagged_hash_midstate(MIDSTATE_BIP374_AUX, &[aux_rand]));
    let a_scalar_bytes = Zeroizing::new(<[u8; 32]>::from(secret_a.to_bytes()));
    let mut t = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        t[i] = a_scalar_bytes[i] ^ aux_hash[i];
    }

    // rand = tagged_hash("BIP0374/nonce", t || cbytes(A) || cbytes(C) || m')
    let rand = Zeroizing::new(match msg {
        Some(m) => {
            tagged_hash_midstate(MIDSTATE_BIP374_NONCE, &[t.as_ref(), &a_bytes, &c_bytes, m])
        }
        None => tagged_hash_midstate(MIDSTATE_BIP374_NONCE, &[t.as_ref(), &a_bytes, &c_bytes]),
    });
    let k_val = <Scalar as Reduce<U256>>::reduce_bytes((&*rand).into());
    let k_valid = (!k_val.is_zero()).unwrap_u8();
    if let Some(f) = declassify {
        f(&k_valid as *const u8, 1);
    }
    if k_valid == 0 {
        return Err(Error::InvalidScalar);
    }
    let k = Zeroizing::new(k_val);

    let r1_coord = if g_point.is_none() {
        comb::multiply_projective(&k).to_affine()
    } else {
        GlvScalar::new(&k)
            .multiply_single_affine(&g_coord)
            .to_affine()
    };
    let r2_coord = GlvScalar::new(&k)
        .multiply_single_affine(&b_coord)
        .to_affine();
    if let Some(f) = declassify {
        f(
            (&r1_coord as *const Affine).cast(),
            core::mem::size_of::<Affine>(),
        );
        f(
            (&r2_coord as *const Affine).cast(),
            core::mem::size_of::<Affine>(),
        );
    }
    let r1_bytes = r1_coord.to_compressed_bytes()?;
    let r2_bytes = r2_coord.to_compressed_bytes()?;

    let e = dleq_challenge(
        &a_bytes, &b_bytes, &c_bytes, &g_bytes, &r1_bytes, &r2_bytes, msg,
    )?;
    let s = Zeroizing::new(*k + e * *secret_a);

    let mut proof = [0u8; 64];
    proof[..32].copy_from_slice(&e.to_bytes());
    proof[32..].copy_from_slice(&s.to_bytes());
    if let Some(f) = declassify {
        f(proof.as_ptr(), proof.len());
    }
    // BIP-374 fault-injection guard: abort if self-verification fails.
    let a_aff = a_coord.to_k256();
    let c_aff = c_coord.to_k256();
    if dleq_verify(&a_aff, b_point, &c_aff, &proof, Some(&g_aff), msg).is_err() {
        proof.zeroize();
        return Err(Error::InvalidProof);
    }
    Ok(proof)
}

/// Verifies a 64-byte BIP-374 v0.3.1 DLEQ proof `(e || s)` for `(A, B, C, G)`.
///
/// When `msg` is `Some`, BIP-374 requires an exact 32-byte message.
pub fn dleq_verify(
    a_point: &AffinePoint,
    b_point: &AffinePoint,
    c_point: &AffinePoint,
    proof: &[u8; 64],
    g_point: Option<&AffinePoint>,
    msg: Option<&[u8]>,
) -> Result<(), Error> {
    if let Some(m) = msg {
        if m.len() != 32 {
            return Err(Error::InvalidProof);
        }
    }
    let g_aff = g_point.copied().unwrap_or(AffinePoint::GENERATOR);
    if bool::from(a_point.is_identity())
        || bool::from(b_point.is_identity())
        || bool::from(c_point.is_identity())
        || bool::from(g_aff.is_identity())
    {
        return Err(Error::InvalidPoint);
    }

    let e_bytes: [u8; 32] = proof[..32].try_into().unwrap();
    let s_bytes: [u8; 32] = proof[32..].try_into().unwrap();
    let e = Option::<Scalar>::from(Scalar::from_repr(e_bytes.into())).ok_or(Error::InvalidProof)?;
    let s = Option::<Scalar>::from(Scalar::from_repr(s_bytes.into())).ok_or(Error::InvalidProof)?;

    let g_proj = ProjectivePoint::from(g_aff);
    let a_proj = ProjectivePoint::from(*a_point);
    let b_proj = ProjectivePoint::from(*b_point);
    let c_proj = ProjectivePoint::from(*c_point);

    let r1_proj = g_proj * s - a_proj * e;
    let r2_proj = b_proj * s - c_proj * e;
    if bool::from(r1_proj.is_identity()) || bool::from(r2_proj.is_identity()) {
        return Err(Error::InvalidProof);
    }

    let a_bytes = compressed(a_point)?;
    let b_bytes = compressed(b_point)?;
    let c_bytes = compressed(c_point)?;
    let g_bytes = compressed(&g_aff)?;
    let r1_bytes = compressed(&r1_proj.to_affine())?;
    let r2_bytes = compressed(&r2_proj.to_affine())?;

    let expected_e = dleq_challenge(
        &a_bytes, &b_bytes, &c_bytes, &g_bytes, &r1_bytes, &r2_bytes, msg,
    )?;
    if bool::from(!e.to_bytes().ct_eq(&expected_e.to_bytes())) {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

/// A single participant's BIP-375 ECDH share and BIP-374 DLEQ proof for one scan key.
#[derive(Clone, Copy, Debug)]
pub struct Bip375SignerShare {
    pub input_pubkey: AffinePoint,
    pub ecdh_share: AffinePoint,
    pub dleq_proof: [u8; 64],
}

/// Audits a BIP-375 collaborative recipient set for both cross-party scan-key
/// collisions and BIP-375 lexicographical `B_spend` self-change (`m = 0`) shadowing.
///
/// Under BIP-375, recipients sharing a scan key `B_scan` are canonically ordered by
/// lexicographical compressed `B_spend`. If an `External` recipient shares `B_scan`
/// with an `OwnVerified` change recipient and `B_spend_external < B_spend_change`,
/// BIP-375 assigns `k = 0` to the external recipient and `k = 1` to the wallet's
/// own change, rendering the change invisible to standard BIP-352 recovery.
#[cfg(feature = "alloc")]
pub fn audit_bip375_recipient_ordering(recipients: &[ProvenancedRecipient]) -> Result<(), Error> {
    let mut keys: Vec<([u8; 33], [u8; 33], RecipientOrigin)> = Vec::with_capacity(recipients.len());
    for r in recipients {
        keys.push((
            compressed(&r.recipient.scan)?,
            compressed(&r.recipient.spend)?,
            r.origin,
        ));
    }

    for (i, (scan_i, spend_i, origin_i)) in keys.iter().enumerate() {
        for (scan_j, spend_j, origin_j) in &keys[i + 1..] {
            if scan_i != scan_j {
                continue;
            }
            match (origin_i, origin_j) {
                (RecipientOrigin::External(p1), RecipientOrigin::External(p2)) if p1 != p2 => {
                    return Err(Error::ScanKeyCollision);
                }
                (RecipientOrigin::OwnVerified, RecipientOrigin::External(_))
                    if spend_j < spend_i =>
                {
                    return Err(Error::ChangeOrderShadowing);
                }
                (RecipientOrigin::External(_), RecipientOrigin::OwnVerified)
                    if spend_i < spend_j =>
                {
                    return Err(Error::ChangeOrderShadowing);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Verifies all BIP-375 signer DLEQ shares for one recipient `scan_pubkey`, aggregates
/// `C_sum`, folds `S = input_hash * C_sum`, assigns `k` by lexicographical ascending
/// compressed `B_spend` (breaking ties by ascending output index per BIP-375), and
/// returns Taproot x-only output keys in the caller's original positional order.
#[cfg(feature = "alloc")]
pub fn derive_bip375_outputs(
    signers: &[Bip375SignerShare],
    scan_pubkey: &AffinePoint,
    smallest_outpoint: &[u8; 36],
    spend_pubkeys: &[AffinePoint],
) -> Result<Vec<[u8; 32]>, Error> {
    if signers.is_empty() || spend_pubkeys.is_empty() {
        return Err(Error::InvalidPoint);
    }
    if spend_pubkeys.len() > K_MAX as usize {
        return Err(Error::BatchTooLarge);
    }

    let mut ordered_spends: Vec<([u8; 33], usize, AffinePoint)> =
        Vec::with_capacity(spend_pubkeys.len());
    for (idx, spend) in spend_pubkeys.iter().enumerate() {
        let enc = compressed(spend)?;
        ordered_spends.push((enc, idx, *spend));
    }
    ordered_spends.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut input_sum = ProjectivePoint::IDENTITY;
    let mut share_sum = ProjectivePoint::IDENTITY;
    for signer in signers {
        dleq_verify(
            &signer.input_pubkey,
            scan_pubkey,
            &signer.ecdh_share,
            &signer.dleq_proof,
            None,
            None,
        )?;
        input_sum += signer.input_pubkey;
        share_sum += signer.ecdh_share;
    }
    if bool::from(input_sum.is_identity()) || bool::from(share_sum.is_identity()) {
        return Err(Error::InvalidPoint);
    }

    let agg_bytes = compressed(&input_sum.to_affine())?;
    let input_hash = scalar(tagged_hash_inputs(smallest_outpoint, &agg_bytes))?;
    let shared_proj = share_sum * input_hash;
    if bool::from(shared_proj.is_identity()) {
        return Err(Error::InvalidPoint);
    }
    let shared_bytes = Zeroizing::new(compressed(&shared_proj.to_affine())?);

    let mut outputs = alloc::vec![[0u8; 32]; spend_pubkeys.len()];
    for (k, (_, orig_idx, spend)) in ordered_spends.into_iter().enumerate() {
        let t_k = Zeroizing::new(scalar(tagged_hash_shared_secret(&shared_bytes, k as u32))?);
        let out_proj = ProjectivePoint::from(spend) + comb::multiply_generator(&t_k);
        if bool::from(out_proj.is_identity()) {
            return Err(Error::InvalidPoint);
        }
        let enc = compressed(&out_proj.to_affine())?;
        outputs[orig_idx].copy_from_slice(&enc[1..33]);
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::sender::Recipient;

    #[test]
    fn dleq_prove_verify_and_tamper_rejection() {
        let a = Scalar::from(0x1337_beef_u64);
        let b = (ProjectivePoint::GENERATOR * Scalar::from(42u64)).to_affine();
        let a_pub = (ProjectivePoint::GENERATOR * a).to_affine();
        let c_pub = (ProjectivePoint::from(b) * a).to_affine();
        let aux = [0x99u8; 32];

        let proof = dleq_prove(&a, &b, &aux, None, None).unwrap();
        assert!(dleq_verify(&a_pub, &b, &c_pub, &proof, None, None).is_ok());

        // With optional 32-byte message
        let msg = [0x37u8; 32];
        let proof_msg = dleq_prove(&a, &b, &aux, None, Some(&msg)).unwrap();
        assert!(dleq_verify(&a_pub, &b, &c_pub, &proof_msg, None, Some(&msg)).is_ok());
        assert_eq!(
            dleq_verify(&a_pub, &b, &c_pub, &proof_msg, None, None),
            Err(Error::InvalidProof)
        );
        // Non-32-byte message rejected per BIP-374
        assert_eq!(
            dleq_prove(&a, &b, &aux, None, Some(b"too-short")),
            Err(Error::InvalidProof)
        );
        assert_eq!(
            dleq_verify(&a_pub, &b, &c_pub, &proof_msg, None, Some(b"too-short")),
            Err(Error::InvalidProof)
        );

        // Single-bit flip rejected
        let mut bad = proof;
        bad[63] ^= 1;
        assert_eq!(
            dleq_verify(&a_pub, &b, &c_pub, &bad, None, None),
            Err(Error::InvalidProof)
        );

        // Wrong point rejected
        let wrong_c = (ProjectivePoint::from(c_pub) + ProjectivePoint::GENERATOR).to_affine();
        assert_eq!(
            dleq_verify(&a_pub, &b, &wrong_c, &proof, None, None),
            Err(Error::InvalidProof)
        );

        // Identity point rejected
        assert_eq!(
            dleq_verify(&a_pub, &b, &AffinePoint::IDENTITY, &proof, None, None),
            Err(Error::InvalidPoint)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn bip375_lex_order_change_shadowing_and_output_derivation() {
        let scan = (ProjectivePoint::GENERATOR * Scalar::from(5u64)).to_affine();
        // Find two compressed spend keys where sp_small < sp_large lexicographically.
        let p1 = (ProjectivePoint::GENERATOR * Scalar::from(10u64)).to_affine();
        let p2 = (ProjectivePoint::GENERATOR * Scalar::from(11u64)).to_affine();
        let (sp_small, sp_large) = if compressed(&p1).unwrap() < compressed(&p2).unwrap() {
            (p1, p2)
        } else {
            (p2, p1)
        };

        // External spend < OwnVerified change -> shadowing MUST fail closed.
        let shadowed = [
            ProvenancedRecipient {
                recipient: Recipient {
                    scan,
                    spend: sp_small,
                },
                origin: RecipientOrigin::External(1),
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan,
                    spend: sp_large,
                },
                origin: RecipientOrigin::OwnVerified,
            },
        ];
        assert_eq!(
            audit_bip375_recipient_ordering(&shadowed),
            Err(Error::ChangeOrderShadowing)
        );

        // OwnVerified change < External spend -> safe under BIP-375 lex ordering.
        let safe = [
            ProvenancedRecipient {
                recipient: Recipient {
                    scan,
                    spend: sp_small,
                },
                origin: RecipientOrigin::OwnVerified,
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan,
                    spend: sp_large,
                },
                origin: RecipientOrigin::External(1),
            },
        ];
        assert!(audit_bip375_recipient_ordering(&safe).is_ok());

        // Cross-party collision still rejected even with OwnVerified present.
        let cross = [
            ProvenancedRecipient {
                recipient: Recipient {
                    scan,
                    spend: sp_small,
                },
                origin: RecipientOrigin::OwnVerified,
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan,
                    spend: sp_large,
                },
                origin: RecipientOrigin::External(1),
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan,
                    spend: sp_large,
                },
                origin: RecipientOrigin::External(2),
            },
        ];
        assert_eq!(
            audit_bip375_recipient_ordering(&cross),
            Err(Error::ScanKeyCollision)
        );

        // End-to-end 2-signer BIP-375 derivation assigns k by lex order regardless of input slice order.
        let a1 = Scalar::from(101u64);
        let a2 = Scalar::from(202u64);
        let s1 = Bip375SignerShare {
            input_pubkey: (ProjectivePoint::GENERATOR * a1).to_affine(),
            ecdh_share: (ProjectivePoint::from(scan) * a1).to_affine(),
            dleq_proof: dleq_prove(&a1, &scan, &[1u8; 32], None, None).unwrap(),
        };
        let s2 = Bip375SignerShare {
            input_pubkey: (ProjectivePoint::GENERATOR * a2).to_affine(),
            ecdh_share: (ProjectivePoint::from(scan) * a2).to_affine(),
            dleq_proof: dleq_prove(&a2, &scan, &[2u8; 32], None, None).unwrap(),
        };
        let outs_ordered =
            derive_bip375_outputs(&[s1, s2], &scan, &[0u8; 36], &[sp_small, sp_large])
                .expect("valid bip375 shares");
        let outs_swapped =
            derive_bip375_outputs(&[s1, s2], &scan, &[0u8; 36], &[sp_large, sp_small])
                .expect("valid bip375 shares");
        assert_eq!(outs_ordered.len(), 2);
        // Positional mapping preserved, k assigned lexicographically:
        assert_eq!(outs_swapped[0], outs_ordered[1]);
        assert_eq!(outs_swapped[1], outs_ordered[0]);
    }
}
