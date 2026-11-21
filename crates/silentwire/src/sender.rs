use crate::{compressed, scalar, tagged_hash, Error, K_MAX};
use alloc::vec::Vec;
use k256::{
    elliptic_curve::{group::Group, ops::MulByGenerator, point::AffineCoordinates},
    AffinePoint, ProjectivePoint, Scalar,
};
use subtle::ConditionallySelectable;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderInput {
    pub secret: [u8; 32],
    pub is_taproot: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recipient {
    pub scan: AffinePoint,
    pub spend: AffinePoint,
}

/// Trust provenance for a recipient inside a shared-scan-key group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientOrigin {
    /// Spend key verified as owned by the caller (own unlabeled spend key,
    /// change label `m = 0`, or a label present in the caller's label cache).
    /// Always ordered ahead of `External` entries sharing the same `scan` key
    /// so self-change remains findable on rescan without rejecting or splitting.
    OwnVerified,
    /// Recipient supplied by an external party identified by `party_id`.
    /// Distinct external parties with different spend keys must not share a
    /// scan key in the same transaction.
    External(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvenancedRecipient {
    pub recipient: Recipient,
    pub origin: RecipientOrigin,
}

pub fn aggregate_secret(inputs: &[SenderInput]) -> Result<Scalar, Error> {
    let mut sum = Zeroizing::new(Scalar::ZERO);
    for input in inputs {
        let mut key = Zeroizing::new(scalar(input.secret)?);
        if input.is_taproot {
            *key = Scalar::conditional_select(
                &key,
                &-*key,
                ProjectivePoint::mul_by_generator(&key)
                    .to_affine()
                    .y_is_odd(),
            );
        }
        *sum += *key;
    }
    Ok(*sum)
}

/// Low-level BIP-352 output derivation matching reference test vectors.
///
/// Recipients sharing `scan` share one `k` counter in slice order. Because
/// BIP-352 receivers stop at the first missing `k`, placing an unowned spend
/// key ahead of a receiver's spend key hides subsequent outputs in that group
/// (including the sender's own `m = 0` change output). Callers batching
/// recipients or emitting BIP-352 change should use [`create_outputs_checked`].
pub fn create_outputs(
    inputs: &[SenderInput],
    outpoints: &[[u8; 36]],
    recipients: &[Recipient],
) -> Result<Vec<[u8; 32]>, Error> {
    let sum = Zeroizing::new(aggregate_secret(inputs)?);
    if bool::from(sum.is_zero()) {
        return Ok(Vec::new());
    }
    let public = ProjectivePoint::mul_by_generator(&sum).to_affine();
    let lowest = outpoints.iter().min().ok_or(Error::InvalidPoint)?;
    let hash = scalar(tagged_hash(
        b"BIP0352/Inputs",
        &[lowest, &compressed(&public)?],
    ))?;
    for recipient in recipients {
        if recipients
            .iter()
            .filter(|r| r.scan == recipient.scan)
            .count()
            > K_MAX as usize
        {
            return Ok(Vec::new());
        }
    }
    let mut outputs = Vec::with_capacity(recipients.len());
    for (index, recipient) in recipients.iter().enumerate() {
        if bool::from(ProjectivePoint::from(recipient.scan).is_identity())
            || bool::from(ProjectivePoint::from(recipient.spend).is_identity())
        {
            return Err(Error::InvalidPoint);
        }
        let k = recipients[..index]
            .iter()
            .filter(|r| r.scan == recipient.scan)
            .count() as u32;
        let shared = (ProjectivePoint::from(recipient.scan) * (hash * *sum)).to_affine();
        let encoded = Zeroizing::new(compressed(&shared)?);
        let tweak = scalar(tagged_hash(
            b"BIP0352/SharedSecret",
            &[encoded.as_ref(), &k.to_be_bytes()],
        ))?;
        let destination = (ProjectivePoint::from(recipient.spend)
            + ProjectivePoint::mul_by_generator(&tweak))
        .to_affine();
        outputs.push(
            compressed(&destination)?[1..]
                .try_into()
                .map_err(|_| Error::InvalidPoint)?,
        );
    }
    outputs.sort_unstable();
    outputs.dedup();
    Ok(outputs)
}

/// Derive BIP-352 output keys in 1-to-1 positional correspondence with
/// `recipients` while enforcing scan-key group safety. Rejects
/// `Error::ScanKeyCollision` when distinct `External` parties share a `scan`
/// key with different `spend` keys, permits identical `(scan, spend)` pairs
/// and same-party labels, and assigns lower `k` (`0..r`) to `OwnVerified`
/// entries ahead of `External` entries so self-change remains recoverable.
pub fn create_outputs_checked(
    inputs: &[SenderInput],
    outpoints: &[[u8; 36]],
    recipients: &[ProvenancedRecipient],
) -> Result<Vec<[u8; 32]>, Error> {
    for entry in recipients {
        if bool::from(ProjectivePoint::from(entry.recipient.scan).is_identity())
            || bool::from(ProjectivePoint::from(entry.recipient.spend).is_identity())
        {
            return Err(Error::InvalidPoint);
        }
    }

    for (i, a) in recipients.iter().enumerate() {
        let mut group_count = 1usize;
        for b in &recipients[i + 1..] {
            if a.recipient.scan != b.recipient.scan {
                continue;
            }
            group_count += 1;
            if a.recipient.spend != b.recipient.spend {
                if let (RecipientOrigin::External(p1), RecipientOrigin::External(p2)) =
                    (a.origin, b.origin)
                {
                    if p1 != p2 {
                        return Err(Error::ScanKeyCollision);
                    }
                }
            }
        }
        if group_count > K_MAX as usize {
            return Err(Error::BatchTooLarge);
        }
    }

    let sum = Zeroizing::new(aggregate_secret(inputs)?);
    if bool::from(sum.is_zero()) {
        return Err(Error::InvalidScalar);
    }
    let public = ProjectivePoint::mul_by_generator(&sum).to_affine();
    let lowest = outpoints.iter().min().ok_or(Error::InvalidPoint)?;
    let hash = scalar(tagged_hash(
        b"BIP0352/Inputs",
        &[lowest, &compressed(&public)?],
    ))?;
    if recipients.is_empty() {
        return Ok(Vec::new());
    }

    let partial = Zeroizing::new(hash * *sum);
    let mut shared_cache: Vec<(AffinePoint, Zeroizing<[u8; 33]>, u32)> = Vec::new();
    for entry in recipients {
        let scan = entry.recipient.scan;
        if let Some((_, _, own_count)) = shared_cache.iter_mut().find(|(s, _, _)| *s == scan) {
            if entry.origin == RecipientOrigin::OwnVerified {
                *own_count += 1;
            }
        } else {
            let shared = (ProjectivePoint::from(scan) * *partial).to_affine();
            let encoded = Zeroizing::new(compressed(&shared)?);
            let own = u32::from(entry.origin == RecipientOrigin::OwnVerified);
            shared_cache.push((scan, encoded, own));
        }
    }

    let mut outputs = Vec::with_capacity(recipients.len());
    for (index, entry) in recipients.iter().enumerate() {
        let scan = entry.recipient.scan;
        let (_, encoded, own_count) = shared_cache
            .iter()
            .find(|(s, _, _)| *s == scan)
            .ok_or(Error::InvalidPoint)?;
        let k = match entry.origin {
            RecipientOrigin::OwnVerified => recipients[..index]
                .iter()
                .filter(|r| r.recipient.scan == scan && r.origin == RecipientOrigin::OwnVerified)
                .count() as u32,
            RecipientOrigin::External(_) => {
                *own_count
                    + recipients[..index]
                        .iter()
                        .filter(|r| {
                            r.recipient.scan == scan
                                && matches!(r.origin, RecipientOrigin::External(_))
                        })
                        .count() as u32
            }
        };
        let tweak = Zeroizing::new(scalar(tagged_hash(
            b"BIP0352/SharedSecret",
            &[encoded.as_ref(), &k.to_be_bytes()],
        ))?);
        let destination = (ProjectivePoint::from(entry.recipient.spend)
            + ProjectivePoint::mul_by_generator(&*tweak))
        .to_affine();
        outputs.push(
            compressed(&destination)?[1..]
                .try_into()
                .map_err(|_| Error::InvalidPoint)?,
        );
    }

    Ok(outputs)
}
