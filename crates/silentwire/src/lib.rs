#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod address;
pub mod batch;
pub mod bip374;
mod comb;
mod coordinates;
pub mod embedded;
pub mod hardened;
mod hash;
pub mod input;
pub mod matcher;
mod scanner;
pub mod sender;
pub mod ssmb;

pub use address::{Network, SilentPaymentAddress};
pub use bip374::{
    audit_bip375_recipient_ordering, derive_bip375_outputs, dleq_prove, dleq_verify,
    Bip375SignerShare,
};
pub use embedded::EmbeddedStaticScanner;
pub use hardened::{audit_candidate_tweak, is_on_quadratic_twist, HardenedMultiplier};
pub use k256;
pub use scanner::{
    BlockPaymentMatch, ScanContext, ScanTransaction, SilentPaymentMatch, SpScannerNaive,
    ADAPTIVE_LABEL_THRESHOLD,
};
pub use subtle;
pub use zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidScalar,
    InvalidPoint,
    InvalidWitness,
    InvalidAddress,
    InvalidProof,
    ScratchTooSmall,
    BatchTooLarge,
    AllocationFailed,
    ScanKeyCollision,
    ChangeOrderShadowing,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidScalar => write!(f, "Invalid scalar"),
            Self::InvalidPoint => write!(f, "Invalid point"),
            Self::InvalidWitness => write!(f, "Invalid witness"),
            Self::InvalidAddress => write!(f, "Invalid BIP-352 address"),
            Self::InvalidProof => write!(f, "Invalid BIP-374 DLEQ proof"),
            Self::ScratchTooSmall => write!(f, "Scratch buffer too small"),
            Self::BatchTooLarge => write!(f, "Batch size exceeds maximum"),
            Self::AllocationFailed => write!(f, "Result allocation failed"),
            Self::ScanKeyCollision => write!(
                f,
                "Recipients from different parties share a scan key with distinct spend keys"
            ),
            Self::ChangeOrderShadowing => write!(
                f,
                "External spend key sorts before own change key under BIP-375 lexicographical ordering"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub const MAX_BATCH: usize = 4096;
pub const K_MAX: u32 = 2323;

pub fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let tag_hash = Sha256::digest(tag);
    let mut state = Sha256::new();
    state.update(tag_hash);
    state.update(tag_hash);
    for part in parts {
        state.update(part);
    }
    state.finalize().into()
}

pub fn scalar(bytes: [u8; 32]) -> Result<k256::Scalar, Error> {
    use k256::elliptic_curve::PrimeField;
    let value = Option::<k256::Scalar>::from(k256::Scalar::from_repr(bytes.into()))
        .ok_or(Error::InvalidScalar)?;
    if bool::from(value.is_zero()) {
        return Err(Error::InvalidScalar);
    }
    Ok(value)
}

pub fn point(bytes: &[u8]) -> Result<k256::AffinePoint, Error> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    if bytes.len() != 33 || !matches!(bytes[0], 2 | 3) {
        return Err(Error::InvalidPoint);
    }
    let encoded = k256::EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPoint)?;
    Option::from(k256::AffinePoint::from_encoded_point(&encoded)).ok_or(Error::InvalidPoint)
}

pub fn compressed(point: &k256::AffinePoint) -> Result<[u8; 33], Error> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    point
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| Error::InvalidPoint)
}

pub fn p2tr_key(script: &[u8]) -> Option<&[u8; 32]> {
    if script.len() == 34 && script[..2] == [0x51, 0x20] {
        script[2..].try_into().ok()
    } else {
        None
    }
}
