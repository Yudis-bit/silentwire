use crate::filter::FastGcsFilterMatcher;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use silentwire::input::PreparedTransaction;
use silentwire::k256::{AffinePoint, ProjectivePoint, Scalar};
use silentwire::{
    audit_candidate_tweak, is_on_quadratic_twist, Error as SpError, SilentPaymentMatch,
    SpScannerNaive,
};

#[derive(Debug, Eq, PartialEq)]
pub enum CtisError {
    UnexpectedEof,
    MalformedCompactSize,
    MalformedPoint(usize),
    TwistPointDetected(usize),
    FilterParseError,
    Arithmetic(SpError),
}

impl core::fmt::Display for CtisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "Unexpected end of file in CTIS stream"),
            Self::MalformedCompactSize => write!(f, "Malformed compact size in CTIS stream"),
            Self::MalformedPoint(idx) => {
                write!(f, "Malformed candidate tweak point at index {idx}")
            }
            Self::TwistPointDetected(idx) => {
                write!(
                    f,
                    "Quadratic twist point rejected fail-closed at index {idx}"
                )
            }
            Self::FilterParseError => write!(f, "Failed to parse BIP-158 GCS filter"),
            Self::Arithmetic(err) => write!(f, "Arithmetic error during CTIS scan: {err}"),
        }
    }
}

impl std::error::Error for CtisError {}

impl From<SpError> for CtisError {
    fn from(value: SpError) -> Self {
        Self::Arithmetic(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactTweakBlock {
    pub height: u32,
    pub block_hash: BlockHash,
    pub candidate_tweaks: Vec<[u8; 33]>,
    pub gcs_filter_bytes: Vec<u8>,
}

fn read_compact_size(data: &[u8], cursor: &mut usize) -> Result<usize, CtisError> {
    if *cursor >= data.len() {
        return Err(CtisError::UnexpectedEof);
    }
    let first = data[*cursor];
    *cursor = cursor.checked_add(1).ok_or(CtisError::UnexpectedEof)?;
    match first {
        0..=0xfc => Ok(usize::from(first)),
        0xfd => {
            let end = cursor.checked_add(2).ok_or(CtisError::UnexpectedEof)?;
            if end > data.len() {
                return Err(CtisError::UnexpectedEof);
            }
            let val = u16::from_le_bytes(data[*cursor..end].try_into().unwrap());
            if val < 0xfd {
                return Err(CtisError::MalformedCompactSize);
            }
            *cursor = end;
            Ok(usize::from(val))
        }
        0xfe => {
            let end = cursor.checked_add(4).ok_or(CtisError::UnexpectedEof)?;
            if end > data.len() {
                return Err(CtisError::UnexpectedEof);
            }
            let val = u32::from_le_bytes(data[*cursor..end].try_into().unwrap());
            if val <= 0xffff {
                return Err(CtisError::MalformedCompactSize);
            }
            *cursor = end;
            usize::try_from(val).map_err(|_| CtisError::UnexpectedEof)
        }
        0xff => {
            let end = cursor.checked_add(8).ok_or(CtisError::UnexpectedEof)?;
            if end > data.len() {
                return Err(CtisError::UnexpectedEof);
            }
            let val = u64::from_le_bytes(data[*cursor..end].try_into().unwrap());
            if val <= 0xffff_ffff {
                return Err(CtisError::MalformedCompactSize);
            }
            *cursor = end;
            usize::try_from(val).map_err(|_| CtisError::UnexpectedEof)
        }
    }
}

fn write_compact_size(val: usize, out: &mut Vec<u8>) {
    if val < 0xfd {
        out.push(val as u8);
    } else if val <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&(val as u64).to_le_bytes());
    }
}

impl CompactTweakBlock {
    pub fn new(
        height: u32,
        block_hash: BlockHash,
        candidate_tweaks: Vec<[u8; 33]>,
        gcs_filter_bytes: Vec<u8>,
    ) -> Self {
        Self {
            height,
            block_hash,
            candidate_tweaks,
            gcs_filter_bytes,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            4 + 32 + 3 + self.candidate_tweaks.len() * 33 + 3 + self.gcs_filter_bytes.len(),
        );
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(self.block_hash.as_byte_array());

        write_compact_size(self.candidate_tweaks.len(), &mut out);
        for tweak in &self.candidate_tweaks {
            out.extend_from_slice(tweak);
        }

        write_compact_size(self.gcs_filter_bytes.len(), &mut out);
        out.extend_from_slice(&self.gcs_filter_bytes);

        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, CtisError> {
        let mut cursor = 0usize;
        if data.len() < 36 {
            return Err(CtisError::UnexpectedEof);
        }

        let height = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;

        let hash_bytes: [u8; 32] = data[cursor..cursor + 32].try_into().unwrap();
        let block_hash = BlockHash::from_byte_array(hash_bytes);
        cursor += 32;

        let tweaks_count = read_compact_size(data, &mut cursor)?;
        let remaining = data
            .len()
            .checked_sub(cursor)
            .ok_or(CtisError::UnexpectedEof)?;
        if tweaks_count > remaining / 33 {
            return Err(CtisError::UnexpectedEof);
        }

        let mut candidate_tweaks = Vec::with_capacity(tweaks_count);
        for _ in 0..tweaks_count {
            let end = cursor.checked_add(33).ok_or(CtisError::UnexpectedEof)?;
            if end > data.len() {
                return Err(CtisError::UnexpectedEof);
            }
            let pt: [u8; 33] = data[cursor..end].try_into().unwrap();
            candidate_tweaks.push(pt);
            cursor = end;
        }

        let filter_len = read_compact_size(data, &mut cursor)?;
        let filter_remaining = data
            .len()
            .checked_sub(cursor)
            .ok_or(CtisError::UnexpectedEof)?;
        if filter_len > filter_remaining {
            return Err(CtisError::UnexpectedEof);
        }
        let filter_end = cursor
            .checked_add(filter_len)
            .ok_or(CtisError::UnexpectedEof)?;
        let gcs_filter_bytes = data[cursor..filter_end].to_vec();
        cursor = filter_end;

        if cursor != data.len() {
            return Err(CtisError::UnexpectedEof);
        }

        Ok(Self {
            height,
            block_hash,
            candidate_tweaks,
            gcs_filter_bytes,
        })
    }

    pub fn validate_points(&self) -> Result<Vec<AffinePoint>, CtisError> {
        let mut points = Vec::with_capacity(self.candidate_tweaks.len());
        for (i, pt) in self.candidate_tweaks.iter().enumerate() {
            if !matches!(pt[0], 2 | 3) {
                return Err(CtisError::MalformedPoint(i));
            }
            let x: [u8; 32] = pt[1..33]
                .try_into()
                .map_err(|_| CtisError::MalformedPoint(i))?;
            if is_on_quadratic_twist(&x) {
                return Err(CtisError::TwistPointDetected(i));
            }
            let affine = audit_candidate_tweak(pt).map_err(|_| CtisError::MalformedPoint(i))?;
            points.push(affine);
        }
        Ok(points)
    }

    pub fn matches_filter(&self, script_pubkeys: &[[u8; 34]]) -> Result<bool, CtisError> {
        if self.gcs_filter_bytes.is_empty() {
            return Ok(true);
        }
        FastGcsFilterMatcher::match_any_raw(
            &self.gcs_filter_bytes,
            &self.block_hash,
            script_pubkeys.iter().map(|s| s.as_slice()),
        )
        .map_err(|_| CtisError::FilterParseError)
    }

    pub fn scan_candidates(
        &self,
        scanner: &SpScannerNaive,
        outputs_per_tweak: &[&[[u8; 32]]],
    ) -> Result<Vec<Vec<SilentPaymentMatch>>, CtisError> {
        let points = self.validate_points()?;
        if points.len() != outputs_per_tweak.len() {
            return Err(CtisError::Arithmetic(SpError::ScratchTooSmall));
        }

        let prepared: Vec<PreparedTransaction> = points
            .into_iter()
            .map(|affine| PreparedTransaction {
                aggregate: affine,
                input_hash: Scalar::ONE,
                tweak: ProjectivePoint::from(affine),
            })
            .collect();
        let all_matches = scanner.scan_batch_glv(&prepared, outputs_per_tweak)?;
        Ok(all_matches)
    }
}
