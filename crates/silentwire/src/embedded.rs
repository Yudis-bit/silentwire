use crate::{
    audit_candidate_tweak, comb,
    coordinates::{parse_x_only, Affine},
    hash::{tagged_hash_label, tagged_hash_shared_secret},
    point, scalar, Error, SilentPaymentMatch, K_MAX,
};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use zeroize::{Zeroize, Zeroizing};

/// Fixed-capacity `no_std` BIP-352 scanner with static compile-time arrays.
/// Precomputes the mandatory `m = 0` change label, isolates outputs per tweak,
/// tracks consumed vouts, and matches outputs in Jacobian coordinates without
/// modular inversions.
#[derive(Clone, Debug)]
pub struct EmbeddedStaticScanner<
    const MAX_TWEAKS: usize,
    const MAX_OUTPUTS: usize,
    const MAX_MATCHES: usize,
> {
    scan_scalar: Zeroizing<Scalar>,
    spend_affine: Affine,
    change_point: Affine,
    change_label: Zeroizing<Scalar>,
    tweaks: [AffinePoint; MAX_TWEAKS],
    tweak_output_ranges: [(u16, u16); MAX_TWEAKS],
    tweak_count: usize,
    outputs: [[u8; 32]; MAX_OUTPUTS],
    output_count: usize,
    matches: [SilentPaymentMatch; MAX_MATCHES],
    match_count: usize,
}

impl<const MAX_TWEAKS: usize, const MAX_OUTPUTS: usize, const MAX_MATCHES: usize>
    EmbeddedStaticScanner<MAX_TWEAKS, MAX_OUTPUTS, MAX_MATCHES>
{
    /// Initialize the embedded scanner with secret scan key and public spend key,
    /// precomputing the mandatory BIP-352 change label (`m = 0`).
    pub fn new(scan_privkey: [u8; 32], spend_pubkey: [u8; 33]) -> Result<Self, Error> {
        let scan_val = scalar(scan_privkey)?;
        let spend_aff = point(&spend_pubkey)?;
        let change_label_bytes = Zeroizing::new(tagged_hash_label(&scan_privkey, 0));
        let change_label = Zeroizing::new(scalar(*change_label_bytes)?);
        let change_proj =
            ProjectivePoint::from(spend_aff) + comb::multiply_generator(&change_label);
        let change_point = Affine::from_k256(&change_proj.to_affine());

        Ok(Self {
            scan_scalar: Zeroizing::new(scan_val),
            spend_affine: Affine::from_k256(&spend_aff),
            change_point,
            change_label,
            tweaks: [AffinePoint::IDENTITY; MAX_TWEAKS],
            tweak_output_ranges: [(0, 0); MAX_TWEAKS],
            tweak_count: 0,
            outputs: [[0u8; 32]; MAX_OUTPUTS],
            output_count: 0,
            matches: core::array::from_fn(|_| SilentPaymentMatch {
                output_index: 0,
                derivation_index: 0,
                label: None,
                taproot_pubkey: [0u8; 32],
                tweak_scalar: [0u8; 32],
            }),
            match_count: 0,
        })
    }

    /// Return the exact static byte footprint of this scanner arena.
    pub const fn memory_footprint() -> usize {
        core::mem::size_of::<Self>()
    }

    /// Reset candidate tweaks, outputs, and match counters without re-deriving key state.
    pub fn clear(&mut self) {
        self.tweak_count = 0;
        self.output_count = 0;
        self.match_count = 0;
        self.tweak_output_ranges = [(0, 0); MAX_TWEAKS];
        for m in self.matches.iter_mut() {
            m.taproot_pubkey.zeroize();
            m.tweak_scalar.zeroize();
        }
    }

    /// Push an unauthenticated candidate public tweak starting a new transaction
    /// output range. Rejects points on the quadratic twist or malformed encodings
    /// fail-closed.
    pub fn add_tweak(&mut self, tweak_bytes: &[u8; 33]) -> Result<(), Error> {
        if self.tweak_count >= MAX_TWEAKS {
            return Err(Error::BatchTooLarge);
        }
        let pt = audit_candidate_tweak(tweak_bytes)?;
        let start = u16::try_from(self.output_count).map_err(|_| Error::BatchTooLarge)?;
        self.tweaks[self.tweak_count] = pt;
        self.tweak_output_ranges[self.tweak_count] = (start, 0);
        self.tweak_count += 1;
        Ok(())
    }

    /// Push a candidate Taproot x-only output pubkey belonging to the most recently
    /// added transaction tweak.
    pub fn add_output(&mut self, output_bytes: &[u8; 32]) -> Result<(), Error> {
        if self.output_count >= MAX_OUTPUTS {
            return Err(Error::BatchTooLarge);
        }
        if self.tweak_count == 0 {
            return Err(Error::InvalidPoint);
        }
        self.outputs[self.output_count] = *output_bytes;
        self.output_count += 1;
        let idx = self.tweak_count - 1;
        self.tweak_output_ranges[idx].1 = self.tweak_output_ranges[idx]
            .1
            .checked_add(1)
            .ok_or(Error::BatchTooLarge)?;
        Ok(())
    }

    /// Scan all buffered tweaks against their isolated output ranges.
    pub fn scan(&mut self) -> Result<&[SilentPaymentMatch], Error> {
        self.match_count = 0;
        if self.tweak_count == 0 || self.output_count == 0 {
            return Ok(&self.matches[..0]);
        }

        let mut consumed = [false; MAX_OUTPUTS];
        for t_idx in 0..self.tweak_count {
            let (start_u16, len_u16) = self.tweak_output_ranges[t_idx];
            let start = usize::from(start_u16);
            let len = usize::from(len_u16);
            if len == 0 {
                continue;
            }
            let end = start.checked_add(len).ok_or(Error::BatchTooLarge)?;
            if end > self.output_count {
                return Err(Error::BatchTooLarge);
            }
            let tweak_aff = self.tweaks[t_idx];
            let shared_proj = ProjectivePoint::from(tweak_aff) * *self.scan_scalar;
            let shared_aff = shared_proj.to_affine();
            let shared_bytes = Zeroizing::new(crate::compressed(&shared_aff)?);

            let mut parsed_x = [None; MAX_OUTPUTS];
            for rel in 0..len {
                parsed_x[rel] = parse_x_only(&self.outputs[start + rel]);
                consumed[rel] = false;
            }

            let mut matched_in_tx = 0usize;
            let mut k = 0u32;
            while k < K_MAX {
                let tweak_scalar_bytes =
                    Zeroizing::new(tagged_hash_shared_secret(&shared_bytes, k));
                let tweak_sc = Zeroizing::new(scalar(*tweak_scalar_bytes)?);
                let gen_proj = comb::multiply_projective(&tweak_sc);

                let base_candidate = gen_proj.add_mixed(&self.spend_affine);
                let change_candidate = gen_proj.add_mixed(&self.change_point);

                let mut best: Option<(usize, Option<u32>, [u8; 32])> = None;
                for rel in 0..len {
                    if consumed[rel] {
                        continue;
                    }
                    let Some(ref x_out) = parsed_x[rel] else {
                        continue;
                    };
                    if bool::from(base_candidate.matches_x(x_out)) {
                        best = Some((rel, None, *tweak_scalar_bytes));
                        break;
                    }
                    if bool::from(change_candidate.matches_x(x_out)) {
                        let combined = Zeroizing::new(*tweak_sc + *self.change_label);
                        best = Some((rel, Some(0), combined.to_bytes().into()));
                        break;
                    }
                }

                let Some((rel, label, final_tweak)) = best else {
                    break;
                };
                if self.match_count >= MAX_MATCHES {
                    return Err(Error::ScratchTooSmall);
                }
                consumed[rel] = true;
                self.matches[self.match_count] = SilentPaymentMatch {
                    output_index: rel as u32,
                    derivation_index: k,
                    label,
                    taproot_pubkey: self.outputs[start + rel],
                    tweak_scalar: final_tweak,
                };
                self.match_count += 1;
                matched_in_tx += 1;
                if matched_in_tx == len {
                    break;
                }
                k += 1;
            }
        }

        Ok(&self.matches[..self.match_count])
    }

    /// Scan a single transaction tweak against its caller-provided Taproot outputs
    /// without buffering into `self.tweaks`/`self.outputs`.
    pub fn scan_tx(
        &mut self,
        tweak_bytes: &[u8; 33],
        outputs: &[[u8; 32]],
    ) -> Result<&[SilentPaymentMatch], Error> {
        self.match_count = 0;
        if outputs.is_empty() {
            return Ok(&self.matches[..0]);
        }
        if outputs.len() > MAX_OUTPUTS {
            return Err(Error::BatchTooLarge);
        }
        let tweak_aff = audit_candidate_tweak(tweak_bytes)?;
        let shared_proj = ProjectivePoint::from(tweak_aff) * *self.scan_scalar;
        let shared_aff = shared_proj.to_affine();
        let shared_bytes = Zeroizing::new(crate::compressed(&shared_aff)?);

        let mut consumed = [false; MAX_OUTPUTS];
        let mut parsed_x = [None; MAX_OUTPUTS];
        for (i, out) in outputs.iter().enumerate() {
            parsed_x[i] = parse_x_only(out);
        }

        let mut matched_in_tx = 0usize;
        let mut k = 0u32;
        while k < K_MAX {
            let tweak_scalar_bytes = Zeroizing::new(tagged_hash_shared_secret(&shared_bytes, k));
            let tweak_sc = Zeroizing::new(scalar(*tweak_scalar_bytes)?);
            let gen_proj = comb::multiply_projective(&tweak_sc);

            let base_candidate = gen_proj.add_mixed(&self.spend_affine);
            let change_candidate = gen_proj.add_mixed(&self.change_point);

            let mut best: Option<(usize, Option<u32>, [u8; 32])> = None;
            for vout in 0..outputs.len() {
                if consumed[vout] {
                    continue;
                }
                let Some(ref x_out) = parsed_x[vout] else {
                    continue;
                };
                if bool::from(base_candidate.matches_x(x_out)) {
                    best = Some((vout, None, *tweak_scalar_bytes));
                    break;
                }
                if bool::from(change_candidate.matches_x(x_out)) {
                    let combined = Zeroizing::new(*tweak_sc + *self.change_label);
                    best = Some((vout, Some(0), combined.to_bytes().into()));
                    break;
                }
            }

            let Some((vout, label, final_tweak)) = best else {
                break;
            };
            if self.match_count >= MAX_MATCHES {
                return Err(Error::ScratchTooSmall);
            }
            consumed[vout] = true;
            self.matches[self.match_count] = SilentPaymentMatch {
                output_index: vout as u32,
                derivation_index: k,
                label,
                taproot_pubkey: outputs[vout],
                tweak_scalar: final_tweak,
            };
            self.match_count += 1;
            matched_in_tx += 1;
            if matched_in_tx == outputs.len() {
                break;
            }
            k += 1;
        }
        Ok(&self.matches[..self.match_count])
    }
}
