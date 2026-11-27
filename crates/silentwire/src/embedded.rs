use crate::{
    audit_candidate_tweak, comb,
    coordinates::{parse_x_only, Affine},
    hash::{tagged_hash_label, tagged_hash_shared_secret},
    point, scalar,
    ssmb::GlvScalar,
    BlockPaymentMatch, Error, SilentPaymentMatch, K_MAX,
};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
struct ScannerKeys {
    glv: GlvScalar,
    spend_affine: Affine,
    change_point: Affine,
    change_label: Zeroizing<Scalar>,
}

/// Fixed-capacity `no_std` BIP-352 scanner with static compile-time arrays and
/// zero heap allocation. Precomputes the mandatory `m = 0` change label,
/// isolates outputs per tweak, tracks consumed vouts and source transaction
/// indices, and matches outputs in Jacobian coordinates without modular
/// inversions or large stack arrays.
#[derive(Clone)]
pub struct EmbeddedStaticScanner<
    const MAX_TWEAKS: usize,
    const MAX_OUTPUTS: usize,
    const MAX_MATCHES: usize,
> {
    keys: ScannerKeys,
    tweaks: [AffinePoint; MAX_TWEAKS],
    tweak_output_ranges: [(u16, u16); MAX_TWEAKS],
    tweak_count: usize,
    outputs: [[u8; 32]; MAX_OUTPUTS],
    output_count: usize,
    matches: [SilentPaymentMatch; MAX_MATCHES],
    match_tx_indices: [u16; MAX_MATCHES],
    match_count: usize,
}

struct MatchSink<'a> {
    matches: &'a mut [SilentPaymentMatch],
    tx_indices: &'a mut [u16],
    count: &'a mut usize,
}

impl<const MAX_TWEAKS: usize, const MAX_OUTPUTS: usize, const MAX_MATCHES: usize> core::fmt::Debug
    for EmbeddedStaticScanner<MAX_TWEAKS, MAX_OUTPUTS, MAX_MATCHES>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EmbeddedStaticScanner")
            .field("tweak_count", &self.tweak_count)
            .field("output_count", &self.output_count)
            .field("match_count", &self.match_count)
            .finish_non_exhaustive()
    }
}

impl<const MAX_TWEAKS: usize, const MAX_OUTPUTS: usize, const MAX_MATCHES: usize> Drop
    for EmbeddedStaticScanner<MAX_TWEAKS, MAX_OUTPUTS, MAX_MATCHES>
{
    fn drop(&mut self) {
        self.clear();
    }
}

impl<const MAX_TWEAKS: usize, const MAX_OUTPUTS: usize, const MAX_MATCHES: usize>
    EmbeddedStaticScanner<MAX_TWEAKS, MAX_OUTPUTS, MAX_MATCHES>
{
    /// Initialize the embedded scanner with secret scan key and public spend key,
    /// precomputing the mandatory BIP-352 change label (`m = 0`).
    pub fn new(scan_privkey: [u8; 32], spend_pubkey: [u8; 33]) -> Result<Self, Error> {
        let scan_key = Zeroizing::new(scan_privkey);
        let scan_val = Zeroizing::new(scalar(*scan_key)?);
        let spend_aff = point(&spend_pubkey)?;
        let change_label_bytes = Zeroizing::new(tagged_hash_label(&scan_key, 0));
        let change_label = Zeroizing::new(scalar(*change_label_bytes)?);
        let change_proj =
            ProjectivePoint::from(spend_aff) + comb::multiply_generator(&change_label);
        let change_point = Affine::from_k256(&change_proj.to_affine());

        Ok(Self {
            keys: ScannerKeys {
                glv: GlvScalar::new(&scan_val),
                spend_affine: Affine::from_k256(&spend_aff),
                change_point,
                change_label,
            },
            tweaks: [AffinePoint::IDENTITY; MAX_TWEAKS],
            tweak_output_ranges: [(0, 0); MAX_TWEAKS],
            tweak_count: 0,
            outputs: [[0u8; 32]; MAX_OUTPUTS],
            output_count: 0,
            matches: [SilentPaymentMatch::default(); MAX_MATCHES],
            match_tx_indices: [0u16; MAX_MATCHES],
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
        self.match_tx_indices.zeroize();
        for m in self.matches.iter_mut() {
            m.zeroize();
        }
    }

    /// Return the 1-to-1 source transaction indices corresponding to the slice
    /// returned by the most recent [`scan`](Self::scan) call.
    pub fn match_transaction_indices(&self) -> &[u16] {
        &self.match_tx_indices[..self.match_count]
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

    fn scan_slice_into(
        keys: &ScannerKeys,
        tx_idx: u16,
        tweak_aff: &AffinePoint,
        tx_outputs: &[[u8; 32]],
        consumed: &mut [bool; MAX_OUTPUTS],
        sink: &mut MatchSink<'_>,
    ) -> Result<(), Error> {
        let len = tx_outputs.len();
        if len == 0 {
            return Ok(());
        }
        if len > MAX_OUTPUTS {
            return Err(Error::BatchTooLarge);
        }

        let tweak_coord = Affine::from_k256(tweak_aff);
        let mut shared_coord = keys.glv.multiply_single_affine(&tweak_coord).to_affine();
        let shared_res = shared_coord.to_compressed_bytes();
        shared_coord.zeroize_coords();
        let shared_bytes = Zeroizing::new(shared_res?);

        consumed[..len].fill(false);

        let mut matched_in_tx = 0usize;
        let mut k = 0u32;
        while k < K_MAX {
            let tweak_scalar_bytes = Zeroizing::new(tagged_hash_shared_secret(&shared_bytes, k));
            let tweak_sc = Zeroizing::new(scalar(*tweak_scalar_bytes)?);
            let gen_proj = comb::multiply_projective(&tweak_sc);

            let base_candidate = gen_proj.add_mixed(&keys.spend_affine);
            let change_candidate = gen_proj.add_mixed(&keys.change_point);
            let (base_z2, base_ok) = base_candidate.match_z2();
            let (change_z2, change_ok) = change_candidate.match_z2();

            let mut best: Option<(usize, Option<u32>, Zeroizing<[u8; 32]>)> = None;
            for (rel, out_bytes) in tx_outputs.iter().enumerate() {
                if consumed[rel] {
                    continue;
                }
                let Some(x_out) = parse_x_only(out_bytes) else {
                    continue;
                };
                if bool::from(base_candidate.matches_x_precomputed(&base_z2, base_ok, &x_out)) {
                    best = Some((rel, None, Zeroizing::new(*tweak_scalar_bytes)));
                    break;
                }
                if bool::from(change_candidate.matches_x_precomputed(&change_z2, change_ok, &x_out))
                {
                    let combined = Zeroizing::new(*tweak_sc + *keys.change_label);
                    best = Some((rel, Some(0), Zeroizing::new(combined.to_bytes().into())));
                    break;
                }
            }

            let Some((rel, label, final_tweak)) = best else {
                break;
            };
            if *sink.count >= MAX_MATCHES {
                return Err(Error::ScratchTooSmall);
            }
            consumed[rel] = true;
            sink.matches[*sink.count] = SilentPaymentMatch {
                output_index: rel as u32,
                derivation_index: k,
                label,
                taproot_pubkey: tx_outputs[rel],
                tweak_scalar: *final_tweak,
            };
            sink.tx_indices[*sink.count] = tx_idx;
            *sink.count += 1;
            matched_in_tx += 1;
            if matched_in_tx == len {
                break;
            }
            k += 1;
        }
        Ok(())
    }

    /// Scan all buffered tweaks against their isolated output ranges.
    /// Call [`match_transaction_indices`](Self::match_transaction_indices) for the
    /// 1-to-1 source transaction index of each returned match.
    pub fn scan(&mut self) -> Result<&[SilentPaymentMatch], Error> {
        self.match_count = 0;
        self.match_tx_indices.zeroize();
        for m in self.matches.iter_mut() {
            m.zeroize();
        }
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
            let tx_idx = u16::try_from(t_idx).map_err(|_| Error::BatchTooLarge)?;
            let mut sink = MatchSink {
                matches: &mut self.matches,
                tx_indices: &mut self.match_tx_indices,
                count: &mut self.match_count,
            };
            Self::scan_slice_into(
                &self.keys,
                tx_idx,
                &self.tweaks[t_idx],
                &self.outputs[start..end],
                &mut consumed,
                &mut sink,
            )?;
        }

        Ok(&self.matches[..self.match_count])
    }

    /// Scan all buffered tweaks and write explicit `(transaction_index, payment)`
    /// records into a caller-provided slice without heap allocation.
    pub fn scan_indexed(&mut self, out: &mut [BlockPaymentMatch]) -> Result<usize, Error> {
        let count = self.scan()?.len();
        if out.len() < count {
            return Err(Error::ScratchTooSmall);
        }
        for (slot, (&tx_idx, &payment)) in out
            .iter_mut()
            .zip(self.match_tx_indices.iter().zip(self.matches.iter()))
            .take(count)
        {
            *slot = BlockPaymentMatch {
                transaction_index: usize::from(tx_idx),
                payment,
            };
        }
        Ok(count)
    }

    /// Scan a single transaction tweak against its caller-provided Taproot outputs
    /// without buffering into `self.tweaks`/`self.outputs`.
    pub fn scan_tx(
        &mut self,
        tweak_bytes: &[u8; 33],
        outputs: &[[u8; 32]],
    ) -> Result<&[SilentPaymentMatch], Error> {
        self.match_count = 0;
        self.match_tx_indices.zeroize();
        for m in self.matches.iter_mut() {
            m.zeroize();
        }
        if outputs.is_empty() {
            return Ok(&self.matches[..0]);
        }
        if outputs.len() > MAX_OUTPUTS {
            return Err(Error::BatchTooLarge);
        }
        let tweak_aff = audit_candidate_tweak(tweak_bytes)?;
        let mut consumed = [false; MAX_OUTPUTS];
        let mut sink = MatchSink {
            matches: &mut self.matches,
            tx_indices: &mut self.match_tx_indices,
            count: &mut self.match_count,
        };
        Self::scan_slice_into(&self.keys, 0, &tweak_aff, outputs, &mut consumed, &mut sink)?;
        Ok(&self.matches[..self.match_count])
    }
}
