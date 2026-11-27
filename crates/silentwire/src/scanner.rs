use crate::{
    compressed,
    coordinates::{lift_x_k256, parse_x_only, Affine},
    hash::{tagged_hash_label, tagged_hash_shared_secret},
    input::PreparedTransaction,
    point, scalar,
    ssmb::{batch_normalize_projective_into, GlvScalar, GLV_FUSED_BASES},
    BlockPaymentMatch, Error, SilentPaymentMatch, K_MAX,
};
use alloc::{vec, vec::Vec};
use k256::{AffinePoint, FieldElement, ProjectivePoint, Scalar};
use zeroize::{Zeroize, Zeroizing};

/// Label count threshold between Mode A (zero-inversion Jacobian projective
/// x-match, `O(L)`) and Mode B (subtractive BIP-352 `±P_tx - P_0` lookup, `O(1)`).
pub const ADAPTIVE_LABEL_THRESHOLD: usize = 8;

/// Transaction association is explicit. The tweak must already be h*A_sum.
#[derive(Clone, Copy)]
pub struct ScanTransaction<'a> {
    pub tweak_point: &'a [u8; 33],
    pub outputs: &'a [[u8; 32]],
}

fn zeroize_affines(points: &mut [Affine]) {
    for pt in points {
        pt.zeroize_coords();
    }
}

#[derive(Clone)]
pub struct ScanContext {
    consumed: [u64; crate::MAX_BATCH / 64],
    results: Vec<Vec<SilentPaymentMatch>>,
}

impl core::fmt::Debug for ScanContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ScanContext")
            .finish_non_exhaustive()
    }
}

impl Default for ScanContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanContext {
    pub fn new() -> Self {
        Self {
            consumed: [0; crate::MAX_BATCH / 64],
            results: Vec::new(),
        }
    }

    /// Compatibility workspace for allocating label/batch adapters.
    pub fn with_capacity(batch_capacity: usize, variant_count: usize) -> Self {
        let mut context = Self::new();
        context.results = (0..batch_capacity.min(crate::MAX_BATCH))
            .map(|_| Vec::with_capacity(variant_count.min(crate::MAX_BATCH)))
            .collect();
        context
    }

    pub fn results(&self) -> &[Vec<SilentPaymentMatch>] {
        &self.results
    }
    pub fn results_capacity(&self) -> usize {
        self.results.capacity()
    }
    pub fn drain_results(&mut self) -> alloc::vec::Drain<'_, Vec<SilentPaymentMatch>> {
        self.results.drain(..)
    }
    pub fn take_results(&mut self) -> Vec<Vec<SilentPaymentMatch>> {
        core::mem::take(&mut self.results)
    }

    fn erase_workspace(&mut self) {
        self.consumed.zeroize();
    }

    pub fn clear(&mut self) {
        self.erase_workspace();
        for list in &mut self.results {
            for item in list.iter_mut() {
                item.tweak_scalar.zeroize();
            }
            list.clear();
        }
    }

    /// No allocations. On a late arithmetic/capacity error the written prefix is erased.
    pub fn scan_transaction_into(
        &mut self,
        scan_privkey: &[u8; 32],
        spend_pubkey: &[u8; 33],
        tweak_point: &[u8; 33],
        outputs: &[[u8; 32]],
        matches: &mut [SilentPaymentMatch],
    ) -> Result<usize, Error> {
        let scan = Zeroizing::new(scalar(*scan_privkey)?);
        let spend = point(spend_pubkey)?;
        let tweak = Affine::from_k256(&point(tweak_point)?);
        if outputs.len() > crate::MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        let mut shared = GlvScalar::new(&scan)
            .multiply_single_affine(&tweak)
            .to_affine();
        let variants = [SpendVariant {
            point: spend,
            affine: Affine::from_k256(&spend),
            tweak: Scalar::ZERO,
            label: None,
        }];
        let result = self.scan_shared_coord_into(&shared, &variants, &[], outputs, matches);
        shared.zeroize_coords();
        self.erase_workspace();
        result
    }

    /// Allocating convenience wrapper. Use scan_transaction_into for a heap-free loop.
    pub fn scan_transaction(
        &mut self,
        scan_privkey: &[u8; 32],
        spend_pubkey: &[u8; 33],
        tweak_point: &[u8; 33],
        outputs: &[[u8; 32]],
    ) -> Result<Vec<SilentPaymentMatch>, Error> {
        if outputs.len() > crate::MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(outputs.len())
            .map_err(|_| Error::AllocationFailed)?;
        result.resize(outputs.len(), SilentPaymentMatch::default());
        let found = self.scan_transaction_into(
            scan_privkey,
            spend_pubkey,
            tweak_point,
            outputs,
            &mut result,
        )?;
        result.truncate(found);
        Ok(result)
    }

    pub fn scan_block(
        &mut self,
        scan_privkey: &[u8; 32],
        spend_pubkey: &[u8; 33],
        transactions: &[ScanTransaction<'_>],
    ) -> Result<Vec<BlockPaymentMatch>, Error> {
        if transactions.len() > crate::MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        let scan = Zeroizing::new(scalar(*scan_privkey)?);
        let spend = point(spend_pubkey)?;
        for tx in transactions {
            point(tx.tweak_point)?;
            if tx.outputs.len() > crate::MAX_BATCH {
                return Err(Error::BatchTooLarge);
            }
        }
        let variants = [SpendVariant {
            point: spend,
            affine: Affine::from_k256(&spend),
            tweak: Scalar::ZERO,
            label: None,
        }];
        let glv = GlvScalar::new(&scan);
        let mut result = Vec::new();
        let mut bases = [Affine::identity(); GLV_FUSED_BASES];
        let mut shareds = [Affine::identity(); GLV_FUSED_BASES];

        for (chunk_idx, tx_chunk) in transactions.chunks(GLV_FUSED_BASES).enumerate() {
            let chunk_len = tx_chunk.len();
            for (slot, tx) in bases[..chunk_len].iter_mut().zip(tx_chunk) {
                *slot = Affine::from_k256(&point(tx.tweak_point)?);
            }
            glv.multiply_affine_batch_to_affine(&bases[..chunk_len], &mut shareds[..chunk_len])?;

            let base_tx_index = chunk_idx * GLV_FUSED_BASES;
            for (rel, tx) in tx_chunk.iter().enumerate() {
                let tx_index = base_tx_index + rel;
                let res = self.scan_shared_coord_visit(
                    &shareds[rel],
                    &variants,
                    &[],
                    tx.outputs,
                    |payment| {
                        result.try_reserve(1).map_err(|_| Error::AllocationFailed)?;
                        result.push(BlockPaymentMatch {
                            transaction_index: tx_index,
                            payment,
                        });
                        Ok(())
                    },
                );
                if let Err(err) = res {
                    zeroize_affines(&mut shareds[..chunk_len]);
                    for item in &mut result {
                        item.zeroize();
                    }
                    self.erase_workspace();
                    return Err(err);
                }
            }
            zeroize_affines(&mut shareds[..chunk_len]);
        }
        self.erase_workspace();
        Ok(result)
    }

    pub fn scan_block_into(
        &mut self,
        scan_privkey: &[u8; 32],
        spend_pubkey: &[u8; 33],
        transactions: &[ScanTransaction<'_>],
        matches: &mut [BlockPaymentMatch],
    ) -> Result<usize, Error> {
        if transactions.len() > crate::MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        let scan = Zeroizing::new(scalar(*scan_privkey)?);
        let spend = point(spend_pubkey)?;
        for tx in transactions {
            point(tx.tweak_point)?;
            if tx.outputs.len() > crate::MAX_BATCH {
                return Err(Error::BatchTooLarge);
            }
        }
        let variants = [SpendVariant {
            point: spend,
            affine: Affine::from_k256(&spend),
            tweak: Scalar::ZERO,
            label: None,
        }];
        let glv = GlvScalar::new(&scan);
        let mut bases = [Affine::identity(); GLV_FUSED_BASES];
        let mut shareds = [Affine::identity(); GLV_FUSED_BASES];
        let mut written = 0usize;

        for (chunk_idx, tx_chunk) in transactions.chunks(GLV_FUSED_BASES).enumerate() {
            let chunk_len = tx_chunk.len();
            for (slot, tx) in bases[..chunk_len].iter_mut().zip(tx_chunk) {
                *slot = Affine::from_k256(&point(tx.tweak_point)?);
            }
            glv.multiply_affine_batch_to_affine(&bases[..chunk_len], &mut shareds[..chunk_len])?;

            let base_tx_index = chunk_idx * GLV_FUSED_BASES;
            for (rel, tx) in tx_chunk.iter().enumerate() {
                let tx_index = base_tx_index + rel;
                let res = self.scan_shared_coord_visit(
                    &shareds[rel],
                    &variants,
                    &[],
                    tx.outputs,
                    |payment| {
                        if written == matches.len() {
                            return Err(Error::ScratchTooSmall);
                        }
                        matches[written] = BlockPaymentMatch {
                            transaction_index: tx_index,
                            payment,
                        };
                        written += 1;
                        Ok(())
                    },
                );
                if let Err(error) = res {
                    zeroize_affines(&mut shareds[..chunk_len]);
                    for item in &mut matches[..written] {
                        item.zeroize();
                    }
                    self.erase_workspace();
                    return Err(error);
                }
            }
            zeroize_affines(&mut shareds[..chunk_len]);
        }
        self.erase_workspace();
        Ok(written)
    }

    fn scan_shared_coord_into(
        &mut self,
        shared: &Affine,
        variants: &[SpendVariant],
        label_lookup: &[([u8; 33], usize)],
        outputs: &[[u8; 32]],
        matches: &mut [SilentPaymentMatch],
    ) -> Result<usize, Error> {
        let mut written = 0;
        let result =
            self.scan_shared_coord_visit(shared, variants, label_lookup, outputs, |payment| {
                if written == matches.len() {
                    return Err(Error::ScratchTooSmall);
                }
                matches[written] = payment;
                written += 1;
                Ok(())
            });
        if result.is_err() {
            for item in &mut matches[..written] {
                item.tweak_scalar.zeroize();
                *item = SilentPaymentMatch::default();
            }
        }
        result
    }

    /// Adaptive BIP-352 output scanner. Uses zero-inversion Jacobian x-match
    /// (`X == x_out * Z^2 mod p`, `Z != 0`, `x_out < p`) up to
    /// `ADAPTIVE_LABEL_THRESHOLD` labels, and switches to `O(1)` subtractive
    /// lookup (`±P_tx - P_0`) over the sorted label table above that threshold.
    fn scan_shared_coord_visit(
        &mut self,
        shared: &Affine,
        variants: &[SpendVariant],
        label_lookup: &[([u8; 33], usize)],
        outputs: &[[u8; 32]],
        mut record: impl FnMut(SilentPaymentMatch) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        if outputs.len() > crate::MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if outputs.is_empty() {
            return Ok(0);
        }
        let consumed_words = outputs.len().div_ceil(64);
        self.consumed[..consumed_words].fill(0);

        let mut parsed_inline = [None::<FieldElement>; 32];
        let use_inline = outputs.len() <= 32;
        if use_inline {
            for (slot, out) in parsed_inline[..outputs.len()].iter_mut().zip(outputs) {
                *slot = parse_x_only(out);
            }
        }

        let use_subtractive =
            variants.len() > ADAPTIVE_LABEL_THRESHOLD + 1 && !label_lookup.is_empty();
        let lifted_outputs: Vec<Option<AffinePoint>> = if use_subtractive {
            outputs.iter().map(lift_x_k256).collect()
        } else {
            Vec::new()
        };

        let shared_enc = Zeroizing::new(shared.to_compressed_bytes()?);
        let mut written = 0usize;

        for k in 0..K_MAX {
            let tweak_bytes = Zeroizing::new(tagged_hash_shared_secret(&shared_enc, k));
            let tweak = Zeroizing::new(scalar(*tweak_bytes)?);
            let generator = crate::comb::multiply_projective(&tweak);

            let mut best: Option<SilentPaymentMatch> = None;

            if !use_subtractive {
                // Mode A: zero-inversion Jacobian projective x-match.
                for variant in variants {
                    let candidate = generator.add_mixed(&variant.affine);
                    let (z2, non_infinity) = candidate.match_z2();
                    for (index, output) in outputs.iter().enumerate() {
                        if self.consumed[index / 64] & (1u64 << (index % 64)) != 0 {
                            continue;
                        }
                        if best
                            .as_ref()
                            .is_some_and(|old| index >= old.output_index as usize)
                        {
                            break;
                        }
                        let x_opt = if use_inline {
                            parsed_inline[index]
                        } else {
                            parse_x_only(output)
                        };
                        let Some(x_out) = x_opt else {
                            continue;
                        };
                        if bool::from(candidate.matches_x_precomputed(&z2, non_infinity, &x_out)) {
                            best = Some(SilentPaymentMatch {
                                output_index: index as u32,
                                derivation_index: k,
                                taproot_pubkey: *output,
                                tweak_scalar: (*tweak + variant.tweak).to_bytes().into(),
                                label: variant.label,
                            });
                            break;
                        }
                    }
                }
            } else {
                // Mode B: O(1) subtractive BIP-352 label scan.
                let base_proj = generator.add_mixed(&variants[0].affine);
                let (z2, non_infinity) = base_proj.match_z2();
                for (index, output) in outputs.iter().enumerate() {
                    if self.consumed[index / 64] & (1u64 << (index % 64)) != 0 {
                        continue;
                    }
                    let x_opt = if use_inline {
                        parsed_inline[index]
                    } else {
                        parse_x_only(output)
                    };
                    let Some(x_out) = x_opt else {
                        continue;
                    };
                    if bool::from(base_proj.matches_x_precomputed(&z2, non_infinity, &x_out)) {
                        best = Some(SilentPaymentMatch {
                            output_index: index as u32,
                            derivation_index: k,
                            taproot_pubkey: *output,
                            tweak_scalar: (*tweak + variants[0].tweak).to_bytes().into(),
                            label: None,
                        });
                        break;
                    }
                }

                let limit_vout = best
                    .as_ref()
                    .map_or(outputs.len(), |old| old.output_index as usize);
                if limit_vout > 0 {
                    let base_k256 = base_proj.to_k256();
                    let neg_base = -ProjectivePoint::from(base_k256);
                    let mut diff_proj = Vec::new();
                    let mut diff_vouts = Vec::new();
                    for (index, lifted) in lifted_outputs[..limit_vout].iter().enumerate() {
                        if self.consumed[index / 64] & (1u64 << (index % 64)) != 0 {
                            continue;
                        }
                        let Some(p_even) = *lifted else {
                            continue;
                        };
                        let p_odd = -p_even;
                        diff_proj.push(neg_base + p_even);
                        diff_vouts.push(index);
                        diff_proj.push(neg_base + p_odd);
                        diff_vouts.push(index);
                    }
                    if !diff_proj.is_empty() {
                        let mut diff_aff = vec![AffinePoint::IDENTITY; diff_proj.len()];
                        batch_normalize_projective_into(&diff_proj, &mut diff_aff);
                        for (aff, vout) in diff_aff.iter().zip(diff_vouts) {
                            if best
                                .as_ref()
                                .is_some_and(|old| vout >= old.output_index as usize)
                            {
                                break;
                            }
                            if let Ok(key) = compressed(aff) {
                                if let Ok(pos) = label_lookup.binary_search_by_key(&key, |e| e.0) {
                                    let variant = &variants[label_lookup[pos].1];
                                    best = Some(SilentPaymentMatch {
                                        output_index: vout as u32,
                                        derivation_index: k,
                                        taproot_pubkey: outputs[vout],
                                        tweak_scalar: (*tweak + variant.tweak).to_bytes().into(),
                                        label: variant.label,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            let Some(payment) = best else {
                break;
            };
            self.consumed[payment.output_index as usize / 64] |=
                1u64 << (payment.output_index as usize % 64);
            record(payment)?;
            written += 1;
            if written == outputs.len() {
                break;
            }
        }
        Ok(written)
    }
}

impl Drop for ScanContext {
    fn drop(&mut self) {
        self.clear();
    }
}

struct SpendVariant {
    point: AffinePoint,
    affine: Affine,
    tweak: Scalar,
    label: Option<u32>,
}

pub struct SpScannerNaive {
    scan: Zeroizing<Scalar>,
    glv: GlvScalar,
    variants: Vec<SpendVariant>,
    label_lookup: Vec<([u8; 33], usize)>,
}

impl Drop for SpScannerNaive {
    fn drop(&mut self) {
        for v in &mut self.variants {
            v.tweak.zeroize();
        }
    }
}

impl SpScannerNaive {
    pub fn new(scan: [u8; 32], spend: [u8; 33], labels: &[u32]) -> Result<Self, Error> {
        Self::from_scalar(Zeroizing::new(scalar(scan)?), spend, labels)
    }

    pub fn from_scalar(
        scan: Zeroizing<Scalar>,
        spend: [u8; 33],
        labels: &[u32],
    ) -> Result<Self, Error> {
        Self::from_scalar_with_declassify(scan, spend, labels, None)
    }

    pub fn from_scalar_with_declassify(
        scan: Zeroizing<Scalar>,
        spend: [u8; 33],
        labels: &[u32],
        declassify: Option<fn(*const u8, usize)>,
    ) -> Result<Self, Error> {
        use k256::elliptic_curve::PrimeField;
        let spend_affine = point(&spend)?;
        let spend_coord = Affine::from_k256(&spend_affine);
        let glv = GlvScalar::new(&scan);
        let mut variants = vec![SpendVariant {
            point: spend_affine,
            affine: spend_coord,
            tweak: Scalar::ZERO,
            label: None,
        }];
        let mut label_points_raw: Vec<(Affine, usize)> = Vec::new();
        let scan_bytes = Zeroizing::new(<[u8; 32]>::from(scan.to_bytes()));
        for m in labels.iter() {
            if variants.iter().any(|v| v.label == Some(*m)) {
                continue;
            }
            let hash = Zeroizing::new(tagged_hash_label(&scan_bytes, *m));
            let ct_option = Scalar::from_repr((*hash).into());
            let is_some = ct_option.is_some();
            let tweak_val = ct_option.unwrap_or(Scalar::ZERO);
            let is_zero = tweak_val.is_zero();
            let is_valid = is_some & !is_zero;
            let valid_u8 = is_valid.unwrap_u8();
            if let Some(f) = declassify {
                f(&valid_u8 as *const u8, 1);
            }
            if valid_u8 == 0 {
                return Err(Error::InvalidScalar);
            }
            let label_jac = crate::comb::multiply_projective(&tweak_val);
            let variant_coord = label_jac.add_mixed(&spend_coord).to_affine();
            if let Some(f) = declassify {
                f(
                    (&variant_coord as *const Affine).cast(),
                    core::mem::size_of::<Affine>(),
                );
            }
            let variant_aff = variant_coord.to_k256();
            let variant_idx = variants.len();
            variants.push(SpendVariant {
                point: variant_aff,
                affine: variant_coord,
                tweak: tweak_val,
                label: Some(*m),
            });
            if labels.len() > ADAPTIVE_LABEL_THRESHOLD {
                let label_aff = label_jac.to_affine();
                if let Some(f) = declassify {
                    f(
                        (&label_aff as *const Affine).cast(),
                        core::mem::size_of::<Affine>(),
                    );
                }
                label_points_raw.push((label_aff, variant_idx));
            }
        }
        let mut label_lookup = Vec::new();
        if variants.len() > ADAPTIVE_LABEL_THRESHOLD + 1 {
            label_lookup.reserve(label_points_raw.len());
            for (pt, idx) in label_points_raw {
                let mut key = pt.to_compressed_bytes()?;
                if let Some(f) = declassify {
                    f(key.as_ptr(), key.len());
                }
                label_lookup.push((key, idx));
                key.zeroize();
            }
            label_lookup.sort_unstable_by_key(|entry| entry.0);
        }
        Ok(Self {
            scan,
            glv,
            variants,
            label_lookup,
        })
    }

    pub fn declassify_variants(&mut self, declassify: impl Fn(*const u8, usize)) {
        for v in &mut self.variants {
            declassify(
                (&v.point as *const AffinePoint).cast(),
                core::mem::size_of::<AffinePoint>(),
            );
            declassify(
                (&v.affine as *const Affine).cast(),
                core::mem::size_of::<Affine>(),
            );
            declassify(
                (&v.tweak as *const Scalar).cast(),
                core::mem::size_of::<Scalar>(),
            );
        }
        for entry in &mut self.label_lookup {
            declassify(entry.0.as_ptr(), entry.0.len());
        }
    }

    pub fn shared_secret(&self, tx: &PreparedTransaction) -> AffinePoint {
        let bases = [tx.tweak];
        let mut secrets = [ProjectivePoint::IDENTITY];
        let mut scratch = [AffinePoint::IDENTITY; crate::ssmb::TABLE_SIZE];
        crate::ssmb::SharedScalar::new(&self.scan)
            .multiply_mixed_into(&bases, &mut secrets, &mut scratch)
            .expect("batch size 1 is valid");
        secrets[0].to_affine()
    }

    pub fn shared_secret_from_tweak(&self, tweak: &AffinePoint) -> AffinePoint {
        let bases = [ProjectivePoint::from(*tweak)];
        let mut secrets = [ProjectivePoint::IDENTITY];
        let mut scratch = [AffinePoint::IDENTITY; crate::ssmb::TABLE_SIZE];
        crate::ssmb::SharedScalar::new(&self.scan)
            .multiply_mixed_into(&bases, &mut secrets, &mut scratch)
            .expect("batch size 1 is valid");
        secrets[0].to_affine()
    }

    pub fn scan_prepared(
        &self,
        tx: &PreparedTransaction,
        outputs: &[[u8; 32]],
    ) -> Result<Vec<SilentPaymentMatch>, Error> {
        self.scan_shared(&self.shared_secret(tx), outputs)
    }

    pub fn scan_prepared_glv(
        &self,
        tx: &PreparedTransaction,
        outputs: &[[u8; 32]],
    ) -> Result<Vec<SilentPaymentMatch>, Error> {
        self.scan_shared(&self.shared_secret_glv(tx), outputs)
    }

    pub fn scan_batch(
        &self,
        transactions: &[PreparedTransaction],
        outputs: &[&[[u8; 32]]],
    ) -> Result<Vec<Vec<SilentPaymentMatch>>, Error> {
        self.scan_batch_glv(transactions, outputs)
    }

    pub fn scan_batch_into(
        &self,
        transactions: &[PreparedTransaction],
        outputs: &[&[[u8; 32]]],
        ctx: &mut ScanContext,
    ) -> Result<(), Error> {
        self.scan_batch_glv_into(transactions, outputs, ctx)
    }

    pub fn shared_secret_from_tweak_glv(&self, tweak: &ProjectivePoint) -> AffinePoint {
        let base = Affine::from_k256(&tweak.to_affine());
        self.glv.multiply_single_affine(&base).to_k256()
    }

    pub fn shared_secret_glv(&self, tx: &PreparedTransaction) -> AffinePoint {
        self.shared_secret_from_tweak_glv(&tx.tweak)
    }

    /// Batched GLV scanner using cross-transaction 8-point `phi(j*P)` Jacobian
    /// fused Montgomery batching, zero-inversion Jacobian x-match (`L <= 8`),
    /// and adaptive `O(1)` subtractive label scanning (`L > 8`).
    pub fn scan_batch_glv_into(
        &self,
        transactions: &[PreparedTransaction],
        outputs: &[&[[u8; 32]]],
        ctx: &mut ScanContext,
    ) -> Result<(), Error> {
        self.scan_batch_glv_with_declassify_into(transactions, outputs, ctx, None)
    }

    /// Variant of `scan_batch_glv_into` with an optional declassification hook
    /// invoked on each normalized shared secret prior to output matching.
    pub fn scan_batch_glv_with_declassify_into(
        &self,
        transactions: &[PreparedTransaction],
        outputs: &[&[[u8; 32]]],
        ctx: &mut ScanContext,
        declassify: Option<fn(*const u8, usize)>,
    ) -> Result<(), Error> {
        if transactions.len() > crate::MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if transactions.len() != outputs.len() {
            return Err(Error::ScratchTooSmall);
        }
        ctx.results.resize_with(transactions.len(), Vec::new);
        ctx.results.truncate(transactions.len());
        if transactions.is_empty() {
            ctx.erase_workspace();
            return Ok(());
        }

        let mut proj_bases = [ProjectivePoint::IDENTITY; GLV_FUSED_BASES];
        let mut aff_bases = [AffinePoint::IDENTITY; GLV_FUSED_BASES];
        let mut coord_bases = [Affine::identity(); GLV_FUSED_BASES];
        let mut shareds = [Affine::identity(); GLV_FUSED_BASES];

        for (chunk_idx, (tx_chunk, out_chunk)) in transactions
            .chunks(GLV_FUSED_BASES)
            .zip(outputs.chunks(GLV_FUSED_BASES))
            .enumerate()
        {
            let chunk_len = tx_chunk.len();
            for (slot, tx) in proj_bases[..chunk_len].iter_mut().zip(tx_chunk) {
                *slot = tx.tweak;
            }
            batch_normalize_projective_into(&proj_bases[..chunk_len], &mut aff_bases[..chunk_len]);
            for i in 0..chunk_len {
                coord_bases[i] = Affine::from_k256(&aff_bases[i]);
            }
            self.glv.multiply_affine_batch_to_affine(
                &coord_bases[..chunk_len],
                &mut shareds[..chunk_len],
            )?;

            if let Some(f) = declassify {
                f(
                    shareds.as_ptr().cast(),
                    chunk_len * core::mem::size_of::<Affine>(),
                );
            }

            let base_idx = chunk_idx * GLV_FUSED_BASES;
            for rel in 0..chunk_len {
                let tx_outputs = out_chunk[rel];
                let mut slot = core::mem::take(&mut ctx.results[base_idx + rel]);
                slot.clear();
                let res = ctx.scan_shared_coord_visit(
                    &shareds[rel],
                    &self.variants,
                    &self.label_lookup,
                    tx_outputs,
                    |payment| {
                        slot.try_reserve(1).map_err(|_| Error::AllocationFailed)?;
                        slot.push(payment);
                        Ok(())
                    },
                );
                if let Err(e) = res {
                    zeroize_affines(&mut shareds[..chunk_len]);
                    for item in &mut slot {
                        item.zeroize();
                    }
                    slot.clear();
                    ctx.results[base_idx + rel] = slot;
                    return Err(e);
                }
                ctx.results[base_idx + rel] = slot;
            }
            zeroize_affines(&mut shareds[..chunk_len]);
        }

        ctx.erase_workspace();
        Ok(())
    }

    /// Direct affine-tweak batch scanner (avoids redundant projective-to-affine
    /// conversion when tweaks are already affine, such as CTIS / FFI inputs).
    pub fn scan_affine_batch_glv_with_declassify_into(
        &self,
        tweaks: &[AffinePoint],
        outputs: &[&[[u8; 32]]],
        ctx: &mut ScanContext,
        declassify: Option<fn(*const u8, usize)>,
    ) -> Result<(), Error> {
        if tweaks.len() > crate::MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if tweaks.len() != outputs.len() {
            return Err(Error::ScratchTooSmall);
        }
        ctx.results.resize_with(tweaks.len(), Vec::new);
        ctx.results.truncate(tweaks.len());
        if tweaks.is_empty() {
            ctx.erase_workspace();
            return Ok(());
        }

        let mut coord_bases = [Affine::identity(); GLV_FUSED_BASES];
        let mut shareds = [Affine::identity(); GLV_FUSED_BASES];

        for (chunk_idx, (tweak_chunk, out_chunk)) in tweaks
            .chunks(GLV_FUSED_BASES)
            .zip(outputs.chunks(GLV_FUSED_BASES))
            .enumerate()
        {
            let chunk_len = tweak_chunk.len();
            for i in 0..chunk_len {
                coord_bases[i] = Affine::from_k256(&tweak_chunk[i]);
            }
            self.glv.multiply_affine_batch_to_affine(
                &coord_bases[..chunk_len],
                &mut shareds[..chunk_len],
            )?;

            if let Some(f) = declassify {
                f(
                    shareds.as_ptr().cast(),
                    chunk_len * core::mem::size_of::<Affine>(),
                );
            }

            let base_idx = chunk_idx * GLV_FUSED_BASES;
            for rel in 0..chunk_len {
                let tx_outputs = out_chunk[rel];
                let mut slot = core::mem::take(&mut ctx.results[base_idx + rel]);
                slot.clear();
                let res = ctx.scan_shared_coord_visit(
                    &shareds[rel],
                    &self.variants,
                    &self.label_lookup,
                    tx_outputs,
                    |payment| {
                        slot.try_reserve(1).map_err(|_| Error::AllocationFailed)?;
                        slot.push(payment);
                        Ok(())
                    },
                );
                if let Err(e) = res {
                    zeroize_affines(&mut shareds[..chunk_len]);
                    for item in &mut slot {
                        item.zeroize();
                    }
                    slot.clear();
                    ctx.results[base_idx + rel] = slot;
                    return Err(e);
                }
                ctx.results[base_idx + rel] = slot;
            }
            zeroize_affines(&mut shareds[..chunk_len]);
        }

        ctx.erase_workspace();
        Ok(())
    }

    /// Zero-per-tx-allocation streaming affine batch GLV scanner invoking `visit(tx_index, match)`
    /// for each detected payment.
    pub fn scan_affine_batch_glv_visit_with_declassify(
        &self,
        tweaks: &[AffinePoint],
        outputs: &[&[[u8; 32]]],
        declassify: Option<fn(*const u8, usize)>,
        mut visit: impl FnMut(usize, SilentPaymentMatch) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if tweaks.len() > crate::MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        if tweaks.len() != outputs.len() {
            return Err(Error::ScratchTooSmall);
        }
        if tweaks.is_empty() {
            return Ok(());
        }

        let mut ctx = ScanContext::new();
        let mut coord_bases = [Affine::identity(); GLV_FUSED_BASES];
        let mut shareds = [Affine::identity(); GLV_FUSED_BASES];

        for (chunk_idx, (tweak_chunk, out_chunk)) in tweaks
            .chunks(GLV_FUSED_BASES)
            .zip(outputs.chunks(GLV_FUSED_BASES))
            .enumerate()
        {
            let chunk_len = tweak_chunk.len();
            for i in 0..chunk_len {
                coord_bases[i] = Affine::from_k256(&tweak_chunk[i]);
            }
            self.glv.multiply_affine_batch_to_affine(
                &coord_bases[..chunk_len],
                &mut shareds[..chunk_len],
            )?;

            if let Some(f) = declassify {
                f(
                    shareds.as_ptr().cast(),
                    chunk_len * core::mem::size_of::<Affine>(),
                );
            }

            let base_idx = chunk_idx * GLV_FUSED_BASES;
            for rel in 0..chunk_len {
                let tx_idx = base_idx + rel;
                let res = ctx.scan_shared_coord_visit(
                    &shareds[rel],
                    &self.variants,
                    &self.label_lookup,
                    out_chunk[rel],
                    |payment| visit(tx_idx, payment),
                );
                if let Err(e) = res {
                    zeroize_affines(&mut shareds[..chunk_len]);
                    ctx.erase_workspace();
                    return Err(e);
                }
            }
            zeroize_affines(&mut shareds[..chunk_len]);
        }

        ctx.erase_workspace();
        Ok(())
    }

    pub fn scan_batch_glv(
        &self,
        transactions: &[PreparedTransaction],
        outputs: &[&[[u8; 32]]],
    ) -> Result<Vec<Vec<SilentPaymentMatch>>, Error> {
        let mut ctx = ScanContext::with_capacity(transactions.len(), self.variants.len());
        self.scan_batch_glv_into(transactions, outputs, &mut ctx)?;
        ctx.results.truncate(transactions.len());
        Ok(core::mem::take(&mut ctx.results))
    }

    pub fn derive_candidate_scripts_for_shared(
        &self,
        shared: &AffinePoint,
        max_k: u32,
    ) -> Result<Vec<[u8; 34]>, Error> {
        let encoded = Zeroizing::new(compressed(shared)?);
        let mut scripts = Vec::new();
        for k in 0..max_k {
            let tweak_bytes = Zeroizing::new(tagged_hash_shared_secret(&encoded, k));
            let tweak = Zeroizing::new(scalar(*tweak_bytes)?);
            let tweak_point = crate::comb::multiply_generator(&tweak);
            for variant in &self.variants {
                if let Ok(candidate) = compressed(&(tweak_point + variant.point).to_affine()) {
                    let mut script = [0u8; 34];
                    script[0] = 0x51;
                    script[1] = 0x20;
                    script[2..].copy_from_slice(&candidate[1..]);
                    scripts.push(script);
                }
            }
        }
        Ok(scripts)
    }

    pub fn derive_candidate_scripts_batch_glv(
        &self,
        transactions: &[PreparedTransaction],
        max_k: u32,
    ) -> Result<Vec<[u8; 34]>, Error> {
        if transactions.is_empty() {
            return Ok(Vec::new());
        }
        let proj_bases: Vec<ProjectivePoint> = transactions.iter().map(|tx| tx.tweak).collect();
        let mut aff_bases = vec![AffinePoint::IDENTITY; proj_bases.len()];
        batch_normalize_projective_into(&proj_bases, &mut aff_bases);
        let coord_bases: Vec<Affine> = aff_bases.iter().map(Affine::from_k256).collect();
        let mut shareds = vec![Affine::identity(); coord_bases.len()];
        let mut all_scripts = Vec::new();
        for (coord_chunk, shared_chunk) in coord_bases
            .chunks(crate::MAX_BATCH)
            .zip(shareds.chunks_mut(crate::MAX_BATCH))
        {
            self.glv
                .multiply_affine_batch_to_affine(coord_chunk, shared_chunk)?;
            for shared in shared_chunk.iter() {
                let mut s = self.derive_candidate_scripts_for_shared(&shared.to_k256(), max_k)?;
                all_scripts.append(&mut s);
            }
            zeroize_affines(shared_chunk);
        }
        Ok(all_scripts)
    }

    pub fn scan_shared(
        &self,
        shared: &AffinePoint,
        outputs: &[[u8; 32]],
    ) -> Result<Vec<SilentPaymentMatch>, Error> {
        let mut context = ScanContext::new();
        let mut result = Vec::new();
        result
            .try_reserve_exact(outputs.len())
            .map_err(|_| Error::AllocationFailed)?;
        result.resize(outputs.len(), SilentPaymentMatch::default());
        let shared_coord = Affine::from_k256(shared);
        let count = context.scan_shared_coord_into(
            &shared_coord,
            &self.variants,
            &self.label_lookup,
            outputs,
            &mut result,
        )?;
        result.truncate(count);
        Ok(result)
    }
}
