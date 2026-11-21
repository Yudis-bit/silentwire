use silentwire::{
    k256::{self, elliptic_curve::PrimeField},
    point,
    zeroize::Zeroizing,
    SpScannerNaive,
};

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[inline(always)]
unsafe fn valgrind_make_mem_defined(ptr: *const u8, len: usize) {
    let args: [usize; 6] = [
        0x4d430002, // VG_USERREQ__MAKE_MEM_DEFINED
        ptr as usize,
        len,
        0,
        0,
        0,
    ];
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            inout("rax") args.as_ptr() => _,
            inout("rdx") 0usize => _,
            options(nostack),
        );
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[inline(always)]
unsafe fn valgrind_make_mem_defined(ptr: *const u8, len: usize) {
    let args: [usize; 6] = [0x4d430002, ptr as usize, len, 0, 0, 0];
    unsafe {
        core::arch::asm!(
            "mov x3, xzr",
            "mov x4, {args}",
            "ror x12, x12, #3",
            "ror x12, x12, #13",
            "ror x12, x12, #51",
            "ror x12, x12, #61",
            "orr x10, x10, x10",
            args = in(reg) args.as_ptr(),
            out("x3") _,
            out("x4") _,
            options(nostack),
        );
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "linux"),
    all(target_arch = "aarch64", target_os = "linux")
)))]
#[inline(always)]
unsafe fn valgrind_make_mem_defined(_ptr: *const u8, _len: usize) {}

fn valgrind_declassify(ptr: *const u8, len: usize) {
    unsafe { valgrind_make_mem_defined(ptr, len) };
}

#[repr(C)]
pub struct SilentwireScanRequest {
    pub scan_key: [u8; 32],
    pub spend_pubkey: [u8; 33],
    pub transaction_tweak: [u8; 33],
    pub labels: *const u32,
    pub label_count: usize,
    pub outputs: *const u8,
    pub output_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SilentwireMatch {
    pub vout: u32,
    pub k: u32,
    pub label: u32,
    pub has_label: u8,
    pub reserved: [u8; 3],
    pub pubkey: [u8; 32],
    pub private_key_tweak: [u8; 32],
}

#[repr(C)]
pub struct SilentwireBatchTx {
    pub transaction_tweak: [u8; 33],
    pub outputs: *const u8,
    pub output_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SilentwireBatchMatch {
    pub tx_index: u32,
    pub vout: u32,
    pub k: u32,
    pub label: u32,
    pub has_label: u8,
    pub reserved: [u8; 3],
    pub pubkey: [u8; 32],
    pub private_key_tweak: [u8; 32],
}

unsafe fn scan_inner(
    request: *const SilentwireScanRequest,
    matches: *mut SilentwireMatch,
    capacity: usize,
    written: *mut usize,
    use_glv: bool,
) -> i32 {
    if written.is_null() || !written.is_aligned() {
        return 1;
    }
    // The caller guarantees a unique writable usize at this aligned pointer.
    unsafe { written.write(0) };
    if request.is_null()
        || !request.is_aligned()
        || capacity > 4096
        || (capacity != 0 && (matches.is_null() || !matches.is_aligned()))
    {
        return 1;
    }
    let result = std::panic::catch_unwind(|| {
        // Pointer validity and the request lifetime are caller obligations.
        let r = unsafe { &*request };
        if r.output_count > 4096
            || r.label_count > 4096
            || (r.output_count != 0 && r.outputs.is_null())
            || (r.label_count != 0 && (r.labels.is_null() || !r.labels.is_aligned()))
        {
            return 1;
        }
        // Counts are bounded above. A byte-array reference has alignment one.
        let outputs: &[[u8; 32]] = if r.output_count == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(r.outputs.cast(), r.output_count) }
        };
        let labels = if r.label_count == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(r.labels, r.label_count) }
        };
        let ct_option = k256::Scalar::from_repr(r.scan_key.into());
        let is_some = ct_option.is_some();
        let scan_val = ct_option.unwrap_or(k256::Scalar::ZERO);
        let is_zero = scan_val.is_zero();
        let is_valid = is_some & !is_zero;
        let valid_u8 = is_valid.unwrap_u8();
        unsafe {
            valgrind_make_mem_defined(&valid_u8 as *const u8, 1);
        }
        if valid_u8 == 0 {
            return 1;
        }
        let scan = Zeroizing::new(scan_val);
        let Ok(mut receiver) = SpScannerNaive::from_scalar_with_declassify(
            scan,
            r.spend_pubkey,
            labels,
            Some(valgrind_declassify),
        ) else {
            return 1;
        };
        let Ok(tweak) = point(&r.transaction_tweak) else {
            return 1;
        };
        let shared = if use_glv {
            receiver.shared_secret_from_tweak_glv(&k256::ProjectivePoint::from(tweak))
        } else {
            receiver.shared_secret_from_tweak(&tweak)
        };
        unsafe {
            valgrind_make_mem_defined(
                (&shared as *const k256::AffinePoint).cast(),
                core::mem::size_of::<k256::AffinePoint>(),
            );
        }
        receiver.declassify_variants(|ptr, len| unsafe {
            valgrind_make_mem_defined(ptr, len);
        });
        let Ok(found) = receiver.scan_shared(&shared, outputs) else {
            return 1;
        };
        // The written count is independent of whether the output capacity suffices.
        unsafe { written.write(found.len()) };
        if found.len() > capacity {
            return 2;
        }
        for (index, payment) in found.iter().enumerate() {
            let value = SilentwireMatch {
                vout: payment.output_index,
                k: payment.derivation_index,
                label: payment.label.unwrap_or(0),
                has_label: u8::from(payment.label.is_some()),
                reserved: [0; 3],
                pubkey: payment.taproot_pubkey,
                private_key_tweak: payment.tweak_scalar,
            };
            // Capacity covers index. Source and destination do not overlap.
            unsafe { matches.add(index).write(value) };
        }
        0
    });
    result.unwrap_or(3)
}

/// Scan a pre-extracted public transaction tweak h * A. Returns 0, 1 (invalid),
/// 2 (capacity, with required count), or 3 (panic).
///
/// # Safety
/// Non-null pointers must be aligned and valid for their declared element counts.
/// Writable regions must be disjoint from all readable regions and each other.
/// Input memory must remain immutable for the call. The caller authenticates h * A.
#[no_mangle]
pub unsafe extern "C" fn silentwire_scan(
    request: *const SilentwireScanRequest,
    matches: *mut SilentwireMatch,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    unsafe { scan_inner(request, matches, capacity, written, false) }
}

/// Scan a pre-extracted public transaction tweak with the GLV endomorphism.
///
/// # Safety
/// Same pointer, alignment, disjointness, and tweak-authentication requirements
/// as [`silentwire_scan`].
#[no_mangle]
pub unsafe extern "C" fn silentwire_scan_glv(
    request: *const SilentwireScanRequest,
    matches: *mut SilentwireMatch,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    unsafe { scan_inner(request, matches, capacity, written, true) }
}

/// Scan an array of transaction tweaks and candidate outputs using GLV batching.
///
/// # Safety
/// All non-null input and output pointers must be aligned, valid for their
/// declared counts, and mutually non-overlapping. The caller authenticates the
/// supplied tweaks.
#[no_mangle]
pub unsafe extern "C" fn silentwire_scan_batch_glv(
    scan_key: *const u8,
    spend_pubkey: *const u8,
    labels: *const u32,
    label_count: usize,
    txs: *const SilentwireBatchTx,
    tx_count: usize,
    matches: *mut SilentwireBatchMatch,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if written.is_null() || !written.is_aligned() {
        return 1;
    }
    unsafe { written.write(0) };
    if scan_key.is_null()
        || spend_pubkey.is_null()
        || capacity > 65536
        || (capacity != 0 && (matches.is_null() || !matches.is_aligned()))
    {
        return 1;
    }
    if tx_count > 4096 || label_count > 4096 {
        return 1;
    }
    if tx_count != 0 && (txs.is_null() || !txs.is_aligned()) {
        return 1;
    }
    if label_count != 0 && (labels.is_null() || !labels.is_aligned()) {
        return 1;
    }
    let result = std::panic::catch_unwind(|| {
        if tx_count == 0 {
            return 0;
        }
        let labels_slice = if label_count == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(labels, label_count) }
        };
        let mut key_arr = [0u8; 32];
        unsafe { core::ptr::copy_nonoverlapping(scan_key, key_arr.as_mut_ptr(), 32) };
        let mut spend_arr = [0u8; 33];
        unsafe { core::ptr::copy_nonoverlapping(spend_pubkey, spend_arr.as_mut_ptr(), 33) };

        let ct_option = k256::Scalar::from_repr(key_arr.into());
        let is_some = ct_option.is_some();
        let scan_val = ct_option.unwrap_or(k256::Scalar::ZERO);
        let is_zero = scan_val.is_zero();
        let is_valid = is_some & !is_zero;
        let valid_u8 = is_valid.unwrap_u8();
        unsafe {
            valgrind_make_mem_defined(&valid_u8 as *const u8, 1);
        }
        if valid_u8 == 0 {
            return 1;
        }
        let scan = Zeroizing::new(scan_val);
        let Ok(mut receiver) = SpScannerNaive::from_scalar_with_declassify(
            scan,
            spend_arr,
            labels_slice,
            Some(valgrind_declassify),
        ) else {
            return 1;
        };
        receiver.declassify_variants(|ptr, len| unsafe {
            valgrind_make_mem_defined(ptr, len);
        });

        let batch_items = unsafe { core::slice::from_raw_parts(txs, tx_count) };
        let mut tweaks = Vec::with_capacity(tx_count);
        let mut outputs_vec = Vec::with_capacity(tx_count);
        for item in batch_items {
            if item.output_count > 4096 || (item.output_count != 0 && item.outputs.is_null()) {
                return 1;
            }
            let Ok(tweak) = point(&item.transaction_tweak) else {
                return 1;
            };
            tweaks.push(tweak);
            let out_slice: &[[u8; 32]] = if item.output_count == 0 {
                &[]
            } else {
                unsafe { core::slice::from_raw_parts(item.outputs.cast(), item.output_count) }
            };
            outputs_vec.push(out_slice);
        }

        let mut found: Vec<SilentwireBatchMatch> = Vec::new();
        if receiver
            .scan_affine_batch_glv_visit_with_declassify(
                &tweaks,
                &outputs_vec,
                Some(valgrind_declassify),
                |tx_idx, payment| {
                    found.push(SilentwireBatchMatch {
                        tx_index: tx_idx as u32,
                        vout: payment.output_index,
                        k: payment.derivation_index,
                        label: payment.label.unwrap_or(0),
                        has_label: u8::from(payment.label.is_some()),
                        reserved: [0; 3],
                        pubkey: payment.taproot_pubkey,
                        private_key_tweak: payment.tweak_scalar,
                    });
                    Ok(())
                },
            )
            .is_err()
        {
            return 1;
        }

        let total_matches = found.len();
        unsafe { written.write(total_matches) };
        if total_matches > capacity {
            return 2;
        }

        for (dest_idx, value) in found.into_iter().enumerate() {
            unsafe { matches.add(dest_idx).write(value) };
        }
        0
    });
    result.unwrap_or(3)
}

/// Computes `Q = secret_scalar * base_pubkey` using dual independent additive
/// scalar blinding and constant-time fault cross-checking.
///
/// # Safety
/// All non-null pointers must refer to valid byte arrays of the documented sizes.
#[no_mangle]
pub unsafe extern "C" fn silentwire_hardened_multiply(
    secret_scalar: *const u8,
    base_pubkey: *const u8,
    blinding_1: *const u8,
    blinding_2: *const u8,
    out_pubkey: *mut u8,
) -> i32 {
    if secret_scalar.is_null()
        || base_pubkey.is_null()
        || blinding_1.is_null()
        || blinding_2.is_null()
        || out_pubkey.is_null()
    {
        return 1;
    }
    let result = std::panic::catch_unwind(|| {
        let mut s_arr = Zeroizing::new([0u8; 32]);
        let mut b1_arr = Zeroizing::new([0u8; 32]);
        let mut b2_arr = Zeroizing::new([0u8; 32]);
        let mut base_arr = [0u8; 33];
        unsafe {
            core::ptr::copy_nonoverlapping(secret_scalar, s_arr.as_mut_ptr(), 32);
            core::ptr::copy_nonoverlapping(blinding_1, b1_arr.as_mut_ptr(), 32);
            core::ptr::copy_nonoverlapping(blinding_2, b2_arr.as_mut_ptr(), 32);
            core::ptr::copy_nonoverlapping(base_pubkey, base_arr.as_mut_ptr(), 33);
        }
        let parse_ct_scalar = |arr: &[u8; 32]| -> Option<k256::Scalar> {
            let ct = k256::Scalar::from_repr((*arr).into());
            let valid = (ct.is_some() & !ct.unwrap_or(k256::Scalar::ZERO).is_zero()).unwrap_u8();
            unsafe { valgrind_make_mem_defined(&valid as *const u8, 1) };
            if valid == 0 {
                None
            } else {
                Some(ct.unwrap_or(k256::Scalar::ZERO))
            }
        };
        let (Some(s), Some(b1), Some(b2)) = (
            parse_ct_scalar(&s_arr),
            parse_ct_scalar(&b1_arr),
            parse_ct_scalar(&b2_arr),
        ) else {
            return 1;
        };
        let Ok(base_aff) = point(&base_arr) else {
            return 1;
        };
        let Ok(enc) = silentwire::HardenedMultiplier::multiply_dual_with_declassify(
            &s,
            &base_aff,
            &b1,
            &b2,
            Some(valgrind_declassify),
        ) else {
            return 1;
        };
        unsafe { core::ptr::copy_nonoverlapping(enc.as_ptr(), out_pubkey, 33) };
        0
    });
    result.unwrap_or(3)
}

/// Generates a 64-byte BIP-374 DLEQ proof for `(secret_a, b_pubkey, aux_rand)`.
///
/// # Safety
/// All non-null pointers must refer to valid byte arrays of the documented sizes.
#[no_mangle]
pub unsafe extern "C" fn silentwire_dleq_prove(
    secret_a: *const u8,
    b_pubkey: *const u8,
    aux_rand: *const u8,
    out_proof: *mut u8,
) -> i32 {
    if secret_a.is_null() || b_pubkey.is_null() || aux_rand.is_null() || out_proof.is_null() {
        return 1;
    }
    let result = std::panic::catch_unwind(|| {
        let mut a_arr = Zeroizing::new([0u8; 32]);
        let mut aux_arr = Zeroizing::new([0u8; 32]);
        let mut b_arr = [0u8; 33];
        unsafe {
            core::ptr::copy_nonoverlapping(secret_a, a_arr.as_mut_ptr(), 32);
            core::ptr::copy_nonoverlapping(aux_rand, aux_arr.as_mut_ptr(), 32);
            core::ptr::copy_nonoverlapping(b_pubkey, b_arr.as_mut_ptr(), 33);
        }
        let ct = k256::Scalar::from_repr((*a_arr).into());
        let a_val = ct.unwrap_or(k256::Scalar::ZERO);
        let valid = (ct.is_some() & !a_val.is_zero()).unwrap_u8();
        unsafe { valgrind_make_mem_defined(&valid as *const u8, 1) };
        if valid == 0 {
            return 1;
        }
        let Ok(b_aff) = point(&b_arr) else {
            return 1;
        };
        let Ok(proof) = silentwire::bip374::dleq_prove_with_declassify(
            &a_val,
            &b_aff,
            &aux_arr,
            None,
            None,
            Some(valgrind_declassify),
        ) else {
            return 1;
        };
        unsafe {
            valgrind_make_mem_defined(proof.as_ptr(), 64);
            core::ptr::copy_nonoverlapping(proof.as_ptr(), out_proof, 64);
        }
        0
    });
    result.unwrap_or(3)
}
