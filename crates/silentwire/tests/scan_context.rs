mod support;
use silentwire::{BlockPaymentMatch, Error, ScanContext, ScanTransaction, SilentPaymentMatch};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

struct CountAlloc;
thread_local! { static TRACK: Cell<bool> = const { Cell::new(false) }; static COUNT: Cell<usize> = const { Cell::new(0) }; }
fn allocation() {
    TRACK.with(|active| {
        if active.get() {
            COUNT.with(|count| count.set(count.get() + 1));
        }
    });
}
// SAFETY: each allocation/deallocation is forwarded unchanged to System.
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountAlloc = CountAlloc;
fn count_allocations<T>(call: impl FnOnce() -> T) -> (T, usize) {
    COUNT.with(|count| count.set(0));
    TRACK.with(|active| active.set(true));
    let result = call();
    TRACK.with(|active| active.set(false));
    (result, COUNT.with(Cell::get))
}

#[test]
fn context_and_caller_buffer_paths_do_not_allocate() {
    let first = support::case(352, 1);
    let second = support::case(352, 2);
    for case in [&first, &second] {
        assert_eq!(
            silentwire::tagged_hash(b"BIP0352/Inputs", &[&case.outpoint, &case.aggregate]),
            case.input_hash
        );
    }
    let (mut context, allocations) = count_allocations(ScanContext::new);
    assert_eq!(allocations, 0);
    let mut results = [SilentPaymentMatch::default(); 4];
    let (found, allocations) = count_allocations(|| {
        context.scan_transaction_into(
            &first.scan,
            &first.spend,
            &first.tweak,
            &first.outputs,
            &mut results,
        )
    });
    assert_eq!(allocations, 0);
    assert_eq!(&results[..found.unwrap()], first.expected);
    // A block shares wallet credentials. Reuse the same independently derived transaction twice.
    let transactions = [ScanTransaction {
        tweak_point: &first.tweak,
        outputs: &first.outputs,
    }; 2];
    let mut block = [BlockPaymentMatch::default(); 4];
    let (found, allocations) = count_allocations(|| {
        context.scan_block_into(&first.scan, &first.spend, &transactions, &mut block)
    });
    assert_eq!(allocations, 0);
    assert_eq!(found.unwrap(), 4);
    assert_eq!(block[0].transaction_index, 0);
    assert_eq!(block[2].transaction_index, 1);
    assert_eq!(block[2].payment, first.expected[0]);
    println!(
        "host ScanContext bytes={}, alignment={}, allocations=0",
        size_of::<ScanContext>(),
        align_of::<ScanContext>()
    );
    assert!(size_of::<ScanContext>() < 16384);
    assert_eq!(support::scan(&mut context, &first), first.expected);
}

#[test]
fn erase_partial_results_on_capacity_error_and_reuse() {
    let case = support::case(352, 1);
    let mut context = ScanContext::new();
    let mut results = [SilentPaymentMatch::default(); 1];
    assert_eq!(
        context.scan_transaction_into(
            &case.scan,
            &case.spend,
            &case.tweak,
            &case.outputs,
            &mut results
        ),
        Err(Error::ScratchTooSmall)
    );
    assert_eq!(results, [SilentPaymentMatch::default()]);
    let tx = [ScanTransaction {
        tweak_point: &case.tweak,
        outputs: &case.outputs,
    }; 2];
    let mut block = [BlockPaymentMatch::default(); 3];
    assert_eq!(
        context.scan_block_into(&case.scan, &case.spend, &tx, &mut block),
        Err(Error::ScratchTooSmall)
    );
    assert_eq!(block, [BlockPaymentMatch::default(); 3]);
    support::scan(&mut context, &case);
}

#[test]
fn reject_invalid_points_scalars_and_oversized_batches() {
    let case = support::case(352, 2);
    let mut context = ScanContext::new();
    assert_eq!(
        context.scan_transaction(&[0; 32], &case.spend, &case.tweak, &[]),
        Err(Error::InvalidScalar)
    );
    assert_eq!(
        context.scan_transaction(&[255; 32], &case.spend, &case.tweak, &[]),
        Err(Error::InvalidScalar)
    );
    assert_eq!(
        context.scan_transaction(&case.scan, &case.spend, &[0; 33], &[]),
        Err(Error::InvalidPoint)
    );
    let too_many = vec![[0; 32]; silentwire::MAX_BATCH + 1];
    assert_eq!(
        context.scan_transaction(&case.scan, &case.spend, &case.tweak, &too_many),
        Err(Error::BatchTooLarge)
    );
    assert_eq!(
        context.scan_transaction(&case.scan, &case.spend, &case.tweak, &[]),
        Ok(vec![])
    );
}

#[test]
fn block_buffers_support_more_than_one_candidate_chunk() {
    let case = support::case_with_count(352, 1, 20);
    let tx = [ScanTransaction {
        tweak_point: &case.tweak,
        outputs: &case.outputs,
    }; 2];
    let mut context = ScanContext::new();
    let mut buffer = [BlockPaymentMatch::default(); 40];
    let (found, allocations) =
        count_allocations(|| context.scan_block_into(&case.scan, &case.spend, &tx, &mut buffer));
    assert_eq!(allocations, 0);
    assert_eq!(found.unwrap(), 40);
    assert_eq!(buffer[39].transaction_index, 1);
    assert_eq!(buffer[39].payment, case.expected[19]);
}
