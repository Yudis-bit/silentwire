const BUCKETS: usize = 64;
const SLOTS: usize = 8;
const MAX_KICKS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C, align(64))]
struct Bucket([u64; SLOTS]);

const _: () = assert!(core::mem::size_of::<Bucket>() == 64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CuckooFilter {
    buckets: [Bucket; BUCKETS],
    saturated: bool,
}

fn hash(key: &[u8; 32]) -> u64 {
    key.iter().fold(0xcbf29ce484222325, |h, byte| {
        (h ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn alternate(bucket: usize, tag: u64) -> usize {
    bucket ^ (tag.wrapping_mul(0x5bd1e995).rotate_right(23) as usize & (BUCKETS - 1))
}

impl Default for CuckooFilter {
    fn default() -> Self {
        Self {
            buckets: [Bucket([0; SLOTS]); BUCKETS],
            saturated: false,
        }
    }
}

impl CuckooFilter {
    pub fn insert(&mut self, key: &[u8; 32]) {
        if self.saturated {
            return;
        }
        let value = hash(key);
        let first = value as usize & (BUCKETS - 1);
        let mut tag = value.max(1);
        let second = alternate(first, tag);
        if self.buckets[first].0.contains(&tag) || self.buckets[second].0.contains(&tag) {
            return;
        }
        for bucket in [first, second] {
            if let Some(slot) = self.buckets[bucket].0.iter_mut().find(|slot| **slot == 0) {
                *slot = tag;
                return;
            }
        }
        let mut bucket = first;
        for kick in 0..MAX_KICKS {
            core::mem::swap(&mut self.buckets[bucket].0[kick % SLOTS], &mut tag);
            bucket = alternate(bucket, tag);
            if let Some(slot) = self.buckets[bucket].0.iter_mut().find(|slot| **slot == 0) {
                *slot = tag;
                return;
            }
        }
        // A failed relocation may have displaced a prior entry. Fail open for all queries.
        self.saturated = true;
    }

    pub fn may_contain(&self, key: &[u8; 32]) -> bool {
        if self.saturated {
            return true;
        }
        let value = hash(key);
        let first = value as usize & (BUCKETS - 1);
        let tag = value.max(1);
        self.buckets[first].0.contains(&tag) || self.buckets[alternate(first, tag)].0.contains(&tag)
    }

    pub fn saturated(&self) -> bool {
        self.saturated
    }
    pub fn clear(&mut self) {
        self.buckets = [Bucket([0; SLOTS]); BUCKETS];
        self.saturated = false;
    }
}
