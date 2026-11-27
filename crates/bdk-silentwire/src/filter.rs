use bitcoin::bip158::BlockFilter;
use bitcoin::consensus::encode::VarInt;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::{siphash24, Hash};
use bitcoin::BlockHash;
use silentwire::{input::PreparedTransaction, Error, SpScannerNaive};

const BIP158_M: u64 = 784931;
const BIP158_P: u8 = 19;

/// Fast bitstream reader for BIP-158 Golomb-Rice bitstreams.
/// Reads through a 64-bit window and counts unary quotient runs using leading zeros
/// (`lzcnt` on x86, `clz` on ARM) in a single instruction rather than bit-by-bit reading.
pub struct FastGcsBitReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
    buffer: u64,
    bits_in_buf: usize,
}

impl<'a> FastGcsBitReader<'a> {
    #[inline(always)]
    pub fn new(bytes: &'a [u8]) -> Self {
        let mut reader = Self {
            bytes,
            cursor: 0,
            buffer: 0,
            bits_in_buf: 0,
        };
        reader.refill();
        reader
    }

    #[inline(always)]
    fn refill(&mut self) {
        while self.bits_in_buf <= 56 && self.cursor < self.bytes.len() {
            let b = self.bytes[self.cursor] as u64;
            self.cursor += 1;
            self.buffer |= b << (56 - self.bits_in_buf);
            self.bits_in_buf += 8;
        }
    }

    /// Decodes a Golomb-Rice symbol with parameter P=19.
    /// Returns the decoded delta value, or None if the bitstream ends prematurely.
    #[inline(always)]
    pub fn decode_golomb_rice_p19(&mut self) -> Option<u64> {
        let mut q = 0u64;
        loop {
            if self.bits_in_buf == 0 {
                self.refill();
                if self.bits_in_buf == 0 {
                    return None;
                }
            }
            let inverted = !self.buffer;
            let ones = (inverted.leading_zeros() as usize).min(self.bits_in_buf);
            q = q.saturating_add(ones as u64);
            if q >= (1u64 << (64 - BIP158_P)) {
                return None;
            }
            if ones < self.bits_in_buf {
                let consume = ones + 1;
                if consume >= 64 {
                    self.buffer = 0;
                } else {
                    self.buffer <<= consume;
                }
                self.bits_in_buf -= consume;
                break;
            } else {
                self.buffer = 0;
                self.bits_in_buf = 0;
                self.refill();
            }
        }

        if self.bits_in_buf < (BIP158_P as usize) {
            self.refill();
            if self.bits_in_buf < (BIP158_P as usize) {
                return None;
            }
        }
        if q >= (1u64 << (64 - BIP158_P)) {
            return None;
        }
        let r = self.buffer >> (64 - BIP158_P);
        self.buffer <<= BIP158_P;
        self.bits_in_buf -= BIP158_P as usize;

        Some((q << BIP158_P) | r)
    }
}

pub struct FastGcsFilterMatcher;

impl FastGcsFilterMatcher {
    /// Matches query scripts against raw BIP-158 GCS filter bytes using word-parallel
    /// Golomb-Rice decoding.
    pub fn match_any_raw<I, B>(
        filter_bytes: &[u8],
        block_hash: &BlockHash,
        query: I,
    ) -> Result<bool, Error>
    where
        I: IntoIterator<Item = B>,
        B: core::borrow::Borrow<[u8]>,
    {
        if filter_bytes.is_empty() {
            return Ok(false);
        }
        let mut cursor = filter_bytes;
        let n_elements = VarInt::consensus_decode(&mut cursor)
            .map_err(|_| Error::InvalidWitness)?
            .0;
        if n_elements == 0 {
            return Ok(false);
        }

        let block_hash_bytes = block_hash.to_byte_array();
        let k0 = u64::from_le_bytes(
            block_hash_bytes[0..8]
                .try_into()
                .map_err(|_| Error::InvalidPoint)?,
        );
        let k1 = u64::from_le_bytes(
            block_hash_bytes[8..16]
                .try_into()
                .map_err(|_| Error::InvalidPoint)?,
        );

        let nm = n_elements
            .checked_mul(BIP158_M)
            .ok_or(Error::InvalidWitness)?;
        let mut mapped: Vec<u64> = query
            .into_iter()
            .map(|q| {
                let h = siphash24::Hash::hash_to_u64_with_keys(k0, k1, q.borrow());
                ((h as u128 * nm as u128) >> 64) as u64
            })
            .collect();

        mapped.sort_unstable();
        mapped.dedup();
        if mapped.is_empty() {
            return Ok(false);
        }

        let mut reader = FastGcsBitReader::new(cursor);
        let mut data = reader
            .decode_golomb_rice_p19()
            .ok_or(Error::InvalidWitness)?;
        let mut remaining = n_elements - 1;

        for p in mapped {
            loop {
                match data.cmp(&p) {
                    core::cmp::Ordering::Equal => return Ok(true),
                    core::cmp::Ordering::Less => {
                        if remaining > 0 {
                            let delta = reader
                                .decode_golomb_rice_p19()
                                .ok_or(Error::InvalidWitness)?;
                            data = data.checked_add(delta).ok_or(Error::InvalidWitness)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        }
                    }
                    core::cmp::Ordering::Greater => break,
                }
            }
        }

        Ok(false)
    }
}

pub struct SpFilterMatcher;

impl SpFilterMatcher {
    /// Evaluates candidate Taproot scriptPubKeys derived for the given scanner across all
    /// eligible transaction tweaks against a BIP-158 basic block filter.
    ///
    /// If this returns false, the block is guaranteed to contain no silent payments for this recipient.
    pub fn matches_block_filter(
        filter: &BlockFilter,
        block_hash: &BlockHash,
        scanner: &SpScannerNaive,
        transactions: &[PreparedTransaction],
        max_k: u32,
    ) -> Result<bool, Error> {
        Self::matches_block_filter_fast(filter, block_hash, scanner, transactions, max_k)
    }

    /// Accelerated version using word-parallel Golomb-Rice decoding.
    pub fn matches_block_filter_fast(
        filter: &BlockFilter,
        block_hash: &BlockHash,
        scanner: &SpScannerNaive,
        transactions: &[PreparedTransaction],
        max_k: u32,
    ) -> Result<bool, Error> {
        let scripts = scanner.derive_candidate_scripts_batch_glv(transactions, max_k)?;
        if scripts.is_empty() {
            return Ok(false);
        }
        let script_refs = scripts.iter().map(|s| s.as_slice());
        FastGcsFilterMatcher::match_any_raw(&filter.content, block_hash, script_refs)
    }
}
