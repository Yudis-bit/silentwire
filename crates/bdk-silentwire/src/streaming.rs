use crate::{BlockMatch, PrevoutProvider, ScanError};
use bitcoin::{
    block::Header,
    consensus::{Decodable, Encodable},
    hashes::{sha256d, Hash},
    BlockHash, OutPoint, Txid,
};
use silentwire::{
    input::{prepare, ValidatedInput},
    p2tr_key, Error, SpScannerNaive,
};

#[derive(Debug, Eq, PartialEq)]
pub enum WireError {
    UnexpectedEof,
    MalformedCompactSize,
    MalformedHeader,
    Scan(ScanError),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "Unexpected end of file"),
            Self::MalformedCompactSize => write!(f, "Malformed compact size"),
            Self::MalformedHeader => write!(f, "Malformed block header"),
            Self::Scan(err) => write!(f, "Scan error: {err}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<ScanError> for WireError {
    fn from(value: ScanError) -> Self {
        Self::Scan(value)
    }
}

impl From<Error> for WireError {
    fn from(value: Error) -> Self {
        Self::Scan(ScanError::Arithmetic(value))
    }
}

pub fn read_compact_size(data: &[u8], cursor: &mut usize) -> Result<usize, WireError> {
    if *cursor >= data.len() {
        return Err(WireError::UnexpectedEof);
    }
    let first = data[*cursor];
    *cursor = cursor.checked_add(1).ok_or(WireError::UnexpectedEof)?;
    match first {
        0..=0xfc => Ok(usize::from(first)),
        0xfd => {
            let end = cursor.checked_add(2).ok_or(WireError::UnexpectedEof)?;
            if end > data.len() {
                return Err(WireError::UnexpectedEof);
            }
            let val = u16::from_le_bytes(data[*cursor..end].try_into().unwrap());
            if val < 0xfd {
                return Err(WireError::MalformedCompactSize);
            }
            *cursor = end;
            Ok(usize::from(val))
        }
        0xfe => {
            let end = cursor.checked_add(4).ok_or(WireError::UnexpectedEof)?;
            if end > data.len() {
                return Err(WireError::UnexpectedEof);
            }
            let val = u32::from_le_bytes(data[*cursor..end].try_into().unwrap());
            if val <= 0xffff {
                return Err(WireError::MalformedCompactSize);
            }
            *cursor = end;
            usize::try_from(val).map_err(|_| WireError::UnexpectedEof)
        }
        0xff => {
            let end = cursor.checked_add(8).ok_or(WireError::UnexpectedEof)?;
            if end > data.len() {
                return Err(WireError::UnexpectedEof);
            }
            let val = u64::from_le_bytes(data[*cursor..end].try_into().unwrap());
            if val <= 0xffff_ffff {
                return Err(WireError::MalformedCompactSize);
            }
            *cursor = end;
            usize::try_from(val).map_err(|_| WireError::UnexpectedEof)
        }
    }
}

#[inline]
fn advance(cursor: &mut usize, len: usize, limit: usize) -> Result<usize, WireError> {
    let end = cursor.checked_add(len).ok_or(WireError::UnexpectedEof)?;
    if end > limit {
        return Err(WireError::UnexpectedEof);
    }
    let start = *cursor;
    *cursor = end;
    Ok(start)
}

pub struct StreamingBlockScanner<'a> {
    raw: &'a [u8],
}

struct ParsedTx {
    txid: Txid,
    prepared: silentwire::input::PreparedTransaction,
    taproot_outputs: Vec<(usize, [u8; 32])>,
}

impl<'a> StreamingBlockScanner<'a> {
    pub fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    fn parse_transactions(
        &self,
        prevouts: &impl PrevoutProvider,
    ) -> Result<(Header, BlockHash, Vec<ParsedTx>), WireError> {
        let total = self.raw.len();
        if total < 80 {
            return Err(WireError::UnexpectedEof);
        }
        let header_bytes = &self.raw[..80];
        let mut header_reader = header_bytes;
        let header =
            Header::consensus_decode(&mut header_reader).map_err(|_| WireError::MalformedHeader)?;
        let mut cursor = 80usize;

        let block_hash = BlockHash::from_raw_hash(sha256d::Hash::hash(header_bytes));
        let tx_count = read_compact_size(self.raw, &mut cursor)?;
        let remaining_for_txs = total.saturating_sub(cursor);
        // Minimum valid Bitcoin transaction is 10 bytes (4 ver + 1 in + 1 out + 4 locktime).
        if tx_count > remaining_for_txs / 10 {
            return Err(WireError::UnexpectedEof);
        }
        let mut parsed_txs = Vec::new();

        for _ in 0..tx_count {
            let tx_start = cursor;
            advance(&mut cursor, 4, total)?; // version

            let mut has_witness = false;
            if cursor.checked_add(2).is_some_and(|end| {
                end <= total && self.raw[cursor] == 0x00 && self.raw[cursor + 1] == 0x01
            }) {
                has_witness = true;
                cursor += 2; // BIP-144 marker (0x00) and flag (0x01)
            }

            let input_count = read_compact_size(self.raw, &mut cursor)?;
            let remaining = total.saturating_sub(cursor);
            // Minimum TxIn is 41 bytes (36 outpoint + 1 script_len + 4 sequence).
            if input_count > remaining / 41 {
                return Err(WireError::UnexpectedEof);
            }
            let mut raw_inputs = Vec::with_capacity(input_count.min(1024));

            for _ in 0..input_count {
                let op_start = advance(&mut cursor, 36, total)?;
                let outpoint_bytes: [u8; 36] =
                    self.raw[op_start..op_start + 36].try_into().unwrap();
                let txid = Txid::from_raw_hash(
                    sha256d::Hash::from_slice(&self.raw[op_start..op_start + 32]).unwrap(),
                );
                let vout =
                    u32::from_le_bytes(self.raw[op_start + 32..op_start + 36].try_into().unwrap());

                let script_len = read_compact_size(self.raw, &mut cursor)?;
                let sig_start = advance(&mut cursor, script_len, total)?;
                let script_sig = &self.raw[sig_start..sig_start + script_len];

                advance(&mut cursor, 4, total)?; // sequence

                raw_inputs.push((OutPoint { txid, vout }, outpoint_bytes, script_sig));
            }

            let output_count = read_compact_size(self.raw, &mut cursor)?;
            let remaining = total.saturating_sub(cursor);
            // Minimum TxOut is 9 bytes (8 value + 1 script_len).
            if output_count > remaining / 9 {
                return Err(WireError::UnexpectedEof);
            }
            let mut taproot_outputs = Vec::new();

            for vout in 0..output_count {
                advance(&mut cursor, 8, total)?; // value

                let script_len = read_compact_size(self.raw, &mut cursor)?;
                let spk_start = advance(&mut cursor, script_len, total)?;
                let script_pubkey = &self.raw[spk_start..spk_start + script_len];

                if let Some(key) = p2tr_key(script_pubkey) {
                    taproot_outputs.push((vout, *key));
                }
            }

            let mut witness_data = Vec::with_capacity(input_count.min(1024));
            if has_witness {
                for _ in 0..input_count {
                    let item_count = read_compact_size(self.raw, &mut cursor)?;
                    let remaining = total.saturating_sub(cursor);
                    // Each witness stack item needs at least 1 byte for its CompactSize length.
                    if item_count > remaining {
                        return Err(WireError::UnexpectedEof);
                    }
                    let mut items = Vec::with_capacity(item_count.min(64));
                    for _ in 0..item_count {
                        let item_len = read_compact_size(self.raw, &mut cursor)?;
                        let item_start = advance(&mut cursor, item_len, total)?;
                        items.push(&self.raw[item_start..item_start + item_len]);
                    }
                    witness_data.push(items);
                }
            } else {
                witness_data.resize_with(input_count, Vec::new);
            }

            advance(&mut cursor, 4, total)?; // locktime

            let is_coinbase = raw_inputs.len() == 1 && raw_inputs[0].0.is_null();
            if is_coinbase || taproot_outputs.is_empty() {
                continue;
            }

            // Compute transaction ID without witness fields
            let txid = if has_witness {
                let mut legacy = Vec::new();
                legacy.extend_from_slice(&self.raw[tx_start..tx_start + 4]); // version
                let mut in_cursor = tx_start + 6; // skip marker and flag
                let legacy_in_count = read_compact_size(self.raw, &mut in_cursor)?;
                let mut in_count_bytes = Vec::new();
                bitcoin::VarInt(legacy_in_count as u64)
                    .consensus_encode(&mut in_count_bytes)
                    .unwrap();
                legacy.extend_from_slice(&in_count_bytes);
                for _ in 0..legacy_in_count {
                    let s = advance(&mut in_cursor, 36, total)?;
                    legacy.extend_from_slice(&self.raw[s..s + 36]);
                    let slen = read_compact_size(self.raw, &mut in_cursor)?;
                    let mut slen_bytes = Vec::new();
                    bitcoin::VarInt(slen as u64)
                        .consensus_encode(&mut slen_bytes)
                        .unwrap();
                    legacy.extend_from_slice(&slen_bytes);
                    let s = advance(&mut in_cursor, slen, total)?;
                    legacy.extend_from_slice(&self.raw[s..s + slen]);
                    let s = advance(&mut in_cursor, 4, total)?;
                    legacy.extend_from_slice(&self.raw[s..s + 4]);
                }
                let mut out_cursor = in_cursor;
                let legacy_out_count = read_compact_size(self.raw, &mut out_cursor)?;
                let mut out_count_bytes = Vec::new();
                bitcoin::VarInt(legacy_out_count as u64)
                    .consensus_encode(&mut out_count_bytes)
                    .unwrap();
                legacy.extend_from_slice(&out_count_bytes);
                for _ in 0..legacy_out_count {
                    let s = advance(&mut out_cursor, 8, total)?;
                    legacy.extend_from_slice(&self.raw[s..s + 8]);
                    let slen = read_compact_size(self.raw, &mut out_cursor)?;
                    let mut slen_bytes = Vec::new();
                    bitcoin::VarInt(slen as u64)
                        .consensus_encode(&mut slen_bytes)
                        .unwrap();
                    legacy.extend_from_slice(&slen_bytes);
                    let s = advance(&mut out_cursor, slen, total)?;
                    legacy.extend_from_slice(&self.raw[s..s + slen]);
                }
                legacy.extend_from_slice(&self.raw[cursor - 4..cursor]); // locktime
                Txid::from_raw_hash(sha256d::Hash::hash(&legacy))
            } else {
                Txid::from_raw_hash(sha256d::Hash::hash(&self.raw[tx_start..cursor]))
            };

            let mut inputs = Vec::with_capacity(input_count);
            for ((outpoint, outpoint_bytes, script_sig), witness) in
                raw_inputs.iter().zip(witness_data.iter())
            {
                let prevout = prevouts
                    .prevout(outpoint)
                    .ok_or(ScanError::MissingPrevout(*outpoint))?;
                inputs.push(ValidatedInput {
                    outpoint: *outpoint_bytes,
                    prevout_script: prevout.script_pubkey.as_bytes(),
                    script_sig,
                    witness,
                });
            }

            let Some(prepared) = prepare(&inputs)? else {
                continue;
            };

            parsed_txs.push(ParsedTx {
                txid,
                prepared,
                taproot_outputs,
            });
        }

        Ok((header, block_hash, parsed_txs))
    }

    pub fn scan(
        &self,
        scanner: &SpScannerNaive,
        prevouts: &impl PrevoutProvider,
    ) -> Result<(Header, Vec<BlockMatch>), WireError> {
        let (header, block_hash, parsed_txs) = self.parse_transactions(prevouts)?;
        let mut found = Vec::new();

        for tx in parsed_txs {
            let keys: Vec<[u8; 32]> = tx.taproot_outputs.iter().map(|(_, key)| *key).collect();
            for mut payment in scanner.scan_prepared(&tx.prepared, &keys)? {
                payment.output_index = tx.taproot_outputs[payment.output_index as usize].0 as u32;
                found.push(BlockMatch {
                    block_hash,
                    txid: tx.txid,
                    payment,
                });
            }
        }

        Ok((header, found))
    }

    pub fn scan_batch(
        &self,
        scanner: &SpScannerNaive,
        prevouts: &impl PrevoutProvider,
    ) -> Result<(Header, Vec<BlockMatch>), WireError> {
        let mut ctx = silentwire::ScanContext::default();
        self.scan_batch_with_context(scanner, prevouts, &mut ctx)
    }

    pub fn scan_batch_with_context(
        &self,
        scanner: &SpScannerNaive,
        prevouts: &impl PrevoutProvider,
        ctx: &mut silentwire::ScanContext,
    ) -> Result<(Header, Vec<BlockMatch>), WireError> {
        let (header, block_hash, parsed_txs) = self.parse_transactions(prevouts)?;
        if parsed_txs.is_empty() {
            return Ok((header, Vec::new()));
        }

        let mut found = Vec::new();
        for chunk in parsed_txs.chunks(silentwire::MAX_BATCH) {
            let prepared_list: Vec<silentwire::input::PreparedTransaction> =
                chunk.iter().map(|tx| tx.prepared.clone()).collect();
            let outputs_storage: Vec<Vec<[u8; 32]>> = chunk
                .iter()
                .map(|tx| tx.taproot_outputs.iter().map(|(_, k)| *k).collect())
                .collect();
            let outputs_refs: Vec<&[[u8; 32]]> =
                outputs_storage.iter().map(|k| k.as_slice()).collect();

            scanner.scan_batch_into(&prepared_list, &outputs_refs, ctx)?;
            for (tx, list) in chunk.iter().zip(ctx.drain_results()) {
                for mut payment in list {
                    payment.output_index =
                        tx.taproot_outputs[payment.output_index as usize].0 as u32;
                    found.push(BlockMatch {
                        block_hash,
                        txid: tx.txid,
                        payment,
                    });
                }
            }
        }

        Ok((header, found))
    }
}

pub const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
pub const TESTNET_MAGIC: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];
pub const REGTEST_MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
pub const SIGNET_MAGIC: [u8; 4] = [0x0a, 0x03, 0xcf, 0x40];

pub struct BlkStreamScanner<'a> {
    data: &'a [u8],
    magic: [u8; 4],
}

impl<'a> BlkStreamScanner<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self::with_magic(data, MAINNET_MAGIC)
    }

    pub fn with_magic(data: &'a [u8], magic: [u8; 4]) -> Self {
        Self { data, magic }
    }

    pub fn scan_blocks(
        &self,
        scanner: &SpScannerNaive,
        prevouts: &impl PrevoutProvider,
    ) -> Result<Vec<(Header, Vec<BlockMatch>)>, WireError> {
        let mut cursor = 0usize;
        let total = self.data.len();
        let mut results = Vec::new();
        let mut ctx = silentwire::ScanContext::with_capacity(1024, 1);
        while cursor.checked_add(8).is_some_and(|end| end <= total) {
            if self.data[cursor..cursor + 4] != self.magic {
                cursor += 1;
                continue;
            }
            cursor += 4;
            let block_len =
                u32::from_le_bytes(self.data[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            let block_start = advance(&mut cursor, block_len, total)?;
            let block_bytes = &self.data[block_start..block_start + block_len];
            let block_scanner = StreamingBlockScanner::new(block_bytes);
            let (header, matches) =
                block_scanner.scan_batch_with_context(scanner, prevouts, &mut ctx)?;
            results.push((header, matches));
        }
        Ok(results)
    }

    pub fn scan_blocks_parallel(
        &self,
        scanner: &SpScannerNaive,
        prevouts: &(impl PrevoutProvider + Sync),
        thread_count: usize,
    ) -> Result<Vec<(Header, Vec<BlockMatch>)>, WireError> {
        let mut cursor = 0usize;
        let total = self.data.len();
        let mut blocks = Vec::new();
        while cursor.checked_add(8).is_some_and(|end| end <= total) {
            if self.data[cursor..cursor + 4] != self.magic {
                cursor += 1;
                continue;
            }
            cursor += 4;
            let block_len =
                u32::from_le_bytes(self.data[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            let block_start = advance(&mut cursor, block_len, total)?;
            blocks.push(&self.data[block_start..block_start + block_len]);
        }

        if blocks.is_empty() {
            return Ok(Vec::new());
        }

        let threads = thread_count.max(1).min(blocks.len());
        if threads == 1 {
            let mut ctx = silentwire::ScanContext::with_capacity(1024, 1);
            return blocks
                .into_iter()
                .map(|b| {
                    StreamingBlockScanner::new(b)
                        .scan_batch_with_context(scanner, prevouts, &mut ctx)
                })
                .collect();
        }

        let chunk_size = blocks.len().div_ceil(threads);
        let chunks: Vec<&[&[u8]]> = blocks.chunks(chunk_size).collect();

        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(chunks.len());
            for chunk in chunks {
                let handle = s.spawn(
                    move || -> Result<Vec<(Header, Vec<BlockMatch>)>, WireError> {
                        let mut batch = Vec::with_capacity(chunk.len());
                        let mut ctx = silentwire::ScanContext::with_capacity(1024, 1);
                        for b in chunk {
                            batch.push(
                                StreamingBlockScanner::new(b)
                                    .scan_batch_with_context(scanner, prevouts, &mut ctx)?,
                            );
                        }
                        Ok(batch)
                    },
                );
                handles.push(handle);
            }

            let mut all_results = Vec::with_capacity(blocks.len());
            for handle in handles {
                let part = handle.join().expect("Worker thread panicked")?;
                all_results.extend(part);
            }
            Ok(all_results)
        })
    }
}
