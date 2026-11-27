#![forbid(unsafe_code)]

pub mod ctis;
pub mod filter;
pub mod streaming;

pub use bitcoin;
use bitcoin::{consensus::serialize, Block, BlockHash, OutPoint, TxOut, Txid};
pub use ctis::{CompactTweakBlock, CtisError};
pub use filter::{FastGcsBitReader, FastGcsFilterMatcher, SpFilterMatcher};
use silentwire::{
    input::{prepare, ValidatedInput},
    p2tr_key, Error, SilentPaymentMatch, SpScannerNaive,
};
pub use streaming::{
    BlkStreamScanner, StreamingBlockScanner, WireError, MAINNET_MAGIC, REGTEST_MAGIC, SIGNET_MAGIC,
    TESTNET_MAGIC,
};

pub trait PrevoutProvider {
    fn prevout(&self, outpoint: &OutPoint) -> Option<&TxOut>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockMatch {
    pub block_hash: BlockHash,
    pub txid: Txid,
    pub payment: SilentPaymentMatch,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ScanError {
    MissingPrevout(OutPoint),
    Arithmetic(Error),
    ReorganizationDetected {
        expected: BlockHash,
        actual: BlockHash,
    },
}

impl core::fmt::Display for ScanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingPrevout(op) => write!(f, "Missing prevout for outpoint {op}"),
            Self::Arithmetic(err) => write!(f, "Arithmetic error: {err}"),
            Self::ReorganizationDetected { expected, actual } => {
                write!(
                    f,
                    "Chain reorganization detected: expected {expected}, actual {actual}"
                )
            }
        }
    }
}

impl std::error::Error for ScanError {}

impl From<Error> for ScanError {
    fn from(value: Error) -> Self {
        Self::Arithmetic(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedBlock {
    pub height: u32,
    pub block_hash: BlockHash,
    pub prev_block_hash: BlockHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedPayment {
    pub height: u32,
    pub block_hash: BlockHash,
    pub txid: Txid,
    pub payment: SilentPaymentMatch,
}

/// Derives the BIP-352 Taproot spending key `b_spend + tweak (mod n)` with
/// automatic zeroization of intermediate scalars. Callers should wrap the
/// returned key bytes in `silentwire::zeroize::Zeroizing`.
pub fn derive_spending_key(
    spend_priv_key: [u8; 32],
    private_key_tweak: [u8; 32],
) -> Result<[u8; 32], Error> {
    use silentwire::zeroize::Zeroizing;
    let spend_bytes = Zeroizing::new(spend_priv_key);
    let tweak_bytes = Zeroizing::new(private_key_tweak);
    let b_spend = Zeroizing::new(silentwire::scalar(*spend_bytes)?);
    let tweak = Zeroizing::new(silentwire::scalar(*tweak_bytes)?);
    let total = Zeroizing::new(*b_spend + *tweak);
    if bool::from(total.is_zero()) {
        return Err(Error::InvalidScalar);
    }
    Ok(total.to_bytes().into())
}

pub struct SpWalletTracker {
    scanner: SpScanner,
    chain: Vec<TrackedBlock>,
    payments: Vec<TrackedPayment>,
    ctx: silentwire::ScanContext,
}

impl SpWalletTracker {
    pub fn new(scanner: SpScanner) -> Self {
        Self {
            scanner,
            chain: Vec::new(),
            payments: Vec::new(),
            ctx: silentwire::ScanContext::with_capacity(1024, 1),
        }
    }

    pub fn tip(&self) -> Option<&TrackedBlock> {
        self.chain.last()
    }

    pub fn tracked_blocks(&self) -> &[TrackedBlock] {
        &self.chain
    }

    pub fn payments(&self) -> &[TrackedPayment] {
        &self.payments
    }

    pub fn apply_block(
        &mut self,
        height: u32,
        block: &Block,
        prevouts: &impl PrevoutProvider,
    ) -> Result<Vec<TrackedPayment>, ScanError> {
        if let Some(tip) = self.chain.last() {
            if block.header.prev_blockhash != tip.block_hash {
                return Err(ScanError::ReorganizationDetected {
                    expected: tip.block_hash,
                    actual: block.header.prev_blockhash,
                });
            }
        }
        let matches = self
            .scanner
            .scan_block_batch_with_context(block, prevouts, &mut self.ctx)?;
        let tracked_block = TrackedBlock {
            height,
            block_hash: block.block_hash(),
            prev_block_hash: block.header.prev_blockhash,
        };
        self.chain.push(tracked_block);
        let mut new_payments = Vec::with_capacity(matches.len());
        for m in matches {
            let tp = TrackedPayment {
                height,
                block_hash: m.block_hash,
                txid: m.txid,
                payment: m.payment,
            };
            self.payments.push(tp.clone());
            new_payments.push(tp);
        }
        Ok(new_payments)
    }

    pub fn rollback_to(&mut self, height: u32) -> Vec<TrackedPayment> {
        self.chain.retain(|b| b.height <= height);
        let mut orphaned = Vec::new();
        self.payments.retain(|p| {
            if p.height > height {
                orphaned.push(p.clone());
                false
            } else {
                true
            }
        });
        orphaned
    }
}

pub struct SpScanner {
    receiver: SpScannerNaive,
}

impl SpScanner {
    pub fn new(receiver: SpScannerNaive) -> Self {
        Self { receiver }
    }

    /// Creates a scanner directly from secp256k1 SecretKey and PublicKey types.
    pub fn from_secp_keys(
        scan_sk: &bitcoin::secp256k1::SecretKey,
        spend_pk: &bitcoin::secp256k1::PublicKey,
        labels: &[u32],
    ) -> Result<Self, ScanError> {
        let receiver = SpScannerNaive::new(scan_sk.secret_bytes(), spend_pk.serialize(), labels)?;
        Ok(Self { receiver })
    }

    pub fn receiver(&self) -> &SpScannerNaive {
        &self.receiver
    }

    /// Scans a block using Montgomery batch normalization across all transactions.
    pub fn scan_block_batch(
        &self,
        block: &Block,
        prevouts: &impl PrevoutProvider,
    ) -> Result<Vec<BlockMatch>, ScanError> {
        let mut ctx = silentwire::ScanContext::default();
        self.scan_block_batch_with_context(block, prevouts, &mut ctx)
    }

    /// Scans a block using Montgomery batch normalization across all eligible
    /// transactions, reusing the caller's ScanContext workspace and chunking
    /// blocks that exceed `silentwire::MAX_BATCH`.
    pub fn scan_block_batch_with_context(
        &self,
        block: &Block,
        prevouts: &impl PrevoutProvider,
        ctx: &mut silentwire::ScanContext,
    ) -> Result<Vec<BlockMatch>, ScanError> {
        let mut prepared_list = Vec::new();
        let mut parsed_txs = Vec::new();
        let mut outputs_storage = Vec::new();

        for tx in &block.txdata {
            if tx.is_coinbase()
                || !tx
                    .output
                    .iter()
                    .any(|output| p2tr_key(output.script_pubkey.as_bytes()).is_some())
            {
                continue;
            }
            let witnesses: Vec<Vec<&[u8]>> = tx
                .input
                .iter()
                .map(|i| i.witness.iter().collect())
                .collect();
            let mut inputs = Vec::with_capacity(tx.input.len());
            for (input, witness) in tx.input.iter().zip(witnesses.iter()) {
                let prevout = prevouts
                    .prevout(&input.previous_output)
                    .ok_or(ScanError::MissingPrevout(input.previous_output))?;
                let outpoint = serialize(&input.previous_output)
                    .try_into()
                    .map_err(|_| Error::InvalidPoint)?;
                inputs.push(ValidatedInput {
                    outpoint,
                    prevout_script: prevout.script_pubkey.as_bytes(),
                    script_sig: input.script_sig.as_bytes(),
                    witness,
                });
            }
            let Some(prepared) = prepare(&inputs)? else {
                continue;
            };
            let indexed: Vec<(usize, [u8; 32])> = tx
                .output
                .iter()
                .enumerate()
                .filter_map(|(i, o)| p2tr_key(o.script_pubkey.as_bytes()).map(|x| (i, *x)))
                .collect();
            let keys: Vec<[u8; 32]> = indexed.iter().map(|(_, key)| *key).collect();
            prepared_list.push(prepared);
            parsed_txs.push((tx.compute_txid(), indexed));
            outputs_storage.push(keys);
        }

        if prepared_list.is_empty() {
            return Ok(Vec::new());
        }

        let mut found = Vec::new();
        let block_hash = block.block_hash();
        let mut offset = 0usize;
        while offset < prepared_list.len() {
            let end = (offset + silentwire::MAX_BATCH).min(prepared_list.len());
            let outputs_refs: Vec<&[[u8; 32]]> = outputs_storage[offset..end]
                .iter()
                .map(|k| k.as_slice())
                .collect();
            self.receiver
                .scan_batch_into(&prepared_list[offset..end], &outputs_refs, ctx)?;
            for ((txid, indexed), list) in parsed_txs[offset..end].iter().zip(ctx.drain_results()) {
                for mut payment in list {
                    payment.output_index = indexed[payment.output_index as usize].0 as u32;
                    found.push(BlockMatch {
                        block_hash,
                        txid: *txid,
                        payment,
                    });
                }
            }
            offset = end;
        }
        Ok(found)
    }

    /// The caller supplies a validated block and authenticated previous outputs.
    pub fn scan_block(
        &self,
        block: &Block,
        prevouts: &impl PrevoutProvider,
    ) -> Result<Vec<BlockMatch>, ScanError> {
        let mut found = Vec::new();
        for tx in &block.txdata {
            if tx.is_coinbase()
                || !tx
                    .output
                    .iter()
                    .any(|output| p2tr_key(output.script_pubkey.as_bytes()).is_some())
            {
                continue;
            }
            let witnesses: Vec<Vec<&[u8]>> = tx
                .input
                .iter()
                .map(|i| i.witness.iter().collect())
                .collect();
            let mut inputs = Vec::with_capacity(tx.input.len());
            for (input, witness) in tx.input.iter().zip(witnesses.iter()) {
                let prevout = prevouts
                    .prevout(&input.previous_output)
                    .ok_or(ScanError::MissingPrevout(input.previous_output))?;
                let outpoint = serialize(&input.previous_output)
                    .try_into()
                    .map_err(|_| Error::InvalidPoint)?;
                inputs.push(ValidatedInput {
                    outpoint,
                    prevout_script: prevout.script_pubkey.as_bytes(),
                    script_sig: input.script_sig.as_bytes(),
                    witness,
                });
            }
            let Some(prepared) = prepare(&inputs)? else {
                continue;
            };
            let indexed: Vec<(usize, [u8; 32])> = tx
                .output
                .iter()
                .enumerate()
                .filter_map(|(i, o)| p2tr_key(o.script_pubkey.as_bytes()).map(|x| (i, *x)))
                .collect();
            let keys: Vec<[u8; 32]> = indexed.iter().map(|(_, key)| *key).collect();
            for mut payment in self.receiver.scan_prepared(&prepared, &keys)? {
                payment.output_index = indexed[payment.output_index as usize].0 as u32;
                found.push(BlockMatch {
                    block_hash: block.block_hash(),
                    txid: tx.compute_txid(),
                    payment,
                });
            }
        }
        Ok(found)
    }
}
