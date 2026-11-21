import Foundation

public struct SpPaymentMatch: Equatable {
    public let vout: UInt32
    public let k: UInt32
    public let label: UInt32?
    public let pubkey: Data
    public let privateKeyTweak: Data

    public init(vout: UInt32, k: UInt32, label: UInt32?, pubkey: Data, privateKeyTweak: Data) {
        self.vout = vout
        self.k = k
        self.label = label
        self.pubkey = pubkey
        self.privateKeyTweak = privateKeyTweak
    }
}

public struct SpBatchPaymentMatch: Equatable {
    public let txIndex: UInt32
    public let vout: UInt32
    public let k: UInt32
    public let label: UInt32?
    public let pubkey: Data
    public let privateKeyTweak: Data

    public init(txIndex: UInt32, vout: UInt32, k: UInt32, label: UInt32?, pubkey: Data, privateKeyTweak: Data) {
        self.txIndex = txIndex
        self.vout = vout
        self.k = k
        self.label = label
        self.pubkey = pubkey
        self.privateKeyTweak = privateKeyTweak
    }
}

public enum SilentwireError: Error, Equatable {
    case invalidInput
    case capacityExceeded
    case executionFailed(Int32)
}

public final class Silentwire {
    public static func scanPrepared(
        scanKey: Data,
        spendPubkey: Data,
        transactionTweak: Data,
        outputs: [Data],
        labels: [UInt32] = []
    ) throws -> [SpPaymentMatch] {
        return try scanPreparedInternal(
            scanKey: scanKey,
            spendPubkey: spendPubkey,
            transactionTweak: transactionTweak,
            outputs: outputs,
            labels: labels,
            useGlv: false
        )
    }

    public static func scanPreparedGlv(
        scanKey: Data,
        spendPubkey: Data,
        transactionTweak: Data,
        outputs: [Data],
        labels: [UInt32] = []
    ) throws -> [SpPaymentMatch] {
        return try scanPreparedInternal(
            scanKey: scanKey,
            spendPubkey: spendPubkey,
            transactionTweak: transactionTweak,
            outputs: outputs,
            labels: labels,
            useGlv: true
        )
    }

    private static func scanPreparedInternal(
        scanKey: Data,
        spendPubkey: Data,
        transactionTweak: Data,
        outputs: [Data],
        labels: [UInt32],
        useGlv: Bool
    ) throws -> [SpPaymentMatch] {
        guard scanKey.count == 32, spendPubkey.count == 33, transactionTweak.count == 33 else {
            throw SilentwireError.invalidInput
        }
        guard outputs.count <= 4096, labels.count <= 4096 else {
            throw SilentwireError.capacityExceeded
        }

        var packedOutputs = Data()
        packedOutputs.reserveCapacity(outputs.count * 32)
        for out in outputs {
            guard out.count == 32 else { throw SilentwireError.invalidInput }
            packedOutputs.append(out)
        }

        var matches = [SilentwireMatch](repeating: SilentwireMatch(), count: 4096)
        var written: size_t = 0

        let status: Int32 = scanKey.withUnsafeBytes { scanPtr in
            spendPubkey.withUnsafeBytes { spendPtr in
                transactionTweak.withUnsafeBytes { tweakPtr in
                    packedOutputs.withUnsafeBytes { outPtr in
                        labels.withUnsafeBufferPointer { labelBuf in
                            var req = SilentwireScanRequest()
                            memcpy(&req.scan_key, scanPtr.baseAddress!, 32)
                            memcpy(&req.spend_pubkey, spendPtr.baseAddress!, 33)
                            memcpy(&req.transaction_tweak, tweakPtr.baseAddress!, 33)
                            req.labels = labelBuf.baseAddress
                            req.label_count = labelBuf.count
                            req.outputs = outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                            req.output_count = outputs.count

                            let rc = matches.withUnsafeMutableBufferPointer { matchBuf in
                                if useGlv {
                                    return silentwire_scan_glv(&req, matchBuf.baseAddress!, 4096, &written)
                                } else {
                                    return silentwire_scan(&req, matchBuf.baseAddress!, 4096, &written)
                                }
                            }
                            _ = withUnsafeMutableBytes(of: &req.scan_key) { ptr in
                                memset_s(ptr.baseAddress!, ptr.count, 0, ptr.count)
                            }
                            return rc
                        }
                    }
                }
            }
        }

        guard status == 0 else {
            matches.withUnsafeMutableBytes { ptr in
                _ = memset_s(ptr.baseAddress!, ptr.count, 0, ptr.count)
            }
            throw SilentwireError.executionFailed(status)
        }

        var result: [SpPaymentMatch] = []
        result.reserveCapacity(written)
        for i in 0..<written {
            let m = matches[i]
            let label = m.has_label != 0 ? m.label : nil
            let pubkey = withUnsafeBytes(of: m.pubkey) { Data($0) }
            let tweak = withUnsafeBytes(of: m.private_key_tweak) { Data($0) }
            result.append(SpPaymentMatch(vout: m.vout, k: m.k, label: label, pubkey: pubkey, privateKeyTweak: tweak))
        }

        matches.withUnsafeMutableBytes { ptr in
            _ = memset_s(ptr.baseAddress!, ptr.count, 0, ptr.count)
        }

        return result
    }

    public static func scanBatchGlv(
        scanKey: Data,
        spendPubkey: Data,
        labels: [UInt32],
        tweaks: [Data],
        outputsPerTx: [[Data]]
    ) throws -> [SpBatchPaymentMatch] {
        guard scanKey.count == 32, spendPubkey.count == 33 else {
            throw SilentwireError.invalidInput
        }
        guard tweaks.count == outputsPerTx.count, tweaks.count <= 4096, labels.count <= 4096 else {
            throw SilentwireError.capacityExceeded
        }

        for tw in tweaks {
            guard tw.count == 33 else { throw SilentwireError.invalidInput }
        }

        var totalOutputs = Data()
        var outputOffsets: [Int] = []
        for outList in outputsPerTx {
            outputOffsets.append(totalOutputs.count)
            for out in outList {
                guard out.count == 32 else { throw SilentwireError.invalidInput }
                totalOutputs.append(out)
            }
        }

        var matches = [SilentwireBatchMatch](repeating: SilentwireBatchMatch(), count: 4096)
        var written: size_t = 0

        let status: Int32 = scanKey.withUnsafeBytes { scanPtr in
            spendPubkey.withUnsafeBytes { spendPtr in
                labels.withUnsafeBufferPointer { labelBuf in
                    totalOutputs.withUnsafeBytes { totalOutPtr in
                        var txStructs = [SilentwireBatchTx]()
                        txStructs.reserveCapacity(tweaks.count)

                        for i in 0..<tweaks.count {
                            var tx = SilentwireBatchTx()
                            _ = tweaks[i].withUnsafeBytes { twPtr in
                                memcpy(&tx.transaction_tweak, twPtr.baseAddress!, 33)
                            }
                            tx.output_count = outputsPerTx[i].count
                            if tx.output_count > 0 {
                                tx.outputs = totalOutPtr.baseAddress!.advanced(by: outputOffsets[i]).assumingMemoryBound(to: UInt8.self)
                            } else {
                                tx.outputs = nil
                            }
                            txStructs.append(tx)
                        }

                        return txStructs.withUnsafeBufferPointer { txBuf in
                            matches.withUnsafeMutableBufferPointer { matchBuf in
                                silentwire_scan_batch_glv(
                                    scanPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                    spendPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                    labelBuf.baseAddress,
                                    labelBuf.count,
                                    txBuf.baseAddress,
                                    txBuf.count,
                                    matchBuf.baseAddress,
                                    4096,
                                    &written
                                )
                            }
                        }
                    }
                }
            }
        }

        guard status == 0 else {
            matches.withUnsafeMutableBytes { ptr in
                _ = memset_s(ptr.baseAddress!, ptr.count, 0, ptr.count)
            }
            throw SilentwireError.executionFailed(status)
        }

        var result: [SpBatchPaymentMatch] = []
        result.reserveCapacity(written)
        for i in 0..<written {
            let m = matches[i]
            let label = m.has_label != 0 ? m.label : nil
            let pubkey = withUnsafeBytes(of: m.pubkey) { Data($0) }
            let tweak = withUnsafeBytes(of: m.private_key_tweak) { Data($0) }
            result.append(SpBatchPaymentMatch(txIndex: m.tx_index, vout: m.vout, k: m.k, label: label, pubkey: pubkey, privateKeyTweak: tweak))
        }

        matches.withUnsafeMutableBytes { ptr in
            _ = memset_s(ptr.baseAddress!, ptr.count, 0, ptr.count)
        }

        return result
    }
}
