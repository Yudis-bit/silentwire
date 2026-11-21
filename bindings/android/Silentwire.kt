package org.silentwire

import java.nio.ByteBuffer
import java.nio.ByteOrder

object Silentwire {
    init { System.loadLibrary("silentwire_jni") }

    @JvmStatic external fun scanPrepared(
        scanKey: ByteArray,
        spendPubkey: ByteArray,
        transactionTweak: ByteArray,
        outputs: ByteArray,
        labels: IntArray
    ): ByteArray

    @JvmStatic external fun scanPreparedGlv(
        scanKey: ByteArray,
        spendPubkey: ByteArray,
        transactionTweak: ByteArray,
        outputs: ByteArray,
        labels: IntArray
    ): ByteArray

    @JvmStatic external fun scanBatchGlv(
        scanKey: ByteArray,
        spendPubkey: ByteArray,
        labels: IntArray,
        tweaks: ByteArray,
        outputs: ByteArray,
        outputCounts: IntArray
    ): ByteArray

    data class Match(
        val vout: Long,
        val k: Long,
        val label: Long?,
        val pubkey: ByteArray,
        val privateKeyTweak: ByteArray
    )

    data class BatchMatch(
        val txIndex: Long,
        val vout: Long,
        val k: Long,
        val label: Long?,
        val pubkey: ByteArray,
        val privateKeyTweak: ByteArray
    )

    fun decodeMatches(encoded: ByteArray): List<Match> {
        require(encoded.size % 80 == 0)
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        return List(encoded.size / 80) {
            val vout = buffer.int.toLong() and 0xffffffffL
            val k = buffer.int.toLong() and 0xffffffffL
            val label = buffer.int.toLong() and 0xffffffffL
            val hasLabel = buffer.get().toInt() != 0
            buffer.position(buffer.position() + 3)
            val pubkey = ByteArray(32).also { buffer.get(it) }
            val tweak = ByteArray(32).also { buffer.get(it) }
            Match(vout, k, if (hasLabel) label else null, pubkey, tweak)
        }
    }

    fun decodeBatchMatches(encoded: ByteArray): List<BatchMatch> {
        require(encoded.size % 84 == 0)
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        return List(encoded.size / 84) {
            val txIndex = buffer.int.toLong() and 0xffffffffL
            val vout = buffer.int.toLong() and 0xffffffffL
            val k = buffer.int.toLong() and 0xffffffffL
            val label = buffer.int.toLong() and 0xffffffffL
            val hasLabel = buffer.get().toInt() != 0
            buffer.position(buffer.position() + 3)
            val pubkey = ByteArray(32).also { buffer.get(it) }
            val tweak = ByteArray(32).also { buffer.get(it) }
            BatchMatch(txIndex, vout, k, if (hasLabel) label else null, pubkey, tweak)
        }
    }
}
