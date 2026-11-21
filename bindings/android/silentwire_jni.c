#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "../include/silentwire.h"

static void wipe(void *memory, size_t size) {
    volatile unsigned char *bytes = memory;
    while (size--) *bytes++ = 0;
}

static jbyteArray invalid(JNIEnv *env, const char *message) {
    jclass type = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (type) (*env)->ThrowNew(env, type, message);
    return NULL;
}

static void be32(uint8_t *destination, uint32_t value) {
    for (size_t i = 0; i < 4; i++) destination[i] = (uint8_t)(value >> (24 - 8 * i));
}

static jbyteArray scan_prepared_internal(
    JNIEnv *env, jbyteArray scan, jbyteArray spend, jbyteArray tweak,
    jbyteArray outputs, jintArray labels, int use_glv) {
    if (!scan || !spend || !tweak || !outputs || !labels) return invalid(env, "Null input");
    if ((*env)->GetArrayLength(env, scan) != 32 || (*env)->GetArrayLength(env, spend) != 33 ||
        (*env)->GetArrayLength(env, tweak) != 33) return invalid(env, "Invalid key length");
    jsize size = (*env)->GetArrayLength(env, outputs), label_count = (*env)->GetArrayLength(env, labels);
    if (size % 32 || size > 4096 * 32 || label_count > 4096) return invalid(env, "Input limit exceeded");
    uint8_t *keys = malloc(size ? (size_t)size : 1);
    jint *java_labels = malloc(label_count ? (size_t)label_count * sizeof(jint) : 1);
    uint32_t *indices = malloc(label_count ? (size_t)label_count * sizeof(uint32_t) : 1);
    SilentwireMatch *matches = calloc(4096, sizeof(SilentwireMatch));
    uint8_t *encoded = calloc(4096, 80);
    if (!keys || !java_labels || !indices || !matches || !encoded) {
        free(keys); free(java_labels); free(indices); free(matches); free(encoded);
        jclass type = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (type) (*env)->ThrowNew(env, type, "Scan buffer allocation failed");
        return NULL;
    }
    SilentwireScanRequest request = {0};
    (*env)->GetByteArrayRegion(env, scan, 0, 32, (jbyte *)request.scan_key);
    (*env)->GetByteArrayRegion(env, spend, 0, 33, (jbyte *)request.spend_pubkey);
    (*env)->GetByteArrayRegion(env, tweak, 0, 33, (jbyte *)request.transaction_tweak);
    (*env)->GetByteArrayRegion(env, outputs, 0, size, (jbyte *)keys);
    (*env)->GetIntArrayRegion(env, labels, 0, label_count, java_labels);
    jbyteArray result = NULL;
    if (!(*env)->ExceptionCheck(env)) {
        for (jsize i = 0; i < label_count; i++) indices[i] = (uint32_t)java_labels[i];
        request.outputs = keys; request.output_count = (size_t)size / 32;
        request.labels = indices; request.label_count = (size_t)label_count;
        size_t written = 0;
        int32_t status = use_glv
            ? silentwire_scan_glv(&request, matches, 4096, &written)
            : silentwire_scan(&request, matches, 4096, &written);
        if (status || written > 4096) invalid(env, "Receiver rejected request");
        else {
            for (size_t i = 0; i < written; i++) {
                uint8_t *record = encoded + i * 80;
                be32(record, matches[i].vout); be32(record + 4, matches[i].k); be32(record + 8, matches[i].label);
                record[12] = matches[i].has_label;
                memcpy(record + 16, matches[i].pubkey, 32);
                memcpy(record + 48, matches[i].private_key_tweak, 32);
            }
            result = (*env)->NewByteArray(env, (jsize)(written * 80));
            if (result) (*env)->SetByteArrayRegion(env, result, 0, (jsize)(written * 80), (jbyte *)encoded);
        }
    }
    wipe(request.scan_key, sizeof(request.scan_key));
    wipe(matches, 4096 * sizeof(SilentwireMatch)); wipe(encoded, 4096 * 80);
    free(keys); free(java_labels); free(indices); free(matches); free(encoded);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_silentwire_Silentwire_scanPrepared(
    JNIEnv *env, jclass owner, jbyteArray scan, jbyteArray spend, jbyteArray tweak,
    jbyteArray outputs, jintArray labels) {
    (void)owner;
    return scan_prepared_internal(env, scan, spend, tweak, outputs, labels, 0);
}

JNIEXPORT jbyteArray JNICALL Java_org_silentwire_Silentwire_scanPreparedGlv(
    JNIEnv *env, jclass owner, jbyteArray scan, jbyteArray spend, jbyteArray tweak,
    jbyteArray outputs, jintArray labels) {
    (void)owner;
    return scan_prepared_internal(env, scan, spend, tweak, outputs, labels, 1);
}

JNIEXPORT jbyteArray JNICALL Java_org_silentwire_Silentwire_scanBatchGlv(
    JNIEnv *env, jclass owner, jbyteArray scan, jbyteArray spend, jintArray labels,
    jbyteArray tweaks, jbyteArray outputs, jintArray output_counts) {
    (void)owner;
    if (!scan || !spend || !labels || !tweaks || !outputs || !output_counts)
        return invalid(env, "Null input");
    if ((*env)->GetArrayLength(env, scan) != 32 || (*env)->GetArrayLength(env, spend) != 33)
        return invalid(env, "Invalid key length");

    jsize tweak_bytes = (*env)->GetArrayLength(env, tweaks);
    if (tweak_bytes % 33 != 0) return invalid(env, "Invalid tweaks length");
    jsize tx_count = tweak_bytes / 33;
    if (tx_count > 4096 || (*env)->GetArrayLength(env, output_counts) != tx_count)
        return invalid(env, "Transaction count mismatch");

    jsize output_bytes = (*env)->GetArrayLength(env, outputs);
    if (output_bytes % 32 != 0 || output_bytes > 4096 * 32)
        return invalid(env, "Invalid outputs length");

    jsize label_count = (*env)->GetArrayLength(env, labels);
    if (label_count > 4096) return invalid(env, "Label limit exceeded");

    uint8_t *raw_tweaks = malloc(tweak_bytes ? (size_t)tweak_bytes : 1);
    uint8_t *raw_outputs = malloc(output_bytes ? (size_t)output_bytes : 1);
    jint *counts = malloc(tx_count ? (size_t)tx_count * sizeof(jint) : 1);
    jint *java_labels = malloc(label_count ? (size_t)label_count * sizeof(jint) : 1);
    uint32_t *indices = malloc(label_count ? (size_t)label_count * sizeof(uint32_t) : 1);
    SilentwireBatchTx *txs = calloc(tx_count ? (size_t)tx_count : 1, sizeof(SilentwireBatchTx));
    SilentwireBatchMatch *matches = calloc(4096, sizeof(SilentwireBatchMatch));
    uint8_t *encoded = calloc(4096, 84);
    uint8_t scan_key[32];
    uint8_t spend_pubkey[33];

    if (!raw_tweaks || !raw_outputs || !counts || !java_labels || !indices || !txs || !matches || !encoded) {
        free(raw_tweaks); free(raw_outputs); free(counts); free(java_labels);
        free(indices); free(txs); free(matches); free(encoded);
        jclass type = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (type) (*env)->ThrowNew(env, type, "Batch allocation failed");
        return NULL;
    }

    (*env)->GetByteArrayRegion(env, scan, 0, 32, (jbyte *)scan_key);
    (*env)->GetByteArrayRegion(env, spend, 0, 33, (jbyte *)spend_pubkey);
    (*env)->GetByteArrayRegion(env, tweaks, 0, tweak_bytes, (jbyte *)raw_tweaks);
    (*env)->GetByteArrayRegion(env, outputs, 0, output_bytes, (jbyte *)raw_outputs);
    (*env)->GetIntArrayRegion(env, output_counts, 0, tx_count, counts);
    (*env)->GetIntArrayRegion(env, labels, 0, label_count, java_labels);

    jbyteArray result = NULL;
    if (!(*env)->ExceptionCheck(env)) {
        for (jsize i = 0; i < label_count; i++) indices[i] = (uint32_t)java_labels[i];

        size_t output_offset = 0;
        size_t total_outputs = (size_t)output_bytes / 32;
        int counts_valid = 1;

        for (jsize i = 0; i < tx_count; i++) {
            if (counts[i] < 0) { counts_valid = 0; break; }
            size_t c = (size_t)counts[i];
            if (output_offset + c > total_outputs) { counts_valid = 0; break; }
            memcpy(txs[i].transaction_tweak, raw_tweaks + (size_t)i * 33, 33);
            txs[i].outputs = raw_outputs + output_offset * 32;
            txs[i].output_count = c;
            output_offset += c;
        }

        if (!counts_valid || output_offset != total_outputs) {
            invalid(env, "Output counts do not sum to total outputs");
        } else {
            size_t written = 0;
            int32_t status = silentwire_scan_batch_glv(
                scan_key, spend_pubkey, indices, (size_t)label_count,
                txs, (size_t)tx_count, matches, 4096, &written
            );
            if (status || written > 4096) {
                invalid(env, "Batch receiver rejected request");
            } else {
                for (size_t i = 0; i < written; i++) {
                    uint8_t *record = encoded + i * 84;
                    be32(record, matches[i].tx_index);
                    be32(record + 4, matches[i].vout);
                    be32(record + 8, matches[i].k);
                    be32(record + 12, matches[i].label);
                    record[16] = matches[i].has_label;
                    record[17] = 0; record[18] = 0; record[19] = 0;
                    memcpy(record + 20, matches[i].pubkey, 32);
                    memcpy(record + 52, matches[i].private_key_tweak, 32);
                }
                result = (*env)->NewByteArray(env, (jsize)(written * 84));
                if (result) (*env)->SetByteArrayRegion(env, result, 0, (jsize)(written * 84), (jbyte *)encoded);
            }
        }
    }

    wipe(scan_key, sizeof(scan_key));
    wipe(matches, 4096 * sizeof(SilentwireBatchMatch));
    wipe(encoded, 4096 * 84);
    free(raw_tweaks); free(raw_outputs); free(counts); free(java_labels);
    free(indices); free(txs); free(matches); free(encoded);
    return result;
}
