#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "../bindings/include/silentwire.h"
#include "ffi_fixture.h"

int main(int argc, char **argv) {
    /* Optional negative control proving Valgrind taint detection is active
     * (must exit with --error-exitcode=42 when executed under Valgrind). */
    if (argc > 1 && strcmp(argv[1], "--negative-control") == 0) {
        volatile uint8_t secret_byte = 1;
        VALGRIND_MAKE_MEM_UNDEFINED(&secret_byte, sizeof(secret_byte));
        if (secret_byte == 1) {
            return 0;
        }
        return 1;
    }

    SilentwireScanRequest request = {0};
    memcpy(request.scan_key, scan, 32);
    memcpy(request.spend_pubkey, spend, 33);
    memcpy(request.transaction_tweak, tweak, 33);
    request.outputs = output;
    request.output_count = 1;
    SilentwireMatch match;
    size_t written = 0;

    /* Single-tx scan (0 labels, Mode A Jacobian x-match). */
    VALGRIND_MAKE_MEM_UNDEFINED(request.scan_key, sizeof(request.scan_key));
    int32_t result1 = silentwire_scan(&request, &match, 1, &written);
    VALGRIND_MAKE_MEM_DEFINED(request.scan_key, sizeof(request.scan_key));
    VALGRIND_MAKE_MEM_DEFINED(&result1, sizeof(result1));
    VALGRIND_MAKE_MEM_DEFINED(&written, sizeof(written));
    VALGRIND_MAKE_MEM_DEFINED(&match, sizeof(match));
    if (result1 != 0 || written != 1) return 1;

    /* Single-tx GLV scan with 2 labels (Mode A, L <= 8). */
    uint32_t labels_small[2] = {0, 1};
    request.labels = labels_small;
    request.label_count = 2;
    written = 0;
    VALGRIND_MAKE_MEM_UNDEFINED(request.scan_key, sizeof(request.scan_key));
    int32_t result2 = silentwire_scan_glv(&request, &match, 1, &written);
    VALGRIND_MAKE_MEM_DEFINED(request.scan_key, sizeof(request.scan_key));
    VALGRIND_MAKE_MEM_DEFINED(&result2, sizeof(result2));
    VALGRIND_MAKE_MEM_DEFINED(&written, sizeof(written));
    VALGRIND_MAKE_MEM_DEFINED(&match, sizeof(match));
    if (result2 != 0 || written != 1) return 2;

    /* Single-tx GLV scan with 12 labels (Mode B subtractive O(1), L > 8). */
    uint32_t labels_large[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    request.labels = labels_large;
    request.label_count = 12;
    written = 0;
    VALGRIND_MAKE_MEM_UNDEFINED(request.scan_key, sizeof(request.scan_key));
    int32_t result3 = silentwire_scan_glv(&request, &match, 1, &written);
    VALGRIND_MAKE_MEM_DEFINED(request.scan_key, sizeof(request.scan_key));
    VALGRIND_MAKE_MEM_DEFINED(&result3, sizeof(result3));
    VALGRIND_MAKE_MEM_DEFINED(&written, sizeof(written));
    VALGRIND_MAKE_MEM_DEFINED(&match, sizeof(match));
    if (result3 != 0 || written != 1) return 3;

    /* Batched 16-tx GLV scan across fused Montgomery normalization. */
    SilentwireBatchTx batch_txs[16];
    for (size_t i = 0; i < 16; i++) {
        memcpy(batch_txs[i].transaction_tweak, tweak, 33);
        batch_txs[i].outputs = output;
        batch_txs[i].output_count = 1;
    }
    SilentwireBatchMatch batch_matches[16];
    uint8_t scan_copy[32];
    memcpy(scan_copy, scan, 32);
    written = 0;
    VALGRIND_MAKE_MEM_UNDEFINED(scan_copy, sizeof(scan_copy));
    int32_t result4 = silentwire_scan_batch_glv(
        scan_copy, spend, labels_small, 2, batch_txs, 16, batch_matches, 16, &written);
    VALGRIND_MAKE_MEM_DEFINED(scan_copy, sizeof(scan_copy));
    VALGRIND_MAKE_MEM_DEFINED(&result4, sizeof(result4));
    VALGRIND_MAKE_MEM_DEFINED(&written, sizeof(written));
    VALGRIND_MAKE_MEM_DEFINED(batch_matches, sizeof(batch_matches));
    if (result4 != 0 || written != 16) return 4;

    /* Dual-blinded HardenedMultiplier scalar multiplication. */
    uint8_t blind1[32] = {0};
    uint8_t blind2[32] = {0};
    blind1[31] = 0x37;
    blind2[31] = 0x91;
    uint8_t out_pub[33] = {0};
    memcpy(scan_copy, scan, 32);
    VALGRIND_MAKE_MEM_UNDEFINED(scan_copy, sizeof(scan_copy));
    int32_t result5 = silentwire_hardened_multiply(scan_copy, tweak, blind1, blind2, out_pub);
    VALGRIND_MAKE_MEM_DEFINED(scan_copy, sizeof(scan_copy));
    VALGRIND_MAKE_MEM_DEFINED(&result5, sizeof(result5));
    VALGRIND_MAKE_MEM_DEFINED(out_pub, sizeof(out_pub));
    if (result5 != 0 || (out_pub[0] != 2 && out_pub[0] != 3)) return 5;

    /* BIP-374 DLEQ prove with tainted secret scalar. */
    uint8_t aux_rand[32];
    memset(aux_rand, 0x5a, sizeof(aux_rand));
    uint8_t proof[64] = {0};
    memcpy(scan_copy, scan, 32);
    VALGRIND_MAKE_MEM_UNDEFINED(scan_copy, sizeof(scan_copy));
    int32_t result6 = silentwire_dleq_prove(scan_copy, tweak, aux_rand, proof);
    VALGRIND_MAKE_MEM_DEFINED(scan_copy, sizeof(scan_copy));
    VALGRIND_MAKE_MEM_DEFINED(&result6, sizeof(result6));
    VALGRIND_MAKE_MEM_DEFINED(proof, sizeof(proof));
    if (result6 != 0) return 6;

    return 0;
}
