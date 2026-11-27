#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../bindings/include/silentwire.h"
#include "ffi_fixture.h"

_Static_assert(sizeof(SilentwireMatch) == 80, "SilentwireMatch ABI size");
_Static_assert(offsetof(SilentwireMatch, pubkey) == 16, "SilentwireMatch pubkey offset");
_Static_assert(offsetof(SilentwireMatch, private_key_tweak) == 48, "SilentwireMatch tweak offset");
_Static_assert(sizeof(SilentwireBatchMatch) == 84, "SilentwireBatchMatch ABI size");
_Static_assert(offsetof(SilentwireBatchMatch, pubkey) == 20, "SilentwireBatchMatch pubkey offset");
_Static_assert(offsetof(SilentwireBatchMatch, private_key_tweak) == 52, "SilentwireBatchMatch tweak offset");
_Static_assert(sizeof(SilentwireBatchTx) == 56, "SilentwireBatchTx ABI size");

int main(void) {
    size_t written = 99;
    assert(silentwire_scan(NULL, NULL, 0, &written) == 1 && written == 0);
    SilentwireScanRequest request = {0};
    memcpy(request.scan_key, scan, 32); memcpy(request.spend_pubkey, spend, 33);
    memcpy(request.transaction_tweak, tweak, 33);
    request.outputs = output; request.output_count = 1;
    assert(silentwire_scan(&request, NULL, 0, &written) == 2 && written == 1);
    SilentwireMatch found;
    memset(&found, 0xa5, sizeof(found));
    assert(silentwire_scan(&request, &found, 0, &written) == 2);
    for (size_t i = 0; i < sizeof(found); i++) assert(((uint8_t *)&found)[i] == 0xa5);
    assert(silentwire_scan(&request, &found, 1, &written) == 0 && written == 1);
    assert(found.vout == 0 && found.k == 0 && !found.has_label);
    assert(memcmp(found.pubkey, output, 32) == 0);
    assert(memcmp(found.private_key_tweak, expected_tweak, 32) == 0);

    /* GLV single transaction parity check */
    SilentwireMatch found_glv;
    memset(&found_glv, 0, sizeof(found_glv));
    written = 99;
    assert(silentwire_scan_glv(&request, &found_glv, 1, &written) == 0 && written == 1);
    assert(found_glv.vout == 0 && found_glv.k == 0 && !found_glv.has_label);
    assert(memcmp(found_glv.pubkey, output, 32) == 0);
    assert(memcmp(found_glv.private_key_tweak, expected_tweak, 32) == 0);

    /* GLV batch transaction scan check */
    SilentwireBatchTx btx = {0};
    memcpy(btx.transaction_tweak, tweak, 33);
    btx.outputs = output;
    btx.output_count = 1;
    SilentwireBatchMatch bmatch;
    memset(&bmatch, 0, sizeof(bmatch));
    written = 99;
    assert(silentwire_scan_batch_glv(scan, spend, NULL, 0, &btx, 1, NULL, 0, &written) == 2 && written == 1);
    assert(silentwire_scan_batch_glv(scan, spend, NULL, 0, &btx, 1, &bmatch, 1, &written) == 0 && written == 1);
    assert(bmatch.tx_index == 0 && bmatch.vout == 0 && bmatch.k == 0 && !bmatch.has_label);
    assert(memcmp(bmatch.pubkey, output, 32) == 0);
    assert(memcmp(bmatch.private_key_tweak, expected_tweak, 32) == 0);
    assert(silentwire_scan_batch_glv(scan, spend, NULL, 0, NULL, 0, NULL, 0, &written) == 0 && written == 0);
    assert(silentwire_scan_batch_glv(NULL, spend, NULL, 0, &btx, 1, &bmatch, 1, &written) == 1 && written == 0);
    uint8_t zero_key[32] = {0};
    assert(silentwire_scan_batch_glv(zero_key, spend, NULL, 0, NULL, 0, NULL, 0, &written) == 1 && written == 0);

    /* Official BIP-374 v0.3.1 vector #5 (standard G, no message) over C ABI */
    static const uint8_t bip374_a[32] = {
        0xc0,0x8c,0xa8,0xe0,0xbb,0x59,0x76,0x9f,0xc6,0xa4,0xe0,0x78,0x45,0x62,0x84,0xe0,
        0x0e,0xa3,0x4f,0x65,0xad,0xd9,0x88,0xc2,0x46,0xe1,0xbb,0xa8,0x58,0x24,0xcc,0xdc
    };
    static const uint8_t bip374_b[33] = {
        0x03,0x4b,0xcc,0xb1,0xc5,0x70,0xac,0x1f,0x3b,0xc4,0x2d,0x61,0xfe,0x35,0xde,0x60,
        0x5b,0x99,0x62,0x65,0x01,0xcc,0xb2,0x02,0x97,0xe1,0xac,0xbb,0xf2,0xd7,0x15,0x2a,0xa1
    };
    static const uint8_t bip374_r[32] = {
        0xc8,0xd7,0x05,0x6a,0xbd,0x47,0x26,0xeb,0x5a,0x0f,0x19,0x87,0x40,0xaf,0x14,0xd6,
        0xc1,0xf0,0xc1,0x6e,0x5d,0x7a,0x37,0xea,0xec,0x62,0x1b,0x66,0x1e,0x66,0x9a,0xc4
    };
    static const uint8_t bip374_expected[64] = {
        0x50,0x35,0x62,0xd3,0x69,0x10,0xcd,0x2d,0x61,0xa4,0xd0,0x7c,0x8f,0xf6,0x80,0x26,
        0x5c,0x71,0x3e,0x63,0xdd,0xe0,0xdc,0xb8,0x8e,0x6e,0xa3,0xc5,0x85,0x97,0xbd,0xc0,
        0x5b,0x86,0xdb,0x9a,0xf9,0x5e,0xcc,0xc4,0x75,0xce,0x21,0x77,0xf9,0x41,0xc1,0x18,
        0xfe,0xfe,0xd2,0x02,0x27,0xd4,0xce,0x8c,0xe9,0x55,0x7c,0xb0,0x08,0x75,0x8d,0xe6
    };
    uint8_t dleq_out[64] = {0};
    assert(silentwire_dleq_prove(bip374_a, bip374_b, bip374_r, dleq_out) == 0);
    assert(memcmp(dleq_out, bip374_expected, 64) == 0);

    request.output_count = 0; request.outputs = NULL;
    assert(silentwire_scan(&request, NULL, 0, &written) == 0 && written == 0);
    request.output_count = 4097;
    assert(silentwire_scan(&request, &found, 1, &written) == 1 && written == 0);
    request.output_count = 0; memset(request.scan_key, 0, 32);
    assert(silentwire_scan(&request, &found, 1, &written) == 1);
    puts("C ABI: vector match, capacity atomicity, nulls, empty input and bounds passed");
    return 0;
}
