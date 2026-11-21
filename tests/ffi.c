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

    request.output_count = 0; request.outputs = NULL;
    assert(silentwire_scan(&request, NULL, 0, &written) == 0 && written == 0);
    request.output_count = 4097;
    assert(silentwire_scan(&request, &found, 1, &written) == 1 && written == 0);
    request.output_count = 0; memset(request.scan_key, 0, 32);
    assert(silentwire_scan(&request, &found, 1, &written) == 1);
    puts("C ABI: vector match, capacity atomicity, nulls, empty input and bounds passed");
    return 0;
}
