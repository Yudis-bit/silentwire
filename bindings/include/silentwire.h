#ifndef SILENTWIRE_H
#define SILENTWIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t scan_key[32];
    uint8_t spend_pubkey[33];
    uint8_t transaction_tweak[33];
    const uint32_t *labels;
    size_t label_count;
    const uint8_t *outputs;
    size_t output_count;
} SilentwireScanRequest;

typedef struct {
    uint32_t vout;
    uint32_t k;
    uint32_t label;
    uint8_t has_label;
    uint8_t reserved[3];
    uint8_t pubkey[32];
    uint8_t private_key_tweak[32];
} SilentwireMatch;

typedef struct {
    uint8_t transaction_tweak[33];
    const uint8_t *outputs;
    size_t output_count;
} SilentwireBatchTx;

typedef struct {
    uint32_t tx_index;
    uint32_t vout;
    uint32_t k;
    uint32_t label;
    uint8_t has_label;
    uint8_t reserved[3];
    uint8_t pubkey[32];
    uint8_t private_key_tweak[32];
} SilentwireBatchMatch;

#define SILENTWIRE_OK 0
#define SILENTWIRE_ERR_INVALID_PARAM 1
#define SILENTWIRE_ERR_BUFFER_TOO_SMALL 2
#define SILENTWIRE_ERR_PANIC 3

/* Scan a single pre-extracted public transaction tweak h*A.
 * Return SILENTWIRE_OK on success, SILENTWIRE_ERR_INVALID_PARAM for invalid input,
 * SILENTWIRE_ERR_BUFFER_TOO_SMALL for insufficient capacity,
 * or SILENTWIRE_ERR_PANIC for a caught panic. */
int32_t silentwire_scan(const SilentwireScanRequest *request, SilentwireMatch *matches,
                       size_t capacity, size_t *written);

/* Scan a single transaction tweak using GLV endomorphism. */
int32_t silentwire_scan_glv(const SilentwireScanRequest *request, SilentwireMatch *matches,
                           size_t capacity, size_t *written);

/* Scan a batch of transaction tweaks using rolling GLV multi-base multiplication. */
int32_t silentwire_scan_batch_glv(const uint8_t *scan_key,
                                 const uint8_t *spend_pubkey,
                                 const uint32_t *labels,
                                 size_t label_count,
                                 const SilentwireBatchTx *txs,
                                 size_t tx_count,
                                 SilentwireBatchMatch *matches,
                                 size_t capacity,
                                 size_t *written);

/* Dual-blinded constant-time scalar multiplication with fault cross-check. */
int32_t silentwire_hardened_multiply(const uint8_t *secret_scalar,
                                     const uint8_t *base_pubkey,
                                     const uint8_t *blinding_1,
                                     const uint8_t *blinding_2,
                                     uint8_t *out_pubkey);

/* Generate a 64-byte BIP-374 DLEQ proof for (secret_a, b_pubkey, aux_rand). */
int32_t silentwire_dleq_prove(const uint8_t *secret_a,
                              const uint8_t *b_pubkey,
                              const uint8_t *aux_rand,
                              uint8_t *out_proof);

#ifdef __cplusplus
}
#endif
#endif
