/* Head-to-head differential parity and throughput harness comparing
 * silentwire (silentwire_scan_batch_glv) against libsecp256k1
 * (secp256k1_silentpayments_recipient_scan_outputs) on identical BIP-352
 * transactions with optional m=0 change label.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_silentpayments.h"
#include "silentwire.h"

typedef struct {
    unsigned char label33[33];
    unsigned char tweak32[32];
} ChangeLabelCtx;

static const unsigned char *lookup_change_label(const unsigned char *label33, const void *ctx) {
    const ChangeLabelCtx *c = (const ChangeLabelCtx *)ctx;
    if (memcmp(label33, c->label33, 33) == 0) {
        return c->tweak32;
    }
    return NULL;
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Minimal SHA-256 for digesting matched payment streams without external deps. */
static const uint32_t SHA_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

typedef struct {
    uint32_t s[8];
    uint8_t buf[64];
    size_t len;
    uint64_t total;
} Sha256Ctx;

static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static void sha256_block(uint32_t s[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[4*i] << 24) | ((uint32_t)blk[4*i+1] << 16) |
               ((uint32_t)blk[4*i+2] << 8) | (uint32_t)blk[4*i+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=s[0], b=s[1], c=s[2], d=s[3], e=s[4], f=s[5], g=s[6], h=s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

static void sha256_init(Sha256Ctx *ctx) {
    static const uint32_t IV[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    memcpy(ctx->s, IV, sizeof(IV));
    ctx->len = 0;
    ctx->total = 0;
}

static void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t n) {
    ctx->total += n;
    while (n > 0) {
        size_t take = 64 - ctx->len;
        if (take > n) take = n;
        memcpy(ctx->buf + ctx->len, data, take);
        ctx->len += take;
        data += take;
        n -= take;
        if (ctx->len == 64) {
            sha256_block(ctx->s, ctx->buf);
            ctx->len = 0;
        }
    }
}

static void sha256_final(Sha256Ctx *ctx, uint8_t out[32]) {
    uint64_t bits = ctx->total * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->len != 56) sha256_update(ctx, &zero, 1);
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) len_be[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(ctx, len_be, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (uint8_t)(ctx->s[i] >> 24);
        out[4*i+1] = (uint8_t)(ctx->s[i] >> 16);
        out[4*i+2] = (uint8_t)(ctx->s[i] >> 8);
        out[4*i+3] = (uint8_t)(ctx->s[i]);
    }
}

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i] = H[b[i] >> 4];
        out[2*i+1] = H[b[i] & 0xf];
    }
    out[2*n] = '\0';
}

static void tagged_hash_inputs(const uint8_t outpoint36[36], const uint8_t agg33[33], uint8_t out32[32]) {
    const char *tag = "BIP0352/Inputs";
    uint8_t th[32];
    Sha256Ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)tag, strlen(tag));
    sha256_final(&c, th);
    sha256_init(&c);
    sha256_update(&c, th, 32);
    sha256_update(&c, th, 32);
    sha256_update(&c, outpoint36, 36);
    sha256_update(&c, agg33, 33);
    sha256_final(&c, out32);
}

int main(int argc, char **argv) {
    size_t tx_count = 1000;
    const char *secp_commit = "0000000000000000000000000000000000000000";
    const char *cpu_affinity = "unpinned";
    int use_change_label = 1;
    int json_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--txs") == 0 && i + 1 < argc) {
            tx_count = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--secp-commit") == 0 && i + 1 < argc) {
            secp_commit = argv[++i];
        } else if (strcmp(argv[i], "--cpu-affinity") == 0 && i + 1 < argc) {
            cpu_affinity = argv[++i];
        } else if (strcmp(argv[i], "--no-label") == 0) {
            use_change_label = 0;
        } else if (strcmp(argv[i], "--json") == 0) {
            json_mode = 1;
        }
    }
    if (tx_count == 0 || tx_count > 4096) {
        fprintf(stderr, "tx_count must be in [1, 4096]\n");
        return 1;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) return 1;

    uint8_t scan_priv[32], spend_priv[32];
    memset(scan_priv, 0x42, 32);
    memset(spend_priv, 0x69, 32);

    secp256k1_pubkey scan_pub, spend_pub, change_spend_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &scan_pub, scan_priv)) return 1;
    if (!secp256k1_ec_pubkey_create(ctx, &spend_pub, spend_priv)) return 1;

    uint8_t spend_pub33[33];
    size_t slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, spend_pub33, &slen, &spend_pub, SECP256K1_EC_COMPRESSED)) return 1;

    secp256k1_silentpayments_label change_label;
    ChangeLabelCtx label_ctx;
    if (!secp256k1_silentpayments_recipient_label_create(ctx, &change_label, label_ctx.tweak32, scan_priv, 0)) return 1;
    if (!secp256k1_silentpayments_recipient_label_serialize(ctx, label_ctx.label33, &change_label)) return 1;
    if (!secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(ctx, &change_spend_pub, &spend_pub, &change_label)) return 1;

    secp256k1_silentpayments_prevouts_summary *summaries = calloc(tx_count, sizeof(*summaries));
    SilentwireBatchTx *sw_txs = calloc(tx_count, sizeof(*sw_txs));
    uint8_t (*outputs_raw)[3][32] = calloc(tx_count, sizeof(*outputs_raw));
    secp256k1_xonly_pubkey (*secp_outs)[3] = calloc(tx_count, sizeof(*secp_outs));
    size_t *out_counts = calloc(tx_count, sizeof(*out_counts));
    if (!summaries || !sw_txs || !outputs_raw || !secp_outs || !out_counts) return 1;

    /* Plant 3 matching transactions across the block: unlabeled, change m=0, and multi-output. */
    size_t hit1 = tx_count / 4;
    size_t hit2 = tx_count / 2;
    size_t hit3 = (tx_count * 3) / 4;

    /* Valid decoy x-only keys derived from real curve points so libsecp256k1 parses them. */
    secp256k1_xonly_pubkey decoy_x[4];
    uint8_t decoy_bytes[4][32];
    for (int d = 0; d < 4; d++) {
        uint8_t sk[32] = {0};
        sk[31] = (uint8_t)(10 + d);
        secp256k1_pubkey p;
        if (!secp256k1_ec_pubkey_create(ctx, &p, sk)) return 1;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &decoy_x[d], NULL, &p)) return 1;
        if (!secp256k1_xonly_pubkey_serialize(ctx, decoy_bytes[d], &decoy_x[d])) return 1;
    }

    size_t total_outputs = 0;
    for (size_t t = 0; t < tx_count; t++) {
        uint8_t in_sk[32] = {0};
        uint64_t val = (uint64_t)(t + 1) * 424242ULL + 7ULL;
        for (int b = 0; b < 8; b++) in_sk[31 - b] = (uint8_t)(val >> (8 * b));
        secp256k1_pubkey in_pk;
        if (!secp256k1_ec_pubkey_create(ctx, &in_pk, in_sk)) return 1;
        uint8_t in_pk33[33];
        size_t l33 = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, in_pk33, &l33, &in_pk, SECP256K1_EC_COMPRESSED)) return 1;

        uint8_t outpoint[36] = {0};
        outpoint[0] = (uint8_t)(t & 0xff);
        outpoint[1] = (uint8_t)((t >> 8) & 0xff);
        outpoint[2] = (uint8_t)((t >> 16) & 0xff);
        outpoint[3] = (uint8_t)((t >> 24) & 0xff);

        const secp256k1_pubkey *pks[1] = { &in_pk };
        if (!secp256k1_silentpayments_recipient_prevouts_summary_create(
                ctx, &summaries[t], outpoint, NULL, 0, pks, 1)) return 1;

        /* Precompute T = input_hash * A_sum for Silentwire batch scanner. */
        uint8_t input_hash[32];
        tagged_hash_inputs(outpoint, in_pk33, input_hash);
        secp256k1_pubkey tweak_pk = in_pk;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tweak_pk, input_hash)) return 1;
        l33 = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, sw_txs[t].transaction_tweak, &l33, &tweak_pk, SECP256K1_EC_COMPRESSED)) return 1;

        const unsigned char *sk_ptrs[1] = { in_sk };
        if (t == hit1) {
            secp256k1_silentpayments_recipient r = { scan_pub, spend_pub, 0 };
            const secp256k1_silentpayments_recipient *r_ptrs[1] = { &r };
            secp256k1_xonly_pubkey gen;
            secp256k1_xonly_pubkey *gen_ptrs[1] = { &gen };
            if (!secp256k1_silentpayments_sender_create_outputs(ctx, gen_ptrs, r_ptrs, 1, outpoint, NULL, 0, sk_ptrs, 1)) return 1;
            secp_outs[t][0] = decoy_x[0];
            memcpy(outputs_raw[t][0], decoy_bytes[0], 32);
            secp_outs[t][1] = gen;
            secp256k1_xonly_pubkey_serialize(ctx, outputs_raw[t][1], &gen);
            out_counts[t] = 2;
        } else if (t == hit2 && use_change_label) {
            secp256k1_silentpayments_recipient r = { scan_pub, change_spend_pub, 0 };
            const secp256k1_silentpayments_recipient *r_ptrs[1] = { &r };
            secp256k1_xonly_pubkey gen;
            secp256k1_xonly_pubkey *gen_ptrs[1] = { &gen };
            if (!secp256k1_silentpayments_sender_create_outputs(ctx, gen_ptrs, r_ptrs, 1, outpoint, NULL, 0, sk_ptrs, 1)) return 1;
            secp_outs[t][0] = gen;
            secp256k1_xonly_pubkey_serialize(ctx, outputs_raw[t][0], &gen);
            secp_outs[t][1] = decoy_x[1];
            memcpy(outputs_raw[t][1], decoy_bytes[1], 32);
            out_counts[t] = 2;
        } else if (t == hit3) {
            secp256k1_silentpayments_recipient r0 = { scan_pub, spend_pub, 0 };
            secp256k1_silentpayments_recipient r1 = { scan_pub, use_change_label ? change_spend_pub : spend_pub, 1 };
            const secp256k1_silentpayments_recipient *r_ptrs[2] = { &r0, &r1 };
            secp256k1_xonly_pubkey gen[2];
            secp256k1_xonly_pubkey *gen_ptrs[2] = { &gen[0], &gen[1] };
            if (!secp256k1_silentpayments_sender_create_outputs(ctx, gen_ptrs, r_ptrs, 2, outpoint, NULL, 0, sk_ptrs, 1)) return 1;
            secp_outs[t][0] = gen[1];
            secp256k1_xonly_pubkey_serialize(ctx, outputs_raw[t][0], &gen[1]);
            secp_outs[t][1] = decoy_x[2];
            memcpy(outputs_raw[t][1], decoy_bytes[2], 32);
            secp_outs[t][2] = gen[0];
            secp256k1_xonly_pubkey_serialize(ctx, outputs_raw[t][2], &gen[0]);
            out_counts[t] = 3;
        } else {
            size_t cnt = (t % 2 == 0) ? 2 : 3;
            for (size_t o = 0; o < cnt; o++) {
                size_t di = (t + o) & 3;
                secp_outs[t][o] = decoy_x[di];
                memcpy(outputs_raw[t][o], decoy_bytes[di], 32);
            }
            out_counts[t] = cnt;
        }
        sw_txs[t].outputs = (const uint8_t *)outputs_raw[t];
        sw_txs[t].output_count = out_counts[t];
        total_outputs += out_counts[t];
    }

    /* Warmup + Timed libsecp256k1 scan */
    secp256k1_silentpayments_found_output found_storage[3];
    secp256k1_silentpayments_found_output *found_ptrs[3] = { &found_storage[0], &found_storage[1], &found_storage[2] };
    const secp256k1_xonly_pubkey *out_ptrs[3];
    Sha256Ctx secp_digest_ctx;
    sha256_init(&secp_digest_ctx);
    size_t secp_total_matches = 0;

    double t0_secp = now_sec();
    for (size_t t = 0; t < tx_count; t++) {
        for (size_t o = 0; o < out_counts[t]; o++) out_ptrs[o] = &secp_outs[t][o];
        uint32_t n_found = 0;
        if (!secp256k1_silentpayments_recipient_scan_outputs(
                ctx, found_ptrs, &n_found, out_ptrs, out_counts[t],
                scan_priv, &summaries[t], &spend_pub,
                use_change_label ? lookup_change_label : NULL,
                use_change_label ? (const void *)&label_ctx : NULL)) {
            fprintf(stderr, "secp256k1 scan failed at tx %zu\n", t);
            return 2;
        }
        for (uint32_t m = 0; m < n_found; m++) {
            uint8_t rec[4 + 32 + 32];
            uint32_t tx_be = (uint32_t)t;
            rec[0] = (uint8_t)(tx_be >> 24);
            rec[1] = (uint8_t)(tx_be >> 16);
            rec[2] = (uint8_t)(tx_be >> 8);
            rec[3] = (uint8_t)(tx_be);
            secp256k1_xonly_pubkey_serialize(ctx, rec + 4, &found_storage[m].output);
            memcpy(rec + 36, found_storage[m].tweak, 32);
            sha256_update(&secp_digest_ctx, rec, sizeof(rec));
            secp_total_matches++;
        }
    }
    double secp_sec = now_sec() - t0_secp;
    uint8_t secp_digest[32];
    sha256_final(&secp_digest_ctx, secp_digest);

    /* Timed silentwire_scan_batch_glv */
    uint32_t labels[1] = { 0 };
    SilentwireBatchMatch *sw_matches = calloc(tx_count * 3, sizeof(*sw_matches));
    if (!sw_matches) return 1;
    size_t sw_written = 0;

    double t0_sw = now_sec();
    int32_t rc = silentwire_scan_batch_glv(
        scan_priv, spend_pub33,
        use_change_label ? labels : NULL,
        use_change_label ? 1 : 0,
        sw_txs, tx_count, sw_matches, tx_count * 3, &sw_written);
    double sw_sec = now_sec() - t0_sw;
    if (rc != SILENTWIRE_OK) {
        fprintf(stderr, "silentwire_scan_batch_glv failed: rc=%d\n", rc);
        return 3;
    }

    Sha256Ctx sw_digest_ctx;
    sha256_init(&sw_digest_ctx);
    for (size_t i = 0; i < sw_written; i++) {
        uint8_t rec[4 + 32 + 32];
        uint32_t tx_be = sw_matches[i].tx_index;
        rec[0] = (uint8_t)(tx_be >> 24);
        rec[1] = (uint8_t)(tx_be >> 16);
        rec[2] = (uint8_t)(tx_be >> 8);
        rec[3] = (uint8_t)(tx_be);
        memcpy(rec + 4, sw_matches[i].pubkey, 32);
        memcpy(rec + 36, sw_matches[i].private_key_tweak, 32);
        sha256_update(&sw_digest_ctx, rec, sizeof(rec));
    }
    uint8_t sw_digest[32];
    sha256_final(&sw_digest_ctx, sw_digest);

    int identical = (sw_written == secp_total_matches) && (memcmp(sw_digest, secp_digest, 32) == 0);
    char sw_hex[65], secp_hex[65];
    to_hex(sw_digest, 32, sw_hex);
    to_hex(secp_digest, 32, secp_hex);

    double sw_us_per_tx = (sw_sec * 1e6) / (double)tx_count;
    double secp_us_per_tx = (secp_sec * 1e6) / (double)tx_count;

    if (json_mode) {
        printf("{\"cases\":%zu,\"nativeDigest\":\"%s\",\"secp256k1Digest\":\"%s\",\"identical\":%s,\"silentwireUsPerTx\":%.3f,\"secp256k1UsPerTx\":%.3f,\"secp256k1Commit\":\"%s\",\"cpuAffinity\":\"%s\"}\n",
               tx_count, sw_hex, secp_hex, identical ? "true" : "false",
               sw_us_per_tx, secp_us_per_tx, secp_commit, cpu_affinity);
    } else {
        printf("head_to_head,txs=%zu,outputs=%zu,change_label=%d,matches=%zu,identical=%s\n",
               tx_count, total_outputs, use_change_label, sw_written, identical ? "PASS" : "FAIL");
        printf("libsecp256k1,commit=%s,total_ms=%.3f,us_per_tx=%.2f,outs_per_sec=%.1f,digest=%s\n",
               secp_commit, secp_sec * 1000.0, secp_us_per_tx, (double)total_outputs / secp_sec, secp_hex);
        printf("silentwire_batch_glv,total_ms=%.3f,us_per_tx=%.2f,outs_per_sec=%.1f,digest=%s\n",
               sw_sec * 1000.0, sw_us_per_tx, (double)total_outputs / sw_sec, sw_hex);
        printf("ratio,secp256k1_over_silentwire=%.2fx\n", secp_us_per_tx / sw_us_per_tx);
    }

    free(sw_matches);
    free(out_counts);
    free(secp_outs);
    free(outputs_raw);
    free(sw_txs);
    free(summaries);
    secp256k1_context_destroy(ctx);
    return identical ? 0 : 4;
}
