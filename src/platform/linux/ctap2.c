// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "ctap2.h"
#include "crypto/crypto.h"
#include "common/util.h"
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <stdio.h>
#include <string.h>

#define CMD_MAKE_CREDENTIAL 0x01
#define CMD_GET_ASSERTION 0x02
#define CMD_GET_INFO 0x04
#define CMD_CLIENT_PIN 0x06

#define PIN_GET_RETRIES 0x01
#define PIN_GET_KEY_AGREEMENT 0x02
#define PIN_GET_TOKEN 0x05
#define PIN_GET_TOKEN_PERMS 0x09
#define PERM_MC 0x01
#define PERM_GA 0x02

#define ST_OPERATION_DENIED 0x27
#define ST_KEEPALIVE_CANCEL 0x2d
#define ST_NO_CREDENTIALS 0x2e
#define ST_USER_ACTION_TIMEOUT 0x2f
#define ST_PIN_INVALID 0x31
#define ST_PIN_BLOCKED 0x32
#define ST_PIN_AUTH_INVALID 0x33
#define ST_PIN_AUTH_BLOCKED 0x34
#define ST_PIN_NOT_SET 0x35
#define ST_PUAT_REQUIRED 0x36
#define ST_PIN_POLICY_VIOLATION 0x37
#define ST_UV_BLOCKED 0x3c

#define FLAG_AT 0x40   // authData has attested credential data
#define FLAG_ED 0x80   // and extensions

// The keys of CTAP's maps (CTAP 2.1, section 6): makeCredential's, getAssertion's and clientPIN's
// parameters, what those answer with, hmac-secret's input, and getInfo's answer.
enum { MC_CLIENT_DATA_HASH = 1, MC_RP = 2, MC_USER = 3, MC_PUB_KEY_PARAMS = 4, MC_EXTENSIONS = 6, MC_PIN_AUTH = 8,
       MC_PIN_PROTOCOL = 9 };
enum { GA_RP_ID = 1, GA_CLIENT_DATA_HASH = 2, GA_ALLOW_LIST = 3, GA_EXTENSIONS = 4, GA_OPTIONS = 5, GA_PIN_AUTH = 6,
       GA_PIN_PROTOCOL = 7 };
enum { CP_PROTOCOL = 1, CP_SUBCOMMAND = 2, CP_KEY_AGREEMENT = 3, CP_PIN_HASH_ENC = 6, CP_PERMISSIONS = 9, CP_RP_ID = 10 };
enum { CP_OUT_KEY_AGREEMENT = 1, CP_OUT_TOKEN = 2, CP_OUT_RETRIES = 3 };
enum { OUT_CREDENTIAL = 1, OUT_AUTH_DATA = 2 };
enum { HS_KEY_AGREEMENT = 1, HS_SALT_ENC = 2, HS_SALT_AUTH = 3, HS_PROTOCOL = 4 };
enum { INFO_EXTENSIONS = 2, INFO_OPTIONS = 4, INFO_PIN_PROTOCOLS = 6 };
// COSE keys (RFC 9052): an EC2 key's type, algorithm, curve and coordinates.
enum { COSE_KTY = 1, COSE_ALG = 3, COSE_CRV = -1, COSE_X = -2, COSE_Y = -3 };
enum { COSE_KTY_EC2 = 2, COSE_CRV_P256 = 1, COSE_ALG_ES256 = -7, COSE_ALG_ECDH_HKDF_256 = -25 };

// Authenticator data: the RP id's hash, the flags, a counter; then with FLAG_AT the AAGUID, the
// credential id's length and the id, and its public key; then with FLAG_ED the extensions.
enum { AD_FLAGS_AT = 32, AD_HEAD = 37, AD_CRED_LEN_AT = 16, AD_ATTESTED_HEAD = 18 };

// The PIN/UV auth protocols: AES-256-CBC with a zero IV (1) or a random one sent first (2), and an
// HMAC that protocol 1 cuts to 16 bytes. Protocol 2's shared key is the HMAC key, then the AES key.
#define AES_BLOCK 16
#define PROTO1_AUTH_LEN 16
#define PROTO2_AES_KEY_AT 32
#define P256_COORD_LEN 32
#define P256_POINT_LEN (1 + 2 * P256_COORD_LEN)
#define POINT_UNCOMPRESSED 0x04
#define PIN_MIN 4
#define PIN_MAX 63
// What a PIN token takes, and the PIN's hash as it's sent: its first half.
#define TOKEN_MIN 16
#define TOKEN_MAX 32
#define PIN_HASH_SENT 16
// The most a PIN token or an hmac-secret output takes encrypted: protocol 2's IV and two blocks.
#define ENC_MAX (AES_BLOCK + 2 * AES_BLOCK)
#define USER_ID_LEN 16
#define CLIENT_DATA_HASH_LEN SHA256_LEN

// CBOR's major types and simple values, and how many bytes of a head's value follow it: below
// AI_1 the value is the additional information itself.
enum { CBOR_UINT, CBOR_NEGINT, CBOR_BYTES, CBOR_TEXT, CBOR_ARRAY, CBOR_MAP, CBOR_TAG, CBOR_SIMPLE };
enum { AI_1 = 24, AI_2 = 25, AI_4 = 26, AI_8 = 27, AI_MASK = 0x1f };
enum { CBOR_FALSE = 20, CBOR_TRUE = 21 };
#define CBOR_DEPTH_MAX 8

static uint8_t g_msg[2048], g_rsp[4096];

// ---- CBOR, the canonical form CTAP asks for: shortest heads, map keys in order ----

typedef struct { uint8_t *b; size_t n, cap; int bad; } cw_t;

static void cw_raw(cw_t *w, const void *p, size_t n) {
    if (w->bad || n > w->cap - w->n) { w->bad = 1; return; }
    memcpy(w->b + w->n, p, n);
    w->n += n;
}

static void cw_head(cw_t *w, int major, uint32_t v) {
    uint8_t h[5];
    size_t n = 1;
    if (v < AI_1) h[0] = (uint8_t)(major << 5 | v);
    else if (v <= UINT8_MAX) { h[0] = (uint8_t)(major << 5 | AI_1); h[1] = (uint8_t)v; n = 2; }
    else if (v <= UINT16_MAX) { h[0] = (uint8_t)(major << 5 | AI_2); store_be16(h + 1, (uint16_t)v); n = 3; }
    else {
        h[0] = (uint8_t)(major << 5 | AI_4);
        store_be32(h + 1, v);
        n = 5;
    }
    cw_raw(w, h, n);
}

static void cw_int(cw_t *w, long v) {
    if (v >= 0) cw_head(w, CBOR_UINT, (uint32_t)v);
    else cw_head(w, CBOR_NEGINT, (uint32_t)(-1 - v));
}
static void cw_bytes(cw_t *w, const uint8_t *p, size_t n) { cw_head(w, CBOR_BYTES, (uint32_t)n); cw_raw(w, p, n); }
static void cw_text(cw_t *w, const char *s) { size_t n = strlen(s); cw_head(w, CBOR_TEXT, (uint32_t)n); cw_raw(w, s, n); }
static void cw_array(cw_t *w, size_t n) { cw_head(w, CBOR_ARRAY, (uint32_t)n); }
static void cw_map(cw_t *w, size_t n) { cw_head(w, CBOR_MAP, (uint32_t)n); }
static void cw_bool(cw_t *w, int b) { uint8_t v = (uint8_t)(CBOR_SIMPLE << 5 | (b ? CBOR_TRUE : CBOR_FALSE)); cw_raw(w, &v, 1); }

typedef struct { const uint8_t *p, *end; } cr_t;

// Indefinite lengths are never CTAP's, and are refused.
static int cr_head(cr_t *r, int *major, uint64_t *v) {
    if (r->p >= r->end) return -1;
    uint8_t b = *r->p++;
    int ai = b & AI_MASK, n = ai == AI_1 ? 1 : ai == AI_2 ? 2 : ai == AI_4 ? 4 : ai == AI_8 ? 8 : 0;
    *major = b >> 5;
    if (ai < AI_1) { *v = (uint64_t)ai; return 0; }
    if (!n || r->end - r->p < n) return -1;
    uint64_t x = 0;
    for (int i = 0; i < n; i++) x = x << 8 | *r->p++;
    *v = x;
    return 0;
}

static int cr_skip(cr_t *r, int depth) {
    int major;
    uint64_t v;
    if (depth > CBOR_DEPTH_MAX || cr_head(r, &major, &v) != 0) return -1;
    switch (major) {
        case CBOR_UINT: case CBOR_NEGINT: case CBOR_SIMPLE: return 0;
        case CBOR_BYTES: case CBOR_TEXT:
            if (v > (uint64_t)(r->end - r->p)) return -1;
            r->p += v;
            return 0;
        case CBOR_ARRAY:
            for (uint64_t i = 0; i < v; i++) if (cr_skip(r, depth + 1) != 0) return -1;
            return 0;
        case CBOR_MAP:
            for (uint64_t i = 0; i < v; i++) if (cr_skip(r, depth + 1) != 0 || cr_skip(r, depth + 1) != 0) return -1;
            return 0;
        default:
            return -1;
    }
}

static int cr_int(cr_t *r, long *out) {
    int major;
    uint64_t v;
    if (cr_head(r, &major, &v) != 0 || major > CBOR_NEGINT || v > INT32_MAX) return -1;
    *out = major ? -1 - (long)v : (long)v;
    return 0;
}

static int cr_string(cr_t *r, int want, const uint8_t **p, size_t *n) {
    int major;
    uint64_t v;
    if (cr_head(r, &major, &v) != 0 || major != want || v > (uint64_t)(r->end - r->p)) return -1;
    *p = r->p;
    *n = (size_t)v;
    r->p += v;
    return 0;
}

static int cr_bytes(cr_t *r, const uint8_t **p, size_t *n) { return cr_string(r, CBOR_BYTES, p, n); }
static int cr_text(cr_t *r, const uint8_t **p, size_t *n) { return cr_string(r, CBOR_TEXT, p, n); }

static int cr_count(cr_t *r, int want, uint64_t *n) {
    int major;
    return cr_head(r, &major, n) == 0 && major == want ? 0 : -1;
}

static int cr_bool(cr_t *r, int *b) {
    int major;
    uint64_t v;
    if (cr_head(r, &major, &v) != 0 || major != CBOR_SIMPLE || (v != CBOR_FALSE && v != CBOR_TRUE)) return -1;
    *b = v == CBOR_TRUE;
    return 0;
}

static int text_is(const uint8_t *p, size_t n, const char *s) { return n == strlen(s) && memcmp(p, s, n) == 0; }

// ---- requests ----

static cw_t request(uint8_t cmd) {
    cw_t w = { g_msg, 1, sizeof g_msg, 0 };
    g_msg[0] = cmd;
    return w;
}

// The status (0 for success) with the answer's CBOR in r, or a CTAP2_ code if it didn't get one.
static int call(ctap2_io_fn io, void *ctx, cw_t *w, cr_t *r, char *why, size_t why_cap) {
    if (w->bad) {
        snprintf(why, why_cap, "the request for the security key came out too long");
        return CTAP2_IO;
    }
    long n = io(ctx, w->b, w->n, g_rsp, sizeof g_rsp, why, why_cap);
    // It can hold a PIN's hash, or a salt.
    crypto_wipe(g_msg, w->n);
    if (n < 0) return (int)n;
    if (n < 1) {
        snprintf(why, why_cap, "the security key gave an empty answer");
        return CTAP2_IO;
    }
    r->p = g_rsp + 1;
    r->end = g_rsp + n;
    return g_rsp[0];
}

static int failed(int st, char *why, size_t why_cap) {
    if (st < 0) return st;
    switch (st) {
        case ST_KEEPALIVE_CANCEL:
            return CTAP2_CANCELLED;
        case ST_NO_CREDENTIALS:
            snprintf(why, why_cap, "it isn't the security key the save was locked with");
            return CTAP2_NO_CRED;
        case ST_USER_ACTION_TIMEOUT:
            snprintf(why, why_cap, "it wasn't touched in time");
            return CTAP2_IO;
        case ST_OPERATION_DENIED:
            snprintf(why, why_cap, "the security key refused");
            return CTAP2_IO;
        case ST_PUAT_REQUIRED:
        case ST_PIN_AUTH_INVALID:
            snprintf(why, why_cap, "it needs its PIN");
            return CTAP2_PIN;
        case ST_PIN_BLOCKED:
            snprintf(why, why_cap, "its PIN is blocked after too many wrong ones, and only resetting it (which wipes its "
                     "credentials) unblocks it");
            return CTAP2_IO;
        case ST_PIN_AUTH_BLOCKED:
            snprintf(why, why_cap, "it takes no more PINs until it's unplugged and plugged in again");
            return CTAP2_IO;
        case ST_PIN_NOT_SET:
            snprintf(why, why_cap, "it wants a PIN, and none is set on it: set one with its own tools first");
            return CTAP2_IO;
        case ST_PIN_POLICY_VIOLATION:
            snprintf(why, why_cap, "that PIN doesn't meet the security key's rules");
            return CTAP2_PIN;
        case ST_UV_BLOCKED:
            snprintf(why, why_cap, "its user verification is blocked");
            return CTAP2_IO;
        default:
            snprintf(why, why_cap, "the security key answered with error 0x%02x", (unsigned)st);
            return CTAP2_IO;
    }
}

int ctap2_get_info(ctap2_io_fn io, void *ctx, ctap2_info_t *info, char *why, size_t why_cap) {
    memset(info, 0, sizeof *info);
    cw_t w = request(CMD_GET_INFO);
    cr_t r;
    int st = call(io, ctx, &w, &r, why, why_cap), make_uv_not_rqd = 0;
    if (st != 0) return failed(st, why, why_cap) == CTAP2_CANCELLED ? CTAP2_CANCELLED : CTAP2_IO;
    uint64_t n;
    if (cr_count(&r, CBOR_MAP, &n) != 0) goto bad;
    for (uint64_t i = 0; i < n; i++) {
        long key;
        if (cr_int(&r, &key) != 0) goto bad;
        if (key == INFO_EXTENSIONS || key == INFO_PIN_PROTOCOLS) {
            uint64_t m;
            if (cr_count(&r, CBOR_ARRAY, &m) != 0) goto bad;
            for (uint64_t j = 0; j < m; j++) {
                if (key == INFO_PIN_PROTOCOLS) {
                    long p;
                    if (cr_int(&r, &p) != 0) goto bad;
                    if (p == 1 || p == 2) info->protocols |= 1 << p;
                    continue;
                }
                const uint8_t *t;
                size_t tl;
                if (cr_text(&r, &t, &tl) != 0) goto bad;
                if (text_is(t, tl, "hmac-secret")) info->hmac_secret = 1;
            }
        } else if (key == INFO_OPTIONS) {
            uint64_t m;
            if (cr_count(&r, CBOR_MAP, &m) != 0) goto bad;
            for (uint64_t j = 0; j < m; j++) {
                const uint8_t *t;
                size_t tl;
                int b;
                if (cr_text(&r, &t, &tl) != 0 || cr_bool(&r, &b) != 0) goto bad;
                if (text_is(t, tl, "clientPin")) info->pin_set = b;
                else if (text_is(t, tl, "alwaysUv")) info->always_uv = b;
                else if (text_is(t, tl, "makeCredUvNotRqd")) make_uv_not_rqd = b;
                else if (text_is(t, tl, "pinUvAuthToken")) info->token_perms = b;
            }
        } else if (cr_skip(&r, 0) != 0) {
            goto bad;
        }
    }
    // CTAP 2.0 keys don't list protocols: they only have the first.
    if (!info->protocols) info->protocols = 1 << 1;
    info->make_needs_pin = info->always_uv || (info->pin_set && !make_uv_not_rqd);
    return 0;
bad:
    snprintf(why, why_cap, "the security key's description of itself can't be read");
    return CTAP2_IO;
}

// ---- the PIN/UV auth protocols: a shared secret from ECDH, then AES-256-CBC and HMAC under it ----

typedef struct {
    int proto;
    uint8_t key[PROTO2_AES_KEY_AT + SHA256_LEN];   // protocol 1: one key for both; protocol 2: the HMAC key, then the AES key
    uint8_t x[P256_COORD_LEN], y[P256_COORD_LEN];   // ours, for the security key
} shared_t;

static int pick_protocol(const ctap2_info_t *info) { return (info->protocols & (1 << 2)) ? 2 : 1; }

static void hkdf_sha256(const uint8_t *ikm, size_t n, const char *info, uint8_t out[SHA256_LEN]) {
    static const uint8_t ZERO_SALT[SHA256_LEN];
    uint8_t prk[SHA256_LEN], t[32];
    size_t il = strlen(info);
    hmac_sha256(ZERO_SALT, sizeof ZERO_SALT, ikm, n, prk);
    memcpy(t, info, il);
    t[il] = 1;
    hmac_sha256(prk, sizeof prk, t, il + 1, out);
    crypto_wipe(prk, sizeof prk);
}

static int aes_cbc(int enc, const uint8_t key[32], uint8_t iv[AES_BLOCK], const uint8_t *in, size_t n, uint8_t *out) {
    mbedtls_aes_context c;
    mbedtls_aes_init(&c);
    int ok = (enc ? mbedtls_aes_setkey_enc(&c, key, 256) : mbedtls_aes_setkey_dec(&c, key, 256)) == 0
          && mbedtls_aes_crypt_cbc(&c, enc ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, n, iv, in, out) == 0;
    mbedtls_aes_free(&c);
    return ok ? 0 : -1;
}

// Returns the length: protocol 2 puts a random IV first.
static long pin_encrypt(const shared_t *s, const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t iv[AES_BLOCK] = { 0 };
    if (n % AES_BLOCK) return -1;
    if (s->proto == 1) return aes_cbc(1, s->key, iv, in, n, out) == 0 ? (long)n : -1;
    gen_random(iv, sizeof iv);
    memcpy(out, iv, sizeof iv);
    return aes_cbc(1, s->key + PROTO2_AES_KEY_AT, iv, in, n, out + AES_BLOCK) == 0 ? (long)(n + AES_BLOCK) : -1;
}

static long pin_decrypt(const shared_t *s, const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t iv[AES_BLOCK] = { 0 };
    if (s->proto == 1) return n % AES_BLOCK == 0 && aes_cbc(0, s->key, iv, in, n, out) == 0 ? (long)n : -1;
    if (n < AES_BLOCK || (n - AES_BLOCK) % AES_BLOCK) return -1;
    memcpy(iv, in, sizeof iv);
    return aes_cbc(0, s->key + PROTO2_AES_KEY_AT, iv, in + AES_BLOCK, n - AES_BLOCK, out) == 0 ? (long)(n - AES_BLOCK) : -1;
}

// Protocol 1 keeps the first half of the HMAC.
static size_t pin_auth(int proto, const uint8_t *key, size_t keylen, const uint8_t *msg, size_t n, uint8_t out[SHA256_LEN]) {
    hmac_sha256(key, keylen, msg, n, out);
    return proto == 1 ? PROTO1_AUTH_LEN : SHA256_LEN;
}

static void cw_cose(cw_t *w, const shared_t *s) {
    cw_map(w, 5);
    cw_int(w, COSE_KTY); cw_int(w, COSE_KTY_EC2);
    cw_int(w, COSE_ALG); cw_int(w, COSE_ALG_ECDH_HKDF_256);   // as CTAP labels it
    cw_int(w, COSE_CRV); cw_int(w, COSE_CRV_P256);
    cw_int(w, COSE_X);   cw_bytes(w, s->x, P256_COORD_LEN);
    cw_int(w, COSE_Y);   cw_bytes(w, s->y, P256_COORD_LEN);
}

static int read_cose_point(cr_t *r, uint8_t x[P256_COORD_LEN], uint8_t y[P256_COORD_LEN]) {
    uint64_t n;
    int got = 0;
    if (cr_count(r, CBOR_MAP, &n) != 0) return -1;
    for (uint64_t i = 0; i < n; i++) {
        long key;
        if (cr_int(r, &key) != 0) return -1;
        if (key == COSE_X || key == COSE_Y) {
            const uint8_t *p;
            size_t len;
            if (cr_bytes(r, &p, &len) != 0 || len != P256_COORD_LEN) return -1;
            memcpy(key == COSE_X ? x : y, p, P256_COORD_LEN);
            got |= key == COSE_X ? 1 : 2;
        } else if (key == COSE_CRV) {
            long crv;
            if (cr_int(r, &crv) != 0 || crv != COSE_CRV_P256) return -1;
        } else if (cr_skip(r, 0) != 0) {
            return -1;
        }
    }
    return got == 3 ? 0 : -1;
}

static int key_agreement(ctap2_io_fn io, void *ctx, int proto, shared_t *s, char *why, size_t why_cap) {
    cw_t w = request(CMD_CLIENT_PIN);
    cw_map(&w, 2);
    cw_int(&w, CP_PROTOCOL); cw_int(&w, proto);
    cw_int(&w, CP_SUBCOMMAND); cw_int(&w, PIN_GET_KEY_AGREEMENT);
    cr_t r;
    int st = call(io, ctx, &w, &r, why, why_cap);
    if (st != 0) return failed(st, why, why_cap);
    uint8_t theirs[P256_POINT_LEN] = { POINT_UNCOMPRESSED };
    uint64_t n;
    int found = 0;
    if (cr_count(&r, CBOR_MAP, &n) != 0) goto bad;
    for (uint64_t i = 0; i < n; i++) {
        long key;
        if (cr_int(&r, &key) != 0) goto bad;
        if (key == CP_OUT_KEY_AGREEMENT) {
            if (read_cose_point(&r, theirs + 1, theirs + 1 + P256_COORD_LEN) != 0) goto bad;
            found = 1;
        } else if (cr_skip(&r, 0) != 0) {
            goto bad;
        }
    }
    if (!found) goto bad;
    // Mbed TLS's own ECDH rather than PSA's: this runs on a thread of its own, and PSA's key store is
    // shared with the relays' TLS, unlocked.
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q, p;
    mbedtls_mpi d, zm;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_ecp_point_init(&p);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&zm);
    uint8_t mine[P256_POINT_LEN], z[P256_COORD_LEN];
    size_t mine_len = 0;
    // The security key's point is checked to be on the curve before it's used.
    int ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0
          && mbedtls_ecdh_gen_public(&grp, &d, &q, crypto_rng, NULL) == 0
          && mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &mine_len, mine, sizeof mine) == 0
          && mine_len == sizeof mine
          && mbedtls_ecp_point_read_binary(&grp, &p, theirs, sizeof theirs) == 0
          && mbedtls_ecp_check_pubkey(&grp, &p) == 0
          && mbedtls_ecdh_compute_shared(&grp, &zm, &p, &d, crypto_rng, NULL) == 0
          && mbedtls_mpi_write_binary(&zm, z, sizeof z) == 0;
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&zm);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_point_free(&p);
    mbedtls_ecp_group_free(&grp);
    if (!ok) {
        crypto_wipe(z, sizeof z);
        snprintf(why, why_cap, "the security key's key agreement key isn't a P-256 point");
        return CTAP2_IO;
    }
    s->proto = proto;
    memcpy(s->x, mine + 1, P256_COORD_LEN);
    memcpy(s->y, mine + 1 + P256_COORD_LEN, P256_COORD_LEN);
    if (proto == 1) {
        sha256_hash(z, sizeof z, s->key);
    } else {
        hkdf_sha256(z, sizeof z, "CTAP2 HMAC key", s->key);
        hkdf_sha256(z, sizeof z, "CTAP2 AES key", s->key + PROTO2_AES_KEY_AT);
    }
    crypto_wipe(z, sizeof z);
    return 0;
bad:
    snprintf(why, why_cap, "the security key's key agreement can't be read");
    return CTAP2_IO;
}

static int pin_retries(ctap2_io_fn io, void *ctx, int proto) {
    char why[64];
    cw_t w = request(CMD_CLIENT_PIN);
    cw_map(&w, 2);
    cw_int(&w, CP_PROTOCOL); cw_int(&w, proto);
    cw_int(&w, CP_SUBCOMMAND); cw_int(&w, PIN_GET_RETRIES);
    cr_t r;
    uint64_t n;
    if (call(io, ctx, &w, &r, why, sizeof why) != 0 || cr_count(&r, CBOR_MAP, &n) != 0) return -1;
    for (uint64_t i = 0; i < n; i++) {
        long key, v;
        if (cr_int(&r, &key) != 0) return -1;
        if (key == CP_OUT_RETRIES) return cr_int(&r, &v) == 0 ? (int)v : -1;
        if (cr_skip(&r, 0) != 0) return -1;
    }
    return -1;
}

// A token for one request, from the PIN. 0, or a CTAP2_ code.
static int pin_token(ctap2_io_fn io, void *ctx, const ctap2_info_t *info, const char *pin, int perms, uint8_t token[TOKEN_MAX],
                     size_t *token_len, int *proto, char *why, size_t why_cap) {
    size_t pl = strlen(pin);
    if (pl < PIN_MIN || pl > PIN_MAX) {
        snprintf(why, why_cap, "a security key's PIN is 4 to 63 characters");
        return CTAP2_PIN;
    }
    shared_t s;
    *proto = pick_protocol(info);
    int rc = key_agreement(io, ctx, *proto, &s, why, why_cap);
    if (rc != 0) return rc;
    uint8_t hash[SHA256_LEN], enc[ENC_MAX];
    sha256_hash(pin, pl, hash);
    long el = pin_encrypt(&s, hash, PIN_HASH_SENT, enc);
    crypto_wipe(hash, sizeof hash);
    if (el < 0) {
        crypto_wipe(&s, sizeof s);
        snprintf(why, why_cap, "chat's AES failed");
        return CTAP2_IO;
    }
    cw_t w = request(CMD_CLIENT_PIN);
    cw_map(&w, info->token_perms ? 6 : 4);
    cw_int(&w, CP_PROTOCOL); cw_int(&w, *proto);
    cw_int(&w, CP_SUBCOMMAND); cw_int(&w, info->token_perms ? PIN_GET_TOKEN_PERMS : PIN_GET_TOKEN);
    cw_int(&w, CP_KEY_AGREEMENT); cw_cose(&w, &s);
    cw_int(&w, CP_PIN_HASH_ENC); cw_bytes(&w, enc, (size_t)el);
    if (info->token_perms) {
        cw_int(&w, CP_PERMISSIONS); cw_int(&w, perms);
        cw_int(&w, CP_RP_ID); cw_text(&w, CTAP2_RP_ID);
    }
    crypto_wipe(enc, sizeof enc);
    cr_t r;
    int st = call(io, ctx, &w, &r, why, why_cap);
    if (st == ST_PIN_INVALID) {
        crypto_wipe(&s, sizeof s);
        int left = pin_retries(io, ctx, *proto);
        if (left >= 0) snprintf(why, why_cap, "that isn't its PIN: %d tr%s left before it's blocked", left, left == 1 ? "y" : "ies");
        else snprintf(why, why_cap, "that isn't its PIN");
        return CTAP2_PIN;
    }
    if (st != 0) {
        crypto_wipe(&s, sizeof s);
        return failed(st, why, why_cap);
    }
    uint64_t n;
    rc = CTAP2_IO;
    snprintf(why, why_cap, "the security key's PIN token can't be read");
    if (cr_count(&r, CBOR_MAP, &n) == 0)
        for (uint64_t i = 0; i < n; i++) {
            long key;
            if (cr_int(&r, &key) != 0) break;
            if (key != CP_OUT_TOKEN) {
                if (cr_skip(&r, 0) != 0) break;
                continue;
            }
            const uint8_t *p;
            size_t len;
            uint8_t plain[ENC_MAX];
            long got;
            if (cr_bytes(&r, &p, &len) != 0 || len > sizeof plain || (got = pin_decrypt(&s, p, len, plain)) < TOKEN_MIN
                || got > TOKEN_MAX)
                break;
            memcpy(token, plain, (size_t)got);
            *token_len = (size_t)got;
            crypto_wipe(plain, sizeof plain);
            rc = 0;
            break;
        }
    crypto_wipe(&s, sizeof s);
    return rc;
}

// ---- credentials and assertions ----

// From authenticator data: the credential id after makeCredential, and its extensions' hmac-secret:
// true after makeCredential, the encrypted secret after getAssertion.
static int parse_auth_data(const uint8_t *a, size_t n, uint8_t *cred, size_t *cred_len, int *hmac_on, const uint8_t **out,
                           size_t *out_len) {
    if (n < AD_HEAD) return -1;
    uint8_t flags = a[AD_FLAGS_AT];
    const uint8_t *p = a + AD_HEAD, *end = a + n;
    if (flags & FLAG_AT) {
        if (end - p < AD_ATTESTED_HEAD) return -1;
        size_t cl = load_be16(p + AD_CRED_LEN_AT);
        p += AD_ATTESTED_HEAD;
        if (cl == 0 || cl > CTAP2_CRED_MAX || (size_t)(end - p) < cl) return -1;
        if (cred) {
            memcpy(cred, p, cl);
            *cred_len = cl;
        }
        p += cl;
        cr_t r = { p, end };
        if (cr_skip(&r, 0) != 0) return -1;   // its public key
        p = r.p;
    }
    if (!(flags & FLAG_ED)) return 0;
    cr_t r = { p, end };
    uint64_t m;
    if (cr_count(&r, CBOR_MAP, &m) != 0) return -1;
    for (uint64_t i = 0; i < m; i++) {
        const uint8_t *t;
        size_t tl;
        if (cr_text(&r, &t, &tl) != 0) return -1;
        if (!text_is(t, tl, "hmac-secret")) {
            if (cr_skip(&r, 0) != 0) return -1;
            continue;
        }
        int b;
        if (r.p < r.end && *r.p >> 5 == CBOR_SIMPLE) {
            if (cr_bool(&r, &b) != 0) return -1;
            if (hmac_on) *hmac_on = b;
        } else if (!out || cr_bytes(&r, out, out_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static void cw_allow(cw_t *w, const uint8_t *const *creds, const size_t *lens, int n) {
    cw_array(w, (size_t)n);
    for (int i = 0; i < n; i++) {
        cw_map(w, 2);
        cw_text(w, "id");   cw_bytes(w, creds[i], lens[i]);
        cw_text(w, "type"); cw_text(w, "public-key");
    }
}

int ctap2_make(ctap2_io_fn io, void *ctx, const ctap2_info_t *info, const char *pin, uint8_t *cred, size_t *cred_len,
               char *why, size_t why_cap) {
    if (!info->hmac_secret) {
        snprintf(why, why_cap, "this security key doesn't have the hmac-secret extension, which chat needs");
        return CTAP2_IO;
    }
    if (info->make_needs_pin && !pin) {
        snprintf(why, why_cap, "it needs its PIN");
        return CTAP2_PIN;
    }
    uint8_t token[TOKEN_MAX], cdh[CLIENT_DATA_HASH_LEN], uid[USER_ID_LEN];
    size_t tl = 0;
    int proto = 0, rc;
    if (pin && (rc = pin_token(io, ctx, info, pin, PERM_MC, token, &tl, &proto, why, why_cap)) != 0) return rc;
    gen_random(cdh, sizeof cdh);
    gen_random(uid, sizeof uid);
    cw_t w = request(CMD_MAKE_CREDENTIAL);
    cw_map(&w, tl ? 7 : 5);
    cw_int(&w, MC_CLIENT_DATA_HASH); cw_bytes(&w, cdh, sizeof cdh);
    cw_int(&w, MC_RP); cw_map(&w, 2);
    cw_text(&w, "id");   cw_text(&w, CTAP2_RP_ID);
    cw_text(&w, "name"); cw_text(&w, CTAP2_RP_ID);
    cw_int(&w, MC_USER); cw_map(&w, 3);
    cw_text(&w, "id");          cw_bytes(&w, uid, sizeof uid);
    cw_text(&w, "name");        cw_text(&w, "chat");
    cw_text(&w, "displayName"); cw_text(&w, "chat");
    cw_int(&w, MC_PUB_KEY_PARAMS); cw_array(&w, 1); cw_map(&w, 2);
    cw_text(&w, "alg");  cw_int(&w, COSE_ALG_ES256);   // which every security key has
    cw_text(&w, "type"); cw_text(&w, "public-key");
    cw_int(&w, MC_EXTENSIONS); cw_map(&w, 1);
    cw_text(&w, "hmac-secret"); cw_bool(&w, 1);
    if (tl) {
        uint8_t param[SHA256_LEN];
        size_t pl = pin_auth(proto, token, tl, cdh, sizeof cdh, param);
        cw_int(&w, MC_PIN_AUTH); cw_bytes(&w, param, pl);
        cw_int(&w, MC_PIN_PROTOCOL); cw_int(&w, proto);
    }
    crypto_wipe(token, sizeof token);
    cr_t r;
    int st = call(io, ctx, &w, &r, why, why_cap);
    if (st != 0) return failed(st, why, why_cap);
    uint64_t n;
    int got = 0, hmac_on = 0;
    if (cr_count(&r, CBOR_MAP, &n) != 0) goto bad;
    for (uint64_t i = 0; i < n; i++) {
        long key;
        if (cr_int(&r, &key) != 0) goto bad;
        if (key != OUT_AUTH_DATA) {
            if (cr_skip(&r, 0) != 0) goto bad;
            continue;
        }
        const uint8_t *a;
        size_t al;
        if (cr_bytes(&r, &a, &al) != 0 || parse_auth_data(a, al, cred, cred_len, &hmac_on, NULL, NULL) != 0
            || !(a[AD_FLAGS_AT] & FLAG_AT))
            goto bad;
        got = 1;
    }
    if (!got) goto bad;
    if (!hmac_on) {
        snprintf(why, why_cap, "the security key made the credential without hmac-secret");
        return CTAP2_IO;
    }
    return 0;
bad:
    snprintf(why, why_cap, "the security key's new credential can't be read");
    return CTAP2_IO;
}

// The credential an assertion is for, and its authenticator data's encrypted hmac-secret. With one
// credential asked for, the answer may leave it out.
static int read_assertion(cr_t *r, const uint8_t *const *creds, const size_t *lens, int n, int *which, const uint8_t **out,
                          size_t *out_len) {
    uint64_t m;
    *which = n == 1 ? 0 : -1;
    if (cr_count(r, CBOR_MAP, &m) != 0) return -1;
    for (uint64_t i = 0; i < m; i++) {
        long key;
        if (cr_int(r, &key) != 0) return -1;
        if (key == OUT_CREDENTIAL) {
            uint64_t k;
            if (cr_count(r, CBOR_MAP, &k) != 0) return -1;
            for (uint64_t j = 0; j < k; j++) {
                const uint8_t *t, *id;
                size_t tl, il;
                if (cr_text(r, &t, &tl) != 0) return -1;
                if (!text_is(t, tl, "id")) {
                    if (cr_skip(r, 0) != 0) return -1;
                    continue;
                }
                if (cr_bytes(r, &id, &il) != 0) return -1;
                *which = -1;
                for (int c = 0; c < n; c++)
                    if (lens[c] == il && memcmp(creds[c], id, il) == 0) *which = c;
            }
        } else if (key == OUT_AUTH_DATA) {
            const uint8_t *a;
            size_t al;
            if (cr_bytes(r, &a, &al) != 0 || parse_auth_data(a, al, NULL, NULL, NULL, out, out_len) != 0) return -1;
        } else if (cr_skip(r, 0) != 0) {
            return -1;
        }
    }
    return *which >= 0 ? 0 : -1;
}

int ctap2_probe(ctap2_io_fn io, void *ctx, const uint8_t *const *creds, const size_t *lens, int n, int *which, char *why,
                size_t why_cap) {
    uint8_t cdh[CLIENT_DATA_HASH_LEN];
    gen_random(cdh, sizeof cdh);
    cw_t w = request(CMD_GET_ASSERTION);
    cw_map(&w, 4);
    cw_int(&w, GA_RP_ID); cw_text(&w, CTAP2_RP_ID);
    cw_int(&w, GA_CLIENT_DATA_HASH); cw_bytes(&w, cdh, sizeof cdh);
    cw_int(&w, GA_ALLOW_LIST); cw_allow(&w, creds, lens, n);
    cw_int(&w, GA_OPTIONS); cw_map(&w, 1);
    cw_text(&w, "up"); cw_bool(&w, 0);
    cr_t r;
    int st = call(io, ctx, &w, &r, why, why_cap);
    if (st == ST_NO_CREDENTIALS) return 0;
    const uint8_t *out = NULL;
    size_t out_len = 0;
    if (st != 0 || read_assertion(&r, creds, lens, n, which, &out, &out_len) != 0) return -1;
    return 1;
}

int ctap2_secret(ctap2_io_fn io, void *ctx, const ctap2_info_t *info, const uint8_t *const *creds, const size_t *lens,
                 int n, const uint8_t salt[CTAP2_SALT_LEN], int uv, const char *pin, uint8_t secret[CTAP2_SECRET_LEN],
                 int *which, char *why, size_t why_cap) {
    if (!info->hmac_secret) {
        snprintf(why, why_cap, "this security key doesn't have the hmac-secret extension, which chat needs");
        return CTAP2_IO;
    }
    if (uv && !pin) {
        snprintf(why, why_cap, "it needs its PIN");
        return CTAP2_PIN;
    }
    uint8_t token[TOKEN_MAX];
    size_t tl = 0;
    int tproto = 0, rc;
    if (uv && (rc = pin_token(io, ctx, info, pin, PERM_GA, token, &tl, &tproto, why, why_cap)) != 0) return rc;
    shared_t s;
    int proto = pick_protocol(info);
    if ((rc = key_agreement(io, ctx, proto, &s, why, why_cap)) != 0) {
        crypto_wipe(token, sizeof token);
        return rc;
    }
    uint8_t salt_enc[ENC_MAX], salt_auth[SHA256_LEN], cdh[CLIENT_DATA_HASH_LEN];
    long se = pin_encrypt(&s, salt, CTAP2_SALT_LEN, salt_enc);
    if (se < 0) {
        crypto_wipe(&s, sizeof s);
        crypto_wipe(token, sizeof token);
        snprintf(why, why_cap, "chat's AES failed");
        return CTAP2_IO;
    }
    size_t sa = pin_auth(proto, s.key, SHA256_LEN, salt_enc, (size_t)se, salt_auth);
    gen_random(cdh, sizeof cdh);
    cw_t w = request(CMD_GET_ASSERTION);
    cw_map(&w, tl ? 6 : 4);
    cw_int(&w, GA_RP_ID); cw_text(&w, CTAP2_RP_ID);
    cw_int(&w, GA_CLIENT_DATA_HASH); cw_bytes(&w, cdh, sizeof cdh);
    cw_int(&w, GA_ALLOW_LIST); cw_allow(&w, creds, lens, n);
    cw_int(&w, GA_EXTENSIONS); cw_map(&w, 1);
    cw_text(&w, "hmac-secret");
    cw_map(&w, proto == 2 ? 4 : 3);
    cw_int(&w, HS_KEY_AGREEMENT); cw_cose(&w, &s);
    cw_int(&w, HS_SALT_ENC); cw_bytes(&w, salt_enc, (size_t)se);
    cw_int(&w, HS_SALT_AUTH); cw_bytes(&w, salt_auth, sa);
    if (proto == 2) { cw_int(&w, HS_PROTOCOL); cw_int(&w, 2); }
    if (tl) {
        uint8_t param[SHA256_LEN];
        size_t pl = pin_auth(tproto, token, tl, cdh, sizeof cdh, param);
        cw_int(&w, GA_PIN_AUTH); cw_bytes(&w, param, pl);
        cw_int(&w, GA_PIN_PROTOCOL); cw_int(&w, tproto);
    }
    crypto_wipe(token, sizeof token);
    crypto_wipe(salt_enc, sizeof salt_enc);
    cr_t r;
    int st = call(io, ctx, &w, &r, why, why_cap);
    if (st != 0) {
        crypto_wipe(&s, sizeof s);
        return failed(st, why, why_cap);
    }
    const uint8_t *out = NULL;
    size_t out_len = 0;
    uint8_t plain[ENC_MAX];
    long got = -1;
    if (read_assertion(&r, creds, lens, n, which, &out, &out_len) == 0 && out && out_len <= sizeof plain)
        got = pin_decrypt(&s, out, out_len, plain);
    crypto_wipe(&s, sizeof s);
    if (got != CTAP2_SECRET_LEN) {
        crypto_wipe(plain, sizeof plain);
        snprintf(why, why_cap, "the security key's answer has no secret chat can read");
        return CTAP2_IO;
    }
    memcpy(secret, plain, CTAP2_SECRET_LEN);
    crypto_wipe(plain, sizeof plain);
    return 0;
}
