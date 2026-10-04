// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "tpm2.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include <psa/crypto.h>
#include <mbedtls/rsa.h>
#include <stdio.h>
#include <string.h>

#define ST_NO_SESSIONS 0x8001
#define ST_SESSIONS 0x8002
#define CC_CREATE_PRIMARY 0x00000131
#define CC_CREATE 0x00000153
#define CC_LOAD 0x00000157
#define CC_UNSEAL 0x0000015E
#define CC_FLUSH_CONTEXT 0x00000165
#define CC_READ_PUBLIC 0x00000173
#define CC_START_AUTH_SESSION 0x00000176
#define RH_OWNER 0x40000001
#define RH_NULL 0x40000007
#define RS_PW 0x40000009
#define SRK_PERSISTENT 0x81000001
#define ALG_RSA 0x0001
#define ALG_AES 0x0006
#define ALG_XOR 0x000A
#define ALG_SHA256 0x000B
#define ALG_NULL 0x0010
#define ALG_ECC 0x0023
#define ALG_CFB 0x0043
#define ECC_NIST_P256 0x0003
#define SE_HMAC 0x00
#define SA_CONTINUE 0x01
#define SA_DECRYPT 0x20
#define SA_ENCRYPT 0x40
#define RC_YIELDED 0x908
#define RC_TESTING 0x90A
#define RC_LOCKOUT 0x921
#define RC_RETRY 0x922
// fixedTPM, fixedParent, userWithAuth, restricted, decrypt: what a key needs to be a parent.
#define STORAGE_ATTRS 0x00030052u

#define NAME_LEN 34
#define NONCE_LEN 32
#define RSP_MAX 4096
#define PRIVATE_MAX 512
// The sealed object's public area as the TPM gives it back: the template, and a 32-byte unique.
#define SEALED_PUBLIC_LEN 46
#define FORMAT 1

// The TCG's storage key template: ECC P-256, SHA-256 names, AES-128-CFB, with fixedTPM,
// fixedParent, sensitiveDataOrigin, userWithAuth, noDA, restricted and decrypt. The same template
// always gives the same key, until the TPM is cleared.
static const uint8_t SRK_TEMPLATE[] = {
    0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00,
    0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x00,
};
#define SRK_HEAD 22   // all but the unique point

// Sealed data: a keyed hash object with no scheme, fixedTPM, fixedParent, userWithAuth and noDA, so
// a wrong password could never count towards the TPM's lockout.
static const uint8_t SEAL_TEMPLATE[] = {
    0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x04, 0x52, 0x00, 0x00,
    0x00, 0x10,
    0x00, 0x00,
};
#define SEAL_HEAD 12

typedef struct { uint8_t *b; size_t cap, n; int bad; } wr_t;
typedef struct { const uint8_t *b; size_t n, i; int bad; } rd_t;

static void w_n(wr_t *w, const void *p, size_t n) {
    if (w->bad || n > w->cap - w->n) { w->bad = 1; return; }
    if (n) memcpy(w->b + w->n, p, n);
    w->n += n;
}
static void w8(wr_t *w, uint8_t v) { w_n(w, &v, 1); }
static void w16(wr_t *w, uint16_t v) { uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v }; w_n(w, b, 2); }
static void w32(wr_t *w, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    w_n(w, b, 4);
}
static void w2b(wr_t *w, const void *p, size_t n) {
    if (n > 0xffff) { w->bad = 1; return; }
    w16(w, (uint16_t)n);
    w_n(w, p, n);
}

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static const uint8_t *r_n(rd_t *r, size_t n) {
    if (r->bad || n > r->n - r->i) { r->bad = 1; return NULL; }
    const uint8_t *p = r->b + r->i;
    r->i += n;
    return p;
}
static uint8_t r8(rd_t *r) { const uint8_t *p = r_n(r, 1); return p ? p[0] : 0; }
static uint16_t r16(rd_t *r) { const uint8_t *p = r_n(r, 2); return p ? (uint16_t)(p[0] << 8 | p[1]) : 0; }
static uint32_t r32(rd_t *r) { const uint8_t *p = r_n(r, 4); return p ? be32(p) : 0; }
static const uint8_t *r2b(rd_t *r, size_t *len) {
    *len = r16(r);
    return r_n(r, *len);
}

static void begin(wr_t *w, uint16_t tag, uint32_t cc) { w16(w, tag); w32(w, 0); w32(w, cc); }
static void end(wr_t *w) {
    if (w->bad || w->n < 10) return;
    uint32_t n = (uint32_t)w->n;
    w->b[2] = (uint8_t)(n >> 24); w->b[3] = (uint8_t)(n >> 16); w->b[4] = (uint8_t)(n >> 8); w->b[5] = (uint8_t)n;
}

// The owner's password, and every key chat makes or uses, is empty.
static void password_auth(wr_t *w) {
    w32(w, 9);
    w32(w, RS_PW);
    w16(w, 0);
    w8(w, SA_CONTINUE);
    w16(w, 0);
}

// KDFa (SP 800-108 counter mode, HMAC-SHA256), as TPM 2.0 has it: one zero byte after the label.
static void kdfa(const uint8_t *key, size_t key_len, const char *label, const uint8_t *u, size_t u_len,
                 const uint8_t *v, size_t v_len, uint8_t *out, size_t out_len) {
    uint8_t msg[4 + 8 + 1 + 2 * NONCE_LEN + 4], block[32];
    size_t label_len = strlen(label);
    uint32_t bits = (uint32_t)out_len * 8;
    for (uint32_t i = 1, done = 0; done < out_len; i++) {
        size_t m = 0;
        msg[m++] = (uint8_t)(i >> 24); msg[m++] = (uint8_t)(i >> 16); msg[m++] = (uint8_t)(i >> 8); msg[m++] = (uint8_t)i;
        memcpy(msg + m, label, label_len); m += label_len;
        msg[m++] = 0;
        memcpy(msg + m, u, u_len); m += u_len;
        memcpy(msg + m, v, v_len); m += v_len;
        msg[m++] = (uint8_t)(bits >> 24); msg[m++] = (uint8_t)(bits >> 16); msg[m++] = (uint8_t)(bits >> 8); msg[m++] = (uint8_t)bits;
        hmac_sha256(key, key_len, msg, m, block);
        size_t take = out_len - done < sizeof block ? out_len - done : sizeof block;
        memcpy(out + done, block, take);
        done += (uint32_t)take;
    }
    crypto_wipe(block, sizeof block);
    crypto_wipe(msg, sizeof msg);
}

// Parameter encryption with TPM_ALG_XOR: a KDFa stream keyed with the session key, fresh for each
// command and answer since the nonces are.
static int xor_param(const uint8_t key[32], const uint8_t *newer, size_t newer_len, const uint8_t *older,
                     size_t older_len, uint8_t *data, size_t len) {
    uint8_t mask[256];
    if (len > sizeof mask) return -1;
    kdfa(key, 32, "XOR", newer, newer_len, older, older_len, mask, len);
    for (size_t i = 0; i < len; i++) data[i] ^= mask[i];
    crypto_wipe(mask, sizeof mask);
    return 0;
}

static void name_of(const uint8_t *pub, size_t len, uint8_t name[NAME_LEN]) {
    name[0] = 0x00;
    name[1] = 0x0B;
    sha256_hash(pub, len, name + 2);
}

typedef struct {
    tpm2_transmit_fn io;
    void *ctx;
    char *why;
    size_t why_cap;
    uint8_t rsp[RSP_MAX];
    size_t rlen;
    uint32_t rc;
} tpm_t;

// 0 if the TPM ran the command, 1 if it answered with an error (in t->rc), -1 if it didn't answer
// (why is set). A TPM that's busy or testing itself hasn't run the command, so it's sent again.
static int call(tpm_t *t, const wr_t *cmd) {
    for (int tries = 0; ; tries++) {
        long n = cmd->bad ? -1 : t->io(t->ctx, cmd->b, cmd->n, t->rsp, sizeof t->rsp);
        if (n < 10 || (size_t)n > sizeof t->rsp || be32(t->rsp + 2) != (uint32_t)n) {
            snprintf(t->why, t->why_cap, "the TPM didn't answer properly");
            return -1;
        }
        t->rlen = (size_t)n;
        t->rc = be32(t->rsp + 6);
        if ((t->rc == RC_RETRY || t->rc == RC_YIELDED || t->rc == RC_TESTING) && tries < 50) {
            platform_sleep_ms(20);
            continue;
        }
        return t->rc == 0 ? 0 : 1;
    }
}

static int auth_error(uint32_t rc) {
    // Format one: TPM_RC_BAD_AUTH or TPM_RC_AUTH_FAIL, for any handle or session.
    return (rc & 0x080) && ((rc & 0x3F) == 0x22 || (rc & 0x3F) == 0x0E);
}

static int failed(tpm_t *t, int rc, const char *what) {
    if (rc <= 0) return -1;
    if (t->rc == RC_LOCKOUT)
        snprintf(t->why, t->why_cap, "%s: the TPM is locked out after too many wrong passwords, for now", what);
    else if (auth_error(t->rc))
        snprintf(t->why, t->why_cap, "%s: the TPM wants a password chat doesn't have (0x%x)", what, (unsigned)t->rc);
    else
        snprintf(t->why, t->why_cap, "%s (TPM error 0x%x)", what, (unsigned)t->rc);
    return -1;
}

// Every key chat makes has no password, so the TPM rejecting a session's HMAC means what crossed the
// bus was changed.
static int session_failed(tpm_t *t, int rc, const char *what) {
    if (rc > 0 && auth_error(t->rc)) {
        snprintf(t->why, t->why_cap, "%s: the TPM didn't accept what chat sent, so something between chat and the "
                 "TPM changed it (0x%x)", what, (unsigned)t->rc);
        return -1;
    }
    return failed(t, rc, what);
}

static void flush(tpm_t *t, uint32_t handle) {
    uint8_t b[14];
    wr_t w = { b, sizeof b, 0, 0 };
    begin(&w, ST_NO_SESSIONS, CC_FLUSH_CONTEXT);
    w32(&w, handle);
    end(&w);
    char why[96], *keep = t->why;
    size_t keep_cap = t->why_cap;
    t->why = why;
    t->why_cap = sizeof why;
    call(t, &w);
    t->why = keep;
    t->why_cap = keep_cap;
}

// The key everything is sealed under: an ECC P-256 or RSA-2048 storage key with SHA-256 names.
typedef struct {
    uint32_t handle;
    int persistent, rsa;
    uint8_t name[NAME_LEN];
    uint8_t x[32], y[32];
    uint8_t n[256];
    uint32_t e;
} parent_t;

static int parse_parent(const uint8_t *pub, size_t n, parent_t *p) {
    rd_t r = { pub, n, 0, 0 };
    uint16_t type = r16(&r), name_alg = r16(&r);
    uint32_t attrs = r32(&r);
    size_t policy_len;
    r2b(&r, &policy_len);
    uint16_t sym = r16(&r), bits = r16(&r), mode = r16(&r), scheme = r16(&r);
    if (r.bad || name_alg != ALG_SHA256 || (attrs & STORAGE_ATTRS) != STORAGE_ATTRS || sym != ALG_AES || bits != 128
        || mode != ALG_CFB || scheme != ALG_NULL)
        return -1;
    if (type == ALG_ECC) {
        uint16_t curve = r16(&r), kdf = r16(&r);
        size_t xl, yl;
        const uint8_t *x = r2b(&r, &xl), *y = r2b(&r, &yl);
        if (r.bad || r.i != n || curve != ECC_NIST_P256 || kdf != ALG_NULL || xl != 32 || yl != 32) return -1;
        p->rsa = 0;
        memcpy(p->x, x, 32);
        memcpy(p->y, y, 32);
    } else if (type == ALG_RSA) {
        uint16_t key_bits = r16(&r);
        uint32_t e = r32(&r);
        size_t ml;
        const uint8_t *m = r2b(&r, &ml);
        if (r.bad || r.i != n || key_bits != 2048 || ml != 256) return -1;
        p->rsa = 1;
        memcpy(p->n, m, 256);
        p->e = e ? e : 65537;
    } else {
        return -1;
    }
    name_of(pub, n, p->name);
    return 0;
}

static int create_primary(tpm_t *t, parent_t *p) {
    uint8_t b[128];
    wr_t w = { b, sizeof b, 0, 0 };
    begin(&w, ST_SESSIONS, CC_CREATE_PRIMARY);
    w32(&w, RH_OWNER);
    password_auth(&w);
    w16(&w, 4);   // inSensitive: no password, no data
    w16(&w, 0);
    w16(&w, 0);
    w2b(&w, SRK_TEMPLATE, sizeof SRK_TEMPLATE);
    w16(&w, 0);   // outsideInfo
    w32(&w, 0);   // creationPCR
    end(&w);
    int rc = call(t, &w);
    if (rc != 0) return rc;
    rd_t r = { t->rsp, t->rlen, 10, 0 };
    p->handle = r32(&r);
    p->persistent = 0;
    r32(&r);
    size_t n;
    const uint8_t *pub = r2b(&r, &n);
    if (r.bad || n < SRK_HEAD || memcmp(pub, SRK_TEMPLATE, SRK_HEAD) != 0 || parse_parent(pub, n, p) != 0) {
        flush(t, p->handle);
        snprintf(t->why, t->why_cap, "the TPM made a storage key other than the one chat asked for");
        return -1;
    }
    return 0;
}

static int read_persistent(tpm_t *t, parent_t *p) {
    uint8_t b[14];
    wr_t w = { b, sizeof b, 0, 0 };
    begin(&w, ST_NO_SESSIONS, CC_READ_PUBLIC);
    w32(&w, SRK_PERSISTENT);
    end(&w);
    int rc = call(t, &w);
    if (rc != 0) return rc;
    rd_t r = { t->rsp, t->rlen, 10, 0 };
    size_t n;
    const uint8_t *pub = r2b(&r, &n);
    if (r.bad || parse_parent(pub, n, p) != 0) {
        snprintf(t->why, t->why_cap, "the TPM's storage key at 0x81000001 isn't one chat can use");
        return -1;
    }
    p->handle = SRK_PERSISTENT;
    p->persistent = 1;
    return 0;
}

static void put_parent_away(tpm_t *t, const parent_t *p) {
    if (!p->persistent) flush(t, p->handle);
}

static int rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    gen_random(out, len);
    return 0;
}

// A session's salt, and the salt encrypted to the parent so only the TPM can read it: RSA-OAEP with
// the label "SECRET", or ECDH with a fresh key and KDFe, as TPM 2.0 has them.
static int make_salt(const parent_t *p, uint8_t salt[32], uint8_t enc[256], size_t *enc_len) {
    if (p->rsa) {
        uint8_t e[4] = { (uint8_t)(p->e >> 24), (uint8_t)(p->e >> 16), (uint8_t)(p->e >> 8), (uint8_t)p->e };
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        gen_random(salt, 32);
        int ok = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256) == 0
              && mbedtls_rsa_import_raw(&rsa, p->n, 256, NULL, 0, NULL, 0, NULL, 0, e, sizeof e) == 0
              && mbedtls_rsa_complete(&rsa) == 0
              && mbedtls_rsa_rsaes_oaep_encrypt(&rsa, rng, NULL, (const unsigned char *)"SECRET", sizeof "SECRET",
                                                32, salt, enc) == 0;
        mbedtls_rsa_free(&rsa);
        *enc_len = 256;
        return ok ? 0 : -1;
    }
    if (psa_crypto_init() != PSA_SUCCESS) return -1;
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&a, PSA_ALG_ECDH);
    mbedtls_svc_key_id_t id;
    if (psa_generate_key(&a, &id) != PSA_SUCCESS) return -1;
    uint8_t mine[65], theirs[65], z[32];
    size_t mine_len = 0, z_len = 0;
    theirs[0] = 0x04;
    memcpy(theirs + 1, p->x, 32);
    memcpy(theirs + 33, p->y, 32);
    int ok = psa_export_public_key(id, mine, sizeof mine, &mine_len) == PSA_SUCCESS && mine_len == 65
          && psa_raw_key_agreement(PSA_ALG_ECDH, id, theirs, sizeof theirs, z, sizeof z, &z_len) == PSA_SUCCESS
          && z_len == 32;
    psa_destroy_key(id);
    if (ok) {
        // KDFe: SHA-256 over a counter, Z, the label and a zero byte, then both x coordinates.
        static const uint8_t one[4] = { 0, 0, 0, 1 }, zero = 0;
        sha256_ctx_t h;
        sha256_init(&h);
        sha256_update(&h, one, sizeof one);
        sha256_update(&h, z, sizeof z);
        sha256_update(&h, "SECRET", 6);
        sha256_update(&h, &zero, 1);
        sha256_update(&h, mine + 1, 32);
        sha256_update(&h, p->x, 32);
        sha256_final(&h, salt);
        crypto_wipe(&h, sizeof h);
        // The encrypted salt is the fresh key's point.
        wr_t w = { enc, 256, 0, 0 };
        w2b(&w, mine + 1, 32);
        w2b(&w, mine + 33, 32);
        *enc_len = w.n;
    }
    crypto_wipe(z, sizeof z);
    return ok ? 0 : -1;
}

typedef struct {
    uint32_t handle;
    uint8_t key[32];
    uint8_t nonce_tpm[NONCE_LEN];
    size_t nonce_tpm_len;
} session_t;

// An HMAC session salted to the parent, with XOR parameter encryption and SHA-256 throughout.
static int start_session(tpm_t *t, const parent_t *p, session_t *s) {
    uint8_t nonce[NONCE_LEN], salt[32], enc[256];
    size_t enc_len = 0;
    gen_random(nonce, sizeof nonce);
    if (make_salt(p, salt, enc, &enc_len) != 0) {
        crypto_wipe(salt, sizeof salt);
        snprintf(t->why, t->why_cap, "couldn't make a key to talk to the TPM with");
        return -1;
    }
    uint8_t b[400];
    wr_t w = { b, sizeof b, 0, 0 };
    begin(&w, ST_NO_SESSIONS, CC_START_AUTH_SESSION);
    w32(&w, p->handle);
    w32(&w, RH_NULL);
    w2b(&w, nonce, sizeof nonce);
    w2b(&w, enc, enc_len);
    w8(&w, SE_HMAC);
    w16(&w, ALG_XOR);
    w16(&w, ALG_SHA256);
    w16(&w, ALG_SHA256);
    end(&w);
    int rc = call(t, &w);
    if (rc != 0) {
        crypto_wipe(salt, sizeof salt);
        return failed(t, rc, "the TPM couldn't start an encrypted session");
    }
    rd_t r = { t->rsp, t->rlen, 10, 0 };
    s->handle = r32(&r);
    size_t nl;
    const uint8_t *nt = r2b(&r, &nl);
    if (r.bad || nl < 16 || nl > NONCE_LEN) {
        crypto_wipe(salt, sizeof salt);
        snprintf(t->why, t->why_cap, "the TPM's session didn't make sense");
        return -1;
    }
    memcpy(s->nonce_tpm, nt, nl);
    s->nonce_tpm_len = nl;
    kdfa(salt, sizeof salt, "ATH", nt, nl, nonce, sizeof nonce, s->key, sizeof s->key);
    crypto_wipe(salt, sizeof salt);
    return 0;
}

// cc for one handle, authorized by s, its first parameter encrypted if attrs has SA_DECRYPT. The
// answer's HMAC is checked, then its first parameter decrypted if attrs has SA_ENCRYPT, and out is
// left on its parameters.
static int session_call(tpm_t *t, session_t *s, uint32_t cc, uint32_t handle, const uint8_t name[NAME_LEN],
                        uint8_t *params, size_t plen, uint8_t attrs, rd_t *out) {
    uint8_t nonce[NONCE_LEN], cc_be[4] = { (uint8_t)(cc >> 24), (uint8_t)(cc >> 16), (uint8_t)(cc >> 8), (uint8_t)cc };
    gen_random(nonce, sizeof nonce);
    if (attrs & SA_DECRYPT) {
        size_t n = plen >= 2 ? (size_t)params[0] << 8 | params[1] : 0;
        if (plen < 2 || 2 + n > plen
            || xor_param(s->key, nonce, sizeof nonce, s->nonce_tpm, s->nonce_tpm_len, params + 2, n) != 0) {
            snprintf(t->why, t->why_cap, "couldn't encrypt what goes to the TPM");
            return -1;
        }
    }
    // The HMAC covers the command's parameters as sent, so after they're encrypted.
    uint8_t cp[32], hmac[32], msg[32 + 2 * NONCE_LEN + 1];
    sha256_ctx_t h;
    sha256_init(&h);
    sha256_update(&h, cc_be, sizeof cc_be);
    sha256_update(&h, name, NAME_LEN);
    if (plen) sha256_update(&h, params, plen);
    sha256_final(&h, cp);
    size_t m = 0;
    memcpy(msg, cp, 32); m += 32;
    memcpy(msg + m, nonce, sizeof nonce); m += sizeof nonce;
    memcpy(msg + m, s->nonce_tpm, s->nonce_tpm_len); m += s->nonce_tpm_len;
    msg[m++] = attrs;
    hmac_sha256(s->key, sizeof s->key, msg, m, hmac);

    uint8_t b[1024];
    wr_t w = { b, sizeof b, 0, 0 };
    begin(&w, ST_SESSIONS, cc);
    w32(&w, handle);
    w32(&w, 4 + 2 + NONCE_LEN + 1 + 2 + 32);
    w32(&w, s->handle);
    w2b(&w, nonce, sizeof nonce);
    w8(&w, attrs);
    w2b(&w, hmac, sizeof hmac);
    w_n(&w, params, plen);
    end(&w);
    int rc = call(t, &w);
    crypto_wipe(b, sizeof b);
    if (rc != 0) return rc;

    rd_t r = { t->rsp, t->rlen, 10, 0 };
    uint32_t psize = r32(&r);
    const uint8_t *rp = r_n(&r, psize);
    size_t ntl, hl;
    const uint8_t *nt = r2b(&r, &ntl);
    uint8_t rattrs = r8(&r);
    const uint8_t *rh = r2b(&r, &hl);
    if (r.bad || r.i != t->rlen || ntl < 16 || ntl > NONCE_LEN || hl != 32) {
        snprintf(t->why, t->why_cap, "the TPM's answer didn't make sense");
        return -1;
    }
    static const uint8_t ok_rc[4] = { 0, 0, 0, 0 };
    uint8_t rph[32], expect[32];
    sha256_init(&h);
    sha256_update(&h, ok_rc, sizeof ok_rc);
    sha256_update(&h, cc_be, sizeof cc_be);
    if (psize) sha256_update(&h, rp, psize);
    sha256_final(&h, rph);
    m = 0;
    memcpy(msg, rph, 32); m += 32;
    memcpy(msg + m, nt, ntl); m += ntl;
    memcpy(msg + m, nonce, sizeof nonce); m += sizeof nonce;
    msg[m++] = rattrs;
    hmac_sha256(s->key, sizeof s->key, msg, m, expect);
    if (crypto_equal(expect, rh, sizeof expect) != 0) {
        snprintf(t->why, t->why_cap, "the TPM's answer failed its check: something between chat and the TPM changed it");
        return -1;
    }
    memcpy(s->nonce_tpm, nt, ntl);
    s->nonce_tpm_len = ntl;
    if (attrs & SA_ENCRYPT) {
        uint8_t *first = t->rsp + (rp - t->rsp);
        size_t n = psize >= 2 ? (size_t)first[0] << 8 | first[1] : 0;
        if (psize < 2 || 2 + n > psize
            || xor_param(s->key, s->nonce_tpm, s->nonce_tpm_len, nonce, sizeof nonce, first + 2, n) != 0) {
            snprintf(t->why, t->why_cap, "the TPM's answer didn't make sense");
            return -1;
        }
    }
    *out = (rd_t){ rp, psize, 0, 0 };
    return 0;
}

// Windows sets a random owner password and forgets it, so where it set the TPM up, the owner's
// storage key can't be made: the one Windows keeps at 0x81000001 is used instead.
static int get_parent(tpm_t *t, parent_t *p) {
    int rc = create_primary(t, p);
    if (rc == 0) return 0;
    if (rc < 0 || !auth_error(t->rc)) return failed(t, rc, "the TPM couldn't make its storage key");
    rc = read_persistent(t, p);
    if (rc == 0) return 0;
    if (rc > 0)
        snprintf(t->why, t->why_cap, "the TPM's owner hierarchy has a password, and there's no storage key at "
                 "0x81000001 to use instead (TPM error 0x%x)", (unsigned)t->rc);
    return -1;
}

long tpm2_seal(tpm2_transmit_fn io, void *ctx, const uint8_t secret[TPM2_SECRET_LEN], uint8_t *out, size_t cap,
               char *why, size_t why_cap) {
    static tpm_t t;
    t = (tpm_t){ .io = io, .ctx = ctx, .why = why, .why_cap = why_cap };
    parent_t p;
    if (get_parent(&t, &p) != 0) return -1;
    long len = -1;
    session_t s;
    if (start_session(&t, &p, &s) == 0) {
        uint8_t params[128];
        wr_t w = { params, sizeof params, 0, 0 };
        w16(&w, 2 + 2 + TPM2_SECRET_LEN);   // inSensitive: no password, the secret as its data
        w16(&w, 0);
        w2b(&w, secret, TPM2_SECRET_LEN);
        w2b(&w, SEAL_TEMPLATE, sizeof SEAL_TEMPLATE);
        w16(&w, 0);
        w32(&w, 0);
        rd_t r;
        int rc = w.bad ? -1 : session_call(&t, &s, CC_CREATE, p.handle, p.name, params, w.n, SA_DECRYPT, &r);
        crypto_wipe(params, sizeof params);
        if (rc == 0) {
            size_t vl, pl;
            const uint8_t *priv = r2b(&r, &vl), *pub = r2b(&r, &pl);
            wr_t o = { out, cap, 0, 0 };
            if (!r.bad && vl <= PRIVATE_MAX && pl == SEALED_PUBLIC_LEN && memcmp(pub, SEAL_TEMPLATE, SEAL_HEAD) == 0) {
                w8(&o, FORMAT);
                w8(&o, (uint8_t)p.persistent);
                w_n(&o, p.name, NAME_LEN);
                w2b(&o, pub, pl);
                w2b(&o, priv, vl);
                if (!o.bad) len = (long)o.n;
            }
            if (len < 0) snprintf(why, why_cap, "the TPM sealed it in a form chat can't keep");
        } else {
            session_failed(&t, rc, "the TPM couldn't seal it");
            // Without a resource manager, a session a failed command didn't use up stays open.
            flush(&t, s.handle);
        }
        crypto_wipe(&s, sizeof s);
    }
    put_parent_away(&t, &p);
    crypto_wipe(&t, sizeof t);
    return len;
}

int tpm2_unseal(tpm2_transmit_fn io, void *ctx, const uint8_t *sealed, size_t len, uint8_t secret[TPM2_SECRET_LEN],
                char *why, size_t why_cap) {
    rd_t in = { sealed, len, 0, 0 };
    uint8_t format = r8(&in), persistent = r8(&in);
    const uint8_t *name = r_n(&in, NAME_LEN);
    size_t pl, vl;
    const uint8_t *pub = r2b(&in, &pl), *priv = r2b(&in, &vl);
    if (in.bad || in.i != len || format != FORMAT || persistent > 1 || pl != SEALED_PUBLIC_LEN || vl > PRIVATE_MAX) {
        snprintf(why, why_cap, "it isn't sealed in a way chat knows");
        return -1;
    }
    static tpm_t t;
    t = (tpm_t){ .io = io, .ctx = ctx, .why = why, .why_cap = why_cap };
    parent_t p;
    int rc = persistent ? read_persistent(&t, &p) : create_primary(&t, &p);
    if (rc != 0)
        return failed(&t, rc, persistent ? "the TPM has no storage key at 0x81000001 any more"
                                         : "the TPM couldn't make its storage key");
    // Pinned: a TPM cleared since makes another key, and so would anything posing as the TPM.
    if (crypto_equal(p.name, name, NAME_LEN) != 0) {
        put_parent_away(&t, &p);
        snprintf(why, why_cap, "this TPM's storage key isn't the one it was sealed under: it was sealed with another "
                 "TPM, this one has been cleared since, or something is posing as the TPM");
        return -1;
    }
    uint8_t b[16 + 2 * 4 + PRIVATE_MAX + SEALED_PUBLIC_LEN + 16];
    wr_t w = { b, sizeof b, 0, 0 };
    begin(&w, ST_SESSIONS, CC_LOAD);
    w32(&w, p.handle);
    password_auth(&w);
    w2b(&w, priv, vl);
    w2b(&w, pub, pl);
    end(&w);
    rc = call(&t, &w);
    if (rc != 0) {
        failed(&t, rc, "the TPM can't load what it sealed: it was sealed with another TPM, or this one has been cleared "
                       "since");
        put_parent_away(&t, &p);
        return -1;
    }
    rd_t r = { t.rsp, t.rlen, 10, 0 };
    uint32_t item = r32(&r);
    int ok = -1;
    session_t s;
    if (start_session(&t, &p, &s) == 0) {
        uint8_t item_name[NAME_LEN];
        name_of(pub, pl, item_name);
        rd_t o;
        rc = session_call(&t, &s, CC_UNSEAL, item, item_name, NULL, 0, SA_ENCRYPT, &o);
        if (rc == 0) {
            size_t dl;
            const uint8_t *d = r2b(&o, &dl);
            if (!o.bad && dl == TPM2_SECRET_LEN) {
                memcpy(secret, d, TPM2_SECRET_LEN);
                ok = 0;
            } else {
                snprintf(why, why_cap, "the TPM unsealed something that isn't chat's");
            }
        } else {
            session_failed(&t, rc, "the TPM couldn't unseal it");
            flush(&t, s.handle);
        }
        crypto_wipe(&s, sizeof s);
    }
    flush(&t, item);
    put_parent_away(&t, &p);
    crypto_wipe(&t, sizeof t);
    return ok;
}
