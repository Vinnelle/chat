// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "pgp.h"
#include "platform.h"
#include "util.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { uint32_t h[5]; uint64_t len; uint8_t buf[64]; size_t buflen; } sha1_ctx;

static uint32_t rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void sha1_block(sha1_ctx *c, const uint8_t *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
    for (int i = 16; i < 80; i++) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & cc) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDC; }
        else { f = b ^ cc ^ d; k = 0xCA62C1D6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = cc; cc = rol(b, 30); b = a; a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}

static void sha1_init(sha1_ctx *c) {
    c->h[0]=0x67452301; c->h[1]=0xEFCDAB89; c->h[2]=0x98BADCFE; c->h[3]=0x10325476; c->h[4]=0xC3D2E1F0;
    c->len = 0; c->buflen = 0;
}
static void sha1_update(sha1_ctx *c, const uint8_t *data, size_t n) {
    c->len += n;
    while (n > 0) {
        size_t take = 64 - c->buflen; if (take > n) take = n;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take; data += take; n -= take;
        if (c->buflen == 64) { sha1_block(c, c->buf); c->buflen = 0; }
    }
}
static void sha1_final(sha1_ctx *c, uint8_t out[20]) {
    uint64_t bitlen = c->len * 8;
    uint8_t pad = 0x80;
    sha1_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) sha1_update(c, &zero, 1);
    uint8_t lenbytes[8];
    for (int i = 0; i < 8; i++) lenbytes[i] = (uint8_t)(bitlen >> (56 - 8 * i));

    memcpy(c->buf + 56, lenbytes, 8);
    sha1_block(c, c->buf);
    for (int i = 0; i < 5; i++) {
        out[i*4] = (uint8_t)(c->h[i] >> 24); out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8); out[i*4+3] = (uint8_t)c->h[i];
    }
}
static void sha1(const uint8_t *data, size_t n, uint8_t out[20]) {
    sha1_ctx c; sha1_init(&c); sha1_update(&c, data, n); sha1_final(&c, out);
}

typedef struct { uint8_t *buf; size_t len, cap; } bb_t;
static void bb_u8(bb_t *b, uint8_t v) { if (b->len < b->cap) b->buf[b->len] = v; b->len++; }
static void bb_bytes(bb_t *b, const void *p, size_t n) {
    if (b->len + n <= b->cap) memcpy(b->buf + b->len, p, n);
    b->len += n;
}
static void bb_u16(bb_t *b, uint16_t v) { bb_u8(b, (uint8_t)(v >> 8)); bb_u8(b, (uint8_t)v); }
static void bb_u32(bb_t *b, uint32_t v) { bb_u8(b, (uint8_t)(v>>24)); bb_u8(b,(uint8_t)(v>>16)); bb_u8(b,(uint8_t)(v>>8)); bb_u8(b,(uint8_t)v); }

static uint16_t mpi_bitlen(const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n && p[i] == 0) i++;
    if (i == n) return 0;
    int hi = 7;
    while (hi > 0 && !((p[i] >> hi) & 1)) hi--;
    return (uint16_t)((n - i - 1) * 8 + hi + 1);
}
static void bb_mpi(bb_t *b, const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n && p[i] == 0) i++;
    bb_u16(b, mpi_bitlen(p, n));
    bb_bytes(b, p + i, n - i);
}

static void bb_packet_header(bb_t *b, int tag, size_t body_len) {
    bb_u8(b, (uint8_t)(0xC0 | tag));
    if (body_len < 192) {
        bb_u8(b, (uint8_t)body_len);
    } else {
        size_t v = body_len - 192;
        bb_u8(b, (uint8_t)(192 + (v >> 8)));
        bb_u8(b, (uint8_t)(v & 0xff));
    }
}

static const uint8_t ED25519_OID[9] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };

static size_t build_pubkey_body(const uint8_t ed_pub[32], uint32_t ctime, uint8_t *out, size_t cap) {
    bb_t b = { out, 0, cap };
    bb_u8(&b, 4);
    bb_u32(&b, ctime);
    bb_u8(&b, 22);
    bb_u8(&b, sizeof ED25519_OID);
    bb_bytes(&b, ED25519_OID, sizeof ED25519_OID);
    uint8_t point[33] = {0x40};
    memcpy(point + 1, ed_pub, 32);
    bb_mpi(&b, point, sizeof point);
    return b.len;
}

static void key_fingerprint(const uint8_t *pubkey_body, size_t pubkey_body_len, uint8_t fp[20]) {
    uint8_t pre[3 + 512];
    bb_t b = { pre, 0, sizeof pre };
    bb_u8(&b, 0x99);
    bb_u16(&b, (uint16_t)pubkey_body_len);
    bb_bytes(&b, pubkey_body, pubkey_body_len);
    sha1(pre, b.len, fp);
}

static uint32_t crc24(const uint8_t *data, size_t n) {
    uint32_t crc = 0xB704CEu;
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint32_t)data[i] << 16;
        for (int j = 0; j < 8; j++) {
            crc <<= 1;
            if (crc & 0x1000000u) crc ^= 0x1864CFBu;
        }
    }
    return crc & 0xFFFFFFu;
}

void pgp_export_public_key(const identity_keypair_t *idkp, const char *nick,
                            char *out, size_t out_cap, uint8_t fingerprint[PGP_FP_LEN]) {
    uint32_t ctime = (uint32_t)time(NULL);
    uint8_t pubkey_body[64];
    size_t pubkey_body_len = build_pubkey_body(idkp->pub, ctime, pubkey_body, sizeof pubkey_body);
    key_fingerprint(pubkey_body, pubkey_body_len, fingerprint);

    char uid[64];
    int uid_len = snprintf(uid, sizeof uid, "%s (chat identity)", nick);
    if (uid_len < 0) uid_len = 0;

    uint8_t hashed_subpkts[6] = { 0x05, 0x02, 0,0,0,0 };
    hashed_subpkts[2] = (uint8_t)(ctime >> 24); hashed_subpkts[3] = (uint8_t)(ctime >> 16);
    hashed_subpkts[4] = (uint8_t)(ctime >> 8);  hashed_subpkts[5] = (uint8_t)ctime;
    uint16_t hashed_len = sizeof hashed_subpkts;

    uint8_t sig_trailer[12];
    bb_t tb = { sig_trailer, 0, sizeof sig_trailer };
    bb_u8(&tb, 4); bb_u8(&tb, 0x13); bb_u8(&tb, 22); bb_u8(&tb, 8 );
    bb_u16(&tb, hashed_len); bb_bytes(&tb, hashed_subpkts, hashed_len);

    uint8_t final_trailer[6] = { 0x04, 0xff, 0,0,0, (uint8_t)tb.len };
    final_trailer[2] = (uint8_t)(tb.len >> 24); final_trailer[3] = (uint8_t)(tb.len >> 16); final_trailer[4] = (uint8_t)(tb.len >> 8);

    uint8_t preimage[3 + 128 + 5 + 256 + 6 + 6];
    bb_t pb = { preimage, 0, sizeof preimage };
    bb_u8(&pb, 0x99); bb_u16(&pb, (uint16_t)pubkey_body_len); bb_bytes(&pb, pubkey_body, pubkey_body_len);
    bb_u8(&pb, 0xb4); bb_u32(&pb, (uint32_t)uid_len); bb_bytes(&pb, uid, (size_t)uid_len);
    bb_bytes(&pb, sig_trailer, tb.len);
    bb_bytes(&pb, final_trailer, sizeof final_trailer);

    uint8_t hash[32];
    crypto_hash_sha256(hash, preimage, pb.len);

    uint8_t ed_sig[64];
    unsigned long long siglen;
    crypto_sign_detached(ed_sig, &siglen, hash, sizeof hash, idkp->priv);

    uint8_t unhashed_subpkts[10];
    bb_t ub = { unhashed_subpkts, 0, sizeof unhashed_subpkts };
    bb_u8(&ub, 9); bb_u8(&ub, 16 ); bb_bytes(&ub, fingerprint + 12, 8);

    uint8_t sigbody[256];
    bb_t sb = { sigbody, 0, sizeof sigbody };
    bb_bytes(&sb, sig_trailer, tb.len);
    bb_u16(&sb, (uint16_t)ub.len); bb_bytes(&sb, unhashed_subpkts, ub.len);
    bb_bytes(&sb, hash, 2);
    bb_mpi(&sb, ed_sig, 32);
    bb_mpi(&sb, ed_sig + 32, 32);

    uint8_t doc[512];
    bb_t db = { doc, 0, sizeof doc };
    bb_packet_header(&db, 6, pubkey_body_len); bb_bytes(&db, pubkey_body, pubkey_body_len);
    bb_packet_header(&db, 13, (size_t)uid_len); bb_bytes(&db, uid, (size_t)uid_len);
    bb_packet_header(&db, 2, sb.len); bb_bytes(&db, sigbody, sb.len);

    char b64[700];
    size_t b64len = base64_encode(doc, db.len, b64);
    uint32_t crc = crc24(doc, db.len);
    uint8_t crcbytes[3] = { (uint8_t)(crc >> 16), (uint8_t)(crc >> 8), (uint8_t)crc };
    char crc64[8]; base64_encode(crcbytes, 3, crc64);

    size_t o = 0;
    o += (size_t)snprintf(out + o, out_cap - o, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n");
    for (size_t i = 0; i < b64len && o < out_cap; i += 64) {
        size_t chunk = b64len - i < 64 ? b64len - i : 64;
        if (o + chunk + 1 >= out_cap) break;
        memcpy(out + o, b64 + i, chunk); o += chunk;
        out[o++] = '\n';
    }
    o += (size_t)snprintf(out + o, out_cap - o, "=%s\n-----END PGP PUBLIC KEY BLOCK-----\n", crc64);
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char *in, size_t inlen, uint8_t *out, size_t out_cap) {
    size_t o = 0;
    int vals[4], n = 0;
    for (size_t i = 0; i < inlen; i++) {
        int v = b64val(in[i]);
        if (v < 0) continue;
        vals[n++] = v;
        if (n == 4) {
            uint32_t x = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) | ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];
            if (o < out_cap) { out[o] = (uint8_t)(x >> 16); }
            o++;
            if (o < out_cap) { out[o] = (uint8_t)(x >> 8); }
            o++;
            if (o < out_cap) { out[o] = (uint8_t)x; }
            o++;
            n = 0;
        }
    }
    return o;
}

static int read_packet_header(const uint8_t *data, size_t len, size_t *pos, int *tag, size_t *body_len) {
    if (*pos >= len) return -1;
    uint8_t first = data[(*pos)++];
    if (!(first & 0x80)) return -1;
    if (first & 0x40) {
        *tag = first & 0x3f;
        if (*pos >= len) return -1;
        uint8_t l0 = data[(*pos)++];
        if (l0 < 192) { *body_len = l0; }
        else if (l0 < 224) {
            if (*pos >= len) return -1;
            *body_len = (size_t)(l0 - 192) * 256 + data[(*pos)++] + 192;
        } else if (l0 == 255) {
            if (*pos + 4 > len) return -1;
            *body_len = ((size_t)data[*pos] << 24) | ((size_t)data[*pos+1] << 16) | ((size_t)data[*pos+2] << 8) | data[*pos+3];
            *pos += 4;
        } else return -1;
    } else {
        *tag = (first >> 2) & 0x0f;
        int ltype = first & 0x03;
        if (ltype == 0) { if (*pos >= len) return -1; *body_len = data[(*pos)++]; }
        else if (ltype == 1) { if (*pos+2 > len) return -1; *body_len = ((size_t)data[*pos]<<8)|data[*pos+1]; *pos += 2; }
        else if (ltype == 2) { if (*pos+4 > len) return -1; *body_len = ((size_t)data[*pos]<<24)|((size_t)data[*pos+1]<<16)|((size_t)data[*pos+2]<<8)|data[*pos+3]; *pos += 4; }
        else return -1;
    }
    if (*pos + *body_len > len) return -1;
    return 0;
}

static uint16_t mpi_read_len(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

int pgp_import_secret_key(const char *path, identity_keypair_t *idkp) {
    FILE *f = platform_fopen(path, "rb");
    if (!f) return -1;
    char text[16384];
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    text[n] = '\0';
    int rc = pgp_import_secret_key_text(text, idkp);
    sodium_memzero(text, sizeof text);
    return rc;
}

int pgp_import_secret_key_text(const char *text, identity_keypair_t *idkp) {
    const char *begin_marker = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    const char *end_marker = "-----END PGP PRIVATE KEY BLOCK-----";
    char *begin = strstr(text, begin_marker);
    if (!begin) return -1;
    char *body_start = begin + strlen(begin_marker);
    char *end = strstr(body_start, end_marker);
    if (!end) return -1;

    uint8_t doc[4096];
    size_t doclen = base64_decode(body_start, (size_t)(end - body_start), doc, sizeof doc);
    if (doclen < 4) return -1;

    size_t pos = 0;
    while (pos < doclen) {
        int tag; size_t blen;
        if (read_packet_header(doc, doclen, &pos, &tag, &blen) != 0) break;
        const uint8_t *body = doc + pos;
        if (tag == 5) {
            size_t p = 0;
            if (blen < 6 || body[p] != 4) { return -1; }
            p += 1 + 4;
            if (body[p] != 22) { return -1; }
            p += 1;
            uint8_t oid_len = body[p++];
            if (oid_len != sizeof ED25519_OID || p + oid_len > blen ||
                memcmp(body + p, ED25519_OID, sizeof ED25519_OID) != 0) { return -1; }
            p += oid_len;
            if (p + 2 > blen) return -1;
            uint16_t pub_bits = mpi_read_len(body + p); p += 2;
            size_t pub_bytes = (size_t)((pub_bits + 7) / 8);
            if (pub_bytes != 33 || p + pub_bytes > blen || body[p] != 0x40) { return -1; }
            uint8_t pgp_pub[32];
            memcpy(pgp_pub, body + p + 1, 32);
            p += pub_bytes;
            if (p >= blen) return -1;
            uint8_t s2k_usage = body[p++];
            if (s2k_usage != 0) { return -1; }
            if (p + 2 > blen) return -1;
            uint16_t sec_bits = mpi_read_len(body + p); p += 2;
            size_t sec_bytes = (size_t)((sec_bits + 7) / 8);
            if (sec_bytes > 32 || p + sec_bytes + 2 > blen) return -1;
            uint8_t seed[32] = {0};
            memcpy(seed + (32 - sec_bytes), body + p, sec_bytes);
            p += sec_bytes;
            uint16_t stored_checksum = mpi_read_len(body + p);

            uint32_t sum = 0;
            for (size_t i = 0; i < 2 + sec_bytes; i++) sum += body[p - 2 - sec_bytes + i];
            if ((uint16_t)(sum & 0xffff) != stored_checksum) return -1;

            uint8_t derived_pub[32];
            crypto_sign_seed_keypair(derived_pub, idkp->priv, seed);
            sodium_memzero(seed, sizeof seed);
            if (memcmp(derived_pub, pgp_pub, 32) != 0) return -1;
            memcpy(idkp->pub, derived_pub, 32);
            return 0;
        }
        pos += blen;
    }
    return -1;
}
