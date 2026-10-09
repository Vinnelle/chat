// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "crypto/pgp.h"
#include "platform/platform.h"
#include "common/util.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// RFC 4880's numbers for the packets chat reads and writes.
enum { PGP_VERSION = 4, PGP_EDDSA = 22, PGP_SHA256 = 8, SIG_POSITIVE_CERT = 0x13 };
enum { TAG_SIGNATURE = 2, TAG_SECRET_KEY = 5, TAG_PUBLIC_KEY = 6, TAG_USER_ID = 13 };
enum { SUBPKT_CREATED = 2, SUBPKT_ISSUER = 16 };
// A packet header's first byte always has the top bit, and the next one for the new format.
#define PACKET_BIT 0x80
#define NEW_FORMAT_BIT 0x40
// A new-format length is one byte below 192, two up to 224, or 255 and four more.
enum { TWO_BYTE_LEN = 192, PARTIAL_LEN = 224, FOUR_BYTE_LEN = 255 };
// What a key and a user id start with when they're hashed, for a fingerprint or a signature.
#define HASH_KEY_PREFIX 0x99
#define HASH_UID_PREFIX 0xb4
#define EDDSA_POINT 0x40
#define EDDSA_POINT_LEN (1 + ID_SIGN_PUB_LEN)
#define KEY_ID_LEN 8      // the end of the fingerprint
#define HASH_LEFT 2       // the hash's first bytes, which a signature repeats
#define ARMOR_LINE 64
#define CRC24_INIT 0xB704CEu
#define CRC24_POLY 0x1864CFBu
#define CRC24_LEN 3
#define PGP_FILE_MAX 16384
#define PGP_DOC_MAX 4096
_Static_assert(PGP_FP_LEN == SHA1_LEN, "a v4 fingerprint is SHA-1");

typedef struct { uint8_t *buf; size_t len, cap; } bb_t;
static void bb_u8(bb_t *b, uint8_t v) { if (b->len < b->cap) b->buf[b->len] = v; b->len++; }
static void bb_bytes(bb_t *b, const void *p, size_t n) {
    if (b->len + n <= b->cap) memcpy(b->buf + b->len, p, n);
    b->len += n;
}
static void bb_u16(bb_t *b, uint16_t v) { bb_u8(b, (uint8_t)(v >> 8)); bb_u8(b, (uint8_t)v); }
static void bb_u32(bb_t *b, uint32_t v) { bb_u16(b, (uint16_t)(v >> 16)); bb_u16(b, (uint16_t)v); }

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

// The bytes an MPI takes after its 2-byte bit count.
static size_t mpi_bytes(const uint8_t *p) { return (size_t)((load_be16(p) + 7) / 8); }

static void bb_packet_header(bb_t *b, int tag, size_t body_len) {
    bb_u8(b, (uint8_t)(PACKET_BIT | NEW_FORMAT_BIT | tag));
    if (body_len < TWO_BYTE_LEN) {
        bb_u8(b, (uint8_t)body_len);
    } else {
        size_t v = body_len - TWO_BYTE_LEN;
        bb_u8(b, (uint8_t)(TWO_BYTE_LEN + (v >> 8)));
        bb_u8(b, (uint8_t)(v & 0xff));
    }
}

static const uint8_t ED25519_OID[9] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };

static size_t build_pubkey_body(const uint8_t ed_pub[ID_SIGN_PUB_LEN], uint32_t ctime, uint8_t *out, size_t cap) {
    bb_t b = { out, 0, cap };
    bb_u8(&b, PGP_VERSION);
    bb_u32(&b, ctime);
    bb_u8(&b, PGP_EDDSA);
    bb_u8(&b, sizeof ED25519_OID);
    bb_bytes(&b, ED25519_OID, sizeof ED25519_OID);
    uint8_t point[EDDSA_POINT_LEN] = { EDDSA_POINT };
    memcpy(point + 1, ed_pub, ID_SIGN_PUB_LEN);
    bb_mpi(&b, point, sizeof point);
    return b.len;
}

static void bb_hashed_key(bb_t *b, const uint8_t *pubkey_body, size_t pubkey_body_len) {
    bb_u8(b, HASH_KEY_PREFIX);
    bb_u16(b, (uint16_t)pubkey_body_len);
    bb_bytes(b, pubkey_body, pubkey_body_len);
}

static void key_fingerprint(const uint8_t *pubkey_body, size_t pubkey_body_len, uint8_t fp[PGP_FP_LEN]) {
    uint8_t pre[3 + 512];
    bb_t b = { pre, 0, sizeof pre };
    bb_hashed_key(&b, pubkey_body, pubkey_body_len);
    sha1_hash(pre, b.len, fp);
}

static uint32_t crc24(const uint8_t *data, size_t n) {
    uint32_t crc = CRC24_INIT;
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint32_t)data[i] << 16;
        for (int j = 0; j < 8; j++) {
            crc <<= 1;
            if (crc & 0x1000000u) crc ^= CRC24_POLY;
        }
    }
    return crc & 0xFFFFFFu;
}

void pgp_export_public_key(const identity_keypair_t *idkp, const char *nick, uint32_t created,
                            char *out, size_t out_cap, uint8_t fingerprint[PGP_FP_LEN]) {
    uint32_t ctime = created;
    uint8_t pubkey_body[64];
    size_t pubkey_body_len = build_pubkey_body(idkp->pub, ctime, pubkey_body, sizeof pubkey_body);
    key_fingerprint(pubkey_body, pubkey_body_len, fingerprint);

    char uid[64];
    int uid_len = snprintf(uid, sizeof uid, "%s (chat identity)", nick);
    if (uid_len < 0) uid_len = 0;

    // The one hashed subpacket: its length, then the key's creation time.
    uint8_t hashed_subpkts[6] = { 5, SUBPKT_CREATED };
    store_be32(hashed_subpkts + 2, ctime);
    uint16_t hashed_len = sizeof hashed_subpkts;

    uint8_t sig_trailer[12];
    bb_t tb = { sig_trailer, 0, sizeof sig_trailer };
    bb_u8(&tb, PGP_VERSION); bb_u8(&tb, SIG_POSITIVE_CERT); bb_u8(&tb, PGP_EDDSA); bb_u8(&tb, PGP_SHA256);
    bb_u16(&tb, hashed_len); bb_bytes(&tb, hashed_subpkts, hashed_len);

    uint8_t final_trailer[6] = { PGP_VERSION, 0xff };
    store_be32(final_trailer + 2, (uint32_t)tb.len);

    uint8_t preimage[3 + 128 + 5 + 256 + 6 + 6];
    bb_t pb = { preimage, 0, sizeof preimage };
    bb_hashed_key(&pb, pubkey_body, pubkey_body_len);
    bb_u8(&pb, HASH_UID_PREFIX); bb_u32(&pb, (uint32_t)uid_len); bb_bytes(&pb, uid, (size_t)uid_len);
    bb_bytes(&pb, sig_trailer, tb.len);
    bb_bytes(&pb, final_trailer, sizeof final_trailer);

    uint8_t hash[SHA256_LEN];
    sha256_hash(preimage, pb.len, hash);

    uint8_t ed_sig[ID_SIGN_LEN];
    identity_sign_bytes(idkp, hash, sizeof hash, ed_sig);

    uint8_t unhashed_subpkts[10];
    bb_t ub = { unhashed_subpkts, 0, sizeof unhashed_subpkts };
    bb_u8(&ub, 1 + KEY_ID_LEN); bb_u8(&ub, SUBPKT_ISSUER); bb_bytes(&ub, fingerprint + PGP_FP_LEN - KEY_ID_LEN, KEY_ID_LEN);

    uint8_t sigbody[256];
    bb_t sb = { sigbody, 0, sizeof sigbody };
    bb_bytes(&sb, sig_trailer, tb.len);
    bb_u16(&sb, (uint16_t)ub.len); bb_bytes(&sb, unhashed_subpkts, ub.len);
    bb_bytes(&sb, hash, HASH_LEFT);
    // R, then S.
    bb_mpi(&sb, ed_sig, ID_SIGN_LEN / 2);
    bb_mpi(&sb, ed_sig + ID_SIGN_LEN / 2, ID_SIGN_LEN / 2);

    uint8_t doc[512];
    bb_t db = { doc, 0, sizeof doc };
    bb_packet_header(&db, TAG_PUBLIC_KEY, pubkey_body_len); bb_bytes(&db, pubkey_body, pubkey_body_len);
    bb_packet_header(&db, TAG_USER_ID, (size_t)uid_len); bb_bytes(&db, uid, (size_t)uid_len);
    bb_packet_header(&db, TAG_SIGNATURE, sb.len); bb_bytes(&db, sigbody, sb.len);

    char b64[BASE64_LEN(sizeof doc) + 1];
    size_t b64len = base64_encode(doc, db.len, b64);
    uint32_t crc = crc24(doc, db.len);
    uint8_t crcbytes[CRC24_LEN] = { (uint8_t)(crc >> 16), (uint8_t)(crc >> 8), (uint8_t)crc };
    char crc64[BASE64_LEN(CRC24_LEN) + 1]; base64_encode(crcbytes, CRC24_LEN, crc64);

    size_t o = 0;
    o += (size_t)snprintf(out + o, out_cap - o, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n");
    for (size_t i = 0; i < b64len && o < out_cap; i += ARMOR_LINE) {
        size_t chunk = b64len - i < ARMOR_LINE ? b64len - i : ARMOR_LINE;
        if (o + chunk + 1 >= out_cap) break;
        memcpy(out + o, b64 + i, chunk); o += chunk;
        out[o++] = '\n';
    }
    o += (size_t)snprintf(out + o, out_cap - o, "=%s\n-----END PGP PUBLIC KEY BLOCK-----\n", crc64);
}

// Appends the base64 in one armor line to out, carrying a partial quartet in q/nq across lines.
// '=' padding ends the data. Returns -1 on a character outside the alphabet or when out is full.
static int b64_line(const char *s, size_t n, uint8_t *out, size_t cap, size_t *o, int q[4], int *nq, int *done) {
    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        if (ch == ' ' || ch == '\t' || ch == '\r') continue;
        if (*done) return -1;
        if (ch == '=') {
            // Padding: 2 or 3 characters of the last quartet carry 1 or 2 bytes.
            if (*nq < 2) return -1;
            uint32_t x = ((uint32_t)q[0] << 18) | ((uint32_t)q[1] << 12) | (*nq > 2 ? (uint32_t)q[2] << 6 : 0);
            size_t bytes = (size_t)(*nq - 1);
            if (*o + bytes > cap) return -1;
            out[(*o)++] = (uint8_t)(x >> 16);
            if (bytes > 1) out[(*o)++] = (uint8_t)(x >> 8);
            *nq = 0;
            *done = 1;
            // Anything after this on the line must be more '='.
            for (i++; i < n; i++) if (s[i] != '=' && s[i] != '\r') return -1;
            return 0;
        }
        int v = base64_value(ch);
        if (v < 0) return -1;
        q[(*nq)++] = v;
        if (*nq == 4) {
            if (*o + 3 > cap) return -1;
            uint32_t x = ((uint32_t)q[0] << 18) | ((uint32_t)q[1] << 12) | ((uint32_t)q[2] << 6) | (uint32_t)q[3];
            out[(*o)++] = (uint8_t)(x >> 16);
            out[(*o)++] = (uint8_t)(x >> 8);
            out[(*o)++] = (uint8_t)x;
            *nq = 0;
        }
    }
    return 0;
}

// Decodes the body of an ASCII-armored block (the text between its BEGIN and END lines): skips
// armor headers ("Key: value" lines before the first blank line), and checks the "=XXXX" CRC-24
// line when there is one. Returns the decoded length, or -1.
static long armor_decode(const char *text, size_t len, uint8_t *out, size_t cap) {
    size_t o = 0;
    int q[4], nq = 0, done = 0, in_headers = 1, have_crc = 0;
    uint32_t crc_want = 0;
    const char *p = text, *end = text + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t n = nl ? (size_t)(nl - p) : (size_t)(end - p);
        while (n > 0 && (p[n - 1] == '\r' || p[n - 1] == ' ' || p[n - 1] == '\t')) n--;
        const char *line = p;
        p = nl ? nl + 1 : end;
        if (n == 0) { in_headers = 0; continue; }
        if (in_headers && memchr(line, ':', n)) continue;
        in_headers = 0;
        if (line[0] == '=' && n == 5) {
            // The checksum line: four base64 characters, three bytes.
            int v[4];
            for (int k = 0; k < 4; k++) if ((v[k] = base64_value(line[1 + k])) < 0) return -1;
            crc_want = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) | ((uint32_t)v[2] << 6) | (uint32_t)v[3];
            have_crc = 1;
            break;
        }
        if (b64_line(line, n, out, cap, &o, q, &nq, &done) != 0) return -1;
    }
    if (nq != 0) return -1;
    if (have_crc && crc24(out, o) != crc_want) return -1;
    return (long)o;
}

static int read_packet_header(const uint8_t *data, size_t len, size_t *pos, int *tag, size_t *body_len) {
    if (*pos >= len) return -1;
    uint8_t first = data[(*pos)++];
    if (!(first & PACKET_BIT)) return -1;
    if (first & NEW_FORMAT_BIT) {
        *tag = first & 0x3f;
        if (*pos >= len) return -1;
        uint8_t l0 = data[(*pos)++];
        if (l0 < TWO_BYTE_LEN) { *body_len = l0; }
        else if (l0 < PARTIAL_LEN) {
            if (*pos >= len) return -1;
            *body_len = (size_t)(l0 - TWO_BYTE_LEN) * 256 + data[(*pos)++] + TWO_BYTE_LEN;
        } else if (l0 == FOUR_BYTE_LEN) {
            if (*pos + 4 > len) return -1;
            *body_len = load_be32(data + *pos);
            *pos += 4;
        } else return -1;
    } else {
        // The old format: the tag, then whether the length takes 1, 2 or 4 bytes, or isn't given.
        *tag = (first >> 2) & 0x0f;
        int ltype = first & 0x03;
        size_t n = (size_t)1 << ltype;
        if (ltype == 3 || n > len - *pos) return -1;
        *body_len = 0;
        for (size_t i = 0; i < n; i++) *body_len = *body_len << 8 | data[(*pos)++];
    }
    if (*body_len > len - *pos) return -1;
    return 0;
}

int pgp_import_secret_key(const char *path, identity_keypair_t *idkp) {
    char text[PGP_FILE_MAX];
    long n = platform_read_file(path, text, sizeof(text) - 1);
    if (n < 0) return -1;
    text[n] = '\0';
    int rc = pgp_import_secret_key_text(text, idkp);
    sodium_memzero(text, sizeof text);
    return rc;
}

// A v4 EdDSA (Ed25519) secret-key packet body, unencrypted, to a keypair.
static int parse_secret_key_packet(const uint8_t *body, size_t blen, identity_keypair_t *out) {
    // version 4, creation time (4), algorithm 22 (EdDSA), OID length, OID
    size_t p = 0;
    if (blen < 7 || body[0] != PGP_VERSION || body[5] != PGP_EDDSA) return -1;
    p = 6;
    uint8_t oid_len = body[p++];
    if (oid_len != sizeof ED25519_OID || oid_len > blen - p || memcmp(body + p, ED25519_OID, oid_len) != 0) return -1;
    p += oid_len;
    // public point: an MPI of 0x40 followed by the 32-byte key
    if (blen - p < 2) return -1;
    size_t pub_bytes = mpi_bytes(body + p);
    p += 2;
    if (pub_bytes != EDDSA_POINT_LEN || pub_bytes > blen - p || body[p] != EDDSA_POINT) return -1;
    const uint8_t *pgp_pub = body + p + 1;
    p += pub_bytes;
    // S2K usage 0 means the secret MPI follows in the clear
    if (blen - p < 1 || body[p++] != 0) return -1;
    if (blen - p < 2) return -1;
    size_t sec_start = p;
    size_t sec_bytes = mpi_bytes(body + p);
    p += 2;
    if (sec_bytes > crypto_sign_SEEDBYTES || blen - p < sec_bytes + 2) return -1;
    // two-byte sum of the secret MPI, length prefix included
    uint32_t sum = 0;
    for (size_t i = sec_start; i < p + sec_bytes; i++) sum += body[i];
    if ((uint16_t)sum != load_be16(body + p + sec_bytes)) return -1;

    uint8_t seed[crypto_sign_SEEDBYTES] = {0};
    memcpy(seed + (sizeof seed - sec_bytes), body + p, sec_bytes);
    identity_keypair_t kp;
    kp.scalar = 0;
    crypto_sign_seed_keypair(kp.pub, kp.priv, seed);
    sodium_memzero(seed, sizeof seed);
    int rc = -1;
    if (memcmp(kp.pub, pgp_pub, ID_SIGN_PUB_LEN) == 0) { *out = kp; rc = 0; }
    sodium_memzero(&kp, sizeof kp);
    return rc;
}

// idkp is only changed on success, so a key that fails to load leaves the current identity as it was.
int pgp_import_secret_key_text(const char *text, identity_keypair_t *idkp) {
    static const char begin_marker[] = PGP_PRIVATE_BEGIN;
    static const char end_marker[] = PGP_PRIVATE_END;
    const char *begin = strstr(text, begin_marker);
    if (!begin) return -1;
    // The body starts on the line after BEGIN.
    const char *body_start = strchr(begin + sizeof begin_marker - 1, '\n');
    if (!body_start) return -1;
    body_start++;
    const char *end = strstr(body_start, end_marker);
    if (!end) return -1;

    uint8_t doc[PGP_DOC_MAX];
    long decoded = armor_decode(body_start, (size_t)(end - body_start), doc, sizeof doc);
    int rc = -1;
    if (decoded >= 4) {
        size_t doclen = (size_t)decoded, pos = 0;
        while (pos < doclen) {
            int tag; size_t blen;
            if (read_packet_header(doc, doclen, &pos, &tag, &blen) != 0) break;
            if (tag == TAG_SECRET_KEY) { rc = parse_secret_key_packet(doc + pos, blen, idkp); break; }
            pos += blen;
        }
    }
    sodium_memzero(doc, sizeof doc);
    return rc;
}
