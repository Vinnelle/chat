// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Inflate (RFC 1950 and 1951), for PNG, into a buffer of exactly the size expected.
#include "common/image/decode.h"
#include <string.h>

#define MAXBITS 15
// The literal/length codes a dynamic block may have, the fixed code's (two of them never used), the
// distance codes, and the codes for code lengths.
enum { MAX_LCODES = 286, FIXED_LCODES = 288, MAX_DCODES = 30, CL_CODES = 19 };
enum { END_OF_BLOCK = 256, FIRST_LENGTH = 257 };
// The code length codes that repeat the last length, and that repeat a zero.
enum { CL_COPY = 16, CL_ZEROS = 17 };
enum { BLOCK_STORED, BLOCK_FIXED, BLOCK_DYNAMIC };

typedef struct {
    const uint8_t *in;
    size_t inlen, inpos;
    uint32_t bitbuf;
    int bitcnt;
    uint8_t *out;
    size_t outlen, outpos;
    int err;
} inflate_t;

typedef struct {
    short count[MAXBITS + 1];
    short symbol[FIXED_LCODES];
} huff_t;

static int bits(inflate_t *s, int need) {
    uint32_t val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->inpos >= s->inlen) { s->err = 1; return 0; }
        val |= (uint32_t)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = val >> need;
    s->bitcnt -= need;
    return (int)(val & ((1u << need) - 1));
}

// Canonical Huffman code from code lengths: 0 complete, above 0 incomplete, below 0 impossible.
static int construct(huff_t *h, const short *length, int n) {
    short offs[MAXBITS + 1];
    for (int len = 0; len <= MAXBITS; len++) h->count[len] = 0;
    for (int i = 0; i < n; i++) h->count[length[i]]++;
    if (h->count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len <= MAXBITS; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return left;
    }
    offs[1] = 0;
    for (int len = 1; len < MAXBITS; len++) offs[len + 1] = (short)(offs[len] + h->count[len]);
    for (int i = 0; i < n; i++) if (length[i] != 0) h->symbol[offs[length[i]]++] = (short)i;
    return left;
}

static int decode(inflate_t *s, const huff_t *h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= MAXBITS; len++) {
        code |= bits(s, 1);
        if (s->err) return -1;
        int count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static int stored(inflate_t *s) {
    s->bitbuf = 0;
    s->bitcnt = 0;
    if (s->inlen - s->inpos < 4) return -1;
    unsigned len = (unsigned)le16(s->in + s->inpos), nlen = (unsigned)le16(s->in + s->inpos + 2);
    s->inpos += 4;
    if (len != (~nlen & 0xffffu)) return -1;
    if (len > s->inlen - s->inpos || len > s->outlen - s->outpos) return -1;
    memcpy(s->out + s->outpos, s->in + s->inpos, len);
    s->inpos += len;
    s->outpos += len;
    return 0;
}

static int codes(inflate_t *s, const huff_t *lencode, const huff_t *distcode) {
    static const short lbase[MAX_LCODES - FIRST_LENGTH] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                                            35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    static const short lext[MAX_LCODES - FIRST_LENGTH] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
                                                           4, 4, 4, 4, 5, 5, 5, 5, 0 };
    static const short dbase[MAX_DCODES] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                                             1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    static const short dext[MAX_DCODES] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
                                            11, 11, 12, 12, 13, 13 };
    for (;;) {
        int symbol = decode(s, lencode);
        if (symbol < 0) return -1;
        if (symbol < END_OF_BLOCK) {
            if (s->outpos >= s->outlen) return -1;
            s->out[s->outpos++] = (uint8_t)symbol;
        } else if (symbol == END_OF_BLOCK) {
            return 0;
        } else {
            symbol -= FIRST_LENGTH;
            if (symbol >= MAX_LCODES - FIRST_LENGTH) return -1;
            size_t len = (size_t)lbase[symbol] + (size_t)bits(s, lext[symbol]);
            int ds = decode(s, distcode);
            if (ds < 0 || ds >= MAX_DCODES) return -1;
            size_t dist = (size_t)dbase[ds] + (size_t)bits(s, dext[ds]);
            if (s->err || dist > s->outpos || len > s->outlen - s->outpos) return -1;
            for (size_t i = 0; i < len; i++, s->outpos++) s->out[s->outpos] = s->out[s->outpos - dist];
        }
    }
}

static int fixed(inflate_t *s) {
    static huff_t lencode, distcode;
    static int built;
    if (!built) {
        // As RFC 1951 3.2.6 gives them.
        short lengths[FIXED_LCODES];
        int i = 0;
        for (; i < 144; i++) lengths[i] = 8;
        for (; i < 256; i++) lengths[i] = 9;
        for (; i < 280; i++) lengths[i] = 7;
        for (; i < FIXED_LCODES; i++) lengths[i] = 8;
        construct(&lencode, lengths, FIXED_LCODES);
        for (i = 0; i < MAX_DCODES; i++) lengths[i] = 5;
        construct(&distcode, lengths, MAX_DCODES);
        built = 1;
    }
    return codes(s, &lencode, &distcode);
}

static int dynamic(inflate_t *s) {
    static const short order[CL_CODES] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    short lengths[MAX_LCODES + MAX_DCODES];
    huff_t lencode, distcode;
    int nlen = bits(s, 5) + FIRST_LENGTH, ndist = bits(s, 5) + 1, ncode = bits(s, 4) + 4;
    if (s->err || nlen > MAX_LCODES || ndist > MAX_DCODES) return -1;
    int index;
    for (index = 0; index < ncode; index++) lengths[order[index]] = (short)bits(s, 3);
    for (; index < CL_CODES; index++) lengths[order[index]] = 0;
    if (s->err || construct(&lencode, lengths, CL_CODES) != 0) return -1;
    index = 0;
    while (index < nlen + ndist) {
        int symbol = decode(s, &lencode);
        if (symbol < 0) return -1;
        if (symbol < CL_COPY) {
            lengths[index++] = (short)symbol;
            continue;
        }
        short len = 0;
        if (symbol == CL_COPY) {
            if (index == 0) return -1;
            len = lengths[index - 1];
            symbol = 3 + bits(s, 2);
        } else if (symbol == CL_ZEROS) {
            symbol = 3 + bits(s, 3);
        } else {
            symbol = 11 + bits(s, 7);
        }
        if (s->err || index + symbol > nlen + ndist) return -1;
        while (symbol--) lengths[index++] = len;
    }
    if (lengths[END_OF_BLOCK] == 0) return -1;
    int err = construct(&lencode, lengths, nlen);
    if (err < 0 || (err > 0 && nlen - lencode.count[0] != 1)) return -1;
    err = construct(&distcode, lengths + nlen, ndist);
    if (err < 0 || (err > 0 && ndist - distcode.count[0] != 1)) return -1;
    return codes(s, &lencode, &distcode);
}

// The most bytes added up before b could pass 32 bits, and the largest prime below 65536.
#define ADLER_NMAX 5552
#define ADLER_MOD 65521

static uint32_t adler32(const uint8_t *p, size_t n) {
    uint32_t a = 1, b = 0;
    while (n > 0) {
        size_t k = n < ADLER_NMAX ? n : ADLER_NMAX;
        n -= k;
        while (k--) { a += *p++; b += a; }
        a %= ADLER_MOD;
        b %= ADLER_MOD;
    }
    return (b << 16) | a;
}

// A zlib stream: a 2-byte header, the deflated data, then the Adler-32 of what it inflates to.
enum { ZLIB_HEAD = 2, ZLIB_TRAILER = 4, ZLIB_DEFLATE = 8, ZLIB_MAX_WINDOW = 7, ZLIB_CHECK = 31, ZLIB_FDICT = 0x20 };

// A zlib stream that inflates to exactly outlen bytes. Anything more or less means it's damaged.
int zlib_inflate(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    if (inlen < ZLIB_HEAD + ZLIB_TRAILER) return -1;
    unsigned cmf = in[0], flg = in[1];
    if ((cmf & 15) != ZLIB_DEFLATE || (cmf >> 4) > ZLIB_MAX_WINDOW || load_be16(in) % ZLIB_CHECK != 0 || (flg & ZLIB_FDICT))
        return -1;
    inflate_t s = { in, inlen, ZLIB_HEAD, 0, 0, out, outlen, 0, 0 };
    int last;
    do {
        last = bits(&s, 1);
        int type = bits(&s, 2);
        if (s.err) return -1;
        int rc = type == BLOCK_STORED ? stored(&s) : type == BLOCK_FIXED ? fixed(&s) : type == BLOCK_DYNAMIC ? dynamic(&s) : -1;
        if (rc != 0 || s.err) return -1;
    } while (!last);
    if (s.outpos != outlen || s.inlen - s.inpos < ZLIB_TRAILER) return -1;
    return !CHECK_SUMS || adler32(out, outlen) == load_be32(in + s.inpos) ? 0 : -1;
}
