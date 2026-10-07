// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_UTIL_H
#define CHAT_UTIL_H

#include <stddef.h>
#include <stdint.h>

void hex_encode(const uint8_t *in, size_t len, char *out);
int hex_decode(const char *in, size_t hexlen, uint8_t *out);
// Hex in groups of four digits, "a1b2 c3d4 ...", for codes people read out to each other.
#define HEX_GROUPS_LEN(n) ((n) * 2 + (n) / 2 + 1)
void hex_groups(const uint8_t *in, size_t len, char *out);

size_t clean_text(const char *in, char *out, size_t max_len);

// True if the text holds any character clean_text strips: control, C1 or bidi controls.
int has_control_chars(const char *in);

void random_session_id(char *out, size_t len);

size_t base64_encode(const uint8_t *in, size_t n, char *out);

// Strict: padded standard alphabet only. Returns the decoded length, or -1.
long base64_decode_strict(const char *in, size_t inlen, uint8_t *out, size_t cap);

// RFC 4648's base32, unpadded, as authenticator apps take a secret. out needs (n * 8 + 4) / 5 + 1.
size_t base32_encode(const uint8_t *in, size_t n, char *out);

// Code point at s[i] (n = length of s). *adv gets its length in bytes. A malformed byte is returned as is.
uint32_t utf8_decode(const char *s, size_t n, size_t i, size_t *adv);
// Writes cp as UTF-8 (1-4 bytes) and returns the length.
size_t utf8_put(uint32_t cp, char *out);

// Terminal columns the character at s[i] takes (0 for combining marks and zero-width characters,
// 2 for East Asian wide ones and emoji). *adv gets its length in bytes. A locale free version of
// wcwidth. A malformed byte or a control character counts as one column, since the UI shows a
// replacement character in its place.
int utf8_char_cols(const char *s, size_t n, size_t i, size_t *adv);
// How many bytes of s (at most len) fit in max_cols columns, stopping on a character boundary.
// *cols (if not NULL) gets the number of columns they take.
size_t utf8_fit_cols(const char *s, size_t len, int max_cols, int *cols);
int utf8_str_cols(const char *s);

void random_nickname(char *out, size_t out_cap);

double now_seconds(void);

void copy_str(char *dst, const char *src, size_t dstsize);

void current_hhmm(char out[6]);
// "YYYY-MM-DD HH:MM", local time.
void current_stamp(char out[17]);

#endif
