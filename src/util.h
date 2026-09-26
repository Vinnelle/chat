// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_UTIL_H
#define CHAT_UTIL_H

#include <stddef.h>
#include <stdint.h>

void hex_encode(const uint8_t *in, size_t len, char *out);
int hex_decode(const char *in, size_t hexlen, uint8_t *out);

size_t clean_text(const char *in, char *out, size_t max_len);

// True if the text holds any character clean_text strips: control, C1 or bidi controls.
int has_control_chars(const char *in);

void random_session_id(char *out, size_t len);

size_t base64_encode(const uint8_t *in, size_t n, char *out);

// Strict: padded standard alphabet only. Returns the decoded length, or -1.
long base64_decode_strict(const char *in, size_t inlen, uint8_t *out, size_t cap);

// Code point at s[i] (n = length of s); *adv gets its byte length. A malformed byte comes back as itself.
uint32_t utf8_decode(const char *s, size_t n, size_t i, size_t *adv);
// Writes cp as UTF-8 (1-4 bytes) and returns the length.
size_t utf8_put(uint32_t cp, char *out);

void random_nickname(char *out, size_t out_cap);

double now_seconds(void);

void copy_str(char *dst, const char *src, size_t dstsize);

void current_hhmm(char out[6]);

#endif
