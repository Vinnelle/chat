// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_UTIL_H
#define CHAT_UTIL_H

#include <stddef.h>
#include <stdint.h>

void hex_encode(const uint8_t *in, size_t len, char *out);
int hex_decode(const char *in, size_t hexlen, uint8_t *out);

size_t clean_text(const char *in, char *out, size_t max_len);

void random_session_id(char *out, size_t len);

size_t base64_encode(const uint8_t *in, size_t n, char *out);

void random_nickname(char *out, size_t out_cap);

double now_seconds(void);

void copy_str(char *dst, const char *src, size_t dstsize);

void current_hhmm(char out[6]);

#endif
