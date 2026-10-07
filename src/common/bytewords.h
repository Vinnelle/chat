// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_BYTEWORDS_H
#define CHAT_BYTEWORDS_H

#include <stddef.h>
#include <stdint.h>

// Bytes as Bytewords, one four-letter word each, in groups of four: "slot axis limp lava · brag ...",
// for reading a code out over a call. out holds BYTEWORDS_LEN(len).
#define BYTEWORDS_LEN(n) ((n) * 8 + 1)
void bytewords(const uint8_t *in, size_t len, char *out);

#endif
