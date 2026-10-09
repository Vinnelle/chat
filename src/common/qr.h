// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_QR_H
#define CHAT_QR_H

#include <stdint.h>

// A QR code (ISO/IEC 18004) for text, in byte mode at error correction level M, version 1 to 10:
// up to 213 bytes, plenty for an otpauth:// link.
#define QR_MAX_VERSION 10
#define QR_SIZE(ver) ((ver) * 4 + 17)
#define QR_MAX_SIZE QR_SIZE(QR_MAX_VERSION)
// Returns the modules on each side, with module (x, y) dark where out[y * size + x] is 1, or -1 if
// the text doesn't fit. A scanner also needs 4 light modules around it.
int qr_encode(const char *text, uint8_t out[QR_MAX_SIZE * QR_MAX_SIZE]);

#endif
