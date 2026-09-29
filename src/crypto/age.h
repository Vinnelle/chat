// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_AGE_H
#define CHAT_AGE_H

#include "crypto/crypto.h"
#include <stddef.h>
#include <stdint.h>

#define AGE_RECIPIENT_STRLEN 62

// "AGE-SECRET-KEY-1" and the key in upper-case bech32, as age-keygen writes it.
#define AGE_SECRET_KEY_STRLEN 74

void age_export_recipient(const identity_keypair_t *idkp, char out[AGE_RECIPIENT_STRLEN + 1]);

// The first AGE secret key in text (an identity file, comments and all), or in the file at path.
// idkp changes only on success.
int age_import_secret_key_text(const char *text, identity_keypair_t *idkp);
int age_import_secret_key(const char *path, identity_keypair_t *idkp);

#endif
