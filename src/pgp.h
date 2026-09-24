// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_PGP_H
#define CHAT_PGP_H

#include "crypto.h"
#include <stddef.h>
#include <stdint.h>

#define PGP_FP_LEN 20
#define PGP_ARMOR_MAX 2048

void pgp_export_public_key(const identity_keypair_t *idkp, const char *nick,
                            char *out, size_t out_cap, uint8_t fingerprint[PGP_FP_LEN]);

int pgp_import_secret_key(const char *path, identity_keypair_t *idkp);

int pgp_import_secret_key_text(const char *armored, identity_keypair_t *idkp);

#endif
