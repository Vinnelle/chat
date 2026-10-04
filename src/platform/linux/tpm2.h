// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TPM2_H
#define CHAT_TPM2_H

#include <stddef.h>
#include <stdint.h>

// A secret sealed with a TPM 2.0 that chat speaks to itself, for systems with no systemd
// credential service (runit, OpenRC, s6, systemd before 256). It's sealed under the TPM's storage
// key, made again from the owner seed each time (or, where Windows set the TPM up and kept its
// password, the key Windows keeps at 0x81000001). The secret crosses the bus encrypted, in a
// session salted to that key, and every answer's HMAC is checked. The sealed form names the key,
// so a cleared TPM, or something posing as the TPM, is refused.
#define TPM2_SECRET_LEN 32
#define TPM2_SEALED_MAX 1024

// Sends one command and reads its answer: the answer's length, or -1.
typedef long (*tpm2_transmit_fn)(void *ctx, const uint8_t *cmd, size_t len, uint8_t *rsp, size_t cap);

// The sealed form's length, or -1 with why set.
long tpm2_seal(tpm2_transmit_fn io, void *ctx, const uint8_t secret[TPM2_SECRET_LEN], uint8_t *out, size_t cap,
               char *why, size_t why_cap);
// 0, or -1 with why set.
int tpm2_unseal(tpm2_transmit_fn io, void *ctx, const uint8_t *sealed, size_t len, uint8_t secret[TPM2_SECRET_LEN],
                char *why, size_t why_cap);

#endif
