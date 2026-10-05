// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_CTAP2_H
#define CHAT_CTAP2_H

#include <stddef.h>
#include <stdint.h>

// FIDO2 (CTAP 2.0 and 2.1) with a security key, as much as a save needs: a credential with the
// hmac-secret extension, and the secret it gives for a salt. The secret only ever crosses the bus
// encrypted, under a key agreed with the security key for that one request.
//
// io sends one CTAPHID_CBOR message (a command byte, then its CBOR) and returns the answer's length
// (a status byte, then CBOR), or CTAP2_IO or CTAP2_CANCELLED with why set.
typedef long (*ctap2_io_fn)(void *ctx, const uint8_t *msg, size_t len, uint8_t *rsp, size_t cap, char *why,
                            size_t why_cap);

#define CTAP2_IO -1          // it went away or didn't answer, or answered with an error: why says
#define CTAP2_PIN -2         // it needs its PIN, or the one given is wrong: why says
#define CTAP2_NO_CRED -3     // none of the credentials is one this security key made
#define CTAP2_CANCELLED -4

#define CTAP2_CRED_MAX 1024
#define CTAP2_SECRET_LEN 32
#define CTAP2_SALT_LEN 32
// The relying party chat's credentials are for.
#define CTAP2_RP_ID "chat"

typedef struct {
    int hmac_secret;      // it has the extension
    int pin_set;          // a PIN is set
    int make_needs_pin;   // making a credential needs the PIN: a CTAP 2.0 key with one, or always UV
    int always_uv;        // everything needs it
    int protocols;        // the PIN/UV auth protocols it takes: bit 1 for protocol 1, bit 2 for protocol 2
    int token_perms;      // CTAP 2.1's tokens with permissions
} ctap2_info_t;

// 0, or CTAP2_IO.
int ctap2_get_info(ctap2_io_fn io, void *ctx, ctap2_info_t *info, char *why, size_t why_cap);

// A new credential, which the security key keeps nothing of: everything it needs to use it again
// is in cred. It takes a touch. pin is NULL unless info says the PIN is needed. 0, or a CTAP2_ code.
int ctap2_make(ctap2_io_fn io, void *ctx, const ctap2_info_t *info, const char *pin, uint8_t *cred,
               size_t *cred_len, char *why, size_t why_cap);

// Whether one of the credentials is this security key's, asked without a touch. 1 if one is, 0 if
// none is, and -1 if it can't say without one (CTAP 2.0 keys may not answer). which gets its index.
int ctap2_probe(ctap2_io_fn io, void *ctx, const uint8_t *const *creds, const size_t *lens, int n, int *which,
                char *why, size_t why_cap);

// The hmac-secret one of the credentials gives for salt, after a touch, with the PIN if uv is set (the
// secret then is a different one). which gets the credential's index. 0, or a CTAP2_ code.
int ctap2_secret(ctap2_io_fn io, void *ctx, const ctap2_info_t *info, const uint8_t *const *creds,
                 const size_t *lens, int n, const uint8_t salt[CTAP2_SALT_LEN], int uv, const char *pin,
                 uint8_t secret[CTAP2_SECRET_LEN], int *which, char *why, size_t why_cap);

#endif
