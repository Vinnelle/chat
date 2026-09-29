// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_UPDATE_H
#define CHAT_UPDATE_H

#include "crypto/crypto.h"
#include <stddef.h>
#include <stdint.h>

#define UPDATE_MSG_MAX 200

// A SOCKS5 proxy (host:port) for every download, or NULL for none. Tor mode sets Tor's, so an
// update check doesn't show GitHub this machine's address.
void update_set_proxy(const char *socks);

int update_start(void);

int update_poll(char *msg, size_t cap);

int update_run(char *msg, size_t cap);

void update_cleanup_stale(void);

// The SHA-256 of the running executable, for peers to check against its release. -1 if unreadable.
int update_self_hash(uint8_t out[BUILD_HASH_LEN]);

// A chat_builds_fn. The first ask for a version fetches its SHA256SUMS and signature from the
// GitHub release in the background, through the update proxy, and checks the signature; until
// then it's CHAT_BUILDS_PENDING. The answer is kept until chat exits. One that couldn't be had is
// fetched again, after a while, when asked again.
int update_official_hashes(const char *version, uint8_t hashes[][BUILD_HASH_LEN], int max);

#endif
