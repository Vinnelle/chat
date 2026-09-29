// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_UPDATE_H
#define CHAT_UPDATE_H

#include "core/chat.h"
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

// The release key (minisign, base64) built in from minisign.pub, or "" if there was none.
const char *update_release_key(void);

// This build as peers are told it: the SHA-256 of the running executable, less the signed list
// of its release's binaries that a release appends, and that list. Returns -1 if unreadable.
int update_self_build(chat_build_t *b);

#endif
