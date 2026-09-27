// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_UPDATE_H
#define CHAT_UPDATE_H

#include <stddef.h>

#define UPDATE_MSG_MAX 200

// A SOCKS5 proxy (host:port) for every download, or NULL for none. Tor mode sets Tor's, so an
// update check doesn't show GitHub this machine's address.
void update_set_proxy(const char *socks);

int update_start(void);

int update_poll(char *msg, size_t cap);

int update_run(char *msg, size_t cap);

void update_cleanup_stale(void);

#endif
