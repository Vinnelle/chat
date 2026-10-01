// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_UPDATE_H
#define CHAT_UPDATE_H

#include "core/chat.h"
#include <stddef.h>
#include <stdint.h>

#define UPDATE_MSG_MAX 200
#define UPDATE_LOG_MAX 24
#define UPDATE_LINE_MAX 160

typedef enum { UPDATE_LINE_DETAIL = 0, UPDATE_LINE_INFO, UPDATE_LINE_GOOD, UPDATE_LINE_BAD } update_line_kind_t;

// Where an update has got, for its box: what it has done so far (the console, oldest first), how
// far along it is in thousandths, the size of what's come against the whole while it downloads
// ("8.4 MB of 20.1 MB", else ""), and the step it's on, put plainly.
typedef struct {
    int started;       // a run since chat began; the rest is about the last one
    int running;
    int ok;            // finished: installed, or already up to date
    int permille;
    char amount[48];
    char step[96];
    int n_log;
    char log[UPDATE_LOG_MAX][UPDATE_LINE_MAX];
    unsigned char kind[UPDATE_LOG_MAX];
} update_view_t;

// A SOCKS5 proxy (host:port) for every download, or NULL for none. Tor mode sets Tor's, so an
// update check doesn't show GitHub this machine's address.
void update_set_proxy(const char *socks);

int update_start(void);

int update_poll(char *msg, size_t cap);

int update_run(char *msg, size_t cap);

// A copy of where the current (or last) update has got.
void update_view(update_view_t *v);

void update_cleanup_stale(void);

// The release key (minisign, base64) built in from minisign.pub, or "" if there was none.
const char *update_release_key(void);

// This build as peers are told it: the SHA-256 of the running executable, less the signed list
// of its release's binaries that a release appends, and that list. Returns -1 if unreadable.
int update_self_build(chat_build_t *b);

#endif
