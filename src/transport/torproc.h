// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TORPROC_H
#define CHAT_TORPROC_H

#include <stddef.h>

// A tor of chat's own, for Tor mode when no usable tor is running. It runs from a private
// temporary folder (its data, cookie and log) with an empty configuration, so nothing from
// /etc/tor/torrc applies. It listens for SOCKS and control connections on random ports on
// 127.0.0.1 only, and takes control logins only with the cookie in that folder. It quits if chat
// dies (tor watches chat's process id; on Windows a job object ends it), and chat deletes the
// folder when it stops it.

typedef struct torproc torproc_t;

typedef enum { TORPROC_STARTING, TORPROC_READY, TORPROC_EXITED } torproc_state_t;

// Starts tor from program (a full path). Returns NULL with the reason in err.
torproc_t *torproc_start(const char *program, char *err, size_t cap);
torproc_state_t torproc_poll(torproc_t *p);
const char *torproc_socks(const torproc_t *p);
const char *torproc_control(const torproc_t *p);
// Bootstrap progress in percent from tor's log, or -1 before the first report.
int torproc_bootstrap(torproc_t *p);
// tor's version line ("" until it has logged one), and the last warning or error it logged.
const char *torproc_version(torproc_t *p);
void torproc_problem(torproc_t *p, char *out, size_t cap);
// Stops tor and deletes its folder.
void torproc_stop(torproc_t *p);

#endif
