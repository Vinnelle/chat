// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TORPROC_H
#define CHAT_TORPROC_H

#include <stddef.h>
#include <stdint.h>

// A tor of chat's own, for Tor mode when no usable tor is running. It runs from a private
// temporary folder (its data and log) with an empty configuration, so nothing from
// /etc/tor/torrc applies. It listens for SOCKS and control connections on random ports on
// 127.0.0.1 only, and takes control logins only with a password chat makes as it starts it, which
// tor is given only the hash of. It quits if chat dies (tor watches chat's process id; on Windows
// a job object ends it), and chat deletes the folder when it stops it.

typedef struct torproc torproc_t;

typedef enum { TORPROC_STARTING, TORPROC_READY, TORPROC_EXITED } torproc_state_t;

// hold_network: tor starts with DisableNetwork, and reaches the Tor network only once
// torproc_setconf has given it what it needs first (bridges). state: tor's state and directory from
// an earlier run (torproc_state), put in its data folder before it starts, so it keeps its entry
// guards and needn't fetch the directory again.
typedef struct {
    int hold_network;
    const uint8_t *state;
    size_t state_len;
} torproc_opts_t;

// Starts tor from program (a full path). Returns NULL with the reason in err.
torproc_t *torproc_start(const char *program, const torproc_opts_t *o, char *err, size_t cap);
// Once it's READY: logs in to its control port, sets conf ("UseBridges=1 Bridge=\"...\" ...", as
// SETCONF takes it), then lets it reach the network. Over the control port, so none of it is on
// tor's command line, where anyone can read it, or on disk. 0, or -1 with why.
int torproc_setconf(torproc_t *p, const char *conf, char *why, size_t cap);
torproc_state_t torproc_poll(torproc_t *p);
const char *torproc_socks(const torproc_t *p);
const char *torproc_control(const torproc_t *p);
// The control port's password. Never on disk: the control port shows which onion services chat
// publishes and connects to, and a cookie file could be read by any program running as this user.
const char *torproc_password(const torproc_t *p);
// Bootstrap progress in percent from tor's log, or -1 before the first report.
int torproc_bootstrap(torproc_t *p);
// tor's version line ("" until it has logged one), and the last warning or error it logged.
const char *torproc_version(torproc_t *p);
void torproc_problem(torproc_t *p, char *out, size_t cap);
// Stops tor and deletes its folder.
void torproc_stop(torproc_t *p);
// Stops tor, letting it write its state first, then gives that and its copy of the directory, packed
// for torproc_opts_t's state (malloc'd, or NULL if it can't), and deletes its folder.
void torproc_finish(torproc_t *p, uint8_t **state, size_t *len);

#endif
