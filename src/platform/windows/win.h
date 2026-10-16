// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the Windows platform files share: process.c, term.c, notify.c, files.c and sandbox.c.
#ifndef CHAT_WIN_H
#define CHAT_WIN_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "platform/platform.h"
#include "common/util.h"
#include <winsock2.h>
#include <windows.h>

// A path, as UTF-8 or as UTF-16, which never takes more units than UTF-8 takes bytes.
#define WPATH_MAX 1400

// process.c
SECURITY_ATTRIBUTES *thread_sa(void);

// files.c
int to_wide(const char *utf8, wchar_t *out, size_t cap);
int from_wide(const wchar_t *w, char *out, size_t cap);
int from_wide_path(const wchar_t *w, char *out, size_t cap);

#endif
