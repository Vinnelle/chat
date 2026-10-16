// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the POSIX platform files share, on Linux and macOS: process.c, term.c, notify.c, files.c and
// sandbox.c. Each includes it first, since it sets the feature test macros the system headers read.
#ifndef CHAT_POSIX_H
#define CHAT_POSIX_H

#define _POSIX_C_SOURCE 200809L
// realpath, mkdtemp: X/Open, which musl only declares when asked for.
#define _XOPEN_SOURCE 700
// syscall (renameat2), which glibc and musl declare only beyond POSIX.
#define _DEFAULT_SOURCE
// O_NOATIME, which they declare only for GNU code.
#define _GNU_SOURCE
// macOS hides what isn't POSIX (gethostuuid among it) once _POSIX_C_SOURCE is set, without this.
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "platform/platform.h"
#include "common/util.h"
#include <spawn.h>

// Files and folders only this user can open, and all of a mode's permission bits.
#define MODE_PRIVATE_FILE 0600
#define MODE_PRIVATE_DIR 0700
#define MODE_BITS 07777
// A buffer for a path, and one for a PATH list.
#define PATH_BUF 4096
#define PATH_LIST_MAX 8192

struct platform_proc { pid_t pid; int exited, code; };

// process.c
int spawn_grouped(pid_t *pid, const char *path, const char *const argv[], const posix_spawn_file_actions_t *fa);

// files.c
const char *tempdir_base(void);

#endif
