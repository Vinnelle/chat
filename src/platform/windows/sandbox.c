// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The sandbox, and the child pictures are decoded in, which are Linux only (posix/sandbox.c): here,
// stubs that say so.
#include "win.h"

unsigned platform_sandbox(const char *const run[], int n_run, const char *write_only, char *why, size_t cap) {
    (void)run; (void)n_run; (void)write_only;
    copy_str(why, "it's only on Linux", cap);
    return 0;
}

void platform_sandbox_narrow(void) {}

platform_proc_t *platform_spawn_self(const char *name, const char *arg, int *link) {
    (void)name; (void)arg; (void)link;
    return NULL;
}
int platform_parent_link(void) { return -1; }
void platform_set_name(const char *name) { (void)name; }
int platform_link_send(int link, const void *msg, size_t len) { (void)link; (void)msg; (void)len; return -1; }

long platform_isolated(void (*fn)(void *arg, int fd), void *arg, void *out, size_t cap, int timeout_ms) {
    (void)fn; (void)arg; (void)out; (void)cap; (void)timeout_ms;
    return -1;
}
int platform_isolated_put(int fd, const void *data, size_t len) { (void)fd; (void)data; (void)len; return -1; }
int platform_link_recv(int link, void *msg, size_t len) { (void)link; (void)msg; (void)len; return -1; }
void platform_link_close(int link) { (void)link; }
