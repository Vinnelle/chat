// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_PLATFORM_H
#define CHAT_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include "platform/net.h"

void platform_harden_process(void);

int platform_env_take(const char *name, char *out, size_t outlen);

int term_is_tty(void);
int term_stdout_is_tty(void);

int term_ansi_ok(void);

void platform_notify(const char *title, const char *body);

void platform_notify_shutdown(void);

int term_read_line(const char *prompt, char *out, size_t outlen);

int term_read_password(const char *prompt, char *out, size_t outlen);

typedef struct stdin_reader stdin_reader_t;
stdin_reader_t *stdin_reader_start(void);
void stdin_reader_stop(stdin_reader_t *r);

int stdin_reader_poll(stdin_reader_t *r, char *line, size_t linelen);

int term_raw_enable(void);
void term_raw_disable(void);

long term_read_raw(uint8_t *buf, size_t cap);

void platform_write_stdout(const char *buf, size_t len);

void term_get_size(int *rows, int *cols);

void term_watch_resize(void);

int term_resized(void);

#define PLATFORM_WAIT_MAX 128
void platform_wait(const sock_t *socks, int n, int *ready, int *stdin_ready, int timeout_ms);

typedef void (*dir_entry_cb)(void *ctx, const char *name, int is_dir);
int platform_list_dir(const char *path, dir_entry_cb cb, void *ctx);

const char *platform_home_dir(void);

// This OS install's machine id, as text: /etc/machine-id on Linux, MachineGuid on Windows. The
// OS makes it when it's installed and keeps it until it's reinstalled. It isn't secret: any
// program here can read it. Returns -1 if there's none.
int platform_machine_id(char *out, size_t cap);

int platform_spawn_thread(void (*fn)(void *), void *arg);

#include <stdio.h>
FILE *platform_fopen(const char *utf8_path, const char *mode);

FILE *platform_fopen_private(const char *utf8_path, const char *mode);

// Up to cap bytes of a regular file, read without blocking: a FIFO, a device or a folder is
// refused, since a path picked in the key browser or named by a Tor control port could be one
// (and a FIFO would hang chat). Returns the bytes read, or -1.
long platform_read_file(const char *utf8_path, void *buf, size_t cap);

int platform_remove(const char *utf8_path);

int platform_exe_path(char *out, size_t cap);

int platform_run_quiet(const char *const argv[]);

int platform_replace_exe(const char *new_path, const char *exe_path);

// Finds a program: path itself when given (not empty), else name on PATH (absolute entries
// only) and the usual install folders. It has to be a regular executable that nobody but its
// owner (root or this user) can change. Writes the full path; returns -1 if there's none.
int platform_find_program(const char *name, const char *path, char *out, size_t cap);

// A new folder only this user can open, under the per-user runtime folder (memory-backed on
// most Linux systems) or the temporary folder. Writes its path.
int platform_private_tempdir(const char *prefix, char *out, size_t cap);
// Deletes a folder and everything in it, never following links out of it.
int platform_remove_tree(const char *path);
// Deletes this user's folders from platform_private_tempdir(prefix) that a crash left behind:
// older than a minute, with lock_rel inside them not held by a running program.
void platform_remove_stale_tempdirs(const char *prefix, const char *lock_rel);

// A background process: argv[0] is a full path, never searched for. It gets no terminal and no
// handles of ours, and on Windows dies with this process. Its output goes to out_path (a new
// file only this user can read), or nowhere if that's NULL.
typedef struct platform_proc platform_proc_t;
platform_proc_t *platform_spawn(const char *const argv[], const char *out_path);
// 1 once it has exited (its code in *code), 0 while it runs.
int platform_proc_exited(platform_proc_t *p, int *code);
// Asks it to stop, waits up to wait_ms, then kills it; frees p.
void platform_proc_stop(platform_proc_t *p, int wait_ms);
long platform_pid(void);
void platform_sleep_ms(int ms);

// The IPv4 default gateway. Returns -1 when there is none.
int platform_default_gateway(uint8_t ip[4]);

// Hands the system's trusted root certificates to one of the callbacks: add_der for each
// certificate in a store, add_file for a PEM bundle (it returns 0 once one loads).
void platform_ca_roots(void (*add_der)(void *ctx, const uint8_t *der, size_t len),
                       int (*add_file)(void *ctx, const char *path), void *ctx);

#endif
