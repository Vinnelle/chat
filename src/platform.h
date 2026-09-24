// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_PLATFORM_H
#define CHAT_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include "net.h"

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

void platform_wait(const sock_t *socks, int n, int *ready, int *stdin_ready, int timeout_ms);

typedef void (*dir_entry_cb)(void *ctx, const char *name, int is_dir);
int platform_list_dir(const char *path, dir_entry_cb cb, void *ctx);

const char *platform_home_dir(void);

int platform_spawn_thread(void (*fn)(void *), void *arg);

#include <stdio.h>
FILE *platform_fopen(const char *utf8_path, const char *mode);

FILE *platform_fopen_private(const char *utf8_path, const char *mode);

#endif
