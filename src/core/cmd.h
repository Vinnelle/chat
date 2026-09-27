// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_CMD_H
#define CHAT_CMD_H

#include <stddef.h>

#define CMD_WORD_MAX 32

typedef enum { CMD_OK = 0, CMD_QUIT, CMD_UNKNOWN } cmd_result_t;

// One entry of a command table. Tables end with an entry whose name is NULL.
typedef struct {
    const char *name;
    const char *aliases;   // space-separated alternative names, or NULL
    const char *args;      // argument synopsis for help, or NULL
    const char *help;
    cmd_result_t (*run)(void *ctx, const char *arg);
} command_t;

// Splits "word rest..." (no leading prefix). Returns the argument with leading spaces skipped, never NULL.
const char *cmd_parse(const char *line, char word[CMD_WORD_MAX]);

const command_t *cmd_find(const command_t *table, const char *word);

// First command name across the NULL-terminated list of tables that extends `typed`, or NULL.
const char *cmd_complete(const command_t *const *tables, const char *typed);

void cmd_format_help(const command_t *cmd, char prefix, char *out, size_t cap);

#endif
