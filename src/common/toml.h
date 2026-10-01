// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TOML_H
#define CHAT_TOML_H

#include <stddef.h>

// The TOML the settings file needs: [table] headers, and keys whose values are one-line strings
// (basic or literal), booleans, integers, or arrays of strings.

#define TOML_KEY_MAX 64
#define TOML_STR_MAX 1024
#define TOML_ARRAY_MAX 16

typedef enum { TOML_STRING, TOML_BOOL, TOML_INT, TOML_ARRAY } toml_type;

typedef struct {
    toml_type type;
    const char *s;
    int b;
    long long i;
    const char *items[TOML_ARRAY_MAX];
    int n;
} toml_value;

typedef void (*toml_fn)(void *ctx, const char *table, const char *key, const toml_value *v);

// Calls fn for each key, with its table ("" before the first). Lines it can't read are skipped:
// returns how many, the first one's number in *bad_line.
int toml_parse(const char *text, toml_fn fn, void *ctx, int *bad_line);

// Appends s as a basic string, quotes included: the new length, or cap if it didn't fit.
size_t toml_put_str(char *out, size_t pos, size_t cap, const char *s);

#endif
