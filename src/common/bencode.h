// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_BENCODE_H
#define CHAT_BENCODE_H

#include <stddef.h>
#include <stdint.h>

#define BE_MAX_NODES 512
#define BE_MAX_DEPTH 16

typedef enum { BE_INT, BE_STR, BE_LIST, BE_DICT } be_type;

typedef struct be_value {
    be_type type;
    int64_t i;
    const uint8_t *s; size_t slen;
    struct be_value *items; size_t n;
    struct be_value *dict_vals;
} be_value;

typedef struct {
    be_value pool[BE_MAX_NODES];
    size_t used;
} be_arena;

const be_value *be_parse(const uint8_t *data, size_t len, be_arena *arena);

const be_value *be_dict_get(const be_value *dict, const char *key);

#endif
