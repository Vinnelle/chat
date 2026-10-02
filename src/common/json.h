// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_JSON_H
#define CHAT_JSON_H

#include <stddef.h>
#include <stdint.h>

// Just enough JSON for Nostr relay messages: a strict parser into a fixed arena, and the
// escaping NIP-01 hashes events with.

#define JS_MAX_NODES 512
#define JS_MAX_DEPTH 16
#define JS_MAX_TEXT 131072

typedef enum { JS_NULL, JS_BOOL, JS_NUM, JS_STR, JS_ARR, JS_OBJ } js_type;

typedef struct js_value {
    js_type type;
    int b;
    int64_t i;           // JS_NUM: the value, when is_int
    int is_int;
    const char *s;       // JS_STR: decoded, NUL-terminated (may hold NUL itself: use slen)
    size_t slen;
    struct js_value *items;   // JS_ARR: elements; JS_OBJ: keys
    struct js_value *vals;    // JS_OBJ: values
    size_t n;
} js_value;

typedef struct {
    js_value pool[JS_MAX_NODES];
    size_t used;
    char text[JS_MAX_TEXT];
    size_t text_used;
} js_arena;

const js_value *js_parse(const char *data, size_t len, js_arena *arena);
const js_value *js_obj_get(const js_value *obj, const char *key);
// The string if v is one, otherwise NULL.
const char *js_str(const js_value *v);

// Appends s (len bytes) as a JSON string, quotes included, escaped as NIP-01 hashes it.
// Returns the new length, or cap (full) if it didn't fit.
size_t js_put_str(char *out, size_t pos, size_t cap, const char *s, size_t len);

#endif
