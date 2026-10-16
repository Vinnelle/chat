// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The settings file, as a hand could have edited it.
#include "common/toml.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void check(int ok) { if (!ok) abort(); }

static char g_first[TOML_STR_MAX];
static int g_have_first;

static void got(void *ctx, const char *table, const char *key, const toml_value *v) {
    (void)ctx;
    check(strlen(key) < TOML_KEY_MAX && strlen(table) < TOML_KEY_MAX);
    if (v->type == TOML_STRING) {
        check(strlen(v->s) < TOML_STR_MAX);
        if (!g_have_first) { strcpy(g_first, v->s); g_have_first = 1; }
    }
    if (v->type == TOML_ARRAY) {
        check(v->n <= TOML_ARRAY_MAX);
        for (int k = 0; k < v->n; k++) check(strlen(v->items[k]) < TOML_STR_MAX);
    }
}

static void again(void *ctx, const char *table, const char *key, const toml_value *v) {
    (void)table; (void)key;
    check(v->type == TOML_STRING && strcmp(v->s, ctx) == 0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *text = malloc(size + 1);
    if (!text) return 0;
    memcpy(text, data, size);
    text[size] = '\0';
    g_have_first = 0;
    toml_parse(text, got, NULL, NULL);
    free(text);
    // A string read comes back the same through the writer.
    if (g_have_first) {
        static char line[TOML_STR_MAX * 6 + 8] = "k = ";
        size_t n = toml_put_str(line, 4, sizeof line, g_first);
        check(n < sizeof line);
        check(toml_parse(line, again, g_first, NULL) == 0);
    }
    return 0;
}
