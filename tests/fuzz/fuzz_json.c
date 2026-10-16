// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What relays and routers send: JSON from Nostr relays, and the HTTP replies and device
// descriptions a UPnP gateway (any device on the LAN that answers discovery) serves.
#include "common/json.h"
#include "transport/portmap.h"
#include "crypto/crypto.h"
#include <stdlib.h>
#include <string.h>

static js_arena g_arena;

static void check(int ok) { if (!ok) abort(); }

// Every node reachable from v has to lie inside the part of the arena the parse used, and every
// string inside the text buffer, NUL-terminated.
static void walk(const js_value *v, int depth) {
    check(depth <= JS_MAX_DEPTH + 1);
    check(v >= g_arena.pool && v < g_arena.pool + g_arena.used);
    switch (v->type) {
        case JS_NULL: case JS_BOOL: case JS_NUM: break;
        case JS_STR:
            check(v->s >= g_arena.text && v->s + v->slen < g_arena.text + JS_MAX_TEXT);
            check(v->s[v->slen] == '\0');
            break;
        case JS_ARR:
            check(v->n == 0 || (v->items >= g_arena.pool && v->items + v->n <= g_arena.pool + g_arena.used));
            for (size_t i = 0; i < v->n; i++) walk(&v->items[i], depth + 1);
            break;
        case JS_OBJ:
            for (size_t i = 0; i < v->n; i++) {
                check(v->items[i].type == JS_STR);
                walk(&v->items[i], depth + 1);
                walk(&v->vals[i], depth + 1);
            }
            break;
        default: check(0);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    crypto_setup();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const js_value *v = js_parse((const char *)data, size, &g_arena);
    if (v) {
        walk(v, 0);
        // What's parsed has to come back out through the escaper whole.
        for (size_t i = 0; v->type == JS_ARR && i < v->n; i++) {
            if (v->items[i].type != JS_STR) continue;
            static char out[JS_MAX_TEXT * 6 + 8];
            size_t n = js_put_str(out, 0, sizeof out, v->items[i].s, v->items[i].slen);
            check(n < sizeof out && out[0] == '"' && out[n - 1] == '"');
        }
    }

    static char text[65537], body[65537], service[96], url[256];
    size_t n = size < sizeof text - 1 ? size : sizeof text - 1;
    memcpy(text, data, n);
    text[n] = '\0';
    int status;
    if (portmap_http_body(text, n, &status, body, sizeof body) == 0) check(strlen(body) < sizeof body);
    if (portmap_parse_control_url(text, n, service, sizeof service, url, sizeof url) == 0)
        check(strlen(service) < sizeof service && strlen(url) < sizeof url);
    return 0;
}
