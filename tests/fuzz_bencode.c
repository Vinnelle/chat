// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Bencode parsing and DHT replies (bytes from any DHT node on the internet).
#include "common/bencode.h"
#include "crypto/crypto.h"
#include "transport/dht.h"
#include <stdlib.h>
#include <string.h>

static be_arena g_arena;

static void check(int ok) { if (!ok) abort(); }

// Every node reachable from v has to lie inside the part of the arena the parse used.
static void walk(const be_value *v, int depth) {
    check(depth <= BE_MAX_DEPTH + 1);
    check(v >= g_arena.pool && v < g_arena.pool + g_arena.used);
    switch (v->type) {
        case BE_INT: break;
        case BE_STR: check(v->slen == 0 || v->s != NULL); break;
        case BE_LIST:
            check(v->n == 0 || (v->items >= g_arena.pool && v->items + v->n <= g_arena.pool + g_arena.used));
            for (size_t i = 0; i < v->n; i++) walk(&v->items[i], depth + 1);
            break;
        case BE_DICT:
            for (size_t i = 0; i < v->n; i++) {
                check(v->items[i].type == BE_STR);
                walk(&v->items[i], depth + 1);
                walk(&v->dict_vals[i], depth + 1);
            }
            break;
        default: check(0);
    }
}

static int g_candidates;
static void on_candidate(void *ctx, addr_t a) { (void)ctx; (void)a; g_candidates++; }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    crypto_setup();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const be_value *v = be_parse(data, size, &g_arena);
    if (v) walk(v, 0);

    // Both lookups in flight, the IPv4 one with one query out, so a reply with t = "aa" from
    // `from` gets read, and IPv6 nodes in it land in the IPv6 lookup.
    static dht_state_t d;
    static const uint8_t infohash[20] = { 1, 2, 3 };
    dht_init(&d, infohash, 40000, 1, 1);
    d.lk[DHT_V4].active = 1;
    d.lk[DHT_V6].active = 1;
    addr_t from;
    uint8_t ip[4] = { 192, 0, 2, 1 };
    addr_set_v4(&from, ip, 6881);
    memcpy(d.lk[DHT_V4].inflight[0].tid, "aa", 2);
    d.lk[DHT_V4].inflight[0].addr = from;
    d.lk[DHT_V4].inflight[0].used = 1;
    dht_on_packet(&d, data, size, from, on_candidate, NULL);
    check(d.lk[DHT_V4].n_cands <= DHT_MAX_CANDS);
    check(d.lk[DHT_V6].n_cands <= DHT_MAX_CANDS);
    for (int i = 0; i < d.lk[DHT_V6].n_cands; i++) check(d.lk[DHT_V6].cands[i].addr.is_v6);
    return 0;
}
