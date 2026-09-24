// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_DHT_H
#define CHAT_DHT_H

#include "net.h"
#include <stdint.h>

#if defined(__STDC_NO_ATOMICS__)
typedef volatile int dht_flag_t;
#define DHT_LOAD(p) (*(p))
#define DHT_STORE(p, v) (*(p) = (v))
#else
#include <stdatomic.h>
typedef _Atomic int dht_flag_t;
#define DHT_LOAD(p) atomic_load_explicit((p), memory_order_acquire)
#define DHT_STORE(p, v) atomic_store_explicit((p), (v), memory_order_release)
#endif

#define DHT_MAX_CANDS 128
#define DHT_MAX_INFLIGHT 8
#define DHT_MAX_QUERIED 80
#define DHT_RANK_TOP 12
#define DHT_ANNOUNCE_TOP 8
#define DHT_LOOKUP_TIMEOUT 15.0
#define DHT_RELOOKUP_IDLE 30.0
#define DHT_RELOOKUP_CONNECTED 300.0
#define DHT_BOOT_MAX 8
#define DHT_RESOLVE_BACKOFF_MAX 300.0

typedef struct {
    addr_t addr;
    uint8_t node_id[20];
    int have_id;
    int queried;
    uint8_t token[64];
    size_t token_len;
    int have_token;
} dht_cand_t;

typedef struct {
    uint8_t tid[2];
    addr_t addr;
    double sent_at;
    int used;
} dht_inflight_t;

typedef struct {
    dht_cand_t cands[DHT_MAX_CANDS];
    int n_cands;
    dht_inflight_t inflight[DHT_MAX_INFLIGHT];
    double t0;
    int found;
    int active;
    int top[DHT_RANK_TOP];
    int n_top;
    int dirty;
} dht_lookup_t;

typedef struct {
    addr_t boot[DHT_BOOT_MAX];
    dht_flag_t n_boot;
    dht_flag_t resolving;
    double next_resolve;
    int resolve_tries;
    uint8_t node_id[20];
    uint8_t infohash[20];
    uint16_t my_port;
    dht_lookup_t lk;
    double next_lookup;
    int told_dht;
    int peers_now;
} dht_state_t;

void dht_init(dht_state_t *d, const uint8_t infohash[20], uint16_t my_port);
void dht_start_bootstrap_resolve(dht_state_t *d);

int dht_step(dht_state_t *d, sock_t sock, double now,
             void (*on_candidate)(void *ctx, addr_t a), void *ctx);

void dht_on_packet(dht_state_t *d, const uint8_t *data, size_t len, addr_t from,
                    void (*on_candidate)(void *ctx, addr_t a), void *ctx);

int dht_queried_count(const dht_state_t *d);
int dht_found_count(const dht_state_t *d);
int dht_bootstrap_ready(const dht_state_t *d);

#endif
