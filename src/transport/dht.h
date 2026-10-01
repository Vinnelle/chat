// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_DHT_H
#define CHAT_DHT_H

#include "platform/net.h"
#include "crypto/crypto.h"
#include <stdint.h>

#define DHT_MAX_CANDS 128
#define DHT_MAX_INFLIGHT 8
#define DHT_MAX_QUERIED 80
#define DHT_RANK_TOP 12
#define DHT_ANNOUNCE_TOP 8
#define DHT_LOOKUP_TIMEOUT 15.0
#define DHT_RELOOKUP_IDLE 30.0
#define DHT_RELOOKUP_CONNECTED 300.0
#define DHT_BOOT_MAX 12
#define DHT_RESOLVE_BACKOFF_MAX 300.0
// For this long either side of the hour, the other hour's lookup key is looked up (and announced
// under) as well: clocks differ, and members only move to the new key at their next lookup.
#define DHT_EPOCH_OVERLAP 600
// Nodes that answered lately, a list per family: lookups start from these, and only go to the
// bootstrap servers while fewer than DHT_KNOWN_ENOUGH are known.
#define DHT_KNOWN_MAX 32
#define DHT_KNOWN_ENOUGH 8

// How the DHT's datagrams leave: to an address, or (host not NULL) to a name that a proxy looks
// up at its end, so nothing asks local DNS.
typedef void (*dht_send_fn)(void *ctx, const void *data, size_t len, const addr_t *to, const char *host, uint16_t port);

typedef struct {
    addr_t addr;
    uint8_t node_id[20];
    int have_id;
    int queried;
    // 1 + the bootstrap server's index when this one is only a name, for the proxy to look up.
    int named;
    uint8_t token[64];
    size_t token_len;
    int have_token;
} dht_cand_t;

typedef struct {
    uint8_t tid[2];
    addr_t addr;
    int named;   // sent to a name: whatever address answers with its transaction id is it
    double sent_at;
    int used;
} dht_inflight_t;

typedef struct {
    int used;
    addr_t addr;
    uint8_t node_id[20];
    double ok_at;
} dht_known_t;

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

// One lookup per address family: IPv4 nodes make up one DHT, IPv6 nodes another (BEP 32).
#define DHT_V4 0
#define DHT_V6 1

typedef struct dht_boot_job dht_boot_job_t;

typedef struct {
    addr_t boot[DHT_BOOT_MAX];
    int n_boot;
    // The bootstrap servers' names are looked up on a thread. The session can end, or turn the
    // DHT off and on, first: the thread only ever writes to its job, and whichever side finishes
    // last frees it.
    dht_boot_job_t *job;
    double next_resolve;
    int resolve_tries;
    // The node id of the round under way. Each hour's lookup key has an id of its own, made at
    // random, so nothing in the DHT's messages ties one hour's lookups to another's.
    uint8_t node_id[20];
    struct { int set; long long epoch; uint8_t id[20]; } ids[2];
    // The room's DHT key, and the hourly lookup key of the round under way. Near the hour's change
    // a second round follows for the other hour's key (alt_epoch).
    uint8_t key[DHT_KEY_LEN];
    uint8_t infohash[20];
    long long alt_epoch;
    int alt_pending;
    dht_known_t known[2][DHT_KNOWN_MAX];
    dht_send_fn send;
    void *send_ctx;
    // Bootstrap servers go out by name, never through local DNS (a proxy resolves them).
    int names_remote;
    uint16_t my_port;
    // Announce my_port as given (a port mapping's external port) instead of the source port the
    // node sees.
    int explicit_port;
    int want[2];
    dht_lookup_t lk[2];
    double next_lookup;
    int told_dht;
    int peers_now;
} dht_state_t;

void dht_init(dht_state_t *d, const uint8_t key[DHT_KEY_LEN], uint16_t my_port, int want_v4, int want_v6);
// Where the DHT sends (it sends nothing until this is set). names_remote: the bootstrap servers go
// out as names, for the other end to look up, instead of through local DNS.
void dht_set_output(dht_state_t *d, dht_send_fn send, void *ctx, int names_remote);
void dht_start_bootstrap_resolve(dht_state_t *d);
// Lets go of a bootstrap lookup still running (it frees itself) and wipes the key. Call before
// dht_init on a state that was used, and when the session ends.
void dht_stop(dht_state_t *d);
// Looks the bootstrap servers up again, for the families wanted now.
void dht_rebootstrap(dht_state_t *d);

int dht_step(dht_state_t *d, double now);

void dht_on_packet(dht_state_t *d, const uint8_t *data, size_t len, addr_t from,
                    void (*on_candidate)(void *ctx, addr_t a), void *ctx);

// Totals over both families, or one family's with dht_*_count_fam.
int dht_queried_count(const dht_state_t *d);
int dht_found_count(const dht_state_t *d);
int dht_queried_count_fam(const dht_state_t *d, int fam);
int dht_found_count_fam(const dht_state_t *d, int fam);

#endif
