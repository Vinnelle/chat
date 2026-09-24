// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "dht.h"
#include "bencode.h"
#include "util.h"
#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "platform.h"

static const struct { const char *host; uint16_t port; } BOOTSTRAP[4] = {
    { "router.bittorrent.com", 6881 },
    { "dht.transmissionbt.com", 6881 },
    { "router.utorrent.com", 6881 },
    { "dht.libtorrent.org", 25401 },
};

void dht_init(dht_state_t *d, const uint8_t infohash[20], uint16_t my_port) {
    memset(d, 0, sizeof *d);
    memcpy(d->infohash, infohash, 20);
    d->my_port = my_port;
    gen_random(d->node_id, 20);
    DHT_STORE(&d->n_boot, 0);
    DHT_STORE(&d->resolving, 0);
}

typedef struct { dht_state_t *d; } resolve_arg_t;

static void resolve_thread(void *arg) {
    dht_state_t *d = ((resolve_arg_t *)arg)->d;
    addr_t got[DHT_BOOT_MAX];
    int n = 0;
    for (int i = 0; i < 4 && n < DHT_BOOT_MAX; i++) {
        addr_t found[ADDR_RESOLVE_MAX];
        int k = addr_resolve_all(BOOTSTRAP[i].host, BOOTSTRAP[i].port, found, ADDR_RESOLVE_MAX);
        for (int j = 0; j < k && n < DHT_BOOT_MAX; j++) {
            if (!addr_is_v4(found[j])) continue;
            int dup = 0;
            for (int m = 0; m < n; m++) if (addr_equal(got[m], found[j])) { dup = 1; break; }
            if (!dup) got[n++] = found[j];
        }
    }
    if (n > 0) memcpy(d->boot, got, sizeof(addr_t) * (size_t)n);
    DHT_STORE(&d->n_boot, n);
    DHT_STORE(&d->resolving, 0);
    free(arg);
}

void dht_start_bootstrap_resolve(dht_state_t *d) {
    if (DHT_LOAD(&d->resolving)) return;
    resolve_arg_t *arg = malloc(sizeof *arg);
    if (!arg) return;
    arg->d = d;
    DHT_STORE(&d->resolving, 1);
    if (platform_spawn_thread(resolve_thread, arg) != 0) { DHT_STORE(&d->resolving, 0); free(arg); }
}

int dht_bootstrap_ready(const dht_state_t *d) {
    return DHT_LOAD(&((dht_state_t *)d)->n_boot) > 0;
}

static void xor_distance(const uint8_t a[20], const uint8_t b[20], uint8_t out[20]) {
    for (int i = 0; i < 20; i++) out[i] = a[i] ^ b[i];
}

static int cand_cmp_dist(const uint8_t infohash[20], const dht_cand_t *x, const dht_cand_t *y) {
    if (!x->have_id && !y->have_id) return 0;
    if (!x->have_id) return 1;
    if (!y->have_id) return -1;
    uint8_t dx[20], dy[20];
    xor_distance(x->node_id, infohash, dx);
    xor_distance(y->node_id, infohash, dy);
    return memcmp(dx, dy, 20);
}

static int rank_select(dht_lookup_t *lk, const uint8_t infohash[20], int top_n, int *out, int need_token) {
    int n = 0;
    for (int i = 0; i < lk->n_cands; i++) {
        if (need_token && !lk->cands[i].have_token) continue;
        int pos = n;
        while (pos > 0 && cand_cmp_dist(infohash, &lk->cands[out[pos - 1]], &lk->cands[i]) > 0) pos--;
        if (pos >= top_n) continue;
        if (n < top_n) n++;
        for (int j = n - 1; j > pos; j--) out[j] = out[j - 1];
        out[pos] = i;
    }
    return n;
}

static int ranked_top(dht_lookup_t *lk, const uint8_t infohash[20], const int **out) {
    if (lk->dirty) {
        lk->n_top = rank_select(lk, infohash, DHT_RANK_TOP, lk->top, 0);
        lk->dirty = 0;
    }
    *out = lk->top;
    return lk->n_top;
}

static dht_cand_t *find_or_add_cand(dht_lookup_t *lk, addr_t a) {
    for (int i = 0; i < lk->n_cands; i++)
        if (addr_equal(lk->cands[i].addr, a)) return &lk->cands[i];
    if (lk->n_cands >= DHT_MAX_CANDS) return NULL;
    dht_cand_t *c = &lk->cands[lk->n_cands++];
    memset(c, 0, sizeof *c);
    c->addr = a;
    lk->dirty = 1;
    return c;
}

static size_t append_raw(uint8_t *buf, size_t pos, const void *data, size_t len) {
    memcpy(buf + pos, data, len);
    return pos + len;
}
static size_t append_str(uint8_t *buf, size_t pos, const char *s) { return append_raw(buf, pos, s, strlen(s)); }
static size_t append_bstr(uint8_t *buf, size_t pos, const uint8_t *data, size_t len) {
    char lenbuf[16];
    int n = snprintf(lenbuf, sizeof lenbuf, "%zu:", len);
    pos = append_raw(buf, pos, lenbuf, (size_t)n);
    return append_raw(buf, pos, data, len);
}
static size_t append_int(uint8_t *buf, size_t pos, long v) {
    char b[24];
    int n = snprintf(b, sizeof b, "i%lde", v);
    return append_raw(buf, pos, b, (size_t)n);
}

static void send_get_peers(dht_state_t *d, sock_t sock, addr_t to, const uint8_t tid[2]) {
    uint8_t buf[128];
    size_t p = 0;
    p = append_str(buf, p, "d1:ad2:id");
    p = append_bstr(buf, p, d->node_id, 20);
    p = append_str(buf, p, "9:info_hash");
    p = append_bstr(buf, p, d->infohash, 20);
    p = append_str(buf, p, "e1:q9:get_peers1:t");
    p = append_bstr(buf, p, tid, 2);
    p = append_str(buf, p, "1:y1:qe");
    net_send(sock, buf, p, to);
}

static void send_announce(dht_state_t *d, sock_t sock, addr_t to, const uint8_t tid[2],
                           const uint8_t *token, size_t token_len) {
    uint8_t buf[256];
    size_t p = 0;
    p = append_str(buf, p, "d1:ad2:id");
    p = append_bstr(buf, p, d->node_id, 20);
    p = append_str(buf, p, "12:implied_porti1e9:info_hash");
    p = append_bstr(buf, p, d->infohash, 20);
    p = append_str(buf, p, "4:port");
    p = append_int(buf, p, (long)d->my_port);
    p = append_str(buf, p, "5:token");
    p = append_bstr(buf, p, token, token_len);
    p = append_str(buf, p, "1:q13:announce_peer1:t");
    p = append_bstr(buf, p, tid, 2);
    p = append_str(buf, p, "1:y1:qe");
    net_send(sock, buf, p, to);
}

static void start_lookup(dht_state_t *d, double now) {
    memset(&d->lk, 0, sizeof d->lk);
    d->lk.t0 = now;
    d->lk.active = 1;
    d->lk.dirty = 1;
    int n_boot = DHT_LOAD(&d->n_boot);
    if (n_boot > DHT_BOOT_MAX) n_boot = DHT_BOOT_MAX;
    for (int i = 0; i < n_boot; i++) find_or_add_cand(&d->lk, d->boot[i]);
}

static void maybe_reresolve(dht_state_t *d, double now) {
    if (DHT_LOAD(&d->resolving) || DHT_LOAD(&d->n_boot) > 0) return;
    if (now < d->next_resolve) return;
    int shift = d->resolve_tries < 6 ? d->resolve_tries : 6;
    double delay = 5.0 * (double)(1u << shift);
    if (delay > DHT_RESOLVE_BACKOFF_MAX) delay = DHT_RESOLVE_BACKOFF_MAX;
    d->resolve_tries++;
    d->next_resolve = now + delay;
    dht_start_bootstrap_resolve(d);
}

int dht_step(dht_state_t *d, sock_t sock, double now,
             void (*on_candidate)(void *ctx, addr_t a), void *ctx) {
    (void)on_candidate; (void)ctx;
    if (!d->lk.active) {
        maybe_reresolve(d, now);
        if (now >= d->next_lookup && !DHT_LOAD(&d->resolving) && DHT_LOAD(&d->n_boot) > 0) start_lookup(d, now);
        return 0;
    }
    dht_lookup_t *lk = &d->lk;

    for (int i = 0; i < DHT_MAX_INFLIGHT; i++)
        if (lk->inflight[i].used && now - lk->inflight[i].sent_at > 3.0) lk->inflight[i].used = 0;

    const int *top;
    int n_top = ranked_top(lk, d->infohash, &top);
    int inflight_count = 0, queried_count = 0;
    for (int i = 0; i < DHT_MAX_INFLIGHT; i++) if (lk->inflight[i].used) inflight_count++;
    for (int i = 0; i < lk->n_cands; i++) if (lk->cands[i].queried) queried_count++;

    int all_top_queried = 1;
    for (int i = 0; i < n_top; i++) {
        dht_cand_t *c = &lk->cands[top[i]];
        if (!c->queried) {
            all_top_queried = 0;
            if (inflight_count < DHT_MAX_INFLIGHT && queried_count < DHT_MAX_QUERIED) {
                c->queried = 1;
                queried_count++;
                for (int s = 0; s < DHT_MAX_INFLIGHT; s++) {
                    if (!lk->inflight[s].used) {
                        gen_random(lk->inflight[s].tid, 2);
                        lk->inflight[s].addr = c->addr;
                        lk->inflight[s].sent_at = now;
                        lk->inflight[s].used = 1;
                        send_get_peers(d, sock, c->addr, lk->inflight[s].tid);
                        inflight_count++;
                        break;
                    }
                }
            }
        }
    }

    if ((inflight_count == 0 && all_top_queried) || now - lk->t0 > DHT_LOOKUP_TIMEOUT) {
        int ann_idx[DHT_ANNOUNCE_TOP];
        int n_ann = rank_select(lk, d->infohash, DHT_ANNOUNCE_TOP, ann_idx, 1);
        for (int i = 0; i < n_ann; i++) {
            dht_cand_t *c = &lk->cands[ann_idx[i]];
            uint8_t tid[2]; gen_random(tid, 2);
            send_announce(d, sock, c->addr, tid, c->token, c->token_len);
        }
        d->next_lookup = now + (d->peers_now ? DHT_RELOOKUP_CONNECTED : DHT_RELOOKUP_IDLE);
        lk->active = 0;
        if (!d->told_dht) d->told_dht = 1;
        return 1;
    }
    return 0;
}

int dht_queried_count(const dht_state_t *d) {
    int n = 0;
    for (int i = 0; i < d->lk.n_cands; i++) if (d->lk.cands[i].queried) n++;
    return n;
}
int dht_found_count(const dht_state_t *d) { return d->lk.found; }

void dht_on_packet(dht_state_t *d, const uint8_t *data, size_t len, addr_t from,
                    void (*on_candidate)(void *ctx, addr_t a), void *ctx) {
    if (!d->lk.active || len == 0 || data[0] != 'd') return;
    be_arena arena;
    const be_value *msg = be_parse(data, len, &arena);
    if (!msg || msg->type != BE_DICT) return;
    const be_value *y = be_dict_get(msg, "y");
    const be_value *t = be_dict_get(msg, "t");
    if (!y || y->type != BE_STR || y->slen != 1 || y->s[0] != 'r') return;
    if (!t || t->type != BE_STR || t->slen != 2) return;

    int slot = -1;
    for (int i = 0; i < DHT_MAX_INFLIGHT; i++) {
        if (d->lk.inflight[i].used && memcmp(d->lk.inflight[i].tid, t->s, 2) == 0 &&
            addr_equal(d->lk.inflight[i].addr, from)) { slot = i; break; }
    }
    if (slot < 0) return;
    d->lk.inflight[slot].used = 0;

    const be_value *r = be_dict_get(msg, "r");
    if (!r || r->type != BE_DICT) return;
    dht_cand_t *c = find_or_add_cand(&d->lk, from);
    if (!c) return;
    const be_value *id = be_dict_get(r, "id");
    if (id && id->type == BE_STR && id->slen == 20 && !c->have_id) {
        memcpy(c->node_id, id->s, 20);
        c->have_id = 1;
        d->lk.dirty = 1;
    }
    const be_value *token = be_dict_get(r, "token");
    if (token && token->type == BE_STR && token->slen <= sizeof(c->token)) {
        memcpy(c->token, token->s, token->slen); c->token_len = token->slen; c->have_token = 1;
    }
    const be_value *nodes = be_dict_get(r, "nodes");
    if (nodes && nodes->type == BE_STR) {
        for (size_t i = 0; i + 26 <= nodes->slen; i += 26) {
            addr_t a;
            uint16_t port = (uint16_t)(((unsigned char)nodes->s[i + 24] << 8) | (unsigned char)nodes->s[i + 25]);
            if (port == 0) continue;
            addr_set_v4(&a, nodes->s + i + 20, port);
            dht_cand_t *nc = find_or_add_cand(&d->lk, a);
            if (nc && !nc->have_id) { memcpy(nc->node_id, nodes->s + i, 20); nc->have_id = 1; d->lk.dirty = 1; }
        }
    }
    const be_value *values = be_dict_get(r, "values");
    if (values && values->type == BE_LIST) {
        for (size_t i = 0; i < values->n; i++) {
            const be_value *v = &values->items[i];
            if (v->type != BE_STR || v->slen != 6) continue;
            addr_t a;
            uint16_t port = (uint16_t)(((unsigned char)v->s[4] << 8) | (unsigned char)v->s[5]);
            if (port == 0) continue;
            addr_set_v4(&a, v->s, port);
            d->lk.found++;
            if (on_candidate) on_candidate(ctx, a);
        }
    }
}
