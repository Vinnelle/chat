// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/dht.h"
#include "common/bencode.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "platform/platform.h"

#if defined(__STDC_NO_ATOMICS__)
typedef volatile int job_state_t;
#define JOB_ATOMIC 0
#else
#include <stdatomic.h>
typedef _Atomic int job_state_t;
#define JOB_ATOMIC 1
#endif
enum { JOB_RUNNING, JOB_DONE, JOB_ABANDONED };

struct dht_boot_job {
    job_state_t state;
    int want[2];
    addr_t out[DHT_BOOT_MAX];
    int n;
};

static const struct { const char *host; uint16_t port; } BOOTSTRAP[4] = {
    { "router.bittorrent.com", 6881 },
    { "dht.transmissionbt.com", 6881 },
    { "router.utorrent.com", 6881 },
    { "dht.libtorrent.org", 25401 },
};

void dht_init(dht_state_t *d, const uint8_t key[DHT_KEY_LEN], uint16_t my_port, int want_v4, int want_v6) {
    memset(d, 0, sizeof *d);
    memcpy(d->key, key, DHT_KEY_LEN);
    d->my_port = my_port;
    d->want[DHT_V4] = want_v4;
    d->want[DHT_V6] = want_v6;
}

void dht_set_output(dht_state_t *d, dht_send_fn send, void *ctx, int names_remote) {
    d->send = send;
    d->send_ctx = ctx;
    d->names_remote = names_remote;
}

static void dht_send(dht_state_t *d, const dht_cand_t *c, const uint8_t *buf, size_t len) {
    if (!d->send) return;
    if (c->named) d->send(d->send_ctx, buf, len, NULL, BOOTSTRAP[c->named - 1].host, BOOTSTRAP[c->named - 1].port);
    else d->send(d->send_ctx, buf, len, &c->addr, NULL, 0);
}

static int known_count(const dht_state_t *d, int fam) {
    int n = 0;
    for (int i = 0; i < DHT_KNOWN_MAX; i++) n += d->known[fam][i].used;
    return n;
}

// A node that answered: kept, in place of the one that answered longest ago when the list is full.
static void known_add(dht_state_t *d, addr_t a, const uint8_t id[20], double now) {
    dht_known_t *list = d->known[a.is_v6 ? DHT_V6 : DHT_V4], *slot = NULL;
    for (int i = 0; i < DHT_KNOWN_MAX && !slot; i++) if (list[i].used && addr_equal(list[i].addr, a)) slot = &list[i];
    for (int i = 0; i < DHT_KNOWN_MAX && !slot; i++) if (!list[i].used) slot = &list[i];
    if (!slot) {
        slot = &list[0];
        for (int i = 1; i < DHT_KNOWN_MAX; i++) if (list[i].ok_at < slot->ok_at) slot = &list[i];
    }
    slot->used = 1;
    slot->addr = a;
    memcpy(slot->node_id, id, 20);
    slot->ok_at = now;
}

static void known_drop(dht_state_t *d, addr_t a) {
    dht_known_t *list = d->known[a.is_v6 ? DHT_V6 : DHT_V4];
    for (int i = 0; i < DHT_KNOWN_MAX; i++) if (list[i].used && addr_equal(list[i].addr, a)) list[i].used = 0;
}

// This hour's node id: made the first time the hour's key is looked up.
static void use_node_id(dht_state_t *d, long long epoch) {
    for (int i = 0; i < 2; i++)
        if (d->ids[i].set && d->ids[i].epoch == epoch) { memcpy(d->node_id, d->ids[i].id, 20); return; }
    int slot = !d->ids[0].set ? 0 : !d->ids[1].set ? 1 : d->ids[0].epoch < d->ids[1].epoch ? 0 : 1;
    d->ids[slot].set = 1;
    d->ids[slot].epoch = epoch;
    gen_random(d->ids[slot].id, 20);
    memcpy(d->node_id, d->ids[slot].id, 20);
}

static void resolve_thread(void *arg) {
    dht_boot_job_t *job = arg;
    int n = 0, per_fam[2] = { 0, 0 };
    for (int i = 0; i < 4 && n < DHT_BOOT_MAX; i++) {
        addr_t found[ADDR_RESOLVE_MAX];
        int k = addr_resolve_all(BOOTSTRAP[i].host, BOOTSTRAP[i].port, found, ADDR_RESOLVE_MAX);
        for (int j = 0; j < k && n < DHT_BOOT_MAX; j++) {
            int fam = found[j].is_v6 ? DHT_V6 : DHT_V4;
            // Half the slots each, so one family's many addresses can't crowd out the other's.
            if (!job->want[fam] || per_fam[fam] >= DHT_BOOT_MAX / 2) continue;
            int dup = 0;
            for (int m = 0; m < n; m++) if (addr_equal(job->out[m], found[j])) { dup = 1; break; }
            if (!dup) { job->out[n++] = found[j]; per_fam[fam]++; }
        }
    }
    job->n = n;
#if JOB_ATOMIC
    if (atomic_exchange(&job->state, JOB_DONE) == JOB_ABANDONED) free(job);
#else
    job->state = JOB_DONE;
#endif
}

static void drop_job(dht_state_t *d) {
    if (!d->job) return;
#if JOB_ATOMIC
    if (atomic_exchange(&d->job->state, JOB_ABANDONED) == JOB_DONE) free(d->job);
#else
    if (d->job->state == JOB_DONE) free(d->job);
    else d->job->state = JOB_ABANDONED;   // left for good: without atomics, never freed
#endif
    d->job = NULL;
}

// Takes the bootstrap list from a lookup that has finished.
static void collect_job(dht_state_t *d) {
    if (!d->job) return;
#if JOB_ATOMIC
    if (atomic_load(&d->job->state) != JOB_DONE) return;
#else
    if (d->job->state != JOB_DONE) return;
#endif
    d->n_boot = d->job->n;
    memcpy(d->boot, d->job->out, sizeof(addr_t) * (size_t)d->n_boot);
    free(d->job);
    d->job = NULL;
}

void dht_start_bootstrap_resolve(dht_state_t *d) {
    if (d->job) return;
    dht_boot_job_t *job = calloc(1, sizeof *job);
    if (!job) return;
    job->state = JOB_RUNNING;
    job->want[DHT_V4] = d->want[DHT_V4];
    job->want[DHT_V6] = d->want[DHT_V6];
    d->job = job;
    if (platform_spawn_thread(resolve_thread, job) != 0) { free(job); d->job = NULL; }
}

void dht_stop(dht_state_t *d) {
    drop_job(d);
    crypto_wipe(d->key, sizeof d->key);
    d->n_boot = 0;
    d->lk[DHT_V4].active = d->lk[DHT_V6].active = 0;
}

void dht_rebootstrap(dht_state_t *d) {
    drop_job(d);
    d->n_boot = 0;
    d->next_resolve = 0;
    d->resolve_tries = 0;
    d->next_lookup = 0;
}

// This round's lookup key: this hour's, or the other hour's in a round straight after while the
// hour's change is near.
static void pick_infohash(dht_state_t *d) {
    long long wall = (long long)time(NULL);
    long long epoch = wall / DHT_EPOCH, into = wall % DHT_EPOCH, use = epoch;
    if (d->alt_pending) {
        use = d->alt_epoch;
        d->alt_pending = 0;
    } else if (into < DHT_EPOCH_OVERLAP) {
        d->alt_epoch = epoch - 1;
        d->alt_pending = 1;
    } else if (into >= DHT_EPOCH - DHT_EPOCH_OVERLAP) {
        d->alt_epoch = epoch + 1;
        d->alt_pending = 1;
    }
    dht_epoch_infohash(d->key, use, d->infohash);
    use_node_id(d, use);
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
        if (!lk->cands[i].named && addr_equal(lk->cands[i].addr, a)) return &lk->cands[i];
    if (lk->n_cands >= DHT_MAX_CANDS) return NULL;
    dht_cand_t *c = &lk->cands[lk->n_cands++];
    memset(c, 0, sizeof *c);
    c->addr = a;
    lk->dirty = 1;
    return c;
}

// A bootstrap server by name, for the proxy to look up.
static void add_named_cand(dht_lookup_t *lk, int index) {
    for (int i = 0; i < lk->n_cands; i++) if (lk->cands[i].named == index + 1) return;
    if (lk->n_cands >= DHT_MAX_CANDS) return;
    dht_cand_t *c = &lk->cands[lk->n_cands++];
    memset(c, 0, sizeof *c);
    c->named = index + 1;
    c->addr.port = BOOTSTRAP[index].port;
    lk->dirty = 1;
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

// With both families on, every query asks for nodes of both (BEP 32 "want"), so an IPv4 node can
// point the IPv6 lookup at IPv6 nodes when no bootstrap server has an IPv6 address.
static size_t append_want(dht_state_t *d, uint8_t *buf, size_t p) {
    if (d->want[DHT_V4] && d->want[DHT_V6]) return append_str(buf, p, "4:wantl2:n42:n6e");
    if (d->want[DHT_V6]) return append_str(buf, p, "4:wantl2:n6e");
    return p;
}

// Every query says "ro" (BEP 43): chat is a read-only node, which answers no queries, so other
// nodes don't put it in their routing tables or ping it, and its silence is what they expect.
static void send_get_peers(dht_state_t *d, const dht_cand_t *to, const uint8_t tid[2]) {
    uint8_t buf[160];
    size_t p = 0;
    p = append_str(buf, p, "d1:ad2:id");
    p = append_bstr(buf, p, d->node_id, 20);
    p = append_str(buf, p, "9:info_hash");
    p = append_bstr(buf, p, d->infohash, 20);
    p = append_want(d, buf, p);
    p = append_str(buf, p, "e1:q9:get_peers2:roi1e1:t");
    p = append_bstr(buf, p, tid, 2);
    p = append_str(buf, p, "1:y1:qe");
    dht_send(d, to, buf, p);
}

static void send_announce(dht_state_t *d, const dht_cand_t *to, const uint8_t tid[2],
                           const uint8_t *token, size_t token_len) {
    uint8_t buf[256];
    size_t p = 0;
    p = append_str(buf, p, "d1:ad2:id");
    p = append_bstr(buf, p, d->node_id, 20);
    p = append_str(buf, p, d->explicit_port ? "12:implied_porti0e9:info_hash" : "12:implied_porti1e9:info_hash");
    p = append_bstr(buf, p, d->infohash, 20);
    p = append_str(buf, p, "4:port");
    p = append_int(buf, p, (long)d->my_port);
    p = append_str(buf, p, "5:token");
    p = append_bstr(buf, p, token, token_len);
    p = append_str(buf, p, "1:q13:announce_peer2:roi1e1:t");
    p = append_bstr(buf, p, tid, 2);
    p = append_str(buf, p, "1:y1:qe");
    dht_send(d, to, buf, p);
}

// Starts from the nodes that answered lately, which the bootstrap servers join only while there
// are too few: those four see every lookup that starts with them.
static void start_lookup(dht_state_t *d, dht_lookup_t *lk, int fam, double now) {
    memset(lk, 0, sizeof *lk);
    lk->t0 = now;
    lk->active = 1;
    lk->dirty = 1;
    for (int i = 0; i < DHT_KNOWN_MAX; i++) {
        const dht_known_t *k = &d->known[fam][i];
        if (!k->used) continue;
        dht_cand_t *c = find_or_add_cand(lk, k->addr);
        if (c) { memcpy(c->node_id, k->node_id, 20); c->have_id = 1; }
    }
    if (known_count(d, fam) >= DHT_KNOWN_ENOUGH) return;
    if (d->names_remote) {
        // The proxy looks the names up, in whatever family it has; IPv6 fills from the replies.
        if (fam == DHT_V4 || !d->want[DHT_V4])
            for (int i = 0; i < 4; i++) add_named_cand(lk, i);
        return;
    }
    for (int i = 0; i < d->n_boot; i++)
        if (d->boot[i].is_v6 == (fam == DHT_V6)) find_or_add_cand(lk, d->boot[i]);
    // A family no bootstrap server answers for starts empty and fills from the other's replies.
}

// Enough to start a round from: the bootstrap servers' addresses, nodes known already, or (by
// name) nothing at all.
static int can_start(const dht_state_t *d) {
    if (d->names_remote || d->n_boot > 0) return 1;
    for (int fam = 0; fam < 2; fam++) if (d->want[fam] && known_count(d, fam) >= DHT_KNOWN_ENOUGH) return 1;
    return 0;
}

static void maybe_reresolve(dht_state_t *d, double now) {
    if (d->names_remote || d->job || d->n_boot > 0) return;
    if (now < d->next_resolve) return;
    int shift = d->resolve_tries < 6 ? d->resolve_tries : 6;
    double delay = 5.0 * (double)(1u << shift);
    if (delay > DHT_RESOLVE_BACKOFF_MAX) delay = DHT_RESOLVE_BACKOFF_MAX;
    d->resolve_tries++;
    d->next_resolve = now + delay;
    dht_start_bootstrap_resolve(d);
}

// Sends the next queries of one lookup. Returns 1 once it has finished (and announced).
static int lookup_step(dht_state_t *d, dht_lookup_t *lk, double now) {
    for (int i = 0; i < DHT_MAX_INFLIGHT; i++) {
        dht_inflight_t *f = &lk->inflight[i];
        if (!f->used || now - f->sent_at <= 3.0) continue;
        // No answer: a node known from before isn't started from again.
        if (!f->named) known_drop(d, f->addr);
        f->used = 0;
    }

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
                        lk->inflight[s].named = c->named;
                        lk->inflight[s].sent_at = now;
                        lk->inflight[s].used = 1;
                        send_get_peers(d, c, lk->inflight[s].tid);
                        inflight_count++;
                        break;
                    }
                }
            }
        }
    }

    // An empty lookup waits a little for the other family's replies to give it nodes.
    int starved = lk->n_cands == 0 && now - lk->t0 < 5.0;
    if ((inflight_count == 0 && all_top_queried && !starved) || now - lk->t0 > DHT_LOOKUP_TIMEOUT) {
        int ann_idx[DHT_ANNOUNCE_TOP];
        int n_ann = rank_select(lk, d->infohash, DHT_ANNOUNCE_TOP, ann_idx, 1);
        for (int i = 0; i < n_ann; i++) {
            dht_cand_t *c = &lk->cands[ann_idx[i]];
            uint8_t tid[2]; gen_random(tid, 2);
            send_announce(d, c, tid, c->token, c->token_len);
        }
        lk->active = 0;
        return 1;
    }
    return 0;
}

int dht_step(dht_state_t *d, double now) {
    collect_job(d);
    int any_active = d->lk[DHT_V4].active || d->lk[DHT_V6].active;
    if (!any_active) {
        maybe_reresolve(d, now);
        if (now >= d->next_lookup && !d->job && can_start(d)) {
            pick_infohash(d);
            for (int fam = 0; fam < 2; fam++)
                if (d->want[fam]) start_lookup(d, &d->lk[fam], fam, now);
        }
        return 0;
    }
    int finished = 0;
    for (int fam = 0; fam < 2; fam++)
        if (d->lk[fam].active) finished |= lookup_step(d, &d->lk[fam], now);
    if (finished && !d->lk[DHT_V4].active && !d->lk[DHT_V6].active) {
        d->next_lookup = d->alt_pending ? now : now + (d->peers_now ? DHT_RELOOKUP_CONNECTED : DHT_RELOOKUP_IDLE);
        if (!d->told_dht) d->told_dht = 1;
        return 1;
    }
    return 0;
}

int dht_queried_count_fam(const dht_state_t *d, int fam) {
    int n = 0;
    for (int i = 0; i < d->lk[fam].n_cands; i++) if (d->lk[fam].cands[i].queried) n++;
    return n;
}
int dht_found_count_fam(const dht_state_t *d, int fam) { return d->lk[fam].found; }
int dht_queried_count(const dht_state_t *d) { return dht_queried_count_fam(d, DHT_V4) + dht_queried_count_fam(d, DHT_V6); }
int dht_found_count(const dht_state_t *d) { return d->lk[DHT_V4].found + d->lk[DHT_V6].found; }

static void add_nodes(dht_state_t *d, const be_value *nodes, int fam) {
    if (!nodes || nodes->type != BE_STR || !d->want[fam]) return;
    dht_lookup_t *lk = &d->lk[fam];
    if (!lk->active) return;
    size_t iplen = fam == DHT_V6 ? 16 : 4, step = 20 + iplen + 2;
    for (size_t i = 0; i + step <= nodes->slen; i += step) {
        const uint8_t *e = (const uint8_t *)nodes->s + i;
        addr_t a;
        uint16_t port = (uint16_t)((e[20 + iplen] << 8) | e[21 + iplen]);
        if (port == 0) continue;
        if (fam == DHT_V6) {
            // A v4-mapped address here is an IPv4 node in the wrong list.
            static const uint8_t v4map[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            if (memcmp(e + 20, v4map, 12) == 0) continue;
            memset(&a, 0, sizeof a);
            memcpy(a.ip, e + 20, 16);
            a.port = port;
            a.is_v6 = 1;
        } else {
            addr_set_v4(&a, e + 20, port);
        }
        dht_cand_t *nc = find_or_add_cand(lk, a);
        if (nc && !nc->have_id) { memcpy(nc->node_id, e, 20); nc->have_id = 1; lk->dirty = 1; }
    }
}

void dht_on_packet(dht_state_t *d, const uint8_t *data, size_t len, addr_t from,
                    void (*on_candidate)(void *ctx, addr_t a), void *ctx) {
    if ((!d->lk[DHT_V4].active && !d->lk[DHT_V6].active) || len == 0 || data[0] != 'd') return;
    be_arena arena;
    const be_value *msg = be_parse(data, len, &arena);
    if (!msg || msg->type != BE_DICT) return;
    const be_value *y = be_dict_get(msg, "y");
    const be_value *t = be_dict_get(msg, "t");
    if (!y || y->type != BE_STR || y->slen != 1 || y->s[0] != 'r') return;
    if (!t || t->type != BE_STR || t->slen != 2) return;

    dht_lookup_t *lk = NULL;
    int slot = -1;
    for (int fam = 0; fam < 2 && slot < 0; fam++) {
        dht_lookup_t *l = &d->lk[fam];
        if (!l->active) continue;
        for (int i = 0; i < DHT_MAX_INFLIGHT; i++) {
            if (l->inflight[i].used && memcmp(l->inflight[i].tid, t->s, 2) == 0 &&
                (l->inflight[i].named || addr_equal(l->inflight[i].addr, from))) { slot = i; lk = l; break; }
        }
    }
    if (slot < 0) return;
    lk->inflight[slot].used = 0;

    const be_value *r = be_dict_get(msg, "r");
    if (!r || r->type != BE_DICT) return;
    dht_cand_t *c = find_or_add_cand(lk, from);
    if (!c) return;
    // A server asked by name answers from an address: that one has been asked already.
    c->queried = 1;
    const be_value *id = be_dict_get(r, "id");
    if (id && id->type == BE_STR && id->slen == 20) {
        if (!c->have_id) {
            memcpy(c->node_id, id->s, 20);
            c->have_id = 1;
            lk->dirty = 1;
        }
        known_add(d, from, (const uint8_t *)id->s, now_seconds());
    }
    const be_value *token = be_dict_get(r, "token");
    if (token && token->type == BE_STR && token->slen <= sizeof(c->token)) {
        memcpy(c->token, token->s, token->slen); c->token_len = token->slen; c->have_token = 1;
    }
    add_nodes(d, be_dict_get(r, "nodes"), DHT_V4);
    add_nodes(d, be_dict_get(r, "nodes6"), DHT_V6);
    const be_value *values = be_dict_get(r, "values");
    if (values && values->type == BE_LIST) {
        for (size_t i = 0; i < values->n; i++) {
            const be_value *v = &values->items[i];
            if (v->type != BE_STR || (v->slen != 6 && v->slen != 18)) continue;
            const uint8_t *e = (const uint8_t *)v->s;
            size_t iplen = v->slen - 2;
            addr_t a;
            uint16_t port = (uint16_t)((e[iplen] << 8) | e[iplen + 1]);
            if (port == 0) continue;
            if (iplen == 16) {
                memset(&a, 0, sizeof a);
                memcpy(a.ip, e, 16);
                a.port = port;
                a.is_v6 = 1;
            } else {
                addr_set_v4(&a, e, port);
            }
            lk->found++;
            if (on_candidate) on_candidate(ctx, a);
        }
    }
}
