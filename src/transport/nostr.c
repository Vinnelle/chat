// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/nostr.h"
#include "common/json.h"
#include "transport/tls.h"
#include "common/util.h"
#include "platform/platform.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <mbedtls/sha1.h>

#define IN_CAP (72 * 1024)
#define OUT_CAP (64 * 1024)
#define MSG_MAX (64 * 1024)
#define EVENT_CAP 16384
#define SEEN_IDS 512
// Inside the wrap: sender id, recipient id, datagram length, then the datagram and padding.
#define WRAP_HDR (ID_LEN * 2 + 2)
#define DGRAM_MAX (NOSTR_WRAP_PLAIN - WRAP_HDR)
#define CONTENT_LEN ((NOSTR_WRAP_LEN + 2) / 3 * 4)
#define STEP_TIMEOUT 15.0
#define IDLE_TIMEOUT 100.0
#define PING_EVERY 30.0
#define BACKOFF_MAX 300.0
#define RESUB_DELAY 30.0
// Relays rate-limit writes, some hard (a ban for a while after a few refusals). A handshake is a
// short burst; steady traffic is one event per peer every few seconds.
#define SEND_RATE 0.5
#define SEND_BURST 8.0
#define PAUSE_MIN 30.0
#define PAUSE_MAX 900.0
// The next ten minutes' connection opens this long before they start (at random between the
// half and the whole of it), and the last ten minutes' closes as long after (likewise): members'
// clocks can differ by the half. Through Tor a connection takes longer to come up.
#define LEAD 120.0
#define LEAD_PROXY 240.0
#define TAIL 120.0

enum { R_IDLE, R_RESOLVING, R_CONNECTING, R_SOCKS, R_TLS, R_UPGRADE, R_OPEN };
// Tor has to build a circuit and reach the relay before the SOCKS reply comes.
#define SOCKS_TIMEOUT 90.0
enum { JOB_RUNNING, JOB_DONE, JOB_ABANDONED };

// A relay's name is looked up on a thread, like the DHT's bootstrap servers. The relay may be
// dropped first, so whichever side finishes last frees the job.
#if defined(__STDC_NO_ATOMICS__)
typedef volatile int job_state_t;
#define JOB_ATOMIC 0
#else
#include <stdatomic.h>
typedef _Atomic int job_state_t;
#define JOB_ATOMIC 1
#endif

typedef struct {
    job_state_t state;
    char host[100];
    uint16_t port;
    addr_t out[4];
    int n;
} resolve_job_t;

typedef struct relay relay_t;

// One connection to a relay, asking for one ten minutes' tag.
typedef struct {
    int used;
    relay_t *relay;
    long long epoch;
    char tag[65];
    int state;
    resolve_job_t *job;
    addr_t addrs[4];
    int n_addrs, addr_i;
    sock_t s;
    tls_conn_t *tls;
    char ws_key[32];
    uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t out_len;
    uint8_t *msg;
    size_t msg_len;
    int msg_op, in_msg;
    double deadline, opened_at, last_rx, next_ping, resub_at;
    int subscribed;
    // A new one for each connection: the same id at several relays, or on one relay from one
    // connection to the next, would tie those connections to one member (and, through Tor, the
    // circuits it gives each relay).
    char subid[17];
    char challenge[160];
    // Through Tor: the SOCKS exchange so far, and this connection's own SOCKS login, so each gets
    // a circuit (and exit) of its own.
    int via_proxy, socks_stage;
    char socks_user[17];
} conn_t;

struct relay {
    char url[NOSTR_URL_MAX];
    char host[100];
    char path[128];
    uint16_t port;
    conn_t conns[2];
    double next_try;
    int fails;
    int warned, refusals;
    double tokens, tokens_at;
    // Writes held back after the relay refused one for rate or policy; reading goes on.
    double paused_until, pause;
    int read_only, odd_refusals;
    // When the next ten minutes' connection opens, and the last one's closes, this time round.
    long long plan_epoch;
    double open_next_at, close_last_at;
};

struct nostr {
    relay_t relays[NOSTR_MAX_RELAYS];
    int n_relays;
    int active;
    // Tor mode: every relay connection goes through this SOCKS proxy, and none goes anywhere
    // until it's known.
    int must_proxy;
    char proxy[64];
    uint8_t tag_key[NOSTR_KEY_LEN];
    uint8_t wrap_key[NOSTR_KEY_LEN];
    uint8_t my_id[ID_LEN];
    uint8_t seen_ids[SEEN_IDS][8];
    int seen_head;
    nostr_deliver_fn deliver;
    nostr_log_fn log;
    void *ctx;
    // The connection whose message is being handled: a send mustn't flush (and maybe drop) it then.
    conn_t *busy;
    js_arena arena;
    char ev[EVENT_CAP];
    char ser[EVENT_CAP];
};

static secp256k1_context *g_secp;

static secp256k1_context *secp(void) {
    if (!g_secp) {
        g_secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        uint8_t seed[32];
        gen_random(seed, sizeof seed);
        if (g_secp && !secp256k1_context_randomize(g_secp, seed)) { /* still usable, just unblinded */ }
        crypto_wipe(seed, sizeof seed);
    }
    return g_secp;
}

static void logf_(nostr_t *n, int verbose_only, const char *fmt, ...) {
    char msg[300];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    if (n->log) n->log(n->ctx, verbose_only, msg);
}

int nostr_url_ok(const char *url) {
    if (strncmp(url, "wss://", 6) != 0) return -1;
    const char *h = url + 6;
    size_t hl = strcspn(h, ":/");
    if (hl == 0 || hl >= 100) return -1;
    for (size_t i = 0; i < hl; i++)
        if (!isalnum((unsigned char)h[i]) && h[i] != '.' && h[i] != '-') return -1;
    const char *p = h + hl;
    if (*p == ':') {
        p++;
        long port = 0;
        size_t digits = 0;
        while (*p >= '0' && *p <= '9' && digits < 6) { port = port * 10 + (*p - '0'); p++; digits++; }
        if (digits == 0 || port <= 0 || port > 65535) return -1;
    }
    if (*p && *p != '/') return -1;
    if (strlen(p) >= 128) return -1;
    for (; *p; p++) if ((unsigned char)*p <= 0x20 || (unsigned char)*p >= 0x7f) return -1;
    return 0;
}

static void parse_url(relay_t *r) {
    const char *h = r->url + 6;
    size_t hl = strcspn(h, ":/");
    memcpy(r->host, h, hl);
    r->host[hl] = '\0';
    const char *p = h + hl;
    r->port = 443;
    if (*p == ':') { r->port = (uint16_t)strtol(p + 1, NULL, 10); p += 1 + strspn(p + 1, "0123456789"); }
    copy_str(r->path, *p ? p : "/", sizeof r->path);
}

static void epoch_tag(const nostr_t *n, long long epoch, char out[65]) {
    uint8_t e[8], mac[32];
    for (int i = 0; i < 8; i++) e[i] = (uint8_t)((unsigned long long)epoch >> (56 - 8 * i));
    hmac_sha256(n->tag_key, sizeof n->tag_key, e, sizeof e, mac);
    hex_encode(mac, sizeof mac, out);
}

nostr_t *nostr_new(const uint8_t tag_key[NOSTR_KEY_LEN], const uint8_t wrap_key[NOSTR_KEY_LEN],
                   const uint8_t my_id[ID_LEN], const char (*relays)[NOSTR_URL_MAX], int n_relays,
                   const char *proxy, nostr_deliver_fn deliver, nostr_log_fn log, void *ctx) {
    if (!secp()) return NULL;
    nostr_t *n = calloc(1, sizeof *n);
    if (!n) return NULL;
    if (proxy) { n->must_proxy = 1; copy_str(n->proxy, proxy, sizeof n->proxy); }
    crypto_lock(n->wrap_key, sizeof n->wrap_key);
    n->deliver = deliver;
    n->log = log;
    n->ctx = ctx;
    memcpy(n->tag_key, tag_key, NOSTR_KEY_LEN);
    memcpy(n->wrap_key, wrap_key, NOSTR_KEY_LEN);
    memcpy(n->my_id, my_id, ID_LEN);
    for (int i = 0; i < n_relays && n->n_relays < NOSTR_MAX_RELAYS; i++) {
        if (nostr_url_ok(relays[i]) != 0) continue;
        relay_t *r = &n->relays[n->n_relays++];
        copy_str(r->url, relays[i], sizeof r->url);
        parse_url(r);
        for (int k = 0; k < 2; k++) { r->conns[k].s = SOCK_INVALID; r->conns[k].relay = r; }
        r->plan_epoch = -1;
    }
    return n;
}

static void resolve_main(void *arg) {
    resolve_job_t *job = arg;
    addr_t found[ADDR_RESOLVE_MAX];
    int k = addr_resolve_all(job->host, job->port, found, ADDR_RESOLVE_MAX);
    int m = 0;
    for (int i = 0; i < k && m < 4; i++) job->out[m++] = found[i];
    job->n = m;
#if JOB_ATOMIC
    if (atomic_exchange(&job->state, JOB_DONE) == JOB_ABANDONED) free(job);
#else
    job->state = JOB_DONE;
#endif
}

static void drop_job(conn_t *c) {
    if (!c->job) return;
#if JOB_ATOMIC
    if (atomic_exchange(&c->job->state, JOB_ABANDONED) == JOB_DONE) free(c->job);
#else
    if (c->job->state == JOB_DONE) free(c->job);
    else c->job->state = JOB_ABANDONED;   // left for good: without atomics, never freed
#endif
    c->job = NULL;
}

static void close_conn(conn_t *c) {
    drop_job(c);
    if (c->tls) { tls_free(c->tls); c->tls = NULL; }
    if (c->s != SOCK_INVALID) { net_close(c->s); c->s = SOCK_INVALID; }
    free(c->in); free(c->out); free(c->msg);
    relay_t *r = c->relay;
    memset(c, 0, sizeof *c);
    c->relay = r;
    c->s = SOCK_INVALID;
    c->state = R_IDLE;
}

static void conn_fail(nostr_t *n, conn_t *c, double now, const char *why) {
    relay_t *r = c->relay;
    int was_open = c->state == R_OPEN;
    double opened_at = c->opened_at;
    char reason[160];
    copy_str(reason, why, sizeof reason);
    close_conn(c);
    // A connection that held for a minute was fine: start the backoff over.
    if (was_open && now - opened_at > 60.0) r->fails = 0;
    int shift = r->fails < 6 ? r->fails : 6;
    double delay = 5.0 * (double)(1u << shift);
    if (delay > BACKOFF_MAX) delay = BACKOFF_MAX;
    r->fails++;
    r->next_try = now + delay;
    if (!r->warned) {
        r->warned = 1;
        logf_(n, 0, "* nostr: %s %s: %s - retrying in the background", r->host, was_open ? "dropped" : "unreachable", reason);
    } else {
        logf_(n, 1, "* nostr: %s %s: %s - next try in %.0fs", r->host, was_open ? "dropped" : "unreachable", reason, delay);
    }
}

void nostr_free(nostr_t *n) {
    if (!n) return;
    for (int i = 0; i < n->n_relays; i++)
        for (int k = 0; k < 2; k++) close_conn(&n->relays[i].conns[k]);
    crypto_unlock(n->wrap_key, sizeof n->wrap_key);
    crypto_wipe(n, sizeof *n);
    free(n);
}

void nostr_set_active(nostr_t *n, int on) {
    if (n->active == !!on) return;
    n->active = !!on;
    if (on) {
        for (int i = 0; i < n->n_relays; i++) { n->relays[i].next_try = 0; n->relays[i].plan_epoch = -1; }
        logf_(n, 1, "* nostr: connecting to the relays");
        return;
    }
    for (int i = 0; i < n->n_relays; i++)
        for (int k = 0; k < 2; k++) close_conn(&n->relays[i].conns[k]);
    logf_(n, 1, "* nostr: off the relays - nothing needs them now");
}

int nostr_active(const nostr_t *n) { return n->active; }

// Appends one masked client frame to the connection's queue. Returns -1 if it won't fit.
static int ws_queue(conn_t *c, int op, const void *data, size_t len) {
    uint8_t hdr[14];
    size_t h = 0;
    hdr[h++] = (uint8_t)(0x80 | op);
    if (len < 126) hdr[h++] = (uint8_t)(0x80 | len);
    else if (len < 65536) { hdr[h++] = 0x80 | 126; hdr[h++] = (uint8_t)(len >> 8); hdr[h++] = (uint8_t)len; }
    else return -1;
    uint8_t mask[4];
    gen_random(mask, 4);
    memcpy(hdr + h, mask, 4);
    h += 4;
    if (!c->out || c->out_len + h + len > OUT_CAP) return -1;
    memcpy(c->out + c->out_len, hdr, h);
    uint8_t *dst = c->out + c->out_len + h;
    const uint8_t *src = data;
    for (size_t i = 0; i < len; i++) dst[i] = src[i] ^ mask[i & 3];
    c->out_len += h + len;
    return 0;
}

static int flush(nostr_t *n, conn_t *c, double now) {
    while (c->out_len > 0) {
        int w = tls_write(c->tls, c->out, c->out_len);
        if (w == 0) return 0;
        if (w < 0) { conn_fail(n, c, now, tls_error(c->tls)); return -1; }
        memmove(c->out, c->out + w, c->out_len - (size_t)w);
        c->out_len -= (size_t)w;
    }
    return 0;
}

static uint32_t rand_below(uint32_t n) {
    uint32_t r;
    gen_random((uint8_t *)&r, sizeof r);
    return r % n;
}

// Builds an event signed with a key made for it alone, and returns its JSON length in n->ev, or 0.
static size_t build_event(nostr_t *n, int kind, const char *tags, const char *content, size_t clen) {
    secp256k1_keypair kp;
    uint8_t sk[32], pk[32];
    char pk_hex[65];
    for (;;) {
        gen_random(sk, sizeof sk);
        if (secp256k1_keypair_create(secp(), &kp, sk)) break;
    }
    crypto_wipe(sk, sizeof sk);
    secp256k1_xonly_pubkey xpk;
    secp256k1_keypair_xonly_pub(secp(), &xpk, NULL, &kp);
    secp256k1_xonly_pubkey_serialize(secp(), pk, &xpk);
    hex_encode(pk, 32, pk_hex);
    // A little off the real time, so the timestamp doesn't pin down when it was written.
    long created = (long)time(NULL) - (long)rand_below(30);
    size_t p = (size_t)snprintf(n->ser, EVENT_CAP, "[0,\"%s\",%ld,%d,%s,", pk_hex, created, kind, tags);
    if (p >= EVENT_CAP) return 0;
    p = js_put_str(n->ser, p, EVENT_CAP, content, clen);
    if (p + 2 >= EVENT_CAP) return 0;
    n->ser[p++] = ']';
    uint8_t id[32], aux[32], sig[64];
    sha256_hash(n->ser, p, id);
    gen_random(aux, sizeof aux);
    int signed_ok = secp256k1_schnorrsig_sign32(secp(), sig, id, &kp, aux);
    crypto_wipe(&kp, sizeof kp);
    if (!signed_ok) return 0;
    char idhex[65], sighex[129];
    hex_encode(id, 32, idhex);
    hex_encode(sig, 64, sighex);
    size_t e = (size_t)snprintf(n->ev, EVENT_CAP, "{\"id\":\"%s\",\"pubkey\":\"%s\",\"created_at\":%ld,\"kind\":%d,\"tags\":%s,\"content\":",
                                idhex, pk_hex, created, kind, tags);
    if (e >= EVENT_CAP) return 0;
    e = js_put_str(n->ev, e, EVENT_CAP, content, clen);
    size_t tail = (size_t)snprintf(n->ev + (e < EVENT_CAP ? e : 0), e < EVENT_CAP ? EVENT_CAP - e : 0, ",\"sig\":\"%s\"}", sighex);
    if (e >= EVENT_CAP || e + tail >= EVENT_CAP) return 0;
    return e + tail;
}

// Asks for this connection's one tag.
static void send_req(conn_t *c) {
    char req[200];
    long since = (long)time(NULL) - 120;
    int len = snprintf(req, sizeof req, "[\"REQ\",\"%s\",{\"#e\":[\"%s\"],\"since\":%ld}]", c->subid, c->tag, since);
    if (ws_queue(c, 1, req, (size_t)len) == 0) c->subscribed = 1;
}

// NIP-42: prove to the relay that we hold the key it sees our events signed with.
static void send_auth(nostr_t *n, conn_t *c) {
    char tags[400];
    size_t p = (size_t)snprintf(tags, sizeof tags, "[[\"relay\",");
    p = js_put_str(tags, p, sizeof tags, c->relay->url, strlen(c->relay->url));
    if (p >= sizeof tags) return;
    p += (size_t)snprintf(tags + p, sizeof tags - p, "],[\"challenge\",");
    p = js_put_str(tags, p, sizeof tags, c->challenge, strlen(c->challenge));
    if (p + 3 >= sizeof tags) return;
    memcpy(tags + p, "]]", 3);
    size_t ev = build_event(n, 22242, tags, "", 0);
    if (!ev) return;
    char head[] = "[\"AUTH\",";
    size_t total = sizeof head - 1 + ev + 1;
    char *msg = malloc(total);
    if (!msg) return;
    memcpy(msg, head, sizeof head - 1);
    memcpy(msg + sizeof head - 1, n->ev, ev);
    msg[total - 1] = ']';
    ws_queue(c, 1, msg, total);
    free(msg);
}

static int seen_before(nostr_t *n, const uint8_t id[8]) {
    for (int i = 0; i < SEEN_IDS; i++) if (memcmp(n->seen_ids[i], id, 8) == 0) return 1;
    memcpy(n->seen_ids[n->seen_head], id, 8);
    n->seen_head = (n->seen_head + 1) % SEEN_IDS;
    return 0;
}

// Kinds 20000-29999 are ephemeral. A few have a meaning relays may act on; the rest are ours to
// pick from at random, so the kind says nothing about who sent an event.
static int kind_reserved(int k) {
    return k == 22242 || k == 23194 || k == 23195 || k == 24133 || k == 27235 || (k >= 21000 && k < 21100);
}

static int random_kind(void) {
    for (;;) {
        int k = 20000 + (int)rand_below(10000);
        if (!kind_reserved(k)) return k;
    }
}

static void on_event(nostr_t *n, conn_t *c, const js_value *ev, double now) {
    const js_value *content = js_obj_get(ev, "content");
    const js_value *kind = js_obj_get(ev, "kind");
    const js_value *tags = js_obj_get(ev, "tags");
    if (!content || content->type != JS_STR || content->slen != CONTENT_LEN) return;
    if (!kind || kind->type != JS_NUM || !kind->is_int || kind->i < 20000 || kind->i > 29999) return;
    if (!tags || tags->type != JS_ARR) return;
    int ours = 0;
    for (size_t i = 0; i < tags->n && !ours; i++) {
        const js_value *t = &tags->items[i];
        if (t->type != JS_ARR || t->n < 2) continue;
        const char *name = js_str(&t->items[0]), *val = js_str(&t->items[1]);
        if (name && val && strcmp(name, "e") == 0 && strcmp(val, c->tag) == 0) ours = 1;
    }
    if (!ours) return;

    // The relay's signature check is enough for the relay; ours is the wrap, which only room
    // members can seal. Signatures by throwaway keys would prove nothing more.
    uint8_t wrapped[NOSTR_WRAP_LEN + 3];
    long wlen = base64_decode_strict(content->s, content->slen, wrapped, sizeof wrapped);
    if (wlen != NOSTR_WRAP_LEN) return;
    // Every relay we use sends its copy: the first one wins. The nonce is random per event.
    if (seen_before(n, wrapped)) return;
    uint8_t plain[NOSTR_WRAP_PLAIN];
    if (nostr_unwrap(n->wrap_key, wrapped, (size_t)wlen, plain) != 0) return;
    static const uint8_t everyone[ID_LEN];
    const uint8_t *from_id = plain, *to_id = plain + ID_LEN;
    size_t dlen = ((size_t)plain[ID_LEN * 2] << 8) | plain[ID_LEN * 2 + 1];
    // Our own events come back to us too, and the others' go to everyone.
    if (memcmp(from_id, n->my_id, ID_LEN) == 0 || memcmp(from_id, everyone, ID_LEN) == 0) return;
    if (memcmp(to_id, n->my_id, ID_LEN) != 0 && memcmp(to_id, everyone, ID_LEN) != 0) return;
    if (dlen == 0 || dlen > DGRAM_MAX) return;
    if (n->deliver) n->deliver(n->ctx, plain + WRAP_HDR, dlen, addr_virtual(ADDR_NOSTR, from_id), now);
    crypto_wipe(plain, sizeof plain);
}

static void on_message(nostr_t *n, conn_t *c, const char *msg, size_t len, double now) {
    relay_t *r = c->relay;
    const js_value *v = js_parse(msg, len, &n->arena);
    if (!v || v->type != JS_ARR || v->n < 2) return;
    const char *type = js_str(&v->items[0]);
    if (!type) return;
    if (strcmp(type, "EVENT") == 0 && v->n >= 3) {
        const char *sub = js_str(&v->items[1]);
        if (sub && strcmp(sub, c->subid) == 0 && v->items[2].type == JS_OBJ) on_event(n, c, &v->items[2], now);
    } else if (strcmp(type, "OK") == 0 && v->n >= 4) {
        if (v->items[2].type == JS_BOOL && !v->items[2].b) {
            const char *why = js_str(&v->items[3]);
            char clean[120];
            clean_text(why ? why : "", clean, sizeof clean - 1);
            // NIP-01 prefixes: back off on rate limits, stop writing on policy. The other relays
            // carry on meanwhile.
            const char *action = "";
            if (strncmp(clean, "rate-limited", 12) == 0 || strncmp(clean, "banned", 6) == 0) {
                r->pause = r->pause > 0 ? r->pause * 2 : PAUSE_MIN;
                if (strncmp(clean, "banned", 6) == 0 && r->pause < PAUSE_MAX / 2) r->pause = PAUSE_MAX / 2;
                if (r->pause > PAUSE_MAX) r->pause = PAUSE_MAX;
                if (now + r->pause > r->paused_until) r->paused_until = now + r->pause;
                action = " - pausing writes there";
            } else if (strncmp(clean, "blocked", 7) == 0 || strncmp(clean, "restricted", 10) == 0
                       || strncmp(clean, "pow", 3) == 0 || strncmp(clean, "invalid", 7) == 0
                       || ++r->odd_refusals >= 3) {
                // A policy (web of trust, payment, proof of work) that throwaway keys won't meet.
                r->read_only = 1;
                action = " - only reading from it now";
            }
            // The first refusal says why relaying may not work through this relay; the rest are noise.
            logf_(n, r->refusals++ > 0, "* nostr: %s refused an event: %s%s", r->host, clean[0] ? clean : "no reason given", action);
        } else if (v->items[2].type == JS_BOOL && v->items[2].b && r->pause > PAUSE_MIN && now > r->paused_until) {
            r->pause /= 2;
        }
    } else if (strcmp(type, "NOTICE") == 0) {
        char clean[160];
        clean_text(js_str(&v->items[1]) ? js_str(&v->items[1]) : "", clean, sizeof clean - 1);
        logf_(n, 1, "* nostr: notice from %s: %s", r->host, clean);
    } else if (strcmp(type, "CLOSED") == 0) {
        const char *why = v->n >= 3 ? js_str(&v->items[2]) : NULL;
        char clean[120];
        clean_text(why ? why : "", clean, sizeof clean - 1);
        logf_(n, 1, "* nostr: %s closed our subscription: %s", r->host, clean);
        c->subscribed = 0;
        if (c->challenge[0]) { send_auth(n, c); send_req(c); }
        else c->resub_at = now + RESUB_DELAY;
    } else if (strcmp(type, "AUTH") == 0) {
        const char *ch = js_str(&v->items[1]);
        if (!ch || strlen(ch) >= sizeof c->challenge) return;
        copy_str(c->challenge, ch, sizeof c->challenge);
        send_auth(n, c);
        if (!c->subscribed) send_req(c);
    }
}

static void start_upgrade(nostr_t *n, conn_t *c, double now) {
    relay_t *r = c->relay;
    uint8_t key[16];
    gen_random(key, sizeof key);
    base64_encode(key, sizeof key, c->ws_key);
    char req[512];
    char hostport[112];
    if (r->port == 443) copy_str(hostport, r->host, sizeof hostport);
    else snprintf(hostport, sizeof hostport, "%s:%u", r->host, (unsigned)r->port);
    int len = snprintf(req, sizeof req,
                       "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
                       r->path, hostport, c->ws_key);
    if (len <= 0 || (size_t)len >= sizeof req || c->out_len + (size_t)len > OUT_CAP) { conn_fail(n, c, now, "request too long"); return; }
    memcpy(c->out + c->out_len, req, (size_t)len);
    c->out_len += (size_t)len;
    c->state = R_UPGRADE;
    c->deadline = now + STEP_TIMEOUT;
    flush(n, c, now);
}

static int header_value(const char *head, const char *name, char *out, size_t cap) {
    size_t nlen = strlen(name);
    for (const char *line = head; line && *line; ) {
        const char *eol = strstr(line, "\r\n");
        size_t llen = eol ? (size_t)(eol - line) : strlen(line);
        if (llen > nlen && line[nlen] == ':' && strncasecmp(line, name, nlen) == 0) {
            const char *v = line + nlen + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t vlen = llen - (size_t)(v - line);
            while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t')) vlen--;
            if (vlen >= cap) return -1;
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return 0;
        }
        line = eol ? eol + 2 : NULL;
    }
    return -1;
}

// Once the whole response head is in: 1 upgraded, 0 not yet, -1 refused.
static int check_upgrade(conn_t *c, char *why, size_t cap) {
    uint8_t *end = NULL;
    for (size_t i = 0; i + 3 < c->in_len; i++)
        if (memcmp(c->in + i, "\r\n\r\n", 4) == 0) { end = c->in + i; break; }
    if (!end) {
        if (c->in_len > 8192) { copy_str(why, "oversized handshake reply", cap); return -1; }
        return 0;
    }
    size_t head_len = (size_t)(end - c->in) + 4;
    char head[8200];
    // One read can bring a long head all at once, past the check above.
    if (head_len > sizeof head) { copy_str(why, "oversized handshake reply", cap); return -1; }
    memcpy(head, c->in, head_len - 2);
    head[head_len - 2] = '\0';
    if (strncmp(head, "HTTP/1.1 101", 12) != 0 && strncmp(head, "HTTP/1.0 101", 12) != 0) {
        char status[48];
        size_t sl = strcspn(head, "\r\n");
        if (sl >= sizeof status) sl = sizeof status - 1;
        memcpy(status, head, sl);
        status[sl] = '\0';
        clean_text(status, why, cap - 1);
        return -1;
    }
    char accept[64];
    if (header_value(head, "Sec-WebSocket-Accept", accept, sizeof accept) != 0) {
        copy_str(why, "no websocket accept header", cap);
        return -1;
    }
    char concat[80];
    snprintf(concat, sizeof concat, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", c->ws_key);
    uint8_t digest[20];
    char expect[32];
    mbedtls_sha1((const unsigned char *)concat, strlen(concat), digest);
    base64_encode(digest, sizeof digest, expect);
    if (strcmp(accept, expect) != 0) { copy_str(why, "bad websocket accept header", cap); return -1; }
    memmove(c->in, c->in + head_len, c->in_len - head_len);
    c->in_len -= head_len;
    return 1;
}

// Handles whole frames in the input buffer. Returns -1 if the connection has to go.
static int read_frames(nostr_t *n, conn_t *c, double now) {
    for (;;) {
        if (c->in_len < 2) return 0;
        uint8_t b0 = c->in[0], b1 = c->in[1];
        int fin = (b0 & 0x80) != 0, op = b0 & 0x0f, masked = (b1 & 0x80) != 0;
        uint64_t plen = b1 & 0x7f;
        size_t h = 2;
        if (plen == 126) {
            if (c->in_len < 4) return 0;
            plen = ((uint64_t)c->in[2] << 8) | c->in[3];
            h = 4;
        } else if (plen == 127) {
            if (c->in_len < 10) return 0;
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | c->in[2 + i];
            h = 10;
        }
        if (plen > MSG_MAX) { conn_fail(n, c, now, "oversized message"); return -1; }
        uint8_t mask[4] = { 0, 0, 0, 0 };
        if (masked) {
            if (c->in_len < h + 4) return 0;
            memcpy(mask, c->in + h, 4);
            h += 4;
        }
        if (c->in_len < h + plen) return 0;
        uint8_t *payload = c->in + h;
        if (masked) for (size_t i = 0; i < plen; i++) payload[i] ^= mask[i & 3];

        if (op == 8) { conn_fail(n, c, now, "closed by the relay"); return -1; }
        if (op == 9) {
            if (plen <= 125) ws_queue(c, 10, payload, (size_t)plen);
        } else if (op == 1 || op == 2 || op == 0) {
            if (op != 0) { c->in_msg = 1; c->msg_op = op; c->msg_len = 0; }
            if (!c->in_msg) { conn_fail(n, c, now, "stray continuation frame"); return -1; }
            if (c->msg_len + plen > MSG_MAX) { conn_fail(n, c, now, "oversized message"); return -1; }
            memcpy(c->msg + c->msg_len, payload, (size_t)plen);
            c->msg_len += (size_t)plen;
            if (fin) {
                c->in_msg = 0;
                if (c->msg_op == 1) {
                    n->busy = c;
                    on_message(n, c, (const char *)c->msg, c->msg_len, now);
                    n->busy = NULL;
                }
                if (c->state != R_OPEN) return -1;
            }
        }
        size_t used = h + (size_t)plen;
        memmove(c->in, c->in + used, c->in_len - used);
        c->in_len -= used;
    }
}

static int alloc_buffers(conn_t *c) {
    if (!c->in) c->in = malloc(IN_CAP);
    if (!c->out) c->out = malloc(OUT_CAP);
    if (!c->msg) c->msg = malloc(MSG_MAX);
    return c->in && c->out && c->msg ? 0 : -1;
}

static void start_tls(nostr_t *n, conn_t *c, double now) {
    relay_t *r = c->relay;
    c->tls = tls_new(c->s, r->host);
    if (!c->tls) {
        char err[160] = "TLS unavailable";
        tls_setup(err, sizeof err);
        conn_fail(n, c, now, err);
        return;
    }
    c->state = R_TLS;
    c->deadline = now + STEP_TIMEOUT;
}

// Through Tor: connect to its SOCKS port. The relay's name goes to Tor as it is, so Tor looks it
// up at the exit; nothing here ever asks local DNS.
static void begin_proxy_connect(nostr_t *n, conn_t *c, double now) {
    addr_t pa;
    if (addr_parse_hostport(n->proxy, &pa) != 0) { conn_fail(n, c, now, "Tor's SOCKS address isn't host:port"); return; }
    if (alloc_buffers(c) != 0) { conn_fail(n, c, now, "out of memory"); return; }
    c->s = net_tcp_connect(pa);
    if (c->s == SOCK_INVALID) { conn_fail(n, c, now, "can't reach Tor's SOCKS port"); return; }
    uint8_t user[8];
    gen_random(user, sizeof user);
    hex_encode(user, sizeof user, c->socks_user);
    c->via_proxy = 1;
    c->socks_stage = 0;
    c->in_len = 0;
    c->state = R_CONNECTING;
    c->deadline = now + STEP_TIMEOUT;
}

static int send_all(sock_t s, const uint8_t *data, size_t len) {
    return net_tcp_send(s, data, len) == (int)len ? 0 : -1;
}

static const char *socks_reply(int rep) {
    switch (rep) {
        case 0x02: return "Tor won't connect there (exit policy)";
        case 0x03: return "network unreachable from the Tor exit";
        case 0x04: return "host unreachable from the Tor exit";
        case 0x05: return "connection refused at the relay";
        case 0x06: return "Tor timed out reaching the relay";
        case 0xf6: return "bad address";
        default:   return "Tor couldn't connect to the relay";
    }
}

// Moves the SOCKS exchange on with what has arrived. 1 once connected through Tor, 0 waiting,
// -1 failed (the connection has been dropped).
static int socks_advance(nostr_t *n, conn_t *c, double now) {
    relay_t *r = c->relay;
    for (;;) {
        if (c->socks_stage == 0) {
            if (c->in_len < 2) return 0;
            if (c->in[0] != 5 || c->in[1] != 2) { conn_fail(n, c, now, "that SOCKS port won't take Tor's login (is it Tor's?)"); return -1; }
            uint8_t auth[20];
            auth[0] = 1; auth[1] = 16;
            memcpy(auth + 2, c->socks_user, 16);
            auth[18] = 1; auth[19] = 'x';
            memmove(c->in, c->in + 2, c->in_len - 2); c->in_len -= 2;
            if (send_all(c->s, auth, sizeof auth) != 0) { conn_fail(n, c, now, "SOCKS write failed"); return -1; }
            c->socks_stage = 1;
        } else if (c->socks_stage == 1) {
            if (c->in_len < 2) return 0;
            if (c->in[1] != 0) { conn_fail(n, c, now, "Tor refused the SOCKS login"); return -1; }
            memmove(c->in, c->in + 2, c->in_len - 2); c->in_len -= 2;
            size_t hl = strlen(r->host);
            uint8_t req[7 + 100];
            req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3; req[4] = (uint8_t)hl;
            memcpy(req + 5, r->host, hl);
            req[5 + hl] = (uint8_t)(r->port >> 8);
            req[6 + hl] = (uint8_t)r->port;
            if (send_all(c->s, req, 7 + hl) != 0) { conn_fail(n, c, now, "SOCKS write failed"); return -1; }
            c->socks_stage = 2;
            c->deadline = now + SOCKS_TIMEOUT;
        } else {
            if (c->in_len < 5) return 0;
            if (c->in[0] != 5 || c->in[1] != 0) { conn_fail(n, c, now, socks_reply(c->in[1])); return -1; }
            size_t need = c->in[3] == 1 ? 10 : c->in[3] == 4 ? 22 : c->in[3] == 3 ? (size_t)7 + c->in[4] : 0;
            if (need == 0) { conn_fail(n, c, now, "bad SOCKS reply"); return -1; }
            if (c->in_len < need) return 0;
            memmove(c->in, c->in + need, c->in_len - need); c->in_len -= need;
            return 1;
        }
    }
}

static void begin_connect(nostr_t *n, conn_t *c, double now) {
    while (c->addr_i < c->n_addrs) {
        c->s = net_tcp_connect(c->addrs[c->addr_i]);
        if (c->s != SOCK_INVALID) {
            c->state = R_CONNECTING;
            c->deadline = now + STEP_TIMEOUT;
            return;
        }
        c->addr_i++;
    }
    conn_fail(n, c, now, "no address could be reached");
}

// Opens a connection for epoch's tag.
static void conn_open(nostr_t *n, relay_t *r, conn_t *c, long long epoch, double now) {
    close_conn(c);
    c->used = 1;
    c->epoch = epoch;
    epoch_tag(n, epoch, c->tag);
    if (n->must_proxy) {
        // No tor yet: wait for one rather than ever connect directly.
        if (n->proxy[0]) begin_proxy_connect(n, c, now);
        return;
    }
    resolve_job_t *job = calloc(1, sizeof *job);
    if (!job) return;
    copy_str(job->host, r->host, sizeof job->host);
    job->port = r->port;
    job->state = JOB_RUNNING;
    c->job = job;
    if (platform_spawn_thread(resolve_main, job) != 0) { free(job); c->job = NULL; conn_fail(n, c, now, "can't look the name up"); return; }
    c->state = R_RESOLVING;
    c->deadline = now + 30.0;
}

static void conn_step(nostr_t *n, conn_t *c, double now) {
    relay_t *r = c->relay;
    switch (c->state) {
        case R_IDLE:
            // A Tor-mode connection that had no tor to go through: now it has.
            if (n->must_proxy && n->proxy[0] && c->s == SOCK_INVALID) begin_proxy_connect(n, c, now);
            return;
        case R_RESOLVING: {
#if JOB_ATOMIC
            int done = atomic_load(&c->job->state) == JOB_DONE;
#else
            int done = c->job->state == JOB_DONE;
#endif
            if (!done) {
                if (now > c->deadline) conn_fail(n, c, now, "name lookup timed out");
                return;
            }
            c->n_addrs = c->job->n;
            memcpy(c->addrs, c->job->out, sizeof(addr_t) * (size_t)c->n_addrs);
            free(c->job);
            c->job = NULL;
            if (c->n_addrs == 0) { conn_fail(n, c, now, "name lookup failed"); return; }
            c->addr_i = 0;
            if (alloc_buffers(c) != 0) { conn_fail(n, c, now, "out of memory"); return; }
            begin_connect(n, c, now);
            return;
        }
        case R_CONNECTING: {
            int rc = net_tcp_connect_done(c->s);
            if (rc == 0 && now < c->deadline) return;
            if (rc != 1 && c->via_proxy) { conn_fail(n, c, now, "can't reach Tor's SOCKS port"); return; }
            if (rc != 1) {
                net_close(c->s);
                c->s = SOCK_INVALID;
                c->addr_i++;
                begin_connect(n, c, now);
                return;
            }
            if (c->via_proxy) {
                static const uint8_t hello[3] = { 5, 1, 2 };
                if (send_all(c->s, hello, sizeof hello) != 0) { conn_fail(n, c, now, "SOCKS write failed"); return; }
                c->state = R_SOCKS;
                c->deadline = now + STEP_TIMEOUT;
                return;
            }
            start_tls(n, c, now);
            return;
        }
        case R_SOCKS: {
            for (;;) {
                if (c->in_len >= IN_CAP) { conn_fail(n, c, now, "SOCKS overflow"); return; }
                int got = net_tcp_recv(c->s, c->in + c->in_len, IN_CAP - c->in_len);
                if (got < 0) { conn_fail(n, c, now, "Tor closed the connection"); return; }
                if (got == 0) break;
                c->in_len += (size_t)got;
            }
            int rc = socks_advance(n, c, now);
            if (rc < 0) return;
            if (rc == 0) { if (now > c->deadline) conn_fail(n, c, now, "Tor didn't reach the relay in time"); return; }
            // Anything past the SOCKS reply would be the relay's TLS, which only starts once we speak.
            c->in_len = 0;
            start_tls(n, c, now);
            return;
        }
        case R_TLS: {
            int rc = tls_handshake(c->tls);
            if (rc < 0) { conn_fail(n, c, now, tls_error(c->tls)); return; }
            if (rc == 0) { if (now > c->deadline) conn_fail(n, c, now, "TLS handshake timed out"); return; }
            start_upgrade(n, c, now);
            return;
        }
        case R_UPGRADE:
        case R_OPEN: {
            if (flush(n, c, now) < 0) return;
            for (;;) {
                if (c->in_len >= IN_CAP) { conn_fail(n, c, now, "input overflow"); return; }
                int got = tls_read(c->tls, c->in + c->in_len, IN_CAP - c->in_len);
                if (got < 0) { conn_fail(n, c, now, tls_error(c->tls)); return; }
                if (got == 0) break;
                c->in_len += (size_t)got;
                c->last_rx = now;
                if (c->state == R_UPGRADE) {
                    char why[80];
                    int up = check_upgrade(c, why, sizeof why);
                    if (up < 0) { conn_fail(n, c, now, why); return; }
                    if (up == 0) continue;
                    c->state = R_OPEN;
                    c->opened_at = now;
                    c->next_ping = now + PING_EVERY;
                    uint8_t sid[8];
                    gen_random(sid, sizeof sid);
                    hex_encode(sid, sizeof sid, c->subid);
                    if (r->warned) logf_(n, 0, "* nostr: %s is back", r->host);
                    else logf_(n, 1, "* nostr: connected to %s", r->host);
                    r->warned = 0;
                    send_req(c);
                }
                if (read_frames(n, c, now) < 0) return;
            }
            if (c->state == R_UPGRADE) {
                if (now > c->deadline) conn_fail(n, c, now, "websocket handshake timed out");
                return;
            }
            if (now - c->last_rx > IDLE_TIMEOUT) { conn_fail(n, c, now, "went quiet"); return; }
            if (now >= c->next_ping) { c->next_ping = now + PING_EVERY; ws_queue(c, 9, "p", 1); }
            if (!c->subscribed && c->resub_at > 0 && now >= c->resub_at) { c->resub_at = 0; send_req(c); }
            flush(n, c, now);
            return;
        }
        default:
            return;
    }
}

static conn_t *conn_for(relay_t *r, long long epoch) {
    for (int k = 0; k < 2; k++) if (r->conns[k].used && r->conns[k].epoch == epoch) return &r->conns[k];
    return NULL;
}

// Which connections a relay should have now: this ten minutes', the next one's from a little
// before it starts, and the last one's until a little after it ended. Nothing else.
static void relay_plan(nostr_t *n, relay_t *r, double now) {
    double wall = (double)time(NULL);
    long long e = (long long)wall / NOSTR_EPOCH;
    if (r->plan_epoch != e) {
        double lead = n->must_proxy ? LEAD_PROXY : LEAD;
        double start = (double)(e * NOSTR_EPOCH), next = (double)((e + 1) * NOSTR_EPOCH);
        r->open_next_at = next - lead / 2 - (double)rand_below((uint32_t)(lead / 2 * 1000)) / 1000.0;
        r->close_last_at = start + TAIL / 2 + (double)rand_below((uint32_t)(TAIL / 2 * 1000)) / 1000.0;
        r->plan_epoch = e;
    }
    for (int k = 0; k < 2; k++) {
        conn_t *c = &r->conns[k];
        if (!c->used) continue;
        int keep = c->epoch == e || (c->epoch == e + 1) || (c->epoch == e - 1 && wall < r->close_last_at);
        if (!keep) {
            logf_(n, 1, "* nostr: %s: closing the last ten minutes' connection", r->host);
            close_conn(c);
        }
    }
    if (now < r->next_try) return;
    long long want[2] = { e, wall >= r->open_next_at ? e + 1 : -1 };
    for (int i = 0; i < 2; i++) {
        if (want[i] < 0 || conn_for(r, want[i])) continue;
        conn_t *slot = !r->conns[0].used ? &r->conns[0] : !r->conns[1].used ? &r->conns[1] : NULL;
        if (!slot) {
            // Both taken: the oldest makes way for the one needed now.
            slot = r->conns[0].epoch < r->conns[1].epoch ? &r->conns[0] : &r->conns[1];
            if (slot->epoch >= want[i]) continue;
        }
        conn_open(n, r, slot, want[i], now);
        if (!slot->used) return;   // it failed at once, and the backoff holds the rest
    }
}

void nostr_step(nostr_t *n, double now) {
    if (!n->active) return;
    for (int i = 0; i < n->n_relays; i++) {
        relay_t *r = &n->relays[i];
        relay_plan(n, r, now);
        for (int k = 0; k < 2; k++) if (r->conns[k].used) conn_step(n, &r->conns[k], now);
    }
}

int nostr_sockets(const nostr_t *n, sock_t *out, int max) {
    int k = 0;
    for (int i = 0; i < n->n_relays; i++)
        for (int j = 0; j < 2 && k < max; j++) {
            const conn_t *c = &n->relays[i].conns[j];
            if (c->used && c->s != SOCK_INVALID && c->state >= R_SOCKS) out[k++] = c->s;
        }
    return k;
}

// The connection to publish on: this ten minutes', else the last one's while it lasts, else the
// next one's. An event carries the tag its connection asks for, never another.
static conn_t *publish_conn(relay_t *r) {
    long long e = (long long)time(NULL) / NOSTR_EPOCH;
    const long long order[3] = { e, e - 1, e + 1 };
    for (int i = 0; i < 3; i++) {
        conn_t *c = conn_for(r, order[i]);
        if (c && c->state == R_OPEN) return c;
    }
    return NULL;
}

static int writable(relay_t *r, double now) { return !r->read_only && now >= r->paused_until && publish_conn(r); }

addr_t nostr_everyone(void) {
    static const uint8_t zero[ID_LEN];
    return addr_virtual(ADDR_NOSTR, zero);
}

int nostr_send(nostr_t *n, addr_t to, const uint8_t *data, size_t len, double now) {
    if (!n->active || to.kind != ADDR_NOSTR || len == 0 || len > DGRAM_MAX) return -1;
    int any = 0;
    for (int i = 0; i < n->n_relays; i++) any |= writable(&n->relays[i], now);
    if (!any) return -1;
    uint8_t plain[NOSTR_WRAP_PLAIN], wrapped[NOSTR_WRAP_LEN];
    memcpy(plain, n->my_id, ID_LEN);
    memcpy(plain + ID_LEN, to.ip, ID_LEN);
    plain[ID_LEN * 2] = (uint8_t)(len >> 8);
    plain[ID_LEN * 2 + 1] = (uint8_t)len;
    memcpy(plain + WRAP_HDR, data, len);
    gen_random(plain + WRAP_HDR + len, NOSTR_WRAP_PLAIN - WRAP_HDR - len);
    nostr_wrap(n->wrap_key, plain, wrapped);
    crypto_wipe(plain, sizeof plain);
    // Seen already, so the relays' copies of our own event are dropped before unwrapping.
    seen_before(n, wrapped);
    char content[CONTENT_LEN + 1];
    size_t clen = base64_encode(wrapped, sizeof wrapped, content);
    int kind = random_kind(), sent = 0;
    // One event per tag: every relay publishing on its connection for the same ten minutes gets
    // the same event, as before.
    char built_tag[65] = "";
    size_t total = 0;
    static const char head[] = "[\"EVENT\",";
    for (int i = 0; i < n->n_relays; i++) {
        relay_t *r = &n->relays[i];
        conn_t *c = publish_conn(r);
        if (!c || r->read_only || now < r->paused_until) continue;
        r->tokens += (now - r->tokens_at) * SEND_RATE;
        if (r->tokens > SEND_BURST) r->tokens = SEND_BURST;
        r->tokens_at = now;
        if (r->tokens < 1.0) continue;
        if (strcmp(built_tag, c->tag) != 0) {
            char tags[80];
            snprintf(tags, sizeof tags, "[[\"e\",\"%s\"]]", c->tag);
            size_t ev = build_event(n, kind, tags, content, clen);
            total = sizeof head - 1 + ev + 1;
            if (!ev || total > EVENT_CAP) { built_tag[0] = '\0'; continue; }
            memcpy(n->ser, head, sizeof head - 1);
            memcpy(n->ser + sizeof head - 1, n->ev, ev);
            n->ser[total - 1] = ']';
            copy_str(built_tag, c->tag, sizeof built_tag);
        }
        if (ws_queue(c, 1, n->ser, total) != 0) continue;
        r->tokens -= 1.0;
        sent++;
        if (c != n->busy) flush(n, c, now);
    }
    return sent > 0 ? 0 : -1;
}

void nostr_set_proxy(nostr_t *n, const char *socks) {
    if (!n->must_proxy || strcmp(n->proxy, socks) == 0) return;
    copy_str(n->proxy, socks, sizeof n->proxy);
    // Whatever went through the old tor is gone with it: start over through the new one.
    for (int i = 0; i < n->n_relays; i++) {
        relay_t *r = &n->relays[i];
        for (int k = 0; k < 2; k++) close_conn(&r->conns[k]);
        r->next_try = 0;
        r->fails = 0;
    }
}

int nostr_relays_up(const nostr_t *n) {
    int k = 0;
    for (int i = 0; i < n->n_relays; i++) {
        const relay_t *r = &n->relays[i];
        k += (r->conns[0].used && r->conns[0].state == R_OPEN) || (r->conns[1].used && r->conns[1].state == R_OPEN);
    }
    return k;
}

int nostr_relay_total(const nostr_t *n) { return n->n_relays; }

void nostr_status(const nostr_t *n, char *out, size_t cap) {
    double now = now_seconds();
    if (!n->active) {
        snprintf(out, cap, "0/%d relays up (not connected: nothing needs them now)", n->n_relays);
        return;
    }
    size_t p = (size_t)snprintf(out, cap, "%d/%d relays up", nostr_relays_up(n), n->n_relays);
    for (int i = 0; i < n->n_relays && p < cap; i++) {
        const relay_t *r = &n->relays[i];
        int open = (r->conns[0].used && r->conns[0].state == R_OPEN) || (r->conns[1].used && r->conns[1].state == R_OPEN);
        int trying = r->conns[0].used || r->conns[1].used;
        const char *st = !open ? (trying ? "connecting" : "waiting")
                       : r->read_only ? "read-only" : now < r->paused_until ? "paused" : "up";
        p += (size_t)snprintf(out + p, cap - p, "%s%s %s", i ? ", " : " (", r->host, st);
    }
    if (n->n_relays > 0 && p + 1 < cap) { out[p++] = ')'; out[p] = '\0'; }
}
