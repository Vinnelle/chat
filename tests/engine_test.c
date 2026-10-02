// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Sessions talking over fake_net: handshake, verify codes, delivery, loss, rekey, the traffic's
// shape on the wire, junk and a third peer.
#include "core/chat.h"
#include "fake_net.h"
#include "common/json.h"
#include "common/toml.h"
#include "transport/portmap.h"
#include "common/image.h"
#include "common/util.h"
#include "crypto/age.h"
#include "crypto/pgp.h"
#include "platform/platform.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_LINES 512

typedef struct {
    const char *who;
    char lines[LOG_LINES][320];
    int n;
    int modified_warnings;
    int anon_joins;   // "* anon ... joined": a peer announced before its nick came
    int joining, unheralded_joins;   // "joining" lines not yet followed by "joined", and "joined" without one
    int compare_prompts;   // "compare this code with ..."
    int held;              // "not sent to ...: compare verify codes first"
    int mismatched;        // "file N ... didn't match what was offered"
    int withdrawn;         // "NICK no longer offers file N"
} log_t;

static chat_t A, B, C;
static log_t log_a = { .who = "alice" }, log_b = { .who = "bob" }, log_c = { .who = "carol" };
static int checks, failures;
// -v: everything the sessions print, and every check as written, pass or fail.
static int verbose;

#define CHECK(cond, ...) do { \
    checks++; \
    if (cond) { if (verbose) printf("  pass  %s\n", #cond); } \
    else { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); \
           if (verbose) printf("  fail  %s\n", #cond); } \
} while (0)

static void on_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len, int file) {
    (void)file;
    log_t *l = ui;
    (void)hhmm; (void)rgb; (void)color_len;
    if (verbose) printf("  [%s%s] %s\n", l->who, (flags & LINE_CHAT) ? " chat" : "", text);
    if (!(flags & LINE_CHAT)) {
        if (strstr(text, "runs a modified client")) l->modified_warnings++;
        if (strncmp(text, "* anon", 6) == 0 && strstr(text, " joined (")) l->anon_joins++;
        if (strncmp(text, "* compare this code with ", 25) == 0) l->compare_prompts++;
        if (strncmp(text, "* not sent to ", 14) == 0) l->held++;
        if (strstr(text, "didn't match what was offered")) l->mismatched++;
        if (strstr(text, " no longer offers file ")) l->withdrawn++;
        if (strncmp(text, "* joining: peer ", 16) == 0) l->joining++;
        else if (strstr(text, " joined (")) { if (l->joining > 0) l->joining--; else l->unheralded_joins++; }
        return;
    }
    if (l->n < LOG_LINES) copy_str(l->lines[l->n++], text, sizeof l->lines[0]);
}

static int log_count(const log_t *l, const char *needle) {
    int k = 0;
    for (int i = 0; i < l->n; i++) if (strstr(l->lines[i], needle)) k++;
    return k;
}

// Release 1.2.3 is alice's and bob's binaries: its list, signed with a release key of the test's
// own as `just release` signs it, names them. Carol's is a build from source, with no list.
static const uint8_t BUILD_ALICE[BUILD_HASH_LEN] = { 1 }, BUILD_BOB[BUILD_HASH_LEN] = { 2 },
                     BUILD_CAROL[BUILD_HASH_LEN] = { 3 };
static char release_pub[64], release_list[BUILD_LIST_LEN + 1], release_sig[MINISIGN_SIG_B64_LEN + 1];

static void make_release(void) {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES], key[MINISIGN_KEY_LEN];
    crypto_sign_keypair(pk, sk);
    memcpy(key, "Ed", 2);
    gen_random(key + 2, 8);
    memcpy(key + 10, pk, sizeof pk);
    base64_encode(key, sizeof key, release_pub);

    char a[BUILD_HASH_LEN * 2 + 1], b[BUILD_HASH_LEN * 2 + 1], content[256];
    hex_encode(BUILD_ALICE, BUILD_HASH_LEN, a);
    hex_encode(BUILD_BOB, BUILD_HASH_LEN, b);
    snprintf(release_list, sizeof release_list, "%s,%s", a, b);
    int len = snprintf(content, sizeof content, "chat v1.2.3\n%s\n%s\n", a, b);
    // minisign's default signature: "ED", the key id, and Ed25519 over BLAKE2b-512 of the file.
    uint8_t h[64], sig[MINISIGN_SIG_LEN];
    crypto_generichash(h, sizeof h, (const uint8_t *)content, (size_t)len, NULL, 0);
    memcpy(sig, "ED", 2);
    memcpy(sig + 2, key + 2, 8);
    crypto_sign_detached(sig + 10, NULL, h, sizeof h, sk);
    base64_encode(sig, sizeof sig, release_sig);
}

static void base_opts(chat_opts_t *o, const char *nick, uint16_t port, const uint16_t *peer_ports, int n, int created) {
    memset(o, 0, sizeof *o);
    copy_str(o->nick, nick, sizeof o->nick);
    copy_str(o->session_name, "TESTSESSION", sizeof o->session_name);
    copy_str(o->password, "correct horse", sizeof o->password);
    o->port = port;
    for (int i = 0; i < n; i++) o->peers[i] = fake_net_addr(peer_ports[i]);
    o->n_peers = n;
    o->created = created;
    o->notify_mode = NOTIFY_NONE;
}

static void start(chat_t *c, log_t *l, const char *nick, uint16_t port, const uint16_t *peer_ports, int n, int created,
                  const uint8_t build[BUILD_HASH_LEN], int released) {
    chat_opts_t o;
    base_opts(&o, nick, port, peer_ports, n, created);
    o.build.ok = 1;
    copy_str(o.build.version, "1.2.3", sizeof o.build.version);
    memcpy(o.build.hash, build, BUILD_HASH_LEN);
    if (released) {
        copy_str(o.build.list, release_list, sizeof o.build.list);
        copy_str(o.build.list_sig, release_sig, sizeof o.build.list_sig);
    }
    copy_str(o.release_key, release_pub, sizeof o.release_key);
    chat_init(c, &o, on_print, NULL, l);
}

static chat_t *const ALL[] = { &A, &B, &C };
static const log_t *const ALL_LOGS[] = { &log_a, &log_b, &log_c };
static int n_live = 2;
static int live_mask = 0x3;   // which of ALL run
static double g_now;          // the time the sessions last ran at, for filters that note when

// Delivers everything queued and ticks every session, `rounds` times, at time t.
static void pump(int rounds, double t) {
    g_now = t;
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < 3; i++) if (live_mask & (1 << i)) chat_on_socket_readable(ALL[i], ALL[i]->sock, t);
        for (int i = 0; i < 3; i++) if (live_mask & (1 << i)) chat_tick(ALL[i], t);
    }
}

// Runs the sessions until cond holds or seconds of simulated time pass, a tenth of a second at a time.
#define RUN_UNTIL(t, seconds, cond) do { \
    double end_ = *(t) + (seconds); \
    while (!(cond) && *(t) < end_) { *(t) += 0.1; pump(2, *(t)); } \
} while (0)
#define RUN_FOR(t, seconds) RUN_UNTIL(t, seconds, 0)

static peer_t *peer_named(chat_t *c, const char *nick) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok && strcmp(c->peers[i].nick, nick) == 0) return &c->peers[i];
    return NULL;
}

static int pending_msgs(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < MAX_PENDING_MSGS; i++) n += c->pending[i].used;
    return n;
}

// Both ends say the codes matched, as two people would once they'd compared them.
static void confirm(chat_t *x, const char *x_calls_y, chat_t *y, const char *y_calls_x) {
    char cmd[64];
    snprintf(cmd, sizeof cmd, "verify %s ok", x_calls_y);
    chat_run_command(x, cmd);
    snprintf(cmd, sizeof cmd, "verify %s ok", y_calls_x);
    chat_run_command(y, cmd);
}

// A datagram unmasked with the room's key: 1 if it's a session frame, not a piece of a room frame.
static int is_session_frame(const void *data, size_t len) {
    uint8_t d[HANDSHAKE_BUF_LEN + 128];
    if (len > sizeof d || !sealed_len_ok(len, SESSION_HEADER_LEN, SESSION_MIN_BODY)) return 0;
    memcpy(d, data, len);
    if (udp_mask(A.udp_key, d, len) != 0) return 0;
    return !(d[0] == CHUNK_MAGIC0 && d[1] == CHUNK_MAGIC1);
}

// Drops the next session frame from one port to another.
typedef struct { int armed; uint16_t from, to; int dropped; } drop_t;

static int drop_one(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    drop_t *d = ctx;
    if (!d->armed || from.port != d->from || to.port != d->to) return 0;
    if (!is_session_frame(data, len)) return 0;
    d->armed = 0;
    d->dropped++;
    return 1;
}

// Drops every fifth session frame from one port to another.
typedef struct { uint16_t from, to; int seen, dropped; } lossy_t;

static int drop_fifth(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    lossy_t *l = ctx;
    if (from.port != l->from || to.port != l->to || !is_session_frame(data, len)) return 0;
    if (++l->seen % 5) return 0;
    l->dropped++;
    return 1;
}

// Nothing waits in x's queues for its peer p.
static int queues_empty(const chat_t *x, const peer_t *p) {
    int slot = (int)(p - x->peers);
    for (int i = 0; i < SENDQ_MAX; i++) if (x->sendq[i].used && x->sendq[i].peer_slot == slot) return 0;
    for (int i = 0; i < ROOMQ_MAX; i++) if (x->roomq[i].used && x->roomq[i].peer_slot == slot) return 0;
    return 1;
}

// Sends text from x, and drops the frame it goes in: with nothing else queued for y, it's the
// next session frame x sends y.
static void send_and_lose(chat_t *x, chat_t *y, const char *y_nick, const char *text, double *t) {
    peer_t *p = peer_named(x, y_nick);
    RUN_UNTIL(t, 30, p && queues_empty(x, p));
    drop_t d = { 1, x->port, y->port, 0 };
    fake_net_filter = drop_one;
    fake_net_filter_ctx = &d;
    chat_send_text(x, text, *t);
    RUN_UNTIL(t, 10, d.dropped);
    fake_net_filter = NULL;
    fake_net_filter_ctx = NULL;
    CHECK(d.dropped == 1, "the frame with \"%s\" wasn't dropped", text);
}

static void test_connect(double *t) {
    RUN_UNTIL(t, 30, chat_online_count(&A) == 1 && chat_online_count(&B) == 1 && A.peers[0].announced && B.peers[0].announced);
    CHECK(chat_online_count(&A) == 1, "alice sees %d peers, want 1", chat_online_count(&A));
    CHECK(chat_online_count(&B) == 1, "bob sees %d peers, want 1", chat_online_count(&B));
    CHECK(peer_named(&A, "bob") != NULL, "alice has no peer called bob");
    CHECK(peer_named(&B, "alice") != NULL, "bob has no peer called alice");
    peer_t *pa = peer_named(&A, "bob"), *pb = peer_named(&B, "alice");
    if (pa && pb) CHECK(memcmp(pa->vfy, pb->vfy, VERIFY_LEN) == 0, "verify codes differ");
    CHECK(log_a.compare_prompts == 1 && log_b.compare_prompts == 1, "the code to compare was shown %d and %d times, want once each",
          log_a.compare_prompts, log_b.compare_prompts);
}

// Nothing goes to a peer whose code wasn't compared; once both say it matched, it does.
static void test_verify_gate(double *t) {
    chat_send_text(&A, "before comparing", *t);
    RUN_FOR(t, 6);
    CHECK(log_count(&log_b, "before comparing") == 0, "bob got a message before the codes were compared");
    CHECK(log_a.held == 1, "alice wasn't told the message was held back");
    CHECK(pending_msgs(&A) == 0, "a message held back waits for an ack");

    chat_run_command(&A, "verify bob no");
    peer_t *pa = peer_named(&A, "bob");
    CHECK(pa && pa->code_ok < 0 && chat_code_state(&A, pa) == 3, "saying the codes differ didn't stick");
    chat_run_command(&A, "verify nobody ok");
    confirm(&A, "bob", &B, "alice");
    CHECK(pa && pa->code_ok == 1 && chat_code_state(&A, pa) == 2, "alice's ok didn't stick");

    chat_send_text(&A, "after comparing", *t);
    RUN_UNTIL(t, 10, log_count(&log_b, "alice: after comparing") == 1);
    CHECK(log_count(&log_b, "alice: after comparing") == 1, "bob didn't get the message once the codes were compared");
}

static void test_message(double *t) {
    chat_send_text(&A, "hello there", *t);
    RUN_UNTIL(t, 10, log_count(&log_b, "alice: hello there") == 1 && pending_msgs(&A) == 0);
    CHECK(log_count(&log_b, "alice: hello there") == 1, "bob didn't get alice's message once");
    CHECK(pending_msgs(&A) == 0, "alice still waits on %d acks", pending_msgs(&A));
}

// When datagrams go from alice to bob, and how big they are.
typedef struct { int n, odd_size; double last, min_gap; } rate_t;

static int watch_rate(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    rate_t *r = ctx;
    (void)data;
    if (from.port != A.port || to.port != B.port) return 0;
    if (len != UDP_CELL) r->odd_size++;
    if (r->n > 0 && g_now - r->last < r->min_gap) r->min_gap = g_now - r->last;
    r->last = g_now;
    r->n++;
    return 0;
}

// Messages don't change when datagrams go or how big they are: every one is a cell, in a slot,
// and slots come no closer together than COVER_INTERVAL, messages or no messages.
static void test_constant_rate(double *t) {
    rate_t r = { 0, 0, 0.0, 1e9 };
    fake_net_filter = watch_rate;
    fake_net_filter_ctx = &r;
    for (int i = 0; i < 8; i++) {
        char text[32];
        snprintf(text, sizeof text, "burst %d", i);
        chat_send_text(&A, text, *t);
        if (i % 3 == 0) chat_send_text(&A, "and another", *t);
        RUN_FOR(t, 0.4 + 0.3 * i);
    }
    RUN_UNTIL(t, 20, log_count(&log_b, "burst 7") == 1 && pending_msgs(&A) == 0);
    fake_net_filter = NULL;
    fake_net_filter_ctx = NULL;
    CHECK(log_count(&log_b, "burst 0") == 1 && log_count(&log_b, "burst 7") == 1, "bob didn't get the burst");
    CHECK(r.odd_size == 0, "%d of %d datagrams to bob weren't one cell", r.odd_size, r.n);
    CHECK(r.n > 5 && r.min_gap >= COVER_INTERVAL - 0.15, "datagrams to bob came %.2f s apart, less than a slot", r.min_gap);
}

// The message itself is lost and a later frame (a cover nop) gets through first, so the peer's
// chain has moved past the message's index: the retry has to be sealed afresh to be readable.
static void test_lost_message(double *t) {
    send_and_lose(&A, &B, "bob", "lost then found", t);
    RUN_FOR(t, 2);
    CHECK(log_count(&log_b, "lost then found") == 0, "bob got a message that was dropped");
    RUN_UNTIL(t, 15, log_count(&log_b, "lost then found") == 1 && pending_msgs(&A) == 0);
    CHECK(log_count(&log_b, "lost then found") == 1, "bob got the retried message %d times, want 1",
          log_count(&log_b, "lost then found"));
    CHECK(pending_msgs(&A) == 0, "alice still waits on %d acks", pending_msgs(&A));
}

static int rekeyed(chat_t *x, const char *y_nick) {
    peer_t *p = peer_named(x, y_nick);
    return p && p->keygen == x->keygen && p->chain_confirmed;
}

static void test_rekey(double *t) {
    uint32_t gen_a = A.keygen, gen_b = B.keygen;
    A.next_rekey = 0;
    B.next_rekey = 0;
    RUN_UNTIL(t, 90, A.keygen == gen_a + 1 && B.keygen == gen_b + 1 && rekeyed(&A, "bob") && rekeyed(&B, "alice"));
    CHECK(A.keygen == gen_a + 1 && B.keygen == gen_b + 1, "no rekey happened");
    CHECK(chat_online_count(&A) == 1 && chat_online_count(&B) == 1, "a rekey dropped the peer");
    CHECK(rekeyed(&A, "bob"), "alice didn't re-handshake with bob");
    CHECK(rekeyed(&B, "alice"), "bob didn't re-handshake with alice");
    peer_t *pa = peer_named(&A, "bob");
    CHECK(pa && pa->code_ok == 1, "the rekey forgot that alice compared bob's code");
    chat_send_text(&B, "after the rekey", *t);
    RUN_UNTIL(t, 10, log_count(&log_a, "bob: after the rekey") == 1);
    CHECK(log_count(&log_a, "bob: after the rekey") == 1, "alice didn't get bob's message after the rekey");
}

// A message lost just before the peer rekeys: its retry has to outlive the re-handshake, which
// reuses the peer's slot.
static void test_message_across_rekey(double *t) {
    send_and_lose(&A, &B, "bob", "sent as bob rekeys", t);
    CHECK(pending_msgs(&A) == 1, "alice isn't waiting on the message's ack");
    uint32_t gen_b = B.keygen;
    B.next_rekey = 0;
    RUN_UNTIL(t, 90, log_count(&log_b, "sent as bob rekeys") > 0 && pending_msgs(&A) == 0 && rekeyed(&B, "alice"));
    CHECK(B.keygen == gen_b + 1, "bob didn't rekey");
    CHECK(log_count(&log_b, "sent as bob rekeys") == 1, "bob got the message %d times across his rekey, want 1",
          log_count(&log_b, "sent as bob rekeys"));
    CHECK(pending_msgs(&A) == 0, "alice still waits on %d acks", pending_msgs(&A));
}

// Counts (and drops) what goes to one port.
typedef struct { uint16_t port; int n; } count_t;

static int count_to(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    count_t *c = ctx;
    (void)from; (void)data; (void)len;
    if (to.port != c->port) return 0;
    c->n++;
    return 1;
}

// A hi recorded once can be replayed from any forged address, and each unknown one gets a cookie
// challenge as big as itself: those are rate-limited, so chat can't be made a reflector.
static void test_cookie_rate(double *t) {
    char msg[HANDSHAKE_BUF_LEN];
    copy_str(msg, A.hi_msg, sizeof msg);
    uint8_t id[ID_LEN];
    gen_random(id, sizeof id);
    char idhex[ID_LEN * 2 + 1];
    hex_encode(id, ID_LEN, idhex);
    memcpy(msg + 3, idhex, ID_LEN * 2);   // "hi\t" and then the id: someone bob has never met
    uint8_t frame[HANDSHAKE_BUF_LEN + 128];
    size_t len;
    CHECK(room_seal(A.room_key, msg, strlen(msg), frame, sizeof frame, &len) == 0, "couldn't seal a hi");

    // Unmasked, as 0.1.9 sent it over UDP, it's junk now: no challenge.
    count_t old = { 5558, 0 };
    fake_net_filter = count_to;
    fake_net_filter_ctx = &old;
    fake_net_inject(fake_net_addr(5558), fake_net_addr(B.port), frame, len);
    pump(2, *t);
    fake_net_filter = NULL;
    CHECK(old.n == 0, "an unmasked hi over UDP was answered (%d datagrams)", old.n);

    // Masked, as any datagram of the room's is over UDP (whole here: the fake net takes it).
    udp_mask(A.udp_key, frame, len);
    count_t c = { 5557, 0 };
    fake_net_filter = count_to;
    fake_net_filter_ctx = &c;
    for (int i = 0; i < 200; i++) fake_net_inject(fake_net_addr(5557), fake_net_addr(B.port), frame, len);
    pump(8, *t);
    fake_net_filter = NULL;
    // Each challenge goes out in three pieces.
    CHECK(c.n > 0, "an unknown hi got no cookie challenge");
    CHECK(c.n <= 3 * (int)CK_BURST, "200 replayed hellos drew %d datagrams, want at most %d", c.n, 3 * (int)CK_BURST);
    CHECK(chat_online_count(&B) == 1, "the replays dropped a peer");
}

// What alice sends bob over UDP, as the network sees it and as bob unmasks it.
typedef struct { int n, clear, chunks, frames, odd_size; uint32_t max_index; } wire_t;

static int watch_wire(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    wire_t *w = ctx;
    uint8_t d[HANDSHAKE_BUF_LEN + 128];
    if (from.port != A.port || to.port != B.port || len > sizeof d) return 0;
    w->n++;
    if (len != UDP_CELL) w->odd_size++;
    memcpy(d, data, len);
    // Masked, a datagram's first eight bytes are never what they unmask to (2^-64 that they are).
    if (udp_mask(A.udp_key, d, len) != 0 || memcmp(d, data, 8) == 0) { w->clear++; return 0; }
    if (d[0] == CHUNK_MAGIC0 && d[1] == CHUNK_MAGIC1) {
        w->chunks++;
    } else if (sealed_len_ok(len, SESSION_HEADER_LEN, SESSION_PAD_TARGET)) {
        uint32_t index = ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | d[3];
        w->frames++;
        if (index > w->max_index) w->max_index = index;
    }
    return 0;
}

// Nothing goes over UDP in the clear: each datagram is masked, and unmasks to a piece of a room
// frame or to a session frame with its ratchet counter, and every one is a cell. The room's LAN
// port is its own.
static void test_udp_masked(double *t) {
    wire_t w = { 0 };
    fake_net_filter = watch_wire;
    fake_net_filter_ctx = &w;
    uint32_t gen_a = A.keygen;
    chat_send_text(&A, "on the wire", *t);
    A.next_rekey = 0;   // a rekey's hi: a room frame, in pieces
    RUN_UNTIL(t, 90, log_count(&log_b, "on the wire") == 1 && A.keygen == gen_a + 1 && rekeyed(&A, "bob") && w.chunks >= 3);
    fake_net_filter = NULL;
    CHECK(log_count(&log_b, "on the wire") == 1, "bob didn't get the message");
    CHECK(w.n > 0 && w.clear == 0, "%d of %d datagrams to bob went out unmasked", w.clear, w.n);
    CHECK(w.odd_size == 0, "%d of %d datagrams to bob weren't one cell", w.odd_size, w.n);
    CHECK(w.chunks >= 3, "only %d masked pieces of room frames went to bob", w.chunks);
    CHECK(w.frames >= 1 && w.max_index < 100000, "%d session frames unmasked with a counter, the highest %u",
          w.frames, (unsigned)w.max_index);
    CHECK(A.lan_port == B.lan_port && A.lan_port >= 49152, "alice's LAN port is %u, bob's %u",
          (unsigned)A.lan_port, (unsigned)B.lan_port);
}

// Every member makes the same lookup key for an hour, and a different one the next hour.
static void test_dht_keys(double *t) {
    (void)t;
    uint8_t ka[DHT_KEY_LEN], kb[DHT_KEY_LEN], h1[DHT_INFOHASH_LEN], h2[DHT_INFOHASH_LEN], h1b[DHT_INFOHASH_LEN];
    derive_dht_key(A.master, ka);
    derive_dht_key(B.master, kb);
    CHECK(memcmp(ka, kb, sizeof ka) == 0, "two members of one room made different DHT keys");
    dht_epoch_infohash(ka, 494000, h1);
    dht_epoch_infohash(kb, 494000, h1b);
    dht_epoch_infohash(ka, 494001, h2);
    CHECK(memcmp(h1, h1b, sizeof h1) == 0, "two members looked up different keys in the same hour");
    CHECK(memcmp(h1, h2, sizeof h1) != 0, "the lookup key didn't change with the hour");
    CHECK(memcmp(h1, ka, sizeof h1) != 0, "the lookup key is the DHT key itself");

    static const uint8_t code[5] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5 };
    char grouped[HEX_GROUPS_LEN(5)];
    hex_groups(code, sizeof code, grouped);
    CHECK(strcmp(grouped, "a1b2 c3d4 e5") == 0, "a code came out grouped as '%s'", grouped);
}

// What a DHT sends, as its output sees it.
#define DHT_SENT_MAX 256
static struct { int n; struct { uint8_t data[300]; size_t len; addr_t to; int named; } m[DHT_SENT_MAX]; } g_dht_sent;

static void dht_capture(void *ctx, const void *data, size_t len, const addr_t *to, const char *host, uint16_t port) {
    (void)ctx; (void)port;
    if (g_dht_sent.n >= DHT_SENT_MAX || len > sizeof g_dht_sent.m[0].data) return;
    memcpy(g_dht_sent.m[g_dht_sent.n].data, data, len);
    g_dht_sent.m[g_dht_sent.n].len = len;
    g_dht_sent.m[g_dht_sent.n].named = host != NULL;
    if (to) g_dht_sent.m[g_dht_sent.n].to = *to;
    g_dht_sent.n++;
}

static const uint8_t *find_bytes(const uint8_t *h, size_t hl, const char *needle) {
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= hl; i++) if (memcmp(h + i, needle, nl) == 0) return h + i;
    return NULL;
}

// The DHT asks as a read-only node, by name through a proxy when it has one, and once it knows
// enough nodes, starts from them instead of the bootstrap servers.
static void test_dht(double *t) {
    (void)t;
    static dht_state_t d;
    uint8_t key[DHT_KEY_LEN] = { 7 };
    dht_init(&d, key, 40000, 1, 0);
    dht_set_output(&d, dht_capture, NULL, 1);
    g_dht_sent.n = 0;
    double now = 1000.0;
    dht_step(&d, now);
    dht_step(&d, now);
    int named = 0, ro = 0;
    for (int i = 0; i < g_dht_sent.n; i++) {
        named += g_dht_sent.m[i].named;
        ro += find_bytes(g_dht_sent.m[i].data, g_dht_sent.m[i].len, "2:roi1e") != NULL;
    }
    CHECK(g_dht_sent.n == 4 && named == 4, "the first round asked %d servers, %d by name; want the 4 bootstrap names", g_dht_sent.n, named);
    CHECK(ro == g_dht_sent.n, "%d of %d queries didn't say read-only", g_dht_sent.n - ro, g_dht_sent.n);

    // Each server answers from an address of its own, with ten nodes.
    int answered = g_dht_sent.n;
    for (int i = 0; i < answered; i++) {
        const uint8_t *tp = find_bytes(g_dht_sent.m[i].data, g_dht_sent.m[i].len, "1:t2:");
        if (!tp) continue;
        uint8_t reply[400];
        size_t p = 0;
        p += (size_t)snprintf((char *)reply, sizeof reply, "d1:rd2:id20:");
        gen_random(reply + p, 20); p += 20;
        p += (size_t)snprintf((char *)reply + p, sizeof reply - p, "5:nodes260:");
        for (int k = 0; k < 10; k++) {
            gen_random(reply + p, 20);
            uint8_t ip[4] = { 10, 1, (uint8_t)i, (uint8_t)(k + 1) };
            memcpy(reply + p + 20, ip, 4);
            reply[p + 24] = 0x1a; reply[p + 25] = 0xe1;
            p += 26;
        }
        p += (size_t)snprintf((char *)reply + p, sizeof reply - p, "e1:t2:");
        memcpy(reply + p, tp + 5, 2); p += 2;
        p += (size_t)snprintf((char *)reply + p, sizeof reply - p, "1:y1:re");
        addr_t from;
        uint8_t fip[4] = { 10, 9, 9, (uint8_t)(i + 1) };
        addr_set_v4(&from, fip, 6881);
        dht_on_packet(&d, reply, p, from, NULL, NULL);
    }
    // The nodes they named answer too, until the round ends.
    for (int round = 0; round < 40 && (d.lk[DHT_V4].active); round++) {
        int from_i = g_dht_sent.n;
        now += 0.5;
        dht_step(&d, now);
        for (int i = from_i; i < g_dht_sent.n; i++) {
            if (g_dht_sent.m[i].named) continue;
            const uint8_t *tp = find_bytes(g_dht_sent.m[i].data, g_dht_sent.m[i].len, "1:t2:");
            if (!tp || !find_bytes(g_dht_sent.m[i].data, g_dht_sent.m[i].len, "9:get_peers")) continue;
            uint8_t reply[128];
            size_t p = (size_t)snprintf((char *)reply, sizeof reply, "d1:rd2:id20:");
            gen_random(reply + p, 20); p += 20;
            p += (size_t)snprintf((char *)reply + p, sizeof reply - p, "5:token4:abcde1:t2:");
            memcpy(reply + p, tp + 5, 2); p += 2;
            p += (size_t)snprintf((char *)reply + p, sizeof reply - p, "1:y1:re");
            dht_on_packet(&d, reply, p, g_dht_sent.m[i].to, NULL, NULL);
        }
    }
    CHECK(!d.lk[DHT_V4].active, "the lookup never finished");
    // The next round: the nodes that answered, and no bootstrap server.
    int before = g_dht_sent.n;
    d.next_lookup = 0;
    now += 1.0;
    dht_step(&d, now);
    dht_step(&d, now);
    int again_named = 0, again = g_dht_sent.n - before;
    for (int i = before; i < g_dht_sent.n; i++) again_named += g_dht_sent.m[i].named;
    CHECK(again > 0 && again_named == 0, "the second round asked %d nodes, %d of them bootstrap servers by name", again, again_named);
}

// Key files and Tor's cookie are read without blocking, and only from regular files: a FIFO
// would otherwise hang chat.
static void test_read_file(double *t) {
    (void)t;
    char dir[] = "/tmp/chat-test-XXXXXX";
    if (!mkdtemp(dir)) { CHECK(0, "no temporary folder for the file test"); return; }
    char fifo[64], file[64];
    snprintf(fifo, sizeof fifo, "%s/fifo", dir);
    snprintf(file, sizeof file, "%s/key", dir);
    char buf[64];
    CHECK(mkfifo(fifo, 0600) == 0, "couldn't make a FIFO");
    CHECK(platform_read_file(fifo, buf, sizeof buf) == -1, "a FIFO was read as a file");
    FILE *f = fopen(file, "wb");
    if (f) { fputs("hello", f); fclose(f); }
    CHECK(platform_read_file(file, buf, sizeof buf) == 5 && memcmp(buf, "hello", 5) == 0, "a regular file didn't read back");
    CHECK(platform_read_file(file, buf, 3) == 3, "a read past cap");
    CHECK(platform_read_file(dir, buf, sizeof buf) == -1, "a folder was read as a file");
    identity_keypair_t id;
    CHECK(age_import_secret_key(fifo, &id) != 0 && pgp_import_secret_key(fifo, &id) != 0, "a key loaded from a FIFO");
    unlink(fifo);
    unlink(file);
    rmdir(dir);
}

// Junk from outside the room, some of it sized like real frames or cells, and pieces of nothing
// from inside it (masked, so they unmask to a piece's header): nothing may break.
static void test_junk(double *t) {
    addr_t stranger = fake_net_addr(5555), a_addr = fake_net_addr(A.port);
    static const size_t sizes[] = { 0, 1, 4, 27, 428, 492, 1004, 1008, 2600, 2664, 3000 };
    uint8_t junk[3000];
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        for (int rep = 0; rep < 4; rep++) {
            gen_random(junk, sizeof junk);
            if (rep == 1 && sizes[k] >= CHUNK_HDR) {
                junk[0] = CHUNK_MAGIC0; junk[1] = CHUNK_MAGIC1; junk[6] = 0; junk[7] = 3; junk[8] = 0x0a; junk[9] = 0x28;
                udp_mask(A.udp_key, junk, sizes[k]);
            }
            if (rep == 2 && sizes[k] >= 1) junk[0] = 'd';
            if (rep == 3 && sizes[k] >= 4) memset(junk, 0, 4);
            fake_net_inject(stranger, a_addr, junk, sizes[k]);
        }
    }
    unsigned other_before = A.st.other;
    pump(2, *t);
    CHECK(A.st.other > other_before, "junk wasn't counted as unreadable");
    CHECK(chat_online_count(&A) == 1, "junk dropped a peer");
    chat_send_text(&A, "still here", *t);
    RUN_UNTIL(t, 10, log_count(&log_b, "still here") == 1);
    CHECK(log_count(&log_b, "still here") == 1, "messages stopped after junk");
}

static void test_lookalike_nick(double *t) {
    chat_set_nick(&B, "ALlCE");
    RUN_UNTIL(t, 10, peer_named(&A, "ALlCE") != NULL);
    peer_t *pb = peer_named(&A, "ALlCE");
    CHECK(pb != NULL, "alice didn't see bob's new nick");
    if (pb) {
        char name[CHAT_NAME_LEN];
        chat_peer_name(&A, pb, name);
        CHECK(strchr(name, '#') != NULL, "a nick that looks like alice's own shows as '%s', without an id", name);
    }
    chat_set_nick(&B, "bob");
    RUN_UNTIL(t, 10, peer_named(&A, "bob") != NULL);
}

// Carol joins through alice only: bob hears about her from alice (px) and connects directly.
// Carol's first session frame to alice is lost, so her next one gets through first. Alice still
// has to say carol joined, not an "anon".
static void test_third_peer(double *t) {
    uint16_t via_alice[1] = { A.port };
    start(&C, &log_c, "carol", 40003, via_alice, 1, 0, BUILD_CAROL, 0);
    n_live = 3;
    live_mask = 0x7;
    drop_t d = { 1, 40003, A.port, 0 };
    fake_net_filter = drop_one;
    fake_net_filter_ctx = &d;
    RUN_UNTIL(t, 60, chat_online_count(&C) == 2 && chat_online_count(&B) == 2 && peer_named(&A, "carol")
                     && peer_named(&B, "carol") && peer_named(&C, "alice") && peer_named(&C, "bob"));
    fake_net_filter = NULL;
    RUN_FOR(t, JOIN_WAIT + 1);
    CHECK(d.dropped == 1, "carol's first frame to alice wasn't dropped");
    CHECK(chat_online_count(&C) == 2, "carol sees %d peers, want 2", chat_online_count(&C));
    CHECK(chat_online_count(&B) == 2, "bob sees %d peers, want 2", chat_online_count(&B));
    CHECK(peer_named(&A, "carol") != NULL, "alice never learned carol's nick");
    CHECK(log_a.anon_joins == 0 && log_b.anon_joins == 0, "a peer joined as anon (alice %d, bob %d)",
          log_a.anon_joins, log_b.anon_joins);
    for (int i = 0; i < n_live; i++) {
        const log_t *l = ALL_LOGS[i];
        CHECK(l->unheralded_joins == 0 && l->joining == 0, "%s printed %d joined without joining first, and %d "
              "joining without joined after", l->who, l->unheralded_joins, l->joining);
    }
    confirm(&A, "carol", &C, "alice");
    confirm(&B, "carol", &C, "bob");
    chat_send_text(&C, "hi all", *t);
    RUN_UNTIL(t, 10, log_count(&log_a, "carol: hi all") == 1 && log_count(&log_b, "carol: hi all") == 1);
    CHECK(log_count(&log_a, "carol: hi all") == 1, "alice didn't get carol's message once");
    CHECK(log_count(&log_b, "carol: hi all") == 1, "bob didn't get carol's message once");
}

// A peer already connected is no candidate: the keepalive's static peers stop being tried.
static void test_candidates_settle(double *t) {
    RUN_FOR(t, KEEPALIVE + 4.0);
    CHECK(chat_candidate_count(&A) == 0, "alice still tries %d candidates she's connected to", chat_candidate_count(&A));
    CHECK(chat_online_count(&A) == 2, "alice lost a peer");
}

// Rekeys carol, which sends her "v" again with whatever her build now says.
static void resend_carol(double *t) {
    uint32_t gen = C.keygen;
    C.next_rekey = 0;
    RUN_UNTIL(t, 90, C.keygen == gen + 1 && rekeyed(&C, "alice") && rekeyed(&C, "bob")
                     && rekeyed(&A, "carol") && rekeyed(&B, "carol"));
    RUN_FOR(t, 8);
}

// Each peer's "v" against the signed list it came with.
static void test_builds(double *t) {
    RUN_FOR(t, 5);
    peer_t *ab = peer_named(&A, "bob"), *ba = peer_named(&B, "alice"), *ca = peer_named(&C, "alice");
    peer_t *ac = peer_named(&A, "carol"), *bc = peer_named(&B, "carol");
    CHECK(ab && ab->build_state == BUILD_OFFICIAL, "alice doesn't see bob's build as official");
    CHECK(ba && ba->build_state == BUILD_OFFICIAL, "bob doesn't see alice's build as official");
    CHECK(ca && ca->build_state == BUILD_OFFICIAL, "carol doesn't see alice's build as official");
    CHECK(ac && ac->build_state == BUILD_MODIFIED, "alice doesn't see carol's build as modified");
    CHECK(bc && bc->build_state == BUILD_MODIFIED, "bob doesn't see carol's build as modified");
    CHECK(log_a.modified_warnings == 1 && log_b.modified_warnings == 1, "carol's build was warned about %d and %d times, want once each",
          log_a.modified_warnings, log_b.modified_warnings);
    CHECK(log_c.modified_warnings == 0, "carol was warned about a release build");
    char label[64];
    if (ab) chat_build_label(ab, label, sizeof label);
    CHECK(ab && strcmp(label, "says official v1.2.3") == 0, "bob's build shows as '%s'", ab ? label : "");

    // A rekey sends the same "v" again: no second warning.
    A.next_rekey = B.next_rekey = 0;
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_MODIFIED, "carol's build isn't modified after the rekey");
    CHECK(log_a.modified_warnings == 1, "a rekey warned about carol's build again");

    // Alice's list, passed on: carol's own hash still isn't in it.
    copy_str(C.build.list, release_list, sizeof C.build.list);
    copy_str(C.build.list_sig, release_sig, sizeof C.build.list_sig);
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_MODIFIED, "carol passed with someone else's list");

    // The list is signed for 1.2.3: under another version, even a hash in it doesn't pass.
    copy_str(C.build.version, "9.9.9", sizeof C.build.version);
    memcpy(C.build.hash, BUILD_ALICE, BUILD_HASH_LEN);
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_MODIFIED && strcmp(ac->build_version, "9.9.9") == 0,
          "1.2.3's list passed for 9.9.9");
    CHECK(log_a.modified_warnings == 2, "alice warned %d times about carol, want 2", log_a.modified_warnings);
    if (ac) chat_build_label(ac, label, sizeof label);
    CHECK(ac && strcmp(label, "modified client (says v9.9.9)") == 0, "carol's build shows as '%s'", ac ? label : "");

    // What no check can catch: carol says she runs alice's binary, and sends its list.
    copy_str(C.build.version, "1.2.3", sizeof C.build.version);
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_OFFICIAL, "a peer lying with an official hash wasn't taken at its word");
}

// What comes from relays, routers and Tor, taken apart without a network.
static void test_passphrase_seal(double *t) {
    (void)t;
    static const uint8_t secret[104] = "a signing key, as :install packs it";
    static const char settings[] = "[profile]\nnick = \"alice\"\n";
    uint8_t sealed[sizeof secret + PASS_SEAL_OVERHEAD], opened[sizeof secret];
    uint8_t sealed2[sizeof settings + PASS_SEAL_OVERHEAD], opened2[sizeof settings];
    size_t n = 0, n2 = 0, got = 0;
    pass_lock_t lk, again, wrong;
    CHECK(pass_lock_new("correct horse", &lk) == 0, "making a lock failed");
    CHECK(pass_seal(&lk, secret, sizeof secret, sealed, sizeof sealed - 1, &n) == PASS_FORMAT,
          "sealing into too small a buffer didn't refuse");
    CHECK(pass_seal(&lk, secret, sizeof secret, sealed, sizeof sealed, &n) == 0 && n == sizeof sealed,
          "sealing failed, or made %zu bytes, want %zu", n, sizeof sealed);
    CHECK(pass_seal(&lk, settings, sizeof settings, sealed2, sizeof sealed2, &n2) == 0
          && memcmp(sealed, sealed2, PASS_HEADER_LEN) == 0 && memcmp(sealed + PASS_HEADER_LEN, sealed2 + PASS_HEADER_LEN,
                                                                     AEAD_NONCE_LEN) != 0,
          "two secrets under one lock didn't share its header, or shared a nonce");
    // One Argon2id run, from either file, opens both.
    int rc = pass_lock_of("correct horse", sealed2, n2, &again);
    CHECK(rc == 0, "the right passphrase didn't make a lock (%d)", rc);
    rc = pass_unseal(&again, sealed, n, opened, sizeof opened, &got);
    CHECK(rc == 0 && got == sizeof secret && memcmp(opened, secret, sizeof secret) == 0,
          "the right passphrase didn't open the key (%d)", rc);
    rc = pass_unseal(&again, sealed2, n2, opened2, sizeof opened2, &got);
    CHECK(rc == 0 && got == sizeof settings && memcmp(opened2, settings, sizeof settings) == 0,
          "the right passphrase didn't open the settings (%d)", rc);
    CHECK(pass_lock_of("correct horsf", sealed, n, &wrong) == 0
          && pass_unseal(&wrong, sealed, n, opened, sizeof opened, &got) == PASS_WRONG,
          "a wrong passphrase didn't fail as one");
    pass_lock_t other;
    CHECK(pass_lock_new("correct horse", &other) == 0
          && pass_unseal(&other, sealed, n, opened, sizeof opened, &got) == PASS_WRONG,
          "the same passphrase with another salt opened it");
    sealed[16] ^= 1;   // the salt
    CHECK(pass_unseal(&lk, sealed, n, opened, sizeof opened, &got) == PASS_WRONG
          && pass_lock_of("correct horse", sealed, n, &wrong) == 0
          && pass_unseal(&wrong, sealed, n, opened, sizeof opened, &got) == PASS_WRONG,
          "a changed header still opened");
    sealed[16] ^= 1;
    sealed[PASS_SEAL_OVERHEAD] ^= 1;   // the sealed secret
    CHECK(pass_unseal(&lk, sealed, n, opened, sizeof opened, &got) == PASS_WRONG, "a changed secret still opened");
    sealed[PASS_SEAL_OVERHEAD] ^= 1;
    sealed[12] = 0xff;   // an Argon2id memory limit no one would ask for
    CHECK(pass_lock_of("correct horse", sealed, n, &wrong) == PASS_FORMAT,
          "a tampered memory limit wasn't refused before Argon2id ran");
    uint8_t junk[PASS_SEAL_OVERHEAD + 8];
    memset(junk, 'x', sizeof junk);
    CHECK(pass_lock_of("correct horse", junk, sizeof junk, &wrong) == PASS_FORMAT
          && pass_unseal(&lk, junk, sizeof junk, opened, sizeof opened, &got) == PASS_FORMAT,
          "bytes that were never sealed weren't refused");
}

static void test_identity_keys(double *t) {
    (void)t;
    // An identity file age-keygen wrote, and the recipient it gave for it.
    static const char age_file[] =
        "# created: 2026-09-29T12:00:00+02:00\n"
        "# public key: age18t0t9tvw7r6at489p6jm9ngptg3j7tcyps5pn47fgvvzayc82dmsnghjje\n"
        "AGE-SECRET-KEY-1DRRXFHJCPKR2T7VJRQ4A4XR2P8NTDCT4J5GMQL3DRVRWMNVU90PST53ZSA\n";
    identity_keypair_t id;
    memset(&id, 0, sizeof id);
    CHECK(age_import_secret_key_text(age_file, &id) == 0 && id.scalar, "an age-keygen key didn't load");
    char recipient[AGE_RECIPIENT_STRLEN + 1];
    age_export_recipient(&id, recipient);
    CHECK(strcmp(recipient, "age18t0t9tvw7r6at489p6jm9ngptg3j7tcyps5pn47fgvvzayc82dmsnghjje") == 0,
          "the AGE key's recipient came out as %s", recipient);

    uint8_t eph_a[PUB_LEN], id_a[ID_LEN], eph_b[PUB_LEN], id_b[ID_LEN], sig[ID_SIGN_LEN];
    gen_random(eph_a, sizeof eph_a); gen_random(id_a, sizeof id_a);
    gen_random(eph_b, sizeof eph_b); gen_random(id_b, sizeof id_b);
    identity_sign(&id, eph_a, id_a, eph_b, id_b, sig);
    CHECK(identity_verify(id.pub, sig, eph_a, id_a, eph_b, id_b) == 0, "a signature by the AGE key didn't verify");
    sig[40] ^= 1;
    CHECK(identity_verify(id.pub, sig, eph_a, id_a, eph_b, id_b) != 0, "a tampered signature verified");

    char typo[sizeof age_file];
    memcpy(typo, age_file, sizeof typo);
    char *c = strstr(typo, "AGE-SECRET-KEY-1") + 30;
    *c = *c == 'Q' ? 'P' : 'Q';
    identity_keypair_t before = id;
    CHECK(age_import_secret_key_text(typo, &id) != 0, "an AGE key with a typo loaded");
    CHECK(memcmp(&id, &before, sizeof id) == 0, "a key that failed to load changed the identity");

    // The scalar signer against libsodium's: a seed key, put as its scalar and nonce key, has to
    // sign the same bytes.
    identity_keypair_t seeded, split;
    gen_identity_keypair(&seeded);
    uint8_t h[64], wide[64] = {0};
    crypto_hash_sha512(h, seeded.priv, 32);
    memcpy(wide, h, 32);
    wide[0] &= 248; wide[31] &= 127; wide[31] |= 64;
    memcpy(split.pub, seeded.pub, sizeof split.pub);
    crypto_core_ed25519_scalar_reduce(split.priv, wide);
    memcpy(split.priv + 32, h + 32, 32);
    split.scalar = 1;
    uint8_t msg[200], want[ID_SIGN_LEN], got[ID_SIGN_LEN];
    gen_random(msg, sizeof msg);
    identity_sign_bytes(&seeded, msg, sizeof msg, want);
    identity_sign_bytes(&split, msg, sizeof msg, got);
    CHECK(memcmp(want, got, sizeof want) == 0, "the scalar signer and libsodium signed differently");

    char armor[PGP_ARMOR_MAX];
    uint8_t fp[PGP_FP_LEN], fp2[PGP_FP_LEN];
    pgp_export_public_key(&seeded, "alice", 1790000000u, armor, sizeof armor, fp);
    pgp_export_public_key(&seeded, "alice", 1790000000u, armor, sizeof armor, fp2);
    CHECK(memcmp(fp, fp2, sizeof fp) == 0, "the same PGP key exported twice changed fingerprint");
    CHECK(strstr(armor, "-----END PGP PUBLIC KEY BLOCK-----") != NULL, "the PGP public key has no END line");

    // A key made from a password has to come out the same on every run and in every version, or
    // everyone's established identity changes. The answer is from Python's cryptography package:
    // Argon2id (4 passes, 512 MiB, one lane) over a BLAKE2b-128 salt of the label and device id.
    static const char device[] = "0123456789abcdef0123456789abcdef";
    identity_keypair_t derived, other;
    CHECK(identity_from_password("correct horse battery staple", device, &derived) == 0 && !derived.scalar,
          "no key came from a password");
    char pubhex[ID_SIGN_PUB_LEN * 2 + 1];
    hex_encode(derived.pub, ID_SIGN_PUB_LEN, pubhex);
    CHECK(strcmp(pubhex, "044354ed8bd36257adf234b893510d040769ba720f4e886431c27211e3b5dec2") == 0,
          "the key from a password came out as %s", pubhex);
    CHECK(identity_from_password("correct horse battery staple", "0123456789abcdef0123456789abcdee", &other) == 0
          && memcmp(derived.pub, other.pub, sizeof derived.pub) != 0, "another device made the same key");
    identity_sign_bytes(&derived, msg, sizeof msg, got);
    CHECK(crypto_sign_verify_detached(got, msg, sizeof msg, derived.pub) == 0, "the key from a password can't sign");
}

// ---- images ----

// A 4x2 PNG and an 8x8 grey (200) JPEG, as Pillow writes them.
static const uint8_t PNG_4X2[92] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00, 0x00, 0xf0, 0xca, 0xea,
    0x34, 0x00, 0x00, 0x00, 0x23, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xc0,
    0xf0, 0x9f, 0x81, 0x81, 0xe1, 0xff, 0xff, 0xff, 0xff, 0x19, 0x18, 0x18, 0x18, 0x1a, 0x1a, 0x1a,
    0xb8, 0x44, 0xe4, 0x4e, 0xa4, 0x18, 0x01, 0x00, 0x7c, 0x18, 0x09, 0x15, 0x20, 0xf5, 0x79, 0xd9,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
};
static const uint8_t JPEG_GREY[333] = {
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02,
    0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x04, 0x03, 0x02, 0x02, 0x02, 0x02, 0x05, 0x04,
    0x04, 0x03, 0x04, 0x06, 0x05, 0x06, 0x06, 0x06, 0x05, 0x06, 0x06, 0x06, 0x07, 0x09, 0x08, 0x06,
    0x07, 0x09, 0x07, 0x06, 0x06, 0x08, 0x0b, 0x08, 0x09, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x06, 0x08,
    0x0b, 0x0c, 0x0b, 0x0a, 0x0c, 0x09, 0x0a, 0x0a, 0x0a, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x08,
    0x00, 0x08, 0x01, 0x01, 0x11, 0x00, 0xff, 0xc4, 0x00, 0x1f, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xc4, 0x00, 0xb5, 0x10, 0x00, 0x02, 0x01, 0x03,
    0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7d, 0x01, 0x02, 0x03, 0x00,
    0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32,
    0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55,
    0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92, 0x93, 0x94,
    0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2,
    0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
    0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
    0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xff, 0xda,
    0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0xfd, 0x20, 0xaf, 0xff, 0xd9,
};

static void test_images(double *t) {
    (void)t;
    static const uint8_t bg[3] = { 0, 0, 0 };
    static const uint8_t want[8][3] = { { 255, 0, 0 }, { 0, 255, 0 }, { 0, 0, 255 }, { 255, 255, 255 },
                                        { 0, 0, 0 }, { 128, 128, 128 }, { 10, 20, 30 }, { 200, 100, 50 } };
    image_thumb_t th;
    char why[160];
    CHECK(image_thumbnail(PNG_4X2, sizeof PNG_4X2, 64, 48, bg, &th, why, sizeof why) == 0 && th.w == 4 && th.h == 2
          && th.src_w == 4 && th.src_h == 2 && memcmp(th.rgb, want, sizeof want) == 0, "the 4x2 PNG: %s", why);
    image_thumb_free(&th);
    // Shrunk to one pixel: the average of all eight.
    CHECK(image_thumbnail(PNG_4X2, sizeof PNG_4X2, 1, 1, bg, &th, why, sizeof why) == 0 && th.w == 1 && th.h == 1,
          "the 4x2 PNG at 1x1: %s", why);
    if (th.rgb) CHECK(th.rgb[0] == 106 && th.rgb[1] == 95 && th.rgb[2] == 90, "1x1 average %u,%u,%u", th.rgb[0], th.rgb[1], th.rgb[2]);
    image_thumb_free(&th);
    CHECK(image_thumbnail(JPEG_GREY, sizeof JPEG_GREY, 64, 48, bg, &th, why, sizeof why) == 0 && th.w == 8 && th.h == 8,
          "the grey JPEG: %s", why);
    int far = 0;
    for (int i = 0; th.rgb && i < 8 * 8 * 3; i++) far += th.rgb[i] < 198 || th.rgb[i] > 202;
    CHECK(far == 0, "the grey JPEG came out %d samples off 200", far);
    image_thumb_free(&th);

    // Damage of every kind is refused with a reason, never read past.
    uint8_t bad[sizeof PNG_4X2];
    memcpy(bad, PNG_4X2, sizeof bad);
    bad[sizeof bad - 20] ^= 0x40;
    CHECK(image_thumbnail(bad, sizeof bad, 64, 48, bg, &th, why, sizeof why) != 0 && why[0], "a damaged PNG decoded");
    for (size_t cut = 0; cut < sizeof PNG_4X2; cut += 7)
        CHECK(image_thumbnail(PNG_4X2, cut, 64, 48, bg, &th, why, sizeof why) != 0, "a PNG cut to %zu bytes decoded", cut);
    for (size_t cut = 0; cut < sizeof JPEG_GREY - 2; cut += 11)
        CHECK(image_thumbnail(JPEG_GREY, cut, 64, 48, bg, &th, why, sizeof why) != 0 || (image_thumb_free(&th), 1),
              "a JPEG cut to %zu bytes", cut);
    CHECK(image_thumbnail((const uint8_t *)"GIF89a", 6, 64, 48, bg, &th, why, sizeof why) != 0, "a GIF decoded");
    CHECK(image_kind(PNG_4X2, sizeof PNG_4X2) && strcmp(image_kind(PNG_4X2, sizeof PNG_4X2), "png") == 0
          && strcmp(image_kind(JPEG_GREY, sizeof JPEG_GREY), "jpeg") == 0, "images weren't told apart");
}

// ---- files ----

static struct { int calls, num; size_t len; uint8_t data[65536]; } g_viewed;

static void on_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
    (void)ui; (void)name;
    g_viewed.calls++;
    g_viewed.num = num;
    g_viewed.len = len;
    memcpy(g_viewed.data, data, len < sizeof g_viewed.data ? len : sizeof g_viewed.data);
}

static int offer_named(chat_t *c, const char *name) {
    for (int n = c->file_seq; n >= 1; n--) {
        const file_entry_t *e = chat_file(c, n);
        if (e && !e->mine && strcmp(e->name, name) == 0) return n;
    }
    return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(data, 1, len, f);
    return fclose(f) == 0 && w == len ? 0 : -1;
}

static int same_file(const char *path, const uint8_t *data, size_t len) {
    static uint8_t buf[300000];
    long n = platform_read_file(path, buf, sizeof buf);
    return n == (long)len && memcmp(buf, data, len) == 0;
}

// How file n's fetch stands, or -1 if there's no file n: an offer that never came fails a check
// rather than the whole test.
static int dl_state(chat_t *c, int n) {
    const file_entry_t *e = n > 0 ? chat_file(c, n) : NULL;
    return e ? (int)e->dl : -1;
}

static int dl_over(chat_t *c, int n) {
    const file_entry_t *e = chat_file(c, n);
    return !e || e->dl == DL_DONE || e->dl == DL_FAILED;
}

// Changes a byte of the file at path.
static void f_flip(const char *path) {
    FILE *f = fopen(path, "r+b");
    if (!f) return;
    int ch = fgetc(f);
    fseek(f, 0, SEEK_SET);
    fputc(ch ^ 1, f);
    fclose(f);
}

static int part_files_left(const char *dir) {
    char cmd[700];
    snprintf(cmd, sizeof cmd, "ls -a '%s' | grep -c '^\\.chat-' > /dev/null", dir);
    return system(cmd) == 0;
}

static void test_files(double *t) {
    // Downloads of the test's own.
    static char home[] = "/tmp/chat-files-XXXXXX";
    CHECK(mkdtemp(home) != NULL, "no temporary folder");
    setenv("HOME", home, 1);
    char dl[600], path[600], cmd[700], want[700];
    snprintf(dl, sizeof dl, "%s/Downloads", home);
    A.file_view = B.file_view = on_view;
    static uint8_t data[200000];
    gen_random(data, sizeof data);

    // A file offered, and nothing moves until bob asks.
    snprintf(path, sizeof path, "%s/notes.txt", home);
    write_file(path, data, 5000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "notes.txt") > 0);
    int n = offer_named(&B, "notes.txt");
    CHECK(n > 0 && log_count(&log_b, "offers notes.txt (5 KB) - :download") == 1, "bob didn't see the offer");
    CHECK(n > 0 && chat_file(&B, n)->size == 5000 && chat_file(&B, n)->dl == DL_NONE, "the offer came wrong, or started by itself");
    CHECK(chat_file_fetch(&B, n, 1, 0, NULL) != 0, "a file not offered as a picture was fetched to show");

    // Saved, whole, under its name. Asked for again, it's already there and isn't fetched. Into
    // another folder, it's copied from there. Once the saved one changes, it's fetched again, under
    // the next name. No partial file is left at any point.
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch notes.txt");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/notes.txt", dl);
    CHECK(dl_state(&B, n) == DL_DONE && same_file(want, data, 5000), "notes.txt didn't arrive whole");
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0 && dl_state(&B, n) == DL_DONE, "notes.txt was fetched again while saved");
    char other[400];
    snprintf(other, sizeof other, "%s/other", home);
    mkdir(other, 0700);
    CHECK(chat_file_fetch(&B, n, 0, 0, other) == 0 && dl_state(&B, n) == DL_DONE, "notes.txt wasn't copied to another folder");
    snprintf(path, sizeof path, "%s/notes.txt", other);
    CHECK(same_file(path, data, 5000) && strcmp(chat_file(&B, n)->saved, path) == 0, "the copy in another folder is wrong");
    f_flip(path);
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0 && dl_state(&B, n) == DL_ACTIVE, "a changed copy wasn't fetched again");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/notes (2).txt", dl);
    CHECK(same_file(want, data, 5000), "the second copy wasn't saved beside the first");
    CHECK(!part_files_left(dl) && !part_files_left(other), "a partial file was left behind");
    platform_remove(want);

    // Past bob's limit only with "anyway".
    chat_set_file_options(&B, 1000, 0);
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) != 0, "a file over the limit was fetched");
    CHECK(chat_file_fetch(&B, n, 0, 1, NULL) == 0, "anyway didn't fetch past the limit");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/notes (2).txt", dl);
    CHECK(same_file(want, data, 5000), "the file fetched anyway didn't arrive");
    chat_set_file_options(&B, 0, 0);

    // A picture, fetched to show: handed over whole, never saved.
    snprintf(path, sizeof path, "%s/pic.png", home);
    write_file(path, PNG_4X2, sizeof PNG_4X2);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "pic.png") > 0);
    n = offer_named(&B, "pic.png");
    CHECK(n > 0 && chat_file(&B, n)->image && log_count(&log_b, ":show") >= 1, "the picture wasn't offered as one");
    g_viewed.calls = 0;
    CHECK(chat_file_fetch(&B, n, 1, 0, NULL) == 0, "bob couldn't fetch the picture to show");
    RUN_UNTIL(t, 60, g_viewed.calls > 0);
    CHECK(g_viewed.calls == 1 && g_viewed.num == n && g_viewed.len == sizeof PNG_4X2
          && memcmp(g_viewed.data, PNG_4X2, sizeof PNG_4X2) == 0, "the picture wasn't handed over whole");
    snprintf(want, sizeof want, "%s/pic.png", dl);
    CHECK(platform_read_file(want, data + 199000, 10) < 0, "a picture fetched to show was saved");

    // Shown again, and then saved, from the copy kept in memory: nothing is fetched again.
    CHECK(chat_file(&B, n)->cache != NULL, "the picture shown wasn't kept");
    CHECK(chat_file_fetch(&B, n, 1, 0, NULL) == 0 && g_viewed.calls == 2 && dl_state(&B, n) == DL_DONE,
          "the picture wasn't shown again from memory");
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0 && dl_state(&B, n) == DL_DONE && same_file(want, PNG_4X2, sizeof PNG_4X2),
          "the picture shown wasn't saved from memory");
    CHECK(!part_files_left(dl), "saving from memory left a partial file");

    // Shown and saved in one fetch: :download while it's coming to be shown.
    snprintf(path, sizeof path, "%s/pic2.png", home);
    write_file(path, PNG_4X2, sizeof PNG_4X2);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "pic2.png") > 0);
    n = offer_named(&B, "pic2.png");
    g_viewed.calls = 0;
    CHECK(chat_file_fetch(&B, n, 1, 0, NULL) == 0 && chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't ask for pic2.png");
    RUN_UNTIL(t, 60, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/pic2.png", dl);
    CHECK(g_viewed.calls == 1 && same_file(want, PNG_4X2, sizeof PNG_4X2), "pic2.png wasn't both shown and saved");

    // Two files from the same sender: the second waits for the first, then starts by itself.
    // :download without a number takes the newest.
    snprintf(path, sizeof path, "%s/one.bin", home);
    write_file(path, data, 4000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    snprintf(path, sizeof path, "%s/two.bin", home);
    write_file(path, data + 4000, 3000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "one.bin") > 0 && offer_named(&B, "two.bin") > 0);
    int one = offer_named(&B, "one.bin"), two = offer_named(&B, "two.bin");
    chat_run_command(&B, "download");
    CHECK(dl_state(&B, two) == DL_ACTIVE, ":download alone didn't take the newest file");
    CHECK(chat_file_fetch(&B, one, 0, 0, NULL) == 0 && dl_state(&B, one) == DL_QUEUED, "one.bin wasn't queued");
    RUN_UNTIL(t, 200, dl_over(&B, one));
    snprintf(want, sizeof want, "%s/two.bin", dl);
    char got1[700];
    snprintf(got1, sizeof got1, "%s/one.bin", dl);
    CHECK(same_file(want, data + 4000, 3000) && same_file(got1, data, 4000), "the queued file didn't follow the first");

    // Changed after it was offered: thrown away, not saved.
    snprintf(path, sizeof path, "%s/changing.bin", home);
    write_file(path, data, 3000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "changing.bin") > 0);
    n = offer_named(&B, "changing.bin");
    FILE *f = fopen(path, "r+b");
    if (f) { fputc(data[0] ^ 1, f); fclose(f); }
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch changing.bin");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/changing.bin", dl);
    CHECK(dl_state(&B, n) == DL_FAILED && log_b.mismatched == 1
          && platform_read_file(want, data + 199000, 10) < 0 && !part_files_left(dl), "a changed file was kept");

    // Every fifth of alice's frames to bob lost while 20 KB comes: a run of chunks that didn't come
    // is asked for again as soon as the rest of its run has, so it comes whole, not long after.
    snprintf(path, sizeof path, "%s/lossy.bin", home);
    write_file(path, data, 20000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "lossy.bin") > 0);
    n = offer_named(&B, "lossy.bin");
    lossy_t lossy = { A.port, B.port, 0, 0 };
    fake_net_filter = drop_fifth;
    fake_net_filter_ctx = &lossy;
    // No rekeys meanwhile: this is about chunks, and re-handshakes are the rekey tests'. After it,
    // they come at their usual spacing again, not all at once.
    for (int k = 0; k < 3; k++) ALL[k]->next_rekey = *t + 1000.0;
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch lossy.bin");
    RUN_UNTIL(t, 300, dl_over(&B, n));
    for (int k = 0; k < 3; k++) ALL[k]->next_rekey = *t + REKEY_INTERVAL * (0.5 + 0.2 * k);
    fake_net_filter = NULL;
    fake_net_filter_ctx = NULL;
    snprintf(want, sizeof want, "%s/lossy.bin", dl);
    CHECK(lossy.dropped > 0 && same_file(want, data, 20000), "20 KB with some of its chunks lost didn't come whole");

    // Fast transfers: the same file in a fraction of the time.
    snprintf(path, sizeof path, "%s/big.bin", home);
    write_file(path, data, 40000);
    chat_set_file_options(&A, 0, 1);
    chat_set_file_options(&B, 0, 1);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "big.bin") > 0);
    n = offer_named(&B, "big.bin");
    double began = *t;
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch big.bin");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/big.bin", dl);
    CHECK(same_file(want, data, 40000) && *t - began < 15.0, "40 KB took %.1f s with fast transfers", *t - began);
    chat_set_file_options(&A, 0, 0);
    chat_set_file_options(&B, 0, 0);

    // Stopped part way: nothing left behind.
    platform_remove(want);
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch big.bin again");
    RUN_FOR(t, 4);
    snprintf(cmd, sizeof cmd, "cancel %d", n);
    chat_run_command(&B, cmd);
    CHECK(dl_state(&B, n) == DL_NONE && !part_files_left(dl), "a cancelled download left something");

    // No longer offered: a fetch is told so.
    int mine = 0;
    for (int k = 1; k <= A.file_seq; k++) if (chat_file(&A, k) && chat_file(&A, k)->mine && strcmp(chat_file(&A, k)->name, "big.bin") == 0) mine = k;
    snprintf(cmd, sizeof cmd, "cancel %d", mine);
    chat_run_command(&A, cmd);
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't ask for big.bin");
    RUN_UNTIL(t, 60, dl_over(&B, n));
    CHECK(dl_state(&B, n) == DL_FAILED && log_b.withdrawn == 1, "a withdrawn file wasn't refused");

    snprintf(cmd, sizeof cmd, "rm -rf '%s'", home);
    if (system(cmd) != 0) printf("couldn't remove %s\n", home);
}

static void test_file_names(double *t) {
    (void)t;
    static const char *const CASES[][2] = {
        { "photo.jpg", "photo.jpg" },
        { "../../etc/passwd", "passwd" },
        { "C:\\Windows\\evil.exe", "evil.exe" },
        { "..", "file" },
        { ".bashrc", "bashrc" },
        { "   ", "file" },
        { "a\x1b[2Jb.txt", "a[2Jb.txt" },
        { "invoice\xe2\x80\xaegpj.exe", "invoicegpj.exe" },   // a right-to-left override, gone
        { "what?.txt", "what_.txt" },
        { "con.txt", "_con.txt" },
        { "NUL", "_NUL" },
        { "LPT1.log", "_LPT1.log" },
        { "trailing. ", "trailing" },
        { "na\tme", "name" },
        { "", "file" },
    };
    char out[FILE_NAME_MAX + 1];
    for (size_t i = 0; i < sizeof CASES / sizeof CASES[0]; i++) {
        file_clean_name(CASES[i][0], out);
        CHECK(strcmp(out, CASES[i][1]) == 0, "name '%s' became '%s', not '%s'", CASES[i][0], out, CASES[i][1]);
    }
    char longname[400];
    memset(longname, 'x', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    file_clean_name(longname, out);
    CHECK(strlen(out) == FILE_NAME_MAX, "a long name came out %zu bytes", strlen(out));
    uint64_t v;
    CHECK(file_parse_size("8M", &v) == 0 && v == 8u * 1024 * 1024 && file_parse_size("512 KB", &v) == 0 && v == 512 * 1024
          && file_parse_size("1.5G", &v) == 0 && v == 1610612736ull && file_parse_size("100", &v) == 0 && v == 100
          && file_parse_size("x", &v) != 0 && file_parse_size("5Q", &v) != 0 && file_parse_size("-1", &v) != 0, "sizes parse wrong");
}

typedef struct { int n; char seen[10][160]; } toml_log_t;

static void toml_got(void *ctx, const char *table, const char *key, const toml_value *v) {
    toml_log_t *l = ctx;
    if (l->n >= 10) return;
    char *o = l->seen[l->n++];
    int p = snprintf(o, 160, "%s.%s=", table, key);
    switch (v->type) {
        case TOML_STRING: snprintf(o + p, 160 - (size_t)p, "s:%s", v->s); break;
        case TOML_BOOL:   snprintf(o + p, 160 - (size_t)p, "b:%d", v->b); break;
        case TOML_INT:    snprintf(o + p, 160 - (size_t)p, "i:%lld", v->i); break;
        case TOML_ARRAY:
            p += snprintf(o + p, 160 - (size_t)p, "a:");
            for (int k = 0; k < v->n; k++) p += snprintf(o + p, 160 - (size_t)p, "%s%s", k ? "|" : "", v->items[k]);
            break;
    }
}

static void test_toml(double *t) {
    (void)t;
    static const char text[] =
        "# a comment\n"
        "top = 1\n"
        "[network]  # after a header\n"
        "routing = \"tor\"\n"
        "lan = false\n"
        "relays = [\n  \"wss://a\", # first\n  'wss://b',\n]\n"
        "port = 4_000\n"
        "ratio = 1.5\n"
        "a.b = true\n"
        "\n[ profile ]\r\n"
        "nick = \"al\\\"i\\u00e9\\\\\"\r\n"
        "\"colour\" = 'pur\\ple'\n"
        "open = \"no end\n"
        "[[x]]\n"
        "lost = 1\n";
    static const char *const want[] = {
        ".top=i:1", "network.routing=s:tor", "network.lan=b:0", "network.relays=a:wss://a|wss://b",
        "network.port=i:4000", "profile.nick=s:al\"i\xc3\xa9\\", "profile.colour=s:pur\\ple",
    };
    toml_log_t l = { 0 };
    int bad_line = 0, bad = toml_parse(text, toml_got, &l, &bad_line);
    CHECK(l.n == 7, "read %d keys, want 7", l.n);
    for (int i = 0; i < l.n && i < 7; i++) CHECK(strcmp(l.seen[i], want[i]) == 0, "read %s, want %s", l.seen[i], want[i]);
    // A float, a dotted key, an unended string, an array of tables, and a key under it.
    CHECK(bad == 5 && bad_line == 11, "%d lines left out from line %d, want 5 from line 11", bad, bad_line);

    char line[256] = "k = ";
    size_t n = toml_put_str(line, 4, sizeof line, "a\"b\\c\n\x01\xc3\xa9");
    toml_log_t back = { 0 };
    CHECK(n < sizeof line && toml_parse(line, toml_got, &back, NULL) == 0 && back.n == 1
          && strcmp(back.seen[0], ".k=s:a\"b\\c\n\x01\xc3\xa9") == 0, "a string didn't come back the same: %s", line);
    CHECK(toml_put_str(line, 0, 4, "abcdef") == 4, "a string that didn't fit wasn't refused");
}

static void test_parsers(double *t) {
    (void)t;
    // An address Tor itself handed out, and the same with one character changed.
    CHECK(onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpyd"), "a real onion address fails its checksum");
    CHECK(!onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpye"), "a mistyped onion address passes");
    CHECK(!onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpy"), "a short onion address passes");

    static js_arena arena;
    const char *msg = "[\"EVENT\",\"ab\",{\"kind\":21000,\"tags\":[[\"e\",\"x\\u00e9\\n\"]],\"content\":\"a\\\"b\"}]";
    const js_value *v = js_parse(msg, strlen(msg), &arena);
    CHECK(v && v->type == JS_ARR && v->n == 3, "a relay message didn't parse");
    if (v && v->n == 3) {
        const js_value *ev = &v->items[2];
        const js_value *kind = js_obj_get(ev, "kind");
        CHECK(kind && kind->is_int && kind->i == 21000, "event kind came out wrong");
        const char *content = js_str(js_obj_get(ev, "content"));
        CHECK(content && strcmp(content, "a\"b") == 0, "escaped content came out as '%s'", content ? content : "");
        const js_value *tags = js_obj_get(ev, "tags");
        const char *tag = tags && tags->n == 1 ? js_str(&tags->items[0].items[1]) : NULL;
        CHECK(tag && strcmp(tag, "x\xc3\xa9\n") == 0, "a \\u escape didn't decode to UTF-8");
        char out[64];
        size_t n = tag ? js_put_str(out, 0, sizeof out, tag, strlen(tag)) : 0;
        CHECK(n > 0 && strcmp(out, "\"x\xc3\xa9\\n\"") == 0, "NIP-01 escaping gave %s", n ? out : "nothing");
    }
    CHECK(js_parse("[1,]", 4, &arena) == NULL, "a trailing comma parsed");
    CHECK(js_parse("[\"\\ud800\"]", 10, &arena) == NULL, "a lone surrogate parsed");

    const char *xml = "<root><service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>"
                      "<controlURL>/ppp</controlURL></service><service><serviceType>"
                      "urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL> /ctl/ip </controlURL>"
                      "</service></root>";
    char service[96], url[256];
    CHECK(portmap_parse_control_url(xml, strlen(xml), service, sizeof service, url, sizeof url) == 0
          && strcmp(url, "/ctl/ip") == 0 && strstr(service, "WANIPConnection:1"),
          "UPnP control URL came out wrong");
    const char *resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    char body[64];
    int status = 0;
    CHECK(portmap_http_body(resp, strlen(resp), &status, body, sizeof body) == 0 && status == 200
          && strcmp(body, "hello world") == 0, "a chunked reply came out as '%s'", body);

    uint8_t key[NOSTR_KEY_LEN], plain[NOSTR_WRAP_PLAIN], back[NOSTR_WRAP_PLAIN], sealed[NOSTR_WRAP_LEN], sealed2[NOSTR_WRAP_LEN];
    gen_random(key, sizeof key);
    gen_random(plain, sizeof plain);
    nostr_wrap(key, plain, sealed);
    nostr_wrap(key, plain, sealed2);
    CHECK(nostr_unwrap(key, sealed, sizeof sealed, back) == 0 && memcmp(back, plain, sizeof plain) == 0, "a wrapped event didn't open");
    CHECK(memcmp(sealed, sealed2, sizeof sealed) != 0, "the same datagram wrapped twice came out the same");
    sealed[100] ^= 1;
    CHECK(nostr_unwrap(key, sealed, sizeof sealed, back) != 0, "a tampered event opened");
}

int main(int argc, char **argv) {
    verbose = argc > 1 && (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0);
    double t_start = now_seconds();
    crypto_setup();
    net_startup();
    uint16_t to_b[1] = { 40002 }, to_a[1] = { 40001 };
    printf("deriving session keys (Argon2id, 512 MiB each)...\n");
    make_release();
    start(&A, &log_a, "alice", 40001, to_b, 1, 1, BUILD_ALICE, 1);
    start(&B, &log_b, "bob", 40002, to_a, 1, 0, BUILD_BOB, 1);
    double t = now_seconds();

    struct { const char *name; void (*fn)(double *); } tests[] = {
        { "connect", test_connect }, { "verify gate", test_verify_gate }, { "message", test_message },
        { "constant rate", test_constant_rate }, { "lost message", test_lost_message },
        { "rekey", test_rekey }, { "rekey mid-message", test_message_across_rekey }, { "cookie rate", test_cookie_rate },
        { "udp masked", test_udp_masked },
        { "junk", test_junk }, { "lookalike nick", test_lookalike_nick },
        { "third peer", test_third_peer }, { "candidates settle", test_candidates_settle }, { "builds", test_builds },
        { "parsers", test_parsers }, { "toml", test_toml }, { "dht keys", test_dht_keys }, { "dht", test_dht }, { "read file", test_read_file },
        { "identity keys", test_identity_keys }, { "passphrase seal", test_passphrase_seal }, { "images", test_images }, { "file names", test_file_names }, { "files", test_files },
    };
    size_t n_tests = sizeof tests / sizeof tests[0];
    int failed[sizeof tests / sizeof tests[0]], n_failed = 0;
    for (size_t i = 0; i < n_tests; i++) {
        int before = failures;
        double t0 = now_seconds();
        if (verbose) printf("\n== %s\n", tests[i].name);
        tests[i].fn(&t);
        int ok = failures == before;
        if (!ok) failed[n_failed++] = (int)i;
        printf("%s %-18s %6.0f ms\n", ok ? "ok  " : "FAIL", tests[i].name, (now_seconds() - t0) * 1000.0);
    }
    for (int i = 0; i < n_live; i++) chat_shutdown(ALL[i]);

    printf("\n%zu tests: %zu passed, %d failed | %d checks, %d failed | %.1f s\n",
           n_tests, n_tests - (size_t)n_failed, n_failed, checks, failures, now_seconds() - t_start);
    if (n_failed) {
        printf("failed:");
        for (int i = 0; i < n_failed; i++) printf("%s %s", i ? "," : "", tests[failed[i]].name);
        printf("\n");
    }
    return failures ? 1 : 0;
}
