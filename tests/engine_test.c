// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Two (or three) sessions talking over fake_net: handshake, delivery, loss, rekey, junk.
#include "chat.h"
#include "fake_net.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_LINES 512

typedef struct {
    const char *who;
    char lines[LOG_LINES][320];
    int n;
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

static void on_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len) {
    log_t *l = ui;
    (void)hhmm; (void)rgb; (void)color_len;
    if (verbose) printf("  [%s%s] %s\n", l->who, (flags & LINE_CHAT) ? " chat" : "", text);
    if (!(flags & LINE_CHAT)) return;
    if (l->n < LOG_LINES) copy_str(l->lines[l->n++], text, sizeof l->lines[0]);
}

static int log_count(const log_t *l, const char *needle) {
    int k = 0;
    for (int i = 0; i < l->n; i++) if (strstr(l->lines[i], needle)) k++;
    return k;
}

static void start(chat_t *c, log_t *l, const char *nick, uint16_t port, const uint16_t *peer_ports, int n, int created) {
    chat_opts_t o;
    memset(&o, 0, sizeof o);
    copy_str(o.nick, nick, sizeof o.nick);
    copy_str(o.session_name, "TESTSESSION", sizeof o.session_name);
    copy_str(o.password, "correct horse", sizeof o.password);
    o.port = port;
    for (int i = 0; i < n; i++) o.peers[i] = fake_net_addr(peer_ports[i]);
    o.n_peers = n;
    o.created = created;
    o.notify_mode = NOTIFY_NONE;
    chat_init(c, &o, on_print, NULL, l);
}

static chat_t *const ALL[] = { &A, &B, &C };
static int n_live = 2;

// Delivers everything queued and ticks every session, `rounds` times, at time t.
static void pump(int rounds, double t) {
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < n_live; i++) chat_on_socket_readable(ALL[i], ALL[i]->sock, t);
        for (int i = 0; i < n_live; i++) chat_tick(ALL[i], t);
    }
}

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

// Drops the next session frame (the only kind this size) from one port to another.
typedef struct { int armed; uint16_t from, to; int dropped; } drop_t;

static int drop_one(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    drop_t *d = ctx;
    (void)data;
    if (!d->armed || from.port != d->from || to.port != d->to) return 0;
    if (!sealed_len_ok(len, SESSION_HEADER_LEN, SESSION_PAD_TARGET)) return 0;
    d->armed = 0;
    d->dropped++;
    return 1;
}

static void test_connect(double *t) {
    for (int i = 0; i < 40 && !(chat_online_count(&A) == 1 && chat_online_count(&B) == 1); i++) {
        *t += 0.05;
        pump(4, *t);
    }
    CHECK(chat_online_count(&A) == 1, "alice sees %d peers, want 1", chat_online_count(&A));
    CHECK(chat_online_count(&B) == 1, "bob sees %d peers, want 1", chat_online_count(&B));
    CHECK(peer_named(&A, "bob") != NULL, "alice has no peer called bob");
    CHECK(peer_named(&B, "alice") != NULL, "bob has no peer called alice");
    peer_t *pa = peer_named(&A, "bob"), *pb = peer_named(&B, "alice");
    if (pa && pb) CHECK(memcmp(pa->vfy, pb->vfy, VERIFY_LEN) == 0, "verify codes differ");
}

static void test_message(double *t) {
    chat_send_text(&A, "hello there", *t);
    pump(4, *t);
    CHECK(log_count(&log_b, "alice: hello there") == 1, "bob didn't get alice's message once");
    CHECK(pending_msgs(&A) == 0, "alice still waits on %d acks", pending_msgs(&A));
}

// The message itself is lost and a later frame (a cover nop) gets through first, so the peer's
// chain has moved past the message's index: the retry has to be sealed afresh to be readable.
static void test_lost_message(double *t) {
    drop_t d = { 1, A.port, B.port, 0 };
    fake_net_filter = drop_one;
    fake_net_filter_ctx = &d;
    chat_send_text(&A, "lost then found", *t);
    fake_net_filter = NULL;
    CHECK(d.dropped == 1, "the message frame wasn't dropped");

    peer_t *pb = peer_named(&A, "bob");
    if (pb) pb->next_cover = 1.0;
    pump(2, *t);
    CHECK(log_count(&log_b, "lost then found") == 0, "bob got a message that was dropped");

    *t += 2.0;
    pump(4, *t);
    CHECK(log_count(&log_b, "lost then found") == 1, "bob got the retried message %d times, want 1",
          log_count(&log_b, "lost then found"));
    CHECK(pending_msgs(&A) == 0, "alice still waits on %d acks", pending_msgs(&A));
}

static void test_rekey(double *t) {
    uint32_t gen_a = A.keygen, gen_b = B.keygen;
    A.next_rekey = 0;
    B.next_rekey = 0;
    for (int i = 0; i < 40; i++) { *t += 0.05; pump(4, *t); }
    CHECK(A.keygen == gen_a + 1 && B.keygen == gen_b + 1, "no rekey happened");
    CHECK(chat_online_count(&A) == 1 && chat_online_count(&B) == 1, "a rekey dropped the peer");
    peer_t *pa = peer_named(&A, "bob"), *pb = peer_named(&B, "alice");
    CHECK(pa && pa->keygen == A.keygen && pa->chain_confirmed, "alice didn't re-handshake with bob");
    CHECK(pb && pb->keygen == B.keygen && pb->chain_confirmed, "bob didn't re-handshake with alice");
    chat_send_text(&B, "after the rekey", *t);
    pump(4, *t);
    CHECK(log_count(&log_a, "bob: after the rekey") == 1, "alice didn't get bob's message after the rekey");
}

// Junk from outside the room, some of it sized like real frames or chunks: nothing may break.
static void test_junk(double *t) {
    addr_t stranger = fake_net_addr(5555), a_addr = fake_net_addr(A.port);
    static const size_t sizes[] = { 0, 1, 4, 27, 428, 492, 1008, 2600, 2664, 3000 };
    uint8_t junk[3000];
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        for (int rep = 0; rep < 4; rep++) {
            gen_random(junk, sizeof junk);
            if (rep == 1 && sizes[k] >= 8) { junk[0] = CHUNK_MAGIC0; junk[1] = CHUNK_MAGIC1; junk[6] = 0; junk[7] = 3; }
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
    pump(4, *t);
    CHECK(log_count(&log_b, "still here") == 1, "messages stopped after junk");
}

static void test_lookalike_nick(double *t) {
    chat_set_nick(&B, "ALlCE");
    pump(4, *t);
    peer_t *pb = peer_named(&A, "ALlCE");
    CHECK(pb != NULL, "alice didn't see bob's new nick");
    if (pb) {
        char name[CHAT_NAME_LEN];
        chat_peer_name(&A, pb, name);
        CHECK(strchr(name, '#') != NULL, "a nick that looks like alice's own shows as '%s', without an id", name);
    }
    chat_set_nick(&B, "bob");
    pump(4, *t);
}

// Carol joins through alice only: bob hears about her from alice (px) and connects directly.
static void test_third_peer(double *t) {
    uint16_t via_alice[1] = { A.port };
    start(&C, &log_c, "carol", 40003, via_alice, 1, 0);
    n_live = 3;
    for (int i = 0; i < 60 && (chat_online_count(&C) < 2 || chat_online_count(&B) < 2); i++) { *t += 0.05; pump(4, *t); }
    CHECK(chat_online_count(&C) == 2, "carol sees %d peers, want 2", chat_online_count(&C));
    CHECK(chat_online_count(&B) == 2, "bob sees %d peers, want 2", chat_online_count(&B));
    chat_send_text(&C, "hi all", *t);
    pump(4, *t);
    CHECK(log_count(&log_a, "carol: hi all") == 1, "alice didn't get carol's message once");
    CHECK(log_count(&log_b, "carol: hi all") == 1, "bob didn't get carol's message once");
}

int main(int argc, char **argv) {
    verbose = argc > 1 && (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0);
    double t_start = now_seconds();
    crypto_setup();
    net_startup();
    uint16_t to_b[1] = { 40002 }, to_a[1] = { 40001 };
    printf("deriving session keys (Argon2id, 512 MiB each)...\n");
    start(&A, &log_a, "alice", 40001, to_b, 1, 1);
    start(&B, &log_b, "bob", 40002, to_a, 1, 0);
    double t = now_seconds();

    struct { const char *name; void (*fn)(double *); } tests[] = {
        { "connect", test_connect }, { "message", test_message }, { "lost message", test_lost_message },
        { "rekey", test_rekey }, { "junk", test_junk }, { "lookalike nick", test_lookalike_nick },
        { "third peer", test_third_peer },
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
        printf("%s %-16s %6.0f ms\n", ok ? "ok  " : "FAIL", tests[i].name, (now_seconds() - t0) * 1000.0);
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
