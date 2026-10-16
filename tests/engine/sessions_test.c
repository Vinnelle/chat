// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Sessions talking over fake_net: the handshake, verify codes, messages and their delivery, loss,
// rekeys, the traffic's shape on the wire, junk, a third peer, direct messages, replies, timers,
// builds, and the room's DHT lookups.
#include "harness.h"

void test_connect(double *t) {
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
void test_verify_gate(double *t) {
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
    RUN_UNTIL(t, 10, log_count(&log_b, "alice (code compared): after comparing") == 1);
    CHECK(log_count(&log_b, "alice (code compared): after comparing") == 1,
          "bob didn't get the message once the codes were compared");
}

void test_message(double *t) {
    chat_send_text(&A, "hello there", *t);
    RUN_UNTIL(t, 10, log_count(&log_b, "alice (code compared): hello there") == 1 && pending_msgs(&A) == 0);
    CHECK(log_count(&log_b, "alice (code compared): hello there") == 1, "bob didn't get alice's message once");
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
// A message as long as MAX_TEXT goes whole to a peer whose k says it reads that much ("l"). To one
// that doesn't, as older versions don't, it goes in parts no longer than OLD_MAX_TEXT, cut between
// words, which together are the message.
void test_long_message(double *t) {
    static char text[MAX_TEXT + 1];
    size_t n = 0;
    for (unsigned w = 1; ; w++) {
        char word[24];
        int wl = snprintf(word, sizeof word, "%sw%x", n ? " " : "", (w * 2654435761u) % (16u << (w % 12)));
        if (n + (size_t)wl > MAX_TEXT) break;
        memcpy(text + n, word, (size_t)wl + 1);
        n += (size_t)wl;
    }
    peer_t *pb = peer_named(&A, "bob");
    CHECK(pb && pb->long_text, "bob's k didn't say it reads long messages");
    if (!pb) return;
    int before = log_b.n;
    chat_send_text(&A, text, *t);
    RUN_UNTIL(t, 20, log_b.n > before);
    CHECK(log_b.n == before + 1 && strstr(log_b.lines[before], text) != NULL, "a %zu-byte message didn't arrive whole", n);
    // As though bob were an older version.
    pb->long_text = 0;
    before = log_b.n;
    chat_send_text(&A, text, *t);
    RUN_UNTIL(t, 60, log_b.n >= before + 2 && pending_msgs(&A) == 0);
    static char joined[MAX_TEXT + 64];
    size_t jl = 0;
    int ok = log_b.n - before >= 2;
    for (int i = before; i < log_b.n && ok; i++) {
        const char *part = strstr(log_b.lines[i], ": ");
        ok = part && strlen(part + 2) <= OLD_MAX_TEXT;
        if (ok) jl += (size_t)snprintf(joined + jl, sizeof joined - jl, "%s%s", jl ? " " : "", part + 2);
    }
    CHECK(ok && strcmp(joined, text) == 0, "an older peer's parts were too long, or weren't the message (%d of them)",
          log_b.n - before);
    pb->long_text = 1;
}

void test_constant_rate(double *t) {
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
void test_lost_message(double *t) {
    send_and_lose(&A, &B, "bob", "lost then found", t);
    RUN_FOR(t, 2);
    CHECK(log_count(&log_b, "lost then found") == 0, "bob got a message that was dropped");
    RUN_UNTIL(t, 15, log_count(&log_b, "lost then found") == 1 && pending_msgs(&A) == 0);
    CHECK(log_count(&log_b, "lost then found") == 1, "bob got the retried message %d times, want 1",
          log_count(&log_b, "lost then found"));
    CHECK(pending_msgs(&A) == 0, "alice still waits on %d acks", pending_msgs(&A));
}

// What became of the message alice is watching.
static struct { unsigned own; int settled, missed; char who[CHAT_NAME_LEN]; } g_delivered;

static void on_delivery(void *ui, unsigned own, chat_delivery_t what, const char *name) {
    (void)ui;
    if (own != g_delivered.own) return;
    if (what == CHAT_SETTLED) g_delivered.settled++;
    else { g_delivered.missed++; copy_str(g_delivered.who, name, sizeof g_delivered.who); }
}

// Drops every session frame from one port to another.
typedef struct { uint16_t from, to; } cut_t;

static int drop_all(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    const cut_t *c = ctx;
    return from.port == c->from && to.port == c->to && is_session_frame(data, len);
}

// Alice's message settles once bob acks it, and when every frame to bob is lost, it settles naming
// him once the last try is given up on.
void test_delivered(double *t) {
    peer_t *p = peer_named(&A, "bob");
    RUN_UNTIL(t, 30, p && queues_empty(&A, p) && pending_msgs(&A) == 0);
    A.delivery = on_delivery;
    memset(&g_delivered, 0, sizeof g_delivered);
    chat_send_text(&A, "did this arrive", *t);
    g_delivered.own = A.own_seq;
    RUN_UNTIL(t, 15, g_delivered.settled);
    CHECK(g_delivered.own && g_delivered.settled == 1 && g_delivered.missed == 0,
          "a message bob acked didn't settle as reached (settled %d, missed %d)", g_delivered.settled,
          g_delivered.missed);

    memset(&g_delivered, 0, sizeof g_delivered);
    cut_t cut = { A.port, B.port };
    fake_net_filter = drop_all;
    fake_net_filter_ctx = &cut;
    chat_send_text(&A, "this won't", *t);
    g_delivered.own = A.own_seq;
    RUN_UNTIL(t, 35, g_delivered.settled);
    fake_net_filter = NULL;
    fake_net_filter_ctx = NULL;
    CHECK(g_delivered.settled == 1 && g_delivered.missed >= 1 && strstr(g_delivered.who, "bob"),
          "a message bob never got didn't settle as missing him (settled %d, missed %d, %s)", g_delivered.settled,
          g_delivered.missed, g_delivered.who);
    A.delivery = NULL;
    RUN_UNTIL(t, 60, chat_online_count(&A) == 1 && chat_online_count(&B) == 1 && pending_msgs(&A) == 0);
}

void test_rekey(double *t) {
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
    RUN_UNTIL(t, 10, log_count(&log_a, "bob (code compared): after the rekey") == 1);
    CHECK(log_count(&log_a, "bob (code compared): after the rekey") == 1,
          "alice didn't get bob's message after the rekey");
}

// A message lost just before the peer rekeys: its retry has to outlive the re-handshake, which
// reuses the peer's slot.
void test_message_across_rekey(double *t) {
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
void test_cookie_rate(double *t) {
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

    // Unmasked, as 0.3.1 sent it over UDP, it's junk now: no challenge.
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
void test_udp_masked(double *t) {
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
void test_dht_keys(double *t) {
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

// The DHT asks as a read-only node, by name through a proxy when it has one, and once it knows
// enough nodes, starts from them instead of the bootstrap servers.
void test_dht(double *t) {
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

// Junk from outside the room, some of it sized like real frames or cells, and pieces of nothing
// from inside it (masked, so they unmask to a piece's header): nothing may break.
void test_junk(double *t) {
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

void test_lookalike_nick(double *t) {
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
void test_third_peer(double *t) {
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
    RUN_UNTIL(t, 10, log_count(&log_a, "carol (code compared): hi all") == 1
                     && log_count(&log_b, "carol (code compared): hi all") == 1);
    CHECK(log_count(&log_a, "carol (code compared): hi all") == 1, "alice didn't get carol's message once");
    CHECK(log_count(&log_b, "carol (code compared): hi all") == 1, "bob didn't get carol's message once");
}

// A direct message: only the peer named gets it, both sides show who it's between, it's acked, and a
// peer whose build can't read one is refused rather than sent it.
void test_direct_message(double *t) {
    chat_run_command(&A, "msg bob just between us");
    RUN_UNTIL(t, 10, log_count(&log_b, "just between us") == 1);
    RUN_FOR(t, 4);
    CHECK(log_count(&log_b, "alice (\xe2\x86\x92 you)") == 1, "bob didn't get alice's direct message once, marked as to him");
    CHECK(log_count(&log_a, "(\xe2\x86\x92 bob) (you): just between us") == 1, "alice doesn't show her direct message to bob");
    CHECK(log_count(&log_c, "just between us") == 0, "carol got a direct message meant for bob");
    int waiting = 0;
    for (int i = 0; i < MAX_PENDING_MSGS; i++) waiting += A.pending[i].used && starts_with(A.pending[i].text, "pm\t");
    CHECK(waiting == 0, "bob never acked alice's direct message");

    peer_t *carol = peer_named(&A, "carol");
    CHECK(carol != NULL, "alice doesn't know carol");
    if (!carol) return;
    carol->can_pm = 0;
    chat_run_command(&A, "msg carol for an old build");
    RUN_FOR(t, 4);
    carol->can_pm = 1;
    CHECK(log_a.dm_old == 1 && log_count(&log_c, "for an old build") == 0,
          "a direct message to a build that can't read one wasn't refused");
}

// Alice answers bob's last message: both show the start of it quoted in front of her answer. A
// build that can't read replies gets an "m" with the quote in its text.
#define QUOTED_BOB "\xe2\x86\xaa bob: what time is it \xc2\xb7 "
void test_reply(double *t) {
    chat_send_text(&B, "what time is it", *t);
    RUN_UNTIL(t, 10, log_count(&log_a, "what time is it") == 1);
    chat_run_command(&A, "reply bob at noon");
    RUN_UNTIL(t, 10, log_count(&log_b, "at noon") == 1);
    CHECK(log_count(&log_b, QUOTED_BOB "at noon") == 1 && log_count(&log_a, QUOTED_BOB "at noon") == 1,
          "alice's reply doesn't show bob's message quoted on both sides");
    peer_t *ab = peer_named(&A, "bob");
    CHECK(ab && ab->can_reply, "bob's build doesn't say it reads replies");
    if (!ab) return;
    ab->can_reply = 0;
    chat_run_command(&A, "reply bob for an old build");
    RUN_UNTIL(t, 10, log_count(&log_b, "for an old build") == 1);
    ab->can_reply = 1;
    CHECK(log_count(&log_b, QUOTED_BOB "for an old build") == 1,
          "a build without replies didn't get the quote as text");
    RUN_FOR(t, 4);
}

// Alice ignores bob: what he says and sends her directly doesn't show for her, but still reaches
// carol. Then she stops, and what he says shows again.
void test_ignore(double *t) {
    chat_run_command(&A, "ignore bob");
    peer_t *ab = peer_named(&A, "bob");
    CHECK(ab && chat_ignored(&A, ab->id), "bob isn't ignored after :ignore bob");
    if (!ab) return;
    chat_send_text(&B, "said while ignored", *t);
    chat_run_command(&B, "msg alice sent while ignored");
    RUN_UNTIL(t, 10, log_count(&log_c, "said while ignored") == 1);
    RUN_FOR(t, 4);
    CHECK(log_count(&log_a, "said while ignored") == 0 && log_count(&log_a, "sent while ignored") == 0,
          "alice shows what bob said or sent her while she ignores him");
    chat_run_command(&A, "ignore bob off");
    CHECK(!chat_ignored(&A, ab->id) && !(ab->identity_state == VERIFY_VERIFIED && ignore_by_key(ab->identity_pub)),
          "bob is still ignored after :ignore bob off");
    chat_send_text(&B, "said once seen again", *t);
    RUN_UNTIL(t, 10, log_count(&log_a, "said once seen again") == 1);
    CHECK(log_count(&log_a, "said once seen again") == 1, "alice doesn't show bob's message once she stops ignoring him");
}

// Alice asks for a message timer: bob is told, keeps to it, and his recent messages from before it go.
// Then she stops asking. And what :timer takes.
void test_timer(double *t) {
    unsigned s = 0;
    char d[16], who[CHAT_NAME_LEN] = "";
    CHECK(chat_parse_timer("10m", &s) == 0 && s == 600 && chat_parse_timer("2h", &s) == 0 && s == 7200
          && chat_parse_timer("off", &s) == 0 && s == 0, "a timer wasn't read");
    CHECK(chat_parse_timer("30s", &s) != 0 && chat_parse_timer("8d", &s) != 0 && chat_parse_timer("10", &s) != 0
          && chat_parse_timer("m", &s) != 0 && chat_parse_timer("-5m", &s) != 0, "a timer that isn't one was taken");
    chat_format_timer(5400, d, sizeof d);
    CHECK(strcmp(d, "90m") == 0, "90 minutes reads %s", d);

    int asks = log_b.timer_asks, stops = log_b.timer_stops;
    chat_run_command(&A, "timer 10m");
    RUN_UNTIL(t, 10, chat_timer(&B, who, sizeof who) == 600);
    CHECK(chat_timer(&B, who, sizeof who) == 600 && strstr(who, "alice") && log_b.timer_asks == asks + 1,
          "bob doesn't keep to alice's timer, or wasn't told once (%d)", log_b.timer_asks - asks);
    int i = (B.recent_next + RECENT_MAX - 1) % RECENT_MAX;
    CHECK(B.recent[i].used, "bob keeps no recent messages");
    B.recent[i].at = *t - 601;
    chat_tick(&B, *t);
    CHECK(!B.recent[i].used, "a message from before the timer wasn't wiped");
    chat_run_command(&A, "timer off");
    RUN_UNTIL(t, 10, chat_timer(&B, NULL, 0) == 0);
    CHECK(chat_timer(&B, NULL, 0) == 0 && log_b.timer_stops == stops + 1,
          "bob still keeps to a timer alice stopped asking for, or wasn't told once");
}

// A peer already connected is no candidate: the keepalive's static peers stop being tried.
void test_candidates_settle(double *t) {
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
void test_builds(double *t) {
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

    // A list signed with the backup key passes too: alice's main key is now another, with another id.
    memcpy(A.backup_key, A.release_key, MINISIGN_KEY_LEN);
    A.has_backup_key = 1;
    gen_random(A.release_key + MINISIGN_ALG_LEN, MINISIGN_ID_LEN);
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_OFFICIAL, "a list signed with the backup key didn't pass");
    A.has_backup_key = 0;
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_MODIFIED, "a list signed with another key passed");
    memcpy(A.release_key, A.backup_key, MINISIGN_KEY_LEN);
    resend_carol(t);
}
