// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The sessions the tests share, what they print, the clock they keep to, and the network's faults.
#include "harness.h"

// A2 and B2: alice and bob in the room :move takes them to.
chat_t A, B, C, A2, B2;
log_t log_a = { .who = "alice" }, log_b = { .who = "bob" }, log_c = { .who = "carol" },
             log_a2 = { .who = "alice, moved" }, log_b2 = { .who = "bob, moved" };
int checks, failures;
// -v: everything the sessions print, and every check as written, pass or fail.
int verbose;

void on_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len, int file) {
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
        if ((flags & LINE_WARN) && strstr(text, "does not sign with the key you verified for")) l->key_warnings++;
        if (strstr(text, "signs with the key you verified")) l->known_keys++;
        if ((flags & LINE_WARN) && strstr(text, " keeps a history of this chat")) l->histories++;
        if (strstr(text, " wants to move this room")) l->move_asks++;
        if (strstr(text, " came along from the room you moved from")) l->came_along++;
        if (strstr(text, "'s chat is too old for direct messages")) l->dm_old++;
        if (strstr(text, " asks for messages here to go after ")) l->timer_asks++;
        if (strstr(text, " stopped asking for messages here to go")) l->timer_stops++;
        if (strstr(text, " went offline (")) l->offline++;
        if (strstr(text, " left (")) l->lefts++;
        if (strncmp(text, "* joining: peer ", 16) == 0) l->joining++;
        else if (strstr(text, " joined (")) { if (l->joining > 0) l->joining--; else l->unheralded_joins++; }
        return;
    }
    if (l->n < LOG_LINES) copy_str(l->lines[l->n++], text, sizeof l->lines[0]);
}

int log_count(const log_t *l, const char *needle) {
    int k = 0;
    for (int i = 0; i < l->n; i++) if (strstr(l->lines[i], needle)) k++;
    return k;
}

// Release 1.2.3 is alice's and bob's binaries: its list, signed with a release key of the test's
// own as `just release` signs it, names them. Carol's is a build from source, with no list.
const uint8_t BUILD_ALICE[BUILD_HASH_LEN] = { 1 }, BUILD_BOB[BUILD_HASH_LEN] = { 2 },
                     BUILD_CAROL[BUILD_HASH_LEN] = { 3 };
static char release_pub[64];
char release_list[BUILD_LIST_LEN + 1], release_sig[MINISIGN_SIG_B64_LEN + 1];

void make_release(void) {
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

void base_opts(chat_opts_t *o, const char *nick, uint16_t port, const uint16_t *peer_ports, int n, int created) {
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

// The time the sessions last ran at, which new ones start at, and filters note.
double g_now;

void start(chat_t *c, log_t *l, const char *nick, uint16_t port, const uint16_t *peer_ports, int n, int created,
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
    chat_init(c, &o, on_print, NULL, l, g_now);
}

chat_t *const ALL[] = { &A, &B, &C, &A2, &B2 };
const log_t *const ALL_LOGS[] = { &log_a, &log_b, &log_c };
int n_live = 2;
int live_mask = 0x3;   // which of ALL run

// Delivers everything queued and ticks every session, `rounds` times, at time t.
void pump(int rounds, double t) {
    g_now = t;
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < N_ALL; i++) if (live_mask & (1 << i)) chat_on_socket_readable(ALL[i], ALL[i]->sock, t);
        for (int i = 0; i < N_ALL; i++) if (live_mask & (1 << i)) chat_tick(ALL[i], t);
    }
}

// Whether a live session is re-handshaking with a peer. Until it's done, what goes to that peer waits
// behind the handshake's pieces, which can take longer than a test gives it.
int rehandshaking_any(void) {
    for (int i = 0; i < N_ALL; i++) {
        if (!(live_mask & (1 << i))) continue;
        const chat_t *c = ALL[i];
        for (int k = 0; k < c->peer_hi; k++)
            if (c->peers[k].used && c->peers[k].ok && rehandshaking_with(c, &c->peers[k])) return 1;
    }
    return 0;
}

peer_t *peer_named(chat_t *c, const char *nick) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok && strcmp(c->peers[i].nick, nick) == 0) return &c->peers[i];
    return NULL;
}

int pending_msgs(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < MAX_PENDING_MSGS; i++) n += c->pending[i].used;
    return n;
}

// Both ends say the codes matched, as two people would once they'd compared them.
void confirm(chat_t *x, const char *x_calls_y, chat_t *y, const char *y_calls_x) {
    char cmd[64];
    snprintf(cmd, sizeof cmd, "verify %s ok", x_calls_y);
    chat_run_command(x, cmd);
    snprintf(cmd, sizeof cmd, "verify %s ok", y_calls_x);
    chat_run_command(y, cmd);
}

// A datagram unmasked with the room's key: 1 if it's a session frame, not a piece of a room frame.
int is_session_frame(const void *data, size_t len) {
    uint8_t d[HANDSHAKE_BUF_LEN + 128];
    if (len > sizeof d || !sealed_len_ok(len, SESSION_HEADER_LEN, SESSION_MIN_BODY)) return 0;
    memcpy(d, data, len);
    if (udp_mask(A.udp_key, d, len) != 0) return 0;
    return !(d[0] == CHUNK_MAGIC0 && d[1] == CHUNK_MAGIC1);
}

int drop_one(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    drop_t *d = ctx;
    if (!d->armed || from.port != d->from || to.port != d->to) return 0;
    if (!is_session_frame(data, len)) return 0;
    d->armed = 0;
    d->dropped++;
    return 1;
}

int drop_fifth(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    lossy_t *l = ctx;
    if (from.port != l->from || to.port != l->to || !is_session_frame(data, len)) return 0;
    if (++l->seen % 5) return 0;
    l->dropped++;
    return 1;
}

// Nothing waits in x's queues for its peer p.
int queues_empty(const chat_t *x, const peer_t *p) {
    int slot = (int)(p - x->peers);
    for (int i = 0; i < SENDQ_MAX; i++) if (x->sendq[i].used && x->sendq[i].peer_slot == slot) return 0;
    for (int i = 0; i < ROOMQ_MAX; i++) if (x->roomq[i].used && x->roomq[i].peer_slot == slot) return 0;
    return 1;
}

// Sends text from x, and drops the frame it goes in: with nothing else queued for y, it's the
// next session frame x sends y.
void send_and_lose(chat_t *x, chat_t *y, const char *y_nick, const char *text, double *t) {
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

int rekeyed(chat_t *x, const char *y_nick) {
    peer_t *p = peer_named(x, y_nick);
    return p && p->keygen == x->keygen && p->chain_confirmed;
}

const uint8_t *find_bytes(const uint8_t *h, size_t hl, const char *needle) {
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= hl; i++) if (memcmp(h + i, needle, nl) == 0) return h + i;
    return NULL;
}

int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(data, 1, len, f);
    return fclose(f) == 0 && w == len ? 0 : -1;
}
