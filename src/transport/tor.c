// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/tor.h"
#include "transport/socks.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include "common/util.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/sha3.h>

#define TOR_FRAME_MAX 4096
#define TX_CAP 32768
#define RX_CAP (TOR_FRAME_MAX + FRAME_LEN_PREFIX)
#define MAX_STREAMS 64
#define MAX_TARGETS 64
#define CTL_BUF 8192
#define STREAM_OPEN_TIMEOUT 120.0
#define STREAM_IDLE_TIMEOUT 150.0
#define CTL_RETRY 10.0
#define CTL_CONNECT_TIMEOUT 10.0
// A login that failed for a reason that needs fixing (a password, a permission) is retried this
// much less often.
#define CTL_FAILED_RETRY 50.0
#define REPUBLISH_MIN_GAP 60.0
#define ROOM_RETRY 60.0
// A target whose streams fail is tried again after a delay that doubles each time, up to the max.
#define TARGET_RETRY_BASE 5.0
#define TARGET_RETRY_SHIFT 4
#define TARGET_RETRY_MAX 80.0
#define ACCEPT_BATCH 8
#define CTL_OK 250
// A stream's frames start with their length.
#define FRAME_LEN_PREFIX 2
#define TARGET_ID_LEN 16
#define AUTH_COOKIE_LEN 32
#define AUTH_NONCE_LEN 32

// v3 onion addresses (rend-spec-v3): the public key, two bytes of checksum and the version, in base32.
#define ONION_VERSION 3
#define ONION_CHECKSUM_LEN 2
#define ONION_RAW_LEN (TOR_PUB_LEN + ONION_CHECKSUM_LEN + 1)
#define ONION_CHECKSUM_LABEL ".onion checksum"
#define SHA3_256_LEN 32

const tor_opts_t TOR_DEFAULTS = { "127.0.0.1:9050", "127.0.0.1:9051", "" };
// Tor Browser runs its own tor on these. Tried when the defaults above don't answer.
#define BROWSER_SOCKS "127.0.0.1:9150"
#define BROWSER_CONTROL "127.0.0.1:9151"

enum { S_FREE, S_CONNECTING, S_METHOD, S_AUTH, S_CONNECT, S_OPEN };

typedef struct {
    int state;
    sock_t s;
    int target;          // outgoing: index into targets; incoming: -1
    uint8_t id[TARGET_ID_LEN];
    uint8_t rx[RX_CAP];
    size_t rx_len;
    uint8_t tx[TX_CAP];
    size_t tx_len;
    double deadline, last_rx;
} stream_t;

typedef struct {
    int used;
    int room;            // one of the room's own onion services: never released
    char host[TOR_ADDR_LEN + 1];
    uint8_t id[TARGET_ID_LEN];
    double next_try, last_used;
    int fails, opened;
} target_t;

// Control-port states, and what the command in flight was.
enum { C_IDLE, C_CONNECTING, C_PROTOCOLINFO, C_CHALLENGE, C_AUTH, C_READY, C_FAILED };
enum { CMD_NONE, CMD_ADD_ME, CMD_ADD_ROOM, CMD_DEL_ROOM };

struct tor {
    tor_opts_t o;
    int probe, probe_done, probe_reached;
    int use_browser_ports;
    sock_t ctl;
    int ctl_state, cmd;
    char ctl_in[CTL_BUF];
    size_t ctl_in_len;
    char reply[CTL_BUF];
    size_t reply_len;
    double ctl_next_try, ctl_deadline;
    int ctl_fails, ctl_warned;
    char cookie_path[512];
    uint8_t client_nonce[AUTH_NONCE_LEN];
    uint8_t cookie[AUTH_COOKIE_LEN];

    sock_t listener;
    uint16_t listen_port;
    char my_onion[TOR_ADDR_LEN + 1];
    char room_onion[TOR_ROOM_SLOTS][TOR_ADDR_LEN + 1];
    uint8_t room_keys[TOR_ROOM_SLOTS][TOR_KEY_LEN];
    int room_targets[TOR_ROOM_SLOTS];
    int host_slot;
    int want_room, room_up, room_republish;
    double room_published_at, room_retry_at;

    char socks_user[SOCKS_USER_LEN + 1];
    stream_t *streams[MAX_STREAMS];
    // The stream whose frames are being passed up. A send to it mustn't close it while that happens.
    int busy;
    target_t targets[MAX_TARGETS];

    tor_deliver_fn deliver;
    tor_log_fn log;
    void *ctx;
    char last_error[160];
};

static void logf_(tor_t *t, int verbose_only, const char *fmt, ...) {
    char msg[300];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    if (t->log) t->log(t->ctx, verbose_only, msg);
}

static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";

static void onion_checksum(const uint8_t pub[TOR_PUB_LEN], uint8_t out[ONION_CHECKSUM_LEN]) {
    enum { LABEL_LEN = sizeof ONION_CHECKSUM_LABEL - 1 };
    uint8_t in[LABEL_LEN + TOR_PUB_LEN + 1], digest[SHA3_256_LEN];
    memcpy(in, ONION_CHECKSUM_LABEL, LABEL_LEN);
    memcpy(in + LABEL_LEN, pub, TOR_PUB_LEN);
    in[LABEL_LEN + TOR_PUB_LEN] = ONION_VERSION;
    mbedtls_sha3(MBEDTLS_SHA3_256, in, sizeof in, digest, sizeof digest);
    memcpy(out, digest, ONION_CHECKSUM_LEN);
}

void onion_address(const uint8_t pub[TOR_PUB_LEN], char out[TOR_ADDR_LEN + 1]) {
    uint8_t raw[ONION_RAW_LEN];
    memcpy(raw, pub, TOR_PUB_LEN);
    onion_checksum(pub, raw + TOR_PUB_LEN);
    raw[ONION_RAW_LEN - 1] = ONION_VERSION;
    base32_encode(raw, sizeof raw, out);
    for (char *c = out; *c; c++) *c = (char)tolower((unsigned char)*c);
}

int onion_valid(const char *s) {
    if (!s || strlen(s) != TOR_ADDR_LEN) return 0;
    uint8_t raw[ONION_RAW_LEN];
    uint32_t buf = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < TOR_ADDR_LEN; i++) {
        const char *p = strchr(B32, s[i]);
        if (!p || !s[i]) return 0;
        buf = (buf << 5) | (uint32_t)(p - B32);
        bits += 5;
        if (bits >= 8) { raw[o++] = (uint8_t)(buf >> (bits - 8)); bits -= 8; }
    }
    if (o != ONION_RAW_LEN || raw[ONION_RAW_LEN - 1] != ONION_VERSION) return 0;
    uint8_t sum[ONION_CHECKSUM_LEN];
    onion_checksum(raw, sum);
    return memcmp(sum, raw + TOR_PUB_LEN, ONION_CHECKSUM_LEN) == 0;
}

static void target_id(const char *host, uint8_t id[TARGET_ID_LEN]) {
    uint8_t h[SHA256_LEN];
    sha256_hash(host, strlen(host), h);
    memcpy(id, h, TARGET_ID_LEN);
}

static int target_has_stream(const tor_t *t, int target) {
    for (int i = 0; i < MAX_STREAMS; i++)
        if (t->streams[i] && t->streams[i]->target == target) return 1;
    return 0;
}

// Every member's session has its own onion address, new each time, so over a long session the
// table fills up. The least recently used target with no stream is dropped to make room.
static int add_target(tor_t *t, const char *host) {
    double now = now_seconds();
    for (int i = 0; i < MAX_TARGETS; i++)
        if (t->targets[i].used && strcmp(t->targets[i].host, host) == 0) { t->targets[i].last_used = now; return i; }
    int slot = -1;
    for (int i = 0; i < MAX_TARGETS && slot < 0; i++) if (!t->targets[i].used) slot = i;
    if (slot < 0) {
        for (int i = 0; i < MAX_TARGETS; i++) {
            const target_t *g = &t->targets[i];
            if (g->room || target_has_stream(t, i)) continue;
            if (slot < 0 || g->last_used < t->targets[slot].last_used) slot = i;
        }
    }
    if (slot < 0) return -1;
    target_t *g = &t->targets[slot];
    memset(g, 0, sizeof *g);
    g->used = 1;
    g->last_used = now;
    copy_str(g->host, host, sizeof g->host);
    target_id(host, g->id);
    return slot;
}

static tor_t *tor_alloc(const tor_opts_t *o) {
    tor_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->o = *o;
    t->ctl = SOCK_INVALID;
    t->listener = SOCK_INVALID;
    t->busy = -1;
    t->host_slot = -1;
    return t;
}

tor_t *tor_new(const tor_opts_t *o, const uint8_t room_keys[TOR_ROOM_SLOTS][TOR_KEY_LEN],
               const uint8_t room_pubs[TOR_ROOM_SLOTS][TOR_PUB_LEN], tor_deliver_fn deliver, tor_log_fn log, void *ctx) {
    tor_t *t = tor_alloc(o);
    if (!t) return NULL;
    t->deliver = deliver;
    t->log = log;
    t->ctx = ctx;
    crypto_lock(t->room_keys, sizeof t->room_keys);
    memcpy(t->room_keys, room_keys, sizeof t->room_keys);
    for (int i = 0; i < TOR_ROOM_SLOTS; i++) {
        onion_address(room_pubs[i], t->room_onion[i]);
        t->room_targets[i] = add_target(t, t->room_onion[i]);
        t->targets[t->room_targets[i]].room = 1;
    }
    uint8_t user[SOCKS_USER_LEN / 2];
    gen_random(user, sizeof user);
    hex_encode(user, sizeof user, t->socks_user);
    t->listener = net_tcp_listen_loopback(&t->listen_port);
    if (t->listener == SOCK_INVALID) {
        // The room's keys are in there, so wipe it like tor_free does.
        crypto_unlock(t->room_keys, sizeof t->room_keys);
        crypto_wipe(t, sizeof *t);
        free(t);
        return NULL;
    }
    return t;
}

tor_t *tor_probe_new(const tor_opts_t *o) {
    tor_t *t = tor_alloc(o);
    if (t) t->probe = 1;
    return t;
}

static void close_stream(tor_t *t, int i) {
    stream_t *s = t->streams[i];
    if (!s) return;
    if (s->s != SOCK_INVALID) net_close(s->s);
    crypto_wipe(s, sizeof *s);
    free(s);
    t->streams[i] = NULL;
}

static void close_ctl(tor_t *t) {
    if (t->ctl != SOCK_INVALID) net_close(t->ctl);
    t->ctl = SOCK_INVALID;
    t->ctl_in_len = t->reply_len = 0;
    t->cmd = CMD_NONE;
}

void tor_free(tor_t *t) {
    if (!t) return;
    for (int i = 0; i < MAX_STREAMS; i++) close_stream(t, i);
    // Closing the control connection also removes our onion services.
    close_ctl(t);
    if (t->listener != SOCK_INVALID) net_close(t->listener);
    crypto_unlock(t->room_keys, sizeof t->room_keys);
    crypto_wipe(t, sizeof *t);
    free(t);
}

void tor_set_ports(tor_t *t, const char *socks, const char *control, const char *password) {
    if (strcmp(t->o.socks, socks) == 0 && strcmp(t->o.control, control) == 0 && strcmp(t->o.password, password) == 0)
        return;
    copy_str(t->o.socks, socks, sizeof t->o.socks);
    copy_str(t->o.control, control, sizeof t->o.control);
    copy_str(t->o.password, password, sizeof t->o.password);
    // Log in to the new one straight away. Streams through the old SOCKS port time out.
    close_ctl(t);
    t->my_onion[0] = '\0';
    t->room_up = 0;
    t->use_browser_ports = 0;
    t->ctl_fails = 0;
    t->ctl_warned = 0;
    t->ctl_state = C_IDLE;
    t->ctl_next_try = 0;
}

static const char *control_addr(const tor_t *t) {
    return t->use_browser_ports ? BROWSER_CONTROL : t->o.control;
}
static const char *socks_addr(const tor_t *t) {
    return t->use_browser_ports ? BROWSER_SOCKS : t->o.socks;
}

static int default_ports(const tor_t *t) {
    return strcmp(t->o.control, TOR_DEFAULTS.control) == 0 && strcmp(t->o.socks, TOR_DEFAULTS.socks) == 0;
}

static void ctl_send(tor_t *t, const char *line) {
    size_t len = strlen(line);
    // The control connection is local and these lines are short, so a partial write means tor is dead.
    if (net_tcp_send(t->ctl, line, len) != (int)len) { close_ctl(t); t->ctl_state = C_IDLE; t->ctl_next_try = 0; }
}

static void ctl_fail(tor_t *t, double now, const char *why, int fatal) {
    close_ctl(t);
    copy_str(t->last_error, why, sizeof t->last_error);
    t->my_onion[0] = '\0';
    t->room_up = 0;
    t->ctl_state = fatal ? C_FAILED : C_IDLE;
    t->ctl_fails++;
    t->ctl_next_try = now + CTL_RETRY;
    if (t->probe) {
        // A probe tries the configured ports and, with the defaults, Tor Browser's, then stops.
        if (fatal || t->ctl_fails >= (default_ports(t) ? 2 : 1)) t->probe_done = -1;
        t->ctl_next_try = now;
        return;
    }
    if (!t->ctl_warned || fatal) {
        t->ctl_warned = 1;
        logf_(t, 0, "* tor: %s", why);
    } else {
        logf_(t, 1, "* tor: %s", why);
    }
}

static void send_add_me(tor_t *t) {
    char line[160];
    snprintf(line, sizeof line, "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=%d,127.0.0.1:%u\r\n",
             TOR_VPORT, (unsigned)t->listen_port);
    t->cmd = CMD_ADD_ME;
    ctl_send(t, line);
}

static void send_add_room(tor_t *t) {
    char b64[BASE64_LEN(TOR_KEY_LEN) + 1];
    base64_encode(t->room_keys[t->host_slot], TOR_KEY_LEN, b64);
    char line[200];
    snprintf(line, sizeof line, "ADD_ONION ED25519-V3:%s Port=%d,127.0.0.1:%u\r\n", b64, TOR_VPORT, (unsigned)t->listen_port);
    t->cmd = CMD_ADD_ROOM;
    ctl_send(t, line);
    crypto_wipe(line, sizeof line);
    crypto_wipe(b64, sizeof b64);
}

// Finds KEY=VALUE (VALUE maybe quoted) in a reply line.
static int reply_field(const char *line, const char *key, char *out, size_t cap) {
    size_t kl = strlen(key);
    for (const char *p = line; (p = strstr(p, key)) != NULL; p++) {
        if (p != line && p[-1] != ' ' && p[-1] != '-') continue;
        if (p[kl] != '=') continue;
        const char *v = p + kl + 1;
        size_t o = 0;
        if (*v == '"') {
            v++;
            while (*v && *v != '"' && o + 1 < cap) {
                if (*v == '\\' && v[1]) v++;
                out[o++] = *v++;
            }
        } else {
            while (*v && *v != ' ' && *v != '\r' && *v != '\n' && o + 1 < cap) out[o++] = *v++;
        }
        out[o] = '\0';
        return 0;
    }
    return -1;
}

// The path comes from whatever answered on the control port. Only a regular file of exactly a
// cookie's size is read, so it can't be a FIFO that hangs chat, or some other file.
static int read_cookie(tor_t *t) {
    if (!t->cookie_path[0]) return -1;
    uint8_t buf[sizeof t->cookie + 1];
    long n = platform_read_file(t->cookie_path, buf, sizeof buf);
    int ok = n == (long)sizeof t->cookie;
    if (ok) memcpy(t->cookie, buf, sizeof t->cookie);
    crypto_wipe(buf, sizeof buf);
    return ok ? 0 : -1;
}

static void on_protocolinfo(tor_t *t, double now) {
    char methods[160] = "";
    for (char *line = t->reply; line && *line; ) {
        char *eol = strstr(line, "\r\n");
        if (eol) *eol = '\0';
        if (starts_with(line, "250-AUTH ")) {
            reply_field(line, "METHODS", methods, sizeof methods);
            reply_field(line, "COOKIEFILE", t->cookie_path, sizeof t->cookie_path);
        }
        line = eol ? eol + 2 : NULL;
    }
    char m[170];
    snprintf(m, sizeof m, ",%s,", methods);
    if (strstr(m, ",NULL,")) {
        t->ctl_state = C_AUTH;
        ctl_send(t, "AUTHENTICATE\r\n");
    } else if (strstr(m, ",SAFECOOKIE,") && read_cookie(t) == 0) {
        // Only SAFECOOKIE. The plain COOKIE login sends the file's contents to whatever answers on the
        // port, and anything can listen there while tor isn't running. Every tor since 0.2.3 offers
        // SAFECOOKIE, where the other side has to prove it read the cookie first.
        gen_random(t->client_nonce, sizeof t->client_nonce);
        char hex[AUTH_NONCE_LEN * 2 + 1], line[120];
        hex_encode(t->client_nonce, sizeof t->client_nonce, hex);
        snprintf(line, sizeof line, "AUTHCHALLENGE SAFECOOKIE %s\r\n", hex);
        t->ctl_state = C_CHALLENGE;
        ctl_send(t, line);
    } else if (strstr(m, ",HASHEDPASSWORD,") && t->o.password[0]) {
        char line[300];
        size_t p = (size_t)snprintf(line, sizeof line, "AUTHENTICATE \"");
        for (const char *c = t->o.password; *c && p + 4 < sizeof line; c++) {
            if (*c == '"' || *c == '\\') line[p++] = '\\';
            line[p++] = *c;
        }
        snprintf(line + p, sizeof line - p, "\"\r\n");
        t->ctl_state = C_AUTH;
        ctl_send(t, line);
        crypto_wipe(line, sizeof line);
    } else {
        char why[260];
        if (strstr(m, ",SAFECOOKIE,"))
            snprintf(why, sizeof why, "can't read Tor's auth cookie (%.120s) - run chat as a user allowed to, "
                     "or set a control password in tor and with :set torpassword", t->cookie_path[0] ? t->cookie_path : "no path given");
        else if (strstr(m, "COOKIE"))
            snprintf(why, sizeof why, "the control port only offers the old COOKIE login, which shows its cookie file "
                     "to whatever answers there - chat needs SAFECOOKIE (any tor since 0.2.3) or a password");
        else if (strstr(m, "HASHEDPASSWORD"))
            snprintf(why, sizeof why, "Tor's control port wants a password - set it with :set torpassword");
        else
            snprintf(why, sizeof why, "Tor's control port offers no way to log in chat knows (%s)", methods);
        ctl_fail(t, now, why, 1);
    }
}

static void on_challenge(tor_t *t, double now) {
    char server_hash_hex[80] = "", server_nonce_hex[80] = "";
    reply_field(t->reply, "SERVERHASH", server_hash_hex, sizeof server_hash_hex);
    reply_field(t->reply, "SERVERNONCE", server_nonce_hex, sizeof server_nonce_hex);
    // Tor writes these in upper case.
    for (char *c = server_hash_hex; *c; c++) *c = (char)tolower((unsigned char)*c);
    for (char *c = server_nonce_hex; *c; c++) *c = (char)tolower((unsigned char)*c);
    uint8_t server_hash[SHA256_LEN], server_nonce[AUTH_NONCE_LEN];
    if (strlen(server_hash_hex) != sizeof server_hash * 2 || strlen(server_nonce_hex) != sizeof server_nonce * 2
        || hex_decode(server_hash_hex, sizeof server_hash * 2, server_hash) != 0
        || hex_decode(server_nonce_hex, sizeof server_nonce * 2, server_nonce) != 0) {
        ctl_fail(t, now, "Tor's SAFECOOKIE reply didn't parse", 1);
        return;
    }
    uint8_t msg[AUTH_COOKIE_LEN + 2 * AUTH_NONCE_LEN], want[SHA256_LEN], mine[SHA256_LEN];
    memcpy(msg, t->cookie, AUTH_COOKIE_LEN);
    memcpy(msg + AUTH_COOKIE_LEN, t->client_nonce, AUTH_NONCE_LEN);
    memcpy(msg + AUTH_COOKIE_LEN + AUTH_NONCE_LEN, server_nonce, AUTH_NONCE_LEN);
    static const char SK[] = "Tor safe cookie authentication server-to-controller hash";
    static const char CK[] = "Tor safe cookie authentication controller-to-server hash";
    hmac_sha256((const uint8_t *)SK, sizeof SK - 1, msg, sizeof msg, want);
    // The server proves it read the same cookie before we show our half.
    if (crypto_equal(want, server_hash, SHA256_LEN) != 0) {
        crypto_wipe(msg, sizeof msg);
        ctl_fail(t, now, "the control port failed Tor's cookie check - it may not be Tor", 1);
        return;
    }
    hmac_sha256((const uint8_t *)CK, sizeof CK - 1, msg, sizeof msg, mine);
    crypto_wipe(msg, sizeof msg);
    crypto_wipe(t->cookie, sizeof t->cookie);
    char hex[SHA256_LEN * 2 + 1], line[100];
    hex_encode(mine, sizeof mine, hex);
    snprintf(line, sizeof line, "AUTHENTICATE %s\r\n", hex);
    t->ctl_state = C_AUTH;
    ctl_send(t, line);
}

static void on_command_reply(tor_t *t, double now, int ok) {
    int cmd = t->cmd;
    t->cmd = CMD_NONE;
    char sid[TOR_ADDR_LEN + 8] = "";
    reply_field(t->reply, "ServiceID", sid, sizeof sid);
    if (cmd == CMD_ADD_ME) {
        if (!ok || !onion_valid(sid)) { ctl_fail(t, now, "Tor refused to publish an onion service for this session", 0); return; }
        copy_str(t->my_onion, sid, sizeof t->my_onion);
        t->ctl_warned = 0;
        t->ctl_fails = 0;
        logf_(t, 0, "* tor: your onion service is %s.onion - peers reach you only through Tor", t->my_onion);
    } else if (cmd == CMD_ADD_ROOM) {
        // Another session on the same tor already publishes the room, which works just as well.
        const char *room = t->room_onion[t->host_slot];
        if (ok && strcmp(sid, room) != 0) {
            // Joiners work out the address themselves, so if Tor's is different they'd connect to the wrong one.
            logf_(t, 0, "* tor: the room's onion address came out as %.56s, not %s - joining through it won't work",
                  sid, room);
        }
        if (ok || strstr(t->reply, "collision")) {
            t->room_up = 1;
            t->room_published_at = now;
            logf_(t, 1, "* tor: publishing room slot %d, %s.onion", t->host_slot, room);
        } else {
            t->room_retry_at = now + ROOM_RETRY;
            logf_(t, 1, "* tor: couldn't publish the room's onion service: %.80s", t->reply);
        }
    } else if (cmd == CMD_DEL_ROOM) {
        t->room_up = 0;
    }
}

// A complete reply has arrived when its last line has a space after the status code.
static void on_reply(tor_t *t, double now) {
    int ok = atoi(t->reply) == CTL_OK;
    switch (t->ctl_state) {
        case C_PROTOCOLINFO:
            if (!ok) { ctl_fail(t, now, "Tor's control port didn't answer PROTOCOLINFO", 0); return; }
            on_protocolinfo(t, now);
            return;
        case C_CHALLENGE:
            if (!ok) { ctl_fail(t, now, "Tor refused the SAFECOOKIE challenge", 1); return; }
            on_challenge(t, now);
            return;
        case C_AUTH:
            if (!ok) { ctl_fail(t, now, "Tor's control port refused the login - check :set torpassword", 1); return; }
            t->ctl_state = C_READY;
            if (t->probe) { t->probe_done = 1; close_ctl(t); return; }
            send_add_me(t);
            return;
        case C_READY:
            on_command_reply(t, now, ok);
            return;
        default:
            return;
    }
}

static void ctl_read(tor_t *t, double now) {
    for (;;) {
        if (t->ctl_in_len >= sizeof t->ctl_in - 1) { ctl_fail(t, now, "oversized reply from Tor", 0); return; }
        int n = net_tcp_recv(t->ctl, t->ctl_in + t->ctl_in_len, sizeof t->ctl_in - 1 - t->ctl_in_len);
        if (n < 0) { ctl_fail(t, now, "Tor closed the control connection", 0); return; }
        if (n == 0) break;
        t->ctl_in_len += (size_t)n;
        t->ctl_in[t->ctl_in_len] = '\0';
        char *eol;
        while ((eol = strstr(t->ctl_in, "\r\n")) != NULL) {
            size_t llen = (size_t)(eol - t->ctl_in) + 2;
            if (t->reply_len + llen + 1 > sizeof t->reply) { ctl_fail(t, now, "oversized reply from Tor", 0); return; }
            memcpy(t->reply + t->reply_len, t->ctl_in, llen);
            t->reply_len += llen;
            t->reply[t->reply_len] = '\0';
            int final = llen >= 6 && isdigit((unsigned char)t->ctl_in[0]) && t->ctl_in[3] == ' ';
            // Asynchronous events (650) aren't requested, and any that arrive are ignored.
            int async = starts_with(t->ctl_in, "650");
            memmove(t->ctl_in, t->ctl_in + llen, t->ctl_in_len - llen + 1);
            t->ctl_in_len -= llen;
            if (async) { if (final) t->reply_len = 0; continue; }
            if (final) {
                on_reply(t, now);
                t->reply_len = 0;
                if (t->ctl == SOCK_INVALID) return;
            }
        }
    }
}

static void ctl_step(tor_t *t, double now) {
    switch (t->ctl_state) {
        case C_FAILED:
            // A fixable problem (a password, a permission), so retry every so often without logging.
            if (now < t->ctl_next_try + CTL_FAILED_RETRY) return;
            t->ctl_state = C_IDLE;
            /* fall through */
        case C_IDLE: {
            if (now < t->ctl_next_try || t->probe_done) return;
            // No tor to talk to yet, because chat is still starting its own.
            if (!t->o.control[0]) return;
            // Each failure switches between the configured ports and Tor Browser's, while the
            // configured ones are the defaults.
            t->use_browser_ports = default_ports(t) && (t->ctl_fails % 2 == 1);
            addr_t a;
            if (addr_parse_hostport(control_addr(t), &a) != 0) { ctl_fail(t, now, "the Tor control port setting isn't host:port", 1); return; }
            t->ctl = net_tcp_connect(a);
            if (t->ctl == SOCK_INVALID) { ctl_fail(t, now, "can't open a connection to Tor's control port", 0); return; }
            t->ctl_state = C_CONNECTING;
            t->ctl_deadline = now + CTL_CONNECT_TIMEOUT;
            return;
        }
        case C_CONNECTING: {
            int rc = net_tcp_connect_done(t->ctl);
            if (rc == 0 && now < t->ctl_deadline) return;
            if (rc != 1) {
                char why[320];
                int defaults = strcmp(t->o.control, TOR_DEFAULTS.control) == 0;
                snprintf(why, sizeof why, "can't reach Tor's control port at %s%s - is tor running with ControlPort on? "
                         "(retrying; :set torsocks and :set torcontrol change the ports)", t->o.control, defaults ? " or Tor Browser's at " BROWSER_CONTROL : "");
                ctl_fail(t, now, why, 0);
                return;
            }
            t->ctl_state = C_PROTOCOLINFO;
            t->probe_reached = 1;
            ctl_send(t, "PROTOCOLINFO 1\r\n");
            return;
        }
        default:
            if (t->ctl != SOCK_INVALID) ctl_read(t, now);
            if (t->ctl_state == C_READY && t->cmd == CMD_NONE && t->my_onion[0]) {
                if (t->want_room && t->room_republish && now - t->room_published_at >= REPUBLISH_MIN_GAP) {
                    t->room_republish = 0;
                    if (t->room_up) {
                        char line[100];
                        snprintf(line, sizeof line, "DEL_ONION %s\r\n", t->room_onion[t->host_slot]);
                        t->cmd = CMD_DEL_ROOM;
                        ctl_send(t, line);
                        return;
                    }
                }
                if (t->want_room && !t->room_up && now >= t->room_retry_at) send_add_room(t);
            }
            return;
    }
}

static stream_t *new_stream(tor_t *t, int *index) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (t->streams[i]) continue;
        stream_t *s = calloc(1, sizeof *s);
        if (!s) return NULL;
        s->s = SOCK_INVALID;
        s->target = -1;
        t->streams[i] = s;
        *index = i;
        return s;
    }
    return NULL;
}

static void stream_fail(tor_t *t, int i, double now, const char *why) {
    stream_t *s = t->streams[i];
    if (s->target >= 0) {
        target_t *g = &t->targets[s->target];
        g->next_try = now + backoff(g->fails, TARGET_RETRY_BASE, TARGET_RETRY_SHIFT, TARGET_RETRY_MAX);
        g->fails++;
        logf_(t, 1, "* tor: stream to %.16s... %s", g->host, why);
    }
    close_stream(t, i);
}

static int stream_flush(tor_t *t, int i, double now) {
    stream_t *s = t->streams[i];
    while (s->tx_len > 0) {
        int n = net_tcp_send(s->s, s->tx, s->tx_len);
        if (n == 0) return 0;
        if (n < 0) { stream_fail(t, i, now, "closed"); return -1; }
        memmove(s->tx, s->tx + n, s->tx_len - (size_t)n);
        s->tx_len -= (size_t)n;
    }
    return 0;
}

static const char *socks_error(int rep) {
    switch (rep) {
        case 0xf0: return "onion service not found (nobody is publishing it right now)";
        case 0xf1: return "onion service descriptor invalid";
        case 0xf2: return "onion service introduction failed";
        case 0xf3: return "onion service rendezvous failed";
        case 0xf6: return "bad onion address";
        case 0xf7: return "onion service introduction timed out";
        case 0x04: return "host unreachable";
        case 0x05: return "connection refused";
        case 0x06: return "timed out";
        default:   return "failed";
    }
}

static void stream_step(tor_t *t, int i, double now) {
    stream_t *s = t->streams[i];
    if (s->state == S_CONNECTING) {
        int rc = net_tcp_connect_done(s->s);
        if (rc == 0) { if (now > s->deadline) stream_fail(t, i, now, "timed out reaching Tor's SOCKS port"); return; }
        if (rc < 0) { stream_fail(t, i, now, "can't reach Tor's SOCKS port"); return; }
        // Username/password "auth" isolates this session's circuits from every other's.
        uint8_t hello[SOCKS_HELLO_LEN];
        socks_hello(hello);
        if (net_tcp_send(s->s, hello, sizeof hello) != (int)sizeof hello) { stream_fail(t, i, now, "SOCKS write failed"); return; }
        s->state = S_METHOD;
        return;
    }
    for (;;) {
        if (s->rx_len >= RX_CAP) { stream_fail(t, i, now, "overflow"); return; }
        int n = net_tcp_recv(s->s, s->rx + s->rx_len, RX_CAP - s->rx_len);
        if (n < 0) { stream_fail(t, i, now, "closed"); return; }
        if (n == 0) break;
        s->rx_len += (size_t)n;
        s->last_rx = now;
        for (;;) {
            if (s->state == S_METHOD) {
                if (s->rx_len < SOCKS_REPLY_LEN) break;
                if (!socks_hello_ok(s->rx)) { stream_fail(t, i, now, "SOCKS port refused (is it Tor's?)"); return; }
                uint8_t auth[SOCKS_LOGIN_LEN];
                socks_login(auth, t->socks_user);
                if (net_tcp_send(s->s, auth, sizeof auth) != (int)sizeof auth) { stream_fail(t, i, now, "SOCKS write failed"); return; }
                memmove(s->rx, s->rx + SOCKS_REPLY_LEN, s->rx_len - SOCKS_REPLY_LEN); s->rx_len -= SOCKS_REPLY_LEN;
                s->state = S_AUTH;
            } else if (s->state == S_AUTH) {
                if (s->rx_len < SOCKS_REPLY_LEN) break;
                if (s->rx[1] != 0) { stream_fail(t, i, now, "SOCKS login refused"); return; }
                memmove(s->rx, s->rx + SOCKS_REPLY_LEN, s->rx_len - SOCKS_REPLY_LEN); s->rx_len -= SOCKS_REPLY_LEN;
                char name[TOR_ADDR_LEN + sizeof ".onion"];
                snprintf(name, sizeof name, "%s.onion", t->targets[s->target].host);
                uint8_t req[SOCKS_CONNECT_LEN(sizeof name)];
                size_t len = socks_connect(req, name, strlen(name), TOR_VPORT);
                if (net_tcp_send(s->s, req, len) != (int)len) { stream_fail(t, i, now, "SOCKS write failed"); return; }
                s->state = S_CONNECT;
            } else if (s->state == S_CONNECT) {
                if (s->rx_len < SOCKS_CONNECT_HEAD) break;
                if (s->rx[1] != 0) { stream_fail(t, i, now, socks_error(s->rx[1])); return; }
                size_t need = socks_connect_reply_len(s->rx);
                if (need == 0) { stream_fail(t, i, now, "bad SOCKS reply"); return; }
                if (s->rx_len < need) break;
                memmove(s->rx, s->rx + need, s->rx_len - need); s->rx_len -= need;
                s->state = S_OPEN;
                target_t *g = &t->targets[s->target];
                g->fails = 0;
                g->opened = 1;
                logf_(t, 1, "* tor: stream open to %.16s...", g->host);
            } else {
                if (s->rx_len < FRAME_LEN_PREFIX) break;
                size_t flen = load_be16(s->rx);
                if (flen == 0 || flen > TOR_FRAME_MAX) { stream_fail(t, i, now, "bad frame"); return; }
                if (s->rx_len < FRAME_LEN_PREFIX + flen) break;
                uint8_t frame[TOR_FRAME_MAX];
                memcpy(frame, s->rx + FRAME_LEN_PREFIX, flen);
                memmove(s->rx, s->rx + FRAME_LEN_PREFIX + flen, s->rx_len - FRAME_LEN_PREFIX - flen);
                s->rx_len -= FRAME_LEN_PREFIX + flen;
                t->busy = i;
                if (t->deliver) t->deliver(t->ctx, frame, flen, addr_virtual(ADDR_TOR, s->id), now);
                t->busy = -1;
            }
        }
    }
    if (s->state != S_OPEN && now > s->deadline) { stream_fail(t, i, now, "timed out"); return; }
    if (s->state == S_OPEN) {
        if (stream_flush(t, i, now) < 0) return;
        if (now - s->last_rx > STREAM_IDLE_TIMEOUT) { stream_fail(t, i, now, "went quiet"); return; }
    }
}

static void accept_streams(tor_t *t, double now) {
    if (t->listener == SOCK_INVALID) return;
    for (int k = 0; k < ACCEPT_BATCH; k++) {
        sock_t a = net_tcp_accept(t->listener);
        if (a == SOCK_INVALID) return;
        int idx;
        stream_t *s = new_stream(t, &idx);
        if (!s) { net_close(a); return; }
        s->s = a;
        s->state = S_OPEN;
        s->last_rx = now;
        gen_random(s->id, TARGET_ID_LEN);
    }
}

void tor_step(tor_t *t, double now) {
    ctl_step(t, now);
    accept_streams(t, now);
    for (int i = 0; i < MAX_STREAMS; i++) if (t->streams[i]) stream_step(t, i, now);
}

int tor_probe_result(const tor_t *t, char *socks, char *control, char *why, size_t why_cap) {
    if (t->probe_done > 0) {
        copy_str(socks, socks_addr(t), TOR_HOST_MAX);
        copy_str(control, control_addr(t), TOR_HOST_MAX);
    } else if (t->probe_done < 0 && why) {
        copy_str(why, t->last_error, why_cap);
    }
    // -2: a tor answered but can't be used. -1: nothing answered.
    return t->probe_done < 0 && t->probe_reached ? -2 : t->probe_done;
}

int tor_sockets(const tor_t *t, sock_t *out, int max) {
    int k = 0;
    if (k < max && t->ctl != SOCK_INVALID) out[k++] = t->ctl;
    if (k < max && t->listener != SOCK_INVALID) out[k++] = t->listener;
    for (int i = 0; i < MAX_STREAMS && k < max; i++)
        if (t->streams[i] && t->streams[i]->state == S_OPEN) out[k++] = t->streams[i]->s;
    return k;
}

static int open_stream(tor_t *t, int target, double now) {
    target_t *g = &t->targets[target];
    if (now < g->next_try) return -1;
    addr_t proxy;
    if (addr_parse_hostport(socks_addr(t), &proxy) != 0) return -1;
    int idx;
    stream_t *s = new_stream(t, &idx);
    if (!s) return -1;
    s->s = net_tcp_connect(proxy);
    if (s->s == SOCK_INVALID) { close_stream(t, idx); g->next_try = now + TARGET_RETRY_BASE; return -1; }
    s->state = S_CONNECTING;
    s->target = target;
    memcpy(s->id, g->id, TARGET_ID_LEN);
    s->deadline = now + STREAM_OPEN_TIMEOUT;
    s->last_rx = now;
    // Until it opens, stream_fail's backoff applies, and a second one isn't opened.
    g->next_try = now + STREAM_OPEN_TIMEOUT;
    return idx;
}

int tor_send(tor_t *t, addr_t to, const uint8_t *data, size_t len, double now) {
    if (to.kind != ADDR_TOR || len == 0 || len > TOR_FRAME_MAX) return -1;
    int idx = -1;
    for (int i = 0; i < MAX_STREAMS; i++) {
        stream_t *s = t->streams[i];
        if (!s || memcmp(s->id, to.ip, TARGET_ID_LEN) != 0) continue;
        if (idx < 0 || s->state == S_OPEN) idx = i;
    }
    if (idx < 0) {
        int target = -1;
        for (int i = 0; i < MAX_TARGETS; i++)
            if (t->targets[i].used && memcmp(t->targets[i].id, to.ip, TARGET_ID_LEN) == 0) { target = i; break; }
        if (target < 0) return -1;
        t->targets[target].last_used = now;
        idx = open_stream(t, target, now);
        if (idx < 0) return -1;
    }
    stream_t *s = t->streams[idx];
    if (s->target >= 0) t->targets[s->target].last_used = now;
    // A stream that's still opening holds a few datagrams. Any more are lost, as with UDP.
    if (s->tx_len + FRAME_LEN_PREFIX + len > TX_CAP) return -1;
    store_be16(s->tx + s->tx_len, (uint16_t)len);
    s->tx_len += FRAME_LEN_PREFIX;
    memcpy(s->tx + s->tx_len, data, len);
    s->tx_len += len;
    if (s->state == S_OPEN && idx != t->busy) stream_flush(t, idx, now);
    return 0;
}

int tor_target(tor_t *t, const char *onion, addr_t *out) {
    if (!onion_valid(onion) || strcmp(onion, t->my_onion) == 0) return -1;
    int i = add_target(t, onion);
    if (i < 0) return -1;
    *out = addr_virtual(ADDR_TOR, t->targets[i].id);
    return 0;
}

addr_t tor_room_target(const tor_t *t, int slot) {
    return addr_virtual(ADDR_TOR, t->targets[t->room_targets[slot]].id);
}

void tor_host_room(tor_t *t, int slot) {
    if (t->want_room) return;
    if (slot < 0 || slot >= TOR_ROOM_SLOTS) {
        // A slot nobody answered on, and not the creator's while others are free.
        int free_slots[TOR_ROOM_SLOTS], n = 0;
        for (int i = 1; i < TOR_ROOM_SLOTS; i++) if (!t->targets[t->room_targets[i]].opened) free_slots[n++] = i;
        slot = n > 0 ? free_slots[gen_uniform((uint32_t)n)] : 1 + (int)gen_uniform(TOR_ROOM_SLOTS - 1);
    }
    t->host_slot = slot;
    t->want_room = 1;
}

int tor_hosted_slot(const tor_t *t) { return t->host_slot; }

void tor_republish_room(tor_t *t) { if (t->want_room) t->room_republish = 1; }

const char *tor_my_onion(const tor_t *t) { return t->my_onion; }

void tor_status(const tor_t *t, char *out, size_t cap) {
    int open = 0, opening = 0;
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!t->streams[i]) continue;
        if (t->streams[i]->state == S_OPEN) open++; else opening++;
    }
    const char *st;
    switch (t->ctl_state) {
        case C_READY:  st = t->my_onion[0] ? "onion service up" : "publishing onion service"; break;
        case C_FAILED: st = "can't log in to Tor"; break;
        case C_IDLE:
        case C_CONNECTING: st = "looking for Tor"; break;
        default:       st = "logging in to Tor"; break;
    }
    char slot[32] = "";
    if (t->room_up) snprintf(slot, sizeof slot, ", room slot %d published", t->host_slot);
    snprintf(out, cap, "%s%s%s, %d stream%s open, %d opening%s", st, slot,
             t->use_browser_ports ? " (Tor Browser's tor)" : "", open, open == 1 ? "" : "s", opening,
             t->last_error[0] && t->ctl_state != C_READY ? " - last problem: " : "");
    size_t n = strlen(out);
    if (t->last_error[0] && t->ctl_state != C_READY && n < cap) snprintf(out + n, cap - n, "%s", t->last_error);
}
