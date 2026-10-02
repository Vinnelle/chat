// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "core/chat.h"
#include "core/trust.h"
#include "common/util.h"
#include "platform/platform.h"
#include "common/image.h"
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SECRETS_OFFSET offsetof(chat_t, keys)
#define SECRETS_LEN (offsetof(chat_t, identity) + sizeof(identity_keypair_t) - offsetof(chat_t, keys))

static void ui_print(chat_t *c, const char *fmt, ...);
static void ui_warn(chat_t *c, const char *fmt, ...);
static int check_trust(chat_t *c, peer_t *p);
static void net_report(chat_t *c);
static void module_log(void *ctx, int verbose_only, const char *msg);
static void knock_room_slots(chat_t *c);

static const char *const DEFAULT_RELAYS[] = {
    "wss://relay.primal.net",
    "wss://nostr.mom",
    "wss://relay.nostr.net",
};

void routing_defaults(routing_t *r) {
    memset(r, 0, sizeof *r);
    r->mode = ROUTE_DHT;
    r->dht4 = r->dht6 = r->lan = r->portmap = r->nostr = 1;
    for (size_t i = 0; i < sizeof DEFAULT_RELAYS / sizeof DEFAULT_RELAYS[0]; i++)
        copy_str(r->relays[r->n_relays++], DEFAULT_RELAYS[i], NOSTR_URL_MAX);
    r->tor = TOR_DEFAULTS;
}

const char *routing_mode_name(route_mode_t m) { return m == ROUTE_TOR ? "tor" : "dht"; }
static void ui_print_colored(chat_t *c, const uint8_t rgb[3], const char *fmt, ...);
static void ui_chat(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text);
static void ui_chat_file(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text, int file);
static int file_next_chunk(chat_t *c, peer_t *p, char *text, size_t *pos, size_t cap);
static void file_on_record(chat_t *c, peer_t *p, char **f, int n, double now);
static void files_tick(chat_t *c, double now);
static void file_offer_all(chat_t *c, peer_t *p);
static int file_downloading_from(const chat_t *c, const peer_t *p);
static void file_free(file_entry_t *e);

const named_color_t COLOR_PALETTE[] = {
    { "red",     0xE5, 0x48, 0x4D }, { "orange",  0xF7, 0x6B, 0x15 },
    { "yellow",  0xF5, 0xD9, 0x0A }, { "green",   0x30, 0xA4, 0x6C },
    { "teal",    0x12, 0xA5, 0x94 }, { "cyan",    0x00, 0xA2, 0xC7 },
    { "blue",    0x00, 0x90, 0xFF }, { "indigo",  0x3E, 0x63, 0xDD },
    { "purple",  0x8E, 0x4E, 0xC6 }, { "pink",    0xD6, 0x40, 0x9F },
    { "brown",   0xAD, 0x7F, 0x58 }, { "gray",    0x8B, 0x8D, 0x98 },
};
const int COLOR_PALETTE_N = (int)(sizeof(COLOR_PALETTE) / sizeof(COLOR_PALETTE[0]));

static int hexval1(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int parse_color(const char *text, uint8_t rgb[3]) {
    const char *h = text;
    if (h[0] == '#') h++;
    size_t len = strlen(h);
    if (len == 6) {
        int ok = 1;
        uint8_t tmp[3];
        for (int i = 0; i < 3; i++) {
            int hi = hexval1(h[i * 2]), lo = hexval1(h[i * 2 + 1]);
            if (hi < 0 || lo < 0) { ok = 0; break; }
            tmp[i] = (uint8_t)((hi << 4) | lo);
        }
        if (ok) { memcpy(rgb, tmp, 3); return 0; }
    }
    for (int i = 0; i < COLOR_PALETTE_N; i++) {
        size_t nlen = strlen(COLOR_PALETTE[i].name);
        if (nlen == strlen(text)) {
            int match = 1;
            for (size_t j = 0; j < nlen; j++)
                if (tolower((unsigned char)text[j]) != COLOR_PALETTE[i].name[j]) { match = 0; break; }
            if (match) { rgb[0] = COLOR_PALETTE[i].r; rgb[1] = COLOR_PALETTE[i].g; rgb[2] = COLOR_PALETTE[i].b; return 0; }
        }
    }
    return -1;
}

static void color_to_hex(const uint8_t rgb[3], char out[7]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 3; i++) { out[i*2] = H[rgb[i]>>4]; out[i*2+1] = H[rgb[i]&0xf]; }
    out[6] = '\0';
}

#define MAX_FIELDS 8

static int split_tabs(char *s, char *fields[], int max) {
    int n = 0;
    char *p = s;
    fields[n++] = p;
    while (*p && n < max) {
        if (*p == '\t') { *p = '\0'; fields[n++] = p + 1; }
        p++;
    }
    return n;
}

static void gen_mid(char out[9]) {
    uint8_t b[4];
    gen_random(b, 4);
    hex_encode(b, 4, out);
}

static int nick_ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

// Characters that render as nothing, or next to nothing.
static int is_invisible(uint32_t cp) {
    return cp == 0xad || cp == 0x34f || cp == 0x61c || cp == 0x115f || cp == 0x1160 || cp == 0x17b4
        || cp == 0x17b5 || cp == 0x180e || (cp >= 0x200b && cp <= 0x200d) || (cp >= 0x2060 && cp <= 0x2064)
        || cp == 0x3164 || cp == 0xfeff || cp == 0xffa0 || (cp >= 0xfe00 && cp <= 0xfe0f)
        || (cp >= 0xe0000 && cp <= 0xe007f);
}

// Fullwidth ASCII, and other brackets and marks that look like the ones the UI uses, mapped to plain ASCII.
static uint32_t fold_punct(uint32_t cp) {
    if (cp >= 0xff01 && cp <= 0xff5e) return cp - 0xff01 + 0x21;
    switch (cp) {
        case 0x207d: case 0x208d: case 0x2768: case 0x276a: case 0x27ee: case 0x2985: case 0xfe59: case 0xff5f:
            return '(';
        case 0x207e: case 0x208e: case 0x2769: case 0x276b: case 0x27ef: case 0x2986: case 0xfe5a: case 0xff60:
            return ')';
        case 0xfe5f: return '#';
        case 0x2d0: case 0x2236: case 0xa789: case 0xfe13: case 0xfe55: return ':';
        case 0xfe6b: return '@';
        default: return cp;
    }
}

// Letters from other scripts that look like Latin ones.
static const struct { uint16_t cp; char ascii; } LOOKALIKES[] = {
    { 0x0131, 'i' }, { 0x0261, 'g' }, { 0x0391, 'A' }, { 0x0392, 'B' }, { 0x0395, 'E' }, { 0x0396, 'Z' },
    { 0x0397, 'H' }, { 0x0399, 'I' }, { 0x039a, 'K' }, { 0x039c, 'M' }, { 0x039d, 'N' }, { 0x039f, 'O' },
    { 0x03a1, 'P' }, { 0x03a4, 'T' }, { 0x03a5, 'Y' }, { 0x03a7, 'X' }, { 0x03b1, 'a' }, { 0x03b9, 'i' },
    { 0x03ba, 'k' }, { 0x03bd, 'v' }, { 0x03bf, 'o' }, { 0x03c1, 'p' }, { 0x03c5, 'u' }, { 0x0405, 'S' },
    { 0x0406, 'I' }, { 0x0408, 'J' }, { 0x0410, 'A' }, { 0x0412, 'B' }, { 0x0415, 'E' }, { 0x041a, 'K' },
    { 0x041c, 'M' }, { 0x041d, 'H' }, { 0x041e, 'O' }, { 0x0420, 'P' }, { 0x0421, 'C' }, { 0x0422, 'T' },
    { 0x0425, 'X' }, { 0x0430, 'a' }, { 0x0435, 'e' }, { 0x043a, 'k' }, { 0x043e, 'o' }, { 0x0440, 'p' },
    { 0x0441, 'c' }, { 0x0443, 'y' }, { 0x0445, 'x' }, { 0x0455, 's' }, { 0x0456, 'i' }, { 0x0458, 'j' },
    { 0x04ae, 'Y' }, { 0x04bb, 'h' }, { 0x04c0, 'I' }, { 0x0501, 'd' }, { 0x051b, 'q' }, { 0x051d, 'w' },
    { 0x217c, 'l' },
};

// A nick normalised for comparing: lookalikes mapped to Latin, i/I/1/| to l, 0 to o, with case
// and invisible characters ignored.
static void nick_skeleton(const char *nick, char *out, size_t cap) {
    size_t n = strlen(nick), i = 0, o = 0;
    while (i < n) {
        size_t adv;
        uint32_t cp = fold_punct(utf8_decode(nick, n, i, &adv));
        i += adv;
        if (is_invisible(cp)) continue;
        for (size_t k = 0; k < sizeof LOOKALIKES / sizeof LOOKALIKES[0]; k++)
            if (LOOKALIKES[k].cp == cp) { cp = (uint32_t)LOOKALIKES[k].ascii; break; }
        if (cp < 0x80) cp = (uint32_t)tolower((int)cp);
        if (cp == 'i' || cp == '|' || cp == '1') cp = 'l';
        else if (cp == '0') cp = 'o';
        char enc[4];
        size_t len = utf8_put(cp, enc);
        if (o + len >= cap) break;
        memcpy(out + o, enc, len);
        o += len;
    }
    out[o] = '\0';
}

void chat_nick_skeleton(const char *nick, char *out, size_t cap) { nick_skeleton(nick, out, cap); }

void chat_clean_nick(const char *in, char out[MAX_NICK + 1]) {
    char tmp[MAX_NICK + 1], kept[MAX_NICK + 1];
    clean_text(in, tmp, MAX_NICK);
    size_t n = strlen(tmp), i = 0, o = 0;
    while (i < n) {
        size_t adv;
        uint32_t cp = utf8_decode(tmp, n, i, &adv);
        uint32_t f = fold_punct(cp);
        if (!is_invisible(cp) && !(f < 0x80 && strchr("()#:@", (int)f))) {
            if (f != cp) kept[o++] = (char)f;
            else { memcpy(kept + o, tmp + i, adv); o += adv; }
        }
        i += adv;
    }
    kept[o] = '\0';
    clean_text(kept, out, MAX_NICK);
    if (!out[0]) copy_str(out, "anon", MAX_NICK + 1);
}

static void set_peer_nick(peer_t *p, const char *nick) {
    chat_clean_nick(nick, p->nick);
    nick_skeleton(p->nick, p->nick_skel, sizeof p->nick_skel);
}

static void set_own_nick(chat_t *c, const char *nick) {
    chat_clean_nick(nick, c->nick);
    nick_skeleton(c->nick, c->nick_skel, sizeof c->nick_skel);
}

void chat_peer_name(const chat_t *c, const peer_t *p, char out[CHAT_NAME_LEN]) {
    int clash = strcmp(p->nick_skel, c->nick_skel) == 0;
    for (int i = 0; i < c->peer_hi && !clash; i++) {
        const peer_t *q = &c->peers[i];
        if (q == p || !q->used || !q->ok) continue;
        clash = strcmp(p->nick_skel, q->nick_skel) == 0;
    }
    if (!clash) { copy_str(out, p->nick, CHAT_NAME_LEN); return; }
    char idhex[9]; hex_encode(p->id, 4, idhex);
    snprintf(out, CHAT_NAME_LEN, "%s#%s", p->nick, idhex);
}

static int has_mention(const char *text, const char *nick) {
    size_t nlen = strlen(nick);
    if (nlen == 0) return 0;
    size_t tlen = strlen(text);
    for (size_t i = 0; i + 1 + nlen <= tlen; i++) {
        if (text[i] != '@') continue;
        int match = 1;
        for (size_t j = 0; j < nlen; j++)
            if (tolower((unsigned char)text[i + 1 + j]) != tolower((unsigned char)nick[j])) { match = 0; break; }
        if (match) return 1;
    }
    return 0;
}

static uint32_t mid_key(const char *mid) {
    uint32_t v = 0;
    for (int i = 0; i < 8; i++) {
        int h = hexval1(mid[i]);
        if (h < 0) break;
        v = (v << 4) | (uint32_t)h;
    }
    return v;
}

static int seen_has(chat_t *c, const char *mid) {
    uint32_t key = mid_key(mid);
    for (int i = 0; i < c->seen_count; i++) {
        int idx = (c->seen_head - 1 - i + 2048) % 2048;
        if (c->seen_mids[idx] == key) return 1;
    }
    return 0;
}
static void seen_add(chat_t *c, const char *mid) {
    c->seen_mids[c->seen_head] = mid_key(mid);
    c->seen_head = (c->seen_head + 1) % 2048;
    if (c->seen_count < 2048) c->seen_count++;
}

static double jitter(double spread) {
    uint32_t r;
    gen_random((uint8_t *)&r, sizeof r);
    return spread * ((double)r / 4294967296.0);
}

// Takes a token from a bucket that fills at rate per second, up to burst. Returns 1 if there was one.
static int take_token(double *tokens, double *at, double now, double rate, double burst) {
    if (now > *at) *tokens += (now - *at) * rate;
    if (*tokens > burst) *tokens = burst;
    *at = now;
    if (*tokens < 1.0) return 0;
    *tokens -= 1.0;
    return 1;
}

static double retry_delay(int tries) {
    int shift = tries < HELLO_MAX_BACKOFF ? tries : HELLO_MAX_BACKOFF;
    double d = RETRY_BASE * (double)(1u << shift);
    if (d > RETRY_CAP) d = RETRY_CAP;
    return d + jitter(d * 0.25);
}

static peer_t *find_peer_by_id(chat_t *c, const uint8_t id[ID_LEN]) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && memcmp(c->peers[i].id, id, ID_LEN) == 0) return &c->peers[i];
    return NULL;
}
static int peer_slot(chat_t *c, peer_t *p) { return (int)(p - c->peers); }

static int live_count(chat_t *c) {
    int n = 0;
    for (int i = 0; i < c->peer_hi; i++) if (c->peers[i].used && c->peers[i].ok) n++;
    return n;
}
static int pending_peer_count(chat_t *c) {
    int n = 0;
    for (int i = 0; i < c->peer_hi; i++) if (c->peers[i].used && !c->peers[i].ok) n++;
    return n;
}

static void pending_clear(pending_msg_t *pm) { crypto_wipe(pm, sizeof *pm); }

static void forget_peer(chat_t *c, peer_t *p) {
    int slot = peer_slot(c, p);
    for (int i = 0; i < MAX_PENDING_MSGS; i++)
        if (c->pending[i].used && c->pending[i].peer_slot == slot) pending_clear(&c->pending[i]);
    for (int i = 0; i < SENDQ_MAX; i++)
        if (c->sendq[i].used && c->sendq[i].peer_slot == slot) crypto_wipe(&c->sendq[i], sizeof c->sendq[i]);
    for (int i = 0; i < ROOMQ_MAX; i++)
        if (c->roomq[i].used && c->roomq[i].peer_slot == slot) c->roomq[i].used = 0;
    crypto_wipe(p, sizeof *p);
    while (c->peer_hi > 0 && !c->peers[c->peer_hi - 1].used) c->peer_hi--;
}

static void rekey_drop_overlap(peer_t *p) {
    crypto_wipe(&p->old_send, sizeof p->old_send);
    crypto_wipe(&p->old_recv, sizeof p->old_recv);
    p->old_until = 0.0;
}

// The DHT's datagrams, never masked since they're normal DHT traffic. Names are never sent: the
// bootstrap servers are looked up here.
static void dht_out(void *ctx, const void *data, size_t len, const addr_t *to, const char *host, uint16_t port) {
    chat_t *c = ctx;
    (void)port;
    if (c->sock == SOCK_INVALID || host || !to) return;
    net_send(c->sock, data, len, *to);
}

// Every datagram is sent from here, over UDP, the relays or Tor depending on its address. In Tor
// mode nothing is sent over UDP. UDP traffic is masked first, so on the network it's random bytes.
// The relays and Tor already hide what they carry, and take it in the same form 0.1.9 sends.
static void xmit(chat_t *c, sock_t sock, const void *data, size_t len, addr_t to) {
    switch (to.kind) {
        case ADDR_NOSTR:
            if (c->nostr) nostr_send(c->nostr, to, data, len, now_seconds());
            return;
        case ADDR_TOR:
            if (c->tor) tor_send(c->tor, to, data, len, now_seconds());
            return;
        default: {
            if (c->route.mode == ROUTE_TOR || sock == SOCK_INVALID) return;
            uint8_t masked[HANDSHAKE_BUF_LEN + 128];
            if (len > sizeof masked) return;
            memcpy(masked, data, len);
            if (udp_mask(c->udp_key, masked, len) == 0) net_send(sock, masked, len, to);
        }
    }
}

// The i-th piece of a room frame, padded to a whole cell.
static void room_piece(const uint8_t *frame, size_t len, const uint8_t id[4], int i, int count, uint8_t cell[UDP_CELL]) {
    size_t off = (size_t)i * CHUNK_PAYLOAD, n = len - off < CHUNK_PAYLOAD ? len - off : CHUNK_PAYLOAD;
    cell[0] = CHUNK_MAGIC0;
    cell[1] = CHUNK_MAGIC1;
    memcpy(cell + 2, id, 4);
    cell[6] = (uint8_t)i;
    cell[7] = (uint8_t)count;
    cell[8] = (uint8_t)(len >> 8);
    cell[9] = (uint8_t)len;
    memcpy(cell + CHUNK_HDR, frame + off, n);
    // Random instead of zeros, since a cell's last bytes pick the keystream it's masked with.
    gen_random(cell + CHUNK_HDR + n, CHUNK_PAYLOAD - n);
}

static peer_t *live_peer_at(chat_t *c, addr_t a) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok && addr_equal(c->peers[i].addr, a)) return &c->peers[i];
    return NULL;
}

static int room_queued(const chat_t *c, int slot) {
    int n = 0;
    for (int i = 0; i < ROOMQ_MAX; i++) n += c->roomq[i].used && c->roomq[i].peer_slot == slot;
    return n;
}

// A room frame for a connected peer waits for its slots. A peer can have a few queued. Beyond
// that (junk replayed at it, for example) they're lost, like datagrams would be, and handshakes retry.
static void queue_room(chat_t *c, peer_t *p, const uint8_t *frame, size_t len, addr_t to) {
    int slot = peer_slot(c, p);
    if (room_queued(c, slot) >= 4) return;
    for (int i = 0; i < ROOMQ_MAX; i++) {
        roomq_t *q = &c->roomq[i];
        if (q->used) continue;
        q->used = 1;
        q->peer_slot = slot;
        q->seq = ++c->queue_seq;
        q->to = to;
        gen_random(q->id, sizeof q->id);
        q->next_piece = 0;
        q->pieces = (int)((len + CHUNK_PAYLOAD - 1) / CHUNK_PAYLOAD);
        q->len = len;
        memcpy(q->frame, frame, len);
        return;
    }
}

static void send_room(chat_t *c, const char *text, addr_t to, sock_t sock) {
    uint8_t frame[HANDSHAKE_BUF_LEN + 128];
    size_t len;
    if (room_seal(c->room_key, text, strlen(text), frame, sizeof frame, &len) != 0 || len > ROOM_FRAME_MAX) return;
    // A connected peer's frames go in its slots, like everything else sent to it.
    peer_t *p = sock == c->sock ? live_peer_at(c, to) : NULL;
    if (p) { queue_room(c, p, frame, len, to); return; }
    // Relays and Tor streams take whole frames; UDP takes cells.
    if (to.kind != ADDR_UDP) { xmit(c, sock, frame, len, to); return; }
    int count = (int)((len + CHUNK_PAYLOAD - 1) / CHUNK_PAYLOAD);
    uint8_t id[4];
    gen_random(id, 4);
    for (int i = 0; i < count; i++) {
        uint8_t cell[UDP_CELL];
        room_piece(frame, len, id, i, count, cell);
        xmit(c, sock, cell, UDP_CELL, to);
    }
}

static int relayed_count(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < c->peer_hi; i++) n += c->peers[i].used && c->peers[i].ok && c->peers[i].addr.kind == ADDR_NOSTR;
    return n;
}

static double cover_interval(chat_t *c, const peer_t *p) {
    int live = live_count(c);
    if (live < 1) live = 1;
    double scale = (double)live / (COVER_MAX_RATE * COVER_INTERVAL);
    double iv = COVER_INTERVAL * (scale > 1.0 ? scale : 1.0);
    if (p && p->addr.kind == ADDR_NOSTR) {
        double least = (double)relayed_count(c) / NOSTR_MAX_RATE;
        if (least < NOSTR_COVER_INTERVAL) least = NOSTR_COVER_INTERVAL;
        if (iv < least) iv = least;
    }
    return iv;
}

// The slot interval for a fast transfer through the relays, instead of iv: no more than
// NOSTR_FAST_RATE a second for all relayed peers together, however many are fast, and never closer
// than NOSTR_FAST_INTERVAL.
static double relay_fast_interval(chat_t *c, double iv) {
    double fast = (double)relayed_count(c) / NOSTR_FAST_RATE;
    if (fast < NOSTR_FAST_INTERVAL) fast = NOSTR_FAST_INTERVAL;
    return fast < iv ? fast : iv;
}

// What a frame through the relays carries has to fit in an event, with the sender and recipient.
_Static_assert(RELAY_FRAME <= NOSTR_WRAP_PLAIN - 2 * ID_LEN - 2, "a relay frame has to fit in a relay event");

static ratchet_t *send_chain_for(peer_t *p) {
    if (!p->send_chain.started && p->old_until > 0.0 && p->old_send.started) return &p->old_send;
    return &p->send_chain;
}

// Seals text as the chain's next frame, with a body of body bytes (a UDP cell, or a relay frame)
// unless it needs more.
static int frame_on_chain(ratchet_t *chain, const char *text, size_t body, uint8_t *frame, size_t frame_cap,
                          size_t *len, uint32_t *index) {
    uint32_t idx = chain->index;
    ratchet_t advanced;
    uint8_t mk[32];
    int rc = -1;
    if (ratchet_peek(chain, idx, mk, &advanced) == 0
        && session_seal_padded(mk, idx, text, strlen(text), body, frame, frame_cap, len) == 0) {
        *chain = advanced;
        *index = idx;
        rc = 0;
    }
    crypto_wipe(mk, sizeof mk);
    return rc;
}

// Queues a record for p's next slot. A record identical to one already waiting isn't queued again,
// so a retry, or a re-sent "rk", only goes once.
static int queue_record(chat_t *c, peer_t *p, const char *text, int old_chain) {
    size_t len = strlen(text);
    if (len == 0 || len > RECORD_MAX) return -1;
    int slot = peer_slot(c, p);
    sendq_t *free_q = NULL;
    for (int i = 0; i < SENDQ_MAX; i++) {
        sendq_t *q = &c->sendq[i];
        if (!q->used) { if (!free_q) free_q = q; continue; }
        if (q->peer_slot == slot && q->old_chain == old_chain && strcmp(q->text, text) == 0) return 0;
    }
    if (!free_q) return -1;
    free_q->used = 1;
    free_q->peer_slot = slot;
    free_q->seq = ++c->queue_seq;
    free_q->old_chain = old_chain;
    copy_str(free_q->text, text, sizeof free_q->text);
    return 0;
}

static int send_peer(chat_t *c, peer_t *p, const char *text) { return queue_record(c, p, text, 0); }

// Sent immediately, outside the slots. Only used for the "bye" of a session that's ending.
static void send_now(chat_t *c, peer_t *p, const char *text) {
    uint8_t frame[UDP_CELL]; size_t len; uint32_t idx;
    if (frame_on_chain(send_chain_for(p), text, SESSION_PAD_TARGET, frame, sizeof frame, &len, &idx) != 0) return;
    xmit(c, c->sock, frame, len, p->addr);
    crypto_wipe(frame, sizeof frame);
}

// A peer's slot: exactly one datagram. The oldest thing waiting goes first: a piece of a room
// frame, or a record and, for a peer that reads several per frame, the ones after it on the same
// chain while they fit. With nothing waiting, a "nop".
static void run_slot(chat_t *c, peer_t *p) {
    int slot = peer_slot(c, p);
    roomq_t *rq = NULL;
    sendq_t *first = NULL;
    for (int i = 0; i < ROOMQ_MAX; i++) {
        roomq_t *q = &c->roomq[i];
        if (q->used && q->peer_slot == slot && (!rq || q->seq < rq->seq)) rq = q;
    }
    for (int i = 0; i < SENDQ_MAX; i++) {
        sendq_t *q = &c->sendq[i];
        if (q->used && q->peer_slot == slot && (!first || q->seq < first->seq)) first = q;
    }
    // Records only wait behind a room frame queued before them while the peer can't read them yet,
    // since a message sealed on our new chain before our kx reaches it would be lost. Otherwise they
    // go first, so a re-handshake doesn't hold up a conversation, but never for more than two slots in
    // a row while the room frame waits, so a busy conversation doesn't hold up the re-handshake.
    int readable = send_chain_for(p) == &p->old_send || p->chain_confirmed;
    int overtake = rq && first && readable && p->room_waited < 2;
    if (rq && (!first || (rq->seq < first->seq && !overtake))) {
        p->room_waited = 0;
        if (rq->to.kind == ADDR_UDP) {
            uint8_t cell[UDP_CELL];
            room_piece(rq->frame, rq->len, rq->id, rq->next_piece, rq->pieces, cell);
            xmit(c, c->sock, cell, UDP_CELL, rq->to);
            if (++rq->next_piece >= rq->pieces) rq->used = 0;
        } else {
            xmit(c, c->sock, rq->frame, rq->len, rq->to);
            rq->used = 0;
        }
        return;
    }

    // Through the relays, to a peer that reads several records per frame, the frame is as big as a
    // relay event can hold (they're all one size there anyway), with room for two file chunks.
    int big = p->batches && p->addr.kind == ADDR_NOSTR;
    size_t cap = big ? RELAY_RECORD_MAX : RECORD_MAX;
    char text[RELAY_RECORD_MAX + 1] = "nop";
    sendq_t *taken[16];
    int n_taken = 0, old_chain = first ? first->old_chain : 0;
    size_t pos = 0;
    uint32_t after = 0;
    while (first) {
        sendq_t *next = NULL;
        for (int i = 0; i < SENDQ_MAX; i++) {
            sendq_t *q = &c->sendq[i];
            if (!q->used || q->peer_slot != slot || (n_taken && q->seq <= after)) continue;
            if (!next || q->seq < next->seq) next = q;
        }
        if (!next || next->old_chain != old_chain || (rq && !overtake && next->seq > rq->seq)) break;
        size_t l = strlen(next->text);
        if (n_taken && (!p->batches || pos + 1 + l > cap || n_taken == 16)) break;
        if (n_taken) text[pos++] = '\n';
        memcpy(text + pos, next->text, l);
        pos += l;
        text[pos] = '\0';
        taken[n_taken++] = next;
        after = next->seq;
    }
    // Space left over: the next chunks of a file this peer asked for. Over UDP a chunk takes its own
    // slot, one that would otherwise carry a nop. Through the relays, as many as fit after the rest.
    while (p->serving && (big || n_taken == 0) && file_next_chunk(c, p, text, &pos, cap)) {}
    ratchet_t *chain = old_chain && p->old_until > 0.0 && p->old_send.started ? &p->old_send : send_chain_for(p);
    uint8_t frame[RELAY_FRAME]; size_t len; uint32_t idx;
    // No chain yet (a responder waiting for the kx), so anything queued waits too.
    if (frame_on_chain(chain, text, big ? SEAL_MAX_BODY : SESSION_PAD_TARGET, frame, sizeof frame, &len, &idx) == 0) {
        xmit(c, c->sock, frame, len, p->addr);
        for (int i = 0; i < n_taken; i++) crypto_wipe(taken[i], sizeof *taken[i]);
        if (rq) p->room_waited++;
    }
    crypto_wipe(frame, sizeof frame);
    crypto_wipe(text, sizeof text);
}

static void add_candidate(chat_t *c, addr_t a) {
    if (a.port == 0) return;
    for (int i = 0; i < c->n_self_addrs; i++) if (addr_equal(c->self_addrs[i], a)) return;
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && addr_equal(c->peers[i].addr, a)) return;
    int same_host = 0;
    for (int i = 0; i < MAX_CANDS; i++) {
        if (!c->cands[i].used) continue;
        addr_t b = c->cands[i].addr;
        if (addr_equal(b, a)) return;
        if (b.is_v6 == a.is_v6 && memcmp(b.ip, a.ip, a.is_v6 ? 16 : 4) == 0) same_host++;
    }
    if (same_host >= CAND_PER_HOST) return;
    for (int i = 0; i < MAX_CANDS; i++) {
        if (!c->cands[i].used) {
            c->cands[i].used = 1;
            c->cands[i].addr = a;
            c->cands[i].tries = 0;
            c->cands[i].next_try = 0;
            return;
        }
    }
}

static void dht_candidate_cb(void *ctx, addr_t a) { add_candidate((chat_t *)ctx, a); }

static int candidate_reached(chat_t *c, addr_t a) {
    for (int i = 0; i < c->peer_hi; i++) {
        const peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        if (addr_equal(p->addr, a)) return 1;
        if (a.kind == ADDR_NOSTR && memcmp(p->id, a.ip, ID_LEN) == 0) return 1;
    }
    return 0;
}

// A message resend waits for the ack's round trip: the message waits for a slot here, the ack for
// a slot there, and relays take a lot longer than UDP.
static double resend_delay(chat_t *c, const peer_t *p) {
    double slots = 2.0 * cover_interval(c, p) * 1.25;
    return slots + (p->addr.kind == ADDR_NOSTR ? 4.0 + jitter(1.0) : 1.0 + jitter(0.5));
}

static void refresh_hi(chat_t *c) {
    char pubhex[65], kemhex[KEM_PUB_LEN * 2 + 1];
    hex_encode(c->my_id, ID_LEN, c->my_idhex);
    hex_encode(c->keys.pub, PUB_LEN, pubhex);
    hex_encode(c->kem_keys.pub, KEM_PUB_LEN, kemhex);
    snprintf(c->hi_msg, sizeof c->hi_msg, "hi\t%s\t%s\t%s", c->my_idhex, pubhex, kemhex);
}

static void send_kx(chat_t *c, peer_t *p, addr_t to) {
    char idhex[33]; hex_encode(c->my_id, ID_LEN, idhex);
    char cthex[KEM_CT_LEN * 2 + 1]; hex_encode(p->kem_ct, KEM_CT_LEN, cthex);
    char kx[16 + 32 + KEM_CT_LEN * 2];
    snprintf(kx, sizeof kx, "kx\t%s\t%s", idhex, cthex);
    send_room(c, kx, to, c->sock);
}

static void build_k_message(chat_t *c, peer_t *p, char *out, size_t out_cap) {
    char colorhex[7]; color_to_hex(c->my_color, colorhex);
    char idpubhex[65] = "", sighex[129] = "";
    int idtype = IDENT_NONE;
    if (c->identity_source != IDENT_NONE) {
        idtype = c->identity_source;
        hex_encode(c->identity.pub, ID_SIGN_PUB_LEN, idpubhex);
        uint8_t sig[ID_SIGN_LEN];
        identity_sign(&c->identity, c->keys.pub, c->my_id, p->pub, p->id, sig);
        hex_encode(sig, ID_SIGN_LEN, sighex);
    }
    // After the logging flag, features this build has that older ones don't: "r" announces rekeys,
    // "b" reads several records per frame.
    snprintf(out, out_cap, "k\t%s\t%s\t%drb\t%d\t%s\t%s", c->nick, colorhex, c->persist, idtype, idpubhex, sighex);
}

// "v": our version, our executable's hash, and our release's signed list of binaries (empty
// fields for a build without one), which p checks the hash against. 0.1.8 only sent the first
// two, and ignores the rest.
static void send_build(chat_t *c, peer_t *p) {
    if (!c->build.ok) return;
    uint8_t proof[BUILD_HASH_LEN];
    build_proof(c->build.hash, c->my_id, p->id, proof);
    char proofhex[BUILD_HASH_LEN * 2 + 1]; hex_encode(proof, BUILD_HASH_LEN, proofhex);
    char msg[8 + MAX_VERSION + BUILD_HASH_LEN * 2 + BUILD_LIST_LEN + MINISIGN_SIG_B64_LEN];
    snprintf(msg, sizeof msg, "v\t%s\t%s\t%s\t%s", c->build.version, proofhex, c->build.list, c->build.list_sig);
    send_peer(c, p, msg);
}

static void send_k_now(chat_t *c, peer_t *p) {
    char k[8 + MAX_NICK + 8 + 5 + 4 + 65 + 129];
    build_k_message(c, p, k, sizeof k);
    send_peer(c, p, k);
    send_build(c, p);
}

static void finish_kem_decap(chat_t *c, peer_t *p, const uint8_t ct[KEM_CT_LEN]);

static peer_t *do_hello(chat_t *c, const uint8_t peer_id[ID_LEN], addr_t addr,
                         const uint8_t their_pub[PUB_LEN], const uint8_t their_kem_pub[KEM_PUB_LEN],
                         double now, int *fresh) {
    *fresh = 0;
    peer_t *p = find_peer_by_id(c, peer_id);

    if (p && memcmp(p->pub, their_pub, PUB_LEN) == 0 && p->keygen == c->keygen) {
        if (!p->ok) p->addr = addr;
        return p;
    }
    // A room member in the middle could swap in its own key at a rekey. A peer that announces rekeys
    // sent us its new key over the current session, which the middle can't change, so a new key it
    // never announced is refused. After a short grace period (the rk may still be on its way) this
    // gives a warning.
    if (p && p->ok && p->announces_rekey && memcmp(p->pub, their_pub, PUB_LEN) != 0
        && !(p->next_pub_set && memcmp(p->next_pub, their_pub, PUB_LEN) == 0)) {
        if (p->rk_refused_since == 0.0) p->rk_refused_since = now;
        if (now - p->rk_refused_since > 10.0 && now >= p->next_rk_warn) {
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            p->next_rk_warn = now + 30.0;
            ui_print(c, "* warning: a new key for %s arrived that %s never announced - refused. Someone may be "
                        "intercepting; if it continues, compare :peers verify codes over another channel", name, name);
        }
        return NULL;
    }
    if (pending_peer_count(c) >= MAX_PENDING_PEERS || live_count(c) >= MAX_PEERS) return NULL;

    peer_t *slot = NULL;
    peer_t *existing = find_peer_by_id(c, peer_id);
    if (existing) slot = existing;
    else {
        for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) if (!c->peers[i].used) { slot = &c->peers[i]; break; }
        if (!slot) return NULL;
    }

    uint8_t shared[32];
    if (ecdh_shared(&c->keys, their_pub, shared) != 0) { crypto_wipe(shared, sizeof shared); return NULL; }
    uint8_t prk_partial[32];
    session_prk(c->master, shared, c->keys.pub, c->my_id, their_pub, peer_id, prk_partial);
    crypto_wipe(shared, sizeof shared);

    // carry holds the old chains for the overlap and any kx that arrived early. It's wiped before
    // returning.
    peer_t carry;
    int rejoin = 0;
    if (existing && existing->ok) { carry = *existing; rejoin = 1; }
    {
        int si = (int)(slot - c->peers) + 1;
        if (si > c->peer_hi) c->peer_hi = si;
    }
    // The same peer reuses its own slot, which is wiped here instead of dropped. Its messages still
    // waiting for an ack are kept and sent again on the new chains, so a rekey can't lose one.
    crypto_wipe(slot, sizeof *slot);
    slot->used = 1;
    memcpy(slot->id, peer_id, ID_LEN);
    set_peer_nick(slot, "anon");
    slot->addr = addr;
    slot->seen = slot->born = now;
    slot->next_hello = now + retry_delay(0);
    slot->hello_tries = 0;
    slot->ok = 0;
    slot->keygen = c->keygen;
    memcpy(slot->pub, their_pub, PUB_LEN);
    memcpy(slot->kem_pub, their_kem_pub, KEM_PUB_LEN);
    if (rejoin) {
        memcpy(slot->nick, carry.nick, sizeof slot->nick);
        memcpy(slot->nick_skel, carry.nick_skel, sizeof slot->nick_skel);
        memcpy(slot->color, carry.color, 3);
        slot->persists = carry.persists;
        slot->ok_since = carry.ok_since;
        slot->k_seen = carry.k_seen;
        slot->announced = carry.announced;
        slot->identity_source = carry.identity_source;
        slot->identity_state = carry.identity_state;
        memcpy(slot->identity_pub, carry.identity_pub, ID_SIGN_PUB_LEN);
        memcpy(slot->identity_fp, carry.identity_fp, ID_FP_LEN);
        memcpy(slot->vfy, carry.vfy, VERIFY_LEN);
        slot->vfy_set = carry.vfy_set;
        // The same "v" arrives again after the rekey, and mustn't be warned about twice.
        memcpy(slot->build_version, carry.build_version, sizeof slot->build_version);
        slot->build_state = carry.build_state;
        slot->build_warn = carry.build_warn;
        slot->ok = 1;
        slot->old_send = carry.send_chain;
        slot->old_recv = carry.recv_chain;
        slot->old_until = now + REKEY_OVERLAP;
        slot->next_cover = carry.next_cover;
        slot->announces_rekey = carry.announces_rekey;
        slot->batches = carry.batches;
        // A file it's fetching from us continues from where it was, so a rekey doesn't stall it.
        slot->serving = carry.serving;
        memcpy(slot->serve_fid, carry.serve_fid, FILE_ID_LEN);
        slot->serve_next = carry.serve_next;
        slot->serve_end = carry.serve_end;
        // The same peer, as the rk it announced proves, so a compared code stays compared.
        slot->code_ok = carry.code_ok;
        slot->trust = carry.trust;
        slot->next_rehello = carry.next_rehello;
    }

    peer_t *result = slot;
    if (memcmp(c->my_id, peer_id, ID_LEN) < 0) {
        uint8_t kem_ss[KEM_SS_LEN], prk[32];
        if (kem_encapsulate(their_kem_pub, slot->kem_ct, kem_ss) == 0) {
            session_prk_finish(prk_partial, kem_ss, prk);
            ratchet_seed(prk, c->keys.pub, &slot->send_chain);
            ratchet_seed(prk, their_pub, &slot->recv_chain);
            if (!slot->vfy_set) { session_verify_code(prk, slot->vfy); slot->vfy_set = 1; }
        } else {
            forget_peer(c, slot);
            result = NULL;
        }
        crypto_wipe(kem_ss, sizeof kem_ss);
        crypto_wipe(prk, sizeof prk);
    } else {
        memcpy(slot->prk_partial, prk_partial, 32);
        if (rejoin && carry.kx_early) finish_kem_decap(c, slot, carry.kem_ct);
    }
    crypto_wipe(prk_partial, sizeof prk_partial);
    if (rejoin) crypto_wipe(&carry, sizeof carry);
    *fresh = result != NULL;
    return result;
}

static int we_initiate(const chat_t *c, const peer_t *p) { return memcmp(c->my_id, p->id, ID_LEN) < 0; }

static int path_rank(addr_t a) { return a.kind == ADDR_UDP ? 2 : a.kind == ADDR_TOR ? 1 : 0; }

// A connected peer's hi came over a better path than the one we use (UDP punched through after
// the relays, or a Tor stream after the relays). A hi proves nothing, since any member can send
// one, so the path doesn't change because of it. Instead a session frame is sent back that way.
// Once the peer opens it, the path is proven on its side and it switches, and its frames then
// switch us too.
static void probe_path(chat_t *c, peer_t *p, addr_t addr) {
    if (!p->ok || path_rank(addr) <= path_rank(p->addr)) return;
    uint8_t frame[UDP_CELL];
    size_t len;
    uint32_t idx;
    if (frame_on_chain(send_chain_for(p), "nop", SESSION_PAD_TARGET, frame, sizeof frame, &len, &idx) != 0) return;
    xmit(c, c->sock, frame, len, addr);
    crypto_wipe(frame, sizeof frame);
}

static void finish_kem_decap(chat_t *c, peer_t *p, const uint8_t ct[KEM_CT_LEN]) {
    // The initiator's chains come from its own encapsulation. Only the responder takes a kx.
    if (we_initiate(c, p)) return;
    if (p->chain_confirmed) {
        // The initiator may send its kx while our side of the re-handshake is still waiting for a cookie.
        if (memcmp(p->kem_ct, ct, KEM_CT_LEN) != 0) { memcpy(p->kem_ct, ct, KEM_CT_LEN); p->kx_early = 1; }
        return;
    }
    // A recorded kx can be replayed, so a different one may replace it until the peer's frames
    // prove which chains are right.
    if (p->send_chain.started && memcmp(p->kem_ct, ct, KEM_CT_LEN) == 0) return;
    uint8_t kem_ss[KEM_SS_LEN];
    if (kem_decapsulate(&c->kem_keys, ct, kem_ss) != 0) return;
    memcpy(p->kem_ct, ct, KEM_CT_LEN);
    uint8_t prk[32];
    session_prk_finish(p->prk_partial, kem_ss, prk);
    ratchet_seed(prk, c->keys.pub, &p->send_chain);
    ratchet_seed(prk, p->pub, &p->recv_chain);
    // vfy_set is left to the first frame that opens on these chains.
    if (!p->vfy_set) session_verify_code(prk, p->vfy);
    crypto_wipe(prk, sizeof prk);
    crypto_wipe(kem_ss, sizeof kem_ss);
    send_k_now(c, p);
}

static void connect_peer(chat_t *c, const uint8_t peer_id[ID_LEN], addr_t addr,
                          const uint8_t their_pub[PUB_LEN], const uint8_t their_kem_pub[KEM_PUB_LEN], double now) {
    if (c->once && c->once_used && !find_peer_by_id(c, peer_id)) return;
    int fresh;
    peer_t *p = do_hello(c, peer_id, addr, their_pub, their_kem_pub, now, &fresh);
    if (!p) return;
    if (fresh) {
        send_room(c, c->hi_msg, addr, c->sock);
    }
    if (p->send_chain.started) {
        // Keep sending the kx until the peer's frames show it was received. The first copy may be lost,
        // or reach the peer before its side of the re-handshake is ready.
        if (we_initiate(c, p) && (fresh || !p->chain_confirmed)) send_kx(c, p, p->addr);
        send_k_now(c, p);
    }

}

#define PX_MAX_BODY (SESSION_PAD_TARGET - 2)

// How to reach p, for "px": its UDP address, or in Tor mode its onion address. Peers only reached
// through the relays don't have one, since the relays already connect them.
static int px_entry(const chat_t *c, const peer_t *p, char out[ADDR_STR_LEN]) {
    if (c->route.mode == ROUTE_TOR) {
        if (!p->onion[0]) return -1;
        snprintf(out, ADDR_STR_LEN, "%s.onion", p->onion);
        return 0;
    }
    if (p->addr.kind != ADDR_UDP) return -1;
    addr_to_string(p->addr, out);
    return 0;
}

static void introduce(chat_t *c, peer_t *newp) {
    // Several px messages if one can't hold them all (onion addresses are long).
    char list[PX_MAX_BODY];
    size_t pos = 0;
    int n = 0, total = 0;
    for (int i = 0; i < c->peer_hi && total < 24; i++) {
        peer_t *q = &c->peers[i];
        char as[ADDR_STR_LEN];
        if (!q->used || !q->ok || q == newp || px_entry(c, q, as) != 0) continue;
        size_t need = strlen(as) + (n ? 1 : 0);
        if (pos + need + 4 > PX_MAX_BODY) {
            char msg[PX_MAX_BODY + 8];
            snprintf(msg, sizeof msg, "px\t%s", list);
            send_peer(c, newp, msg);
            pos = 0; n = 0; need = strlen(as);
        }
        pos += (size_t)snprintf(list + pos, sizeof(list) - pos, "%s%s", n ? "," : "", as);
        n++;
        total++;
    }
    if (n > 0) {
        char msg[PX_MAX_BODY + 8];
        snprintf(msg, sizeof msg, "px\t%s", list);
        send_peer(c, newp, msg);
    }
    char newp_addr[ADDR_STR_LEN];
    if (px_entry(c, newp, newp_addr) != 0) return;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *q = &c->peers[i];
        if (!q->used || !q->ok || q == newp) continue;
        char msg[16 + ADDR_STR_LEN];
        snprintf(msg, sizeof msg, "px\t%s", newp_addr);
        send_peer(c, q, msg);
    }
}

// In Tor mode, tells p our onion address, which it passes on in px.
static void send_onion(chat_t *c, peer_t *p) {
    if (!c->tor || !tor_my_onion(c->tor)[0]) return;
    char msg[8 + TOR_ADDR_LEN];
    snprintf(msg, sizeof msg, "ta\t%s", tor_my_onion(c->tor));
    send_peer(c, p, msg);
}

static void drop_peer(chat_t *c, peer_t *p, const char *why) {
    int was_ok = p->ok;
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    if (was_ok && p->vfy_set) {
        int g = c->gone_head;
        c->gone[g].used = 1;
        memcpy(c->gone[g].id, p->id, ID_LEN);
        memcpy(c->gone[g].vfy, p->vfy, VERIFY_LEN);
        c->gone_head = (g + 1) % (int)(sizeof c->gone / sizeof c->gone[0]);
    }
    forget_peer(c, p);
    if (was_ok) ui_print(c, "* %s %s (%d online)", name, why, live_count(c) + 1);
    // The peer who left may have been the latest publisher of the room onion, so point it back at us.
    if (was_ok && c->tor && c->tor_hosting && c->tor_republish_at == 0.0) c->tor_republish_at = now_seconds() + 5.0 + jitter(25.0);
}

// A version as a peer may give it: short, and nothing a terminal or a URL would treat specially.
static int version_ok(const char *v) {
    size_t n = strlen(v);
    if (n == 0 || n > MAX_VERSION) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)v[i]) && v[i] != '.' && v[i] != '-') return 0;
    return 1;
}

// 0.1.8 sent "v" before binaries carried their list: the SHA-256 of each of its binaries as
// published, from its signed SHA256SUMS.
static const struct { const char *version; const char *sha256[2]; } LISTLESS_RELEASES[] = {
    { "0.1.8", { "9d50e1c7de24f14424c6f512eaa7b928d1a1a898d9b9e9daee2afefc4c148085",
                 "69af5f3c89ff5fa59c82b4d535c47efb26ea28979ed8b61bdfb384054c723539" } },
};

// The hashes in a list a peer sent, if the release key signed it for that version. Returns how
// many, or -1.
static int signed_list(const chat_t *c, const char *version, const char *list, const char *sig,
                       uint8_t hashes[BUILD_LIST_MAX][BUILD_HASH_LEN]) {
    // What `just release` signs: "chat vVERSION", then each hash, a line each.
    char content[16 + MAX_VERSION + BUILD_LIST_LEN];
    size_t pos = (size_t)snprintf(content, sizeof content, "chat v%s\n", version);
    int n = 0;
    for (const char *item = list; *item; ) {
        const char *end = strchr(item, ',');
        size_t len = end ? (size_t)(end - item) : strlen(item);
        char hex[BUILD_HASH_LEN * 2 + 1];
        if (n == BUILD_LIST_MAX || len != sizeof hex - 1) return -1;
        memcpy(hex, item, len); hex[len] = '\0';
        // Lowercase only, as sha256sum writes it, so the signed text has one spelling.
        if (strspn(hex, "0123456789abcdef") != len || hex_decode(hex, len, hashes[n]) != 0) return -1;
        memcpy(content + pos, hex, len);
        pos += len;
        content[pos++] = '\n';
        n++;
        if (!end) break;
        item = end + 1;
    }
    if (n == 0 || minisign_verify(c->release_key, content, pos, sig, strlen(sig), NULL) != 0) return -1;
    return n;
}

// The warning includes p's name, so it waits until p's join is announced.
static void tell_build(chat_t *c, peer_t *p) {
    if (!p->build_warn || !p->announced) return;
    p->build_warn = 0;
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    ui_print(c, "* warning: %s runs a modified client - it says v%s, but isn't one of that release's binaries",
             name, p->build_version);
}

// Checks the build p's "v" names: its hash against the signed list it came with (list NULL:
// 0.1.8's format, which has none), and warns about one that isn't a release binary.
static void check_build(chat_t *c, peer_t *p, const char *version, const uint8_t proof[BUILD_HASH_LEN],
                        const char *list, const char *sig) {
    // "v" comes with every k, so a verdict already given isn't repeated.
    int again = p->build_state == BUILD_MODIFIED && strcmp(p->build_version, version) == 0;
    copy_str(p->build_version, version, sizeof p->build_version);
    if (!c->has_release_key) { p->build_state = BUILD_UNCHECKED; return; }
    uint8_t hashes[BUILD_LIST_MAX][BUILD_HASH_LEN];
    int n = -1;
    if (list) {
        n = signed_list(c, version, list, sig, hashes);
    } else {
        for (size_t i = 0; i < sizeof LISTLESS_RELEASES / sizeof LISTLESS_RELEASES[0]; i++) {
            if (strcmp(LISTLESS_RELEASES[i].version, version) != 0) continue;
            for (n = 0; n < 2; n++) hex_decode(LISTLESS_RELEASES[i].sha256[n], BUILD_HASH_LEN * 2, hashes[n]);
        }
    }
    int official = 0;
    for (int i = 0; i < n && !official; i++) {
        uint8_t want[BUILD_HASH_LEN];
        build_proof(hashes[i], p->id, c->my_id, want);
        official = crypto_equal(want, proof, BUILD_HASH_LEN) == 0;
    }
    p->build_state = official ? BUILD_OFFICIAL : BUILD_MODIFIED;
    if (official) p->build_warn = 0;
    else if (!again) p->build_warn = 1;
    tell_build(c, p);
}

static void on_session(chat_t *c, peer_t *p, char *plain, double now) {
    char *f[MAX_FIELDS];
    int n = split_tabs(plain, f, MAX_FIELDS);
    if (n == 7 && strcmp(f[0], "k") == 0) {
        p->k_seen = 1;
        set_peer_nick(p, f[1]);
        identity_source_t had_source = p->identity_source;
        verify_state_t had_state = p->identity_state;
        uint8_t had_pub[ID_SIGN_PUB_LEN];
        memcpy(had_pub, p->identity_pub, ID_SIGN_PUB_LEN);
        uint8_t rgb[3];
        if (parse_color(f[2], rgb) == 0) memcpy(p->color, rgb, 3);
        // f[3] is the logging flag, then capability letters older builds ignore: "r" = sends rk,
        // "b" = reads records joined by newlines.
        p->persists = (f[3][0] == '1');
        p->announces_rekey = strchr(f[3], 'r') != NULL;
        p->batches = strchr(f[3], 'b') != NULL;
        int idtype = atoi(f[4]);
        size_t idpub_len = strlen(f[5]), sig_len = strlen(f[6]);
        if (idtype > IDENT_NONE && idtype <= IDENT_PGP && idpub_len == 64 && sig_len == 128) {
            uint8_t idpub[ID_SIGN_PUB_LEN], sig[ID_SIGN_LEN];
            if (hex_decode(f[5], 64, idpub) == 0 && hex_decode(f[6], 128, sig) == 0) {
                p->identity_source = (identity_source_t)idtype;
                memcpy(p->identity_pub, idpub, ID_SIGN_PUB_LEN);
                identity_fingerprint(idpub, p->identity_fp);

                p->identity_state = identity_verify(idpub, sig, p->pub, p->id, c->keys.pub, c->my_id) == 0
                                     ? VERIFY_VERIFIED : VERIFY_FAILED;
            } else {
                p->identity_source = IDENT_NONE; p->identity_state = VERIFY_UNVERIFIED;
            }
        } else {
            p->identity_source = IDENT_NONE; p->identity_state = VERIFY_UNVERIFIED;
        }
        // A peer that joined before its k came is checked now, and one whose nick or key changed again.
        int warned = 0, was_ok = p->code_ok;
        if (p->announced) {
            warned = check_trust(c, p);
            if (was_ok != 1 && p->code_ok == 1) file_offer_all(c, p);
        }
        // A re-handshake (rekey, rejoin) sends k again. Say so if the identity behind it changes.
        if (had_source != IDENT_NONE && !warned) {
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            if (p->identity_source == IDENT_NONE) {
                ui_print(c, "* warning: %s no longer presents a signing identity", name);
            } else if (memcmp(had_pub, p->identity_pub, ID_SIGN_PUB_LEN) != 0) {
                char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(p->identity_fp, ID_FP_LEN, fphex);
                ui_print(c, "* warning: %s now presents a different signing identity (fingerprint %s) - :verify it again",
                         name, fphex);
            } else if (p->identity_state == VERIFY_FAILED && had_state != VERIFY_FAILED) {
                ui_print(c, "* warning: %s's identity signature is now invalid", name);
            }
        }
    } else if (n == 2 && strcmp(f[0], "rk") == 0) {
        // The key this peer will re-handshake with next, sent over the session we already trust.
        uint8_t next[PUB_LEN];
        if (hex_decode(f[1], PUB_LEN * 2, next) == 0) {
            memcpy(p->next_pub, next, PUB_LEN);
            p->next_pub_set = 1;
            p->rk_refused_since = 0.0;
        }
    } else if (n == 2 && strcmp(f[0], "c") == 0) {
        uint8_t rgb[3];
        if (parse_color(f[1], rgb) == 0) memcpy(p->color, rgb, 3);
    } else if (n == 2 && strcmp(f[0], "n") == 0) {
        set_peer_nick(p, f[1]);
        if (p->announced) {
            int was_ok = p->code_ok;
            if (p->trust == 2) p->trust = 0;
            check_trust(c, p);
            if (was_ok != 1 && p->code_ok == 1) file_offer_all(c, p);
        }
    } else if (n == 2 && strcmp(f[0], "px") == 0) {
        char *item = f[1];
        for (int cnt = 0; item && *item && cnt < 12; cnt++) {
            char *comma = strchr(item, ',');
            if (comma) *comma = '\0';
            addr_t a;
            size_t il = strlen(item);
            if (il == TOR_ADDR_LEN + 6 && strcmp(item + TOR_ADDR_LEN, ".onion") == 0) {
                // Only Tor mode uses onion addresses. Nothing else may ever look them up.
                item[TOR_ADDR_LEN] = '\0';
                if (c->tor && tor_target(c->tor, item, &a) == 0) add_candidate(c, a);
            } else if (c->route.mode == ROUTE_DHT && addr_parse_ip_port(item, &a) == 0) {
                // Numeric only. A hostname here would make us resolve any name a peer sends.
                add_candidate(c, a);
            }
            item = comma ? comma + 1 : NULL;
        }
    } else if (n == 2 && strcmp(f[0], "ta") == 0) {
        if (onion_valid(f[1])) copy_str(p->onion, f[1], sizeof p->onion);
    } else if ((n == 3 || n == 5) && strcmp(f[0], "v") == 0) {
        uint8_t proof[BUILD_HASH_LEN];
        if (!version_ok(f[1]) || strlen(f[2]) != BUILD_HASH_LEN * 2
            || hex_decode(f[2], BUILD_HASH_LEN * 2, proof) != 0) return;
        check_build(c, p, f[1], proof, n == 5 ? f[3] : NULL, n == 5 ? f[4] : NULL);
    } else if (n == 5 && strcmp(f[0], "m") == 0) {
        // Only p itself is authenticated here. f[2] and f[3] (origin id, nick) are whatever p says.
        uint8_t mid_raw[4], origin[ID_LEN];
        if (hex_decode(f[1], 8, mid_raw) != 0 || hex_decode(f[2], ID_LEN * 2, origin) != 0) return;
        char ack[16]; snprintf(ack, sizeof ack, "a\t%s", f[1]);
        send_peer(c, p, ack);
        int direct = memcmp(origin, p->id, ID_LEN) == 0;
        if (!direct) {
            if (memcmp(origin, c->my_id, ID_LEN) == 0) return;
            // The origin is connected to us, so its own copy will arrive. A relayed one could be forged.
            peer_t *op = find_peer_by_id(c, origin);
            if (op && op->ok) return;
        }
        if (seen_has(c, f[1])) return;
        seen_add(c, f[1]);
        char nick[MAX_NICK + 1], text[MAX_TEXT + 1], via[CHAT_NAME_LEN];
        if (direct) copy_str(nick, p->nick, sizeof nick);
        else chat_clean_nick(f[3], nick);
        clean_text(f[4], text, MAX_TEXT);
        int mentioned = has_mention(text, c->nick);
        char shown[MAX_NICK + CHAT_NAME_LEN + 48];
        chat_peer_name(c, p, via);
        // A relayed nick is only the relayer's claim, so it always includes the origin's id. Nicks can't
        // contain brackets, so what's added in brackets can't be faked.
        const char *mark = p->code_ok < 0 ? " (codes differ)" : c->verify_required && p->code_ok != 1 ? " (code not compared)" : "";
        if (direct) snprintf(shown, sizeof shown, "%s%s", via, mark);
        else snprintf(shown, sizeof shown, "%s#%.8s (via %s%s)", nick, f[2], via, mark);
        ui_chat(c, direct ? p->color : NULL, mentioned, shown, text);
        // Only as much as the preview setting allows, since desktops keep what a notification shows.
        if (c->notify && (c->notify_mode == NOTIFY_ALL || (c->notify_mode == NOTIFY_MENTIONS && mentioned)))
            c->notify(c->ui, c->notify_preview >= PREVIEW_NICK ? shown : NULL,
                      c->notify_preview == PREVIEW_MESSAGE ? text : NULL, mentioned);
        char rejoin[MSG_LINE_LEN];
        snprintf(rejoin, sizeof rejoin, "m\t%s\t%s\t%s\t%s", f[1], f[2], nick, text);
        for (int i = 0; i < c->peer_hi; i++) {
            peer_t *q = &c->peers[i];
            if (!q->used || !q->ok || q == p || memcmp(q->id, origin, ID_LEN) == 0) continue;
            // Only passed on to peers our own messages would go to.
            if (q->code_ok < 0 || (c->verify_required && q->code_ok != 1)) continue;
            send_peer(c, q, rejoin);
        }
    } else if (n == 2 && strcmp(f[0], "a") == 0) {
        for (int i = 0; i < MAX_PENDING_MSGS; i++)
            if (c->pending[i].used && c->pending[i].peer_slot == peer_slot(c, p) && strcmp(c->pending[i].mid, f[1]) == 0)
                pending_clear(&c->pending[i]);
    } else if (f[0][0] == 'f' && f[0][1] && !f[0][2]) {
        file_on_record(c, p, f, n, now);
    } else if (n == 1 && strcmp(f[0], "nop") == 0) {

    } else if (n == 1 && strcmp(f[0], "bye") == 0) {
        drop_peer(c, p, "left");
    }
    (void)now;
}

// Our own hi came back from addr, so it's one of our addresses and never a candidate. Each is
// kept once, so replays of it can't fill the list.
static void note_self_addr(chat_t *c, addr_t addr) {
    // A relayed address represents a peer or a Tor stream, so it's never one of ours.
    if (addr.kind != ADDR_UDP) return;
    int cap = (int)(sizeof c->self_addrs / sizeof c->self_addrs[0]);
    for (int i = 0; i < c->n_self_addrs; i++) if (addr_equal(c->self_addrs[i], addr)) return;
    if (c->n_self_addrs < cap) c->self_addrs[c->n_self_addrs++] = addr;
}

static void on_room(chat_t *c, char *plain, addr_t addr, double now) {
    char *f[MAX_FIELDS];
    int n = split_tabs(plain, f, MAX_FIELDS);
    const char *my_idhex = c->my_idhex;

    if (n == 4 && strcmp(f[0], "hi") == 0 && strlen(f[1]) == 32 && strlen(f[2]) == 64
        && strlen(f[3]) == KEM_PUB_LEN * 2) {
        if (strcmp(f[1], my_idhex) == 0) {
            note_self_addr(c, addr);
            for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used && addr_equal(c->cands[i].addr, addr)) c->cands[i].used = 0;
            return;
        }
        uint8_t peer_id[ID_LEN], pub[PUB_LEN], kem_pub[KEM_PUB_LEN];
        if (hex_decode(f[1], 32, peer_id) != 0 || hex_decode(f[2], 64, pub) != 0
            || hex_decode(f[3], KEM_PUB_LEN * 2, kem_pub) != 0) return;
        c->st.hi++;
        char addr_str[ADDR_STR_LEN]; addr_to_string(addr, addr_str);
        peer_t *existing = find_peer_by_id(c, peer_id);
        if (c->net_verbose) {
            char shortid[9]; hex_encode(peer_id, 4, shortid);
            ui_print(c, "* hi from %s, peer %s%s", addr_str, shortid, existing ? " (known)" : " (new)");
        }
        // Anyone who recorded a hi can replay it from anywhere. Only accept one without a check if it
        // changes nothing. New keys, or a new address mid-handshake, must answer a cookie first.
        int trusted = existing && existing->keygen == c->keygen && memcmp(existing->pub, pub, PUB_LEN) == 0
                      && (existing->ok || addr_equal(existing->addr, addr));
        if (trusted) {
            connect_peer(c, peer_id, addr, pub, kem_pub, now);
            peer_t *p = find_peer_by_id(c, peer_id);
            if (p) probe_path(c, p, addr);
        } else if ((existing || !(c->once && c->once_used))
                   && take_token(&c->ck_tokens, &c->ck_at, now, CK_RATE, CK_BURST)) {
            uint8_t cookie[COOKIE_LEN];
            cookie_compute(c->cookie_secret, addr_str, peer_id, pub, cookie);
            char cookiehex[33]; hex_encode(cookie, COOKIE_LEN, cookiehex);
            char msg[8 + 32 + 32];
            snprintf(msg, sizeof msg, "ck\t%s\t%s", f[1], cookiehex);
            send_room(c, msg, addr, c->sock);
            if (c->net_verbose) ui_print(c, "* sent cookie challenge to %s", addr_str);
        }
    } else if (n == 3 && strcmp(f[0], "ck") == 0 && strcmp(f[1], my_idhex) == 0 && strlen(f[2]) == 32) {
        c->st.ck++;
        if (c->net_verbose) {
            char addr_str[ADDR_STR_LEN]; addr_to_string(addr, addr_str);
            ui_print(c, "* cookie challenge from %s - answering with hi2", addr_str);
        }
        char pubhex[65]; hex_encode(c->keys.pub, PUB_LEN, pubhex);
        char kemhex[KEM_PUB_LEN * 2 + 1]; hex_encode(c->kem_keys.pub, KEM_PUB_LEN, kemhex);
        char msg[HANDSHAKE_BUF_LEN];
        snprintf(msg, sizeof msg, "hi2\t%s\t%s\t%s\t%s", my_idhex, pubhex, kemhex, f[2]);
        send_room(c, msg, addr, c->sock);
    } else if (n == 5 && strcmp(f[0], "hi2") == 0 && strlen(f[1]) == 32 && strlen(f[2]) == 64
               && strlen(f[3]) == KEM_PUB_LEN * 2 && strlen(f[4]) == 32) {
        if (strcmp(f[1], my_idhex) == 0) {
            note_self_addr(c, addr);
            return;
        }
        uint8_t peer_id[ID_LEN], pub[PUB_LEN], kem_pub[KEM_PUB_LEN], given[COOKIE_LEN];
        if (hex_decode(f[1], 32, peer_id) != 0 || hex_decode(f[2], 64, pub) != 0
            || hex_decode(f[3], KEM_PUB_LEN * 2, kem_pub) != 0 || hex_decode(f[4], 32, given) != 0) return;
        char addr_str[ADDR_STR_LEN]; addr_to_string(addr, addr_str);
        uint8_t expect[COOKIE_LEN];

        cookie_compute(c->cookie_secret, addr_str, peer_id, pub, expect);
        c->st.hi2++;
        int cookie_ok = crypto_equal(given, expect, COOKIE_LEN) == 0;
        if (c->net_verbose) {
            char shortid[9]; hex_encode(peer_id, 4, shortid);
            ui_print(c, "* hi2 from %s, peer %s - cookie %s", addr_str, shortid, cookie_ok ? "ok" : "MISMATCH");
        }
        if (cookie_ok) connect_peer(c, peer_id, addr, pub, kem_pub, now);
        else c->st.hi2_bad++;
    } else if (n == 3 && strcmp(f[0], "kx") == 0 && strlen(f[1]) == 32 && strlen(f[2]) == KEM_CT_LEN * 2) {
        uint8_t peer_id[ID_LEN], ct[KEM_CT_LEN];
        if (hex_decode(f[1], 32, peer_id) != 0 || hex_decode(f[2], KEM_CT_LEN * 2, ct) != 0) return;
        c->st.kx++;
        peer_t *p = find_peer_by_id(c, peer_id);
        if (c->net_verbose) {
            char addr_str[ADDR_STR_LEN]; addr_to_string(addr, addr_str);
            char shortid[9]; hex_encode(peer_id, 4, shortid);
            ui_print(c, "* kx from %s, peer %s%s", addr_str, shortid, p ? "" : " (unknown peer, ignored)");
        }
        if (p) finish_kem_decap(c, p, ct);
    } else if (n == 2 && strcmp(f[0], "nb") == 0 && addr.kind == ADDR_NOSTR && strlen(f[1]) == 32
               && strcmp(f[1], my_idhex) != 0) {
        // A member announcing itself on the relays. Someone we already hear from directly needs nothing.
        // Anyone else gets a hi through the relays.
        uint8_t peer_id[ID_LEN];
        if (hex_decode(f[1], 32, peer_id) != 0) return;
        peer_t *known = find_peer_by_id(c, peer_id);
        if (known && known->ok && now - known->seen < UDP_STALE) return;
        add_candidate(c, addr_virtual(ADDR_NOSTR, peer_id));
    } else if (n == 3 && strcmp(f[0], "lan") == 0 && addr.kind == ADDR_UDP && strcmp(f[1], my_idhex) != 0) {
        // Only a real broadcast shows where someone is on the LAN. Over the relays or a Tor stream the
        // port would be applied to an address that represents a peer.
        c->st.lan++;
        int port = atoi(f[2]);
        if (port > 0 && port <= 65535) {
            addr_t a = addr; a.port = (uint16_t)port;
            add_candidate(c, a);
            if (c->net_verbose) { char as[ADDR_STR_LEN]; addr_to_string(a, as); ui_print(c, "* lan beacon - candidate %s added", as); }
        }
    }
}

// 1 if data was a frame: the room's, or a peer's session frame.
static int on_frame(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now);

static int on_chunk(chat_t *c, const uint8_t *d, size_t len, addr_t addr, double now) {
    if (len != UDP_CELL || d[0] != CHUNK_MAGIC0 || d[1] != CHUNK_MAGIC1) return 0;
    int idx = d[6], count = d[7];
    size_t total = ((size_t)d[8] << 8) | d[9];
    if (count < 2 || count > CHUNK_MAX || idx >= count) return 0;
    if (total <= (size_t)(count - 1) * CHUNK_PAYLOAD || total > (size_t)count * CHUNK_PAYLOAD) return 0;
    c->st.rx_chunks++;

    reasm_t *slot = NULL, *oldest = &c->reasm[0];
    for (int i = 0; i < REASM_SLOTS; i++) {
        reasm_t *r = &c->reasm[i];
        if (r->used && now - r->born > REASM_TTL) r->used = 0;
        if (r->used && addr_equal(r->from, addr) && memcmp(r->id, d + 2, 4) == 0 && r->count == count
            && r->total == total) { slot = r; break; }
        if (r->born < oldest->born) oldest = r;
    }
    if (!slot) {
        for (int i = 0; i < REASM_SLOTS; i++) if (!c->reasm[i].used) { slot = &c->reasm[i]; break; }
        if (!slot) slot = oldest;
        memset(slot, 0, sizeof *slot);
        slot->used = 1; slot->from = addr; memcpy(slot->id, d + 2, 4);
        slot->count = count; slot->born = now;
        slot->total = total;
    }
    memcpy(slot->buf + (size_t)idx * CHUNK_PAYLOAD, d + CHUNK_HDR, CHUNK_PAYLOAD);
    slot->got |= 1u << idx;
    if (slot->got != (1u << count) - 1) return 1;

    uint8_t whole[CHUNK_MAX * CHUNK_PAYLOAD];
    memcpy(whole, slot->buf, total);
    slot->used = 0;
    c->st.rx_chunk_done++;
    if (!on_frame(c, whole, total, addr, now)) c->st.other++;
    return 1;
}

static void note_source(chat_t *c, addr_t a) {
    net_stats_t *st = &c->st;
    for (int i = 0; i < st->n_src; i++) if (addr_equal(st->src[i], a)) { st->src_n[i]++; return; }
    int slot = st->n_src < 6 ? st->n_src++ : 5;
    st->src[slot] = a; st->src_n[slot] = 1;
}

// A datagram from a UDP socket, unmasked: a piece of a room frame, or a frame. Anything else is
// passed to the DHT unchanged, since DHT messages are never masked.
static void on_udp(chat_t *c, const uint8_t *raw, size_t len, addr_t addr, double now) {
    c->st.rx++;
    note_source(c, addr);
    uint8_t d[HANDSHAKE_BUF_LEN + 128];
    if (len <= sizeof d) {
        memcpy(d, raw, len);
        if (udp_mask(c->udp_key, d, len) == 0 && (on_chunk(c, d, len, addr, now) || on_frame(c, d, len, addr, now)))
            return;
    }
    c->st.other++;
    if (c->dht_on && addr.kind == ADDR_UDP) dht_on_packet(&c->dht, raw, len, addr, dht_candidate_cb, c);
}

// A datagram through the relays or Tor, which carry whole frames, unmasked.
static void on_relayed(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now) {
    c->st.rx++;
    note_source(c, addr);
    if (!on_frame(c, data, len, addr, now)) c->st.other++;
}

static int in_window(const ratchet_t *r, uint32_t index, uint32_t max_skip) {
    return r->started && index >= r->index && index - r->index <= max_skip;
}

static int peer_try_unseal(peer_t *p, const uint8_t *data, size_t len, uint32_t index, uint32_t max_skip,
                            uint8_t *plain, size_t plain_cap, size_t *plain_len, int *on_old) {
    uint8_t mk[32];
    ratchet_t advanced;
    *on_old = 0;
    int got = in_window(&p->recv_chain, index, max_skip)
               && ratchet_peek(&p->recv_chain, index, mk, &advanced) == 0
               && session_unseal(mk, index, data, len, plain, plain_cap, plain_len) == 0;
    if (!got && p->old_until > 0.0 && in_window(&p->old_recv, index, max_skip)
        && ratchet_peek(&p->old_recv, index, mk, &advanced) == 0
        && session_unseal(mk, index, data, len, plain, plain_cap, plain_len) == 0) {
        got = 1;
        *on_old = 1;
    }
    crypto_wipe(mk, sizeof mk);
    if (!got) return 0;
    if (*on_old) p->old_recv = advanced;
    else p->recv_chain = advanced;
    return 1;
}

// Compares p's nick and signing key with the verified keys (core/trust.h), once "k" has brought
// them. A key verified before, in this run or one before it, signed this handshake's keys, so
// nobody in the middle could have made it: the code doesn't need comparing again. A peer with the
// nick of a verified key that signs with another key, or none, is warned about once. Returns 1 if
// it warned.
static int check_trust(chat_t *c, peer_t *p) {
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    const trust_entry_t *t = p->identity_state == VERIFY_VERIFIED ? trust_by_key(p->identity_pub) : NULL;
    if (t) {
        char was[MAX_NICK + 1]; copy_str(was, t->nick, sizeof was);
        int renamed = strcmp(t->nick, p->nick) != 0;
        // The entry follows the nick, so the next peer with the old nick isn't taken for this one.
        if (renamed) trust_add(p->identity_source, p->identity_pub, p->nick);
        if (p->trust == 1) return 0;
        p->trust = 1;
        if (p->code_ok != 0) return 0;
        p->code_ok = 1;
        if (renamed) ui_print(c, "* %s signs with the key you verified for %s - no need to compare codes again", name, was);
        else ui_print(c, "* %s signs with the key you verified before - no need to compare codes again", name);
        return 0;
    }
    int i = trust_find_nick(p->nick_skel, 0);
    if (i < 0) { p->trust = 0; return 0; }
    if (p->trust == 2) return 0;
    p->trust = 2;
    t = trust_at(i);
    char was[HEX_GROUPS_LEN(ID_FP_LEN)], now_fp[HEX_GROUPS_LEN(ID_FP_LEN) + 16];
    uint8_t fp[ID_FP_LEN];
    identity_fingerprint(t->pub, fp);
    hex_groups(fp, ID_FP_LEN, was);
    if (p->identity_source == IDENT_NONE) copy_str(now_fp, "no signing key", sizeof now_fp);
    else if (p->identity_state == VERIFY_FAILED) copy_str(now_fp, "a key with an invalid signature", sizeof now_fp);
    else { hex_groups(p->identity_fp, ID_FP_LEN, now_fp); }
    ui_warn(c, "* warning: %s does not sign with the key you verified for %s (fingerprint %s); it signs with %s. "
               "Their key changed, or someone else uses this nick. Treat them as unverified until you compare "
               "verify codes again: :verify %s",
            name, t->nick, was, now_fp, name);
    return 1;
}

// "* NICK (verified) joined": shown once p's nick and identity are known, which "k" carries. It's
// the first frame p sends, but it can be lost or overtaken, and another frame opening first would
// otherwise announce "anon (unverified)".
static void announce_join(chat_t *c, peer_t *p) {
    p->announced = 1;
    const char *idlabel;
    switch (p->identity_state) {
        case VERIFY_VERIFIED: idlabel = " (verified)"; break;
        case VERIFY_FAILED:   idlabel = " (\xe2\x9a\xa0 signature invalid)"; break;
        case VERIFY_UNVERIFIED:
        default:               idlabel = " (unverified)"; break;
    }
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    ui_print_colored(c, p->color, "* %s%s%s joined (%d online)", name, idlabel,
                      p->persists ? " [logging chat locally]" : "", live_count(c) + 1);
    // A peer that dropped and came back did a fresh handshake, with nothing linking it to the one
    // that may have been verified. Someone who forced the drop could be in the middle of it.
    for (size_t g = 0; g < sizeof c->gone / sizeof c->gone[0]; g++) {
        if (!c->gone[g].used || memcmp(c->gone[g].id, p->id, ID_LEN) != 0) continue;
        c->gone[g].used = 0;
        if (memcmp(c->gone[g].vfy, p->vfy, VERIFY_LEN) == 0) continue;
        char was[HEX_GROUPS_LEN(VERIFY_LEN)], now_hex[HEX_GROUPS_LEN(VERIFY_LEN)];
        hex_groups(c->gone[g].vfy, VERIFY_LEN, was); hex_groups(p->vfy, VERIFY_LEN, now_hex);
        ui_print(c, "* %s reconnected with a new verify code (was %s, now %s) - if you had compared "
                    "codes with them, compare the new one", name, was, now_hex);
    }
    check_trust(c, p);
    if (p->code_ok == 0) {
        char code[HEX_GROUPS_LEN(VERIFY_LEN)]; hex_groups(p->vfy, VERIFY_LEN, code);
        // The room's password only proves someone is a member, and any member could sit between two
        // others. The code only matches on both ends if nobody is in the middle.
        if (c->verify_required)
            ui_print(c, "* compare this code with %s over another channel (in person, a call): %s - then :verify %s ok, "
                        "or :verify %s no if theirs differs. Until then nothing you send reaches them",
                     name, code, name, name);
        else
            ui_print(c, "* verify code with %s: %s - compare it over another channel, then :verify %s ok", name, code, name);
    }
    tell_build(c, p);
    file_offer_all(c, p);
}

int chat_code_state(const chat_t *c, const peer_t *p) {
    if (p->code_ok < 0) return 3;
    if (p->code_ok > 0) return 2;
    if (p->trust == 2) return 4;
    return c->verify_required ? 1 : 0;
}

static int on_frame(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now) {
    uint8_t plain[HANDSHAKE_BUF_LEN + 128];
    size_t plain_len;
    if (room_unseal(c->room_key, data, len, plain, sizeof plain - 1, &plain_len) == 0) {
        plain[plain_len] = '\0';
        c->st.room_ok++;
        on_room(c, (char *)plain, addr, now);
        return 1;
    }
    // Checked before the peer loop, so a frame no sealer could produce doesn't cost ratchet steps.
    if (sealed_len_ok(len, SESSION_HEADER_LEN, SESSION_MIN_BODY)) {
        uint32_t index = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
        int hit = -1, fast = -1, on_old = 0;
        for (int i = 0; i < c->peer_hi && fast < 0; i++)
            if (c->peers[i].used && addr_equal(c->peers[i].addr, addr)) fast = i;
        for (int i = 0; i < c->peer_hi && fast < 0; i++)
            if (c->peers[i].used && c->peers[i].prev_addr.port && addr_equal(c->peers[i].prev_addr, addr)) fast = i;
        if (fast >= 0 && peer_try_unseal(&c->peers[fast], data, len, index, RATCHET_MAX_SKIP, plain,
                                          sizeof plain - 1, &plain_len, &on_old))
            hit = fast;
        if (hit < 0 && take_token(&c->roam_tokens, &c->roam_at, now, ROAM_RATE, ROAM_BURST)) {
            for (int i = 0; i < c->peer_hi; i++) {
                if (i == fast || !c->peers[i].used) continue;
                if (peer_try_unseal(&c->peers[i], data, len, index, ROAM_MAX_SKIP, plain, sizeof plain - 1,
                                     &plain_len, &on_old)) { hit = i; break; }
            }
        }
        if (hit >= 0) {
            peer_t *p = &c->peers[hit];
            if (!on_old) {
                if (p->old_until > 0.0) rekey_drop_overlap(p);
                p->chain_confirmed = 1;
                p->vfy_set = 1;
            }
            c->st.session_ok++;
            plain[plain_len] = '\0';
            // The best path that works: direct UDP, then Tor (end to end, no relay in the middle), then the
            // relays. A worse path is only used once the better one goes quiet.
            if (!addr_equal(p->addr, addr)
                && (path_rank(addr) >= path_rank(p->addr) || now - p->path_seen[p->addr.kind] > UDP_STALE)) {
                p->prev_addr = p->addr;
                p->addr = addr;
            }
            p->path_seen[addr.kind] = now;
            p->seen = now;
            int was_pending = !p->ok;
            p->ok = 1;
            if (was_pending) p->ok_since = now;
            // Records, one per line. No record contains a newline.
            for (char *rec = (char *)plain; rec; ) {
                char *nl = strchr(rec, '\n');
                if (nl) *nl = '\0';
                on_session(c, p, rec, now);
                if (!p->used) return 1;
                rec = nl ? nl + 1 : NULL;
            }
            if (was_pending) {
                c->st.connects++;

                send_k_now(c, p);
                p->k_sent = 1;
                p->next_k = now + K_EVERY;
                if (!c->created && !c->ever_connected) ui_print(c, "* connected - chat is open");
                // "joined" follows once the nick and identity are in.
                char idhex[9]; hex_encode(p->id, 4, idhex);
                ui_print(c, "* joining: peer %s - connected, waiting for its nick and identity", idhex);
                c->ever_connected = 1;
                c->once_used = 1;
                send_onion(c, p);
                introduce(c, p);
            }
            if (!p->announced && p->k_seen) announce_join(c, p);
            return 1;
        }
    }
    return 0;
}

int chat_sockets(chat_t *c, sock_t out[CHAT_MAX_SOCKS]) {
    int k = 0;
    if (c->sock != SOCK_INVALID) out[k++] = c->sock;
    if (c->lan_sock != SOCK_INVALID) out[k++] = c->lan_sock;
    // The relays' and Tor's sockets only wake the loop. chat_tick does their I/O.
    if (c->nostr) k += nostr_sockets(c->nostr, out + k, CHAT_MAX_SOCKS - k);
    if (c->tor) k += tor_sockets(c->tor, out + k, CHAT_MAX_SOCKS - k);
    return k;
}

int chat_started(const chat_t *c) { return c->started; }

const char *chat_start_error(const chat_t *c) {
    if (c->started) return NULL;
    return c->start_error ? c->start_error : "it couldn't start";
}

int chat_online_count(const chat_t *c) { return live_count((chat_t *)c); }
int chat_pending_count(const chat_t *c) { return pending_peer_count((chat_t *)c); }
int chat_candidate_count(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used) n++;
    return n;
}

int chat_ready(const chat_t *c) { return c->created || c->ever_connected; }

static void transports_step(chat_t *c, double now) {
    if (c->nostr) nostr_step(c->nostr, now);
    if (c->tor) tor_step(c->tor, now);
}

void chat_on_socket_readable(chat_t *c, sock_t which, double now) {
    if (which == SOCK_INVALID) return;
    if (which != c->sock && which != c->lan_sock) { transports_step(c, now); return; }
    uint8_t buf[HANDSHAKE_BUF_LEN + 128];
    addr_t from;
    for (int i = 0; i < 64; i++) {
        int n = net_recv(which, buf, sizeof buf, &from);
        if (n < 0) break;
        on_udp(c, buf, (size_t)n, from, now);
    }
}

static int pending_any(const chat_t *c) {
    for (int i = 0; i < MAX_PENDING_MSGS; i++) if (c->pending[i].used) return 1;
    return 0;
}

// A re-handshake still in progress with p: ours (not yet on our keys with p, or not yet sure p has
// the new chains), or p's (a key it announced that we haven't re-handshaken with yet).
static int rehandshaking_with(const chat_t *c, const peer_t *p) {
    return p->keygen != c->keygen || !p->chain_confirmed
        || (p->next_pub_set && memcmp(p->next_pub, p->pub, PUB_LEN) != 0);
}

static int rehandshaking(const chat_t *c) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok && rehandshaking_with(c, &c->peers[i])) return 1;
    return 0;
}

// Our next key, announced over the session p reads now, or (old) the one it read before our
// rekey, until it has re-handshaken.
static void send_rk(chat_t *c, peer_t *p, int old) {
    char pubhex[PUB_LEN * 2 + 1]; hex_encode(c->keys.pub, PUB_LEN, pubhex);
    char rk[8 + PUB_LEN * 2];
    snprintf(rk, sizeof rk, "rk\t%s", pubhex);
    queue_record(c, p, rk, old);
}

static void session_rekey(chat_t *c, double now) {
    crypto_wipe(&c->keys, sizeof c->keys);
    crypto_wipe(&c->kem_keys, sizeof c->kem_keys);
    gen_keypair(&c->keys);
    kem_gen_keypair(&c->kem_keys);
    gen_random(c->cookie_secret, 32);
    c->keygen++;

    refresh_hi(c);
    int told = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used) continue;
        // Announce the new key over the current session before the hi that uses it. They're sent in the
        // order they're queued.
        if (p->ok) { send_rk(c, p, 0); p->next_rk = now + RK_RESEND; }
        send_room(c, c->hi_msg, p->addr, c->sock);
        p->hello_tries = 0;
        p->next_hello = now + retry_delay(0);
        p->next_rehello = now + REHELLO_EVERY + jitter(REHELLO_EVERY * 0.25);
        told++;
    }
    if (c->net_verbose)
        ui_print(c, "* rekey: fresh session keys (generation %u), re-handshaking %d peer%s",
                  (unsigned)c->keygen, told, told == 1 ? "" : "s");
}

static void send_beacon(chat_t *c) {
    char beacon[48];
    snprintf(beacon, sizeof beacon, "nb\t%s", c->my_idhex);
    send_room(c, beacon, nostr_everyone(), c->sock);
}

static void tor_tick(chat_t *c, double now) {
    const char *me = tor_my_onion(c->tor);
    // Tor published our onion (again, after tor restarted), so peers get it for px.
    if (me[0] && strcmp(me, c->told_onion) != 0) {
        copy_str(c->told_onion, me, sizeof c->told_onion);
        for (int i = 0; i < c->peer_hi; i++)
            if (c->peers[i].used && c->peers[i].ok) send_onion(c, &c->peers[i]);
    }
    if (!c->tor_hosting && (c->ever_connected || now - c->start > TOR_HOST_AFTER)) {
        c->tor_hosting = 1;
        tor_host_room(c->tor, -1);
        // Trying our own slot from now on would only reach ourselves.
        addr_t mine = tor_room_target(c->tor, tor_hosted_slot(c->tor));
        for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used && addr_equal(c->cands[i].addr, mine)) c->cands[i].used = 0;
    }
    if (c->tor_republish_at > 0.0 && now >= c->tor_republish_at) {
        c->tor_republish_at = 0.0;
        tor_republish_room(c->tor);
    }
}

// Whether the relays are needed: always in Tor mode (that's where DHT members are met) or when set
// to always. Otherwise while nobody is reached yet, while a peer is reached (or being reached)
// only through them, or while a peer's UDP has gone quiet and they may be needed next.
static int relays_needed(chat_t *c, double now) {
    if (c->route.mode == ROUTE_TOR || c->route.nostr == NOSTR_ALWAYS) return 1;
    if (live_count(c) == 0) return 1;
    for (int i = 0; i < c->peer_hi; i++) {
        const peer_t *p = &c->peers[i];
        if (!p->used) continue;
        if (p->addr.kind == ADDR_NOSTR || (p->ok && now - p->seen > UDP_STALE / 2)) return 1;
    }
    for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used && c->cands[i].addr.kind == ADDR_NOSTR) return 1;
    return 0;
}

void chat_tick(chat_t *c, double now) {
    if (c->nostr) {
        if (relays_needed(c, now)) c->relays_until = now + RELAY_LINGER;
        nostr_set_active(c->nostr, now < c->relays_until);
    }
    transports_step(c, now);
    if (c->tor) tor_tick(c, now);
    if (c->pm) {
        portmap_step(c->pm, now);
        // With a mapping active, the DHT is given the router's forwarded port, not the source port it sees.
        uint16_t ext = 0;
        int mapped = portmap_mapped(c->pm, &ext);
        if (c->dht_on && mapped && (!c->dht.explicit_port || c->dht.my_port != ext)) {
            c->dht.explicit_port = 1;
            c->dht.my_port = ext;
            c->dht.next_lookup = 0;
        } else if (c->dht_on && !mapped && c->dht.explicit_port) {
            c->dht.explicit_port = 0;
            c->dht.my_port = c->port;
        }
    }
    if (c->nostr && nostr_relays_up(c->nostr) > 0 && now >= c->next_beacon) {
        double every = live_count(c) > 0 ? NOSTR_BEACON_CONNECTED : NOSTR_BEACON_ALONE;
        c->next_beacon = now + every + jitter(every * 0.3);
        send_beacon(c);
    }
    if (c->dht_on) {
        c->dht.peers_now = live_count(c) > 0;
        if (dht_step(&c->dht, now) && !c->dht_summary_printed) {
            c->dht_summary_printed = 1;
            ui_print(c, "* internet lookup done: %d nodes reached, %d peers found",
                      dht_queried_count(&c->dht), dht_found_count(&c->dht));
        }
    }
    c->probe_tokens += (now - c->probe_at) * PROBE_RATE;
    if (c->probe_tokens > PROBE_BURST) c->probe_tokens = PROBE_BURST;
    c->probe_at = now;
    for (int i = 0; i < MAX_CANDS; i++) {
        cand_t *cd = &c->cands[i];
        if (!cd->used) continue;
        // Already reached at this address, or (relays) under this id, so there's nothing left to try.
        if (candidate_reached(c, cd->addr)) { cd->used = 0; continue; }
        if (now >= cd->next_try) {
            if (c->probe_tokens < 1.0) break;
            c->probe_tokens -= 1.0;
            send_room(c, c->hi_msg, cd->addr, c->sock);
            cd->next_try = now + retry_delay(cd->tries);
            cd->tries++;
            if (c->net_verbose) {
                char as[ADDR_STR_LEN]; addr_to_string(cd->addr, as);
                ui_print(c, "* hi -> candidate %s (try %d/%d)", as, cd->tries, CAND_MAX_TRIES);
            }
            if (cd->tries >= CAND_MAX_TRIES) cd->used = 0;
        }
    }
    files_tick(c, now);
    for (int i = 0; i < MAX_PENDING_MSGS; i++) {
        pending_msg_t *pm = &c->pending[i];
        if (!pm->used) continue;
        if (now >= pm->next_retry) {
            peer_t *p = &c->peers[pm->peer_slot];
            if (!p->used || !p->ok || pm->tries >= 5) pending_clear(pm);
            else { send_peer(c, p, pm->text); pm->tries++; pm->next_retry = now + resend_delay(c, p); }
        }
    }
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || p->ok) continue;
        if (now - p->born > PENDING_TTL) forget_peer(c, p);
        else if (now >= p->next_hello) {
            p->next_hello = now + retry_delay(p->hello_tries);
            p->hello_tries++;
            send_room(c, c->hi_msg, p->addr, c->sock);
            char shortid[9]; hex_encode(p->id, 4, shortid);
            if (c->net_verbose) {
                char as[ADDR_STR_LEN]; addr_to_string(p->addr, as);
                ui_print(c, "* hi retry -> pending peer %s at %s", shortid, as);
            }

            if (p->send_chain.started && we_initiate(c, p)) {
                send_kx(c, p, p->addr);
                if (c->net_verbose) ui_print(c, "* kx retry -> pending peer %s", shortid);
            }
        }
    }
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        // Its path (UDP, or a Tor stream) has gone quiet, so try the relays. Frames that come back through
        // them move the peer there.
        if (c->nostr && p->addr.kind != ADDR_NOSTR && now - p->seen > UDP_STALE) {
            p->prev_addr = p->addr;
            p->addr = addr_virtual(ADDR_NOSTR, p->id);
            if (c->net_verbose) ui_print(c, "* %s went quiet - trying the relays", p->nick);
        }
        // Slots keep a live peer's path active, so a hi only goes to a peer that went quiet, in case it
        // lost the session, or to one that hasn't re-handshaken with our new keys. Through the relays a hi
        // costs every member an event, so there only the re-handshake gets one.
        if (p->k_sent > 0 && p->k_sent < K_SENDS && now >= p->next_k) {
            send_k_now(c, p);
            p->k_sent++;
            p->next_k = now + K_EVERY;
        }
        int quiet = now - p->seen > KEEPALIVE && p->addr.kind != ADDR_NOSTR;
        int stuck = c->keygen > 1 && (p->keygen != c->keygen || !p->chain_confirmed);
        if ((quiet || stuck) && now >= p->next_rehello && !room_queued(c, peer_slot(c, p))) {
            p->next_rehello = now + REHELLO_EVERY + jitter(REHELLO_EVERY * 0.25);
            send_room(c, c->hi_msg, p->addr, c->sock);
            if (c->net_verbose) ui_print(c, "* hi -> %s (%s)", p->nick, stuck ? "re-handshake" : "quiet");
        }
    }
    if (now >= c->next_alive) {
        c->next_alive = now + KEEPALIVE + jitter(3.0);
        for (int i = 0; i < c->n_static; i++) add_candidate(c, c->static_peers[i]);
        if (c->tor) knock_room_slots(c);
    }
    if (c->lan_sock != SOCK_INVALID && now >= c->next_lan) {
        c->next_lan = now + 5 + jitter(2.0);
        if (c->net_verbose) ui_print(c, "* lan beacon sent");
        char idhex[33]; hex_encode(c->my_id, ID_LEN, idhex);
        char beacon[64]; snprintf(beacon, sizeof beacon, "lan\t%s\t%u", idhex, (unsigned)c->port);
        send_room(c, beacon, addr_broadcast_lan(c->lan_port), c->lan_sock);
        send_room(c, beacon, addr_loopback(c->lan_port), c->lan_sock);
    }
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used) continue;

        // Until the peer re-handshakes with our new key, keep announcing it on the chain it can still read.
        if (p->ok && p->announces_rekey && c->keygen > 1 && now >= p->next_rk
            && (p->keygen != c->keygen || !p->chain_confirmed)) {
            p->next_rk = now + RK_RESEND;
            if (p->keygen != c->keygen) send_rk(c, p, 0);
            else if (p->old_until > 0.0 && p->old_send.started) send_rk(c, p, 1);
        }
        if (p->old_until > 0.0 && now > p->old_until) rekey_drop_overlap(p);
        // During a re-handshake a peer's frames can go unread for a while: the initiator's, from its kx
        // until the responder takes it, a cookie round trip later. Through the relays, with a slot every
        // five seconds or so, that's most of a minute, which has been longer than the timeout. So there it
        // gets the overlap time on top before it's dropped.
        double timeout = PEER_TIMEOUT
                       + (p->addr.kind == ADDR_NOSTR && rehandshaking_with(c, p) ? REKEY_OVERLAP : 0.0);
        if (p->ok && now - p->seen > timeout) drop_peer(c, p, "timed out");
    }

    if (now >= c->next_rekey) {
        if (c->rekey_due == 0.0) c->rekey_due = now;
        double waited = now - c->rekey_due;
        if ((!pending_any(c) || waited > REKEY_DRAIN_GRACE) && (!rehandshaking(c) || waited > REKEY_DEFER_MAX)) {
            session_rekey(c, now);
            c->rekey_due = 0.0;
            c->next_rekey = now + REKEY_INTERVAL + jitter(REKEY_INTERVAL * 0.2);
        }
    }

    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used) continue;
        if (p->ok && !p->announced && now - p->ok_since >= JOIN_WAIT) announce_join(c, p);
        // Slots start once there's a chain to send on. Before a peer is connected, our first frame to it
        // is what connects it.
        if (!p->ok && !send_chain_for(p)->started) continue;
        double iv = cover_interval(c, p);
        if (p->next_cover == 0.0) { p->next_cover = now + jitter(iv); continue; }
        if (now < p->next_cover) continue;
        // Fast transfers: while one runs with this peer (and not through the relays), its slots
        // come every few milliseconds, as many as are due since the last tick.
        if (c->fast_files && p->ok && p->addr.kind != ADDR_NOSTR && (p->serving || file_downloading_from(c, p))) {
            for (int burst = 0; burst < 64 && now >= p->next_cover; burst++) {
                run_slot(c, p);
                p->next_cover += FILE_FAST_INTERVAL;
            }
            if (now >= p->next_cover) p->next_cover = now + FILE_FAST_INTERVAL;
            continue;
        }
        run_slot(c, p);
        // Through the relays a transfer can't burst. Instead, slots for a fast transfer we're sending come
        // as often as the relays allow.
        if (c->fast_files && p->ok && p->serving && p->addr.kind == ADDR_NOSTR) iv = relay_fast_interval(c, iv);
        p->next_cover = now + iv + jitter(iv * 0.25);
    }
    if (!c->created && !c->warned_lonely && !c->ever_connected && now - c->start > LONELY_HINT_AFTER) {
        c->warned_lonely = 1;
        ui_print(c, "* nobody has answered for this session yet - check the id and password with "
                     "whoever shared them, or they may not have started their app yet");
        // DHT and Tor sessions only meet on the relays. Without them the room splits in two without any
        // warning.
        if (!c->nostr)
            ui_print(c, "* Nostr relays are off here, so members using %s routing can't reach you - :set nostr on turns them on%s",
                     c->route.mode == ROUTE_TOR ? "DHT" : "Tor", c->route.mode == ROUTE_TOR ? " (through Tor)" : "");
        net_report(c);
    }
}

static void net_report(chat_t *c) {
    net_stats_t *st = &c->st;
    int cands = 0;
    for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used) cands++;
    if (c->route.mode == ROUTE_TOR) {
        char ts[300] = "not running";
        if (c->tor) tor_status(c->tor, ts, sizeof ts);
        ui_print(c, "* net: tor | %s | candidates to try: %d | handshakes in progress: %d | connected: %d",
                 ts, cands, pending_peer_count(c), live_count(c));
        char ns[300] = "off - DHT peers can't reach this session";
        if (c->nostr) nostr_status(c->nostr, ns, sizeof ns);
        int relayed = 0;
        for (int i = 0; i < c->peer_hi; i++) if (c->peers[i].used && c->peers[i].ok && c->peers[i].addr.kind == ADDR_NOSTR) relayed++;
        ui_print(c, "* nostr relays through Tor: %s | peers through relays: %d", ns, relayed);
    } else if (c->dht_on) {
        ui_print(c, "* net: udp/%u | internet lookup: IPv4 %s%d nodes, %d peers | IPv6 %s%d nodes, %d peers | candidates to try: %d | handshakes in progress: %d | connected: %d",
                 (unsigned)c->port, c->dht.want[DHT_V4] ? "" : "(off) ", dht_queried_count_fam(&c->dht, DHT_V4),
                 dht_found_count_fam(&c->dht, DHT_V4), c->dht.want[DHT_V6] ? "" : "(off) ",
                 dht_queried_count_fam(&c->dht, DHT_V6), dht_found_count_fam(&c->dht, DHT_V6),
                 cands, pending_peer_count(c), live_count(c));
    } else {
        ui_print(c, "* net: udp/%u | internet lookup: off | candidates to try: %d | handshakes in progress: %d | connected: %d",
                 (unsigned)c->port, cands, pending_peer_count(c), live_count(c));
    }
    if (c->route.mode != ROUTE_TOR) {
        char pm[160] = "off", ns[300] = "off";
        if (c->pm) portmap_status(c->pm, pm, sizeof pm);
        if (c->nostr) nostr_status(c->nostr, ns, sizeof ns);
        int relayed = 0;
        for (int i = 0; i < c->peer_hi; i++) if (c->peers[i].used && c->peers[i].ok && c->peers[i].addr.kind == ADDR_NOSTR) relayed++;
        ui_print(c, "* port mapping: %s | lan: %s | nostr fallback: %s | peers through relays: %d", pm,
                 c->lan_sock != SOCK_INVALID ? "on" : "off", ns, relayed);
    }
    ui_print(c, "* rx: %u datagrams | readable with this room's key: %u (hi %u, ck %u, hi2 %u of which %u bad-cookie, kx %u, lan %u) | from connected peers: %u | unreadable: %u | handshake pieces: %u (%u rebuilt)",
             st->rx, st->room_ok, st->hi, st->ck, st->hi2, st->hi2_bad, st->kx, st->lan, st->session_ok, st->other, st->rx_chunks, st->rx_chunk_done);
    if (st->n_src > 0) {
        char list[400]; size_t pos = 0;
        for (int i = 0; i < st->n_src && pos < sizeof list - 60; i++) {
            char as[ADDR_STR_LEN]; addr_to_string(st->src[i], as);
            pos += (size_t)snprintf(list + pos, sizeof list - pos, "%s%s (%u)", i ? ", " : "", as, st->src_n[i]);
        }
        ui_print(c, "* recent senders: %s", list);
    }
    const char *why;
    if (st->rx == 0 && c->route.mode == ROUTE_TOR) why = "nothing has reached this session through Tor yet - publishing and finding onion services takes a minute or two";
    else if (st->rx == 0) why = "nothing at all has reached this session's port - a firewall/NAT is blocking inbound UDP, or nobody is sending to you yet";
    else if (st->room_ok == 0 && st->other > 0) why = "packets arrive but none are readable - wrong session id or password, or the other side runs an incompatible build";
    else if (st->hi > 0 && st->connects == 0) why = "a handshake started but never finished - typically a NAT that can't be hole-punched, or handshake pieces being lost";
    else if (st->connects > 0) why = "connected to at least one peer";
    else why = "no handshake traffic yet";
    ui_print(c, "* diagnosis: %s", why);
}

const char *chat_verify_label(verify_state_t s) {
    switch (s) {
        case VERIFY_VERIFIED: return "verified";
        case VERIFY_FAILED:   return "\xe2\x9a\xa0 signature invalid";
        case VERIFY_UNVERIFIED:
        default:               return "unverified";
    }
}

void chat_build_label(const peer_t *p, char *out, size_t cap) {
    switch (p->build_state) {
        // Only its claim. A client modified to lie can send an official build's hash.
        case BUILD_OFFICIAL:  snprintf(out, cap, "says official v%s", p->build_version); break;
        case BUILD_MODIFIED:  snprintf(out, cap, "modified client (says v%s)", p->build_version); break;
        case BUILD_UNCHECKED: snprintf(out, cap, "v%s, build not checked", p->build_version); break;
        case BUILD_UNKNOWN:
        default:              snprintf(out, cap, "build unknown"); break;
    }
}

static void send_to_live_peers(chat_t *c, const char *msg) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) send_peer(c, &c->peers[i], msg);
}

void chat_set_nick(chat_t *c, const char *nick) {
    set_own_nick(c, nick);
    ui_print(c, "* your nickname is now %s", c->nick);
    char msg[8 + MAX_NICK];
    snprintf(msg, sizeof msg, "n\t%s", c->nick);
    send_to_live_peers(c, msg);
}

void chat_set_colour(chat_t *c, const uint8_t rgb[3]) {
    memcpy(c->my_color, rgb, 3);
    char hex[7]; color_to_hex(rgb, hex);
    ui_print_colored(c, c->my_color, "* your colour is now #%s", hex);
    char msg[10]; snprintf(msg, sizeof msg, "c\t%s", hex);
    send_to_live_peers(c, msg);
}

void chat_set_identity(chat_t *c, identity_source_t source, const identity_keypair_t *idkp) {
    c->identity_source = source;
    if (source != IDENT_NONE) c->identity = *idkp;
    if (source == IDENT_NONE) ui_print(c, "* signing turned off - your messages here are no longer signed");
    else ui_print(c, "* signing key set - re-announcing it to everyone already here");
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) send_k_now(c, &c->peers[i]);
}

static cmd_result_t cmd_help(void *ctx, const char *arg) {
    chat_t *c = ctx; (void)arg;
    ui_print(c, "* commands - anything not starting with : is sent to the room:");
    for (const command_t *cmd = CHAT_COMMANDS; cmd->name; cmd++) {
        char line[160]; cmd_format_help(cmd, ':', line, sizeof line);
        ui_print(c, "%s", line);
    }
    return CMD_OK;
}

static cmd_result_t cmd_peers(void *ctx, const char *arg) {
    chat_t *c = ctx; (void)arg;
    int n = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        if (n++ == 0) ui_print(c, "* online: %s (you), and:", c->nick);
        char idhex[9]; hex_encode(p->id, 4, idhex);
        char vfyhex[HEX_GROUPS_LEN(VERIFY_LEN)]; hex_groups(p->vfy, VERIFY_LEN, vfyhex);
        char build[64]; chat_build_label(p, build, sizeof build);
        static const char *const CODE[] = { "", ", code not compared", ", code compared", ", CODES DIFFER", ", KEY CHANGED" };
        ui_print(c, "*   %s#%s (verify %s%s, %s, %s%s)", p->nick, idhex, vfyhex, CODE[chat_code_state(c, p)],
                 chat_verify_label(p->identity_state), build, p->persists ? ", logging" : "");
    }
    if (n == 0) ui_print(c, "* nobody else yet");
    return CMD_OK;
}

// The online peer an argument refers to: a nick, or NICK#ID (a prefix of the id :peers shows) when
// nicks look alike. NULL if none, or (*ambiguous) more than one.
static peer_t *peer_by_name(chat_t *c, const char *arg, int *ambiguous) {
    char name[CHAT_NAME_LEN];
    copy_str(name, arg, sizeof name);
    char *hash = strchr(name, '#');
    const char *prefix = "";
    if (hash) { *hash = '\0'; prefix = hash + 1; }
    peer_t *found = NULL;
    *ambiguous = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok || !nick_ieq(p->nick, name)) continue;
        char idhex[ID_LEN * 2 + 1]; hex_encode(p->id, ID_LEN, idhex);
        if (strlen(prefix) > sizeof idhex - 1 || strncmp(idhex, prefix, strlen(prefix)) != 0) continue;
        if (found) { *ambiguous = 1; return NULL; }
        found = p;
    }
    return found;
}

// Adds p's signing key to the verified keys. If p was warned about for having the nick of another
// verified key, the entries with that nick are replaced: the user compared codes with this key.
static void pin_identity(chat_t *c, peer_t *p) {
    (void)c;
    if (p->identity_state != VERIFY_VERIFIED) return;
    if (p->trust == 2)
        for (int i = trust_find_nick(p->nick_skel, 0); i >= 0; i = trust_find_nick(p->nick_skel, i))
            trust_remove(i);
    trust_add(p->identity_source, p->identity_pub, p->nick);
    p->trust = 1;
}

static cmd_result_t cmd_verify(void *ctx, const char *arg) {
    chat_t *c = ctx;
    // "NICK", "NICK ok" or "NICK no". The verdict is the last word, since a nick can contain spaces.
    char who[MAX_TEXT + 1], verdict[8] = "";
    copy_str(who, arg, sizeof who);
    char *sp = strrchr(who, ' ');
    if (sp && (strcmp(sp + 1, "ok") == 0 || strcmp(sp + 1, "yes") == 0 || strcmp(sp + 1, "no") == 0)) {
        copy_str(verdict, sp + 1, sizeof verdict);
        while (sp > who && sp[-1] == ' ') sp--;
        *sp = '\0';
    }
    if (!who[0]) {
        ui_print(c, "* usage: :verify NICK shows the code to compare with them; :verify NICK ok once it matches theirs, "
                    ":verify NICK no if it doesn't");
        return CMD_OK;
    }
    int ambiguous;
    peer_t *p = peer_by_name(c, who, &ambiguous);
    if (!p) {
        if (ambiguous) ui_print(c, "* more than one peer is called %s - add the #id :peers shows (:verify %s#1a2b...)", who, who);
        else ui_print(c, "* no online peer named '%s'", who);
        return CMD_OK;
    }
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    char code[HEX_GROUPS_LEN(VERIFY_LEN)]; hex_groups(p->vfy, VERIFY_LEN, code);
    if (verdict[0] == 'n') {
        p->code_ok = -1;
        ui_print(c, "* %s: the codes differ - someone with this room's password may be between you. Nothing you send goes "
                    "to them now. Leave this session and start a new one, with a new password shared over a channel you trust",
                 name);
    } else if (verdict[0]) {
        int was = p->code_ok, replaced = p->trust == 2;
        p->code_ok = 1;
        pin_identity(c, p);
        if (was != 1) file_offer_all(c, p);
        const char *kept = p->identity_state != VERIFY_VERIFIED
            ? ". They have no valid signing key, so this lasts for this session only"
            : trust_saved() ? ". Their signing key is saved as verified (:verified lists them)"
            : ". Their signing key counts as verified until chat exits; :install saves it";
        ui_print(c, "* %s: verify code confirmed - what you send reaches them%s%s", name, kept,
                 replaced && p->identity_state == VERIFY_VERIFIED ? ". It replaces the key verified for this nick before" : "");
    } else {
        static const char *const STATE[] = { "", " - not compared yet", " - compared", " - you said it differs",
                                             " - not compared, and they sign with another key than the one verified for this nick" };
        ui_print(c, "* %s: verify code %s%s", name, code, STATE[chat_code_state(c, p)]);
        if (p->identity_source != IDENT_NONE) {
            char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(p->identity_fp, ID_FP_LEN, fphex);
            ui_print(c, "* %s: signing identity fingerprint %s (%s)", name, fphex, chat_verify_label(p->identity_state));
        }
        ui_print(c, "* read the code out to them over another channel (in person, a call); if theirs is the same, "
                    ":verify %s ok - if not, :verify %s no", name, name);
    }
    return CMD_OK;
}

// ":verified" lists the verified keys, ":verified forget NICK" removes the ones with that nick,
// ":verified forget all" removes every one.
static cmd_result_t cmd_verified(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char word[CMD_WORD_MAX];
    const char *rest = cmd_parse(arg, word);
    if (strcmp(word, "forget") == 0) {
        char who[MAX_TEXT + 1];
        copy_str(who, rest, sizeof who);
        size_t wl = strlen(who);
        while (wl > 0 && who[wl - 1] == ' ') who[--wl] = '\0';
        if (!who[0]) { ui_print(c, "* usage: :verified forget NICK, or :verified forget all"); return CMD_OK; }
        int removed = 0;
        if (strcmp(who, "all") == 0) {
            while (trust_count() > 0) { trust_remove(trust_count() - 1); removed++; }
        } else {
            char nick[MAX_NICK + 1], skel[NICK_SKEL_LEN];
            chat_clean_nick(who, nick);
            nick_skeleton(nick, skel, sizeof skel);
            for (int i = trust_find_nick(skel, 0); i >= 0; i = trust_find_nick(skel, i)) { trust_remove(i); removed++; }
        }
        if (!removed) { ui_print(c, "* no verified key has the nick %s - :verified lists them", who); return CMD_OK; }
        // Peers here keep what was compared in this session, but are checked against the list again.
        for (int i = 0; i < c->peer_hi; i++) if (c->peers[i].used && c->peers[i].trust == 1) c->peers[i].trust = 0;
        ui_print(c, "* removed %d verified key%s%s", removed, removed == 1 ? "" : "s",
                 trust_saved() ? " from what :install saved" : "");
        return CMD_OK;
    }
    if (word[0]) { ui_print(c, "* usage: :verified lists the verified keys; :verified forget NICK removes one"); return CMD_OK; }
    int n = trust_count();
    if (n == 0) {
        ui_print(c, "* no verified keys yet. :verify NICK ok adds the signing key of a peer whose code you compared");
        return CMD_OK;
    }
    ui_print(c, "* %d verified key%s%s:", n, n == 1 ? "" : "s",
             trust_saved() ? ", saved with what :install saved" : ", kept until chat exits (:install saves them)");
    for (int i = 0; i < n; i++) {
        const trust_entry_t *t = trust_at(i);
        uint8_t fp[ID_FP_LEN]; identity_fingerprint(t->pub, fp);
        char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(fp, ID_FP_LEN, fphex);
        static const char *const SRC[] = { "", "key", "AGE", "PGP" };
        ui_print(c, "*   %s  %s (%s)", t->nick, fphex, SRC[t->source >= IDENT_NATIVE && t->source <= IDENT_PGP ? t->source : 0]);
    }
    return CMD_OK;
}

static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };
static const char *const PREVIEW_NAMES[] = { "off", "nick", "message" };
static const char *const NET_LOG_NAMES[] = { "normal", "verbose" };

static int name_index(const char *const *names, int n, const char *s) {
    for (int i = 0; i < n; i++) if (strcmp(names[i], s) == 0) return i;
    return -1;
}

// The --simple :set, for the settings a session holds itself. The full-screen UI handles :set
// itself, using the settings page.
static cmd_result_t cmd_set(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char key[CMD_WORD_MAX];
    const char *value = cmd_parse(arg, key);
    char hex[7]; color_to_hex(c->my_color, hex);
    if (!key[0]) {
        ui_print(c, "* nick %s, colour #%s, notify %s, preview %s, net %s - :set NAME VALUE changes one", c->nick, hex,
                 NOTIFY_NAMES[c->notify_mode], PREVIEW_NAMES[c->notify_preview], NET_LOG_NAMES[c->net_verbose != 0]);
    } else if (strcmp(key, "nick") == 0) {
        if (!value[0]) ui_print(c, "* nick: %s. usage: :set nick NAME", c->nick);
        else chat_set_nick(c, value);
    } else if (strcmp(key, "colour") == 0 || strcmp(key, "color") == 0) {
        uint8_t rgb[3];
        if (!value[0]) {
            char list[512]; size_t pos = 0;
            for (int i = 0; i < COLOR_PALETTE_N; i++)
                pos += (size_t)snprintf(list + pos, sizeof(list) - pos, "%s%s", i ? ", " : "", COLOR_PALETTE[i].name);
            ui_print(c, "* colour: #%s. usage: :set colour NAME|#RRGGBB. names: %s", hex, list);
        } else if (parse_color(value, rgb) != 0) {
            ui_print(c, "* unknown colour '%s' - try a name or #RRGGBB", value);
        } else {
            chat_set_colour(c, rgb);
        }
    } else if (strcmp(key, "notify") == 0) {
        int m = name_index(NOTIFY_NAMES, 3, value);
        if (m < 0) {
            ui_print(c, "* notify: %s. usage: :set notify all|mentions|none", NOTIFY_NAMES[c->notify_mode]);
        } else {
            c->notify_mode = (notify_mode_t)m;
            ui_print(c, "* notify: %s", NOTIFY_NAMES[m]);
        }
    } else if (strcmp(key, "preview") == 0) {
        int m = name_index(PREVIEW_NAMES, 3, value);
        if (m < 0) {
            ui_print(c, "* preview: %s. usage: :set preview off|nick|message - what a notification shows besides "
                        "that a message came (desktops keep notifications)", PREVIEW_NAMES[c->notify_preview]);
        } else {
            c->notify_preview = (notify_preview_t)m;
            ui_print(c, "* preview: %s", PREVIEW_NAMES[m]);
        }
    } else if (strcmp(key, "net") == 0) {
        int v = name_index(NET_LOG_NAMES, 2, value);
        if (v < 0) {
            ui_print(c, "* net: %s. usage: :set net normal|verbose", NET_LOG_NAMES[c->net_verbose != 0]);
        } else {
            c->net_verbose = v;
            ui_print(c, v ? "* net: verbose - every handshake packet now gets its own console line" : "* net: normal");
        }
    } else {
        ui_print(c, "* no setting %s here - :set lists them", key);
    }
    return CMD_OK;
}

static cmd_result_t cmd_net(void *ctx, const char *arg) {
    (void)arg;
    net_report(ctx);
    return CMD_OK;
}

static cmd_result_t cmd_port(void *ctx, const char *arg) {
    chat_t *c = ctx;
    if (c->route.mode != ROUTE_DHT) {
        ui_print(c, "* this session runs over Tor and has no udp port of its own");
        return CMD_OK;
    }
    if (!arg[0]) {
        ui_print(c, "* udp port: %u. usage: :port N (0 picks a free one)", (unsigned)c->port);
        return CMD_OK;
    }
    char *end;
    long want = strtol(arg, &end, 10);
    if (*end || want < 0 || want > 65535) {
        ui_print(c, "* not a port: %s. usage: :port N (0-65535, 0 picks a free one)", arg);
        return CMD_OK;
    }
    if (want != 0 && want == c->port) {
        ui_print(c, "* already on udp port %u", (unsigned)c->port);
        return CMD_OK;
    }
    uint16_t got = 0;
    sock_t s = net_udp_open((uint16_t)want, NET_DUAL, &got);
    if (s == SOCK_INVALID) {
        ui_print(c, "* cannot bind udp port %ld - staying on %u", want, (unsigned)c->port);
        return CMD_OK;
    }
    net_close(c->sock);
    c->sock = s;
    c->port = got;
    // Peers follow the source address of our next hi, and the DHT announces again from the new socket.
    c->next_alive = 0;
    c->next_lan = 0;
    if (c->dht_on) { c->dht.my_port = got; c->dht.explicit_port = 0; c->dht.next_lookup = 0; }
    // The old mapping pointed at the old port.
    if (c->pm) { portmap_free(c->pm); c->pm = portmap_new(c->port, module_log, c); }
    ui_print(c, "* now on udp port %u", (unsigned)got);
    return CMD_OK;
}

static cmd_result_t cmd_quit(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    return CMD_QUIT;
}

// ---- files ----

static int peer_trusted(const chat_t *c, const peer_t *p) {
    return p->code_ok >= 0 && (!c->verify_required || p->code_ok == 1);
}

static file_entry_t *file_by_num(chat_t *c, int num) {
    for (int i = 0; i < FILE_OFFERS_MAX; i++) if (c->files[i].used && c->files[i].num == num) return &c->files[i];
    return NULL;
}

const file_entry_t *chat_file(const chat_t *c, int num) {
    for (int i = 0; i < FILE_OFFERS_MAX; i++) if (c->files[i].used && c->files[i].num == num) return &c->files[i];
    return NULL;
}

static file_entry_t *file_by_fid(chat_t *c, const uint8_t owner[ID_LEN], const uint8_t fid[FILE_ID_LEN]) {
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        file_entry_t *e = &c->files[i];
        if (e->used && memcmp(e->owner, owner, ID_LEN) == 0 && memcmp(e->fid, fid, FILE_ID_LEN) == 0) return e;
    }
    return NULL;
}

static peer_t *file_owner(chat_t *c, const file_entry_t *e) {
    peer_t *p = find_peer_by_id(c, e->owner);
    return p && p->ok ? p : NULL;
}

uint64_t chat_file_got(const file_entry_t *e) {
    uint64_t got = e->done;
    for (int i = 0; i < e->win_n && i < FILE_WINDOW; i++) {
        if (!(e->win_got >> i & 1)) continue;
        uint64_t off = e->win_off + (uint64_t)i * FILE_CHUNK;
        got += off < e->size && e->size - off < FILE_CHUNK ? e->size - off : FILE_CHUNK;
    }
    return got < e->size ? got : e->size;
}

// The bytes p sends in an otherwise empty slot: one chunk over UDP or Tor, two through the relays.
static double file_slot_bytes(const peer_t *p) {
    return (p->batches && p->addr.kind == ADDR_NOSTR ? 2.0 : 1.0) * FILE_CHUNK;
}

double chat_file_eta(const chat_t *cc, const file_entry_t *e, double now) {
    chat_t *c = (chat_t *)cc;
    peer_t *p = file_owner(c, e);
    if (!p) return -1.0;
    if (!peer_trusted(c, p)) return -2.0;
    uint64_t got = chat_file_got(e);
    double left = (double)(e->size - got), took = now - e->since;
    // The rate so far, once there are enough chunks to measure it. Until then, chat's normal rate on
    // its path: a slot comes up to a quarter of its interval late, an eighth on average.
    if (got >= 4 * FILE_CHUNK && took > 0.0) return left * took / (double)got;
    return left / file_slot_bytes(p) * cover_interval(c, p) * 1.125;
}

// Stops a download: deletes the partial file and wipes anything in memory.
static void file_stop_download(file_entry_t *e, dl_state_t to) {
    if (e->out) { fclose(e->out); e->out = NULL; }
    if (e->part_path[0]) { platform_remove(e->part_path); e->part_path[0] = '\0'; }
    if (e->mem) { crypto_wipe(e->mem, e->size ? (size_t)e->size : 1); free(e->mem); e->mem = NULL; }
    if (e->win) { crypto_wipe(e->win, (size_t)FILE_WINDOW * FILE_CHUNK); free(e->win); e->win = NULL; }
    e->dl = to;
}

static void file_cache_drop(file_entry_t *e) {
    if (e->cache) { crypto_wipe(e->cache, e->size ? (size_t)e->size : 1); free(e->cache); e->cache = NULL; }
}

// Keeps e->mem (a whole file, checked) as e's cache, dropping the oldest others to stay within
// FILE_CACHE_MAX.
static void file_cache_keep(chat_t *c, file_entry_t *e) {
    uint8_t *m = e->mem;
    e->mem = NULL;
    if (!m) return;
    file_cache_drop(e);
    if (e->size > FILE_CACHE_MAX) { crypto_wipe(m, e->size ? (size_t)e->size : 1); free(m); return; }
    for (;;) {
        uint64_t total = e->size;
        file_entry_t *old = NULL;
        for (int i = 0; i < FILE_OFFERS_MAX; i++) {
            file_entry_t *o = &c->files[i];
            if (!o->used || !o->cache || o == e) continue;
            total += o->size;
            if (!old || o->num < old->num) old = o;
        }
        if (total <= FILE_CACHE_MAX || !old) break;
        file_cache_drop(old);
    }
    e->cache = m;
}

static void file_free(file_entry_t *e) {
    file_stop_download(e, DL_NONE);
    file_cache_drop(e);
    if (e->fp) { fclose(e->fp); e->fp = NULL; }
    crypto_wipe(e, sizeof *e);
}

// A free slot, or the oldest one that isn't ours and isn't being transferred. A peer over
// FILE_OFFERS_PER_PEER replaces its own oldest instead, so nobody can push out everyone else's offers.
#define FILE_OFFERS_PER_PEER 16
static file_entry_t *file_new(chat_t *c, const uint8_t *owner) {
    file_entry_t *pick = NULL;
    int theirs = 0;
    for (int i = 0; owner && i < FILE_OFFERS_MAX; i++)
        theirs += c->files[i].used && !c->files[i].mine && memcmp(c->files[i].owner, owner, ID_LEN) == 0;
    for (int i = 0; i < FILE_OFFERS_MAX && !pick && theirs < FILE_OFFERS_PER_PEER; i++) if (!c->files[i].used) pick = &c->files[i];
    for (int i = 0; i < FILE_OFFERS_MAX && !pick; i++) {
        file_entry_t *e = &c->files[i];
        if (e->mine || e->dl == DL_ACTIVE || e->dl == DL_QUEUED) continue;
        if (theirs >= FILE_OFFERS_PER_PEER && memcmp(e->owner, owner, ID_LEN) != 0) continue;
        if (!pick || e->num < pick->num) pick = e;
    }
    if (!pick) return NULL;
    file_free(pick);
    pick->used = 1;
    pick->num = ++c->file_seq;
    return pick;
}

static void file_desc(const file_entry_t *e, char *out, size_t cap) {
    char sz[32];
    file_format_size(e->size, sz, sizeof sz);
    snprintf(out, cap, "%s (%s%s)", e->name, sz, e->image ? ", image" : "");
}

static int file_downloading_from(const chat_t *c, const peer_t *p) {
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        const file_entry_t *e = &c->files[i];
        if (e->used && e->dl == DL_ACTIVE && memcmp(e->owner, p->id, ID_LEN) == 0) return 1;
    }
    return 0;
}

static void file_send_offer(chat_t *c, peer_t *p, const file_entry_t *e, double now) {
    char mid[9]; gen_mid(mid);
    char fidhex[FILE_ID_LEN * 2 + 1], shahex[65];
    hex_encode(e->fid, FILE_ID_LEN, fidhex);
    hex_encode(e->sha, 32, shahex);
    char rec[MSG_LINE_LEN];
    snprintf(rec, sizeof rec, "fo\t%s\t%s\t%llu\t%s\t%s\t%s", mid, fidhex, (unsigned long long)e->size, shahex,
             e->image ? "image" : "file", e->name);
    if (send_peer(c, p, rec) != 0) return;
    // Retried until acked, like a message.
    for (int s = 0; s < MAX_PENDING_MSGS; s++) {
        pending_msg_t *pm = &c->pending[s];
        if (pm->used) continue;
        pm->used = 1;
        memcpy(pm->mid, mid, sizeof pm->mid);
        pm->peer_slot = peer_slot(c, p);
        copy_str(pm->text, rec, sizeof pm->text);
        pm->tries = 1;
        pm->next_retry = now + resend_delay(c, p);
        break;
    }
}

// Our offers, to a peer that has just joined or whose code was just compared.
static void file_offer_all(chat_t *c, peer_t *p) {
    if (!p->ok || !peer_trusted(c, p)) return;
    for (int i = 0; i < FILE_OFFERS_MAX; i++)
        if (c->files[i].used && c->files[i].mine && c->files[i].fp) file_send_offer(c, p, &c->files[i], now_seconds());
}

// A path typed in a command: trailing spaces and the quotes file managers copy paths with are
// removed, and a leading ~ is the home folder.
static void typed_path(const char *in, char *path, size_t cap) {
    while (*in == ' ') in++;
    copy_str(path, in, cap);
    size_t pl = strlen(path);
    while (pl > 0 && path[pl - 1] == ' ') path[--pl] = '\0';
    if (pl >= 2 && (path[0] == '"' || path[0] == '\'') && path[pl - 1] == path[0]) { memmove(path, path + 1, pl - 2); path[pl - 2] = '\0'; }
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char *home = platform_home_dir();
        char full[1024];
        if (home) { snprintf(full, sizeof full, "%s%s", home, path + 1); copy_str(path, full, cap); }
    }
}

static cmd_result_t cmd_send(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char path[1024];
    typed_path(arg, path, sizeof path);
    if (!path[0]) { ui_print(c, "* usage: :send PATH - offers a file to everyone here; nobody gets it unless they fetch it"); return CMD_OK; }
    chat_send_file(c, path);
    return CMD_OK;
}

void chat_send_file(chat_t *c, const char *path) {
    uint64_t size = 0;
    FILE *f = platform_open_regular(path, &size);
    if (!f) { ui_print(c, "* can't send %s: not a file chat can read", path); return; }
    if (size > FILE_HARD_MAX) {
        fclose(f);
        char lim[32]; file_format_size(FILE_HARD_MAX, lim, sizeof lim);
        ui_print(c, "* can't send %s: files go up to %s", path, lim);
        return;
    }
    // Hashed while it's read now. Chunks are read from the same open file later, so a file changed
    // since then gives a hash that doesn't match, and nothing else is ever sent in its place.
    sha256_ctx_t h;
    sha256_init(&h);
    uint8_t buf[65536], head[8] = { 0 };
    uint64_t total = 0;
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (total < sizeof head) memcpy(head + total, buf, n < sizeof head - total ? n : sizeof head - total);
        sha256_update(&h, buf, n);
        total += n;
        if (total > size) break;
    }
    if (ferror(f) || total != size) { fclose(f); ui_print(c, "* can't send %s: it changed while it was read", path); return; }
    file_entry_t *e = file_new(c, NULL);
    if (!e) { fclose(f); ui_print(c, "* can't offer more files at once - :cancel one you offered first"); return; }
    e->mine = 1;
    memcpy(e->owner, c->my_id, ID_LEN);
    gen_random(e->fid, FILE_ID_LEN);
    e->size = size;
    sha256_final(&h, e->sha);
    file_clean_name(file_basename(path), e->name);
    e->image = image_kind(head, total < sizeof head ? (size_t)total : sizeof head) != NULL;
    e->fp = f;
    char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
    char who[MAX_NICK + 8]; snprintf(who, sizeof who, "%s (you)", c->nick);
    char text[FILE_NAME_MAX + 96];
    snprintf(text, sizeof text, "offered %s as file %d", desc, e->num);
    ui_chat_file(c, c->my_color, 0, who, text, e->num);
    int sent = 0, held = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        if (!peer_trusted(c, p)) { held++; continue; }
        file_send_offer(c, p, e, now_seconds());
        sent++;
    }
    if (held) ui_print(c, "* not offered to %d peer%s whose verify code you haven't compared", held, held == 1 ? "" : "s");
    else if (!sent) ui_print(c, "* nobody else is here yet - it's offered to whoever joins");
    if (e->image) ui_print(c, "* it's offered as a picture: others see it hidden until they choose :show %d", e->num);
}

// Asks p for the first run of the window that hasn't arrived (the whole window at the start).
// Anything that arrived after the run isn't requested again.
static void file_request(chat_t *c, file_entry_t *e, peer_t *p, double now) {
    if (e->win_n == 0) {
        uint64_t left = e->size - e->win_off;
        uint64_t chunks = (left + FILE_CHUNK - 1) / FILE_CHUNK;
        e->win_n = chunks > FILE_WINDOW ? FILE_WINDOW : (int)chunks;
        e->win_got = 0;
    }
    int first = 0;
    while (first < e->win_n && (e->win_got >> first & 1)) first++;
    int end = first;
    while (end < e->win_n && !(e->win_got >> end & 1)) end++;
    e->req_end = end;
    char fidhex[FILE_ID_LEN * 2 + 1]; hex_encode(e->fid, FILE_ID_LEN, fidhex);
    char rec[96];
    snprintf(rec, sizeof rec, "fg\t%s\t%llu\t%d", fidhex, (unsigned long long)(e->win_off + (uint64_t)first * FILE_CHUNK),
             end - first);
    send_peer(c, p, rec);
    double iv = c->fast_files && p->addr.kind != ADDR_NOSTR ? FILE_FAST_INTERVAL : cover_interval(c, p);
    e->retry_at = now + 6.0 * iv + 4.0;
}

// The folder file e is saved in: the one asked for, else Downloads.
static int file_dir(const file_entry_t *e, char *dir, size_t cap) {
    if (e->save_dir[0]) { copy_str(dir, e->save_dir, cap); return 0; }
    return platform_downloads_dir(dir, cap);
}

// The same folder, as messages name it.
static void file_dir_name(const file_entry_t *e, char *out, size_t cap) {
    copy_str(out, e->save_dir[0] ? e->save_dir : "Downloads", cap);
}

// A new hidden file in e's folder to write it to, under a name nothing else will use. file_save_as
// gives it its real name once its hash matches.
static FILE *file_open_part(file_entry_t *e) {
    char dir[600];
    if (file_dir(e, dir, sizeof dir) != 0) return NULL;
    uint8_t r[6]; gen_random(r, sizeof r);
    char rh[13]; hex_encode(r, sizeof r, rh);
    snprintf(e->part_path, sizeof e->part_path, "%s/.chat-%s.part", dir, rh);
    FILE *f = platform_create_new(e->part_path);
    if (!f) e->part_path[0] = '\0';
    return f;
}

// Renames the part file to e's name in its folder: name, otherwise "name (2).ext" and so on.
// Sets e->saved.
static int file_save_as(file_entry_t *e) {
    char dir[600], saved[sizeof e->saved];
    if (file_dir(e, dir, sizeof dir) != 0) return -1;
    const char *dot = strrchr(e->name, '.');
    size_t stem = dot && dot != e->name ? (size_t)(dot - e->name) : strlen(e->name);
    for (int k = 1; k < 100; k++) {
        if (k == 1) snprintf(saved, sizeof saved, "%s/%s", dir, e->name);
        else snprintf(saved, sizeof saved, "%s/%.*s (%d)%s", dir, (int)stem, e->name, k, e->name + stem);
        if (platform_move_new(e->part_path, saved) == 0) {
            e->part_path[0] = '\0';
            copy_str(e->saved, saved, sizeof e->saved);
            return 0;
        }
    }
    return -1;
}

// Reads f to the end, hashing it, and writing it to out and mem if given. Returns 1 if it's
// exactly e's size and matches its hash, 0 if not, -1 if out couldn't be written.
static int file_copy_checked(const file_entry_t *e, FILE *f, FILE *out, uint8_t *mem) {
    sha256_ctx_t h;
    sha256_init(&h);
    uint8_t buf[65536];
    uint64_t total = 0;
    size_t n;
    int match = 1, ok = 1;
    while (ok && (n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (n > e->size - total) { match = 0; break; }
        sha256_update(&h, buf, n);
        if (mem) memcpy(mem + total, buf, n);
        if (out) ok = fwrite(buf, 1, n, out) == n;
        total += n;
    }
    crypto_wipe(buf, sizeof buf);
    uint8_t got[32];
    sha256_final(&h, got);
    if (ferror(f) || total != e->size || crypto_equal(got, e->sha, 32) != 0) match = 0;
    return !ok ? -1 : match;
}

// Whether the file e was saved as is still there and still matches the offer. With mem, its
// bytes are put in *mem (for one up to FILE_VIEW_MAX). Returns 0 if it matches.
static int file_check_saved(const file_entry_t *e, uint8_t **mem) {
    if (mem) *mem = NULL;
    if (!e->saved[0] || (mem && e->size > FILE_VIEW_MAX)) return -1;
    uint64_t size = 0;
    FILE *f = platform_open_regular(e->saved, &size);
    if (!f) return -1;
    uint8_t *m = NULL;
    if (size != e->size || (mem && !(m = malloc(size ? (size_t)size : 1)))) { fclose(f); return -1; }
    int match = file_copy_checked(e, f, NULL, m);
    fclose(f);
    if (match != 1) {
        if (m) { crypto_wipe(m, size ? (size_t)size : 1); free(m); }
        return -1;
    }
    if (mem) *mem = m;
    return 0;
}

// Saves file e in its folder without fetching it: from mem (its bytes, already checked), or as a
// copy of where it was saved before, checked as it's read. Returns 0 once saved, 1 if there's no
// copy that still matches, -1 if it couldn't be written (after saying why).
static int file_save_local(chat_t *c, file_entry_t *e, const uint8_t *mem) {
    FILE *src = NULL;
    uint64_t size = 0;
    if (!mem) {
        if (!e->saved[0] || !(src = platform_open_regular(e->saved, &size))) { e->saved[0] = '\0'; return 1; }
        if (size != e->size) { fclose(src); e->saved[0] = '\0'; return 1; }
    }
    char where[600]; file_dir_name(e, where, sizeof where);
    FILE *out = file_open_part(e);
    if (!out) {
        if (src) fclose(src);
        ui_print(c, "* can't write a file in %s", where);
        return -1;
    }
    int r = 1;
    if (mem) r = fwrite(mem, 1, (size_t)e->size, out) == (size_t)e->size ? 1 : -1;
    else { r = file_copy_checked(e, src, out, NULL); fclose(src); }
    if (fflush(out) != 0) r = -1;
    if (fclose(out) != 0) r = -1;
    if (r == 1 && file_save_as(e) == 0) return 0;
    platform_remove(e->part_path);
    e->part_path[0] = '\0';
    if (r == 0) { e->saved[0] = '\0'; return 1; }
    ui_print(c, "* couldn't save file %d in %s", e->num, where);
    return -1;
}

static void file_finish(chat_t *c, file_entry_t *e) {
    uint8_t got[32];
    sha256_final(&e->hash, got);
    char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
    if (crypto_equal(got, e->sha, 32) != 0) {
        file_stop_download(e, DL_FAILED);
        ui_print(c, "* file %d (%s) didn't match what was offered - it was thrown away", e->num, desc);
        return;
    }
    if (e->view) {
        if (c->file_view) c->file_view(c->ui, e->num, e->name, e->mem, (size_t)e->size);
        if (e->also_save && file_save_local(c, e, e->mem) == 0) ui_print(c, "* saved file %d to %s", e->num, e->saved);
        e->also_save = 0;
        // Kept, so :show and :download don't fetch it again.
        file_cache_keep(c, e);
        file_stop_download(e, DL_DONE);
        return;
    }
    char took[48]; file_format_duration(now_seconds() - e->since, took, sizeof took);
    int ok = e->out && fflush(e->out) == 0;
    if (e->out) { if (fclose(e->out) != 0) ok = 0; e->out = NULL; }
    if (!ok || file_save_as(e) != 0) {
        char where[600]; file_dir_name(e, where, sizeof where);
        file_stop_download(e, DL_FAILED);
        ui_print(c, "* file %d (%s) downloaded, but couldn't be saved in %s", e->num, desc, where);
        return;
    }
    file_stop_download(e, DL_DONE);
    char sz[32]; file_format_size(e->size, sz, sizeof sz);
    ui_print(c, "* saved file %d to %s (%s, took %s)", e->num, e->saved, sz, took);
    if (e->also_show) {
        e->also_show = 0;
        if (file_check_saved(e, &e->mem) != 0) { ui_print(c, "* can't show file %d: it changed after it was saved", e->num); return; }
        if (c->file_view) c->file_view(c->ui, e->num, e->name, e->mem, (size_t)e->size);
        file_cache_keep(c, e);
    }
}

int chat_file_queued_after(const chat_t *c, const file_entry_t *e) {
    if (e->dl != DL_QUEUED) return 0;
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        const file_entry_t *o = &c->files[i];
        if (o->used && o->dl == DL_ACTIVE && memcmp(o->owner, e->owner, ID_LEN) == 0) return o->num;
    }
    return 0;
}

// Starts fetching e from p, to show or to save as e->view says. Returns 0, or -1 after saying why.
static int file_start(chat_t *c, file_entry_t *e, peer_t *p) {
    e->done = e->win_off = 0;
    e->win_n = e->req_end = 0;
    e->retries = 0;
    e->gone_since = 0.0;
    e->win = malloc((size_t)FILE_WINDOW * FILE_CHUNK);
    if (e->view) e->mem = malloc(e->size ? (size_t)e->size : 1);
    if (!e->win || (e->view && !e->mem)) { file_stop_download(e, DL_FAILED); ui_print(c, "* out of memory"); return -1; }
    if (!e->view && !(e->out = file_open_part(e))) {
        char where[600]; file_dir_name(e, where, sizeof where);
        file_stop_download(e, DL_FAILED);
        ui_print(c, "* can't write a file in %s", where);
        return -1;
    }
    sha256_init(&e->hash);
    e->dl = DL_ACTIVE;
    e->since = now_seconds();
    if (e->size == 0) { file_finish(c, e); return 0; }
    file_request(c, e, p, e->since);
    // How long it takes depends on the sender. Fast transfers only speed up what you send.
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    char sz[32]; file_format_size(e->size, sz, sizeof sz);
    char eta[48]; file_format_duration(chat_file_eta(c, e, e->since), eta, sizeof eta);
    if (p->addr.kind == ADDR_NOSTR)
        ui_print(c, "* fetching file %d (%s) from %s through the relays: %s at chat's normal rate, up to half that if "
                    "%s has fast transfers on", e->num, sz, name, eta, name);
    else
        ui_print(c, "* fetching file %d (%s) from %s: %s at chat's normal rate, seconds if %s has fast transfers on",
                 e->num, sz, name, eta, name);
    return 0;
}

int chat_file_fetch(chat_t *c, int num, int view, int anyway, const char *dir) {
    file_entry_t *e = file_by_num(c, num);
    if (!e) { ui_print(c, "* there's no file %d - :files lists them", num); return -1; }
    if (e->mine) { ui_print(c, "* file %d is yours", num); return -1; }
    if (view && !e->image) { ui_print(c, "* file %d isn't offered as a picture - :download %d saves it instead", num, num); return -1; }
    char sz[32]; file_format_size(e->size, sz, sizeof sz);
    if (view && e->size > FILE_VIEW_MAX) {
        ui_print(c, "* file %d is too big to show (%s) - :download %d saves it instead", num, sz, num);
        return -1;
    }
    int coming = e->dl == DL_ACTIVE || e->dl == DL_QUEUED;
    if (view) {
        // Shown before, or saved: no need to fetch it again.
        uint8_t *m = NULL;
        if (!e->cache && !coming && file_check_saved(e, &m) == 0) { e->mem = m; file_cache_keep(c, e); }
        if (e->cache) {
            if (c->file_view) c->file_view(c->ui, e->num, e->name, e->cache, (size_t)e->size);
            return 0;
        }
        if (coming) {
            if (e->view) { ui_print(c, "* file %d is already on its way (:files shows how far)", num); return -1; }
            e->also_show = 1;
            ui_print(c, "* file %d is on its way to be saved, and is shown too once it's here", num);
            return 0;
        }
    } else {
        char want[600] = "";
        if (dir) copy_str(want, dir, sizeof want);
        size_t wl = strlen(want);
        while (wl > 1 && (want[wl - 1] == '/' || want[wl - 1] == '\\')) want[--wl] = '\0';
        if (coming) {
            if (!e->view) { ui_print(c, "* file %d is already on its way (:files shows how far)", num); return -1; }
            e->also_save = 1;
            copy_str(e->save_dir, want, sizeof e->save_dir);
            ui_print(c, "* file %d is on its way to be shown, and is saved too once it's here", num);
            return 0;
        }
        if (!want[0] && e->saved[0]) {
            if (file_check_saved(e, NULL) == 0) {
                ui_print(c, "* file %d is already saved at %s - :download %d FOLDER saves another copy", num, e->saved, num);
                return 0;
            }
            e->saved[0] = '\0';
        }
        copy_str(e->save_dir, want, sizeof e->save_dir);
        // Shown before, or saved somewhere else: copied from there instead of fetched again.
        if (e->cache || e->saved[0]) {
            int r = file_save_local(c, e, e->cache);
            if (r == 0) { ui_print(c, "* saved file %d to %s, from the copy already here", num, e->saved); return 0; }
            if (r < 0) return -1;
        }
    }
    peer_t *p = file_owner(c, e);
    if (!p) { ui_print(c, "* whoever offered file %d isn't here now - try again once they're back", num); return -1; }
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    if (!peer_trusted(c, p)) {
        ui_print(c, "* compare verify codes with %s first (:verify %s): until then someone in the middle could be sending it", name, name);
        return -1;
    }
    uint64_t cap = c->file_cap ? c->file_cap : FILE_CAP_DEFAULT;
    char lim[32]; file_format_size(cap, lim, sizeof lim);
    if (e->size > cap && !anyway) {
        ui_print(c, "* file %d is %s, over your %s limit - :%s %d anyway fetches it regardless", num, sz, lim,
                 view ? "show" : "download", num);
        return -1;
    }
    e->view = view;
    e->also_show = e->also_save = 0;
    // One file at a time from each sender. The others wait their turn in files_tick.
    if (file_downloading_from(c, p)) {
        e->dl = DL_QUEUED;
        ui_print(c, "* file %d is queued: it starts once file %d from %s is done", num, chat_file_queued_after(c, e), name);
        return 0;
    }
    return file_start(c, e, p);
}

// :download [N] [anyway] [FOLDER]. Without N, the newest file offered that isn't saved or on its way.
static cmd_result_t cmd_download(void *ctx, const char *arg) {
    chat_t *c = ctx;
    while (*arg == ' ') arg++;
    long num = 0;
    if (*arg >= '0' && *arg <= '9') {
        char *end;
        num = strtol(arg, &end, 10);
        if ((*end && *end != ' ') || num > 1000000) num = -1;
        arg = end;
    }
    while (*arg == ' ') arg++;
    int anyway = strncmp(arg, "anyway", 6) == 0 && (arg[6] == '\0' || arg[6] == ' ');
    if (anyway) arg += 6;
    char dir[600];
    typed_path(arg, dir, sizeof dir);
    if (num < 0) {
        ui_print(c, "* usage: :download [N] [anyway] [FOLDER] - N from :files (the newest if left out), FOLDER instead of Downloads");
        return CMD_OK;
    }
    if (num == 0) {
        const file_entry_t *pick = NULL;
        for (int i = 0; i < FILE_OFFERS_MAX; i++) {
            const file_entry_t *e = &c->files[i];
            if (!e->used || e->mine || e->saved[0] || e->dl == DL_ACTIVE || e->dl == DL_QUEUED) continue;
            if (!pick || e->num > pick->num) pick = e;
        }
        if (!pick) { ui_print(c, "* no file to download - :files lists what's been offered"); return CMD_OK; }
        num = pick->num;
    }
    chat_file_fetch(c, (int)num, 0, anyway, dir);
    return CMD_OK;
}

static cmd_result_t cmd_cancel(void *ctx, const char *arg) {
    chat_t *c = ctx;
    file_entry_t *e = file_by_num(c, atoi(arg));
    if (!e) { ui_print(c, "* usage: :cancel N - stops fetching file N, or stops offering one of yours"); return CMD_OK; }
    if (e->mine) {
        if (e->fp) { fclose(e->fp); e->fp = NULL; }
        for (int i = 0; i < c->peer_hi; i++)
            if (c->peers[i].used && c->peers[i].serving && memcmp(c->peers[i].serve_fid, e->fid, FILE_ID_LEN) == 0) c->peers[i].serving = 0;
        ui_print(c, "* file %d is no longer offered", e->num);
    } else if (e->dl == DL_ACTIVE) {
        file_stop_download(e, DL_NONE);
        ui_print(c, "* stopped fetching file %d", e->num);
    } else if (e->dl == DL_QUEUED) {
        e->dl = DL_NONE;
        ui_print(c, "* file %d is no longer queued", e->num);
    } else {
        ui_print(c, "* file %d isn't being fetched", e->num);
    }
    return CMD_OK;
}

static cmd_result_t cmd_files(void *ctx, const char *arg) {
    chat_t *c = ctx;
    (void)arg;
    int any = 0;
    for (int n = 1; n <= c->file_seq; n++) {
        file_entry_t *e = file_by_num(c, n);
        if (!e) continue;
        any = 1;
        char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
        char who[CHAT_NAME_LEN] = "you";
        peer_t *p = e->mine ? NULL : find_peer_by_id(c, e->owner);
        if (!e->mine) { if (p) chat_peer_name(c, p, who); else copy_str(who, "someone who left", sizeof who); }
        char state[1024] = "";
        if (e->mine) copy_str(state, e->fp ? "offered" : "no longer offered", sizeof state);
        else if (e->dl == DL_ACTIVE) {
            uint64_t got = chat_file_got(e);
            double s = chat_file_eta(c, e, now_seconds());
            char gs[32], eta[48];
            file_format_size(got, gs, sizeof gs);
            if (s >= 0.0) { file_format_duration(s, eta, sizeof eta); strcat(eta, " left"); }
            else copy_str(eta, s < -1.0 ? "waiting until verify codes are compared" : "waiting for its sender", sizeof eta);
            snprintf(state, sizeof state, "fetching, %d%% (%s), %s%s", e->size ? (int)(got * 100 / e->size) : 100, gs, eta,
                     e->also_save ? ", saved too once it's here" : e->also_show ? ", shown too once it's here" : "");
        }
        else if (e->dl == DL_QUEUED) {
            int after = chat_file_queued_after(c, e);
            if (after) snprintf(state, sizeof state, "queued, starts after file %d", after);
            else copy_str(state, "queued, waiting for its sender", sizeof state);
        }
        else if (e->saved[0]) snprintf(state, sizeof state, "saved to %s", e->saved);
        else if (e->cache) snprintf(state, sizeof state, "shown - :download %d saves it without fetching it again", e->num);
        else if (e->dl == DL_DONE) copy_str(state, "shown", sizeof state);
        else if (e->dl == DL_FAILED) snprintf(state, sizeof state, "failed - :%s %d tries again", e->view ? "show" : "download", e->num);
        else copy_str(state, e->image ? ":show or :download" : ":download", sizeof state);
        ui_print(c, "* file %d from %s: %s - %s", e->num, who, desc, state);
    }
    if (!any) ui_print(c, "* no files yet - :send PATH offers one");
    return CMD_OK;
}

// The next chunk p asked for, as a record after the *pos bytes of text already there (instead of a
// nop if there are none), if it fits in cap. Returns 1 if it was added.
static int file_next_chunk(chat_t *c, peer_t *p, char *text, size_t *pos, size_t cap) {
    file_entry_t *e = file_by_fid(c, c->my_id, p->serve_fid);
    if (!e || !e->fp || p->serve_next >= p->serve_end) { p->serving = 0; return 0; }
    size_t want = p->serve_end - p->serve_next < FILE_CHUNK ? (size_t)(p->serve_end - p->serve_next) : FILE_CHUNK;
    char fidhex[FILE_ID_LEN * 2 + 1]; hex_encode(e->fid, FILE_ID_LEN, fidhex);
    char head[64];
    int hl = snprintf(head, sizeof head, "%sfd\t%s\t%llu\t", *pos ? "\n" : "", fidhex, (unsigned long long)p->serve_next);
    if (hl < 0 || *pos + (size_t)hl + (want + 2) / 3 * 4 > cap) return 0;
    uint8_t buf[FILE_CHUNK];
    if (fseek(e->fp, (long)p->serve_next, SEEK_SET) != 0 || fread(buf, 1, want, e->fp) != want) { p->serving = 0; return 0; }
    memcpy(text + *pos, head, (size_t)hl);
    *pos += (size_t)hl;
    base64_encode(buf, want, text + *pos);
    *pos += (want + 2) / 3 * 4;
    text[*pos] = '\0';
    crypto_wipe(buf, sizeof buf);
    p->serve_next += want;
    if (p->serve_next >= p->serve_end) p->serving = 0;
    return 1;
}

static int parse_u64(const char *s, uint64_t *out) {
    if (!*s || strlen(s) > 19) return -1;
    uint64_t v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (uint64_t)(*s - '0');
    }
    *out = v;
    return 0;
}

// A file record from p: an offer, a request for chunks of one of ours, a chunk, or "not offered".
static void file_on_record(chat_t *c, peer_t *p, char **f, int n, double now) {
    uint8_t fid[FILE_ID_LEN];
    if (n == 7 && strcmp(f[0], "fo") == 0) {
        uint8_t mid_raw[4], sha[32];
        uint64_t size;
        if (hex_decode(f[1], 8, mid_raw) != 0 || strlen(f[2]) != FILE_ID_LEN * 2 || hex_decode(f[2], FILE_ID_LEN * 2, fid) != 0
            || parse_u64(f[3], &size) != 0 || strlen(f[4]) != 64 || hex_decode(f[4], 64, sha) != 0) return;
        char ack[16]; snprintf(ack, sizeof ack, "a\t%s", f[1]);
        send_peer(c, p, ack);
        if (size > FILE_HARD_MAX || (strcmp(f[5], "image") != 0 && strcmp(f[5], "file") != 0)) return;
        if (file_by_fid(c, p->id, fid)) return;   // a retry of one we have
        file_entry_t *e = file_new(c, p->id);
        if (!e) return;
        memcpy(e->owner, p->id, ID_LEN);
        memcpy(e->fid, fid, FILE_ID_LEN);
        e->size = size;
        memcpy(e->sha, sha, 32);
        e->image = strcmp(f[5], "image") == 0;
        file_clean_name(f[6], e->name);
        char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
        uint64_t cap = c->file_cap ? c->file_cap : FILE_CAP_DEFAULT;
        char lim[32]; file_format_size(cap, lim, sizeof lim);
        char text[FILE_NAME_MAX + 200], shown[CHAT_NAME_LEN + 32];
        int over = size > cap;
        if (e->image)
            snprintf(text, sizeof text, "offers %s - :show %d%s to see it, :download %d%s to save it%s", desc, e->num,
                     over ? " anyway" : "", e->num, over ? " anyway" : "", over ? " (over your limit)" : "");
        else
            snprintf(text, sizeof text, "offers %s - :download %d%s to save it%s", desc, e->num, over ? " anyway" : "",
                     over ? " (over your limit)" : "");
        char via[CHAT_NAME_LEN]; chat_peer_name(c, p, via);
        const char *mark = p->code_ok < 0 ? " (codes differ)" : c->verify_required && p->code_ok != 1 ? " (code not compared)" : "";
        snprintf(shown, sizeof shown, "%s%s", via, mark);
        ui_chat_file(c, p->color, 0, shown, text, e->num);
        if (c->notify && c->notify_mode == NOTIFY_ALL)
            c->notify(c->ui, c->notify_preview >= PREVIEW_NICK ? shown : NULL,
                      c->notify_preview == PREVIEW_MESSAGE ? "offered a file" : NULL, 0);
    } else if (n == 4 && strcmp(f[0], "fg") == 0) {
        uint64_t off, count;
        if (strlen(f[1]) != FILE_ID_LEN * 2 || hex_decode(f[1], FILE_ID_LEN * 2, fid) != 0 || parse_u64(f[2], &off) != 0
            || parse_u64(f[3], &count) != 0) return;
        file_entry_t *e = file_by_fid(c, c->my_id, fid);
        // Only our files, still offered, to someone who would have been offered them. A file of ours that
        // isn't offered any more gets "fx". One that never was gets nothing, so made up ids can't fill the
        // queue every peer shares.
        if (!e) return;
        if (!e->fp || !peer_trusted(c, p)) {
            char rec[40]; snprintf(rec, sizeof rec, "fx\t%s", f[1]);
            send_peer(c, p, rec);
            return;
        }
        if (count < 1 || count > FILE_WINDOW || off % FILE_CHUNK != 0 || off >= e->size) return;
        p->serving = 1;
        memcpy(p->serve_fid, fid, FILE_ID_LEN);
        p->serve_next = off;
        p->serve_end = off + count * FILE_CHUNK < e->size ? off + count * FILE_CHUNK : e->size;
    } else if (n == 4 && strcmp(f[0], "fd") == 0) {
        uint64_t off;
        if (strlen(f[1]) != FILE_ID_LEN * 2 || hex_decode(f[1], FILE_ID_LEN * 2, fid) != 0 || parse_u64(f[2], &off) != 0) return;
        file_entry_t *e = file_by_fid(c, p->id, fid);
        if (!e || e->dl != DL_ACTIVE || off < e->win_off || off % FILE_CHUNK != 0) return;
        uint64_t idx = (off - e->win_off) / FILE_CHUNK;
        if (idx >= (uint64_t)e->win_n || (e->win_got >> idx & 1)) return;
        size_t want = e->size - off < FILE_CHUNK ? (size_t)(e->size - off) : FILE_CHUNK;
        uint8_t buf[FILE_CHUNK + 3];
        if (strlen(f[3]) != (want + 2) / 3 * 4 || base64_decode_strict(f[3], strlen(f[3]), buf, sizeof buf) != (long)want) return;
        memcpy(e->win + idx * FILE_CHUNK, buf, want);
        e->win_got |= 1ull << idx;
        e->retries = 0;
        double iv = c->fast_files && p->addr.kind != ADDR_NOSTR ? FILE_FAST_INTERVAL : cover_interval(c, p);
        e->retry_at = now + 6.0 * iv + 4.0;
        uint64_t full = e->win_n == 64 ? ~0ull : (1ull << e->win_n) - 1;
        if (e->win_got != full) {
            // The last of the requested run has arrived and the window still has a gap. Whatever is in it was
            // lost (or never requested), so it's requested now instead of when the retry is due. Through the
            // relays that saves half a minute.
            if ((int)idx + 1 == e->req_end) file_request(c, e, p, now);
            return;
        }
        // The window is complete: write it in order to the file (or memory), and add it to the hash.
        size_t bytes = e->size - e->win_off < (uint64_t)e->win_n * FILE_CHUNK ? (size_t)(e->size - e->win_off)
                                                                              : (size_t)e->win_n * FILE_CHUNK;
        if (e->view) memcpy(e->mem + e->done, e->win, bytes);
        else if (fwrite(e->win, 1, bytes, e->out) != bytes) {
            char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
            file_stop_download(e, DL_FAILED);
            ui_print(c, "* couldn't write file %d (%s) - is the disk full?", e->num, desc);
            return;
        }
        sha256_update(&e->hash, e->win, bytes);
        e->done += bytes;
        e->win_off += bytes;
        e->win_n = 0;
        if (e->done >= e->size) file_finish(c, e);
        else file_request(c, e, p, now);
    } else if (n == 2 && strcmp(f[0], "fx") == 0) {
        if (strlen(f[1]) != FILE_ID_LEN * 2 || hex_decode(f[1], FILE_ID_LEN * 2, fid) != 0) return;
        file_entry_t *e = file_by_fid(c, p->id, fid);
        if (!e || e->dl != DL_ACTIVE) return;
        file_stop_download(e, DL_FAILED);
        char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
        ui_print(c, "* %s no longer offers file %d", name, e->num);
    }
}

static void files_tick(chat_t *c, double now) {
    // Queued files start once nothing else is coming from their sender, the oldest first.
    for (;;) {
        file_entry_t *next = NULL;
        for (int i = 0; i < FILE_OFFERS_MAX; i++) {
            file_entry_t *e = &c->files[i];
            if (!e->used || e->dl != DL_QUEUED) continue;
            peer_t *p = file_owner(c, e);
            if (!p || !peer_trusted(c, p) || file_downloading_from(c, p)) continue;
            if (!next || e->num < next->num) next = e;
        }
        if (!next) break;
        file_start(c, next, file_owner(c, next));
    }
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        file_entry_t *e = &c->files[i];
        if (!e->used || e->dl != DL_ACTIVE) continue;
        peer_t *p = file_owner(c, e);
        // Its sender may only have stalled for a moment (a Tor circuit, a relay). The fetch waits for
        // them, and if they come back with a new verify code, for that to be compared again.
        if (!p || !peer_trusted(c, p)) {
            if (p || e->gone_since == 0.0) e->gone_since = now;
            if (p || now - e->gone_since < FILE_OWNER_GRACE) continue;
            file_stop_download(e, DL_FAILED);
            ui_print(c, "* whoever offered file %d left before it finished - fetch it again once they're back", e->num);
            continue;
        }
        // Back after a short time away. What it was sending was lost with its old session, so it's
        // requested again from where it stopped.
        if (e->gone_since > 0.0) {
            e->gone_since = 0.0;
            e->retries = 0;
            file_request(c, e, p, now);
            continue;
        }
        if (now < e->retry_at) continue;
        // During a re-handshake with its sender, our request may use keys it can't read yet, so the retry
        // waits for it to finish instead of being used up. If it never finishes the peer times out.
        if (rehandshaking_with(c, p)) { e->retry_at = now + 1.0; continue; }
        if (++e->retries > FILE_RETRIES) {
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            file_stop_download(e, DL_FAILED);
            ui_print(c, "* file %d stopped downloading from %s - try again later", e->num, name);
            continue;
        }
        file_request(c, e, p, now);
    }
}

void chat_set_file_options(chat_t *c, uint64_t cap, int fast) {
    c->file_cap = cap ? cap : FILE_CAP_DEFAULT;
    c->fast_files = fast != 0;
}

const command_t CHAT_COMMANDS[] = {
    { "help",       NULL,     NULL,              "list commands",                                   cmd_help },
    { "peers",      NULL,     NULL,              "who is online, with verify codes and builds",     cmd_peers },
    { "verify",     NULL,     "NICK [ok|no]",    "compare a peer's verify code; ok once it matches", cmd_verify },
    { "verified",   NULL,     "[forget NICK]",   "list the signing keys you verified, or remove one", cmd_verified },
    { "net",        NULL,     NULL,              "network report and diagnosis",                    cmd_net },
    { "port",       NULL,     "[N]",             "show or change this session's udp port",          cmd_port },
    { "set",        NULL,     "[NAME [VALUE]]",  "show or change nick, colour, notify, preview, net", cmd_set },
    { "send",       NULL,     "[PATH]",          "offer a file; nobody gets it unless they fetch it", cmd_send },
    { "files",      NULL,     NULL,              "the files offered here, and how they're coming",   cmd_files },
    { "download",   "dl",     "[N] [anyway] [FOLDER]", "save file N (the newest if left out) in Downloads or FOLDER", cmd_download },
    { "cancel",     NULL,     "N",               "stop fetching or queueing file N, or stop offering yours", cmd_cancel },
    { "quit",       "q exit", NULL,              "leave the session",                               cmd_quit },
    { NULL, NULL, NULL, NULL, NULL }
};

cmd_result_t chat_run_command(chat_t *c, const char *line_in) {
    char line[MAX_TEXT + 1];
    clean_text(line_in, line, MAX_TEXT);
    char word[CMD_WORD_MAX];
    const char *arg = cmd_parse(line, word);
    const command_t *cmd = cmd_find(CHAT_COMMANDS, word);
    if (!cmd) {
        ui_print(c, "* unknown command :%s - try :help", word);
        return CMD_UNKNOWN;
    }
    return cmd->run(c, arg);
}

void chat_send_text(chat_t *c, const char *text_in, double now) {
    char line[MAX_TEXT + 1];
    clean_text(text_in, line, MAX_TEXT);
    if (!line[0]) return;
    if (!chat_ready(c)) {
        ui_print(c, "* not connected yet - message not sent, chat opens once someone answers");
        return;
    }
    char mid[9]; gen_mid(mid);
    seen_add(c, mid);
    char myidhex[33]; hex_encode(c->my_id, ID_LEN, myidhex);
    char text[MSG_LINE_LEN];
    snprintf(text, sizeof text, "m\t%s\t%s\t%s\t%s", mid, myidhex, c->nick, line);
    char who[MAX_NICK + 8]; snprintf(who, sizeof who, "%s (you)", c->nick);
    ui_chat(c, c->my_color, 0, who, line);
    int sent = 0, s = 0, held = 0;
    char held_names[3 * CHAT_NAME_LEN] = "";
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        // A peer whose code wasn't compared may be someone in the middle: it gets nothing.
        if (p->code_ok < 0 || (c->verify_required && p->code_ok != 1)) {
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            if (held < 3) snprintf(held_names + strlen(held_names), sizeof held_names - strlen(held_names), "%s%s", held ? ", " : "", name);
            held++;
            continue;
        }
        if (send_peer(c, p, text) != 0) continue;
        sent++;
        // With every retry slot taken the message still goes out once, just without retries.
        while (s < MAX_PENDING_MSGS && c->pending[s].used) s++;
        if (s == MAX_PENDING_MSGS) continue;
        pending_msg_t *pm = &c->pending[s];
        pm->used = 1;
        memcpy(pm->mid, mid, sizeof pm->mid);
        pm->peer_slot = i;
        copy_str(pm->text, text, sizeof pm->text);
        pm->tries = 1;
        pm->next_retry = now + resend_delay(c, p);
    }
    if (held)
        ui_print(c, "* not sent to %s%s: compare verify codes first (:peers lists them, :verify NICK ok once they match)",
                 held_names, held > 3 ? " and others" : "");
    else if (!sent) ui_print(c, "* nobody else is here yet, message not delivered");
}

int chat_submit_line(chat_t *c, const char *line_in, double now) {
    char line[MAX_TEXT + 1];
    clean_text(line_in, line, MAX_TEXT);
    if (line[0] == ':') return chat_run_command(c, line + 1) != CMD_QUIT;
    chat_send_text(c, line, now);
    return 1;
}

static void module_log(void *ctx, int verbose_only, const char *msg) {
    chat_t *c = ctx;
    if (!verbose_only || c->net_verbose) ui_print(c, "%s", msg);
}

static void module_deliver(void *ctx, const uint8_t *data, size_t len, addr_t from, double now) {
    uint8_t buf[HANDSHAKE_BUF_LEN + 128];
    if (len > sizeof buf) return;
    memcpy(buf, data, len);
    on_relayed((chat_t *)ctx, buf, len, from, now);
}

// The room slots someone else may publish. Always worth a hi, since members publishing different
// slots only find each other by trying them.
static void knock_room_slots(chat_t *c) {
    for (int i = 0; i < TOR_ROOM_SLOTS; i++)
        if (i != tor_hosted_slot(c->tor)) add_candidate(c, tor_room_target(c->tor, i));
}

static void start_dht(chat_t *c) {
    if (c->dht_on || c->sock == SOCK_INVALID || !(c->route.dht4 || c->route.dht6)) return;
    uint8_t key[DHT_KEY_LEN];
    derive_dht_key(c->master, key);
    dht_init(&c->dht, key, c->port, c->route.dht4, c->route.dht6);
    crypto_wipe(key, sizeof key);
    dht_set_output(&c->dht, dht_out, c, 0);
    dht_start_bootstrap_resolve(&c->dht);
    c->dht_on = 1;
}

static void stop_dht(chat_t *c) {
    if (c->dht_on) dht_stop(&c->dht);
    c->dht_on = 0;
}

static void start_nostr(chat_t *c) {
    if (c->nostr || !c->route.nostr || c->route.n_relays == 0) return;
    uint8_t tag_key[NOSTR_KEY_LEN], wrap_key[NOSTR_KEY_LEN];
    derive_nostr_keys(c->master, tag_key, wrap_key);
    // In Tor mode the relays are where DHT peers can be met, and they're only reached through Tor:
    // its SOCKS port, or not at all until chat has one.
    const char *proxy = c->route.mode == ROUTE_TOR ? c->route.tor.socks : NULL;
    c->nostr = nostr_new(tag_key, wrap_key, c->my_id, (const char (*)[NOSTR_URL_MAX])c->route.relays, c->route.n_relays,
                         proxy, module_deliver, module_log, c);
    crypto_wipe(tag_key, sizeof tag_key);
    crypto_wipe(wrap_key, sizeof wrap_key);
    c->next_beacon = 0;
    c->relays_until = 0;
}

static void start_dht_routing(chat_t *c) {
    if (c->route.lan) c->lan_sock = net_udp_open(c->lan_port, NET_REUSE, NULL);
    start_dht(c);
    if (c->route.portmap) c->pm = portmap_new(c->port, module_log, c);
    start_nostr(c);
}

static int relays_differ(const routing_t *a, const routing_t *b) {
    if (a->n_relays != b->n_relays) return 1;
    for (int i = 0; i < a->n_relays; i++) if (strcmp(a->relays[i], b->relays[i]) != 0) return 1;
    return 0;
}

int chat_apply_routing(chat_t *c, const routing_t *r) {
    int later = r->mode != c->route.mode || strcmp(r->tor.password, c->route.tor.password) != 0;
    routing_t was = c->route;
    // The relays apply in both modes. A Tor session reaches them through Tor.
    c->route.nostr = r->nostr;
    memcpy(c->route.relays, r->relays, sizeof r->relays);
    c->route.n_relays = r->n_relays;
    if (c->nostr && (!r->nostr || relays_differ(&was, r))) {
        // Peers only reached through the relays go back to waiting for another path, and time out if
        // none comes.
        nostr_free(c->nostr);
        c->nostr = NULL;
    }
    start_nostr(c);
    if (c->route.mode == ROUTE_TOR) return later;
    c->route.dht4 = r->dht4; c->route.dht6 = r->dht6;
    c->route.lan = r->lan;
    c->route.portmap = r->portmap;

    if (r->lan && c->lan_sock == SOCK_INVALID) c->lan_sock = net_udp_open(c->lan_port, NET_REUSE, NULL);
    if (!r->lan && c->lan_sock != SOCK_INVALID) { net_close(c->lan_sock); c->lan_sock = SOCK_INVALID; }

    if (!r->dht4 && !r->dht6) stop_dht(c);
    else if (!c->dht_on) start_dht(c);
    else if (was.dht4 != r->dht4 || was.dht6 != r->dht6) {
        c->dht.want[DHT_V4] = r->dht4;
        c->dht.want[DHT_V6] = r->dht6;
        // The bootstrap list only holds the families that were wanted, so look it up again.
        dht_rebootstrap(&c->dht);
    }

    if (r->portmap && !c->pm) c->pm = portmap_new(c->port, module_log, c);
    if (!r->portmap && c->pm) {
        portmap_free(c->pm);
        c->pm = NULL;
        if (c->dht_on && c->dht.explicit_port) { c->dht.explicit_port = 0; c->dht.my_port = c->port; }
    }
    return later;
}

void chat_tor_set_ports(chat_t *c, const char *socks, const char *control) {
    if (!c->tor) return;
    copy_str(c->route.tor.socks, socks, sizeof c->route.tor.socks);
    copy_str(c->route.tor.control, control, sizeof c->route.tor.control);
    tor_set_ports(c->tor, socks, control);
    if (c->nostr) nostr_set_proxy(c->nostr, socks);
}

void chat_tor_connected(chat_t *c) {
    if (c->nostr) nostr_retry_now(c->nostr);
}

void chat_init(chat_t *c, const chat_opts_t *o, chat_print_fn print, chat_notify_fn notify, void *ui) {
    memset(c, 0, sizeof *c);
    // Locked before any key is stored there. Best effort: a low RLIMIT_MEMLOCK only means they may be
    // swapped. The peers hold their chain keys.
    crypto_lock((uint8_t *)c + SECRETS_OFFSET, SECRETS_LEN);
    crypto_lock(c->peers, sizeof c->peers);
    // What's queued to send holds messages as typed.
    crypto_lock(c->sendq, sizeof c->sendq);
    c->print = print;
    c->notify = notify;
    c->ui = ui;
    set_own_nick(c, o->nick);
    copy_str(c->session_name, o->session_name, sizeof c->session_name);
    c->created = o->created;
    c->route = o->route;
    c->once = o->once;
    c->notify_mode = o->notify_mode;
    c->notify_preview = o->notify_preview;
    c->verify_required = !o->verify_optional;
    chat_set_file_options(c, o->file_cap, o->fast_files);

    if (o->has_color) memcpy(c->my_color, o->color, 3);
    else {
        uint8_t r; gen_random(&r, 1);
        const named_color_t *pick = &COLOR_PALETTE[r % COLOR_PALETTE_N];
        c->my_color[0] = pick->r; c->my_color[1] = pick->g; c->my_color[2] = pick->b;
    }

    c->identity_source = o->identity_source;
    if (c->identity_source != IDENT_NONE) c->identity = o->identity;

    c->build = o->build;
    c->build.version[MAX_VERSION] = c->build.list[BUILD_LIST_LEN] = c->build.list_sig[MINISIGN_SIG_B64_LEN] = '\0';
    if (!version_ok(c->build.version)) c->build.ok = 0;
    // They're sent between tabs in "v".
    if (strspn(c->build.list, "0123456789abcdef,") != strlen(c->build.list)
        || strspn(c->build.list_sig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != strlen(c->build.list_sig))
        c->build.list[0] = c->build.list_sig[0] = '\0';
    c->has_release_key = minisign_pubkey(o->release_key, c->release_key) == 0;

    gen_random(c->my_id, ID_LEN);
    gen_keypair(&c->keys);
    kem_gen_keypair(&c->kem_keys);
    c->keygen = 1;
    gen_random(c->cookie_secret, 32);
    c->sock = c->lan_sock = SOCK_INVALID;
    if (derive_master(o->password, o->session_name, c->master) != 0) {
        c->start_error = "not enough free memory to derive the session key (it needs 512 MiB for a few seconds)";
        return;
    }
    derive_room_key(c->master, c->room_key);
    derive_udp_key(c->master, c->udp_key);
    c->lan_port = derive_lan_port(c->master);
    refresh_hi(c);

    if (c->route.mode == ROUTE_TOR) {
        // No UDP socket at all. Everything goes through Tor.
        uint8_t room_keys[TOR_ROOM_SLOTS][64], room_pubs[TOR_ROOM_SLOTS][32];
        for (int i = 0; i < TOR_ROOM_SLOTS; i++) derive_tor_room_key(c->master, i, room_keys[i], room_pubs[i]);
        c->tor = tor_new(&c->route.tor, (const uint8_t (*)[64])room_keys, (const uint8_t (*)[32])room_pubs,
                         module_deliver, module_log, c);
        crypto_wipe(room_keys, sizeof room_keys);
        c->started = c->tor != NULL;
        if (!c->started) c->start_error = "could not set up Tor";
        if (c->tor && c->created) { tor_host_room(c->tor, 0); c->tor_hosting = 1; }
        if (c->tor) { knock_room_slots(c); start_nostr(c); }
    } else {
        // Without the main socket the caller abandons this session, so nothing else is started.
        c->sock = net_udp_open(o->port, NET_DUAL, &c->port);
        c->started = c->sock != SOCK_INVALID;
        if (!c->started) c->start_error = "could not open a UDP socket (is the port in use?)";
        if (c->started) start_dht_routing(c);
    }

    int n_static = c->route.mode == ROUTE_TOR ? 0 : o->n_peers;
    if (n_static < 0) n_static = 0;
    if (n_static > (int)(sizeof c->static_peers / sizeof c->static_peers[0]))
        n_static = (int)(sizeof c->static_peers / sizeof c->static_peers[0]);
    memcpy(c->static_peers, o->peers, sizeof(addr_t) * (size_t)n_static);
    c->n_static = n_static;

    c->persist = o->persist;
    if (c->persist) {

        c->log_fp = platform_fopen_private(o->log_path, "a");
        if (!c->log_fp) { ui_print(c, "* could not open %s for logging - continuing without it", o->log_path); c->persist = 0; }
    }
    c->start = now_seconds();
    c->next_rekey = c->start + REKEY_INTERVAL + jitter(REKEY_INTERVAL * 0.2);
    c->probe_tokens = PROBE_BURST;
    c->probe_at = c->start;
    c->ck_tokens = CK_BURST;
    c->ck_at = c->start;
    c->roam_tokens = ROAM_BURST;
    c->roam_at = c->start;
}

void chat_shutdown(chat_t *c) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) send_now(c, &c->peers[i], "bye");
    nostr_free(c->nostr);
    tor_free(c->tor);
    portmap_free(c->pm);
    stop_dht(c);
    net_close(c->sock);
    net_close(c->lan_sock);
    // Files we offered are closed, and downloads in progress don't leave half-written files behind.
    for (int i = 0; i < FILE_OFFERS_MAX; i++) if (c->files[i].used) file_free(&c->files[i]);
    if (c->log_fp) fclose(c->log_fp);

    crypto_unlock((uint8_t *)c + SECRETS_OFFSET, SECRETS_LEN);
    crypto_unlock(c->peers, sizeof c->peers);
    crypto_unlock(c->sendq, sizeof c->sendq);

    crypto_wipe(c, sizeof *c);
}

#include <stdarg.h>

static void emit_line_file(chat_t *c, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len,
                           int file) {
    c->print(c->ui, hhmm, text, rgb, flags, color_len, file);
    if (c->log_fp) { fprintf(c->log_fp, "[%s] %s\n", hhmm, text); fflush(c->log_fp); }
}

static void emit_line(chat_t *c, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len) {
    c->print(c->ui, hhmm, text, rgb, flags, color_len, 0);
    if (c->log_fp) { fprintf(c->log_fp, "[%s] %s\n", hhmm, text); fflush(c->log_fp); }
}

static void ui_print(chat_t *c, const char *fmt, ...) {
    char msg[2200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    char hhmm[6]; current_hhmm(hhmm);
    emit_line(c, hhmm, msg, NULL, 0, 0);
}

static void ui_warn(chat_t *c, const char *fmt, ...) {
    char msg[2200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    char hhmm[6]; current_hhmm(hhmm);
    emit_line(c, hhmm, msg, NULL, LINE_WARN, 0);
}

static void ui_chat(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text) {
    char msg[2200];
    int head = snprintf(msg, sizeof msg, "%s%s:", mention ? "@ " : "", name);
    snprintf(msg + head, sizeof msg - (size_t)head, " %s", text);
    char hhmm[6]; current_hhmm(hhmm);
    emit_line(c, hhmm, msg, rgb, LINE_CHAT | (mention ? LINE_MENTION : 0u), head);
}

static void ui_chat_file(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text, int file) {
    char msg[2200];
    int head = snprintf(msg, sizeof msg, "%s%s:", mention ? "@ " : "", name);
    snprintf(msg + head, sizeof msg - (size_t)head, " %s", text);
    char hhmm[6]; current_hhmm(hhmm);
    emit_line_file(c, hhmm, msg, rgb, LINE_CHAT | (mention ? LINE_MENTION : 0u), head, file);
}

static void ui_print_colored(chat_t *c, const uint8_t rgb[3], const char *fmt, ...) {
    char msg[2200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    char hhmm[6]; current_hhmm(hhmm);
    emit_line(c, hhmm, msg, rgb, 0, 0);
}
