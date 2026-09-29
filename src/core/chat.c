// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "core/chat.h"
#include "common/util.h"
#include "platform/platform.h"
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SECRETS_OFFSET offsetof(chat_t, keys)
#define SECRETS_LEN (offsetof(chat_t, identity) + sizeof(identity_keypair_t) - offsetof(chat_t, keys))

static void ui_print(chat_t *c, const char *fmt, ...);
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
    r->mode = ROUTE_DIRECT;
    r->dht4 = r->dht6 = r->lan = r->portmap = r->nostr = 1;
    for (size_t i = 0; i < sizeof DEFAULT_RELAYS / sizeof DEFAULT_RELAYS[0]; i++)
        copy_str(r->relays[r->n_relays++], DEFAULT_RELAYS[i], NOSTR_URL_MAX);
    r->tor = TOR_DEFAULTS;
}

const char *routing_mode_name(route_mode_t m) { return m == ROUTE_TOR ? "tor" : "direct"; }
static void ui_print_colored(chat_t *c, const uint8_t rgb[3], const char *fmt, ...);
static void ui_chat(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text);

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

// Fullwidth ASCII, and other brackets and marks that pass for the ones the UI uses, as plain ASCII.
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

// What a nick looks like, for comparing: lookalikes as Latin, i/I/1/| as l, 0 as o, case and
// invisible characters ignored.
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
    for (int i = 0; i < MAX_PENDING_MSGS; i++)
        if (c->pending[i].used && c->pending[i].peer_slot == peer_slot(c, p)) pending_clear(&c->pending[i]);
    crypto_wipe(p, sizeof *p);
    while (c->peer_hi > 0 && !c->peers[c->peer_hi - 1].used) c->peer_hi--;
}

static void rekey_drop_overlap(peer_t *p) {
    crypto_wipe(&p->old_send, sizeof p->old_send);
    crypto_wipe(&p->old_recv, sizeof p->old_recv);
    p->old_until = 0.0;
}

// Every datagram leaves through here, to UDP, the relays or Tor as its address says. In Tor mode
// nothing goes out over UDP at all.
static void xmit(chat_t *c, sock_t sock, const void *data, size_t len, addr_t to) {
    switch (to.kind) {
        case ADDR_NOSTR:
            if (c->nostr) nostr_send(c->nostr, to, data, len, now_seconds());
            return;
        case ADDR_TOR:
            if (c->tor) tor_send(c->tor, to, data, len, now_seconds());
            return;
        default:
            if (c->route.mode == ROUTE_TOR || sock == SOCK_INVALID) return;
            net_send(sock, data, len, to);
    }
}

static void send_room(chat_t *c, const char *text, addr_t to, sock_t sock) {

    uint8_t frame[HANDSHAKE_BUF_LEN + 128];
    size_t len;
    if (room_seal(c->room_key, text, strlen(text), frame, sizeof frame, &len) != 0) return;
    // Relays and Tor streams take whole frames; only UDP needs them in pieces.
    if (len <= CHUNK_PAYLOAD || to.kind != ADDR_UDP) { xmit(c, sock, frame, len, to); return; }

    size_t count = (len + CHUNK_PAYLOAD - 1) / CHUNK_PAYLOAD;
    if (count > CHUNK_MAX) return;
    uint8_t id[4]; gen_random(id, 4);
    for (size_t i = 0; i < count; i++) {
        uint8_t pkt[CHUNK_HDR + CHUNK_PAYLOAD];
        size_t off = i * CHUNK_PAYLOAD;
        size_t n = len - off < CHUNK_PAYLOAD ? len - off : CHUNK_PAYLOAD;
        pkt[0] = CHUNK_MAGIC0; pkt[1] = CHUNK_MAGIC1;
        memcpy(pkt + 2, id, 4);
        pkt[6] = (uint8_t)i; pkt[7] = (uint8_t)count;
        memcpy(pkt + CHUNK_HDR, frame + off, n);
        xmit(c, sock, pkt, CHUNK_HDR + n, to);
    }
}

static double cover_interval(chat_t *c, const peer_t *p) {
    int live = live_count(c);
    if (live < 1) live = 1;
    double scale = (double)live / (COVER_MAX_RATE * COVER_INTERVAL);
    double iv = COVER_INTERVAL * (scale > 1.0 ? scale : 1.0);
    if (p && p->addr.kind == ADDR_NOSTR && iv < NOSTR_COVER_INTERVAL) iv = NOSTR_COVER_INTERVAL;
    return iv;
}

static ratchet_t *send_chain_for(peer_t *p) {
    if (!p->send_chain.started && p->old_until > 0.0 && p->old_send.started) return &p->old_send;
    return &p->send_chain;
}

static int frame_on_chain(ratchet_t *chain, const char *text, uint8_t *frame, size_t frame_cap,
                          size_t *len, uint32_t *index) {
    uint32_t idx = chain->index;
    ratchet_t advanced;
    uint8_t mk[32];
    int rc = -1;
    if (ratchet_peek(chain, idx, mk, &advanced) == 0
        && session_seal(mk, idx, text, strlen(text), frame, frame_cap, len) == 0) {
        *chain = advanced;
        *index = idx;
        rc = 0;
    }
    crypto_wipe(mk, sizeof mk);
    return rc;
}

static int send_peer_on(chat_t *c, peer_t *p, ratchet_t *chain, const char *text) {
    uint8_t frame[512]; size_t len; uint32_t idx;
    if (frame_on_chain(chain, text, frame, sizeof frame, &len, &idx) != 0) return -1;
    xmit(c, c->sock, frame, len, p->addr);
    crypto_wipe(frame, sizeof frame);

    double iv = cover_interval(c, p);
    p->next_cover = now_seconds() + iv + jitter(iv * 0.25);
    return 0;
}

static int send_peer(chat_t *c, peer_t *p, const char *text) { return send_peer_on(c, p, send_chain_for(p), text); }

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

// A message resend waits for the ack's round trip: relays take a good deal longer than UDP.
static double resend_delay(const peer_t *p) {
    return p->addr.kind == ADDR_NOSTR ? 4.0 + jitter(1.0) : 1.0 + jitter(0.5);
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
    snprintf(out, out_cap, "k\t%s\t%s\t%dr\t%d\t%s\t%s", c->nick, colorhex, c->persist, idtype, idpubhex, sighex);
}

// "v": our version and our executable's hash, which p checks against that version's release.
static void send_build(chat_t *c, peer_t *p) {
    if (!c->has_build) return;
    uint8_t proof[BUILD_HASH_LEN];
    build_proof(c->build_hash, c->my_id, p->id, proof);
    char proofhex[BUILD_HASH_LEN * 2 + 1]; hex_encode(proof, BUILD_HASH_LEN, proofhex);
    char msg[4 + MAX_VERSION + BUILD_HASH_LEN * 2];
    snprintf(msg, sizeof msg, "v\t%s\t%s", c->version, proofhex);
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
    // A room member in the middle could swap in its own key at a rekey. A peer that announces
    // rekeys told us its new key over the current session, which the middle can't touch, so a
    // new key it never announced is refused. After a short grace (the rk may still be on its
    // way) that gets a warning.
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

    // carry holds the old chains for the overlap and the kx that may have come early; it is
    // wiped on the way out.
    peer_t carry;
    int rejoin = 0;
    if (existing && existing->ok) { carry = *existing; rejoin = 1; }
    if (existing) forget_peer(c, existing);
    {
        int si = (int)(slot - c->peers) + 1;
        if (si > c->peer_hi) c->peer_hi = si;
    }
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
        // The same "v" comes again after the rekey: it needn't be checked, or warned about, twice.
        memcpy(slot->build_version, carry.build_version, sizeof slot->build_version);
        memcpy(slot->build_proof, carry.build_proof, BUILD_HASH_LEN);
        slot->build_state = carry.build_state;
        slot->ok = 1;
        slot->old_send = carry.send_chain;
        slot->old_recv = carry.recv_chain;
        slot->old_until = now + REKEY_OVERLAP;
        slot->next_cover = carry.next_cover;
        slot->announces_rekey = carry.announces_rekey;
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
// the relays, a Tor stream after the relays). A hi proves nothing - any member can send one - so
// the path doesn't change on it. Instead a session frame goes back that way: once the peer opens
// it, the path is proven on its side and it moves there, and its frames then move us.
static void probe_path(chat_t *c, peer_t *p, addr_t addr) {
    if (!p->ok || path_rank(addr) <= path_rank(p->addr)) return;
    uint8_t frame[512];
    size_t len;
    uint32_t idx;
    if (frame_on_chain(send_chain_for(p), "nop", frame, sizeof frame, &len, &idx) != 0) return;
    xmit(c, c->sock, frame, len, addr);
    crypto_wipe(frame, sizeof frame);
}

static void finish_kem_decap(chat_t *c, peer_t *p, const uint8_t ct[KEM_CT_LEN]) {
    // The initiator's chains come from its own encapsulation; only the responder takes a kx.
    if (we_initiate(c, p)) return;
    if (p->chain_confirmed) {
        // The initiator may send its kx while our side of the re-handshake still waits on a cookie.
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
        // Keep offering the kx until the peer's frames show it took it: the first copy may be lost,
        // or reach the peer before its side of the re-handshake is ready.
        if (we_initiate(c, p) && (fresh || !p->chain_confirmed)) send_kx(c, p, p->addr);
        send_k_now(c, p);
    }

}

#define PX_MAX_BODY (SESSION_PAD_TARGET - 2)

// How to reach p, for "px": its UDP address, or in Tor mode its onion address. Peers only
// reached through the relays have none to give: the relays introduce them by themselves.
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
    // The one who left may have been the room onion's latest publisher: point it back at us.
    if (was_ok && c->tor && c->tor_hosting && c->tor_republish_at == 0.0) c->tor_republish_at = now_seconds() + 5.0 + jitter(25.0);
}

// A version as a peer may name it: short, and nothing a terminal or a URL would read as more.
static int version_ok(const char *v) {
    size_t n = strlen(v);
    if (n == 0 || n > MAX_VERSION) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)v[i]) && v[i] != '.' && v[i] != '-') return 0;
    return 1;
}

// Compares p's build with the official binaries of the version it names, once their hashes are in.
static void check_build(chat_t *c, peer_t *p) {
    if (!c->builds) { p->build_state = BUILD_UNCHECKED; return; }
    // Its warning names p: wait for the join, which waits for the nick. chat_tick checks again.
    if (!p->announced) { p->build_state = BUILD_CHECKING; return; }
    uint8_t hashes[CHAT_BUILDS_MAX][BUILD_HASH_LEN];
    int n = c->builds(p->build_version, hashes, CHAT_BUILDS_MAX);
    if (n == CHAT_BUILDS_PENDING) { p->build_state = BUILD_CHECKING; return; }
    if (n == CHAT_BUILDS_UNKNOWN || n > CHAT_BUILDS_MAX) { p->build_state = BUILD_UNCHECKED; return; }
    int official = 0;
    for (int i = 0; i < n && !official; i++) {
        uint8_t want[BUILD_HASH_LEN];
        build_proof(hashes[i], p->id, c->my_id, want);
        official = crypto_equal(want, p->build_proof, BUILD_HASH_LEN) == 0;
    }
    p->build_state = official ? BUILD_OFFICIAL : BUILD_MODIFIED;
    if (official) return;
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    if (n == CHAT_BUILDS_NONE)
        ui_print(c, "* warning: %s runs a modified client - it says v%s, and there's no signed release of that",
                 name, p->build_version);
    else
        ui_print(c, "* warning: %s runs a modified client - it says v%s, but isn't a binary from that release",
                 name, p->build_version);
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
        // f[3] is the logging flag, then capability letters older builds ignore: "r" = sends rk.
        p->persists = (f[3][0] == '1');
        p->announces_rekey = strchr(f[3], 'r') != NULL;
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
        // A re-handshake (rekey, rejoin) re-sends k: say so when the identity behind it moves.
        if (had_source != IDENT_NONE) {
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            if (p->identity_source == IDENT_NONE) {
                ui_print(c, "* warning: %s no longer presents a signing identity", name);
            } else if (memcmp(had_pub, p->identity_pub, ID_SIGN_PUB_LEN) != 0) {
                char fphex[ID_FP_LEN * 2 + 1]; hex_encode(p->identity_fp, ID_FP_LEN, fphex);
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
    } else if (n == 2 && strcmp(f[0], "px") == 0) {
        char *item = f[1];
        for (int cnt = 0; item && *item && cnt < 12; cnt++) {
            char *comma = strchr(item, ',');
            if (comma) *comma = '\0';
            addr_t a;
            size_t il = strlen(item);
            if (il == TOR_ADDR_LEN + 6 && strcmp(item + TOR_ADDR_LEN, ".onion") == 0) {
                // Only Tor mode follows onion addresses; nothing else may ever look them up.
                item[TOR_ADDR_LEN] = '\0';
                if (c->tor && tor_target(c->tor, item, &a) == 0) add_candidate(c, a);
            } else if (c->route.mode == ROUTE_DIRECT && addr_parse_ip_port(item, &a) == 0) {
                // Numeric only: a hostname here would have us resolve whatever a peer names.
                add_candidate(c, a);
            }
            item = comma ? comma + 1 : NULL;
        }
    } else if (n == 2 && strcmp(f[0], "ta") == 0) {
        if (onion_valid(f[1])) copy_str(p->onion, f[1], sizeof p->onion);
    } else if (n == 3 && strcmp(f[0], "v") == 0) {
        uint8_t proof[BUILD_HASH_LEN];
        if (!version_ok(f[1]) || strlen(f[2]) != BUILD_HASH_LEN * 2
            || hex_decode(f[2], BUILD_HASH_LEN * 2, proof) != 0) return;
        // It comes with every k: only a different one needs checking again.
        if (p->build_state != BUILD_UNKNOWN && strcmp(p->build_version, f[1]) == 0
            && memcmp(p->build_proof, proof, BUILD_HASH_LEN) == 0) return;
        copy_str(p->build_version, f[1], sizeof p->build_version);
        memcpy(p->build_proof, proof, BUILD_HASH_LEN);
        check_build(c, p);
    } else if (n == 5 && strcmp(f[0], "m") == 0) {
        // Only p itself is authenticated here. f[2] and f[3] (origin id, nick) are whatever p says.
        uint8_t mid_raw[4], origin[ID_LEN];
        if (hex_decode(f[1], 8, mid_raw) != 0 || hex_decode(f[2], ID_LEN * 2, origin) != 0) return;
        char ack[16]; snprintf(ack, sizeof ack, "a\t%s", f[1]);
        send_peer(c, p, ack);
        int direct = memcmp(origin, p->id, ID_LEN) == 0;
        if (!direct) {
            if (memcmp(origin, c->my_id, ID_LEN) == 0) return;
            // The origin is connected to us, so its own copy will come: a relayed one could be forged.
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
        char shown[MAX_NICK + CHAT_NAME_LEN + 24];
        chat_peer_name(c, p, via);
        // A relayed nick is only the relayer's word, so it always carries the origin's id.
        if (direct) copy_str(shown, via, sizeof shown);
        else snprintf(shown, sizeof shown, "%s#%.8s (via %s)", nick, f[2], via);
        ui_chat(c, direct ? p->color : NULL, mentioned, shown, text);
        if (c->notify && (c->notify_mode == NOTIFY_ALL || (c->notify_mode == NOTIFY_MENTIONS && mentioned)))
            c->notify(c->ui, shown, text, mentioned);
        char rejoin[MSG_LINE_LEN];
        snprintf(rejoin, sizeof rejoin, "m\t%s\t%s\t%s\t%s", f[1], f[2], nick, text);
        for (int i = 0; i < c->peer_hi; i++) {
            peer_t *q = &c->peers[i];
            if (!q->used || !q->ok || q == p || memcmp(q->id, origin, ID_LEN) == 0) continue;
            send_peer(c, q, rejoin);
        }
    } else if (n == 2 && strcmp(f[0], "a") == 0) {
        for (int i = 0; i < MAX_PENDING_MSGS; i++)
            if (c->pending[i].used && c->pending[i].peer_slot == peer_slot(c, p) && strcmp(c->pending[i].mid, f[1]) == 0)
                pending_clear(&c->pending[i]);
    } else if (n == 1 && strcmp(f[0], "nop") == 0) {

    } else if (n == 1 && strcmp(f[0], "bye") == 0) {
        drop_peer(c, p, "left");
    }
    (void)now;
}

// Our own hi came back from addr, so it's one of ours: never a candidate. Kept once each, so
// replays of it can't fill the list.
static void note_self_addr(chat_t *c, addr_t addr) {
    // A relayed address stands for a peer, or a Tor stream: never ours to rule out.
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
        // Anyone who recorded a hi can replay it from anywhere. Take one on trust only if it changes
        // nothing; new keys, or a new address mid-handshake, must answer a cookie first.
        int trusted = existing && existing->keygen == c->keygen && memcmp(existing->pub, pub, PUB_LEN) == 0
                      && (existing->ok || addr_equal(existing->addr, addr));
        if (trusted) {
            connect_peer(c, peer_id, addr, pub, kem_pub, now);
            peer_t *p = find_peer_by_id(c, peer_id);
            if (p) probe_path(c, p, addr);
        } else if (existing || !(c->once && c->once_used)) {
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
        // A member announcing itself on the relays. Someone we already hear from directly
        // needs nothing; anyone else gets a hi through the relays.
        uint8_t peer_id[ID_LEN];
        if (hex_decode(f[1], 32, peer_id) != 0) return;
        peer_t *known = find_peer_by_id(c, peer_id);
        if (known && known->ok && now - known->seen < UDP_STALE) return;
        add_candidate(c, addr_virtual(ADDR_NOSTR, peer_id));
    } else if (n == 3 && strcmp(f[0], "lan") == 0 && strcmp(f[1], my_idhex) != 0) {
        c->st.lan++;
        int port = atoi(f[2]);
        if (port > 0 && port <= 65535) {
            addr_t a = addr; a.port = (uint16_t)port;
            add_candidate(c, a);
            if (c->net_verbose) { char as[ADDR_STR_LEN]; addr_to_string(a, as); ui_print(c, "* lan beacon - candidate %s added", as); }
        }
    }
}

static void on_frame(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now);

static int on_chunk(chat_t *c, const uint8_t *d, size_t len, addr_t addr, double now) {
    if (len <= CHUNK_HDR || len > CHUNK_HDR + CHUNK_PAYLOAD) return 0;
    if (d[0] != CHUNK_MAGIC0 || d[1] != CHUNK_MAGIC1) return 0;
    int idx = d[6], count = d[7];
    if (count < 2 || count > CHUNK_MAX || idx >= count) return 0;
    size_t plen = len - CHUNK_HDR;
    if (idx < count - 1 && plen != CHUNK_PAYLOAD) return 0;
    c->st.rx_chunks++;

    reasm_t *slot = NULL, *oldest = &c->reasm[0];
    for (int i = 0; i < REASM_SLOTS; i++) {
        reasm_t *r = &c->reasm[i];
        if (r->used && now - r->born > REASM_TTL) r->used = 0;
        if (r->used && addr_equal(r->from, addr) && memcmp(r->id, d + 2, 4) == 0 && r->count == count) { slot = r; break; }
        if (r->born < oldest->born) oldest = r;
    }
    if (!slot) {
        for (int i = 0; i < REASM_SLOTS; i++) if (!c->reasm[i].used) { slot = &c->reasm[i]; break; }
        if (!slot) slot = oldest;
        memset(slot, 0, sizeof *slot);
        slot->used = 1; slot->from = addr; memcpy(slot->id, d + 2, 4);
        slot->count = count; slot->born = now;
    }
    memcpy(slot->buf + (size_t)idx * CHUNK_PAYLOAD, d + CHUNK_HDR, plen);
    slot->got |= 1u << idx;
    if (idx == count - 1) slot->last_len = plen;
    if (slot->got != (1u << count) - 1) return 1;

    uint8_t whole[CHUNK_MAX * CHUNK_PAYLOAD];
    size_t total = (size_t)(count - 1) * CHUNK_PAYLOAD + slot->last_len;
    memcpy(whole, slot->buf, total);
    slot->used = 0;
    c->st.rx_chunk_done++;
    on_frame(c, whole, total, addr, now);
    return 1;
}

static void note_source(chat_t *c, addr_t a) {
    net_stats_t *st = &c->st;
    for (int i = 0; i < st->n_src; i++) if (addr_equal(st->src[i], a)) { st->src_n[i]++; return; }
    int slot = st->n_src < 6 ? st->n_src++ : 5;
    st->src[slot] = a; st->src_n[slot] = 1;
}

static void on_packet(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now) {
    c->st.rx++;
    note_source(c, addr);
    if (on_chunk(c, data, len, addr, now)) return;
    on_frame(c, data, len, addr, now);
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

// "* NICK (verified) joined": once p's nick and identity are known, which "k" brings. It's the
// first frame p sends, but it can be lost or overtaken, and another frame opening first would
// otherwise announce an "anon (unverified)".
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
    // A peer that dropped and came back ran a fresh handshake, with nothing tying it to
    // the one that may have been verified. Someone who forced the drop could be in it.
    for (size_t g = 0; g < sizeof c->gone / sizeof c->gone[0]; g++) {
        if (!c->gone[g].used || memcmp(c->gone[g].id, p->id, ID_LEN) != 0) continue;
        c->gone[g].used = 0;
        if (memcmp(c->gone[g].vfy, p->vfy, VERIFY_LEN) == 0) continue;
        char was[VERIFY_LEN * 2 + 1], now_hex[VERIFY_LEN * 2 + 1];
        hex_encode(c->gone[g].vfy, VERIFY_LEN, was); hex_encode(p->vfy, VERIFY_LEN, now_hex);
        ui_print(c, "* %s reconnected with a new verify code (was %s, now %s) - if you had compared "
                    "codes with them, compare the new one", name, was, now_hex);
    }
}

static void on_frame(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now) {
    uint8_t plain[HANDSHAKE_BUF_LEN + 128];
    size_t plain_len;
    if (room_unseal(c->room_key, data, len, plain, sizeof plain - 1, &plain_len) == 0) {
        plain[plain_len] = '\0';
        c->st.room_ok++;
        on_room(c, (char *)plain, addr, now);
        return;
    }
    // Checked before the peer loop: a frame no sealer could make shouldn't cost ratchet steps.
    if (sealed_len_ok(len, SESSION_HEADER_LEN, SESSION_PAD_TARGET)) {
        uint32_t index = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
        int hit = -1, fast = -1, on_old = 0;
        for (int i = 0; i < c->peer_hi; i++)
            if (c->peers[i].used && addr_equal(c->peers[i].addr, addr)) { fast = i; break; }
        if (fast >= 0 && peer_try_unseal(&c->peers[fast], data, len, index, RATCHET_MAX_SKIP, plain,
                                          sizeof plain - 1, &plain_len, &on_old))
            hit = fast;
        if (hit < 0) {
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
            // The best path that works: direct UDP, then Tor (end to end, no relay in the middle),
            // then the relays. A worse path takes over only once the better one goes quiet.
            if (!addr_equal(p->addr, addr)
                && (path_rank(addr) >= path_rank(p->addr) || now - p->path_seen[p->addr.kind] > UDP_STALE))
                p->addr = addr;
            p->path_seen[addr.kind] = now;
            p->seen = now;
            int was_pending = !p->ok;
            p->ok = 1;
            if (was_pending) p->ok_since = now;
            on_session(c, p, (char *)plain, now);
            if (!p->used) return;
            if (was_pending) {
                c->st.connects++;

                send_k_now(c, p);
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
            return;
        }
    }
    c->st.other++;
    if (c->dht_on && addr.kind == ADDR_UDP) dht_on_packet(&c->dht, data, len, addr, dht_candidate_cb, c);
}

int chat_sockets(chat_t *c, sock_t out[CHAT_MAX_SOCKS]) {
    int k = 0;
    if (c->sock != SOCK_INVALID) out[k++] = c->sock;
    if (c->lan_sock != SOCK_INVALID) out[k++] = c->lan_sock;
    // The relays' and Tor's sockets only wake the loop; chat_tick does their I/O.
    if (c->nostr) k += nostr_sockets(c->nostr, out + k, CHAT_MAX_SOCKS - k);
    if (c->tor) k += tor_sockets(c->tor, out + k, CHAT_MAX_SOCKS - k);
    return k;
}

int chat_started(const chat_t *c) { return c->started; }

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
        on_packet(c, buf, (size_t)n, from, now);
    }
}

static int pending_any(const chat_t *c) {
    for (int i = 0; i < MAX_PENDING_MSGS; i++) if (c->pending[i].used) return 1;
    return 0;
}

static void send_rk(chat_t *c, peer_t *p, ratchet_t *chain) {
    char pubhex[PUB_LEN * 2 + 1]; hex_encode(c->keys.pub, PUB_LEN, pubhex);
    char rk[8 + PUB_LEN * 2];
    snprintf(rk, sizeof rk, "rk\t%s", pubhex);
    send_peer_on(c, p, chain, rk);
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
        // Announce the new key over the current session before the hi that uses it.
        if (p->ok) { send_rk(c, p, send_chain_for(p)); p->next_rk = now + RK_RESEND; }
        send_room(c, c->hi_msg, p->addr, c->sock);
        p->hello_tries = 0;
        p->next_hello = now + retry_delay(0);
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
    // Tor published our onion (again, after a restart of tor): peers learn it for px.
    if (me[0] && strcmp(me, c->told_onion) != 0) {
        copy_str(c->told_onion, me, sizeof c->told_onion);
        for (int i = 0; i < c->peer_hi; i++)
            if (c->peers[i].used && c->peers[i].ok) send_onion(c, &c->peers[i]);
    }
    if (!c->tor_hosting && (c->ever_connected || now - c->start > TOR_HOST_AFTER)) {
        c->tor_hosting = 1;
        tor_host_room(c->tor, -1);
        // Knocking on our own slot from now on would only reach ourselves.
        addr_t mine = tor_room_target(c->tor, tor_hosted_slot(c->tor));
        for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used && addr_equal(c->cands[i].addr, mine)) c->cands[i].used = 0;
    }
    if (c->tor_republish_at > 0.0 && now >= c->tor_republish_at) {
        c->tor_republish_at = 0.0;
        tor_republish_room(c->tor);
    }
}

void chat_tick(chat_t *c, double now) {
    transports_step(c, now);
    if (c->tor) tor_tick(c, now);
    if (c->pm) {
        portmap_step(c->pm, now);
        // With a mapping up, the DHT is told the router's forwarded port, not whatever source
        // port it sees.
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
        if (dht_step(&c->dht, c->sock, now, dht_candidate_cb, c) && !c->dht_summary_printed) {
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
        // Reached already, at this address or (relays) under this id: nothing left to try.
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
    for (int i = 0; i < MAX_PENDING_MSGS; i++) {
        pending_msg_t *pm = &c->pending[i];
        if (!pm->used) continue;
        if (now >= pm->next_retry) {
            peer_t *p = &c->peers[pm->peer_slot];
            if (!p->used || !p->ok || pm->tries >= 5) pending_clear(pm);
            else { send_peer(c, p, pm->text); pm->tries++; pm->next_retry = now + resend_delay(p); }
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
    if (now >= c->next_alive) {
        c->next_alive = now + KEEPALIVE + jitter(3.0);
        int sent_to = 0;
        for (int i = 0; i < c->peer_hi; i++) {
            peer_t *p = &c->peers[i];
            if (!p->used || !p->ok) continue;
            // Its path gone quiet (UDP, or a Tor stream): try the relays. Frames that come back
            // through them move the peer there.
            if (c->nostr && p->addr.kind != ADDR_NOSTR && now - p->seen > UDP_STALE) {
                p->addr = addr_virtual(ADDR_NOSTR, p->id);
                if (c->net_verbose) ui_print(c, "* %s went quiet - trying the relays", p->nick);
            }
            // Relayed peers keep alive on cover traffic: a hi there costs every member an event.
            if (p->addr.kind == ADDR_NOSTR) continue;
            send_room(c, c->hi_msg, p->addr, c->sock);
            sent_to++;
        }
        if (c->net_verbose && sent_to > 0) ui_print(c, "* keepalive hi -> %d connected peer%s", sent_to, sent_to == 1 ? "" : "s");
        for (int i = 0; i < c->n_static; i++) add_candidate(c, c->static_peers[i]);
        if (c->tor) knock_room_slots(c);
    }
    if (c->lan_sock != SOCK_INVALID && now >= c->next_lan) {
        c->next_lan = now + 5 + jitter(2.0);
        if (c->net_verbose) ui_print(c, "* lan beacon sent");
        char idhex[33]; hex_encode(c->my_id, ID_LEN, idhex);
        char beacon[64]; snprintf(beacon, sizeof beacon, "lan\t%s\t%u", idhex, (unsigned)c->port);
        send_room(c, beacon, addr_broadcast_lan(LAN_PORT), c->lan_sock);
        send_room(c, beacon, addr_loopback(LAN_PORT), c->lan_sock);
    }
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used) continue;

        // Until the peer re-handshakes with our new key, keep announcing it on the chain it can still read.
        if (p->ok && p->announces_rekey && c->keygen > 1 && now >= p->next_rk
            && (p->keygen != c->keygen || !p->chain_confirmed)) {
            p->next_rk = now + RK_RESEND;
            if (p->keygen != c->keygen) send_rk(c, p, send_chain_for(p));
            else if (p->old_until > 0.0 && p->old_send.started) send_rk(c, p, &p->old_send);
        }
        if (p->ok && (p->build_state == BUILD_CHECKING || p->build_state == BUILD_UNCHECKED)) check_build(c, p);
        if (p->old_until > 0.0 && now > p->old_until) rekey_drop_overlap(p);
        if (p->ok && now - p->seen > PEER_TIMEOUT) drop_peer(c, p, "timed out");
    }

    if (now >= c->next_rekey) {
        if (c->rekey_due == 0.0) c->rekey_due = now;
        if (!pending_any(c) || now - c->rekey_due > REKEY_DRAIN_GRACE) {
            session_rekey(c, now);
            c->rekey_due = 0.0;
            c->next_rekey = now + REKEY_INTERVAL + jitter(REKEY_INTERVAL * 0.2);
        }
    }

    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        if (!p->announced && now - p->ok_since >= JOIN_WAIT) announce_join(c, p);
        double cover_iv = cover_interval(c, p);
        if (p->next_cover == 0.0) { p->next_cover = now + jitter(cover_iv); continue; }
        if (now >= p->next_cover) send_peer(c, p, "nop");
    }
    if (!c->created && !c->warned_lonely && !c->ever_connected && now - c->start > LONELY_HINT_AFTER) {
        c->warned_lonely = 1;
        ui_print(c, "* nobody has answered for this session yet - check the id and password with "
                     "whoever shared them, or they may not have started their app yet");
        // Direct and Tor sessions only meet on the relays: without them the room splits in two
        // without a word.
        if (!c->nostr)
            ui_print(c, "* Nostr relays are off here, so members using %s routing can't reach you - :set nostr on turns them on%s",
                     c->route.mode == ROUTE_TOR ? "direct" : "Tor", c->route.mode == ROUTE_TOR ? " (through Tor)" : "");
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
        char ns[300] = "off - direct peers can't reach this session";
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
    if (c->route.mode == ROUTE_DIRECT) {
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
        case BUILD_OFFICIAL:  snprintf(out, cap, "official v%s", p->build_version); break;
        case BUILD_MODIFIED:  snprintf(out, cap, "modified client (says v%s)", p->build_version); break;
        case BUILD_CHECKING:  snprintf(out, cap, "v%s, checking the build", p->build_version); break;
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
        char vfyhex[VERIFY_LEN * 2 + 1]; hex_encode(p->vfy, VERIFY_LEN, vfyhex);
        char build[64]; chat_build_label(p, build, sizeof build);
        ui_print(c, "*   %s#%s (verify %s, %s, %s%s)", p->nick, idhex, vfyhex, chat_verify_label(p->identity_state),
                 build, p->persists ? ", logging" : "");
    }
    if (n == 0) ui_print(c, "* nobody else yet");
    return CMD_OK;
}

static cmd_result_t cmd_verify(void *ctx, const char *arg) {
    chat_t *c = ctx;
    if (!*arg) {
        ui_print(c, "* usage: :verify NICK - shows their identity fingerprint to read out and compare");
        return CMD_OK;
    }
    int found = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok || !nick_ieq(p->nick, arg)) continue;
        found = 1;
        char idhex[9]; hex_encode(p->id, 4, idhex);
        if (p->identity_source == IDENT_NONE) {
            ui_print(c, "* %s#%s presented no identity - nothing to verify", p->nick, idhex);
        } else {
            char fphex[ID_FP_LEN * 2 + 1]; hex_encode(p->identity_fp, ID_FP_LEN, fphex);
            ui_print(c, "* %s#%s fingerprint %s (%s) - read it out over another channel to be sure it's really them",
                     p->nick, idhex, fphex, chat_verify_label(p->identity_state));
        }
    }
    if (!found) ui_print(c, "* no online peer named '%s'", arg);
    return CMD_OK;
}

static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };
static const char *const NET_LOG_NAMES[] = { "normal", "verbose" };

static int name_index(const char *const *names, int n, const char *s) {
    for (int i = 0; i < n; i++) if (strcmp(names[i], s) == 0) return i;
    return -1;
}

// The --simple :set, for the settings a session holds itself. The full-screen UI answers :set on
// its own, with the settings page behind it.
static cmd_result_t cmd_set(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char key[CMD_WORD_MAX];
    const char *value = cmd_parse(arg, key);
    char hex[7]; color_to_hex(c->my_color, hex);
    if (!key[0]) {
        ui_print(c, "* nick %s, colour #%s, notify %s, net %s - :set NAME VALUE changes one", c->nick, hex,
                 NOTIFY_NAMES[c->notify_mode], NET_LOG_NAMES[c->net_verbose != 0]);
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
    if (c->route.mode == ROUTE_TOR) {
        ui_print(c, "* this session runs over Tor and has no udp port");
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
    // Peers follow the source address of our next hi; the DHT re-announces from the new socket.
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

const command_t CHAT_COMMANDS[] = {
    { "help",       NULL,     NULL,              "list commands",                                   cmd_help },
    { "peers",      NULL,     NULL,              "who is online, with verify codes and builds",     cmd_peers },
    { "verify",     NULL,     "NICK",            "show a peer's identity fingerprint",              cmd_verify },
    { "net",        NULL,     NULL,              "network report and diagnosis",                    cmd_net },
    { "port",       NULL,     "[N]",             "show or change this session's udp port",          cmd_port },
    { "set",        NULL,     "[NAME [VALUE]]",  "show or change nick, colour, notify or net",      cmd_set },
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
    int sent = 0, s = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok || send_peer(c, p, text) != 0) continue;
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
        pm->next_retry = now + resend_delay(p);
    }
    if (!sent) ui_print(c, "* nobody else is here yet, message not delivered");
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
    on_packet((chat_t *)ctx, buf, len, from, now);
}

// The room slots someone else may publish: always worth a hi, since members publishing different
// slots only find each other by knocking.
static void knock_room_slots(chat_t *c) {
    for (int i = 0; i < TOR_ROOM_SLOTS; i++)
        if (i != tor_hosted_slot(c->tor)) add_candidate(c, tor_room_target(c->tor, i));
}

static void start_dht(chat_t *c) {
    if (c->dht_on || c->sock == SOCK_INVALID || !(c->route.dht4 || c->route.dht6)) return;
    dht_init(&c->dht, c->infohash, c->port, c->route.dht4, c->route.dht6);
    dht_start_bootstrap_resolve(&c->dht);
    c->dht_on = 1;
}

static void start_nostr(chat_t *c) {
    if (c->nostr || !c->route.nostr || c->route.n_relays == 0) return;
    uint8_t tag_key[NOSTR_KEY_LEN], wrap_key[NOSTR_KEY_LEN];
    derive_nostr_keys(c->master, tag_key, wrap_key);
    // In Tor mode the relays are where direct peers can be met, and they're only ever reached
    // through Tor: its SOCKS port, or nothing at all until chat has one.
    const char *proxy = c->route.mode == ROUTE_TOR ? c->route.tor.socks : NULL;
    c->nostr = nostr_new(tag_key, wrap_key, c->my_id, (const char (*)[NOSTR_URL_MAX])c->route.relays, c->route.n_relays,
                         proxy, module_deliver, module_log, c);
    crypto_wipe(tag_key, sizeof tag_key);
    crypto_wipe(wrap_key, sizeof wrap_key);
    c->next_beacon = 0;
}

static void start_direct(chat_t *c) {
    if (c->route.lan) c->lan_sock = net_udp_open(LAN_PORT, NET_REUSE, NULL);
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
    // The relays apply in both modes: a Tor session reaches them through Tor.
    c->route.nostr = r->nostr;
    memcpy(c->route.relays, r->relays, sizeof r->relays);
    c->route.n_relays = r->n_relays;
    if (c->nostr && (!r->nostr || relays_differ(&was, r))) {
        // Peers reached only through the relays move back to waiting for another path; they
        // time out if none comes.
        nostr_free(c->nostr);
        c->nostr = NULL;
    }
    start_nostr(c);
    if (c->route.mode == ROUTE_TOR) return later;
    c->route.dht4 = r->dht4; c->route.dht6 = r->dht6; c->route.lan = r->lan;
    c->route.portmap = r->portmap;

    if (r->lan && c->lan_sock == SOCK_INVALID) c->lan_sock = net_udp_open(LAN_PORT, NET_REUSE, NULL);
    if (!r->lan && c->lan_sock != SOCK_INVALID) { net_close(c->lan_sock); c->lan_sock = SOCK_INVALID; }

    if (!r->dht4 && !r->dht6) c->dht_on = 0;
    else if (!c->dht_on) start_dht(c);
    else if (was.dht4 != r->dht4 || was.dht6 != r->dht6) {
        c->dht.want[DHT_V4] = r->dht4;
        c->dht.want[DHT_V6] = r->dht6;
        // The bootstrap list only holds the families that were wanted: look it up again.
        DHT_STORE(&c->dht.n_boot, 0);
        c->dht.next_resolve = 0;
        c->dht.next_lookup = 0;
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

void chat_route_summary(const chat_t *c, char *out, size_t cap) {
    if (c->route.mode == ROUTE_TOR) {
        size_t p = (size_t)snprintf(out, cap, "tor%s", c->tor && tor_my_onion(c->tor)[0] ? "" : " (waiting)");
        if (c->nostr && p < cap) snprintf(out + p, cap - p, "+nostr %d/%d", nostr_relays_up(c->nostr), nostr_relay_total(c->nostr));
        return;
    }
    size_t p = (size_t)snprintf(out, cap, "direct");
    if (c->pm && portmap_mapped(c->pm, NULL) && p < cap) p += (size_t)snprintf(out + p, cap - p, "+map");
    if (c->nostr && p < cap) snprintf(out + p, cap - p, "+nostr %d/%d", nostr_relays_up(c->nostr), nostr_relay_total(c->nostr));
}

void chat_init(chat_t *c, const chat_opts_t *o, chat_print_fn print, chat_notify_fn notify, void *ui) {
    memset(c, 0, sizeof *c);
    // Locked before any key lands there. Best effort: a low RLIMIT_MEMLOCK only means they may be
    // swapped. The peers hold their chain keys.
    crypto_lock((uint8_t *)c + SECRETS_OFFSET, SECRETS_LEN);
    crypto_lock(c->peers, sizeof c->peers);
    c->print = print;
    c->notify = notify;
    c->ui = ui;
    set_own_nick(c, o->nick);
    copy_str(c->session_name, o->session_name, sizeof c->session_name);
    c->created = o->created;
    c->route = o->route;
    c->once = o->once;
    c->notify_mode = o->notify_mode;

    if (o->has_color) memcpy(c->my_color, o->color, 3);
    else {
        uint8_t r; gen_random(&r, 1);
        const named_color_t *pick = &COLOR_PALETTE[r % COLOR_PALETTE_N];
        c->my_color[0] = pick->r; c->my_color[1] = pick->g; c->my_color[2] = pick->b;
    }

    c->identity_source = o->identity_source;
    if (c->identity_source != IDENT_NONE) c->identity = o->identity;

    c->has_build = o->has_build && version_ok(o->version);
    if (c->has_build) {
        copy_str(c->version, o->version, sizeof c->version);
        memcpy(c->build_hash, o->build_hash, BUILD_HASH_LEN);
    }
    c->builds = o->builds;

    gen_random(c->my_id, ID_LEN);
    gen_keypair(&c->keys);
    kem_gen_keypair(&c->kem_keys);
    c->keygen = 1;
    gen_random(c->cookie_secret, 32);
    derive_master(o->password, o->session_name, c->master);
    derive_room_key(c->master, c->room_key);
    derive_fingerprint(c->master, c->fingerprint);
    refresh_hi(c);

    derive_dht_infohash(c->master, c->infohash);
    c->sock = c->lan_sock = SOCK_INVALID;
    if (c->route.mode == ROUTE_TOR) {
        // No UDP socket at all: whatever goes out, goes through Tor.
        uint8_t room_keys[TOR_ROOM_SLOTS][64], room_pubs[TOR_ROOM_SLOTS][32];
        for (int i = 0; i < TOR_ROOM_SLOTS; i++) derive_tor_room_key(c->master, i, room_keys[i], room_pubs[i]);
        c->tor = tor_new(&c->route.tor, (const uint8_t (*)[64])room_keys, (const uint8_t (*)[32])room_pubs,
                         module_deliver, module_log, c);
        crypto_wipe(room_keys, sizeof room_keys);
        c->started = c->tor != NULL;
        if (c->tor && c->created) { tor_host_room(c->tor, 0); c->tor_hosting = 1; }
        if (c->tor) { knock_room_slots(c); start_nostr(c); }
    } else {
        // Without the main socket the caller gives up on this session, so nothing else is started.
        c->sock = net_udp_open(o->port, NET_DUAL, &c->port);
        c->started = c->sock != SOCK_INVALID;
        if (c->started) start_direct(c);
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
}

void chat_shutdown(chat_t *c) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) send_peer(c, &c->peers[i], "bye");
    nostr_free(c->nostr);
    tor_free(c->tor);
    portmap_free(c->pm);
    net_close(c->sock);
    net_close(c->lan_sock);
    if (c->log_fp) fclose(c->log_fp);

    crypto_unlock((uint8_t *)c + SECRETS_OFFSET, SECRETS_LEN);
    crypto_unlock(c->peers, sizeof c->peers);

    crypto_wipe(c, sizeof *c);
}

#include <stdarg.h>

static void emit_line(chat_t *c, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len) {
    c->print(c->ui, hhmm, text, rgb, flags, color_len);
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

static void ui_chat(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text) {
    char msg[2200];
    int head = snprintf(msg, sizeof msg, "%s%s:", mention ? "@ " : "", name);
    snprintf(msg + head, sizeof msg - (size_t)head, " %s", text);
    char hhmm[6]; current_hhmm(hhmm);
    emit_line(c, hhmm, msg, rgb, LINE_CHAT | (mention ? LINE_MENTION : 0u), head);
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
