// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "chat.h"
#include "util.h"
#include "platform.h"
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

void chat_peer_name(const chat_t *c, const peer_t *p, char out[CHAT_NAME_LEN]) {
    char mine[4 * MAX_NICK + 1], other[4 * MAX_NICK + 1];
    nick_skeleton(p->nick, mine, sizeof mine);
    nick_skeleton(c->nick, other, sizeof other);
    int clash = strcmp(mine, other) == 0;
    for (int i = 0; i < c->peer_hi && !clash; i++) {
        const peer_t *q = &c->peers[i];
        if (q == p || !q->used || !q->ok) continue;
        nick_skeleton(q->nick, other, sizeof other);
        clash = strcmp(mine, other) == 0;
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

static void forget_peer(chat_t *c, peer_t *p) {
    for (int i = 0; i < MAX_PENDING_MSGS; i++)
        if (c->pending[i].used && c->pending[i].peer_slot == peer_slot(c, p)) c->pending[i].used = 0;
    memset(p, 0, sizeof *p);
    while (c->peer_hi > 0 && !c->peers[c->peer_hi - 1].used) c->peer_hi--;
}

static void rekey_drop_overlap(peer_t *p) {
    crypto_wipe(&p->old_send, sizeof p->old_send);
    crypto_wipe(&p->old_recv, sizeof p->old_recv);
    p->old_until = 0.0;
}

static void send_room(chat_t *c, const char *text, addr_t to, sock_t sock) {

    uint8_t frame[HANDSHAKE_BUF_LEN + 128];
    size_t len;
    if (room_seal(c->room_key, text, strlen(text), frame, sizeof frame, &len) != 0) return;
    if (len <= CHUNK_PAYLOAD) { net_send(sock, frame, len, to); return; }

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
        net_send(sock, pkt, CHUNK_HDR + n, to);
    }
}

static double cover_interval(chat_t *c) {
    int live = live_count(c);
    if (live < 1) live = 1;
    double scale = (double)live / (COVER_MAX_RATE * COVER_INTERVAL);
    return COVER_INTERVAL * (scale > 1.0 ? scale : 1.0);
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

static int frame_for_peer(peer_t *p, const char *text, uint8_t *frame, size_t frame_cap,
                          size_t *len, uint32_t *index) {
    return frame_on_chain(send_chain_for(p), text, frame, frame_cap, len, index);
}

static void send_peer_on(chat_t *c, peer_t *p, ratchet_t *chain, const char *text) {
    uint8_t frame[512]; size_t len; uint32_t idx;
    if (frame_on_chain(chain, text, frame, sizeof frame, &len, &idx) != 0) return;
    net_send(c->sock, frame, len, p->addr);
    crypto_wipe(frame, sizeof frame);

    double iv = cover_interval(c);
    p->next_cover = now_seconds() + iv + jitter(iv * 0.25);
}

static void send_peer(chat_t *c, peer_t *p, const char *text) { send_peer_on(c, p, send_chain_for(p), text); }

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

static void send_k_now(chat_t *c, peer_t *p) {
    char k[8 + MAX_NICK + 8 + 5 + 4 + 65 + 129];
    build_k_message(c, p, k, sizeof k);
    send_peer(c, p, k);
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
                        "intercepting; if it continues, compare /peers verify codes over another channel", name, name);
        }
        return NULL;
    }
    if (pending_peer_count(c) >= MAX_PENDING_PEERS || live_count(c) >= MAX_PEERS) return NULL;
    uint8_t shared[32];
    keypair_t mine = c->keys;
    if (ecdh_shared(&mine, their_pub, shared) != 0) return NULL;
    uint8_t prk_partial[32];
    session_prk(c->master, shared, c->keys.pub, c->my_id, their_pub, peer_id, prk_partial);

    peer_t *slot = NULL;
    peer_t *existing = find_peer_by_id(c, peer_id);

    peer_t carry;
    int rejoin = 0;
    if (existing && existing->ok) { carry = *existing; rejoin = 1; }
    if (existing) { forget_peer(c, existing); slot = existing; }
    else {
        for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) if (!c->peers[i].used) { slot = &c->peers[i]; break; }
        if (!slot) return NULL;
    }
    {
        int si = (int)(slot - c->peers) + 1;
        if (si > c->peer_hi) c->peer_hi = si;
    }
    memset(slot, 0, sizeof *slot);
    slot->used = 1;
    memcpy(slot->id, peer_id, ID_LEN);
    strcpy(slot->nick, "anon");
    slot->addr = addr;
    slot->seen = slot->born = now;
    slot->next_hello = now + retry_delay(0);
    slot->hello_tries = 0;
    slot->ok = 0;
    slot->keygen = c->keygen;
    memcpy(slot->pub, their_pub, PUB_LEN);
    memcpy(slot->kem_pub, their_kem_pub, KEM_PUB_LEN);
    if (rejoin) {
        copy_str(slot->nick, carry.nick, sizeof slot->nick);
        memcpy(slot->color, carry.color, 3);
        slot->persists = carry.persists;
        slot->identity_source = carry.identity_source;
        slot->identity_state = carry.identity_state;
        memcpy(slot->identity_pub, carry.identity_pub, ID_SIGN_PUB_LEN);
        memcpy(slot->identity_fp, carry.identity_fp, ID_FP_LEN);
        memcpy(slot->vfy, carry.vfy, VERIFY_LEN);
        slot->vfy_set = carry.vfy_set;
        slot->ok = 1;
        slot->old_send = carry.send_chain;
        slot->old_recv = carry.recv_chain;
        slot->old_until = now + REKEY_OVERLAP;
        slot->next_cover = carry.next_cover;
        slot->announces_rekey = carry.announces_rekey;
    }

    if (memcmp(c->my_id, peer_id, ID_LEN) < 0) {
        uint8_t kem_ss[KEM_SS_LEN];
        if (kem_encapsulate(their_kem_pub, slot->kem_ct, kem_ss) != 0) { memset(slot, 0, sizeof *slot); return NULL; }
        uint8_t prk[32];
        session_prk_finish(prk_partial, kem_ss, prk);
        ratchet_seed(prk, c->keys.pub, &slot->send_chain);
        ratchet_seed(prk, their_pub, &slot->recv_chain);
        if (!slot->vfy_set) { session_verify_code(prk, slot->vfy); slot->vfy_set = 1; }
        crypto_wipe(prk, sizeof prk);
    } else {
        memcpy(slot->prk_partial, prk_partial, 32);
        if (rejoin && carry.kx_early) finish_kem_decap(c, slot, carry.kem_ct);
    }
    *fresh = 1;
    return slot;
}

static int we_initiate(const chat_t *c, const peer_t *p) { return memcmp(c->my_id, p->id, ID_LEN) < 0; }

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

static void introduce(chat_t *c, peer_t *newp) {
    char list[PX_MAX_BODY];
    size_t pos = 0;
    int n = 0;
    for (int i = 0; i < c->peer_hi && n < 12; i++) {
        peer_t *q = &c->peers[i];
        if (!q->used || !q->ok || q == newp) continue;
        char as[ADDR_STR_LEN]; addr_to_string(q->addr, as);
        size_t need = strlen(as) + (n ? 1 : 0);
        if (pos + need + 4 > PX_MAX_BODY) break;
        pos += (size_t)snprintf(list + pos, sizeof(list) - pos, "%s%s", n ? "," : "", as);
        n++;
    }
    if (n > 0) {
        char msg[PX_MAX_BODY + 8];
        snprintf(msg, sizeof msg, "px\t%s", list);
        send_peer(c, newp, msg);
    }
    char newp_addr[ADDR_STR_LEN]; addr_to_string(newp->addr, newp_addr);
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *q = &c->peers[i];
        if (!q->used || !q->ok || q == newp) continue;
        char msg[16 + ADDR_STR_LEN];
        snprintf(msg, sizeof msg, "px\t%s", newp_addr);
        send_peer(c, q, msg);
    }
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
}

static void on_session(chat_t *c, peer_t *p, char *plain, double now) {
    char *f[MAX_FIELDS];
    int n = split_tabs(plain, f, MAX_FIELDS);
    if (n == 7 && strcmp(f[0], "k") == 0) {
        chat_clean_nick(f[1], p->nick);
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
                ui_print(c, "* warning: %s now presents a different signing identity (fingerprint %s) - /verify it again",
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
        chat_clean_nick(f[1], p->nick);
    } else if (n == 2 && strcmp(f[0], "px") == 0) {
        char *item = strtok(f[1], ",");
        int cnt = 0;
        while (item && cnt < 12) {
            addr_t a;
            // Numeric only: a hostname here would have us resolve whatever a peer names.
            if (addr_parse_ip_port(item, &a) == 0) add_candidate(c, a);
            item = strtok(NULL, ",");
            cnt++;
        }
    } else if (n == 5 && strcmp(f[0], "m") == 0) {
        char ack[16]; snprintf(ack, sizeof ack, "a\t%s", f[1]);
        send_peer(c, p, ack);
        // Only p itself is authenticated here. f[2] and f[3] (origin id, nick) are whatever p says.
        uint8_t origin[ID_LEN];
        if (hex_decode(f[2], ID_LEN * 2, origin) != 0) return;
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
        char rejoin[16 + MAX_NICK + MAX_TEXT + 32];
        snprintf(rejoin, sizeof rejoin, "m\t%s\t%s\t%s\t%s", f[1], f[2], nick, text);
        for (int i = 0; i < c->peer_hi; i++) {
            peer_t *q = &c->peers[i];
            if (!q->used || !q->ok || q == p) continue;
            char qid[33]; hex_encode(q->id, ID_LEN, qid);
            if (strcmp(qid, f[2]) != 0) send_peer(c, q, rejoin);
        }
    } else if (n == 2 && strcmp(f[0], "a") == 0) {
        for (int i = 0; i < MAX_PENDING_MSGS; i++)
            if (c->pending[i].used && c->pending[i].peer_slot == peer_slot(c, p) && strcmp(c->pending[i].mid, f[1]) == 0)
                c->pending[i].used = 0;
    } else if (n == 1 && strcmp(f[0], "nop") == 0) {

    } else if (n == 1 && strcmp(f[0], "bye") == 0) {
        drop_peer(c, p, "left");
    }
    (void)now;
}

static void on_room(chat_t *c, char *plain, addr_t addr, double now) {
    char *f[MAX_FIELDS];
    int n = split_tabs(plain, f, MAX_FIELDS);
    const char *my_idhex = c->my_idhex;

    if (n == 4 && strcmp(f[0], "hi") == 0 && strlen(f[1]) == 32 && strlen(f[2]) == 64
        && strlen(f[3]) == KEM_PUB_LEN * 2) {
        if (strcmp(f[1], my_idhex) == 0) {
            if (c->n_self_addrs < 8) c->self_addrs[c->n_self_addrs++] = addr;
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
            if (c->n_self_addrs < 8) c->self_addrs[c->n_self_addrs++] = addr;
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

static void on_frame(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now) {
    uint8_t plain[HANDSHAKE_BUF_LEN + 128];
    size_t plain_len;
    if (room_unseal(c->room_key, data, len, plain, sizeof plain - 1, &plain_len) == 0) {
        plain[plain_len] = '\0';
        c->st.room_ok++;
        on_room(c, (char *)plain, addr, now);
        return;
    }
    if (len >= 4) {
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
            if (!addr_equal(p->addr, addr)) p->addr = addr;
            p->seen = now;
            int was_pending = !p->ok;
            p->ok = 1;
            on_session(c, p, (char *)plain, now);
            if (!p->used) return;
            if (was_pending) {
                c->st.connects++;

                send_k_now(c, p);
                if (!c->created && !c->ever_connected) ui_print(c, "* connected - chat is open");
                c->ever_connected = 1;
                c->once_used = 1;
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
                introduce(c, p);
            }
            return;
        }
    }
    c->st.other++;
    if (c->dht_on) dht_on_packet(&c->dht, data, len, addr, dht_candidate_cb, c);
}

int chat_sockets(chat_t *c, sock_t out[2]) {
    int k = 0;
    out[k++] = c->sock;
    if (c->lan_sock != SOCK_INVALID) out[k++] = c->lan_sock;
    return k;
}

int chat_online_count(const chat_t *c) { return live_count((chat_t *)c); }
int chat_pending_count(const chat_t *c) { return pending_peer_count((chat_t *)c); }
int chat_candidate_count(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used) n++;
    return n;
}

int chat_ready(const chat_t *c) { return c->created || c->ever_connected; }

void chat_on_socket_readable(chat_t *c, sock_t which, double now) {

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

void chat_tick(chat_t *c, double now) {
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
            if (!p->used || pm->tries >= 5) pm->used = 0;
            else { net_send(c->sock, pm->frame, pm->frame_len, p->addr); pm->tries++; pm->next_retry = now + 1 + jitter(0.5); }
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
        for (int i = 0; i < c->peer_hi; i++)
            if (c->peers[i].used && c->peers[i].ok) { send_room(c, c->hi_msg, c->peers[i].addr, c->sock); sent_to++; }
        if (c->net_verbose && sent_to > 0) ui_print(c, "* keepalive hi -> %d connected peer%s", sent_to, sent_to == 1 ? "" : "s");
        for (int i = 0; i < c->n_static; i++) add_candidate(c, c->static_peers[i]);
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

    double cover_iv = cover_interval(c);
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        if (p->next_cover == 0.0) { p->next_cover = now + jitter(cover_iv); continue; }
        if (now >= p->next_cover) send_peer(c, p, "nop");
    }
    if (!c->created && !c->warned_lonely && !c->ever_connected && now - c->start > LONELY_HINT_AFTER) {
        c->warned_lonely = 1;
        ui_print(c, "* nobody has answered for this session yet - check the id and password with "
                     "whoever shared them, or they may not have started their app yet");
        net_report(c);
    }
}

static void net_report(chat_t *c) {
    net_stats_t *st = &c->st;
    int cands = 0;
    for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used) cands++;
    if (c->dht_on)
        ui_print(c, "* net: udp/%u | internet lookup: %d nodes reached, %d peers found | candidates to try: %d | handshakes in progress: %d | connected: %d",
                 (unsigned)c->port, dht_queried_count(&c->dht), dht_found_count(&c->dht), cands, pending_peer_count(c), live_count(c));
    else
        ui_print(c, "* net: udp/%u | internet lookup: off | candidates to try: %d | handshakes in progress: %d | connected: %d",
                 (unsigned)c->port, cands, pending_peer_count(c), live_count(c));
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
    if (st->rx == 0) why = "nothing at all has reached this session's port - a firewall/NAT is blocking inbound UDP, or nobody is sending to you yet";
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

static void send_to_live_peers(chat_t *c, const char *msg) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) send_peer(c, &c->peers[i], msg);
}

void chat_set_nick(chat_t *c, const char *nick) {
    chat_clean_nick(nick, c->nick);
    ui_print(c, "* your nickname is now %s", c->nick);
    char msg[8 + MAX_NICK];
    snprintf(msg, sizeof msg, "n\t%s", c->nick);
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
    ui_print(c, "* commands - anything not starting with / is sent to the room:");
    for (const command_t *cmd = CHAT_COMMANDS; cmd->name; cmd++) {
        char line[160]; cmd_format_help(cmd, '/', line, sizeof line);
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
        ui_print(c, "*   %s#%s (verify %s, %s%s)", p->nick, idhex, vfyhex, chat_verify_label(p->identity_state),
                 p->persists ? ", logging" : "");
    }
    if (n == 0) ui_print(c, "* nobody else yet");
    return CMD_OK;
}

static cmd_result_t cmd_verify(void *ctx, const char *arg) {
    chat_t *c = ctx;
    if (!*arg) {
        ui_print(c, "* usage: /verify NICK - shows their identity fingerprint to read out and compare");
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

static cmd_result_t cmd_nick(void *ctx, const char *arg) {
    chat_t *c = ctx;
    if (!*arg) ui_print(c, "* current nickname: %s. usage: /nick NAME", c->nick);
    else chat_set_nick(c, arg);
    return CMD_OK;
}

static cmd_result_t cmd_colour(void *ctx, const char *arg) {
    chat_t *c = ctx;
    if (!*arg) {
        char list[512]; size_t pos = 0;
        for (int i = 0; i < COLOR_PALETTE_N; i++)
            pos += (size_t)snprintf(list + pos, sizeof(list) - pos, "%s%s", i ? ", " : "", COLOR_PALETTE[i].name);
        char cur[7]; color_to_hex(c->my_color, cur);
        ui_print(c, "* current colour: #%s. usage: /colour NAME|#RRGGBB. names: %s", cur, list);
        return CMD_OK;
    }
    uint8_t rgb[3];
    if (parse_color(arg, rgb) != 0) {
        ui_print(c, "* unknown colour '%s' - try a name or #RRGGBB", arg);
        return CMD_OK;
    }
    memcpy(c->my_color, rgb, 3);
    char hex[7]; color_to_hex(rgb, hex);
    ui_print_colored(c, c->my_color, "* your colour is now #%s", hex);
    char msg[10]; snprintf(msg, sizeof msg, "c\t%s", hex);
    send_to_live_peers(c, msg);
    return CMD_OK;
}

static cmd_result_t cmd_notify(void *ctx, const char *arg) {
    static const char *const names[] = { "none", "mentions", "all" };
    chat_t *c = ctx;
    for (int m = NOTIFY_NONE; m <= NOTIFY_ALL; m++) {
        if (strcmp(arg, names[m]) != 0) continue;
        c->notify_mode = (notify_mode_t)m;
        ui_print(c, "* notifications: %s", names[m]);
        return CMD_OK;
    }
    ui_print(c, "* notifications: %s. usage: /notify all|mentions|none", names[c->notify_mode]);
    return CMD_OK;
}

static cmd_result_t cmd_net(void *ctx, const char *arg) {
    (void)arg;
    net_report(ctx);
    return CMD_OK;
}

static cmd_result_t cmd_netverbose(void *ctx, const char *arg) {
    chat_t *c = ctx;
    if (strcmp(arg, "on") == 0) {
        c->net_verbose = 1;
        ui_print(c, "* net verbose logging: on - every handshake packet now gets its own console line");
    } else if (strcmp(arg, "off") == 0) {
        c->net_verbose = 0;
        ui_print(c, "* net verbose logging: off");
    } else {
        ui_print(c, "* net verbose logging: %s. usage: /netverbose on|off", c->net_verbose ? "on" : "off");
    }
    return CMD_OK;
}

static cmd_result_t cmd_port(void *ctx, const char *arg) {
    chat_t *c = ctx;
    if (!arg[0]) {
        ui_print(c, "* udp port: %u. usage: /port N (0 picks a free one)", (unsigned)c->port);
        return CMD_OK;
    }
    char *end;
    long want = strtol(arg, &end, 10);
    if (*end || want < 0 || want > 65535) {
        ui_print(c, "* not a port: %s. usage: /port N (0-65535, 0 picks a free one)", arg);
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
    if (c->dht_on) { c->dht.my_port = got; c->dht.next_lookup = 0; }
    ui_print(c, "* now on udp port %u", (unsigned)got);
    return CMD_OK;
}

static cmd_result_t cmd_quit(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    return CMD_QUIT;
}

const command_t CHAT_COMMANDS[] = {
    { "help",       NULL,     NULL,              "list commands",                                   cmd_help },
    { "peers",      NULL,     NULL,              "who is online, with verify codes",                cmd_peers },
    { "verify",     NULL,     "NICK",            "show a peer's identity fingerprint",              cmd_verify },
    { "nick",       NULL,     "[NAME]",          "show or change your nickname",                    cmd_nick },
    { "colour",     "color",  "[NAME|#RRGGBB]",  "show or change your colour",                      cmd_colour },
    { "notify",     NULL,     "[all|mentions|none]", "show or change desktop notifications",        cmd_notify },
    { "net",        NULL,     NULL,              "network report and diagnosis",                    cmd_net },
    { "netverbose", NULL,     "[on|off]",        "log every handshake packet",                      cmd_netverbose },
    { "port",       NULL,     "[N]",             "show or change this session's udp port",          cmd_port },
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
        ui_print(c, "* unknown command /%s - try /help", word);
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
    char text[16 + MAX_NICK + MAX_TEXT + 32];
    snprintf(text, sizeof text, "m\t%s\t%s\t%s\t%s", mid, myidhex, c->nick, line);
    char who[MAX_NICK + 8]; snprintf(who, sizeof who, "%s (you)", c->nick);
    ui_chat(c, c->my_color, 0, who, line);
    int sent = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        for (int s = 0; s < MAX_PENDING_MSGS; s++) {
            if (!c->pending[s].used) {
                c->pending[s].used = 1;
                strcpy(c->pending[s].mid, mid);
                c->pending[s].peer_slot = i;
                uint32_t idx;
                if (frame_for_peer(p, text, c->pending[s].frame, sizeof c->pending[s].frame,
                                    &c->pending[s].frame_len, &idx) != 0) {
                    c->pending[s].used = 0;
                    break;
                }
                c->pending[s].tries = 1;
                c->pending[s].next_retry = now + 1 + jitter(0.5);
                net_send(c->sock, c->pending[s].frame, c->pending[s].frame_len, p->addr);
                sent++;
                break;
            }
        }
    }
    if (!sent) ui_print(c, "* nobody else is here yet, message not delivered");
}

int chat_submit_line(chat_t *c, const char *line_in, double now) {
    char line[MAX_TEXT + 1];
    clean_text(line_in, line, MAX_TEXT);
    if (line[0] == '/') return chat_run_command(c, line + 1) != CMD_QUIT;
    chat_send_text(c, line, now);
    return 1;
}

void chat_init(chat_t *c, const chat_opts_t *o, chat_print_fn print, chat_notify_fn notify, void *ui) {
    memset(c, 0, sizeof *c);
    c->print = print;
    c->notify = notify;
    c->ui = ui;
    chat_clean_nick(o->nick, c->nick);
    copy_str(c->session_name, o->session_name, sizeof c->session_name);
    c->created = o->created;
    c->dht_on = o->dht_on;
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

    gen_random(c->my_id, ID_LEN);
    gen_keypair(&c->keys);
    kem_gen_keypair(&c->kem_keys);
    c->keygen = 1;
    gen_random(c->cookie_secret, 32);
    derive_master(o->password, o->session_name, c->master);
    derive_room_key(c->master, c->room_key);
    derive_fingerprint(c->master, c->fingerprint);
    refresh_hi(c);

    c->sock = net_udp_open(o->port, NET_DUAL, &c->port);
    c->lan_sock = net_udp_open(LAN_PORT, NET_REUSE, NULL);

    memcpy(c->static_peers, o->peers, sizeof(addr_t) * (size_t)o->n_peers);
    c->n_static = o->n_peers;

    if (c->dht_on) {
        uint8_t infohash[DHT_INFOHASH_LEN];
        derive_dht_infohash(c->master, infohash);
        dht_init(&c->dht, infohash, c->port);
        dht_start_bootstrap_resolve(&c->dht);
    }

    crypto_lock((uint8_t *)c + SECRETS_OFFSET, SECRETS_LEN);

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
    net_close(c->sock);
    net_close(c->lan_sock);
    if (c->log_fp) fclose(c->log_fp);

    crypto_unlock((uint8_t *)c + SECRETS_OFFSET, SECRETS_LEN);

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
