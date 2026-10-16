// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Finding peers and connecting to them: candidates, the handshake, peer exchange and builds.
#include "core/engine.h"

// The session keys, ours and p's, of the chain p's records are sealed on now, for "k" and "mp" to sign.
static void signed_pubs(peer_t *p, const uint8_t **mine, const uint8_t **theirs) {
    int prev = send_chain_for(p) == &p->old_send;
    *mine = prev ? p->prev_my_pub : p->my_pub;
    *theirs = prev ? p->prev_pub : p->pub;
}

// 0 if sig by key signs this session with p, or the one before its last re-handshake: a record
// signed then can still arrive, on either chain, while each side's rekey reaches the other.
int check_session_sig(const chat_t *c, const peer_t *p, session_sig_fn verify, const uint8_t *key,
                      const uint8_t *sig) {
    if (verify(key, sig, p->pub, p->id, p->my_pub, c->my_id) == 0) return 0;
    return p->prev_set && verify(key, sig, p->prev_pub, p->id, p->prev_my_pub, c->my_id) == 0 ? 0 : -1;
}

// One of our own addresses, or one a peer (connected or still handshaking) is at, so not worth a hi.
int known_addr(const chat_t *c, addr_t a) {
    for (int i = 0; i < c->n_self_addrs; i++) if (addr_equal(c->self_addrs[i], a)) return 1;
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && addr_equal(c->peers[i].addr, a)) return 1;
    return 0;
}

void add_candidate(chat_t *c, addr_t a) {
    if (a.port == 0 || known_addr(c, a)) return;
    int same_host = 0;
    for (int i = 0; i < MAX_CANDS; i++) {
        if (!c->cands[i].used) continue;
        addr_t b = c->cands[i].addr;
        if (addr_equal(b, a)) return;
        if (b.is_v6 == a.is_v6 && memcmp(b.ip, a.ip, addr_ip_len(a)) == 0) same_host++;
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

void dht_candidate_cb(void *ctx, addr_t a) { add_candidate((chat_t *)ctx, a); }

int candidate_reached(chat_t *c, addr_t a) {
    for (int i = 0; i < c->peer_hi; i++) {
        const peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        if (addr_equal(p->addr, a)) return 1;
        if (a.kind == ADDR_NOSTR && memcmp(p->id, a.ip, ID_LEN) == 0) return 1;
    }
    return 0;
}

void refresh_hi(chat_t *c) {
    char pubhex[PUB_LEN * 2 + 1], kemhex[KEM_PUB_LEN * 2 + 1];
    hex_encode(c->my_id, ID_LEN, c->my_idhex);
    hex_encode(c->keys.pub, PUB_LEN, pubhex);
    hex_encode(c->kem_keys.pub, KEM_PUB_LEN, kemhex);
    snprintf(c->hi_msg, sizeof c->hi_msg, "hi\t%s\t%s\t%s", c->my_idhex, pubhex, kemhex);
}

void send_kx(chat_t *c, peer_t *p, addr_t to) {
    char cthex[KEM_CT_LEN * 2 + 1]; hex_encode(p->kem_ct, KEM_CT_LEN, cthex);
    char kx[16 + ID_LEN * 2 + KEM_CT_LEN * 2];
    snprintf(kx, sizeof kx, "kx\t%s\t%s", c->my_idhex, cthex);
    send_room(c, kx, to, c->sock);
}

static void build_k_message(chat_t *c, peer_t *p, char *out, size_t out_cap) {
    char colorhex[COLOR_HEX_LEN + 1]; color_to_hex(c->my_color, colorhex);
    char idpubhex[ID_SIGN_PUB_LEN * 2 + 1] = "", sighex[ID_SIGN_LEN * 2 + 1] = "";
    int idtype = IDENT_NONE;
    if (c->identity_source != IDENT_NONE) {
        idtype = c->identity_source;
        hex_encode(c->identity.pub, ID_SIGN_PUB_LEN, idpubhex);
        uint8_t sig[ID_SIGN_LEN];
        const uint8_t *mine, *theirs;
        signed_pubs(p, &mine, &theirs);
        identity_sign(&c->identity, mine, c->my_id, theirs, p->id, sig);
        hex_encode(sig, ID_SIGN_LEN, sighex);
    }
    // After the logging flag, features this build has that older ones don't: "r" announces rekeys,
    // "b" reads several records per frame, "l" reads messages up to MAX_TEXT, "m" moves rooms, "p"
    // reads direct messages, "q" reads replies, "o" reads "off", "t" keeps to message timers, then our
    // timer.
    snprintf(out, out_cap, "k\t%s\t%s\t%drblmpqot%u\t%d\t%s\t%s", c->nick, colorhex, c->persist, c->timer, idtype,
             idpubhex, sighex);
}

// "v": our version, our executable's hash, and our release's signed list of binaries (empty
// fields for a build without one), which p checks the hash against. 0.3.0 only sent the first
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

// "mp": this session's keys, signed with the key we showed in the room we moved here from.
static void send_move_proof(chat_t *c, peer_t *p) {
    uint8_t sig[ID_SIGN_LEN];
    const uint8_t *mine, *theirs;
    signed_pubs(p, &mine, &theirs);
    move_sign(&c->moved_key, mine, c->my_id, theirs, p->id, sig);
    char sighex[ID_SIGN_LEN * 2 + 1]; hex_encode(sig, ID_SIGN_LEN, sighex);
    char msg[8 + ID_SIGN_LEN * 2];
    snprintf(msg, sizeof msg, "mp\t%s", sighex);
    send_peer(c, p, msg);
}

void send_k_now(chat_t *c, peer_t *p) {
    char k[8 + MAX_NICK + 8 + 5 + 4 + ID_SIGN_PUB_LEN * 2 + 1 + ID_SIGN_LEN * 2 + 1];
    // Ahead of k, so it's read before the join is announced, which would ask to compare codes.
    if (c->moved) send_move_proof(c, p);
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
    enum { RK_GRACE = 10, RK_WARN_EVERY = 30 };
    if (p && p->ok && p->announces_rekey && memcmp(p->pub, their_pub, PUB_LEN) != 0
        && !(p->next_pub_set && memcmp(p->next_pub, their_pub, PUB_LEN) == 0)) {
        if (p->rk_refused_since == 0.0) p->rk_refused_since = now;
        if (now - p->rk_refused_since > RK_GRACE && now >= p->next_rk_warn) {
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            p->next_rk_warn = now + RK_WARN_EVERY;
            ui_print(c, "* warning: a new key for %s arrived that %s never announced - refused. Someone may be "
                        "intercepting; if it continues, compare :peers verify codes over another channel", name, name);
        }
        return NULL;
    }
    if (pending_peer_count(c) >= MAX_PENDING_PEERS || live_count(c) >= MAX_PEERS) return NULL;

    peer_t *slot = p;
    if (!slot) {
        for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) if (!c->peers[i].used) { slot = &c->peers[i]; break; }
        if (!slot) return NULL;
    }

    uint8_t shared[SHARED_LEN];
    if (ecdh_shared(&c->keys, their_pub, shared) != 0) { crypto_wipe(shared, sizeof shared); return NULL; }
    uint8_t prk_partial[PRK_LEN];
    session_prk(c->master, shared, c->keys.pub, c->my_id, their_pub, peer_id, prk_partial);
    crypto_wipe(shared, sizeof shared);

    // carry holds the old chains for the overlap and any kx that arrived early. It's wiped before
    // returning.
    peer_t carry;
    int rejoin = 0;
    if (p && p->ok) { carry = *p; rejoin = 1; }
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
    memcpy(slot->my_pub, c->keys.pub, PUB_LEN);
    if (rejoin) {
        memcpy(slot->prev_pub, carry.pub, PUB_LEN);
        memcpy(slot->prev_my_pub, carry.my_pub, PUB_LEN);
        slot->prev_set = 1;
        memcpy(slot->nick, carry.nick, sizeof slot->nick);
        memcpy(slot->nick_skel, carry.nick_skel, sizeof slot->nick_skel);
        memcpy(slot->color, carry.color, 3);
        slot->persists = carry.persists;
        slot->can_timer = carry.can_timer;
        slot->timer = carry.timer;
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
        slot->long_text = carry.long_text;
        // A file it's fetching from us continues from where it was, so a rekey doesn't stall it.
        slot->serving = carry.serving;
        memcpy(slot->serve_fid, carry.serve_fid, FILE_ID_LEN);
        slot->serve_next = carry.serve_next;
        slot->serve_end = carry.serve_end;
        slot->serve_at = carry.serve_at;
        // The same peer, as the rk it announced proves, so a compared code stays compared.
        slot->code_ok = carry.code_ok;
        slot->trust = carry.trust;
        slot->next_rehello = carry.next_rehello;
        slot->can_move = carry.can_move;
        slot->can_pm = carry.can_pm;
        slot->can_reply = carry.can_reply;
        memcpy(slot->move_pub, carry.move_pub, ID_SIGN_PUB_LEN);
        slot->move_pub_set = carry.move_pub_set;
        slot->move_passed = carry.move_passed;
        slot->move_with = carry.move_with;
        slot->key_sent = carry.key_sent;
        slot->came_with = carry.came_with;
    }

    peer_t *result = slot;
    if (memcmp(c->my_id, peer_id, ID_LEN) < 0) {
        uint8_t kem_ss[KEM_SS_LEN], prk[PRK_LEN];
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
        memcpy(slot->prk_partial, prk_partial, PRK_LEN);
        if (rejoin && carry.kx_early) finish_kem_decap(c, slot, carry.kem_ct);
    }
    crypto_wipe(prk_partial, sizeof prk_partial);
    if (rejoin) crypto_wipe(&carry, sizeof carry);
    *fresh = result != NULL;
    return result;
}

int we_initiate(const chat_t *c, const peer_t *p) { return memcmp(c->my_id, p->id, ID_LEN) < 0; }

int path_rank(addr_t a) { return a.kind == ADDR_UDP ? 2 : a.kind == ADDR_TOR ? 1 : 0; }

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
    uint8_t prk[PRK_LEN];
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
    if (fresh) send_room(c, c->hi_msg, addr, c->sock);
    if (p->send_chain.started) {
        // Keep sending the kx until the peer's frames show it was received. The first copy may be lost,
        // or reach the peer before its side of the re-handshake is ready.
        if (we_initiate(c, p) && (fresh || !p->chain_confirmed)) send_kx(c, p, p->addr);
        send_k_now(c, p);
    }
}

#define PX_MAX_BODY RECORD_MAX
#define PX_MAX_PEERS 24

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

static void send_px(chat_t *c, peer_t *p, const char *list) {
    char msg[PX_MAX_BODY + 8];
    snprintf(msg, sizeof msg, "px\t%s", list);
    send_peer(c, p, msg);
}

void introduce(chat_t *c, peer_t *newp) {
    // Several px messages if one can't hold them all (onion addresses are long).
    char list[PX_MAX_BODY];
    size_t pos = 0;
    int n = 0, total = 0;
    for (int i = 0; i < c->peer_hi && total < PX_MAX_PEERS; i++) {
        peer_t *q = &c->peers[i];
        char as[ADDR_STR_LEN];
        if (!q->used || !q->ok || q == newp || px_entry(c, q, as) != 0) continue;
        size_t need = strlen(as) + (n ? 1 : 0);
        if (pos + need + sizeof "px\t" > PX_MAX_BODY) {
            send_px(c, newp, list);
            pos = 0; n = 0; need = strlen(as);
        }
        pos += (size_t)snprintf(list + pos, sizeof(list) - pos, "%s%s", n ? "," : "", as);
        n++;
        total++;
    }
    if (n > 0) send_px(c, newp, list);
    char newp_addr[ADDR_STR_LEN];
    if (px_entry(c, newp, newp_addr) != 0) return;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *q = &c->peers[i];
        if (q->used && q->ok && q != newp) send_px(c, q, newp_addr);
    }
}

// In Tor mode, tells p our onion address, which it passes on in px.
void send_onion(chat_t *c, peer_t *p) {
    if (!c->tor || !tor_my_onion(c->tor)[0]) return;
    char msg[8 + TOR_ADDR_LEN];
    snprintf(msg, sizeof msg, "ta\t%s", tor_my_onion(c->tor));
    send_peer(c, p, msg);
}

// A version as a peer may give it: short, and nothing a terminal or a URL would treat specially.
int version_ok(const char *v) {
    size_t n = strlen(v);
    if (n == 0 || n > MAX_VERSION) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)v[i]) && v[i] != '.' && v[i] != '-') return 0;
    return 1;
}

// 0.3.0 sent "v" before binaries carried their list: the SHA-256 of each of its binaries as
// published, from its signed SHA256SUMS.
static const struct { const char *version; const char *sha256[2]; } LISTLESS_RELEASES[] = {
    { "0.3.0", { "aa35cb3847b48a957522241dc21462ac1ad2d73da5f439a6d8c348791fdbe839",
                 "f18f1d9b3f07f5f811c0a6a6afcb536f2eef28a2aa96b5b1a8f8990b02c86933" } },
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
        if (strspn(hex, HEX_DIGITS) != len || hex_decode(hex, len, hashes[n]) != 0) return -1;
        memcpy(content + pos, hex, len);
        pos += len;
        content[pos++] = '\n';
        n++;
        if (!end) break;
        item = end + 1;
    }
    if (n == 0) return -1;
    if (!(c->has_release_key && minisign_verify(c->release_key, content, pos, sig, strlen(sig), NULL) == 0)
        && !(c->has_backup_key && minisign_verify(c->backup_key, content, pos, sig, strlen(sig), NULL) == 0))
        return -1;
    return n;
}

// The warning includes p's name, so it waits until p's join is announced.
void tell_build(chat_t *c, peer_t *p) {
    if (!p->build_warn || !p->announced) return;
    p->build_warn = 0;
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    ui_print(c, "* warning: %s runs a modified client - it says v%s, but isn't one of that release's binaries",
             name, p->build_version);
}

// Checks the build p's "v" names: its hash against the signed list it came with (list NULL:
// 0.3.0's format, which has none), and warns about one that isn't a release binary.
void check_build(chat_t *c, peer_t *p, const char *version, const uint8_t proof[BUILD_HASH_LEN],
                 const char *list, const char *sig) {
    // "v" comes with every k, so a verdict already given isn't repeated.
    int again = p->build_state == BUILD_MODIFIED && strcmp(p->build_version, version) == 0;
    copy_str(p->build_version, version, sizeof p->build_version);
    if (!c->has_release_key && !c->has_backup_key) { p->build_state = BUILD_UNCHECKED; return; }
    uint8_t hashes[BUILD_LIST_MAX][BUILD_HASH_LEN];
    int n = -1;
    if (list) {
        n = signed_list(c, version, list, sig, hashes);
    } else {
        for (size_t i = 0; i < COUNT_OF(LISTLESS_RELEASES); i++) {
            if (strcmp(LISTLESS_RELEASES[i].version, version) != 0) continue;
            for (n = 0; n < (int)COUNT_OF(LISTLESS_RELEASES[i].sha256); n++)
                hex_decode(LISTLESS_RELEASES[i].sha256[n], BUILD_HASH_LEN * 2, hashes[n]);
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

// Our own hi came back from addr, so it's one of our addresses and never a candidate. Each is
// kept once, so replays of it can't fill the list.
static void note_self_addr(chat_t *c, addr_t addr) {
    // A relayed address represents a peer or a Tor stream, so it's never one of ours.
    if (addr.kind != ADDR_UDP) return;
    for (int i = 0; i < c->n_self_addrs; i++) if (addr_equal(c->self_addrs[i], addr)) return;
    if (c->n_self_addrs < MAX_SELF_ADDRS) c->self_addrs[c->n_self_addrs++] = addr;
}

// The fields of handshake records, as hex.
#define ID_HEX (ID_LEN * 2)
#define PUB_HEX (PUB_LEN * 2)
#define COOKIE_HEX (COOKIE_LEN * 2)

void on_room(chat_t *c, char *plain, addr_t addr, double now) {
    char *f[MAX_FIELDS];
    int n = split_tabs(plain, f, MAX_FIELDS);
    const char *my_idhex = c->my_idhex;

    if (n == 4 && strcmp(f[0], "hi") == 0 && strlen(f[1]) == ID_HEX && strlen(f[2]) == PUB_HEX
        && strlen(f[3]) == KEM_PUB_LEN * 2) {
        if (strcmp(f[1], my_idhex) == 0) {
            note_self_addr(c, addr);
            for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used && addr_equal(c->cands[i].addr, addr)) c->cands[i].used = 0;
            return;
        }
        uint8_t peer_id[ID_LEN], pub[PUB_LEN], kem_pub[KEM_PUB_LEN];
        if (hex_decode(f[1], ID_HEX, peer_id) != 0 || hex_decode(f[2], PUB_HEX, pub) != 0
            || hex_decode(f[3], KEM_PUB_LEN * 2, kem_pub) != 0) return;
        c->st.hi++;
        char addr_str[ADDR_STR_LEN]; addr_to_string(addr, addr_str);
        peer_t *existing = find_peer_by_id(c, peer_id);
        if (c->net_verbose) {
            char shortid[SHORT_ID_HEX + 1]; short_id(peer_id, shortid);
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
            char cookiehex[COOKIE_HEX + 1]; hex_encode(cookie, COOKIE_LEN, cookiehex);
            char msg[8 + ID_HEX + COOKIE_HEX];
            snprintf(msg, sizeof msg, "ck\t%s\t%s", f[1], cookiehex);
            send_room(c, msg, addr, c->sock);
            if (c->net_verbose) ui_print(c, "* sent cookie challenge to %s", addr_str);
        }
    } else if (n == 3 && strcmp(f[0], "ck") == 0 && strcmp(f[1], my_idhex) == 0 && strlen(f[2]) == COOKIE_HEX) {
        c->st.ck++;
        if (c->net_verbose) {
            char addr_str[ADDR_STR_LEN]; addr_to_string(addr, addr_str);
            ui_print(c, "* cookie challenge from %s - answering with hi2", addr_str);
        }
        char pubhex[PUB_HEX + 1]; hex_encode(c->keys.pub, PUB_LEN, pubhex);
        char kemhex[KEM_PUB_LEN * 2 + 1]; hex_encode(c->kem_keys.pub, KEM_PUB_LEN, kemhex);
        char msg[HANDSHAKE_BUF_LEN];
        snprintf(msg, sizeof msg, "hi2\t%s\t%s\t%s\t%s", my_idhex, pubhex, kemhex, f[2]);
        send_room(c, msg, addr, c->sock);
    } else if (n == 5 && strcmp(f[0], "hi2") == 0 && strlen(f[1]) == ID_HEX && strlen(f[2]) == PUB_HEX
               && strlen(f[3]) == KEM_PUB_LEN * 2 && strlen(f[4]) == COOKIE_HEX) {
        if (strcmp(f[1], my_idhex) == 0) {
            note_self_addr(c, addr);
            return;
        }
        uint8_t peer_id[ID_LEN], pub[PUB_LEN], kem_pub[KEM_PUB_LEN], given[COOKIE_LEN];
        if (hex_decode(f[1], ID_HEX, peer_id) != 0 || hex_decode(f[2], PUB_HEX, pub) != 0
            || hex_decode(f[3], KEM_PUB_LEN * 2, kem_pub) != 0 || hex_decode(f[4], COOKIE_HEX, given) != 0) return;
        char addr_str[ADDR_STR_LEN]; addr_to_string(addr, addr_str);
        uint8_t expect[COOKIE_LEN];
        cookie_compute(c->cookie_secret, addr_str, peer_id, pub, expect);
        c->st.hi2++;
        int cookie_ok = crypto_equal(given, expect, COOKIE_LEN) == 0;
        if (c->net_verbose) {
            char shortid[SHORT_ID_HEX + 1]; short_id(peer_id, shortid);
            ui_print(c, "* hi2 from %s, peer %s - cookie %s", addr_str, shortid, cookie_ok ? "ok" : "MISMATCH");
        }
        if (cookie_ok) connect_peer(c, peer_id, addr, pub, kem_pub, now);
        else c->st.hi2_bad++;
    } else if (n == 3 && strcmp(f[0], "kx") == 0 && strlen(f[1]) == ID_HEX && strlen(f[2]) == KEM_CT_LEN * 2) {
        uint8_t peer_id[ID_LEN], ct[KEM_CT_LEN];
        if (hex_decode(f[1], ID_HEX, peer_id) != 0 || hex_decode(f[2], KEM_CT_LEN * 2, ct) != 0) return;
        c->st.kx++;
        peer_t *p = find_peer_by_id(c, peer_id);
        if (c->net_verbose) {
            char addr_str[ADDR_STR_LEN]; addr_to_string(addr, addr_str);
            char shortid[SHORT_ID_HEX + 1]; short_id(peer_id, shortid);
            ui_print(c, "* kx from %s, peer %s%s", addr_str, shortid, p ? "" : " (unknown peer, ignored)");
        }
        if (p) finish_kem_decap(c, p, ct);
    } else if (n == 2 && strcmp(f[0], "nb") == 0 && addr.kind == ADDR_NOSTR && strlen(f[1]) == ID_HEX
               && strcmp(f[1], my_idhex) != 0) {
        // A member announcing itself on the relays. Someone we already hear from directly needs nothing.
        // Anyone else gets a hi through the relays.
        uint8_t peer_id[ID_LEN];
        if (hex_decode(f[1], ID_HEX, peer_id) != 0) return;
        peer_t *known = find_peer_by_id(c, peer_id);
        if (known && known->ok && now - known->seen < UDP_STALE) return;
        add_candidate(c, addr_virtual(ADDR_NOSTR, peer_id));
    } else if (n == 3 && strcmp(f[0], "lan") == 0 && addr.kind == ADDR_UDP && strcmp(f[1], my_idhex) != 0) {
        // Only a real broadcast shows where someone is on the LAN. Over the relays or a Tor stream the
        // port would be applied to an address that represents a peer.
        c->st.lan++;
        int port = atoi(f[2]);
        if (port > 0 && port <= UINT16_MAX) {
            addr_t a = addr; a.port = (uint16_t)port;
            add_candidate(c, a);
            if (c->net_verbose) { char as[ADDR_STR_LEN]; addr_to_string(a, as); ui_print(c, "* lan beacon - candidate %s added", as); }
        }
    }
}

int on_chunk(chat_t *c, const uint8_t *d, size_t len, addr_t addr, double now) {
    if (len != UDP_CELL || d[0] != CHUNK_MAGIC0 || d[1] != CHUNK_MAGIC1) return 0;
    int idx = d[CHUNK_INDEX_AT], count = d[CHUNK_COUNT_AT];
    size_t total = load_be16(d + CHUNK_LEN_AT);
    if (count < 2 || count > CHUNK_MAX || idx >= count) return 0;
    if (total <= (size_t)(count - 1) * CHUNK_PAYLOAD || total > (size_t)count * CHUNK_PAYLOAD) return 0;
    c->st.rx_chunks++;

    reasm_t *slot = NULL, *oldest = &c->reasm[0];
    for (int i = 0; i < REASM_SLOTS; i++) {
        reasm_t *r = &c->reasm[i];
        if (r->used && now - r->born > REASM_TTL) r->used = 0;
        if (r->used && addr_equal(r->from, addr) && memcmp(r->id, d + CHUNK_ID_AT, CHUNK_ID_LEN) == 0 && r->count == count
            && r->total == total) { slot = r; break; }
        if (r->born < oldest->born) oldest = r;
    }
    if (!slot) {
        for (int i = 0; i < REASM_SLOTS; i++) if (!c->reasm[i].used) { slot = &c->reasm[i]; break; }
        if (!slot) slot = oldest;
        memset(slot, 0, sizeof *slot);
        slot->used = 1; slot->from = addr; memcpy(slot->id, d + CHUNK_ID_AT, CHUNK_ID_LEN);
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
