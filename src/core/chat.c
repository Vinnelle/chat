// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// A session: starting and stopping it, what it does each tick, and what the app sets and asks of it.
#include "core/engine.h"

#define SECRETS_OFFSET offsetof(chat_t, keys)
#define SECRETS_LEN (offsetof(chat_t, move_staged_set) + sizeof(int) - offsetof(chat_t, keys))

static void knock_room_slots(chat_t *c, double now);

static const char *const DEFAULT_RELAYS[] = {
    "wss://relay.primal.net",
    "wss://nostr.mom",
    "wss://relay.nostr.net",
};

void routing_defaults(routing_t *r) {
    memset(r, 0, sizeof *r);
    r->mode = ROUTE_UDP;
    r->dht4 = r->dht6 = r->lan = r->portmap = r->nostr = 1;
    for (size_t i = 0; i < COUNT_OF(DEFAULT_RELAYS); i++)
        copy_str(r->relays[r->n_relays++], DEFAULT_RELAYS[i], NOSTR_URL_MAX);
    r->tor = TOR_DEFAULTS;
}

const char *routing_mode_name(route_mode_t m) { return m == ROUTE_TOR ? "tor" : "udp"; }

int split_tabs(char *s, char *fields[], int max) {
    int n = 0;
    char *p = s;
    fields[n++] = p;
    while (*p && n < max) {
        if (*p == '\t') { *p = '\0'; fields[n++] = p + 1; }
        p++;
    }
    return n;
}

double jitter(double spread) {
    uint32_t r;
    gen_random((uint8_t *)&r, sizeof r);
    return spread * ((double)r / ((double)UINT32_MAX + 1.0));
}

// d, and up to a quarter more.
static double jittered(double d) { return d + jitter(d * JITTER); }

#define REKEY_JITTER 0.2
#define BEACON_JITTER 0.3
#define KEEPALIVE_SPREAD 3.0
#define LAN_EVERY 5.0
#define LAN_SPREAD 2.0

static double rekey_after(double t) { return t + REKEY_INTERVAL + jitter(REKEY_INTERVAL * REKEY_JITTER); }

// Takes a token from a bucket that fills at rate per second, up to burst. Returns 1 if there was one.
int take_token(double *tokens, double *at, double now, double rate, double burst) {
    if (now > *at) *tokens += (now - *at) * rate;
    if (*tokens > burst) *tokens = burst;
    *at = now;
    if (*tokens < 1.0) return 0;
    *tokens -= 1.0;
    return 1;
}

double retry_delay(int tries) { return jittered(backoff(tries, RETRY_BASE, HELLO_MAX_BACKOFF, RETRY_CAP)); }

peer_t *find_peer_by_id(chat_t *c, const uint8_t id[ID_LEN]) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && memcmp(c->peers[i].id, id, ID_LEN) == 0) return &c->peers[i];
    return NULL;
}
int peer_slot(chat_t *c, peer_t *p) { return (int)(p - c->peers); }

int live_count(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < c->peer_hi; i++) if (c->peers[i].used && c->peers[i].ok) n++;
    return n;
}
int pending_peer_count(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < c->peer_hi; i++) if (c->peers[i].used && !c->peers[i].ok) n++;
    return n;
}

// Whether p gets what's sent: never with a code that differs, and with comparing required, only once compared.
int peer_trusted(const chat_t *c, const peer_t *p) {
    return p->code_ok != CODE_DIFFERENT && (!c->verify_required || p->code_ok == CODE_SAME);
}

void forget_peer(chat_t *c, peer_t *p) {
    int slot = peer_slot(c, p);
    for (int i = 0; i < MAX_PENDING_MSGS; i++)
        if (c->pending[i].used && c->pending[i].peer_slot == slot) own_missed(c, p, &c->pending[i]);
    for (int i = 0; i < SENDQ_MAX; i++)
        if (c->sendq[i].used && c->sendq[i].peer_slot == slot) crypto_wipe(&c->sendq[i], sizeof c->sendq[i]);
    for (int i = 0; i < ROOMQ_MAX; i++)
        if (c->roomq[i].used && c->roomq[i].peer_slot == slot) c->roomq[i].used = 0;
    crypto_wipe(p, sizeof *p);
    while (c->peer_hi > 0 && !c->peers[c->peer_hi - 1].used) c->peer_hi--;
}

void rekey_drop_overlap(peer_t *p) {
    crypto_wipe(&p->old_send, sizeof p->old_send);
    crypto_wipe(&p->old_recv, sizeof p->old_recv);
    p->old_until = 0.0;
}

#define REPUBLISH_WAIT 5.0
#define REPUBLISH_SPREAD 25.0

void drop_peer(chat_t *c, peer_t *p, const char *why) {
    int was_ok = p->ok;
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    if (was_ok && p->vfy_set) {
        int g = c->gone_head;
        c->gone[g].used = 1;
        memcpy(c->gone[g].id, p->id, ID_LEN);
        memcpy(c->gone[g].vfy, p->vfy, VERIFY_LEN);
        c->gone_head = (g + 1) % GONE_MAX;
    }
    forget_peer(c, p);
    if (was_ok) ui_print(c, "* %s %s (%d online)", name, why, live_count(c) + 1);
    // The peer who left may have been the latest publisher of the room onion, so point it back at us.
    if (was_ok && c->tor && c->tor_hosting && c->tor_republish_at == 0.0)
        c->tor_republish_at = now_seconds() + REPUBLISH_WAIT + jitter(REPUBLISH_SPREAD);
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

int chat_online_count(const chat_t *c) { return live_count(c); }
int chat_pending_count(const chat_t *c) { return pending_peer_count(c); }
int chat_candidate_count(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used) n++;
    return n;
}

int chat_ready(const chat_t *c) { return c->created || c->ever_connected; }

// How many times a message is sent before it's given up on.
#define MSG_TRIES 5

static int pending_any(const chat_t *c) {
    for (int i = 0; i < MAX_PENDING_MSGS; i++) if (c->pending[i].used) return 1;
    return 0;
}

// A re-handshake still in progress with p: ours (not yet on our keys with p, or not yet sure p has
// the new chains), or p's (a key it announced that we haven't re-handshaken with yet).
int rehandshaking_with(const chat_t *c, const peer_t *p) {
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
    gen_random(c->cookie_secret, sizeof c->cookie_secret);
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
        p->next_rehello = now + jittered(REHELLO_EVERY);
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
    }
    if (c->tor_republish_at > 0.0 && now >= c->tor_republish_at) {
        c->tor_republish_at = 0.0;
        tor_republish_room(c->tor);
    }
}

// Whether the relays are needed, the same in both routes: always when set to always. Otherwise while
// nobody is reached yet, while a peer is reached (or being reached) only through them, or while a
// peer's own path has gone quiet and they may be needed next.
static int relays_needed(chat_t *c, double now) {
    if (c->route.nostr == NOSTR_ALWAYS) return 1;
    if (live_count(c) == 0) return 1;
    for (int i = 0; i < c->peer_hi; i++) {
        const peer_t *p = &c->peers[i];
        if (!p->used) continue;
        if (p->addr.kind == ADDR_NOSTR || (p->ok && now - p->seen > UDP_STALE / 2)) return 1;
    }
    for (int i = 0; i < MAX_CANDS; i++) if (c->cands[i].used && c->cands[i].addr.kind == ADDR_NOSTR) return 1;
    return 0;
}

// The most slots a fast transfer runs in one tick, if ticks fall behind.
#define FAST_BURST_MAX 64

// Messages older than the timer go from the ones kept for replies.
static void expire_recent(chat_t *c, double now) {
    unsigned timer = chat_timer(c, NULL, 0);
    for (int i = 0; timer && i < RECENT_MAX; i++)
        if (c->recent[i].used && now - c->recent[i].at > timer) crypto_wipe(&c->recent[i], sizeof c->recent[i]);
}

static void portmap_tick(chat_t *c, double now) {
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
}

static void beacon_tick(chat_t *c, double now) {
    if (c->nostr && nostr_relays_up(c->nostr) > 0 && now >= c->next_beacon) {
        double every = live_count(c) > 0 ? NOSTR_BEACON_CONNECTED : NOSTR_BEACON_ALONE;
        c->next_beacon = now + every + jitter(every * BEACON_JITTER);
        send_beacon(c);
    }
}

static void dht_tick(chat_t *c, double now) {
    if (c->dht_on) {
        c->dht.peers_now = live_count(c) > 0;
        if (dht_step(&c->dht, now) && !c->dht_summary_printed) {
            c->dht_summary_printed = 1;
            if (!c->net_quiet)
                ui_print(c, "* internet lookup done: %d nodes reached, %d peers found",
                         dht_queried_count(&c->dht), dht_found_count(&c->dht));
        }
    }
}

static void try_candidates(chat_t *c, double now) {
    for (int i = 0; i < MAX_CANDS; i++) {
        cand_t *cd = &c->cands[i];
        if (!cd->used) continue;
        // Already reached at this address, or (relays) under this id, so there's nothing left to try.
        if (candidate_reached(c, cd->addr)) { cd->used = 0; continue; }
        if (now >= cd->next_try) {
            if (!take_token(&c->probe_tokens, &c->probe_at, now, PROBE_RATE, PROBE_BURST)) break;
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
}

static void resend_messages(chat_t *c, double now) {
    for (int i = 0; i < MAX_PENDING_MSGS; i++) {
        pending_msg_t *pm = &c->pending[i];
        if (!pm->used) continue;
        if (now >= pm->next_retry) {
            peer_t *p = &c->peers[pm->peer_slot];
            if (!p->used || !p->ok || pm->tries >= MSG_TRIES) own_missed(c, p, pm);
            else { send_peer(c, p, pm->text); pm->tries++; pm->next_retry = now + resend_delay(c, p); }
        }
    }
}

// A peer we have no session with yet gets our hi again, and our kx if we start the session.
static void hello_pending(chat_t *c, double now) {
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || p->ok) continue;
        if (now - p->born > PENDING_TTL) forget_peer(c, p);
        else if (now >= p->next_hello) {
            p->next_hello = now + retry_delay(p->hello_tries);
            p->hello_tries++;
            send_room(c, c->hi_msg, p->addr, c->sock);
            char shortid[SHORT_ID_HEX + 1]; short_id(p->id, shortid);
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
}

static void keep_paths(chat_t *c, double now) {
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
            p->next_rehello = now + jittered(REHELLO_EVERY);
            send_room(c, c->hi_msg, p->addr, c->sock);
            if (c->net_verbose) ui_print(c, "* hi -> %s (%s)", p->nick, stuck ? "re-handshake" : "quiet");
        }
    }
}

static void alive_tick(chat_t *c, double now) {
    if (now >= c->next_alive) {
        c->next_alive = now + KEEPALIVE + jitter(KEEPALIVE_SPREAD);
        for (int i = 0; i < c->n_static; i++) add_candidate(c, c->static_peers[i]);
        if (c->tor) knock_room_slots(c, now);
    }
}

static void lan_tick(chat_t *c, double now) {
    if (c->lan_sock != SOCK_INVALID && now >= c->next_lan) {
        c->next_lan = now + LAN_EVERY + jitter(LAN_SPREAD);
        if (c->net_verbose) ui_print(c, "* lan beacon sent");
        char beacon[64]; snprintf(beacon, sizeof beacon, "lan\t%s\t%u", c->my_idhex, (unsigned)c->port);
        send_room(c, beacon, addr_broadcast_lan(c->lan_port), c->lan_sock);
        send_room(c, beacon, addr_loopback(c->lan_port), c->lan_sock);
    }
}

static void rekeys_and_timeouts(chat_t *c, double now) {
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
}

static void rekey_tick(chat_t *c, double now) {
    if (now >= c->next_rekey) {
        if (c->rekey_due == 0.0) c->rekey_due = now;
        double waited = now - c->rekey_due;
        if ((!pending_any(c) || waited > REKEY_DRAIN_GRACE) && (!rehandshaking(c) || waited > REKEY_DEFER_MAX)) {
            session_rekey(c, now);
            c->rekey_due = 0.0;
            c->next_rekey = rekey_after(now);
        }
    }
}

static void run_slots(chat_t *c, double now) {
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used) continue;
        if (p->serving) p->serve_at = now;
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
            for (int burst = 0; burst < FAST_BURST_MAX && now >= p->next_cover; burst++) {
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
        p->next_cover = now + jittered(iv);
    }
}

static void lonely_hint(chat_t *c, double now) {
    if (!c->created && !c->warned_lonely && !c->ever_connected && now - c->start > LONELY_HINT_AFTER) {
        c->warned_lonely = 1;
        ui_print(c, "* nobody has answered for this session yet - check the id and password with "
                     "whoever shared them, or they may not have started their app yet");
        // UDP and Tor sessions only meet on the relays. Without them the room splits in two without any
        // warning.
        if (!c->nostr)
            ui_print(c, "* Nostr relays are off here, so members using %s routing can't reach you - :set nostr fallback turns them on%s",
                     c->route.mode == ROUTE_TOR ? "UDP" : "Tor", c->route.mode == ROUTE_TOR ? " (through Tor)" : "");
        net_report(c);
    }
}

void chat_tick(chat_t *c, double now) {
    expire_recent(c, now);
    if (c->nostr) {
        if (relays_needed(c, now)) c->relays_until = now + RELAY_LINGER;
        nostr_set_active(c->nostr, now < c->relays_until);
    }
    transports_step(c, now);
    if (c->tor) tor_tick(c, now);
    portmap_tick(c, now);
    beacon_tick(c, now);
    dht_tick(c, now);
    try_candidates(c, now);
    if (c->move_req.used && !c->move_req.asked) move_ask_now(c, now);
    pass_move_keys(c);
    files_tick(c, now);
    resend_messages(c, now);
    hello_pending(c, now);
    keep_paths(c, now);
    alive_tick(c, now);
    lan_tick(c, now);
    rekeys_and_timeouts(c, now);
    rekey_tick(c, now);
    run_slots(c, now);
    lonely_hint(c, now);
}

void net_report(chat_t *c) {
    net_stats_t *st = &c->st;
    int cands = chat_candidate_count(c);
    if (c->route.mode == ROUTE_TOR) {
        char ts[300] = "not running";
        if (c->tor) tor_status(c->tor, ts, sizeof ts);
        ui_print(c, "* net: tor | %s | candidates to try: %d | handshakes in progress: %d | connected: %d",
                 ts, cands, pending_peer_count(c), live_count(c));
        char ns[300] = "off - members using UDP routing can't reach this session";
        if (c->nostr) nostr_status(c->nostr, ns, sizeof ns);
        ui_print(c, "* nostr relays through Tor: %s | peers through relays: %d", ns, relayed_count(c));
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
        ui_print(c, "* port mapping: %s | lan: %s | nostr fallback: %s | peers through relays: %d", pm,
                 c->lan_sock != SOCK_INVALID ? "on" : "off", ns, relayed_count(c));
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

void chat_set_nick(chat_t *c, const char *nick) {
    set_own_nick(c, nick);
    ui_print(c, "* your nickname is now %s", c->nick);
    char msg[8 + MAX_NICK];
    snprintf(msg, sizeof msg, "n\t%s", c->nick);
    send_to_live_peers(c, msg);
}

void chat_set_colour(chat_t *c, const uint8_t rgb[3]) {
    memcpy(c->my_color, rgb, 3);
    char hex[COLOR_HEX_LEN + 1]; color_to_hex(rgb, hex);
    ui_print_colored(c, c->my_color, "* your colour is now #%s", hex);
    char msg[sizeof "c\t" + COLOR_HEX_LEN]; snprintf(msg, sizeof msg, "c\t%s", hex);
    send_to_live_peers(c, msg);
}

void chat_set_history(chat_t *c, int on) {
    if (!c->persist == !on) return;
    c->persist = on != 0;
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) send_k_now(c, &c->peers[i]);
    if (live_count(c) > 0) ui_print(c, "* everyone here is told you %s", on ? "keep a history of this chat now" : "stopped keeping a history of it");
}

void chat_set_net_log(chat_t *c, int level) {
    c->net_verbose = level == NET_LOG_VERBOSE;
    c->net_quiet = level == NET_LOG_OFF;
}

// Only a peer whose code was compared is listened to, so nobody else can wipe the chat from under you.
unsigned chat_timer(const chat_t *c, char *who, size_t cap) {
    unsigned best = c->timer;
    if (who && best) copy_str(who, "you", cap);
    for (int i = 0; i < c->peer_hi; i++) {
        const peer_t *p = &c->peers[i];
        if (!p->used || !p->ok || !p->timer || (best && p->timer >= best) || !peer_trusted(c, p)) continue;
        best = p->timer;
        if (who && cap >= CHAT_NAME_LEN) chat_peer_name(c, p, who);
    }
    return best;
}

void chat_set_timer(chat_t *c, unsigned seconds) {
    if ((seconds && (seconds < TIMER_MIN || seconds > TIMER_MAX)) || c->timer == seconds) return;
    c->timer = seconds;
    int deaf = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        send_k_now(c, p);
        deaf += !p->can_timer;
    }
    char d[16], who[CHAT_NAME_LEN];
    chat_format_timer(seconds, d, sizeof d);
    if (seconds)
        ui_print(c, "* messages here go after %s from now: off the screen and out of memory, here and on every "
                    "chat here that keeps to it (a modified chat, or a screenshot, can keep anything)%s", d,
                 deaf ? ". Some here run a chat too old to keep to it" : "");
    else if (chat_timer(c, who, sizeof who))
        ui_print(c, "* you stopped asking for messages here to go - %s still asks", who);
    else
        ui_print(c, "* you stopped asking for messages here to go");
}

// From the session's key, so only its members can tell which history is this session's.
void chat_history_id(const chat_t *c, uint8_t out[CHAT_HISTORY_ID_LEN]) {
    static const char LABEL[] = "chat history v1";
    uint8_t h[SHA256_LEN];
    hmac_sha256(c->master, MASTER_LEN, (const uint8_t *)LABEL, sizeof LABEL - 1, h);
    memcpy(out, h, CHAT_HISTORY_ID_LEN);
    crypto_wipe(h, sizeof h);
}

void chat_set_identity(chat_t *c, identity_source_t source, const identity_keypair_t *idkp) {
    c->identity_source = source;
    if (source != IDENT_NONE) c->identity = *idkp;
    if (source == IDENT_NONE) ui_print(c, "* signing turned off - your messages here are no longer signed");
    else ui_print(c, "* signing key set - re-announcing it to everyone already here");
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) send_k_now(c, &c->peers[i]);
}

void module_log(void *ctx, int kind, const char *msg) {
    chat_t *c = ctx;
    if (kind == NET_LINE_PROBLEM || (kind == NET_LINE_DETAIL ? c->net_verbose : !c->net_quiet)) ui_print(c, "%s", msg);
}

static void module_deliver(void *ctx, const uint8_t *data, size_t len, addr_t from, double now) {
    uint8_t buf[FRAME_BUF_LEN];
    if (len > sizeof buf) return;
    memcpy(buf, data, len);
    on_relayed((chat_t *)ctx, buf, len, from, now);
}

// The room slots someone else may publish. Always worth a hi, since members publishing different
// slots only find each other by trying them. Each hi opens a stream: Tor's backoff paces the slots
// nobody publishes, and a stream that's open already took a hi, which either got an answer or won't.
static void knock_room_slots(chat_t *c, double now) {
    for (int i = 0; i < TOR_ROOM_SLOTS; i++) {
        addr_t a = tor_room_target(c->tor, i);
        if (i == tor_hosted_slot(c->tor) || known_addr(c, a) || !tor_can_open(c->tor, a, now)) continue;
        if (c->net_verbose && !tor_failing(c->tor, a)) ui_print(c, "* hi -> room slot %d", i);
        send_room(c, c->hi_msg, a, c->sock);
    }
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
    // In Tor mode the relays are where UDP peers can be met, and they're only reached through Tor:
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

void chat_tor_set_ports(chat_t *c, const char *socks, const char *control, const char *password) {
    if (!c->tor) return;
    copy_str(c->route.tor.socks, socks, sizeof c->route.tor.socks);
    copy_str(c->route.tor.control, control, sizeof c->route.tor.control);
    // c->route keeps the password set for a running tor, which chat_apply_routing compares.
    tor_set_ports(c->tor, socks, control, password ? password : c->route.tor.password);
    if (c->nostr) nostr_set_proxy(c->nostr, socks);
}

void chat_tor_connected(chat_t *c) {
    if (c->nostr) nostr_retry_now(c->nostr);
}

void chat_tor_refresh(chat_t *c) {
    if (!c->tor) return;
    tor_refresh(c->tor);
    if (c->nostr) nostr_reconnect(c->nostr);
}

void chat_init(chat_t *c, const chat_opts_t *o, chat_print_fn print, chat_notify_fn notify, void *ui) {
    memset(c, 0, sizeof *c);
    // Locked before any key is stored there. Best effort: a low RLIMIT_MEMLOCK only means they may be
    // swapped. The peers hold their chain keys.
    crypto_lock((uint8_t *)c + SECRETS_OFFSET, SECRETS_LEN);
    crypto_lock(c->peers, sizeof c->peers);
    // What's queued to send holds messages as typed, and the recent ones what was said.
    crypto_lock(c->sendq, sizeof c->sendq);
    crypto_lock(c->recent, sizeof c->recent);
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
    c->picture_noise = o->picture_noise;

    if (o->has_color) memcpy(c->my_color, o->color, 3);
    else chat_random_colour(c->my_color);

    c->identity_source = o->identity_source;
    if (c->identity_source != IDENT_NONE) c->identity = o->identity;
    c->moved = o->moved;
    if (c->moved) c->moved_key = o->moved_key;

    c->build = o->build;
    c->build.version[MAX_VERSION] = c->build.list[BUILD_LIST_LEN] = c->build.list_sig[MINISIGN_SIG_B64_LEN] = '\0';
    if (!version_ok(c->build.version)) c->build.ok = 0;
    // They're sent between tabs in "v".
    if (strspn(c->build.list, HEX_DIGITS ",") != strlen(c->build.list)
        || strspn(c->build.list_sig, BASE64_CHARS "=") != strlen(c->build.list_sig))
        c->build.list[0] = c->build.list_sig[0] = '\0';
    c->has_release_key = minisign_pubkey(o->release_key, c->release_key) == 0;
    c->has_backup_key = minisign_pubkey(o->release_backup_key, c->backup_key) == 0;

    gen_random(c->my_id, ID_LEN);
    gen_keypair(&c->keys);
    kem_gen_keypair(&c->kem_keys);
    c->keygen = 1;
    gen_random(c->cookie_secret, sizeof c->cookie_secret);
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
        uint8_t room_keys[TOR_ROOM_SLOTS][TOR_KEY_LEN], room_pubs[TOR_ROOM_SLOTS][TOR_PUB_LEN];
        for (int i = 0; i < TOR_ROOM_SLOTS; i++) derive_tor_room_key(c->master, i, room_keys[i], room_pubs[i]);
        c->tor = tor_new(&c->route.tor, (const uint8_t (*)[TOR_KEY_LEN])room_keys, (const uint8_t (*)[TOR_PUB_LEN])room_pubs,
                         module_deliver, module_log, c);
        crypto_wipe(room_keys, sizeof room_keys);
        c->started = c->tor != NULL;
        if (!c->started) c->start_error = "could not set up Tor";
        if (c->tor && c->created) { tor_host_room(c->tor, 0); c->tor_hosting = 1; }
        if (c->tor) { knock_room_slots(c, now_seconds()); start_nostr(c); }
    } else {
        // Without the main socket the caller abandons this session, so nothing else is started.
        c->sock = net_udp_open(o->port, NET_DUAL, &c->port);
        c->started = c->sock != SOCK_INVALID;
        if (!c->started) c->start_error = "could not open a UDP socket (is the port in use?)";
        if (c->started) start_dht_routing(c);
    }

    int n_static = c->route.mode == ROUTE_TOR ? 0 : o->n_peers;
    if (n_static < 0) n_static = 0;
    if (n_static > MAX_STATIC_PEERS) n_static = MAX_STATIC_PEERS;
    memcpy(c->static_peers, o->peers, sizeof(addr_t) * (size_t)n_static);
    c->n_static = n_static;

    c->persist = o->persist;
    c->start = now_seconds();
    c->next_rekey = rekey_after(c->start);
    c->probe_tokens = PROBE_BURST;
    c->probe_at = c->start;
    c->ck_tokens = CK_BURST;
    c->ck_at = c->start;
    c->roam_tokens = ROAM_BURST;
    c->roam_at = c->start;
}

void chat_shutdown(chat_t *c) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok)
            send_now(c, &c->peers[i], c->coming_back && c->peers[i].can_offline ? "off" : "bye");
    nostr_free(c->nostr);
    tor_free(c->tor);
    portmap_free(c->pm);
    stop_dht(c);
    net_close(c->sock);
    net_close(c->lan_sock);
    // Files we offered are closed, and downloads in progress don't leave half-written files behind.
    for (int i = 0; i < FILE_OFFERS_MAX; i++) if (c->files[i].used) file_free(&c->files[i]);

    crypto_unlock((uint8_t *)c + SECRETS_OFFSET, SECRETS_LEN);
    crypto_unlock(c->peers, sizeof c->peers);
    crypto_unlock(c->sendq, sizeof c->sendq);
    crypto_unlock(c->recent, sizeof c->recent);

    crypto_wipe(c, sizeof *c);
}

#define UI_LINE_MAX 2200

static void emit(chat_t *c, const char *text, const uint8_t *rgb, unsigned flags, int color_len, int file) {
    char hhmm[HHMM_LEN]; current_hhmm(hhmm);
    c->print(c->ui, hhmm, text, rgb, flags, color_len, file);
}

static void ui_vprint(chat_t *c, const uint8_t *rgb, unsigned flags, const char *fmt, va_list ap) {
    char msg[UI_LINE_MAX];
    vsnprintf(msg, sizeof msg, fmt, ap);
    emit(c, msg, rgb, flags, 0, 0);
}

void ui_print(chat_t *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    ui_vprint(c, NULL, 0, fmt, ap);
    va_end(ap);
}

void ui_warn(chat_t *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    ui_vprint(c, NULL, LINE_WARN, fmt, ap);
    va_end(ap);
}

void ui_print_colored(chat_t *c, const uint8_t rgb[3], const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    ui_vprint(c, rgb, 0, fmt, ap);
    va_end(ap);
}

void ui_chat_file(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text, int file) {
    char msg[UI_LINE_MAX];
    int head = snprintf(msg, sizeof msg, "%s%s:", mention ? "@ " : "", name);
    snprintf(msg + head, sizeof msg - (size_t)head, " %s", text);
    emit(c, msg, rgb, LINE_CHAT | (mention ? LINE_MENTION : 0u), head, file);
}

void ui_chat(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text) {
    ui_chat_file(c, rgb, mention, name, text, 0);
}

// Ours, numbered own_seq.
void ui_own(chat_t *c, const char *name, const char *text) {
    char msg[UI_LINE_MAX];
    int head = snprintf(msg, sizeof msg, "%s:", name);
    snprintf(msg + head, sizeof msg - (size_t)head, " %s", text);
    emit(c, msg, c->my_color, LINE_CHAT | LINE_OWN, head, 0);
}

// A direct message: its name says who it's between, so it has no "@ " in front even when it's to us.
void ui_direct(chat_t *c, const uint8_t rgb[3], int to_me, const char *name, const char *text) {
    char msg[UI_LINE_MAX];
    int head = snprintf(msg, sizeof msg, "%s:", name);
    snprintf(msg + head, sizeof msg - (size_t)head, " %s", text);
    emit(c, msg, rgb, LINE_CHAT | (to_me ? LINE_MENTION : LINE_OWN), head, 0);
}
