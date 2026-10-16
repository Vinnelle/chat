// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Sending: each peer's slots, the records and room frames queued for them, and a frame's way out.
#include "core/engine.h"

// The DHT's datagrams, never masked since they're normal DHT traffic. Names are never sent: the
// bootstrap servers are looked up here.
void dht_out(void *ctx, const void *data, size_t len, const addr_t *to, const char *host, uint16_t port) {
    chat_t *c = ctx;
    (void)port;
    if (c->sock == SOCK_INVALID || host || !to) return;
    net_send(c->sock, data, len, *to);
}

// Every datagram is sent from here, over UDP, the relays or Tor depending on its address. In Tor
// mode nothing is sent over UDP. UDP traffic is masked first, so on the network it's random bytes.
// The relays and Tor already hide what they carry, and take it in the same form 0.3.1 sends.
void xmit(chat_t *c, sock_t sock, const void *data, size_t len, addr_t to) {
    switch (to.kind) {
        case ADDR_NOSTR:
            if (c->nostr) nostr_send(c->nostr, to, data, len, now_seconds());
            return;
        case ADDR_TOR:
            if (c->tor) tor_send(c->tor, to, data, len, now_seconds());
            return;
        default: {
            if (c->route.mode == ROUTE_TOR || sock == SOCK_INVALID) return;
            uint8_t masked[FRAME_BUF_LEN];
            if (len > sizeof masked) return;
            memcpy(masked, data, len);
            if (udp_mask(c->udp_key, masked, len) == 0) net_send(sock, masked, len, to);
        }
    }
}

static int room_pieces(size_t len) { return (int)((len + CHUNK_PAYLOAD - 1) / CHUNK_PAYLOAD); }

// The i-th piece of a room frame, padded to a whole cell.
static void room_piece(const uint8_t *frame, size_t len, const uint8_t id[CHUNK_ID_LEN], int i, int count,
                       uint8_t cell[UDP_CELL]) {
    size_t off = (size_t)i * CHUNK_PAYLOAD, n = len - off < CHUNK_PAYLOAD ? len - off : CHUNK_PAYLOAD;
    cell[0] = CHUNK_MAGIC0;
    cell[1] = CHUNK_MAGIC1;
    memcpy(cell + CHUNK_ID_AT, id, CHUNK_ID_LEN);
    cell[CHUNK_INDEX_AT] = (uint8_t)i;
    cell[CHUNK_COUNT_AT] = (uint8_t)count;
    store_be16(cell + CHUNK_LEN_AT, (uint16_t)len);
    memcpy(cell + CHUNK_HDR, frame + off, n);
    // Random instead of zeros, since a cell's last bytes pick the keystream it's masked with.
    gen_random(cell + CHUNK_HDR + n, CHUNK_PAYLOAD - n);
}

static peer_t *live_peer_at(chat_t *c, addr_t a) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok && addr_equal(c->peers[i].addr, a)) return &c->peers[i];
    return NULL;
}

int room_queued(const chat_t *c, int slot) {
    int n = 0;
    for (int i = 0; i < ROOMQ_MAX; i++) n += c->roomq[i].used && c->roomq[i].peer_slot == slot;
    return n;
}

// A room frame for a connected peer waits for its slots. A peer can have a few queued. Beyond
// that (junk replayed at it, for example) they're lost, like datagrams would be, and handshakes retry.
#define ROOMQ_PER_PEER 4
static void queue_room(chat_t *c, peer_t *p, const uint8_t *frame, size_t len, addr_t to) {
    int slot = peer_slot(c, p);
    if (room_queued(c, slot) >= ROOMQ_PER_PEER) return;
    for (int i = 0; i < ROOMQ_MAX; i++) {
        roomq_t *q = &c->roomq[i];
        if (q->used) continue;
        q->used = 1;
        q->peer_slot = slot;
        q->seq = ++c->queue_seq;
        q->to = to;
        gen_random(q->id, sizeof q->id);
        q->next_piece = 0;
        q->pieces = room_pieces(len);
        q->len = len;
        memcpy(q->frame, frame, len);
        return;
    }
}

void send_room(chat_t *c, const char *text, addr_t to, sock_t sock) {
    uint8_t frame[FRAME_BUF_LEN];
    size_t len;
    if (room_seal(c->room_key, text, strlen(text), frame, sizeof frame, &len) != 0 || len > ROOM_FRAME_MAX) return;
    // A connected peer's frames go in its slots, like everything else sent to it.
    peer_t *p = sock == c->sock ? live_peer_at(c, to) : NULL;
    if (p) { queue_room(c, p, frame, len, to); return; }
    // Relays and Tor streams take whole frames; UDP takes cells.
    if (to.kind != ADDR_UDP) { xmit(c, sock, frame, len, to); return; }
    int count = room_pieces(len);
    uint8_t id[CHUNK_ID_LEN];
    gen_random(id, CHUNK_ID_LEN);
    for (int i = 0; i < count; i++) {
        uint8_t cell[UDP_CELL];
        room_piece(frame, len, id, i, count, cell);
        xmit(c, sock, cell, UDP_CELL, to);
    }
}

int relayed_count(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < c->peer_hi; i++) n += c->peers[i].used && c->peers[i].ok && c->peers[i].addr.kind == ADDR_NOSTR;
    return n;
}

double cover_interval(chat_t *c, const peer_t *p) {
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
double relay_fast_interval(chat_t *c, double iv) {
    double fast = (double)relayed_count(c) / NOSTR_FAST_RATE;
    if (fast < NOSTR_FAST_INTERVAL) fast = NOSTR_FAST_INTERVAL;
    return fast < iv ? fast : iv;
}

// What a frame through the relays carries has to fit in an event, with the sender and recipient.
_Static_assert(RELAY_FRAME <= NOSTR_WRAP_PLAIN - 2 * ID_LEN - 2, "a relay frame has to fit in a relay event");

ratchet_t *send_chain_for(peer_t *p) {
    if (!p->send_chain.started && p->old_until > 0.0 && p->old_send.started) return &p->old_send;
    return &p->send_chain;
}

// Seals text as the chain's next frame, with a body of body bytes (a UDP cell, or a relay frame)
// unless it needs more.
int frame_on_chain(ratchet_t *chain, const char *text, size_t body, uint8_t *frame, size_t frame_cap,
                   size_t *len, uint32_t *index) {
    uint32_t idx = chain->index;
    ratchet_t advanced;
    uint8_t mk[MSG_KEY_LEN];
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
int queue_record(chat_t *c, peer_t *p, const char *text, int old_chain) {
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

int send_peer(chat_t *c, peer_t *p, const char *text) { return queue_record(c, p, text, 0); }

// Sent immediately, outside the slots. Only used for the "bye" or "off" of a session that's ending.
void send_now(chat_t *c, peer_t *p, const char *text) {
    uint8_t frame[UDP_CELL]; size_t len; uint32_t idx;
    if (frame_on_chain(send_chain_for(p), text, SESSION_PAD_TARGET, frame, sizeof frame, &len, &idx) != 0) return;
    xmit(c, c->sock, frame, len, p->addr);
    crypto_wipe(frame, sizeof frame);
}

// A peer's slot: exactly one datagram. The oldest thing waiting goes first: a piece of a room
// frame, or a record and, for a peer that reads several per frame, the ones after it on the same
// chain while they fit. With nothing waiting, a "nop".
#define ROOM_OVERTAKE_MAX 2
#define BATCH_MAX 16
void run_slot(chat_t *c, peer_t *p) {
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
    int overtake = rq && first && readable && p->room_waited < ROOM_OVERTAKE_MAX;
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
    sendq_t *taken[BATCH_MAX];
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
        if (n_taken && (!p->batches || pos + 1 + l > cap || n_taken == BATCH_MAX)) break;
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

void send_to_live_peers(chat_t *c, const char *msg) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) send_peer(c, &c->peers[i], msg);
}
