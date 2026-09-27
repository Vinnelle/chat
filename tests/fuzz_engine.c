// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The whole receive path of a session, alice, already connected to bob. The first input byte
// picks what the rest becomes:
//   0  a datagram from a stranger          1  a datagram from bob's address
//   2  a room message (sealed with the room key, as any room member could send)
//   3  a session message from bob (sealed on bob's chain to alice: an authenticated peer)
// Both sessions go back to the connected snapshot before every input. tests/seeds/engine holds
// one input per message type.
#include "core/chat.h"
#include "fake_net.h"
#include "common/util.h"
#include <stdlib.h>
#include <string.h>

static chat_t A, B, A0, B0;
static double t0;

static void quiet(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len) {
    (void)ui; (void)hhmm; (void)text; (void)rgb; (void)flags; (void)color_len;
}

static void start(chat_t *c, const char *nick, uint16_t port, uint16_t peer_port, int created) {
    chat_opts_t o;
    memset(&o, 0, sizeof o);
    copy_str(o.nick, nick, sizeof o.nick);
    copy_str(o.session_name, "FUZZSESSION", sizeof o.session_name);
    o.port = port;
    o.peers[0] = fake_net_addr(peer_port);
    o.n_peers = 1;
    o.created = created;
    chat_init(c, &o, quiet, NULL, NULL);
}

static peer_t *bobs_view_of_alice(void) {
    for (int i = 0; i < B.peer_hi; i++) if (B.peers[i].used && B.peers[i].ok) return &B.peers[i];
    return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    crypto_setup();
    start(&A, "alice", 41001, 41002, 1);
    start(&B, "bob", 41002, 41001, 0);
    t0 = now_seconds();
    for (int i = 0; i < 200 && !(chat_online_count(&A) && chat_online_count(&B)); i++) {
        chat_on_socket_readable(&A, A.sock, t0);
        chat_on_socket_readable(&B, B.sock, t0);
        chat_tick(&A, t0);
        chat_tick(&B, t0);
    }
    if (!chat_online_count(&A) || !bobs_view_of_alice()) abort();
    fake_net_clear();
    A0 = A;
    B0 = B;
    return 0;
}

// Peer ids are random, so inputs name them with markers: \x01A becomes alice's id in hex,
// \x01B bob's. Without that no input could ever carry a real origin id.
static size_t expand_ids(const uint8_t *in, size_t n, uint8_t *out, size_t cap) {
    char a[ID_LEN * 2 + 1], b[ID_LEN * 2 + 1];
    hex_encode(A.my_id, ID_LEN, a);
    hex_encode(B.my_id, ID_LEN, b);
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        const char *id = NULL;
        if (in[i] == 1 && i + 1 < n && (in[i + 1] == 'A' || in[i + 1] == 'B')) id = in[i + 1] == 'A' ? a : b;
        size_t len = id ? ID_LEN * 2 : 1;
        if (o + len > cap) break;
        if (id) { memcpy(out + o, id, len); i++; }
        else out[o] = in[i];
        o += len;
    }
    return o;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    A = A0;
    B = B0;
    fake_net_clear();
    int mode = data[0] & 3;
    static uint8_t text[4096];
    size = expand_ids(data + 1, size - 1, text, sizeof text);
    data = text;

    addr_t to = fake_net_addr(A.port), from = mode == 0 ? fake_net_addr(5555) : fake_net_addr(B.port);
    uint8_t frame[4096];
    size_t len = 0;
    if (mode <= 1) {
        if (size > sizeof frame) return 0;
        memcpy(frame, data, size);
        len = size;
    } else if (mode == 2) {
        if (room_seal(A.room_key, data, size, frame, sizeof frame, &len) != 0) return 0;
    } else {
        peer_t *p = bobs_view_of_alice();
        uint8_t mk[32];
        ratchet_t next;
        if (!p || ratchet_peek(&p->send_chain, p->send_chain.index, mk, &next) != 0) return 0;
        if (session_seal(mk, p->send_chain.index, data, size, frame, sizeof frame, &len) != 0) return 0;
    }
    fake_net_inject(from, to, frame, len);
    chat_on_socket_readable(&A, A.sock, t0 + 1.0);
    chat_tick(&A, t0 + 1.0);
    return 0;
}
