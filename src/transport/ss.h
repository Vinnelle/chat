// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_SS_H
#define CHAT_SS_H

#include <stddef.h>
#include <stdint.h>
#include "platform/net.h"

// Shadowsocks 2022 (SIP022), for chat's own traffic through a server its user runs. The network
// in between sees one stream of random bytes to that server, and peers, DHT nodes and relays see
// the server's address instead of this one. Datagrams (peers, the DHT) go through its UDP relay,
// and each relay connection (the Nostr relays' wss://) through a TCP tunnel of its own. A name
// goes to the server as a name, for it to look up: nothing here asks local DNS but for the
// server's own name.
//
// Methods 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm and 2022-blake3-chacha20-poly1305,
// with one key (no multi-user identity headers). Both ends' clocks have to be within 30 seconds.

#define SS_URL_MAX 320
#define SS_HOST_MAX 256

typedef enum { SS_AES_128_GCM, SS_AES_256_GCM, SS_CHACHA20_POLY1305 } ss_method_t;

typedef struct {
    ss_method_t method;
    uint8_t psk[32];
    size_t key_len;
    char host[SS_HOST_MAX];
    uint16_t port;
} ss_config_t;

// An ss:// link as SIP002 writes one: ss://METHOD:KEY@HOST:PORT, the userinfo percent-encoded
// (as 2022 links are) or base64url. 0, or -1 with why.
int ss_parse_url(const char *url, ss_config_t *out, char *why, size_t why_cap);
const char *ss_method_name(ss_method_t m);

// ---- UDP relay ----

// One relay session: a session id of its own, and so one address on the server's side for as
// long as it lasts. The server end (for tests) opens what a client seals, and seals replies.
typedef struct ss_udp ss_udp_t;
ss_udp_t *ss_udp_new(const ss_config_t *c, int server);
void ss_udp_free(ss_udp_t *u);

// Room for a datagram of len bytes, sealed.
#define SS_UDP_OVERHEAD (24 + 8 + 8 + 1 + 8 + 8 + 2 + 1 + 1 + SS_HOST_MAX + 2 + 16)
// Every client packet is padded to about this size (the padding stops at 900 bytes, as the spec
// has it): short DHT messages and chat's cells look alike to anyone between here and the server.
#define SS_UDP_TARGET 1100

// Seals data for to, or for host:port when host isn't NULL. Returns the packet's length, or -1.
long ss_udp_seal(ss_udp_t *u, const addr_t *to, const char *host, uint16_t port, const uint8_t *data,
                 size_t len, uint8_t *out, size_t cap);
// Opens a packet in place. *data points at the datagram inside and *from gets the address it came
// from (a server end: where it's for). Returns the datagram's length, or -1 for anything that
// isn't a fresh packet of this session's.
long ss_udp_open(ss_udp_t *u, uint8_t *pkt, size_t len, addr_t *from, const uint8_t **data, double now);

// ---- TCP tunnel ----

// Byte I/O underneath a stream, as net_tcp_send and net_tcp_recv do it: bytes moved, 0 when it
// would block, -1 on an error or (recv) a closed connection.
typedef struct {
    int (*send)(void *ctx, const void *data, size_t len);
    int (*recv)(void *ctx, void *buf, size_t cap);
    void *ctx;
} ss_io_t;

// A proxied connection to host:port. The request goes out with the first data sent, so the
// server sees one write of header and data together. A server end (for tests) reads the target
// from the request: ss_stream_target.
typedef struct ss_stream ss_stream_t;
ss_stream_t *ss_stream_new(const ss_config_t *c, const ss_io_t *io, const char *host, uint16_t port, int server);
void ss_stream_free(ss_stream_t *s);
// Takes data (all of it, or 0 to say try again later) or -1. Plaintext out, sealed, may wait in
// the stream for the socket: ss_stream_flush pushes it.
int ss_stream_send(ss_stream_t *s, const void *data, size_t len);
int ss_stream_recv(ss_stream_t *s, void *buf, size_t cap);
// 0 once everything sealed has gone out, 1 while some waits, -1 on an error.
int ss_stream_flush(ss_stream_t *s);
const char *ss_stream_error(const ss_stream_t *s);
// 1 once the stream has failed for good (ss_stream_error says why).
int ss_stream_dead(const ss_stream_t *s);
// A server end's view of the request: the target, once its header is in.
int ss_stream_target(const ss_stream_t *s, char *host, size_t cap, uint16_t *port);

#endif
