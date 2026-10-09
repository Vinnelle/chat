// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_NET_H
#define CHAT_NET_H

#include <stddef.h>
#include <stdint.h>

#include "os.h"

#define ADDR_STR_LEN 72

// Where a datagram goes. ADDR_UDP is a real address. The others name a peer on a relayed
// transport. ip holds an id the transport picked (a Nostr key prefix, a Tor stream id) and port is 1.
typedef enum { ADDR_UDP = 0, ADDR_NOSTR = 1, ADDR_TOR = 2 } addr_kind_t;
#define ADDR_KINDS 3

#define IP4_LEN 4
#define IP6_LEN 16

typedef struct {
    uint8_t ip[IP6_LEN];
    uint32_t scope;
    uint16_t port;
    uint8_t is_v6;
    uint8_t kind;
} addr_t;

static inline size_t addr_ip_len(addr_t a) { return a.is_v6 ? IP6_LEN : IP4_LEN; }

addr_t addr_virtual(addr_kind_t kind, const uint8_t id[IP6_LEN]);

#define NET_REUSE 1u
#define NET_DUAL  2u

void net_startup(void);
void net_shutdown(void);

sock_t net_udp_open(uint16_t port, unsigned flags, uint16_t *bound_port);
void net_close(sock_t s);

int net_send(sock_t s, const void *data, size_t len, addr_t to);
int net_recv(sock_t s, void *buf, size_t buflen, addr_t *from);

// Non-blocking TCP. net_tcp_connect starts a connection. net_tcp_connect_done returns 1 once it's
// connected, 0 while it's still connecting, -1 if it failed. send/recv return the bytes moved, 0
// when they would block, -1 on an error or (recv) a closed connection.
sock_t net_tcp_connect(addr_t to);
int net_tcp_connect_done(sock_t s);
sock_t net_tcp_listen_loopback(uint16_t *port);
sock_t net_tcp_accept(sock_t listener);
int net_tcp_send(sock_t s, const void *data, size_t len);
int net_tcp_recv(sock_t s, void *buf, size_t cap);

// The local address the system would send from to reach dest. Sends nothing.
int net_local_addr_toward(addr_t dest, addr_t *out);
// Sends this IPv4 socket's multicast out of the interface holding local_ip, not wherever the
// routing table points (a VPN, often).
int net_set_multicast_if(sock_t s, const uint8_t local_ip[IP4_LEN]);

void net_wait(sock_t *socks, int *ready, int n, int timeout_ms);

#define ADDR_RESOLVE_MAX 8
int addr_resolve_all(const char *host, uint16_t port, addr_t *out, int max);
int addr_resolve(const char *host, uint16_t port, addr_t *out);
// True for names that only Tor can reach: those must never go to DNS.
int host_is_onion(const char *host);
// IP literals only. Never uses DNS.
int addr_resolve_numeric(const char *host, uint16_t port, addr_t *out);
void addr_to_string(addr_t a, char out[ADDR_STR_LEN]);
int addr_parse_hostport(const char *hostport, addr_t *out);
// 0 if hostport has addr_parse_hostport's form; the host isn't looked up.
int addr_check_hostport(const char *hostport);
// Like addr_parse_hostport, for addresses from the network: "IP:PORT" or "[IPv6]:PORT" only.
int addr_parse_ip_port(const char *hostport, addr_t *out);
int addr_equal(addr_t a, addr_t b);
addr_t addr_broadcast_lan(uint16_t port);
addr_t addr_loopback(uint16_t port);

void addr_set_v4(addr_t *a, const void *net_order_4, uint16_t port);
int addr_is_v4(addr_t a);

#endif
