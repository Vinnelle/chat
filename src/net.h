// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_NET_H
#define CHAT_NET_H

#include <stddef.h>
#include <stdint.h>

#include "os.h"

#define ADDR_STR_LEN 72

typedef struct {
    uint8_t ip[16];
    uint32_t scope;
    uint16_t port;
    uint8_t is_v6;
} addr_t;

#define NET_REUSE 1u
#define NET_DUAL  2u

void net_startup(void);
void net_shutdown(void);

sock_t net_udp_open(uint16_t port, unsigned flags, uint16_t *bound_port);
void net_close(sock_t s);

int net_send(sock_t s, const void *data, size_t len, addr_t to);
int net_recv(sock_t s, void *buf, size_t buflen, addr_t *from);

void net_wait(sock_t *socks, int *ready, int n, int timeout_ms);

#define ADDR_RESOLVE_MAX 8
int addr_resolve_all(const char *host, uint16_t port, addr_t *out, int max);
int addr_resolve(const char *host, uint16_t port, addr_t *out);
void addr_to_string(addr_t a, char out[ADDR_STR_LEN]);
int addr_parse_hostport(const char *hostport, addr_t *out);
int addr_equal(addr_t a, addr_t b);
addr_t addr_broadcast_lan(uint16_t port);
addr_t addr_loopback(uint16_t port);

void addr_set_v4(addr_t *a, const void *net_order_4, uint16_t port);
int addr_is_v4(addr_t a);

#endif
