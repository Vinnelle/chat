// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_FAKE_NET_H
#define CHAT_FAKE_NET_H

#include "net.h"

// Called for each datagram a session sends; returning nonzero drops it.
typedef int (*fake_net_filter_fn)(void *ctx, addr_t from, addr_t to, const void *data, size_t len);
extern fake_net_filter_fn fake_net_filter;
extern void *fake_net_filter_ctx;

addr_t fake_net_addr(uint16_t port);
// Queues a datagram as though `from` had sent it.
void fake_net_inject(addr_t from, addr_t to, const void *data, size_t len);
int fake_net_pending(void);
void fake_net_clear(void);

#endif
