// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_PORTMAP_H
#define CHAT_PORTMAP_H

#include <stddef.h>
#include <stdint.h>
#include "net.h"

// Asks the home router to forward a UDP port to this session, so peers behind NATs that can't
// be hole-punched can still reach it. Tries PCP, then NAT-PMP, then UPnP-IGD, and keeps the
// mapping renewed. The mapping is removed when the session ends.

typedef struct portmap portmap_t;

typedef void (*portmap_log_fn)(void *ctx, int verbose_only, const char *msg);

portmap_t *portmap_new(uint16_t internal_port, portmap_log_fn log, void *ctx);
void portmap_step(portmap_t *p, double now);
// Removes the mapping (waits up to about a second for the router), then frees.
void portmap_free(portmap_t *p);

// 1 once a mapping is up, with the port the router opened.
int portmap_mapped(const portmap_t *p, uint16_t *external_port);
void portmap_status(const portmap_t *p, char *out, size_t cap);

// Parsers for what the router sends, exposed for the fuzz target.
int portmap_parse_control_url(const char *xml, size_t len, char *service, size_t scap, char *url, size_t ucap);
int portmap_http_body(const char *resp, size_t len, int *status, char *body, size_t cap);

#endif
