// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_NOSTR_H
#define CHAT_NOSTR_H

#include <stddef.h>
#include <stdint.h>
#include "platform/net.h"
#include "crypto/crypto.h"

// Datagrams over Nostr relays, for peers that can't reach each other directly.
//
// Relays see as little as possible. Each datagram is one ephemeral event (relays pass it on and
// don't store it), signed with a key made for that event only, with a random ephemeral kind and a
// timestamp a few seconds off. It has one tag, which changes every ten minutes and only room
// members can work out. The content is the same size for every event: sender, recipient,
// datagram and random padding, sealed together under the room's wrap key with a fresh nonce. So
// a relay can't tell which events come from the same person, who they're for, or what kind of
// message they hold.
//
// Each ten minute tag has its own connections: a new one to each relay, with a new subscription
// id (and through Tor, a new circuit), asking for that tag only. Around the change, the next one
// opens a minute or two early and the last one closes a minute or two late, to allow for clock
// differences. A relay still sees the address each connection comes from (the same one every ten
// minutes, unless it's a Tor exit), when events come and go, and which tag a connection asks for,
// which every member of the room also asks for.
//
// Every member gets every event for the room and drops those addressed to someone else. Peers
// appear as ADDR_NOSTR addresses holding their session id; the all-zero id means everyone.

#define NOSTR_MAX_RELAYS 6
#define NOSTR_URL_MAX 128
#define NOSTR_EPOCH 600

typedef struct nostr nostr_t;

typedef void (*nostr_deliver_fn)(void *ctx, const uint8_t *data, size_t len, addr_t from, double now);
// verbose_only: a detail only shown with verbose network logging. Otherwise it gets its own
// console line.
typedef void (*nostr_log_fn)(void *ctx, int verbose_only, const char *msg);

// proxy: NULL connects to relays directly. Otherwise (Tor mode) every connection goes through
// that SOCKS proxy, never directly, and "" means none is known yet, so nothing connects until
// nostr_set_proxy sets one. Relays start inactive, and nostr_set_active connects them.
nostr_t *nostr_new(const uint8_t tag_key[NOSTR_KEY_LEN], const uint8_t wrap_key[NOSTR_KEY_LEN],
                   const uint8_t my_id[ID_LEN], const char (*relays)[NOSTR_URL_MAX], int n_relays,
                   const char *proxy, nostr_deliver_fn deliver, nostr_log_fn log, void *ctx);
void nostr_free(nostr_t *n);
void nostr_set_proxy(nostr_t *n, const char *socks);
// The proxy's tor has just connected to the Tor network, so anything that failed before is retried.
void nostr_retry_now(nostr_t *n);
// On: connect and stay connected. Off: close every connection and open none until it's on again.
void nostr_set_active(nostr_t *n, int on);
int nostr_active(const nostr_t *n);

// All relay I/O: connecting, reading, writing, reconnecting.
void nostr_step(nostr_t *n, double now);
int nostr_sockets(const nostr_t *n, sock_t *out, int max);

// The address that reaches every room member on the relays.
addr_t nostr_everyone(void);
// A datagram to one peer or, to nostr_everyone(), to all. Returns -1 if no relay took it.
int nostr_send(nostr_t *n, addr_t to, const uint8_t *data, size_t len, double now);

int nostr_relays_up(const nostr_t *n);
int nostr_relay_total(const nostr_t *n);
void nostr_status(const nostr_t *n, char *out, size_t cap);

// Checks a relay URL: wss://host[:port][/path]. Returns 0 if chat can use it.
int nostr_url_ok(const char *url);

#endif
