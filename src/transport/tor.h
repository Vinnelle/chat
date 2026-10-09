// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TOR_H
#define CHAT_TOR_H

#include <stddef.h>
#include <stdint.h>
#include "platform/net.h"
#include "crypto/crypto.h"

// Datagrams over Tor, for sessions that must not show anyone their IP address. Needs a running
// tor (the system service, or Tor Browser) with its control port on.
//
// Each session publishes an onion service of its own, and one of the room's onion services. The
// room has TOR_ROOM_SLOTS of them, their keys derived from the session id and password. The
// creator takes slot 0, and a joiner takes a slot where nobody answered. Everyone keeps trying
// the slots they don't publish, gets the members' own onion addresses from whoever answers, and
// connects to those. One shared slot wouldn't work: Tor hands out the newest descriptor, so two
// members publishing the same one could only ever reach themselves.
// All the services are removed when the session ends. Datagrams are sent over Tor streams as
// 2-byte length-prefixed frames.

#define TOR_VPORT 7474
#define TOR_ROOM_SLOTS 6
#define TOR_ADDR_LEN 56
#define TOR_HOST_MAX 64
#define TOR_PASSWORD_MAX 128

typedef struct tor tor_t;

typedef struct {
    char socks[TOR_HOST_MAX];     // host:port of Tor's SOCKS port
    char control[TOR_HOST_MAX];   // host:port of Tor's control port
    char password[TOR_PASSWORD_MAX];   // for HashedControlPassword; empty uses cookie or no auth
} tor_opts_t;

typedef void (*tor_deliver_fn)(void *ctx, const uint8_t *data, size_t len, addr_t from, double now);
typedef void (*tor_log_fn)(void *ctx, int verbose_only, const char *msg);

extern const tor_opts_t TOR_DEFAULTS;

tor_t *tor_new(const tor_opts_t *o, const uint8_t room_keys[TOR_ROOM_SLOTS][TOR_KEY_LEN],
               const uint8_t room_pubs[TOR_ROOM_SLOTS][TOR_PUB_LEN], tor_deliver_fn deliver, tor_log_fn log, void *ctx);
void tor_free(tor_t *t);

// Points a session at another tor, and the password its control port takes: the one chat
// started, or one it found running. An empty control address means none yet; the session waits.
void tor_set_ports(tor_t *t, const char *socks, const char *control, const char *password);

// Checks whether a running tor is one chat can use: its control port answers and lets chat log
// in (onion services need that). Nothing is published. tor_probe_result: 1 usable (the ports
// that worked in socks and control), -1 no tor answered, -2 one answered but chat can't use it
// (the reason in why), 0 still checking.
tor_t *tor_probe_new(const tor_opts_t *o);
int tor_probe_result(const tor_t *t, char *socks, char *control, char *why, size_t why_cap);

void tor_step(tor_t *t, double now);
int tor_sockets(const tor_t *t, sock_t *out, int max);

// Queues a datagram. Sending to a target with no stream opens one through Tor.
int tor_send(tor_t *t, addr_t to, const uint8_t *data, size_t len, double now);

// The address to send to for the onion service at onion (56 characters, no ".onion").
// Returns -1 for a malformed address, or our own.
int tor_target(tor_t *t, const char *onion, addr_t *out);
addr_t tor_room_target(const tor_t *t, int slot);

// Publishes one of the room's onion services (once): slot, or -1 for one where nobody answered.
// tor_republish_room publishes it again, so its descriptor points here again after someone else
// who published the same slot has left.
void tor_host_room(tor_t *t, int slot);
int tor_hosted_slot(const tor_t *t);
void tor_republish_room(tor_t *t);

// Our own onion address, "" until Tor has published it.
const char *tor_my_onion(const tor_t *t);
void tor_status(const tor_t *t, char *out, size_t cap);

// Onion service v3 address of an ed25519 public key, and a check that s is one.
void onion_address(const uint8_t pub[TOR_PUB_LEN], char out[TOR_ADDR_LEN + 1]);
int onion_valid(const char *s);

#endif
