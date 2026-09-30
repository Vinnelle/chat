// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_BRIDGES_H
#define CHAT_BRIDGES_H

#include <stddef.h>

// Tor bridges for chat's own tor, so the network sees a pluggable transport's traffic instead of
// a connection to a Tor relay: Snowflake (WebRTC through volunteers' browser proxies, reached
// through a domain-fronted broker), obfs4 (random bytes), WebTunnel (HTTPS to a web server), and
// the rest Tor Browser uses. The bridges are other people's, so nothing needs a server here; the
// transport's program (snowflake-client, lyrebird, obfs4proxy) has to be installed.

#define BRIDGE_MAX 8
#define BRIDGE_LINE_MAX 1024
#define BRIDGE_TEXT_MAX 600

typedef struct {
    int n;
    int builtin;   // the built-in Snowflake bridges
    char line[BRIDGE_MAX][BRIDGE_LINE_MAX];
} bridges_t;

// "snowflake" for the built-in Snowflake bridges, or bridge lines as bridges.torproject.org or a
// torrc gives them ("Bridge " in front is optional), separated by ';' or line breaks; "" or "off"
// for none. Replaces what's in out. 0, or -1 with why.
int bridges_parse(const char *text, bridges_t *out, char *why, size_t why_cap);
// Adds text's bridges to those in out (the built-in ones can't be mixed with others).
int bridges_add(const char *text, bridges_t *out, char *why, size_t why_cap);

// "built-in Snowflake", "3 bridges (obfs4, webtunnel)" or "off".
void bridges_describe(const bridges_t *b, char *out, size_t cap);

// Finds the program for transport, looking for it as program (one of the names it goes by): its
// full path in out, or -1. Asked again with the next name when there's another.
typedef int (*bridge_find_fn)(void *ctx, const char *transport, const char *program, char *out, size_t cap);

// The torrc lines that make tor use the bridges: UseBridges, a ClientTransportPlugin for each
// program the transports need (found with find), and a Bridge line each. 0, or -1 with why: a
// transport chat doesn't know, or one whose program isn't installed.
int bridges_torrc(const bridges_t *b, bridge_find_fn find, void *ctx, char *out, size_t cap, char *why, size_t why_cap);

#endif
