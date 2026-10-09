// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_SOCKS_H
#define CHAT_SOCKS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// SOCKS5 (RFC 1928) to Tor's SOCKS port, logging in with a username (RFC 1929): Tor gives each
// username circuits of its own. These only make and read the messages; the caller sends them.
#define SOCKS_VERSION 5
#define SOCKS_USER_LEN 16
#define SOCKS_HELLO_LEN 3
#define SOCKS_LOGIN_LEN (SOCKS_USER_LEN + 4)
#define SOCKS_CONNECT_LEN(host_len) (7 + (host_len))
// The replies to the greeting and the login, and the start of the reply to CONNECT.
#define SOCKS_REPLY_LEN 2
#define SOCKS_CONNECT_HEAD 5

enum { SOCKS_AUTH_USERNAME = 2, SOCKS_CMD_CONNECT = 1, SOCKS_ATYP_IPV4 = 1, SOCKS_ATYP_NAME = 3, SOCKS_ATYP_IPV6 = 4 };

// SOCKS5, offering one method: a username and password.
static inline void socks_hello(uint8_t out[SOCKS_HELLO_LEN]) {
    out[0] = SOCKS_VERSION;
    out[1] = 1;
    out[2] = SOCKS_AUTH_USERNAME;
}

// The greeting's reply chose the username and password.
static inline int socks_hello_ok(const uint8_t r[SOCKS_REPLY_LEN]) {
    return r[0] == SOCKS_VERSION && r[1] == SOCKS_AUTH_USERNAME;
}

// The login: the username, and a password Tor ignores.
static inline void socks_login(uint8_t out[SOCKS_LOGIN_LEN], const char user[SOCKS_USER_LEN]) {
    out[0] = 1;
    out[1] = SOCKS_USER_LEN;
    memcpy(out + 2, user, SOCKS_USER_LEN);
    out[2 + SOCKS_USER_LEN] = 1;
    out[3 + SOCKS_USER_LEN] = 'x';
}

// CONNECT to a name (at most 255 bytes) and port, for Tor to look up at its end.
static inline size_t socks_connect(uint8_t *out, const char *host, size_t host_len, uint16_t port) {
    out[0] = SOCKS_VERSION;
    out[1] = SOCKS_CMD_CONNECT;
    out[2] = 0;
    out[3] = SOCKS_ATYP_NAME;
    out[4] = (uint8_t)host_len;
    memcpy(out + 5, host, host_len);
    out[5 + host_len] = (uint8_t)(port >> 8);
    out[6 + host_len] = (uint8_t)port;
    return SOCKS_CONNECT_LEN(host_len);
}

// The whole length of CONNECT's reply, from its first SOCKS_CONNECT_HEAD bytes, or 0 if it's no reply.
static inline size_t socks_connect_reply_len(const uint8_t r[SOCKS_CONNECT_HEAD]) {
    return r[3] == SOCKS_ATYP_IPV4 ? 10 : r[3] == SOCKS_ATYP_IPV6 ? 22 : r[3] == SOCKS_ATYP_NAME ? (size_t)7 + r[4] : 0;
}

#endif
