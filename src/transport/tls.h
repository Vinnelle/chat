// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TLS_H
#define CHAT_TLS_H

#include <stddef.h>
#include "platform/net.h"

// A TLS client over a non-blocking TCP socket, or anything that moves bytes like one, checked
// against the system's root certificates.

typedef struct tls_conn tls_conn_t;

// Byte I/O like net_tcp_send and net_tcp_recv: returns bytes moved, 0 when it would block, -1 on
// an error or (recv) a closed connection.
typedef struct {
    int (*send)(void *ctx, const void *data, size_t len);
    int (*recv)(void *ctx, void *buf, size_t cap);
    void *ctx;
} tls_io_t;

// Loads the root certificates once. Returns 0, or -1 with the reason in err.
int tls_setup(char *err, size_t cap);

tls_conn_t *tls_new(sock_t s, const char *host);
tls_conn_t *tls_new_io(const tls_io_t *io, const char *host);
// 1 once the handshake is done, 0 while it needs more I/O, -1 if it failed (see tls_error).
int tls_handshake(tls_conn_t *t);
// Bytes moved, 0 when the socket would block, -1 on an error or a closed connection.
int tls_write(tls_conn_t *t, const void *data, size_t len);
int tls_read(tls_conn_t *t, void *buf, size_t cap);
const char *tls_error(const tls_conn_t *t);
// Frees the connection. The socket stays open for the caller to close.
void tls_free(tls_conn_t *t);

#endif
