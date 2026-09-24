// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_CHAT_H
#define CHAT_CHAT_H

#include "net.h"
#include "crypto.h"
#include "dht.h"
#include "cmd.h"
#include <stdint.h>
#include <stdio.h>

#define MAX_PEERS 50
#define MAX_PENDING_PEERS 64
#define MAX_CANDS 64
#define MAX_PENDING_MSGS 128
#define MAX_NICK 24
#define MAX_TEXT 250
#define MAX_SESSION_NAME 64
#define LAN_PORT 47474
#define KEEPALIVE 10.0
#define PEER_TIMEOUT 40.0
#define PENDING_TTL 45.0
#define LONELY_HINT_AFTER 15.0

#define CAND_MAX_TRIES 12
#define HELLO_MAX_BACKOFF 5
#define RETRY_BASE 2.0
#define RETRY_CAP 32.0

#define HANDSHAKE_BUF_LEN 2700

#define CHUNK_MAGIC0 0xC5
#define CHUNK_MAGIC1 0x7A
#define CHUNK_HDR 8
#define CHUNK_PAYLOAD 1000
#define CHUNK_MAX 4

#define REASM_SLOTS 32
#define REASM_TTL 5.0

#ifndef REKEY_INTERVAL
#define REKEY_INTERVAL 300.0
#endif

#define REKEY_DRAIN_GRACE 20.0

#define REKEY_OVERLAP 20.0

#define COVER_INTERVAL 1.5
#define COVER_MAX_RATE 8.0

typedef struct {
    unsigned rx;
    unsigned rx_chunks, rx_chunk_done;
    unsigned room_ok;
    unsigned hi, ck, hi2, hi2_bad, kx, lan;
    unsigned session_ok;
    unsigned other;
    unsigned connects;
    addr_t src[6];
    unsigned src_n[6];
    int n_src;
} net_stats_t;

typedef struct {
    int used;
    addr_t from;
    uint8_t id[4];
    int count;
    unsigned got;
    size_t last_len;
    double born;
    uint8_t buf[CHUNK_MAX * CHUNK_PAYLOAD];
} reasm_t;

typedef enum { NOTIFY_NONE = 0, NOTIFY_MENTIONS = 1, NOTIFY_ALL = 2 } notify_mode_t;
typedef enum { IDENT_NONE = 0, IDENT_NATIVE = 1, IDENT_AGE = 2, IDENT_PGP = 3 } identity_source_t;

typedef enum { VERIFY_UNVERIFIED = 0, VERIFY_VERIFIED = 1, VERIFY_FAILED = 2 } verify_state_t;

typedef struct {
    int used;
    uint8_t id[ID_LEN];
    char nick[MAX_NICK + 1];
    addr_t addr;
    double seen, born, next_hello;
    int hello_tries;
    int ok;
    uint8_t pub[PUB_LEN];
    ratchet_t send_chain;
    ratchet_t recv_chain;
    uint8_t vfy[VERIFY_LEN];
    uint8_t color[3];
    int persists;
    identity_source_t identity_source;
    verify_state_t identity_state;
    uint8_t identity_pub[ID_SIGN_PUB_LEN];
    uint8_t identity_fp[ID_FP_LEN];

    uint8_t kem_pub[KEM_PUB_LEN];
    uint8_t prk_partial[32];
    uint8_t kem_ct[KEM_CT_LEN];

    uint32_t keygen;
    double next_cover;
    int vfy_set;

    ratchet_t old_send, old_recv;
    double old_until;
} peer_t;

typedef struct {
    int used;
    addr_t addr;
    int tries;
    double next_try;
} cand_t;

typedef struct {
    int used;
    char mid[9];
    int peer_slot;
    uint8_t frame[700];
    size_t frame_len;
    int tries;
    double next_retry;
} pending_msg_t;

typedef void (*chat_print_fn)(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                              unsigned flags, int color_len);

#define LINE_CHAT 1u
#define LINE_MENTION 2u

typedef void (*chat_notify_fn)(void *ui, const char *nick, const char *text, int mentioned);

typedef struct {

    char nick[MAX_NICK + 1];
    char session_name[MAX_SESSION_NAME + 1];
    uint8_t my_id[ID_LEN];

    keypair_t keys;
    kem_keypair_t kem_keys;
    uint8_t master[MASTER_LEN];
    uint8_t room_key[ROOM_KEY_LEN];
    uint8_t fingerprint[FP_LEN];
    uint8_t cookie_secret[32];
    int created;
    uint8_t my_color[3];

    identity_source_t identity_source;
    identity_keypair_t identity;

    int persist;
    FILE *log_fp;

    notify_mode_t notify_mode;

    int once, once_used;

    int net_verbose;

    sock_t sock, lan_sock;
    uint16_t port;

    peer_t peers[MAX_PEERS + MAX_PENDING_PEERS];
    int peer_hi;
    cand_t cands[MAX_CANDS];
    addr_t static_peers[16];
    int n_static;
    pending_msg_t pending[MAX_PENDING_MSGS];
    addr_t self_addrs[8];
    int n_self_addrs;

    int dht_on;
    dht_state_t dht;

    double start, next_alive, next_lan;
    uint32_t keygen;
    double next_rekey;
    double rekey_due;

    int warned_lonely, ever_connected, dht_summary_printed;

    uint32_t seen_mids[2048];
    int seen_head, seen_count;

    char my_idhex[ID_LEN * 2 + 1];
    char hi_msg[HANDSHAKE_BUF_LEN];

    reasm_t reasm[REASM_SLOTS];
    net_stats_t st;

    chat_print_fn print;
    chat_notify_fn notify;
    void *ui;
} chat_t;

typedef struct {
    char nick[MAX_NICK + 1];
    char session_name[MAX_SESSION_NAME + 1];
    char password[256];
    uint16_t port;
    addr_t peers[16];
    int n_peers;
    int dht_on;
    int created;
    int once;
    notify_mode_t notify_mode;
    int persist;
    char log_path[512];

    identity_source_t identity_source;
    identity_keypair_t identity;
    int has_color;
    uint8_t color[3];
} chat_opts_t;

void chat_init(chat_t *c, const chat_opts_t *o, chat_print_fn print, chat_notify_fn notify, void *ui);
void chat_shutdown(chat_t *c);

void chat_tick(chat_t *c, double now);
void chat_on_socket_readable(chat_t *c, sock_t which, double now);

// Plain-mode entry point: "/name args" runs a command, anything else is sent. Returns 0 on /quit.
int chat_submit_line(chat_t *c, const char *line, double now);

// Runs "name args" (no leading '/') from CHAT_COMMANDS against this session.
cmd_result_t chat_run_command(chat_t *c, const char *line);
void chat_send_text(chat_t *c, const char *text, double now);

extern const command_t CHAT_COMMANDS[];

void chat_set_nick(chat_t *c, const char *nick);

void chat_set_identity(chat_t *c, identity_source_t source, const identity_keypair_t *idkp);

int chat_sockets(chat_t *c, sock_t out[2]);
int chat_online_count(const chat_t *c);
int chat_pending_count(const chat_t *c);
int chat_candidate_count(const chat_t *c);

int chat_ready(const chat_t *c);
const char *chat_verify_label(verify_state_t s);

typedef struct { const char *name; uint8_t r, g, b; } named_color_t;
extern const named_color_t COLOR_PALETTE[];
extern const int COLOR_PALETTE_N;

int parse_color(const char *text, uint8_t rgb[3]);

#endif
