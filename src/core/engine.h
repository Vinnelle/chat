// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the engine's files share with each other: chat.c, names.c, messages.c, send.c, handshake.c,
// receive.c, move.c, transfer.c and commands.c. The app uses chat.h.
#ifndef CHAT_ENGINE_H
#define CHAT_ENGINE_H

#include "core/chat.h"
#include "core/trust.h"
#include "common/util.h"
#include "common/bytewords.h"
#include "platform/platform.h"
#include "common/image.h"
#include "common/clean.h"
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

// Timers wait up to this much longer, at random, so they don't line up between peers.
#define JITTER 0.25
// A buffer for a sealed handshake: the text, with its nonce, padding and tag.
#define FRAME_BUF_LEN (HANDSHAKE_BUF_LEN + 128)
#define COLOR_HEX_LEN 6

// Who a direct message is between, in brackets after the sender's name, since no nick can hold '('.
#define DM_ARROW "\xe2\x86\x92"

#define MAX_FIELDS 8

// What a reply shows in front of its text: "↪ NICK: QUOTE · ".
#define REPLY_PREFIX_MAX (MAX_NICK + QUOTE_MAX + 32)

typedef int (*session_sig_fn)(const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *,
                              const uint8_t *);

// chat.c
int split_tabs(char *s, char *fields[], int max);
double jitter(double spread);
int take_token(double *tokens, double *at, double now, double rate, double burst);
double retry_delay(int tries);
peer_t *find_peer_by_id(chat_t *c, const uint8_t id[ID_LEN]);
int peer_slot(chat_t *c, peer_t *p);
int live_count(const chat_t *c);
int pending_peer_count(const chat_t *c);
int peer_trusted(const chat_t *c, const peer_t *p);
void forget_peer(chat_t *c, peer_t *p);
void rekey_drop_overlap(peer_t *p);
void drop_peer(chat_t *c, peer_t *p, const char *why);
int rehandshaking_with(const chat_t *c, const peer_t *p);
void net_report(chat_t *c);
void module_log(void *ctx, int kind, const char *msg);
void ui_print(chat_t *c, const char *fmt, ...) PRINTF_LIKE(2, 3);
void ui_warn(chat_t *c, const char *fmt, ...) PRINTF_LIKE(2, 3);
void ui_print_colored(chat_t *c, const uint8_t rgb[3], const char *fmt, ...) PRINTF_LIKE(3, 4);
void ui_chat_file(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text, int file);
void ui_chat(chat_t *c, const uint8_t rgb[3], int mention, const char *name, const char *text);
void ui_own(chat_t *c, const char *name, const char *text);
void ui_direct(chat_t *c, const uint8_t rgb[3], int to_me, const char *name, const char *text);

// names.c
int nick_ieq(const char *a, const char *b);
void color_to_hex(const uint8_t rgb[3], char out[COLOR_HEX_LEN + 1]);
void short_id(const uint8_t id[ID_LEN], char out[SHORT_ID_HEX + 1]);
void nick_skeleton(const char *nick, char *out, size_t cap);
void set_peer_nick(peer_t *p, const char *nick);
void set_own_nick(chat_t *c, const char *nick);
int has_mention(const char *text, const char *nick);
const char *code_mark(const chat_t *c, const peer_t *p);

// messages.c
void gen_mid(char out[MID_HEX + 1]);
int seen_has(chat_t *c, const char *mid);
void seen_add(chat_t *c, const char *mid);
void set_ignored(chat_t *c, const uint8_t id[ID_LEN], int on);
void recent_add(chat_t *c, const char *mid, const uint8_t origin[ID_LEN], const char *nick, const char *text,
                double now);
const recent_msg_t *recent_find(const chat_t *c, const char *mid);
const recent_msg_t *recent_from(const chat_t *c, const uint8_t *origin, const char *arg, const char **rest);
void reply_prefix(const chat_t *c, const char *reply_mid, char *out, size_t cap);
void pending_clear(pending_msg_t *pm);
void own_settled(chat_t *c, unsigned own);
void own_missed(chat_t *c, peer_t *p, pending_msg_t *pm);
double resend_delay(chat_t *c, const peer_t *p);
void part_mid(const char *mid, int i, char out[MID_HEX + 1]);
void track_message(chat_t *c, peer_t *p, const char *mid, const char *record, unsigned own, double now);
int send_message(chat_t *c, peer_t *q, const char *mid, const char *idhex, const char *nick, const char *text,
                 unsigned own, double now);
int send_reply(chat_t *c, peer_t *q, const char *mid, const char *reply_mid, const char *idhex,
               const char *nick, const char *text, const char *prefix, unsigned own, double now);
int ack_record(chat_t *c, peer_t *p, const char *mid);
void send_text(chat_t *c, const char *text_in, const recent_msg_t *reply, double now);

// send.c
void dht_out(void *ctx, const void *data, size_t len, const addr_t *to, const char *host, uint16_t port);
void xmit(chat_t *c, sock_t sock, const void *data, size_t len, addr_t to);
int room_queued(const chat_t *c, int slot);
void send_room(chat_t *c, const char *text, addr_t to, sock_t sock);
int relayed_count(const chat_t *c);
double cover_interval(chat_t *c, const peer_t *p);
double relay_fast_interval(chat_t *c, double iv);
ratchet_t *send_chain_for(peer_t *p);
int frame_on_chain(ratchet_t *chain, const char *text, size_t body, uint8_t *frame, size_t frame_cap,
                   size_t *len, uint32_t *index);
int queue_record(chat_t *c, peer_t *p, const char *text, int old_chain);
int send_peer(chat_t *c, peer_t *p, const char *text);
void send_now(chat_t *c, peer_t *p, const char *text);
void run_slot(chat_t *c, peer_t *p);
void send_to_live_peers(chat_t *c, const char *msg);

// handshake.c
int check_session_sig(const chat_t *c, const peer_t *p, session_sig_fn verify, const uint8_t *key,
                      const uint8_t *sig);
int known_addr(const chat_t *c, addr_t a);
void add_candidate(chat_t *c, addr_t a);
void dht_candidate_cb(void *ctx, addr_t a);
int candidate_reached(chat_t *c, addr_t a);
void refresh_hi(chat_t *c);
void send_kx(chat_t *c, peer_t *p, addr_t to);
void send_k_now(chat_t *c, peer_t *p);
int we_initiate(const chat_t *c, const peer_t *p);
int path_rank(addr_t a);
void introduce(chat_t *c, peer_t *newp);
void send_onion(chat_t *c, peer_t *p);
int version_ok(const char *v);
void tell_build(chat_t *c, peer_t *p);
void check_build(chat_t *c, peer_t *p, const char *version, const uint8_t proof[BUILD_HASH_LEN],
                 const char *list, const char *sig);
void on_room(chat_t *c, char *plain, addr_t addr, double now);
int on_chunk(chat_t *c, const uint8_t *d, size_t len, addr_t addr, double now);

// receive.c
void on_relayed(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now);
void announce_join(chat_t *c, peer_t *p);
int on_frame(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now);
void transports_step(chat_t *c, double now);

// move.c
void move_ask_now(chat_t *c, double now);
void on_move(chat_t *c, peer_t *p, char **f, double now);
void tell_came_with(chat_t *c, peer_t *p);
void check_came_with(chat_t *c, peer_t *p);
void pass_move_keys(chat_t *c);
void say_nobody_moves(chat_t *c, const chat_move_plan_t *plan);

// transfer.c
void file_free(file_entry_t *e);
int file_downloading_from(const chat_t *c, const peer_t *p);
void file_offer_all(chat_t *c, peer_t *p);
cmd_result_t cmd_send(void *ctx, const char *arg);
cmd_result_t cmd_download(void *ctx, const char *arg);
cmd_result_t cmd_cancel(void *ctx, const char *arg);
cmd_result_t cmd_files(void *ctx, const char *arg);
int file_next_chunk(chat_t *c, peer_t *p, char *text, size_t *pos, size_t cap);
void file_on_record(chat_t *c, peer_t *p, char **f, int n, double now);
void files_tick(chat_t *c, double now);

#endif
