// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the rest of the app uses of sessions/: sessions.c, history.c, pics.c and torlink.c (rooms.c
// has rooms.h). app.h includes it, after the types it uses.
#ifndef CHAT_APP_SESSIONS_H
#define CHAT_APP_SESSIONS_H

#include "app/app.h"

// sessions.c
void session_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len,
                   int file);
void session_delivery(void *ui, unsigned own, chat_delivery_t what, const char *name);
int session_ready(const session_slot_t *s);
void timers_tick(double now);
void send_notification(const char *nick, const char *text, int mentioned);
void session_notify(void *ui, const char *nick, const char *text, int mentioned);
int slot_index(session_slot_t *s);
session_slot_t *find_free_slot(void);
void lock_scrollbacks(session_slot_t *s);
void release_scrollbacks(session_slot_t *s);
void select_session(session_slot_t *s);
session_slot_t *first_session(void);
void close_session(session_slot_t *s);
void select_step(int dir);
void console_note(session_slot_t *s, const char *fmt, ...) PRINTF_LIKE(2, 3);
extern chat_build_t g_self_build;
void app_session_opts(chat_opts_t *o);
session_slot_t *start_session(const char *session_name, const char *password, int created, uint16_t port,
                              const addr_t *peers, int n_peers);
session_slot_t *start_moved_session(const chat_move_to_t *to);
void begin_prompt(app_mode_t mode);
void begin_new_session(void);
void end_prompt(void);
cmd_result_t app_new(void *ctx, const char *arg);
cmd_result_t app_join(void *ctx, const char *arg);
cmd_result_t app_keep(void *ctx, const char *arg);
void begin_rooms(void);
void rooms_key(const tui_key_t *key);
void rooms_join_at_start(void);
// Kept in the open save to open again (Reopen sessions), so it goes offline rather than leaving.
int session_kept(const session_slot_t *s);
void reopen_tick(void);
void keep_sessions_saved(void);
cmd_result_t app_call(void *ctx, const char *arg);
void contacts_tick(void);

// history.c
int history_possible(void);
void history_add(session_slot_t *s, const char *text, const uint8_t *rgb, int mention, int color_len);
void histories_write(void);
void history_start(session_slot_t *s, int show);
void history_stop(session_slot_t *s, int write);
void history_sync(double now);
void history_expire(session_slot_t *s, unsigned seconds);

// pics.c
pic_t *pic_find(session_slot_t *s, int num);
void pic_free(pic_t *p);
void pics_free(session_slot_t *s);
const tui_image_t *pic_for(const void *ctx, int file);
const char *pic_why(const session_slot_t *s, int num);
int fetch_progress(const chat_t *e, const file_entry_t *f, char *text, size_t cap);
const tui_progress_t *progress_for(const void *ctx, int file);
// image_thumbnail, in a child process of its own where the platform can do that.
int thumb_decode(const uint8_t *data, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
                 char *why, size_t why_cap);
void session_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len);

// torlink.c
extern const char *const TOR_LAUNCH_NAMES[];
extern tor_link_t g_tor;
void sync_update_proxy(void);
void tor_link_ensure(double now);
void tor_link_step(double now);
void tor_link_stop(void);
// Whose tor Tor mode uses ("own" or "running", NULL until that's known), and how far it has got.
const char *tor_link_whose(void);
void tor_link_status(char *out, size_t cap);
void tor_link_restart(void);
// Bridge lines as typed (separated by ';'), as "LINE; LINE" in out, or -1 with why. How many there
// are, and their transports in kinds ("obfs4, snowflake").
int bridges_parse(const char *typed, char *out, size_t cap, char *why, size_t why_cap);
int bridge_count(const char *text, char *kinds, size_t cap);
// The transport programs bridges can need, found as chat's own tor would find them: their paths, and a
// line for the settings page saying which are there.
int transport_paths(char out[][TOR_PATH_MAX], int max);
void transport_line(char *out, size_t cap);
void tor_state_choose(int on);
void tor_state_yes(void);
void tor_state_no(void);
cmd_result_t app_newtor(void *ctx, const char *arg);

#endif
