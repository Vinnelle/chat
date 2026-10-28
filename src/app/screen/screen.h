// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the rest of the app uses of screen/: what's on screen, the keys and commands, and the pages.
// app.h includes it, after the types it uses.
#ifndef CHAT_APP_SCREEN_H
#define CHAT_APP_SCREEN_H

#include "app/app.h"

// screen.c
int add_para(tui_para_t *p, int n, tui_para_kind_t kind, const char *text);
int install_mode(app_mode_t m);
// The page a mode shows: itself, for a page, or the one under its box (MODE_CHAT for the chat screen).
app_mode_t page_of(app_mode_t m);
int on_chat_screen(void);
tui_session_state_t session_state(const session_slot_t *s);
tui_view_t current_view(char *sub, size_t cap);
void chat_input(tui_bar_t *b, const tui_input_t *in);
void render_bar(void);
void render(void);

// keys.c
void handle_key(const tui_key_t *key);

// commands.c
extern const command_t APP_COMMANDS[];
extern const command_t *const ALL_COMMANDS[];
void begin_help(void);
int begin_install(const char *arg);
void move_yes(void);
void move_no(void);
void move_ask_key(const tui_key_t *key);
void move_tick(double now);
cmd_result_t app_help(void *ctx, const char *arg);
cmd_result_t app_changelog(void *ctx, const char *arg);
int file_arg(const char *arg, int *anyway);
cmd_result_t app_show(void *ctx, const char *arg);
cmd_result_t app_files(void *ctx, const char *arg);
cmd_result_t app_saveto(void *ctx, const char *arg);
cmd_result_t app_hide(void *ctx, const char *arg);
void render_help(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void help_key(const tui_key_t *key);
void run_command(const char *line);
cmd_result_t app_quit(void *ctx, const char *arg);
cmd_result_t app_quitall(void *ctx, const char *arg);
cmd_result_t app_copyid(void *ctx, const char *arg);
cmd_result_t app_invite(void *ctx, const char *arg);
cmd_result_t app_update(void *ctx, const char *arg);
void update_key(const tui_key_t *key);

// cmdline.c
int command_word(const char *word, int whole);
const char *complete_mention(const char *typed);
int suggest_command(const char *typed, int nth, tui_suggestion_t *out);

// pages.c
list_key_t list_key(const tui_key_t *key);
int section_digit(const tui_key_t *key);
void list_move(list_key_t k, int *sel, int n);
void settings_key(const tui_key_t *key);
void settings_search_key(const tui_key_t *key);
void settings_search_box(tui_dialog_t *d, tui_para_t *paras);
void sign_picker_key(const tui_key_t *key);
void paste_key(const tui_key_t *key);
void render_settings(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void render_sign_picker(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void begin_changelog(void);
void render_changelog(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void changelog_key(const tui_key_t *key);
int page_section_step(const tui_row_t *rows, int n, int sel, int dir);
int page_section_nth(const tui_row_t *rows, int n, int nth);

// files_page.c
void file_ask(int what, const file_entry_t *f);
int echo_fetch(session_slot_t *s, int num, int view, int anyway, const char *dir);
void file_ask_yes(void);
void file_ask_no(void);
int file_ask_paras(tui_para_t *paras, const char **title, const char **keys);
const char *files_hint(void);
void begin_files(void);
void render_files(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void files_key(const tui_key_t *key);
void view_forget(const session_slot_t *s);
void render_viewer(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void viewer_key(const tui_key_t *key);
const char *viewer_hint(void);

// browser.c
int path_is_root(const char *p);
void path_join(char *out, size_t cap, const char *dir, const char *name);
void path_parent(char *p);
int browser_load(browser_t *b, const char *path);
void browser_select(browser_t *b, const char *name);
void browser_entry_path(const browser_t *b, const dir_entry_t *e, char *out, size_t cap);
void browser_key(const tui_key_t *key);
void begin_send_browse(int asis);
void send_browser_key(const tui_key_t *key);
void begin_save_browse(int num, int anyway);
void save_browser_key(const tui_key_t *key);
void begin_key_export(void);
void export_browser_key(const tui_key_t *key);
void render_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void render_send_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void render_save_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void render_export_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);

// clipboard.c
// Public text goes on the clipboard with osc52_copy. A secret goes with copy_secret, and comes off
// again after CLIPBOARD_CLEAR_SECONDS, or as soon as chat quits, locks or panics.
#define CLIPBOARD_CLEAR_SECONDS 30
void osc52_copy(const char *text);
void copy_secret(const char *text);
void clipboard_clear_now(void);
void clipboard_tick(double now);
void copy_session_id(session_slot_t *s);
void copy_invite(session_slot_t *s);

// links.c
cmd_result_t app_open(void *ctx, const char *arg);
void open_link_key(const tui_key_t *key);

// lock.c
#define N_LOCK_AFTER 5
#define N_LOCK_KEYS 5
extern const char *const LOCK_AFTER_NAMES[N_LOCK_AFTER];
extern const int LOCK_AFTER_SECONDS[N_LOCK_AFTER];
extern const char *const LOCK_KEY_NAMES[N_LOCK_KEYS];
int lock_by_passphrase(void);
const char *lock_note(void);
int lock_key_is(const tui_key_t *key);
void lock_saw_key(void);
void lock_screen(void);
void lock_after_choose(int i);
void lock_tick(void);
void locked_key(const tui_key_t *key);
void pin_key(const tui_key_t *key);
void lock_forget(void);
cmd_result_t app_lock(void *ctx, const char *arg);

#endif
