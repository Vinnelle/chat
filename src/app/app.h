// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What src/app's files share: the app's state, and what one file uses of another's.
#ifndef CHAT_APP_H
#define CHAT_APP_H

#include "core/chat.h"
#include "core/trust.h"
#include "crypto/crypto.h"
#include "crypto/age.h"
#include "crypto/pgp.h"
#include "platform/net.h"
#include "platform/platform.h"
#include "app/tui.h"
#include "common/util.h"
#include "app/update.h"
#include "app/install.h"
#include "transport/torproc.h"
#include "common/image.h"
#include "common/qr.h"
#include "common/toml.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include "os.h"
#include "build_stamp.h"

#ifdef CHAT_TEST_BUILD
#define TEST_BUILD 1
#define TEST_LABEL "testing " CHAT_BUILD_ID
#else
#define TEST_BUILD 0
#define TEST_LABEL ""
#endif

#define MAX_SESSIONS 12
// A new session's id: this many characters from random_session_id.
#define SESSION_ID_LEN 10
#define MAX_PEER_ARGS 16

#define PEER_ARG_LEN 256

// A picture fetched to show: its thumbnail, drawn under the line that offered it while shown, or
// why it can't be shown.
#define MAX_PICS 16
typedef struct {
    int used, num, shown;
    image_thumb_t th;
    tui_image_t ti;
    char why[96];
} pic_t;

// Frees a thumbnail, wiping it first since it's a picture from the conversation.
static inline void thumb_free(image_thumb_t *t) {
    if (t->rgb) crypto_wipe(t->rgb, (size_t)t->w * (size_t)t->h * 3);
    image_thumb_free(t);
}

typedef struct {
    chat_t engine;
    tui_scrollback_t sb;
    tui_scrollback_t console;
    pic_t pics[MAX_PICS];
    int unread;      // messages that came while another session was on screen
    int mentioned;   // and one of them mentions you
    // While on screen, the messages from new_at (in sb.total's count) onwards arrived while it wasn't,
    // and a line separates them from the rest until you leave it or send something.
    int has_new;
    unsigned new_at;
    int initialising;
    int scroll;   // the newest messages hidden below the chat after scrolling back
    char name[MAX_SESSION_NAME + 1];
    // While its history is kept: the lines so far (HISTORY_LINE's), in locked memory, the save they're
    // kept in, and whether they've changed since they were written there.
    char *hist;
    size_t hist_len;
    int hist_dirty;
    char hist_save[INSTALL_NAME_MAX + 1];
} session_slot_t;

typedef enum {
    MODE_HELP,
    MODE_CHANGELOG,
    MODE_SETTINGS,
    MODE_SETTINGS_EDIT,
    MODE_SIGN_CHOICE,
    MODE_SIGN_BROWSE,
    MODE_SEND_BROWSE,
    MODE_SAVE_BROWSE,
    MODE_FILES,
    MODE_FILE_VIEW,
    MODE_FILE_ASK,
    MODE_SIGN_PASTE,
    MODE_SIGN_PASSWORD,
    MODE_SIGN_PATH,
    MODE_CHAT,
    MODE_NEW_PASSWORD,
    MODE_JOIN_ID,
    MODE_JOIN_PASSWORD,
    MODE_INSTALL,
    MODE_INSTALL_PASS,
    MODE_INSTALL_PASS2,
    MODE_INSTALL_UNLOCK,
    MODE_INSTALL_EXISTING,
    MODE_INSTALL_PICK,
    MODE_INSTALL_OVERWRITE,
    MODE_INSTALL_NAME,
    MODE_INSTALL_FIRST,
    MODE_UNINSTALL,
    MODE_SAVES,
    MODE_UNLOCK,
    MODE_DEVICE_LOCK,
    MODE_FACTOR,
    MODE_CODE_SETUP,
    MODE_KEY_WAIT,
    MODE_KEY_PIN,
    MODE_UNLOCK_CODE,
    MODE_SHADOW_PASS,
    MODE_SHADOW_PASS2,
    MODE_UPDATE
} app_mode_t;

// What a security key is being touched for: to register it for the open save or the new one
// :install is making, or to open a save, at the start or for :install.
typedef enum { KP_FACTOR, KP_NEW_SAVE, KP_UNLOCK, KP_INSTALL_UNLOCK } key_purpose_t;

// KEY_MADE is a new random key, KEY_DERIVED one made from a password on this device.
typedef enum { KEY_MADE, KEY_DERIVED, KEY_FILE, KEY_PASTED } key_origin_t;

// A PGP key's fingerprint covers its creation time, so a key made from a password always
// gets this one (2026-01-01) to keep its fingerprint.
#define DERIVED_PGP_CREATED 1767225600u

#define MAX_DIR_ITEMS 512
#define KEY_PATH_MAX 1024
// A folder being browsed, or where something is saved, as the app keeps and shows it.
#define APP_PATH_MAX 900
#define TOR_PATH_MAX 512

typedef struct {
    char name[200];   // a folder's ends in '/'
    int is_dir;
} dir_entry_t;

typedef struct {
    char path[APP_PATH_MAX];
    dir_entry_t items[MAX_DIR_ITEMS];
    int n_items;
    int selected;
} browser_t;

typedef struct {
    session_slot_t sessions[MAX_SESSIONS];
    int used[MAX_SESSIONS];
    session_slot_t *selected;
    char nick[MAX_NICK + 1];
    int color_enabled;
    routing_t route;
    int route_chosen;
    int nostr_flag;   // what --nonostr or --nostr-always asked for, or -1
    notify_mode_t notify_mode;
    notify_preview_t notify_preview;
    int verify_optional;
    int net_verbose;
    uint16_t default_port;
    int settings_sel;
    int settings_page;   // the section shown: settings_sel's, or the one whose Done button it is
    int settings_rows[8];   // each section's row selected last, which Tab goes back to
    int help_sel;
    int changelog_scroll, changelog_most;
    char message[200];   // the bottom bar's result of the last action, until the next key
    int onboarding;   // the settings page chat opens on: its Done button starts chat
    int sign_sel;
    key_origin_t key_origin;       // where the identity in use came from
    uint32_t pgp_created;          // a PGP key made here: its creation time, which its fingerprint covers
    identity_source_t load_kind;   // AGE or PGP: what the key file browser, the path field or the paste page takes
    char key_path[KEY_PATH_MAX];   // a key from a file (KEY_FILE): the file's full path, or "" if it isn't known
    int path_from_browser;         // the path field was opened from the browser, so Esc goes back there
    int tor_launch;
    char tor_path[TOR_PATH_MAX];
    uint64_t file_cap;   // 0: the default
    int fast_files;
    int betas;
    int history;    // keep each session's history, sealed in the save open
    int autosave;   // what's changed is saved as it changes, while installed
    // Locked to this device: the open save, or with none open, the new one :install is making for it
    // (install_for). device_want is what the DEVICE LOCK box asks to change it to, and device_back
    // where it goes back to.
    // device_new: the box is for the new save :install is making, before its passphrase.
    int device_lock, device_want, device_new;
    app_mode_t device_back;
    // What locking would use here. DEVICE_NONE: it can't, and device_why says why. Checked at the
    // start, and again whenever something that shows it opens.
    device_kind_t device_kind;
    char device_why[200];
    // A security key and an authenticator code, like the device lock. seckey_ok: security keys work
    // here (seckey_why if not).
    int key_factor, code_factor, seckey_ok;
    char seckey_why[200];
    // One of those turned on with no save open asks to :install first, and install_for is the factor
    // (INSTALL_FACTOR_) that :install then sets up. install_back: the page :install's boxes are over
    // and go back to, the chat or the settings page.
    unsigned install_for;
    app_mode_t install_back;
    // The open save deletes itself after this many wrong passphrases (0 off); with none open, what
    // the next save :install makes starts with. Mirrored to the save's unsealed tries file.
    int destroy_limit;
    char shadow_pass[INSTALL_PASS_MAX];   // the shadow passphrase while its box asks for it again to confirm
    // The FACTOR box turns factor (INSTALL_FACTOR_) on (factor_want) or off, from the settings page or
    // the chat (factor_back); factor_new: it's a step of :install making a new save. key_purpose: what
    // the security key is touched for, and key_pin what to send it if it asks for its PIN.
    unsigned factor;
    int factor_want, factor_new;
    app_mode_t factor_back;
    key_purpose_t key_purpose;
    char key_pin[64];
    int key_stage, key_touches;   // what its thread waits for (seckey_stage_t), and the touches it's had
    // The new authenticator secret, in base32 and as the link a QR code holds. code_qr: its box shows
    // the QR code in place of its text (Tab).
    char code_b32[40];
    char code_uri[160];
    int code_qr;
    // The startup unlock's passphrase came from CHAT_INSTALL_PASSWORD, and waits in install_pass
    // for the security key or the code the save needs.
    int unlock_env;
    uint8_t color[3];
    identity_source_t identity_source;
    identity_keypair_t identity;
    // installed: what :install saved is open and kept up to date. locked: it exists but is still
    // sealed. install_pass holds the passphrase while it's typed the second time.
    int installed, locked;
    int saved_key_known;
    uint8_t saved_key_pub[ID_SIGN_PUB_LEN];
    char saved_key_path[KEY_PATH_MAX];   // what :install saved is the path to a key file: that path, else ""
    char install_pass[INSTALL_PASS_MAX];
    int unlock_at_start;
    // The saves :install made, to pick from at start when there's more than one, and the save
    // :install or :uninstall acts on while its box is open.
    install_save_t saves[INSTALL_SAVES_MAX];
    int n_saves, save_sel;
    char save_target[INSTALL_NAME_MAX + 1];
    // :install for a save that's sealed: after its passphrase, save what's in use over it (1, only
    // while another save is open), or use what's saved there (0). install_pick: the save to use is
    // picked from the list of saves. save_named: :install or :uninstall was given a NAME.
    // save_random: the name a new save gets if none is typed.
    int install_overwrite, install_pick, save_named;
    char save_random[INSTALL_NAME_MAX + 1];
    app_mode_t mode;
    int asking_quit;   // Ctrl+C's QUIT box, over whatever mode is showing
    char pending_session_id[MAX_SESSION_NAME + 1];
    int show_sidebar, show_console, show_chat;
    int dirty;
    int input_dirty;

    tui_scrollback_t log;
    tui_input_t input;
    tui_input_t saved_input;
    browser_t browser;
    char send_dir[APP_PATH_MAX];   // the folder :send's browser last offered a file from
    char save_dir[APP_PATH_MAX];   // the folder :saveto's browser last saved a file in
    int save_num, save_anyway;   // what :saveto's browser saves
    app_mode_t browse_back;      // where :send's and :saveto's browsers go back to
    // The files page's selected file, by its number. A y/n box over it or the picture asks file_ask
    // about file file_ask_num, then goes back to file_back.
    int file_num, file_ask, file_ask_num;
    app_mode_t file_back;
    char paste_buf[16384];
    size_t paste_len;
    char paste_status[80];

    char pending_auto_session[MAX_SESSION_NAME + 1];
    char pending_auto_password[MAX_PASSWORD + 1];
    uint16_t pending_auto_port;
    // As given. A name in them is only looked up once the startup settings page is done.
    char pending_auto_peer_args[MAX_PEER_ARGS][PEER_ARG_LEN];
    int pending_auto_n_peers;
} app_t;

// The command line, read again once what :install saved is open, so its options still override it.
typedef struct {
    char nick[MAX_NICK + 1];
    char identity[520];   // age or pgp, then :KEYFILE for a key of your own
    char session[MAX_SESSION_NAME + 1];
    char save[INSTALL_NAME_MAX + 1];
    uint16_t port;
    char peers[MAX_PEER_ARGS][PEER_ARG_LEN];
    int n_peers;
    int simple, update, has_color;
    uint8_t color[3];
} options_t;

// ---- which tor Tor mode uses ----
//
// A tor that's already running is better when chat can use it, since it keeps its entry guards
// between runs and any bridges its torrc sets up. Chat can only use it if its control port answers
// and lets chat log in, since publishing onion services needs that. Otherwise chat starts its own
// tor (torproc.c).

typedef enum { TOR_LAUNCH_AUTO = 0, TOR_LAUNCH_ALWAYS = 1, TOR_LAUNCH_NEVER = 2 } tor_launch_t;

typedef enum { TL_OFF, TL_PROBING, TL_STARTING, TL_READY, TL_FAILED } tor_link_state_t;

typedef struct {
    tor_link_state_t state;
    tor_t *probe;
    torproc_t *proc;
    char socks[TOR_HOST_MAX], control[TOR_HOST_MAX];
    int boot_told, starts;
    double retry_at;
} tor_link_t;

// ---- the settings page ----
//
// Every setting is a row on this page, and :set NAME VALUE sets a row without opening it. Either
// way the change applies immediately, to open sessions and to ones opened later.

enum { K_TOGGLE, K_CHOICE, K_TEXT, K_SECRET, K_ACTION };

// In the order of the settings file's tables (setting_table).
typedef enum {
    SET_ROUTING, SET_DHT4, SET_DHT6, SET_PORTMAP, SET_LAN,
    SET_TOR_LAUNCH, SET_TOR_PATH, SET_TOR_SOCKS, SET_TOR_CONTROL, SET_TOR_PASSWORD,
    SET_NOSTR, SET_RELAYS,
    SET_NICK, SET_COLOUR, SET_SIGN, SET_AGE_RECIPIENT, SET_PGP_PUBKEY, SET_AUTOSAVE, SET_DEVICE_LOCK,
    SET_SECURITY_KEY, SET_AUTHENTICATOR, SET_DESTROY, SET_SHADOW,
    SET_VERIFY, SET_FILE_LIMIT, SET_FAST_FILES, SET_NOTIFY, SET_PREVIEW, SET_HISTORY, SET_NET, SET_PORT, SET_BETAS,
    N_SETTING_IDS
} setting_id_t;

typedef struct {
    setting_id_t id;
    const char *section;  // starts a section, which has a page of its own
    const char *group;    // starts a group within the section, under this heading
    const char *key;      // its name after :set
    const char *label;
    int kind;
    const char *values;   // what :set takes, or NULL for a row only the page sets
    const char *help;
} setting_def_t;

#define N_SETTINGS ((int)COUNT_OF(SETTINGS))

#define ROW_TEXT_MAX (NOSTR_MAX_RELAYS * NOSTR_URL_MAX)

// The page shows one section at a time, its listed rows and then a Done button.
#define SETTINGS_DONE N_SETTINGS   // settings_sel of the Done button, on g_app.settings_page

// ---- the signing identity, chosen on a page under the settings ----

// Off, then for each of AGE and PGP: a key made here, a key file picked in the browser, a key file
// whose path is typed, and a key pasted in.
typedef enum {
    PICK_OFF,
    PICK_AGE_MADE, PICK_AGE_FILE, PICK_AGE_PATH, PICK_AGE_PASTE,
    PICK_PGP_MADE, PICK_PGP_FILE, PICK_PGP_PATH, PICK_PGP_PASTE,
    N_PICKS
} sign_pick_t;

// Why a key of your own has to be the secret key, in one sentence for the rows' help.
#define WHY_SECRET "chat signs your handshakes with it, and only the secret key can make a signature. "

typedef struct { const char *section, *label, *help; } sign_pick_row_t;

// ---- keys on the list pages ----

typedef enum {
    LIST_NONE, LIST_UP, LIST_DOWN, LIST_FIRST, LIST_LAST, LIST_CHOOSE, LIST_LEFT, LIST_RIGHT, LIST_BACK, LIST_CLOSE,
    LIST_NEXT_SECTION, LIST_PREV_SECTION
} list_key_t;

// main.c
extern app_t g_app;
extern options_t g_opts;
extern volatile sig_atomic_t g_interrupted;
extern int g_plain;
extern int g_echo;
void push_log(const char *fmt, ...);
void session_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len,
                   int file);
int session_ready(const session_slot_t *s);
pic_t *pic_find(session_slot_t *s, int num);
const tui_image_t *pic_for(const void *ctx, int file);
const char *pic_why(const session_slot_t *s, int num);
int fetch_progress(const chat_t *e, const file_entry_t *f, char *text, size_t cap);
const tui_progress_t *progress_for(const void *ctx, int file);
void session_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len);
void session_notify(void *ui, const char *nick, const char *text, int mentioned);
int slot_index(session_slot_t *s);
session_slot_t *find_free_slot(void);
void lock_scrollbacks(session_slot_t *s);
void release_scrollbacks(session_slot_t *s);
void select_session(session_slot_t *s);
session_slot_t *first_session(void);
void close_session(session_slot_t *s);
void select_step(int dir);
void console_note(session_slot_t *s, const char *fmt, ...);
void note(const char *fmt, ...);
void osc52_copy(const char *text);
void copy_session_id(session_slot_t *s);
const char *route_label(void);
void reapply_options(void);

// history.c
int history_possible(void);
void history_add(session_slot_t *s, const char *text, const uint8_t *rgb, int mention, int color_len);
void histories_write(void);
void history_start(session_slot_t *s, int show);
void history_stop(session_slot_t *s, int write);
void history_sync(double now);

// torlink.c
extern const char *const TOR_LAUNCH_NAMES[];
extern chat_t *g_plain_engine;
extern tor_link_t g_tor;
extern chat_build_t g_self_build;
void sync_update_proxy(void);
void tor_link_ensure(double now);
void tor_link_step(double now);
void tor_link_stop(void);
void tor_link_line(char *out, size_t cap);
void app_session_opts(chat_opts_t *o);
session_slot_t *start_session(const char *session_name, const char *password, int created, uint16_t port,
                              const addr_t *peers, int n_peers);
int pgp_key_made_here(void);
void pgp_public_key(char armor[PGP_ARMOR_MAX], uint8_t fp[PGP_FP_LEN]);
void show_identity_result(void);
void finish_onboarding(void);
int path_is_root(const char *p);
void path_join(char *out, size_t cap, const char *dir, const char *name);
void path_parent(char *p);
int browser_load(browser_t *b, const char *path);
void browser_select(browser_t *b, const char *name);
void browser_entry_path(const browser_t *b, const dir_entry_t *e, char *out, size_t cap);
void begin_prompt(app_mode_t mode);
void end_prompt(void);
cmd_result_t app_new(void *ctx, const char *arg);
cmd_result_t app_join(void *ctx, const char *arg);
cmd_result_t app_quit(void *ctx, const char *arg);
cmd_result_t app_quitall(void *ctx, const char *arg);
cmd_result_t app_copyid(void *ctx, const char *arg);
cmd_result_t app_update(void *ctx, const char *arg);
void update_key(const tui_key_t *key);

// settings.c
extern const setting_def_t SETTINGS[N_SETTING_IDS];
extern setting_id_t g_edit_id;
extern char g_setting_defaults[N_SETTINGS][ROW_TEXT_MAX];
extern char g_saved_rows[N_SETTINGS][ROW_TEXT_MAX];
extern char g_seen_rows[N_SETTINGS][ROW_TEXT_MAX];
extern int g_unsaved_rows[N_SETTINGS];
extern int g_hold_sessions;
extern const char DEVICE_REMINDER[];
extern const char KEY_REMINDER[];
extern const sign_pick_row_t SIGN_PICKS[N_PICKS];
extern const char KEY_WHY[];
extern const char KEY_FILE_SAVED[];
extern const char KEY_PASTE_SAVED[];
extern const char AGE_PASTE_HELP[];
extern const char PGP_PASTE_HELP[];
extern const char AGE_PATH_HELP[];
extern const char PGP_PATH_HELP[];
extern const char SIGN_PASSWORD_HELP[];
int settings_index(setting_id_t id);
const setting_def_t *setting_def(setting_id_t id);
const setting_def_t *setting_by_key(const char *key);
int setting_shown(setting_id_t id);
int setting_options(setting_id_t id, const char *const **names, int *n);
int setting_choices(setting_id_t id, const char *const **names, int *n);
tui_value_kind_t setting_kind(const setting_def_t *d);
void setting_value(setting_id_t id, char *out, size_t cap);
int setting_text(setting_id_t id, char *out, size_t cap);
void note_setting_defaults(void);
void note_settings_seen(void);
const char *setting_table(setting_id_t id);
size_t put_text(char *out, size_t p, size_t cap, const char *s);
int settings_text(char *out, size_t cap);
void keep_settings_saved(void);
void settings_to_sessions(void);
void device_check(void);
int row_greyed(setting_id_t id);
void setting_choose(setting_id_t id, int i);
void setting_step(setting_id_t id, int dir);
void begin_setting_edit(setting_id_t id);
void end_setting_edit(void);
int valid_host_port(const char *s);
void setting_apply_text(setting_id_t id, const char *typed);
void commit_setting_edit(void);
int settings_sections(const char **out, int cap);
int settings_section_index(setting_id_t id);
int section_begin(int s);
int section_row(int s, int dir);
int settings_n_sections(void);
void settings_select(int sel);
void settings_go_section(int s);
void settings_step(int dir);
void settings_fix_sel(void);
void settings_section_step(int dir);
void begin_settings(void);
void settings_open_at(setting_id_t id);
void settings_done(void);
const char *settings_hint(void);
int sign_row_in_use(void);
void begin_sign(void);
void identity_chosen(void);
void say_key_saved_state(void);
const char *make_identity(identity_source_t kind, const char *password);
void end_sign_password(void);
void commit_sign_password(void);
void tilde_path(const char *path, char *out, size_t cap);
int read_key_file(identity_source_t kind, const char *path, identity_keypair_t *kp, char *full, size_t cap);
int load_key_file(identity_source_t kind, const char *path);
void begin_key_path(identity_source_t kind, const char *start, int from_browser);
void end_key_path(void);
void commit_key_path(void);
void paste_clear(void);
int try_load_key_from_browser(void);
void sign_pick(int pick);
void copy_age_recipient(void);
void copy_pgp_public_key(void);

// pages.c
list_key_t list_key(const tui_key_t *key);
int section_digit(const tui_key_t *key);
void list_move(list_key_t k, int *sel, int n);
void settings_key(const tui_key_t *key);
void sign_picker_key(const tui_key_t *key);
void browser_key(const tui_key_t *key);
void begin_send_browse(void);
void send_browser_key(const tui_key_t *key);
void begin_save_browse(int num, int anyway);
void save_browser_key(const tui_key_t *key);
void paste_key(const tui_key_t *key);
void render_settings(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void render_sign_picker(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void render_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void render_send_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void render_save_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
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
void begin_changelog(void);
void render_changelog(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
void changelog_key(const tui_key_t *key);
int page_section_step(const tui_row_t *rows, int n, int sel, int dir);
int page_section_nth(const tui_row_t *rows, int n, int nth);

// saves.c
void saved_note(const char *fmt, ...);
void say_saved_notes(void);
int key_saved_as_path(void);
void save_verified(void);
void autosave_changed(void);
void factors_text(unsigned f, char *out, size_t cap);
void save_detail(const install_save_t *sv, char *out, size_t cap);
int save_to_pick(void);
void unlock_at_start(int in_box);
int key_in_use_saved(void);
int is_current_save(const char *name);
int save_exists(const char *name);
void pick_random_save_name(void);
int install_resaves(void);
void cancel_install(void);
void install_confirmed(void);
void install_use_existing(void);
void install_new_save(void);
void back_from_install_name(void);
void install_pick_key(const tui_key_t *key);
void install_overwrite_yes(void);
void back_from_install_unlock(void);
void choice_key(const tui_key_t *key, void (*yes)(void), void (*no)(void), void (*esc)(void));
void commit_install_name(void);
void commit_install_pass(void);
void commit_install_pass2(void);
void commit_install_unlock(void);
void uninstall_confirmed(void);
void settle_start(void);
void commit_unlock(void);
void back_from_unlock(void);
void saves_key(const tui_key_t *key);
void cancel_uninstall(void);
void install_first_yes(void);
void install_first_no(void);
void device_lock_choose(int on);
void device_lock_yes(void);
void device_lock_no(void);
void factor_choose(unsigned factor, int on);
void factor_yes(void);
void factor_no(void);
void destroy_choose(int limit);
void shadow_off(void);
void begin_shadow(void);
void commit_shadow_pass(void);
void commit_shadow_pass2(void);
void cancel_shadow_pass(void);
void commit_key_pin(void);
void cancel_key_pin(void);
void key_wait_key(const tui_key_t *key);
void key_wait_tick(void);
void unlock_go(key_purpose_t why);
void commit_unlock_code(void);
void back_from_unlock_code(void);
void confirm_key(const tui_key_t *key, void (*yes)(void), void (*no)(void));
void quit_key(const tui_key_t *key);
void field_key(const tui_key_t *key, void (*enter)(void), void (*esc)(void));
void code_setup_key(const tui_key_t *key);

// commands.c
int begin_install(const char *arg);
cmd_result_t app_help(void *ctx, const char *arg);
cmd_result_t app_changelog(void *ctx, const char *arg);
int file_arg(const char *arg, int *anyway);
cmd_result_t app_show(void *ctx, const char *arg);
cmd_result_t app_files(void *ctx, const char *arg);
cmd_result_t app_saveto(void *ctx, const char *arg);
cmd_result_t app_hide(void *ctx, const char *arg);
void render_help(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar);
int command_word(const char *word, int whole);
const char *complete_mention(const char *typed);
int suggest_command(const char *typed, int nth, tui_suggestion_t *out);
void handle_key(const tui_key_t *key);
int install_mode(app_mode_t m);
int on_chat_screen(void);
tui_session_state_t session_state(const session_slot_t *s);
tui_view_t current_view(char *sub, size_t cap);
void chat_input(tui_bar_t *b, const tui_input_t *in);

// screen.c
int add_para(tui_para_t *p, int n, tui_para_kind_t kind, const char *text);
void render_bar(void);
void render(void);

#endif
