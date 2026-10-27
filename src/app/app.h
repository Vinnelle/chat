// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What src/app's files share: the app's state, and what the files at the top of src/app offer the
// rest. Each folder's own header, included at the end, has what its files offer.
#ifndef CHAT_APP_H
#define CHAT_APP_H

#include "core/chat.h"
#include "core/trust.h"
#include "crypto/crypto.h"
#include "crypto/age.h"
#include "crypto/pgp.h"
#include "platform/net.h"
#include "platform/platform.h"
#include "tui/tui.h"
#include "common/util.h"
#include "app/update.h"
#include "app/saves/saves.h"
#include "app/sessions/rooms.h"
#include "transport/torproc.h"
#include "common/image/image.h"
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
    chat_t *engine;
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
    int console_scroll;   // and the newest lines below the console
    char name[MAX_SESSION_NAME + 1];
    // While its history is kept: the lines so far (HISTORY_LINE's), in locked memory, the save they're
    // kept in, and whether they've changed since they were written there.
    char *hist;
    size_t hist_len;
    int hist_dirty;
    char hist_save[INSTALL_NAME_MAX + 1];
    // It moved to a new room (:move), so it's off the screen, and closes once the engine says it's done.
    int leaving;
    // The request to move (its seq) put away with Esc, which doesn't come up again until :move.
    unsigned move_later;
    // The room's password, for :keep. Locked memory, wiped when it closes.
    char password[MAX_PASSWORD + 1];
    // A call (:call): the verified key it's with, and the day its room is for. While nobody's there,
    // it follows the day.
    int contact;
    uint8_t contact_pub[ID_SIGN_PUB_LEN];
    uint64_t contact_day;
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
    MODE_EXPORT_BROWSE,
    MODE_FILES,
    MODE_FILE_VIEW,
    MODE_FILE_ASK,
    MODE_EXPORT_ASK,
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
    MODE_UPDATE,
    MODE_MOVE,
    MODE_MOVE_ASK,
    MODE_TOR_STATE,
    MODE_ROOMS
} app_mode_t;

// What a security key is being touched for: to register it for the open save or the new one
// :install is making, or to open a save, at the start or for :install.
typedef enum { KP_FACTOR, KP_NEW_SAVE, KP_UNLOCK, KP_INSTALL_UNLOCK } key_purpose_t;

// KEY_MADE is a new random key, KEY_DERIVED one made from a password on this device, and
// KEY_DERIVED_NICK from a password and the nick. A save keeps the number, so new ones go last.
typedef enum { KEY_MADE, KEY_DERIVED, KEY_FILE, KEY_PASTED, KEY_DERIVED_NICK } key_origin_t;

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
    notify_mode_t notify_mode;
    notify_preview_t notify_preview;
    int verify_optional;
    int net_log;   // NET_LOG_NORMAL, _VERBOSE or _OFF
    uint16_t default_port;
    struct {
        int sel;
        int page;      // the section shown: sel's, or the one whose Done button it is
        int rows[8];   // each section's row selected last, which Tab goes back to
    } settings;
    int help_sel;
    struct { int scroll, most; } changelog;
    char message[200];   // the bottom bar's result of the last action, until the next key
    int onboarding;   // the settings page chat opens on: its Done button starts chat
    struct {
        int sel;
        key_origin_t origin;           // where the identity in use came from
        uint32_t pgp_created;          // a PGP key made here: its creation time, which its fingerprint covers
        identity_source_t load_kind;   // AGE or PGP: what the key file browser, the path field or the paste page takes
        int load_nick;                 // the password box makes a key with the nick
        int remake;                    // the password box asks again because the nick changed, and Esc keeps the key
        app_mode_t remake_back;        // where it goes back to then
        char nick[MAX_NICK + 1];       // a key made with the nick (KEY_DERIVED_NICK): that nick
        int start_pending;             // --identity's password waits for the nick (start_identity)
        char start_password[MAX_PASSWORD + 1];
        char path[KEY_PATH_MAX];       // a key from a file (KEY_FILE): the file's full path, or "" if it isn't known
        int path_from_browser;         // the path field was opened from the browser, so Esc goes back there
        app_mode_t export_back;        // where :exportkey's browser goes back to
        char export_path[KEY_PATH_MAX]; // the new file its box asks to write the key to
    } key;
    struct {
        int launch;
        char path[TOR_PATH_MAX];
        // Bridge lines for chat's own tor, separated by ';', and the folder with the programs they need
        // ("": next to tor, then PATH). keep_state: its guards and directory are kept in the save, once
        // the box MODE_TOR_STATE shows over back says what that means.
        char bridges[TUI_LINE_MAX];
        char pt_dir[TOR_PATH_MAX];
        int keep_state;
        app_mode_t back;
    } tor;
    // The kept rooms' list (Ctrl+J): the row selected, and whether it asks to forget that one.
    struct { int sel, forgetting; } rooms;
    uint64_t file_cap;   // 0: the default
    int fast_files;
    int picture_noise;   // a JPEG sent gets noise nobody can see (common/image/clean.h)
    int betas;
    int history;    // keep each session's history, sealed in the save open
    // Keep the sessions open in the save open, to open again as chat starts. reopen_due: a save was
    // opened, and its sessions haven't been. quit_leaving: :quitall, which leaves them for good.
    int reopen, reopen_due, quit_leaving;
    int autosave;   // what's changed is saved as it changes, while installed
    // The key that panics, by its place in PANIC_KEY_NAMES (0: no key). A panic deletes the open save
    // with wipe, and writes the histories kept with history.
    struct { int key, wipe, history; } panic;
    // Put the sandbox up once chat starts reaching the network (Linux), and what of it is up
    // (PLATFORM_SANDBOX_), and start the updater outside it just before.
    int sandbox;
    unsigned sandboxed;
    int updater;
    struct {
        // Locked to this device: the open save, or with none open, the new one :install is making for
        // it (install.for_factor). want is what the DEVICE LOCK box asks to change it to, and back where
        // it goes back to. new_save: the box is for the new save :install is making, before its passphrase.
        int lock, want, new_save;
        app_mode_t back;
        // What locking would use here. DEVICE_NONE: it can't, and why says why. Checked at the start, and
        // again whenever something that shows it opens.
        device_kind_t kind;
        char why[200];
    } device;
    struct {
        // A security key and an authenticator code, like the device lock. seckey_ok: security keys work
        // here (seckey_why if not).
        int key, code, seckey_ok;
        char seckey_why[200];
        // The FACTOR box turns which (INSTALL_FACTOR_) on (want) or off, from the settings page or the
        // chat (back); new_save: it's a step of :install making a new save. key_purpose: what the security
        // key is touched for, and key_pin what to send it if it asks for its PIN.
        unsigned which;
        int want, new_save;
        app_mode_t back;
        key_purpose_t key_purpose;
        char key_pin[64];
        int key_stage, key_touches;   // what its thread waits for (seckey_stage_t), and the touches it's had
        // The new authenticator secret, in base32 and as the link a QR code holds. code_qr: its box shows
        // the QR code in place of its text (Tab).
        char code_b32[40];
        char code_uri[160];
        int code_qr;
    } factor;
    struct {
        // A factor turned on with no save open asks to :install first, and for_factor is the factor
        // (INSTALL_FACTOR_) that :install then sets up. back: the page :install's boxes are over and go
        // back to, the chat or the settings page.
        unsigned for_factor;
        app_mode_t back;
        // The open save deletes itself after this many wrong passphrases (0 off); with none open, what
        // the next save :install makes starts with. Mirrored to the save's unsealed tries file.
        int destroy_limit;
        char shadow_pass[INSTALL_PASS_MAX];   // the shadow passphrase while its box asks for it again to confirm
        // The startup unlock's passphrase came from CHAT_INSTALL_PASSWORD, and waits in pass for the
        // security key or the code the save needs.
        int unlock_env;
        int key_known;
        uint8_t key_pub[ID_SIGN_PUB_LEN];
        char key_path[KEY_PATH_MAX];   // what :install saved is the path to a key file: that path, else ""
        char pass[INSTALL_PASS_MAX];   // the passphrase while it's typed the second time
        int unlock_at_start;
        // The saves :install made, to pick from at start when there's more than one, and the save
        // :install or :uninstall acts on while its box is open.
        install_save_t saves[INSTALL_SAVES_MAX];
        int n_saves, sel;
        char target[INSTALL_NAME_MAX + 1];
        // :install for a save that's sealed: after its passphrase, save what's in use over it (1, only
        // while another save is open), or use what's saved there (0). pick: the save to use is picked
        // from the list of saves. named: :install or :uninstall was given a NAME. random_name: the name a
        // new save gets if none is typed.
        int overwrite, pick, named;
        char random_name[INSTALL_NAME_MAX + 1];
    } install;
    uint8_t color[3];
    identity_source_t identity_source;
    identity_keypair_t identity;
    // installed: what :install saved is open and kept up to date. locked: it exists but is still
    // sealed.
    int installed, locked;
    app_mode_t mode;
    int asking_quit;   // Ctrl+C's QUIT box, over whatever mode is showing
    struct {
        // Seconds without a key before the screen locks itself (0 never), and the key that locks it, by
        // its place in LOCK_KEY_NAMES (0: no key).
        int after, key;
        // The lock screen (on), over whatever mode is showing: nothing is drawn but its box, and nothing
        // but it and the panic key takes keys. input is its field, apart from g_app.input, which a box
        // under it may be using. checking: what was typed there is being tried. last_key: when the last
        // key came, for after, in wall time (lock_saw_key).
        int on, checking;
        double last_key;
        tui_input_t input;
        // The LOCK SCREEN box asking for a PIN to unlock with while no save is open, over whatever mode
        // is showing, in input: pin_step 1, then 2 for it again. Then pin_then: lock (-1), or turn
        // auto-lock on after that many seconds.
        int pin_step, pin_then;
    } lock;
    double move_shown;   // when a request to move came up by itself, for the keys typed just before
    char pending_session_id[MAX_SESSION_NAME + 1];
    int pw_suggested;   // NEW SESSION's field still holds the random password it opened with
    struct { int sidebar, console, chat; } show;
    int dirty;
    int input_dirty;

    tui_scrollback_t log;
    int log_scroll;
    tui_input_t input;
    tui_input_t saved_input;
    browser_t browser;
    struct {
        char send_dir[APP_PATH_MAX];   // the folder :send's browser last offered a file from
        int send_asis;                 // and it sends a picture as it is (:send asis), not cleaned
        char save_dir[APP_PATH_MAX];   // the folder :saveto's browser last saved a file in
        int save_num, save_anyway;     // what :saveto's browser saves
        app_mode_t browse_back;        // where :send's and :saveto's browsers go back to
        // The files page's selected file, by its number. A y/n box over it or the picture asks ask
        // about file ask_num, then goes back to back.
        int num, ask, ask_num;
        app_mode_t back;
    } files;
    struct {
        char buf[16384];
        size_t len;
        char status[80];
        int cut;   // some of the paste coming in didn't fit in the input line
    } paste;

    // The session given on the command line.
    struct {
        char session[MAX_SESSION_NAME + 1];
        char password[MAX_PASSWORD + 1];
        uint16_t port;
        // As given. A name in them is only looked up once the startup settings page is done.
        char peer_args[MAX_PEER_ARGS][PEER_ARG_LEN];
        int n_peers;
    } autostart;
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
    int simple, update, has_color, nosandbox;
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
    int bridged;   // chat's own, started holding the network until it has its bridges
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
    SET_TOR_LAUNCH, SET_TOR_PATH, SET_TOR_SOCKS, SET_TOR_CONTROL, SET_TOR_PASSWORD, SET_BRIDGES, SET_TRANSPORTS,
    SET_TOR_STATE,
    SET_NOSTR, SET_RELAYS,
    SET_NICK, SET_COLOUR, SET_SIGN, SET_AGE_RECIPIENT, SET_PGP_PUBKEY, SET_EXPORT_KEY, SET_AUTOSAVE, SET_DEVICE_LOCK,
    SET_SECURITY_KEY, SET_AUTHENTICATOR, SET_DESTROY, SET_SHADOW,
    SET_LOCK, SET_LOCK_KEY, SET_PANIC_KEY, SET_PANIC_WIPE, SET_PANIC_HISTORY, SET_SANDBOX, SET_UPDATER,
    SET_VERIFY, SET_FILE_LIMIT, SET_FAST_FILES, SET_NOISE, SET_NOTIFY, SET_PREVIEW, SET_HISTORY, SET_REOPEN, SET_NET, SET_PORT,
    SET_BETAS,
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

// What a row's edit line holds.
#define ROW_TEXT_MAX TUI_LINE_MAX

// The page shows one section at a time, its listed rows and then a Done button.
#define SETTINGS_DONE N_SETTINGS   // g_app.settings.sel of the Done button, on g_app.settings.page

// ---- the signing identity, chosen on a page under the settings ----

// Off, then for each of AGE and PGP: a key made here (with the nick, then without), a key file
// picked in the browser, a key file whose path is typed, and a key pasted in.
typedef enum {
    PICK_OFF,
    PICK_AGE_MADE, PICK_AGE_NO_NICK, PICK_AGE_FILE, PICK_AGE_PATH, PICK_AGE_PASTE,
    PICK_PGP_MADE, PICK_PGP_NO_NICK, PICK_PGP_FILE, PICK_PGP_PATH, PICK_PGP_PASTE,
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

#define CRUMB " \xe2\x80\xba "   // between the levels of a page's title

// main.c
extern app_t g_app;
extern options_t g_opts;
extern volatile sig_atomic_t g_interrupted;
extern volatile sig_atomic_t g_ctrl_c;
extern volatile sig_atomic_t g_sigquit;
extern int g_plain;
extern int g_echo;
// The longest the main loops wait for a socket or a key before doing their timed work.
#define WAIT_MS 200
void catch_quit_signals(void);
void push_console(tui_scrollback_t *sb, int *scroll, const char *hhmm, const char *text, const uint8_t *rgb);
void push_log(const char *fmt, ...) PRINTF_LIKE(1, 2);
void note(const char *fmt, ...) PRINTF_LIKE(1, 2);
void choose_route(route_mode_t m);
const char *route_label(void);
void reapply_options(void);
// Why the main loop is ending at once, with no frame after: the panic key (or SIGQUIT), or on the lock
// screen, the shadow passphrase or the wrong passphrase that set off self-destruct.
typedef enum { PANIC_NONE, PANIC_KEY, PANIC_DECOY, PANIC_DESTROYED } panic_t;
extern panic_t g_panic;
void panic(panic_t why);
void panic_saves(void);
void sandbox_up(void);
#define N_PANIC_KEYS 5
extern const char *const PANIC_KEY_NAMES[N_PANIC_KEYS];
int panic_key_is(const tui_key_t *key);

// plain.c
extern chat_t *g_plain_engine;
int run_plain(const char *session_name, const char *password, uint16_t port,
              const char peer_args[][PEER_ARG_LEN], int n_peer_args);

// settings.c
extern const setting_def_t SETTINGS[N_SETTING_IDS];
extern const char *const ROUTE_NAMES[];
extern const char *const NOSTR_NAMES[];
extern setting_id_t g_edit_id;
extern char g_setting_defaults[N_SETTINGS][ROW_TEXT_MAX];
extern char g_saved_rows[N_SETTINGS][ROW_TEXT_MAX];
extern char g_seen_rows[N_SETTINGS][ROW_TEXT_MAX];
extern int g_unsaved_rows[N_SETTINGS];
extern int g_hold_sessions;
extern int g_loading_settings;
extern const char DEVICE_REMINDER[];
extern const char KEY_REMINDER[];
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
int settings_write(void);
// One entry of the [ignored] table. 0, or -1 if it isn't one.
int ignored_load(const toml_value *v);
void save_ignored(void);
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
// What goes between the items of the list being edited (bridges, relays), or NULL for a single value.
const char *setting_edit_separator(void);
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
void finish_onboarding(void);

// identity.c
extern const sign_pick_row_t SIGN_PICKS[N_PICKS];
extern const char KEY_WHY[];
extern const char KEY_FILE_SAVED[];
extern const char KEY_PASTE_SAVED[];
extern const char AGE_PASTE_HELP[];
extern const char PGP_PASTE_HELP[];
extern const char AGE_PATH_HELP[];
extern const char PGP_PATH_HELP[];
int sign_row_in_use(void);
void begin_sign(void);
void identity_chosen(void);
void say_key_saved_state(void);
const char *make_identity(identity_source_t kind, const char *password, int with_nick);
void start_identity(int on_screen);
void nick_changed(void);
const char *sign_password_help(void);
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
int pgp_key_made_here(void);
void pgp_public_key(char armor[PGP_ARMOR_MAX], uint8_t fp[PGP_FP_LEN]);
void show_identity_result(void);
const char *key_export_refusal(void);
const char *key_export_name(void);
void begin_export_ask(const char *dir);
void export_key_yes(void);
void export_key_no(void);

#include "app/sessions/sessions.h"
#include "app/screen/screen.h"
#include "app/saves/install.h"

#endif
