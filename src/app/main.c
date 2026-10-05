// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
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
#include "changelog.h"

#ifdef CHAT_TEST_BUILD
#define TEST_BUILD 1
#define TEST_LABEL "testing " CHAT_BUILD_ID
#else
#define TEST_BUILD 0
#define TEST_LABEL ""
#endif

static const char *USAGE =
    "usage: chat [--nick NAME] [--colour NAME|#HEX] [--identity age|pgp[:KEYFILE]] [--simple]\n"
    "            [--save NAME]\n"
    "            [--routing dht+nostr|dht|tor] [--nodht] [--noipv6] [--nolan]\n"
    "            [--noportmap] [--nonostr] [--nostr-always] [--relay wss://HOST ...]\n"
    "            [--tor-launch auto|always|never] [--tor-path PATH] [--tor-socks HOST:PORT]\n"
    "            [--tor-control HOST:PORT] [--verify-required] [--file-limit SIZE]\n"
    "            [--fast-files]\n"
    "            [--session ID --port UDP_PORT --peer HOST:PORT ...]\n"
    "       chat --update | --version\n"
    "\n"
    "In a terminal, chat opens a full-screen UI. Sessions you've joined or created are listed\n"
    "on the left (Tab/Shift+Tab to switch), with who's online and how the session reaches\n"
    "them below that. The selected session's chat takes up the rest, and you type in the box\n"
    "at the bottom. The UI uses the terminal's own colours, so it matches a light or dark\n"
    "theme and follows it when it changes. chat starts on the settings page, where you set\n"
    "routing, your nickname, colour, signing key and the rest. Start chatting at the bottom\n"
    "(or Esc) goes to your sessions. Nothing goes on the network before that: no tor is\n"
    "looked for or started, and no --peer name is looked up. Once :install has saved your\n"
    "settings, chat starts on your sessions instead.\n"
    "\n"
    "  Ctrl+N     create a new session (asks for a password; blank still encrypts)\n"
    "  Ctrl+J     join an existing session (asks for its id, then its password)\n"
    "  Tab        next session       Shift+Tab   previous session (j/k in NORMAL too)\n"
    "  PgUp/PgDn  scroll the chat back and forward (Ctrl+U/Ctrl+D in NORMAL, G the newest)\n"
    "  Ctrl+B     hide/show the sidebar   Ctrl+O   hide/show the console\n"
    "  Ctrl+T     hide/show the chat (hide two of the three and the last one fills the screen)\n"
    "  Ctrl+S     settings: routing, identity, files, notifications (also :set)\n"
    "  Ctrl+F     files offered here and yours: show, save or stop them (f in NORMAL, :files)\n"
    "  F1         list all commands and keybinds (also ? in NORMAL, and :help)\n"
    "  Ctrl+C     quit chat, after asking (every open session leaves cleanly first)\n"
    "\n"
    "Each session has two parts: the conversation, and a console above it for everything\n"
    "else, such as people joining and leaving, network lookups and command output. A session\n"
    "you joined is locked (the chat says \"connecting\") until someone answers. The bottom\n"
    "row shows where you are, what the keys do there, and the result of your last action,\n"
    "until the next key.\n"
    "\n"
    "The input line works like a small vim. It starts in NORMAL: h/l move, 0/$ go to the\n"
    "ends, x deletes, j/k switch session, s/c/C hide/show the sidebar/console/chat, f opens\n"
    "the files.\n"
    "  i/a/I/A  NORMAL -> INSERT, where Enter sends\n"
    "  /        on an empty line: the command line, with a menu of matching commands. Once\n"
    "           the text can't be a command (/shrug, /usr/bin) it's sent as normal text\n"
    "  Ctrl+W   delete a word          Ctrl+U   delete back to the start of the line\n"
    "  Esc      INSERT -> NORMAL\n"
    "  :        NORMAL -> COMMAND: type a command, Tab completes, Up/Down pick from the\n"
    "           menu, Enter runs, Esc cancels. After :verify it lists the online peers\n"
    "           whose nick starts with what's typed, like @ does in INSERT\n"
    "Prompts (a password, a session id, a setting's new value, a question) open in a box\n"
    "over the screen. Enter confirms, Esc cancels, a question takes y or n, and whatever you\n"
    "were typing comes back afterwards.\n"
    "\n"
    "Commands run from the command line (/ on an empty line, or : in NORMAL). Anything else\n"
    "you type is sent:\n"
    "  :new :join :quit (:q) :quitall (:qa) :copyid :update :peers :verify NICK [ok|no] :net\n"
    "  :verified [forget NICK] :port [N] :set [NAME [VALUE]] :install :uninstall :help\n"
    "  :send [PATH] :files :download [N] :show N :hide N :cancel N\n"
    "  (:help opens a page of keys and commands)\n"
    "\n"
    "Anyone with a session's id and password can sit between two other members. When a peer\n"
    "joins, chat shows a verify code to compare with them over another channel (a call, in\n"
    "person), and :verify NICK ok marks it as matching. --verify-required (:set verify\n"
    "required) sends nothing to a peer until then. For a peer that signs with an identity,\n"
    ":verify NICK ok also keeps its signing key as verified: next time it signs with that key,\n"
    "the code needs no comparing. If a peer with that nick signs with another key, or none,\n"
    "chat shows a warning and the sidebar says key changed. :verified lists the keys, and\n"
    ":install saves them.\n"
    "\n"
    "Each setting is a row on the settings page. :set NAME VALUE changes it without opening\n"
    "the page (:set nick bob, :set net verbose, :set routing tor). :set alone opens the page,\n"
    "and :set NAME opens it on that row. The settings page and the pages under it use the\n"
    "same keys: j/k move, g/G go to the ends, Enter chooses, h/l change a value or go out/in,\n"
    "Tab goes to the next section, Esc goes back, q closes.\n"
    "\n"
    "Settings and the signing key last until chat exits. :install saves them, after saying\n"
    "what that leaves on disk. Both go in ~/.config/chat (%LOCALAPPDATA%\\chat on Windows),\n"
    "sealed with one passphrase that chat asks for on startup (or reads from\n"
    "CHAT_INSTALL_PASSWORD). What you change after that waits for :save, unless :set autosave\n"
    "on (then it's saved as it changes). Options given here override what's saved, for that\n"
    "run only. :uninstall deletes it.\n"
    "A new save goes in ~/.config/chat/saves/NAME, with its own passphrase. :install asks for its\n"
    "name, and a blank one picks a random name. :install NAME makes another save named NAME.\n"
    "With more than one save, chat lists them on startup to pick the one to open.\n"
    ":set devicelock on locks a save to this device too: its key also needs a secret only this\n"
    "device can unseal (its TPM: on Linux through systemd's credential service, or without one,\n"
    "/dev/tpmrm0), so a copy of its files can't be opened anywhere else, even with the passphrase.\n"
    ":set securitykey on makes it need your FIDO2 security key as well (a touch, and its secret\n"
    "goes into the key), and :set authenticator on asks for an authenticator app's code each time\n"
    "it opens (a check chat makes: the code's secret is kept in the save). One, the other or both.\n"
    ":set destroy N deletes a save after N wrong passphrases in a row, and :set shadow on adds a\n"
    "second passphrase that opens a decoy and deletes the real save for good.\n"
    "\n"
    "  --save      open the save with this name, without the list\n"
    "              (default is the one in ~/.config/chat itself). If there's no save\n"
    "              with that name, chat starts from its defaults and :install makes it\n"
    "  --nick      display name. A random one (like \"swift-otter42\") is used if omitted.\n"
    "              :set nick changes it at any time, for every session\n"
    "  --colour    your display colour in every session; random by default (--color too)\n"
    "  --routing   how sessions reach peers, preset on the settings page chat opens on.\n"
    "              dht+nostr: UDP between peers, found through the BitTorrent DHT (IPv4\n"
    "              and IPv6), the LAN and router port mapping, with Nostr relays carrying\n"
    "              encrypted traffic when UDP can't get through. dht: the same without\n"
    "              relays. tor: Tor onion services, plus the relays through Tor. Tor and\n"
    "              DHT members can only reach each other on the relays, so both need them.\n"
    "  --nodht     don't use the BitTorrent DHT (IPv4 and IPv6)\n"
    "  --noipv6    don't use the IPv6 DHT\n"
    "  --nolan     don't use LAN broadcast discovery\n"
    "  --noportmap don't ask the router to forward a port (UPnP-IGD, NAT-PMP, PCP)\n"
    "  --nonostr   no Nostr relays. Tor and DHT members can only reach each other\n"
    "              through them, so with this set they can't\n"
    "  --nostr-always\n"
    "              stay connected to the relays. By default DHT routing only uses them\n"
    "              while nobody is reached yet or a peer's UDP fails, so Tor members\n"
    "              can't find a room whose members all reach each other directly\n"
    "  --verify-required\n"
    "              send nothing to a peer until you've compared its verify code. By\n"
    "              default messages go to everyone, compared or not\n"
    "  --file-limit\n"
    "              the largest file fetched without adding anyway (default 8M; up to 1G)\n"
    "  --fast-files\n"
    "              send files in quick bursts instead of chat's regular slots. It takes\n"
    "              seconds instead of minutes, but the transfer is visible on the network.\n"
    "              Through the relays (Tor and DHT members) it goes as often as they\n"
    "              allow, about twice as fast\n"
    "  --relay     a Nostr relay (wss://...) to use instead of the defaults; repeatable\n"
    "  --tor-launch\n"
    "              which tor Tor mode uses. auto (default): a tor that's already running if\n"
    "              its control port lets chat log in (it keeps its entry guards and\n"
    "              bridges), otherwise chat starts its own. always: chat's own. never: only\n"
    "              a running one. chat's own tor uses random 127.0.0.1 ports, a cookie login,\n"
    "              and keeps its data in a private temporary folder deleted on exit. It\n"
    "              quits if chat does\n"
    "  --tor-path  the tor program to start (default: tor on PATH, or the usual folders)\n"
    "  --tor-socks, --tor-control\n"
    "              where to look for a running tor (default 127.0.0.1:9050 and :9051; Tor\n"
    "              Browser's 9150 and 9151 are tried too)\n"
    "  --identity  age: an Ed25519 identity that signs every session you join, with an\n"
    "              AGE recipient (age1...) others can `age -r` encrypt files to.\n"
    "              pgp: the same key as PGP, whose public key others can import.\n"
    "              Both ask for a password (or read CHAT_SIGN_PASSWORD) and make the key\n"
    "              from it and this device's machine id. The same password on the same\n"
    "              device and OS always gives the same key, so use the same password every\n"
    "              time to keep your signing identity. A blank password gives a new key\n"
    "              each run.\n"
    "              age:KEYFILE, pgp:KEYFILE: sign with your own key instead, either an\n"
    "              identity file from age-keygen or an UNENCRYPTED armored EdDSA secret key\n"
    "              from gpg. chat needs the secret key because it signs with it; it stays\n"
    "              in memory and is never sent. Without --identity chat starts unsigned, or\n"
    "              with the key :install saved. Signing identity on the settings page\n"
    "              (:set sign) sets up any of these, or turns signing off, without\n"
    "              restarting. A key file can be picked in a file browser or its path\n"
    "              typed, and a key can be pasted in. For a key file :install saves its\n"
    "              path, not the key. Any other key is only written to disk by :install,\n"
    "              sealed.\n"
    "  --simple    don't use the full-screen UI, even in a terminal. Prints plain\n"
    "              \"[HH:MM] ...\" lines for one session and reads lines from stdin. A line\n"
    "              starting with : is a command (:help lists them). For scripts and basic\n"
    "              terminals. This is also used automatically when stdout isn't a tty.\n"
    "              Typed in a terminal, Ctrl+C quits on a second press within 3 seconds.\n"
    "  --session   join this session at startup (needs --port; \"chat --session ID\" alone\n"
    "              still opens the TUI so you can join yourself)\n"
    "  --update    install the latest release from GitHub and exit, without opening chat\n"
    "  --version   print the version and exit\n"
    "\n"
    "Encryption: X25519 + ML-KEM-768 (hybrid, post-quantum), XChaCha20-Poly1305, and a\n"
    "ratchet per message for forward secrecy. Nothing is written to disk unless you ask\n"
    "for it with :install or :download. Messages are never saved.\n";

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

typedef struct {
    char name[200];   // a folder's ends in '/'
    int is_dir;
} dir_entry_t;

typedef struct {
    char path[900];
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
    char tor_path[512];
    uint64_t file_cap;   // 0: the default
    int fast_files;
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
    char shadow_pass[256];   // the shadow passphrase while its box asks for it again to confirm
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
    char install_pass[256];
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
    char send_dir[900];   // the folder :send's browser last offered a file from
    char save_dir[900];   // the folder :saveto's browser last saved a file in
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
    char pending_auto_password[256];
    uint16_t pending_auto_port;
    // As given. A name in them is only looked up once the startup settings page is done.
    char pending_auto_peer_args[MAX_PEER_ARGS][PEER_ARG_LEN];
    int pending_auto_n_peers;
} app_t;

static app_t g_app;

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

static options_t g_opts;
static int g_argc;
static char **g_argv;   // a copy: the real command line is blanked where other programs read it

// Passwords chat can be given in the environment. They leave it as chat starts.
static const char *const SECRET_ENV[] = { "CHAT_PASSWORD", "CHAT_INSTALL_PASSWORD", "CHAT_SIGN_PASSWORD", NULL };

static char **copy_args(int argc, char **argv) {
    char **out = calloc((size_t)argc + 1, sizeof *out);
    for (int i = 0; out && i < argc; i++) {
        size_t n = strlen(argv[i]) + 1;
        if (!(out[i] = malloc(n))) return NULL;
        memcpy(out[i], argv[i], n);
    }
    return out;
}

// g_interrupted ends the main loop. SIGINT only sets g_ctrl_c, and the loop asks before quitting,
// since Ctrl+C is easy to press by accident (to copy, say). In the full-screen UI on Linux, Ctrl+C
// is a key instead (term_raw_enable), so SIGINT there is a kill -INT.
static volatile sig_atomic_t g_interrupted = 0;
static volatile sig_atomic_t g_ctrl_c = 0;
static void on_quit_signal(int sig) {
    if (sig == SIGINT) g_ctrl_c = 1;
    else g_interrupted = 1;
#ifdef _WIN32
    // The Windows C runtime puts the default back before calling a handler.
    signal(sig, on_quit_signal);
#endif
}

// A kill, a closed terminal or a confirmed Ctrl+C all end the main loop, so sessions say bye, keys
// are wiped, the terminal is restored and chat's own tor is stopped, instead of the process just
// dying. The handler has to stay in place for a second signal too. With plain signal() and
// _POSIX_C_SOURCE, glibc resets it after the first, and a second Ctrl+C or kill skipped all of that.
static void catch_quit_signals(void) {
#ifdef _WIN32
    signal(SIGINT, on_quit_signal);
    signal(SIGTERM, on_quit_signal);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_quit_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
#endif
}

// App level notes go wherever the user is looking: the selected session's console, otherwise the startup log.
static int g_plain;   // --simple (or no terminal): app notes go to stdout

static void push_log(const char *fmt, ...) {
    char msg[TUI_LINE_MAX];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    char hhmm[6]; current_hhmm(hhmm);
    if (g_plain) { printf("[%s] %s\n", hhmm, msg); fflush(stdout); return; }
    tui_scrollback_push(g_app.selected ? &g_app.selected->console : &g_app.log, hhmm, msg, NULL, 0, 0);
    g_app.dirty = 1;
}

// While set, the first line a session prints to its console goes on the bottom bar too: the reply to
// a file action, which would otherwise only reach a console that may be hidden, or not on screen.
static int g_echo;

static void session_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                          unsigned flags, int color_len, int file) {
    session_slot_t *s = (session_slot_t *)ui;
    if (g_echo == 1 && !(flags & LINE_CHAT) && s == g_app.selected) {
        copy_str(g_app.message, strncmp(text, "* ", 2) == 0 ? text + 2 : text, sizeof g_app.message);
        g_echo = 2;
    }
    // A warning goes in the chat too, since the console can be hidden.
    if (flags & LINE_WARN) {
        tui_scrollback_push(&s->sb, hhmm, text, NULL, 0, 0);
        if (s != g_app.selected) { s->unread++; s->mentioned = 1; }
        if (s->scroll > 0 && s->scroll < s->sb.count - 1) s->scroll++;
    }
    if (flags & LINE_CHAT) {
        tui_scrollback_push(&s->sb, hhmm, text, rgb, (flags & LINE_MENTION) != 0, color_len);
        if (file) tui_scrollback_mark_file(&s->sb, file);
        if (s != g_app.selected) {
            s->unread++;
            if (flags & LINE_MENTION) s->mentioned = 1;
        }
        // When scrolled back, the chat stays on the messages in view.
        if (s->scroll > 0 && s->scroll < s->sb.count - 1) s->scroll++;
    } else {
        tui_scrollback_push(&s->console, hhmm, text, rgb, 0, 0);
    }
    g_app.dirty = 1;
}

static int session_ready(const session_slot_t *s) { return !s->initialising && chat_ready(&s->engine); }

static void console_note(session_slot_t *s, const char *fmt, ...);

static pic_t *pic_find(session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used && s->pics[i].num == num) return &s->pics[i];
    return NULL;
}

static void pic_free(pic_t *p) {
    if (p->th.rgb) crypto_wipe(p->th.rgb, (size_t)p->th.w * (size_t)p->th.h * 3);
    image_thumb_free(&p->th);
    memset(p, 0, sizeof *p);
}

static void pics_free(session_slot_t *s) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used) pic_free(&s->pics[i]);
}

static const tui_image_t *pic_for(const void *ctx, int file) {
    const session_slot_t *s = ctx;
    for (int i = 0; i < MAX_PICS; i++)
        if (s->pics[i].used && s->pics[i].num == file && s->pics[i].shown && s->pics[i].th.rgb) return &s->pics[i].ti;
    return NULL;
}

static void tilde_path(const char *path, char *out, size_t cap);

static const char *pic_why(const session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++)
        if (s->pics[i].used && s->pics[i].num == num && !s->pics[i].th.rgb && s->pics[i].why[0]) return s->pics[i].why;
    return NULL;
}

// The progress of a fetch, as its row in the chat and the picture page say it.
static int fetch_progress(const chat_t *e, const file_entry_t *f, char *text, size_t cap) {
    if (f->dl == DL_QUEUED) {
        int after = chat_file_queued_after(e, f);
        if (after) snprintf(text, cap, "queued \xc2\xb7 starts after file %d", after);
        else snprintf(text, cap, "queued \xc2\xb7 waiting for its sender");
        return 0;
    }
    uint64_t got = chat_file_got(f);
    int permille = f->size ? (int)(got * 1000 / f->size) : 1000;
    char gs[32], all[32], eta[64];
    file_format_size(got, gs, sizeof gs);
    file_format_size(f->size, all, sizeof all);
    double left = chat_file_eta(e, f, now_seconds());
    if (left >= 0.0) { file_format_duration(left, eta, sizeof eta); strcat(eta, " left"); }
    else copy_str(eta, left < -1.0 ? "waiting until verify codes are compared" : "waiting for its sender", sizeof eta);
    snprintf(text, cap, "%d%% \xc2\xb7 %s of %s \xc2\xb7 %s", permille / 10, gs, all, eta);
    return permille;
}

// The row under the line that offered a file: how a fetch is going (through the relays it can take
// a long time), where it was saved or why it failed, and for one of ours, who's fetching it or has.
static const tui_progress_t *progress_for(const void *ctx, int file) {
    static tui_progress_t pg;
    const session_slot_t *s = ctx;
    const file_entry_t *f = chat_file(&s->engine, file);
    if (!f) return NULL;
    memset(&pg, 0, sizeof pg);
    if (f->mine) {
        char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
        int pm, n = chat_file_sending(&s->engine, f, now_seconds(), name, &pm);
        chat_file_sent_to(f, to, sizeof to);
        if (n) {
            pg.permille = pm;
            snprintf(pg.text, sizeof pg.text, "%d%% \xc2\xb7 sending to %s%s", pm / 10, name, n > 1 ? " and others" : "");
        } else if (to[0]) {
            pg.kind = TUI_PROGRESS_DONE;
            snprintf(pg.text, sizeof pg.text, "sent to %s%s", to, f->fp ? "" : " \xc2\xb7 no longer offered");
        } else if (!f->fp) {
            pg.kind = TUI_PROGRESS_NOTE;
            copy_str(pg.text, "no longer offered", sizeof pg.text);
        } else {
            return NULL;
        }
        return &pg;
    }
    if (f->dl == DL_ACTIVE || f->dl == DL_QUEUED) {
        pg.permille = fetch_progress(&s->engine, f, pg.text, sizeof pg.text);
        return &pg;
    }
    if (f->dl == DL_FAILED) {
        pg.kind = TUI_PROGRESS_FAILED;
        snprintf(pg.text, sizeof pg.text, "%s \xc2\xb7 :%s %d tries again", f->why[0] ? f->why : "it didn't finish",
                 f->view ? "show" : "download", f->num);
        return &pg;
    }
    if (f->saved[0]) {
        char where[sizeof f->saved];
        tilde_path(f->saved, where, sizeof where);
        pg.kind = TUI_PROGRESS_DONE;
        snprintf(pg.text, sizeof pg.text, "saved to %.150s", where);
        return &pg;
    }
    const char *why = pic_why(s, file);
    if (why) {
        pg.kind = TUI_PROGRESS_FAILED;
        snprintf(pg.text, sizeof pg.text, "can't show it: %s \xc2\xb7 :download %d saves it", why, f->num);
        return &pg;
    }
    return NULL;
}

static pic_t *pic_slot(session_slot_t *s, int num) {
    pic_t *p = pic_find(s, num);
    if (!p) for (int i = 0; i < MAX_PICS && !p; i++) if (!s->pics[i].used) p = &s->pics[i];
    if (!p) {
        p = &s->pics[0];
        for (int i = 1; i < MAX_PICS; i++) if (s->pics[i].num < p->num) p = &s->pics[i];
    }
    pic_free(p);
    p->used = 1;
    p->num = num;
    return p;
}

// A picture fetched to show has arrived. It's decoded into a thumbnail here, then the bytes are discarded.
static void session_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
    session_slot_t *s = ui;
    (void)name;
    static const uint8_t bg[3] = { 0, 0, 0 };
    image_thumb_t th;
    char why[160];
    if (image_thumbnail(data, len, TUI_IMAGE_MAX_W, TUI_IMAGE_MAX_H, bg, &th, why, sizeof why) != 0) {
        const file_entry_t *f = chat_file(&s->engine, num);
        copy_str(pic_slot(s, num)->why, why, sizeof s->pics[0].why);
        if (f && f->mine) console_note(s, "* can't show file %d: %s", num, why);
        else console_note(s, "* can't show file %d: %s - :download %d saves it", num, why, num);
        return;
    }
    pic_t *p = pic_slot(s, num);
    p->shown = 1;
    p->th = th;
    p->ti = (tui_image_t){ th.w, th.h, th.rgb };
    console_note(s, "* file %d shown (%dx%d) - :hide %d hides it", num, th.src_w, th.src_h, num);
    g_app.dirty = 1;
}

// That a message came in, plus who sent it and what it says only if the preview setting let the
// engine pass them on (otherwise nick and text are NULL). Never the session, since desktops keep a
// history of notifications (Windows writes it to disk), and with a blank password a session's id
// is all someone needs to join it.
static void send_notification(const char *nick, const char *text, int mentioned) {
    char title[CHAT_NAME_LEN * 2 + 48], body[MAX_TEXT + CHAT_NAME_LEN * 2 + 48];
    if (nick && text) {
        snprintf(title, sizeof title, mentioned ? "%s mentioned you" : "%s", nick);
        copy_str(body, text, sizeof body);
    } else if (nick) {
        copy_str(title, "chat", sizeof title);
        snprintf(body, sizeof body, mentioned ? "%s mentioned you" : "new message from %s", nick);
    } else {
        copy_str(title, "chat", sizeof title);
        copy_str(body, mentioned ? "you were mentioned" : "new message", sizeof body);
    }
    platform_notify(title, body);
    crypto_wipe(body, sizeof body);
}

static void session_notify(void *ui, const char *nick, const char *text, int mentioned) {
    (void)ui;
    send_notification(nick, text, mentioned);
}

static int slot_index(session_slot_t *s) { return (int)(s - g_app.sessions); }

static session_slot_t *find_free_slot(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) if (!g_app.used[i]) return &g_app.sessions[i];
    return NULL;
}

// The conversation and console on screen are kept out of swap, like the keys. Best effort: beyond
// RLIMIT_MEMLOCK they're just kept in memory as normal.
static void lock_scrollbacks(session_slot_t *s) {
    crypto_lock(&s->sb, sizeof s->sb);
    crypto_lock(&s->console, sizeof s->console);
}

// Zeroes them as it unlocks them.
static void release_scrollbacks(session_slot_t *s) {
    crypto_unlock(&s->sb, sizeof s->sb);
    crypto_unlock(&s->console, sizeof s->console);
}

// Puts s on screen (or none). The session being left loses its new messages line, and s gets one
// above what arrived while it was away, which then counts as read.
static void select_session(session_slot_t *s) {
    if (g_app.selected && g_app.selected != s) g_app.selected->has_new = 0;
    g_app.selected = s;
    g_app.dirty = 1;
    if (!s) return;
    if (s->unread > 0 && !s->has_new) {
        s->has_new = 1;
        s->new_at = s->sb.total - (unsigned)s->unread;
    }
    s->unread = 0;
    s->mentioned = 0;
}

// The first open session, or NULL.
static session_slot_t *first_session(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) return &g_app.sessions[i];
    return NULL;
}

static void view_forget(const session_slot_t *s);

static void close_session(session_slot_t *s) {
    if (!s) return;
    int idx = slot_index(s);
    view_forget(s);
    chat_shutdown(&s->engine);
    pics_free(s);
    release_scrollbacks(s);
    g_app.used[idx] = 0;
    if (g_app.selected == s) {
        g_app.selected = NULL;
        select_session(first_session());
    }
    g_app.dirty = 1;
}

static void select_step(int dir) {
    session_slot_t *vis[MAX_SESSIONS]; int n = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) vis[n++] = &g_app.sessions[i];
    if (n == 0) { select_session(NULL); return; }
    int cur = 0;
    for (int i = 0; i < n; i++) if (vis[i] == g_app.selected) { cur = i; break; }
    select_session(vis[(cur + dir + n) % n]);
}

static void render(void);

static void console_note(session_slot_t *s, const char *fmt, ...) {
    char msg[300];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    char hhmm[6]; current_hhmm(hhmm);
    tui_scrollback_push(&s->console, hhmm, msg, NULL, 0, 0);
    g_app.dirty = 1;
}

// The result of the user's last action, on the bottom bar until their next key. Reports and
// anything that happens by itself go to the console instead.
static void note(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_app.message, sizeof g_app.message, fmt, ap);
    va_end(ap);
    g_app.dirty = 1;
}

// Asks the terminal to put text (up to 255 bytes) on the clipboard. A terminal that doesn't allow OSC 52 ignores it.
#define OSC52_MAX 1024   // a PGP public key fits

static void osc52_copy(const char *text) {
    size_t n = strlen(text);
    if (n > OSC52_MAX) n = OSC52_MAX;
    char b64[(OSC52_MAX + 2) / 3 * 4 + 1];
    base64_encode((const uint8_t *)text, n, b64);
    char osc[sizeof b64 + 16];
    snprintf(osc, sizeof osc, "\x1b]52;c;%s\x07", b64);
    platform_write_stdout(osc, strlen(osc));
}

static void copy_session_id(session_slot_t *s) {
    if (!s) { note("no session selected - nothing to copy"); return; }
    const char *sid = s->engine.session_name;
    osc52_copy(sid);
    note("session id copied to the clipboard (OSC 52): %s", sid);
}

// ---- which tor Tor mode uses ----
//
// A tor that's already running is better when chat can use it, since it keeps its entry guards
// between runs and any bridges its torrc sets up. Chat can only use it if its control port answers
// and lets chat log in, since publishing onion services needs that. Otherwise chat starts its own
// tor (torproc.c).

typedef enum { TOR_LAUNCH_AUTO = 0, TOR_LAUNCH_ALWAYS = 1, TOR_LAUNCH_NEVER = 2 } tor_launch_t;
static const char *const TOR_LAUNCH_NAMES[] = { "auto", "always", "never" };

typedef enum { TL_OFF, TL_PROBING, TL_STARTING, TL_READY, TL_FAILED } tor_link_state_t;

// The session of --simple mode, which isn't in the session list.
static chat_t *g_plain_engine;

static struct {
    tor_link_state_t state;
    tor_t *probe;
    torproc_t *proc;
    char socks[TOR_HOST_MAX], control[TOR_HOST_MAX];
    int boot_told, starts;
    double retry_at;
} g_tor;

// Downloads (:update) go through Tor whenever Tor mode is on: to the tor in use once there is one,
// and until then to a port nothing listens on, so they fail instead of going direct.
static void sync_update_proxy(void) {
    if (g_app.route.mode == ROUTE_DHT) update_set_proxy(NULL);
    else update_set_proxy(g_tor.state == TL_READY ? g_tor.socks : "127.0.0.1:1");
}

// What chat's own tor takes at its control port, or NULL for a tor that was running already.
static const char *tor_link_password(void) {
    return g_tor.proc ? torproc_password(g_tor.proc) : NULL;
}

static void tor_link_apply(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_t *e = &g_app.sessions[i].engine;
        if (e->route.mode == ROUTE_TOR) chat_tor_set_ports(e, g_tor.socks, g_tor.control, tor_link_password());
    }
    if (g_plain_engine && g_plain_engine->route.mode == ROUTE_TOR)
        chat_tor_set_ports(g_plain_engine, g_tor.socks, g_tor.control, tor_link_password());
    sync_update_proxy();
}

// Relays tried while tor was still connecting failed and backed off for up to five minutes, so
// once it's connected they're retried straight away.
static void tor_link_connected(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_t *e = &g_app.sessions[i].engine;
        if (e->route.mode == ROUTE_TOR) chat_tor_connected(e);
    }
    if (g_plain_engine && g_plain_engine->route.mode == ROUTE_TOR) chat_tor_connected(g_plain_engine);
}

static void tor_link_fail(double now, double retry_in) {
    g_tor.state = TL_FAILED;
    g_tor.retry_at = now + retry_in;
}

static void tor_link_start_own(double now) {
    char program[1024], err[160];
    if (platform_find_program("tor", g_app.tor_path, program, sizeof program) != 0) {
        if (g_app.tor_path[0])
            push_log("* tor: can't use %s as tor - it has to be a program only root or you can change", g_app.tor_path);
        else
            push_log("* tor: tor isn't installed. Install it (Arch: sudo pacman -S tor, Debian/Ubuntu: sudo apt install tor, "
                     "Windows: the Tor Expert Bundle), set where it is with :set torpath, or start Tor Browser");
        tor_link_fail(now, 30.0);
        return;
    }
    g_tor.proc = torproc_start(program, err, sizeof err);
    if (!g_tor.proc) {
        push_log("* tor: couldn't start %s: %s", program, err);
        tor_link_fail(now, 30.0);
        return;
    }
    g_tor.state = TL_STARTING;
    g_tor.boot_told = -1;
    push_log("* tor: starting chat's own tor (%s) - its data is kept in a private temporary folder, deleted when chat exits",
             program);
}

// Makes sure Tor mode has a tor, or is getting one.
static void tor_link_ensure(double now) {
    if (g_app.route.mode != ROUTE_TOR) return;
    if (g_tor.state == TL_FAILED && now >= g_tor.retry_at) g_tor.state = TL_OFF;
    if (g_tor.state != TL_OFF) return;
    if (g_app.tor_launch == TOR_LAUNCH_ALWAYS) { tor_link_start_own(now); return; }
    g_tor.probe = tor_probe_new(&g_app.route.tor);
    if (!g_tor.probe) { tor_link_fail(now, 30.0); return; }
    g_tor.state = TL_PROBING;
}

static void tor_link_step(double now) {
    switch (g_tor.state) {
        case TL_PROBING: {
            tor_step(g_tor.probe, now);
            char why[160] = "";
            int r = tor_probe_result(g_tor.probe, g_tor.socks, g_tor.control, why, sizeof why);
            if (r == 0) return;
            tor_free(g_tor.probe);
            g_tor.probe = NULL;
            if (r > 0) {
                g_tor.state = TL_READY;
                push_log("* tor: using the tor that's already running (control port %s) - it keeps its entry guards "
                         "and any bridges it's set up with", g_tor.control);
                tor_link_apply();
            } else if (g_app.tor_launch == TOR_LAUNCH_NEVER) {
                if (r == -2) push_log("* tor: the running tor won't let chat in: %s", why);
                else push_log("* tor: no tor is running at %s or Tor Browser's ports - start one, or let chat start its "
                              "own (:set torlaunch auto)", g_app.route.tor.control);
                tor_link_fail(now, 30.0);
            } else {
                if (r == -2) push_log("* tor: a tor is running but won't let chat in (%s) - starting chat's own", why);
                else push_log("* tor: no tor running - starting chat's own");
                tor_link_start_own(now);
            }
            return;
        }
        case TL_STARTING:
        case TL_READY: {
            if (!g_tor.proc) return;
            torproc_state_t st = torproc_poll(g_tor.proc);
            if (st == TORPROC_EXITED) {
                char problem[200];
                torproc_problem(g_tor.proc, problem, sizeof problem);
                push_log("* tor: chat's tor stopped%s%s", problem[0] ? ": " : "", problem);
                torproc_stop(g_tor.proc);
                g_tor.proc = NULL;
                // Most likely another program took a port first, so try new ones a couple of times.
                if (++g_tor.starts < 3) { g_tor.state = TL_OFF; tor_link_start_own(now); }
                else tor_link_fail(now, 60.0);
                return;
            }
            if (g_tor.state == TL_STARTING && st == TORPROC_READY) {
                g_tor.state = TL_READY;
                copy_str(g_tor.socks, torproc_socks(g_tor.proc), sizeof g_tor.socks);
                copy_str(g_tor.control, torproc_control(g_tor.proc), sizeof g_tor.control);
                const char *v = torproc_version(g_tor.proc);
                push_log("* tor: %s is up on %s, connecting to the Tor network...", v[0] ? v : "tor", g_tor.control);
                tor_link_apply();
            }
            int b = torproc_bootstrap(g_tor.proc);
            if (g_tor.state == TL_READY && b >= 0 && (b == 100 ? g_tor.boot_told < 100 : b >= g_tor.boot_told + 25)) {
                g_tor.boot_told = b;
                if (b == 100) { g_tor.starts = 0; push_log("* tor: connected to the Tor network"); tor_link_connected(); }
                else push_log("* tor: connecting to the Tor network: %d%%", b);
            }
            return;
        }
        default:
            return;
    }
}

static void tor_link_stop(void) {
    if (g_tor.probe) { tor_free(g_tor.probe); g_tor.probe = NULL; }
    torproc_stop(g_tor.proc);
    g_tor.proc = NULL;
    g_tor.state = TL_OFF;
}

static void tor_link_line(char *out, size_t cap) {
    switch (g_tor.state) {
        case TL_PROBING:  snprintf(out, cap, "tor: looking"); break;
        case TL_STARTING: snprintf(out, cap, "tor: starting"); break;
        case TL_FAILED:   snprintf(out, cap, "tor: none"); break;
        case TL_READY:
            if (!g_tor.proc) snprintf(out, cap, "tor: running one");
            else if (g_tor.boot_told < 100) snprintf(out, cap, "tor: own %d%%", torproc_bootstrap(g_tor.proc) < 0 ? 0 : torproc_bootstrap(g_tor.proc));
            else snprintf(out, cap, "tor: own");
            break;
        default: snprintf(out, cap, "tor: off"); break;
    }
}

// This build as reported to peers, read at startup before :update can replace the file.
static chat_build_t g_self_build;

// What peers are told about this build ("v"), and the key used to check the builds they report.
static void set_build_opts(chat_opts_t *o) {
    o->build = g_self_build;
    copy_str(o->release_key, update_release_key(), sizeof o->release_key);
}

static session_slot_t *start_session(const char *session_name, const char *password, int created,
                                      uint16_t port, const addr_t *peers, int n_peers) {
    session_slot_t *s = find_free_slot();
    if (!s) { push_log("* too many sessions open already"); return NULL; }
    int idx = slot_index(s);
    memset(s, 0, sizeof *s);
    lock_scrollbacks(s);
    copy_str(s->name, session_name, sizeof s->name);

    char pw[256];
    copy_str(pw, password, sizeof pw);

    s->initialising = 1;
    g_app.used[idx] = 1;
    select_session(s);
    console_note(s, "chat build %s - initialising session '%s', deriving keys...", CHAT_BUILD_STAMP, s->name);
    render();
    g_app.dirty = 0;

    chat_opts_t o; memset(&o, 0, sizeof o);
    copy_str(o.nick, g_app.nick, sizeof o.nick);
    copy_str(o.session_name, session_name, sizeof o.session_name);
    copy_str(o.password, pw, sizeof o.password);
    crypto_wipe(pw, sizeof pw);
    o.port = port ? port : g_app.default_port;
    if (n_peers > 0) { memcpy(o.peers, peers, sizeof(addr_t) * (size_t)n_peers); o.n_peers = n_peers; }
    o.route = g_app.route;
    if (o.route.mode == ROUTE_TOR) {
        // The tor found or started for Tor mode. Until there is one, the session waits for it.
        tor_link_ensure(now_seconds());
        copy_str(o.route.tor.socks, g_tor.state == TL_READY ? g_tor.socks : "", sizeof o.route.tor.socks);
        copy_str(o.route.tor.control, g_tor.state == TL_READY ? g_tor.control : "", sizeof o.route.tor.control);
    }
    o.created = created;
    o.notify_mode = g_app.notify_mode;
    o.notify_preview = g_app.notify_preview;
    o.verify_optional = g_app.verify_optional;
    o.file_cap = g_app.file_cap;
    o.fast_files = g_app.fast_files;
    o.has_color = 1;
    memcpy(o.color, g_app.color, 3);
    o.identity_source = g_app.identity_source;
    if (g_app.identity_source != IDENT_NONE) o.identity = g_app.identity;
    set_build_opts(&o);

    chat_init(&s->engine, &o, session_print, session_notify, s);
    s->engine.file_view = session_file_view;
    crypto_wipe(&o, sizeof o);
    if (!chat_started(&s->engine)) {
        const char *why = chat_start_error(&s->engine);
        chat_shutdown(&s->engine);
        release_scrollbacks(s);
        g_app.used[idx] = 0;
        g_app.selected = NULL;
        select_session(first_session());
        push_log("* couldn't start that session: %s", why);
        return NULL;
    }
    // The session's routing holds the password for a running tor, not the one chat's own tor takes.
    if (s->engine.route.mode == ROUTE_TOR && g_tor.state == TL_READY && g_tor.proc)
        chat_tor_set_ports(&s->engine, g_tor.socks, g_tor.control, torproc_password(g_tor.proc));
    s->engine.net_verbose = g_app.net_verbose;
    s->initialising = 0;
    g_app.dirty = 1;

    char idhex[9]; hex_encode(s->engine.my_id, 4, idhex);
    if (created) {
        console_note(s, "new session '%s' - share the id and password to invite others. you are %s (peer %s)",
                     s->engine.session_name, s->engine.nick, idhex);
    } else {
        console_note(s, "joining '%s' as %s (peer %s) - chat opens once someone answers",
                     s->engine.session_name, s->engine.nick, idhex);
    }
    if (g_app.route.mode == ROUTE_TOR)
        console_note(s, "* routing: Tor onion services only - connecting takes a little longer");
    return s;
}

static int pgp_key_made_here(void) {
    return g_app.identity_source == IDENT_PGP && (g_app.key_origin == KEY_MADE || g_app.key_origin == KEY_DERIVED);
}

// The PGP key made here, armored, with the nick as it is now in its user id.
static void pgp_public_key(char armor[PGP_ARMOR_MAX], uint8_t fp[PGP_FP_LEN]) {
    pgp_export_public_key(&g_app.identity, g_app.nick[0] ? g_app.nick : "chat", g_app.pgp_created,
                          armor, PGP_ARMOR_MAX, fp);
}

static void show_identity_result(void) {
    if (g_app.identity_source == IDENT_NONE) return;
    uint8_t fp[ID_FP_LEN]; identity_fingerprint(g_app.identity.pub, fp);
    char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(fp, ID_FP_LEN, fphex);
    push_log("your identity fingerprint: %s - compare it with peers over another channel", fphex);
    if (g_app.identity_source == IDENT_AGE) {
        char recipient[AGE_RECIPIENT_STRLEN + 1];
        age_export_recipient(&g_app.identity, recipient);
        push_log("AGE recipient (others can `age -r` encrypt files to you): %s", recipient);
    }
    if (pgp_key_made_here()) {
        char armor[PGP_ARMOR_MAX]; uint8_t pgp_fp[PGP_FP_LEN];
        pgp_public_key(armor, pgp_fp);
        push_log("PGP public key (others can `gpg --import` it; Enter on it in the settings copies it):");
        // Line by line, including the blank one after BEGIN, which gpg needs.
        for (char *line = armor, *nl; *line; line = nl + 1) {
            nl = strchr(line, '\n');
            if (!nl) { push_log("%s", line); break; }
            *nl = '\0';
            push_log("%s", line);
        }
    }
}

static void finish_onboarding(void) {
    g_app.mode = MODE_CHAT;

    if (g_app.pending_auto_session[0]) {
        addr_t peers[MAX_PEER_ARGS];
        int n_peers = 0;
        if (g_app.pending_auto_n_peers > 0 && g_app.route.mode == ROUTE_TOR) {
            // Looking a name up here would go around Tor.
            push_log("* --peer left out: Tor mode never reaches peers over UDP, so their addresses aren't looked up");
        } else {
            for (int i = 0; i < g_app.pending_auto_n_peers; i++) {
                if (addr_parse_hostport(g_app.pending_auto_peer_args[i], &peers[n_peers]) == 0) n_peers++;
                else push_log("* --peer %s left out: can't find that address", g_app.pending_auto_peer_args[i]);
            }
        }
        start_session(g_app.pending_auto_session, g_app.pending_auto_password, 0,
                      g_app.pending_auto_port, peers, n_peers);
        crypto_wipe(g_app.pending_auto_password, sizeof g_app.pending_auto_password);
        g_app.pending_auto_session[0] = '\0';
    }
    g_app.dirty = 1;
}

// Folders first, then files. In each, hidden ones (starting with '.') last.
static int entry_cmp(const void *a, const void *b) {
    const dir_entry_t *ea = a, *eb = b;
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir;
    int ha = ea->name[0] == '.', hb = eb->name[0] == '.';
    if (ha != hb) return ha - hb;
    return strcasecmp(ea->name, eb->name);
}

static int path_is_root(const char *p) {
    size_t n = strlen(p);
    return strcmp(p, "/") == 0 || (n == 2 && p[1] == ':') || (n == 3 && p[1] == ':' && p[2] == '/');
}

static void path_join(char *out, size_t cap, const char *dir, const char *name) {
    size_t n = strlen(dir);
    snprintf(out, cap, (n > 0 && dir[n - 1] == '/') ? "%s%s" : "%s/%s", dir, name);
}

static void path_parent(char *p) {
    if (path_is_root(p)) return;
    size_t n = strlen(p);
    while (n > 1 && p[n - 1] == '/') p[--n] = '\0';
    char *slash = strrchr(p, '/');
    if (!slash) return;
    if (slash == p) p[1] = '\0';
    else if (slash == p + 2 && p[1] == ':') slash[1] = '\0';
    else *slash = '\0';
}

static void browser_add(void *ctx, const char *name, int is_dir) {
    browser_t *b = ctx;
    if (b->n_items >= MAX_DIR_ITEMS) return;
    // Names are written straight to the terminal, and one containing escape sequences could control it.
    if (has_control_chars(name)) return;
    // The tree above the entries shows the parent folders, and h goes up.
    if (strcmp(name, "..") == 0) return;
    dir_entry_t *item = &b->items[b->n_items++];
    snprintf(item->name, sizeof item->name, "%s%s", name, is_dir ? "/" : "");
    item->is_dir = is_dir;
}

static int browser_load(browser_t *b, const char *path) {
    static browser_t tmp;
    memset(&tmp, 0, sizeof tmp);
    copy_str(tmp.path, path, sizeof tmp.path);
    if (platform_list_dir(tmp.path, browser_add, &tmp) != 0) return -1;
    qsort(tmp.items, (size_t)tmp.n_items, sizeof(dir_entry_t), entry_cmp);
    *b = tmp;
    return 0;
}

// Selects the entry called name (a folder's without its '/'), if it's there.
static void browser_select(browser_t *b, const char *name) {
    size_t n = strlen(name);
    if (!n) return;
    for (int i = 0; i < b->n_items; i++) {
        const char *e = b->items[i].name;
        if (strncmp(e, name, n) == 0 && (e[n] == '\0' || (e[n] == '/' && e[n + 1] == '\0'))) { b->selected = i; return; }
    }
}

// The path of an entry in the folder the browser shows, without a folder's trailing '/'.
static void browser_entry_path(const browser_t *b, const dir_entry_t *e, char *out, size_t cap) {
    char name[sizeof e->name];
    copy_str(name, e->name, sizeof name);
    size_t n = strlen(name);
    if (n > 0 && name[n - 1] == '/') name[n - 1] = '\0';
    path_join(out, cap, b->path, name);
}

// New/join prompts use the input line. The draft is saved and restored when the prompt ends.
static void begin_prompt(app_mode_t mode) {
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_app.mode = mode;
    g_app.dirty = 1;
}

static void end_prompt(void) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    crypto_wipe(g_app.pending_session_id, sizeof g_app.pending_session_id);
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = MODE_CHAT;
    g_app.dirty = 1;
}

static cmd_result_t app_new(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_prompt(MODE_NEW_PASSWORD);
    return CMD_OK;
}

static cmd_result_t app_join(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_prompt(MODE_JOIN_ID);
    return CMD_OK;
}

static cmd_result_t app_quit(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    if (g_app.selected) close_session(g_app.selected);
    else g_interrupted = 1;
    return CMD_OK;
}

static cmd_result_t app_quitall(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    g_interrupted = 1;
    return CMD_OK;
}

static cmd_result_t app_copyid(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    copy_session_id(g_app.selected);
    return CMD_OK;
}

static cmd_result_t app_update(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    if (g_app.route.mode == ROUTE_TOR && g_tor.state != TL_READY) {
        push_log("* update: Tor mode downloads through Tor, and there's no tor yet - try again once it's connected");
        return CMD_OK;
    }
    // If an update is already running, its box is shown again.
    if (update_start() == 0) push_log("* update: checking GitHub for a newer release (v" CHAT_VERSION " here)...");
    begin_prompt(MODE_UPDATE);
    return CMD_OK;
}

// The box only shows the update. Closing it leaves the update running, and the result goes to the
// console either way.
static void update_key(const tui_key_t *key) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (key->type != TUI_KEY_ESCAPE && key->type != TUI_KEY_ENTER && ch != 'q') return;
    update_view_t v;
    update_view(&v);
    end_prompt();
    if (v.running) note("the update keeps running - :update shows it again");
}

static cmd_result_t app_help(void *ctx, const char *arg);
static cmd_result_t app_changelog(void *ctx, const char *arg);
static cmd_result_t app_files(void *ctx, const char *arg);
static cmd_result_t app_show(void *ctx, const char *arg);
static cmd_result_t app_hide(void *ctx, const char *arg);
static cmd_result_t app_saveto(void *ctx, const char *arg);

// ---- routing: asked at the start of --simple; the full-screen UI opens on the settings page ----

static const char *const ROUTE_CHOICE_LINES[] = {
    "* how should chat reach people?",
    ("*   [1] DHT + Nostr fallback (recommended): UDP straight to peers, found through the BitTorrent DHT "
     "(IPv4 and IPv6), your LAN and a router port mapping. Public Nostr relays carry the traffic, encrypted "
     "and padded, when UDP can't get through"),
    "*   [2] DHT only: the same without relays. Some peers behind strict NATs won't connect, and neither can "
        "members using Tor",
    ("*   [3] Tor: onion services, and the Nostr relays reached through Tor to meet DHT peers. Hides "
     "your IP address from peers and everyone else. Uses tor or Tor Browser if one is running, else starts "
     "its own; connecting takes longer"),
};

// A routing choice doesn't override --nonostr or --nostr-always. DHT + Nostr uses the relays as
// those options say, and only DHT alone turns the relays off.
static void apply_route_choice(int choice) {
    if (choice == 3) {
        g_app.route.mode = ROUTE_TOR;
    } else {
        g_app.route.mode = ROUTE_DHT;
        g_app.route.nostr = choice == 2 ? NOSTR_OFF : g_app.nostr_flag >= 0 ? g_app.nostr_flag : NOSTR_FALLBACK;
    }
    g_app.route_chosen = 1;
}

static const char *route_label(void) {
    if (g_app.route.mode == ROUTE_TOR) return "Tor onion services only";
    return g_app.route.nostr == NOSTR_ALWAYS ? "DHT, with Nostr relays always"
         : g_app.route.nostr ? "DHT, with Nostr relay fallback" : "DHT only";
}

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
    SET_VERIFY, SET_FILE_LIMIT, SET_FAST_FILES, SET_NOTIFY, SET_PREVIEW, SET_NET, SET_PORT,
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

static const setting_def_t SETTINGS[] = {
    { SET_ROUTING, "Network", NULL, "routing", "Routing", K_CHOICE, "dht|tor",
      "dht: UDP directly between peers, found using the options below. tor: onion services, plus the Nostr "
      "relays through Tor to meet DHT members. Hides your IP address from everyone. Uses a running tor or "
      "starts chat's own, and connecting takes longer. Applies to sessions you open from now on." },
    { SET_DHT4, NULL, "DHT", "dht", "BitTorrent DHT (IPv4)", K_TOGGLE, "on|off",
      "Finds peers on the internet through the public BitTorrent DHT. DHT nodes see your IP address next to a "
      "lookup key only room members can work out, and a node id that changes with it every hour." },
    { SET_DHT6, NULL, NULL, "dht6", "IPv6 DHT", K_TOGGLE, "on|off",
      "Also looks for peers on the IPv6 DHT (BEP 32). IPv6 usually has no NAT to punch through, so peers there "
      "connect more reliably." },
    { SET_PORTMAP, NULL, NULL, "portmap", "Router port mapping", K_TOGGLE, "on|off",
      "Asks your router to forward this session's UDP port (PCP, NAT-PMP or UPnP-IGD), so peers behind NATs that "
      "can't be hole punched can still reach you. Removed when the session ends. The router may log it." },
    { SET_LAN, NULL, NULL, "lan", "LAN discovery", K_TOGGLE, "on|off",
      "Broadcasts an encrypted beacon on your local network, so room members on it can find you without the "
      "internet." },
    { SET_TOR_LAUNCH, NULL, "Tor", "torlaunch", "Start chat's own tor", K_CHOICE, "auto|always|never",
      "auto: use a tor that's already running if its control port lets chat log in (it keeps its entry guards "
      "and any bridges), otherwise start chat's own. always: chat's own, separate from any other tor, but with "
      "new entry guards each run and nothing from your torrc. never: only a running tor. Chat's own tor uses "
      "random 127.0.0.1 ports, a cookie login and a private temporary folder deleted on exit." },
    { SET_TOR_PATH, NULL, NULL, "torpath", "Tor program", K_TEXT, "PATH",
      "The tor program chat starts: a full path, or empty for tor on PATH or in the usual folders. It must be a "
      "program that only root or you can change." },
    { SET_TOR_SOCKS, NULL, NULL, "torsocks", "Tor SOCKS port", K_TEXT, "HOST:PORT",
      "Where to look for a running tor's SOCKS port (host:port). With the defaults, Tor Browser's "
      "127.0.0.1:9150 is tried too. Applies to sessions you open from now on." },
    { SET_TOR_CONTROL, NULL, NULL, "torcontrol", "Tor control port", K_TEXT, "HOST:PORT",
      "Where to look for a running tor's control port (host:port). It needs ControlPort on, and chat has to be "
      "able to read its cookie file (or have its password). Applies to sessions you open from now on." },
    { SET_TOR_PASSWORD, NULL, NULL, "torpassword", "Tor control password", K_SECRET, NULL,
      "Only for a tor set up with HashedControlPassword. Kept in memory only. Applies to sessions you open from now on." },
    // After both modes' rows: the relays apply in both, so they stay put when the mode changes.
    { SET_NOSTR, NULL, "Relays", "nostr", "Nostr relays", K_CHOICE, "off|on|always",
      "on: DHT routing only connects to the relays while it needs them (nobody reached yet, or a peer UDP can't"
      " reach) and disconnects a minute after. always: stays connected, so Tor members can find a room whose "
      "members all reach each other directly (they only meet on the relays). Tor routing reaches them through "
      "Tor and always stays connected. Each event has a one-off key, a random kind, a fixed size and fresh "
      "encryption, under a tag that changes every 10 minutes, with a new connection for each tag." },
    { SET_RELAYS, NULL, NULL, "relays", "Relay list", K_TEXT, "wss://URL ... (up to 6)",
      "The relays the fallback uses: up to 6 wss:// URLs, separated by spaces or commas." },
    { SET_PORT, NULL, "Advanced", "port", "UDP port for new sessions", K_TEXT, "N",
      "The UDP port new sessions listen on. 0 picks a free one each time. :port moves an open session to another." },
    { SET_NET, NULL, NULL, "net", "Network log", K_CHOICE, "normal|verbose",
      "How much of the network the console shows, in every session. verbose adds every handshake packet, relay "
      "and Tor event." },
    { SET_NICK, "Profile", NULL, "nick", "Nickname", K_TEXT, "NAME", "Your name in every session." },
    { SET_COLOUR, NULL, NULL, "colour", "Colour", K_TEXT, "NAME|#RRGGBB",
      "Your colour in every session. h/l step through the palette, and Enter takes a name or #RRGGBB." },
    { SET_SIGN, NULL, "Keys", "sign", "Signing identity", K_ACTION, "off|age|pgp|age:PATH|pgp:PATH",
      "A key that signs your handshakes so peers can check it's you. Either an AGE or PGP key made here from a "
      "password, or your own key from a file or pasted in. Enter picks one, replaces it or turns signing off. "
      "Kept in memory only, unless :install saves it: a key file's path, or any other key sealed to disk." },
    { SET_AGE_RECIPIENT, NULL, NULL, "agerecipient", "AGE recipient", K_ACTION, NULL,
      "The age1... string others give to age -r to encrypt files to you. Enter copies it to the clipboard." },
    { SET_PGP_PUBKEY, NULL, NULL, "pgpkey", "PGP public key", K_ACTION, NULL,
      "The public half of the PGP key made here, shown by its fingerprint, for others to gpg --import. Enter "
      "copies it to the clipboard. It's in the console too." },
    { SET_AUTOSAVE, "Security", NULL, "autosave", "Autosave", K_TOGGLE, "on|off",
      "Once chat is installed: on saves a setting you change, and a key you verify or forget, as you change it. "
      "off keeps changes until chat exits, unless :save saves them. The signing key is only saved by :save or "
      ":install either way, so a key you're trying out isn't kept by accident." },
    { SET_DEVICE_LOCK, NULL, "Unlocking", "devicelock", "Device lock", K_TOGGLE, "on|off",
      "Requires a secret this device keeps (in its TPM, where there's one) to unlock the save, so it can't be "
      "unlocked anywhere else." },
    { SET_SECURITY_KEY, NULL, NULL, "securitykey", "Security key", K_TOGGLE, "on|off",
      "Requires your FIDO2 security key (a YubiKey, say) to unlock the save: a touch each time, and its PIN if it "
      "has one." },
    { SET_AUTHENTICATOR, NULL, NULL, "authenticator", "Authenticator app", K_TOGGLE, "on|off",
      "Requires the 6-digit code from an authenticator app (Aegis, Google Authenticator, 2FAS...) to unlock the "
      "save." },
    { SET_DESTROY, NULL, "Duress", "destroy", "Self-destruct", K_CHOICE, "off|3|5|10",
      "Deletes what :install saves for good after this many wrong passphrases in a row, so a found or taken "
      "device can't be guessed at forever. The count is kept next to the save, not sealed (it has to be read "
      "before the passphrase opens anything), so someone who copies the files first can reset it: this stops "
      "guessing at the keyboard, not a forensic copy. A right passphrase clears the count." },
    { SET_SHADOW, NULL, NULL, "shadow", "Shadow password", K_ACTION, "on|off",
      "A second passphrase that opens a decoy instead of the real save, and deletes the real save first, for "
      "good. Afterwards only the decoy is there, so there's nothing left to be forced to hand over. The decoy "
      "needs the same security key, device and code, so opening it looks the same. Enter sets or removes it. "
      "Only while a save is open, and it needs the save's own factors to hand." },
    { SET_VERIFY, "Chat", NULL, "verify", "Compare verify codes", K_CHOICE, "required|optional",
      "Anyone with a session's id and password could sit between two members and read what they say. When a peer "
      "joins, chat shows a code to compare with them over another channel. It only matches on both ends if "
      "nobody is in the middle. required: nothing you send goes to a peer until you mark it as matching "
      "(:verify NICK ok). optional: messages go to everyone, compared or not." },
    { SET_NOTIFY, NULL, NULL, "notify", "Notifications", K_CHOICE, "all|mentions|none",
      "Desktop notifications, for open and new sessions: every message, mentions of your nick, or none." },
    { SET_PREVIEW, NULL, NULL, "preview", "Notification preview", K_CHOICE, "off|nick|message",
      "What a notification shows. off: only that a message came in. nick: who it's from. message: who, and what "
      "they said. Desktops keep notifications (Windows writes them to disk), so what they show can outlast chat. "
      "The session is never shown, since its id is all someone needs to join one with a blank password." },
    { SET_FILE_LIMIT, NULL, "Files", "filelimit", "File size limit", K_TEXT, "SIZE (8M, 500K, 1G)",
      "The largest file chat fetches when you ask. An offer over the limit says so, and :download N anyway (or "
      ":show N anyway) fetches it regardless. Nothing is fetched until you ask. Files can be up to 1 GB." },
    { SET_FAST_FILES, NULL, NULL, "fastfiles", "Fast file transfers", K_TOGGLE, "on|off",
      "off: files are sent in chat's regular slots, so a transfer doesn't show up on the network, but it's slow: "
      "about 25 KB a minute, half that through the relays (where Tor and DHT members meet). on: while you send a "
      "file, your slots to that peer come every few milliseconds. It takes seconds instead of minutes, but anyone "
      "watching the network sees a burst about the size of the file. Through the relays it goes as often as they "
      "allow, about twice the normal rate, and the relays can see that. Only the sender's setting matters." },
};
#define N_SETTINGS ((int)(sizeof SETTINGS / sizeof SETTINGS[0]))
_Static_assert(N_SETTINGS == N_SETTING_IDS, "every setting has a row");

static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };
static const char *const PREVIEW_NAMES[] = { "off", "nick", "message" };
static const char *const ON_OFF[] = { "off", "on" };
static const char *const ROUTE_NAMES[] = { "dht", "tor" };
static const char *const NOSTR_NAMES[] = { "off", "on", "always" };
static const char *const VERIFY_NAMES[] = { "required", "optional" };
static const char *const NET_LOG_NAMES[] = { "normal", "verbose" };
static const char *const DESTROY_NAMES[] = { "off", "3", "5", "10" };
static const int DESTROY_VALS[] = { 0, 3, 5, 10 };

static setting_id_t g_edit_id;

static int settings_index(setting_id_t id) {
    for (int i = 0; i < N_SETTINGS; i++) if (SETTINGS[i].id == id) return i;
    return 0;
}

static const setting_def_t *setting_def(setting_id_t id) { return &SETTINGS[settings_index(id)]; }

static const setting_def_t *setting_by_key(const char *key) {
    if (strcmp(key, "color") == 0) key = "colour";
    for (int i = 0; i < N_SETTINGS; i++) if (strcmp(SETTINGS[i].key, key) == 0) return &SETTINGS[i];
    return NULL;
}

static int dht_setting(setting_id_t id) { return id == SET_DHT4 || id == SET_DHT6; }
static int dht_routing_only_setting(setting_id_t id) { return id == SET_PORTMAP || id == SET_LAN; }
static int tor_only_setting(setting_id_t id) {
    return id == SET_TOR_LAUNCH || id == SET_TOR_PATH || id == SET_TOR_SOCKS || id == SET_TOR_CONTROL
        || id == SET_TOR_PASSWORD;
}

// Settings that don't apply right now aren't listed: the DHT ones in Tor mode, the Tor ones in
// DHT mode, the relay list with relays off, the AGE recipient without an AGE identity, and the
// PGP public key without a PGP key made here.
static int setting_shown(setting_id_t id) {
    route_mode_t m = g_app.route.mode;
    if (m != ROUTE_DHT && dht_routing_only_setting(id)) return 0;
    if (m == ROUTE_TOR && dht_setting(id)) return 0;
    if (m != ROUTE_TOR && tor_only_setting(id)) return 0;
    if (id == SET_RELAYS && !g_app.route.nostr) return 0;
    if (id == SET_AGE_RECIPIENT && g_app.identity_source != IDENT_AGE) return 0;
    if (id == SET_PGP_PUBKEY && !pgp_key_made_here()) return 0;
    return 1;
}

static const char *setting_hidden_why(setting_id_t id) {
    if (dht_routing_only_setting(id)) return "it only applies with dht routing";
    if (dht_setting(id)) return "it doesn't apply with tor routing";
    if (tor_only_setting(id)) return "it only applies with tor routing";
    if (id == SET_RELAYS) return "it only applies with the Nostr relays on";
    if (id == SET_PGP_PUBKEY) return "it needs a PGP signing key made here";
    return "it needs an AGE signing identity";
}

// A toggle or choice row's values, in the order h/l steps through them, and the index of the
// current one. Other rows have none, and get -1.
static int setting_options(setting_id_t id, const char *const **names, int *n) {
    const routing_t *r = &g_app.route;
    *names = ON_OFF;
    *n = 2;
    switch (id) {
        case SET_ROUTING:    *names = ROUTE_NAMES; *n = 2; return (int)r->mode;
        case SET_DHT4:       return r->dht4 != 0;
        case SET_DHT6:       return r->dht6 != 0;
        case SET_PORTMAP:    return r->portmap != 0;
        case SET_LAN:        return r->lan != 0;
        case SET_NOSTR:      *names = NOSTR_NAMES; *n = 3; return r->nostr;
        case SET_VERIFY:     *names = VERIFY_NAMES; return g_app.verify_optional != 0;
        case SET_FAST_FILES: return g_app.fast_files != 0;
        case SET_AUTOSAVE:   return g_app.autosave != 0;
        case SET_DEVICE_LOCK: return g_app.device_lock != 0;
        case SET_SECURITY_KEY: return g_app.key_factor != 0;
        case SET_AUTHENTICATOR: return g_app.code_factor != 0;
        case SET_DESTROY: {
            *names = DESTROY_NAMES; *n = 4;
            for (int i = 0; i < 4; i++) if (DESTROY_VALS[i] == g_app.destroy_limit) return i;
            return 0;
        }
        case SET_TOR_LAUNCH: *names = TOR_LAUNCH_NAMES; *n = 3; return g_app.tor_launch;
        case SET_NOTIFY:     *names = NOTIFY_NAMES; *n = 3; return (int)g_app.notify_mode;
        case SET_PREVIEW:    *names = PREVIEW_NAMES; *n = 3; return (int)g_app.notify_preview;
        case SET_NET:        *names = NET_LOG_NAMES; return g_app.net_verbose != 0;
        default:             *names = NULL; *n = 0; return -1;
    }
}

static const char *const SIGN_NAMES[] = { "off", "age", "pgp" };

// What :set takes for a row, for the command line's menu: its values, and the signing identity's
// kinds (age:PATH and pgp:PATH, for a key file, are typed in full, and a pasted key is only chosen on
// the page).
static int setting_choices(setting_id_t id, const char *const **names, int *n) {
    if (id != SET_SIGN) return setting_options(id, names, n);
    *names = SIGN_NAMES;
    *n = 3;
    return g_app.identity_source == IDENT_AGE ? 1 : g_app.identity_source == IDENT_PGP ? 2 : 0;
}

// How the page draws a row's value: a switch, a choice h/l steps through, a way into another
// page, or text.
static tui_value_kind_t setting_kind(const setting_def_t *d) {
    const char *const *names;
    int n, cur = setting_options(d->id, &names, &n);
    if (d->kind == K_TOGGLE) return cur > 0 ? TUI_V_ON : TUI_V_OFF;
    if (d->kind == K_CHOICE) return TUI_V_CHOICE;
    if (d->id == SET_SIGN || d->id == SET_SHADOW) return TUI_V_LINK;
    if (d->kind == K_SECRET) return TUI_V_MUTED;
    return TUI_V_TEXT;
}

static void setting_value(setting_id_t id, char *out, size_t cap) {
    const char *const *names;
    int n, cur = setting_options(id, &names, &n);
    if (cur >= 0) { snprintf(out, cap, "%s", names[cur]); return; }
    const routing_t *r = &g_app.route;
    switch (id) {
        case SET_RELAYS: {
            size_t p = 0;
            out[0] = '\0';
            for (int i = 0; i < r->n_relays && p < cap; i++)
                p += (size_t)snprintf(out + p, cap - p, "%s%s", i ? " " : "", r->relays[i] + 6);
            if (r->n_relays == 0) snprintf(out, cap, "none");
            break;
        }
        case SET_TOR_PATH: {
            char found[1024];
            if (g_app.tor_path[0]) snprintf(out, cap, "%s", g_app.tor_path);
            else if (platform_find_program("tor", NULL, found, sizeof found) == 0) snprintf(out, cap, "found %s", found);
            else snprintf(out, cap, "not installed");
            break;
        }
        case SET_FILE_LIMIT:   file_format_size(g_app.file_cap ? g_app.file_cap : FILE_CAP_DEFAULT, out, cap); break;
        case SET_TOR_SOCKS:    snprintf(out, cap, "%s", r->tor.socks); break;
        case SET_TOR_CONTROL:  snprintf(out, cap, "%s", r->tor.control); break;
        case SET_TOR_PASSWORD: snprintf(out, cap, "%s", r->tor.password[0] ? "set" : "not set (cookie or no login)"); break;
        case SET_NICK:         snprintf(out, cap, "%s", g_app.nick); break;
        case SET_COLOUR: {
            const char *name = NULL;
            for (int i = 0; i < COLOR_PALETTE_N; i++)
                if (COLOR_PALETTE[i].r == g_app.color[0] && COLOR_PALETTE[i].g == g_app.color[1] && COLOR_PALETTE[i].b == g_app.color[2])
                    name = COLOR_PALETTE[i].name;
            if (name) snprintf(out, cap, "%s", name);
            else snprintf(out, cap, "#%02x%02x%02x", g_app.color[0], g_app.color[1], g_app.color[2]);
            break;
        }
        case SET_SIGN: {
            if (g_app.identity_source == IDENT_NONE) { snprintf(out, cap, "off"); break; }
            uint8_t fp[ID_FP_LEN]; identity_fingerprint(g_app.identity.pub, fp);
            char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(fp, ID_FP_LEN, fphex);
            snprintf(out, cap, "%s%s, fingerprint %s", g_app.identity_source == IDENT_AGE ? "age" : "pgp",
                     g_app.key_origin == KEY_DERIVED ? " from password" : "", fphex);
            break;
        }
        case SET_AGE_RECIPIENT: {
            if (g_app.identity_source != IDENT_AGE) { snprintf(out, cap, "none"); break; }
            char recipient[AGE_RECIPIENT_STRLEN + 1];
            age_export_recipient(&g_app.identity, recipient);
            snprintf(out, cap, "%s", recipient);
            break;
        }
        case SET_PGP_PUBKEY: {
            if (!pgp_key_made_here()) { snprintf(out, cap, "none"); break; }
            char armor[PGP_ARMOR_MAX]; uint8_t fp[PGP_FP_LEN];
            pgp_public_key(armor, fp);
            char fphex[PGP_FP_LEN * 2 + 1]; hex_encode(fp, PGP_FP_LEN, fphex);
            snprintf(out, cap, "%s", fphex);
            break;
        }
        case SET_PORT:
            if (g_app.default_port) snprintf(out, cap, "%u", (unsigned)g_app.default_port);
            else snprintf(out, cap, "0 (a free one)");
            break;
        case SET_SHADOW:
            snprintf(out, cap, "%s", g_app.installed && install_has_shadow(install_current()) ? "on" : "off");
            break;
        default:
            out[0] = '\0';
            break;
    }
}

// A row's value in the form :set takes. 0 for a secret, or a value that comes from the signing key.
static int setting_text(setting_id_t id, char *out, size_t cap) {
    const setting_def_t *d = setting_def(id);
    // What a save needs to open is how it's sealed, not a setting in it.
    if (d->kind == K_SECRET || d->kind == K_ACTION || id == SET_DEVICE_LOCK || id == SET_SECURITY_KEY
        || id == SET_AUTHENTICATOR || id == SET_DESTROY)
        return 0;
    const routing_t *r = &g_app.route;
    switch (id) {
        case SET_RELAYS: {
            size_t p = 0;
            out[0] = '\0';
            for (int i = 0; i < r->n_relays && p < cap; i++)
                p += (size_t)snprintf(out + p, cap - p, "%s%s", i ? " " : "", r->relays[i]);
            break;
        }
        case SET_PORT:     snprintf(out, cap, "%u", (unsigned)g_app.default_port); break;
        case SET_TOR_PATH: copy_str(out, g_app.tor_path, cap); break;
        case SET_FILE_LIMIT: {
            uint64_t v = g_app.file_cap ? g_app.file_cap : FILE_CAP_DEFAULT;
            const char *unit = v % (1024u * 1024 * 1024) == 0 ? "G" : v % (1024 * 1024) == 0 ? "M" : v % 1024 == 0 ? "K" : "";
            uint64_t per = unit[0] == 'G' ? 1024u * 1024 * 1024 : unit[0] == 'M' ? 1024 * 1024 : unit[0] == 'K' ? 1024 : 1;
            snprintf(out, cap, "%llu%s", (unsigned long long)(v / per), unit);
            break;
        }
        default: setting_value(id, out, cap); break;
    }
    return 1;
}

#define ROW_TEXT_MAX (NOSTR_MAX_RELAYS * NOSTR_URL_MAX)

// A row is only saved while it isn't the default, so if a later version changes a default you
// still get it. Once installed, a row changed in chat is saved, but one set by a command line
// option isn't. With autosave off, a changed row waits in g_unsaved_rows for autosave or :save.
static char g_setting_defaults[N_SETTINGS][ROW_TEXT_MAX];
static char g_saved_rows[N_SETTINGS][ROW_TEXT_MAX];
static char g_seen_rows[N_SETTINGS][ROW_TEXT_MAX];
static int g_unsaved_rows[N_SETTINGS];

static void note_setting_defaults(void) {
    for (int i = 0; i < N_SETTINGS; i++)
        if (!setting_text(SETTINGS[i].id, g_setting_defaults[i], sizeof g_setting_defaults[i])) g_setting_defaults[i][0] = '\0';
    memcpy(g_saved_rows, g_setting_defaults, sizeof g_saved_rows);
}

static void note_settings_seen(void) {
    for (int i = 0; i < N_SETTINGS; i++)
        if (!setting_text(SETTINGS[i].id, g_seen_rows[i], sizeof g_seen_rows[i])) g_seen_rows[i][0] = '\0';
    memset(g_unsaved_rows, 0, sizeof g_unsaved_rows);
}

// Rows that have moved to another section keep their table, so files saved before still load.
static const char *setting_table(setting_id_t id) {
    return id < SET_NICK ? "network" : id < SET_VERIFY ? "profile" : "chat";
}

static size_t put_text(char *out, size_t p, size_t cap, const char *s) {
    size_t n = strlen(s);
    if (p >= cap || n >= cap - p) return cap;
    memcpy(out + p, s, n + 1);
    return p + n;
}

static size_t put_row_value(int i, const char *v, char *out, size_t p, size_t cap) {
    if (SETTINGS[i].kind == K_TOGGLE) return put_text(out, p, cap, strcmp(v, "on") == 0 ? "true" : "false");
    if (SETTINGS[i].id == SET_PORT) return put_text(out, p, cap, v);
    if (SETTINGS[i].id != SET_RELAYS) return toml_put_str(out, p, cap, v);
    char urls[ROW_TEXT_MAX];
    copy_str(urls, v, sizeof urls);
    p = put_text(out, p, cap, "[");
    int first = 1;
    for (char *url = strtok(urls, " "); url; url = strtok(NULL, " "), first = 0) {
        if (!first) p = put_text(out, p, cap, ", ");
        p = toml_put_str(out, p, cap, url);
    }
    return put_text(out, p, cap, "]");
}

// -1 if it doesn't fit.
static int settings_text(char *out, size_t cap) {
    size_t p = 0;
    const char *table = "";
    out[0] = '\0';
    for (int id = 0; id < N_SETTING_IDS; id++) {
        int i = settings_index((setting_id_t)id);
        if (strcmp(g_saved_rows[i], g_setting_defaults[i]) == 0) continue;
        const char *t = setting_table((setting_id_t)id);
        if (strcmp(t, table) != 0) {
            p = put_text(out, p, cap, p ? "\n[" : "[");
            p = put_text(out, p, cap, t);
            p = put_text(out, p, cap, "]\n");
            table = t;
        }
        p = put_text(out, p, cap, SETTINGS[i].key);
        p = put_text(out, p, cap, " = ");
        p = put_row_value(i, g_saved_rows[i], out, p, cap);
        p = put_text(out, p, cap, "\n");
    }
    return p < cap ? 0 : -1;
}

// Checked before every frame, so any change to a row (from the page or :set) is picked up. The
// autosave row itself is always saved, so turning it on or off lasts.
static void keep_settings_saved(void) {
    if (!g_app.installed) return;
    int changed = 0, held = 0;
    for (int i = 0; i < N_SETTINGS; i++) {
        char v[ROW_TEXT_MAX];
        if (!setting_text(SETTINGS[i].id, v, sizeof v)) continue;
        int fresh = strcmp(v, g_seen_rows[i]) != 0;
        if (fresh) {
            copy_str(g_seen_rows[i], v, sizeof g_seen_rows[i]);
            g_unsaved_rows[i] = strcmp(v, g_saved_rows[i]) != 0;
        }
        if (!g_unsaved_rows[i]) continue;
        if (!g_app.autosave && SETTINGS[i].id != SET_AUTOSAVE) { held |= fresh; continue; }
        copy_str(g_saved_rows[i], v, sizeof g_saved_rows[i]);
        g_unsaved_rows[i] = 0;
        changed = 1;
    }
    size_t n = strlen(g_app.message);
    if (held && n > 0) snprintf(g_app.message + n, sizeof g_app.message - n, " \xc2\xb7 not saved (autosave is off)");
    if (!changed) return;
    static char text[INSTALL_SETTINGS_MAX];
    if (settings_text(text, sizeof text) != 0 || install_write_settings(text) != 0) {
        char where[900] = "";
        install_where(install_current(), where, sizeof where);
        note("couldn't save that in %s/settings - it lasts until chat exits", where);
        return;
    }
    n = strlen(g_app.message);
    if (n > 0 && !held) snprintf(g_app.message + n, sizeof g_app.message - n, " \xc2\xb7 saved");
}

// Pushes the routing settings to the open sessions, where the toggles take effect immediately. On
// the startup settings page nothing goes on the network before Done, so settings_done does it then.
// While a save opened mid-run loads, its rows aren't sent to open sessions one by one: they get the
// final values once it's loaded (settings_to_sessions), so peers don't see a nick go and come back.
static int g_hold_sessions;

static int takes_settings(int i) {
    return g_app.used[i] && !g_app.sessions[i].initialising && !g_hold_sessions;
}

static void settings_to_sessions(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!takes_settings(i)) continue;
        chat_t *e = &g_app.sessions[i].engine;
        chat_apply_routing(e, &g_app.route);
        chat_set_file_options(e, g_app.file_cap, g_app.fast_files);
        e->verify_required = !g_app.verify_optional;
        e->notify_mode = g_app.notify_mode;
        e->notify_preview = g_app.notify_preview;
        e->net_verbose = g_app.net_verbose;
        if (strcmp(e->nick, g_app.nick) != 0) chat_set_nick(e, g_app.nick);
        if (memcmp(e->my_color, g_app.color, 3) != 0) chat_set_colour(e, g_app.color);
    }
}

static void routing_changed(setting_id_t id) {
    int later = 0, any = 0;
    if (!g_app.onboarding) {
        sync_update_proxy();
        tor_link_ensure(now_seconds());
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!takes_settings(i)) continue;
        later |= chat_apply_routing(&g_app.sessions[i].engine, &g_app.route);
        any = 1;
    }
    char v[160]; setting_value(id, v, sizeof v);
    const char *label = setting_def(id)->label;
    if (id == SET_ROUTING || tor_only_setting(id) || (later && !dht_routing_only_setting(id)))
        note("%s: %s - for sessions you open from now on%s", label, v, any ? "; open ones keep their routing" : "");
    else
        note("%s: %s%s", label, v, any ? " - applied to open sessions too" : "");
}

static void set_colour_all(void) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (takes_settings(i)) chat_set_colour(&g_app.sessions[i].engine, g_app.color);
}

// Sets a toggle or choice row to its i-th value, wherever it applies.
static void autosave_changed(void);
static void device_lock_choose(int on);
static void factor_choose(unsigned factor, int on);
static void destroy_choose(int limit);
static void begin_shadow(void);

// Security keys too.
static void device_check(void) {
    g_app.device_why[0] = g_app.seckey_why[0] = '\0';
    g_app.device_kind = platform_device_kind(g_app.device_why, sizeof g_app.device_why);
    g_app.seckey_ok = platform_seckey_usable(g_app.seckey_why, sizeof g_app.seckey_why) == 0;
}

static const char DEVICE_REMINDER[] =
    "* device lock: before you clear the TPM, update the firmware, replace the motherboard or reinstall the OS, "
    ":set devicelock off first, and lock it again after - or the save is gone for good";

static const char KEY_REMINDER[] =
    "* security key: if it's lost, broken or reset, the save is gone for good - :set securitykey off before you "
    "reset it or stop using it";

// Turning the lock off never needs the device, so a save locked to it, or a lock already chosen,
// stays usable. The same for a security key.
static int device_lock_greyed(void) { return g_app.device_kind == DEVICE_NONE && !g_app.device_lock; }
static int security_key_greyed(void) { return !g_app.seckey_ok && !g_app.key_factor; }
static int row_greyed(setting_id_t id) {
    return (id == SET_DEVICE_LOCK && device_lock_greyed()) || (id == SET_SECURITY_KEY && security_key_greyed());
}

static void setting_choose(setting_id_t id, int i) {
    routing_t *r = &g_app.route;
    switch (id) {
        case SET_ROUTING: r->mode = (route_mode_t)i; routing_changed(id); return;
        case SET_DHT4:    r->dht4 = i; routing_changed(id); return;
        case SET_DHT6:    r->dht6 = i; routing_changed(id); return;
        case SET_PORTMAP: r->portmap = i; routing_changed(id); return;
        case SET_LAN:     r->lan = i; routing_changed(id); return;
        case SET_NOSTR:   r->nostr = i; routing_changed(id); return;
        case SET_VERIFY:
            g_app.verify_optional = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) g_app.sessions[s].engine.verify_required = !i;
            break;
        case SET_TOR_LAUNCH:
            g_app.tor_launch = i;
            note("Start chat's own tor: %s - for the next tor chat looks for; a tor already in use stays",
                 TOR_LAUNCH_NAMES[i]);
            return;
        case SET_NOTIFY:
            g_app.notify_mode = (notify_mode_t)i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) g_app.sessions[s].engine.notify_mode = g_app.notify_mode;
            break;
        case SET_PREVIEW:
            g_app.notify_preview = (notify_preview_t)i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) g_app.sessions[s].engine.notify_preview = g_app.notify_preview;
            break;
        case SET_NET:
            g_app.net_verbose = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) g_app.sessions[s].engine.net_verbose = i;
            break;
        case SET_FAST_FILES:
            g_app.fast_files = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) chat_set_file_options(&g_app.sessions[s].engine, g_app.file_cap, i);
            break;
        case SET_AUTOSAVE:
            g_app.autosave = i;
            autosave_changed();
            break;
        case SET_DEVICE_LOCK: device_lock_choose(i); return;
        case SET_SECURITY_KEY: factor_choose(INSTALL_FACTOR_KEY, i); return;
        case SET_AUTHENTICATOR: factor_choose(INSTALL_FACTOR_CODE, i); return;
        case SET_DESTROY: destroy_choose(DESTROY_VALS[i]); return;
        default: return;
    }
    char v[32]; setting_value(id, v, sizeof v);
    note("%s: %s", setting_def(id)->label, v);
}

// h/l on a row: the next or previous value, wrapping around. The colour steps through the palette.
static void setting_step(setting_id_t id, int dir) {
    if (id == SET_COLOUR) {
        int cur = -1;
        for (int i = 0; i < COLOR_PALETTE_N; i++)
            if (COLOR_PALETTE[i].r == g_app.color[0] && COLOR_PALETTE[i].g == g_app.color[1] && COLOR_PALETTE[i].b == g_app.color[2]) cur = i;
        int next = cur < 0 ? 0 : (cur + (dir < 0 ? COLOR_PALETTE_N - 1 : 1)) % COLOR_PALETTE_N;
        g_app.color[0] = COLOR_PALETTE[next].r; g_app.color[1] = COLOR_PALETTE[next].g; g_app.color[2] = COLOR_PALETTE[next].b;
        set_colour_all();
        note("Colour: %s", COLOR_PALETTE[next].name);
        return;
    }
    const char *const *names;
    int n, cur = setting_options(id, &names, &n);
    if (cur >= 0) setting_choose(id, (cur + (dir < 0 ? n - 1 : 1)) % n);
}

static void begin_setting_edit(setting_id_t id) {
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_edit_id = id;
    // A secret starts empty, and what's typed replaces it.
    char v[1024];
    if (setting_text(id, v, sizeof v)) {
        copy_str(g_app.input.buf, v, sizeof g_app.input.buf);
        g_app.input.len = g_app.input.cursor = (int)strlen(g_app.input.buf);
    }
    g_app.mode = MODE_SETTINGS_EDIT;
    g_app.dirty = 1;
}

static void end_setting_edit(void) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = MODE_SETTINGS;
    g_app.dirty = 1;
}

static int valid_host_port(const char *s) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || !colon[1] || strlen(s) >= TOR_HOST_MAX) return 0;
    for (const char *p = colon + 1; *p; p++) if (*p < '0' || *p > '9') return 0;
    long port = strtol(colon + 1, NULL, 10);
    for (const char *p = s; p < colon; p++)
        if (!isalnum((unsigned char)*p) && !strchr(".-[]:", *p)) return 0;
    return port > 0 && port <= 65535;
}

// Sets a text row from what was typed for it, on the page or after :set NAME.
static void setting_apply_text(setting_id_t id, const char *typed) {
    char text[sizeof g_app.input.buf];
    copy_str(text, typed, sizeof text);
    routing_t *r = &g_app.route;
    switch (id) {
        case SET_RELAYS: {
            char urls[NOSTR_MAX_RELAYS][NOSTR_URL_MAX];
            int n = 0;
            for (char *tok = strtok(text, " ,"); tok; tok = strtok(NULL, " ,")) {
                if (nostr_url_ok(tok) != 0) { note("not a relay chat can use: %.80s (wss://host[:port][/path])", tok); return; }
                if (n >= NOSTR_MAX_RELAYS) { note("at most %d relays", NOSTR_MAX_RELAYS); return; }
                copy_str(urls[n++], tok, NOSTR_URL_MAX);
            }
            memcpy(r->relays, urls, sizeof urls);
            r->n_relays = n;
            routing_changed(id);
            return;
        }
        case SET_TOR_SOCKS:
        case SET_TOR_CONTROL:
            if (!valid_host_port(text)) { note("that isn't host:port"); return; }
            copy_str(id == SET_TOR_SOCKS ? r->tor.socks : r->tor.control, text, TOR_HOST_MAX);
            routing_changed(id);
            return;
        case SET_TOR_PATH: {
            char found[1024];
            if (text[0] && platform_find_program("tor", text, found, sizeof found) != 0) {
                note("can't use %.100s - it has to be a full path to a program only root or you can change", text);
                return;
            }
            copy_str(g_app.tor_path, text[0] ? found : "", sizeof g_app.tor_path);
            note("Tor program: %s", g_app.tor_path[0] ? g_app.tor_path : "search PATH and the usual folders");
            return;
        }
        case SET_FILE_LIMIT: {
            uint64_t v;
            if (file_parse_size(text, &v) != 0 || v == 0 || v > FILE_HARD_MAX) { note("that isn't a size from 1 byte to 1 GB (8M, 500K, 1G)"); return; }
            g_app.file_cap = v;
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (takes_settings(i)) chat_set_file_options(&g_app.sessions[i].engine, v, g_app.fast_files);
            char sz[32]; file_format_size(v, sz, sizeof sz);
            note("File size limit: %s - for open sessions too", sz);
            return;
        }
        case SET_TOR_PASSWORD:
            copy_str(r->tor.password, text, sizeof r->tor.password);
            crypto_wipe(text, sizeof text);
            routing_changed(id);
            return;
        case SET_NICK:
            if (!text[0]) return;
            chat_clean_nick(text, g_app.nick);
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (takes_settings(i)) chat_set_nick(&g_app.sessions[i].engine, g_app.nick);
            note("Nickname: %s", g_app.nick);
            return;
        case SET_COLOUR: {
            uint8_t rgb[3];
            if (parse_color(text, rgb) != 0) { note("unknown colour %.40s - try a name or #RRGGBB", text); return; }
            memcpy(g_app.color, rgb, 3);
            set_colour_all();
            note("Colour: #%02x%02x%02x", rgb[0], rgb[1], rgb[2]);
            return;
        }
        case SET_PORT: {
            char *end;
            long port = strtol(text, &end, 10);
            if (!text[0] || *end || port < 0 || port > 65535) { note("not a port: %.20s (0-65535, 0 picks a free one)", text); return; }
            g_app.default_port = (uint16_t)port;
            note("UDP port for new sessions: %ld%s", port, port ? "" : " (a free one)");
            return;
        }
        default:
            return;
    }
}

static void commit_setting_edit(void) {
    char text[sizeof g_app.input.buf];
    copy_str(text, g_app.input.buf, sizeof text);
    setting_id_t id = g_edit_id;
    end_setting_edit();
    setting_apply_text(id, text);
    crypto_wipe(text, sizeof text);
}

// The page shows one section at a time, its listed rows and then a Done button.
#define SETTINGS_DONE N_SETTINGS   // settings_sel of the Done button, on g_app.settings_page

// The settings' sections, for the list on the left of the pages.
static int settings_sections(const char **out, int cap) {
    int n = 0;
    for (int i = 0; i < N_SETTINGS && n < cap; i++) if (SETTINGS[i].section) out[n++] = SETTINGS[i].section;
    return n;
}

static int settings_section_index(setting_id_t id) {
    int n = -1;
    for (int i = 0; i < N_SETTINGS; i++) {
        if (SETTINGS[i].section) n++;
        if (SETTINGS[i].id == id) return n;
    }
    return n;
}

// Section s's first row, or N_SETTINGS after the last section.
static int section_begin(int s) {
    for (int i = 0, n = 0; i < N_SETTINGS; i++)
        if (SETTINGS[i].section && n++ == s) return i;
    return N_SETTINGS;
}

// Section s's first listed row, or its last for dir < 0, or the Done button if none is listed.
static int section_row(int s, int dir) {
    int a = section_begin(s), b = section_begin(s + 1);
    for (int i = dir > 0 ? a : b - 1; i >= a && i < b; i += dir)
        if (setting_shown(SETTINGS[i].id)) return i;
    return SETTINGS_DONE;
}

static int settings_n_sections(void) {
    int n = 0;
    while (section_begin(n) < N_SETTINGS) n++;
    return n;
}

static void settings_select(int sel) {
    g_app.settings_sel = sel;
    if (sel >= N_SETTINGS) return;
    g_app.settings_page = settings_section_index(SETTINGS[sel].id);
    g_app.settings_rows[g_app.settings_page] = sel;
}

// Section s, on the row selected there last if it's still listed, otherwise its first.
static void settings_go_section(int s) {
    int i = g_app.settings_rows[s];
    if (i < section_begin(s) || i >= section_begin(s + 1) || !setting_shown(SETTINGS[i].id)) i = section_row(s, 1);
    g_app.settings_page = s;
    settings_select(i);
}

// j/k go through the sections in turn, each one's listed rows and then its Done button.
static void settings_step(int dir) {
    int sel = g_app.settings_sel, s = g_app.settings_page;
    int a = section_begin(s), b = section_begin(s + 1);
    if (sel == SETTINGS_DONE) {
        if (dir < 0) settings_select(section_row(s, -1));
        else if (b < N_SETTINGS) settings_select(section_row(s + 1, 1));
        return;
    }
    for (int i = sel + dir; i >= a && i < b; i += dir)
        if (setting_shown(SETTINGS[i].id)) { settings_select(i); return; }
    if (dir < 0 && s == 0) return;
    if (dir < 0) g_app.settings_page = s - 1;
    g_app.settings_sel = SETTINGS_DONE;
}

// Moves the selection off a row that stopped being listed, to the next one up in its section, or
// down.
static void settings_fix_sel(void) {
    int sel = g_app.settings_sel;
    if (sel >= N_SETTINGS || setting_shown(SETTINGS[sel].id)) return;
    int s = settings_section_index(SETTINGS[sel].id), a = section_begin(s), b = section_begin(s + 1), i = sel - 1;
    while (i >= a && !setting_shown(SETTINGS[i].id)) i--;
    if (i < a) for (i = sel + 1; i < b && !setting_shown(SETTINGS[i].id); i++) {}
    settings_select(i >= a && i < b ? i : SETTINGS_DONE);
}

// Tab and Shift+Tab: the next or previous section, round from the last to the first.
static void settings_section_step(int dir) {
    int n = settings_n_sections();
    settings_go_section((g_app.settings_page + dir + n) % n);
}

static void begin_settings(void) {
    if (g_app.mode != MODE_CHAT) return;
    device_check();
    g_app.mode = MODE_SETTINGS;
    if (g_app.settings_sel == SETTINGS_DONE) settings_go_section(g_app.settings_page);
    settings_fix_sel();
    g_app.dirty = 1;
}

// Opens the page on a row, or says why the row isn't on it right now.
static void settings_open_at(setting_id_t id) {
    begin_settings();
    if (setting_shown(id)) settings_select(settings_index(id));
    else note("%s isn't on the page right now: %s", setting_def(id)->label, setting_hidden_why(id));
}

// The Done button. Esc, q and Ctrl+S do the same. On the startup settings page, this is where chat
// starts. Until then nothing goes on the network, not even a tor or a --peer name lookup.
static void settings_done(void) {
    g_app.mode = MODE_CHAT;
    if (g_app.onboarding) {
        g_app.onboarding = 0;
        push_log("* routing: %s", route_label());
        sync_update_proxy();
        tor_link_ensure(now_seconds());
        finish_onboarding();
    }
    g_app.dirty = 1;
}

// What the keys do on the selected row, with the main action first.
static const char *settings_hint(void) {
    const setting_def_t *d = g_app.settings_sel < N_SETTINGS ? &SETTINGS[g_app.settings_sel] : NULL;
    const char *act;
    if (!d) act = g_app.onboarding ? "enter start" : "enter done";
    else if (d->id == SET_COLOUR) act = "h/l step \xc2\xb7 enter type one";
    else if (d->kind == K_TEXT || d->kind == K_SECRET) act = "enter edit";
    else if (d->id == SET_SIGN) act = "enter choose";
    else if (d->id == SET_SHADOW) act = "enter set";
    else if (d->id == SET_AGE_RECIPIENT || d->id == SET_PGP_PUBKEY) act = "enter copy";
    else if (row_greyed(d->id)) act = NULL;
    else act = "h/l change";
    static char hint[160];
    snprintf(hint, sizeof hint, "%s%sj/k move \xc2\xb7 tab/1-%d section \xc2\xb7 esc %s", act ? act : "",
             act ? " \xc2\xb7 " : "", settings_n_sections(), g_app.onboarding ? "start" : "done");
    return hint;
}

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

static const struct { const char *section, *label, *help; } SIGN_PICKS[N_PICKS] = {
    { NULL, "Off", "Don't sign. Peers see you as unverified." },
    { "AGE", "Native", "A key made here, with an age1... recipient others can encrypt files to you with "
                       "(age -r). Enter asks for a password: the same password on this device and OS always makes "
                       "the same key, so always use the same one to keep an established signing identity. Blank "
                       "makes a new key that lasts until chat exits." },
    { NULL, "Pick a key file", "Your own AGE key, picked in a file browser: the file age-keygen writes. "
                               WHY_SECRET "It stays in memory and isn't sent. :install saves the file's path, not "
                               "the key." },
    { NULL, "Type a key file path", "Your own AGE key from a file whose path you type, such as "
                                    "~/.config/age/key.txt. " WHY_SECRET ":install saves the path, not the key." },
    { NULL, "Paste a key", "Your own AGE key pasted in: the AGE-SECRET-KEY-1... line. " WHY_SECRET "There's no "
                           "file to point to, so :install seals the key itself to disk." },
    { "PGP", "Native", "A PGP key made here, whose public key is in the settings and the console for others "
                       "to import. Enter asks for a password: the same password on this device and OS always makes "
                       "the same key, so always use the same one to keep an established signing identity. Blank "
                       "makes a new key that lasts until chat exits." },
    { NULL, "Pick a key file", "Your own key, picked in a file browser: an unencrypted EdDSA/Ed25519 secret key, "
                               "armored, as gpg --export-secret-keys --armor writes it. " WHY_SECRET ":install "
                               "saves the file's path, not the key." },
    { NULL, "Type a key file path", "Your own key from a file whose path you type: an unencrypted, armored "
                                    "EdDSA/Ed25519 secret key. " WHY_SECRET ":install saves the path, not the key." },
    { NULL, "Paste a key", "Your own key pasted in, armored. " WHY_SECRET "There's no file to point to, so "
                           ":install seals the key itself to disk." },
};

// Why chat asks for your secret key, and what happens to it, for the pages that take one.
static const char KEY_WHY[] =
    "**Why the secret key:** chat signs the handshake of every session you join, so peers can check it's "
    "you. Only the secret key can make a signature; the public key can only check one. The key is kept in "
    "memory and never sent: peers get your public key and the signatures.";

static const char KEY_FILE_SAVED[] =
    "**What :install keeps:** this file's path, not the key. chat reads the file again each time it starts, "
    "so leave it where it is.";

static const char KEY_PASTE_SAVED[] =
    "**What :install keeps:** with no file to point to, the key itself, sealed with your passphrase. Until "
    "then it's only in memory. To keep it out of chat's files, save it to a file and pick that instead.";

static const char AGE_PASTE_HELP[] =
    "Paste your AGE secret key now: the AGE-SECRET-KEY-1... line, or the whole file age-keygen wrote. It's read "
    "when its line ends (Enter, if the paste didn't end it).";

static const char PGP_PASTE_HELP[] =
    "Paste your armored PGP private key now, BEGIN line to END line. It's read as soon as the END line "
    "arrives. It has to be an unencrypted EdDSA/Ed25519 key (gpg --export-secret-keys --armor, from a key "
    "with no passphrase).";

static const char AGE_PATH_HELP[] =
    "Type the path to your AGE key file, as age-keygen writes it. ~ is your home folder.";

static const char PGP_PATH_HELP[] =
    "Type the path to your PGP key file: an unencrypted, armored EdDSA/Ed25519 secret key, as gpg "
    "--export-secret-keys --armor writes it from a key with no passphrase. ~ is your home folder.";

static const char SIGN_PASSWORD_HELP[] =
    "Type the password to make your key from. The same password on this device and OS always makes the same "
    "key and fingerprint, so always use the same password to keep an established signing identity: a different "
    "one, or a typo, makes a different key. Make it long, since anyone who learns this device's id can guess at "
    "it. Blank makes a new key that lasts until chat exits. Nothing is written to disk unless you :install.";

static int sign_row_in_use(void) {
    int age = g_app.identity_source == IDENT_AGE;
    if (!age && g_app.identity_source != IDENT_PGP) return PICK_OFF;
    switch (g_app.key_origin) {
        case KEY_FILE:   return age ? PICK_AGE_FILE : PICK_PGP_FILE;
        case KEY_PASTED: return age ? PICK_AGE_PASTE : PICK_PGP_PASTE;
        default:         return age ? PICK_AGE_MADE : PICK_PGP_MADE;
    }
}

// Opens the picker from the Signing identity row, on the choice in use.
static void begin_sign(void) {
    g_app.sign_sel = sign_row_in_use();
    g_app.mode = MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

static int key_in_use_saved(void);

// Passes the identity just chosen to every open session.
static void say_key_saved_state(void);

static void identity_chosen(void) {
    int any = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_set_identity(&g_app.sessions[i].engine, g_app.identity_source, &g_app.identity);
        any = 1;
    }
    show_identity_result();
    say_key_saved_state();
    char v[160]; setting_value(SET_SIGN, v, sizeof v);
    note("Signing identity: %s%s", v, any ? " - applied to open sessions too" : "");
}

// Whether the key in use is the one saved, once a save is open.
static void say_key_saved_state(void) {
    if (g_app.installed && g_app.identity_source != IDENT_NONE && !key_in_use_saved())
        push_log("* this signing key isn't saved: :save %s with your settings' passphrase%s",
                 g_app.key_origin == KEY_FILE && g_app.key_path[0] ? "saves its file's path, sealed" : "seals it",
                 install_has_key(install_current()) ? ", in place of the saved one" : "");
    else if (g_app.installed && g_app.identity_source == IDENT_NONE && install_has_key(install_current()))
        push_log("* the saved signing key stays saved, and signs again the next time chat starts");
}

// A key of kind (AGE or PGP) made here: from password and this device's id, the same every time,
// or a new random one if password is empty. Returns NULL once it's the identity in use, otherwise
// the reason it isn't, and the current identity stays.
static const char *make_identity(identity_source_t kind, const char *password) {
    if (!password[0]) {
        gen_identity_keypair(&g_app.identity);
        g_app.key_origin = KEY_MADE;
        g_app.pgp_created = (uint32_t)time(NULL);
    } else {
        char device[128];
        if (platform_machine_id(device, sizeof device) != 0)
            return "this system has no machine id to make the key with - leave the password blank for a new key";
        if (identity_from_password(password, device, &g_app.identity) != 0)
            return "couldn't make the key - it needs 512 MiB of free memory for a moment";
        g_app.key_origin = KEY_DERIVED;
        g_app.pgp_created = DERIVED_PGP_CREATED;
    }
    g_app.identity_source = kind;
    return NULL;
}

// The password a native key is made from, typed on the bottom bar with the picker still up.
static void begin_sign_password(identity_source_t kind) {
    g_app.load_kind = kind;
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_app.mode = MODE_SIGN_PASSWORD;
    g_app.dirty = 1;
}

static void end_sign_password(void) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

static void commit_sign_password(void) {
    char pw[sizeof g_app.input.buf];
    copy_str(pw, g_app.input.buf, sizeof pw);
    end_sign_password();
    if (pw[0]) {
        // Argon2id takes a few seconds, so say so before the screen freezes.
        note("making your key from the password...");
        render();
    }
    const char *why = make_identity(g_app.load_kind, pw);
    crypto_wipe(pw, sizeof pw);
    if (why) { note("%s", why); return; }
    identity_chosen();
    g_app.mode = MODE_SETTINGS;
}

// A typed path with a leading ~ (alone, or followed by /) as the home folder.
static void expand_home(const char *path, char *out, size_t cap) {
    const char *home = platform_home_dir();
    if (home && path[0] == '~' && (path[1] == '\0' || path[1] == '/')) snprintf(out, cap, "%s%s", home, path + 1);
    else copy_str(out, path, cap);
}

// path with the home folder as ~, to show.
static void tilde_path(const char *path, char *out, size_t cap) {
    const char *home = platform_home_dir();
    size_t hl = home ? strlen(home) : 0;
    if (hl > 1 && strncmp(path, home, hl) == 0 && (path[hl] == '/' || path[hl] == '\0'))
        snprintf(out, cap, "~%s", path + hl);
    else copy_str(out, path, cap);
}

// kind's key (AGE or PGP) from the file at path, into kp. Its full path goes in full, for :install to
// save. Returns 0, or -1 if the file isn't such a key.
static int read_key_file(identity_source_t kind, const char *path, identity_keypair_t *kp, char *full, size_t cap) {
    char p[KEY_PATH_MAX];
    expand_home(path, p, sizeof p);
    int rc = kind == IDENT_AGE ? age_import_secret_key(p, kp) : pgp_import_secret_key(p, kp);
    if (rc != 0) return -1;
    if (platform_full_path(p, full, cap) != 0) copy_str(full, p, cap);
    return 0;
}

// kind's key (AGE or PGP) from the file at path. Returns 0 once it's the identity in use.
static int load_key_file(identity_source_t kind, const char *path) {
    identity_keypair_t kp;
    char full[KEY_PATH_MAX];
    int rc = read_key_file(kind, path, &kp, full, sizeof full);
    if (rc == 0) {
        g_app.identity = kp;
        g_app.identity_source = kind;
        g_app.key_origin = KEY_FILE;
        copy_str(g_app.key_path, full, sizeof g_app.key_path);
    }
    crypto_wipe(&kp, sizeof kp);
    return rc;
}

// The key file in use, if it's kind's, for the browser and the path field to start at.
static const char *key_path_of(identity_source_t kind) {
    return g_app.key_origin == KEY_FILE && g_app.identity_source == kind && g_app.key_path[0] ? g_app.key_path : NULL;
}

static void browser_select(browser_t *b, const char *name);

// Opens in the folder of the key file in use, if there is one, otherwise the home folder.
static void begin_key_browse(identity_source_t kind) {
    g_app.load_kind = kind;
    const char *home = platform_home_dir();
    char dir[KEY_PATH_MAX] = "", name[200] = "";
    if (key_path_of(kind)) {
        copy_str(dir, g_app.key_path, sizeof dir);
        const char *slash = strrchr(g_app.key_path, '/');
        if (slash) copy_str(name, slash + 1, sizeof name);
        path_parent(dir);
    }
    if (dir[0] && browser_load(&g_app.browser, dir) == 0) browser_select(&g_app.browser, name);
    else if (!home || browser_load(&g_app.browser, home) != 0) browser_load(&g_app.browser, "/");
    g_app.mode = MODE_SIGN_BROWSE;
    g_app.dirty = 1;
}

// The field for a key file's path, on the picker or the browser, starting with start (or empty).
static void begin_key_path(identity_source_t kind, const char *start, int from_browser) {
    g_app.load_kind = kind;
    g_app.path_from_browser = from_browser;
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    if (start) {
        char shown[sizeof g_app.input.buf];
        tilde_path(start, shown, sizeof shown);
        copy_str(g_app.input.buf, shown, sizeof g_app.input.buf);
        g_app.input.len = g_app.input.cursor = (int)strlen(g_app.input.buf);
    }
    g_app.mode = MODE_SIGN_PATH;
    g_app.dirty = 1;
}

static void end_key_path(void) {
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = g_app.path_from_browser ? MODE_SIGN_BROWSE : MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

// A path that isn't a key stays in the field to be fixed.
static void commit_key_path(void) {
    char path[sizeof g_app.input.buf];
    copy_str(path, g_app.input.buf, sizeof path);
    if (!path[0]) { note("type the key file's path - or Esc to go back"); return; }
    if (load_key_file(g_app.load_kind, path) != 0) {
        if (g_app.load_kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", path);
        else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", path);
        return;
    }
    end_key_path();
    identity_chosen();
    g_app.mode = MODE_SETTINGS;
}

static void paste_clear(void) {
    crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
    g_app.paste_len = 0;
    copy_str(g_app.paste_status, "waiting for the paste", sizeof g_app.paste_status);
}

static void begin_key_paste(identity_source_t kind) {
    g_app.load_kind = kind;
    paste_clear();
    g_app.mode = MODE_SIGN_PASTE;
    g_app.dirty = 1;
}

// Loads the key file picked in the browser. Returns 0 once it's the identity in use.
static int try_load_key_from_browser(void) {
    const dir_entry_t *sel = &g_app.browser.items[g_app.browser.selected];
    char full[1200]; browser_entry_path(&g_app.browser, sel, full, sizeof full);
    if (load_key_file(g_app.load_kind, full) != 0) {
        if (g_app.load_kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", sel->name);
        else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", sel->name);
        return -1;
    }
    identity_chosen();
    return 0;
}

// Off takes effect immediately. A key made here asks for its password first, and a key file or
// paste opens its own page.
static void sign_pick(int pick) {
    switch (pick) {
        case PICK_OFF:
            g_app.identity_source = IDENT_NONE;
            crypto_wipe(&g_app.identity, sizeof g_app.identity);
            identity_chosen();
            return;
        case PICK_AGE_MADE:  begin_sign_password(IDENT_AGE); return;
        case PICK_PGP_MADE:  begin_sign_password(IDENT_PGP); return;
        case PICK_AGE_FILE:  begin_key_browse(IDENT_AGE); return;
        case PICK_AGE_PATH:  begin_key_path(IDENT_AGE, key_path_of(IDENT_AGE), 0); return;
        case PICK_AGE_PASTE: begin_key_paste(IDENT_AGE); return;
        case PICK_PGP_FILE:  begin_key_browse(IDENT_PGP); return;
        case PICK_PGP_PATH:  begin_key_path(IDENT_PGP, key_path_of(IDENT_PGP), 0); return;
        case PICK_PGP_PASTE: begin_key_paste(IDENT_PGP); return;
        default: return;
    }
}

static void copy_age_recipient(void) {
    if (g_app.identity_source != IDENT_AGE) return;
    char recipient[AGE_RECIPIENT_STRLEN + 1];
    age_export_recipient(&g_app.identity, recipient);
    osc52_copy(recipient);
    note("AGE recipient copied to the clipboard (OSC 52)");
}

static void copy_pgp_public_key(void) {
    if (!pgp_key_made_here()) return;
    char armor[PGP_ARMOR_MAX]; uint8_t fp[PGP_FP_LEN];
    pgp_public_key(armor, fp);
    osc52_copy(armor);
    note("PGP public key copied to the clipboard (OSC 52)");
}

// ---- keys on the list pages ----

typedef enum {
    LIST_NONE, LIST_UP, LIST_DOWN, LIST_FIRST, LIST_LAST, LIST_CHOOSE, LIST_LEFT, LIST_RIGHT, LIST_BACK, LIST_CLOSE,
    LIST_NEXT_SECTION, LIST_PREV_SECTION
} list_key_t;

// The keys every list page shares: j/k or up/down move, g/G or Home/End go to the ends,
// Tab/Shift+Tab or PgDn/PgUp go to the next or previous section, Enter or space chooses, h/l or
// left/right go sideways (Backspace too, like vim's h), Esc goes back a level, and q or Ctrl+S
// closes the page.
static list_key_t list_key(const tui_key_t *key) {
    switch (key->type) {
        case TUI_KEY_UP:        return LIST_UP;
        case TUI_KEY_DOWN:      return LIST_DOWN;
        case TUI_KEY_HOME:      return LIST_FIRST;
        case TUI_KEY_END:       return LIST_LAST;
        case TUI_KEY_TAB:
        case TUI_KEY_PAGE_DOWN: return LIST_NEXT_SECTION;
        case TUI_KEY_BACKTAB:
        case TUI_KEY_PAGE_UP:   return LIST_PREV_SECTION;
        case TUI_KEY_ENTER:     return LIST_CHOOSE;
        case TUI_KEY_LEFT:
        case TUI_KEY_BACKSPACE: return LIST_LEFT;
        case TUI_KEY_RIGHT:     return LIST_RIGHT;
        case TUI_KEY_ESCAPE:    return LIST_BACK;
        case TUI_KEY_SETTINGS:  return LIST_CLOSE;
        case TUI_KEY_CHAR:      break;
        default:                return LIST_NONE;
    }
    if (key->ch_len != 1) return LIST_NONE;
    switch (key->ch[0]) {
        case 'k': return LIST_UP;
        case 'j': return LIST_DOWN;
        case 'g': return LIST_FIRST;
        case 'G': return LIST_LAST;
        case ' ': return LIST_CHOOSE;
        case 'h': return LIST_LEFT;
        case 'l': return LIST_RIGHT;
        case 'q': return LIST_CLOSE;
        default:  return LIST_NONE;
    }
}

// 1 to 9 on a page with sections: the section, from 0, or -1 for any other key.
static int section_digit(const tui_key_t *key) {
    if (key->type != TUI_KEY_CHAR || key->ch_len != 1 || key->ch[0] < '1' || key->ch[0] > '9') return -1;
    return key->ch[0] - '1';
}

static void list_move(list_key_t k, int *sel, int n) {
    if (k == LIST_UP && *sel > 0) (*sel)--;
    else if (k == LIST_DOWN && *sel < n - 1) (*sel)++;
    else if (k == LIST_FIRST) *sel = 0;
    else if (k == LIST_LAST) *sel = n > 0 ? n - 1 : 0;
}

// Left/right on a row changes its value. On the Signing identity row, right opens the picker.
static void settings_key(const tui_key_t *key) {
    const setting_def_t *d = g_app.settings_sel < N_SETTINGS ? &SETTINGS[g_app.settings_sel] : NULL;
    const char *const *names;
    int n;
    int steps = d && (setting_options(d->id, &names, &n) >= 0 || d->id == SET_COLOUR);
    int s = section_digit(key);
    if (s >= 0 && s < settings_n_sections()) settings_go_section(s);
    if (s >= 0) { g_app.dirty = 1; return; }
    switch (list_key(key)) {
        case LIST_UP:    settings_step(-1); break;
        case LIST_DOWN:  settings_step(1); break;
        case LIST_FIRST: settings_select(section_row(g_app.settings_page, 1)); break;
        case LIST_LAST:  g_app.settings_sel = SETTINGS_DONE; break;
        case LIST_NEXT_SECTION: settings_section_step(1); break;
        case LIST_PREV_SECTION: settings_section_step(-1); break;
        case LIST_LEFT:  if (steps) setting_step(d->id, -1); break;
        case LIST_RIGHT:
            if (steps) setting_step(d->id, 1);
            else if (d && d->id == SET_SIGN) begin_sign();
            else if (d && d->id == SET_SHADOW) begin_shadow();
            break;
        case LIST_CHOOSE:
            if (!d) settings_done();
            else if (steps && d->id != SET_COLOUR) setting_step(d->id, 1);
            else if (d->kind == K_TEXT || d->kind == K_SECRET) begin_setting_edit(d->id);
            else if (d->id == SET_SIGN) begin_sign();
            else if (d->id == SET_SHADOW) begin_shadow();
            else if (d->id == SET_AGE_RECIPIENT) copy_age_recipient();
            else if (d->id == SET_PGP_PUBKEY) copy_pgp_public_key();
            break;
        case LIST_BACK:
        case LIST_CLOSE: settings_done(); break;
        default: break;
    }
    settings_fix_sel();
    g_app.dirty = 1;
}

static void sign_picker_key(const tui_key_t *key) {
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT:
            sign_pick(g_app.sign_sel);
            if (g_app.mode == MODE_SIGN_CHOICE) g_app.mode = MODE_SETTINGS;
            break;
        case LIST_LEFT:
        case LIST_BACK:  g_app.mode = MODE_SETTINGS; break;
        case LIST_CLOSE: settings_done(); break;
        default: list_move(k, &g_app.sign_sel, N_PICKS); break;
    }
    g_app.dirty = 1;
}

// Up to the parent folder, with the folder just left selected.
static void browser_up(void) {
    char up[900], name[200] = "";
    copy_str(up, g_app.browser.path, sizeof up);
    size_t n = strlen(up);
    while (n > 1 && up[n - 1] == '/') up[--n] = '\0';
    const char *slash = strrchr(up, '/');
    if (slash) copy_str(name, slash + 1, sizeof name);
    path_parent(up);
    if (browser_load(&g_app.browser, up) == 0) browser_select(&g_app.browser, name);
}

static void browser_home(void) {
    const char *home = platform_home_dir();
    if (home) browser_load(&g_app.browser, home);
}

// Besides the list keys: / types a path instead, starting with the file selected or the folder
// shown, and ~ goes to the home folder.
static void browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && (key->ch[0] == '/' || key->ch[0] == '~')) {
        if (key->ch[0] == '~') { browser_home(); g_app.dirty = 1; return; }
        char start[1200];
        if (b->n_items > 0 && !b->items[b->selected].is_dir) browser_entry_path(b, &b->items[b->selected], start, sizeof start);
        else path_join(start, sizeof start, b->path, "");
        begin_key_path(g_app.load_kind, start, 1);
        return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_LEFT: browser_up(); break;
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            if (b->n_items == 0) break;
            const dir_entry_t *sel = &b->items[b->selected];
            if (sel->is_dir) {
                char next[1200]; browser_entry_path(b, sel, next, sizeof next);
                browser_load(b, next);
            } else if (try_load_key_from_browser() == 0) {
                g_app.mode = MODE_SETTINGS;
            }
            break;
        }
        case LIST_BACK:  g_app.mode = MODE_SIGN_CHOICE; break;
        case LIST_CLOSE: settings_done(); break;
        default: list_move(k, &b->selected, b->n_items); break;
    }
    g_app.dirty = 1;
}

// :send without a path: the file is picked here, starting where the last one came from.
static void begin_send_browse(void) {
    if (g_app.mode != MODE_CHAT && g_app.mode != MODE_FILES) return;
    const char *home = platform_home_dir();
    if ((!g_app.send_dir[0] || browser_load(&g_app.browser, g_app.send_dir) != 0)
        && (!home || browser_load(&g_app.browser, home) != 0))
        browser_load(&g_app.browser, "/");
    g_app.browse_back = g_app.mode;
    g_app.mode = MODE_SEND_BROWSE;
    g_app.dirty = 1;
}

static void send_browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && key->ch[0] == '~') { browser_home(); g_app.dirty = 1; return; }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_LEFT: browser_up(); break;
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            if (b->n_items == 0) break;
            const dir_entry_t *sel = &b->items[b->selected];
            char full[1200]; browser_entry_path(b, sel, full, sizeof full);
            if (sel->is_dir) {
                browser_load(b, full);
            } else if (k == LIST_CHOOSE) {
                g_app.mode = g_app.browse_back;
                if (!g_app.selected || g_app.selected->initialising) {
                    note("no session to send %.80s to", sel->name);
                    break;
                }
                copy_str(g_app.send_dir, b->path, sizeof g_app.send_dir);
                chat_t *e = &g_app.selected->engine;
                int was = e->file_seq;
                g_echo = 1;
                chat_send_file(e, full);
                g_echo = 0;
                if (e->file_seq != was) g_app.file_num = e->file_seq;
            }
            break;
        }
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = g_app.browse_back; break;
        default: list_move(k, &b->selected, b->n_items); break;
    }
    g_app.dirty = 1;
}

// :saveto N: the folder to save file N in is picked here, starting where the last one went, or in
// Downloads.
static void begin_save_browse(int num, int anyway) {
    if (g_app.mode != MODE_CHAT && g_app.mode != MODE_FILES && g_app.mode != MODE_FILE_VIEW) return;
    char dl[600];
    const char *home = platform_home_dir();
    if ((!g_app.save_dir[0] || browser_load(&g_app.browser, g_app.save_dir) != 0)
        && (platform_downloads_dir(dl, sizeof dl) != 0 || browser_load(&g_app.browser, dl) != 0)
        && (!home || browser_load(&g_app.browser, home) != 0))
        browser_load(&g_app.browser, "/");
    g_app.save_num = num;
    g_app.save_anyway = anyway;
    g_app.browse_back = g_app.mode;
    g_app.mode = MODE_SAVE_BROWSE;
    g_app.dirty = 1;
}

// Enter opens the selected folder and s saves in the one shown.
static void save_browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && key->ch[0] == '~') { browser_home(); g_app.dirty = 1; return; }
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && key->ch[0] == 's') {
        g_app.mode = g_app.browse_back;
        g_app.dirty = 1;
        if (!g_app.selected || g_app.selected->initialising) { note("no session to save file %d from", g_app.save_num); return; }
        copy_str(g_app.save_dir, b->path, sizeof g_app.save_dir);
        g_echo = 1;
        chat_file_fetch(&g_app.selected->engine, g_app.save_num, 0, g_app.save_anyway, b->path);
        g_echo = 0;
        return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_LEFT: browser_up(); break;
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            if (b->n_items == 0) break;
            const dir_entry_t *sel = &b->items[b->selected];
            if (!sel->is_dir) break;
            char full[1200]; browser_entry_path(b, sel, full, sizeof full);
            browser_load(b, full);
            break;
        }
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = g_app.browse_back; break;
        default: list_move(k, &b->selected, b->n_items); break;
    }
    g_app.dirty = 1;
}

// Everything except Esc is the paste arriving, one key at a time.
static void paste_key(const tui_key_t *key) {
    if (key->type == TUI_KEY_ESCAPE) {
        paste_clear();
        g_app.mode = MODE_SIGN_CHOICE;
        g_app.dirty = 1;
        return;
    }
    size_t room = sizeof g_app.paste_buf - 1 - g_app.paste_len;
    if (key->type == TUI_KEY_CHAR && room >= (size_t)key->ch_len) {
        memcpy(g_app.paste_buf + g_app.paste_len, key->ch, (size_t)key->ch_len);
        g_app.paste_len += (size_t)key->ch_len;
    } else if ((key->type == TUI_KEY_ENTER || key->type == TUI_KEY_JOIN_SESSION) && room >= 1) {
        g_app.paste_buf[g_app.paste_len++] = '\n';
    } else if (key->type == TUI_KEY_BACKSPACE && g_app.paste_len > 0) {
        g_app.paste_len--;
    } else {
        return;
    }
    g_app.paste_buf[g_app.paste_len] = '\0';
    snprintf(g_app.paste_status, sizeof g_app.paste_status, "%zu bytes so far", g_app.paste_len);
    g_app.dirty = 1;
    int age = g_app.load_kind == IDENT_AGE;
    if (age) {
        // Read when the key's last line ends, so a pasted file's own newline doesn't end up on the settings page.
        const char *at = strstr(g_app.paste_buf, "AGE-SECRET-KEY-1");
        if (!at || g_app.paste_buf[g_app.paste_len - 1] != '\n'
            || g_app.paste_len - 1 - (size_t)(at - g_app.paste_buf) < AGE_SECRET_KEY_STRLEN) return;
    } else {
        // Only look at the end, where the END line will be.
        static const char end_line[] = "-----END PGP PRIVATE KEY BLOCK-----";
        size_t el = sizeof end_line - 1;
        if (g_app.paste_len < el || memcmp(g_app.paste_buf + g_app.paste_len - el, end_line, el) != 0) return;
    }
    int rc = age ? age_import_secret_key_text(g_app.paste_buf, &g_app.identity)
                 : pgp_import_secret_key_text(g_app.paste_buf, &g_app.identity);
    paste_clear();
    if (rc == 0) {
        g_app.identity_source = g_app.load_kind;
        g_app.key_origin = KEY_PASTED;
        identity_chosen();
        g_app.mode = MODE_SETTINGS;
    } else if (age) {
        note("that isn't an AGE secret key - paste another, or Esc");
    } else {
        note("that isn't an unencrypted EdDSA/Ed25519 secret key - paste another, or Esc");
    }
}

// ---- drawing the pages ----

#define CRUMB " \xe2\x80\xba "   // between the levels of a page's title

// Under its group's heading, a label doesn't repeat it: "Tor SOCKS port" under Tor is "SOCKS port".
static const char *page_label(const char *label, const char *group, char *out, size_t cap) {
    size_t n = group ? strlen(group) : 0;
    if (!n || strncmp(label, group, n) != 0 || label[n] != ' ') return label;
    copy_str(out, label + n + 1, cap);
    out[0] = (char)toupper((unsigned char)out[0]);
    return out;
}

static void render_settings(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    tui_row_t rows[N_SETTINGS];
    char values[N_SETTINGS][160], labels[N_SETTINGS][64];
    int n_rows = 0, sel_row = -1, s = g_app.settings_page, end = section_begin(s + 1);
    const char *group = NULL, *heading = NULL;
    for (int i = section_begin(s); i < end; i++) {
        const setting_def_t *d = &SETTINGS[i];
        if (d->group) group = heading = d->group;   // the heading goes on its group's first listed row
        if (!setting_shown(d->id)) continue;
        if (i == g_app.settings_sel) sel_row = n_rows;
        setting_value(d->id, values[n_rows], sizeof values[n_rows]);
        int greyed = row_greyed(d->id);
        if (greyed) copy_str(values[n_rows], "can't be used here", sizeof values[n_rows]);
        rows[n_rows] = (tui_row_t){ heading, page_label(d->label, group, labels[n_rows], sizeof labels[n_rows]),
                                    values[n_rows], setting_kind(d), d->id == SET_COLOUR ? g_app.color : NULL,
                                    NULL, 0, greyed };
        heading = NULL;
        n_rows++;
    }
    if (g_app.settings_sel == SETTINGS_DONE) sel_row = n_rows;   // the Done button
    const setting_def_t *d = g_app.settings_sel < N_SETTINGS ? &SETTINGS[g_app.settings_sel] : NULL;
    char help[600], usage[96] = "";
    if (!d) {
        if (g_app.onboarding)
            snprintf(help, sizeof help, "Go on to your sessions: Ctrl+N creates one, Ctrl+J joins one. Everything here "
                     "applies at once%s", g_app.installed && g_app.autosave
                     ? ", and what you change is saved where :install put it."
                     : g_app.installed ? ", and with autosave off, lasts until chat exits unless you :save."
                     : g_app.locked ? " and isn't saved: what :install saved stays sealed until :install opens it."
                     : " and lasts until chat exits. It's only written to disk if you :install.");
        else
            snprintf(help, sizeof help, "Back to your sessions. Everything here already applies%s",
                     !g_app.installed ? "." : g_app.autosave ? ", and is saved." : ". Autosave is off: :save saves it.");
        copy_str(usage, "ctrl+s or :set brings this page back", sizeof usage);
    } else {
        // The row cuts off a recipient on a narrow screen, and not every terminal supports OSC 52.
        char recipient[AGE_RECIPIENT_STRLEN + 3] = "";
        if (d->id == SET_AGE_RECIPIENT && g_app.identity_source == IDENT_AGE) {
            age_export_recipient(&g_app.identity, recipient);
            strcat(recipient, ": ");
        }
        int greyed = row_greyed(d->id);
        if (greyed && d->id == SET_SECURITY_KEY)
            snprintf(help, sizeof help, "Can't be used here: %s. A security key's secret is only given after a touch, "
                     "and chat needs a way to ask it for one.", g_app.seckey_why);
        else if (greyed)
            snprintf(help, sizeof help, "Can't be used here: %s. The device lock makes the save unlock only on this "
                     "device, by sealing a secret with something the device keeps to itself: its TPM, on Linux "
                     "through systemd's credential service or /dev/tpmrm0. Without that, there's nothing to seal it "
                     "with.",
                     g_app.device_why);
        else
            snprintf(help, sizeof help, "%s%s", recipient, d->help);
        if (d->values && !greyed) snprintf(usage, sizeof usage, ":set %s %s", d->key, d->values);
        else if (d->kind == K_SECRET) snprintf(usage, sizeof usage, ":set %s", d->key);
    }
    const char *nav[8];
    char title[64];
    snprintf(title, sizeof title, "Settings" CRUMB "%s", SETTINGS[section_begin(s)].section);
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .intro = g_app.onboarding
            ? "chat is an end-to-end encrypted chat with no server. Check how it reaches peers, then press "
              "Start chatting. Nothing goes on the network before that."
            : NULL,
        .nav = nav, .n_nav = settings_sections(nav, 8), .nav_sel = s,
        .rows = rows, .n_rows = n_rows, .selected = sel_row,
        .help = help, .usage = usage[0] ? usage : NULL,
        .button = g_app.onboarding ? "Start chatting" : "Done",
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

static void render_sign_picker(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    tui_row_t rows[N_PICKS];
    int in_use = sign_row_in_use();
    for (int i = 0; i < N_PICKS; i++) {
        rows[i] = (tui_row_t){ SIGN_PICKS[i].section, SIGN_PICKS[i].label, NULL, TUI_V_TEXT, NULL, NULL, 0, 0 };
        if (i == in_use) { rows[i].value = "in use"; rows[i].kind = TUI_V_ON; }
    }
    char help[600], usage[32] = "";
    char now[160]; setting_value(SET_SIGN, now, sizeof now);
    snprintf(help, sizeof help, "%s Now: %s.", SIGN_PICKS[g_app.sign_sel].help, now);
    static const char *const SET[N_PICKS] = { "off", "age", "age:PATH", "age:PATH", NULL, "pgp", "pgp:PATH", "pgp:PATH", NULL };
    if (SET[g_app.sign_sel]) snprintf(usage, sizeof usage, ":set sign %s", SET[g_app.sign_sel]);
    const char *nav[8];
    tui_page_t page = {
        .title = "Settings" CRUMB "Profile" CRUMB "Signing identity",
        .clock = clock,
        .nav = nav, .n_nav = settings_sections(nav, 8), .nav_sel = settings_section_index(SET_SIGN),
        .rows = rows, .n_rows = N_PICKS, .selected = g_app.sign_sel,
        .help = help, .usage = usage[0] ? usage : NULL,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

// The browser as a tree: the folder shown and the folders above it, one level per row, then its
// folders (drawn like rows that open a page) and files one level further in. As many levels get
// their own row as leave room for the names at this width. The levels above those are joined
// into the top row's path. The intro says what's in the folder.
#define TREE_MAX_LEVELS 32
#define TREE_INDENT 3        // columns per level
#define TREE_NAME_ROOM 14    // columns kept for the names
static tui_row_t g_browser_rows[TREE_MAX_LEVELS + MAX_DIR_ITEMS];
static char g_browser_labels[MAX_DIR_ITEMS][200];
static int g_browser_levels;   // rows above the entries

// The parent folder's entries for the column left of the tree, read again only when the folder
// shown changes. room: the columns its path gets.
// Returns 0 at the root, which has no parent.
static int parent_nav(const browser_t *b, int room, const char **nav, int *n, int *sel, char *title, size_t cap) {
    static browser_t parent;
    static char of[900], name[200];
    static int ok;
    if (strcmp(of, b->path) != 0) {
        copy_str(of, b->path, sizeof of);
        char up[900];
        copy_str(up, b->path, sizeof up);
        size_t len = strlen(up);
        while (len > 1 && up[len - 1] == '/' && !path_is_root(up)) up[--len] = '\0';
        const char *slash = strrchr(up, '/');
        copy_str(name, slash ? slash + 1 : "", sizeof name);
        ok = !path_is_root(up) && name[0];
        path_parent(up);
        ok = ok && browser_load(&parent, up) == 0;
    }
    if (!ok) return 0;
    *n = 0;
    *sel = -1;
    for (int i = 0; i < parent.n_items && *n < MAX_DIR_ITEMS; i++) {
        const char *e = parent.items[i].name;
        size_t nl = strlen(name);
        if (strncmp(e, name, nl) == 0 && e[nl] == '/' && e[nl + 1] == '\0') *sel = *n;
        nav[(*n)++] = e;
    }
    // Its path, cut from the left to fit.
    char shown[900];
    tilde_path(parent.path, shown, sizeof shown);
    size_t len = strlen(shown);
    const char *tail = shown;
    if (room > 4 && len > (size_t)room) {
        tail = shown + len - (room - 1);
        while ((*tail & 0xc0) == 0x80) tail++;
        snprintf(title, cap, "\xe2\x80\xa6%s", tail);
    } else {
        copy_str(title, shown, cap);
    }
    return 1;
}

static void browser_rows(const browser_t *b, int row_cols, int list_rows, char *intro, size_t cap) {
    static char shown[900], head[900], level_pre[TREE_MAX_LEVELS][TREE_MAX_LEVELS * TREE_INDENT + 8];
    static char mid_pre[TREE_MAX_LEVELS * TREE_INDENT + 8], last_pre[TREE_MAX_LEVELS * TREE_INDENT + 8];
    tilde_path(b->path, shown, sizeof shown);
    size_t len = strlen(shown);
    while (len > 1 && shown[len - 1] == '/' && !path_is_root(shown)) shown[--len] = '\0';

    // The folder's path split at each '/', where the first part is "" if it starts at the root.
    const char *parts[256];
    int n = 0;
    static char split[900];
    copy_str(split, shown, sizeof split);
    for (char *at = split; n < 256; ) {
        parts[n++] = at;
        char *slash = strchr(at, '/');
        if (!slash) break;
        *slash = '\0';
        at = slash + 1;
    }
    if (n > 1 && !parts[n - 1][0]) n--;   // "/" or "C:/": the root alone

    // The names and their tree lines get half the row when there's a value column (tui_render_page).
    int levels = (row_cols / 2 - TREE_NAME_ROOM) / TREE_INDENT;
    if (levels < 1) levels = 1;
    if (levels > TREE_MAX_LEVELS) levels = TREE_MAX_LEVELS;
    if (levels > n) levels = n;
    // And room under them for a few entries, so the top of the tree isn't scrolled away.
    int below = b->n_items < 3 ? b->n_items : 3;
    if (levels > list_rows - below) levels = list_rows - below > 1 ? list_rows - below : 1;
    // The top row: every part not given a row of its own.
    int joined = n - (levels - 1);
    size_t p = 0;
    head[0] = '\0';
    for (int i = 0; i < joined && p < sizeof head - 1; i++)
        p += (size_t)snprintf(head + p, sizeof head - p, "%s%s", i ? "/" : "", parts[i]);
    if (!head[0] || (joined == 1 && n > 1 && !parts[0][0])) copy_str(head, "/", sizeof head);
    // Too long for its room: its end, which says where it is, after a "\xe2\x80\xa6".
    int room = row_cols / 2 - 3;
    size_t hl = strlen(head);
    if (room > 8 && hl > (size_t)room) {
        const char *tail = head + hl - (room - 1);
        while ((*tail & 0xc0) == 0x80) tail++;
        char cut[900];
        snprintf(cut, sizeof cut, "\xe2\x80\xa6%s", tail);
        copy_str(head, cut, sizeof head);
    }
    g_browser_rows[0] = (tui_row_t){ NULL, head, NULL, TUI_V_TEXT, NULL, NULL, 0, 0 };
    for (int i = 1; i < levels; i++) {
        snprintf(level_pre[i], sizeof level_pre[i], "%*s\xe2\x94\x94\xe2\x94\x80 ", (i - 1) * TREE_INDENT, "");
        g_browser_rows[i] = (tui_row_t){ NULL, parts[joined + i - 1], NULL, TUI_V_TEXT, NULL, level_pre[i], 0, 0 };
    }
    g_browser_levels = levels;

    snprintf(mid_pre, sizeof mid_pre, "%*s\xe2\x94\x9c\xe2\x94\x80 ", (levels - 1) * TREE_INDENT, "");
    snprintf(last_pre, sizeof last_pre, "%*s\xe2\x94\x94\xe2\x94\x80 ", (levels - 1) * TREE_INDENT, "");
    int folders = 0, files = 0;
    for (int i = 0; i < b->n_items; i++) {
        const dir_entry_t *e = &b->items[i];
        copy_str(g_browser_labels[i], e->name, sizeof g_browser_labels[i]);
        size_t ln = strlen(g_browser_labels[i]);
        if (e->is_dir && ln > 1 && g_browser_labels[i][ln - 1] == '/') g_browser_labels[i][ln - 1] = '\0';
        if (e->is_dir) folders++; else files++;
        g_browser_rows[levels + i] = (tui_row_t){ NULL, g_browser_labels[i], e->is_dir ? "" : NULL, TUI_V_LINK, NULL,
                                                  i == b->n_items - 1 ? last_pre : mid_pre, 0, 0 };
    }
    char f[24] = "", g[24] = "";
    if (folders) snprintf(f, sizeof f, "%d folder%s", folders, folders == 1 ? "" : "s");
    if (files) snprintf(g, sizeof g, "%s%d file%s", folders ? " \xc2\xb7 " : "", files, files == 1 ? "" : "s");
    snprintf(intro, cap, "%s%s", folders || files ? f : "empty", g);
}

// The help for the selected entry when it's a folder, or when there's none. Returns 0 for a file.
static int browser_folder_help(const browser_t *b, char *out, size_t cap) {
    if (b->n_items == 0) { snprintf(out, cap, "Nothing here. h goes up a folder."); return 1; }
    const dir_entry_t *e = &b->items[b->selected];
    if (!e->is_dir) return 0;
    snprintf(out, cap, "Enter opens %s. h goes up a folder.", g_browser_labels[b->selected]);
    return 1;
}

// What the sidebar says about the selected entry: its name, then what it is, its size (or for a
// folder, how many entries it has), when it was changed and who can read it. In the key browser
// (kind AGE or PGP), a small file is also read to say whether it holds a secret key. Worked out
// again only when the selection changes.
static void count_cb(void *ctx, const char *name, int is_dir) {
    (void)is_dir;
    if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) (*(int *)ctx)++;
}

#define INFO_LINES 16
static int browser_info(const browser_t *b, identity_source_t kind, const char **lines) {
    static char of[1200], text[INFO_LINES][120];
    static identity_source_t of_kind;
    static int n;
    if (b->n_items == 0) return 0;
    char full[1200];
    browser_entry_path(b, &b->items[b->selected], full, sizeof full);
    if (strcmp(full, of) == 0 && kind == of_kind) goto done;
    copy_str(of, full, sizeof of);
    of_kind = kind;
    n = 0;
    copy_str(text[n++], g_browser_labels[b->selected], sizeof text[0]);
    text[n++][0] = '\0';
    file_info_t fi;
    if (platform_file_info(full, &fi) != 0) {
        copy_str(text[n++], "can't be read", sizeof text[0]);
        goto done;
    }
    if (fi.is_dir) {
        int count = 0;
        copy_str(text[n++], fi.is_link ? "link to a folder" : "folder", sizeof text[0]);
        if (platform_list_dir(full, count_cb, &count) == 0)
            snprintf(text[n++], sizeof text[0], "%d entr%s", count, count == 1 ? "y" : "ies");
        else
            copy_str(text[n++], "can't be opened", sizeof text[0]);
    } else {
        copy_str(text[n++], fi.is_link ? "link to a file" : "file", sizeof text[0]);
        file_format_size(fi.size, text[n++], sizeof text[0]);
    }
    if (fi.modified[0]) {
        // "YYYY-MM-DD HH:MM" on two rows, to fit the sidebar.
        text[n++][0] = '\0';
        copy_str(text[n++], "changed", sizeof text[0]);
        snprintf(text[n++], sizeof text[0], "%.10s", fi.modified);
        copy_str(text[n++], fi.modified + 11, sizeof text[0]);
    }
    if (fi.mode >= 0) {
        static const char RWX[] = "rwxrwxrwx";
        char perm[10];
        for (int i = 0; i < 9; i++) perm[i] = fi.mode & (0400 >> i) ? RWX[i] : '-';
        perm[9] = '\0';
        snprintf(text[n++], sizeof text[0], "%s %03o", perm, fi.mode & 0777);
    }
    if (kind != IDENT_NONE && !fi.is_dir) {
        text[n++][0] = '\0';
        static char head[16384];
        long got = fi.size <= 65536 ? platform_read_file(full, head, sizeof head - 1) : -1;
        int found = 0;
        if (got >= 0) {
            head[got] = '\0';
            if (strstr(head, "AGE-SECRET-KEY-1")) found = IDENT_AGE;
            else if (strstr(head, "-----BEGIN PGP PRIVATE KEY BLOCK-----")) found = IDENT_PGP;
            crypto_wipe(head, sizeof head);
        }
        if (fi.size > 65536) copy_str(text[n++], "too big for a key", sizeof text[0]);
        else if (got < 0) copy_str(text[n++], "can't be read", sizeof text[0]);
        else if (!found) copy_str(text[n++], "no secret key", sizeof text[0]);
        else snprintf(text[n++], sizeof text[0], "%s secret key", found == IDENT_AGE ? "AGE" : "PGP");
        if (found && found != (int)kind)
            snprintf(text[n++], sizeof text[0], "but this is %s", kind == IDENT_AGE ? "AGE" : "PGP");
        // Readable by more than its owner.
        if (found && fi.mode >= 0 && (fi.mode & 077)) {
            copy_str(text[n++], "not private:", sizeof text[0]);
            copy_str(text[n++], "chmod 600 it", sizeof text[0]);
        }
    }
done:
    for (int i = 0; i < n; i++) lines[i] = text[i];
    return n;
}

static void render_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const browser_t *b = &g_app.browser;
    int age = g_app.load_kind == IDENT_AGE;
    char intro[1000], help[700], usage[1100] = "", side_title[900];
    static const char *side[MAX_DIR_ITEMS];
    int n_side = 0, side_sel = -1, sw = tui_side_width(cols_n, 1);
    int columns = sw && parent_nav(b, sw - 4, side, &n_side, &side_sel, side_title, sizeof side_title);
    browser_rows(b, tui_page_row_cols(cols_n, 1) - (columns ? sw : 0), rows_n - 12, intro, sizeof intro);
    if (!browser_folder_help(b, help, sizeof help)) {
        char full[1200], shown[1200];
        browser_entry_path(b, &b->items[b->selected], full, sizeof full);
        tilde_path(full, shown, sizeof shown);
        snprintf(help, sizeof help, "Enter uses %s as your %s key. " WHY_SECRET "It stays in memory and isn't sent. "
                 ":install saves this file's path, not the key.", g_browser_labels[b->selected], age ? "AGE" : "PGP");
        snprintf(usage, sizeof usage, ":set sign %s:%s", age ? "age" : "pgp", shown);
    }
    const char *nav[INFO_LINES];
    int n_nav = browser_info(b, g_app.load_kind, nav);
    tui_page_t page = {
        .title = age ? "Settings" CRUMB "Profile" CRUMB "Signing identity" CRUMB "AGE key file"
                     : "Settings" CRUMB "Profile" CRUMB "Signing identity" CRUMB "PGP key file",
        .clock = clock,
        .intro = intro,
        .nav = nav, .n_nav = n_nav, .nav_sel = 0,
        .side = columns ? side : NULL, .n_side = n_side, .side_sel = side_sel, .side_title = side_title,
        .rows = g_browser_rows, .n_rows = g_browser_levels + b->n_items, .selected = g_browser_levels + b->selected,
        .help = help, .usage = usage[0] ? usage : NULL,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

static void render_send_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const browser_t *b = &g_app.browser;
    char intro[1000], help[700], side_title[900];
    const char *info[INFO_LINES];
    static const char *side[MAX_DIR_ITEMS];
    int n_side = 0, side_sel = -1, sw = tui_side_width(cols_n, 1);
    int columns = sw && parent_nav(b, sw - 4, side, &n_side, &side_sel, side_title, sizeof side_title);
    browser_rows(b, tui_page_row_cols(cols_n, 1) - (columns ? sw : 0), rows_n - 12, intro, sizeof intro);
    int n_info = browser_info(b, IDENT_NONE, info);
    if (!browser_folder_help(b, help, sizeof help))
        snprintf(help, sizeof help, "Enter offers %s to everyone in this session. Nobody gets it unless they fetch it.",
                 g_browser_labels[b->selected]);
    tui_page_t page = {
        .title = "Send a file",
        .clock = clock,
        .intro = intro,
        .nav = info, .n_nav = n_info, .nav_sel = 0,
        .side = columns ? side : NULL, .n_side = n_side, .side_sel = side_sel, .side_title = side_title,
        .rows = g_browser_rows, .n_rows = g_browser_levels + b->n_items, .selected = g_browser_levels + b->selected,
        .help = help,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

static void render_save_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const browser_t *b = &g_app.browser;
    char intro[1000], help[1400], title[160], side_title[900];
    const char *info[INFO_LINES];
    static const char *side[MAX_DIR_ITEMS];
    int n_side = 0, side_sel = -1, sw = tui_side_width(cols_n, 1);
    int columns = sw && parent_nav(b, sw - 4, side, &n_side, &side_sel, side_title, sizeof side_title);
    browser_rows(b, tui_page_row_cols(cols_n, 1) - (columns ? sw : 0), rows_n - 12, intro, sizeof intro);
    int n_info = browser_info(b, IDENT_NONE, info);
    const file_entry_t *f = g_app.selected ? chat_file(&g_app.selected->engine, g_app.save_num) : NULL;
    char what[FILE_NAME_MAX + 48];
    if (f) {
        char sz[32]; file_format_size(f->size, sz, sizeof sz);
        snprintf(what, sizeof what, "%s (%s)", f->name, sz);
    } else {
        snprintf(what, sizeof what, "file %d", g_app.save_num);
    }
    snprintf(title, sizeof title, "Save file %d", g_app.save_num);
    char open_help[700] = "";
    if (b->n_items > 0 && b->items[b->selected].is_dir) browser_folder_help(b, open_help, sizeof open_help);
    snprintf(help, sizeof help, "s saves %s in %s.%s%s", what, b->path, open_help[0] ? " " : "", open_help);
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .intro = intro,
        .nav = info, .n_nav = n_info, .nav_sel = 0,
        .side = columns ? side : NULL, .n_side = n_side, .side_sel = side_sel, .side_title = side_title,
        .rows = g_browser_rows, .n_rows = g_browser_levels + b->n_items, .selected = g_browser_levels + b->selected,
        .help = help,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

// ---- the files page, and a picture on a page of its own ----

static int add_para(tui_para_t *p, int n, tui_para_kind_t kind, const char *text);

typedef enum { FS_NEW, FS_OVER, FS_COMING, FS_QUEUED, FS_FAILED, FS_SAVED, FS_HERE, FS_BROKEN, FS_MINE } file_state_t;

// What a y/n box over the files page or the picture asks.
enum { ASK_VIEW = 1, ASK_SHOW, ASK_FETCH, ASK_RETRY, ASK_SAVETO, ASK_STOP, ASK_UNOFFER };

static const pic_t *pic_of(const session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used && s->pics[i].num == num) return &s->pics[i];
    return NULL;
}

static file_state_t file_state(const session_slot_t *s, const file_entry_t *f) {
    if (f->mine) return FS_MINE;
    if (f->dl == DL_ACTIVE) return FS_COMING;
    if (f->dl == DL_QUEUED) return FS_QUEUED;
    if (f->dl == DL_FAILED) return FS_FAILED;
    if (f->saved[0]) return FS_SAVED;
    const pic_t *p = pic_of(s, f->num);
    if (f->cache || (p && p->th.rgb)) return FS_HERE;
    if (p && p->why[0]) return FS_BROKEN;
    uint64_t cap = s->engine.file_cap ? s->engine.file_cap : FILE_CAP_DEFAULT;
    return f->size > cap ? FS_OVER : FS_NEW;
}

// Fetching f now would take it past the size limit: it's over, and there's no copy here to use instead.
static int file_needs_anyway(const session_slot_t *s, const file_entry_t *f) {
    uint64_t cap = s->engine.file_cap ? s->engine.file_cap : FILE_CAP_DEFAULT;
    return !f->mine && f->size > cap && !f->cache && !f->saved[0] && f->dl != DL_ACTIVE && f->dl != DL_QUEUED;
}

static int file_cmp(const void *a, const void *b) {
    const file_entry_t *x = *(const file_entry_t *const *)a, *y = *(const file_entry_t *const *)b;
    return x->mine != y->mine ? x->mine - y->mine : y->num - x->num;
}

// The session's files in the page's order: those offered to you, then yours, newest first.
static int files_list(const session_slot_t *s, const file_entry_t **l) {
    int n = 0;
    for (int i = 0; s && !s->initialising && i < FILE_OFFERS_MAX; i++)
        if (s->engine.files[i].used) l[n++] = &s->engine.files[i];
    qsort(l, (size_t)n, sizeof *l, file_cmp);
    return n;
}

static int files_sel(const file_entry_t *const *l, int n) {
    for (int i = 0; i < n; i++) if (l[i]->num == g_app.file_num) return i;
    return 0;
}

static const file_entry_t *selected_file(void) {
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(g_app.selected, l);
    return n ? l[files_sel(l, n)] : NULL;
}

static void file_owner_name(const chat_t *e, const file_entry_t *f, char out[CHAT_NAME_LEN]) {
    if (f->mine) { copy_str(out, "you", CHAT_NAME_LEN); return; }
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        const peer_t *p = &e->peers[i];
        if (p->used && memcmp(p->id, f->owner, ID_LEN) == 0) { chat_peer_name(e, p, out); return; }
    }
    copy_str(out, "someone who left", CHAT_NAME_LEN);
}

static tui_value_kind_t file_value(const session_slot_t *s, const file_entry_t *f, char *out, size_t cap, int *permille) {
    char sz[32]; file_format_size(f->size, sz, sizeof sz);
    *permille = 0;
    switch (file_state(s, f)) {
        case FS_MINE: {
            char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
            int pm, n = chat_file_sending(&s->engine, f, now_seconds(), name, &pm);
            chat_file_sent_to(f, to, sizeof to);
            if (n) {
                *permille = pm;
                snprintf(out, cap, "%d%% \xc2\xb7 sending to %s%s", pm / 10, name, n > 1 ? " and others" : "");
                return TUI_V_PROGRESS;
            }
            if (to[0]) { snprintf(out, cap, "sent to %s", to); return TUI_V_ON; }
            if (!f->fp) { snprintf(out, cap, "no longer offered"); return TUI_V_MUTED; }
            snprintf(out, cap, "offered \xc2\xb7 %s", sz);
            return TUI_V_TEXT;
        }
        case FS_COMING:
        case FS_QUEUED: *permille = fetch_progress(&s->engine, f, out, cap); return TUI_V_PROGRESS;
        case FS_FAILED: snprintf(out, cap, "%s", f->why[0] ? f->why : "it didn't finish"); return TUI_V_BAD;
        case FS_SAVED:  snprintf(out, cap, "saved \xc2\xb7 %s", sz); return TUI_V_ON;
        case FS_HERE: {
            const pic_t *p = pic_of(s, f->num);
            snprintf(out, cap, "%s \xc2\xb7 %s", p && p->shown && p->th.rgb ? "shown" : "here, hidden", sz);
            return TUI_V_ON;
        }
        case FS_BROKEN: snprintf(out, cap, "can't be shown"); return TUI_V_BAD;
        case FS_OVER:   snprintf(out, cap, "%s \xc2\xb7 over your size limit", sz); return TUI_V_OFF;
        default:        snprintf(out, cap, "%s \xc2\xb7 %s", f->image ? "picture" : "file", sz); return TUI_V_OFF;
    }
}

#define DETAIL_LINES 24
static int add_wrapped(char lines[][128], int n, const char *t, int width) {
    size_t len = strlen(t);
    if (len == 0 && n < DETAIL_LINES) lines[n++][0] = '\0';
    while (len > 0 && n < DETAIL_LINES) {
        size_t fit = utf8_fit_cols(t, len, width, NULL);
        if (fit == 0) utf8_char_cols(t, len, 0, &fit);
        if (fit < len) {
            size_t sp = fit;
            while (sp > 0 && t[sp] != ' ') sp--;
            if (sp > 0) fit = sp;
        }
        snprintf(lines[n++], 128, "%.*s", (int)(fit < 127 ? fit : 127), t);
        t += fit;
        len -= fit;
        while (len > 0 && *t == ' ') { t++; len--; }
    }
    return n;
}

static int file_details(const session_slot_t *s, const file_entry_t *f, int width, const char **out) {
    static char lines[DETAIL_LINES][128];
    char t[900], sz[32], who[CHAT_NAME_LEN];
    int n = 0;
    if (width < 8) return 0;
    file_format_size(f->size, sz, sizeof sz);
    file_owner_name(&s->engine, f, who);
    n = add_wrapped(lines, n, f->name, width);
    n = add_wrapped(lines, n, "", width);
    snprintf(t, sizeof t, "%s \xc2\xb7 %s", f->image ? "picture" : "file", sz);
    n = add_wrapped(lines, n, t, width);
    if (f->mine) copy_str(t, "yours", sizeof t);
    else snprintf(t, sizeof t, "from %s", who);
    n = add_wrapped(lines, n, t, width);
    snprintf(t, sizeof t, "file %d, at %s", f->num, f->at[0] ? f->at : "--:--");
    n = add_wrapped(lines, n, t, width);
    n = add_wrapped(lines, n, "", width);
    char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
    int pm;
    switch (file_state(s, f)) {
        case FS_MINE:
            chat_file_sent_to(f, to, sizeof to);
            if (chat_file_sending(&s->engine, f, now_seconds(), name, &pm)) snprintf(t, sizeof t, "sending to %s: %d%%", name, pm / 10);
            else snprintf(t, sizeof t, "%s", f->fp ? "offered to everyone here" : "no longer offered");
            n = add_wrapped(lines, n, t, width);
            if (to[0]) { snprintf(t, sizeof t, "sent to %s", to); n = add_wrapped(lines, n, t, width); }
            break;
        case FS_COMING:
        case FS_QUEUED: {
            fetch_progress(&s->engine, f, t, sizeof t);
            for (char *part = t, *next; part; part = next) {
                next = strstr(part, " \xc2\xb7 ");
                if (next) { *next = '\0'; next += 4; }
                n = add_wrapped(lines, n, part, width);
            }
            break;
        }
        case FS_FAILED:
            snprintf(t, sizeof t, "failed: %s", f->why[0] ? f->why : "it didn't finish");
            n = add_wrapped(lines, n, t, width);
            break;
        case FS_SAVED: {
            char where[sizeof f->saved];
            tilde_path(f->saved, where, sizeof where);
            char *slash = strrchr(where, '/');
            n = add_wrapped(lines, n, "saved in", width);
            if (slash) { *slash = '\0'; n = add_wrapped(lines, n, where[0] ? where : "/", width); }
            snprintf(t, sizeof t, "as %s", slash ? slash + 1 : where);
            n = add_wrapped(lines, n, t, width);
            break;
        }
        case FS_HERE: {
            const pic_t *p = pic_of(s, f->num);
            n = add_wrapped(lines, n, p && p->shown && p->th.rgb ? "shown in the chat" : "here, hidden in the chat", width);
            n = add_wrapped(lines, n, "only in memory", width);
            break;
        }
        case FS_BROKEN:
            snprintf(t, sizeof t, "can't be shown: %s", pic_why(s, f->num));
            n = add_wrapped(lines, n, t, width);
            break;
        case FS_OVER: {
            uint64_t cap = s->engine.file_cap ? s->engine.file_cap : FILE_CAP_DEFAULT;
            char lim[32]; file_format_size(cap, lim, sizeof lim);
            snprintf(t, sizeof t, "not fetched, and over your %s limit", lim);
            n = add_wrapped(lines, n, t, width);
            break;
        }
        default:
            n = add_wrapped(lines, n, "not fetched yet", width);
            break;
    }
    for (int i = 0; i < n; i++) out[i] = lines[i];
    return n;
}

// What Enter does with f, for the bottom row, or NULL for nothing.
static const char *file_enter(const session_slot_t *s, const file_entry_t *f) {
    file_state_t st = file_state(s, f);
    if (f->image && st != FS_BROKEN) return st == FS_NEW || st == FS_OVER || st == FS_FAILED ? "show" : "view";
    if (st == FS_NEW || st == FS_OVER) return "download";
    return st == FS_FAILED ? "retry" : NULL;
}

// usage gets the command that does what Enter does.
static void file_help(const session_slot_t *s, const file_entry_t *f, char *help, size_t cap, char *usage, size_t ucap) {
    char who[CHAT_NAME_LEN], where[sizeof f->saved] = "";
    file_owner_name(&s->engine, f, who);
    if (f->saved[0]) tilde_path(f->saved, where, sizeof where);
    const char *save = "d saves it in Downloads, s in a folder you pick.";
    usage[0] = '\0';
    switch (file_state(s, f)) {
        case FS_MINE:
            if (!f->fp) snprintf(help, cap, "Yours, and no longer offered. :send offers it again, as a new file.");
            else snprintf(help, cap, "Yours, offered to everyone here%s.%s x stops offering it.",
                          s->engine.verify_required ? " whose verify code you've compared" : "",
                          f->image ? " Enter shows it big." : "");
            if (f->fp) snprintf(usage, ucap, ":cancel %d", f->num);
            return;
        case FS_COMING:
        case FS_QUEUED:
            snprintf(help, cap, "%s%s x stops it.", f->dl == DL_QUEUED ? "Queued: one file comes from each sender at a time." : "On its way.",
                     f->image ? " Enter shows how far it's got, then the picture." : "");
            snprintf(usage, ucap, ":cancel %d", f->num);
            return;
        case FS_FAILED:
            snprintf(help, cap, "Failed: %s. Enter tries again. %s", f->why[0] ? f->why : "it stopped", save);
            snprintf(usage, ucap, ":%s %d", f->image ? "show" : "download", f->num);
            return;
        case FS_SAVED:
            snprintf(help, cap, "Saved as %s.%s y copies where it is, s saves a copy in another folder.", where,
                     f->image ? " Enter shows it big, v in the chat." : "");
            snprintf(usage, ucap, ":saveto %d", f->num);
            return;
        case FS_HERE:
            snprintf(help, cap, "Enter shows it big, v shows or hides it in the chat. It's only in memory: %s", save);
            snprintf(usage, ucap, ":download %d", f->num);
            return;
        case FS_BROKEN:
            snprintf(help, cap, "chat can't show it (%s). d saves it in Downloads, to open with something else.", pic_why(s, f->num));
            snprintf(usage, ucap, ":download %d", f->num);
            return;
        default: {
            const char *over = file_state(s, f) == FS_OVER ? " It's over your file size limit, so chat asks first." : "";
            if (f->image)
                snprintf(help, cap, "%s offers it. Enter fetches it and shows it big, and in the chat under the offer. %s%s",
                         who, save, over);
            else
                snprintf(help, cap, "%s offers it. Enter saves it in Downloads, s in a folder you pick. Nothing is fetched until "
                         "you ask.%s", who, over);
            snprintf(usage, ucap, ":%s %d%s", f->image ? "show" : "download", f->num, *over ? " anyway" : "");
            return;
        }
    }
}

static void file_ask(int what, const file_entry_t *f) {
    g_app.file_ask = what;
    g_app.file_ask_num = f->num;
    g_app.file_back = g_app.mode;
    g_app.mode = MODE_FILE_ASK;
}

// The engine's reply goes on the bottom bar, since the page covers the console.
static int echo_fetch(session_slot_t *s, int num, int view, int anyway, const char *dir) {
    g_echo = 1;
    int r = chat_file_fetch(&s->engine, num, view, anyway, dir);
    g_echo = 0;
    return r;
}

static void echo_cancel(session_slot_t *s, int num) {
    char cmd[32];
    snprintf(cmd, sizeof cmd, "cancel %d", num);
    g_echo = 1;
    chat_run_command(&s->engine, cmd);
    g_echo = 0;
}

static void file_download(session_slot_t *s, const file_entry_t *f) {
    if (f->mine) note("file %d is yours", f->num);
    else if (file_needs_anyway(s, f)) file_ask(ASK_FETCH, f);
    else echo_fetch(s, f->num, 0, 0, NULL);
}

static void file_save_in(session_slot_t *s, const file_entry_t *f) {
    if (f->mine) note("file %d is yours", f->num);
    else if (file_needs_anyway(s, f)) file_ask(ASK_SAVETO, f);
    else begin_save_browse(f->num, 0);
}

static void file_toggle_shown(session_slot_t *s, const file_entry_t *f) {
    if (!f->image) { note("only pictures are shown in the chat - d saves %s", f->name); return; }
    pic_t *p = pic_find(s, f->num);
    if (p && p->th.rgb) {
        p->shown = !p->shown;
        note(p->shown ? "file %d is shown in the chat" : "file %d is hidden in the chat - v shows it again", f->num);
    } else if (file_needs_anyway(s, f)) {
        file_ask(ASK_SHOW, f);
    } else {
        echo_fetch(s, f->num, 1, 0, NULL);
    }
}

static void file_stop(session_slot_t *s, const file_entry_t *f) {
    if (f->mine && f->fp) file_ask(ASK_UNOFFER, f);
    else if (f->mine) note("file %d isn't offered any more", f->num);
    else if (f->dl == DL_ACTIVE) file_ask(ASK_STOP, f);
    else if (f->dl == DL_QUEUED) echo_cancel(s, f->num);
    else note("file %d isn't on its way - there's nothing to stop", f->num);
}

static void file_copy_path(const file_entry_t *f) {
    if (!f->saved[0]) { note(f->mine ? "file %d is yours, not a copy chat saved" : "file %d isn't saved - d saves it", f->num); return; }
    osc52_copy(f->saved);
    char where[sizeof f->saved];
    tilde_path(f->saved, where, sizeof where);
    note("copied %s to the clipboard (OSC 52)", where);
}

// The keys the files page and the picture share. Returns 1 if ch is one of them.
static int file_action(char ch, session_slot_t *s, const file_entry_t *f) {
    switch (ch) {
        case 'd': file_download(s, f); return 1;
        case 's': file_save_in(s, f); return 1;
        case 'v': file_toggle_shown(s, f); return 1;
        case 'x': file_stop(s, f); return 1;
        case 'y': file_copy_path(f); return 1;
        default:  return 0;
    }
}

// Enter: a picture opens on a page of its own, fetched first if it isn't here. A file is saved in
// Downloads, or where it was going if that failed.
static void file_open(session_slot_t *s, const file_entry_t *f) {
    file_state_t st = file_state(s, f);
    if (f->image && st != FS_BROKEN) {
        if (st == FS_NEW || st == FS_OVER || st == FS_FAILED) {
            if (file_needs_anyway(s, f)) { file_ask(ASK_VIEW, f); return; }
            if (echo_fetch(s, f->num, 1, 0, NULL) != 0) return;
        }
        g_app.mode = MODE_FILE_VIEW;
        return;
    }
    switch (st) {
        case FS_MINE:   note("file %d is yours - x stops offering it", f->num); break;
        case FS_BROKEN: note("chat can't show it (%s) - d saves it", pic_why(s, f->num)); break;
        case FS_COMING: note("file %d is on its way - x stops it", f->num); break;
        case FS_QUEUED: note("file %d is queued - x takes it off the queue", f->num); break;
        case FS_SAVED: {
            char where[sizeof f->saved];
            tilde_path(f->saved, where, sizeof where);
            note("saved as %s - y copies where it is", where);
            break;
        }
        case FS_FAILED:
            if (file_needs_anyway(s, f)) file_ask(ASK_RETRY, f);
            else echo_fetch(s, f->num, 0, 0, f->save_dir);
            break;
        default: file_download(s, f); break;
    }
}

static void file_ask_yes(void) {
    session_slot_t *s = g_app.selected;
    int num = g_app.file_ask_num;
    g_app.mode = g_app.file_back;
    g_app.dirty = 1;
    const file_entry_t *f = s && !s->initialising ? chat_file(&s->engine, num) : NULL;
    if (!f) return;
    switch (g_app.file_ask) {
        case ASK_VIEW:    if (echo_fetch(s, num, 1, 1, NULL) == 0) g_app.mode = MODE_FILE_VIEW; break;
        case ASK_SHOW:    echo_fetch(s, num, 1, 1, NULL); break;
        case ASK_FETCH:   echo_fetch(s, num, 0, 1, NULL); break;
        case ASK_RETRY: {
            char dir[sizeof f->save_dir];
            copy_str(dir, f->save_dir, sizeof dir);
            echo_fetch(s, num, 0, 1, dir);
            break;
        }
        case ASK_SAVETO:  begin_save_browse(num, 1); break;
        case ASK_STOP:
        case ASK_UNOFFER: echo_cancel(s, num); break;
        default: break;
    }
}

static void file_ask_no(void) {
    g_app.mode = g_app.file_back;
    g_app.dirty = 1;
}

static int file_ask_paras(tui_para_t *paras, const char **title, const char **keys) {
    static char text[900];
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = s && !s->initialising ? chat_file(&s->engine, g_app.file_ask_num) : NULL;
    if (!f) { *title = "FILES"; *keys = "n back"; return add_para(paras, 0, TUI_P_TEXT, "That file isn't here any more."); }
    char sz[32], lim[32];
    file_format_size(f->size, sz, sizeof sz);
    file_format_size(s->engine.file_cap ? s->engine.file_cap : FILE_CAP_DEFAULT, lim, sizeof lim);
    switch (g_app.file_ask) {
        case ASK_STOP: {
            char got[32]; file_format_size(chat_file_got(f), got, sizeof got);
            *title = "STOP";
            *keys = "y stop \xc2\xb7 n keep it coming";
            snprintf(text, sizeof text, "Stop fetching `%s`? The %s that's come so far is thrown away, and fetching it again "
                     "starts from the beginning.", f->name, got);
            break;
        }
        case ASK_UNOFFER:
            *title = "STOP";
            *keys = "y stop offering \xc2\xb7 n keep offering";
            snprintf(text, sizeof text, "Stop offering `%s`? Nobody can fetch it after this, and anyone fetching it now stops. "
                     "`:send` offers it again, as a new file.", f->name);
            break;
        default: {
            char eta[48], took[160] = "";
            double left = chat_file_eta(&s->engine, f, now_seconds());
            if (left >= 0.0) {
                char who[CHAT_NAME_LEN];
                file_owner_name(&s->engine, f, who);
                file_format_duration(left, eta, sizeof eta);
                snprintf(took, sizeof took, " At chat's normal rate it takes %s to come, less if %s has fast transfers on.", eta, who);
            }
            int ask = g_app.file_ask;
            *title = "OVER YOUR LIMIT";
            *keys = "y fetch it \xc2\xb7 n cancel";
            snprintf(text, sizeof text, "`%s` is %s, over your %s file size limit. Fetch it anyway%s?%s", f->name, sz, lim,
                     ask == ASK_SAVETO ? ", into a folder you pick" : ask == ASK_VIEW || ask == ASK_SHOW ? ", to show it" : "", took);
            break;
        }
    }
    return add_para(paras, 0, TUI_P_TEXT, text);
}

static const char *files_hint(void) {
    static char hint[200];
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = selected_file();
    if (!f) return "n send a file \xc2\xb7 esc close";
    const char *enter = file_enter(s, f);
    file_state_t st = file_state(s, f);
    snprintf(hint, sizeof hint, "%s%s%s%s%s%sn send \xc2\xb7 esc close", enter ? "enter " : "", enter ? enter : "",
             enter ? " \xc2\xb7 " : "", f->saved[0] ? "y copy path \xc2\xb7 " : "",
             f->mine ? "" : "d download \xc2\xb7 s save in \xc2\xb7 ",
             (f->mine && f->fp) || st == FS_COMING || st == FS_QUEUED ? "x stop \xc2\xb7 " : "");
    return hint;
}

static void begin_files(void) {
    if (g_app.mode != MODE_CHAT) return;
    session_slot_t *s = g_app.selected;
    if (!s || s->initialising) { note("no session open - ctrl+n starts one, ctrl+j joins one"); return; }
    // The newest file, since that's usually the one to do something with.
    g_app.file_num = s->engine.file_seq;
    g_app.mode = MODE_FILES;
    g_app.dirty = 1;
}

static void render_files(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    static tui_row_t rows[FILE_OFFERS_MAX];
    static char values[FILE_OFFERS_MAX][160], prefix[FILE_OFFERS_MAX][24];
    static char title[MAX_SESSION_NAME + 16], intro[200], help[1200], usage[64];
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n), digits = 1, theirs = 0, coming = 0;
    snprintf(title, sizeof title, "%s" CRUMB "Files", s ? s->name : "");
    for (int i = 0; i < n; i++) {
        char d[12];
        int w = snprintf(d, sizeof d, "%d", l[i]->num);
        if (w > digits) digits = w;
        theirs += !l[i]->mine;
        coming += l[i]->dl == DL_ACTIVE || l[i]->dl == DL_QUEUED;
    }
    for (int i = 0; i < n; i++) {
        int pm;
        tui_value_kind_t kind = file_value(s, l[i], values[i], sizeof values[i], &pm);
        snprintf(prefix[i], sizeof prefix[i], "%*d  ", digits, l[i]->num);
        const char *section = i == 0 || l[i]->mine != l[i - 1]->mine ? (l[i]->mine ? "Yours" : "Offered to you") : NULL;
        rows[i] = (tui_row_t){ section, l[i]->name, values[i], kind, NULL, prefix[i], pm, 0 };
    }
    char parts[3][40];
    int np = 0;
    if (theirs) snprintf(parts[np++], sizeof parts[0], "%d offered to you", theirs);
    if (coming) snprintf(parts[np++], sizeof parts[0], "%d on the way", coming);
    if (n - theirs) snprintf(parts[np++], sizeof parts[0], "%d yours", n - theirs);
    if (!n) snprintf(intro, sizeof intro, "Nothing's been offered here yet.");
    else snprintf(intro, sizeof intro, "%s%s%s%s%s", parts[0], np > 1 ? " \xc2\xb7 " : "", np > 1 ? parts[1] : "",
                  np > 2 ? " \xc2\xb7 " : "", np > 2 ? parts[2] : "");
    const char *nav[DETAIL_LINES];
    int n_nav = 0;
    usage[0] = '\0';
    if (n) {
        n_nav = file_details(s, l[sel], tui_nav_text_cols(cols_n), nav);
        file_help(s, l[sel], help, sizeof help, usage, sizeof usage);
    } else {
        snprintf(help, sizeof help, "n picks a file to send, or :send PATH. What others offer shows up here, and nothing is "
                 "fetched until you ask.");
    }
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .intro = intro,
        .nav = n_nav ? nav : NULL, .n_nav = n_nav, .nav_sel = 0,
        .rows = rows, .n_rows = n, .selected = sel,
        .help = help, .usage = usage[0] ? usage : NULL,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

static void files_key(const tui_key_t *key) {
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n);
    const file_entry_t *f = n ? l[sel] : NULL;
    g_app.dirty = 1;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1) {
        if (key->ch[0] == 'n') { begin_send_browse(); return; }
        if (f && file_action(key->ch[0], s, f)) return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT: if (f) file_open(s, f); break;
        case LIST_LEFT:
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = MODE_CHAT; break;
        case LIST_NEXT_SECTION:
        case LIST_PREV_SECTION:
            for (int i = 0; i < n; i++) if (l[i]->mine != (f && f->mine)) { g_app.file_num = l[i]->num; break; }
            break;
        default:
            list_move(k, &sel, n);
            if (n) g_app.file_num = l[sel]->num;
            break;
    }
}

// The picture on its own page, decoded to fit the screen. It's decoded again for another file or
// size, or when its bytes may have come.
static struct {
    const session_slot_t *s;
    int num, w, h;
    unsigned sig;
    image_thumb_t th;
    tui_image_t ti;
    char why[160];
} g_view;

static void view_drop(void) {
    if (g_view.th.rgb) crypto_wipe(g_view.th.rgb, (size_t)g_view.th.w * (size_t)g_view.th.h * 3);
    image_thumb_free(&g_view.th);
    memset(&g_view, 0, sizeof g_view);
}

static void view_forget(const session_slot_t *s) {
    if (g_view.s == s) view_drop();
}

static unsigned view_sig(const file_entry_t *f) {
    return (unsigned)f->dl | (f->cache ? 8u : 0u) | (f->saved[0] ? 16u : 0u) | (f->fp ? 32u : 0u);
}

static void view_update(session_slot_t *s, const file_entry_t *f, int w, int h) {
    if (g_view.s == s && g_view.num == f->num && g_view.w == w && g_view.h == h && g_view.sig == view_sig(f)) return;
    view_drop();
    g_view.s = s;
    g_view.num = f->num;
    g_view.w = w;
    g_view.h = h;
    const uint8_t *b = f->dl == DL_ACTIVE || f->dl == DL_QUEUED ? NULL : chat_file_bytes(&s->engine, f->num);
    static const uint8_t bg[3] = { 0, 0, 0 };
    if (b && image_thumbnail(b, (size_t)f->size, w, h, bg, &g_view.th, g_view.why, sizeof g_view.why) == 0)
        g_view.ti = (tui_image_t){ g_view.th.w, g_view.th.h, g_view.th.rgb };
    g_view.sig = view_sig(f);
}

static void render_viewer(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    static char title[MAX_SESSION_NAME + FILE_NAME_MAX + 32], caption[400], text[700];
    static tui_progress_t pg;
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = selected_file();
    tui_picture_t pic = { .title = title, .clock = clock, .caption = caption };
    caption[0] = '\0';
    if (!f || !f->image) {
        snprintf(title, sizeof title, "%s" CRUMB "Files", s ? s->name : "");
        pic.note = "That picture isn't here any more\nesc goes back to the files";
        tui_render_picture(rows_n, cols_n, &pic, bar, g_app.color_enabled);
        return;
    }
    snprintf(title, sizeof title, "%s" CRUMB "Files" CRUMB "%s", s->name, f->name);
    int w, h;
    tui_picture_room(rows_n, cols_n, &w, &h);
    view_update(s, f, w, h);

    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), at = 0, pics = 0;
    for (int i = 0; i < n; i++) if (l[i]->image) { pics++; if (l[i] == f) at = pics; }
    char sz[32], who[CHAT_NAME_LEN], dims[32] = "", of[40] = "";
    file_format_size(f->size, sz, sizeof sz);
    file_owner_name(&s->engine, f, who);
    const pic_t *small = pic_of(s, f->num);
    file_state_t st = file_state(s, f);
    if (g_view.th.rgb) {
        pic.image = &g_view.ti;
        snprintf(dims, sizeof dims, "%d\xc3\x97%d \xc2\xb7 ", g_view.th.src_w, g_view.th.src_h);
    } else if (small && small->th.rgb && st != FS_COMING && st != FS_QUEUED) {
        // Only the small copy the chat shows is left: what was fetched has been dropped from memory.
        pic.image = &small->ti;
        snprintf(dims, sizeof dims, "small copy \xc2\xb7 ");
    }
    if (pics > 1) snprintf(of, sizeof of, " \xc2\xb7 %d of %d", at, pics);
    snprintf(caption, sizeof caption, "%s \xc2\xb7 %s%s \xc2\xb7 %s%s%s", f->name, dims, sz, f->mine ? "yours" : "from ",
             f->mine ? "" : who, of);
    if (!pic.image) {
        memset(&pg, 0, sizeof pg);
        switch (st) {
            case FS_COMING:
            case FS_QUEUED: {
                snprintf(text, sizeof text, "On its way\n%s from %s", sz, who);
                pg.permille = fetch_progress(&s->engine, f, pg.text, sizeof pg.text);
                // The bar has the percentage already.
                char *after = f->dl == DL_ACTIVE ? strstr(pg.text, " \xc2\xb7 ") : NULL;
                if (after) memmove(pg.text, after + 4, strlen(after + 4) + 1);
                pic.progress = &pg;
                break;
            }
            case FS_FAILED:
                snprintf(text, sizeof text, "It didn't finish\n%s\nenter tries again", f->why[0] ? f->why : "it stopped");
                break;
            case FS_OVER:
                snprintf(text, sizeof text, "Not fetched yet\n%s, over your file size limit\nenter fetches it, after asking", sz);
                break;
            case FS_NEW:
                snprintf(text, sizeof text, "Not fetched yet\n%s from %s\nenter fetches it \xc2\xb7 d saves it in Downloads", sz, who);
                break;
            case FS_MINE:
                snprintf(text, sizeof text, "It can't be shown\n%s", g_view.why[0] ? g_view.why
                         : f->fp ? "it's changed since you offered it" : "it isn't offered any more");
                break;
            default:
                if (g_view.why[0] || st == FS_BROKEN)
                    snprintf(text, sizeof text, "chat can't show this picture\n%s\nd saves it, to open with something else",
                             g_view.why[0] ? g_view.why : pic_why(s, f->num));
                else
                    snprintf(text, sizeof text, "It isn't here any more\nthe copy shown was dropped from memory, or the "
                             "saved one has changed\nenter fetches it again");
                break;
        }
        pic.note = text;
    }
    tui_render_picture(rows_n, cols_n, &pic, bar, g_app.color_enabled);
}

static void view_fetch(session_slot_t *s, const file_entry_t *f) {
    if (g_view.th.rgb && g_view.num == f->num) return;
    file_state_t st = file_state(s, f);
    if (st == FS_COMING || st == FS_QUEUED) note("on its way - it's shown here once it's come");
    else if (st == FS_MINE) note("it can't be shown - it's changed since you offered it, or isn't offered any more");
    else if (st == FS_BROKEN || g_view.why[0]) note("chat can't show it - d saves it");
    else if (file_needs_anyway(s, f)) file_ask(ASK_SHOW, f);
    else echo_fetch(s, f->num, 1, 0, NULL);
}

// The picture page: j and k go to the next and previous picture in the files page's order.
static void viewer_key(const tui_key_t *key) {
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n);
    const file_entry_t *f = n ? l[sel] : NULL;
    g_app.dirty = 1;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && f && file_action(key->ch[0], s, f)) return;
    int pics[FILE_OFFERS_MAX], np = 0, at = -1;
    for (int i = 0; i < n; i++) if (l[i]->image) { if (i == sel) at = np; pics[np++] = i; }
    switch (list_key(key)) {
        case LIST_DOWN:  if (at + 1 < np) g_app.file_num = l[pics[at + 1]]->num; break;
        case LIST_UP:    if (at > 0) g_app.file_num = l[pics[at - 1]]->num; break;
        case LIST_FIRST: if (np) g_app.file_num = l[pics[0]]->num; break;
        case LIST_LAST:  if (np) g_app.file_num = l[pics[np - 1]]->num; break;
        case LIST_CHOOSE:
        case LIST_RIGHT: if (f) view_fetch(s, f); break;
        case LIST_LEFT:
        case LIST_BACK:  view_drop(); g_app.mode = MODE_FILES; break;
        case LIST_CLOSE: view_drop(); g_app.mode = MODE_CHAT; break;
        default: break;
    }
}

static const char *viewer_hint(void) {
    static char hint[200];
    const file_entry_t *f = selected_file();
    if (!f) return "esc back";
    file_state_t st = file_state(g_app.selected, f);
    int fetch = !(g_view.th.rgb && g_view.num == f->num) && st != FS_MINE && st != FS_COMING && st != FS_QUEUED && st != FS_BROKEN;
    snprintf(hint, sizeof hint, "%sj/k next/previous \xc2\xb7 %sv in chat \xc2\xb7 esc back", fetch ? "enter fetch \xc2\xb7 " : "",
             f->mine ? "x stop offering \xc2\xb7 " : "d download \xc2\xb7 s save in \xc2\xb7 ");
    return hint;
}

// ---- the help page: every key, then every command ----

static const struct { const char *section, *keys, *what; } HELP_KEYS[] = {
    { "Sessions",    "ctrl+n",          "start a new session" },
    { NULL,          "ctrl+j",          "join a session by its id and password" },
    { NULL,          "tab  shift+tab",  "next / previous session" },
    { NULL,          "ctrl+s",          "settings" },
    { NULL,          "ctrl+c",          "quit, after asking - every session leaves cleanly first" },
    { "Screen",      "ctrl+b",          "show or hide the sidebar" },
    { NULL,          "ctrl+o",          "show or hide the console" },
    { NULL,          "ctrl+t",          "show or hide the chat" },
    { NULL,          "pgup  pgdn",      "scroll the chat back / forward" },
    { NULL,          "f1",              "this page" },
    { "Typing",      "enter",           "send" },
    { NULL,          "/",               "on an empty line: a command (what isn't one stays text)" },
    { NULL,          "@nick  tab",      "finish a nick" },
    { NULL,          "ctrl+w  ctrl+u",  "delete a word / back to the start" },
    { NULL,          "esc",             "NORMAL mode" },
    { "Normal mode", "i  a  I  A",      "type: at / after the cursor, at the start / end" },
    { NULL,          "h  l  0  $  x",   "move, to the start / end, delete" },
    { NULL,          "j  k",            "next / previous session" },
    { NULL,          "ctrl+u  ctrl+d",  "scroll the chat back / forward" },
    { NULL,          "G",               "back to the newest message" },
    { NULL,          "s  c  C",         "show or hide the sidebar / console / chat" },
    { NULL,          "f",               "the files" },
    { NULL,          ":  /",            "the command line" },
    { NULL,          "?",               "this page" },
    { "Files",       "ctrl+f",          "the files offered here, and yours (f in NORMAL)" },
    { NULL,          "enter",           "show a picture big, fetching it first, or download a file" },
    { NULL,          "d  s",            "save in Downloads / in a folder you pick" },
    { NULL,          "v",               "show or hide a picture in the chat" },
    { NULL,          "x",               "stop fetching it, or stop offering yours" },
    { NULL,          "y",               "copy where it was saved" },
    { NULL,          "n",               "send a file" },
    { NULL,          "j  k",            "on a picture: the next / previous one" },
    { "Pages",       "j  k  g  G",      "move, to the first / last" },
    { NULL,          "h  l  enter",     "change a value, go in, choose" },
    { NULL,          "tab  shift+tab",  "next / previous section (pgdn / pgup too)" },
    { NULL,          "1 - 9",           "the first to ninth section" },
    { NULL,          "esc  q",          "back / close" },
};
#define N_HELP_KEYS ((int)(sizeof HELP_KEYS / sizeof HELP_KEYS[0]))
#define MAX_HELP_COMMANDS 32
#define MAX_HELP_ROWS (N_HELP_KEYS + MAX_HELP_COMMANDS)

static void begin_help(void) {
    if (g_app.mode != MODE_CHAT) return;
    g_app.mode = MODE_HELP;
    g_app.dirty = 1;
}

// ---- :changelog ----

// The changelog built into this binary, as paragraphs of Markdown for the page to lay out:
// headings, list items (nested by their indent), numbered items, quotes, fenced code and rules,
// with a paragraph's continuation lines joined. The inline marks stay in the text.
static int changelog_paras(const tui_para_t **out) {
    static tui_para_t paras[1024];
    static char *text;
    static int n = -1;
    if (n >= 0) { *out = paras; return n; }
    n = 0;
    size_t len = strlen(CHANGELOG_TEXT);
    text = malloc(len + 1);
    if (!text) { *out = paras; return 0; }
    memcpy(text, CHANGELOG_TEXT, len + 1);
    const int max = (int)(sizeof paras / sizeof paras[0]) - 1;
    char *para = NULL;   // the paragraph a next line may join, if any
    int fenced = 0;
    for (char *line = text; line && n < max; ) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';
        char *next = eol ? eol + 1 : NULL;
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll - 1] == '\r' || (!fenced && line[ll - 1] == ' '))) line[--ll] = '\0';
        int indent = 0;
        while (line[indent] == ' ') indent++;
        char *raw = line, *t = line + indent;
        line = next;
        if (strncmp(t, "```", 3) == 0 || strncmp(t, "~~~", 3) == 0) {
            fenced = !fenced;
            para = NULL;
            continue;
        }
        if (fenced) {
            paras[n++] = (tui_para_t){ .kind = TUI_P_CODE, .text = raw };
            continue;
        }
        if (*t == '\0') {
            if (n > 0 && paras[n - 1].kind != TUI_P_BLANK) paras[n++] = (tui_para_t){ .kind = TUI_P_BLANK, .text = "" };
            para = NULL;
            continue;
        }
        int hashes = 0;
        while (t[hashes] == '#') hashes++;
        if (hashes > 0 && hashes <= 6 && t[hashes] == ' ') {
            para = NULL;
            if (hashes == 1) continue;   // the file's own title: the page has its own
            paras[n++] = (tui_para_t){ .kind = hashes == 2 ? TUI_P_HEADING : TUI_P_SUBHEADING, .text = t + hashes + 1 };
            continue;
        }
        // A rule: three or more of one of - * _, nothing else but spaces.
        if (*t == '-' || *t == '*' || *t == '_') {
            int marks = 0, other = 0;
            for (const char *p = t; *p; p++) {
                if (*p == *t) marks++;
                else if (*p != ' ') other = 1;
            }
            if (marks >= 3 && !other) {
                paras[n++] = (tui_para_t){ .kind = TUI_P_RULE, .text = "" };
                para = NULL;
                continue;
            }
        }
        if ((*t == '-' || *t == '*' || *t == '+') && t[1] == ' ') {
            para = t + 2;
            paras[n++] = (tui_para_t){ .kind = TUI_P_BULLET, .text = para, .level = indent / 2 };
            continue;
        }
        int digits = 0;
        while (t[digits] >= '0' && t[digits] <= '9') digits++;
        if (digits > 0 && digits <= 6 && (t[digits] == '.' || t[digits] == ')') && t[digits + 1] == ' ') {
            tui_para_t p = { .kind = TUI_P_NUMBERED, .level = indent / 3 };
            memcpy(p.marker, t, (size_t)digits + 1);
            p.marker[digits + 1] = '\0';
            para = t + digits + 2;
            p.text = para;
            paras[n++] = p;
            continue;
        }
        int quote = *t == '>';
        if (quote) { t++; while (*t == ' ') t++; }
        // A line under a paragraph continues it (a quote only continues under a quote). The NUL that
        // ended the paragraph becomes a space.
        if (para && *t && (!quote || paras[n - 1].kind == TUI_P_QUOTE)) {
            size_t pl = strlen(para);
            memmove(para + pl + 1, t, strlen(t) + 1);
            para[pl] = ' ';
            continue;
        }
        para = t;
        paras[n++] = (tui_para_t){ .kind = quote ? TUI_P_QUOTE : TUI_P_TEXT, .text = para };
    }
    while (n > 0 && paras[n - 1].kind == TUI_P_BLANK) n--;
    if (n > 0 && paras[0].kind == TUI_P_BLANK) { memmove(paras, paras + 1, sizeof paras[0] * (size_t)(n - 1)); n--; }
    *out = paras;
    return n;
}

static void begin_changelog(void) {
    if (g_app.mode != MODE_CHAT) return;
    g_app.mode = MODE_CHANGELOG;
    g_app.changelog_scroll = 0;
    g_app.dirty = 1;
}

static void render_changelog(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const tui_para_t *paras;
    int n = changelog_paras(&paras);
    char title[48];
    snprintf(title, sizeof title, "Changelog (v%s here)", CHAT_VERSION);
    g_app.changelog_most = tui_render_text(rows_n, cols_n, title, clock, paras, n, &g_app.changelog_scroll, bar,
                                           g_app.color_enabled);
}

static void changelog_key(const tui_key_t *key) {
    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);
    int page = rows_n > 6 ? rows_n - 4 : 1;
    int *s = &g_app.changelog_scroll;
    switch (key->type) {
        case TUI_KEY_UP:        (*s)--; break;
        case TUI_KEY_DOWN:      (*s)++; break;
        case TUI_KEY_PAGE_UP:   *s -= page; break;
        case TUI_KEY_PAGE_DOWN: *s += page; break;
        case TUI_KEY_HOME:      *s = 0; break;
        case TUI_KEY_END:       *s = g_app.changelog_most; break;
        case TUI_KEY_ESCAPE:
        case TUI_KEY_HELP:      g_app.mode = MODE_CHAT; break;
        case TUI_KEY_CHAR:
            if (key->ch_len != 1) break;
            switch (key->ch[0]) {
                case 'k': (*s)--; break;
                case 'j': (*s)++; break;
                case ' ': *s += page; break;
                case 'b': *s -= page; break;
                case 'g': *s = 0; break;
                case 'G': *s = g_app.changelog_most; break;
                case 'q': g_app.mode = MODE_CHAT; break;
                default: break;
            }
            break;
        default: break;
    }
    if (*s < 0) *s = 0;
    if (*s > g_app.changelog_most) *s = g_app.changelog_most;
    g_app.dirty = 1;
}

// Tab and Shift+Tab: the first row of the next or previous section, round from the last to the first.
static int page_section_step(const tui_row_t *rows, int n, int sel, int dir) {
    while (sel > 0 && !rows[sel].section) sel--;
    for (int k = 1; k < n; k++) {
        int i = ((sel + dir * k) % n + n) % n;
        if (rows[i].section) return i;
    }
    return sel;
}

// The first row of the nth section, or -1 if there aren't that many.
static int page_section_nth(const tui_row_t *rows, int n, int nth) {
    for (int i = 0; i < n; i++) if (rows[i].section && nth-- == 0) return i;
    return -1;
}

// ---- :install, and what it saved ----

// Shown once the screen is up.
#define MAX_SAVED_NOTES 8
static char g_saved_notes[MAX_SAVED_NOTES][240];
static int g_n_saved_notes;

static void saved_note(const char *fmt, ...) {
    if (g_n_saved_notes >= MAX_SAVED_NOTES) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_saved_notes[g_n_saved_notes++], sizeof g_saved_notes[0], fmt, ap);
    va_end(ap);
}

static void say_saved_notes(void) {
    for (int i = 0; i < g_n_saved_notes; i++) push_log("%s", g_saved_notes[i]);
    g_n_saved_notes = 0;
}

// A row's value from the settings file in the form :set takes, otherwise what it should have been.
static const char *row_from_toml(const setting_def_t *d, const toml_value *v, char *out, size_t cap) {
    if (d->kind == K_TOGGLE) {
        if (v->type != TOML_BOOL) return "true or false";
        copy_str(out, v->b ? "on" : "off", cap);
    } else if (d->id == SET_RELAYS) {
        if (v->type != TOML_ARRAY) return "a list of \"wss://...\" strings";
        size_t p = 0;
        out[0] = '\0';
        for (int k = 0; k < v->n; k++) {
            if (k) p = put_text(out, p, cap, " ");
            p = put_text(out, p, cap, v->items[k]);
        }
        if (p >= cap) return "fewer relays";
    } else if (v->type == TOML_INT && (d->id == SET_PORT || d->id == SET_FILE_LIMIT)) {
        snprintf(out, cap, "%lld", v->i);
    } else if (v->type == TOML_STRING && d->id != SET_PORT) {
        copy_str(out, v->s, cap);
    } else {
        return d->id == SET_PORT ? "a number" : "a string in quotes";
    }
    return NULL;
}

// Sets a row from a value in the form :set takes. If it isn't one of the row's values, or can't be
// used, g_app.message says why.
static void apply_row(const setting_def_t *d, const char *value) {
    const char *const *names;
    int n;
    if (setting_options(d->id, &names, &n) >= 0) {
        int i = 0;
        while (i < n && strcmp(value, names[i]) != 0) i++;
        if (i < n) setting_choose(d->id, i);
        else snprintf(g_app.message, sizeof g_app.message, "it takes %s", d->values);
    } else {
        setting_apply_text(d->id, value);
    }
}

typedef struct { char where[920]; } loading_t;

static void load_setting(void *ctx, const char *table, const char *key, const toml_value *tv) {
    loading_t *l = ctx;
    const setting_def_t *d = setting_by_key(key);
    char value[ROW_TEXT_MAX], before[ROW_TEXT_MAX], now[ROW_TEXT_MAX];
    if (!d || strcmp(setting_table(d->id), table) != 0 || !setting_text(d->id, before, sizeof before)) {
        saved_note("* %s: [%.20s] %.40s isn't a setting this chat saves - left out", l->where, table, key);
        return;
    }
    const char *want = row_from_toml(d, tv, value, sizeof value);
    if (want) {
        saved_note("* %s: %s takes %s - left out", l->where, d->key, want);
        return;
    }
    g_app.message[0] = '\0';
    apply_row(d, value);
    // One that didn't apply stays saved anyway, since a tor that's gone now may be back next time.
    setting_text(d->id, now, sizeof now);
    int took = strcmp(now, value) == 0 || strcmp(now, before) != 0;
    if (!took) saved_note("* %s: %s %.60s wasn't used - %s", l->where, d->key, value, g_app.message);
    copy_str(g_saved_rows[settings_index(d->id)], took ? now : value, ROW_TEXT_MAX);
    if (took && d->id == SET_ROUTING) g_app.route_chosen = 1;
}

static void load_saved_settings(void) {
    static char text[INSTALL_SETTINGS_MAX];
    loading_t l;
    char where[900] = "";
    install_where(install_current(), where, sizeof where);
    snprintf(l.where, sizeof l.where, "%s/settings", where);
    long n = install_read_settings(text, sizeof text);
    if (n == INSTALL_NO_FILE) return;
    if (n < 0) { saved_note("* %s is damaged, or isn't sealed with this passphrase - left out", l.where); return; }
    // Like the startup settings page, nothing goes on the network meanwhile.
    int was = g_app.onboarding, bad_line = 0;
    g_app.onboarding = 1;
    int bad = toml_parse(text, load_setting, &l, &bad_line);
    g_app.onboarding = was;
    g_app.message[0] = '\0';
    crypto_wipe(text, sizeof text);
    if (bad) saved_note("* %s: %d line%s it can't read, from line %d - left out", l.where, bad, bad == 1 ? "" : "s", bad_line);
}

// Format, kind, origin, scalar flag, and the creation time a PGP key made here has (its
// fingerprint covers it), then the public key. Format 1 follows it with the secret key. Format 2,
// for a key from a file, with the file's full path instead, so the secret key isn't copied: the
// file is read again when it's opened. The public key tells whether the file still holds that key.
#define KEY_BLOB_HEAD (8 + ID_SIGN_PUB_LEN)
#define KEY_BLOB_LEN (KEY_BLOB_HEAD + ID_SIGN_PRIV_LEN)
#define KEY_BLOB_MAX (KEY_BLOB_HEAD + KEY_PATH_MAX)
_Static_assert(KEY_BLOB_MAX <= INSTALL_KEY_MAX, "a sealed key has room for the signing key or its path");

static int key_saved_as_path(void) {
    return g_app.key_origin == KEY_FILE && g_app.key_path[0];
}

// Returns the length.
static size_t identity_pack(uint8_t out[KEY_BLOB_MAX]) {
    int path = key_saved_as_path();
    out[0] = path ? 2 : 1;
    out[1] = (uint8_t)g_app.identity_source;
    out[2] = (uint8_t)g_app.key_origin;
    out[3] = (uint8_t)(g_app.identity.scalar != 0);
    for (int i = 0; i < 4; i++) out[4 + i] = (uint8_t)(g_app.pgp_created >> (24 - 8 * i));
    memcpy(out + 8, g_app.identity.pub, ID_SIGN_PUB_LEN);
    if (!path) {
        memcpy(out + KEY_BLOB_HEAD, g_app.identity.priv, ID_SIGN_PRIV_LEN);
        return KEY_BLOB_LEN;
    }
    size_t n = strlen(g_app.key_path);
    memcpy(out + KEY_BLOB_HEAD, g_app.key_path, n);
    return KEY_BLOB_HEAD + n;
}

// The saved key's public half (and path) is kept even when it isn't used, to tell whether the key
// in use is the same one. A key file that's gone or changed is said why with saved_note.
static int identity_unpack(const uint8_t *in, size_t len, int use) {
    if (len < KEY_BLOB_HEAD || (in[0] != 1 && in[0] != 2) || (in[1] != IDENT_AGE && in[1] != IDENT_PGP)
        || in[2] > KEY_PASTED || in[3] > 1)
        return -1;
    int path = in[0] == 2;
    if (path ? in[2] != KEY_FILE || len == KEY_BLOB_HEAD || len >= KEY_BLOB_MAX : len != KEY_BLOB_LEN) return -1;
    char saved_path[KEY_PATH_MAX] = "";
    if (path) {
        memcpy(saved_path, in + KEY_BLOB_HEAD, len - KEY_BLOB_HEAD);
        saved_path[len - KEY_BLOB_HEAD] = '\0';
        if (strlen(saved_path) != len - KEY_BLOB_HEAD) return -1;
    }
    memcpy(g_app.saved_key_pub, in + 8, ID_SIGN_PUB_LEN);
    copy_str(g_app.saved_key_path, saved_path, sizeof g_app.saved_key_path);
    g_app.saved_key_known = 1;
    if (!use) return 0;
    identity_source_t kind = (identity_source_t)in[1];
    identity_keypair_t kp;
    char full[KEY_PATH_MAX];
    if (path) {
        char shown[KEY_PATH_MAX];
        tilde_path(saved_path, shown, sizeof shown);
        if (read_key_file(kind, saved_path, &kp, full, sizeof full) != 0) {
            saved_note("* your saved signing key's file %.200s can't be read, or no longer holds %s secret key - "
                       "it isn't used, and :set sign picks a key", shown, kind == IDENT_AGE ? "an AGE" : "a PGP");
            crypto_wipe(&kp, sizeof kp);
            return 0;
        }
        if (crypto_equal(kp.pub, g_app.saved_key_pub, ID_SIGN_PUB_LEN) != 0)
            saved_note("* %.200s holds a different key from the one :install saved - chat signs with it, and "
                       ":install records it", shown);
    } else {
        kp.scalar = in[3];
        memcpy(kp.pub, in + 8, ID_SIGN_PUB_LEN);
        memcpy(kp.priv, in + KEY_BLOB_HEAD, ID_SIGN_PRIV_LEN);
    }
    g_app.identity = kp;
    crypto_wipe(&kp, sizeof kp);
    g_app.identity_source = kind;
    g_app.key_origin = (key_origin_t)in[2];
    g_app.pgp_created = (uint32_t)in[4] << 24 | (uint32_t)in[5] << 16 | (uint32_t)in[6] << 8 | in[7];
    // A key file saved as the key itself, before :install saved paths, has no path to show.
    copy_str(g_app.key_path, saved_path, sizeof g_app.key_path);
    return 0;
}

// 0, a PASS_ code or INSTALL_NO_FILE. The identity in use is only changed on success.
static int open_saved_key(int use) {
    uint8_t blob[INSTALL_KEY_MAX];
    size_t len = 0;
    int rc = install_read_key(blob, sizeof blob, &len);
    if (rc == 0 && identity_unpack(blob, len, use) != 0) rc = PASS_FORMAT;
    crypto_wipe(blob, sizeof blob);
    return rc;
}

// A save needing a code that wasn't given, by open_saved.
#define OPEN_NO_CODE (-20)

static const char *open_error(int rc) {
    static char why[320];
    switch (rc) {
        case PASS_WRONG:
            return install_factors(install_current()) & INSTALL_FACTOR_KEY
                ? "that passphrase doesn't open what :install saved, with that security key"
                : "that passphrase doesn't open what :install saved";
        case PASS_NOMEM:      return "opening what :install saved needs 512 MiB of free memory for a moment";
        case INSTALL_NO_FILE: return "what :install saved isn't there any more";
        case INSTALL_KEY:     return "what :install saved needs its security key";
        case INSTALL_DEVICE:
            snprintf(why, sizeof why, "what :install saved only opens on the device it's locked to: %s", install_why());
            return why;
        case INSTALL_LOST:
            snprintf(why, sizeof why, "what :install saved can't be opened: %s", install_why());
            return why;
        case INSTALL_DESTROYED:
            snprintf(why, sizeof why, "what :install saved has been deleted - %s", install_why());
            return why;
        case OPEN_NO_CODE:    return "what :install saved needs the code your authenticator app shows";
        default:              return "what :install saved is damaged, or isn't something chat wrote";
    }
}

// The verified keys (core/trust.h) are saved each time they change, while what :install saved is
// open, its verified file could be read and autosave is on. trust_saved() says whether they are.
static int g_verified_ok;

static void verified_saving(int ok) {
    g_verified_ok = ok;
    trust_set_saved(ok && g_app.autosave);
}

static void save_verified(void) {
    if (!trust_saved() || !g_app.installed || g_app.locked) return;
    static char text[TRUST_TEXT_MAX];
    if (trust_text(text, sizeof text) == 0 && install_write_verified(text) == 0) return;
    char where[900] = "";
    install_where(install_current(), where, sizeof where);
    push_log("* couldn't save the verified keys in %s/verified - they last until chat exits", where);
}

// Turned on, it saves the keys verified or forgotten meanwhile. The rows are keep_settings_saved's.
static void autosave_changed(void) {
    verified_saving(g_verified_ok);
    if (g_app.autosave) save_verified();
}

// Adds the saved verified keys to the ones in use. 0, or a PASS_ code.
static int load_saved_verified(void) {
    static char text[INSTALL_VERIFIED_MAX + 1];
    char where[900] = "";
    install_where(install_current(), where, sizeof where);
    long n = install_read_verified(text, sizeof text);
    if (n == INSTALL_NO_FILE) return 0;
    if (n < 0) {
        saved_note("* %s/verified is damaged, or isn't sealed with this passphrase - left out", where);
        return (int)n;
    }
    int bad = trust_load(text);
    crypto_wipe(text, sizeof text);
    if (bad) saved_note("* %s/verified: %d line%s it can't read - left out", where, bad, bad == 1 ? "" : "s");
    return 0;
}

static void reapply_options(void);

// The factors the open save needs, as its rows show them.
static void factors_in_use(void) {
    unsigned f = install_open_factors();
    g_app.device_lock = (f & INSTALL_FACTOR_DEVICE) != 0;
    g_app.key_factor = (f & INSTALL_FACTOR_KEY) != 0;
    g_app.code_factor = (f & INSTALL_FACTOR_CODE) != 0;
}

static int *factor_flag(unsigned factor) {
    return factor == INSTALL_FACTOR_DEVICE ? &g_app.device_lock
         : factor == INSTALL_FACTOR_KEY ? &g_app.key_factor : &g_app.code_factor;
}

static const char *factor_label(unsigned factor) {
    return factor == INSTALL_FACTOR_DEVICE ? "Device lock"
         : factor == INSTALL_FACTOR_KEY ? "Security key" : "Authenticator app";
}

// What f needs, for a sentence: "this device and the security key".
static void factors_text(unsigned f, char *out, size_t cap) {
    const char *part[3];
    int n = 0;
    if (f & INSTALL_FACTOR_DEVICE) part[n++] = "this device";
    if (f & INSTALL_FACTOR_KEY) part[n++] = "the security key";
    if (f & INSTALL_FACTOR_CODE) part[n++] = "an authenticator code";
    size_t p = 0;
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        if (i) p = put_text(out, p, cap, i < n - 1 ? ", " : n == 2 ? " and " : ", and ");
        p = put_text(out, p, cap, part[i]);
    }
}

// The save just opened is the one in use from now on: its settings, then the command line options
// again so they still override them, then the key unless --identity chose another. Rows its
// settings don't have keep their value. loaded, if given, gets each row's value before the options
// are applied again.
static void use_opened_save(char (*loaded)[ROW_TEXT_MAX]) {
    g_app.installed = 1;
    g_app.locked = 0;
    factors_in_use();
    g_app.destroy_limit = install_destroy_limit(install_current());
    char needs[96];
    factors_text(install_open_factors(), needs, sizeof needs);
    if (install_relocked() > 0)
        saved_note("* the save %s was only part way through a change to what it needs: chat stopped while changing it, "
                   "or one of its files was replaced. It's sealed again needing %s - :set changes that",
                   install_shown_name(install_current()), needs);
    else if (install_relocked() < 0)
        saved_note("* the save %s is only part way through a change to what it needs, and couldn't be sealed again: %s",
                   install_shown_name(install_current()), install_why());
    memcpy(g_saved_rows, g_setting_defaults, sizeof g_saved_rows);
    load_saved_settings();
    for (int i = 0; loaded && i < N_SETTINGS; i++)
        if (!setting_text(SETTINGS[i].id, loaded[i], ROW_TEXT_MAX)) loaded[i][0] = '\0';
    // A damaged file isn't overwritten by the keys verified this run.
    verified_saving(load_saved_verified() == 0);
    reapply_options();
    note_settings_seen();
    g_app.saved_key_known = 0;
    g_app.saved_key_path[0] = '\0';
    int rc = open_saved_key(!g_opts.identity[0]);
    if (rc != 0 && rc != INSTALL_NO_FILE)
        saved_note("* your saved signing key is damaged, or isn't sealed with this passphrase - it's left out");
}

// Before the screen is up: the save's security key, waited for here. 0 once it's given its secret.
static int key_in_terminal(const char *name) {
    char pin[64] = "";
    for (int tries = 0; tries < 4; tries++) {
        if (install_key_open(name, pin[0] ? pin : NULL) != 0) break;
        crypto_wipe(pin, sizeof pin);
        int stage = -1, said = -1;
        install_key_state_t st;
        while ((st = install_key_poll(&stage, NULL)) == INSTALL_KEY_RUNNING) {
            if (stage != said && stage != SECKEY_BUSY) {
                fprintf(stderr, "chat: %s\n", stage == SECKEY_LOOKING ? "plug in the save's security key"
                                              : "touch your security key (it's blinking)");
                said = stage;
            }
            platform_sleep_ms(50);
        }
        if (st == INSTALL_KEY_DONE) return 0;
        if (st != INSTALL_KEY_PIN || !term_is_tty()) break;
        fprintf(stderr, "chat: %s\n", install_key_why());
        if (term_read_password("security key PIN: ", pin, sizeof pin) != 0 || !pin[0]) return -1;
    }
    crypto_wipe(pin, sizeof pin);
    fprintf(stderr, "chat: the security key: %s\n", install_key_why());
    return -1;
}

static int code_in_terminal(void) {
    for (int tries = 0; tries < 5 && term_is_tty(); tries++) {
        char line[32] = "";
        if (term_read_line("the code your authenticator app shows: ", line, sizeof line) != 0) return -1;
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (!line[0]) return -1;
        int rc = install_check_code(line);
        if (rc == 0) return 0;
        fprintf(stderr, "chat: %s\n", rc == PASS_FORMAT ? "a code is 6 digits"
                                      : "that isn't the code it shows - check the clocks of this computer and the phone");
    }
    return -1;
}

// 0, or the reason it stayed sealed. Before the screen is up, so a security key is waited for, and a
// code typed, in the terminal.
static int open_saved(const char *name, const char *passphrase) {
    if ((install_factors(name) & INSTALL_FACTOR_KEY) && !install_key_ready(name) && key_in_terminal(name) != 0)
        return INSTALL_KEY;
    int rc = install_unlock(name, passphrase);
    if (rc != 0) return rc;
    if (install_code_pending() && code_in_terminal() != 0) {
        install_code_cancel();
        return OPEN_NO_CODE;
    }
    use_opened_save(NULL);
    return 0;
}

// What a save holds, what it needs to open and when it was last written, for the list to pick one from.
static void save_detail(const install_save_t *sv, char *out, size_t cap) {
    snprintf(out, cap, "%s%s%s%s%s%s", sv->settings && sv->key ? "settings and key" : sv->settings ? "settings" : "key",
             sv->factors & INSTALL_FACTOR_DEVICE ? " \xc2\xb7 this device only" : "",
             sv->factors & INSTALL_FACTOR_KEY ? " \xc2\xb7 security key" : "",
             sv->factors & INSTALL_FACTOR_CODE ? " \xc2\xb7 code" : "", sv->modified[0] ? " \xc2\xb7 " : "", sv->modified);
}

// With more than one save and no --save, one is picked from a list before its passphrase is asked for.
static int save_to_pick(void) { return g_app.n_saves > 1 && !g_opts.save[0]; }

// The saves, numbered, then a number or name typed in. 0 once one is in use, -1 for none.
static int pick_save_in_terminal(void) {
    printf("chat: :install made %d saves here, each sealed with its own passphrase:\n", g_app.n_saves);
    for (int i = 0; i < g_app.n_saves; i++) {
        char detail[112];
        save_detail(&g_app.saves[i], detail, sizeof detail);
        printf("  %2d  %-*s  %s\n", i + 1, INSTALL_NAME_MAX < 16 ? INSTALL_NAME_MAX : 16,
               install_shown_name(g_app.saves[i].name), detail);
    }
    for (int tries = 0; tries < 3; tries++) {
        char line[64] = "";
        if (term_read_line("which one to open (number or name, blank: none): ", line, sizeof line) != 0) return -1;
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' || line[n - 1] == ' ')) line[--n] = '\0';
        if (!line[0]) return -1;
        char *end;
        long num = strtol(line, &end, 10);
        for (int i = 0; i < g_app.n_saves; i++) {
            if ((!*end && num == i + 1) || strcmp(line, install_shown_name(g_app.saves[i].name)) == 0) {
                install_use(g_app.saves[i].name);
                return 0;
            }
        }
        fprintf(stderr, "chat: there's no save %s\n", line);
    }
    return -1;
}

// From CHAT_INSTALL_PASSWORD, otherwise asked for in a box once the screen is up, or in the terminal.
// With more than one save and no --save, CHAT_INSTALL_PASSWORD opens the first one it can that needs
// no security key or code, and otherwise the one to open is picked first. A save that needs them
// takes the passphrase from it, and asks for them in the box, or in the terminal.
static void unlock_at_start(int in_box) {
    g_app.locked = 1;
    char pw[256] = "";
    int from_env = platform_env_take("CHAT_INSTALL_PASSWORD", pw, sizeof pw) == 0;
    const unsigned more = INSTALL_FACTOR_KEY | INSTALL_FACTOR_CODE;
    if (from_env && in_box && !save_to_pick() && (install_factors(install_current()) & more)) {
        copy_str(g_app.install_pass, pw, sizeof g_app.install_pass);
        crypto_wipe(pw, sizeof pw);
        g_app.unlock_env = g_app.unlock_at_start = 1;
        return;
    }
    if (from_env) {
        int rc = PASS_WRONG, elsewhere = 0;
        if (!save_to_pick()) rc = open_saved(install_current(), pw);
        else for (int i = 0; i < g_app.n_saves && (rc == PASS_WRONG || rc == INSTALL_DEVICE); i++) {
            if (g_app.saves[i].factors & more) continue;
            rc = open_saved(g_app.saves[i].name, pw);
            elsewhere |= rc == INSTALL_DEVICE;
        }
        crypto_wipe(pw, sizeof pw);
        if (rc == 0) return;
        saved_note("* CHAT_INSTALL_PASSWORD: %s", rc == PASS_WRONG && save_to_pick()
                   ? (elsewhere ? "that passphrase doesn't open any of the saves :install made that open on this device"
                                : "that passphrase doesn't open any of the saves :install made")
                   : open_error(rc));
    }
    if (in_box) { g_app.unlock_at_start = 1; return; }
    int picked = !save_to_pick() || (term_is_tty() && pick_save_in_terminal() == 0);
    for (int tries = 0; tries < 3 && picked && term_is_tty(); tries++) {
        char prompt[96];
        snprintf(prompt, sizeof prompt, "passphrase for %s%s (blank: start without it): ",
                 g_app.n_saves > 1 ? "the save " : "what :install saved",
                 g_app.n_saves > 1 ? install_shown_name(install_current()) : "");
        if (term_read_password(prompt, pw, sizeof pw) != 0 || !pw[0]) break;
        int rc = open_saved(install_current(), pw);
        crypto_wipe(pw, sizeof pw);
        if (rc == 0) return;
        fprintf(stderr, "chat: %s\n", open_error(rc));
        if (rc != PASS_WRONG) break;
    }
    crypto_wipe(pw, sizeof pw);
    saved_note("* what :install saved stays sealed: this run starts from chat's defaults and saves nothing%s",
               from_env ? "" : " (CHAT_INSTALL_PASSWORD opens it)");
}

// The same key, saved the same way: by its file's path for a key file, otherwise as the key. A key
// file saved as the key, before :install saved paths, counts as saved until it's picked again.
static int key_in_use_saved(void) {
    return g_app.identity_source != IDENT_NONE && g_app.saved_key_known
        && crypto_equal(g_app.saved_key_pub, g_app.identity.pub, ID_SIGN_PUB_LEN) == 0
        && strcmp(g_app.saved_key_path, key_saved_as_path() ? g_app.key_path : "") == 0;
}

// The verified keys in use when the open save was uninstalled. They last until chat exits, or until
// :install opens another save, which has its own.
static uint8_t g_uninstalled_keys[TRUST_MAX][ID_SIGN_PUB_LEN];
static int g_n_uninstalled_keys;

static int is_current_save(const char *name);

// A new passphrase first, since Argon2id is the slow part and can fail if there isn't enough
// memory. Then the settings, which are always there, then a key not saved yet, sealed under the
// same passphrase.
static void finish_install(const char *passphrase) {
    int resave = !passphrase && g_app.installed && is_current_save(g_app.save_target);
    char where[900] = "";
    install_where(g_app.save_target, where, sizeof where);
    if (passphrase) {
        note(g_app.device_lock ? "sealing, and locking it to this device..." : "sealing...");
        render();
        // With the device lock on, a save that can't be locked isn't made at all, and likewise for the
        // security key and the code set up for it.
        unsigned factors = (g_app.device_lock ? INSTALL_FACTOR_DEVICE : 0) | (g_app.key_factor ? INSTALL_FACTOR_KEY : 0)
                         | (g_app.code_factor ? INSTALL_FACTOR_CODE : 0);
        int rc = install_lock_new(g_app.save_target, passphrase, factors);
        if (rc == INSTALL_DEVICE) {
            push_log("* not installed: it can't be locked to this device - %s", install_why());
            note("not installed: it can't be locked to this device - %s", install_why());
            install_setup_forget();
            return;
        }
        if (rc == PASS_NOMEM) {
            note("not installed: sealing needs 512 MiB of free memory for a moment");
            install_setup_forget();
            return;
        }
        if (rc != 0) {
            note("not installed: %s", install_why());
            install_setup_forget();
            return;
        }
        // A new save has no key in it yet.
        g_app.saved_key_known = 0;
        g_app.saved_key_path[0] = '\0';
    }
    // Everything in use, including the options.
    note_settings_seen();
    memcpy(g_saved_rows, g_seen_rows, sizeof g_saved_rows);
    static char text[INSTALL_SETTINGS_MAX];
    if (settings_text(text, sizeof text) != 0 || install_write_settings(text) != 0) {
        if (passphrase) {
            // A new save leaves nothing behind, not even its device or security key files.
            if (install_open_factors()) install_remove(g_app.save_target);
            install_forget();
            g_app.installed = 0;
        }
        note("couldn't write your settings to %s%s", where, g_app.installed ? "" : " - not installed");
        return;
    }
    g_app.installed = 1;
    g_app.locked = 0;
    factors_in_use();
    install_arm_destroy(g_app.save_target, (unsigned)g_app.destroy_limit);
    // A new save, or one saved over, gets every key in use.
    g_n_uninstalled_keys = 0;
    static char vtext[TRUST_TEXT_MAX];
    int verified = trust_text(vtext, sizeof vtext) == 0 && install_write_verified(vtext) == 0;
    verified_saving(verified);
    if (!verified) push_log("* couldn't write the verified keys to %s - they last until chat exits", where);
    int key = g_app.identity_source != IDENT_NONE && !key_in_use_saved();
    int path = key && key_saved_as_path();
    if (key) {
        uint8_t blob[KEY_BLOB_MAX];
        size_t len = identity_pack(blob);
        int rc = install_write_key(blob, len);
        crypto_wipe(blob, sizeof blob);
        if (rc != 0) { note("your settings are saved, but your signing key couldn't be written to %s", where); return; }
        memcpy(g_app.saved_key_pub, g_app.identity.pub, ID_SIGN_PUB_LEN);
        copy_str(g_app.saved_key_path, path ? g_app.key_path : "", sizeof g_app.saved_key_path);
        g_app.saved_key_known = 1;
    }
    char needs[96], also[120] = "";
    factors_text(install_open_factors(), needs, sizeof needs);
    if (needs[0]) snprintf(also, sizeof also, ", needing %s as well as the passphrase", needs);
    push_log("* %s: your settings%s are in %s, sealed%s, for next time. :uninstall deletes them",
             resave ? "saved" : "installed", path ? " and your signing key's path" : key ? " and signing key" : "", where,
             also);
    if (passphrase && g_app.device_lock) push_log("%s", DEVICE_REMINDER);
    if (passphrase && g_app.key_factor) push_log("%s", KEY_REMINDER);
    note("%s in %s", resave ? "saved" : "installed", where);
}

// If installed, it saves under the passphrase it has. Otherwise existing files need their own
// passphrase, and if there's nothing there it needs a new one, with or without a key.
// Another save than the one in use is switched to only once it's sealed or opened.
static int is_current_save(const char *name) {
    return strcmp(install_shown_name(name), install_shown_name(install_current())) == 0;
}

static int save_exists(const char *name) { return install_has_settings(name) || install_has_key(name); }

static void pick_random_save_name(void) {
    do random_nickname(g_app.save_random, sizeof g_app.save_random);
    while (save_exists(g_app.save_random));
}

// :install for the save that's open and installed already only saves what's in use to it.
static int install_resaves(void) { return g_app.installed && is_current_save(g_app.save_target); }

// :install is over, whether or not it made or opened a save, and its boxes go. A new save has the
// factor it was for set up already; a save it opened is asked about it now; with nothing open, the
// row is off again.
static void install_ended(void) {
    unsigned f = g_app.install_for;
    g_app.install_for = 0;
    if (g_app.install_back == MODE_SETTINGS && g_app.mode == MODE_CHAT) g_app.mode = MODE_SETTINGS;
    if (!f) return;
    if (!g_app.installed) *factor_flag(f) = 0;
    else if (install_open_factors() & f) return;
    else if (f == INSTALL_FACTOR_DEVICE) device_lock_choose(1);
    else factor_choose(f, 1);
}

static void cancel_install(void) {
    crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
    install_setup_forget();
    end_prompt();
    note(install_resaves() ? "not saved - nothing was written" : "not installed - nothing was written");
    install_ended();
}

static void to_install_mode(app_mode_t mode) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    g_app.mode = mode;
    g_app.dirty = 1;
}

static void not_installed(const char *fmt, const char *why) {
    install_setup_forget();
    end_prompt();
    note(fmt, why);
    install_ended();
}

// What a new save needs is set up before its passphrase, one box after another: the device lock's,
// which says what would lose the save for good, then the security key's, with its touches, then the
// authenticator's QR code. after is the step just done.
enum { STEP_START, STEP_DEVICE, STEP_KEY, STEP_CODE };

static void install_step(int after) {
    if (after < STEP_DEVICE && g_app.device_lock) {
        device_check();
        if (g_app.device_kind == DEVICE_NONE) {
            not_installed("not installed: it can't be locked to this device - %s", g_app.device_why);
            return;
        }
        g_app.device_want = g_app.device_new = 1;
        g_app.device_back = g_app.install_back;
        g_app.mode = MODE_DEVICE_LOCK;
        g_app.dirty = 1;
        return;
    }
    g_app.factor_want = g_app.factor_new = 1;
    g_app.factor_back = g_app.install_back;
    if (after < STEP_KEY && g_app.key_factor) {
        device_check();
        if (!g_app.seckey_ok) {
            not_installed("not installed: a security key can't be used here - %s", g_app.seckey_why);
            return;
        }
        g_app.factor = INSTALL_FACTOR_KEY;
        to_install_mode(MODE_FACTOR);
        return;
    }
    if (after < STEP_CODE && g_app.code_factor) {
        g_app.factor = INSTALL_FACTOR_CODE;
        install_code_new(g_app.save_target, g_app.code_b32, sizeof g_app.code_b32, g_app.code_uri, sizeof g_app.code_uri);
        g_app.code_qr = 0;
        to_install_mode(MODE_CODE_SETUP);
        return;
    }
    g_app.factor_new = 0;
    to_install_mode(MODE_INSTALL_PASS);
}

static void install_confirmed(void) {
    if (install_resaves()) {
        end_prompt();
        finish_install(NULL);
        install_ended();
        return;
    }
    install_step(STEP_START);
}

// No save is open and there are saves: use one, which needs its passphrase, or make a new save.
static void install_use_existing(void) {
    g_app.install_overwrite = 0;
    to_install_mode(g_app.install_pick ? MODE_INSTALL_PICK : MODE_INSTALL_UNLOCK);
}
static void install_new_save(void) {
    pick_random_save_name();
    to_install_mode(MODE_INSTALL_NAME);
}
static void back_to_existing(void) { to_install_mode(MODE_INSTALL_EXISTING); }
// With no saves there, the name was the first box: there's nothing to go back to.
static void back_from_install_name(void) {
    if (g_app.n_saves > 0) back_to_existing();
    else cancel_install();
}

static void install_pick_key(const tui_key_t *key) {
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT:
            copy_str(g_app.save_target, g_app.saves[g_app.save_sel].name, sizeof g_app.save_target);
            to_install_mode(MODE_INSTALL_UNLOCK);
            break;
        case LIST_LEFT:
        case LIST_BACK:  back_to_existing(); break;
        case LIST_CLOSE: cancel_install(); break;
        default:
            list_move(k, &g_app.save_sel, g_app.n_saves);
            g_app.dirty = 1;
            break;
    }
}

// While a save is open, saving over another one needs that save's passphrase.
static void install_overwrite_yes(void) {
    g_app.install_overwrite = 1;
    to_install_mode(MODE_INSTALL_UNLOCK);
}

static void back_from_install_unlock(void) {
    to_install_mode(g_app.install_overwrite ? MODE_INSTALL_OVERWRITE
                    : g_app.install_pick ? MODE_INSTALL_PICK : MODE_INSTALL_EXISTING);
}

// y, n, or Esc and q.
static void choice_key(const tui_key_t *key, void (*yes)(void), void (*no)(void), void (*esc)(void)) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') yes();
    else if (ch == 'n' || ch == 'N') no();
    else if (ch == 'q' || key->type == TUI_KEY_ESCAPE) esc();
}

static void commit_install_name(void) {
    char name[64];
    copy_str(name, g_app.input.buf, sizeof name);
    size_t n = strlen(name);
    while (n > 0 && name[n - 1] == ' ') name[--n] = '\0';
    const char *p = name;
    while (*p == ' ') p++;
    if (!*p) p = g_app.save_random;
    if (install_name_ok(p) != 0) { note("a save's name is 1 to %d letters, digits, - and _", INSTALL_NAME_MAX); return; }
    if (save_exists(p)) { note("there's a save called %s already - pick another name", install_shown_name(p)); return; }
    copy_str(g_app.save_target, strcmp(p, "default") == 0 ? "" : p, sizeof g_app.save_target);
    // What it leaves on disk, then its passphrase.
    to_install_mode(MODE_INSTALL);
}

static void commit_install_pass(void) {
    if (!g_app.input.buf[0]) { note("what's saved needs a passphrase - or Esc to cancel"); return; }
    copy_str(g_app.install_pass, g_app.input.buf, sizeof g_app.install_pass);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    g_app.mode = MODE_INSTALL_PASS2;
    g_app.dirty = 1;
}

static void commit_install_pass2(void) {
    int same = strcmp(g_app.input.buf, g_app.install_pass) == 0;
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (!same) {
        crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
        g_app.mode = MODE_INSTALL_PASS;
        note("they weren't the same - type the passphrase again");
        return;
    }
    char pw[sizeof g_app.install_pass];
    copy_str(pw, g_app.install_pass, sizeof pw);
    crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
    end_prompt();
    finish_install(pw);
    crypto_wipe(pw, sizeof pw);
    install_ended();
}

// The save :install just opened is used from now on, as if it had been opened at the start, with
// these differences. A setting changed this run isn't put back to its command line option. One the
// save doesn't have keeps its value and is saved to it, and so are keys verified this run. Keys from
// a save uninstalled this run are left out.
static void use_save_now(void) {
    static char ran[N_SETTINGS][ROW_TEXT_MAX], loaded[N_SETTINGS][ROW_TEXT_MAX];
    int changed[N_SETTINGS];
    for (int i = 0; i < N_SETTINGS; i++) {
        if (!setting_text(SETTINGS[i].id, ran[i], sizeof ran[i])) ran[i][0] = '\0';
        changed[i] = strcmp(ran[i], g_seen_rows[i]) != 0;
    }
    int dropped = 0;
    for (int i = trust_count() - 1; i >= 0; i--)
        for (int k = 0; k < g_n_uninstalled_keys; k++)
            if (crypto_equal(trust_at(i)->pub, g_uninstalled_keys[k], ID_SIGN_PUB_LEN) == 0) {
                trust_remove(i);
                dropped++;
                break;
            }
    g_n_uninstalled_keys = 0;
    int verified_here = trust_count();
    identity_source_t src = g_app.identity_source;
    uint8_t pub[ID_SIGN_PUB_LEN];
    memcpy(pub, g_app.identity.pub, sizeof pub);

    g_hold_sessions = 1;
    int was = g_app.onboarding;
    g_app.onboarding = 1;
    use_opened_save(loaded);
    // A row the save doesn't have is at its default in g_saved_rows.
    int keep = 0;
    for (int i = 0; i < N_SETTINGS; i++) {
        const setting_def_t *d = &SETTINGS[i];
        char now[ROW_TEXT_MAX];
        if (!changed[i] || !setting_text(d->id, now, sizeof now)) continue;
        if (strcmp(now, loaded[i]) != 0) {
            g_app.message[0] = '\0';
            apply_row(d, loaded[i]);
            setting_text(d->id, now, sizeof now);
            if (strcmp(now, loaded[i]) != 0) saved_note("* %s %.60s wasn't used - %s", d->key, loaded[i], g_app.message);
            else if (d->id == SET_ROUTING) g_app.route_chosen = 1;
        }
        if (strcmp(g_saved_rows[i], g_setting_defaults[i]) != 0 || strcmp(now, ran[i]) != 0) continue;
        copy_str(g_saved_rows[i], now, sizeof g_saved_rows[i]);
        keep = 1;
    }
    g_app.message[0] = '\0';
    g_app.onboarding = was;
    g_hold_sessions = 0;
    note_settings_seen();

    const char *shown = install_shown_name(install_current());
    char where[900] = "";
    install_where(install_current(), where, sizeof where);
    if (keep) {
        static char text[INSTALL_SETTINGS_MAX];
        if (settings_text(text, sizeof text) != 0 || install_write_settings(text) != 0)
            push_log("* couldn't save the settings changed this run in %s/settings - they last until chat exits", where);
    }
    if (verified_here > 0) save_verified();
    settings_to_sessions();
    // As at the end of the startup settings page: :update's proxy, and a tor for Tor mode.
    if (!g_app.onboarding) {
        sync_update_proxy();
        tor_link_ensure(now_seconds());
    }
    say_saved_notes();
    // The rows the save changed, by name. All the names fit.
    char rows[320] = "";
    size_t rp = 0;
    int row_ids[N_SETTINGS], n_rows = 0;
    for (int i = 0; i < N_SETTINGS; i++) {
        char now[ROW_TEXT_MAX];
        if (setting_text(SETTINGS[i].id, now, sizeof now) && strcmp(now, ran[i]) != 0) row_ids[n_rows++] = i;
    }
    for (int k = 0; k < n_rows; k++) {
        rp = put_text(rows, rp, sizeof rows, k == 0 ? "" : k == n_rows - 1 ? " and " : ", ");
        rp = put_text(rows, rp, sizeof rows, SETTINGS[row_ids[k]].key);
    }
    if (n_rows) push_log("* the save %s changed %s - :set shows the values", shown, rows);
    if (dropped)
        push_log("* %d verified key%s from the save you uninstalled %s left out: each save keeps its own "
                 "(:verified lists them)", dropped, dropped == 1 ? "" : "s", dropped == 1 ? "is" : "are");
    if (g_app.identity_source != src || crypto_equal(pub, g_app.identity.pub, ID_SIGN_PUB_LEN) != 0) identity_chosen();
    else say_key_saved_state();
    push_log("* opened the save %s in %s: its settings are in use%s, and %s", shown, where,
             keep ? ", with the ones changed this run that it doesn't have" : "",
             g_app.autosave ? "changes are saved to it" : "autosave is off, so :save saves changes to it");
    note("opened the save %s", shown);
}

static void install_unlock_done(int rc) {
    end_prompt();
    if (rc != 0) {
        if (rc == INSTALL_NO_FILE && is_current_save(g_app.save_target)) g_app.locked = 0;
        note("%s: %s", g_app.install_overwrite ? "not installed" : "not opened", open_error(rc));
        install_ended();
        return;
    }
    if (!g_app.install_overwrite) { use_save_now(); install_ended(); return; }
    g_app.saved_key_known = 0;
    g_app.saved_key_path[0] = '\0';
    open_saved_key(0);
    // The keys verified in an earlier run are kept, with the ones verified in this one added.
    load_saved_verified();
    say_saved_notes();
    finish_install(NULL);
    install_ended();
}

// The passphrase is in install_pass, and the save's security key has given its secret, if it needs one.
static void install_unlock_result(int rc) {
    g_app.mode = MODE_INSTALL_UNLOCK;
    if (rc == PASS_WRONG) { note("that passphrase doesn't open the save %s", install_shown_name(g_app.save_target)); return; }
    if (rc == PASS_NOMEM) { note("%s", open_error(rc)); return; }
    if (rc == 0 && install_code_pending()) {
        g_app.key_purpose = KP_INSTALL_UNLOCK;
        g_app.message[0] = '\0';
        to_install_mode(MODE_UNLOCK_CODE);
        return;
    }
    install_unlock_done(rc);
}

static void unlock_go(key_purpose_t why);

// What's in use stays in use. The passphrase only opens what's saved, so it can be overwritten.
static void commit_install_unlock(void) {
    if (!g_app.input.buf[0]) { note("type its passphrase - or Esc to go back"); return; }
    copy_str(g_app.install_pass, g_app.input.buf, sizeof g_app.install_pass);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    unlock_go(KP_INSTALL_UNLOCK);
}

static void uninstall_confirmed(void) {
    end_prompt();
    char where[900] = "";
    install_where(g_app.save_target, where, sizeof where);
    if (install_remove(g_app.save_target) != 0) { note("couldn't delete everything chat saved in %s", where); return; }
    if (!is_current_save(g_app.save_target)) {
        push_log("* uninstalled: the save %s in %s is deleted", install_shown_name(g_app.save_target), where);
        note("uninstalled %s", install_shown_name(g_app.save_target));
        return;
    }
    g_app.installed = g_app.locked = 0;
    factors_in_use();
    verified_saving(0);
    g_n_uninstalled_keys = 0;
    for (int i = 0; i < trust_count(); i++)
        memcpy(g_uninstalled_keys[g_n_uninstalled_keys++], trust_at(i)->pub, ID_SIGN_PUB_LEN);
    g_app.saved_key_known = 0;
    g_app.saved_key_path[0] = '\0';
    push_log("* uninstalled: chat's files in %s are deleted. What's in use now lasts until chat exits", where);
    note("uninstalled");
}

// What the run starts with (the options, what's saved, a random nick) doesn't count as a change to save.
static void settle_start(void) {
    if (!g_app.nick[0]) {
        random_nickname(g_app.nick, sizeof g_app.nick);
        push_log("welcome to chat. you're %s for now - :set nick NAME renames you anytime",
                 g_app.nick);
    }
    note_settings_seen();
    say_saved_notes();
}

// Once opened, chat starts with its saved settings straight away. Otherwise it opens on the settings page.
static void end_unlock(void) {
    end_prompt();
    settle_start();
    if (g_app.installed && install_has_settings(install_current())) settings_done();
    else g_app.mode = MODE_SETTINGS;
}

static void unlock_done(int rc) {
    if (rc == 0) use_opened_save(NULL);
    // Deleted after too many wrong tries: there's nothing to open any more.
    if (rc == INSTALL_DESTROYED) { g_app.installed = 0; verified_saving(0); }
    // The key before chat starts, so a --session opens signed.
    if (key_in_use_saved()) identity_chosen();
    end_unlock();
    if (rc != 0) note("%s", open_error(rc));
}

static void unlock_result(int rc) {
    g_app.mode = MODE_UNLOCK;
    if (rc == PASS_WRONG || rc == PASS_NOMEM || rc == INSTALL_DEVICE || rc == INSTALL_KEY) { note("%s", open_error(rc)); return; }
    if (rc == 0 && install_code_pending()) {
        g_app.key_purpose = KP_UNLOCK;
        g_app.message[0] = '\0';
        to_install_mode(MODE_UNLOCK_CODE);
        return;
    }
    unlock_done(rc);
}

static void commit_unlock(void) {
    if (!g_app.input.buf[0]) { note("type its passphrase - or Esc to start without it"); return; }
    copy_str(g_app.install_pass, g_app.input.buf, sizeof g_app.install_pass);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    unlock_go(KP_UNLOCK);
}

static void skip_unlock(void) {
    end_unlock();
    note("what :install saved stays sealed: chat starts from its defaults, and saves nothing until :install opens a save");
}

// Esc on the passphrase goes back to the list, if it came from one.
static void back_from_unlock(void) {
    if (!save_to_pick()) { skip_unlock(); return; }
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    g_app.mode = MODE_SAVES;
    g_app.dirty = 1;
}

static void saves_key(const tui_key_t *key) {
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT:
            install_use(g_app.saves[g_app.save_sel].name);
            g_app.mode = MODE_UNLOCK;
            break;
        case LIST_BACK:
            skip_unlock();
            break;
        default:
            list_move(k, &g_app.save_sel, g_app.n_saves);
            break;
    }
    g_app.dirty = 1;
}

static void cancel_uninstall(void) {
    end_prompt();
    note("nothing was deleted");
}

// ---- a factor turned on with no save open ----
//
// It's for a save, so a box asks to :install first. Yes turns it on for the new save :install makes,
// which sets it up before the passphrase, and install_ended sets it up for a save :install opens.

static int begin_install(const char *arg);

static void install_first(unsigned factor) {
    g_app.install_for = factor;
    g_app.install_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    g_app.n_saves = install_list(g_app.saves, INSTALL_SAVES_MAX);
    begin_prompt(MODE_INSTALL_FIRST);
}

static void install_first_yes(void) {
    end_prompt();
    if (g_app.install_back == MODE_SETTINGS) g_app.mode = MODE_SETTINGS;
    *factor_flag(g_app.install_for) = 1;
    if (begin_install(NULL) != 0) install_ended();
}

static void install_first_no(void) {
    const char *label = factor_label(g_app.install_for);
    end_prompt();
    install_ended();
    note("%s: off - nothing was installed", label);
}

// The open save is sealed again, after a box asks.
static void device_lock_choose(int on) {
    device_check();
    if (on && g_app.device_kind == DEVICE_NONE) { note("Device lock: can't be used here - %s", g_app.device_why); return; }
    if (!g_app.installed && on) { install_first(INSTALL_FACTOR_DEVICE); return; }
    if (!g_app.installed) {
        g_app.device_lock = 0;
        note("Device lock: off");
        return;
    }
    if (!on == !g_app.device_lock) {
        // This also finishes one a failed write left half done.
        if (install_set_factor(INSTALL_FACTOR_DEVICE, on) == 0) note("Device lock: %s already", on ? "on" : "off");
        else note("Device lock: %s - %s", on ? "on" : "off", install_why());
        return;
    }
    g_app.device_want = on;
    g_app.device_new = 0;
    g_app.device_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    if (g_app.device_back == MODE_CHAT) begin_prompt(MODE_DEVICE_LOCK);
    else { g_app.mode = MODE_DEVICE_LOCK; g_app.dirty = 1; }
}

static void device_lock_back(void) {
    if (g_app.device_back == MODE_CHAT) { end_prompt(); return; }
    g_app.mode = g_app.device_back;
    g_app.dirty = 1;
}

static void device_lock_yes(void) {
    if (g_app.device_new) {
        g_app.device_new = 0;
        install_step(STEP_DEVICE);
        return;
    }
    int on = g_app.device_want;
    device_lock_back();
    const char *shown = install_shown_name(install_current());
    char where[900] = "";
    install_where(install_current(), where, sizeof where);
    // A TPM can take a few seconds to make a key.
    note(on ? "locking %s to this device..." : "unlocking %s from this device...", shown);
    render();
    int rc = install_set_factor(INSTALL_FACTOR_DEVICE, on);
    device_kind_t kind = install_device_lock();
    g_app.device_lock = kind != DEVICE_NONE;
    const char *also = install_why();
    if (rc != 0) {
        push_log("* device lock: %s for the save %s - %s", g_app.device_lock ? "on" : "off", shown, also);
        note("Device lock: %s - %s", g_app.device_lock ? "on" : "off", also);
        return;
    }
    factors_in_use();
    if (on) {
        push_log("* device lock: the save %s in %s is locked to this device. It uses %s", shown, where,
                 platform_device_uses(kind));
        push_log("%s", DEVICE_REMINDER);
    } else {
        push_log("* device lock: the save %s in %s isn't locked to this device any more, and opens wherever its files "
                 "are", shown, where);
    }
    if (also[0]) push_log("* device lock: %s", also);
    note(on ? "Device lock: on - %s only opens on this device" : "Device lock: off - %s opens on any device", shown);
}

static void device_lock_no(void) {
    if (g_app.device_new) {
        g_app.device_new = 0;
        cancel_install();
        return;
    }
    device_lock_back();
    note("nothing was changed");
}

// ---- the security key and the authenticator app ----
//
// Like the device lock: with no save open, turning one on asks to :install first. For the open
// save, a box asks first, and the save is sealed again.

static void key_start(key_purpose_t why);
static void key_ended(install_key_state_t st);

// The factor boxes open over the settings page or the chat, and their fields take the input line,
// saved meanwhile.
static void factor_close(void) {
    app_mode_t back = g_app.factor_back;
    end_prompt();
    if (back == MODE_SETTINGS) g_app.mode = MODE_SETTINGS;
}

static void factor_choose(unsigned factor, int on) {
    const char *label = factor_label(factor);
    int *flag = factor_flag(factor);
    device_check();
    if (on && factor == INSTALL_FACTOR_KEY && !g_app.seckey_ok) {
        note("Security key: can't be used here - %s", g_app.seckey_why);
        return;
    }
    if (!g_app.installed && on) { install_first(factor); return; }
    if (!g_app.installed) {
        *flag = 0;
        note("%s: off", label);
        return;
    }
    if (!on == !*flag) {
        // This also finishes one a failed write left half done.
        if (install_set_factor(factor, on) == 0) note("%s: %s already", label, on ? "on" : "off");
        else note("%s: %s - %s", label, on ? "on" : "off", install_why());
        factors_in_use();
        return;
    }
    g_app.factor = factor;
    g_app.factor_want = on;
    g_app.factor_new = 0;
    g_app.factor_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    if (factor == INSTALL_FACTOR_CODE && on) {
        install_code_new(install_current(), g_app.code_b32, sizeof g_app.code_b32, g_app.code_uri, sizeof g_app.code_uri);
        g_app.code_qr = 0;
        begin_prompt(MODE_CODE_SETUP);
    } else {
        begin_prompt(MODE_FACTOR);
    }
}

// Seals the open save again with the factor box's change, once a security key or an authenticator
// app has been set up for turning it on.
static void factor_apply(void) {
    unsigned factor = g_app.factor;
    int on = g_app.factor_want, key = factor == INSTALL_FACTOR_KEY;
    const char *shown = install_shown_name(install_current());
    factor_close();
    note("sealing %s again...", shown);
    render();
    int rc = install_set_factor(factor, on);
    install_setup_forget();
    factors_in_use();
    const char *also = install_why();
    if (rc != 0) {
        push_log("* %s: not changed for the save %s - %s", key ? "security key" : "authenticator app", shown, also);
        note("%s: not changed - %s", factor_label(factor), also);
        return;
    }
    if (key && on) {
        push_log("* security key: the save %s needs your security key now, as well as its passphrase. Without it, "
                 "nothing opens the save", shown);
        push_log("%s", KEY_REMINDER);
    } else if (key) {
        push_log("* security key: the save %s opens without a security key again", shown);
    } else if (on) {
        push_log("* authenticator app: the save %s asks for the code your app shows each time it opens. Keep a copy of "
                 "the secret somewhere safe: without the app or the secret, chat won't open the save", shown);
    } else {
        push_log("* authenticator app: the save %s doesn't ask for a code any more, and the secret is deleted: remove "
                 "its entry from your app", shown);
    }
    if (also[0]) push_log("* %s", also);
    note("%s: %s for %s", factor_label(factor), on ? "on" : "off", shown);
}

static void factor_yes(void) {
    // Registering takes two touches: one for the credential, one for its secret.
    if (g_app.factor == INSTALL_FACTOR_KEY && g_app.factor_want) {
        key_start(g_app.factor_new ? KP_NEW_SAVE : KP_FACTOR);
        return;
    }
    factor_apply();
}

static void factor_no(void) {
    if (g_app.factor_new) { cancel_install(); return; }
    factor_close();
    note("nothing was changed");
}

static void commit_code_setup(void) {
    char code[32];
    copy_str(code, g_app.input.buf, sizeof code);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (!code[0]) { note("type the code your app shows for it - or Esc to cancel"); return; }
    int rc = install_code_try(code);
    if (rc == PASS_FORMAT) { note("a code is 6 digits, as your app shows it"); return; }
    if (rc != 0) {
        note("that isn't the code for this secret - check the app has the new one, and the clocks of this computer and "
             "the phone");
        return;
    }
    if (g_app.factor_new) { install_step(STEP_CODE); return; }
    factor_apply();
}

static void cancel_code_setup(void) {
    install_setup_forget();
    if (g_app.factor_new) { cancel_install(); return; }
    factor_close();
    note("Authenticator app: not changed - delete the entry you added to your app, if you did");
}

// ---- self-destruct, and the shadow passphrase ----

static void destroy_choose(int limit) {
    g_app.destroy_limit = limit;
    const char *shown = install_shown_name(install_current());
    if (!g_app.installed) {
        if (limit) note("Self-destruct: on - the save :install makes next deletes itself after %d wrong passphrases", limit);
        else note("Self-destruct: off");
        return;
    }
    if (install_arm_destroy(install_current(), (unsigned)limit) != 0) {
        g_app.destroy_limit = install_destroy_limit(install_current());
        note("Self-destruct: couldn't write the save's tries file");
        return;
    }
    if (limit) {
        push_log("* self-destruct: the save %s deletes everything chat saved for it after %d wrong passphrases in a "
                 "row. A right one clears the count", shown, limit);
        note("Self-destruct: on - after %d wrong passphrases", limit);
    } else {
        push_log("* self-destruct: off for the save %s", shown);
        note("Self-destruct: off");
    }
}

// The decoy is a clean save with no signing key or verified peers: it looks like a fresh install.
static void shadow_set_decoy(void) {
    const char *shown = install_shown_name(install_current());
    int rc = install_shadow_set(g_app.shadow_pass, "", NULL, 0, "");
    crypto_wipe(g_app.shadow_pass, sizeof g_app.shadow_pass);
    factor_close();
    if (rc == PASS_NOMEM) { note("Shadow password: setting it up needs 512 MiB of free memory for a moment"); return; }
    if (rc != 0) { note("Shadow password: couldn't set it - %s", install_why()); return; }
    push_log("* shadow password: the save %s now has a decoy. Opening it with the shadow passphrase deletes the real "
             "save for good and keeps only the decoy. Don't forget which passphrase is which", shown);
    note("Shadow password: on for %s", shown);
}

static void begin_shadow(void) {
    if (!g_app.installed || g_app.locked) {
        note("Shadow password: open a save first - :install, then set it while the save is open");
        return;
    }
    const char *shown = install_shown_name(install_current());
    if (install_has_shadow(install_current())) {
        install_shadow_clear(install_current());
        push_log("* shadow password: removed for the save %s - there's no decoy now", shown);
        note("Shadow password: off");
        return;
    }
    crypto_wipe(g_app.shadow_pass, sizeof g_app.shadow_pass);
    g_app.factor_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    begin_prompt(MODE_SHADOW_PASS);
}

static void commit_shadow_pass(void) {
    if (!g_app.input.buf[0]) { note("type the shadow passphrase - or Esc to cancel"); return; }
    copy_str(g_app.shadow_pass, g_app.input.buf, sizeof g_app.shadow_pass);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    g_app.mode = MODE_SHADOW_PASS2;
    g_app.dirty = 1;
}

static void commit_shadow_pass2(void) {
    int same = strcmp(g_app.input.buf, g_app.shadow_pass) == 0;
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (!same) {
        crypto_wipe(g_app.shadow_pass, sizeof g_app.shadow_pass);
        g_app.mode = MODE_SHADOW_PASS;
        note("they weren't the same - type the shadow passphrase again");
        return;
    }
    note("setting up the decoy...");
    render();
    shadow_set_decoy();
}

static void cancel_shadow_pass(void) {
    crypto_wipe(g_app.shadow_pass, sizeof g_app.shadow_pass);
    factor_close();
    note("Shadow password: not changed");
}

// The security key's thread starts, and its box shows what it's waiting for until it's done.
static void key_start(key_purpose_t why) {
    const char *pin = g_app.key_pin[0] ? g_app.key_pin : NULL;
    g_app.key_purpose = why;
    if (why != KP_FACTOR) g_app.factor_back = why == KP_UNLOCK ? MODE_CHAT : g_app.install_back;
    int rc = why == KP_FACTOR || why == KP_NEW_SAVE
        ? install_key_make(pin)
        : install_key_open(why == KP_INSTALL_UNLOCK ? g_app.save_target : install_current(), pin);
    crypto_wipe(g_app.key_pin, sizeof g_app.key_pin);
    g_app.key_stage = SECKEY_BUSY;
    g_app.key_touches = 0;
    to_install_mode(MODE_KEY_WAIT);
    if (rc != 0) key_ended(INSTALL_KEY_FAILED);
}

// Where what the security key's thread came to leads, for what it was touched for.
static void key_ended(install_key_state_t st) {
    key_purpose_t why = g_app.key_purpose;
    if (st == INSTALL_KEY_PIN) {
        to_install_mode(MODE_KEY_PIN);
        note("%s", install_key_why());
        return;
    }
    if (st == INSTALL_KEY_DONE) {
        if (why == KP_NEW_SAVE) install_step(STEP_KEY);
        else if (why == KP_FACTOR) factor_apply();
        else unlock_go(why);
        return;
    }
    const char *what = st == INSTALL_KEY_CANCELLED ? "stopped" : install_key_why();
    switch (why) {
        case KP_NEW_SAVE:
            not_installed("not installed - security key: %s", what);
            return;
        case KP_FACTOR:
            install_setup_forget();
            factor_close();
            note("Security key: not changed - %s", what);
            return;
        default:
            crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
            to_install_mode(why == KP_INSTALL_UNLOCK ? MODE_INSTALL_UNLOCK : MODE_UNLOCK);
            note("not opened - security key: %s", what);
            return;
    }
}

static void commit_key_pin(void) {
    if (!g_app.input.buf[0]) { note("type the security key's PIN - or Esc to cancel"); return; }
    copy_str(g_app.key_pin, g_app.input.buf, sizeof g_app.key_pin);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    key_start(g_app.key_purpose);
}

static void cancel_key_pin(void) { key_ended(INSTALL_KEY_CANCELLED); }

static void key_wait_key(const tui_key_t *key) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (key->type != TUI_KEY_ESCAPE && ch != 'q') return;
    install_key_cancel();
    note("stopping...");
}

// Each time round the main loop while the box waits: what it's waiting for, and when it's done.
static void key_wait_tick(void) {
    int s, t;
    install_key_state_t st = install_key_poll(&s, &t);
    if (st == INSTALL_KEY_RUNNING) {
        if (s != g_app.key_stage || t != g_app.key_touches) g_app.dirty = 1;
        g_app.key_stage = s;
        g_app.key_touches = t;
        return;
    }
    g_app.key_stage = SECKEY_LOOKING;
    g_app.key_touches = 0;
    if (st != INSTALL_KEY_IDLE) key_ended(st);
}

// Opening a save: its security key's secret first, then the passphrase in install_pass, then a code
// it needs.
static void unlock_go(key_purpose_t why) {
    const char *name = why == KP_INSTALL_UNLOCK ? g_app.save_target : install_current();
    if ((install_factors(name) & INSTALL_FACTOR_KEY) && !install_key_ready(name)) {
        key_start(why);
        return;
    }
    // Argon2id takes a few seconds, so say so before the screen freezes.
    if (why == KP_INSTALL_UNLOCK) note("opening the save %s...", install_shown_name(name));
    else note("opening what :install saved...");
    render();
    int rc = install_unlock(name, g_app.install_pass);
    crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
    if (why == KP_INSTALL_UNLOCK) install_unlock_result(rc);
    else unlock_result(rc);
}

static void commit_unlock_code(void) {
    char code[32];
    copy_str(code, g_app.input.buf, sizeof code);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (!code[0]) { note("type the code your authenticator app shows - or Esc to go back"); return; }
    note("checking the code...");
    render();
    int rc = install_check_code(code);
    crypto_wipe(code, sizeof code);
    if (rc == PASS_FORMAT) { note("a code is 6 digits, as your authenticator app shows it"); return; }
    if (rc != 0) {
        note("that isn't the code your authenticator app shows for it - check the clocks of this computer and the phone");
        return;
    }
    if (g_app.key_purpose == KP_INSTALL_UNLOCK) install_unlock_done(0);
    else unlock_done(0);
}

static void back_from_unlock_code(void) {
    install_code_cancel();
    to_install_mode(g_app.key_purpose == KP_INSTALL_UNLOCK ? MODE_INSTALL_UNLOCK : MODE_UNLOCK);
    note("not opened: it needs its passphrase, then the code");
}

// Enter doesn't answer. A question takes y or n.
static void confirm_key(const tui_key_t *key, void (*yes)(void), void (*no)(void)) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') yes();
    else if (ch == 'n' || ch == 'N' || ch == 'q' || key->type == TUI_KEY_ESCAPE) no();
}

// Only y quits: not a second Ctrl+C, the easy mistake, nor q, which closes boxes elsewhere. Staying
// leaves whatever the box was over as it was.
static void quit_key(const tui_key_t *key) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') g_interrupted = 1;
    else if (ch == 'n' || ch == 'N' || key->type == TUI_KEY_ESCAPE) { g_app.asking_quit = 0; g_app.dirty = 1; }
}

static void field_key(const tui_key_t *key, void (*enter)(void), void (*esc)(void)) {
    if (key->type == TUI_KEY_ESCAPE) esc();
    else if (key->type == TUI_KEY_ENTER) enter();
    else if (tui_input_feed(&g_app.input, key)) g_app.dirty = 1;
}

// Tab is only offered when the text and the QR code don't fit together, and then picks between them.
static void code_setup_key(const tui_key_t *key) {
    if (key->type == TUI_KEY_TAB) { g_app.code_qr = !g_app.code_qr; g_app.dirty = 1; }
    else field_key(key, commit_code_setup, cancel_code_setup);
}

// ---- commands ----

// :set opens the settings page and :set NAME opens it on that row. :set NAME VALUE sets the row
// without opening it, the same as the page would.
static cmd_result_t app_set(void *ctx, const char *arg) {
    (void)ctx;
    char key[CMD_WORD_MAX];
    const char *value = cmd_parse(arg, key);
    if (!key[0]) { begin_settings(); return CMD_OK; }
    const setting_def_t *d = setting_by_key(key);
    if (!d) { note("no setting called %s - :set opens the page with all of them", key); return CMD_OK; }
    if (!value[0]) { settings_open_at(d->id); return CMD_OK; }

    const char *const *names;
    int n;
    if (setting_options(d->id, &names, &n) >= 0) {
        for (int i = 0; i < n; i++)
            if (strcmp(value, names[i]) == 0) { setting_choose(d->id, i); return CMD_OK; }
        note("%s takes %s, not %.40s", d->key, d->values, value);
        return CMD_OK;
    }
    switch (d->kind) {
        case K_TEXT:
            setting_apply_text(d->id, value);
            return CMD_OK;
        case K_SECRET:
            // On the command line it would be visible. The page's field hides it.
            settings_open_at(d->id);
            if (!setting_shown(d->id)) return CMD_OK;   // settings_open_at said why it isn't there
            begin_setting_edit(d->id);
            note("type the %s here instead, where it's hidden", d->label);
            return CMD_OK;
        default:
            break;
    }
    if (d->id == SET_SHADOW) {
        int on = g_app.installed && install_has_shadow(install_current());
        if (strcmp(value, "off") == 0) {
            if (!on) { note("Shadow password: off already"); return CMD_OK; }
            install_shadow_clear(install_current());
            push_log("* shadow password: removed for the save %s - there's no decoy now",
                     install_shown_name(install_current()));
            note("Shadow password: off");
        } else if (strcmp(value, "on") == 0) {
            if (on) note("Shadow password: on already - :set shadow off removes it");
            else begin_shadow();
        } else {
            note("shadow takes on or off");
        }
        return CMD_OK;
    }
    if (d->id == SET_SIGN) {
        static const struct { const char *name; sign_pick_t pick; } SIGN_VALUES[] = {
            { "off", PICK_OFF }, { "age", PICK_AGE_MADE }, { "pgp", PICK_PGP_MADE },
        };
        int pick = -1;
        for (size_t i = 0; i < sizeof SIGN_VALUES / sizeof SIGN_VALUES[0]; i++)
            if (strcmp(value, SIGN_VALUES[i].name) == 0) pick = SIGN_VALUES[i].pick;
        if (pick == PICK_OFF) { sign_pick(pick); return CMD_OK; }
        // age:PATH or pgp:PATH: a key file, like --identity takes.
        if ((strncmp(value, "age:", 4) == 0 || strncmp(value, "pgp:", 4) == 0) && value[4]) {
            identity_source_t kind = value[0] == 'a' ? IDENT_AGE : IDENT_PGP;
            if (load_key_file(kind, value + 4) == 0) { identity_chosen(); return CMD_OK; }
            if (kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", value + 4);
            else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", value + 4);
            return CMD_OK;
        }
        settings_open_at(SET_SIGN);
        begin_sign();
        if (pick < 0) { note("sign takes off, age, pgp, age:PATH or pgp:PATH - a pasted key is chosen here"); return CMD_OK; }
        // The password is typed on the page, where it's hidden.
        g_app.sign_sel = pick;
        sign_pick(pick);
        return CMD_OK;
    }
    settings_open_at(d->id);
    if (setting_shown(d->id)) note("%s comes from your signing key and can't be set - Enter copies it", d->label);
    return CMD_OK;
}

// The save named in arg, else the one in use. -1 if arg can't name a save.
static int pick_save_target(const char *arg) {
    while (arg && *arg == ' ') arg++;
    char name[64] = "";
    if (arg) copy_str(name, arg, sizeof name);
    size_t n = strlen(name);
    while (n > 0 && name[n - 1] == ' ') name[--n] = '\0';
    if (name[0] && install_name_ok(name) != 0) {
        note("a save's name is 1 to %d letters, digits, - and _", INSTALL_NAME_MAX);
        return -1;
    }
    copy_str(g_app.save_target, name[0] ? name : install_current(), sizeof g_app.save_target);
    if (strcmp(g_app.save_target, "default") == 0) g_app.save_target[0] = '\0';
    g_app.save_named = name[0] != '\0';
    return 0;
}

// 0 once its first box is open.
static int begin_install(const char *arg) {
    if (pick_save_target(arg) != 0) return -1;
    device_check();
    char where[900];
    if (install_where(g_app.save_target, where, sizeof where) != 0) { note("there's nowhere to install to - no home folder"); return -1; }
    g_app.n_saves = install_list(g_app.saves, INSTALL_SAVES_MAX);
    const char *t = g_app.save_target;
    int named = g_app.save_named || g_opts.save[0];
    app_mode_t mode = MODE_INSTALL;
    if (g_app.installed) {
        // The open save is saved to after the usual question. Another one that's there needs its
        // passphrase to be saved over.
        if (!is_current_save(t) && save_exists(t)) mode = MODE_INSTALL_OVERWRITE;
    } else if (save_exists(t) || (!named && g_app.n_saves > 0)) {
        // Nothing is open: the saves there are offered before a new one is made. Without a NAME or
        // --save, the only save is offered, or one is picked from a list.
        if (!named && g_app.n_saves == 1) copy_str(g_app.save_target, g_app.saves[0].name, sizeof g_app.save_target);
        g_app.install_pick = !named && g_app.n_saves > 1;
        g_app.save_sel = 0;
        for (int i = 0; i < g_app.n_saves; i++)
            if (strcmp(g_app.saves[i].name, t) == 0) g_app.save_sel = i;
        mode = MODE_INSTALL_EXISTING;
    } else if (!named) {
        pick_random_save_name();
        mode = MODE_INSTALL_NAME;
    }
    g_app.install_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    begin_prompt(mode);
    return 0;
}

static cmd_result_t app_install(void *ctx, const char *arg) {
    (void)ctx;
    g_app.install_for = 0;
    begin_install(arg);
    return CMD_OK;
}

// The same as :install, for the save in use.
static cmd_result_t app_save(void *ctx, const char *arg) {
    (void)arg;
    return app_install(ctx, NULL);
}

static cmd_result_t app_uninstall(void *ctx, const char *arg) {
    (void)ctx;
    if (pick_save_target(arg) != 0) return CMD_OK;
    if (!save_exists(g_app.save_target)) {
        if (arg && arg[0]) note("nothing to uninstall - there's no save called %s", install_shown_name(g_app.save_target));
        else note("nothing to uninstall - chat has saved nothing here");
        return CMD_OK;
    }
    begin_prompt(MODE_UNINSTALL);
    return CMD_OK;
}

// Checked before CHAT_COMMANDS, so entries here shadow the per-session ones of the same name.
static const command_t APP_COMMANDS[] = {
    { "help",    NULL,                  NULL,     "list all commands and keybinds (F1)",          app_help },
    { "new",     NULL,                  NULL,     "create a session (Ctrl+N)",                       app_new },
    { "join",    NULL,                  NULL,     "join a session by id (Ctrl+J)",                   app_join },
    { "quit",    "q exit close bd bw",  NULL,     "leave this session; quits if none are open",       app_quit },
    { "quitall", "qa qall",             NULL,     "leave every session and quit (Ctrl+C)",           app_quitall },
    { "set",     NULL,        "[NAME [VALUE]]",   "change a setting; alone, opens them all (Ctrl+S)", app_set },
    { "copyid",  NULL,                  NULL,     "copy this session's id to the clipboard",         app_copyid },
    { "update",  NULL,                  NULL,     "install the latest release from GitHub",          app_update },
    { "install", NULL,                  "[NAME]", "save your settings and signing key on this computer (NAME: as a save of that name)", app_install },
    { "save",    NULL,                  NULL,     "save what's in use now to the open save, after asking (or :install it)", app_save },
    { "uninstall", NULL,                "[NAME]", "delete what :install saved (NAME: that save)",    app_uninstall },
    { "changelog", "news",              NULL,     "show changelog",                    app_changelog },
    { "files",   NULL,                  NULL,     "the files offered here: show, save or stop them (Ctrl+F)", app_files },
    { "show",    NULL,                  "N [anyway]", "show picture N in the chat, where it was offered", app_show },
    { "hide",    NULL,                  "N",      "tuck picture N away again",                       app_hide },
    { "saveto",  NULL,                  "N [anyway]", "pick a folder in a file browser and save file N there", app_saveto },
    { NULL, NULL, NULL, NULL, NULL }
};

static const command_t *const ALL_COMMANDS[] = { APP_COMMANDS, CHAT_COMMANDS, NULL };

static cmd_result_t app_help(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_help();
    return CMD_OK;
}

static cmd_result_t app_changelog(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_changelog();
    return CMD_OK;
}

// "N" or "N anyway": the number, and whether anyway was given. 0 if it's neither.
static int file_arg(const char *arg, int *anyway) {
    char *end;
    long n = strtol(arg, &end, 10);
    while (*end == ' ') end++;
    *anyway = strcmp(end, "anyway") == 0;
    return n > 0 && n < 1000000 && (!*end || *anyway) ? (int)n : 0;
}

// Pictures are only fetched when you ask to show them, and drawn where they were offered.
static cmd_result_t app_show(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    int anyway, n = file_arg(arg, &anyway);
    if (!s || s->initialising) { note("open a session first"); return CMD_OK; }
    if (!n) { note("usage: :show N [anyway] - N is the number in the offer"); return CMD_OK; }
    pic_t *p = pic_find(s, n);
    if (p && p->th.rgb) { p->shown = 1; g_app.dirty = 1; return CMD_OK; }
    echo_fetch(s, n, 1, anyway, NULL);
    return CMD_OK;
}

static cmd_result_t app_files(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_files();
    return CMD_OK;
}

static cmd_result_t app_saveto(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    int anyway, n = file_arg(arg, &anyway);
    if (!s || s->initialising) { note("open a session first"); return CMD_OK; }
    if (!n) { note("usage: :saveto N [anyway] - N is the number in the offer"); return CMD_OK; }
    const file_entry_t *f = chat_file(&s->engine, n);
    if (!f) { note("there's no file %d - :files lists them", n); return CMD_OK; }
    if (f->mine) { note("file %d is yours", n); return CMD_OK; }
    begin_save_browse(n, anyway);
    return CMD_OK;
}

static cmd_result_t app_hide(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    int anyway, n = file_arg(arg, &anyway);
    pic_t *p = s && n ? pic_find(s, n) : NULL;
    if (!p || !p->shown) { note("picture %s isn't shown", arg); return CMD_OK; }
    p->shown = 0;
    g_app.dirty = 1;
    return CMD_OK;
}

// The help page's rows, and each one's command (NULL for a key's).
static int help_rows(tui_row_t *rows, const command_t **cmds) {
    static char labels[MAX_HELP_COMMANDS][CMD_WORD_MAX + 24];
    int n = 0, k = 0;
    for (int i = 0; i < N_HELP_KEYS; i++) {
        rows[n] = (tui_row_t){ HELP_KEYS[i].section, HELP_KEYS[i].keys, HELP_KEYS[i].what, TUI_V_TEXT, NULL, NULL, 0, 0 };
        cmds[n++] = NULL;
    }
    for (const command_t *const *t = ALL_COMMANDS; *t; t++) {
        for (const command_t *cmd = *t; cmd->name && k < MAX_HELP_COMMANDS; cmd++) {
            if (*t != APP_COMMANDS && cmd_find(APP_COMMANDS, cmd->name)) continue;
            snprintf(labels[k], sizeof labels[k], ":%s%s%s", cmd->name, cmd->args ? " " : "", cmd->args ? cmd->args : "");
            rows[n] = (tui_row_t){ k == 0 ? "Commands" : NULL, labels[k], cmd->help, TUI_V_TEXT, NULL, NULL, 0, 0 };
            cmds[n++] = cmd;
            k++;
        }
    }
    return n;
}

static void render_help(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    tui_row_t rows[MAX_HELP_ROWS];
    const command_t *cmds[MAX_HELP_ROWS];
    int n = help_rows(rows, cmds);
    if (g_app.help_sel >= n) g_app.help_sel = n - 1;
    const command_t *c = cmds[g_app.help_sel];
    char help[200] = "";
    if (c) {
        size_t p = (size_t)snprintf(help, sizeof help, "Enter puts it on the command line.");
        const char *sep = " Also";
        for (const char *a = c->aliases; a && *a && p < sizeof help; ) {
            size_t len = strcspn(a, " ");
            p += (size_t)snprintf(help + p, sizeof help - p, "%s :%.*s", sep, (int)len, a);
            sep = ",";
            a += len;
            while (*a == ' ') a++;
        }
        if (c->aliases && p < sizeof help) snprintf(help + p, sizeof help - p, ".");
    }
    tui_page_t page = {
        .title = "Keys & commands",
        .clock = clock,
        .rows = rows, .n_rows = n, .selected = g_app.help_sel,
        .help = help[0] ? help : NULL,
        .keys = 1,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

// Enter on a command puts it on the command line, to be completed and run. F1 and ? close the page
// as well as open it.
static void help_key(const tui_key_t *key) {
    tui_row_t rows[MAX_HELP_ROWS];
    const command_t *cmds[MAX_HELP_ROWS];
    int n = help_rows(rows, cmds);
    int s = section_digit(key);
    if (s >= 0) {
        int i = page_section_nth(rows, n, s);
        if (i >= 0) g_app.help_sel = i;
        g_app.dirty = 1;
        return;
    }
    list_key_t k = list_key(key);
    if (key->type == TUI_KEY_HELP || (key->type == TUI_KEY_CHAR && key->ch[0] == '?')) k = LIST_CLOSE;
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            const command_t *c = cmds[g_app.help_sel];
            if (!c) break;
            g_app.mode = MODE_CHAT;
            char text[CMD_WORD_MAX + 2];
            snprintf(text, sizeof text, "%s%s", c->name, c->args ? " " : "");
            tui_input_command(&g_app.input, g_app.input.mode == TUI_IMODE_NORMAL ? ':' : '/', text);
            break;
        }
        case LIST_LEFT:
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = MODE_CHAT; break;
        case LIST_NEXT_SECTION: g_app.help_sel = page_section_step(rows, n, g_app.help_sel, 1); break;
        case LIST_PREV_SECTION: g_app.help_sel = page_section_step(rows, n, g_app.help_sel, -1); break;
        default: list_move(k, &g_app.help_sel, n); break;
    }
    g_app.dirty = 1;
}

// Whether a command's name or one of its aliases starts with word (or, with whole, is word). A line
// opened with '/' that can't be a command stays as text, for a message that starts with '/'.
static int command_word(const char *word, int whole) {
    size_t n = strlen(word);
    for (const command_t *const *t = ALL_COMMANDS; *t; t++) {
        for (const command_t *c = *t; c->name; c++) {
            if (whole ? strcmp(c->name, word) == 0 : strncmp(c->name, word, n) == 0) return 1;
            for (const char *a = c->aliases; a && *a; ) {
                size_t len = strcspn(a, " ");
                if ((whole ? len == n : len >= n) && strncmp(a, word, n) == 0) return 1;
                a += len;
                while (*a == ' ') a++;
            }
        }
    }
    return 0;
}

static int nick_has_prefix(const char *nick, const char *typed) {
    for (; *typed; nick++, typed++)
        if (tolower((unsigned char)*nick) != tolower((unsigned char)*typed)) return 0;
    return 1;
}

// The selected session's engine, once there is one to name peers from.
static chat_t *peer_engine(void) {
    if (g_app.mode != MODE_CHAT || !g_app.selected || g_app.selected->initialising) return NULL;
    return &g_app.selected->engine;
}

// First online peer whose nick starts with typed, ignoring case.
static const char *complete_mention(const char *typed) {
    chat_t *e = peer_engine();
    if (!e) return NULL;
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        peer_t *p = &e->peers[i];
        if (p->used && p->ok && nick_has_prefix(p->nick, typed)) return p->nick;
    }
    return NULL;
}

static const command_t *find_command(const char *word) {
    const command_t *c = cmd_find(APP_COMMANDS, word);
    return c ? c : cmd_find(CHAT_COMMANDS, word);
}

// What commands' arguments can be, in order, for the menu over the COMMAND line.
enum { A_NICK = 1, A_WORD, A_FILE, A_PATH, A_FOLDER, A_SAVE, A_TRUSTED, A_KIND = 0xf };
#define A_TYPED 0x10  // Enter fills it in only once some of it is typed
#define A_SKIP  0x20  // A_TYPED, and it can be left out with the next one in its place, so that's listed too
#define A_PICK  0x40  // Enter never fills it in: it's typed in full or picked in the menu

static const struct { const char *cmd; int args[4]; } COMMAND_ARGS[] = {
    { "verify",    { A_NICK, A_WORD | A_TYPED } },
    { "verified",  { A_WORD | A_TYPED, A_TRUSTED | A_PICK } },
    { "send",      { A_PATH | A_PICK } },
    { "download",  { A_FILE | A_SKIP, A_WORD | A_SKIP, A_FOLDER | A_PICK } },
    { "cancel",    { A_FILE | A_TYPED } },
    { "show",      { A_FILE, A_WORD | A_TYPED } },
    { "hide",      { A_FILE } },
    { "saveto",    { A_FILE, A_WORD | A_TYPED } },
    { "install",   { A_SAVE | A_TYPED } },
    { "uninstall", { A_SAVE | A_TYPED } },
};

static const struct { const char *cmd, *word, *help; } ARG_WORDS[] = {
    { "verify",   "ok",     "their code is the same - what you send reaches them" },
    { "verify",   "no",     "their code differs - nothing you send reaches them" },
    { "verified", "forget", "remove a verified key" },
    { "show",     "anyway", "even if it's over your file size limit" },
    { "saveto",   "anyway", "even if it's over your file size limit" },
    { "download", "anyway", "even if it's over your file size limit" },
};

// Bumped when the menu is listed from the start, so the folders and saves it reads are read again.
static unsigned g_menu_gen;

typedef struct {
    const command_t *c;
    const char *typed;
    int *nth;
    tui_suggestion_t *out;
} arg_menu_t;

// The next item in the menu: the line up to at, then text. 1 if it's the one asked for, with out
// filled in but for help. One the line can't hold isn't listed.
static int arg_item(arg_menu_t *m, const char *at, const char *text, const char *name, const char *group) {
    int n = snprintf(m->out->line, sizeof m->out->line, "%.*s%s", (int)(at - m->typed), m->typed, text);
    if (n < 0 || (size_t)n >= sizeof m->out->line || (*m->nth)-- > 0) return 0;
    copy_str(m->out->name, name, sizeof m->out->name);
    copy_str(m->out->group, group, sizeof m->out->group);
    return 1;
}

// The online peers whose nick starts with typed, ignoring case. An exact match comes first, so
// Enter on "id" doesn't run it as "ida". The rest are sorted by nick.
static int match_peers(const chat_t *e, const char *typed, const peer_t **m) {
    size_t tn = strlen(typed);
    int n = 0;
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        const peer_t *p = &e->peers[i];
        if (!p->used || !p->ok || !nick_has_prefix(p->nick, typed)) continue;
        int exact = strlen(p->nick) == tn, j = n++;
        for (; j > 0; j--) {
            int prev_exact = strlen(m[j - 1]->nick) == tn;
            if (prev_exact > exact || (prev_exact == exact && strcasecmp(m[j - 1]->nick, p->nick) <= 0)) break;
            m[j] = m[j - 1];
        }
        m[j] = p;
    }
    return n;
}

static int arg_nicks(arg_menu_t *m, const char *rest) {
    chat_t *e = peer_engine();
    const peer_t *p[MAX_PEERS + MAX_PENDING_PEERS];
    int n = e ? match_peers(e, rest, p) : 0;
    for (int i = 0; i < n; i++) {
        char name[CHAT_NAME_LEN]; chat_peer_name(e, p[i], name);
        if (!arg_item(m, rest, p[i]->nick, name, "peers")) continue;
        snprintf(m->out->help, sizeof m->out->help, "%s%s",
                 p[i]->identity_source == IDENT_NONE ? "unsigned" : chat_verify_label(p[i]->identity_state),
                 p[i]->build_state == BUILD_MODIFIED ? " \xc2\xb7 modified client" : "");
        return 1;
    }
    return 0;
}

static int arg_words(arg_menu_t *m, const char *rest) {
    for (size_t i = 0; i < sizeof ARG_WORDS / sizeof *ARG_WORDS; i++) {
        const char *w = ARG_WORDS[i].word;
        if (strcmp(ARG_WORDS[i].cmd, m->c->name) != 0 || strncmp(w, rest, strlen(rest)) != 0) continue;
        if (!arg_item(m, rest, w, w, m->c->name)) continue;
        copy_str(m->out->help, ARG_WORDS[i].help, sizeof m->out->help);
        return 1;
    }
    return 0;
}

// Whether file f is one the command can take.
static int file_fits(const command_t *c, const file_entry_t *f) {
    pic_t *p = pic_find(g_app.selected, f->num);
    if (strcmp(c->name, "show") == 0) return f->image && !(p && p->shown && p->th.rgb);
    if (strcmp(c->name, "hide") == 0) return p && p->shown && p->th.rgb;
    if (strcmp(c->name, "cancel") == 0) return f->mine ? f->fp != NULL : f->dl == DL_ACTIVE || f->dl == DL_QUEUED;
    return !f->mine;
}

// Files by number: the one with the number typed first, then the newest.
static int arg_files(arg_menu_t *m, const char *rest) {
    chat_t *e = peer_engine();
    const file_entry_t *l[FILE_OFFERS_MAX];
    size_t rn = strlen(rest);
    int n = 0, exact = e && rn ? atoi(rest) : 0;
    for (int i = 0; e && i < FILE_OFFERS_MAX; i++) {
        const file_entry_t *f = &e->files[i];
        char ns[12]; snprintf(ns, sizeof ns, "%d", f->num);
        if (!f->used || strncmp(ns, rest, rn) != 0 || !file_fits(m->c, f)) continue;
        int j = n++;
        for (; j > 0 && l[j - 1]->num != exact && (f->num == exact || l[j - 1]->num < f->num); j--) l[j] = l[j - 1];
        l[j] = f;
    }
    for (int i = 0; i < n; i++) {
        const file_entry_t *f = l[i];
        char ns[12]; snprintf(ns, sizeof ns, "%d", f->num);
        if (!arg_item(m, rest, ns, ns, "files")) continue;
        char sz[32]; file_format_size(f->size, sz, sizeof sz);
        snprintf(m->out->help, sizeof m->out->help, "%s \xc2\xb7 %s%s", f->name, sz,
                 f->mine ? " \xc2\xb7 yours" : f->dl == DL_ACTIVE ? " \xc2\xb7 fetching" : f->dl == DL_QUEUED ? " \xc2\xb7 queued"
                 : f->saved[0] ? " \xc2\xb7 saved" : "");
        return 1;
    }
    return 0;
}

// The files and folders (or only folders) in the folder typed so far, as typed_path reads it.
// Hidden ones once a '.' is typed.
static int arg_paths(arg_menu_t *m, const char *rest, int folders) {
    static browser_t dir;
    static unsigned gen;
    const char *base = strrchr(rest, '/');
    base = base ? base + 1 : rest;
    char path[sizeof dir.path];
    const char *home = platform_home_dir();
    if (base == rest) copy_str(path, ".", sizeof path);
    else if (rest[0] == '~' && rest[1] == '/' && home) snprintf(path, sizeof path, "%s%.*s", home, (int)(base - rest - 1), rest + 1);
    else snprintf(path, sizeof path, "%.*s", (int)(base - rest), rest);
    if (gen != g_menu_gen || strcmp(dir.path, path) != 0) {
        gen = g_menu_gen;
        if (browser_load(&dir, path) != 0) { dir.n_items = 0; copy_str(dir.path, path, sizeof dir.path); }
    }
    size_t bn = strlen(base);
    for (int i = 0; i < dir.n_items; i++) {
        const dir_entry_t *d = &dir.items[i];
        if ((folders && !d->is_dir) || (d->name[0] == '.' && base[0] != '.') || strncmp(d->name, base, bn) != 0) continue;
        if (!arg_item(m, base, d->name, d->name, folders ? "folders" : "your files")) continue;
        copy_str(m->out->help, d->is_dir ? "folder" : "", sizeof m->out->help);
        return 1;
    }
    return 0;
}

static int arg_saves(arg_menu_t *m, const char *rest) {
    static install_save_t saves[INSTALL_SAVES_MAX];
    static int n;
    static unsigned gen;
    if (gen != g_menu_gen) { gen = g_menu_gen; n = install_list(saves, INSTALL_SAVES_MAX); }
    for (int i = 0; i < n; i++) {
        const char *name = install_shown_name(saves[i].name);
        if (strncmp(name, rest, strlen(rest)) != 0 || !arg_item(m, rest, name, name, "saves")) continue;
        snprintf(m->out->help, sizeof m->out->help, "saved %s%s", saves[i].modified,
                 g_app.installed && is_current_save(saves[i].name) ? " \xc2\xb7 open" : "");
        return 1;
    }
    return 0;
}

// The nicks of the verified keys, each once, then "all".
static int arg_trusted(arg_menu_t *m, const char *rest) {
    int n = trust_count();
    for (int i = 0; i < n; i++) {
        const char *nick = trust_at(i)->nick;
        int keys = 0, seen = 0;
        for (int j = 0; j < n; j++) {
            const trust_entry_t *t = trust_at(j);
            if (!t || strcmp(t->nick, nick) != 0) continue;
            keys++;
            seen |= j < i;
        }
        if (seen || !nick_has_prefix(nick, rest) || !arg_item(m, rest, nick, nick, "verified")) continue;
        snprintf(m->out->help, sizeof m->out->help, "%d verified key%s", keys, keys == 1 ? "" : "s");
        return 1;
    }
    if (n == 0 || strncmp("all", rest, strlen(rest)) != 0 || !arg_item(m, rest, "all", "all", "verified")) return 0;
    copy_str(m->out->help, "every verified key", sizeof m->out->help);
    return 1;
}

// Where the argument after a whole one of this kind at the start of rest begins, past its space, or
// NULL. Nicks can have spaces, so it's after the longest online one there. Paths, saves and
// verified nicks take the rest of the line.
static const char *arg_end(const command_t *c, int kind, const char *rest) {
    size_t n = 0;
    if (kind == A_FILE) n = strspn(rest, "0123456789");
    else if (kind == A_WORD) {
        for (size_t i = 0; i < sizeof ARG_WORDS / sizeof *ARG_WORDS; i++) {
            size_t wl = strlen(ARG_WORDS[i].word);
            if (strcmp(ARG_WORDS[i].cmd, c->name) == 0 && strncmp(rest, ARG_WORDS[i].word, wl) == 0) n = wl;
        }
    } else if (kind == A_NICK) {
        chat_t *e = peer_engine();
        for (int i = 0; e && i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
            const peer_t *p = &e->peers[i];
            size_t pl = strlen(p->nick);
            if (p->used && p->ok && pl > n && nick_has_prefix(rest, p->nick) && rest[pl] == ' ') n = pl;
        }
    }
    return n > 0 && rest[n] == ' ' ? rest + n + 1 : NULL;
}

// The menu for args[0], with rest typed for it: what it can be, then what can follow once rest
// holds a whole one, then (if it can be left out) what can come in its place.
static int arg_suggest(arg_menu_t *m, const int *args, const char *rest) {
    int a = args[0], k = a & A_KIND, found = 0;
    if (!a) return 0;
    switch (k) {
        case A_NICK: found = arg_nicks(m, rest); break;
        case A_WORD: found = arg_words(m, rest); break;
        case A_FILE: found = arg_files(m, rest); break;
        case A_PATH: case A_FOLDER: found = arg_paths(m, rest, k == A_FOLDER); break;
        case A_SAVE: found = arg_saves(m, rest); break;
        case A_TRUSTED: found = arg_trusted(m, rest); break;
    }
    if (found) {
        m->out->no_default = (a & A_PICK) || ((a & (A_TYPED | A_SKIP)) && !*rest);
        return 1;
    }
    const char *next = arg_end(m->c, k, rest);
    if (next && arg_suggest(m, args + 1, next)) return 1;
    return (a & A_SKIP) && arg_suggest(m, args + 1, rest);
}

// The menu above the COMMAND line: commands by name. After "set ", the settings with their current
// values. After "set NAME ", the values it takes. After other commands, what their arguments can be.
static int suggest_command(const char *typed, int nth, tui_suggestion_t *out) {
    memset(out, 0, sizeof *out);
    if (nth == 0) g_menu_gen++;
    size_t wn = strcspn(typed, " ");
    char word[CMD_WORD_MAX];
    if (typed[wn] == ' ' && wn < sizeof word) {
        memcpy(word, typed, wn);
        word[wn] = '\0';
        const command_t *c = find_command(word);
        for (size_t i = 0; c && i < sizeof COMMAND_ARGS / sizeof *COMMAND_ARGS; i++) {
            if (strcmp(COMMAND_ARGS[i].cmd, c->name) != 0) continue;
            arg_menu_t m = { c, typed, &nth, out };
            return arg_suggest(&m, COMMAND_ARGS[i].args, typed + wn + 1);
        }
    }
    if (strncmp(typed, "set ", 4) == 0) {
        copy_str(out->group, "settings", sizeof out->group);
        const char *key = typed + 4, *sp = strchr(key, ' ');
        const char *const *names;
        int n;
        if (sp) {
            char name[CMD_WORD_MAX];
            size_t kl = (size_t)(sp - key);
            if (kl >= sizeof name) return 0;
            memcpy(name, key, kl);
            name[kl] = '\0';
            const setting_def_t *d = setting_by_key(name);
            int cur = d ? setting_choices(d->id, &names, &n) : -1;
            if (cur < 0) return 0;
            const char *v = sp + 1;
            for (int i = 0; i < n; i++) {
                if (strncmp(names[i], v, strlen(v)) != 0 || nth-- > 0) continue;
                snprintf(out->line, sizeof out->line, "set %s %s", d->key, names[i]);
                copy_str(out->name, names[i], sizeof out->name);
                snprintf(out->help, sizeof out->help, "%s%s", d->label, i == cur ? " \xc2\xb7 now" : "");
                return 1;
            }
            return 0;
        }
        size_t kn = strlen(key);
        for (int i = 0; i < N_SETTINGS; i++) {
            const setting_def_t *d = &SETTINGS[i];
            if (strncmp(d->key, key, kn) != 0 || nth-- > 0) continue;
            int takes = setting_choices(d->id, &names, &n) >= 0 || d->kind == K_TEXT;
            snprintf(out->line, sizeof out->line, "set %s%s", d->key, takes ? " " : "");
            snprintf(out->name, sizeof out->name, "set %s", d->key);
            copy_str(out->args, d->values ? d->values : "", sizeof out->args);
            char v[96]; setting_value(d->id, v, sizeof v);
            snprintf(out->help, sizeof out->help, "%s \xc2\xb7 %s", d->label, v);
            return 1;
        }
        return 0;
    }
    if (strchr(typed, ' ')) return 0;
    copy_str(out->group, "commands", sizeof out->group);
    size_t tn = strlen(typed);
    for (const command_t *const *t = ALL_COMMANDS; *t; t++) {
        for (const command_t *c = *t; c->name; c++) {
            if (*t != APP_COMMANDS && cmd_find(APP_COMMANDS, c->name)) continue;
            if (strncmp(c->name, typed, tn) != 0 || nth-- > 0) continue;
            snprintf(out->line, sizeof out->line, "%s%s", c->name, c->args ? " " : "");
            copy_str(out->name, c->name, sizeof out->name);
            copy_str(out->args, c->args ? c->args : "", sizeof out->args);
            copy_str(out->help, c->help, sizeof out->help);
            return 1;
        }
    }
    return 0;
}

// Runs "name args" typed on the COMMAND line, after ':'.
static void run_command(const char *line) {
    char word[CMD_WORD_MAX];
    const char *arg = cmd_parse(line, word);
    if (!word[0]) return;
    const command_t *cmd = cmd_find(APP_COMMANDS, word);
    if (cmd) { cmd->run(NULL, arg); return; }
    if (!cmd_find(CHAT_COMMANDS, word)) { note("no command :%s - :help lists them", word); return; }
    if (!g_app.selected) {
        note(":%s needs a session - Ctrl+N (or :new) creates one, Ctrl+J (or :join) joins one", word);
        return;
    }
    if (strcmp(word, "send") == 0 && !arg[strspn(arg, " ")]) { begin_send_browse(); return; }
    g_echo = strcmp(word, "download") == 0 || strcmp(word, "dl") == 0 || strcmp(word, "cancel") == 0 || strcmp(word, "send") == 0;
    cmd_result_t r = chat_run_command(&g_app.selected->engine, line);
    g_echo = 0;
    if (r == CMD_QUIT) close_session(g_app.selected);
}

static void submit_prompt(void) {
    tui_input_t *input = &g_app.input;
    switch (g_app.mode) {
        case MODE_NEW_PASSWORD: {
            char session_id[MAX_SESSION_NAME + 1], pw[sizeof input->buf];
            random_session_id(session_id, 10);
            copy_str(pw, input->buf, sizeof pw);
            end_prompt();
            start_session(session_id, pw, 1, 0, NULL, 0);
            crypto_wipe(pw, sizeof pw);
            break;
        }
        case MODE_JOIN_ID:
            if (input->len == 0) break;
            copy_str(g_app.pending_session_id, input->buf, sizeof g_app.pending_session_id);
            tui_input_clear(input);
            g_app.mode = MODE_JOIN_PASSWORD;
            g_app.dirty = 1;
            break;
        case MODE_JOIN_PASSWORD: {
            char session_id[MAX_SESSION_NAME + 1], pw[sizeof input->buf];
            copy_str(session_id, g_app.pending_session_id, sizeof session_id);
            copy_str(pw, input->buf, sizeof pw);
            end_prompt();
            start_session(session_id, pw, 0, 0, NULL, 0);
            crypto_wipe(pw, sizeof pw);
            break;
        }
        default:
            break;
    }
}

static void submit_chat_line(void) {
    tui_input_t *input = &g_app.input;
    g_app.dirty = 1;

    if (input->mode == TUI_IMODE_COMMAND) {
        char line[sizeof input->cmd];
        copy_str(line, input->cmd, sizeof line);
        // Enter on a line the menu would complete runs what the menu has selected, so ":se" runs ":set",
        // as the menu shows.
        tui_suggestion_t s;
        size_t n = strlen(line);
        if ((n > 0 || input->menu_sel > 0) && tui_input_completion(input, &s)) copy_str(line, s.line, sizeof line);
        // If opened by typing '/', a line that turns out not to be a command is the start of a message.
        // It goes back in the input as text, for Enter to send.
        char word[CMD_WORD_MAX];
        cmd_parse(line, word);
        if (input->cmd_as_text && line[0] && !command_word(word, 1)) {
            tui_input_command_to_text(input);
            crypto_wipe(line, sizeof line);
            return;
        }
        tui_input_end_command(input);
        crypto_wipe(input->cmd, sizeof input->cmd);
        run_command(line);
        crypto_wipe(line, sizeof line);
        return;
    }

    const char *text = input->buf;
    while (*text == ' ') text++;
    if (!text[0]) return;
    if (!g_app.selected) {
        note("no session yet - ctrl+n starts one, ctrl+j joins one");
        return;
    }
    if (!session_ready(g_app.selected)) {
        note(g_app.selected->initialising ? "still starting - hold on a moment"
                                          : "not connected yet - your text is kept until someone answers");
        return;
    }
    // Over the limit the end would be cut off when sent. The count under the box is red, and this
    // explains why Enter didn't send.
    if (input->len > MAX_TEXT) {
        note("too long to send by %d - a message holds %d bytes", input->len - MAX_TEXT, MAX_TEXT);
        return;
    }
    chat_send_text(&g_app.selected->engine, input->buf, now_seconds());
    tui_input_clear(input);
    g_app.selected->scroll = 0;
    // Sending a reply counts as reading, so the new messages line is removed.
    g_app.selected->has_new = 0;
}

// PgUp and PgDn (Ctrl+U and Ctrl+D in NORMAL) scroll the chat by a third of the screen's rows. G
// goes back to the newest.
static void scroll_chat(int dir) {
    session_slot_t *s = g_app.selected;
    if (!s) return;
    int rows_n, cols_n;
    term_get_size(&rows_n, &cols_n);
    int page = rows_n / 3 > 1 ? rows_n / 3 : 1;
    long v = dir == 0 ? 0 : (long)s->scroll + (long)dir * page;
    if (v > s->sb.count - 1) v = s->sb.count - 1;
    if (v < 0) v = 0;
    s->scroll = (int)v;
    g_app.dirty = 1;
}

static void handle_key(const tui_key_t *key) {
    tui_input_t *input = &g_app.input;

    // The terminal's reports aren't keys, so they don't clear the bar's message.
    if (key->type == TUI_KEY_BG_REPORT) {
        tui_set_background((const uint8_t *)key->ch);
        g_app.dirty = 1;
        return;
    }
    if (key->type == TUI_KEY_THEME_CHANGED) {
        platform_write_stdout(TUI_THEME_QUERY, sizeof TUI_THEME_QUERY - 1);
        g_app.dirty = 1;
        return;
    }

    // A message is the result of the previous key, so this key resets the bar.
    if (g_app.message[0]) { g_app.message[0] = '\0'; g_app.dirty = 1; }

    if (key->type == TUI_KEY_CTRL_C) { g_app.asking_quit = 1; g_app.dirty = 1; return; }
    if (g_app.asking_quit) { quit_key(key); return; }

    // The pages draw their fields in their rows, so a key there redraws the page.
    switch (g_app.mode) {
        case MODE_HELP:            help_key(key); return;
        case MODE_CHANGELOG:       changelog_key(key); return;
        case MODE_SETTINGS:        settings_key(key); return;
        case MODE_SIGN_CHOICE:     sign_picker_key(key); return;
        case MODE_SIGN_BROWSE: browser_key(key); return;
        case MODE_SEND_BROWSE: send_browser_key(key); return;
        case MODE_SAVE_BROWSE: save_browser_key(key); return;
        case MODE_FILES:       files_key(key); return;
        case MODE_FILE_VIEW:   viewer_key(key); return;
        case MODE_FILE_ASK:    confirm_key(key, file_ask_yes, file_ask_no); return;
        case MODE_SIGN_PASTE:  paste_key(key); return;
        case MODE_SIGN_PASSWORD:  field_key(key, commit_sign_password, end_sign_password); return;
        case MODE_SIGN_PATH:      field_key(key, commit_key_path, end_key_path); return;
        case MODE_SETTINGS_EDIT:  field_key(key, commit_setting_edit, end_setting_edit); return;
        case MODE_NEW_PASSWORD:
        case MODE_JOIN_ID:
        case MODE_JOIN_PASSWORD:  field_key(key, submit_prompt, end_prompt); return;
        case MODE_INSTALL:        confirm_key(key, install_confirmed, cancel_install); return;
        case MODE_INSTALL_PASS:   field_key(key, commit_install_pass, cancel_install); return;
        case MODE_INSTALL_PASS2:  field_key(key, commit_install_pass2, cancel_install); return;
        case MODE_INSTALL_UNLOCK: field_key(key, commit_install_unlock, back_from_install_unlock); return;
        case MODE_INSTALL_EXISTING:  choice_key(key, install_use_existing, install_new_save, cancel_install); return;
        case MODE_INSTALL_PICK:      install_pick_key(key); return;
        case MODE_INSTALL_OVERWRITE: confirm_key(key, install_overwrite_yes, cancel_install); return;
        case MODE_INSTALL_NAME:   field_key(key, commit_install_name, back_from_install_name); return;
        case MODE_INSTALL_FIRST:  confirm_key(key, install_first_yes, install_first_no); return;
        case MODE_UNINSTALL:      confirm_key(key, uninstall_confirmed, cancel_uninstall); return;
        case MODE_SAVES:          saves_key(key); return;
        case MODE_UNLOCK:         field_key(key, commit_unlock, back_from_unlock); return;
        case MODE_DEVICE_LOCK:    confirm_key(key, device_lock_yes, device_lock_no); return;
        case MODE_FACTOR:         confirm_key(key, factor_yes, factor_no); return;
        case MODE_CODE_SETUP:     code_setup_key(key); return;
        case MODE_KEY_WAIT:       key_wait_key(key); return;
        case MODE_KEY_PIN:        field_key(key, commit_key_pin, cancel_key_pin); return;
        case MODE_UNLOCK_CODE:    field_key(key, commit_unlock_code, back_from_unlock_code); return;
        case MODE_SHADOW_PASS:    field_key(key, commit_shadow_pass, cancel_shadow_pass); return;
        case MODE_SHADOW_PASS2:   field_key(key, commit_shadow_pass2, cancel_shadow_pass); return;
        case MODE_UPDATE:         update_key(key); return;
        default:
            break;
    }

    tui_input_mode_t was = input->mode;
    if (tui_input_feed(input, key)) {
        // The menu above the COMMAND line covers part of the chat, so it needs a full frame.
        if (was == TUI_IMODE_COMMAND || input->mode == TUI_IMODE_COMMAND) g_app.dirty = 1;
        else g_app.input_dirty = 1;
        return;
    }

    // NORMAL leaves these to the app: j and k switch sessions, like moving through a list, G goes back
    // to the newest message, ? opens the help, f the files, and c, C and s show or hide the console,
    // the chat and the sidebar.
    if (key->type == TUI_KEY_CHAR && input->mode == TUI_IMODE_NORMAL) {
        switch (key->ch[0]) {
            case 'j': select_step(1); break;
            case 'k': select_step(-1); break;
            case 'G': scroll_chat(0); break;
            case '?': begin_help(); break;
            case 'f': begin_files(); break;
            case 'c': g_app.show_console = !g_app.show_console; g_app.dirty = 1; break;
            case 'C': g_app.show_chat = !g_app.show_chat; g_app.dirty = 1; break;
            case 's': g_app.show_sidebar = !g_app.show_sidebar; g_app.dirty = 1; break;
            default: break;
        }
        return;
    }

    switch (key->type) {
        case TUI_KEY_TAB:            select_step(1); break;
        case TUI_KEY_BACKTAB:        select_step(-1); break;
        case TUI_KEY_NEW_SESSION:    begin_prompt(MODE_NEW_PASSWORD); break;
        case TUI_KEY_JOIN_SESSION:   begin_prompt(MODE_JOIN_ID); break;
        case TUI_KEY_TOGGLE_SIDEBAR: g_app.show_sidebar = !g_app.show_sidebar; g_app.dirty = 1; break;
        case TUI_KEY_TOGGLE_CONSOLE: g_app.show_console = !g_app.show_console; g_app.dirty = 1; break;
        case TUI_KEY_TOGGLE_CHAT:    g_app.show_chat = !g_app.show_chat; g_app.dirty = 1; break;
        case TUI_KEY_SETTINGS:       begin_settings(); break;
        case TUI_KEY_HELP:           begin_help(); break;
        case TUI_KEY_FILES:          begin_files(); break;
        case TUI_KEY_PAGE_UP:
        case TUI_KEY_CTRL_U:         scroll_chat(1); break;
        case TUI_KEY_PAGE_DOWN:
        case TUI_KEY_CTRL_D:         scroll_chat(-1); break;
        case TUI_KEY_ENTER:          submit_chat_line(); break;
        default: break;
    }
}

// :install's own boxes, over the page install_back says.
static int install_mode(app_mode_t m) {
    switch (m) {
        case MODE_INSTALL: case MODE_INSTALL_PASS: case MODE_INSTALL_PASS2: case MODE_INSTALL_UNLOCK:
        case MODE_INSTALL_EXISTING: case MODE_INSTALL_PICK: case MODE_INSTALL_OVERWRITE: case MODE_INSTALL_NAME:
        case MODE_INSTALL_FIRST:
            return 1;
        case MODE_UNLOCK_CODE:
            return g_app.key_purpose == KP_INSTALL_UNLOCK;
        default:
            return 0;
    }
}

static int on_chat_screen(void) {
    if (install_mode(g_app.mode)) return g_app.install_back == MODE_CHAT;
    switch (g_app.mode) {
        case MODE_CHAT: case MODE_NEW_PASSWORD: case MODE_JOIN_ID: case MODE_JOIN_PASSWORD:
        case MODE_UNINSTALL: case MODE_SAVES: case MODE_UNLOCK: case MODE_UPDATE: case MODE_UNLOCK_CODE:
            return 1;
        case MODE_DEVICE_LOCK:
            return g_app.device_back == MODE_CHAT;
        case MODE_FACTOR: case MODE_CODE_SETUP: case MODE_KEY_WAIT: case MODE_KEY_PIN:
        case MODE_SHADOW_PASS: case MODE_SHADOW_PASS2:
            return g_app.factor_back == MODE_CHAT;
        default:
            return 0;
    }
}

static int session_count(void) {
    int n = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) n += g_app.used[i] != 0;
    return n;
}

static tui_session_state_t session_state(const session_slot_t *s) {
    if (s->initialising) return TUI_SESSION_STARTING;
    return chat_ready(&s->engine) ? TUI_SESSION_LIVE : TUI_SESSION_CONNECTING;
}

// What the chat shows while a session has no messages: its progress, and what to do next.
static const char *session_empty_text(const session_slot_t *s) {
    static char text[400];
    const chat_t *e = &s->engine;
    if (s->initialising)
        copy_str(text, "Starting the session\nDeriving its keys - this takes a moment.", sizeof text);
    else if (!chat_ready(e))
        snprintf(text, sizeof text, "Connecting to %s\nThe chat opens once someone in the session answers.\n"
                 "Finding them can take a minute%s.", s->name, e->route.mode == ROUTE_TOR ? " over Tor" : "");
    else if (chat_online_count(e) == 0)
        snprintf(text, sizeof text, "No one else is here yet\nTo invite peers, share the session id and its "
                 "password.\n\n%s\n/copyid copies the id", s->name);
    else
        copy_str(text, "No messages yet\nSay hello - it's end-to-end encrypted.", sizeof text);
    return text;
}

// The chat pane: the selected session's name, how it's connected, what to show while it's empty,
// where the messages that arrived while it was away start, and unread counts for other sessions.
static tui_view_t current_view(char *sub, size_t cap) {
    tui_view_t v = { g_app.show_sidebar, g_app.show_console, g_app.show_chat, NULL, NULL, TUI_SESSION_LIVE,
                     NULL, NULL, 0, NULL, NULL, NULL, 0, 0, 0, NULL, TEST_BUILD ? TEST_LABEL : NULL };
    for (int i = 0; i < MAX_SESSIONS; i++) {
        const session_slot_t *o = &g_app.sessions[i];
        if (!g_app.used[i] || o == g_app.selected) continue;
        v.elsewhere += o->unread;
        v.elsewhere_mention |= o->mentioned;
    }
    const session_slot_t *s = g_app.selected;
    if (!s) return v;
    v.title = s->name;
    v.state = session_state(s);
    v.scroll = s->scroll;
    v.empty = session_empty_text(s);
    v.image = pic_for;
    v.image_ctx = s;
    if (!s->initialising) {
        v.self = s->engine.nick;
        v.progress = progress_for;
    }
    if (s->has_new) v.new_lines = (int)(s->sb.total - s->new_at);
    if (s->initialising) snprintf(sub, cap, "starting");
    else snprintf(sub, cap, "%d online \xc2\xb7 %s", chat_online_count(&s->engine) + 1, routing_mode_name(s->engine.route.mode));
    v.subtitle = sub;
    return v;
}

// Who in s doesn't get what you send until their verify code is compared, for the input box's title
// while that's the case, since the console's note that a message went to nobody is easy to miss.
// NULL when everyone gets it, or the setting sends to everyone anyway.
static const char *held_warning(const session_slot_t *s) {
    static char warn[64 + CHAT_NAME_LEN * 2];
    if (!s || !session_ready(s) || !s->engine.verify_required) return NULL;
    const chat_t *e = &s->engine;
    int held = 0;
    char first[CHAT_NAME_LEN] = "";
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        const peer_t *p = &e->peers[i];
        int code = chat_code_state(e, p);
        if (!p->used || !p->ok || (code != 1 && !(code == 4 && e->verify_required))) continue;
        if (held++ == 0) chat_peer_name(e, p, first);
    }
    if (held == 0) return NULL;
    if (held == 1)
        snprintf(warn, sizeof warn, "not sent to %s until you compare codes \xc2\xb7 :verify %s", first, first);
    else
        snprintf(warn, sizeof warn, "not sent to %d peers until you compare codes \xc2\xb7 :peers", held);
    return warn;
}

// The chat screen's input: its faint text while it's empty, and what the keys do there.
static void chat_input(tui_bar_t *b, const tui_input_t *in) {
    static char placeholder[MAX_SESSION_NAME + 64];
    static char hint[160];
    const session_slot_t *s = g_app.selected;
    tui_input_mode_t m = in->mode;
    b->chip = tui_mode_name(m);
    b->tone = m == TUI_IMODE_NORMAL ? TUI_TONE_NORMAL : m == TUI_IMODE_COMMAND ? TUI_TONE_COMMAND : TUI_TONE_INSERT;
    b->input = in;
    b->limit = MAX_TEXT;
    b->warn = held_warning(s);
    if (m == TUI_IMODE_NORMAL) {
        b->placeholder = "i to type \xc2\xb7 : for a command";
        b->hint = s && !s->initialising ? "i type \xc2\xb7 : command \xc2\xb7 f files \xc2\xb7 j/k session \xc2\xb7 pgup/pgdn scroll \xc2\xb7 ? help"
                                        : "i type \xc2\xb7 : command \xc2\xb7 j/k session \xc2\xb7 pgup/pgdn scroll \xc2\xb7 ? help";
        return;
    }
    if (m == TUI_IMODE_COMMAND) {
        b->hint = "enter run \xc2\xb7 tab complete \xc2\xb7 \xe2\x86\x91\xe2\x86\x93 choose \xc2\xb7 esc back";
        return;
    }
    if (!s) {
        b->placeholder = "No session yet \xc2\xb7 ctrl+n starts one, ctrl+j joins one, / for commands";
        b->hint = "ctrl+n new \xc2\xb7 ctrl+j join \xc2\xb7 / commands \xc2\xb7 ctrl+s settings";
        return;
    }
    if (s->initialising) snprintf(placeholder, sizeof placeholder, "Starting %s\xe2\x80\xa6", s->name);
    else if (!session_ready(s)) snprintf(placeholder, sizeof placeholder, "Waiting for someone in %s to answer\xe2\x80\xa6", s->name);
    else snprintf(placeholder, sizeof placeholder, "Message %s", s->name);
    b->placeholder = placeholder;
    snprintf(hint, sizeof hint, "enter send \xc2\xb7 / commands%s%s \xc2\xb7 esc normal \xc2\xb7 f1 help",
             session_count() > 1 ? " \xc2\xb7 tab next session" : "",
             !s->initialising && s->engine.file_seq > 0 ? " \xc2\xb7 ctrl+f files" : "");
    b->hint = hint;
}

// ---- the dialogs ----

#define MAX_DIALOG_PARAS 48

static int add_para(tui_para_t *p, int n, tui_para_kind_t kind, const char *text) {
    p[n] = (tui_para_t){ .kind = kind, .text = text };
    return n + 1;
}

static int install_paras(tui_para_t *p) {
    static char settings[1200], key[1400], intro[600], verified[1200], outro[400], device[1200], factors[300];
    char where[900] = "";
    const char *target = g_app.save_target;
    install_where(target, where, sizeof where);
    snprintf(settings, sizeof settings, "`%s/settings`: the settings you've changed - your nickname, colour, routing, "
             "relays and the like. Never the Tor control password.", where);
    int same = is_current_save(target), exists = save_exists(target), open = g_app.installed && same;
    snprintf(verified, sizeof verified, "`%s/verified`: the signing keys of peers whose verify code you compared "
             "(`:verify NICK ok`), with their nicks, so they don't need comparing again (%d now). `:verified` lists "
             "them.", where, trust_count());
    int saved = install_has_key(target);
    if (g_app.identity_source == IDENT_NONE && saved)
        snprintf(key, sizeof key, "`%s/key`: the signing key saved there stays as it is, though signing is off now.", where);
    else if (g_app.identity_source == IDENT_NONE)
        copy_str(key, "No signing key: signing is off. One you choose later (`:set sign`) is kept by `:install` again, "
                 "under the same passphrase.", sizeof key);
    else if (same && key_in_use_saved())
        snprintf(key, sizeof key, "`%s/key`: your signing key%s, saved already. It stays as it is.", where,
                 g_app.saved_key_path[0] ? "'s path" : "");
    else if (key_saved_as_path()) {
        char shown[KEY_PATH_MAX];
        tilde_path(g_app.key_path, shown, sizeof shown);
        snprintf(key, sizeof key, "`%s/key`: the path to your signing key, `%.600s`. The key itself isn't copied: "
                 "chat reads the file each time it starts.%s", where, shown, saved ? " It replaces what's saved there now." : "");
    } else
        snprintf(key, sizeof key, "`%s/key`: your signing key.%s", where, saved ? " It replaces the key saved there now." : "");
    int others = 0;
    for (int i = 0; i < g_app.n_saves; i++) others += !exists || strcmp(g_app.saves[i].name, target) != 0;
    if (open)
        snprintf(intro, sizeof intro, "`%s` is already installed, in `%s`, and open. Save what's in use now to it, in "
                 "place of what's saved there:", install_shown_name(target), where);
    else if (exists)
        snprintf(intro, sizeof intro, "chat is installed here%s%s%s: this saves what's in use now in place of what's "
                 "saved. **The files are a trail**: they tell anyone who can read this disk (an admin, malware, a "
                 "backup, forensics) that chat is used here.", target[0] ? " as `" : "", target, target[0] ? "`" : "");
    else if (others > 0 || g_app.installed)
        snprintf(intro, sizeof intro, "This makes a new save, `%s`, next to what `:install` saved already, with its "
                 "own passphrase. When there's more than one save, chat asks which one to open when it starts, or "
                 "`--save NAME` picks it. **The files are a trail**: they tell anyone who can read this disk (an admin, "
                 "malware, a backup, forensics) that chat is used here.", install_shown_name(target));
    else
        copy_str(intro, "Until you install, chat keeps nothing on disk. **Installing leaves a trail**: files that tell "
                 "anyone who can read this disk (an admin, malware, a backup, forensics) that chat is used here.",
                 sizeof intro);
    int n = add_para(p, 0, TUI_P_TEXT, intro);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_BULLET, settings);
    n = add_para(p, n, TUI_P_BULLET, key);
    n = add_para(p, n, TUI_P_BULLET, verified);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, open
        ? "It's all sealed (Argon2id, XChaCha20-Poly1305) with the passphrase it's sealed with now: there's "
          "nothing to type."
        : exists
        ? "It's all sealed (Argon2id, XChaCha20-Poly1305) with the passphrase of what's saved there now, asked for next."
        : "It's all sealed (Argon2id, XChaCha20-Poly1305) with one passphrase you choose next, which chat asks for "
          "when it starts.");
    n = add_para(p, n, TUI_P_BLANK, "");
    device[0] = '\0';
    if (!exists && g_app.device_lock && g_app.device_kind == DEVICE_NONE)
        copy_str(device, "**Device lock is on**, but this device can't lock anything now, so installing stops there and "
                 "says why.", sizeof device);
    else if (!exists && g_app.device_lock)
        copy_str(device, "**Locked to this device** as well: its files won't open anywhere else, even with the "
                 "passphrase. The next box says what would lose it for good.", sizeof device);
    else if (!exists && g_app.device_kind != DEVICE_NONE)
        copy_str(device, "Not locked to this device: a copy of the files opens anywhere with the passphrase. "
                 "`:set devicelock on` locks it to this device as well, once it's installed.", sizeof device);
    else if (!exists)
        snprintf(device, sizeof device, "Not locked to this device, which can't lock a save to it: %s.",
                 g_app.device_why);
    else if (open && install_device_lock() != DEVICE_NONE)
        copy_str(device, "It stays locked to this device.", sizeof device);
    if (device[0]) {
        n = add_para(p, n, TUI_P_TEXT, device);
        n = add_para(p, n, TUI_P_BLANK, "");
    }
    if (!exists && (g_app.key_factor || g_app.code_factor)) {
        snprintf(factors, sizeof factors, "%s%s%s",
                 g_app.key_factor ? "**It needs your security key** as well: a box registers it next, with two touches."
                                  : "",
                 g_app.key_factor && g_app.code_factor ? " " : "",
                 g_app.code_factor ? "**It asks for an authenticator code** as well: a box shows a QR code to scan." : "");
        n = add_para(p, n, TUI_P_TEXT, factors);
        n = add_para(p, n, TUI_P_BLANK, "");
    }
    snprintf(outro, sizeof outro, "%s Never saved: sessions, their passwords, messages or files. `:uninstall` deletes "
             "it all - but a disk and its backups can keep traces of deleted files.", g_app.autosave
             ? "Settings and verified keys you change from then on are saved as you change them (`:set autosave off` "
               "stops that)."
             : "Autosave is off: what you change from then on lasts until you `:save` again (`:set autosave on` saves "
               "it as you go).");
    return add_para(p, n, TUI_P_TEXT, outro);
}

static int install_first_paras(tui_para_t *p) {
    static char text[500];
    unsigned f = g_app.install_for;
    const char *what = f == INSTALL_FACTOR_DEVICE ? "The device lock"
                     : f == INSTALL_FACTOR_KEY ? "A security key" : "An authenticator app";
    const char *then = f == INSTALL_FACTOR_DEVICE ? "locks it to this device"
                     : f == INSTALL_FACTOR_KEY ? "registers your security key for it, with two touches"
                     : "shows a QR code that adds it to your authenticator app";
    if (g_app.n_saves > 0)
        snprintf(text, sizeof text, "**%s needs a save open first**, and none is. Install now? Yes goes through "
                 "`:install`, which opens a save here or makes a new one, and %s.", what, then);
    else
        snprintf(text, sizeof text, "**%s needs chat installed first.** Until `:install` saves your settings, sealed "
                 "with a passphrase, chat keeps nothing on disk. Install now? Yes goes through `:install`, which makes "
                 "a save and %s.", what, then);
    return add_para(p, 0, TUI_P_TEXT, text);
}

// What would lose the save comes straight after the intro, since a box too tall for the screen
// loses its end.
static int device_lock_paras(tui_para_t *p) {
    static char intro[600], lead[160], uses[900];
    static const char *losses[DEVICE_LOSSES_MAX + 2];
    const char *shown = install_shown_name(g_app.device_new ? g_app.save_target : install_current());
    if (!g_app.device_want) {
        snprintf(intro, sizeof intro, "This seals the save `%s` again with its passphrase alone: its files open wherever "
                 "they're copied, for anyone with the passphrase, as if it had never been locked. `:set devicelock on` "
                 "locks it again.", shown);
        return add_para(p, 0, TUI_P_TEXT, intro);
    }
    snprintf(intro, sizeof intro, "%s `%s` %s: it only opens here, with its passphrase. A copy of its files anywhere "
             "else, from a backup or from the disk itself, can't be opened, even with the passphrase.",
             g_app.device_new ? "The new save" : "This locks the save", shown,
             g_app.device_new ? "is locked to this device" : "to this device");
    int key = g_app.device_new ? g_app.identity_source != IDENT_NONE && !key_saved_as_path()
                               : install_has_key(install_current()) && !g_app.saved_key_path[0];
    snprintf(lead, sizeof lead, "**The save is gone for good%s, with no way back, if:**",
             key ? ", and the signing key only saved in it" : "");
    int n_losses = platform_device_losses(g_app.device_kind, losses, DEVICE_LOSSES_MAX);
    losses[n_losses++] = "its `device` file is deleted: a backup it's restored from needs that file too";
    losses[n_losses++] = "this computer breaks or is lost";
    snprintf(uses, sizeof uses, "It uses %s.", platform_device_uses(g_app.device_kind));
    int n = add_para(p, 0, TUI_P_TEXT, intro);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, lead);
    for (int i = 0; i < n_losses; i++) n = add_para(p, n, TUI_P_BULLET, losses[i]);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, "Before one of those you can see coming, like a firmware update or a reinstall, "
                                   "`:set devicelock off` here first, then lock it again after.");
    n = add_para(p, n, TUI_P_BLANK, "");
    return add_para(p, n, TUI_P_TEXT, uses);
}

// The save a factor box is for: the new one :install is making, or the open one.
static const char *factor_save(void) {
    return install_shown_name(g_app.factor_new ? g_app.save_target : install_current());
}

static int factor_paras(tui_para_t *p) {
    static char intro[800], lead[160];
    const char *shown = factor_save();
    if (g_app.factor == INSTALL_FACTOR_CODE) {
        snprintf(intro, sizeof intro, "This stops the save `%s` asking for the code your authenticator app shows. Its "
                 "`authenticator` file is deleted, and with it the secret the codes come from: delete the save's entry "
                 "from the app too. `:set authenticator on` sets up a new one.", shown);
        return add_para(p, 0, TUI_P_TEXT, intro);
    }
    if (!g_app.factor_want) {
        snprintf(intro, sizeof intro, "This seals the save `%s` again without the security key, as if it had never needed "
                 "one: a copy of its files opens with what else it needs. Its `securitykey` file is deleted. The security "
                 "key keeps nothing for it, so there's nothing to delete from the key.", shown);
        return add_para(p, 0, TUI_P_TEXT, intro);
    }
    snprintf(intro, sizeof intro, "%s `%s` %s your security key as well as its passphrase: a FIDO2 key with hmac-secret, "
             "which most have (YubiKey 5, Nitrokey 3, SoloKey 2, Google Titan...). Each time it opens, chat asks you to "
             "touch the key, which gives back a secret that goes into the key the files are sealed with. Without the "
             "security key, the passphrase opens nothing, wherever the files are copied.",
             g_app.factor_new ? "The new save" : "This makes the save", shown, g_app.factor_new ? "needs" : "need");
    int key = g_app.factor_new ? g_app.identity_source != IDENT_NONE && !key_saved_as_path()
                               : install_has_key(install_current()) && !g_app.saved_key_path[0];
    snprintf(lead, sizeof lead, "**The save is gone for good%s, with no way back, if:**",
             key ? ", and the signing key only saved in it" : "");
    int n = add_para(p, 0, TUI_P_TEXT, intro);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, lead);
    n = add_para(p, n, TUI_P_BULLET, "the security key is lost or broken");
    n = add_para(p, n, TUI_P_BULLET, "it's reset: a FIDO reset (from its maker's app, or `ykman fido reset`) wipes what "
                                     "it needs to give the secret back");
    n = add_para(p, n, TUI_P_BULLET, "its `securitykey` file is deleted: a backup it's restored from needs that file too");
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, "Before you reset it or stop using it, `:set securitykey off` first.");
    n = add_para(p, n, TUI_P_BLANK, "");
#ifdef _WIN32
    return add_para(p, n, TUI_P_TEXT, "Windows asks for the security key in a window of its own, twice: once to register "
                                      "it and once to read its secret.");
#else
    return add_para(p, n, TUI_P_TEXT, "Registering it takes two touches, one after the other: plug it in now. chat asks "
                                      "for its PIN only if the key wants it.");
#endif
}

// The authenticator secret's QR code: a row for two modules, with the 4 modules of light margin a
// scanner needs. Drawn in the terminal's own foreground, which is the light modules on a dark theme
// and the dark ones on a light theme, so it comes out dark on light either way.
#define QR_ROWS_MAX ((QR_MAX_SIZE + 9) / 2)
#define QR_ROW_BYTES ((QR_MAX_SIZE + 8) * 3 + 1)
_Static_assert(QR_ROWS_MAX + 8 <= MAX_DIALOG_PARAS, "the authenticator's box holds its QR code and its text");

static int qr_ink(const uint8_t *m, int size, int x, int y, int light) {
    int dark = x >= 0 && y >= 0 && x < size && y < size && m[y * size + x];
    return light ? dark : !dark;
}

// Returns how many rows, each as wide as the first is long in columns, or 0.
static int qr_rows(const char *text, char rows[QR_ROWS_MAX][QR_ROW_BYTES], int *cols) {
    static uint8_t m[QR_MAX_SIZE * QR_MAX_SIZE];
    int size = qr_encode(text, m);
    if (size < 0) return 0;
    int full = size + 8, light = tui_background_light(), n = 0;
    for (int y = 0; y < full; y += 2) {
        char *o = rows[n++];
        for (int x = 0; x < full; x++) {
            int top = qr_ink(m, size, x - 4, y - 4, light);
            int bottom = y + 1 < full && qr_ink(m, size, x - 4, y - 3, light);
            const char *g = top && bottom ? "\xe2\x96\x88" : top ? "\xe2\x96\x80" : bottom ? "\xe2\x96\x84" : " ";
            size_t gl = strlen(g);
            memcpy(o, g, gl);
            o += gl;
        }
        *o = '\0';
    }
    *cols = full;
    return n;
}

static int code_setup_text(tui_para_t *p, int n, int qr) {
    static char scan[400];
    snprintf(scan, sizeof scan, "%s your authenticator app (Aegis, Google Authenticator, 2FAS...)%s, then type the 6-digit "
             "code it shows for `chat:%s`, to be sure it has it.", qr ? "Scan this with" : "Type the secret below into",
             qr ? ", or type in the secret below" : "", factor_save());
    n = add_para(p, n, TUI_P_TEXT, scan);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, "**A check chat makes, not a lock on the files:** the secret the codes come from is "
                                   "kept in the save, sealed with it, so whoever can open its files (with the passphrase, "
                                   "and the device or security key if they're on) can make the codes too. It stops "
                                   "someone who knows your passphrase opening the save in chat without your phone. The "
                                   "security key or the device lock protect the files themselves.");
    n = add_para(p, n, TUI_P_BLANK, "");
    return add_para(p, n, TUI_P_TEXT, "Lose the app's entry and chat won't open the save, so keep a copy of the secret "
                                      "somewhere safe, or `:set authenticator off` first.");
}

// The QR code goes over the text only when neither is cut off: a cut QR code can't be scanned, and
// the text's warning is at its end. Otherwise Tab swaps the text for the QR code alone, if that fits.
static void code_setup_dialog(tui_dialog_t *d, tui_para_t *p) {
    static char rows[QR_ROWS_MAX][QR_ROW_BYTES], secret[200], keys[80];
    const char *enter = g_app.factor_new ? "enter next" : "enter turn on";
    int term_rows, term_cols, qr_cols = 0, alone = 0;
    term_get_size(&term_rows, &term_cols);
    int nq = qr_rows(g_app.code_uri, rows, &qr_cols);
    char grouped[48];
    size_t g = 0;
    for (size_t i = 0; g_app.code_b32[i] && g + 2 < sizeof grouped; i++) {
        if (i && i % 4 == 0) grouped[g++] = ' ';
        grouped[g++] = g_app.code_b32[i];
    }
    grouped[g] = '\0';
    snprintf(secret, sizeof secret, "Secret: %s", grouped);
    crypto_wipe(grouped, sizeof grouped);

    if (nq > 0 && term_cols >= qr_cols + 12) {
        for (int i = 0; i < nq; i++) add_para(p, i, TUI_P_ART, rows[i]);
        d->n_text = code_setup_text(p, add_para(p, nq, TUI_P_BLANK, ""), 1);
        d->note = secret;
        snprintf(keys, sizeof keys, "%s \xc2\xb7 esc cancel", enter);
        d->keys = keys;
        if (tui_dialog_rows(term_cols, d) <= term_rows) return;
        d->n_text = nq;
        d->note = NULL;
        alone = tui_dialog_rows(term_cols, d) <= term_rows;
        if (alone && g_app.code_qr) {
            snprintf(keys, sizeof keys, "%s \xc2\xb7 tab text \xc2\xb7 esc cancel", enter);
            return;
        }
    }
    d->n_text = code_setup_text(p, 0, 0);
    size_t sl = strlen(secret);
    if (nq > 0 && !alone) snprintf(secret + sl, sizeof secret - sl, " \xc2\xb7 a bigger window shows a QR code");
    d->note = secret;
    snprintf(keys, sizeof keys, "%s%s \xc2\xb7 esc cancel", enter, alone ? " \xc2\xb7 tab QR code" : "");
    d->keys = keys;
}

static int key_wait_paras(tui_para_t *p) {
    static char text[300];
    int making = g_app.key_purpose == KP_FACTOR || g_app.key_purpose == KP_NEW_SAVE;
#ifdef _WIN32
    (void)making;
    copy_str(text, "Windows asks for the security key in a window of its own: follow it there.", sizeof text);
#else
    const char *shown = install_shown_name(g_app.key_purpose == KP_INSTALL_UNLOCK ? g_app.save_target : install_current());
    if (g_app.key_stage == SECKEY_LOOKING && making)
        copy_str(text, "Plug in your security key.", sizeof text);
    else if (g_app.key_stage == SECKEY_LOOKING)
        snprintf(text, sizeof text, "Plug in the security key the save `%s` was locked with.", shown);
    else if (g_app.key_stage == SECKEY_TOUCH && making)
        snprintf(text, sizeof text, "**Touch your security key now** (%d of 2): it's blinking.", g_app.key_touches + 1);
    else if (g_app.key_stage == SECKEY_TOUCH)
        snprintf(text, sizeof text, "**Touch your security key now**, to open `%s`: it's blinking.", shown);
    else
        copy_str(text, "Asking the security key...", sizeof text);
#endif
    return add_para(p, 0, TUI_P_TEXT, text);
}

static int uninstall_paras(tui_para_t *p) {
    static char what[1200];
    char where[900] = "";
    const char *target = g_app.save_target;
    install_where(target, where, sizeof where);
    int settings = install_has_settings(target), key = install_has_key(target), same = is_current_save(target);
    snprintf(what, sizeof what, "This deletes what `:install` saved in `%s`: your %s, and the signing keys of peers "
             "you verified.%s%s", where,
             settings && key ? "sealed settings and signing key" : settings ? "sealed settings" : "sealed signing key",
             install_factors(target) & INSTALL_FACTOR_DEVICE ? " It's locked to this device, and the secret the device "
                                                               "sealed for it goes too." : "",
             same ? " What's in use now lasts until chat exits." : "");
    int n = add_para(p, 0, TUI_P_TEXT, what);
    if (key && same && g_app.saved_key_known && g_app.saved_key_path[0]) {
        n = add_para(p, n, TUI_P_BLANK, "");
        n = add_para(p, n, TUI_P_TEXT, "The saved key is only the path to your key file. The file itself isn't touched.");
    } else if (key) {
        n = add_para(p, n, TUI_P_BLANK, "");
        n = add_para(p, n, TUI_P_TEXT, "**A key saved only there is gone for good**, and with it the fingerprint peers "
                                       "know you by.");
    }
    n = add_para(p, n, TUI_P_BLANK, "");
    return add_para(p, n, TUI_P_TEXT, "Deleting isn't erasing: the disk, its snapshots and its backups can keep "
                                      "traces of the files.");
}

static const tui_dialog_t *quit_dialog(void) {
    static tui_dialog_t d;
    static tui_para_t paras[MAX_DIALOG_PARAS];
    static char what[240], files[120], unsaved[200];
    int n_sessions = 0, online = 0, downloads = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i]) continue;
        n_sessions++;
        if (g_app.sessions[i].initialising) continue;
        const chat_t *e = &g_app.sessions[i].engine;
        online += chat_online_count(e);
        for (int f = 0; f < FILE_OFFERS_MAX; f++)
            downloads += e->files[f].used && (e->files[f].dl == DL_ACTIVE || e->files[f].dl == DL_QUEUED);
    }
    const char *tor = g_tor.proc ? " Chat's own tor stops too." : "";
    if (n_sessions == 0)
        snprintf(what, sizeof what, "No sessions are open.%s", tor);
    else
        snprintf(what, sizeof what, "Quitting leaves %d session%s, with %d peer%s online: each says bye, then closes, "
                 "and its keys are wiped from memory.%s", n_sessions, n_sessions == 1 ? "" : "s",
                 online, online == 1 ? "" : "s", tor);
    int n = add_para(paras, 0, TUI_P_TEXT, what);

    const char *lost[3];
    int n_lost = 0;
    if (downloads == 1) lost[n_lost++] = "A file that's still downloading stops, and what's come of it is deleted.";
    else if (downloads) {
        snprintf(files, sizeof files, "%d files that are still downloading stop, and what's come of them is deleted.", downloads);
        lost[n_lost++] = files;
    }
    int rows = 0;
    if (g_app.installed && !g_app.autosave)
        for (int i = 0; i < N_SETTINGS; i++) rows += g_unsaved_rows[i] != 0;
    int key = g_app.installed && g_app.identity_source != IDENT_NONE && !key_in_use_saved();
    if (rows || key) {
        char settings[64];
        snprintf(settings, sizeof settings, "%d changed setting%s", rows, rows == 1 ? "" : "s");
        snprintf(unsaved, sizeof unsaved, "%s%s%s %s saved: n, then `:save`, keeps %s.",
                 rows ? settings : "", rows && key ? " and " : "", key ? (rows ? "the signing key in use" : "The signing key in use") : "",
                 rows + key > 1 ? "aren't" : "isn't", rows + key > 1 ? "them" : "it");
        lost[n_lost++] = unsaved;
    }
    update_view_t v;
    update_view(&v);
    if (v.running) lost[n_lost++] = "An update is still running, and won't be installed.";
    if (n_lost) n = add_para(paras, n, TUI_P_BLANK, "");
    for (int i = 0; i < n_lost; i++) n = add_para(paras, n, TUI_P_BULLET, lost[i]);

    d = (tui_dialog_t){ .title = "QUIT", .text = paras, .n_text = n, .keys = "y quit \xc2\xb7 n stay" };
    return &d;
}

// Its field is the input line, saved meanwhile by begin_prompt and similar.
static const tui_dialog_t *current_dialog(void) {
    static tui_dialog_t d;
    static tui_para_t paras[MAX_DIALOG_PARAS];
    static char title[64], note_text[MAX_SESSION_NAME + 64];
    d = (tui_dialog_t){ .input = &g_app.input, .mask = 1, .text = paras };
    switch (g_app.mode) {
        case MODE_NEW_PASSWORD:
            d.title = "NEW SESSION";
            d.placeholder = "password";
            d.note = "Blank is fine: it still encrypts. Whoever you invite needs the password and the session's id.";
            d.keys = "enter create \xc2\xb7 esc cancel";
            break;
        case MODE_JOIN_ID:
            d.title = "JOIN SESSION";
            d.mask = 0;
            d.placeholder = "session id";
            d.note = "The id you were given. Its password comes next.";
            d.keys = "enter next \xc2\xb7 esc cancel";
            break;
        case MODE_JOIN_PASSWORD:
            d.title = "JOIN SESSION";
            d.placeholder = "password";
            snprintf(note_text, sizeof note_text, "The password for %s, as you were given it.", g_app.pending_session_id);
            d.note = note_text;
            d.keys = "enter join \xc2\xb7 esc cancel";
            break;
        case MODE_SIGN_PASSWORD:
            d.title = g_app.load_kind == IDENT_AGE ? "NATIVE AGE KEY" : "NATIVE PGP KEY";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, SIGN_PASSWORD_HELP);
            d.placeholder = "password (blank: a new key until chat exits)";
            d.keys = "enter make the key \xc2\xb7 esc back";
            break;
        case MODE_SIGN_PATH: {
            int age = g_app.load_kind == IDENT_AGE;
            d.title = age ? "AGE KEY FILE" : "PGP KEY FILE";
            int n = add_para(paras, 0, TUI_P_TEXT, age ? AGE_PATH_HELP : PGP_PATH_HELP);
            n = add_para(paras, n, TUI_P_BLANK, "");
            n = add_para(paras, n, TUI_P_TEXT, KEY_WHY);
            n = add_para(paras, n, TUI_P_BLANK, "");
            d.n_text = add_para(paras, n, TUI_P_TEXT, KEY_FILE_SAVED);
            d.mask = 0;
            d.placeholder = age ? "~/.config/age/key.txt" : "~/key.asc";
            d.keys = "enter use this key \xc2\xb7 esc back";
            break;
        }
        case MODE_SIGN_PASTE: {
            int n = add_para(paras, 0, TUI_P_TEXT, g_app.load_kind == IDENT_AGE ? AGE_PASTE_HELP : PGP_PASTE_HELP);
            n = add_para(paras, n, TUI_P_BLANK, "");
            n = add_para(paras, n, TUI_P_TEXT, KEY_WHY);
            n = add_para(paras, n, TUI_P_BLANK, "");
            d.n_text = add_para(paras, n, TUI_P_TEXT, KEY_PASTE_SAVED);
            d.title = g_app.load_kind == IDENT_AGE ? "PASTE AN AGE KEY" : "PASTE A PGP KEY";
            d.input = NULL;
            d.status = g_app.paste_status;
            d.keys = "esc back";
            break;
        }
        case MODE_SETTINGS_EDIT: {
            const setting_def_t *sd = setting_def(g_edit_id);
            size_t i = 0;
            for (; sd->label[i] && i < sizeof title - 1; i++) title[i] = (char)toupper((unsigned char)sd->label[i]);
            title[i] = '\0';
            d.title = title;
            d.mask = sd->kind == K_SECRET;
            d.placeholder = sd->values;
            d.note = sd->help;
            d.keys = "enter save \xc2\xb7 esc cancel";
            break;
        }
        case MODE_INSTALL:
            d.title = install_resaves() ? "SAVE" : "INSTALL";
            d.n_text = install_paras(paras);
            d.input = NULL;
            d.keys = install_resaves() ? "y save \xc2\xb7 n cancel" : "y install \xc2\xb7 n cancel";
            break;
        case MODE_INSTALL_FIRST:
            d.title = g_app.install_for == INSTALL_FACTOR_DEVICE ? "DEVICE LOCK"
                    : g_app.install_for == INSTALL_FACTOR_KEY ? "SECURITY KEY" : "AUTHENTICATOR APP";
            d.n_text = install_first_paras(paras);
            d.input = NULL;
            d.keys = "y install \xc2\xb7 n cancel";
            break;
        case MODE_INSTALL_PASS:
        case MODE_INSTALL_PASS2: {
            int first = g_app.mode == MODE_INSTALL_PASS;
            d.title = "INSTALL \xc2\xb7 PASSPHRASE";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, !first ? "Type it again, to be sure of it."
                : g_app.identity_source != IDENT_NONE && g_app.device_lock
                ? "Your settings and signing key are sealed with this passphrase, which chat asks for when it starts. "
                  "Make it long: anyone who gets onto this device can try passphrases against them. Forget it, and "
                  "they're lost."
                : g_app.device_lock
                ? "Your settings are sealed with this passphrase, which chat asks for when it starts, and so is a "
                  "signing key you `:install` later. Make it long: anyone who gets onto this device can try passphrases "
                  "against them. Forget it, and they're lost."
                : g_app.identity_source != IDENT_NONE
                ? "Your settings and signing key are sealed with this passphrase, which chat asks for when it starts. "
                  "Make it long: anyone who gets the files can try passphrases against them. Forget it, and they're lost."
                : "Your settings are sealed with this passphrase, which chat asks for when it starts, and so is a "
                  "signing key you `:install` later. Make it long: anyone who gets the files can try passphrases "
                  "against them. Forget it, and they're lost.");
            d.placeholder = first ? "passphrase" : "the same passphrase";
            d.keys = first ? "enter next \xc2\xb7 esc cancel" : "enter install \xc2\xb7 esc cancel";
            break;
        }
        case MODE_INSTALL_EXISTING:
        case MODE_INSTALL_PICK:
        case MODE_INSTALL_OVERWRITE:
        case MODE_INSTALL_UNLOCK:
        case MODE_INSTALL_NAME: {
            static char text[900];
            static const char *names[INSTALL_SAVES_MAX], *details[INSTALL_SAVES_MAX];
            static char detail_text[INSTALL_SAVES_MAX][112];
            char where[900] = "";
            const char *shown = install_shown_name(g_app.save_target);
            install_where(g_app.save_target, where, sizeof where);
            d.title = "INSTALL";
            if (g_app.mode == MODE_INSTALL_EXISTING) {
                if (g_app.install_pick)
                    snprintf(text, sizeof text, "There are %d saves here already, each sealed with its own passphrase, "
                             "and none is open in this run. Use one of them? Yes lists them to pick one, then asks for "
                             "its passphrase, and what's saved there is used from then on. No makes a new save, with a "
                             "name and a passphrase of its own.", g_app.n_saves);
                else
                    snprintf(text, sizeof text, "There's a save here already: `%s`, in `%s`, sealed with its own "
                             "passphrase and not open in this run. Use it? Yes asks for its passphrase, and what's "
                             "saved there is used from then on. No makes a new save, with a name and a passphrase of "
                             "its own.", shown, where);
                d.input = NULL;
                d.keys = "y use it \xc2\xb7 n new save \xc2\xb7 esc cancel";
            } else if (g_app.mode == MODE_INSTALL_PICK) {
                for (int i = 0; i < g_app.n_saves; i++) {
                    names[i] = install_shown_name(g_app.saves[i].name);
                    save_detail(&g_app.saves[i], detail_text[i], sizeof detail_text[i]);
                    details[i] = detail_text[i];
                }
                copy_str(text, "Pick the save to use. Its passphrase is asked for next.", sizeof text);
                d.input = NULL;
                d.items = names;
                d.details = details;
                d.n_items = g_app.n_saves;
                d.sel = g_app.save_sel;
                d.keys = "enter choose \xc2\xb7 j/k move \xc2\xb7 esc back";
            } else if (g_app.mode == MODE_INSTALL_OVERWRITE) {
                snprintf(text, sizeof text, "`%s` is another save, in `%s`, sealed with its own passphrase. Save what's "
                         "in use now over it? That's your settings, %s and the keys you verified, which are added to "
                         "the ones saved there. Its passphrase is asked for next, and from then on `%s` is the save in "
                         "use. To use what's saved there as it is, start chat with `--save %s`. `:install NEWNAME` "
                         "makes a new save instead.", shown, where,
                         g_app.identity_source == IDENT_NONE ? "not your signing key (signing is off),"
                         : !install_has_key(g_app.save_target)
                         ? (key_saved_as_path() ? "the path to your signing key's file," : "your signing key,")
                         : key_saved_as_path() ? "the path to your signing key's file in place of the key saved there,"
                         : "your signing key in place of the one saved there,", shown, shown);
                d.input = NULL;
                d.keys = "y overwrite \xc2\xb7 n cancel";
            } else if (g_app.mode == MODE_INSTALL_UNLOCK) {
                snprintf(text, sizeof text, "Its passphrase opens `%s`, %s Forgot it? Esc goes back%s, and "
                         "`:uninstall %s` deletes it.", shown, g_app.install_overwrite
                         ? "and what's in use now is saved over it under the same one."
                         : "and what's saved there is used from now on.",
                         g_app.install_overwrite ? "" : g_app.install_pick ? " to the list"
                         : ", where n makes a new save instead", shown);
                d.title = "INSTALL \xc2\xb7 PASSPHRASE";
                d.placeholder = "passphrase";
                d.keys = g_app.install_overwrite ? "enter install \xc2\xb7 esc back" : "enter open \xc2\xb7 esc back";
            } else {
                snprintf(text, sizeof text, "A name for the new save: 1 to %d letters, digits, - and _, or blank for "
                         "`%s`, picked at random. It goes in `saves/NAME` in chat's folder (`default` is the folder "
                         "itself), and anyone who can read the disk can see the folder's name. What it leaves on disk "
                         "is shown next.", INSTALL_NAME_MAX, g_app.save_random);
                d.title = "INSTALL \xc2\xb7 NEW SAVE";
                d.mask = 0;
                d.placeholder = g_app.save_random;
                d.keys = g_app.n_saves > 0 ? "enter next \xc2\xb7 esc back" : "enter next \xc2\xb7 esc cancel";
            }
            d.n_text = add_para(paras, 0, TUI_P_TEXT, text);
            break;
        }
        case MODE_UNINSTALL:
            d.title = "UNINSTALL";
            d.n_text = uninstall_paras(paras);
            d.input = NULL;
            d.keys = "y delete \xc2\xb7 n cancel";
            break;
        case MODE_DEVICE_LOCK:
            d.title = "DEVICE LOCK";
            d.n_text = device_lock_paras(paras);
            d.input = NULL;
            d.keys = g_app.device_new ? "y lock it \xc2\xb7 n cancel"
                   : g_app.device_want ? "y lock \xc2\xb7 n cancel" : "y unlock \xc2\xb7 n cancel";
            break;
        case MODE_FILE_ASK:
            d.n_text = file_ask_paras(paras, &d.title, &d.keys);
            d.input = NULL;
            break;
        case MODE_UPDATE: {
            static update_view_t v;
            static const char *lines[UPDATE_LOG_MAX];
            static tui_progress_t pg;
            update_view(&v);
            for (int i = 0; i < v.n_log; i++) lines[i] = v.log[i];
            pg.permille = v.permille;
            copy_str(pg.text, v.amount, sizeof pg.text);
            d.title = "UPDATE";
            d.console = 1;
            d.log = lines;
            d.log_kind = v.kind;
            d.n_log = v.n_log;
            d.progress = &pg;
            d.step = v.step;
            d.step_kind = v.running ? TUI_LOG_INFO : v.ok ? TUI_LOG_GOOD : TUI_LOG_BAD;
            d.input = NULL;
            d.keys = v.running ? "esc hide" : "enter close";
            break;
        }
        case MODE_SAVES: {
            static const char *names[INSTALL_SAVES_MAX], *details[INSTALL_SAVES_MAX];
            static char detail_text[INSTALL_SAVES_MAX][112];
            for (int i = 0; i < g_app.n_saves; i++) {
                names[i] = install_shown_name(g_app.saves[i].name);
                save_detail(&g_app.saves[i], detail_text[i], sizeof detail_text[i]);
                details[i] = detail_text[i];
            }
            d.title = "UNLOCK";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, "`:install` made more than one save here, each sealed with its "
                                "own passphrase. Pick the one to open; Esc starts without any, from chat's defaults, "
                                "and saves nothing until `:install` opens a save or makes a new one.");
            d.input = NULL;
            d.items = names;
            d.details = details;
            d.n_items = g_app.n_saves;
            d.sel = g_app.save_sel;
            d.keys = "enter open \xc2\xb7 j/k move \xc2\xb7 esc skip";
            break;
        }
        case MODE_UNLOCK: {
            static char text[500];
            const char *name = install_current();
            int key = install_has_key(name);
            unsigned f = install_factors(name);
            const char *here = f & INSTALL_FACTOR_DEVICE ? " and locked to this device" : "";
            char more[120] = "", then[96];
            factors_text(f & (INSTALL_FACTOR_KEY | INSTALL_FACTOR_CODE), then, sizeof then);
            if (then[0]) snprintf(more, sizeof more, ", then %s", then);
            if (g_app.n_saves > 1 || name[0])
                snprintf(text, sizeof text, "`:install` saved your settings%s here as `%s`, sealed%s. Its passphrase "
                         "opens it%s; Esc %s.", key ? " and signing key" : "", install_shown_name(name), here, more,
                         save_to_pick() ? "goes back to the list"
                                        : "starts without it, from chat's defaults, and saves nothing until `:install` opens a "
                                          "save or makes a new one");
            else
                snprintf(text, sizeof text, "`:install` saved your settings%s here, sealed%s. Their passphrase opens "
                         "them%s; Esc starts without them, from chat's defaults, and saves nothing until `:install` opens a "
                         "save or makes a new one.",
                         key ? " and signing key" : "", here, more);
            d.n_text = add_para(paras, 0, TUI_P_TEXT, text);
            d.title = "UNLOCK";
            d.placeholder = "passphrase";
            d.keys = save_to_pick() ? "enter open \xc2\xb7 esc back" : "enter open \xc2\xb7 esc skip";
            break;
        }
        case MODE_FACTOR:
            d.title = g_app.factor == INSTALL_FACTOR_KEY ? "SECURITY KEY" : "AUTHENTICATOR APP";
            d.n_text = factor_paras(paras);
            d.input = NULL;
            d.keys = g_app.factor_want ? "y register \xc2\xb7 n cancel" : "y turn off \xc2\xb7 n cancel";
            break;
        case MODE_CODE_SETUP:
            d.title = "AUTHENTICATOR APP";
            d.mask = 0;
            d.placeholder = "6-digit code";
            code_setup_dialog(&d, paras);
            break;
        case MODE_KEY_WAIT:
            d.title = "SECURITY KEY";
            d.n_text = key_wait_paras(paras);
            d.input = NULL;
            d.keys = "esc cancel";
            break;
        case MODE_KEY_PIN:
            d.title = "SECURITY KEY \xc2\xb7 PIN";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, "Your security key wants its PIN for this. chat sends it to the key "
                                "encrypted, and doesn't keep it.");
            d.note = install_key_why();
            d.placeholder = "PIN";
            d.keys = "enter send \xc2\xb7 esc cancel";
            break;
        case MODE_UNLOCK_CODE: {
            static char text[300];
            const char *shown = install_shown_name(g_app.key_purpose == KP_INSTALL_UNLOCK ? g_app.save_target : install_current());
            snprintf(text, sizeof text, "The save `%s` also asks for the 6-digit code your authenticator app shows for "
                     "`chat:%s`.", shown, shown);
            d.n_text = add_para(paras, 0, TUI_P_TEXT, text);
            d.title = g_app.key_purpose == KP_INSTALL_UNLOCK ? "INSTALL \xc2\xb7 CODE" : "UNLOCK \xc2\xb7 CODE";
            d.mask = 0;
            d.placeholder = "6-digit code";
            d.keys = "enter open \xc2\xb7 esc back";
            break;
        }
        case MODE_SHADOW_PASS:
        case MODE_SHADOW_PASS2: {
            int first = g_app.mode == MODE_SHADOW_PASS;
            d.title = "SHADOW PASSWORD";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, first
                ? "A second passphrase for this save. Opening the save with it deletes the real save for good and "
                  "leaves only a decoy - a clean, empty account that needs the same security key, device and code. "
                  "Make it different from the real one, and don't forget which is which."
                : "Type the shadow passphrase again, to be sure of it.");
            d.placeholder = first ? "shadow passphrase" : "the same passphrase";
            d.keys = first ? "enter next \xc2\xb7 esc cancel" : "enter set \xc2\xb7 esc cancel";
            break;
        }
        default:
            return NULL;
    }
    return &d;
}

// The bottom row for the current screen: the chip names it, and the hint says what the keys do there.
static tui_bar_t current_bar(void) {
    tui_bar_t b = {
        .chip = "SETTINGS",
        .tone = TUI_TONE_PAGE,
        .message = g_app.message,
        .badge = (tui_identity_badge_t)g_app.identity_source,
        .nick = g_app.nick,
        .nick_color = g_app.color,
    };
    switch (g_app.mode) {
        case MODE_CHANGELOG:
            b.chip = "CHANGELOG";
            b.hint = "j/k scroll \xc2\xb7 space/b page \xc2\xb7 g/G top/bottom \xc2\xb7 q close";
            break;
        case MODE_HELP:
            b.chip = "HELP";
            b.hint = "enter use \xc2\xb7 j/k move \xc2\xb7 tab section \xc2\xb7 esc close";
            break;
        case MODE_SETTINGS:        b.hint = settings_hint(); break;
        case MODE_SIGN_CHOICE:     b.hint = "enter choose \xc2\xb7 j/k move \xc2\xb7 esc back \xc2\xb7 q close"; break;
        case MODE_SIGN_BROWSE:
            b.hint = "enter open \xc2\xb7 h up \xc2\xb7 / type a path \xc2\xb7 ~ home \xc2\xb7 esc back \xc2\xb7 q close";
            break;
        case MODE_SEND_BROWSE:
            b.chip = "SEND";
            b.hint = "enter send \xc2\xb7 h up \xc2\xb7 ~ home \xc2\xb7 j/k move \xc2\xb7 esc close";
            break;
        case MODE_SAVE_BROWSE:
            b.chip = "SAVE";
            b.hint = "s save here \xc2\xb7 enter open \xc2\xb7 h up \xc2\xb7 ~ home \xc2\xb7 j/k move \xc2\xb7 esc close";
            break;
        case MODE_FILES:
            b.chip = "FILES";
            b.hint = files_hint();
            break;
        case MODE_FILE_VIEW:
            b.chip = "PICTURE";
            b.hint = viewer_hint();
            break;
        case MODE_FILE_ASK:
            b.chip = g_app.file_back == MODE_FILE_VIEW ? "PICTURE" : "FILES";
            b.tone = TUI_TONE_PROMPT;
            break;
        case MODE_DEVICE_LOCK:
            if (g_app.device_back == MODE_CHAT) chat_input(&b, &g_app.saved_input);
            b.chip = g_app.device_new ? "INSTALL" : "SETTINGS";
            b.tone = TUI_TONE_PROMPT;
            break;
        case MODE_FACTOR:
        case MODE_CODE_SETUP:
        case MODE_KEY_WAIT:
        case MODE_KEY_PIN:
        case MODE_UNLOCK_CODE: {
            int unlocking = g_app.mode == MODE_UNLOCK_CODE || g_app.mode == MODE_KEY_WAIT || g_app.mode == MODE_KEY_PIN;
            key_purpose_t why = unlocking ? g_app.key_purpose : g_app.factor_new ? KP_NEW_SAVE : KP_FACTOR;
            if (on_chat_screen()) chat_input(&b, &g_app.saved_input);
            b.chip = why == KP_UNLOCK ? "UNLOCK" : why == KP_FACTOR ? "SETTINGS" : "INSTALL";
            b.tone = TUI_TONE_PROMPT;
            break;
        }
        case MODE_SHADOW_PASS:
        case MODE_SHADOW_PASS2:
            if (g_app.factor_back == MODE_CHAT) chat_input(&b, &g_app.saved_input);
            b.chip = g_app.factor_back == MODE_CHAT ? "CHAT" : "SETTINGS";
            b.tone = TUI_TONE_PROMPT;
            break;
        case MODE_CHAT:
            chat_input(&b, &g_app.input);
            break;
        case MODE_SAVES:
        case MODE_UNLOCK:
        case MODE_NEW_PASSWORD:
        case MODE_JOIN_ID:
        case MODE_JOIN_PASSWORD:
        case MODE_INSTALL:
        case MODE_INSTALL_PASS:
        case MODE_INSTALL_PASS2:
        case MODE_INSTALL_UNLOCK:
        case MODE_INSTALL_EXISTING:
        case MODE_INSTALL_PICK:
        case MODE_INSTALL_OVERWRITE:
        case MODE_INSTALL_NAME:
        case MODE_INSTALL_FIRST:
        case MODE_UNINSTALL:
        case MODE_UPDATE:
            if (on_chat_screen()) chat_input(&b, &g_app.saved_input);
            b.chip = g_app.mode == MODE_NEW_PASSWORD ? "NEW"
                   : g_app.mode == MODE_JOIN_ID || g_app.mode == MODE_JOIN_PASSWORD ? "JOIN"
                   : g_app.mode == MODE_UNLOCK || g_app.mode == MODE_SAVES ? "UNLOCK"
                   : g_app.mode == MODE_UNINSTALL ? "UNINSTALL"
                   : g_app.mode == MODE_UPDATE ? "UPDATE"
                   : g_app.mode == MODE_INSTALL && install_resaves() ? "SAVE" : "INSTALL";
            b.tone = TUI_TONE_PROMPT;
            break;
        default:
            break;
    }
    b.dialog = current_dialog();
    if (g_app.asking_quit) {
        b.dialog = quit_dialog();
        b.chip = "QUIT";
        b.tone = TUI_TONE_PROMPT;
    }
    if (b.dialog) b.hint = b.dialog->keys;
    return b;
}

static void render_bar(void) {
    if (!on_chat_screen()) { render(); return; }
    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);
    char sub[64]; tui_view_t view = current_view(sub, sizeof sub);
    tui_bar_t bar = current_bar();
    // The text wrapped onto one row more or fewer, so the chat above it moves too.
    if (tui_render_bar(rows_n, cols_n, &view, &bar, g_app.color_enabled) != 0) render();
}

// How the selected session reaches its peers, for the sidebar: the route, its port or tor, the
// relays and port mapping, the DHT, and the traffic so far.
#define MAX_NET 10
static int build_net(tui_kv_t kv[MAX_NET], char vals[MAX_NET][32]) {
    if (!g_app.selected || g_app.selected->initialising) return 0;
    const chat_t *e = &g_app.selected->engine;
    int n = 0;
#define KV(l, ...) do { snprintf(vals[n], 32, __VA_ARGS__); kv[n].label = (l); kv[n].value = vals[n]; n++; } while (0)
    if (e->route.mode == ROUTE_TOR) {
        char t[32];
        tor_link_line(t, sizeof t);
        KV("route", "tor");
        KV("tor", "%s", strncmp(t, "tor: ", 5) == 0 ? t + 5 : t);
        KV("onion", "%s", e->tor && tor_my_onion(e->tor)[0] ? "published" : "waiting");
    } else {
        KV("route", "dht");
        KV("port", "udp/%u", (unsigned)e->port);
        KV("portmap", "%s", !e->pm ? "off" : portmap_mapped(e->pm, NULL) ? "mapped" : "not yet");
    }
    if (e->nostr && !nostr_active(e->nostr)) KV("relays", "not needed");
    else if (e->nostr) KV("relays", "%d/%d up", nostr_relays_up(e->nostr), nostr_relay_total(e->nostr));
    else KV("relays", "off");
    if (e->route.mode != ROUTE_TOR) {
        if (e->dht_on) {
            KV("dht", "%d nodes", dht_queried_count(&e->dht));
            KV("found", "%d peers", dht_found_count(&e->dht));
        } else {
            KV("dht", "off");
        }
    }
    KV("cands", "%d", chat_candidate_count(e));
    KV("pending", "%d", chat_pending_count(e));
    KV("rx", "%u packets", e->st.rx);
#undef KV
    return n;
}

static void render(void) {
    tui_session_row_t rows[MAX_SESSIONS];
    int n = 0, sel = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i]) continue;
        session_slot_t *s = &g_app.sessions[i];
        tui_session_row_t *r = &rows[n];
        copy_str(r->label, s->name, sizeof r->label);
        r->online = s->initialising ? 1 : chat_online_count(&s->engine) + 1;
        r->unread = s->unread;
        r->mention = s->mentioned;
        r->state = session_state(s);
        if (s == g_app.selected) sel = n;
        n++;
    }

    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);
    tui_bar_t bar = current_bar();
    char hhmm[6]; current_hhmm(hhmm);

    if (install_mode(g_app.mode) && g_app.install_back == MODE_SETTINGS) { render_settings(rows_n, cols_n, hhmm, &bar); return; }
    switch (g_app.mode) {
        case MODE_HELP:            render_help(rows_n, cols_n, hhmm, &bar); return;
        case MODE_CHANGELOG:       render_changelog(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SETTINGS:
        case MODE_SETTINGS_EDIT:   render_settings(rows_n, cols_n, hhmm, &bar); return;
        case MODE_DEVICE_LOCK:
            if (g_app.device_back == MODE_SETTINGS) { render_settings(rows_n, cols_n, hhmm, &bar); return; }
            break;
        case MODE_FACTOR:
        case MODE_CODE_SETUP:
        case MODE_KEY_WAIT:
        case MODE_KEY_PIN:
        case MODE_SHADOW_PASS:
        case MODE_SHADOW_PASS2:
            if (g_app.factor_back == MODE_SETTINGS) { render_settings(rows_n, cols_n, hhmm, &bar); return; }
            break;
        case MODE_SIGN_CHOICE:
        case MODE_SIGN_PASTE:
        case MODE_SIGN_PASSWORD:   render_sign_picker(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SIGN_PATH:
            if (g_app.path_from_browser) render_browser(rows_n, cols_n, hhmm, &bar);
            else render_sign_picker(rows_n, cols_n, hhmm, &bar);
            return;
        case MODE_SIGN_BROWSE:     render_browser(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SEND_BROWSE:     render_send_browser(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SAVE_BROWSE:     render_save_browser(rows_n, cols_n, hhmm, &bar); return;
        case MODE_FILES:           render_files(rows_n, cols_n, hhmm, &bar); return;
        case MODE_FILE_VIEW:       render_viewer(rows_n, cols_n, hhmm, &bar); return;
        case MODE_FILE_ASK:
            if (g_app.file_back == MODE_FILE_VIEW) render_viewer(rows_n, cols_n, hhmm, &bar);
            else render_files(rows_n, cols_n, hhmm, &bar);
            return;
        default: break;
    }

    static tui_peer_row_t peer_rows[MAX_PEERS + MAX_PENDING_PEERS + 1];
    int n_peers = 0;
    if (g_app.selected && !g_app.selected->initialising) {
        chat_t *e = &g_app.selected->engine;
        tui_peer_row_t *me = &peer_rows[n_peers++];
        memset(me, 0, sizeof *me);
        copy_str(me->nick, e->nick, sizeof me->nick);
        memcpy(me->color, e->my_color, 3);
        me->you = 1;
        for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS && n_peers < MAX_PEERS + MAX_PENDING_PEERS + 1; i++) {
            peer_t *p = &e->peers[i];
            if (!p->used || !p->ok) continue;
            tui_peer_row_t *r = &peer_rows[n_peers++];
            memset(r, 0, sizeof *r);
            // Nicks can't contain '#', so one here is the id added to tell lookalikes apart, which the sidebar
            // never cuts off.
            char name[CHAT_NAME_LEN]; chat_peer_name(e, p, name);
            char *tag = strchr(name, '#');
            if (tag) { copy_str(r->tag, tag, sizeof r->tag); *tag = '\0'; }
            copy_str(r->nick, name, sizeof r->nick);
            memcpy(r->color, p->color, 3);
            r->verify = (int)p->identity_state;
            r->code = chat_code_state(e, p);
            r->modified = p->build_state == BUILD_MODIFIED;
        }
    }

    tui_scrollback_t *sb = g_app.selected ? &g_app.selected->sb : NULL;
    tui_scrollback_t *console = g_app.selected ? &g_app.selected->console : &g_app.log;
    char sub[64]; tui_view_t view = current_view(sub, sizeof sub);
    view.clock = hhmm;
    tui_kv_t net[MAX_NET];
    char net_vals[MAX_NET][32];
    int n_net = build_net(net, net_vals);
    tui_render(rows_n, cols_n, rows, n, sel, peer_rows, n_peers, net, n_net, sb, console, &view, &bar,
               g_app.color_enabled);
}

static int run_plain(const char *session_name, const char *password, uint16_t port,
                     const char peer_args[][PEER_ARG_LEN], int n_peer_args);

static int run_tui(const char *explicit_session, char *explicit_password, uint16_t explicit_port,
                    const char peer_args[][PEER_ARG_LEN], int n_peer_args) {
    term_watch_resize();
    if (term_raw_enable() != 0) {

        fprintf(stderr, "chat: this terminal can't do the full-screen UI, using --simple instead\n");
        if (g_app.unlock_at_start) unlock_at_start(0);
        if (!g_app.nick[0]) random_nickname(g_app.nick, sizeof g_app.nick);
        return run_plain(explicit_session, explicit_password, explicit_port, peer_args, n_peer_args);
    }

    // The terminal's background colour, and reports of its theme changing, arrive as keys.
    fputs("\x1b[22;0t\x1b]0;chat\x07\x1b[?1049h\x1b[2J\x1b[H" TUI_THEME_WATCH, stdout);
    fflush(stdout);
    catch_quit_signals();

    crypto_lock(&g_app.log, sizeof g_app.log);
    tui_input_clear(&g_app.input);
    g_app.input.modal = 1;
    g_app.input.mode = TUI_IMODE_NORMAL;   // i to type
    g_app.input.suggest = suggest_command;
    g_app.input.is_command = command_word;
    g_app.input.mention = complete_mention;
    g_app.dirty = 1;

    if (explicit_session) {
        copy_str(g_app.pending_auto_session, explicit_session, sizeof g_app.pending_auto_session);
        copy_str(g_app.pending_auto_password, explicit_password, sizeof g_app.pending_auto_password);
        g_app.pending_auto_port = explicit_port;
        for (int i = 0; i < n_peer_args && i < MAX_PEER_ARGS; i++)
            copy_str(g_app.pending_auto_peer_args[i], peer_args[i], PEER_ARG_LEN);
        g_app.pending_auto_n_peers = n_peer_args < MAX_PEER_ARGS ? n_peer_args : MAX_PEER_ARGS;
        crypto_wipe(explicit_password, strlen(explicit_password));
    }

    // Everything is set up on the settings page first, and its button starts chat. If installed, the
    // saved settings are used, so chat starts straight away.
    g_app.onboarding = 1;
    settings_select(0);
    g_app.mode = MODE_SETTINGS;
    if (g_app.unlock_at_start) {
        begin_prompt(save_to_pick() ? MODE_SAVES : MODE_UNLOCK);
        // CHAT_INSTALL_PASSWORD's passphrase, for a save that needs its security key or a code too.
        if (g_app.unlock_env) {
            g_app.unlock_env = 0;
            unlock_go(KP_UNLOCK);
        }
    } else {
        settle_start();
        if (g_app.installed && install_has_settings(install_current())) settings_done();
    }
    render();

    double next_ui_tick = now_seconds() + 1.0;

    while (!g_interrupted) {
        sock_t socks[PLATFORM_WAIT_MAX];
        session_slot_t *owner[PLATFORM_WAIT_MAX];
        int ready[PLATFORM_WAIT_MAX];
        int n = 0;
        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
            sock_t mine[CHAT_MAX_SOCKS];
            int ns = chat_sockets(&g_app.sessions[i].engine, mine);
            // Beyond the limit a socket just waits for the next tick, 200 ms at most.
            for (int j = 0; j < ns && n < PLATFORM_WAIT_MAX; j++) { socks[n] = mine[j]; owner[n] = &g_app.sessions[i]; n++; }
        }
        int stdin_ready = 0;
        platform_wait(socks, n, ready, &stdin_ready, 200);

        if (g_ctrl_c) { g_ctrl_c = 0; g_app.asking_quit = 1; g_app.dirty = 1; }

        if (stdin_ready) {
            uint8_t buf[512];
            long got = term_read_raw(buf, sizeof buf);
            if (got > 0) {
                size_t off = 0;
                while ((size_t)got > off) {
                    tui_key_t key;
                    size_t used = tui_decode_key(buf + off, (size_t)got - off, &key);
                    if (used == 0) break;
                    off += used;
                    handle_key(&key);
                }
            } else if (got < 0) {
                g_interrupted = 1;
            }
        }
        double now = now_seconds();
        for (int i = 0; i < n; i++)
            if (ready[i]) chat_on_socket_readable(&owner[i]->engine, socks[i], now);
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (g_app.used[i]) chat_tick(&g_app.sessions[i].engine, now_seconds());

        if (!g_app.onboarding) {
            tor_link_ensure(now);
            tor_link_step(now);
        }

        char update_msg[UPDATE_MSG_MAX];
        if (update_poll(update_msg, sizeof update_msg)) { push_log("%s", update_msg); g_app.dirty = 1; }
        // Its box redraws on each wait while the update runs, so the bar moves as the file downloads.
        if (g_app.mode == MODE_UPDATE) {
            update_view_t v;
            update_view(&v);
            if (v.running) g_app.dirty = 1;
        }
        if (g_app.mode == MODE_KEY_WAIT) key_wait_tick();

        // The terminal may have redrawn or reflowed the screen, so the next frame is sent in full.
        if (term_resized()) { g_app.dirty = 1; tui_invalidate(); }
        if (now >= next_ui_tick) { next_ui_tick = now + 1.0; g_app.dirty = 1; }
        if (g_app.dirty) { keep_settings_saved(); render(); g_app.dirty = 0; g_app.input_dirty = 0; }
        else if (g_app.input_dirty) { render_bar(); g_app.input_dirty = 0; }
    }

    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) close_session(&g_app.sessions[i]);
    // After the sessions, so their onion services are removed with their control connections first.
    tor_link_stop();
    install_key_cancel();
    crypto_wipe(&g_app.input, sizeof g_app.input);
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
    crypto_wipe(g_app.pending_auto_password, sizeof g_app.pending_auto_password);
    crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
    install_forget();
    tui_scrollback_clear(&g_app.log);

    // Back to the main screen with the cursor visible, its default shape and autowrap on, however
    // the last frame left them.
    fputs(TUI_THEME_UNWATCH "\x1b[?7h\x1b[0 q\x1b[?25h\x1b[?1049l\x1b[23;0t", stdout);
    term_raw_disable();
    fflush(stdout);
    net_shutdown();
    platform_notify_shutdown();

    _exit(0);
}

// --simple: a picture requested with :show is printed at the current point in the conversation,
// two pixel rows per line of half blocks.
static void plain_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
    (void)ui; (void)name;
    static const uint8_t bg[3] = { 0, 0, 0 };
    image_thumb_t th;
    char why[160];
    const file_entry_t *f = g_plain_engine ? chat_file(g_plain_engine, num) : NULL;
    if (!term_ansi_ok()) {
        // One you've just sent isn't worth a note.
        if (!(f && f->mine)) printf("* file %d came, but showing a picture needs a terminal with colour - :download %d saves it\n", num, num);
        return;
    }
    if (image_thumbnail(data, len, TUI_IMAGE_MAX_W, TUI_IMAGE_MAX_H, bg, &th, why, sizeof why) != 0) {
        printf("* can't show file %d: %s - :download %d saves it\n", num, why, num);
        return;
    }
    for (int y = 0; y < th.h; y += 2) {
        fputs("  ", stdout);
        for (int x = 0; x < th.w; x++) {
            const uint8_t *t = th.rgb + ((size_t)y * (size_t)th.w + (size_t)x) * 3;
            if (y + 1 < th.h) {
                const uint8_t *b = t + (size_t)th.w * 3;
                printf("\x1b[38;2;%u;%u;%u;48;2;%u;%u;%um\xe2\x96\x80", t[0], t[1], t[2], b[0], b[1], b[2]);
            } else {
                printf("\x1b[0;38;2;%u;%u;%um\xe2\x96\x80", t[0], t[1], t[2]);
            }
        }
        fputs("\x1b[0m\n", stdout);
    }
    printf("* file %d (%dx%d)\n", num, th.src_w, th.src_h);
    fflush(stdout);
    crypto_wipe(th.rgb, (size_t)th.w * (size_t)th.h * 3);
    image_thumb_free(&th);
}

static void plain_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                        unsigned flags, int color_len, int file) {
    (void)ui;
    (void)file;
    int mention = (flags & LINE_MENTION) != 0;
    int ansi = term_ansi_ok();
    if (ansi && mention) printf("[%s] \x1b[1m\x1b[48;2;110;70;10m%s\x1b[0m\n", hhmm, text);
    else if (ansi && (flags & LINE_WARN)) printf("[%s] \x1b[1;33m%s\x1b[0m\n", hhmm, text);
    else if (ansi && rgb && color_len > 0 && (size_t)color_len < strlen(text))
        printf("[%s] \x1b[38;2;%d;%d;%dm%.*s\x1b[0m%s\n", hhmm, rgb[0], rgb[1], rgb[2], color_len, text, text + color_len);
    else if (ansi && rgb) printf("[%s] \x1b[38;2;%d;%d;%dm%s\x1b[0m\n", hhmm, rgb[0], rgb[1], rgb[2], text);
    else printf("[%s] %s\n", hhmm, text);
    fflush(stdout);
}
static void plain_notify(void *ui, const char *nick, const char *text, int mentioned) {
    (void)ui;
    send_notification(nick, text, mentioned);
}

static int run_plain(const char *session_name, const char *password, uint16_t port,
                     const char peer_args[][PEER_ARG_LEN], int n_peer_args) {
    int tty = term_is_tty();
    g_plain = 1;
    say_saved_notes();
    chat_opts_t o; memset(&o, 0, sizeof o);
    copy_str(o.nick, g_app.nick[0] ? g_app.nick : "anon", sizeof o.nick);

    if (session_name) {
        copy_str(o.session_name, session_name, sizeof o.session_name);
    } else if (tty) {
        char line[MAX_SESSION_NAME + 1];
        if (term_read_line("session id (blank = start a new one): ", line, sizeof line) != 0) return 1;
        if (line[0]) copy_str(o.session_name, line, sizeof o.session_name);
        else { random_session_id(o.session_name, 10); o.created = 1; printf("new session id: %s  (share this and the password)\n", o.session_name); }
    } else {
        // No fixed default, since a well known id with a blank password would be a room anyone can join.
        random_session_id(o.session_name, 10);
        o.created = 1;
        printf("new session id: %s  (share this and the password)\n", o.session_name);
    }

    if (password) copy_str(o.password, password, sizeof o.password);
    else if (platform_env_take("CHAT_PASSWORD", o.password, sizeof o.password) == 0) {  }
    else if (tty && term_read_password(o.created ? "create password: " : "password: ", o.password, sizeof o.password) != 0) return 1;

    o.port = port;
    if (!g_app.route_chosen) {
        // Without a terminal to ask, --nonostr means DHT only.
        int choice = g_app.nostr_flag == NOSTR_OFF ? 2 : 1;
        if (tty) {
            for (size_t i = 0; i < sizeof ROUTE_CHOICE_LINES / sizeof ROUTE_CHOICE_LINES[0]; i++)
                printf("%s\n", ROUTE_CHOICE_LINES[i] + 2);
            char line[16];
            if (term_read_line("routing [1/2/3, Enter = 1]: ", line, sizeof line) != 0) return 1;
            if (line[0] >= '1' && line[0] <= '3') choice = line[0] - '0';
        }
        apply_route_choice(choice);
    }
    // --peer names are only looked up once the routing is decided, and never for Tor, where the lookup
    // would bypass it.
    if (n_peer_args > 0 && g_app.route.mode == ROUTE_TOR) {
        fprintf(stderr, "chat: --peer can't be used with Tor routing\n");
        crypto_wipe(&o, sizeof o);
        return 1;
    }
    for (int i = 0; i < n_peer_args && o.n_peers < (int)(sizeof o.peers / sizeof o.peers[0]); i++) {
        if (addr_parse_hostport(peer_args[i], &o.peers[o.n_peers]) != 0) {
            fprintf(stderr, "chat: can't use --peer %s\n", peer_args[i]);
            crypto_wipe(&o, sizeof o);
            return 1;
        }
        o.n_peers++;
    }
    sync_update_proxy();
    o.route = g_app.route;
    if (o.route.mode == ROUTE_TOR) {
        tor_link_ensure(now_seconds());
        o.route.tor.socks[0] = o.route.tor.control[0] = '\0';
    }
    o.notify_mode = g_app.notify_mode;
    o.notify_preview = g_app.notify_preview;
    o.verify_optional = g_app.verify_optional;
    o.file_cap = g_app.file_cap;
    o.fast_files = g_app.fast_files;
    o.has_color = 1;
    memcpy(o.color, g_app.color, 3);
    o.identity_source = g_app.identity_source;
    if (g_app.identity_source != IDENT_NONE) o.identity = g_app.identity;
    set_build_opts(&o);

    static chat_t c;
    chat_init(&c, &o, plain_print, plain_notify, NULL);
    c.file_view = plain_file_view;
    g_plain_engine = &c;
    crypto_wipe(&o, sizeof o);
    if (!chat_started(&c)) {
        fprintf(stderr, "chat: %s\n", chat_start_error(&c));
        chat_shutdown(&c);
        g_plain_engine = NULL;
        tor_link_stop();
        return 1;
    }
    c.net_verbose = g_app.net_verbose;
    char idhex[9]; hex_encode(c.my_id, 4, idhex);
    if (c.route.mode == ROUTE_TOR)
        printf("session '%s', you are %s (peer %s). encrypted, over Tor only. :quit or EOF to stop.\n",
               c.session_name, c.nick, idhex);
    else
        printf("session '%s', you are %s (peer %s). encrypted, udp/%u, routing: %s. :quit or EOF to stop.\n",
               c.session_name, c.nick, idhex, (unsigned)c.port, route_label());

    catch_quit_signals();
    stdin_reader_t *reader = stdin_reader_start();
    int alive = 1;
    double ctrl_c_at = -10.0;
    while (alive && !g_interrupted) {
        sock_t socks[CHAT_MAX_SOCKS]; int ns = chat_sockets(&c, socks);
        int ready[CHAT_MAX_SOCKS] = {0};
        net_wait(socks, ready, ns, 200);
        double now = now_seconds();
        // No box to ask in here, so a second press confirms. From a script, Ctrl+C still quits at once.
        if (g_ctrl_c) {
            g_ctrl_c = 0;
            if (!term_is_tty() || now - ctrl_c_at < 3.0) break;
            ctrl_c_at = now;
            push_log("* Ctrl+C again within 3 seconds leaves the session and quits (so does :quit)");
        }
        for (int i = 0; i < ns; i++) if (ready[i]) chat_on_socket_readable(&c, socks[i], now);
        char line[MAX_TEXT + 1];
        int rc = stdin_reader_poll(reader, line, sizeof line);
        int show_anyway, show_n = rc == 1 && strncmp(line, ":show ", 6) == 0 ? file_arg(line + 6, &show_anyway) : 0;
        if (rc == 1 && (strcmp(line, ":changelog") == 0 || strcmp(line, ":news") == 0)) { fputs(CHANGELOG_TEXT, stdout); fflush(stdout); }
        else if (show_n) chat_file_fetch(&c, show_n, 1, show_anyway, NULL);
        else if (rc == 1) alive = chat_submit_line(&c, line, now);
        else if (rc == -1) alive = 0;
        tor_link_ensure(now);
        tor_link_step(now);
        chat_tick(&c, now_seconds());
    }
    chat_shutdown(&c);
    g_plain_engine = NULL;
    tor_link_stop();
    if (reader) stdin_reader_stop(reader);
    term_raw_disable();
    net_shutdown();
    platform_notify_shutdown();
    fflush(stdout);
    _exit(0);
}

// -1 to go on, else what chat exits with.
static int read_options(int argc, char **argv, options_t *o) {
    memset(o, 0, sizeof *o);
    int relays_given = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *key = a;
        while (*key == '-') key++;
        if (strcmp(key, "nick") == 0 && i + 1 < argc) {
            copy_str(o->nick, argv[++i], sizeof o->nick);
        } else if (strcmp(key, "save") == 0 && i + 1 < argc) {
            if (install_name_ok(argv[++i]) != 0) {
                fprintf(stderr, "chat: bad --save %s (1 to %d letters, digits, - and _)\n", argv[i], INSTALL_NAME_MAX);
                return 1;
            }
            copy_str(o->save, argv[i], sizeof o->save);
        } else if (strcmp(key, "session") == 0 && i + 1 < argc) {
            copy_str(o->session, argv[++i], sizeof o->session);
        } else if (strcmp(key, "port") == 0 && i + 1 < argc) {
            char *end;
            long port = strtol(argv[++i], &end, 10);
            if (!argv[i][0] || *end || port < 0 || port > 65535) {
                fprintf(stderr, "chat: bad --port %s (0-65535, 0 picks a free one)\n", argv[i]);
                return 1;
            }
            o->port = (uint16_t)port;
        } else if (strcmp(key, "peer") == 0 && i + 1 < argc) {
            if (o->n_peers >= MAX_PEER_ARGS) { fprintf(stderr, "chat: at most %d --peer options\n", MAX_PEER_ARGS); return 1; }
            copy_str(o->peers[o->n_peers++], argv[++i], sizeof o->peers[0]);
        } else if (strcmp(key, "nodht") == 0) {
            g_app.route.dht4 = g_app.route.dht6 = 0;
        } else if (strcmp(key, "noipv6") == 0) {
            g_app.route.dht6 = 0;
        } else if (strcmp(key, "nolan") == 0) {
            g_app.route.lan = 0;
        } else if (strcmp(key, "noportmap") == 0) {
            g_app.route.portmap = 0;
        } else if (strcmp(key, "nonostr") == 0) {
            g_app.route.nostr = g_app.nostr_flag = NOSTR_OFF;
        } else if (strcmp(key, "nostr-always") == 0) {
            g_app.route.nostr = g_app.nostr_flag = NOSTR_ALWAYS;
        } else if (strcmp(key, "file-limit") == 0 && i + 1 < argc) {
            uint64_t v;
            if (file_parse_size(argv[++i], &v) != 0 || v == 0 || v > FILE_HARD_MAX) {
                fprintf(stderr, "chat: --file-limit takes a size from 1 byte to 1 GB (8M, 500K, 1G)\n");
                return 1;
            }
            g_app.file_cap = v;
        } else if (strcmp(key, "fast-files") == 0) {
            g_app.fast_files = 1;
        } else if (strcmp(key, "verify-optional") == 0) {
            g_app.verify_optional = 1;
        } else if (strcmp(key, "verify-required") == 0) {
            g_app.verify_optional = 0;
        } else if (strcmp(key, "routing") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            // direct+nostr and direct: the modes' old names, still accepted.
            if (strcmp(v, "dht+nostr") == 0 || strcmp(v, "nostr") == 0 || strcmp(v, "direct+nostr") == 0) apply_route_choice(1);
            else if (strcmp(v, "dht") == 0 || strcmp(v, "direct") == 0) apply_route_choice(2);
            else if (strcmp(v, "tor") == 0) apply_route_choice(3);
            else { fprintf(stderr, "chat: --routing takes dht+nostr, dht or tor\n"); return 1; }
        } else if (strcmp(key, "relay") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if (nostr_url_ok(v) != 0) { fprintf(stderr, "chat: bad --relay %s (want wss://host[:port][/path])\n", v); return 1; }
            if (!relays_given) { g_app.route.n_relays = 0; relays_given = 1; }
            if (g_app.route.n_relays >= NOSTR_MAX_RELAYS) { fprintf(stderr, "chat: at most %d --relay options\n", NOSTR_MAX_RELAYS); return 1; }
            copy_str(g_app.route.relays[g_app.route.n_relays++], v, NOSTR_URL_MAX);
        } else if (strcmp(key, "tor-launch") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "auto") == 0) g_app.tor_launch = TOR_LAUNCH_AUTO;
            else if (strcmp(v, "always") == 0) g_app.tor_launch = TOR_LAUNCH_ALWAYS;
            else if (strcmp(v, "never") == 0) g_app.tor_launch = TOR_LAUNCH_NEVER;
            else { fprintf(stderr, "chat: --tor-launch takes auto, always or never\n"); return 1; }
        } else if (strcmp(key, "tor-path") == 0 && i + 1 < argc) {
            char found[1024];
            if (platform_find_program("tor", argv[++i], found, sizeof found) != 0) {
                fprintf(stderr, "chat: can't use %s as tor - it has to be a full path to a program only root or you can change\n", argv[i]);
                return 1;
            }
            copy_str(g_app.tor_path, found, sizeof g_app.tor_path);
        } else if ((strcmp(key, "tor-socks") == 0 || strcmp(key, "tor-control") == 0) && i + 1 < argc) {
            const char *v = argv[++i];
            if (!valid_host_port(v)) { fprintf(stderr, "chat: bad --%s %s (want host:port)\n", key, v); return 1; }
            copy_str(strcmp(key, "tor-socks") == 0 ? g_app.route.tor.socks : g_app.route.tor.control, v, TOR_HOST_MAX);
        } else if (strcmp(key, "simple") == 0) {
            o->simple = 1;
        } else if ((strcmp(key, "colour") == 0 || strcmp(key, "color") == 0) && i + 1 < argc) {
            if (parse_color(argv[++i], o->color) != 0) { fprintf(stderr, "chat: unknown colour %s\n", argv[i]); return 1; }
            o->has_color = 1;
        } else if (strcmp(key, "identity") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if ((strncmp(v, "age", 3) != 0 && strncmp(v, "pgp", 3) != 0) || (v[3] != '\0' && v[3] != ':')) {
                fprintf(stderr, "chat: --identity takes age, pgp, age:KEYFILE or pgp:KEYFILE\n");
                return 1;
            }
            copy_str(o->identity, v, sizeof o->identity);
        } else if (strcmp(key, "update") == 0) {
            o->update = 1;
        } else if (strcmp(key, "version") == 0) {
            printf("chat %s, built %s (wire: hybrid X25519+ML-KEM-768, masked UDP)\n",
                   TEST_BUILD ? CHAT_VERSION " (" TEST_LABEL ")" : CHAT_VERSION, CHAT_BUILD_STAMP);
            return 0;
        } else if (strcmp(key, "h") == 0 || strcmp(key, "help") == 0 || strcmp(key, "?") == 0) {
            fputs(USAGE, stdout);
            return 0;
        } else {
            fprintf(stderr, "chat: unknown option %s\n", a);
            fputs(USAGE, stderr);
            return 1;
        }
    }
    return -1;
}

static void reapply_options(void) {
    options_t o;
    read_options(g_argc, g_argv, &o);
    if (o.has_color) memcpy(g_app.color, o.color, 3);
    if (o.nick[0]) chat_clean_nick(o.nick, g_app.nick);
}

int main(int argc, char **argv) {
    platform_harden_process(SECRET_ENV);
    g_argc = argc;
    g_argv = copy_args(argc, argv);
    if (!g_argv) return 1;
    platform_hide_args(argc, argv);
    routing_defaults(&g_app.route);
    g_app.nostr_flag = -1;
    g_app.notify_mode = NOTIFY_MENTIONS;
    g_app.verify_optional = 1;
    g_app.show_sidebar = g_app.show_console = g_app.show_chat = 1;
    note_setting_defaults();
    trust_on_change(save_verified);
    int exit_code = read_options(g_argc, g_argv, &g_opts);
    if (exit_code >= 0) return exit_code;
    const options_t *o = &g_opts;

    update_cleanup_stale();

    crypto_setup();
    device_check();
    update_self_build(&g_self_build);
    // The signing key, a pasted key block and typed passwords pass through these for the whole run.
    // Best effort, as in chat_init.
    crypto_lock(&g_app.identity, sizeof g_app.identity);
    crypto_lock(g_app.paste_buf, sizeof g_app.paste_buf);
    crypto_lock(&g_app.input, sizeof g_app.input);
    crypto_lock(&g_app.saved_input, sizeof g_app.saved_input);
    crypto_lock(g_app.pending_auto_password, sizeof g_app.pending_auto_password);
    crypto_lock(g_app.install_pass, sizeof g_app.install_pass);

    // The save to open: the one --save names, the only one there is, or one picked later.
    g_app.n_saves = install_list(g_app.saves, INSTALL_SAVES_MAX);
    if (o->save[0]) install_use(o->save);
    else if (g_app.n_saves == 1) install_use(g_app.saves[0].name);
    int saved = o->save[0] ? save_exists(o->save) : g_app.n_saves > 0;
    if (o->save[0] && !saved && !o->update)
        saved_note("* there's no save called %s yet: chat starts from its defaults, and :install makes it",
                   install_shown_name(o->save));
    if (o->update) {
        // What :install saved may route the download through Tor, so it isn't skipped silently.
        if (saved) unlock_at_start(0);
        if (g_app.locked && !g_app.route_chosen) {
            fprintf(stderr, "chat: not updating - what :install saved stays sealed, and with it the routing to "
                            "download by: CHAT_INSTALL_PASSWORD opens it, or --routing chooses one\n");
            return 1;
        }
        // With --routing tor the download goes through Tor, never direct, so find or start a tor first.
        int over_tor = g_app.route_chosen && g_app.route.mode == ROUTE_TOR;
        if (over_tor) {
            net_startup();
            g_plain = 1;
            double give_up = now_seconds() + 120.0;
            tor_link_ensure(now_seconds());
            while (g_tor.state != TL_READY && g_tor.state != TL_FAILED && now_seconds() < give_up) {
                tor_link_step(now_seconds());
                platform_sleep_ms(100);
            }
            if (g_tor.state != TL_READY) {
                fprintf(stderr, "chat: no tor to download through - not updating\n");
                tor_link_stop();
                return 1;
            }
            sync_update_proxy();
        }
        printf("chat: checking GitHub for a newer release (v" CHAT_VERSION " here)%s...\n", over_tor ? " through Tor" : "");
        fflush(stdout);
        char msg[UPDATE_MSG_MAX];
        int rc = update_run(msg, sizeof msg);
        if (over_tor) tor_link_stop();
        const char *text = strncmp(msg, "* update: ", 10) == 0 ? msg + 10 : msg;
        fprintf(rc == 0 ? stdout : stderr, "chat: %s\n", text);
        return rc == 0 ? 0 : 1;
    }

    net_startup();

    int interactive = !o->simple && term_is_tty() && term_stdout_is_tty() && term_ansi_ok();
    // NO_COLOR (no-color.org) limits the UI to bold, faint and reverse.
    const char *no_color = getenv("NO_COLOR");
    g_app.color_enabled = interactive && !(no_color && no_color[0]);
    if (o->has_color) memcpy(g_app.color, o->color, 3);
    else {
        uint8_t r; gen_random(&r, 1);
        const named_color_t *pick = &COLOR_PALETTE[r % COLOR_PALETTE_N];
        g_app.color[0] = pick->r; g_app.color[1] = pick->g; g_app.color[2] = pick->b;
    }
    if (o->nick[0]) chat_clean_nick(o->nick, g_app.nick);

    // Only the format is checked here. Nothing goes on the network before the routing is decided, so
    // a name is looked up when the session starts.
    for (int i = 0; i < o->n_peers; i++) {
        if (addr_check_hostport(o->peers[i]) != 0) {
            fprintf(stderr, "chat: bad --peer %s\n", o->peers[i]);
            return 1;
        }
    }

    g_app.identity_source = IDENT_NONE;
    if (o->identity[0]) {
        identity_source_t kind = o->identity[0] == 'a' ? IDENT_AGE : IDENT_PGP;
        const char *path = o->identity[3] == ':' ? o->identity + 4 : NULL;
        if (!path) {
            // Like a session's password: from the environment, otherwise asked for, otherwise blank.
            char pw[256] = "";
            if (platform_env_take("CHAT_SIGN_PASSWORD", pw, sizeof pw) != 0 && term_is_tty())
                term_read_password("signing key password (always the same one keeps the same key; blank for a "
                                   "new key): ", pw, sizeof pw);
            const char *why = make_identity(kind, pw);
            crypto_wipe(pw, sizeof pw);
            if (why) fprintf(stderr, "chat: %s\n", why);
        } else if (!path[0] || load_key_file(kind, path) != 0)
            fprintf(stderr, "chat: could not load %s identity from %s\n", kind == IDENT_AGE ? "an AGE" : "a PGP",
                    path[0] ? path : "(no path given)");
    }

    if (saved) unlock_at_start(interactive);
    // What's still sealed could have chosen Tor, and with nobody to ask, chat doesn't guess.
    if (g_app.locked && !g_app.route_chosen && !interactive && !term_is_tty()) {
        fprintf(stderr, "chat: what :install saved stays sealed, and with it your routing: CHAT_INSTALL_PASSWORD "
                        "opens it, or --routing chooses one\n");
        return 1;
    }
    if (g_app.route_chosen && g_app.route.mode == ROUTE_TOR && o->n_peers > 0) {
        // A --peer address would be reached over UDP, which Tor mode never uses.
        fprintf(stderr, "chat: --peer can't be used with --routing tor\n");
        return 1;
    }

    if (!interactive) {
        if (!g_app.nick[0]) random_nickname(g_app.nick, sizeof g_app.nick);
        return run_plain(o->session[0] ? o->session : NULL, NULL, o->port, o->peers, o->n_peers);
    }

    if (!o->session[0]) {
        return run_tui(NULL, NULL, 0, NULL, 0);
    }

    char explicit_password[256] = "";

    if (platform_env_take("CHAT_PASSWORD", explicit_password, sizeof explicit_password) != 0) {
        if (term_read_password("password: ", explicit_password, sizeof explicit_password) != 0) return 1;
    }
    int rc = run_tui(o->session, explicit_password, o->port, o->peers, o->n_peers);
    crypto_wipe(explicit_password, sizeof explicit_password);
    return rc;
}
