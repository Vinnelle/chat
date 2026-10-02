// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "core/chat.h"
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
    "  F1         every key and command on one page (also ? in NORMAL, and :help)\n"
    "  Ctrl+C     quit chat (every open session leaves cleanly first)\n"
    "\n"
    "Each session has two parts: the conversation, and a console above it for everything\n"
    "else, such as people joining and leaving, network lookups and command output. A session\n"
    "you joined is locked (the chat says \"connecting\") until someone answers. The bottom\n"
    "row shows where you are, what the keys do there, and the result of your last action,\n"
    "until the next key.\n"
    "\n"
    "The input line works like a small vim. It starts in NORMAL: h/l move, 0/$ go to the\n"
    "ends, x deletes, j/k switch session, s/c/C hide/show the sidebar/console/chat.\n"
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
    "  :port [N] :set [NAME [VALUE]] :install :uninstall :help   (:help opens a page of keys\n"
    "  and commands)\n"
    "\n"
    "Anyone with a session's id and password can sit between two other members. When a peer\n"
    "joins, chat shows a verify code to compare with them over another channel (a call, in\n"
    "person), and :verify NICK ok marks it as matching. --verify-required (:set verify\n"
    "required) sends nothing to a peer until then.\n"
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
    "CHAT_INSTALL_PASSWORD), and settings are saved again whenever one changes. Options\n"
    "given here override what's saved, for that run only. :uninstall deletes it.\n"
    "\n"
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
    "              from gpg. Without --identity chat starts unsigned, or with the key\n"
    "              :install saved. Signing identity on the settings page (:set sign) sets\n"
    "              up any of these, or turns signing off, without restarting. A key can come\n"
    "              from a file browser or be pasted in, and is only written to disk by\n"
    "              :install, sealed.\n"
    "  --simple    don't use the full-screen UI, even in a terminal. Prints plain\n"
    "              \"[HH:MM] ...\" lines for one session and reads lines from stdin. A line\n"
    "              starting with : is a command (:help lists them). For scripts and basic\n"
    "              terminals. This is also used automatically when stdout isn't a tty.\n"
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

// A picture fetched to show: its thumbnail, drawn under the line that offered it while shown.
#define MAX_PICS 16
typedef struct {
    int used, num, shown;
    image_thumb_t th;
    tui_image_t ti;
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
    MODE_SIGN_PASTE,
    MODE_SIGN_PASSWORD,
    MODE_CHAT,
    MODE_NEW_PASSWORD,
    MODE_JOIN_ID,
    MODE_JOIN_PASSWORD,
    MODE_INSTALL,
    MODE_INSTALL_PASS,
    MODE_INSTALL_PASS2,
    MODE_INSTALL_UNLOCK,
    MODE_UNINSTALL,
    MODE_UNLOCK,
    MODE_UPDATE
} app_mode_t;

// KEY_MADE is a new random key, KEY_DERIVED one made from a password on this device.
typedef enum { KEY_MADE, KEY_DERIVED, KEY_FILE, KEY_PASTED } key_origin_t;

// A PGP key's fingerprint covers its creation time, so a key made from a password always
// gets this one (2026-01-01) to keep its fingerprint.
#define DERIVED_PGP_CREATED 1767225600u

#define MAX_DIR_ITEMS 512

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
    int help_sel;
    int changelog_scroll, changelog_most;
    char message[200];   // the bottom bar's result of the last action, until the next key
    int onboarding;   // the settings page chat opens on: its Done button starts chat
    int sign_sel;
    key_origin_t key_origin;       // where the identity in use came from
    uint32_t pgp_created;          // a PGP key made here: its creation time, which its fingerprint covers
    identity_source_t load_kind;   // AGE or PGP: what the key file browser or the paste page takes
    int tor_launch;
    char tor_path[512];
    uint64_t file_cap;   // 0: the default
    int fast_files;
    uint8_t color[3];
    identity_source_t identity_source;
    identity_keypair_t identity;
    // installed: what :install saved is open and kept up to date. locked: it exists but is still
    // sealed. install_pass holds the passphrase while it's typed the second time.
    int installed, locked;
    int saved_key_known;
    uint8_t saved_key_pub[ID_SIGN_PUB_LEN];
    char install_pass[256];
    int unlock_at_start;
    app_mode_t mode;
    char pending_session_id[MAX_SESSION_NAME + 1];
    int show_sidebar, show_console, show_chat;
    int dirty;
    int input_dirty;

    tui_scrollback_t log;
    tui_input_t input;
    tui_input_t saved_input;
    browser_t browser;
    char send_dir[900];   // the folder :send's browser last offered a file from
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
    uint16_t port;
    char peers[MAX_PEER_ARGS][PEER_ARG_LEN];
    int n_peers;
    int simple, update, has_color;
    uint8_t color[3];
} options_t;

static options_t g_opts;
static int g_argc;
static char **g_argv;

static volatile sig_atomic_t g_interrupted = 0;
static void on_sigint(int sig) {
    g_interrupted = 1;
#ifdef _WIN32
    // The Windows C runtime puts the default back before calling a handler.
    signal(sig, on_sigint);
#else
    (void)sig;
#endif
}

// Ctrl+C, a kill or a closed terminal all end the main loop, so sessions say bye, keys are wiped,
// the terminal is restored and chat's own tor is stopped, instead of the process just dying. The
// handler has to stay in place for a second signal too. With plain signal() and _POSIX_C_SOURCE,
// glibc resets it after the first, and a second Ctrl+C or kill skipped all of that.
static void catch_quit_signals(void) {
#ifdef _WIN32
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint;
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

static void session_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                          unsigned flags, int color_len, int file) {
    session_slot_t *s = (session_slot_t *)ui;
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
        if (s->pics[i].used && s->pics[i].num == file && s->pics[i].shown) return &s->pics[i].ti;
    return NULL;
}

// Someone else's file being fetched, for the row under the line that offered it. Through the
// relays it can take a long time, and nothing else shows its progress.
static const tui_progress_t *progress_for(const void *ctx, int file) {
    static tui_progress_t pg;
    const session_slot_t *s = ctx;
    const file_entry_t *f = chat_file(&s->engine, file);
    if (!f || f->mine || f->dl != DL_ACTIVE) return NULL;
    uint64_t got = chat_file_got(f);
    pg.permille = f->size ? (int)(got * 1000 / f->size) : 1000;
    char gs[32], all[32], eta[64];
    file_format_size(got, gs, sizeof gs);
    file_format_size(f->size, all, sizeof all);
    double left = chat_file_eta(&s->engine, f, now_seconds());
    if (left >= 0.0) { file_format_duration(left, eta, sizeof eta); strcat(eta, " left"); }
    else copy_str(eta, left < -1.0 ? "waiting until verify codes are compared" : "waiting for its sender", sizeof eta);
    snprintf(pg.text, sizeof pg.text, "%d%% \xc2\xb7 %s of %s \xc2\xb7 %s", pg.permille / 10, gs, all, eta);
    return &pg;
}

// A picture fetched to show has arrived. It's decoded into a thumbnail here, then the bytes are discarded.
static void session_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
    session_slot_t *s = ui;
    (void)name;
    static const uint8_t bg[3] = { 0, 0, 0 };
    image_thumb_t th;
    char why[160];
    if (image_thumbnail(data, len, TUI_IMAGE_MAX_W, TUI_IMAGE_MAX_H, bg, &th, why, sizeof why) != 0) {
        console_note(s, "* can't show file %d: %s - :download %d saves it", num, why, num);
        return;
    }
    pic_t *p = pic_find(s, num);
    if (!p) for (int i = 0; i < MAX_PICS && !p; i++) if (!s->pics[i].used) p = &s->pics[i];
    if (!p) {
        p = &s->pics[0];
        for (int i = 1; i < MAX_PICS; i++) if (s->pics[i].num < p->num) p = &s->pics[i];
    }
    pic_free(p);
    p->used = 1;
    p->num = num;
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

static void close_session(session_slot_t *s) {
    if (!s) return;
    int idx = slot_index(s);
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

static void tor_link_apply(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_t *e = &g_app.sessions[i].engine;
        if (e->route.mode == ROUTE_TOR) chat_tor_set_ports(e, g_tor.socks, g_tor.control);
    }
    if (g_plain_engine && g_plain_engine->route.mode == ROUTE_TOR) chat_tor_set_ports(g_plain_engine, g_tor.socks, g_tor.control);
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

static int entry_cmp(const void *a, const void *b) {
    const dir_entry_t *ea = a, *eb = b;
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir;
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
    if (strcmp(name, "..") == 0 && path_is_root(b->path)) return;
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
static cmd_result_t app_show(void *ctx, const char *arg);
static cmd_result_t app_hide(void *ctx, const char *arg);

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

typedef enum {
    SET_ROUTING, SET_DHT4, SET_DHT6, SET_PORTMAP, SET_LAN,
    SET_TOR_LAUNCH, SET_TOR_PATH, SET_TOR_SOCKS, SET_TOR_CONTROL, SET_TOR_PASSWORD,
    SET_NOSTR, SET_RELAYS,
    SET_NICK, SET_COLOUR, SET_SIGN, SET_AGE_RECIPIENT, SET_PGP_PUBKEY,
    SET_VERIFY, SET_FILE_LIMIT, SET_FAST_FILES, SET_NOTIFY, SET_PREVIEW, SET_NET, SET_PORT
} setting_id_t;

typedef struct {
    setting_id_t id;
    const char *section;
    const char *key;      // its name after :set
    const char *label;
    int kind;
    const char *values;   // what :set takes, or NULL for a row only the page sets
    const char *help;
} setting_def_t;

static const setting_def_t SETTINGS[] = {
    { SET_ROUTING, "Network", "routing", "Routing", K_CHOICE, "dht|tor",
      "dht: UDP directly between peers, found using the options below. tor: onion services, plus the Nostr "
      "relays through Tor to meet DHT members. Hides your IP address from everyone. Uses a running tor or "
      "starts chat's own, and connecting takes longer. Applies to sessions you open from now on." },
    { SET_DHT4, NULL, "dht", "BitTorrent DHT (IPv4)", K_TOGGLE, "on|off",
      "Finds peers on the internet through the public BitTorrent DHT. DHT nodes see your IP address next to a "
      "lookup key only room members can work out, and a node id that changes with it every hour." },
    { SET_DHT6, NULL, "dht6", "IPv6 DHT", K_TOGGLE, "on|off",
      "Also looks for peers on the IPv6 DHT (BEP 32). IPv6 usually has no NAT to punch through, so peers there "
      "connect more reliably." },
    { SET_PORTMAP, NULL, "portmap", "Router port mapping", K_TOGGLE, "on|off",
      "Asks your router to forward this session's UDP port (PCP, NAT-PMP or UPnP-IGD), so peers behind NATs that "
      "can't be hole punched can still reach you. Removed when the session ends. The router may log it." },
    { SET_LAN, NULL, "lan", "LAN discovery", K_TOGGLE, "on|off",
      "Broadcasts an encrypted beacon on your local network, so room members on it can find you without the "
      "internet." },
    { SET_TOR_LAUNCH, NULL, "torlaunch", "Start chat's own tor", K_CHOICE, "auto|always|never",
      "auto: use a tor that's already running if its control port lets chat log in (it keeps its entry guards "
      "and any bridges), otherwise start chat's own. always: chat's own, separate from any other tor, but with "
      "new entry guards each run and nothing from your torrc. never: only a running tor. Chat's own tor uses "
      "random 127.0.0.1 ports, a cookie login and a private temporary folder deleted on exit." },
    { SET_TOR_PATH, NULL, "torpath", "Tor program", K_TEXT, "PATH",
      "The tor program chat starts: a full path, or empty for tor on PATH or in the usual folders. It must be a "
      "program that only root or you can change." },
    { SET_TOR_SOCKS, NULL, "torsocks", "Tor SOCKS port", K_TEXT, "HOST:PORT",
      "Where to look for a running tor's SOCKS port (host:port). With the defaults, Tor Browser's "
      "127.0.0.1:9150 is tried too. Applies to sessions you open from now on." },
    { SET_TOR_CONTROL, NULL, "torcontrol", "Tor control port", K_TEXT, "HOST:PORT",
      "Where to look for a running tor's control port (host:port). It needs ControlPort on, and chat has to be "
      "able to read its cookie file (or have its password). Applies to sessions you open from now on." },
    { SET_TOR_PASSWORD, NULL, "torpassword", "Tor control password", K_SECRET, NULL,
      "Only for a tor set up with HashedControlPassword. Kept in memory only. Applies to sessions you open from now on." },
    // Last in the section: the relays apply in both modes, so they stay put when the mode changes.
    { SET_NOSTR, NULL, "nostr", "Nostr relays", K_CHOICE, "off|on|always",
      "on: DHT routing only connects to the relays while it needs them (nobody reached yet, or a peer UDP can't"
      " reach) and disconnects a minute after. always: stays connected, so Tor members can find a room whose "
      "members all reach each other directly (they only meet on the relays). Tor routing reaches them through "
      "Tor and always stays connected. Each event has a one-off key, a random kind, a fixed size and fresh "
      "encryption, under a tag that changes every 10 minutes, with a new connection for each tag." },
    { SET_RELAYS, NULL, "relays", "Relay list", K_TEXT, "wss://URL ... (up to 6)",
      "The relays the fallback uses: up to 6 wss:// URLs, separated by spaces or commas." },
    { SET_NICK, "Profile", "nick", "Nickname", K_TEXT, "NAME", "Your name in every session." },
    { SET_COLOUR, NULL, "colour", "Colour", K_TEXT, "NAME|#RRGGBB",
      "Your colour in every session. h/l step through the palette, and Enter takes a name or #RRGGBB." },
    { SET_SIGN, NULL, "sign", "Signing identity", K_ACTION, "off|age|pgp",
      "A key that signs your handshakes so peers can check it's you. Either an AGE or PGP key made here from a "
      "password, or your own key from a file or pasted in. Enter picks one, replaces it or turns signing off. "
      "Kept in memory only, unless :install seals it to disk." },
    { SET_AGE_RECIPIENT, NULL, "agerecipient", "AGE recipient", K_ACTION, NULL,
      "The age1... string others give to age -r to encrypt files to you. Enter copies it to the clipboard." },
    { SET_PGP_PUBKEY, NULL, "pgpkey", "PGP public key", K_ACTION, NULL,
      "The public half of the PGP key made here, shown by its fingerprint, for others to gpg --import. Enter "
      "copies it to the clipboard. It's in the console too." },
    { SET_VERIFY, "Chat", "verify", "Compare verify codes", K_CHOICE, "required|optional",
      "Anyone with a session's id and password could sit between two members and read what they say. When a peer "
      "joins, chat shows a code to compare with them over another channel. It only matches on both ends if "
      "nobody is in the middle. required: nothing you send goes to a peer until you mark it as matching "
      "(:verify NICK ok). optional: messages go to everyone, compared or not." },
    { SET_FILE_LIMIT, NULL, "filelimit", "File size limit", K_TEXT, "SIZE (8M, 500K, 1G)",
      "The largest file chat fetches when you ask. An offer over the limit says so, and :download N anyway (or "
      ":show N anyway) fetches it regardless. Nothing is fetched until you ask. Files can be up to 1 GB." },
    { SET_FAST_FILES, NULL, "fastfiles", "Fast file transfers", K_TOGGLE, "on|off",
      "off: files are sent in chat's regular slots, so a transfer doesn't show up on the network, but it's slow: "
      "about 25 KB a minute, half that through the relays (where Tor and DHT members meet). on: while you send a "
      "file, your slots to that peer come every few milliseconds. It takes seconds instead of minutes, but anyone "
      "watching the network sees a burst about the size of the file. Through the relays it goes as often as they "
      "allow, about twice the normal rate, and the relays can see that. Only the sender's setting matters." },
    { SET_NOTIFY, NULL, "notify", "Notifications", K_CHOICE, "all|mentions|none",
      "Desktop notifications, for open and new sessions: every message, mentions of your nick, or none." },
    { SET_PREVIEW, NULL, "preview", "Notification preview", K_CHOICE, "off|nick|message",
      "What a notification shows. off: only that a message came in. nick: who it's from. message: who, and what "
      "they said. Desktops keep notifications (Windows writes them to disk), so what they show can outlast chat. "
      "The session is never shown, since its id is all someone needs to join one with a blank password." },
    { SET_NET, NULL, "net", "Network log", K_CHOICE, "normal|verbose",
      "How much of the network the console shows, in every session. verbose adds every handshake packet, relay "
      "and Tor event." },
    { SET_PORT, NULL, "port", "UDP port for new sessions", K_TEXT, "N",
      "The UDP port new sessions listen on. 0 picks a free one each time. :port moves an open session to another." },
};
#define N_SETTINGS ((int)(sizeof SETTINGS / sizeof SETTINGS[0]))

static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };
static const char *const PREVIEW_NAMES[] = { "off", "nick", "message" };
static const char *const ON_OFF[] = { "off", "on" };
static const char *const ROUTE_NAMES[] = { "dht", "tor" };
static const char *const NOSTR_NAMES[] = { "off", "on", "always" };
static const char *const VERIFY_NAMES[] = { "required", "optional" };
static const char *const NET_LOG_NAMES[] = { "normal", "verbose" };

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
        case SET_TOR_LAUNCH: *names = TOR_LAUNCH_NAMES; *n = 3; return g_app.tor_launch;
        case SET_NOTIFY:     *names = NOTIFY_NAMES; *n = 3; return (int)g_app.notify_mode;
        case SET_PREVIEW:    *names = PREVIEW_NAMES; *n = 3; return (int)g_app.notify_preview;
        case SET_NET:        *names = NET_LOG_NAMES; return g_app.net_verbose != 0;
        default:             *names = NULL; *n = 0; return -1;
    }
}

static const char *const SIGN_NAMES[] = { "off", "age", "pgp" };

// What :set takes for a row, for the command line's menu: its values, and the signing identity's
// kinds (a key file or a pasted key is only chosen on the page).
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
    if (d->id == SET_SIGN) return TUI_V_LINK;
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
        default:
            out[0] = '\0';
            break;
    }
}

// A row's value in the form :set takes. 0 for a secret, or a value that comes from the signing key.
static int setting_text(setting_id_t id, char *out, size_t cap) {
    const setting_def_t *d = setting_def(id);
    if (d->kind == K_SECRET || d->kind == K_ACTION) return 0;
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
// option isn't.
static char g_setting_defaults[N_SETTINGS][ROW_TEXT_MAX];
static char g_saved_rows[N_SETTINGS][ROW_TEXT_MAX];
static char g_seen_rows[N_SETTINGS][ROW_TEXT_MAX];

static void note_setting_defaults(void) {
    for (int i = 0; i < N_SETTINGS; i++)
        if (!setting_text(SETTINGS[i].id, g_setting_defaults[i], sizeof g_setting_defaults[i])) g_setting_defaults[i][0] = '\0';
    memcpy(g_saved_rows, g_setting_defaults, sizeof g_saved_rows);
}

static void note_settings_seen(void) {
    for (int i = 0; i < N_SETTINGS; i++)
        if (!setting_text(SETTINGS[i].id, g_seen_rows[i], sizeof g_seen_rows[i])) g_seen_rows[i][0] = '\0';
}

static void row_table(int i, char *out, size_t cap) {
    while (i > 0 && !SETTINGS[i].section) i--;
    size_t n = 0;
    for (const char *c = SETTINGS[i].section; *c && n + 1 < cap; c++) out[n++] = (char)tolower((unsigned char)*c);
    out[n] = '\0';
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
    char table[16] = "";
    out[0] = '\0';
    for (int i = 0; i < N_SETTINGS; i++) {
        if (strcmp(g_saved_rows[i], g_setting_defaults[i]) == 0) continue;
        char t[16];
        row_table(i, t, sizeof t);
        if (strcmp(t, table) != 0) {
            p = put_text(out, p, cap, p ? "\n[" : "[");
            p = put_text(out, p, cap, t);
            p = put_text(out, p, cap, "]\n");
            copy_str(table, t, sizeof table);
        }
        p = put_text(out, p, cap, SETTINGS[i].key);
        p = put_text(out, p, cap, " = ");
        p = put_row_value(i, g_saved_rows[i], out, p, cap);
        p = put_text(out, p, cap, "\n");
    }
    return p < cap ? 0 : -1;
}

// Checked before every frame, so any change to a row (from the page or :set) is picked up.
static void keep_settings_saved(void) {
    if (!g_app.installed) return;
    int changed = 0;
    for (int i = 0; i < N_SETTINGS; i++) {
        char v[ROW_TEXT_MAX];
        if (!setting_text(SETTINGS[i].id, v, sizeof v) || strcmp(v, g_seen_rows[i]) == 0) continue;
        copy_str(g_seen_rows[i], v, sizeof g_seen_rows[i]);
        if (strcmp(v, g_saved_rows[i]) == 0) continue;
        copy_str(g_saved_rows[i], v, sizeof g_saved_rows[i]);
        changed = 1;
    }
    if (!changed) return;
    static char text[INSTALL_SETTINGS_MAX];
    if (settings_text(text, sizeof text) != 0 || install_write_settings(text) != 0) {
        char where[900] = "";
        install_where(where, sizeof where);
        note("couldn't save that in %s/settings - it lasts until chat exits", where);
        return;
    }
    size_t n = strlen(g_app.message);
    if (n > 0) snprintf(g_app.message + n, sizeof g_app.message - n, " \xc2\xb7 saved");
}

// Pushes the routing settings to the open sessions, where the toggles take effect immediately. On
// the startup settings page nothing goes on the network before Done, so settings_done does it then.
static void routing_changed(setting_id_t id) {
    int later = 0, any = 0;
    if (!g_app.onboarding) {
        sync_update_proxy();
        tor_link_ensure(now_seconds());
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
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
        if (g_app.used[i] && !g_app.sessions[i].initialising) chat_set_colour(&g_app.sessions[i].engine, g_app.color);
}

// Sets a toggle or choice row to its i-th value, wherever it applies.
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
                if (g_app.used[s] && !g_app.sessions[s].initialising) g_app.sessions[s].engine.verify_required = !i;
            break;
        case SET_TOR_LAUNCH:
            g_app.tor_launch = i;
            note("Start chat's own tor: %s - for the next tor chat looks for; a tor already in use stays",
                 TOR_LAUNCH_NAMES[i]);
            return;
        case SET_NOTIFY:
            g_app.notify_mode = (notify_mode_t)i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (g_app.used[s] && !g_app.sessions[s].initialising) g_app.sessions[s].engine.notify_mode = g_app.notify_mode;
            break;
        case SET_PREVIEW:
            g_app.notify_preview = (notify_preview_t)i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (g_app.used[s] && !g_app.sessions[s].initialising) g_app.sessions[s].engine.notify_preview = g_app.notify_preview;
            break;
        case SET_NET:
            g_app.net_verbose = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (g_app.used[s] && !g_app.sessions[s].initialising) g_app.sessions[s].engine.net_verbose = i;
            break;
        case SET_FAST_FILES:
            g_app.fast_files = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (g_app.used[s] && !g_app.sessions[s].initialising) chat_set_file_options(&g_app.sessions[s].engine, g_app.file_cap, i);
            break;
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
                if (g_app.used[i] && !g_app.sessions[i].initialising) chat_set_file_options(&g_app.sessions[i].engine, v, g_app.fast_files);
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
                if (g_app.used[i] && !g_app.sessions[i].initialising) chat_set_nick(&g_app.sessions[i].engine, g_app.nick);
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

#define SETTINGS_DONE N_SETTINGS   // settings_sel of the Done button, after the last setting

// The next listed row from the selected one in direction dir: the Done button after the last, and
// the same row again before the first.
static int settings_step_sel(int dir) {
    for (int i = g_app.settings_sel + dir; i >= 0 && i < N_SETTINGS; i += dir)
        if (setting_shown(SETTINGS[i].id)) return i;
    return dir > 0 ? SETTINGS_DONE : g_app.settings_sel;
}

// Moves the selection off a row that stopped being listed.
static void settings_fix_sel(void) {
    if (g_app.settings_sel >= N_SETTINGS || setting_shown(SETTINGS[g_app.settings_sel].id)) return;
    int up = settings_step_sel(-1);
    g_app.settings_sel = up != g_app.settings_sel ? up : settings_step_sel(1);
}

static int first_shown_from(int i) {
    for (; i < N_SETTINGS; i++) if (setting_shown(SETTINGS[i].id)) return i;
    return SETTINGS_DONE;
}

static int section_start(int i) {
    if (i >= N_SETTINGS) i = N_SETTINGS - 1;
    while (i > 0 && !SETTINGS[i].section) i--;
    return i;
}

// Tab: the next section's first row, or the Done button after the last. Shift+Tab: this section's
// first row, or if already there, the previous section's.
static int settings_section_step(int dir) {
    int sel = g_app.settings_sel;
    if (dir > 0) {
        for (int i = sel + 1; i < N_SETTINGS; i++) if (SETTINGS[i].section) return first_shown_from(i);
        return SETTINGS_DONE;
    }
    int start = section_start(sel), first = first_shown_from(start);
    if (sel == SETTINGS_DONE || first < sel) return first;
    return start > 0 ? first_shown_from(section_start(start - 1)) : first;
}

static void begin_settings(void) {
    if (g_app.mode != MODE_CHAT) return;
    g_app.mode = MODE_SETTINGS;
    if (g_app.settings_sel == SETTINGS_DONE) g_app.settings_sel = 0;
    settings_fix_sel();
    g_app.dirty = 1;
}

// Opens the page on a row, or says why the row isn't on it right now.
static void settings_open_at(setting_id_t id) {
    begin_settings();
    if (setting_shown(id)) g_app.settings_sel = settings_index(id);
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
    else if (d->id == SET_AGE_RECIPIENT || d->id == SET_PGP_PUBKEY) act = "enter copy";
    else act = "h/l change";
    static char hint[160];
    snprintf(hint, sizeof hint, "%s \xc2\xb7 j/k move \xc2\xb7 tab section \xc2\xb7 esc %s", act,
             g_app.onboarding ? "start" : "done");
    return hint;
}

// ---- the signing identity, chosen on a page under the settings ----

// Off, then for each of AGE and PGP a key made here, one from a file and one pasted in.
typedef enum {
    PICK_OFF, PICK_AGE_MADE, PICK_AGE_FILE, PICK_AGE_PASTE, PICK_PGP_MADE, PICK_PGP_FILE, PICK_PGP_PASTE, N_PICKS
} sign_pick_t;

static const struct { const char *section, *label, *help; } SIGN_PICKS[N_PICKS] = {
    { NULL, "Off", "Don't sign. Peers see you as unverified." },
    { "AGE", "Native", "A key made here, with an age1... recipient others can encrypt files to you with "
                       "(age -r). Enter asks for a password: the same password on this device and OS always makes "
                       "the same key, so always use the same one to keep an established signing identity. Blank "
                       "makes a new key that lasts until chat exits." },
    { NULL, "Key file", "Your own AGE key from a file, as age-keygen writes it. Your age1... recipient stays "
                        "the same." },
    { NULL, "Paste a key", "Your own AGE key pasted in: the AGE-SECRET-KEY-1... line. Kept in memory: only "
                           ":install writes it to disk, sealed." },
    { "PGP", "Native", "A PGP key made here, whose public key is in the settings and the console for others "
                       "to import. Enter asks for a password: the same password on this device and OS always makes "
                       "the same key, so always use the same one to keep an established signing identity. Blank "
                       "makes a new key that lasts until chat exits." },
    { NULL, "Key file", "Your own key from a file: an unencrypted EdDSA/Ed25519 secret key, armored, as "
                        "gpg --export-secret-keys --armor writes it." },
    { NULL, "Paste a key", "Your own key pasted in, armored. Kept in memory: only :install writes it to disk, "
                           "sealed." },
};

static const char AGE_PASTE_HELP[] =
    "Paste your AGE secret key now: the AGE-SECRET-KEY-1... line, or the whole file age-keygen wrote. It's read "
    "when its line ends (Enter, if the paste didn't end it) and kept in memory: only :install writes it to disk, "
    "sealed.";

static const char PGP_PASTE_HELP[] =
    "Paste your armored PGP private key now, BEGIN line to END line. It's read as soon as the END line "
    "arrives and kept in memory: only :install writes it to disk, sealed. It has to be an unencrypted "
    "EdDSA/Ed25519 key (gpg --export-secret-keys --armor, from a key with no passphrase).";

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
static void identity_chosen(void) {
    int any = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_set_identity(&g_app.sessions[i].engine, g_app.identity_source, &g_app.identity);
        any = 1;
    }
    show_identity_result();
    if (g_app.installed && g_app.identity_source != IDENT_NONE && !key_in_use_saved())
        push_log("* this signing key isn't saved: :install seals it with your settings' passphrase%s",
                 install_has_key() ? ", in place of the saved one" : "");
    else if (g_app.installed && g_app.identity_source == IDENT_NONE && install_has_key())
        push_log("* the saved signing key stays saved, and signs again the next time chat starts");
    char v[160]; setting_value(SET_SIGN, v, sizeof v);
    note("Signing identity: %s%s", v, any ? " - applied to open sessions too" : "");
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

// kind's key (AGE or PGP) from the file at path. Returns 0 once it's the identity in use.
static int load_key_file(identity_source_t kind, const char *path) {
    int rc = kind == IDENT_AGE ? age_import_secret_key(path, &g_app.identity)
                               : pgp_import_secret_key(path, &g_app.identity);
    if (rc != 0) return -1;
    g_app.identity_source = kind;
    g_app.key_origin = KEY_FILE;
    return 0;
}

static void begin_key_browse(identity_source_t kind) {
    g_app.load_kind = kind;
    const char *home = platform_home_dir();
    if (!home || browser_load(&g_app.browser, home) != 0) browser_load(&g_app.browser, "/");
    g_app.mode = MODE_SIGN_BROWSE;
    g_app.dirty = 1;
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
        if (g_app.load_kind == IDENT_AGE) note("%.80s holds no AGE secret key", sel->name);
        else note("%.80s isn't an unencrypted EdDSA/Ed25519 secret key", sel->name);
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
        case PICK_AGE_PASTE: begin_key_paste(IDENT_AGE); return;
        case PICK_PGP_FILE:  begin_key_browse(IDENT_PGP); return;
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
// Tab/Shift+Tab go to the next or previous section, Enter or space chooses, h/l or left/right go
// sideways (Backspace too, like vim's h), Esc goes back a level, and q or Ctrl+S closes the page.
static list_key_t list_key(const tui_key_t *key) {
    switch (key->type) {
        case TUI_KEY_UP:        return LIST_UP;
        case TUI_KEY_DOWN:      return LIST_DOWN;
        case TUI_KEY_HOME:      return LIST_FIRST;
        case TUI_KEY_END:       return LIST_LAST;
        case TUI_KEY_TAB:       return LIST_NEXT_SECTION;
        case TUI_KEY_BACKTAB:   return LIST_PREV_SECTION;
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
    switch (list_key(key)) {
        case LIST_UP:    g_app.settings_sel = settings_step_sel(-1); break;
        case LIST_DOWN:  g_app.settings_sel = settings_step_sel(1); break;
        case LIST_FIRST: g_app.settings_sel = 0; break;
        case LIST_LAST:  g_app.settings_sel = SETTINGS_DONE; break;
        case LIST_NEXT_SECTION: g_app.settings_sel = settings_section_step(1); break;
        case LIST_PREV_SECTION: g_app.settings_sel = settings_section_step(-1); break;
        case LIST_LEFT:  if (steps) setting_step(d->id, -1); break;
        case LIST_RIGHT:
            if (steps) setting_step(d->id, 1);
            else if (d && d->id == SET_SIGN) begin_sign();
            break;
        case LIST_CHOOSE:
            if (!d) settings_done();
            else if (steps && d->id != SET_COLOUR) setting_step(d->id, 1);
            else if (d->kind == K_TEXT || d->kind == K_SECRET) begin_setting_edit(d->id);
            else if (d->id == SET_SIGN) begin_sign();
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

static void browser_up(void) {
    char up[900]; copy_str(up, g_app.browser.path, sizeof up);
    path_parent(up);
    browser_load(&g_app.browser, up);
}

static void browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_LEFT: browser_up(); break;
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            if (b->n_items == 0) break;
            const dir_entry_t *sel = &b->items[b->selected];
            if (strcmp(sel->name, "../") == 0) {
                browser_up();
            } else if (sel->is_dir) {
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
    if (g_app.mode != MODE_CHAT) return;
    const char *home = platform_home_dir();
    if ((!g_app.send_dir[0] || browser_load(&g_app.browser, g_app.send_dir) != 0)
        && (!home || browser_load(&g_app.browser, home) != 0))
        browser_load(&g_app.browser, "/");
    g_app.mode = MODE_SEND_BROWSE;
    g_app.dirty = 1;
}

static void send_browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_LEFT: browser_up(); break;
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            if (b->n_items == 0) break;
            const dir_entry_t *sel = &b->items[b->selected];
            char full[1200]; browser_entry_path(b, sel, full, sizeof full);
            if (strcmp(sel->name, "../") == 0) {
                browser_up();
            } else if (sel->is_dir) {
                browser_load(b, full);
            } else if (k == LIST_CHOOSE) {
                g_app.mode = MODE_CHAT;
                if (!g_app.selected || g_app.selected->initialising) {
                    note("no session to send %.80s to", sel->name);
                    break;
                }
                copy_str(g_app.send_dir, b->path, sizeof g_app.send_dir);
                chat_send_file(&g_app.selected->engine, full);
            }
            break;
        }
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = MODE_CHAT; break;
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

// The settings' sections, for the list on the left of the pages under them.
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

static void render_settings(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    tui_row_t rows[N_SETTINGS];
    char values[N_SETTINGS][160];
    int n_rows = 0, sel_row = -1;
    const char *section = NULL;
    for (int i = 0; i < N_SETTINGS; i++) {
        const setting_def_t *d = &SETTINGS[i];
        if (d->section) section = d->section;   // the heading goes on its section's first listed row
        if (!setting_shown(d->id)) continue;
        if (i == g_app.settings_sel) sel_row = n_rows;
        setting_value(d->id, values[n_rows], sizeof values[n_rows]);
        rows[n_rows] = (tui_row_t){ section, d->label, values[n_rows], setting_kind(d),
                                    d->id == SET_COLOUR ? g_app.color : NULL };
        section = NULL;
        n_rows++;
    }
    if (g_app.settings_sel == SETTINGS_DONE) sel_row = n_rows;   // the Done button
    const setting_def_t *d = g_app.settings_sel < N_SETTINGS ? &SETTINGS[g_app.settings_sel] : NULL;
    char help[600], usage[96] = "";
    if (!d) {
        if (g_app.onboarding)
            snprintf(help, sizeof help, "Go on to your sessions: Ctrl+N creates one, Ctrl+J joins one. Everything here "
                     "applies at once%s", g_app.installed
                     ? ", and what you change is saved where :install put it."
                     : g_app.locked ? " and lasts until chat exits: what :install saved stays sealed this run."
                     : " and lasts until chat exits. It's only written to disk if you :install.");
        else
            snprintf(help, sizeof help, "Back to your sessions. Everything here already applies%s",
                     g_app.installed ? ", and is saved." : ".");
        copy_str(usage, "ctrl+s or :set brings this page back", sizeof usage);
    } else {
        // The row cuts off a recipient on a narrow screen, and not every terminal supports OSC 52.
        char recipient[AGE_RECIPIENT_STRLEN + 3] = "";
        if (d->id == SET_AGE_RECIPIENT && g_app.identity_source == IDENT_AGE) {
            age_export_recipient(&g_app.identity, recipient);
            strcat(recipient, ": ");
        }
        snprintf(help, sizeof help, "%s%s", recipient, d->help);
        if (d->values) snprintf(usage, sizeof usage, ":set %s %s", d->key, d->values);
        else if (d->kind == K_SECRET) snprintf(usage, sizeof usage, ":set %s", d->key);
    }
    tui_page_t page = {
        .title = "Settings",
        .clock = clock,
        .intro = g_app.onboarding
            ? "chat is an end-to-end encrypted chat with no server. Check how it reaches peers, then press "
              "Start chatting. Nothing goes on the network before that."
            : NULL,
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
        rows[i] = (tui_row_t){ SIGN_PICKS[i].section, SIGN_PICKS[i].label, NULL, TUI_V_TEXT, NULL };
        if (i == in_use) { rows[i].value = "in use"; rows[i].kind = TUI_V_ON; }
    }
    char help[600], usage[32] = "";
    char now[160]; setting_value(SET_SIGN, now, sizeof now);
    snprintf(help, sizeof help, "%s Now: %s.", SIGN_PICKS[g_app.sign_sel].help, now);
    static const char *const SET[N_PICKS] = { "off", "age", NULL, NULL, "pgp", NULL, NULL };
    if (SET[g_app.sign_sel]) snprintf(usage, sizeof usage, ":set sign %s", SET[g_app.sign_sel]);
    const char *nav[8];
    tui_page_t page = {
        .title = "Settings" CRUMB "Signing identity",
        .clock = clock,
        .nav = nav, .n_nav = settings_sections(nav, 8), .nav_sel = settings_section_index(SET_SIGN),
        .rows = rows, .n_rows = N_PICKS, .selected = g_app.sign_sel,
        .help = help, .usage = usage[0] ? usage : NULL,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

// A folder's row is drawn like a row that opens a page.
static void render_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    static tui_row_t rows[MAX_DIR_ITEMS];
    const browser_t *b = &g_app.browser;
    for (int i = 0; i < b->n_items; i++)
        rows[i] = (tui_row_t){ NULL, b->items[i].name, b->items[i].is_dir ? "" : NULL, TUI_V_LINK, NULL };
    char title[1000];
    snprintf(title, sizeof title, "Settings" CRUMB "Signing identity" CRUMB "%s", b->path);
    const char *nav[8];
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .nav = nav, .n_nav = settings_sections(nav, 8), .nav_sel = settings_section_index(SET_SIGN),
        .rows = rows, .n_rows = b->n_items, .selected = b->selected,
        .help = SIGN_PICKS[g_app.load_kind == IDENT_AGE ? PICK_AGE_FILE : PICK_PGP_FILE].help,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

static void render_send_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    static tui_row_t rows[MAX_DIR_ITEMS];
    const browser_t *b = &g_app.browser;
    for (int i = 0; i < b->n_items; i++)
        rows[i] = (tui_row_t){ NULL, b->items[i].name, b->items[i].is_dir ? "" : NULL, TUI_V_LINK, NULL };
    char title[1000];
    snprintf(title, sizeof title, "Send a file" CRUMB "%s", b->path);
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .rows = rows, .n_rows = b->n_items, .selected = b->selected,
        .help = "offered to everyone here; nobody gets it unless they fetch it",
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

// ---- the help page: every key, then every command ----

static const struct { const char *section, *keys, *what; } HELP_KEYS[] = {
    { "Sessions",    "ctrl+n",          "start a new session" },
    { NULL,          "ctrl+j",          "join a session by its id and password" },
    { NULL,          "tab  shift+tab",  "next / previous session" },
    { NULL,          "ctrl+s",          "settings" },
    { NULL,          "ctrl+c",          "quit - every session leaves cleanly first" },
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
    { NULL,          ":  /",            "the command line" },
    { NULL,          "?",               "this page" },
    { "Pages",       "j  k  g  G",      "move, to the first / last" },
    { NULL,          "h  l  enter",     "change a value, go in, choose" },
    { NULL,          "tab  shift+tab",  "next / previous section" },
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

// Tab and Shift+Tab: the first row of the next section, or of this one (then the previous one).
static int page_section_step(const tui_row_t *rows, int n, int sel, int dir) {
    if (dir > 0) {
        for (int i = sel + 1; i < n; i++) if (rows[i].section) return i;
        return sel;
    }
    int start = sel;
    while (start > 0 && !rows[start].section) start--;
    if (start < sel) return start;
    for (int i = start - 1; i >= 0; i--) if (rows[i].section) return i;
    return start;
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

typedef struct { char where[920]; } loading_t;

static void load_setting(void *ctx, const char *table, const char *key, const toml_value *tv) {
    loading_t *l = ctx;
    const setting_def_t *d = setting_by_key(key);
    char t[16] = "", value[ROW_TEXT_MAX], before[ROW_TEXT_MAX], now[ROW_TEXT_MAX];
    if (d) row_table(settings_index(d->id), t, sizeof t);
    if (!d || strcmp(t, table) != 0 || !setting_text(d->id, before, sizeof before)) {
        saved_note("* %s: [%.20s] %.40s isn't a setting this chat saves - left out", l->where, table, key);
        return;
    }
    const char *want = row_from_toml(d, tv, value, sizeof value);
    if (want) {
        saved_note("* %s: %s takes %s - left out", l->where, d->key, want);
        return;
    }
    g_app.message[0] = '\0';
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
    install_where(where, sizeof where);
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
// fingerprint covers it), then the key.
#define KEY_BLOB_LEN (8 + ID_SIGN_PUB_LEN + ID_SIGN_PRIV_LEN)
_Static_assert(KEY_BLOB_LEN <= INSTALL_KEY_MAX, "a sealed key has room for the signing key");

static void identity_pack(uint8_t out[KEY_BLOB_LEN]) {
    out[0] = 1;
    out[1] = (uint8_t)g_app.identity_source;
    out[2] = (uint8_t)g_app.key_origin;
    out[3] = (uint8_t)(g_app.identity.scalar != 0);
    for (int i = 0; i < 4; i++) out[4 + i] = (uint8_t)(g_app.pgp_created >> (24 - 8 * i));
    memcpy(out + 8, g_app.identity.pub, ID_SIGN_PUB_LEN);
    memcpy(out + 8 + ID_SIGN_PUB_LEN, g_app.identity.priv, ID_SIGN_PRIV_LEN);
}

// The saved key's public half is kept even when it isn't used, to tell whether the key in use is the same one.
static int identity_unpack(const uint8_t *in, size_t len, int use) {
    if (len != KEY_BLOB_LEN || in[0] != 1 || (in[1] != IDENT_AGE && in[1] != IDENT_PGP) || in[2] > KEY_PASTED || in[3] > 1)
        return -1;
    memcpy(g_app.saved_key_pub, in + 8, ID_SIGN_PUB_LEN);
    g_app.saved_key_known = 1;
    if (!use) return 0;
    g_app.identity_source = (identity_source_t)in[1];
    g_app.key_origin = (key_origin_t)in[2];
    g_app.identity.scalar = in[3];
    g_app.pgp_created = (uint32_t)in[4] << 24 | (uint32_t)in[5] << 16 | (uint32_t)in[6] << 8 | in[7];
    memcpy(g_app.identity.pub, in + 8, ID_SIGN_PUB_LEN);
    memcpy(g_app.identity.priv, in + 8 + ID_SIGN_PUB_LEN, ID_SIGN_PRIV_LEN);
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

static const char *open_error(int rc) {
    switch (rc) {
        case PASS_WRONG:      return "that passphrase doesn't open what :install saved";
        case PASS_NOMEM:      return "opening what :install saved needs 512 MiB of free memory for a moment";
        case INSTALL_NO_FILE: return "what :install saved isn't there any more";
        default:              return "what :install saved is damaged, or isn't something chat wrote";
    }
}

static void reapply_options(void);

// The settings, then the command line options again so they still override them, then the key
// unless --identity chose another. 0, or the reason it stayed sealed.
static int open_saved(const char *passphrase) {
    int rc = install_unlock(passphrase);
    if (rc != 0) return rc;
    g_app.installed = 1;
    g_app.locked = 0;
    load_saved_settings();
    reapply_options();
    note_settings_seen();
    rc = open_saved_key(!g_opts.identity[0]);
    if (rc != 0 && rc != INSTALL_NO_FILE)
        saved_note("* your saved signing key is damaged, or isn't sealed with this passphrase - it's left out");
    return 0;
}

// From CHAT_INSTALL_PASSWORD, otherwise asked for in a box once the screen is up, or in the terminal.
static void unlock_at_start(int in_box) {
    g_app.locked = 1;
    char pw[256] = "";
    int from_env = platform_env_take("CHAT_INSTALL_PASSWORD", pw, sizeof pw) == 0;
    if (from_env) {
        int rc = open_saved(pw);
        crypto_wipe(pw, sizeof pw);
        if (rc == 0) return;
        saved_note("* CHAT_INSTALL_PASSWORD: %s", open_error(rc));
    }
    if (in_box) { g_app.unlock_at_start = 1; return; }
    for (int tries = 0; tries < 3 && term_is_tty(); tries++) {
        if (term_read_password("passphrase for what :install saved (blank: start without it): ", pw, sizeof pw) != 0
            || !pw[0]) break;
        int rc = open_saved(pw);
        crypto_wipe(pw, sizeof pw);
        if (rc == 0) return;
        fprintf(stderr, "chat: %s\n", open_error(rc));
        if (rc != PASS_WRONG) break;
    }
    crypto_wipe(pw, sizeof pw);
    saved_note("* what :install saved stays sealed: this run starts from chat's defaults and saves nothing%s",
               from_env ? "" : " (CHAT_INSTALL_PASSWORD opens it)");
}

static int key_in_use_saved(void) {
    return g_app.identity_source != IDENT_NONE && g_app.saved_key_known
        && crypto_equal(g_app.saved_key_pub, g_app.identity.pub, ID_SIGN_PUB_LEN);
}

// A new passphrase first, since Argon2id is the slow part and can fail if there isn't enough
// memory. Then the settings, which are always there, then a key not saved yet, sealed under the
// same passphrase.
static void finish_install(const char *passphrase) {
    char where[900] = "";
    install_where(where, sizeof where);
    if (passphrase) {
        note("sealing...");
        render();
        if (install_lock_new(passphrase) != 0) { note("not installed: sealing needs 512 MiB of free memory for a moment"); return; }
    }
    // Everything in use, including the options.
    note_settings_seen();
    memcpy(g_saved_rows, g_seen_rows, sizeof g_saved_rows);
    static char text[INSTALL_SETTINGS_MAX];
    if (settings_text(text, sizeof text) != 0 || install_write_settings(text) != 0) {
        if (passphrase) install_forget();
        note("couldn't write your settings to %s%s", where, g_app.installed ? "" : " - not installed");
        return;
    }
    g_app.installed = 1;
    g_app.locked = 0;
    int key = g_app.identity_source != IDENT_NONE && !key_in_use_saved();
    if (key) {
        uint8_t blob[KEY_BLOB_LEN];
        identity_pack(blob);
        int rc = install_write_key(blob, sizeof blob);
        crypto_wipe(blob, sizeof blob);
        if (rc != 0) { note("your settings are saved, but your signing key couldn't be written to %s", where); return; }
        memcpy(g_app.saved_key_pub, g_app.identity.pub, ID_SIGN_PUB_LEN);
        g_app.saved_key_known = 1;
    }
    push_log("* installed: your settings%s are in %s, sealed, for next time. :uninstall deletes them",
             key ? " and signing key" : "", where);
    note("installed in %s", where);
}

// If installed, it saves under the passphrase it has. Otherwise existing files need their own
// passphrase, and if there's nothing there it needs a new one, with or without a key.
static void install_confirmed(void) {
    if (g_app.installed) {
        end_prompt();
        finish_install(NULL);
        return;
    }
    g_app.mode = g_app.locked ? MODE_INSTALL_UNLOCK : MODE_INSTALL_PASS;
    g_app.dirty = 1;
}

static void cancel_install(void) {
    crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
    end_prompt();
    note("not installed - nothing was written");
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
}

// What's in use stays in use. The passphrase only opens what's saved, so it can be overwritten.
static void commit_install_unlock(void) {
    char pw[sizeof g_app.input.buf];
    copy_str(pw, g_app.input.buf, sizeof pw);
    if (!pw[0]) { note("type its passphrase - or Esc to cancel"); return; }
    note("opening what :install saved...");
    render();
    int rc = install_unlock(pw);
    crypto_wipe(pw, sizeof pw);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (rc == PASS_WRONG || rc == PASS_NOMEM) { note("%s", open_error(rc)); return; }
    end_prompt();
    if (rc != 0) {
        if (rc == INSTALL_NO_FILE) g_app.locked = 0;
        note("not installed: %s", open_error(rc));
        return;
    }
    open_saved_key(0);
    finish_install(NULL);
}

static void uninstall_confirmed(void) {
    end_prompt();
    char where[900] = "";
    install_where(where, sizeof where);
    if (install_remove() != 0) { note("couldn't delete everything chat saved in %s", where); return; }
    g_app.installed = g_app.locked = 0;
    g_app.saved_key_known = 0;
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
    if (g_app.installed && install_has_settings()) settings_done();
    else g_app.mode = MODE_SETTINGS;
}

static void commit_unlock(void) {
    char pw[sizeof g_app.input.buf];
    copy_str(pw, g_app.input.buf, sizeof pw);
    if (!pw[0]) { note("type its passphrase - or Esc to start without it"); return; }
    // Argon2id takes a few seconds, so say so before the screen freezes.
    note("opening what :install saved...");
    render();
    int rc = open_saved(pw);
    crypto_wipe(pw, sizeof pw);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (rc == PASS_WRONG || rc == PASS_NOMEM) { note("%s", open_error(rc)); return; }
    // The key before chat starts, so a --session opens signed.
    if (key_in_use_saved()) identity_chosen();
    end_unlock();
    if (rc != 0) note("%s", open_error(rc));
}

static void skip_unlock(void) {
    end_unlock();
    note("what :install saved stays sealed: chat starts from its defaults and saves nothing this run");
}

static void cancel_uninstall(void) {
    end_prompt();
    note("nothing was deleted");
}

// Enter doesn't answer. A question takes y or n.
static void confirm_key(const tui_key_t *key, void (*yes)(void), void (*no)(void)) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') yes();
    else if (ch == 'n' || ch == 'N' || ch == 'q' || key->type == TUI_KEY_ESCAPE) no();
}

static void field_key(const tui_key_t *key, void (*enter)(void), void (*esc)(void)) {
    if (key->type == TUI_KEY_ESCAPE) esc();
    else if (key->type == TUI_KEY_ENTER) enter();
    else if (tui_input_feed(&g_app.input, key)) g_app.dirty = 1;
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
    if (d->id == SET_SIGN) {
        static const struct { const char *name; sign_pick_t pick; } SIGN_VALUES[] = {
            { "off", PICK_OFF }, { "age", PICK_AGE_MADE }, { "pgp", PICK_PGP_MADE },
        };
        int pick = -1;
        for (size_t i = 0; i < sizeof SIGN_VALUES / sizeof SIGN_VALUES[0]; i++)
            if (strcmp(value, SIGN_VALUES[i].name) == 0) pick = SIGN_VALUES[i].pick;
        if (pick == PICK_OFF) { sign_pick(pick); return CMD_OK; }
        settings_open_at(SET_SIGN);
        begin_sign();
        if (pick < 0) { note("sign takes off, age or pgp - a key file or a pasted key is chosen here"); return CMD_OK; }
        // The password is typed on the page, where it's hidden.
        g_app.sign_sel = pick;
        sign_pick(pick);
        return CMD_OK;
    }
    settings_open_at(d->id);
    if (setting_shown(d->id)) note("%s comes from your signing key and can't be set - Enter copies it", d->label);
    return CMD_OK;
}

static cmd_result_t app_install(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    char where[900];
    if (install_where(where, sizeof where) != 0) { note("there's nowhere to install to - no home folder"); return CMD_OK; }
    begin_prompt(MODE_INSTALL);
    return CMD_OK;
}

static cmd_result_t app_uninstall(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    if (!install_has_settings() && !install_has_key()) { note("nothing to uninstall - chat has saved nothing here"); return CMD_OK; }
    begin_prompt(MODE_UNINSTALL);
    return CMD_OK;
}

// Checked before CHAT_COMMANDS, so entries here shadow the per-session ones of the same name.
static const command_t APP_COMMANDS[] = {
    { "help",    NULL,                  NULL,     "every key and command on one page (F1)",          app_help },
    { "new",     NULL,                  NULL,     "create a session (Ctrl+N)",                       app_new },
    { "join",    NULL,                  NULL,     "join a session by id (Ctrl+J)",                   app_join },
    { "quit",    "q exit close bd bw",  NULL,     "leave this session; quits if none is open",       app_quit },
    { "quitall", "qa qall",             NULL,     "leave every session and quit (Ctrl+C)",           app_quitall },
    { "set",     NULL,        "[NAME [VALUE]]",   "change a setting; alone, opens them all (Ctrl+S)", app_set },
    { "copyid",  NULL,                  NULL,     "copy this session's id to the clipboard",         app_copyid },
    { "update",  NULL,                  NULL,     "install the latest release from GitHub",          app_update },
    { "install", NULL,                  NULL,     "save your settings and signing key on this computer", app_install },
    { "uninstall", NULL,                NULL,     "delete what :install saved",                      app_uninstall },
    { "changelog", "news",              NULL,     "what changed in each version",                    app_changelog },
    { "show",    NULL,                  "N [anyway]", "show picture N in the chat, where it was offered", app_show },
    { "hide",    NULL,                  "N",      "tuck picture N away again",                       app_hide },
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
    if (p) { p->shown = 1; g_app.dirty = 1; return CMD_OK; }
    chat_file_fetch(&s->engine, n, 1, anyway);
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
        rows[n] = (tui_row_t){ HELP_KEYS[i].section, HELP_KEYS[i].keys, HELP_KEYS[i].what, TUI_V_TEXT, NULL };
        cmds[n++] = NULL;
    }
    for (const command_t *const *t = ALL_COMMANDS; *t; t++) {
        for (const command_t *cmd = *t; cmd->name && k < MAX_HELP_COMMANDS; cmd++) {
            if (*t != APP_COMMANDS && cmd_find(APP_COMMANDS, cmd->name)) continue;
            snprintf(labels[k], sizeof labels[k], ":%s%s%s", cmd->name, cmd->args ? " " : "", cmd->args ? cmd->args : "");
            rows[n] = (tui_row_t){ k == 0 ? "Commands" : NULL, labels[k], cmd->help, TUI_V_TEXT, NULL };
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

// Whether word is a command whose argument is a peer's nick (its args start with NICK).
static int takes_nick(const char *word) {
    const command_t *c = cmd_find(APP_COMMANDS, word);
    if (!c) c = cmd_find(CHAT_COMMANDS, word);
    return c && c->args && strncmp(c->args, "NICK", 4) == 0;
}

// The nth online peer whose nick starts with typed, ignoring case. An exact match comes first, so
// Enter on "id" doesn't run it as "ida". The rest are sorted by nick.
static const peer_t *nth_peer(const chat_t *e, const char *typed, int nth) {
    const peer_t *m[MAX_PEERS + MAX_PENDING_PEERS];
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
    return nth < n ? m[nth] : NULL;
}

// The menu above the COMMAND line: commands by name. After "set ", the settings with their current
// values. After "set NAME ", the values it takes. After a command that takes a NICK, the online peers.
static int suggest_command(const char *typed, int nth, tui_suggestion_t *out) {
    memset(out, 0, sizeof *out);
    size_t wn = strcspn(typed, " ");
    char word[CMD_WORD_MAX];
    if (typed[wn] == ' ' && wn < sizeof word) {
        memcpy(word, typed, wn);
        word[wn] = '\0';
        chat_t *e = takes_nick(word) ? peer_engine() : NULL;
        if (e) {
            const peer_t *p = nth_peer(e, typed + wn + 1, nth);
            if (!p) return 0;
            snprintf(out->line, sizeof out->line, "%s %s", word, p->nick);
            char name[CHAT_NAME_LEN]; chat_peer_name(e, p, name);
            copy_str(out->name, name, sizeof out->name);
            snprintf(out->help, sizeof out->help, "%s%s",
                     p->identity_source == IDENT_NONE ? "unsigned" : chat_verify_label(p->identity_state),
                     p->build_state == BUILD_MODIFIED ? " \xc2\xb7 modified client" : "");
            copy_str(out->group, "peers", sizeof out->group);
            return 1;
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
    if (chat_run_command(&g_app.selected->engine, line) == CMD_QUIT) close_session(g_app.selected);
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
        if ((n > 0 || input->menu_sel > 0) && tui_input_suggestion(input, &s) && strlen(s.line) > n
            && strncmp(s.line, line, n) == 0)
            copy_str(line, s.line, sizeof line);
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

    // The pages draw their fields in their rows, so a key there redraws the page.
    switch (g_app.mode) {
        case MODE_HELP:            help_key(key); return;
        case MODE_CHANGELOG:       changelog_key(key); return;
        case MODE_SETTINGS:        settings_key(key); return;
        case MODE_SIGN_CHOICE:     sign_picker_key(key); return;
        case MODE_SIGN_BROWSE: browser_key(key); return;
        case MODE_SEND_BROWSE: send_browser_key(key); return;
        case MODE_SIGN_PASTE:  paste_key(key); return;
        case MODE_SIGN_PASSWORD:  field_key(key, commit_sign_password, end_sign_password); return;
        case MODE_SETTINGS_EDIT:  field_key(key, commit_setting_edit, end_setting_edit); return;
        case MODE_NEW_PASSWORD:
        case MODE_JOIN_ID:
        case MODE_JOIN_PASSWORD:  field_key(key, submit_prompt, end_prompt); return;
        case MODE_INSTALL:        confirm_key(key, install_confirmed, cancel_install); return;
        case MODE_INSTALL_PASS:   field_key(key, commit_install_pass, cancel_install); return;
        case MODE_INSTALL_PASS2:  field_key(key, commit_install_pass2, cancel_install); return;
        case MODE_INSTALL_UNLOCK: field_key(key, commit_install_unlock, cancel_install); return;
        case MODE_UNINSTALL:      confirm_key(key, uninstall_confirmed, cancel_uninstall); return;
        case MODE_UNLOCK:         field_key(key, commit_unlock, skip_unlock); return;
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
    // to the newest message, ? opens the help, and c, C and s show or hide the console, the chat and
    // the sidebar.
    if (key->type == TUI_KEY_CHAR && input->mode == TUI_IMODE_NORMAL) {
        switch (key->ch[0]) {
            case 'j': select_step(1); break;
            case 'k': select_step(-1); break;
            case 'G': scroll_chat(0); break;
            case '?': begin_help(); break;
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
        case TUI_KEY_PAGE_UP:
        case TUI_KEY_CTRL_U:         scroll_chat(1); break;
        case TUI_KEY_PAGE_DOWN:
        case TUI_KEY_CTRL_D:         scroll_chat(-1); break;
        case TUI_KEY_ENTER:          submit_chat_line(); break;
        default: break;
    }
}

static int on_chat_screen(void) {
    switch (g_app.mode) {
        case MODE_CHAT: case MODE_NEW_PASSWORD: case MODE_JOIN_ID: case MODE_JOIN_PASSWORD:
        case MODE_INSTALL: case MODE_INSTALL_PASS: case MODE_INSTALL_PASS2: case MODE_INSTALL_UNLOCK:
        case MODE_UNINSTALL: case MODE_UNLOCK: case MODE_UPDATE:
            return 1;
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
        if (!p->used || !p->ok || chat_code_state(e, p) != 1) continue;
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
        b->hint = "i type \xc2\xb7 : command \xc2\xb7 j/k session \xc2\xb7 pgup/pgdn scroll \xc2\xb7 ? help";
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
    snprintf(hint, sizeof hint, "enter send \xc2\xb7 / commands%s \xc2\xb7 esc normal \xc2\xb7 f1 help",
             session_count() > 1 ? " \xc2\xb7 tab next session" : "");
    b->hint = hint;
}

// ---- the dialogs ----

#define MAX_DIALOG_PARAS 8

static int add_para(tui_para_t *p, int n, tui_para_kind_t kind, const char *text) {
    p[n] = (tui_para_t){ .kind = kind, .text = text };
    return n + 1;
}

static int install_paras(tui_para_t *p) {
    static char settings[1200], key[1400];
    char where[900] = "";
    install_where(where, sizeof where);
    snprintf(settings, sizeof settings, "`%s/settings`: the settings you've changed - your nickname, colour, routing, "
             "relays and the like. Never the Tor control password.", where);
    int saved = install_has_key();
    if (g_app.identity_source == IDENT_NONE && saved)
        snprintf(key, sizeof key, "`%s/key`: the signing key saved there stays as it is, though signing is off now.", where);
    else if (g_app.identity_source == IDENT_NONE)
        copy_str(key, "No signing key: signing is off. One you choose later (`:set sign`) is kept by `:install` again, "
                 "under the same passphrase.", sizeof key);
    else if (key_in_use_saved())
        snprintf(key, sizeof key, "`%s/key`: your signing key, saved already. It stays as it is.", where);
    else
        snprintf(key, sizeof key, "`%s/key`: your signing key.%s", where, saved ? " It replaces the key saved there now." : "");
    int n = add_para(p, 0, TUI_P_TEXT, g_app.installed || g_app.locked
        ? "chat is installed here: this saves what's in use now in place of what's saved. **The files are a trail**: "
          "they tell anyone who can read this disk (an admin, malware, a backup, forensics) that chat is used here."
        : "Until you install, chat keeps nothing on disk. **Installing leaves a trail**: files that tell anyone who "
          "can read this disk (an admin, malware, a backup, forensics) that chat is used here.");
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_BULLET, settings);
    n = add_para(p, n, TUI_P_BULLET, key);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, g_app.installed
        ? "It's all sealed (Argon2id, XChaCha20-Poly1305) with the passphrase it's sealed with now: there's "
          "nothing to type."
        : g_app.locked
        ? "It's all sealed (Argon2id, XChaCha20-Poly1305) with the passphrase of what's saved there now, asked for next."
        : "It's all sealed (Argon2id, XChaCha20-Poly1305) with one passphrase you choose next, which chat asks for "
          "when it starts.");
    n = add_para(p, n, TUI_P_BLANK, "");
    return add_para(p, n, TUI_P_TEXT,
        "Settings you change from then on are saved as you change them. Never saved: sessions, their passwords, "
        "messages, peers or files. `:uninstall` deletes it all - but a disk and its backups can keep traces of "
        "deleted files.");
}

static int uninstall_paras(tui_para_t *p) {
    static char what[1200];
    char where[900] = "";
    install_where(where, sizeof where);
    int settings = install_has_settings(), key = install_has_key();
    snprintf(what, sizeof what, "This deletes what `:install` saved in `%s`: your %s. What's in use now lasts until "
             "chat exits.", where, settings && key ? "sealed settings and signing key" : settings ? "sealed settings" : "sealed signing key");
    int n = add_para(p, 0, TUI_P_TEXT, what);
    if (key) {
        n = add_para(p, n, TUI_P_BLANK, "");
        n = add_para(p, n, TUI_P_TEXT, "**A key saved only there is gone for good**, and with it the fingerprint peers "
                                       "know you by.");
    }
    n = add_para(p, n, TUI_P_BLANK, "");
    return add_para(p, n, TUI_P_TEXT, "Deleting isn't erasing: the disk, its snapshots and its backups can keep "
                                      "traces of the files.");
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
        case MODE_SIGN_PASTE:
            d.title = g_app.load_kind == IDENT_AGE ? "PASTE AN AGE KEY" : "PASTE A PGP KEY";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, g_app.load_kind == IDENT_AGE ? AGE_PASTE_HELP : PGP_PASTE_HELP);
            d.input = NULL;
            d.status = g_app.paste_status;
            d.keys = "esc back";
            break;
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
            d.title = "INSTALL";
            d.n_text = install_paras(paras);
            d.input = NULL;
            d.keys = "y install \xc2\xb7 n cancel";
            break;
        case MODE_INSTALL_PASS:
        case MODE_INSTALL_PASS2: {
            int first = g_app.mode == MODE_INSTALL_PASS;
            d.title = "INSTALL \xc2\xb7 PASSPHRASE";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, !first ? "Type it again, to be sure of it."
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
        case MODE_INSTALL_UNLOCK:
            d.title = "INSTALL \xc2\xb7 PASSPHRASE";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, "What `:install` saved here is still sealed. Its passphrase opens "
                                "it, and what's in use now is saved over it under the same one. Forgot it? Esc, then "
                                "`:uninstall` deletes it, and `:install` starts afresh.");
            d.placeholder = "passphrase";
            d.keys = "enter install \xc2\xb7 esc cancel";
            break;
        case MODE_UNINSTALL:
            d.title = "UNINSTALL";
            d.n_text = uninstall_paras(paras);
            d.input = NULL;
            d.keys = "y delete \xc2\xb7 n cancel";
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
        case MODE_UNLOCK:
            d.title = "UNLOCK";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, install_has_key()
                ? "`:install` saved your settings and signing key here, sealed. Their passphrase opens them; Esc "
                  "starts without them, from chat's defaults, and saves nothing this run."
                : "`:install` saved your settings here, sealed. Their passphrase opens them; Esc starts without them, "
                  "from chat's defaults, and saves nothing this run.");
            d.placeholder = "passphrase";
            d.keys = "enter open \xc2\xb7 esc skip";
            break;
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
            b.hint = "enter open \xc2\xb7 h up a folder \xc2\xb7 j/k move \xc2\xb7 esc back \xc2\xb7 q close";
            break;
        case MODE_SEND_BROWSE:
            b.chip = "SEND";
            b.hint = "enter send \xc2\xb7 h up a folder \xc2\xb7 j/k move \xc2\xb7 esc close";
            break;
        case MODE_CHAT:
            chat_input(&b, &g_app.input);
            break;
        case MODE_UNLOCK:
        case MODE_NEW_PASSWORD:
        case MODE_JOIN_ID:
        case MODE_JOIN_PASSWORD:
        case MODE_INSTALL:
        case MODE_INSTALL_PASS:
        case MODE_INSTALL_PASS2:
        case MODE_INSTALL_UNLOCK:
        case MODE_UNINSTALL:
        case MODE_UPDATE:
            chat_input(&b, &g_app.saved_input);
            b.chip = g_app.mode == MODE_NEW_PASSWORD ? "NEW"
                   : g_app.mode == MODE_JOIN_ID || g_app.mode == MODE_JOIN_PASSWORD ? "JOIN"
                   : g_app.mode == MODE_UNLOCK ? "UNLOCK"
                   : g_app.mode == MODE_UNINSTALL ? "UNINSTALL"
                   : g_app.mode == MODE_UPDATE ? "UPDATE" : "INSTALL";
            b.tone = TUI_TONE_PROMPT;
            break;
        default:
            break;
    }
    b.dialog = current_dialog();
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

    switch (g_app.mode) {
        case MODE_HELP:            render_help(rows_n, cols_n, hhmm, &bar); return;
        case MODE_CHANGELOG:       render_changelog(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SETTINGS:
        case MODE_SETTINGS_EDIT:   render_settings(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SIGN_CHOICE:
        case MODE_SIGN_PASTE:
        case MODE_SIGN_PASSWORD:   render_sign_picker(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SIGN_BROWSE:     render_browser(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SEND_BROWSE:     render_send_browser(rows_n, cols_n, hhmm, &bar); return;
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
    g_app.settings_sel = 0;
    g_app.mode = MODE_SETTINGS;
    if (g_app.unlock_at_start) {
        begin_prompt(MODE_UNLOCK);
    } else {
        settle_start();
        if (g_app.installed && install_has_settings()) settings_done();
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

        // The terminal may have redrawn or reflowed the screen, so the next frame is sent in full.
        if (term_resized()) { g_app.dirty = 1; tui_invalidate(); }
        if (now >= next_ui_tick) { next_ui_tick = now + 1.0; g_app.dirty = 1; }
        if (g_app.dirty) { keep_settings_saved(); render(); g_app.dirty = 0; g_app.input_dirty = 0; }
        else if (g_app.input_dirty) { render_bar(); g_app.input_dirty = 0; }
    }

    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) close_session(&g_app.sessions[i]);
    // After the sessions, so their onion services are removed with their control connections first.
    tor_link_stop();
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
    if (!term_ansi_ok()) { printf("* file %d came, but showing a picture needs a terminal with colour - :download %d saves it\n", num, num); return; }
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
    while (alive && !g_interrupted) {
        sock_t socks[CHAT_MAX_SOCKS]; int ns = chat_sockets(&c, socks);
        int ready[CHAT_MAX_SOCKS] = {0};
        net_wait(socks, ready, ns, 200);
        double now = now_seconds();
        for (int i = 0; i < ns; i++) if (ready[i]) chat_on_socket_readable(&c, socks[i], now);
        char line[MAX_TEXT + 1];
        int rc = stdin_reader_poll(reader, line, sizeof line);
        int show_anyway, show_n = rc == 1 && strncmp(line, ":show ", 6) == 0 ? file_arg(line + 6, &show_anyway) : 0;
        if (rc == 1 && (strcmp(line, ":changelog") == 0 || strcmp(line, ":news") == 0)) { fputs(CHANGELOG_TEXT, stdout); fflush(stdout); }
        else if (show_n) chat_file_fetch(&c, show_n, 1, show_anyway);
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
    routing_defaults(&g_app.route);
    g_app.nostr_flag = -1;
    g_app.notify_mode = NOTIFY_MENTIONS;
    g_app.verify_optional = 1;
    g_app.show_sidebar = g_app.show_console = g_app.show_chat = 1;
    note_setting_defaults();
    g_argc = argc;
    g_argv = argv;
    int exit_code = read_options(argc, argv, &g_opts);
    if (exit_code >= 0) return exit_code;
    const options_t *o = &g_opts;

    platform_harden_process();
    update_cleanup_stale();

    crypto_setup();
    update_self_build(&g_self_build);
    // The signing key, a pasted key block and typed passwords pass through these for the whole run.
    // Best effort, as in chat_init.
    crypto_lock(&g_app.identity, sizeof g_app.identity);
    crypto_lock(g_app.paste_buf, sizeof g_app.paste_buf);
    crypto_lock(&g_app.input, sizeof g_app.input);
    crypto_lock(&g_app.saved_input, sizeof g_app.saved_input);
    crypto_lock(g_app.pending_auto_password, sizeof g_app.pending_auto_password);
    crypto_lock(g_app.install_pass, sizeof g_app.install_pass);

    int saved = install_has_settings() || install_has_key();
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
