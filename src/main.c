// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "chat.h"
#include "crypto.h"
#include "age.h"
#include "pgp.h"
#include "net.h"
#include "platform.h"
#include "tui.h"
#include "util.h"
#include "update.h"
#include "torproc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <stdarg.h>
#include "os.h"
#include "build_stamp.h"

static const char *USAGE =
    "usage: chat [--nick NAME] [--colour NAME|#HEX] [--identity native|age|pgp:KEYFILE] [--simple]\n"
    "            [--routing direct+nostr|direct|tor] [--nodht] [--noipv6] [--nolan] [--noportmap]\n"
    "            [--nonostr] [--relay wss://HOST ...] [--tor-launch auto|always|never] [--tor-path PATH]\n"
    "            [--tor-socks HOST:PORT] [--tor-control HOST:PORT]\n"
    "            [--session ID --port UDP_PORT --peer HOST:PORT ...]\n"
    "       chat --update | --version\n"
    "\n"
    "With a real terminal, chat opens a full-screen UI: sessions you've joined or created\n"
    "sit in a list on the left (switch with Tab/Shift+Tab), the selected one's messages and\n"
    "timestamps fill the rest of the screen, who's online sits below the session list, and\n"
    "you type at the bottom. Your nickname and, optionally, an identity key are set up in\n"
    "this same screen the first time you run it.\n"
    "\n"
    "  Ctrl+N   create a new session (asks for a password; blank is fine, still encrypts)\n"
    "  Ctrl+J   join an existing session (asks for its id, then its password)\n"
    "  Ctrl+W   leave the session you're currently looking at\n"
    "  Tab      next session       Shift+Tab   previous session\n"
    "  Ctrl+B   hide/show the session sidebar   Ctrl+O   hide/show the console\n"
    "  Ctrl+T   hide/show the chat (hide two of the three and the last one fills the screen)\n"
    "  Ctrl+S   settings: routing, identity, notifications, layout (also /settings)\n"
    "  Ctrl+C   quit chat (every open session leaves cleanly first)\n"
    "\n"
    "Each session has two sections: the conversation, and a console above it for everything\n"
    "that isn't chat - people joining and leaving, the internet lookup, command output. A\n"
    "session you joined is locked (the prompt says \"connecting\") until someone answers.\n"
    "\n"
    "The input line is a small vim. It starts in INSERT: type and press Enter to send.\n"
    "  Esc      INSERT -> NORMAL: h/l move, 0/$ ends, x delete, i/a/I/A back to INSERT\n"
    "  :        NORMAL -> COMMAND: type a command, Tab completes, Enter runs, Esc cancels\n"
    "The password and session-id prompts are plain fields: Enter confirms, Esc cancels,\n"
    "and whatever you were typing before comes back afterwards.\n"
    "\n"
    "Commands are the same whether typed as /name in INSERT or :name in COMMAND:\n"
    "  /new /join /quit (/q) /quitall (/qa) /nick [NAME] /sign /copyid /update\n"
    "  /peers /verify NICK /colour [NAME|#HEX] /notify [all|mentions|none] /net /settings\n"
    "  /netverbose [on|off] /help   - /help lists them all with a line each\n"
    "\n"
    "  --nick      display name; a random one (\"swift-otter42\"-style) is assigned if\n"
    "              omitted - /nick renames it anytime, shared by every session\n"
    "  --colour    your display colour in every session; random by default (--color too)\n"
    "  --routing   how sessions reach peers, instead of asking at startup:\n"
    "              direct+nostr: UDP between peers, found through the BitTorrent DHT (IPv4\n"
    "              and IPv6), the LAN and a router port mapping, with Nostr relays carrying\n"
    "              encrypted traffic when UDP can't get through. direct: the same without\n"
    "              relays. tor: Tor onion services, plus the relays through Tor. Tor and\n"
    "              direct members only reach each other on the relays: both need them\n"
    "  --nodht     skip the BitTorrent DHT (IPv4 and IPv6)\n"
    "  --noipv6    skip the IPv6 DHT only\n"
    "  --nolan     skip LAN broadcast discovery\n"
    "  --noportmap don't ask the router to forward a port (UPnP-IGD, NAT-PMP, PCP)\n"
    "  --nonostr   no Nostr relays. Tor and direct members only reach each other\n"
    "              through them, so with this off they can't\n"
    "  --relay     a Nostr relay (wss://...) to use instead of the defaults; repeatable\n"
    "  --tor-launch\n"
    "              which tor Tor mode uses. auto (default): a tor that's already running if\n"
    "              its control port lets chat log in (it keeps its entry guards and bridges),\n"
    "              else chat starts its own. always: chat's own. never: only a running one.\n"
    "              chat's own tor has random 127.0.0.1 ports, a cookie login, and its data in\n"
    "              a private temporary folder deleted on exit; it quits if chat does\n"
    "  --tor-path  the tor program to start (default: tor on PATH, or the usual folders)\n"
    "  --tor-socks, --tor-control\n"
    "              where to look for a running tor (default 127.0.0.1:9050 and :9051; Tor\n"
    "              Browser's 9150 and 9151 are tried too)\n"
    "  --identity  native: a fresh Ed25519 identity, used to sign every session you join.\n"
    "              age: same, plus an AGE recipient string (age1...) others can `age -r`\n"
    "              encrypt files to. pgp:KEYFILE: import an UNENCRYPTED armored EdDSA\n"
    "              secret key from real gpg and sign with it instead. There's no prompt\n"
    "              for this at startup anymore - chat opens unsigned by default, and\n"
    "              /sign sets one up whenever you actually want it,\n"
    "              live, without restarting: browse for a key file, paste one directly\n"
    "              (never written to disk), or turn signing off again.\n"
    "  --simple    skip the full-screen UI even on a real terminal: plain \"[HH:MM] ...\"\n"
    "              lines, one session, reads lines from stdin. For scripting/low-feature\n"
    "              terminals; this is also the automatic fallback when stdout isn't a tty.\n"
    "  --session   also join this session immediately at startup (needs --port; \"chat\n"
    "              --session ID\" alone still opens straight into the TUI to join by hand)\n"
    "  --update    install the latest release from GitHub and exit, without opening chat\n"
    "  --version   print the version and exit\n"
    "\n"
    "encrypted with X25519 + ML-KEM-768 (hybrid, post-quantum) + XChaCha20-Poly1305 + a\n"
    "per-message forward-secrecy ratchet. Nothing is ever written to disk unless you ask\n"
    "for it (there is no --log flag here - persistence wasn't worth the ephemerality trade\n"
    "for a multi-session UI; ask if you want it back for a specific session).\n";

#define MAX_SESSIONS 12

typedef struct {
    chat_t engine;
    tui_scrollback_t sb;
    tui_scrollback_t console;
    int unread;
    int initialising;
    char name[MAX_SESSION_NAME + 1];
} session_slot_t;

typedef enum {
    MODE_ROUTE_CHOICE,
    MODE_SETTINGS,
    MODE_SETTINGS_EDIT,
    MODE_SIGN_CHOICE,
    MODE_SIGN_PGP_CHOICE,
    MODE_SIGN_PGP_BROWSE,
    MODE_SIGN_PGP_PASTE,
    MODE_CHAT,
    MODE_NEW_PASSWORD,
    MODE_JOIN_ID,
    MODE_JOIN_PASSWORD
} app_mode_t;

#define MAX_DIR_ITEMS 512

typedef struct {
    char path[900];
    tui_list_item_t items[MAX_DIR_ITEMS];
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
    int net_verbose;
    uint16_t default_port;
    int settings_sel;
    char settings_note[200];
    int tor_launch;
    char tor_path[512];
    uint8_t color[3];
    identity_source_t identity_source;
    identity_keypair_t identity;
    app_mode_t mode;
    char pending_session_id[MAX_SESSION_NAME + 1];
    int show_sidebar, show_console, show_chat;
    int dirty;
    int input_dirty;

    tui_scrollback_t log;
    tui_input_t input;
    tui_input_t saved_input;
    browser_t browser;
    char paste_buf[16384];
    size_t paste_len;
    char paste_status[80];

    char pending_auto_session[MAX_SESSION_NAME + 1];
    char pending_auto_password[256];
    uint16_t pending_auto_port;
    addr_t pending_auto_peers[16];
    int pending_auto_n_peers;
} app_t;

static app_t g_app;
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

// Ctrl+C, a kill or a closed terminal all end the main loop, so sessions say bye, keys are
// wiped, the terminal is restored and chat's own tor is stopped, instead of the process just
// dying. The handler has to stay in place for a second signal too: with plain signal() and
// _POSIX_C_SOURCE, glibc resets it after the first, and a second Ctrl+C or kill skipped all that.
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

// App-level notes go wherever the user is looking: the selected session's console, else the startup log.
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
                          unsigned flags, int color_len) {
    session_slot_t *s = (session_slot_t *)ui;
    if (flags & LINE_CHAT) {
        tui_scrollback_push(&s->sb, hhmm, text, rgb, (flags & LINE_MENTION) != 0, color_len);
        if (s != g_app.selected) s->unread = 1;
    } else {
        tui_scrollback_push(&s->console, hhmm, text, rgb, 0, 0);
    }
    g_app.dirty = 1;
}

static int session_ready(const session_slot_t *s) { return !s->initialising && chat_ready(&s->engine); }

static void send_notification(const char *session, const char *nick, const char *text, int mentioned) {
    char title[MAX_NICK + MAX_SESSION_NAME + 32];
    if (session) snprintf(title, sizeof title, mentioned ? "%s mentioned you in %s" : "%s in %s", nick, session);
    else snprintf(title, sizeof title, mentioned ? "%s mentioned you" : "%s", nick);
    platform_notify(title, text);
}

static void session_notify(void *ui, const char *nick, const char *text, int mentioned) {
    session_slot_t *s = (session_slot_t *)ui;
    send_notification(s->engine.session_name, nick, text, mentioned);
}

static int slot_index(session_slot_t *s) { return (int)(s - g_app.sessions); }

static session_slot_t *find_free_slot(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) if (!g_app.used[i]) return &g_app.sessions[i];
    return NULL;
}

static void close_session(session_slot_t *s) {
    if (!s) return;
    int idx = slot_index(s);
    chat_shutdown(&s->engine);
    tui_scrollback_clear(&s->sb);
    tui_scrollback_clear(&s->console);
    g_app.used[idx] = 0;
    if (g_app.selected == s) {
        g_app.selected = NULL;
        for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) { g_app.selected = &g_app.sessions[i]; break; }
    }
    g_app.dirty = 1;
}

static void select_step(int dir) {
    session_slot_t *vis[MAX_SESSIONS]; int n = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) vis[n++] = &g_app.sessions[i];
    if (n == 0) { g_app.selected = NULL; return; }
    int cur = 0;
    for (int i = 0; i < n; i++) if (vis[i] == g_app.selected) { cur = i; break; }
    g_app.selected = vis[(cur + dir + n) % n];
    g_app.selected->unread = 0;
    g_app.dirty = 1;
}

static void render(void);

static void console_note(session_slot_t *s, const char *fmt, ...) {
    char msg[300];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    char hhmm[6]; current_hhmm(hhmm);
    tui_scrollback_push(&s->console, hhmm, msg, NULL, 0, 0);
    g_app.dirty = 1;
}

static void copy_session_id(session_slot_t *s) {
    if (!s) { push_log("* no session selected - nothing to copy"); return; }
    const char *sid = s->engine.session_name;
    char b64[(MAX_SESSION_NAME + 2) / 3 * 4 + 1];
    base64_encode((const uint8_t *)sid, strlen(sid), b64);
    char osc[sizeof b64 + 16];
    snprintf(osc, sizeof osc, "\x1b]52;c;%s\x07", b64);
    platform_write_stdout(osc, strlen(osc));
    console_note(s, "* session id copied to clipboard (OSC 52): %s", sid);
}

// ---- which tor Tor mode uses ----
//
// A tor that's already running is the better one to use when chat can: it keeps its entry guards
// from run to run, and any bridges its torrc sets up. Chat can use it only if its control port
// answers and lets chat log in, since publishing onion services needs that. Otherwise chat starts
// a tor of its own (torproc.c).

typedef enum { TOR_LAUNCH_AUTO = 0, TOR_LAUNCH_ALWAYS = 1, TOR_LAUNCH_NEVER = 2 } tor_launch_t;
static const char *const TOR_LAUNCH_NAMES[] = { "when none is running", "always", "never" };

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

// Downloads (/update) go through Tor whenever Tor mode is on: to the tor in use once there is
// one, and to a port nothing listens on until then, so they fail instead of going direct.
static void sync_update_proxy(void) {
    if (g_app.route.mode != ROUTE_TOR) update_set_proxy(NULL);
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
                     "Windows: the Tor Expert Bundle), set where it is in /settings, or start Tor Browser");
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
    push_log("* tor: starting chat's own tor (%s) - its data lives in a private temporary folder, deleted when chat exits",
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
                              "own (/settings: Start chat's own tor)", g_app.route.tor.control);
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
                // Most likely a port another program took first: new ones, a couple of times.
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
                if (b == 100) { g_tor.starts = 0; push_log("* tor: connected to the Tor network"); }
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

static session_slot_t *start_session(const char *session_name, const char *password, int created,
                                      uint16_t port, const addr_t *peers, int n_peers) {
    session_slot_t *s = find_free_slot();
    if (!s) { push_log("* too many sessions open already"); return NULL; }
    int idx = slot_index(s);
    memset(s, 0, sizeof *s);
    copy_str(s->name, session_name, sizeof s->name);

    char pw[256];
    copy_str(pw, password, sizeof pw);

    s->initialising = 1;
    g_app.used[idx] = 1;
    g_app.selected = s;
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
        // The tor found or started for Tor mode; until there is one, the session waits for it.
        tor_link_ensure(now_seconds());
        copy_str(o.route.tor.socks, g_tor.state == TL_READY ? g_tor.socks : "", sizeof o.route.tor.socks);
        copy_str(o.route.tor.control, g_tor.state == TL_READY ? g_tor.control : "", sizeof o.route.tor.control);
    }
    o.created = created;
    o.notify_mode = g_app.notify_mode;
    o.has_color = 1;
    memcpy(o.color, g_app.color, 3);
    o.identity_source = g_app.identity_source;
    if (g_app.identity_source != IDENT_NONE) o.identity = g_app.identity;

    chat_init(&s->engine, &o, session_print, session_notify, s);
    crypto_wipe(&o, sizeof o);
    if (!chat_started(&s->engine)) {
        chat_shutdown(&s->engine);
        tui_scrollback_clear(&s->console);
        g_app.used[idx] = 0;
        g_app.selected = NULL;
        for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) { g_app.selected = &g_app.sessions[i]; break; }
        push_log(g_app.route.mode == ROUTE_TOR ? "* could not set up Tor for that session"
                                               : "* could not open a network socket for that session");
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

static void show_identity_result(void) {
    if (g_app.identity_source == IDENT_NONE) return;
    uint8_t fp[ID_FP_LEN]; identity_fingerprint(g_app.identity.pub, fp);
    char fphex[ID_FP_LEN * 2 + 1]; hex_encode(fp, ID_FP_LEN, fphex);
    push_log("your identity fingerprint: %s - read it out to peers to verify you independently", fphex);
    if (g_app.identity_source == IDENT_AGE) {
        char recipient[AGE_RECIPIENT_STRLEN + 1];
        age_export_recipient(&g_app.identity, recipient);
        push_log("AGE recipient (others can `age -r` encrypt files to you): %s", recipient);
    }
}

static void begin_sign(void) {
    g_app.mode = MODE_SIGN_CHOICE;
    g_app.dirty = 1;
    if (g_app.identity_source == IDENT_NONE) {
        push_log("* no signing identity set. add one? [n] no  [a] age  [p] pgp (Esc cancels, keeps it off)");
    } else {
        const char *kind = g_app.identity_source == IDENT_NATIVE ? "native"
                          : g_app.identity_source == IDENT_AGE ? "age" : "pgp";
        uint8_t fp[ID_FP_LEN]; identity_fingerprint(g_app.identity.pub, fp);
        char fphex[ID_FP_LEN * 2 + 1]; hex_encode(fp, ID_FP_LEN, fphex);
        push_log("* current identity: %s, fingerprint %s. replace it? [n] turn off  [a] age  [p] pgp "
                 "(Esc cancels, keeps this one)", kind, fphex);
    }
}

static void identity_chosen(void) {
    int any = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_set_identity(&g_app.sessions[i].engine, g_app.identity_source, &g_app.identity);
        any = 1;
    }
    if (!any) push_log(g_app.identity_source == IDENT_NONE
                        ? "* signing stays off for sessions you open from now on"
                        : "* signing key set - it applies to sessions you open from now on");
    g_app.mode = MODE_CHAT;
    g_app.dirty = 1;
}

static void finish_onboarding(void) {
    g_app.mode = MODE_CHAT;

    push_log("* ready. Ctrl+N (or /new) creates a session, Ctrl+J (or /join) joins one, "
             "/sign adds a signing key so others can verify you, /help lists everything");
    if (g_app.pending_auto_session[0]) {
        start_session(g_app.pending_auto_session, g_app.pending_auto_password, 0,
                      g_app.pending_auto_port, g_app.pending_auto_peers, g_app.pending_auto_n_peers);
        crypto_wipe(g_app.pending_auto_password, sizeof g_app.pending_auto_password);
        g_app.pending_auto_session[0] = '\0';
    }
    g_app.dirty = 1;
}

static int entry_cmp(const void *a, const void *b) {
    const tui_list_item_t *ea = a, *eb = b;
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir;
    return strcasecmp(ea->label, eb->label);
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
    // Names go straight to the terminal; one carrying escape sequences could drive it.
    if (has_control_chars(name)) return;
    if (strcmp(name, "..") == 0 && path_is_root(b->path)) return;
    tui_list_item_t *item = &b->items[b->n_items++];
    copy_str(item->label, name, sizeof item->label);
    item->is_dir = is_dir;
}

static int browser_load(browser_t *b, const char *path) {
    browser_t tmp;
    memset(&tmp, 0, sizeof tmp);
    copy_str(tmp.path, path, sizeof tmp.path);
    if (platform_list_dir(tmp.path, browser_add, &tmp) != 0) return -1;
    qsort(tmp.items, (size_t)tmp.n_items, sizeof(tui_list_item_t), entry_cmp);
    *b = tmp;
    return 0;
}

static void begin_pgp_browse(void) {
    const char *home = platform_home_dir();
    if (!home || browser_load(&g_app.browser, home) != 0) browser_load(&g_app.browser, "/");
    g_app.mode = MODE_SIGN_PGP_BROWSE;
    g_app.dirty = 1;
}

static void begin_pgp_paste(void) {
    g_app.paste_len = 0;
    g_app.paste_buf[0] = '\0';
    copy_str(g_app.paste_status, "pasting (0 bytes so far, Esc to cancel)", sizeof g_app.paste_status);
    g_app.mode = MODE_SIGN_PGP_PASTE;
    push_log("paste your armored PGP private key now - it's picked up automatically once the END line arrives");
}

static void try_load_pgp_from_browser(void) {
    tui_list_item_t *sel = &g_app.browser.items[g_app.browser.selected];
    char full[1200]; path_join(full, sizeof full, g_app.browser.path, sel->label);
    if (pgp_import_secret_key(full, &g_app.identity) == 0) {
        g_app.identity_source = IDENT_PGP;
        show_identity_result();
        identity_chosen();
    } else {
        push_log("* could not load a PGP identity from %s (must be an unencrypted EdDSA/Ed25519 secret key)", sel->label);
    }
    g_app.dirty = 1;
}

// New/join prompts borrow the input line: the draft is stashed and comes back when the prompt ends.
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

static cmd_result_t app_nick(void *ctx, const char *arg) {
    (void)ctx;
    if (!*arg) { push_log("* current nickname: %s. usage: /nick NAME", g_app.nick); return CMD_OK; }
    chat_clean_nick(arg, g_app.nick);
    int any = 0;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_app.used[i]) { chat_set_nick(&g_app.sessions[i].engine, g_app.nick); any = 1; }
    if (!any) push_log("* your nickname is now %s", g_app.nick);
    g_app.dirty = 1;
    return CMD_OK;
}

static cmd_result_t app_sign(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_sign();
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
    if (update_start() == 0) push_log("* update: checking GitHub for a newer release (v" CHAT_VERSION " here)...");
    else push_log("* update: already running");
    return CMD_OK;
}

static cmd_result_t app_help(void *ctx, const char *arg);

// ---- routing, asked once at startup ----

static const char *const ROUTE_CHOICE_LINES[] = {
    "* how should chat reach people? (Ctrl+S or /settings changes this, and more, later)",
    ("*   [1] direct + Nostr fallback (recommended): UDP straight to peers, found through the BitTorrent DHT "
     "(IPv4 and IPv6), your LAN and a router port mapping. Public Nostr relays carry the traffic, encrypted "
     "and padded, when UDP can't get through"),
    "*   [2] direct only: the same without relays. Some peers behind strict NATs won't connect, and neither can "
        "members using Tor",
    ("*   [3] Tor: onion services, and the Nostr relays reached through Tor to meet direct peers. Hides "
     "your IP address from peers and everyone else. Uses tor or Tor Browser if one is running, else starts "
     "its own; connecting takes longer"),
};

static void apply_route_choice(int choice) {
    if (choice == 3) {
        g_app.route.mode = ROUTE_TOR;
    } else {
        g_app.route.mode = ROUTE_DIRECT;
        g_app.route.nostr = choice == 1;
    }
    g_app.route_chosen = 1;
}

static const char *route_label(void) {
    if (g_app.route.mode == ROUTE_TOR) return "Tor onion services only";
    return g_app.route.nostr ? "direct, with Nostr relay fallback" : "direct only";
}

static void finish_onboarding(void);

static void begin_route_choice(void) {
    g_app.mode = MODE_ROUTE_CHOICE;
    g_app.input.hint = "press 1, 2 or 3 (Enter takes 1)";
    for (size_t i = 0; i < sizeof ROUTE_CHOICE_LINES / sizeof ROUTE_CHOICE_LINES[0]; i++) push_log("%s", ROUTE_CHOICE_LINES[i]);
}

static void route_chosen(int choice) {
    g_app.input.hint = NULL;
    apply_route_choice(choice);
    sync_update_proxy();
    push_log("* routing: %s", route_label());
    tor_link_ensure(now_seconds());
    finish_onboarding();
}

// ---- the settings page ----

enum { K_TOGGLE, K_CHOICE, K_TEXT, K_SECRET, K_ACTION };

typedef enum {
    SET_ROUTING, SET_DHT4, SET_DHT6, SET_PORTMAP, SET_LAN, SET_NOSTR, SET_RELAYS,
    SET_TOR_LAUNCH, SET_TOR_PATH, SET_TOR_SOCKS, SET_TOR_CONTROL, SET_TOR_PASSWORD,
    SET_NICK, SET_COLOUR, SET_SIGN,
    SET_NOTIFY, SET_NETVERBOSE, SET_PORT,
    SET_SIDEBAR, SET_CONSOLE, SET_CHAT
} setting_id_t;

typedef struct {
    setting_id_t id;
    const char *section;
    const char *label;
    int kind;
    const char *help;
} setting_def_t;

static const setting_def_t SETTINGS[] = {
    { SET_ROUTING, "routing", "Routing", K_CHOICE,
      "direct: UDP straight between peers, using the options below. tor: Tor onion services only - hides your "
      "IP address from everyone; needs tor or Tor Browser running. Applies to sessions you open from now on." },
    { SET_DHT4, NULL, "BitTorrent DHT (IPv4)", K_TOGGLE,
      "Finds peers on the internet through the public BitTorrent DHT. Its nodes see your IP address next to a "
      "lookup key only room members can compute." },
    { SET_DHT6, NULL, "IPv6 DHT", K_TOGGLE,
      "Also looks peers up on the IPv6 DHT (BEP 32). IPv6 usually has no NAT to punch through, so peers there "
      "connect more reliably." },
    { SET_PORTMAP, NULL, "Router port mapping", K_TOGGLE,
      "Asks your router to forward this session's UDP port (PCP, NAT-PMP or UPnP-IGD), so peers behind NATs that "
      "can't be hole-punched still reach you. Removed when the session ends; the router may log it." },
    { SET_LAN, NULL, "LAN discovery", K_TOGGLE,
      "Broadcasts an encrypted beacon on your local network, so room members there find you without the internet." },
    { SET_NOSTR, NULL, "Nostr relays", K_TOGGLE,
      "Tor and direct members can only reach each other through these relays, so both need this on. Direct: "
      "they carry traffic when UDP can't get through. Tor: they're reached only through Tor and never see your "
      "IP. Each event has a one-off key, a random kind, one size and fresh encryption, under a tag that changes "
      "every 10 minutes." },
    { SET_RELAYS, NULL, "Relay list", K_TEXT,
      "The relays the fallback uses: up to 6 wss:// URLs, separated by spaces or commas." },
    { SET_TOR_LAUNCH, NULL, "Start chat's own tor", K_CHOICE,
      "when none is running: use a tor that's already running if its control port lets chat log in - it keeps "
      "its entry guards and any bridges - else start chat's own. always: chat's own, apart from any other tor, "
      "but with new entry guards each run and nothing from your torrc. never: only a running tor. Chat's own tor "
      "has random 127.0.0.1 ports, a cookie login and a private temporary folder deleted on exit." },
    { SET_TOR_PATH, NULL, "Tor program", K_TEXT,
      "The tor chat starts: a full path, or empty for tor on PATH or in the usual folders. It has to be a "
      "program only root or you can change." },
    { SET_TOR_SOCKS, NULL, "Tor SOCKS port", K_TEXT,
      "Where to look for a running tor's SOCKS port (host:port). With the defaults, Tor Browser's "
      "127.0.0.1:9150 is tried too. Applies to sessions you open from now on." },
    { SET_TOR_CONTROL, NULL, "Tor control port", K_TEXT,
      "Where to look for a running tor's control port (host:port); it needs ControlPort on, and chat has to be "
      "able to read its cookie file (or have its password). Applies to sessions you open from now on." },
    { SET_TOR_PASSWORD, NULL, "Tor control password", K_SECRET,
      "Only for a tor set up with HashedControlPassword. Kept in memory only. Applies to sessions you open from now on." },
    { SET_NICK, "you", "Nickname", K_TEXT, "Your name in every session." },
    { SET_COLOUR, NULL, "Colour", K_TEXT,
      "Your colour in every session. Left/right step through the palette; Enter takes a name or #RRGGBB." },
    { SET_SIGN, NULL, "Signing identity", K_ACTION,
      "A key that signs your handshakes so peers can check it's you. Enter sets one up, replaces it or turns it off." },
    { SET_NOTIFY, "chat", "Notifications", K_CHOICE,
      "Desktop notifications, for open sessions and new ones: every message, mentions of your nick, or none." },
    { SET_NETVERBOSE, NULL, "Network log", K_TOGGLE,
      "Logs every handshake packet, relay and Tor event to the console, in every session." },
    { SET_PORT, NULL, "UDP port", K_TEXT,
      "The UDP port new sessions listen on; 0 picks a free one each time. /port changes an open session's." },
    { SET_SIDEBAR, "layout", "Session sidebar", K_TOGGLE, "The list of sessions and who is online (Ctrl+B)." },
    { SET_CONSOLE, NULL, "Console", K_TOGGLE, "The console above each conversation (Ctrl+O)." },
    { SET_CHAT, NULL, "Chat", K_TOGGLE, "The conversation itself (Ctrl+T)." },
};
#define N_SETTINGS ((int)(sizeof SETTINGS / sizeof SETTINGS[0]))

static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };

static setting_id_t g_edit_id;

static int direct_only_setting(setting_id_t id) {
    return id == SET_DHT4 || id == SET_DHT6 || id == SET_PORTMAP || id == SET_LAN;
}
static int tor_only_setting(setting_id_t id) {
    return id == SET_TOR_LAUNCH || id == SET_TOR_PATH || id == SET_TOR_SOCKS || id == SET_TOR_CONTROL
        || id == SET_TOR_PASSWORD;
}

static void setting_value(setting_id_t id, char *out, size_t cap) {
    const routing_t *r = &g_app.route;
    switch (id) {
        case SET_ROUTING:   snprintf(out, cap, "%s", r->mode == ROUTE_TOR ? "tor" : "direct"); break;
        case SET_DHT4:      snprintf(out, cap, "%s", r->dht4 ? "on" : "off"); break;
        case SET_DHT6:      snprintf(out, cap, "%s", r->dht6 ? "on" : "off"); break;
        case SET_PORTMAP:   snprintf(out, cap, "%s", r->portmap ? "on" : "off"); break;
        case SET_LAN:       snprintf(out, cap, "%s", r->lan ? "on" : "off"); break;
        case SET_NOSTR:     snprintf(out, cap, "%s", r->nostr ? "on" : "off"); break;
        case SET_RELAYS: {
            size_t p = 0;
            out[0] = '\0';
            for (int i = 0; i < r->n_relays && p < cap; i++)
                p += (size_t)snprintf(out + p, cap - p, "%s%s", i ? " " : "", r->relays[i] + 6);
            if (r->n_relays == 0) snprintf(out, cap, "none");
            break;
        }
        case SET_TOR_LAUNCH:   snprintf(out, cap, "%s", TOR_LAUNCH_NAMES[g_app.tor_launch]); break;
        case SET_TOR_PATH: {
            char found[1024];
            if (g_app.tor_path[0]) snprintf(out, cap, "%s", g_app.tor_path);
            else if (platform_find_program("tor", NULL, found, sizeof found) == 0) snprintf(out, cap, "found %s", found);
            else snprintf(out, cap, "not installed");
            break;
        }
        case SET_TOR_SOCKS:    snprintf(out, cap, "%s", r->tor.socks); break;
        case SET_TOR_CONTROL:  snprintf(out, cap, "%s", r->tor.control); break;
        case SET_TOR_PASSWORD: snprintf(out, cap, "%s", r->tor.password[0] ? "set" : "not set (cookie or no login)"); break;
        case SET_NICK:      snprintf(out, cap, "%s", g_app.nick); break;
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
            char fphex[ID_FP_LEN * 2 + 1]; hex_encode(fp, ID_FP_LEN, fphex);
            snprintf(out, cap, "%s, fingerprint %s", g_app.identity_source == IDENT_NATIVE ? "native"
                     : g_app.identity_source == IDENT_AGE ? "age" : "pgp", fphex);
            break;
        }
        case SET_NOTIFY:     snprintf(out, cap, "%s", NOTIFY_NAMES[g_app.notify_mode]); break;
        case SET_NETVERBOSE: snprintf(out, cap, "%s", g_app.net_verbose ? "on" : "off"); break;
        case SET_PORT:
            if (g_app.default_port) snprintf(out, cap, "%u", (unsigned)g_app.default_port);
            else snprintf(out, cap, "0 (a free one)");
            break;
        case SET_SIDEBAR: snprintf(out, cap, "%s", g_app.show_sidebar ? "shown" : "hidden"); break;
        case SET_CONSOLE: snprintf(out, cap, "%s", g_app.show_console ? "shown" : "hidden"); break;
        case SET_CHAT:    snprintf(out, cap, "%s", g_app.show_chat ? "shown" : "hidden"); break;
    }
}

static void settings_note(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_app.settings_note, sizeof g_app.settings_note, fmt, ap);
    va_end(ap);
    g_app.dirty = 1;
}

// Pushes the routing settings to the open sessions. The toggles take effect there at once.
static void routing_changed(setting_id_t id) {
    int later = 0, any = 0;
    sync_update_proxy();
    tor_link_ensure(now_seconds());
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        later |= chat_apply_routing(&g_app.sessions[i].engine, &g_app.route);
        any = 1;
    }
    char v[160]; setting_value(id, v, sizeof v);
    const char *label = "";
    for (int i = 0; i < N_SETTINGS; i++) if (SETTINGS[i].id == id) label = SETTINGS[i].label;
    if (id == SET_ROUTING || tor_only_setting(id) || (later && !direct_only_setting(id)))
        settings_note("%s: %s - for sessions you open from now on%s", label, v, any ? "; open ones keep their routing" : "");
    else if (any && g_app.route.mode == ROUTE_TOR && direct_only_setting(id))
        settings_note("%s: %s - for direct sessions; Tor mode doesn't use it", label, v);
    else
        settings_note("%s: %s%s", label, v, any ? " - applied to open sessions too" : "");
}

static void set_notify_all(void) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_app.used[i] && !g_app.sessions[i].initialising) g_app.sessions[i].engine.notify_mode = g_app.notify_mode;
}

static void set_colour_all(void) {
    char hex[8];
    snprintf(hex, sizeof hex, "#%02x%02x%02x", g_app.color[0], g_app.color[1], g_app.color[2]);
    char cmd[16];
    snprintf(cmd, sizeof cmd, "colour %s", hex);
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_app.used[i] && !g_app.sessions[i].initialising) chat_run_command(&g_app.sessions[i].engine, cmd);
}

static void setting_step(setting_id_t id, int dir) {
    routing_t *r = &g_app.route;
    switch (id) {
        case SET_ROUTING: r->mode = r->mode == ROUTE_TOR ? ROUTE_DIRECT : ROUTE_TOR; routing_changed(id); return;
        case SET_DHT4:    r->dht4 = !r->dht4; routing_changed(id); return;
        case SET_DHT6:    r->dht6 = !r->dht6; routing_changed(id); return;
        case SET_PORTMAP: r->portmap = !r->portmap; routing_changed(id); return;
        case SET_LAN:     r->lan = !r->lan; routing_changed(id); return;
        case SET_NOSTR:   r->nostr = !r->nostr; routing_changed(id); return;
        case SET_TOR_LAUNCH:
            g_app.tor_launch = (g_app.tor_launch + (dir < 0 ? 2 : 1)) % 3;
            settings_note("Start chat's own tor: %s - for the next tor chat looks for; a tor already in use stays",
                          TOR_LAUNCH_NAMES[g_app.tor_launch]);
            return;
        case SET_NOTIFY:
            g_app.notify_mode = (notify_mode_t)(((int)g_app.notify_mode + (dir < 0 ? 2 : 1)) % 3);
            set_notify_all();
            settings_note("Notifications: %s", NOTIFY_NAMES[g_app.notify_mode]);
            return;
        case SET_NETVERBOSE:
            g_app.net_verbose = !g_app.net_verbose;
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (g_app.used[i] && !g_app.sessions[i].initialising) g_app.sessions[i].engine.net_verbose = g_app.net_verbose;
            settings_note("Network log: %s", g_app.net_verbose ? "on" : "off");
            return;
        case SET_COLOUR: {
            int cur = -1;
            for (int i = 0; i < COLOR_PALETTE_N; i++)
                if (COLOR_PALETTE[i].r == g_app.color[0] && COLOR_PALETTE[i].g == g_app.color[1] && COLOR_PALETTE[i].b == g_app.color[2]) cur = i;
            int next = cur < 0 ? 0 : (cur + (dir < 0 ? COLOR_PALETTE_N - 1 : 1)) % COLOR_PALETTE_N;
            g_app.color[0] = COLOR_PALETTE[next].r; g_app.color[1] = COLOR_PALETTE[next].g; g_app.color[2] = COLOR_PALETTE[next].b;
            set_colour_all();
            settings_note("Colour: %s", COLOR_PALETTE[next].name);
            return;
        }
        case SET_SIDEBAR: g_app.show_sidebar = !g_app.show_sidebar; g_app.dirty = 1; return;
        case SET_CONSOLE: g_app.show_console = !g_app.show_console; g_app.dirty = 1; return;
        case SET_CHAT:    g_app.show_chat = !g_app.show_chat; g_app.dirty = 1; return;
        default: return;
    }
}

static void begin_setting_edit(setting_id_t id) {
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_edit_id = id;
    if (id != SET_TOR_PASSWORD) {
        char v[600];
        if (id == SET_RELAYS) {
            size_t p = 0;
            v[0] = '\0';
            for (int i = 0; i < g_app.route.n_relays && p < sizeof v; i++)
                p += (size_t)snprintf(v + p, sizeof v - p, "%s%s", i ? " " : "", g_app.route.relays[i]);
        } else if (id == SET_PORT) {
            snprintf(v, sizeof v, "%u", (unsigned)g_app.default_port);
        } else if (id == SET_TOR_PATH) {
            copy_str(v, g_app.tor_path, sizeof v);
        } else {
            setting_value(id, v, sizeof v);
        }
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

static void commit_setting_edit(void) {
    char text[sizeof g_app.input.buf];
    copy_str(text, g_app.input.buf, sizeof text);
    setting_id_t id = g_edit_id;
    end_setting_edit();
    routing_t *r = &g_app.route;
    switch (id) {
        case SET_RELAYS: {
            char urls[NOSTR_MAX_RELAYS][NOSTR_URL_MAX];
            int n = 0;
            for (char *tok = strtok(text, " ,"); tok; tok = strtok(NULL, " ,")) {
                if (nostr_url_ok(tok) != 0) { settings_note("not a relay chat can use: %.80s (wss://host[:port][/path])", tok); return; }
                if (n >= NOSTR_MAX_RELAYS) { settings_note("at most %d relays", NOSTR_MAX_RELAYS); return; }
                copy_str(urls[n++], tok, NOSTR_URL_MAX);
            }
            memcpy(r->relays, urls, sizeof urls);
            r->n_relays = n;
            routing_changed(id);
            return;
        }
        case SET_TOR_SOCKS:
        case SET_TOR_CONTROL:
            if (!valid_host_port(text)) { settings_note("that isn't host:port"); return; }
            copy_str(id == SET_TOR_SOCKS ? r->tor.socks : r->tor.control, text, TOR_HOST_MAX);
            routing_changed(id);
            return;
        case SET_TOR_PATH: {
            char found[1024];
            if (text[0] && platform_find_program("tor", text, found, sizeof found) != 0) {
                settings_note("can't use %.100s - it has to be a full path to a program only root or you can change", text);
                return;
            }
            copy_str(g_app.tor_path, text[0] ? found : "", sizeof g_app.tor_path);
            settings_note("Tor program: %s", g_app.tor_path[0] ? g_app.tor_path : "search PATH and the usual folders");
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
            settings_note("Nickname: %s", g_app.nick);
            return;
        case SET_COLOUR: {
            uint8_t rgb[3];
            if (parse_color(text, rgb) != 0) { settings_note("unknown colour %.40s - try a name or #RRGGBB", text); return; }
            memcpy(g_app.color, rgb, 3);
            set_colour_all();
            settings_note("Colour: #%02x%02x%02x", rgb[0], rgb[1], rgb[2]);
            return;
        }
        case SET_PORT: {
            char *end;
            long port = strtol(text, &end, 10);
            if (!text[0] || *end || port < 0 || port > 65535) { settings_note("not a port: %.20s (0-65535, 0 picks a free one)", text); return; }
            g_app.default_port = (uint16_t)port;
            settings_note("UDP port for new sessions: %ld%s", port, port ? "" : " (a free one)");
            return;
        }
        default:
            return;
    }
}

static void begin_settings(void) {
    if (g_app.mode != MODE_CHAT) return;
    g_app.mode = MODE_SETTINGS;
    g_app.settings_note[0] = '\0';
    g_app.dirty = 1;
}

static void settings_key(const tui_key_t *key) {
    const setting_def_t *d = &SETTINGS[g_app.settings_sel];
    int ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (key->type == TUI_KEY_UP || ch == 'k') {
        if (g_app.settings_sel > 0) g_app.settings_sel--;
    } else if (key->type == TUI_KEY_DOWN || ch == 'j' || key->type == TUI_KEY_TAB) {
        if (g_app.settings_sel < N_SETTINGS - 1) g_app.settings_sel++;
    } else if (key->type == TUI_KEY_HOME) {
        g_app.settings_sel = 0;
    } else if (key->type == TUI_KEY_END) {
        g_app.settings_sel = N_SETTINGS - 1;
    } else if (key->type == TUI_KEY_LEFT || ch == 'h') {
        if (d->kind == K_TOGGLE || d->kind == K_CHOICE || d->id == SET_COLOUR) setting_step(d->id, -1);
    } else if (key->type == TUI_KEY_RIGHT || ch == 'l') {
        if (d->kind == K_TOGGLE || d->kind == K_CHOICE || d->id == SET_COLOUR) setting_step(d->id, 1);
    } else if (key->type == TUI_KEY_ENTER || ch == ' ') {
        if (d->kind == K_TOGGLE || d->kind == K_CHOICE) setting_step(d->id, 1);
        else if (d->kind == K_TEXT || d->kind == K_SECRET) begin_setting_edit(d->id);
        else if (d->id == SET_SIGN) { g_app.mode = MODE_CHAT; begin_sign(); }
    } else if (key->type == TUI_KEY_ESCAPE || ch == 'q' || key->type == TUI_KEY_SETTINGS) {
        g_app.mode = MODE_CHAT;
    }
    g_app.dirty = 1;
}

static void render_settings(const tui_session_row_t *rows, int n, int sel, int rows_n, int cols_n) {
    tui_setting_row_t items[N_SETTINGS];
    for (int i = 0; i < N_SETTINGS; i++) {
        const setting_def_t *d = &SETTINGS[i];
        tui_setting_row_t *it = &items[i];
        it->section = d->section;
        copy_str(it->label, d->label, sizeof it->label);
        setting_value(d->id, it->value, sizeof it->value);
        it->dim = (g_app.route.mode == ROUTE_TOR && direct_only_setting(d->id))
               || (g_app.route.mode == ROUTE_DIRECT && tor_only_setting(d->id));
    }
    const setting_def_t *d = &SETTINGS[g_app.settings_sel];
    char help[400];
    snprintf(help, sizeof help, "%s%s", d->help,
             items[g_app.settings_sel].dim ? (g_app.route.mode == ROUTE_TOR ? " (Not used in Tor mode.)" : " (Only used in Tor mode.)") : "");
    const char *hint = d->kind == K_TEXT || d->kind == K_SECRET ? "up/down move \xc2\xb7 Enter edit \xc2\xb7 Esc close"
                     : d->kind == K_ACTION ? "up/down move \xc2\xb7 Enter open \xc2\xb7 Esc close"
                     : "up/down move \xc2\xb7 Enter/space/left/right change \xc2\xb7 Esc close";
    int editing = g_app.mode == MODE_SETTINGS_EDIT;
    tui_render_settings(rows_n, cols_n, rows, n, sel, items, N_SETTINGS, g_app.settings_sel, help,
                        g_app.settings_note, hint, g_app.color_enabled,
                        editing ? &g_app.input : NULL, editing ? d->label : NULL, editing && d->kind == K_SECRET,
                        g_app.nick[0] ? g_app.nick : "chat");
}

static cmd_result_t app_settings(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_settings();
    return CMD_OK;
}

// Checked before CHAT_COMMANDS, so entries here shadow the per-session ones of the same name.
static const command_t APP_COMMANDS[] = {
    { "help",    NULL,                  NULL,     "list commands and keys",                          app_help },
    { "new",     NULL,                  NULL,     "create a session (Ctrl+N)",                       app_new },
    { "join",    NULL,                  NULL,     "join a session by id (Ctrl+J)",                   app_join },
    { "quit",    "q exit close bd bw",  NULL,     "leave this session (Ctrl+W); quits if none open", app_quit },
    { "quitall", "qa qall",             NULL,     "leave every session and quit (Ctrl+C)",           app_quitall },
    { "nick",    NULL,                  "[NAME]", "show or change your nickname everywhere",         app_nick },
    { "sign",    NULL,                  NULL,     "set up, replace or turn off your signing key",    app_sign },
    { "settings", "set prefs",          NULL,     "routing, identity, notifications, layout (Ctrl+S)", app_settings },
    { "copyid",  NULL,                  NULL,     "copy this session's id to the clipboard",         app_copyid },
    { "update",  NULL,                  NULL,     "install the latest release from GitHub",          app_update },
    { NULL, NULL, NULL, NULL, NULL }
};

static const command_t *const ALL_COMMANDS[] = { APP_COMMANDS, CHAT_COMMANDS, NULL };

static cmd_result_t app_help(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    push_log("* commands - type /name in INSERT, or Esc then :name. anything else is sent to the room:");
    for (const command_t *const *t = ALL_COMMANDS; *t; t++) {
        for (const command_t *cmd = *t; cmd->name; cmd++) {
            if (*t != APP_COMMANDS && cmd_find(APP_COMMANDS, cmd->name)) continue;
            char line[160]; cmd_format_help(cmd, '/', line, sizeof line);
            push_log("%s", line);
        }
    }
    push_log("* keys: Ctrl+N new  Ctrl+J join  Ctrl+W close  Tab/Shift+Tab switch  "
             "Ctrl+B/Ctrl+O/Ctrl+T sidebar/console/chat  Ctrl+C quit");
    return CMD_OK;
}

static const char *complete_command(const char *typed) { return cmd_complete(ALL_COMMANDS, typed); }

// First online peer whose nick starts with typed, ignoring case.
static int nick_has_prefix(const char *nick, const char *typed) {
    for (; *typed; nick++, typed++)
        if (tolower((unsigned char)*nick) != tolower((unsigned char)*typed)) return 0;
    return 1;
}

static const char *complete_mention(const char *typed) {
    if (g_app.mode != MODE_CHAT || !g_app.selected || g_app.selected->initialising) return NULL;
    chat_t *e = &g_app.selected->engine;
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        peer_t *p = &e->peers[i];
        if (p->used && p->ok && nick_has_prefix(p->nick, typed)) return p->nick;
    }
    return NULL;
}

static int is_command(const char *line) {
    char word[CMD_WORD_MAX]; cmd_parse(line, word);
    return cmd_find(APP_COMMANDS, word) || cmd_find(CHAT_COMMANDS, word);
}

// Runs "name args" typed after '/' or ':'; both prefixes reach the same commands.
static void run_command(const char *line) {
    char word[CMD_WORD_MAX];
    const char *arg = cmd_parse(line, word);
    if (!word[0]) return;
    const command_t *cmd = cmd_find(APP_COMMANDS, word);
    if (cmd) { cmd->run(NULL, arg); return; }
    if (!cmd_find(CHAT_COMMANDS, word)) { push_log("* unknown command %s - try /help", word); return; }
    if (!g_app.selected) {
        push_log("* /%s needs a session - Ctrl+N (or /new) creates one, Ctrl+J (or /join) joins one", word);
        return;
    }
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
        input->mode = TUI_IMODE_NORMAL;
        input->cmd_len = 0; input->cmd[0] = '\0';
        run_command(line);
        return;
    }

    const char *text = input->buf;
    while (*text == ' ') text++;
    if (text[0] == '/' || (text[0] == ':' && is_command(text + 1))) {
        char line[sizeof input->buf];
        copy_str(line, text + 1, sizeof line);
        tui_input_clear(input);
        run_command(line);
        return;
    }
    if (!text[0]) return;
    if (!g_app.selected) {
        push_log("* no session yet - Ctrl+N (or /new) creates one, Ctrl+J (or /join) joins one");
        tui_input_clear(input);
        return;
    }
    if (!session_ready(g_app.selected)) {
        console_note(g_app.selected, g_app.selected->initialising
            ? "* still initialising - hold on a moment"
            : "* not connected yet - chat opens once someone answers (your text is kept; Ctrl+W leaves)");
        return;
    }
    chat_send_text(&g_app.selected->engine, input->buf, now_seconds());
    tui_input_clear(input);
}

static void handle_key(const tui_key_t *key) {
    tui_input_t *input = &g_app.input;

    if (g_app.mode == MODE_ROUTE_CHOICE) {
        int ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
        if (key->type == TUI_KEY_ENTER) route_chosen(1);
        else if (ch >= '1' && ch <= '3') route_chosen(ch - '0');
        return;
    }
    if (g_app.mode == MODE_SETTINGS) { settings_key(key); return; }
    if (g_app.mode == MODE_SETTINGS_EDIT) {
        if (key->type == TUI_KEY_ESCAPE) end_setting_edit();
        else if (key->type == TUI_KEY_ENTER) commit_setting_edit();
        else if (tui_input_feed(input, key)) g_app.input_dirty = 1;
        return;
    }

    if (g_app.mode == MODE_SIGN_PGP_PASTE) {
        if (key->type == TUI_KEY_ESCAPE) {
            crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
            g_app.paste_len = 0;
            g_app.mode = MODE_SIGN_PGP_CHOICE;
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
        snprintf(g_app.paste_status, sizeof g_app.paste_status,
                 "pasting (%zu bytes so far, Esc to cancel)", g_app.paste_len);
        g_app.dirty = 1;
        // A paste arrives one key at a time: look only at the end, where the END line lands.
        static const char end_line[] = "-----END PGP PRIVATE KEY BLOCK-----";
        size_t el = sizeof end_line - 1;
        if (g_app.paste_len >= el && memcmp(g_app.paste_buf + g_app.paste_len - el, end_line, el) == 0) {
            if (pgp_import_secret_key_text(g_app.paste_buf, &g_app.identity) == 0) {
                g_app.identity_source = IDENT_PGP;
                crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
                g_app.paste_len = 0;
                show_identity_result();
                identity_chosen();
            } else {
                push_log("* that didn't parse as an unencrypted EdDSA/Ed25519 secret key - try again, or Esc");
                crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
                g_app.paste_len = 0;
            }
        }
        return;
    }

    if (g_app.mode == MODE_SIGN_PGP_BROWSE) {
        switch (key->type) {
            case TUI_KEY_UP:
                if (g_app.browser.selected > 0) { g_app.browser.selected--; g_app.dirty = 1; }
                return;
            case TUI_KEY_DOWN:
                if (g_app.browser.selected < g_app.browser.n_items - 1) { g_app.browser.selected++; g_app.dirty = 1; }
                return;
            case TUI_KEY_BACKSPACE: {
                char up[900]; copy_str(up, g_app.browser.path, sizeof up);
                path_parent(up);
                browser_load(&g_app.browser, up);
                g_app.dirty = 1;
                return;
            }
            case TUI_KEY_ENTER: {
                if (g_app.browser.n_items == 0) return;
                tui_list_item_t *sel = &g_app.browser.items[g_app.browser.selected];
                if (strcmp(sel->label, "..") == 0) {
                    char up[900]; copy_str(up, g_app.browser.path, sizeof up);
                    path_parent(up);
                    browser_load(&g_app.browser, up);
                } else if (sel->is_dir) {
                    char next[1200]; path_join(next, sizeof next, g_app.browser.path, sel->label);
                    browser_load(&g_app.browser, next);
                } else {
                    try_load_pgp_from_browser();
                }
                g_app.dirty = 1;
                return;
            }
            case TUI_KEY_ESCAPE:
                g_app.mode = MODE_SIGN_PGP_CHOICE;
                g_app.dirty = 1;
                return;
            default:
                return;
        }
    }

    if (g_app.mode == MODE_SIGN_CHOICE) {

        if (key->type == TUI_KEY_ESCAPE) {
            g_app.mode = MODE_CHAT;
            g_app.dirty = 1;
        } else if (key->type == TUI_KEY_CHAR && tolower((unsigned char)key->ch[0]) == 'n') {
            g_app.identity_source = IDENT_NONE;
            identity_chosen();
        } else if (key->type == TUI_KEY_CHAR && tolower((unsigned char)key->ch[0]) == 'a') {
            gen_identity_keypair(&g_app.identity);
            g_app.identity_source = IDENT_AGE;
            show_identity_result();
            identity_chosen();
        } else if (key->type == TUI_KEY_CHAR && tolower((unsigned char)key->ch[0]) == 'p') {
            g_app.mode = MODE_SIGN_PGP_CHOICE;
            push_log("[f] browse for a key file   [p] paste key text   (Esc to go back)");
        }
        return;
    }

    if (g_app.mode == MODE_SIGN_PGP_CHOICE) {
        if (key->type == TUI_KEY_ESCAPE) { begin_sign(); return; }
        if (key->type == TUI_KEY_CHAR && tolower((unsigned char)key->ch[0]) == 'f') { begin_pgp_browse(); return; }
        if (key->type == TUI_KEY_CHAR && tolower((unsigned char)key->ch[0]) == 'p') { begin_pgp_paste(); return; }
        return;
    }

    if (tui_input_feed(input, key)) { g_app.input_dirty = 1; return; }

    if (g_app.mode != MODE_CHAT) {
        if (key->type == TUI_KEY_ESCAPE) end_prompt();
        else if (key->type == TUI_KEY_ENTER) submit_prompt();
        return;
    }

    switch (key->type) {
        case TUI_KEY_TAB:            select_step(1); break;
        case TUI_KEY_BACKTAB:        select_step(-1); break;
        case TUI_KEY_NEW_SESSION:    begin_prompt(MODE_NEW_PASSWORD); break;
        case TUI_KEY_JOIN_SESSION:   begin_prompt(MODE_JOIN_ID); break;
        case TUI_KEY_CLOSE_SESSION:  if (g_app.selected) close_session(g_app.selected); break;
        case TUI_KEY_TOGGLE_SIDEBAR: g_app.show_sidebar = !g_app.show_sidebar; g_app.dirty = 1; break;
        case TUI_KEY_TOGGLE_CONSOLE: g_app.show_console = !g_app.show_console; g_app.dirty = 1; break;
        case TUI_KEY_TOGGLE_CHAT:    g_app.show_chat = !g_app.show_chat; g_app.dirty = 1; break;
        case TUI_KEY_SETTINGS:       begin_settings(); break;
        case TUI_KEY_ENTER:          submit_chat_line(); break;
        default: break;
    }
}

static const char *current_prompt(int *mask) {
    const char *mode_prompt = NULL;
    *mask = 0;
    switch (g_app.mode) {
        case MODE_ROUTE_CHOICE: mode_prompt = "routing [1/2/3]"; break;
        case MODE_SETTINGS_EDIT: {
            for (int i = 0; i < N_SETTINGS; i++)
                if (SETTINGS[i].id == g_edit_id) { mode_prompt = SETTINGS[i].label; *mask = SETTINGS[i].kind == K_SECRET; }
            break;
        }
        case MODE_SIGN_CHOICE: mode_prompt = "[n/a/p]"; break;
        case MODE_SIGN_PGP_CHOICE: mode_prompt = "[f/p]"; break;
        case MODE_NEW_PASSWORD:    mode_prompt = "create password"; *mask = 1; break;
        case MODE_JOIN_ID:         mode_prompt = "session id"; break;
        case MODE_JOIN_PASSWORD:   mode_prompt = "password"; *mask = 1; break;
        default: break;
    }
    if (g_app.mode == MODE_SIGN_PGP_PASTE) mode_prompt = g_app.paste_status;

    if (g_app.mode == MODE_CHAT && g_app.selected && !session_ready(g_app.selected))
        mode_prompt = g_app.selected->initialising ? "initialising" : "connecting";
    return mode_prompt;
}

static tui_view_t current_view(char *title, size_t cap) {
    tui_view_t v = { g_app.show_sidebar, g_app.show_console, g_app.show_chat, NULL };
    if (g_app.selected) {
        snprintf(title, cap, "%s@%s (%d online)", g_app.nick, g_app.selected->name,
                 g_app.selected->initialising ? 1 : chat_online_count(&g_app.selected->engine) + 1);
    } else {
        snprintf(title, cap, "no session yet");
    }
    v.title = title;
    return v;
}

static void build_status_right(char *buf, size_t cap) {
    char hhmm[6]; current_hhmm(hhmm);
    if (g_app.mode == MODE_CHAT && g_app.selected && !g_app.selected->initialising)
        snprintf(buf, cap, "%d online \xc2\xb7 %s", chat_online_count(&g_app.selected->engine) + 1, hhmm);
    else
        snprintf(buf, cap, "%s", hhmm);
}

static tui_identity_badge_t identity_badge(void) {
    return (tui_identity_badge_t)g_app.identity_source;
}

static void render_input(void) {
    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);
    int mask; const char *mode_prompt = current_prompt(&mask);
    char title[120]; tui_view_t view = current_view(title, sizeof title);
    char status[64]; build_status_right(status, sizeof status);
    tui_render_input(rows_n, cols_n, &view, g_app.nick[0] ? g_app.nick : "chat", mode_prompt,
                     &g_app.input, g_app.color_enabled, mask, identity_badge(), status);
}

#define MAX_NET_LINES 6
static int build_net_lines(char lines[MAX_NET_LINES][32]) {
    if (!g_app.selected || g_app.selected->initialising) return 0;
    chat_t *e = &g_app.selected->engine;
    int n = 0;
    chat_route_summary(e, lines[n++], 32);
    if (e->route.mode == ROUTE_TOR) tor_link_line(lines[n++], 32);
    else snprintf(lines[n++], 32, "port %u", (unsigned)e->port);
    snprintf(lines[n++], 32, "rx %u dg", e->st.rx);
    snprintf(lines[n++], 32, "cands %d", chat_candidate_count(e));
    snprintf(lines[n++], 32, "pending %d", chat_pending_count(e));
    if (e->dht_on) snprintf(lines[n++], 32, "lookup %d/%d", dht_queried_count(&e->dht), dht_found_count(&e->dht));
    else snprintf(lines[n++], 32, "lookup off");
    return n;
}

static void render(void) {
    tui_session_row_t rows[MAX_SESSIONS];
    int n = 0, sel = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i]) continue;
        session_slot_t *s = &g_app.sessions[i];
        tui_session_row_t *r = &rows[n];
        snprintf(r->label, sizeof r->label, "%s@%s", g_app.nick, s->name);
        r->online = s->initialising ? 1 : chat_online_count(&s->engine) + 1;
        r->unread = s->unread;
        memcpy(r->color, g_app.color, 3);
        if (s == g_app.selected) sel = n;
        n++;
    }

    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);

    if (g_app.mode == MODE_SETTINGS || g_app.mode == MODE_SETTINGS_EDIT) {
        render_settings(rows, n, sel, rows_n, cols_n);
        return;
    }

    if (g_app.mode == MODE_SIGN_PGP_BROWSE) {
        tui_render_list(rows_n, cols_n, rows, n, sel, g_app.browser.path,
                         g_app.browser.items, g_app.browser.n_items, g_app.browser.selected,
                         "up/down move  Enter open/select  Backspace up a dir  Esc cancel",
                         g_app.color_enabled);
        return;
    }

    tui_peer_row_t peer_rows[MAX_PEERS + MAX_PENDING_PEERS + 1];
    int n_peers = 0;
    if (g_app.selected && !g_app.selected->initialising) {
        chat_t *e = &g_app.selected->engine;
        snprintf(peer_rows[n_peers].label, sizeof peer_rows[0].label, "%s (you)", e->nick);
        memcpy(peer_rows[n_peers].color, e->my_color, 3);
        n_peers++;
        int pane_x, pane_rows;
        int sbw = tui_pane_geometry(rows_n, cols_n, &pane_x, &pane_rows);
        for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS && n_peers < MAX_PEERS + MAX_PENDING_PEERS + 1; i++) {
            peer_t *p = &e->peers[i];
            if (!p->used || !p->ok) continue;
            // Cut the nick, never the status, so a long or lookalike nick can't push the real one out of view.
            char name[CHAT_NAME_LEN]; chat_peer_name(e, p, name);
            char *tag = strchr(name, '#');   // nicks can't hold '#': this is the id added to tell lookalikes apart
            char status[64];
            snprintf(status, sizeof status, "%s (%s)", tag ? tag : "", chat_verify_label(p->identity_state));
            if (tag) *tag = '\0';
            char *label = peer_rows[n_peers].label;
            size_t cap = sizeof peer_rows[0].label;
            int room = sbw - 2 - utf8_str_cols(status);
            if (room < 0) room = 0;
            size_t nlen = utf8_fit_cols(name, strlen(name), room, NULL);
            // The label buffer is bytes, not columns: the status still has to fit after the nick.
            size_t slen = strlen(status);
            while (nlen > 0 && nlen + slen >= cap) {
                nlen--;
                while (nlen > 0 && ((unsigned char)name[nlen] & 0xc0) == 0x80) nlen--;
            }
            memcpy(label, name, nlen);
            copy_str(label + nlen, status, cap - nlen);
            memcpy(peer_rows[n_peers].color, p->color, 3);
            n_peers++;
        }
    }

    int mask = 0;
    const char *mode_prompt = current_prompt(&mask);

    tui_scrollback_t *sb = g_app.selected ? &g_app.selected->sb : &g_app.log;
    tui_scrollback_t *console = g_app.selected ? &g_app.selected->console : NULL;
    char title[120]; tui_view_t view = current_view(title, sizeof title);
    char status[64]; build_status_right(status, sizeof status);
    char net_line_bufs[MAX_NET_LINES][32];
    int n_net_lines = build_net_lines(net_line_bufs);
    const char *net_lines[MAX_NET_LINES];
    for (int i = 0; i < n_net_lines; i++) net_lines[i] = net_line_bufs[i];
    tui_render(rows_n, cols_n, rows, n, sel, peer_rows, n_peers, sb, console, &view,
               g_app.nick[0] ? g_app.nick : "chat", mode_prompt, &g_app.input, g_app.color_enabled, mask,
               identity_badge(), status, net_lines, n_net_lines);
}

static int run_plain(const char *session_name, const char *password, uint16_t port,
                     const addr_t *peers, int n_peers);

static int run_tui(const char *explicit_session, char *explicit_password, uint16_t explicit_port,
                    const addr_t *peers, int n_peers) {
    term_watch_resize();
    if (term_raw_enable() != 0) {

        fprintf(stderr, "chat: this terminal can't do the full-screen UI, using --simple instead\n");
        if (!g_app.nick[0]) random_nickname(g_app.nick, sizeof g_app.nick);
        return run_plain(explicit_session, explicit_password, explicit_port, peers, n_peers);
    }

    fputs("\x1b[22;0t\x1b]0;chat\x07\x1b[?1049h\x1b[2J\x1b[H", stdout);
    fflush(stdout);
    catch_quit_signals();

    tui_input_clear(&g_app.input);
    g_app.input.modal = 1;
    g_app.input.complete = complete_command;
    g_app.input.mention = complete_mention;
    g_app.dirty = 1;

    if (explicit_session) {
        copy_str(g_app.pending_auto_session, explicit_session, sizeof g_app.pending_auto_session);
        copy_str(g_app.pending_auto_password, explicit_password, sizeof g_app.pending_auto_password);
        g_app.pending_auto_port = explicit_port;
        if (n_peers > 0) memcpy(g_app.pending_auto_peers, peers, sizeof(addr_t) * (size_t)n_peers);
        g_app.pending_auto_n_peers = n_peers;
        crypto_wipe(explicit_password, strlen(explicit_password));
    }

    if (!g_app.nick[0]) {
        random_nickname(g_app.nick, sizeof g_app.nick);
        push_log("welcome to chat. you're %s for now - /nick NAME renames you anytime",
                 g_app.nick);
    }

    if (g_app.route_chosen) {
        push_log("* routing: %s", route_label());
        finish_onboarding();
    } else {
        begin_route_choice();
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
            // Past the limit a socket only waits for the next tick, 200 ms at most.
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

        tor_link_ensure(now);
        tor_link_step(now);

        char update_msg[UPDATE_MSG_MAX];
        if (update_poll(update_msg, sizeof update_msg)) push_log("%s", update_msg);

        if (term_resized()) g_app.dirty = 1;
        if (now >= next_ui_tick) { next_ui_tick = now + 1.0; g_app.dirty = 1; }
        if (g_app.dirty) { render(); g_app.dirty = 0; g_app.input_dirty = 0; }
        else if (g_app.input_dirty) { render_input(); g_app.input_dirty = 0; }
    }

    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) close_session(&g_app.sessions[i]);
    // After the sessions: their onion services go with their control connections first.
    tor_link_stop();
    crypto_wipe(&g_app.input, sizeof g_app.input);
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
    crypto_wipe(g_app.pending_auto_password, sizeof g_app.pending_auto_password);
    tui_scrollback_clear(&g_app.log);

    // Back to the main screen with the cursor visible, its default shape and autowrap on, however
    // the last frame left them.
    fputs("\x1b[?7h\x1b[0 q\x1b[?25h\x1b[?1049l\x1b[23;0t", stdout);
    term_raw_disable();
    fflush(stdout);
    net_shutdown();
    platform_notify_shutdown();

    _exit(0);
}

static void plain_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                        unsigned flags, int color_len) {
    (void)ui;
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
    send_notification(NULL, nick, text, mentioned);
}

static int run_plain(const char *session_name, const char *password, uint16_t port,
                     const addr_t *peers, int n_peers) {
    int tty = term_is_tty();
    g_plain = 1;
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
        // No fixed default: a well-known id with a blank password would be a room anyone can join.
        random_session_id(o.session_name, 10);
        o.created = 1;
        printf("new session id: %s  (share this and the password)\n", o.session_name);
    }

    if (password) copy_str(o.password, password, sizeof o.password);
    else if (platform_env_take("CHAT_PASSWORD", o.password, sizeof o.password) == 0) {  }
    else if (tty && term_read_password(o.created ? "create password: " : "password: ", o.password, sizeof o.password) != 0) return 1;

    if (n_peers > 0) { memcpy(o.peers, peers, sizeof(addr_t) * (size_t)n_peers); o.n_peers = n_peers; }
    o.port = port;
    if (!g_app.route_chosen) {
        int choice = 1;
        if (tty) {
            for (size_t i = 0; i < sizeof ROUTE_CHOICE_LINES / sizeof ROUTE_CHOICE_LINES[0]; i++)
                printf("%s\n", ROUTE_CHOICE_LINES[i] + 2);
            char line[16];
            if (term_read_line("routing [1/2/3, Enter = 1]: ", line, sizeof line) != 0) return 1;
            if (line[0] >= '1' && line[0] <= '3') choice = line[0] - '0';
        }
        apply_route_choice(choice);
    }
    sync_update_proxy();
    o.route = g_app.route;
    if (o.route.mode == ROUTE_TOR) {
        tor_link_ensure(now_seconds());
        o.route.tor.socks[0] = o.route.tor.control[0] = '\0';
    }
    o.notify_mode = g_app.notify_mode;
    o.has_color = 1;
    memcpy(o.color, g_app.color, 3);
    o.identity_source = g_app.identity_source;
    if (g_app.identity_source != IDENT_NONE) o.identity = g_app.identity;

    static chat_t c;
    chat_init(&c, &o, plain_print, plain_notify, NULL);
    g_plain_engine = &c;
    crypto_wipe(&o, sizeof o);
    if (!chat_started(&c)) {
        if (g_app.route.mode == ROUTE_TOR) fprintf(stderr, "chat: could not set up Tor\n");
        else fprintf(stderr, "chat: cannot bind udp port %u\n", (unsigned)port);
        chat_shutdown(&c);
        return 1;
    }
    c.net_verbose = g_app.net_verbose;
    char idhex[9]; hex_encode(c.my_id, 4, idhex);
    if (c.route.mode == ROUTE_TOR)
        printf("session '%s', you are %s (peer %s). encrypted, over Tor only. /quit or EOF to stop.\n",
               c.session_name, c.nick, idhex);
    else
        printf("session '%s', you are %s (peer %s). encrypted, udp/%u, routing: %s. /quit or EOF to stop.\n",
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
        if (rc == 1) alive = chat_submit_line(&c, line, now);
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

int main(int argc, char **argv) {
    char nick_arg[MAX_NICK + 1] = "";
    char identity_arg[16] = "";
    char pgp_key_path[512] = "";
    char explicit_session[MAX_SESSION_NAME + 1] = "";
    uint16_t explicit_port = 0;
    char peer_args[16][256]; int n_peer_args = 0;
    int has_color = 0, force_simple = 0, do_update = 0, relays_given = 0;
    routing_defaults(&g_app.route);
    g_app.notify_mode = NOTIFY_MENTIONS;
    uint8_t color[3] = {0, 0, 0};

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *key = a;
        while (*key == '-') key++;
        if (strcmp(key, "nick") == 0 && i + 1 < argc) {
            copy_str(nick_arg, argv[++i], sizeof nick_arg);
        } else if (strcmp(key, "session") == 0 && i + 1 < argc) {
            copy_str(explicit_session, argv[++i], sizeof explicit_session);
        } else if (strcmp(key, "port") == 0 && i + 1 < argc) {
            char *end;
            long port = strtol(argv[++i], &end, 10);
            if (!argv[i][0] || *end || port < 0 || port > 65535) {
                fprintf(stderr, "chat: bad --port %s (0-65535, 0 picks a free one)\n", argv[i]);
                return 1;
            }
            explicit_port = (uint16_t)port;
        } else if (strcmp(key, "peer") == 0 && i + 1 < argc) {
            if (n_peer_args >= 16) { fprintf(stderr, "chat: at most 16 --peer options\n"); return 1; }
            copy_str(peer_args[n_peer_args++], argv[++i], sizeof peer_args[0]);
        } else if (strcmp(key, "nodht") == 0) {
            g_app.route.dht4 = g_app.route.dht6 = 0;
        } else if (strcmp(key, "noipv6") == 0) {
            g_app.route.dht6 = 0;
        } else if (strcmp(key, "nolan") == 0) {
            g_app.route.lan = 0;
        } else if (strcmp(key, "noportmap") == 0) {
            g_app.route.portmap = 0;
        } else if (strcmp(key, "nonostr") == 0) {
            g_app.route.nostr = 0;
        } else if (strcmp(key, "routing") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "direct+nostr") == 0 || strcmp(v, "nostr") == 0) apply_route_choice(1);
            else if (strcmp(v, "direct") == 0) apply_route_choice(2);
            else if (strcmp(v, "tor") == 0) apply_route_choice(3);
            else { fprintf(stderr, "chat: --routing takes direct+nostr, direct or tor\n"); return 1; }
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
            force_simple = 1;
        } else if ((strcmp(key, "colour") == 0 || strcmp(key, "color") == 0) && i + 1 < argc) {
            if (parse_color(argv[++i], color) != 0) { fprintf(stderr, "chat: unknown colour %s\n", argv[i]); return 1; }
            has_color = 1;
        } else if (strcmp(key, "identity") == 0 && i + 1 < argc) {
            char *v = argv[++i];
            if (strncmp(v, "pgp:", 4) == 0) { copy_str(identity_arg, "pgp", sizeof identity_arg); copy_str(pgp_key_path, v + 4, sizeof pgp_key_path); }
            else copy_str(identity_arg, v, sizeof identity_arg);
        } else if (strcmp(key, "update") == 0) {
            do_update = 1;
        } else if (strcmp(key, "version") == 0) {
            printf("chat " CHAT_VERSION ", built %s (wire: hybrid X25519+ML-KEM-768, chunked handshake)\n", CHAT_BUILD_STAMP);
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

    platform_harden_process();
    update_cleanup_stale();

    crypto_setup();
    // The signing key, a pasted key block and typed passwords pass through these for the whole
    // run. Best effort, as in chat_init.
    crypto_lock(&g_app.identity, sizeof g_app.identity);
    crypto_lock(g_app.paste_buf, sizeof g_app.paste_buf);
    crypto_lock(&g_app.input, sizeof g_app.input);
    crypto_lock(&g_app.saved_input, sizeof g_app.saved_input);
    crypto_lock(g_app.pending_auto_password, sizeof g_app.pending_auto_password);

    if (do_update) {
        // With --routing tor the download goes through Tor, never direct: find or start a tor first.
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

    int interactive = !force_simple && term_is_tty() && term_stdout_is_tty() && term_ansi_ok();
    g_app.show_sidebar = g_app.show_console = g_app.show_chat = 1;
    g_app.color_enabled = interactive;
    if (has_color) memcpy(g_app.color, color, 3);
    else {
        uint8_t r; gen_random(&r, 1);
        const named_color_t *pick = &COLOR_PALETTE[r % COLOR_PALETTE_N];
        g_app.color[0] = pick->r; g_app.color[1] = pick->g; g_app.color[2] = pick->b;
    }
    if (nick_arg[0]) chat_clean_nick(nick_arg, g_app.nick);

    addr_t peers[16]; int n_peers = 0;
    if (g_app.route_chosen && g_app.route.mode == ROUTE_TOR && n_peer_args > 0) {
        // A --peer address would be reached over UDP, which Tor mode never uses.
        fprintf(stderr, "chat: --peer can't be used with --routing tor\n");
        return 1;
    }
    for (int i = 0; i < n_peer_args; i++) {
        if (addr_parse_hostport(peer_args[i], &peers[n_peers]) != 0) {
            fprintf(stderr, "chat: bad --peer %s\n", peer_args[i]);
            return 1;
        }
        n_peers++;
    }

    g_app.identity_source = IDENT_NONE;
    if (identity_arg[0]) {
        if (strcmp(identity_arg, "native") == 0) { g_app.identity_source = IDENT_NATIVE; gen_identity_keypair(&g_app.identity); }
        else if (strcmp(identity_arg, "age") == 0) { g_app.identity_source = IDENT_AGE; gen_identity_keypair(&g_app.identity); }
        else if (strcmp(identity_arg, "pgp") == 0) {
            if (!pgp_key_path[0] || pgp_import_secret_key(pgp_key_path, &g_app.identity) != 0) {
                fprintf(stderr, "chat: could not load a PGP identity from %s\n", pgp_key_path[0] ? pgp_key_path : "(no path given)");
            } else g_app.identity_source = IDENT_PGP;
        }
    }

    if (!interactive) {
        if (!g_app.nick[0]) random_nickname(g_app.nick, sizeof g_app.nick);
        return run_plain(explicit_session[0] ? explicit_session : NULL, NULL, explicit_port, peers, n_peers);
    }

    if (!explicit_session[0]) {
        return run_tui(NULL, NULL, 0, NULL, 0);
    }

    char explicit_password[256] = "";

    if (platform_env_take("CHAT_PASSWORD", explicit_password, sizeof explicit_password) != 0) {
        if (term_read_password("password: ", explicit_password, sizeof explicit_password) != 0) return 1;
    }
    int rc = run_tui(explicit_session, explicit_password, explicit_port, peers, n_peers);
    crypto_wipe(explicit_password, sizeof explicit_password);
    return rc;
}
