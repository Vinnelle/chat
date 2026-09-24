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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <stdarg.h>
#include "os.h"
#include "build_stamp.h"

static const char *USAGE =
    "usage: chat [--nick NAME] [--colour NAME|#HEX] [--nodht] [--identity native|age|pgp:KEYFILE]\n"
    "            [--simple] [--session ID --port UDP_PORT --peer HOST:PORT ...]\n"
    "\n"
    "With a real terminal, chat opens a full-screen UI: sessions you've joined or created\n"
    "sit in a list on the left (switch with Tab/Shift+Tab), the selected one's messages and\n"
    "timestamps fill the rest of the screen, who's online sits below the session list, and\n"
    "you type at the bottom. Your nickname and, optionally, an identity key are set up in\n"
    "this same screen the first time you run it.\n"
    "\n"
    "  Ctrl+N   create a new session (asks for a password; blank is fine, still encrypts)\n"
    "  Ctrl+J   join an existing session (asks for its id, then its password)\n"
    "  /new /join   the same two, typed - for a terminal where the shortcuts don't arrive\n"
    "  Ctrl+W   leave/close the session you're currently looking at\n"
    "  Tab      next session       Shift+Tab   previous session\n"
    "\n"
    "Each session has two sections: the conversation, and a console above it for everything\n"
    "that isn't chat - people joining and leaving, the internet lookup, /command output. A\n"
    "session you joined is locked (the prompt says \"connecting\") until someone answers.\n"
    "\n"
    "  Ctrl+B   hide/show the session sidebar   Ctrl+O   hide/show the console\n"
    "  Ctrl+T   hide/show the chat (hide two of the three and the last one fills the screen)\n"
    "  Esc      leave INSERT for NORMAL (see below); a second Esc cancels a prompt/menu/browser\n"
    "  Ctrl+C   quit chat (every open session leaves cleanly first)\n"
    "  /peers /net /netverbose on|off /colour /nick /verify NICK /notify /help   typed into\n"
    "  any session - every one also works as a ':' command below (:peers, :net, ...)\n"
    "\n"
    "The input line is a small vim: it starts in INSERT (type immediately, as always); Esc\n"
    "drops to NORMAL for h/l cursor movement, i/a/I/A back to INSERT, x to delete a character.\n"
    "':' from NORMAL opens a command line: :new :join :close (:bd/:bw) :nick NAME :sign\n"
    ":copyid :verify NICK :net :peers :colour :notify :update :help :q :qa\n"
    "\n"
    "  --nick      display name; a random one (\"swift-otter42\"-style) is assigned if\n"
    "              omitted - /nick or :nick renames it anytime, shared by every session\n"
    "  --colour    your display colour in every session; random by default (--color too)\n"
    "  --nodht     skip internet discovery, use LAN broadcast only\n"
    "  --identity  native: a fresh Ed25519 identity, used to sign every session you join.\n"
    "              age: same, plus an AGE recipient string (age1...) others can `age -r`\n"
    "              encrypt files to. pgp:KEYFILE: import an UNENCRYPTED armored EdDSA\n"
    "              secret key from real gpg and sign with it instead. There's no prompt\n"
    "              for this at startup anymore - chat opens unsigned by default, and\n"
    "              :sign (or /sign) sets one up whenever you actually want it,\n"
    "              live, without restarting: browse for a key file, paste one directly\n"
    "              (never written to disk), or turn signing off again.\n"
    "  --simple    skip the full-screen UI even on a real terminal: plain \"[HH:MM] ...\"\n"
    "              lines, one session, reads lines from stdin. For scripting/low-feature\n"
    "              terminals; this is also the automatic fallback when stdout isn't a tty.\n"
    "  --session   also join this session immediately at startup (needs --port; \"chat\n"
    "              --session ID\" alone still opens straight into the TUI to join by hand)\n"
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
    MODE_ONBOARD_IDENTITY,
    MODE_ONBOARD_PGP_CHOICE,
    MODE_ONBOARD_PGP_BROWSE,
    MODE_ONBOARD_PGP_PASTE,
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
    int dht_on;
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
static void on_sigint(int sig) { (void)sig; g_interrupted = 1; }

static void push_log(const char *fmt, ...) {
    char msg[256];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    char hhmm[6]; current_hhmm(hhmm);
    tui_scrollback_push(&g_app.log, hhmm, msg, NULL, 0, 0);
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

static session_slot_t *start_session(const char *session_name, const char *password, int created,
                                      uint16_t port, const addr_t *peers, int n_peers) {
    session_slot_t *s = find_free_slot();
    if (!s) { push_log("* too many sessions open already"); return NULL; }
    int idx = slot_index(s);
    memset(s, 0, sizeof *s);
    copy_str(s->name, session_name, sizeof s->name);

    char pw[256];
    copy_str(pw, password, sizeof pw);
    if (g_app.mode == MODE_NEW_PASSWORD || g_app.mode == MODE_JOIN_PASSWORD) {
        crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
        tui_input_clear(&g_app.input);
        g_app.mode = MODE_CHAT;
    }

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
    o.port = port;
    if (n_peers > 0) { memcpy(o.peers, peers, sizeof(addr_t) * (size_t)n_peers); o.n_peers = n_peers; }
    o.dht_on = g_app.dht_on;
    o.created = created;
    o.notify_mode = NOTIFY_MENTIONS;
    o.has_color = 1;
    memcpy(o.color, g_app.color, 3);
    o.identity_source = g_app.identity_source;
    if (g_app.identity_source != IDENT_NONE) o.identity = g_app.identity;

    chat_init(&s->engine, &o, session_print, session_notify, s);
    crypto_wipe(o.password, sizeof o.password);
    if (s->engine.sock == SOCK_INVALID) {
        crypto_wipe(&s->engine, sizeof s->engine);
        tui_scrollback_clear(&s->console);
        g_app.used[idx] = 0;
        g_app.selected = NULL;
        for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) { g_app.selected = &g_app.sessions[i]; break; }
        push_log("* could not open a network socket for that session");
        return NULL;
    }
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

static void begin_identity_stage(void) {
    g_app.mode = MODE_ONBOARD_IDENTITY;
    tui_input_clear(&g_app.input);
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

    g_app.input.mode = TUI_IMODE_NORMAL;
    g_app.dirty = 1;
}

static void finish_onboarding(void) {
    g_app.mode = MODE_CHAT;
    g_app.input.mode = TUI_IMODE_NORMAL;

    push_log("* ready. Ctrl+N (or /new) creates a session, Ctrl+J (or /join) joins one, "
             ":sign adds a signing key so others can verify you");
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
    g_app.mode = MODE_ONBOARD_PGP_BROWSE;
    g_app.dirty = 1;
}

static void begin_pgp_paste(void) {
    g_app.paste_len = 0;
    g_app.paste_buf[0] = '\0';
    copy_str(g_app.paste_status, "pasting (0 bytes so far, Esc to cancel)", sizeof g_app.paste_status);
    g_app.mode = MODE_ONBOARD_PGP_PASTE;
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

static void begin_new_session_prompt(void) {
    g_app.mode = MODE_NEW_PASSWORD; tui_input_clear(&g_app.input); g_app.dirty = 1;
}
static void begin_join_session_prompt(void) {
    g_app.mode = MODE_JOIN_ID; tui_input_clear(&g_app.input); g_app.dirty = 1;
}

static void colon_first_word(const char *cmd, char *out, size_t out_cap) {
    const char *sp = strchr(cmd, ' ');
    size_t wlen = sp ? (size_t)(sp - cmd) : strlen(cmd);
    if (wlen >= out_cap) wlen = out_cap - 1;
    memcpy(out, cmd, wlen); out[wlen] = '\0';
}

static int colon_word_is_known(const char *cmd) {
    static const char *known[] = { "q", "quit", "close", "bd", "bw", "qa", "qall", "quitall",
                                    "new", "join", "nick", "sign", "copyid", "verify", "netverbose",
                                    "net", "peers", "colour", "color", "notify", "update", "help" };
    char word[16]; colon_first_word(cmd, word, sizeof word);
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++)
        if (strcmp(word, known[i]) == 0) return 1;
    return 0;
}

static void run_session_slash(const char *slash, const char *arg) {
    if (!g_app.selected) { push_log("* no session selected - :%s needs one you're in", slash + 1); return; }
    char line[16 + MAX_NICK + MAX_TEXT];
    if (arg && *arg) snprintf(line, sizeof line, "%s %s", slash, arg);
    else copy_str(line, slash, sizeof line);
    chat_submit_line(&g_app.selected->engine, line, now_seconds());
}

static void run_colon_command(const char *cmd) {
    char word[16]; colon_first_word(cmd, word, sizeof word);
    const char *arg = strchr(cmd, ' ');
    while (arg && *arg == ' ') arg++;

    if (word[0] == '\0') return;
    if (strcmp(word, "q") == 0 || strcmp(word, "quit") == 0) {

        if (g_app.selected) close_session(g_app.selected);
        else g_interrupted = 1;
    } else if (strcmp(word, "close") == 0 || strcmp(word, "bd") == 0 || strcmp(word, "bw") == 0) {
        if (g_app.selected) close_session(g_app.selected);
        else push_log("* no session to close");
    } else if (strcmp(word, "qa") == 0 || strcmp(word, "qall") == 0 || strcmp(word, "quitall") == 0) {
        g_interrupted = 1;
    } else if (strcmp(word, "new") == 0) {
        begin_new_session_prompt();
    } else if (strcmp(word, "join") == 0) {
        begin_join_session_prompt();
    } else if (strcmp(word, "nick") == 0) {
        if (!arg || !*arg) { push_log("* usage: :nick NAME"); return; }
        char cleaned[MAX_NICK + 1];
        clean_text(arg, cleaned, MAX_NICK);
        copy_str(g_app.nick, cleaned[0] ? cleaned : "anon", sizeof g_app.nick);
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (g_app.used[i]) chat_set_nick(&g_app.sessions[i].engine, g_app.nick);
        g_app.dirty = 1;
    } else if (strcmp(word, "sign") == 0) {
        begin_identity_stage();
    } else if (strcmp(word, "copyid") == 0) {
        copy_session_id(g_app.selected);
    } else if (strcmp(word, "verify") == 0) {
        run_session_slash("/verify", arg);
    } else if (strcmp(word, "netverbose") == 0) {
        run_session_slash("/netverbose", arg);
    } else if (strcmp(word, "net") == 0) {
        run_session_slash("/net", NULL);
    } else if (strcmp(word, "peers") == 0) {
        run_session_slash("/peers", NULL);
    } else if (strcmp(word, "colour") == 0 || strcmp(word, "color") == 0) {
        run_session_slash("/colour", arg);
    } else if (strcmp(word, "notify") == 0) {
        run_session_slash("/notify", arg);
    } else if (strcmp(word, "update") == 0) {
        if (update_start() == 0) push_log("* update: checking GitHub for a newer release (v" CHAT_VERSION " here)...");
        else push_log("* update: already running");
    } else if (strcmp(word, "help") == 0) {
        run_session_slash("/help", NULL);
    } else {
        push_log("* unknown command: %s (try :new :join :close :nick :sign :copyid :verify "
                  ":netverbose :net :peers :colour :notify :update :help :q :qa)", word);
    }
}

static void handle_key(const tui_key_t *key) {
    tui_input_t *input = &g_app.input;

    if (g_app.mode == MODE_ONBOARD_PGP_PASTE) {
        if (key->type == TUI_KEY_ESCAPE) {
            crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
            g_app.paste_len = 0;
            g_app.mode = MODE_ONBOARD_PGP_CHOICE;
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
        if (strstr(g_app.paste_buf, "-----END PGP PRIVATE KEY BLOCK-----")) {
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

    if (g_app.mode == MODE_ONBOARD_PGP_BROWSE) {
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
                g_app.mode = MODE_ONBOARD_PGP_CHOICE;
                g_app.dirty = 1;
                return;
            default:
                return;
        }
    }

    if (g_app.mode == MODE_ONBOARD_IDENTITY) {

        if (key->type == TUI_KEY_ESCAPE) {
            g_app.mode = MODE_CHAT;
            g_app.input.mode = TUI_IMODE_NORMAL;
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
            g_app.mode = MODE_ONBOARD_PGP_CHOICE;
            push_log("[f] browse for a key file   [p] paste key text   (Esc to go back)");
        }
        return;
    }

    if (g_app.mode == MODE_ONBOARD_PGP_CHOICE) {
        if (key->type == TUI_KEY_ESCAPE) { begin_identity_stage(); return; }
        if (key->type == TUI_KEY_CHAR && tolower((unsigned char)key->ch[0]) == 'f') { begin_pgp_browse(); return; }
        if (key->type == TUI_KEY_CHAR && tolower((unsigned char)key->ch[0]) == 'p') { begin_pgp_paste(); return; }
        return;
    }

    if (tui_input_feed(input, key)) { g_app.input_dirty = 1; return; }

    switch (key->type) {
        case TUI_KEY_ESCAPE:
            if (g_app.mode == MODE_NEW_PASSWORD || g_app.mode == MODE_JOIN_ID || g_app.mode == MODE_JOIN_PASSWORD) {
                crypto_wipe(input->buf, sizeof input->buf);
                tui_input_clear(input);
                crypto_wipe(g_app.pending_session_id, sizeof g_app.pending_session_id);
                g_app.mode = MODE_CHAT;
                g_app.dirty = 1;
            }
            break;

        case TUI_KEY_TAB:
            if (g_app.mode == MODE_CHAT) select_step(1);
            break;
        case TUI_KEY_BACKTAB:
            if (g_app.mode == MODE_CHAT) select_step(-1);
            break;
        case TUI_KEY_NEW_SESSION:
            if (g_app.mode == MODE_CHAT) { g_app.mode = MODE_NEW_PASSWORD; tui_input_clear(input); g_app.dirty = 1; }
            break;
        case TUI_KEY_JOIN_SESSION:
            if (g_app.mode == MODE_CHAT) { g_app.mode = MODE_JOIN_ID; tui_input_clear(input); g_app.dirty = 1; }
            break;
        case TUI_KEY_CLOSE_SESSION:
            if (g_app.mode == MODE_CHAT && g_app.selected) close_session(g_app.selected);
            break;

        case TUI_KEY_TOGGLE_SIDEBAR:
            if (g_app.mode == MODE_CHAT) { g_app.show_sidebar = !g_app.show_sidebar; g_app.dirty = 1; }
            break;
        case TUI_KEY_TOGGLE_CONSOLE:
            if (g_app.mode == MODE_CHAT) { g_app.show_console = !g_app.show_console; g_app.dirty = 1; }
            break;
        case TUI_KEY_TOGGLE_CHAT:
            if (g_app.mode == MODE_CHAT) { g_app.show_chat = !g_app.show_chat; g_app.dirty = 1; }
            break;

        case TUI_KEY_ENTER:
            switch (g_app.mode) {
                case MODE_CHAT:

                    if (input->mode == TUI_IMODE_COMMAND) {
                        run_colon_command(input->cmd);

                        if (input->mode == TUI_IMODE_COMMAND) {
                            input->mode = TUI_IMODE_NORMAL;
                            input->cmd_len = 0; input->cmd[0] = '\0';
                        }
                        break;
                    }

                    if (input->buf[0] == ':' && input->len > 1 && colon_word_is_known(input->buf + 1)) {
                        run_colon_command(input->buf + 1);
                        tui_input_clear(input);
                        g_app.dirty = 1;
                        break;
                    }

                    if (strcmp(input->buf, "/new") == 0) { begin_new_session_prompt(); break; }
                    if (strcmp(input->buf, "/join") == 0) { begin_join_session_prompt(); break; }
                    if (strcmp(input->buf, "/sign") == 0) { begin_identity_stage(); break; }
                    if (strcmp(input->buf, "/copyid") == 0) { copy_session_id(g_app.selected); tui_input_clear(input); break; }
                    if (!g_app.selected && input->len > 0) {
                        push_log("* no session yet - Ctrl+N (or /new) creates one, Ctrl+J (or /join) joins one");
                        tui_input_clear(input); g_app.dirty = 1; break;
                    }
                    if (g_app.selected && input->len > 0) {

                        if (input->buf[0] != '/' && !session_ready(g_app.selected)) {
                            console_note(g_app.selected, g_app.selected->initialising
                                ? "* still initialising - hold on a moment"
                                : "* not connected yet - chat opens once someone answers (your text is kept; Ctrl+W leaves)");
                            break;
                        }
                        double now = now_seconds();
                        if (chat_submit_line(&g_app.selected->engine, input->buf, now) == 0)
                            close_session(g_app.selected);
                    }
                    tui_input_clear(input);
                    g_app.dirty = 1;
                    break;
                case MODE_NEW_PASSWORD: {
                    char session_id[MAX_SESSION_NAME + 1];
                    random_session_id(session_id, 10);
                    start_session(session_id, input->buf, 1, 0, NULL, 0);
                    crypto_wipe(input->buf, sizeof input->buf);
                    tui_input_clear(input);
                    g_app.mode = MODE_CHAT;
                    break;
                }
                case MODE_JOIN_ID:
                    if (input->len > 0) {
                        copy_str(g_app.pending_session_id, input->buf, sizeof g_app.pending_session_id);
                        tui_input_clear(input);
                        g_app.mode = MODE_JOIN_PASSWORD;
                        g_app.dirty = 1;
                    }
                    break;
                case MODE_JOIN_PASSWORD:
                    start_session(g_app.pending_session_id, input->buf, 0, 0, NULL, 0);
                    crypto_wipe(input->buf, sizeof input->buf);
                    crypto_wipe(g_app.pending_session_id, sizeof g_app.pending_session_id);
                    tui_input_clear(input);
                    g_app.mode = MODE_CHAT;
                    break;
                default:
                    break;
            }
            break;

        default:
            break;
    }
}

static const char *current_prompt(int *mask) {
    const char *mode_prompt = NULL;
    *mask = 0;
    switch (g_app.mode) {
        case MODE_ONBOARD_IDENTITY: mode_prompt = "[n/a/p]"; break;
        case MODE_ONBOARD_PGP_CHOICE: mode_prompt = "[f/p]"; break;
        case MODE_NEW_PASSWORD:    mode_prompt = "create password"; *mask = 1; break;
        case MODE_JOIN_ID:         mode_prompt = "session id"; break;
        case MODE_JOIN_PASSWORD:   mode_prompt = "password"; *mask = 1; break;
        default: break;
    }
    if (g_app.mode == MODE_ONBOARD_PGP_PASTE) mode_prompt = g_app.paste_status;

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

#define MAX_NET_LINES 5
static int build_net_lines(char lines[MAX_NET_LINES][32]) {
    if (!g_app.selected || g_app.selected->initialising) return 0;
    chat_t *e = &g_app.selected->engine;
    int n = 0;
    snprintf(lines[n++], 32, "port %u", (unsigned)e->port);
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

    if (g_app.mode == MODE_ONBOARD_PGP_BROWSE) {
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
        for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS && n_peers < MAX_PEERS + MAX_PENDING_PEERS + 1; i++) {
            peer_t *p = &e->peers[i];
            if (!p->used || !p->ok) continue;
            snprintf(peer_rows[n_peers].label, sizeof peer_rows[0].label, "%s (%s)",
                     p->nick, chat_verify_label(p->identity_state));
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
    signal(SIGINT, on_sigint);

    tui_input_clear(&g_app.input);
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
        push_log("welcome to chat. you're %s for now - /nick NAME or :nick NAME renames you anytime",
                 g_app.nick);
    }

    finish_onboarding();
    render();

    double next_ui_tick = now_seconds() + 1.0;

    while (!g_interrupted) {
        sock_t socks[MAX_SESSIONS * 2];
        session_slot_t *owner[MAX_SESSIONS * 2];
        int ready[MAX_SESSIONS * 2];
        int n = 0;
        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (!g_app.used[i]) continue;
            sock_t pair[2];
            int ns = chat_sockets(&g_app.sessions[i].engine, pair);
            for (int j = 0; j < ns; j++) { socks[n] = pair[j]; owner[n] = &g_app.sessions[i]; n++; }
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

        char update_msg[UPDATE_MSG_MAX];
        if (update_poll(update_msg, sizeof update_msg)) push_log("%s", update_msg);

        if (term_resized()) g_app.dirty = 1;
        if (now >= next_ui_tick) { next_ui_tick = now + 1.0; g_app.dirty = 1; }
        if (g_app.dirty) { render(); g_app.dirty = 0; g_app.input_dirty = 0; }
        else if (g_app.input_dirty) { render_input(); g_app.input_dirty = 0; }
    }

    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) close_session(&g_app.sessions[i]);
    crypto_wipe(&g_app.input, sizeof g_app.input);
    crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
    crypto_wipe(g_app.pending_auto_password, sizeof g_app.pending_auto_password);
    tui_scrollback_clear(&g_app.log);

    fputs("\x1b[?1049l\x1b[23;0t", stdout);
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
        copy_str(o.session_name, "lobby", sizeof o.session_name);
    }

    if (password) copy_str(o.password, password, sizeof o.password);
    else if (platform_env_take("CHAT_PASSWORD", o.password, sizeof o.password) == 0) {  }
    else if (tty && term_read_password(o.created ? "create password: " : "password: ", o.password, sizeof o.password) != 0) return 1;

    if (n_peers > 0) { memcpy(o.peers, peers, sizeof(addr_t) * (size_t)n_peers); o.n_peers = n_peers; }
    o.port = port;
    o.dht_on = g_app.dht_on;
    o.notify_mode = NOTIFY_MENTIONS;
    o.has_color = 1;
    memcpy(o.color, g_app.color, 3);
    o.identity_source = g_app.identity_source;
    if (g_app.identity_source != IDENT_NONE) o.identity = g_app.identity;

    chat_t c;
    chat_init(&c, &o, plain_print, plain_notify, NULL);
    crypto_wipe(o.password, sizeof o.password);
    if (c.sock == SOCK_INVALID) {
        fprintf(stderr, "chat: cannot bind udp port %u\n", (unsigned)port);
        crypto_wipe(&c, sizeof c);
        return 1;
    }
    char idhex[9]; hex_encode(c.my_id, 4, idhex);
    printf("session '%s', you are %s (peer %s). encrypted, udp/%u. /quit or EOF to stop.\n",
           c.session_name, c.nick, idhex, (unsigned)c.port);

    signal(SIGINT, on_sigint);
    stdin_reader_t *reader = stdin_reader_start();
    int alive = 1;
    while (alive && !g_interrupted) {
        sock_t socks[2]; int ns = chat_sockets(&c, socks);
        int ready[2] = {0, 0};
        net_wait(socks, ready, ns, 200);
        double now = now_seconds();
        for (int i = 0; i < ns; i++) if (ready[i]) chat_on_socket_readable(&c, socks[i], now);
        char line[MAX_TEXT + 1];
        int rc = stdin_reader_poll(reader, line, sizeof line);
        if (rc == 1) alive = chat_submit_line(&c, line, now);
        else if (rc == -1) alive = 0;
        chat_tick(&c, now_seconds());
    }
    chat_shutdown(&c);
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
    int dht_on = 1, has_color = 0, force_simple = 0;
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
            explicit_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(key, "peer") == 0 && i + 1 < argc) {
            if (n_peer_args < 16) copy_str(peer_args[n_peer_args++], argv[++i], sizeof peer_args[0]);
            else i++;
        } else if (strcmp(key, "nodht") == 0) {
            dht_on = 0;
        } else if (strcmp(key, "simple") == 0) {
            force_simple = 1;
        } else if ((strcmp(key, "colour") == 0 || strcmp(key, "color") == 0) && i + 1 < argc) {
            if (parse_color(argv[++i], color) != 0) { fprintf(stderr, "chat: unknown colour %s\n", argv[i]); return 1; }
            has_color = 1;
        } else if (strcmp(key, "identity") == 0 && i + 1 < argc) {
            char *v = argv[++i];
            if (strncmp(v, "pgp:", 4) == 0) { copy_str(identity_arg, "pgp", sizeof identity_arg); copy_str(pgp_key_path, v + 4, sizeof pgp_key_path); }
            else copy_str(identity_arg, v, sizeof identity_arg);
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
    net_startup();

    int interactive = !force_simple && term_is_tty() && term_stdout_is_tty() && term_ansi_ok();
    g_app.dht_on = dht_on;
    g_app.show_sidebar = g_app.show_console = g_app.show_chat = 1;
    g_app.color_enabled = interactive;
    if (has_color) memcpy(g_app.color, color, 3);
    else {
        uint8_t r; gen_random(&r, 1);
        const named_color_t *pick = &COLOR_PALETTE[r % COLOR_PALETTE_N];
        g_app.color[0] = pick->r; g_app.color[1] = pick->g; g_app.color[2] = pick->b;
    }
    copy_str(g_app.nick, nick_arg, sizeof g_app.nick);

    addr_t peers[16]; int n_peers = 0;
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
