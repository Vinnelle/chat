// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"
#include "changelog.h"

static const char *USAGE =
    "usage: chat [--nick NAME] [--colour NAME|#HEX] [--identity age|pgp[:KEYFILE]] [--simple]\n"
    "            [--save NAME]\n"
    "            [--routing dht+nostr|dht|tor] [--nodht] [--noipv6] [--nolan]\n"
    "            [--noportmap] [--nonostr] [--nostr-always] [--relay wss://HOST ...]\n"
    "            [--tor-launch auto|always|never] [--tor-path PATH] [--tor-socks HOST:PORT]\n"
    "            [--tor-control HOST:PORT] [--verify-required] [--file-limit SIZE]\n"
    "            [--fast-files] [--betas]\n"
    "            [--session ID --port UDP_PORT --peer HOST:PORT ...]\n"
    "       chat --update [--betas] | --version\n"
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
    "second passphrase that opens a decoy in its place and deletes the real save's files.\n"
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
    "  --betas     let :update and --update install betas too, the test builds of the\n"
    "              next release (:set betas on keeps it)\n"
    "  --version   print the version and exit\n"
    "\n"
    "Encryption: X25519 + ML-KEM-768 (hybrid, post-quantum), XChaCha20-Poly1305, and a\n"
    "ratchet per message for forward secrecy. Nothing is written to disk unless you ask\n"
    "for it with :install or :download. Messages are only kept with :set history on, sealed\n"
    "in a save, and everyone in the session is told.\n";

// A message is shown on one line, after who sent it: "nick#1a2b3c4d (via nick (code not compared)): ".
_Static_assert(TUI_LINE_MAX >= MAX_TEXT + 2 * CHAT_NAME_LEN + 48, "a whole message fits a line on screen");

app_t g_app;

options_t g_opts;

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
volatile sig_atomic_t g_interrupted = 0;

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
int g_plain;   // --simple (or no terminal): app notes go to stdout

void push_log(const char *fmt, ...) {
    char msg[TUI_LINE_MAX];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    char hhmm[HHMM_LEN]; current_hhmm(hhmm);
    if (g_plain) { printf("[%s] %s\n", hhmm, msg); fflush(stdout); return; }
    tui_scrollback_push(g_app.selected ? &g_app.selected->console : &g_app.log, hhmm, msg, NULL, 0, 0);
    g_app.dirty = 1;
}

// While set, the first line a session prints to its console goes on the bottom bar too: the reply to
// a file action, which would otherwise only reach a console that may be hidden, or not on screen.
int g_echo;

void session_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                          unsigned flags, int color_len, int file) {
    session_slot_t *s = (session_slot_t *)ui;
    if ((flags & LINE_CHAT) && s->hist) history_add(s, text, rgb, (flags & LINE_MENTION) != 0, color_len);
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

int session_ready(const session_slot_t *s) { return !s->initialising && chat_ready(&s->engine); }

pic_t *pic_find(session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used && s->pics[i].num == num) return &s->pics[i];
    return NULL;
}

static void pic_free(pic_t *p) {
    thumb_free(&p->th);
    memset(p, 0, sizeof *p);
}

static void pics_free(session_slot_t *s) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used) pic_free(&s->pics[i]);
}

const tui_image_t *pic_for(const void *ctx, int file) {
    const session_slot_t *s = ctx;
    for (int i = 0; i < MAX_PICS; i++)
        if (s->pics[i].used && s->pics[i].num == file && s->pics[i].shown && s->pics[i].th.rgb) return &s->pics[i].ti;
    return NULL;
}

const char *pic_why(const session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++)
        if (s->pics[i].used && s->pics[i].num == num && !s->pics[i].th.rgb && s->pics[i].why[0]) return s->pics[i].why;
    return NULL;
}

// The progress of a fetch, as its row in the chat and the picture page say it.
int fetch_progress(const chat_t *e, const file_entry_t *f, char *text, size_t cap) {
    if (f->dl == DL_QUEUED) {
        int after = chat_file_queued_after(e, f);
        if (after) snprintf(text, cap, "queued" DOT_SEP "starts after file %d", after);
        else snprintf(text, cap, "queued" DOT_SEP "waiting for its sender");
        return 0;
    }
    uint64_t got = chat_file_got(f);
    int permille = f->size ? (int)(got * 1000 / f->size) : 1000;
    char gs[32], all[32], eta[64];
    file_format_size(got, gs, sizeof gs);
    file_format_size(f->size, all, sizeof all);
    double left = chat_file_eta(e, f, now_seconds());
    if (left >= 0.0) { file_format_duration(left, eta, sizeof eta); strcat(eta, " left"); }
    else copy_str(eta, left < ETA_AWAY ? "waiting until verify codes are compared" : "waiting for its sender", sizeof eta);
    snprintf(text, cap, "%d%%" DOT_SEP "%s of %s" DOT_SEP "%s", permille / 10, gs, all, eta);
    return permille;
}

// The row under the line that offered a file: how a fetch is going (through the relays it can take
// a long time), where it was saved or why it failed, and for one of ours, who's fetching it or has.
const tui_progress_t *progress_for(const void *ctx, int file) {
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
            snprintf(pg.text, sizeof pg.text, "%d%%" DOT_SEP "sending to %s%s", pm / 10, name, n > 1 ? " and others" : "");
        } else if (to[0]) {
            pg.kind = TUI_PROGRESS_DONE;
            snprintf(pg.text, sizeof pg.text, "sent to %s%s", to, f->fp ? "" : DOT_SEP "no longer offered");
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
        snprintf(pg.text, sizeof pg.text, "%s" DOT_SEP ":%s %d tries again", f->why[0] ? f->why : "it didn't finish",
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
        snprintf(pg.text, sizeof pg.text, "can't show it: %s" DOT_SEP ":download %d saves it", why, f->num);
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
void session_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
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

void session_notify(void *ui, const char *nick, const char *text, int mentioned) {
    (void)ui;
    send_notification(nick, text, mentioned);
}

int slot_index(session_slot_t *s) { return (int)(s - g_app.sessions); }

session_slot_t *find_free_slot(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) if (!g_app.used[i]) return &g_app.sessions[i];
    return NULL;
}

// The conversation and console on screen are kept out of swap, like the keys. Best effort: beyond
// RLIMIT_MEMLOCK they're just kept in memory as normal.
void lock_scrollbacks(session_slot_t *s) {
    crypto_lock(&s->sb, sizeof s->sb);
    crypto_lock(&s->console, sizeof s->console);
}

// Zeroes them as it unlocks them.
void release_scrollbacks(session_slot_t *s) {
    crypto_unlock(&s->sb, sizeof s->sb);
    crypto_unlock(&s->console, sizeof s->console);
}

// Puts s on screen (or none). The session being left loses its new messages line, and s gets one
// above what arrived while it was away, which then counts as read.
void select_session(session_slot_t *s) {
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
session_slot_t *first_session(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) return &g_app.sessions[i];
    return NULL;
}

void close_session(session_slot_t *s) {
    if (!s) return;
    int idx = slot_index(s);
    view_forget(s);
    history_stop(s, 1);
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

void select_step(int dir) {
    session_slot_t *vis[MAX_SESSIONS]; int n = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) vis[n++] = &g_app.sessions[i];
    if (n == 0) { select_session(NULL); return; }
    int cur = 0;
    for (int i = 0; i < n; i++) if (vis[i] == g_app.selected) { cur = i; break; }
    select_session(vis[(cur + dir + n) % n]);
}

void console_note(session_slot_t *s, const char *fmt, ...) {
    char msg[300];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    char hhmm[HHMM_LEN]; current_hhmm(hhmm);
    tui_scrollback_push(&s->console, hhmm, msg, NULL, 0, 0);
    g_app.dirty = 1;
}

// The result of the user's last action, on the bottom bar until their next key. Reports and
// anything that happens by itself go to the console instead.
void note(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_app.message, sizeof g_app.message, fmt, ap);
    va_end(ap);
    g_app.dirty = 1;
}

// Asks the terminal to put text (up to OSC52_MAX bytes) on the clipboard. A terminal that doesn't allow OSC 52 ignores it.
#define OSC52_MAX 1024   // a PGP public key fits

void osc52_copy(const char *text) {
    size_t n = strlen(text);
    if (n > OSC52_MAX) n = OSC52_MAX;
    char b64[BASE64_LEN(OSC52_MAX) + 1];
    base64_encode((const uint8_t *)text, n, b64);
    char osc[sizeof b64 + 16];
    snprintf(osc, sizeof osc, "\x1b]52;c;%s\x07", b64);
    platform_write_stdout(osc, strlen(osc));
}

void copy_session_id(session_slot_t *s) {
    if (!s) { note("no session selected - nothing to copy"); return; }
    const char *sid = s->engine.session_name;
    osc52_copy(sid);
    note("session id copied to the clipboard (OSC 52): %s", sid);
}

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

// The choices, by their numbers above.
enum { CHOICE_DHT_NOSTR = 1, CHOICE_DHT, CHOICE_TOR };

// A routing choice doesn't override --nonostr or --nostr-always. DHT + Nostr uses the relays as
// those options say, and only DHT alone turns the relays off.
static void apply_route_choice(int choice) {
    if (choice == CHOICE_TOR) {
        g_app.route.mode = ROUTE_TOR;
    } else {
        g_app.route.mode = ROUTE_DHT;
        g_app.route.nostr = choice == CHOICE_DHT ? NOSTR_OFF : g_app.nostr_flag >= 0 ? g_app.nostr_flag : NOSTR_FALLBACK;
    }
    g_app.route_chosen = 1;
}

const char *route_label(void) {
    if (g_app.route.mode == ROUTE_TOR) return "Tor onion services only";
    return g_app.route.nostr == NOSTR_ALWAYS ? "DHT, with Nostr relays always"
         : g_app.route.nostr ? "DHT, with Nostr relay fallback" : "DHT only";
}

static int run_plain(const char *session_name, const char *password, uint16_t port,
                     const char peer_args[][PEER_ARG_LEN], int n_peer_args);

// The longest the main loops wait for a socket or a key before doing their timed work.
#define WAIT_MS 200
// The full-screen UI: the window's title saved and set to chat, then the alternate screen, cleared.
// Leaving it undoes that.
#define SCREEN_ENTER "\x1b[22;0t\x1b]0;chat\x07\x1b[?1049h\x1b[2J\x1b[H"
#define SCREEN_LEAVE "\x1b[?7h\x1b[0 q\x1b[?25h\x1b[?1049l\x1b[23;0t"

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
    fputs(SCREEN_ENTER TUI_THEME_WATCH, stdout);
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

    // Once a second at least, for the clock.
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
            // Beyond the limit a socket just waits for the next tick, WAIT_MS at most.
            for (int j = 0; j < ns && n < PLATFORM_WAIT_MAX; j++) { socks[n] = mine[j]; owner[n] = &g_app.sessions[i]; n++; }
        }
        int stdin_ready = 0;
        platform_wait(socks, n, ready, &stdin_ready, WAIT_MS);

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
        history_sync(now);

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
    fputs(TUI_THEME_UNWATCH SCREEN_LEAVE, stdout);
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
    thumb_free(&th);
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
        copy_str(o.session_name, line, sizeof o.session_name);
    }
    if (!o.session_name[0]) {
        // Without a terminal too: no fixed default, since a well known id with a blank password would
        // be a room anyone can join.
        random_session_id(o.session_name, SESSION_ID_LEN);
        o.created = 1;
        printf("new session id: %s  (share this and the password)\n", o.session_name);
    }

    if (password) copy_str(o.password, password, sizeof o.password);
    else if (platform_env_take("CHAT_PASSWORD", o.password, sizeof o.password) != 0 && tty
             && term_read_password(o.created ? "create password: " : "password: ", o.password, sizeof o.password) != 0)
        return 1;

    o.port = port;
    if (!g_app.route_chosen) {
        // Without a terminal to ask, --nonostr means DHT only.
        int choice = g_app.nostr_flag == NOSTR_OFF ? CHOICE_DHT : CHOICE_DHT_NOSTR;
        if (tty) {
            // Without the "* " the log puts first.
            for (size_t i = 0; i < COUNT_OF(ROUTE_CHOICE_LINES); i++)
                printf("%s\n", ROUTE_CHOICE_LINES[i] + 2);
            char line[16];
            if (term_read_line("routing [1/2/3, Enter = 1]: ", line, sizeof line) != 0) return 1;
            if (line[0] >= '0' + CHOICE_DHT_NOSTR && line[0] <= '0' + CHOICE_TOR) choice = line[0] - '0';
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
    for (int i = 0; i < n_peer_args && o.n_peers < (int)COUNT_OF(o.peers); i++) {
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
    app_session_opts(&o);

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
    char idhex[SHORT_ID_HEX + 1]; hex_encode(c.my_id, SHORT_ID_LEN, idhex);
    if (c.route.mode == ROUTE_TOR)
        printf("session '%s', you are %s (peer %s). encrypted, over Tor only. :quit or EOF to stop.\n",
               c.session_name, c.nick, idhex);
    else
        printf("session '%s', you are %s (peer %s). encrypted, udp/%u, routing: %s. :quit or EOF to stop.\n",
               c.session_name, c.nick, idhex, (unsigned)c.port, route_label());

    catch_quit_signals();
    stdin_reader_t *reader = stdin_reader_start();
    int alive = 1;
    // No box to ask in here, so a second press within CTRL_C_AGAIN seconds confirms. From a script,
    // Ctrl+C still quits at once.
    enum { CTRL_C_AGAIN = 3 };
    double ctrl_c_at = -CTRL_C_AGAIN;
    while (alive && !g_interrupted) {
        sock_t socks[CHAT_MAX_SOCKS]; int ns = chat_sockets(&c, socks);
        int ready[CHAT_MAX_SOCKS] = {0};
        net_wait(socks, ready, ns, WAIT_MS);
        double now = now_seconds();
        if (g_ctrl_c) {
            g_ctrl_c = 0;
            if (!term_is_tty() || now - ctrl_c_at < CTRL_C_AGAIN) break;
            ctrl_c_at = now;
            push_log("* Ctrl+C again within %d seconds leaves the session and quits (so does :quit)", CTRL_C_AGAIN);
        }
        for (int i = 0; i < ns; i++) if (ready[i]) chat_on_socket_readable(&c, socks[i], now);
        char line[MAX_TEXT + 1];
        int rc = stdin_reader_poll(reader, line, sizeof line);
        static const char show[] = ":show ";
        int show_anyway, show_n = rc == 1 && starts_with(line, show) ? file_arg(line + sizeof show - 1, &show_anyway) : 0;
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
            if (!argv[i][0] || *end || port < 0 || port > UINT16_MAX) {
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
        } else if (strcmp(key, "betas") == 0) {
            g_app.betas = 1;
        } else if (strcmp(key, "verify-optional") == 0) {
            g_app.verify_optional = 1;
        } else if (strcmp(key, "verify-required") == 0) {
            g_app.verify_optional = 0;
        } else if (strcmp(key, "routing") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            // direct+nostr and direct: the modes' old names, still accepted.
            if (strcmp(v, "dht+nostr") == 0 || strcmp(v, "nostr") == 0 || strcmp(v, "direct+nostr") == 0)
                apply_route_choice(CHOICE_DHT_NOSTR);
            else if (strcmp(v, "dht") == 0 || strcmp(v, "direct") == 0) apply_route_choice(CHOICE_DHT);
            else if (strcmp(v, "tor") == 0) apply_route_choice(CHOICE_TOR);
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
            char found[TOR_PATH_MAX];
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

void reapply_options(void) {
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
            enum { TOR_WAIT_S = 120, TOR_POLL_MS = 100 };
            net_startup();
            g_plain = 1;
            double give_up = now_seconds() + TOR_WAIT_S;
            tor_link_ensure(now_seconds());
            while (g_tor.state != TL_READY && g_tor.state != TL_FAILED && now_seconds() < give_up) {
                tor_link_step(now_seconds());
                platform_sleep_ms(TOR_POLL_MS);
            }
            if (g_tor.state != TL_READY) {
                fprintf(stderr, "chat: no tor to download through - not updating\n");
                tor_link_stop();
                return 1;
            }
            sync_update_proxy();
        }
        printf("chat: checking GitHub for a newer release%s (v" CHAT_VERSION " here)%s...\n",
               g_app.betas ? " or beta" : "", over_tor ? " through Tor" : "");
        fflush(stdout);
        char msg[UPDATE_MSG_MAX];
        int rc = update_run(g_app.betas, msg, sizeof msg);
        if (over_tor) tor_link_stop();
        const char *text = starts_with(msg, UPDATE_PREFIX) ? msg + sizeof UPDATE_PREFIX - 1 : msg;
        fprintf(rc == 0 ? stdout : stderr, "chat: %s\n", text);
        return rc == 0 ? 0 : 1;
    }

    net_startup();

    int interactive = !o->simple && term_is_tty() && term_stdout_is_tty() && term_ansi_ok();
    // NO_COLOR (no-color.org) limits the UI to bold, faint and reverse.
    const char *no_color = getenv("NO_COLOR");
    g_app.color_enabled = interactive && !(no_color && no_color[0]);
    if (o->has_color) memcpy(g_app.color, o->color, 3);
    else chat_random_colour(g_app.color);
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
            char pw[MAX_PASSWORD + 1] = "";
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

    char explicit_password[MAX_PASSWORD + 1] = "";
    if (platform_env_take("CHAT_PASSWORD", explicit_password, sizeof explicit_password) != 0
        && term_read_password("password: ", explicit_password, sizeof explicit_password) != 0) return 1;
    int rc = run_tui(o->session, explicit_password, o->port, o->peers, o->n_peers);
    crypto_wipe(explicit_password, sizeof explicit_password);
    return rc;
}
