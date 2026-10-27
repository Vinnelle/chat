// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"

static const char *USAGE =
    "usage: chat [--nick NAME] [--colour NAME|#HEX] [--identity age|pgp[-nonick|:KEYFILE]]\n"
    "            [--simple] [--save NAME]\n"
    "            [--routing udp|tor] [--nodht] [--noipv6] [--nolan] [--noportmap]\n"
    "            [--nostr off|fallback|always] [--relay wss://HOST ...]\n"
    "            [--tor-launch auto|always|never] [--tor-path PATH] [--tor-socks HOST:PORT]\n"
    "            [--tor-control HOST:PORT] [--verify-required] [--file-limit SIZE]\n"
    "            [--fast-files] [--betas] [--nosandbox]\n"
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
    "  Ctrl+N     create a new session: a random password is filled in, or type your own\n"
    "  Ctrl+J     join a session: its id, then its password, or an invite (:invite); or a kept one\n"
    "  Tab        next session       Shift+Tab   previous session (j/k in NORMAL too)\n"
    "  PgUp/PgDn  scroll the chat back and forward (Ctrl+U/Ctrl+D in NORMAL, G the newest)\n"
    "  Up/Down    scroll the chat by a message. The mouse wheel scrolls what it's over: the\n"
    "             chat, the console, or the sessions or peers when there are more than fit\n"
    "             (hold Shift to select text with the mouse)\n"
    "  Ctrl+B     hide/show the sidebar   Ctrl+O   hide/show the console\n"
    "  Ctrl+T     hide/show the chat (hide two of the three and the last one fills the screen)\n"
    "  Ctrl+S     settings: routing, identity, files, notifications (also :set)\n"
    "  Ctrl+F     files offered here and yours: show, save or stop them (f in NORMAL, :files)\n"
    "  F1         list all commands and keybinds (also ? in NORMAL, and :help)\n"
    "  Ctrl+C     quit chat: twice, or y (sessions leave, or go offline with :set reopen on)\n"
    "  Ctrl+L     lock the screen (also :lock): the save's passphrase, or a PIN, unlocks it\n"
    "  Ctrl+\\     panic: clear the screen and quit at once, without asking. :set lockkey and\n"
    "             :set panickey choose other keys, or none\n"
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
    "A paste goes into the input as text, its lines run together, and waits for Enter.\n"
    "Prompts (a password, a session id, a setting's new value, a question) open in a box\n"
    "over the screen. Enter confirms, Esc cancels, a question takes y or n, and whatever you\n"
    "were typing comes back afterwards.\n"
    "\n"
    "Commands run from the command line (/ on an empty line, or : in NORMAL). Anything else\n"
    "you type is sent:\n"
    "  :new :join :quit (:q) :quitall (:qa) :copyid :invite :update :peers :verify NICK [ok|no]\n"
    "  :net :verified [forget NICK] :port [N] :set [NAME [VALUE]] :install :uninstall :help\n"
    "  :send [PATH] :files :download [N] :show N :hide N :cancel N :keep [LABEL|forget]\n"
    "  :call NICK (a room only you and a verified key can work out)\n"
    "  :ignore NICK [off] (hide what a peer says, on your screen only)\n"
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
    ":set lock 5m locks the screen after five minutes without a key. Locked, nothing shows but a\n"
    "box for the save's passphrase, where wrong ones count toward :set destroy and the shadow one\n"
    "panics. :set panicwipe on makes the panic key delete the open save too.\n"
    "\n"
    "  --save      open the save with this name, without the list\n"
    "              (default is the one in ~/.config/chat itself). If there's no save\n"
    "              with that name, chat starts from its defaults and :install makes it\n"
    "  --nick      display name. A random one (like \"swift-otter42\") is used if omitted.\n"
    "              :set nick changes it at any time, for every session\n"
    "  --colour    your display colour in every session; random by default (--color too)\n"
    "  --routing   how sessions reach peers, preset on the settings page chat opens on.\n"
    "              udp: UDP straight between peers, found through the BitTorrent DHT\n"
    "              (IPv4 and IPv6), the LAN and router port mapping. Peers see your IP\n"
    "              address. tor: Tor onion services, which hide it. UDP and Tor members\n"
    "              only reach each other on the Nostr relays\n"
    "  --nodht     don't use the BitTorrent DHT (IPv4 and IPv6)\n"
    "  --noipv6    don't use the IPv6 DHT\n"
    "  --nolan     don't use LAN broadcast discovery\n"
    "  --noportmap don't ask the router to forward a port (UPnP-IGD, NAT-PMP, PCP)\n"
    "  --nostr     the Nostr relays, which carry encrypted traffic the route can't,\n"
    "              through Tor with tor routing. fallback (default): only while they're\n"
    "              needed. always: stay connected, so members on the other route can\n"
    "              find a room whose members all reach each other. off: none, so UDP\n"
    "              and Tor members can't reach each other\n"
    "  --verify-required\n"
    "              send nothing to a peer until you've compared its verify code. By\n"
    "              default messages go to everyone, compared or not\n"
    "  --file-limit\n"
    "              the largest file fetched without adding anyway (default 8M; up to 1G)\n"
    "  --fast-files\n"
    "              send files in quick bursts instead of chat's regular slots. It takes\n"
    "              seconds instead of minutes, but the transfer is visible on the network.\n"
    "              Through the relays (Tor and UDP members) it goes as often as they\n"
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
    "              from it, your nick and this device's machine id. The same password\n"
    "              and nick on the same device and OS always give the same key, so keep\n"
    "              both to keep your signing identity; a new nick asks for the password\n"
    "              again. A blank password gives a new key each run.\n"
    "              age-nonick, pgp-nonick: the key from the password and machine id\n"
    "              alone, as earlier versions made it, whatever your nick.\n"
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
    "  --nosandbox don't put the sandbox up for this run (Linux; :set sandbox off keeps it\n"
    "              down)\n"
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

volatile sig_atomic_t g_ctrl_c = 0;

// SIGQUIT panics: in --simple the terminal sends it for Ctrl+\, and the full-screen UI only gets it
// from a kill -QUIT. With the panic key off, it quits like SIGTERM.
volatile sig_atomic_t g_sigquit = 0;

static void on_quit_signal(int sig) {
    if (sig == SIGINT) g_ctrl_c = 1;
#ifdef SIGQUIT
    else if (sig == SIGQUIT) g_sigquit = 1;
#endif
    else g_interrupted = 1;
#ifdef _WIN32
    // The Windows C runtime puts the default back before calling a handler.
    signal(sig, on_quit_signal);
#endif
}

// A kill, a closed terminal or a confirmed Ctrl+C all end the main loop, so sessions say bye (or go
// offline, if kept), keys are wiped, the terminal is restored and chat's own tor is stopped, instead
// of the process just dying. The handler has to stay in place for a second signal too. With plain
// signal() and _POSIX_C_SOURCE, glibc resets it after the first, and a second Ctrl+C or kill skipped
// all of that.
void catch_quit_signals(void) {
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
    sigaction(SIGQUIT, &sa, NULL);
#endif
}

// When scrolled back, a console stays on the lines in view, as the chat does.
void push_console(tui_scrollback_t *sb, int *scroll, const char *hhmm, const char *text, const uint8_t *rgb) {
    tui_scrollback_push(sb, hhmm, text, rgb, 0, 0);
    if (*scroll > 0 && *scroll < sb->count - 1) (*scroll)++;
}

// App level notes go wherever the user is looking: the selected session's console, otherwise the startup log.
int g_plain;   // --simple (or no terminal): app notes go to stdout

void push_log(const char *fmt, ...) {
    char msg[TUI_LINE_MAX];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    char hhmm[HHMM_LEN]; current_hhmm(hhmm);
    if (g_plain) { printf("[%s] %s\n", hhmm, msg); fflush(stdout); return; }
    session_slot_t *s = g_app.selected;
    push_console(s ? &s->console : &g_app.log, s ? &s->console_scroll : &g_app.log_scroll, hhmm, msg, NULL);
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

void choose_route(route_mode_t m) {
    g_app.route.mode = m;
    g_app.route_chosen = 1;
}

const char *route_label(void) {
    static const char *const RELAYS[] = { "without relays", "with Nostr relay fallback", "with Nostr relays always" };
    static char label[64];
    snprintf(label, sizeof label, "%s, %s", g_app.route.mode == ROUTE_TOR ? "Tor onion services" : "UDP",
             RELAYS[g_app.route.nostr]);
    return label;
}

static int name_index(const char *v, const char *const *names, int n) {
    for (int i = 0; i < n; i++) if (strcmp(v, names[i]) == 0) return i;
    return -1;
}

// How long a sequence a read cut off waits for the rest.
#define KEY_CUT_WAIT_MS 25
// A paste comes all at once. One whose end hasn't come after this long without input never will, so
// keys are keys again.
#define PASTE_GAP_MAX 2.0
// The full-screen UI: the window's title saved and set to chat, the mouse reported, then the
// alternate screen, cleared. Leaving it undoes that.
#define SCREEN_ENTER "\x1b[22;0t\x1b]0;chat\x07" TUI_MOUSE_ON TUI_PASTE_ON "\x1b[?1049h\x1b[2J\x1b[H"
#define SCREEN_LEAVE "\x1b[?7h\x1b[0 q\x1b[?25h" TUI_MOUSE_OFF TUI_PASTE_OFF "\x1b[?1049l\x1b[23;0t"
#define CLEAR_SCREEN "\x1b[2J\x1b[H"
#define CLEAR_SCROLLBACK "\x1b[3J"

const char *const PANIC_KEY_NAMES[N_PANIC_KEYS] = { "off", "ctrl+\\", "ctrl+q", "ctrl+x", "f12" };

static const tui_keytype_t PANIC_KEYS[N_PANIC_KEYS] = {
    TUI_KEY_NONE, TUI_KEY_CTRL_BACKSLASH, TUI_KEY_CTRL_Q, TUI_KEY_CTRL_X, TUI_KEY_F12
};

int panic_key_is(const tui_key_t *key) { return g_app.panic.key > 0 && key->type == PANIC_KEYS[g_app.panic.key]; }

panic_t g_panic;

// The screen goes first, before anything that can take time: cleared before it's left, so nothing of
// it lingers, then the one it goes back to cleared too. --simple's lines are in the terminal's
// scrollback, so that goes as well. The main loop ends without drawing another frame, and the rest is
// in its ending: no question, and nothing saved but what panic.history keeps.
void panic(panic_t why) {
    if (g_panic) return;
    g_panic = why;
    g_interrupted = 1;
    if (g_plain) {
        static const char clear[] = CLEAR_SCREEN CLEAR_SCROLLBACK;
        if (term_stdout_is_tty() && term_ansi_ok()) platform_write_stdout(clear, sizeof clear - 1);
        return;
    }
    clipboard_clear_now();
    static const char out[] = CLEAR_SCREEN TUI_THEME_UNWATCH SCREEN_LEAVE CLEAR_SCREEN;
    platform_write_stdout(out, sizeof out - 1);
    term_raw_disable();
}

// Before chat first reaches the network, so whatever it reads from there (DHT packets, relay
// messages, pictures) is read inside it.
void sandbox_up(void) {
    static int done;
    if (done) return;
    done = 1;
#ifdef __linux__
    if (!g_app.sandbox || g_opts.nosandbox) {
        push_log("* sandbox: off %s", g_opts.nosandbox ? "for this run (--nosandbox)" : "- :set sandbox on puts it up from the next start");
        return;
    }
    // tor, and the transport programs its bridges can need, even with none set yet.
    char found[4][TOR_PATH_MAX], why[160];
    const char *run[4];
    int tor = platform_find_program("tor", g_app.tor.path, found[0], sizeof found[0]) == 0;
    int n = tor ? 1 + transport_paths(found + 1, 3) : 0;
    for (int i = 0; i < n; i++) run[i] = found[i];
    // Once the sandbox is up, nothing chat starts is outside it.
    if (g_app.updater) update_helper_start();
    unsigned up = g_app.sandboxed = platform_sandbox(run, n, NULL, why, sizeof why);
    if (!(up & PLATFORM_SANDBOX_FILES)) update_helper_stop();
    if (up & PLATFORM_SANDBOX_FILES)
        push_log("* sandbox: on - from now on chat%s can only write to the folders in your home that aren't hidden or on "
                 "PATH, its own folder and the temporary folders, and only run %s%s", tor ? " and tor" : "",
                 n > 1 ? "tor and its transport programs" : tor ? "tor" : "nothing else", up & PLATFORM_SANDBOX_CALLS
                 ? "; calls chat never makes (ptrace, mount, bpf...) are refused" : "");
    else if (up & PLATFORM_SANDBOX_CALLS)
        push_log("* sandbox: partly up - calls chat never makes are refused, but %s, so it can still write anywhere you can",
                 why);
    else
        push_log("* sandbox: not up - %s", why);
#endif
}

// The open save goes first with panic.wipe, unless the shadow passphrase has put the decoy in its place.
// The histories kept are dropped unwritten, unless panic.history keeps them.
void panic_saves(void) {
    int wipe = g_panic == PANIC_KEY && g_app.panic.wipe && g_app.installed && !g_app.locked;
    if (wipe && install_remove(install_current()) == 0) g_app.installed = 0;
    int keep = g_panic == PANIC_KEY && g_app.panic.history && !wipe;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_app.used[i] && !keep) history_stop(&g_app.sessions[i], 0);
}

// The terminal's state while the full-screen UI runs, and the first frame.
static void open_tui(const char *explicit_session, char *explicit_password, uint16_t explicit_port,
                     const char peer_args[][PEER_ARG_LEN], int n_peer_args) {
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
        copy_str(g_app.autostart.session, explicit_session, sizeof g_app.autostart.session);
        copy_str(g_app.autostart.password, explicit_password, sizeof g_app.autostart.password);
        g_app.autostart.port = explicit_port;
        for (int i = 0; i < n_peer_args && i < MAX_PEER_ARGS; i++)
            copy_str(g_app.autostart.peer_args[i], peer_args[i], PEER_ARG_LEN);
        g_app.autostart.n_peers = n_peer_args < MAX_PEER_ARGS ? n_peer_args : MAX_PEER_ARGS;
        crypto_wipe(explicit_password, strlen(explicit_password));
    }

    // Everything is set up on the settings page first, and its button starts chat. If installed, the
    // saved settings are used, so chat starts straight away.
    g_app.onboarding = 1;
    settings_select(0);
    g_app.mode = MODE_SETTINGS;
    if (g_app.install.unlock_at_start) {
        begin_prompt(save_to_pick() ? MODE_SAVES : MODE_UNLOCK);
        // CHAT_INSTALL_PASSWORD's passphrase, for a save that needs its security key or a code too.
        if (g_app.install.unlock_env) {
            g_app.install.unlock_env = 0;
            unlock_go(KP_UNLOCK);
        }
    } else {
        settle_start();
        if (g_app.installed && install_has_settings(install_current())) settings_done();
    }
    render();
}

// The sockets of the sessions running, waited on with the keyboard, and which of them can be read.
typedef struct {
    sock_t socks[PLATFORM_WAIT_MAX];
    session_slot_t *owner[PLATFORM_WAIT_MAX];
    int ready[PLATFORM_WAIT_MAX];
    int n, stdin_ready;
} waited_t;

static void wait_for_input(waited_t *w, int wait_ms) {
    w->n = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        sock_t mine[CHAT_MAX_SOCKS];
        int ns = chat_sockets(g_app.sessions[i].engine, mine);
        // Beyond the limit a socket just waits for the next tick, WAIT_MS at most.
        for (int j = 0; j < ns && w->n < PLATFORM_WAIT_MAX; j++) { w->socks[w->n] = mine[j]; w->owner[w->n] = &g_app.sessions[i]; w->n++; }
    }
    w->stdin_ready = 0;
    platform_wait(w->socks, w->n, w->ready, &w->stdin_ready, wait_ms);
}

static void take_signals(void) {
    if (g_ctrl_c) {
        g_ctrl_c = 0;
        // A second one quits once the QUIT box shows, as a second Ctrl+C key does.
        if (g_app.asking_quit && !g_app.lock.on) g_interrupted = 1;
        else { g_app.asking_quit = 1; g_app.dirty = 1; }
    }
    if (g_sigquit) {
        g_sigquit = 0;
        if (g_app.panic.key) panic(PANIC_KEY);
        else g_interrupted = 1;
    }
}

// Keys as the terminal sends them: what a read cut off, waiting for the rest, and whether a paste is
// coming in.
typedef struct {
    uint8_t cut[TUI_KEY_CUT_MAX];
    size_t n_cut;
    double cut_at;
    int pasting;
    double paste_at;
} key_reader_t;

static void read_keys(key_reader_t *r, int stdin_ready) {
    // A read can stop partway through a sequence: Windows hands over input a few dozen characters
    // at a time, and a burst of mouse wheel reports can fill buf. What's cut off waits for the
    // rest, which comes straight after, rather than being typed as text. An Esc on its own waits
    // too, then it's the key.
    int cut_due = r->n_cut && now_seconds() - r->cut_at >= KEY_CUT_WAIT_MS / 1000.0;
    if ((stdin_ready || cut_due) && !g_panic) {
        uint8_t buf[512];
        memcpy(buf, r->cut, r->n_cut);
        long got = stdin_ready ? term_read_raw(buf + r->n_cut, sizeof buf - r->n_cut) : 0;
        if (got < 0) {
            g_interrupted = 1;
        } else if (got > 0 || cut_due) {
            size_t len = r->n_cut + (size_t)got, off = 0;
            r->n_cut = got > 0 ? tui_key_cut(buf, len) : 0;
            len -= r->n_cut;
            memcpy(r->cut, buf + len, r->n_cut);
            r->cut_at = now_seconds();
            if (r->pasting) r->paste_at = now_seconds();
            while (len > off && !g_panic) {
                tui_key_t key;
                size_t used = tui_decode_key(buf + off, len - off, &key);
                if (used == 0) break;
                off += used;
                if (key.type == TUI_KEY_PASTE_START || key.type == TUI_KEY_PASTE_END) {
                    r->pasting = key.type == TUI_KEY_PASTE_START;
                    r->paste_at = now_seconds();
                } else if (r->pasting && !tui_key_paste(&key)) {
                    continue;
                }
                handle_key(&key);
            }
        }
    }
    if (r->pasting && now_seconds() - r->paste_at > PASTE_GAP_MAX) r->pasting = 0;
}

// The sessions' sockets and ticks, then everything else the app does on its own.
static void run_ticks(const waited_t *w, double now) {
    for (int i = 0; i < w->n; i++)
        if (w->ready[i]) chat_on_socket_readable(w->owner[i]->engine, w->socks[i], now);
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_app.used[i]) chat_tick(g_app.sessions[i].engine, now_seconds());
    move_tick(now_seconds());
    contacts_tick();
    reopen_tick();
    timers_tick(now_seconds());
    lock_tick();
    clipboard_tick(now_seconds());
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
}

static void redraw(double now, double *next_ui_tick) {
    // The terminal may have redrawn or reflowed the screen, so the next frame is sent in full.
    if (term_resized()) { g_app.dirty = 1; tui_invalidate(); }
    if (now >= *next_ui_tick) { *next_ui_tick = now + 1.0; g_app.dirty = 1; }
    if (g_app.dirty) { keep_settings_saved(); keep_sessions_saved(); render(); g_app.dirty = 0; g_app.input_dirty = 0; }
    else if (g_app.input_dirty) { render_bar(); g_app.input_dirty = 0; }
}

static _Noreturn void close_tui(void) {
    if (g_panic) panic_saves();
    else keep_sessions_saved();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i]) continue;
        chat_set_coming_back(g_app.sessions[i].engine, session_kept(&g_app.sessions[i]));
        close_session(&g_app.sessions[i]);
    }
    // After the sessions, so their onion services are removed with their control connections first.
    tor_link_stop();
    install_key_cancel();
    crypto_wipe(&g_app.input, sizeof g_app.input);
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    crypto_wipe(g_app.paste.buf, sizeof g_app.paste.buf);
    crypto_wipe(g_app.autostart.password, sizeof g_app.autostart.password);
    crypto_wipe(g_app.install.pass, sizeof g_app.install.pass);
    lock_forget();
    rooms_clear();
    ignore_clear();
    install_forget();
    tui_scrollback_clear(&g_app.log);

    // Back to the main screen with the cursor visible, its default shape and autowrap on, however
    // the last frame left them. A panic has done that already.
    if (!g_panic) {
        fflush(stdout);
        clipboard_clear_now();
        fputs(TUI_THEME_UNWATCH SCREEN_LEAVE, stdout);
        term_raw_disable();
    }
    fflush(stdout);
    net_shutdown();
    platform_notify_shutdown();

    _exit(0);
}

static int run_tui(const char *explicit_session, char *explicit_password, uint16_t explicit_port,
                    const char peer_args[][PEER_ARG_LEN], int n_peer_args) {
    term_watch_resize();
    if (term_raw_enable() != 0) {
        fprintf(stderr, "chat: this terminal can't do the full-screen UI, using --simple instead\n");
        if (g_app.install.unlock_at_start) unlock_at_start(0);
        if (!g_app.nick[0]) random_nickname(g_app.nick, sizeof g_app.nick);
        start_identity(0);
        return run_plain(explicit_session, explicit_password, explicit_port, peer_args, n_peer_args);
    }
    open_tui(explicit_session, explicit_password, explicit_port, peer_args, n_peer_args);

    // Once a second at least, for the clock.
    double next_ui_tick = now_seconds() + 1.0;
    lock_saw_key();
    key_reader_t keys = { 0 };
    while (!g_interrupted) {
        waited_t w;
        wait_for_input(&w, keys.n_cut ? KEY_CUT_WAIT_MS : WAIT_MS);
        take_signals();
        read_keys(&keys, w.stdin_ready);
        if (g_panic) break;
        double now = now_seconds();
        run_ticks(&w, now);
        redraw(now, &next_ui_tick);
    }
    close_tui();
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
        } else if (strcmp(key, "nostr") == 0 && i + 1 < argc) {
            int k = name_index(argv[++i], NOSTR_NAMES, 3);
            if (k < 0) { fprintf(stderr, "chat: --nostr takes off, fallback or always\n"); return 1; }
            g_app.route.nostr = k;
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
            int k = name_index(argv[++i], ROUTE_NAMES, 2);
            if (k < 0) { fprintf(stderr, "chat: --routing takes udp or tor\n"); return 1; }
            choose_route((route_mode_t)k);
        } else if (strcmp(key, "relay") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if (nostr_url_ok(v) != 0) { fprintf(stderr, "chat: bad --relay %s (want wss://host[:port][/path])\n", v); return 1; }
            if (!relays_given) { g_app.route.n_relays = 0; relays_given = 1; }
            if (g_app.route.n_relays >= NOSTR_MAX_RELAYS) { fprintf(stderr, "chat: at most %d --relay options\n", NOSTR_MAX_RELAYS); return 1; }
            copy_str(g_app.route.relays[g_app.route.n_relays++], v, NOSTR_URL_MAX);
        } else if (strcmp(key, "tor-launch") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "auto") == 0) g_app.tor.launch = TOR_LAUNCH_AUTO;
            else if (strcmp(v, "always") == 0) g_app.tor.launch = TOR_LAUNCH_ALWAYS;
            else if (strcmp(v, "never") == 0) g_app.tor.launch = TOR_LAUNCH_NEVER;
            else { fprintf(stderr, "chat: --tor-launch takes auto, always or never\n"); return 1; }
        } else if (strcmp(key, "tor-path") == 0 && i + 1 < argc) {
            char found[TOR_PATH_MAX];
            if (platform_find_program("tor", argv[++i], found, sizeof found) != 0) {
                fprintf(stderr, "chat: can't use %s as tor - it has to be a full path to a program only root or you can change\n", argv[i]);
                return 1;
            }
            copy_str(g_app.tor.path, found, sizeof g_app.tor.path);
        } else if ((strcmp(key, "tor-socks") == 0 || strcmp(key, "tor-control") == 0) && i + 1 < argc) {
            const char *v = argv[++i];
            if (!valid_host_port(v)) { fprintf(stderr, "chat: bad --%s %s (want host:port)\n", key, v); return 1; }
            copy_str(strcmp(key, "tor-socks") == 0 ? g_app.route.tor.socks : g_app.route.tor.control, v, TOR_HOST_MAX);
        } else if (strcmp(key, "simple") == 0) {
            o->simple = 1;
        } else if (strcmp(key, "nosandbox") == 0) {
            o->nosandbox = 1;
        } else if ((strcmp(key, "colour") == 0 || strcmp(key, "color") == 0) && i + 1 < argc) {
            if (parse_color(argv[++i], o->color) != 0) { fprintf(stderr, "chat: unknown colour %s\n", argv[i]); return 1; }
            o->has_color = 1;
        } else if (strcmp(key, "identity") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if ((strncmp(v, "age", 3) != 0 && strncmp(v, "pgp", 3) != 0)
                || (v[3] != '\0' && v[3] != ':' && strcmp(v + 3, "-nonick") != 0)) {
                fprintf(stderr, "chat: --identity takes age, pgp, age-nonick, pgp-nonick, age:KEYFILE or pgp:KEYFILE\n");
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

static void app_defaults(void) {
    routing_defaults(&g_app.route);
    g_app.notify_mode = NOTIFY_MENTIONS;
    g_app.verify_optional = 1;
    g_app.show.sidebar = g_app.show.console = g_app.show.chat = 1;
    g_app.lock.key = g_app.panic.key = 1;
    g_app.sandbox = g_app.updater = 1;
    g_app.picture_noise = 1;
    note_setting_defaults();
    trust_on_change(save_verified);
    ignore_on_change(save_ignored);
}

static void lock_app_secrets(void) {
    // The signing key, a pasted key block and typed passwords pass through these for the whole run.
    // Best effort, as in chat_init.
    crypto_lock(&g_app.identity, sizeof g_app.identity);
    crypto_lock(g_app.paste.buf, sizeof g_app.paste.buf);
    crypto_lock(&g_app.input, sizeof g_app.input);
    crypto_lock(&g_app.saved_input, sizeof g_app.saved_input);
    crypto_lock(&g_app.lock.input, sizeof g_app.lock.input);
    crypto_lock(g_app.autostart.password, sizeof g_app.autostart.password);
    crypto_lock(g_app.install.pass, sizeof g_app.install.pass);
    crypto_lock(g_app.key.start_password, sizeof g_app.key.start_password);
}

static int pick_save(const options_t *o) {
    // The save to open: the one --save names, the only one there is, or one picked later.
    g_app.install.n_saves = install_list(g_app.install.saves, INSTALL_SAVES_MAX);
    if (o->save[0]) install_use(o->save);
    else if (g_app.install.n_saves == 1) install_use(g_app.install.saves[0].name);
    int saved = o->save[0] ? save_exists(o->save) : g_app.install.n_saves > 0;
    if (o->save[0] && !saved && !o->update)
        saved_note("* there's no save called %s yet: chat starts from its defaults, and :install makes it",
                   install_shown_name(o->save));
    return saved;
}

// --update: what chat exits with.
static int run_update(int saved) {
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

static void identity_from_options(const options_t *o) {
    g_app.identity_source = IDENT_NONE;
    if (o->identity[0]) {
        identity_source_t kind = o->identity[0] == 'a' ? IDENT_AGE : IDENT_PGP;
        const char *path = o->identity[3] == ':' ? o->identity + 4 : NULL;
        if (!path) {
            // Like a session's password: from the environment, otherwise asked for, otherwise blank.
            char *pw = g_app.key.start_password;
            size_t cap = sizeof g_app.key.start_password;
            const char *prompt = o->identity[3]
                ? "signing key password (always the same one keeps the same key; blank for a new key): "
                : "signing key password (always the same one, with the same nick, keeps the same key; blank for a "
                  "new key): ";
            if (platform_env_take("CHAT_SIGN_PASSWORD", pw, cap) != 0 && term_is_tty()) term_read_password(prompt, pw, cap);
            g_app.key.start_pending = 1;
        } else if (!path[0] || load_key_file(kind, path) != 0)
            fprintf(stderr, "chat: could not load %s identity from %s\n", kind == IDENT_AGE ? "an AGE" : "a PGP",
                    path[0] ? path : "(no path given)");
    }
}

int main(int argc, char **argv) {
    platform_harden_process(SECRET_ENV);
    g_argc = argc;
    g_argv = copy_args(argc, argv);
    if (!g_argv) return 1;
    platform_hide_args(argc, argv);
    int link;
    if (g_argc == 2 && strcmp(g_argv[1], UPDATE_HELPER_ARG) == 0 && (link = platform_parent_link()) >= 0) {
        crypto_setup();
        return update_helper(link);
    }
    app_defaults();
    int exit_code = read_options(g_argc, g_argv, &g_opts);
    if (exit_code >= 0) return exit_code;
    const options_t *o = &g_opts;

    update_cleanup_stale();

    crypto_setup();
    device_check();
    update_self_build(&g_self_build);
    lock_app_secrets();

    int saved = pick_save(o);
    if (o->update) return run_update(saved);

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

    identity_from_options(o);

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
        start_identity(0);
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
