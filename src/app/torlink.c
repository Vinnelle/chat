// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"
#include "common/bytewords.h"

const char *const TOR_LAUNCH_NAMES[] = { "auto", "always", "never" };

// The session of --simple mode, which isn't in the session list.
chat_t *g_plain_engine;

tor_link_t g_tor;

// Downloads (:update) go through Tor whenever Tor mode is on: to the tor in use once there is one,
// and until then to a port nothing listens on, so they fail instead of going direct.
#define NO_PROXY "127.0.0.1:1"

void sync_update_proxy(void) {
    if (g_app.route.mode == ROUTE_UDP) update_set_proxy(NULL);
    else update_set_proxy(g_tor.state == TL_READY ? g_tor.socks : NO_PROXY);
}

// How long until chat looks for a tor again after there's none, and after its own stopped
// OWN_STARTS times in a row. A bootstrap is reported in steps of BOOT_STEP percent.
#define TOR_RETRY 30.0
#define OWN_TOR_RETRY 60.0
#define OWN_STARTS 3
#define BOOT_DONE 100
#define BOOT_STEP 25

// What chat's own tor takes at its control port, or NULL for a tor that was running already.
static const char *tor_link_password(void) {
    return g_tor.proc ? torproc_password(g_tor.proc) : NULL;
}

// fn on each session in Tor mode, --simple's too.
static void each_tor_session(void (*fn)(chat_t *e)) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_t *e = &g_app.sessions[i].engine;
        if (e->route.mode == ROUTE_TOR) fn(e);
    }
    if (g_plain_engine && g_plain_engine->route.mode == ROUTE_TOR) fn(g_plain_engine);
}

static void set_tor_ports(chat_t *e) { chat_tor_set_ports(e, g_tor.socks, g_tor.control, tor_link_password()); }

static void tor_link_apply(void) {
    each_tor_session(set_tor_ports);
    sync_update_proxy();
}

// Relays tried while tor was still connecting failed and backed off for up to five minutes, so
// once it's connected they're retried straight away.
static void tor_link_connected(void) { each_tor_session(chat_tor_connected); }

static void tor_link_fail(double now, double retry_in) {
    g_tor.state = TL_FAILED;
    g_tor.retry_at = now + retry_in;
}

// ---- bridges ----

#ifdef _WIN32
#define EXE ".exe"
#else
#define EXE ""
#endif
// What chat's own tor is given over its control port: UseBridges, the lines and a program or two.
#define BRIDGES_CONF_MAX (2 * TUI_LINE_MAX + 2 * TOR_PATH_MAX)

// The transport programs: lyrebird, or obfs4proxy, which it grew out of and which some systems still
// package (without webtunnel), and snowflake-client.
enum { PT_LYREBIRD, PT_OBFS4PROXY, PT_SNOWFLAKE, N_PT };
static const char *const PT_PROGRAMS[N_PT] = { "lyrebird", "obfs4proxy", "snowflake-client" };
static const struct { const char *name; int program; } TRANSPORTS[] = {
    { "obfs4", PT_LYREBIRD }, { "webtunnel", PT_LYREBIRD }, { "meek_lite", PT_LYREBIRD }, { "obfs3", PT_LYREBIRD },
    { "scramblesuit", PT_LYREBIRD }, { "snowflake", PT_SNOWFLAKE },
};
#define N_TRANSPORTS ((int)COUNT_OF(TRANSPORTS))
#define PLAIN N_TRANSPORTS

// The next bridge line in text from *at, trimmed: they're separated by ';' (or new lines, if a paste
// kept them). 0 once there are no more.
static int next_bridge(const char *text, size_t *at, char *out, size_t cap) {
    for (;;) {
        const char *s = text + *at;
        if (!*s) return 0;
        size_t n = strcspn(s, ";\r\n");
        *at += n + (s[n] != '\0');
        while (n && (*s == ' ' || *s == '\t')) { s++; n--; }
        while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) n--;
        if (!n || n >= cap) continue;
        memcpy(out, s, n);
        out[n] = '\0';
        return 1;
    }
}

// Its place in TRANSPORTS, PLAIN for a bridge without a transport (it starts with its address), or
// -1. Its first word goes in word.
static int bridge_kind(const char *line, char *word, size_t cap) {
    size_t n = strcspn(line, " ");
    snprintf(word, cap, "%.*s", (int)n, line);
    if (line[0] == '[' || (isdigit((unsigned char)line[0]) && memchr(line, ':', n))) return PLAIN;
    for (int i = 0; i < N_TRANSPORTS; i++) if (strcmp(word, TRANSPORTS[i].name) == 0) return i;
    return -1;
}

// Bridge lines as typed, as "LINE; LINE" in out. A line may start with "Bridge", as in a torrc.
// -1 with why for one tor couldn't take. Nothing of a line goes in why: they're kept out of the console.
int bridges_parse(const char *typed, char *out, size_t cap, char *why, size_t why_cap) {
    char line[TUI_LINE_MAX], word[32];
    size_t at = 0, p = 0;
    int n = 0, rc = 0;
    out[0] = '\0';
    while (rc == 0 && next_bridge(typed, &at, line, sizeof line)) {
        char *l = line;
        n++;
        for (char *c = l; *c; c++) if (*c == '\t') *c = ' ';
        if (strncasecmp(l, "Bridge ", 7) == 0) l += 7;
        while (*l == ' ') l++;
        for (const char *c = l; *c && rc == 0; c++)
            if (*c < ' ' || *c > '~' || *c == '"' || *c == '\\') {
                snprintf(why, why_cap, "bridge %d has a character bridge lines never have", n);
                rc = -1;
            }
        int k = rc == 0 ? bridge_kind(l, word, sizeof word) : PLAIN;
        // The first word is only shown if it looks like a transport's name, not an address.
        if (k < 0 && strspn(word, "abcdefghijklmnopqrstuvwxyz0123456789_") == strlen(word)) {
            snprintf(why, why_cap, "bridge %d: chat doesn't know the transport %.20s - it knows obfs4, webtunnel, "
                     "meek_lite, obfs3, scramblesuit and snowflake, or IP:PORT starts a plain bridge", n, word);
            rc = -1;
        } else if (k < 0) {
            snprintf(why, why_cap, "bridge %d starts with neither a transport nor an IP:PORT address", n);
            rc = -1;
        } else if (rc == 0 && k != PLAIN && !strchr(l, ' ')) {
            snprintf(why, why_cap, "bridge %d has no address after its transport", n);
            rc = -1;
        }
        if (rc == 0) {
            p = put_text(out, p, cap, n > 1 ? "; " : "");
            p = put_text(out, p, cap, l);
        }
    }
    if (rc == 0 && p >= cap) { copy_str(why, "too long", why_cap); rc = -1; }
    crypto_wipe(line, sizeof line);
    if (rc != 0) crypto_wipe(out, cap);
    return rc;
}

int bridge_count(const char *text, char *kinds, size_t cap) {
    char line[TUI_LINE_MAX], word[32];
    int n = 0, seen[N_TRANSPORTS + 1] = { 0 };
    size_t at = 0, p = 0;
    kinds[0] = '\0';
    while (next_bridge(text, &at, line, sizeof line)) {
        int k = bridge_kind(line, word, sizeof word);
        n++;
        if (k < 0 || seen[k]) continue;
        seen[k] = 1;
        p = put_text(kinds, p, cap, p ? ", " : "");
        p = put_text(kinds, p, cap, k == PLAIN ? "plain" : TRANSPORTS[k].name);
    }
    crypto_wipe(line, sizeof line);
    return n;
}

static char *last_sep(char *path) {
    char *at = NULL;
    for (; *path; path++) if (*path == '/' || *path == '\\') at = path;
    return at;
}

// A transport program: in the folder set for them, or else next to tor (or in a pluggable_transports
// or PluggableTransports folder there, as the Tor Expert Bundle and Tor Browser have them), on PATH
// or in the usual folders. Only one that only root or you can change. 0, or -1 if there's none.
static int transport_find(const char *name, char *out, size_t cap) {
    static const char *const NEAR_TOR[] = { "", "pluggable_transports/", "PluggableTransports/",
                                            "../pluggable_transports/" };
    char dir[TOR_PATH_MAX], path[TOR_PATH_MAX + 64];
    if (g_app.pt_dir[0]) {
        snprintf(path, sizeof path, "%s/%s" EXE, g_app.pt_dir, name);
        return platform_find_program(name, path, out, cap);
    }
    char *sep;
    if (platform_find_program("tor", g_app.tor_path, dir, sizeof dir) == 0 && (sep = last_sep(dir)) != NULL) {
        sep[1] = '\0';
        for (size_t i = 0; i < COUNT_OF(NEAR_TOR); i++) {
            snprintf(path, sizeof path, "%s%s%s" EXE, dir, NEAR_TOR[i], name);
            if (platform_find_program(name, path, out, cap) == 0) return 0;
        }
    }
    return platform_find_program(name, NULL, out, cap);
}

int transport_paths(char out[][TOR_PATH_MAX], int max) {
    int n = 0;
    for (int i = 0; i < N_PT && n < max; i++) n += transport_find(PT_PROGRAMS[i], out[n], TOR_PATH_MAX) == 0;
    return n;
}

void transport_line(char *out, size_t cap) {
    char path[TOR_PATH_MAX];
    int lyre = transport_find(PT_PROGRAMS[PT_LYREBIRD], path, sizeof path) == 0;
    int old = !lyre && transport_find(PT_PROGRAMS[PT_OBFS4PROXY], path, sizeof path) == 0;
    int snow = transport_find(PT_PROGRAMS[PT_SNOWFLAKE], path, sizeof path) == 0;
    const char *lyre_name = old ? "obfs4proxy" : "lyrebird";
    snprintf(out, cap, "%s: %s%s%s%s", g_app.pt_dir[0] ? g_app.pt_dir : "next to tor or on PATH",
             lyre || old ? lyre_name : "", (lyre || old) && snow ? " and " : "", snow ? "snowflake-client" : "",
             lyre || old || snow ? " found" : "neither lyrebird nor snowflake-client found");
}

// Quoted for SETCONF, where a backslash (in a Windows path) is escaped.
static size_t put_quoted(char *out, size_t p, size_t cap, const char *s) {
    p = put_text(out, p, cap, "\"");
    for (; *s && p < cap; s++) {
        char c[3] = { *s, '\0', '\0' };
        if (*s == '\\' || *s == '"') { c[0] = '\\'; c[1] = *s; }
        p = put_text(out, p, cap, c);
    }
    return put_text(out, p, cap, "\"");
}

// What chat's own tor is given over its control port with bridges set: UseBridges, a Bridge for each
// line and a ClientTransportPlugin for each program they need. -1 with why if one can't be used.
static int bridges_conf(char *out, size_t cap, char *why, size_t why_cap) {
    char line[TUI_LINE_MAX], word[32], program[TOR_PATH_MAX], plugin[TOR_PATH_MAX + 128];
    int need[N_PT] = { 0 }, webtunnel = 0;
    size_t at = 0, p = put_text(out, 0, cap, "UseBridges=1");
    while (next_bridge(g_app.bridges, &at, line, sizeof line)) {
        int k = bridge_kind(line, word, sizeof word);
        if (k >= 0 && k != PLAIN) need[TRANSPORTS[k].program] = 1;
        webtunnel |= k >= 0 && k != PLAIN && strcmp(TRANSPORTS[k].name, "webtunnel") == 0;
        p = put_text(out, p, cap, " Bridge=");
        p = put_quoted(out, p, cap, line);
    }
    crypto_wipe(line, sizeof line);
    for (int i = 0; i < N_PT; i++) {
        if (!need[i]) continue;
        int use = i;
        if (transport_find(PT_PROGRAMS[i], program, sizeof program) != 0) {
            use = i == PT_LYREBIRD && transport_find(PT_PROGRAMS[PT_OBFS4PROXY], program, sizeof program) == 0
                ? PT_OBFS4PROXY : -1;
            if (use < 0) {
                snprintf(why, why_cap, "%s, which isn't next to tor, on PATH or where :set transports says",
                         i == PT_SNOWFLAKE ? "snowflake bridges need snowflake-client"
                                           : "obfs4, webtunnel and meek_lite bridges need lyrebird (or obfs4proxy)");
                return -1;
            }
            if (webtunnel) {
                copy_str(why, "webtunnel bridges need lyrebird: obfs4proxy, found instead, doesn't have them", why_cap);
                return -1;
            }
        }
        if (strchr(program, ' ')) {
            snprintf(why, why_cap, "tor can't run %s from a folder with a space in its path - copy it to one without "
                     "and :set transports to that", PT_PROGRAMS[use]);
            return -1;
        }
        size_t q = 0;
        for (int k = 0; k < N_TRANSPORTS; k++) {
            if (TRANSPORTS[k].program != i || (use == PT_OBFS4PROXY && strcmp(TRANSPORTS[k].name, "webtunnel") == 0))
                continue;
            q = put_text(plugin, q, sizeof plugin, q ? "," : "");
            q = put_text(plugin, q, sizeof plugin, TRANSPORTS[k].name);
        }
        q = put_text(plugin, q, sizeof plugin, " exec ");
        q = put_text(plugin, q, sizeof plugin, program);
        p = put_text(out, p, cap, " ClientTransportPlugin=");
        p = put_quoted(out, p, cap, plugin);
    }
    if (p >= cap) { copy_str(why, "the bridge lines are too long", why_cap); return -1; }
    return 0;
}

// Kept from a tor that's stopping, and given to the next one.
static int keep_tor_state(void) {
    return g_app.tor_state && g_app.installed && !g_app.locked && !g_panic;
}

static void tor_link_start_own(double now) {
    char program[1024], err[160];
    if (platform_find_program("tor", g_app.tor_path, program, sizeof program) != 0) {
        if (g_app.tor_path[0])
            push_log("* tor: can't use %s as tor - it has to be a program only root or you can change", g_app.tor_path);
        else
            push_log("* tor: tor isn't installed. Install it (Arch: sudo pacman -S tor, Debian/Ubuntu: sudo apt install tor, "
                     "Windows: the Tor Expert Bundle), set where it is with :set torpath, or start Tor Browser");
        tor_link_fail(now, TOR_RETRY);
        return;
    }
    torproc_opts_t o = { 0 };
    if (g_app.bridges[0]) {
        static char conf[BRIDGES_CONF_MAX];
        char why[200];
        int rc = bridges_conf(conf, sizeof conf, why, sizeof why);
        crypto_wipe(conf, sizeof conf);
        if (rc != 0) {
            push_log("* tor: not starting chat's own tor: %s", why);
            tor_link_fail(now, TOR_RETRY);
            return;
        }
        o.hold_network = 1;
    }
    uint8_t *state = NULL;
    size_t state_len = 0;
    if (keep_tor_state() && install_read_tor(&state, &state_len) == 0) { o.state = state; o.state_len = state_len; }
    g_tor.proc = torproc_start(program, &o, err, sizeof err);
    if (state) { crypto_wipe(state, state_len); free(state); }
    if (!g_tor.proc) {
        push_log("* tor: couldn't start %s: %s%s", program, err, g_app.sandboxed & PLATFORM_SANDBOX_FILES
                 ? " - the sandbox only lets chat run the tor it found when it started" : "");
        tor_link_fail(now, TOR_RETRY);
        return;
    }
    g_tor.state = TL_STARTING;
    g_tor.boot_told = -1;
    g_tor.bridged = o.hold_network;
    if (g_app.net_log != NET_LOG_OFF)
        push_log("* tor: starting chat's own tor (%s)%s - its control port only takes a password made at random for "
                 "this run, which only chat knows (tor is given its hash), and its data is kept in a private temporary "
                 "folder, deleted when chat exits%s", program, o.hold_network ? " with your bridges" : "",
                 o.state ? ". It starts from the guards and directory kept in the save" : "");
}

// Makes sure Tor mode has a tor, or is getting one.
void tor_link_ensure(double now) {
    if (g_app.route.mode != ROUTE_TOR) return;
    if (g_tor.state == TL_FAILED && now >= g_tor.retry_at) g_tor.state = TL_OFF;
    if (g_tor.state != TL_OFF) return;
    // A tor that's running may not use the bridges.
    if (g_app.tor_launch == TOR_LAUNCH_ALWAYS || (g_app.tor_launch == TOR_LAUNCH_AUTO && g_app.bridges[0])) {
        tor_link_start_own(now);
        return;
    }
    g_tor.probe = tor_probe_new(&g_app.route.tor);
    if (!g_tor.probe) { tor_link_fail(now, TOR_RETRY); return; }
    g_tor.state = TL_PROBING;
}

void tor_link_step(double now) {
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
                if (g_app.net_log != NET_LOG_OFF)
                    push_log("* tor: using the tor that's already running (control port %s) - it keeps its entry "
                             "guards and any bridges it's set up with%s", g_tor.control, g_app.bridges[0]
                             ? ". Your bridges are only for chat's own tor, which torlaunch never doesn't start" : "");
                tor_link_apply();
            } else if (g_app.tor_launch == TOR_LAUNCH_NEVER) {
                if (r == -2) push_log("* tor: the running tor won't let chat in: %s", why);
                else push_log("* tor: no tor is running at %s or Tor Browser's ports - start one, or let chat start its "
                              "own (:set torlaunch auto)", g_app.route.tor.control);
                tor_link_fail(now, TOR_RETRY);
            } else {
                if (g_app.net_log != NET_LOG_OFF) {
                    if (r == -2) push_log("* tor: a tor is running but won't let chat in (%s) - starting chat's own", why);
                    else push_log("* tor: no tor running - starting chat's own");
                }
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
                if (++g_tor.starts < OWN_STARTS) { g_tor.state = TL_OFF; tor_link_start_own(now); }
                else tor_link_fail(now, OWN_TOR_RETRY);
                return;
            }
            if (g_tor.state == TL_STARTING && st == TORPROC_READY && g_tor.bridged) {
                static char conf[BRIDGES_CONF_MAX];
                char why[200];
                int rc = bridges_conf(conf, sizeof conf, why, sizeof why);
                if (rc == 0) rc = torproc_setconf(g_tor.proc, conf, why, sizeof why);
                crypto_wipe(conf, sizeof conf);
                if (rc != 0) {
                    push_log("* tor: %s - stopped chat's own tor, which never connects without its bridges", why);
                    torproc_stop(g_tor.proc);
                    g_tor.proc = NULL;
                    tor_link_fail(now, OWN_TOR_RETRY);
                    return;
                }
            }
            if (g_tor.state == TL_STARTING && st == TORPROC_READY) {
                g_tor.state = TL_READY;
                copy_str(g_tor.socks, torproc_socks(g_tor.proc), sizeof g_tor.socks);
                copy_str(g_tor.control, torproc_control(g_tor.proc), sizeof g_tor.control);
                const char *v = torproc_version(g_tor.proc);
                if (g_app.net_log != NET_LOG_OFF)
                    push_log("* tor: %s is up on %s, connecting to the Tor network...", v[0] ? v : "tor", g_tor.control);
                tor_link_apply();
            }
            int b = torproc_bootstrap(g_tor.proc);
            if (g_tor.state == TL_READY && b >= 0
                && (b == BOOT_DONE ? g_tor.boot_told < BOOT_DONE : b >= g_tor.boot_told + BOOT_STEP)) {
                g_tor.boot_told = b;
                int news = g_app.net_log != NET_LOG_OFF;
                if (b == BOOT_DONE) {
                    g_tor.starts = 0;
                    if (news) push_log("* tor: connected to the Tor network");
                    tor_link_connected();
                } else if (news) {
                    push_log("* tor: connecting to the Tor network: %d%%", b);
                }
            }
            return;
        }
        default:
            return;
    }
}

void tor_link_stop(void) {
    if (g_tor.probe) { tor_free(g_tor.probe); g_tor.probe = NULL; }
    // Only from a tor that got connected, so one that never did doesn't replace what's kept.
    if (g_tor.proc && g_tor.boot_told >= BOOT_DONE && keep_tor_state()) {
        uint8_t *state;
        size_t len;
        torproc_finish(g_tor.proc, &state, &len);
        if (!state || install_write_tor(state, len) != 0) push_log("* tor: couldn't keep its guards in the save");
        if (state) { crypto_wipe(state, len); free(state); }
    } else {
        torproc_stop(g_tor.proc);
    }
    g_tor.proc = NULL;
    g_tor.state = TL_OFF;
}

// The bridges or their programs changed: chat's own tor starts again, with them or without, unless
// there's no tor yet or chat still waits to reach the network.
void tor_link_restart(void) {
    if (g_app.route.mode != ROUTE_TOR || g_tor.state == TL_OFF || g_app.onboarding) return;
    if (!g_tor.proc && g_tor.state != TL_FAILED && !(g_app.bridges[0] && g_app.tor_launch == TOR_LAUNCH_AUTO)) return;
    tor_link_stop();
    g_tor.starts = 0;
    tor_link_ensure(now_seconds());
}

static int g_refreshed;

static void refresh_session(chat_t *e) {
    chat_tor_refresh(e);
    g_refreshed++;
}

cmd_result_t app_newtor(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    g_refreshed = 0;
    each_tor_session(refresh_session);
    if (g_refreshed == 0) note("no session goes through Tor - :set routing tor sends the next ones through it");
    else note("new Tor circuits and onion address%s for %d session%s", g_refreshed == 1 ? "" : "es", g_refreshed,
              g_refreshed == 1 ? "" : "s");
    return CMD_OK;
}

void tor_state_choose(int on) {
    if (g_loading_settings || !on) {
        g_app.tor_state = on;
        if (g_loading_settings) return;
        if (g_app.installed && !g_app.locked) install_forget_tor();
        note("Keep tor's guards: off%s", g_app.installed ? " - deleted from the save" : "");
        return;
    }
    if (!g_app.installed) { note("Keep tor's guards: it needs a save to keep them in - :install makes one"); return; }
    if (g_app.tor_state) { note("Keep tor's guards: on already"); return; }
    g_app.tor_state_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    if (g_app.tor_state_back == MODE_CHAT) begin_prompt(MODE_TOR_STATE);
    else { g_app.mode = MODE_TOR_STATE; g_app.dirty = 1; }
}

static void tor_state_back(void) {
    if (g_app.tor_state_back == MODE_CHAT) { end_prompt(); return; }
    g_app.mode = g_app.tor_state_back;
    g_app.dirty = 1;
}

void tor_state_yes(void) {
    tor_state_back();
    g_app.tor_state = 1;
    note("Keep tor's guards: on - kept in the save once chat's own tor has connected, from when it stops");
}

void tor_state_no(void) {
    tor_state_back();
    note("Keep tor's guards: off");
}

const char *tor_link_whose(void) {
    if (g_tor.proc) return "own";
    return g_tor.state == TL_READY ? "running" : NULL;
}

void tor_link_status(char *out, size_t cap) {
    switch (g_tor.state) {
        case TL_PROBING:  snprintf(out, cap, "Looking"); break;
        case TL_STARTING: snprintf(out, cap, "Starting"); break;
        case TL_FAILED:   snprintf(out, cap, "Failed"); break;
        case TL_READY: {
            // A running tor isn't asked how far it has got: it's taken to be connected.
            int b = g_tor.proc ? torproc_bootstrap(g_tor.proc) : 0;
            if (g_tor.proc && g_tor.boot_told < BOOT_DONE) snprintf(out, cap, "Connecting (%d%%)", b < 0 ? 0 : b);
            else snprintf(out, cap, "Connected");
            break;
        }
        default: snprintf(out, cap, "Off"); break;
    }
}

// This build as reported to peers, read at startup before :update can replace the file.
chat_build_t g_self_build;

// What every session takes from the settings: notifications, files, colour and signing identity.
// Then what peers are told about this build ("v"), and the key used to check the builds they report.
void app_session_opts(chat_opts_t *o) {
    o->notify_mode = g_app.notify_mode;
    o->notify_preview = g_app.notify_preview;
    o->verify_optional = g_app.verify_optional;
    o->file_cap = g_app.file_cap;
    o->fast_files = g_app.fast_files;
    o->picture_noise = g_app.picture_noise;
    o->has_color = 1;
    memcpy(o->color, g_app.color, 3);
    o->identity_source = g_app.identity_source;
    if (g_app.identity_source != IDENT_NONE) o->identity = g_app.identity;
    o->build = g_self_build;
    copy_str(o->release_key, update_release_key(), sizeof o->release_key);
    copy_str(o->release_backup_key, update_release_backup_key(), sizeof o->release_backup_key);
}

// move: the room :move made or was asked to, which gets a port of its own while the room being left
// keeps ours, and is said to be new and where it came from.
static session_slot_t *open_session(const char *session_name, const char *password, int created, uint16_t port,
                                    const addr_t *peers, int n_peers, const chat_move_to_t *move) {
    session_slot_t *s = find_free_slot();
    if (!s) { push_log("* too many sessions open already"); return NULL; }
    int idx = slot_index(s);
    memset(s, 0, sizeof *s);
    lock_scrollbacks(s);
    copy_str(s->name, session_name, sizeof s->name);

    char pw[MAX_PASSWORD + 1];
    copy_str(pw, password, sizeof pw);
    copy_str(s->password, password, sizeof s->password);

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
    o.port = move ? 0 : port ? port : g_app.default_port;
    if (n_peers > 0) { memcpy(o.peers, peers, sizeof(addr_t) * (size_t)n_peers); o.n_peers = n_peers; }
    o.route = g_app.route;
    if (o.route.mode == ROUTE_TOR) {
        // The tor found or started for Tor mode. Until there is one, the session waits for it.
        tor_link_ensure(now_seconds());
        copy_str(o.route.tor.socks, g_tor.state == TL_READY ? g_tor.socks : "", sizeof o.route.tor.socks);
        copy_str(o.route.tor.control, g_tor.state == TL_READY ? g_tor.control : "", sizeof o.route.tor.control);
    }
    o.created = created;
    app_session_opts(&o);
    if (move) { o.moved = 1; o.moved_key = move->key; }

    chat_init(&s->engine, &o, session_print, session_notify, s);
    s->engine.file_view = session_file_view;
    s->engine.delivery = session_delivery;
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
    chat_set_net_log(&s->engine, g_app.net_log);
    s->initialising = 0;
    g_app.dirty = 1;
    // Before anyone can connect, so peers hear of it in the handshake.
    if (g_app.history && history_possible()) history_start(s, 1);
    chat_set_history(&s->engine, s->hist != NULL);

    char idhex[SHORT_ID_HEX + 1]; hex_encode(s->engine.my_id, SHORT_ID_LEN, idhex);
    if (move) {
        console_note(s, "moved here from '%s' as %s (peer %s) - %s. Codes compared there count here as each peer arrives",
                     move->from, s->engine.nick, idhex, created ? "the peers asked along come once they say yes"
                                                                 : "chat opens once someone here answers");
        // Nobody typed them, and nothing else shows them.
        console_note(s, "this room's id is %s and its password \"%s\" - this is the only time they're shown: :invite "
                        "copies them, to pass on, and :keep keeps the room", s->engine.session_name, move->password);
    } else if (created) {
        console_note(s, "new session '%s' - :invite copies its id and password, to pass on. you are %s (peer %s)",
                     s->engine.session_name, s->engine.nick, idhex);
    } else {
        console_note(s, "joining '%s' as %s (peer %s) - chat opens once someone answers",
                     s->engine.session_name, s->engine.nick, idhex);
    }
    if (g_app.route.mode == ROUTE_TOR && g_app.net_log != NET_LOG_OFF)
        console_note(s, "* routing: %s - connecting takes a little longer", route_label());
    return s;
}

session_slot_t *start_session(const char *session_name, const char *password, int created, uint16_t port,
                              const addr_t *peers, int n_peers) {
    return open_session(session_name, password, created, port, peers, n_peers, NULL);
}

session_slot_t *start_moved_session(const chat_move_to_t *to) {
    return open_session(to->session_name, to->password, to->created, 0, NULL, 0, to);
}

int pgp_key_made_here(void) {
    return g_app.identity_source == IDENT_PGP && (g_app.key_origin == KEY_MADE || g_app.key_origin == KEY_DERIVED);
}

// The PGP key made here, armored, with the nick as it is now in its user id.
void pgp_public_key(char armor[PGP_ARMOR_MAX], uint8_t fp[PGP_FP_LEN]) {
    pgp_export_public_key(&g_app.identity, g_app.nick[0] ? g_app.nick : "chat", g_app.pgp_created,
                          armor, PGP_ARMOR_MAX, fp);
}

void show_identity_result(void) {
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

void finish_onboarding(void) {
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
    rooms_join_at_start();
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

int path_is_root(const char *p) {
    size_t n = strlen(p);
    return strcmp(p, "/") == 0 || (n == 2 && p[1] == ':') || (n == 3 && p[1] == ':' && p[2] == '/');
}

void path_join(char *out, size_t cap, const char *dir, const char *name) {
    size_t n = strlen(dir);
    snprintf(out, cap, (n > 0 && dir[n - 1] == '/') ? "%s%s" : "%s/%s", dir, name);
}

void path_parent(char *p) {
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

int browser_load(browser_t *b, const char *path) {
    static browser_t tmp;
    memset(&tmp, 0, sizeof tmp);
    copy_str(tmp.path, path, sizeof tmp.path);
    if (platform_list_dir(tmp.path, browser_add, &tmp) != 0) return -1;
    qsort(tmp.items, (size_t)tmp.n_items, sizeof(dir_entry_t), entry_cmp);
    *b = tmp;
    return 0;
}

// Selects the entry called name (a folder's without its '/'), if it's there.
void browser_select(browser_t *b, const char *name) {
    size_t n = strlen(name);
    if (!n) return;
    for (int i = 0; i < b->n_items; i++) {
        const char *e = b->items[i].name;
        if (strncmp(e, name, n) == 0 && (e[n] == '\0' || (e[n] == '/' && e[n + 1] == '\0'))) { b->selected = i; return; }
    }
}

// The path of an entry in the folder the browser shows, without a folder's trailing '/'.
void browser_entry_path(const browser_t *b, const dir_entry_t *e, char *out, size_t cap) {
    char name[sizeof e->name];
    copy_str(name, e->name, sizeof name);
    size_t n = strlen(name);
    if (n > 0 && name[n - 1] == '/') name[n - 1] = '\0';
    path_join(out, cap, b->path, name);
}

// New/join prompts use the input line. The draft is saved and restored when the prompt ends.
void begin_prompt(app_mode_t mode) {
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_app.mode = mode;
    g_app.dirty = 1;
}

// The id is often passed around in the open, so the password carries the weight against guessing: the
// field starts with a random one, unmasked since it has to be passed on.
void begin_new_session(void) {
    begin_prompt(MODE_NEW_PASSWORD);
    uint8_t pw[MOVE_PASSWORD_BYTES];
    gen_random(pw, sizeof pw);
    bytewords_plain(pw, sizeof pw, g_app.input.buf);
    crypto_wipe(pw, sizeof pw);
    g_app.input.len = g_app.input.cursor = (int)strlen(g_app.input.buf);
    g_app.pw_suggested = 1;
}

void end_prompt(void) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    crypto_wipe(g_app.pending_session_id, sizeof g_app.pending_session_id);
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.pw_suggested = 0;
    g_app.mode = MODE_CHAT;
    g_app.dirty = 1;
}

cmd_result_t app_new(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_new_session();
    return CMD_OK;
}

cmd_result_t app_join(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_rooms();
    return CMD_OK;
}

// ---- kept rooms ----

static session_slot_t *open_room(const char *id) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_app.used[i] && !g_app.sessions[i].leaving && strcmp(g_app.sessions[i].name, id) == 0)
            return &g_app.sessions[i];
    return NULL;
}

// The kept rooms written to the open save, then done said.
static void rooms_saved(const char *done) {
    char where[APP_PATH_MAX] = "";
    install_where(install_current(), where, sizeof where);
    if (settings_write() != 0) note("couldn't write that to %s/settings - it lasts until chat exits", where);
    else note("%s", done);
}

// The room on screen, kept in the open save under a label (its id unless one's given, or the one it
// has), for Ctrl+J to join it again. "forget" lets it go.
cmd_result_t app_keep(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    if (!s || s->initialising) { note("no room on screen to keep"); return CMD_OK; }
    if (s->contact) { note("a call's room changes every day - :call finds it again"); return CMD_OK; }
    int at = rooms_find(s->name);
    char label[ROOM_LABEL_MAX + 1], done[160];
    const char *shown = install_shown_name(install_current());
    if (strcmp(arg, "forget") == 0) {
        if (at < 0) { note("this room isn't kept"); return CMD_OK; }
        snprintf(done, sizeof done, "%s: no longer kept in the save %s", room_at(at)->label, shown);
        rooms_forget(at);
        rooms_saved(done);
        return CMD_OK;
    }
    if (!g_app.installed || g_app.locked) { note("a room is kept in a save - :install makes one"); return CMD_OK; }
    if (at < 0 && rooms_count() >= ROOMS_MAX) {
        note("%d rooms are kept already - :keep forget one", ROOMS_MAX);
        return CMD_OK;
    }
    copy_str(label, arg[0] ? arg : at >= 0 ? room_at(at)->label : s->name, sizeof label);
    int i = rooms_keep(label, s->name, s->password);
    if (i < 0) { note("this room can't be kept"); return CMD_OK; }
    snprintf(done, sizeof done, "%s: %s in the save %s" DOT_SEP "Ctrl+J joins it", room_at(i)->label,
             at < 0 ? "kept" : "kept, with that label,", shown);
    rooms_saved(done);
    return CMD_OK;
}

// With rooms kept, Ctrl+J lists them, and "another room" under them asks for an id as before.
void begin_rooms(void) {
    if (!rooms_count()) { begin_prompt(MODE_JOIN_ID); return; }
    if (g_app.rooms_sel > rooms_count()) g_app.rooms_sel = 0;
    g_app.rooms_forgetting = 0;
    begin_prompt(MODE_ROOMS);
}

static void join_room(int i) {
    const room_t *r = room_at(i);
    if (!r) return;
    session_slot_t *s = open_room(r->id);
    end_prompt();
    if (s) { select_session(s); note("%s is open already", r->label); return; }
    char id[MAX_SESSION_NAME + 1], pw[MAX_PASSWORD + 1];
    copy_str(id, r->id, sizeof id);
    copy_str(pw, r->password, sizeof pw);
    start_session(id, pw, 0, 0, NULL, 0);
    crypto_wipe(pw, sizeof pw);
}

void rooms_key(const tui_key_t *key) {
    int n = rooms_count(), i = g_app.rooms_sel;
    if (g_app.rooms_forgetting) {
        int yes = key->type == TUI_KEY_CHAR && key->ch_len == 1 && (key->ch[0] == 'y' || key->ch[0] == 'Y');
        int no = key->type == TUI_KEY_ESCAPE
              || (key->type == TUI_KEY_CHAR && key->ch_len == 1 && strchr("nNq", key->ch[0]));
        if (!yes && !no) return;
        g_app.rooms_forgetting = 0;
        g_app.dirty = 1;
        if (no) return;
        char done[160];
        snprintf(done, sizeof done, "%s: no longer kept in the save %s", room_at(i)->label,
                 install_shown_name(install_current()));
        rooms_forget(i);
        if (g_app.rooms_sel > 0 && g_app.rooms_sel >= rooms_count()) g_app.rooms_sel--;
        if (!rooms_count()) end_prompt();
        rooms_saved(done);
        return;
    }
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && i < n && (key->ch[0] == 'd' || key->ch[0] == 's')) {
        if (key->ch[0] == 'd') { g_app.rooms_forgetting = 1; g_app.dirty = 1; return; }
        char done[160];
        rooms_set_start(i, !room_at(i)->at_start);
        snprintf(done, sizeof done, "%s: %s", room_at(i)->label,
                 room_at(i)->at_start ? "joined as chat starts" : "not joined as chat starts");
        rooms_saved(done);
        g_app.dirty = 1;
        return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT:
            if (i < n) { join_room(i); return; }
            end_prompt();
            begin_prompt(MODE_JOIN_ID);
            return;
        case LIST_LEFT:
        case LIST_BACK:
        case LIST_CLOSE:
            end_prompt();
            return;
        default:
            list_move(k, &g_app.rooms_sel, n + 1);
            g_app.dirty = 1;
            return;
    }
}

// The rooms marked to, once chat starts reaching the network.
void rooms_join_at_start(void) {
    if (!g_app.installed || g_app.locked) return;
    for (int i = 0; i < rooms_count(); i++) {
        const room_t *r = room_at(i);
        if (!r || !r->at_start || open_room(r->id)) continue;
        char id[MAX_SESSION_NAME + 1], pw[MAX_PASSWORD + 1];
        copy_str(id, r->id, sizeof id);
        copy_str(pw, r->password, sizeof pw);
        start_session(id, pw, 0, 0, NULL, 0);
        crypto_wipe(pw, sizeof pw);
    }
}

// ---- reopening sessions ----

// Only once the row's saved, so with autosave off nothing goes in the save before :save.
static int reopen_saving(void) {
    return g_app.reopen && !g_app.quit_leaving && g_app.installed && !g_app.locked
           && strcmp(g_saved_rows[settings_index(SET_REOPEN)], "on") == 0;
}

// Calls aren't kept: :call finds the day's room again.
int session_kept(const session_slot_t *s) {
    return reopen_saving() && !g_app.reopen_due && !s->leaving && !s->contact && !s->initialising;
}

// The sessions kept in a save that's just opened, once chat reaches the network. One that can't open
// (a port in use, say) stays kept for the next start.
void reopen_tick(void) {
    if (!g_app.reopen_due || g_app.onboarding || !g_app.installed || g_app.locked) return;
    g_app.reopen_due = 0;
    if (!reopen_saving()) return;
    for (int i = 0; i < reopen_count(); i++) {
        const room_t *r = reopen_at(i);
        if (!r || open_room(r->id)) continue;
        char id[MAX_SESSION_NAME + 1], pw[MAX_PASSWORD + 1];
        copy_str(id, r->id, sizeof id);
        copy_str(pw, r->password, sizeof pw);
        if (!start_session(id, pw, 0, 0, NULL, 0)) reopen_failed(i);
        crypto_wipe(pw, sizeof pw);
    }
}

// Before every frame, like the settings: the open save keeps the sessions open as they open and close.
void keep_sessions_saved(void) {
    if (g_app.reopen_due || g_app.onboarding || !g_app.installed || g_app.locked) return;
    reopen_begin();
    if (reopen_saving()) {
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (g_app.used[i] && session_kept(&g_app.sessions[i]))
                reopen_add(g_app.sessions[i].name, g_app.sessions[i].password, 0);
        for (int i = 0; i < reopen_count(); i++) {
            const room_t *r = reopen_at(i);
            if (r->unopened && !open_room(r->id)) reopen_add(r->id, r->password, 1);
        }
    }
    if (reopen_end() && settings_write() != 0) {
        char where[APP_PATH_MAX] = "";
        install_where(install_current(), where, sizeof where);
        note("couldn't write the sessions to reopen to %s/settings", where);
    }
}

// ---- calls ----

static session_slot_t *open_call(const uint8_t pub[ID_SIGN_PUB_LEN]) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_slot_t *s = &g_app.sessions[i];
        if (g_app.used[i] && !s->leaving && s->contact && memcmp(s->contact_pub, pub, ID_SIGN_PUB_LEN) == 0) return s;
    }
    return NULL;
}

// Only the verified key gets anything there, whatever :set verify says.
static session_slot_t *call_open(const trust_entry_t *t, uint64_t day) {
    char id[SESSION_ID_LEN + 1], pw[CONTACT_PASSWORD_LEN + 1], nick[MAX_NICK + 1];
    uint8_t pub[ID_SIGN_PUB_LEN];
    memcpy(pub, t->pub, sizeof pub);
    copy_str(nick, t->nick, sizeof nick);
    if (chat_contact_room(&g_app.identity, pub, day, id, pw) != 0) {
        note("no room can be worked out with %s's key", nick);
        return NULL;
    }
    session_slot_t *s = start_session(id, pw, 0, 0, NULL, 0);
    crypto_wipe(pw, sizeof pw);
    if (!s) return NULL;
    s->contact = 1;
    memcpy(s->contact_pub, pub, sizeof s->contact_pub);
    s->contact_day = day;
    snprintf(s->name, sizeof s->name, "@%s", nick);
    s->engine.verify_required = 1;
    console_note(s, "* calling %s: a room only your signing key and theirs can work out, for today (UTC). They "
                    "have to :call you too, and nothing goes to anyone there but the key you verified", nick);
    return s;
}

// :call NICK: the room of a verified key's, which they open with :call too.
cmd_result_t app_call(void *ctx, const char *arg) {
    (void)ctx;
    if (!arg[0]) { note("call whom? :call NICK, for a key :verified lists"); return CMD_OK; }
    if (g_app.identity_source == IDENT_NONE) {
        note("a call needs a signing identity of yours, which they've verified - :set sign");
        return CMD_OK;
    }
    char skel[NICK_SKEL_LEN];
    chat_nick_skeleton(arg, skel, sizeof skel);
    int at = trust_find_nick(skel, 0);
    if (at < 0) { note("no verified key goes by %.40s - :verified lists them", arg); return CMD_OK; }
    if (trust_find_nick(skel, at + 1) >= 0) {
        note("more than one verified key goes by %.40s - :verified forget the one that's gone", arg);
        return CMD_OK;
    }
    const trust_entry_t *t = trust_at(at);
    session_slot_t *s = open_call(t->pub);
    if (s) { select_session(s); note("the call with %s is open already", t->nick); return CMD_OK; }
    call_open(t, chat_contact_day());
    return CMD_OK;
}

// A call nobody's in moves to the new day's room as the day changes, so two who :call either side of
// midnight (UTC), or with clocks a little apart, still meet.
void contacts_tick(void) {
    uint64_t day = chat_contact_day();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_slot_t *s = &g_app.sessions[i], *sel = g_app.selected;
        if (!g_app.used[i] || s->leaving || !s->contact || s->initialising || s->contact_day == day
            || chat_online_count(&s->engine) > 0)
            continue;
        const trust_entry_t *t = trust_by_key(s->contact_pub);
        char name[sizeof s->name];
        copy_str(name, s->name, sizeof name);
        close_session(s);
        if (!t) { push_log("* the call %s ended: their key isn't verified any more", name); continue; }
        if (call_open(t, day) && sel != s && sel && g_app.used[slot_index(sel)]) select_session(sel);
    }
}

cmd_result_t app_quit(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    if (g_app.selected) close_session(g_app.selected);
    else g_interrupted = 1;
    return CMD_OK;
}

cmd_result_t app_quitall(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    g_app.quit_leaving = 1;
    g_interrupted = 1;
    return CMD_OK;
}

cmd_result_t app_copyid(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    copy_session_id(g_app.selected);
    return CMD_OK;
}

cmd_result_t app_invite(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    copy_invite(g_app.selected);
    return CMD_OK;
}

cmd_result_t app_update(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    if ((g_app.sandboxed & PLATFORM_SANDBOX_FILES) && !update_helper_running()) {
        if (g_app.updater)
            note("the sandbox keeps chat from replacing itself, and the updater isn't running - quit and run chat "
                 "--update");
        else
            note("the sandbox keeps chat from replacing itself, and the updater is off - quit and run chat --update, "
                 "or :set updater on for the next start");
        return CMD_OK;
    }
    if (g_app.route.mode == ROUTE_TOR && g_tor.state != TL_READY) {
        push_log(UPDATE_PREFIX "Tor mode downloads through Tor, and there's no tor yet - try again once it's connected");
        return CMD_OK;
    }
    // If an update is already running, its box is shown again.
    if (update_start(g_app.betas) == 0)
        push_log(UPDATE_PREFIX "checking GitHub for a newer release%s (v" CHAT_VERSION " here)...", g_app.betas ? " or beta" : "");
    begin_prompt(MODE_UPDATE);
    return CMD_OK;
}

// The box only shows the update. Closing it leaves the update running, and the result goes to the
// console either way.
void update_key(const tui_key_t *key) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (key->type != TUI_KEY_ESCAPE && key->type != TUI_KEY_ENTER && ch != 'q') return;
    update_view_t v;
    update_view(&v);
    end_prompt();
    if (v.running) note("the update keeps running - :update shows it again");
}
