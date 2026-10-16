// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"

const char *const TOR_LAUNCH_NAMES[] = { "auto", "always", "never" };

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
        chat_t *e = g_app.sessions[i].engine;
        if (chat_route_mode(e) == ROUTE_TOR) fn(e);
    }
    if (g_plain_engine && chat_route_mode(g_plain_engine) == ROUTE_TOR) fn(g_plain_engine);
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
    if (g_app.tor.pt_dir[0]) {
        snprintf(path, sizeof path, "%s/%s" EXE, g_app.tor.pt_dir, name);
        return platform_find_program(name, path, out, cap);
    }
    char *sep;
    if (platform_find_program("tor", g_app.tor.path, dir, sizeof dir) == 0 && (sep = last_sep(dir)) != NULL) {
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
    snprintf(out, cap, "%s: %s%s%s%s", g_app.tor.pt_dir[0] ? g_app.tor.pt_dir : "next to tor or on PATH",
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
    while (next_bridge(g_app.tor.bridges, &at, line, sizeof line)) {
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
    return g_app.tor.keep_state && g_app.installed && !g_app.locked && !g_panic;
}

static void tor_link_start_own(double now) {
    char program[1024], err[160];
    if (platform_find_program("tor", g_app.tor.path, program, sizeof program) != 0) {
        if (g_app.tor.path[0])
            push_log("* tor: can't use %s as tor - it has to be a program only root or you can change", g_app.tor.path);
        else
            push_log("* tor: tor isn't installed. Install it (Arch: sudo pacman -S tor, Debian/Ubuntu: sudo apt install tor, "
                     "Windows: the Tor Expert Bundle), set where it is with :set torpath, or start Tor Browser");
        tor_link_fail(now, TOR_RETRY);
        return;
    }
    torproc_opts_t o = { 0 };
    if (g_app.tor.bridges[0]) {
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
    if (g_app.tor.launch == TOR_LAUNCH_ALWAYS || (g_app.tor.launch == TOR_LAUNCH_AUTO && g_app.tor.bridges[0])) {
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
                             "guards and any bridges it's set up with%s", g_tor.control, g_app.tor.bridges[0]
                             ? ". Your bridges are only for chat's own tor, which torlaunch never doesn't start" : "");
                tor_link_apply();
            } else if (g_app.tor.launch == TOR_LAUNCH_NEVER) {
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
    if (!g_tor.proc && g_tor.state != TL_FAILED && !(g_app.tor.bridges[0] && g_app.tor.launch == TOR_LAUNCH_AUTO)) return;
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
        g_app.tor.keep_state = on;
        if (g_loading_settings) return;
        if (g_app.installed && !g_app.locked) install_forget_tor();
        note("Keep tor's guards: off%s", g_app.installed ? " - deleted from the save" : "");
        return;
    }
    if (!g_app.installed) { note("Keep tor's guards: it needs a save to keep them in - :install makes one"); return; }
    if (g_app.tor.keep_state) { note("Keep tor's guards: on already"); return; }
    g_app.tor.back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    if (g_app.tor.back == MODE_CHAT) begin_prompt(MODE_TOR_STATE);
    else { g_app.mode = MODE_TOR_STATE; g_app.dirty = 1; }
}

static void tor_state_back(void) {
    if (g_app.tor.back == MODE_CHAT) { end_prompt(); return; }
    g_app.mode = g_app.tor.back;
    g_app.dirty = 1;
}

void tor_state_yes(void) {
    tor_state_back();
    g_app.tor.keep_state = 1;
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
