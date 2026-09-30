// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/bridges.h"
#include "platform/net.h"
#include "common/util.h"
#include <stdio.h>
#include <string.h>

// Tor Browser's built-in Snowflake bridges: the broker is reached through a CDN (domain fronting),
// and the fingerprints are the two Snowflake bridges' own.
static const char *const SNOWFLAKE[] = {
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net "
    "ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,"
    "stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 "
    "utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA "
    "url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net "
    "ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,"
    "stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 "
    "utls-imitate=hellorandomizedalpn",
};

// Each transport and the programs that speak it, most usual first. lyrebird is obfs4proxy's
// successor, and what Tor Browser ships.
static const struct { const char *transport; const char *programs[2]; } TRANSPORTS[] = {
    { "snowflake", { "snowflake-client", NULL } },
    { "obfs4", { "lyrebird", "obfs4proxy" } },
    { "webtunnel", { "lyrebird", "webtunnel-client" } },
    { "meek_lite", { "lyrebird", "obfs4proxy" } },
    { "scramblesuit", { "lyrebird", "obfs4proxy" } },
    { "obfs3", { "lyrebird", "obfs4proxy" } },
    { "conjure", { "conjure-client", NULL } },
};
#define N_TRANSPORTS (sizeof TRANSPORTS / sizeof TRANSPORTS[0])

static int fail(char *why, size_t cap, const char *msg) {
    if (why && cap) copy_str(why, msg, cap);
    return -1;
}

static int lower_ascii(int c) { return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c; }

static int word_is(const char *s, size_t n, const char *word) {
    if (strlen(word) != n) return 0;
    for (size_t i = 0; i < n; i++) if (lower_ascii((unsigned char)s[i]) != word[i]) return 0;
    return 1;
}

// A torrc value can't hold these: '#' starts a comment, and quotes and backslashes change how
// tor reads the rest. Anything else printable is left for tor to judge.
static int line_char_ok(int c) { return c > ' ' && c < 0x7f && c != '#' && c != '"' && c != '\\'; }

static int is_hex40(const char *s, size_t n) {
    if (n != 40) return 0;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
    }
    return 1;
}

static int transport_name_ok(const char *s, size_t n) {
    if (n == 0 || n > 31 || s[0] < 'a' || s[0] > 'z') return 0;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return 0;
    }
    return 1;
}

static int addr_token_ok(const char *s, size_t n) {
    char buf[64];
    addr_t a;
    if (n == 0 || n >= sizeof buf) return 0;
    memcpy(buf, s, n);
    buf[n] = '\0';
    return addr_parse_ip_port(buf, &a) == 0 && a.port != 0;
}

// The transport a line uses ("" for a plain bridge), up to cap bytes.
static void line_transport(const char *line, char *out, size_t cap) {
    size_t n = strcspn(line, " ");
    if (strchr(line, ' ') && transport_name_ok(line, n) && n < cap) { memcpy(out, line, n); out[n] = '\0'; }
    else copy_str(out, "", cap);
}

// One line, tidied into out: "Bridge " dropped, runs of spaces made one. 1 if it's a line, 0 if
// blank, -1 with why.
static int tidy_line(const char *in, size_t len, char *out, size_t cap, char *why, size_t why_cap) {
    size_t o = 0;
    int space = 1;
    for (size_t i = 0; i < len; i++) {
        int c = (unsigned char)in[i];
        if (c == ' ' || c == '\t' || c == '\r') { space = 1; continue; }
        if (!line_char_ok(c)) return fail(why, why_cap, "a bridge line can't hold quotes, backslashes, '#' or control characters");
        if (space && o > 0) { if (o + 1 >= cap) return fail(why, why_cap, "a bridge line is too long"); out[o++] = ' '; }
        space = 0;
        if (o + 1 >= cap) return fail(why, why_cap, "a bridge line is too long");
        out[o++] = (char)c;
    }
    out[o] = '\0';
    if (o > 7 && word_is(out, 6, "bridge") && out[6] == ' ') memmove(out, out + 7, o - 6);
    return out[0] ? 1 : 0;
}

// transport? address fingerprint? key=value...: the forms bridges.torproject.org hands out.
static int line_ok(const char *line, char *why, size_t why_cap) {
    const char *p = line;
    size_t n = strcspn(p, " ");
    if (!addr_token_ok(p, n)) {
        if (!transport_name_ok(p, n)) return fail(why, why_cap, "a bridge line starts with its transport (obfs4, webtunnel, snowflake...) or its IP:PORT");
        p += n;
        if (*p != ' ') return fail(why, why_cap, "a bridge line needs the bridge's IP:PORT after its transport");
        p++;
        n = strcspn(p, " ");
        if (!addr_token_ok(p, n)) return fail(why, why_cap, "a bridge line needs the bridge's IP:PORT after its transport");
    }
    p += n;
    while (*p == ' ') {
        p++;
        n = strcspn(p, " ");
        const char *eq = memchr(p, '=', n);
        if (!is_hex40(p, n) && (!eq || eq == p))
            return fail(why, why_cap, "after the address a bridge line takes a fingerprint (40 hex digits) and key=value arguments");
        p += n;
    }
    return 0;
}

static int push_line(bridges_t *b, const char *line, char *why, size_t why_cap) {
    for (int i = 0; i < b->n; i++) if (strcmp(b->line[i], line) == 0) return 0;
    if (b->n >= BRIDGE_MAX) {
        char msg[64];
        snprintf(msg, sizeof msg, "at most %d bridges", BRIDGE_MAX);
        return fail(why, why_cap, msg);
    }
    copy_str(b->line[b->n++], line, BRIDGE_LINE_MAX);
    return 0;
}

int bridges_add(const char *text, bridges_t *out, char *why, size_t why_cap) {
    bridges_t b = *out;
    char line[BRIDGE_LINE_MAX];
    for (const char *p = text; ; ) {
        size_t len = strcspn(p, ";\n");
        int r = tidy_line(p, len, line, sizeof line, why, why_cap);
        if (r < 0) return -1;
        if (r > 0 && word_is(line, strlen(line), "off")) {
            memset(&b, 0, sizeof b);
        } else if (r > 0 && word_is(line, strlen(line), "snowflake")) {
            for (size_t i = 0; i < sizeof SNOWFLAKE / sizeof SNOWFLAKE[0]; i++)
                if (push_line(&b, SNOWFLAKE[i], why, why_cap) != 0) return -1;
            b.builtin = 1;
        } else if (r > 0) {
            if (line_ok(line, why, why_cap) != 0) return -1;
            if (push_line(&b, line, why, why_cap) != 0) return -1;
        }
        if (!p[len]) break;
        p += len + 1;
    }
    *out = b;
    return 0;
}

int bridges_parse(const char *text, bridges_t *out, char *why, size_t why_cap) {
    bridges_t b;
    memset(&b, 0, sizeof b);
    if (bridges_add(text, &b, why, why_cap) != 0) return -1;
    *out = b;
    return 0;
}

void bridges_describe(const bridges_t *b, char *out, size_t cap) {
    if (b->n == 0) { copy_str(out, "off", cap); return; }
    int builtin_only = b->builtin && b->n == (int)(sizeof SNOWFLAKE / sizeof SNOWFLAKE[0]);
    if (builtin_only) { copy_str(out, "built-in Snowflake", cap); return; }
    char kinds[160] = "";
    size_t k = 0;
    for (int i = 0; i < b->n; i++) {
        char t[32];
        line_transport(b->line[i], t, sizeof t);
        if (!t[0]) copy_str(t, "plain", sizeof t);
        int seen = 0;
        for (int j = 0; j < i && !seen; j++) {
            char u[32];
            line_transport(b->line[j], u, sizeof u);
            if (!u[0]) copy_str(u, "plain", sizeof u);
            seen = strcmp(t, u) == 0;
        }
        if (!seen && k < sizeof kinds) k += (size_t)snprintf(kinds + k, sizeof kinds - k, "%s%s", k ? ", " : "", t);
    }
    snprintf(out, cap, "%d bridge%s (%s)", b->n, b->n == 1 ? "" : "s", kinds);
}

static int has_space(const char *s) {
    for (; *s; s++) if (*s == ' ' || *s == '\t') return 1;
    return 0;
}

int bridges_torrc(const bridges_t *b, bridge_find_fn find, void *ctx, char *out, size_t cap, char *why, size_t why_cap) {
    // Each transport in use, with the program that speaks it.
    char transport[BRIDGE_MAX][32], program[BRIDGE_MAX][1024];
    int n_t = 0;
    for (int i = 0; i < b->n; i++) {
        char t[32];
        line_transport(b->line[i], t, sizeof t);
        if (!t[0]) continue;
        int seen = 0;
        for (int j = 0; j < n_t && !seen; j++) seen = strcmp(transport[j], t) == 0;
        if (seen) continue;
        size_t k = 0;
        while (k < N_TRANSPORTS && strcmp(TRANSPORTS[k].transport, t) != 0) k++;
        char msg[200];
        if (k == N_TRANSPORTS) {
            snprintf(msg, sizeof msg, "chat doesn't know which program speaks the %s transport", t);
            return fail(why, why_cap, msg);
        }
        int found = 0;
        for (int m = 0; m < 2 && TRANSPORTS[k].programs[m] && !found; m++)
            found = find(ctx, t, TRANSPORTS[k].programs[m], program[n_t], sizeof program[n_t]) == 0;
        if (!found) {
            const char *const *pr = TRANSPORTS[k].programs;
            snprintf(msg, sizeof msg, "%s bridges need %s%s%s installed (or its path set with :set torpt %s=PATH)", t, pr[0],
                     pr[1] ? " or " : "", pr[1] ? pr[1] : "", t);
            return fail(why, why_cap, msg);
        }
        if (has_space(program[n_t])) {
            snprintf(msg, sizeof msg, "tor can't run %.120s: its path has a space in it", program[n_t]);
            return fail(why, why_cap, msg);
        }
        copy_str(transport[n_t++], t, sizeof transport[0]);
    }

    size_t o = 0;
#define EMIT(...) do { \
        int w_ = snprintf(out + o, cap - o, __VA_ARGS__); \
        if (w_ < 0 || (size_t)w_ >= cap - o) return fail(why, why_cap, "too many bridges to write out"); \
        o += (size_t)w_; \
    } while (0)
    if (cap == 0) return fail(why, why_cap, "too many bridges to write out");
    out[0] = '\0';
    if (b->n == 0) return 0;
    EMIT("UseBridges 1\n");
    // One plugin line per program, naming every transport it runs for.
    for (int i = 0; i < n_t; i++) {
        int first = 1;
        for (int j = 0; j < i && first; j++) first = strcmp(program[j], program[i]) != 0;
        if (!first) continue;
        EMIT("ClientTransportPlugin ");
        int k = 0;
        for (int j = i; j < n_t; j++)
            if (strcmp(program[j], program[i]) == 0) EMIT("%s%s", k++ ? "," : "", transport[j]);
        EMIT(" exec %s\n", program[i]);
    }
    for (int i = 0; i < b->n; i++) EMIT("Bridge %s\n", b->line[i]);
#undef EMIT
    return 0;
}
