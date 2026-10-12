// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/torproc.h"
#include "platform/net.h"
#include "platform/platform.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include <mbedtls/sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAIL 16384
#define LOG_READ_EVERY 1.0
#define STOP_WAIT_MS 3000
#define DIR_MAX 1024
#define FILE_PATH_MAX (DIR_MAX + 76)
// The control password: random bytes, as hex.
#define PASSWORD_SECRET_LEN 32
#define ARGV_MAX 40
// How long the control port gets to answer, as tor starts.
#define CTL_WAIT 5.0
#define CTL_POLL_MS 10
#define CTL_LINE_MAX 512
#define CTL_OK 250
// What's kept of tor between runs, packed: this, then each file's name, a NUL, its length (4 bytes,
// big-endian) and its bytes.
#define STATE_MAGIC "chat tor state 1\n"
// The directory alone is tens of MB: a fresh tor's microdescriptor journal is over 30.
#define STATE_MAX (64u * 1024 * 1024)
#define STATE_LEN_BYTES 4
#define N_KEPT (sizeof KEPT / sizeof KEPT[0])

// Its entry guards (state) and its copy of the directory, so the next tor starts where it left off.
static const char *const KEPT[] = { "state", "cached-certs", "cached-microdesc-consensus", "cached-microdescs",
                                    "cached-microdescs.new" };

// OpenPGP's salted and iterated S2K (RFC 4880 3.7.1.3), as tor's HashedControlPassword takes it.
#define S2K_SALT_LEN 8
#define S2K_COUNT 0x60
#define S2K_EXPBIAS 6
#define S2K_SPEC_LEN (S2K_SALT_LEN + 1 + SHA1_LEN)
#define S2K_PREFIX "16:"
#define S2K_PASSWORD_MAX 64

struct torproc {
    platform_proc_t *proc;
    char dir[DIR_MAX];
    char torrc[FILE_PATH_MAX], data[FILE_PATH_MAX], port_file[FILE_PATH_MAX], log[FILE_PATH_MAX];
    char socks[32], control[32];
    char password[PASSWORD_SECRET_LEN * 2 + 1];
    char version[80];
    char problem[200], last_line[200];
    int code;
    int boot;
    double next_read;
};

// Two free ports on 127.0.0.1, held open together so they're different. Another program could
// take one before tor does. tor then exits and the caller starts it again.
static int free_ports(uint16_t *a, uint16_t *b) {
    sock_t s1 = net_tcp_listen_loopback(a);
    sock_t s2 = net_tcp_listen_loopback(b);
    int ok = s1 != SOCK_INVALID && s2 != SOCK_INVALID;
    net_close(s1);
    net_close(s2);
    return ok ? 0 : -1;
}

static int path_in(char *out, size_t cap, const char *dir, const char *name) {
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

// HashedControlPassword for password, as `tor --hash-password` makes it: OpenPGP's salted and
// iterated S2K over SHA-1, written "16:" then in hex the 8 byte salt, the count byte 0x60 (64 KiB
// hashed) and the hash. out needs 62 bytes.
static int hash_password(const char *password, char *out, size_t cap) {
    uint8_t spec[S2K_SPEC_LEN], salted[S2K_SALT_LEN + S2K_PASSWORD_MAX];
    size_t plen = strlen(password);
    if (plen > S2K_PASSWORD_MAX || cap < sizeof S2K_PREFIX - 1 + 2 * sizeof spec + 1) return -1;
    gen_random(spec, S2K_SALT_LEN);
    uint8_t count = spec[S2K_SALT_LEN] = S2K_COUNT;
    memcpy(salted, spec, S2K_SALT_LEN);
    memcpy(salted + S2K_SALT_LEN, password, plen);
    size_t chunk = S2K_SALT_LEN + plen, left = (size_t)(16 + (count & 15)) << ((count >> 4) + S2K_EXPBIAS);
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    int rc = mbedtls_sha1_starts(&ctx);
    while (rc == 0 && left > 0) {
        size_t n = left < chunk ? left : chunk;
        rc = mbedtls_sha1_update(&ctx, salted, n);
        left -= n;
    }
    if (rc == 0) rc = mbedtls_sha1_finish(&ctx, spec + S2K_SALT_LEN + 1);
    mbedtls_sha1_free(&ctx);
    crypto_wipe(salted, sizeof salted);
    if (rc != 0) return -1;
    memcpy(out, S2K_PREFIX, sizeof S2K_PREFIX - 1);
    hex_encode(spec, sizeof spec, out + sizeof S2K_PREFIX - 1);
    return 0;
}

// Files a pack doesn't name are left out, and so is the rest of one that doesn't add up.
static void unpack_state(const torproc_t *p, const uint8_t *d, size_t n) {
    size_t i = sizeof STATE_MAGIC - 1;
    if (n < i || memcmp(d, STATE_MAGIC, i) != 0) return;
    while (i < n) {
        const uint8_t *nul = memchr(d + i, 0, n - i);
        if (!nul) return;
        const char *name = (const char *)(d + i);
        size_t at = (size_t)(nul - d) + 1;
        if (n - at < STATE_LEN_BYTES) return;
        uint32_t len = (uint32_t)d[at] << 24 | (uint32_t)d[at + 1] << 16 | (uint32_t)d[at + 2] << 8 | d[at + 3];
        at += STATE_LEN_BYTES;
        if (len > n - at) return;
        for (size_t k = 0; k < N_KEPT; k++) {
            char path[FILE_PATH_MAX + 32];
            if (strcmp(name, KEPT[k]) == 0 && path_in(path, sizeof path, p->data, name) == 0)
                platform_write_private(path, d + at, len);
        }
        i = at + len;
    }
}

torproc_t *torproc_start(const char *program, const torproc_opts_t *o, char *err, size_t cap) {
    torproc_t *p = calloc(1, sizeof *p);
    if (!p) { copy_str(err, "out of memory", cap); return NULL; }
    p->boot = -1;
    // Left by a crashed chat. Its tor has quit by now (it watches chat's process) but the folder is
    // still there.
    platform_remove_stale_tempdirs("chat-tor", "data/lock");
    if (platform_private_tempdir("chat-tor", p->dir, sizeof p->dir) != 0) {
        copy_str(err, "can't make a private folder for tor", cap);
        free(p);
        return NULL;
    }
    if (path_in(p->torrc, sizeof p->torrc, p->dir, "torrc") || path_in(p->data, sizeof p->data, p->dir, "data")
        || path_in(p->port_file, sizeof p->port_file, p->dir, "control-port")
        || path_in(p->log, sizeof p->log, p->dir, "tor.log")) {
        copy_str(err, "the temporary folder's path is too long", cap);
        torproc_stop(p);
        return NULL;
    }
    if (o && o->state && platform_private_dir(p->data) == 0) unpack_state(p, o->state, o->state_len);
    // An empty config file for both the torrc and the defaults, so nothing in the system's
    // /etc/tor/torrc (hidden services, other ports) applies.
    FILE *f = platform_fopen_private(p->torrc, "w");
    if (!f) { copy_str(err, "can't write tor's configuration", cap); torproc_stop(p); return NULL; }
    fclose(f);
    uint16_t socks_port, control_port;
    if (free_ports(&socks_port, &control_port) != 0) {
        copy_str(err, "no free local ports for tor", cap);
        torproc_stop(p);
        return NULL;
    }
    snprintf(p->socks, sizeof p->socks, "127.0.0.1:%u", (unsigned)socks_port);
    snprintf(p->control, sizeof p->control, "127.0.0.1:%u", (unsigned)control_port);
    uint8_t secret[PASSWORD_SECRET_LEN];
    char hashed[64];
    gen_random(secret, sizeof secret);
    hex_encode(secret, sizeof secret, p->password);
    crypto_wipe(secret, sizeof secret);
    if (hash_password(p->password, hashed, sizeof hashed) != 0) {
        copy_str(err, "couldn't make a password for tor's control port", cap);
        torproc_stop(p);
        return NULL;
    }
    char owner[24];
    snprintf(owner, sizeof owner, "%ld", platform_pid());
    const char *argv[ARGV_MAX] = {
        program,
        "-f", p->torrc,
        "--defaults-torrc", p->torrc,
        "--DataDirectory", p->data,
        "--SocksPort", p->socks,
        "--ControlPort", p->control,
        "--ControlPortWriteToFile", p->port_file,
        // Only the hash is on tor's command line, which anyone can read; the password stays in chat.
        "--HashedControlPassword", hashed,
        "--CookieAuthentication", "0",
        // tor exits by itself once chat's process is gone, crash or not.
        "--__OwningControllerProcess", owner,
        "--Log", "notice stdout",
        "--AvoidDiskWrites", "1",
        // Refuse SOCKS requests with an IP address, since that means a DNS lookup happened outside Tor.
        "--SafeSocks", "1",
        "--RunAsDaemon", "0",
    };
    int argc = 0;
    while (argv[argc]) argc++;
    // Not a byte to the Tor network until torproc_setconf has given it its bridges.
    if (o && o->hold_network) { argv[argc++] = "--DisableNetwork"; argv[argc++] = "1"; }
    argv[argc] = NULL;
    p->proc = platform_spawn(argv, p->log);
    if (!p->proc) {
        copy_str(err, "couldn't start tor", cap);
        torproc_stop(p);
        return NULL;
    }
    return p;
}

static int ctl_send_all(sock_t s, const char *text, double deadline) {
    size_t n = strlen(text), off = 0;
    while (off < n) {
        int w = net_tcp_send(s, text + off, n - off);
        if (w < 0) return -1;
        if (w == 0) {
            if (now_seconds() > deadline) return -1;
            platform_sleep_ms(CTL_POLL_MS);
            continue;
        }
        off += (size_t)w;
    }
    return 0;
}

// The code of tor's reply, from its last line ("250 OK"), with that line in last.
static int ctl_reply(sock_t s, double deadline, char *last, size_t cap) {
    char line[CTL_LINE_MAX];
    size_t n = 0;
    for (;;) {
        char ch;
        int r = net_tcp_recv(s, &ch, 1);
        if (r < 0) return -1;
        if (r == 0) {
            if (now_seconds() > deadline) return -1;
            int ready = 0;
            net_wait(&s, &ready, 1, CTL_POLL_MS);
            continue;
        }
        if (ch != '\n') {
            if (n < sizeof line - 1) line[n++] = ch;
            continue;
        }
        if (n && line[n - 1] == '\r') n--;
        line[n] = '\0';
        if (n >= 4 && line[3] == ' ') { clean_text(line, last, cap - 1); return atoi(line); }
        n = 0;
    }
}

// Logs in to tor's control port and sends each command, stopping at the first one tor refuses. 0, or
// -1 with why: "couldn't " the step that failed, and tor's answer.
static int ctl_run(const torproc_t *p, const char *const cmds[], const char *const steps[], int n, char *why,
                   size_t cap) {
    addr_t a;
    char last[CTL_LINE_MAX] = "";
    const char *step = "reach its control port";
    size_t cmd_cap = sizeof p->password + 32;
    for (int i = 0; i < n; i++)
        if (strlen(cmds[i]) + 3 > cmd_cap) cmd_cap = strlen(cmds[i]) + 3;
    char *cmd = malloc(cmd_cap);
    sock_t s = SOCK_INVALID;
    double deadline = now_seconds() + CTL_WAIT;
    int rc = -1, up = 0;
    if (cmd && addr_parse_ip_port(p->control, &a) == 0 && (s = net_tcp_connect(a)) != SOCK_INVALID)
        while ((up = net_tcp_connect_done(s)) == 0 && now_seconds() < deadline) platform_sleep_ms(CTL_POLL_MS);
    if (up == 1) {
        step = "log in to it";
        snprintf(cmd, cmd_cap, "AUTHENTICATE \"%s\"\r\n", p->password);
        rc = ctl_send_all(s, cmd, deadline) == 0 && ctl_reply(s, deadline, last, sizeof last) == CTL_OK ? 0 : -1;
        for (int i = 0; i < n && rc == 0; i++) {
            step = steps[i];
            snprintf(cmd, cmd_cap, "%s\r\n", cmds[i]);
            rc = ctl_send_all(s, cmd, deadline) == 0 && ctl_reply(s, deadline, last, sizeof last) == CTL_OK ? 0 : -1;
        }
    }
    if (rc != 0) snprintf(why, cap, "couldn't %s%s%s", step, last[0] ? ": " : "", last);
    if (cmd) { crypto_wipe(cmd, cmd_cap); free(cmd); }
    if (s != SOCK_INVALID) net_close(s);
    return rc;
}

int torproc_setconf(torproc_t *p, const char *conf, char *why, size_t cap) {
    size_t n = strlen(conf) + sizeof "SETCONF ";
    char *set = malloc(n);
    if (!set) { copy_str(why, "out of memory", cap); return -1; }
    snprintf(set, n, "SETCONF %s", conf);
    const char *cmds[] = { set, "SETCONF DisableNetwork=0" };
    static const char *const steps[] = { "give it its bridges", "let it reach the network" };
    int rc = ctl_run(p, cmds, steps, 2, why, cap);
    crypto_wipe(set, n);
    free(set);
    return rc;
}

// The files are measured first, so the pack is only as big as they are.
static void pack_state(const torproc_t *p, uint8_t **out, size_t *len) {
    FILE *f[N_KEPT] = { 0 };
    uint64_t size[N_KEPT];
    size_t total = sizeof STATE_MAGIC - 1, n = total;
    for (size_t k = 0; k < N_KEPT; k++) {
        char path[FILE_PATH_MAX + 32];
        size_t head = strlen(KEPT[k]) + 1 + STATE_LEN_BYTES;
        if (path_in(path, sizeof path, p->data, KEPT[k]) != 0) continue;
        if (!(f[k] = platform_open_regular(path, &size[k]))) continue;
        if (size[k] > STATE_MAX - total || head > STATE_MAX - total - size[k]) { fclose(f[k]); f[k] = NULL; continue; }
        total += head + (size_t)size[k];
    }
    uint8_t *buf = malloc(total);
    if (buf) memcpy(buf, STATE_MAGIC, n);
    for (size_t k = 0; k < N_KEPT; k++) {
        if (!f[k]) continue;
        if (buf) {
            size_t name_len = strlen(KEPT[k]) + 1, at = n + name_len + STATE_LEN_BYTES;
            size_t got = fread(buf + at, 1, (size_t)size[k], f[k]);
            memcpy(buf + n, KEPT[k], name_len);
            buf[n + name_len] = (uint8_t)(got >> 24);
            buf[n + name_len + 1] = (uint8_t)(got >> 16);
            buf[n + name_len + 2] = (uint8_t)(got >> 8);
            buf[n + name_len + 3] = (uint8_t)got;
            n = at + got;
        }
        fclose(f[k]);
    }
    *out = buf;
    *len = buf ? n : 0;
}

void torproc_finish(torproc_t *p, uint8_t **state, size_t *len) {
    *state = NULL;
    *len = 0;
    if (!p) return;
    // tor writes its state as it exits, but only when it exits by itself: on Windows, stopping it
    // ends it on the spot.
    static const char *const halt[] = { "SIGNAL HALT" }, *const halt_step[] = { "stop it" };
    char why[CTL_LINE_MAX];
    if (!platform_proc_exited(p->proc, NULL) && ctl_run(p, halt, halt_step, 1, why, sizeof why) == 0)
        for (int waited = 0; waited < STOP_WAIT_MS && !platform_proc_exited(p->proc, NULL); waited += CTL_POLL_MS)
            platform_sleep_ms(CTL_POLL_MS);
    pack_state(p, state, len);
    torproc_stop(p);
}

static void read_log(torproc_t *p) {
    double now = now_seconds();
    if (now < p->next_read) return;
    p->next_read = now + LOG_READ_EVERY;
    FILE *f = platform_fopen(p->log, "rb");
    if (!f) return;
    static char buf[LOG_TAIL + 1];
    long start = 0;
    if (fseek(f, 0, SEEK_END) == 0) {
        long size = ftell(f);
        if (size > LOG_TAIL) start = size - LOG_TAIL;
    }
    fseek(f, start, SEEK_SET);
    size_t n = fread(buf, 1, LOG_TAIL, f);
    fclose(f);
    buf[n] = '\0';
    for (char *line = buf; line && *line; ) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';
        static const char BOOT[] = "Bootstrapped ", TOR[] = "Tor ";
        const char *b = strstr(line, BOOT);
        if (b) p->boot = atoi(b + sizeof BOOT - 1);
        const char *v = strstr(line, TOR);
        if (!p->version[0] && v && strstr(line, "running on")) {
            size_t vl = strcspn(v + sizeof TOR - 1, " (") + sizeof TOR - 1;
            if (vl < sizeof p->version) { memcpy(p->version, v, vl); p->version[vl] = '\0'; }
        }
        if (strstr(line, "[warn]") || strstr(line, "[err]")) {
            const char *m = strstr(line, "] ");
            clean_text(m ? m + 2 : line, p->problem, sizeof p->problem - 1);
        }
        // The last thing tor printed. If it dies before logging (a missing library, say), this has why.
        if (line[0]) clean_text(line, p->last_line, sizeof p->last_line - 1);
        line = eol ? eol + 1 : NULL;
    }
}

torproc_state_t torproc_poll(torproc_t *p) {
    read_log(p);
    if (platform_proc_exited(p->proc, &p->code)) {
        p->next_read = 0;
        read_log(p);
        return TORPROC_EXITED;
    }
    FILE *f = platform_fopen(p->port_file, "rb");
    if (!f) return TORPROC_STARTING;
    fclose(f);
    return TORPROC_READY;
}

const char *torproc_socks(const torproc_t *p) { return p->socks; }
const char *torproc_control(const torproc_t *p) { return p->control; }
const char *torproc_password(const torproc_t *p) { return p->password; }
int torproc_bootstrap(torproc_t *p) { read_log(p); return p->boot; }
const char *torproc_version(torproc_t *p) { read_log(p); return p->version; }
void torproc_problem(torproc_t *p, char *out, size_t cap) {
    if (p->problem[0]) copy_str(out, p->problem, cap);
    else if (p->last_line[0]) snprintf(out, cap, "%s (exit code %d)", p->last_line, p->code);
    else snprintf(out, cap, "exit code %d, nothing logged", p->code);
}

void torproc_stop(torproc_t *p) {
    if (!p) return;
    platform_proc_stop(p->proc, STOP_WAIT_MS);
    if (p->dir[0]) platform_remove_tree(p->dir);
    crypto_wipe(p->password, sizeof p->password);
    free(p);
}
