// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/torproc.h"
#include "platform/net.h"
#include "platform/platform.h"
#include "common/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAIL 16384

struct torproc {
    platform_proc_t *proc;
    char dir[1024];
    char torrc[1100], data[1100], port_file[1100], cookie[1100], log[1100];
    char socks[32], control[32];
    char version[80];
    char problem[200], last_line[200];
    int code;
    int boot;
    double next_read;
};

// Two free ports on 127.0.0.1, held open together so they differ. Another program could take
// one before tor does; tor then exits and the caller starts it again.
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

torproc_t *torproc_start(const char *program, char *err, size_t cap) {
    torproc_t *p = calloc(1, sizeof *p);
    if (!p) { copy_str(err, "out of memory", cap); return NULL; }
    p->boot = -1;
    // What a crashed chat left: its tor has quit by now (it watches chat's process), the folder stays.
    platform_remove_stale_tempdirs("chat-tor", "data/lock");
    if (platform_private_tempdir("chat-tor", p->dir, sizeof p->dir) != 0) {
        copy_str(err, "can't make a private folder for tor", cap);
        free(p);
        return NULL;
    }
    if (path_in(p->torrc, sizeof p->torrc, p->dir, "torrc") || path_in(p->data, sizeof p->data, p->dir, "data")
        || path_in(p->port_file, sizeof p->port_file, p->dir, "control-port")
        || path_in(p->cookie, sizeof p->cookie, p->dir, "control_auth_cookie")
        || path_in(p->log, sizeof p->log, p->dir, "tor.log")) {
        copy_str(err, "the temporary folder's path is too long", cap);
        torproc_stop(p);
        return NULL;
    }
    // An empty configuration of our own for both the torrc and the defaults, so the system's
    // /etc/tor/torrc (hidden services, other ports, whatever it holds) plays no part.
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
    char owner[24];
    snprintf(owner, sizeof owner, "%ld", platform_pid());
    const char *argv[] = {
        program,
        "-f", p->torrc,
        "--defaults-torrc", p->torrc,
        "--DataDirectory", p->data,
        "--SocksPort", p->socks,
        "--ControlPort", p->control,
        "--ControlPortWriteToFile", p->port_file,
        "--CookieAuthentication", "1",
        "--CookieAuthFile", p->cookie,
        // tor exits by itself once chat's process is gone, crash or not.
        "--__OwningControllerProcess", owner,
        "--Log", "notice stdout",
        "--AvoidDiskWrites", "1",
        // Refuse SOCKS requests that carry an IP address a DNS lookup elsewhere must have made.
        "--SafeSocks", "1",
        "--RunAsDaemon", "0",
        NULL
    };
    p->proc = platform_spawn(argv, p->log);
    if (!p->proc) {
        copy_str(err, "couldn't start tor", cap);
        torproc_stop(p);
        return NULL;
    }
    return p;
}

static void read_log(torproc_t *p) {
    double now = now_seconds();
    if (now < p->next_read) return;
    p->next_read = now + 1.0;
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
        const char *b = strstr(line, "Bootstrapped ");
        if (b) p->boot = atoi(b + 13);
        const char *v = strstr(line, "Tor ");
        if (!p->version[0] && v && strstr(line, "running on")) {
            size_t vl = strcspn(v + 4, " (") + 4;
            if (vl < sizeof p->version) { memcpy(p->version, v, vl); p->version[vl] = '\0'; }
        }
        if (strstr(line, "[warn]") || strstr(line, "[err]")) {
            const char *m = strstr(line, "] ");
            clean_text(m ? m + 2 : line, p->problem, sizeof p->problem - 1);
        }
        // Whatever tor printed last: a program that dies before it logs (a missing library) says why there.
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
int torproc_bootstrap(torproc_t *p) { read_log(p); return p->boot; }
const char *torproc_version(torproc_t *p) { read_log(p); return p->version; }
void torproc_problem(torproc_t *p, char *out, size_t cap) {
    if (p->problem[0]) copy_str(out, p->problem, cap);
    else if (p->last_line[0]) snprintf(out, cap, "%s (exit code %d)", p->last_line, p->code);
    else snprintf(out, cap, "exit code %d, nothing logged", p->code);
}

void torproc_stop(torproc_t *p) {
    if (!p) return;
    platform_proc_stop(p->proc, 3000);
    if (p->dir[0]) platform_remove_tree(p->dir);
    free(p);
}
