// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Notifications, the clipboard, and opening links.
#include "posix.h"
#include "crypto/crypto.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

// Notifications go to the desktop's notification service over the session bus, straight from
// chat. Through notify-send, each would start a process anyone can see, with its title and text
// on a command line every user on the computer can read.
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int g_bus = -1;
static uint32_t g_bus_serial;
// A reply was left half read on it, so the next message goes on a new connection.
static int g_bus_stale;

// A D-Bus message: its header (byte order, type, flags, version, body length, serial, then the
// header fields), padded to 8, then the body. A field is its code and a variant.
#define DBUS_MSG_MAX 4096
#define DBUS_ALIGN 8
enum { DBUS_METHOD_CALL = 1, DBUS_VERSION = 1, DBUS_NO_REPLY = 1 };
enum { DF_PATH = 1, DF_INTERFACE = 2, DF_MEMBER = 3, DF_DESTINATION = 6, DF_SIGNATURE = 8 };
// A connection's timeouts. This runs on the UI's thread: a hung bus costs a moment, not the run.
#define BUS_TIMEOUT_US 300000

// A D-Bus message being written. Values are aligned from the start of the message.
typedef struct { uint8_t b[DBUS_MSG_MAX]; size_t n; int bad; } dmsg_t;

static void d_put(dmsg_t *d, const void *p, size_t len) {
    if (d->bad || d->n + len > sizeof d->b) { d->bad = 1; return; }
    memcpy(d->b + d->n, p, len);
    d->n += len;
}

static void d_pad(dmsg_t *d, size_t align) {
    static const uint8_t zero[DBUS_ALIGN];
    if (d->n % align) d_put(d, zero, align - d->n % align);
}

static void d_u32(dmsg_t *d, uint32_t v) { d_pad(d, sizeof v); d_put(d, &v, sizeof v); }

static void d_str(dmsg_t *d, const char *s) {
    size_t len = strlen(s);
    d_u32(d, (uint32_t)len);
    d_put(d, s, len + 1);
}

static void d_sig(dmsg_t *d, const char *s) {
    uint8_t len = (uint8_t)strlen(s);
    d_put(d, &len, 1);
    d_put(d, s, (size_t)len + 1);
}

// A header field: its code, then its value as a variant.
static void d_field(dmsg_t *d, uint8_t code, const char *type, const char *value) {
    d_pad(d, DBUS_ALIGN);
    d_put(d, &code, 1);
    d_sig(d, type);
    if (type[0] == 'g') d_sig(d, value);
    else d_str(d, value);
}

// A method call, in this machine's byte order. args was written from offset 0, which aligns its
// values as they will be at the 8 byte boundary the body starts on.
static int d_call(dmsg_t *m, uint8_t flags, const char *dest, const char *path, const char *iface, const char *member,
                  const char *sig, const dmsg_t *args) {
    static const uint16_t one = 1;
    const uint8_t head[4] = { *(const uint8_t *)&one ? 'l' : 'B', DBUS_METHOD_CALL, flags, DBUS_VERSION };
    m->n = 0;
    m->bad = 0;
    d_put(m, head, sizeof head);
    d_u32(m, args ? (uint32_t)args->n : 0);
    d_u32(m, ++g_bus_serial);
    size_t len_at = m->n;
    d_u32(m, 0);
    d_pad(m, DBUS_ALIGN);
    size_t start = m->n;
    d_field(m, DF_PATH, "o", path);
    d_field(m, DF_INTERFACE, "s", iface);
    d_field(m, DF_MEMBER, "s", member);
    d_field(m, DF_DESTINATION, "s", dest);
    if (sig) d_field(m, DF_SIGNATURE, "g", sig);
    uint32_t fields = (uint32_t)(m->n - start);
    if (!m->bad) memcpy(m->b + len_at, &fields, sizeof fields);
    d_pad(m, DBUS_ALIGN);
    if (args) d_put(m, args->b, args->n);
    return m->bad || (args && args->bad) ? -1 : 0;
}

static int send_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t w = send(fd, p, len, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        len -= (size_t)w;
    }
    return 0;
}

static int recv_line(int fd, char *out, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = recv(fd, out + n, 1, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        if (out[n] == '\n') { out[n] = '\0'; return 0; }
        n++;
    }
    return -1;
}

// The session bus's socket: the first unix: path or abstract name in DBUS_SESSION_BUS_ADDRESS
// (its values %-escaped), otherwise $XDG_RUNTIME_DIR/bus.
static int bus_address(struct sockaddr_un *sa, socklen_t *len) {
    memset(sa, 0, sizeof *sa);
    sa->sun_family = AF_UNIX;
    const char *env = getenv("DBUS_SESSION_BUS_ADDRESS");
    char addr[1024];
    copy_str(addr, env ? env : "", sizeof addr);
    static const char BUS_UNIX[] = "unix:", KEY_ABSTRACT[] = "abstract=", KEY_PATH[] = "path=";
    for (char *s1 = NULL, *a = strtok_r(addr, ";", &s1); a; a = strtok_r(NULL, ";", &s1)) {
        if (!starts_with(a, BUS_UNIX)) continue;
        for (char *s2 = NULL, *kv = strtok_r(a + sizeof BUS_UNIX - 1, ",", &s2); kv; kv = strtok_r(NULL, ",", &s2)) {
            size_t abstract = starts_with(kv, KEY_ABSTRACT);
            if (!abstract && !starts_with(kv, KEY_PATH)) continue;
            const char *v = kv + (abstract ? sizeof KEY_ABSTRACT - 1 : sizeof KEY_PATH - 1);
            char *out = sa->sun_path + abstract;
            size_t cap = sizeof sa->sun_path - abstract - 1, o = 0;
            for (; *v && o < cap; v++) {
                if (*v == '%' && hex_value(v[1]) >= 0 && hex_value(v[2]) >= 0) {
                    out[o++] = (char)(hex_value(v[1]) * 16 + hex_value(v[2]));
                    v += 2;
                } else out[o++] = *v;
            }
            if (*v || o == 0) continue;
            out[o] = '\0';
            // An abstract name is the bytes after a leading NUL, with none to end it.
            if (abstract) sa->sun_path[0] = '\0';
            *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + abstract + o + !abstract);
            return 0;
        }
    }
    const char *rt = getenv("XDG_RUNTIME_DIR");
    if (!rt || rt[0] != '/') return -1;
    int n = snprintf(sa->sun_path, sizeof sa->sun_path, "%s/bus", rt);
    if (n <= 0 || (size_t)n >= sizeof sa->sun_path) return -1;
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + (size_t)n + 1);
    return 0;
}

static int bus_connect(void) {
    struct sockaddr_un sa;
    socklen_t salen;
    if (bus_address(&sa, &salen) != 0) return -1;
#ifdef SOCK_CLOEXEC
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
    if (fd < 0) return -1;
    struct timeval tv = { 0, BUS_TIMEOUT_US };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    // EXTERNAL: the bus checks the uid the kernel reports for the socket, sent as hex of its digits.
    char uid[24], auth[64], line[160];
    snprintf(uid, sizeof uid, "%u", (unsigned)geteuid());
    size_t n = 1;
    auth[0] = '\0';
    n += (size_t)snprintf(auth + n, sizeof auth - n, "AUTH EXTERNAL ");
    for (const char *c = uid; *c; c++) n += (size_t)snprintf(auth + n, sizeof auth - n, "%02x", (unsigned)(unsigned char)*c);
    n += (size_t)snprintf(auth + n, sizeof auth - n, "\r\n");
    dmsg_t hello;
    if (connect(fd, (struct sockaddr *)&sa, salen) != 0 || send_all(fd, auth, n) != 0
        || recv_line(fd, line, sizeof line) != 0 || !starts_with(line, "OK ") || send_all(fd, "BEGIN\r\n", sizeof "BEGIN\r\n" - 1) != 0
        || d_call(&hello, 0, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", NULL, NULL) != 0
        || send_all(fd, hello.b, hello.n) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Replies and signals (Hello's answer, NameAcquired, an error) are read and dropped, so they never
// pile up. -1 once the bus has closed the connection.
static int bus_drain(int fd) {
    char junk[1024];
    for (;;) {
        ssize_t r = recv(fd, junk, sizeof junk, MSG_DONTWAIT);
        if (r > 0 || (r < 0 && errno == EINTR)) continue;
        return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    }
}

// Once more on a new connection if the bus has dropped the old one.
static int bus_send(const dmsg_t *m) {
    if (g_bus >= 0 && g_bus_stale) { close(g_bus); g_bus = -1; }
    g_bus_stale = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (g_bus < 0) g_bus = bus_connect();
        if (g_bus < 0) return -1;
        if (bus_drain(g_bus) == 0 && send_all(g_bus, m->b, m->n) == 0) return 0;
        close(g_bus);
        g_bus = -1;
    }
    return -1;
}

// The bus drops a connection that sends malformed UTF-8, so such bytes become '?'.
static void utf8_safe(const char *in, char *out, size_t cap) {
    size_t n = strlen(in), o = 0, adv = 1;
    for (size_t i = 0; i < n && o + 4 < cap; i += adv) {
        uint32_t cp = utf8_decode(in, n, i, &adv);
        if (adv == 1 && cp >= 0x80) out[o++] = '?';
        else { memcpy(out + o, in + i, adv); o += adv; }
    }
    out[o] = '\0';
}

static void markup_escape(const char *in, char *out, size_t outlen) {
    size_t o = 0;
    for (; *in; in++) {
        const char *rep = NULL;
        if (*in == '&') rep = "&amp;";
        else if (*in == '<') rep = "&lt;";
        else if (*in == '>') rep = "&gt;";
        size_t n = rep ? strlen(rep) : 1;
        if (o + n >= outlen) break;
        if (rep) memcpy(out + o, rep, n);
        else out[o] = *in;
        o += n;
    }
    out[o] = '\0';
}

// org.freedesktop.Notifications.Notify, with no reply asked for. Called from the main thread only.
void platform_notify(const char *title, const char *body) {
    char t[160], esc[1400], b[1400];
    utf8_safe(title, t, sizeof t);
    markup_escape(body, esc, sizeof esc);
    utf8_safe(esc, b, sizeof b);
    dmsg_t args = { .n = 0 }, call;
    d_str(&args, "chat");      // app_name
    d_u32(&args, 0);           // replaces_id
    d_str(&args, "");          // app_icon
    d_str(&args, t);           // summary
    d_str(&args, b);           // body
    d_u32(&args, 0);           // actions: none
    // hints: {"transient": true}. Shown, but not kept in the desktop's notification history, which
    // would otherwise record when messages came in (and, with previews on, what they said).
    d_u32(&args, 0);
    size_t hints_len_at = args.n - 4;
    d_pad(&args, 8);
    size_t hints_at = args.n;
    d_str(&args, "transient");
    d_sig(&args, "b");
    d_u32(&args, 1);
    uint32_t hints_len = (uint32_t)(args.n - hints_at);
    if (!args.bad) memcpy(args.b + hints_len_at, &hints_len, sizeof hints_len);
    d_u32(&args, UINT32_MAX);   // expire_timeout -1: the desktop's default
    if (d_call(&call, DBUS_NO_REPLY, "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
               "org.freedesktop.Notifications", "Notify", "susssasa{sv}i", &args) == 0)
        bus_send(&call);
    crypto_wipe(t, sizeof t);
    crypto_wipe(esc, sizeof esc);
    crypto_wipe(b, sizeof b);
    crypto_wipe(&args, sizeof args);
    crypto_wipe(&call, sizeof call);
}

void platform_notify_shutdown(void) {
    if (g_bus >= 0) { close(g_bus); g_bus = -1; }
}

#ifndef __APPLE__
// How long opening a link waits for the portal's answer, on the UI's thread. A portal still starting
// gets the link once it's up, so no answer by then counts as taken.
#define PORTAL_WAIT_MS 1500
#define DBUS_HEAD 16
enum { DBUS_METHOD_RETURN = 2, DBUS_ERROR = 3, DF_REPLY_SERIAL = 5 };
enum { BUS_ANSWERED = 0, BUS_REFUSED = -1, BUS_BROKEN = -2, BUS_LATE = 1 };

// len bytes by end, as now_seconds() counts.
static int bus_read(int fd, uint8_t *buf, size_t len, double end) {
    while (len > 0) {
        int ms = (int)((end - now_seconds()) * 1000);
        if (ms <= 0) return BUS_LATE;
        struct pollfd pf = { fd, POLLIN, 0 };
        int r = poll(&pf, 1, ms);
        if (r < 0 && errno == EINTR) continue;
        if (r == 0) return BUS_LATE;
        ssize_t got = r < 0 ? -1 : recv(fd, buf, len, MSG_DONTWAIT);
        if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (got <= 0) return BUS_BROKEN;
        buf += got;
        len -= (size_t)got;
    }
    return 0;
}

static uint32_t d_get32(const uint8_t *p, int big) {
    return big ? load_be32(p) : (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

// The REPLY_SERIAL among a message's header fields (n bytes, from an 8 byte boundary), or 0.
static uint32_t d_reply_serial(const uint8_t *f, size_t n, int big) {
    for (size_t i = 0; i + 4 <= n; ) {
        uint8_t code = f[i], sl = f[i + 1];
        size_t v = i + 2 + sl + 1;
        if (v > n) break;
        char t = sl == 1 ? (char)f[i + 2] : 0;
        if (t == 'u' || t == 's' || t == 'o') {
            v = (v + 3) & ~(size_t)3;
            if (v + 4 > n) break;
            uint32_t x = d_get32(f + v, big);
            if (t == 'u' && code == DF_REPLY_SERIAL) return x;
            if (t != 'u' && x > n) break;
            v += 4 + (t == 'u' ? 0 : (size_t)x + 1);
        } else if (t == 'g') {
            if (v >= n) break;
            v += 1 + (size_t)f[v] + 1;
        } else {
            break;
        }
        i = (v + DBUS_ALIGN - 1) & ~(size_t)(DBUS_ALIGN - 1);
    }
    return 0;
}

// Reads what the bus sends until the answer to the call numbered serial.
static int bus_reply(int fd, uint32_t serial, double end) {
    uint8_t head[DBUS_HEAD], buf[DBUS_MSG_MAX];
    for (;;) {
        int r = bus_read(fd, head, sizeof head, end);
        if (r != 0) return r;
        int big = head[0] == 'B';
        if (!big && head[0] != 'l') return BUS_BROKEN;
        uint32_t body = d_get32(head + 4, big), fields = d_get32(head + 12, big);
        uint64_t rest = (uint64_t)fields + (DBUS_ALIGN - (DBUS_HEAD + fields) % DBUS_ALIGN) % DBUS_ALIGN + body;
        uint32_t answers = 0;
        if (fields <= sizeof buf) {
            if ((r = bus_read(fd, buf, fields, end)) != 0) return r;
            answers = d_reply_serial(buf, fields, big);
            rest -= fields;
        }
        while (rest > 0) {
            size_t chunk = rest < sizeof buf ? (size_t)rest : sizeof buf;
            if ((r = bus_read(fd, buf, chunk, end)) != 0) return r;
            rest -= chunk;
        }
        if (answers == serial && head[1] == DBUS_METHOD_RETURN) return BUS_ANSWERED;
        if (answers == serial && head[1] == DBUS_ERROR) return BUS_REFUSED;
    }
}

// The desktop portal's OpenURI: the desktop opens it, outside chat and its sandbox.
static int portal_open(const char *url) {
    dmsg_t args = { .n = 0 }, call;
    d_str(&args, "");    // parent_window
    d_str(&args, url);
    d_u32(&args, 0);     // options: none
    d_pad(&args, DBUS_ALIGN);
    if (d_call(&call, 0, "org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop",
               "org.freedesktop.portal.OpenURI", "OpenURI", "ssa{sv}", &args) != 0) return -1;
    uint32_t serial = g_bus_serial;
    if (bus_send(&call) != 0) return -1;
    int r = bus_reply(g_bus, serial, now_seconds() + PORTAL_WAIT_MS / 1000.0);
    if (r == BUS_LATE) g_bus_stale = 1;
    if (r == BUS_BROKEN) { close(g_bus); g_bus = -1; }
    return r == BUS_ANSWERED || r == BUS_LATE ? 0 : -1;
}
#endif

// Linux: the portal, else xdg-open, which the sandbox doesn't let chat start.
int platform_open_url(const char *url, char *why, size_t cap) {
#ifdef __APPLE__
    const char *const argv[] = { "open", url, NULL };
    if (platform_run_quiet(argv) == 0) return 0;
    copy_str(why, "macOS's open couldn't open it", cap);
    return -1;
#else
    if (portal_open(url) == 0) return 0;
    char path[PATH_BUF];
    if (platform_find_program("xdg-open", NULL, path, sizeof path) != 0) {
        copy_str(why, "no desktop portal answered, and there's no xdg-open", cap);
        return -1;
    }
    int rc = posix_run_detached(path, url);
    if (rc == 0) return 0;
    snprintf(why, cap, "no desktop portal answered, and %s",
             rc == EACCES || rc == EPERM ? "the sandbox keeps chat from starting xdg-open" : "xdg-open didn't start");
    return -1;
#endif
}

// The clipboard belongs to the desktop, which chat doesn't talk to, so the terminal sets it.
int platform_clipboard_set(const char *text) { (void)text; return -1; }
int platform_clipboard_clear(void) { return -1; }
