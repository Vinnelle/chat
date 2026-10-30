// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Files and folders: listing, reading and writing them, the folders chat keeps its files in,
// temporary folders, and what chat reads from the system (the machine id, the default gateway, the
// CA roots).
#include "posix.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <uuid/uuid.h>
#endif

// The permission bits that let in anyone but this user.
#define MODE_GROUP_OTHER 077
// The most folders deep a tree is removed, and how many times it's gone over.
#define REMOVE_DEPTH_MAX 16
#define REMOVE_PASSES 4
// A temporary folder younger than this may still be being set up by another chat.
#define STALE_AFTER 60
#define MACHINE_ID_LEN 32
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1u
#endif

int platform_list_dir(const char *path, dir_entry_cb cb, void *ctx) {
    DIR *d = opendir(path);
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0) continue;
        char full[1400];
        snprintf(full, sizeof full, "%s/%s", path, de->d_name);
        struct stat st;
        cb(ctx, de->d_name, (stat(full, &st) == 0) && S_ISDIR(st.st_mode));
    }
    closedir(d);
    return 0;
}

int platform_file_info(const char *utf8_path, file_info_t *out) {
    struct stat st, lst;
    if (lstat(utf8_path, &lst) != 0) return -1;
    if (stat(utf8_path, &st) != 0) st = lst;   // a broken link: the link itself
    out->is_dir = S_ISDIR(st.st_mode);
    out->is_link = S_ISLNK(lst.st_mode);
    out->size = st.st_size > 0 ? (uint64_t)st.st_size : 0;
    struct tm tmv;
    time_t t = st.st_mtime;
    if (localtime_r(&t, &tmv)) strftime(out->modified, sizeof out->modified, "%Y-%m-%d %H:%M", &tmv);
    else out->modified[0] = '\0';
    out->mode = (int)(st.st_mode & MODE_BITS);
    return 0;
}

const char *platform_home_dir(void) {
    const char *h = getenv("HOME");
    return (h && h[0]) ? h : NULL;
}

int platform_machine_id(char *out, size_t cap) {
#ifdef __APPLE__
    // The hardware UUID, which, like a Linux machine id, any program can read.
    uuid_t u;
    struct timespec wait = { 0, 0 };
    if (cap <= MACHINE_ID_LEN || gethostuuid(u, &wait) != 0) return -1;
    hex_encode(u, sizeof u, out);
    return 0;
#endif
    static const char *const PATHS[] = { "/etc/machine-id", "/var/lib/dbus/machine-id" };
    for (size_t i = 0; i < COUNT_OF(PATHS); i++) {
        FILE *f = fopen(PATHS[i], "r");
        if (!f) continue;
        char line[64];
        char *got = fgets(line, sizeof line, f);
        fclose(f);
        if (!got) continue;
        line[strcspn(line, "\r\n")] = '\0';
        // 32 hex digits; systemd writes "uninitialized" there until the first boot is done.
        if (strlen(line) == MACHINE_ID_LEN && strspn(line, HEX_DIGITS) == MACHINE_ID_LEN && cap > MACHINE_ID_LEN) {
            copy_str(out, line, cap);
            return 0;
        }
    }
    return -1;
}

FILE *platform_fopen(const char *utf8_path, const char *mode) {
    return fopen(utf8_path, mode);
}

FILE *platform_fopen_private(const char *utf8_path, const char *mode) {
    int flags;
    if (mode[0] == 'r') flags = (strchr(mode, '+') ? O_RDWR : O_RDONLY);
    else if (mode[0] == 'w') flags = O_CREAT | O_TRUNC | (strchr(mode, '+') ? O_RDWR : O_WRONLY);
    else if (mode[0] == 'a') flags = O_CREAT | O_APPEND | (strchr(mode, '+') ? O_RDWR : O_WRONLY);
    else return NULL;
    int fd = open(utf8_path, flags | O_NOFOLLOW | O_CLOEXEC, MODE_PRIVATE_FILE);
    if (fd < 0) return NULL;
    fchmod(fd, MODE_PRIVATE_FILE);
    FILE *f = fdopen(fd, mode);
    if (!f) close(fd);
    return f;
}

long platform_read_file(const char *utf8_path, void *buf, size_t cap) {
    int fd = -1;
#ifdef O_NOATIME
    // Reading a save doesn't record when it was opened. Refused for a file someone else owns.
    fd = open(utf8_path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC | O_NOATIME);
    if (fd < 0 && errno == EPERM)
#endif
        fd = open(utf8_path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    long got = -1;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        size_t n = 0;
        while (n < cap) {
            ssize_t r = read(fd, (char *)buf + n, cap - n);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            n += (size_t)r;
        }
        got = (long)n;
    }
    close(fd);
    return got;
}

int platform_full_path(const char *utf8_path, char *out, size_t cap) {
    if (utf8_path[0] == '/') {
        int n = snprintf(out, cap, "%s", utf8_path);
        return n > 0 && (size_t)n < cap ? 0 : -1;
    }
    char cwd[1024];
    if (!getcwd(cwd, sizeof cwd)) return -1;
    int n = snprintf(out, cap, "%s/%s", strcmp(cwd, "/") == 0 ? "" : cwd, utf8_path);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

FILE *platform_open_regular(const char *utf8_path, uint64_t *size) {
    int fd = open(utf8_path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) { close(fd); return NULL; }
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    FILE *f = fdopen(fd, "rb");
    if (!f) { close(fd); return NULL; }
    *size = (uint64_t)st.st_size;
    return f;
}

int platform_downloads_dir(char *out, size_t cap) {
    const char *home = getenv("HOME");
    if (!home || home[0] != '/') return -1;
    int n = snprintf(out, cap, "%s/Downloads", home);
    if (n <= 0 || (size_t)n >= cap) return -1;
    if (mkdir(out, MODE_PRIVATE_DIR) != 0 && errno != EEXIST) return -1;
    struct stat st;
    return stat(out, &st) == 0 && S_ISDIR(st.st_mode) ? 0 : -1;
}

FILE *platform_create_new(const char *utf8_path) {
    int fd = open(utf8_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC, MODE_PRIVATE_FILE);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "wb");
    if (!f) close(fd);
    return f;
}

int platform_move_new(const char *from, const char *to) {
#ifdef __ANDROID__
    // Android's SELinux policy refuses hard links, and an app's own filter kills a process for
    // renameat2 before Android 11. So the name is taken with a new empty file first, which fails if
    // it's already taken, and the rename only replaces that.
    int fd = open(to, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    close(fd);
    if (rename(from, to) == 0) return 0;
    unlink(to);
    return -1;
#else
    // A hard link fails if the name is taken, so nothing is ever replaced.
    if (link(from, to) == 0) { unlink(from); return 0; }
    if (errno == EEXIST) return -1;
#ifdef SYS_renameat2
    // A filesystem without hard links (FAT, some FUSE ones): use a rename that won't replace.
    if (syscall(SYS_renameat2, AT_FDCWD, from, AT_FDCWD, to, RENAME_NOREPLACE) == 0) return 0;
#endif
    return -1;
#endif
}

int platform_config_dir(char *out, size_t cap, int create) {
    const char *xdg = getenv("XDG_CONFIG_HOME"), *home = getenv("HOME");
    char base[900];
    int n;
    // The XDG spec ignores a relative one.
    if (xdg && xdg[0] == '/') n = snprintf(base, sizeof base, "%s", xdg);
    else if (home && home[0] == '/') n = snprintf(base, sizeof base, "%s/.config", home);
    else return -1;
    if (n <= 0 || (size_t)n >= sizeof base) return -1;
    n = snprintf(out, cap, "%s/chat", base);
    if (n <= 0 || (size_t)n >= cap) return -1;
    if (!create) return 0;
    if (mkdir(base, MODE_PRIVATE_DIR) != 0 && errno != EEXIST) return -1;
    return platform_private_dir(out);
}

int platform_private_dir(const char *utf8_path) {
    if (mkdir(utf8_path, MODE_PRIVATE_DIR) != 0 && errno != EEXIST) return -1;
    // Not a link to somewhere else.
    struct stat st;
    if (lstat(utf8_path, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid()) return -1;
    return (st.st_mode & MODE_GROUP_OTHER) && chmod(utf8_path, MODE_PRIVATE_DIR) != 0 ? -1 : 0;
}

int platform_write_private(const char *utf8_path, const void *data, size_t len) {
    char tmp[PATH_BUF];
    int n = snprintf(tmp, sizeof tmp, "%s.new", utf8_path);
    if (n <= 0 || (size_t)n >= sizeof tmp) return -1;
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC, MODE_PRIVATE_FILE);
    if (fd < 0) return -1;
    const char *p = data;
    int ok = 1;
    for (size_t left = len; ok && left > 0; ) {
        ssize_t w = write(fd, p, left);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) ok = 0;
        else { p += w; left -= (size_t)w; }
    }
    if (ok && fsync(fd) != 0) ok = 0;
    if (close(fd) != 0) ok = 0;
    if (!ok || rename(tmp, utf8_path) != 0) { unlink(tmp); return -1; }
    // The rename is only on disk once the folder is synced.
    char dir[PATH_BUF];
    copy_str(dir, utf8_path, sizeof dir);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
    }
    return 0;
}

int platform_remove(const char *utf8_path) {
    return unlink(utf8_path);
}

// A route's flags in /proc/net/route: it's up, and it goes through a gateway.
#define ROUTE_UP 0x1
#define ROUTE_GATEWAY 0x2

// macOS has no /proc: there the router is asked over UPnP alone, which finds it by multicast.
int platform_default_gateway(uint8_t ip[IP4_LEN]) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;
    char line[256];
    int found = -1;
    unsigned best_metric = ~0u;
    // Iface Destination Gateway Flags RefCnt Use Metric Mask ..., addresses in host byte order hex.
    while (fgets(line, sizeof line, f)) {
        char iface[64];
        unsigned dest, gw, flags, refcnt, use, metric, mask;
        if (sscanf(line, "%63s %x %x %x %u %u %u %x", iface, &dest, &gw, &flags, &refcnt, &use, &metric, &mask) != 8) continue;
        if (dest != 0 || mask != 0 || !(flags & ROUTE_GATEWAY) || !(flags & ROUTE_UP) || gw == 0) continue;
        if (found == 0 && metric >= best_metric) continue;
        memcpy(ip, &gw, IP4_LEN);
        best_metric = metric;
        found = 0;
    }
    fclose(f);
    return found;
}

#ifdef __ANDROID__
// Android keeps its roots one to a file. How many of dir's were added.
static int add_cert_dir(const char *dir, int (*add_file)(void *ctx, const char *path), void *ctx) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int n = 0;
    char path[PATH_BUF];
    for (struct dirent *e; (e = readdir(d)) != NULL;) {
        if (e->d_name[0] == '.') continue;
        int len = snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (len > 0 && (size_t)len < sizeof path && add_file(ctx, path) == 0) n++;
    }
    closedir(d);
    return n;
}
#endif

void platform_ca_roots(void (*add_der)(void *ctx, const uint8_t *der, size_t len),
                       int (*add_file)(void *ctx, const char *path), void *ctx) {
    (void)add_der;
    static const char *const BUNDLES[] = {
        "/etc/ssl/certs/ca-certificates.crt",   // Debian, Ubuntu, Arch, Gentoo
        "/etc/pki/tls/certs/ca-bundle.crt",     // Fedora, RHEL
        "/etc/ssl/ca-bundle.pem",               // openSUSE
        "/etc/pki/tls/cacert.pem",              // OpenELEC
        "/etc/ssl/cert.pem",                    // Alpine, Void
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    };
    const char *env = getenv("SSL_CERT_FILE");
    if (env && env[0] && add_file(ctx, env) == 0) return;
#ifdef __ANDROID__
    // Since Android 14 the roots kept up to date come with the Conscrypt module, and the system's
    // own can be out of date.
    static const char *const DIRS[] = { "/apex/com.android.conscrypt/cacerts", "/system/etc/security/cacerts" };
    for (size_t i = 0; i < COUNT_OF(DIRS); i++)
        if (add_cert_dir(DIRS[i], add_file, ctx) > 0) return;
#endif
    for (size_t i = 0; i < COUNT_OF(BUNDLES); i++)
        if (add_file(ctx, BUNDLES[i]) == 0) return;
}

static int private_dir_ok(const char *dir) {
    struct stat st;
    return dir && dir[0] == '/' && stat(dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid()
        && (st.st_mode & MODE_GROUP_OTHER) == 0;
}

const char *tempdir_base(void) {
    // XDG_RUNTIME_DIR belongs to this user only and is usually in memory, and macOS gives each user
    // a private TMPDIR. /tmp is the fallback, where mkdtemp still creates the folder as 0700 with a
    // name nobody can guess.
    const char *base = getenv("XDG_RUNTIME_DIR");
    if (private_dir_ok(base)) return base;
    base = getenv("TMPDIR");
    return private_dir_ok(base) ? base : "/tmp";
}

int platform_private_tempdir(const char *prefix, char *out, size_t cap) {
    const char *base = tempdir_base();
    char tmpl[PATH_BUF];
    int n = snprintf(tmpl, sizeof tmpl, "%s/%s-XXXXXX", base, prefix);
    if (n <= 0 || (size_t)n >= sizeof tmpl || (size_t)n >= cap) return -1;
    if (!mkdtemp(tmpl)) return -1;
    copy_str(out, tmpl, cap);
    return 0;
}

static int remove_at(int dirfd, const char *name, int depth) {
    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return unlinkat(dirfd, name, 0);
    if (depth < REMOVE_DEPTH_MAX) {
        int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        DIR *d = fd >= 0 ? fdopendir(fd) : NULL;
        if (!d && fd >= 0) close(fd);
        // Deleting while reading can skip entries, so repeat until a pass finds none.
        for (int pass = 0; d && pass < REMOVE_PASSES; pass++) {
            int found = 0;
            rewinddir(d);
            struct dirent *e;
            while ((e = readdir(d)) != NULL) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
                found = 1;
                remove_at(fd, e->d_name, depth + 1);
            }
            if (!found) break;
        }
        if (d) closedir(d);
    }
    return unlinkat(dirfd, name, AT_REMOVEDIR);
}

int platform_remove_tree(const char *path) { return remove_at(AT_FDCWD, path, 0); }

void platform_remove_stale_tempdirs(const char *prefix, const char *lock_rel) {
    const char *base = tempdir_base();
    DIR *d = opendir(base);
    if (!d) return;
    size_t pl = strlen(prefix);
    struct dirent *e;
    time_t now = time(NULL);
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, pl) != 0 || e->d_name[pl] != '-') continue;
        char path[PATH_BUF], lock[PATH_BUF + 104];
        snprintf(path, sizeof path, "%s/%s", base, e->d_name);
        struct stat st;
        // Only ours, created by mkdtemp (0700), and not one another chat is in the middle of setting up.
        if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & MODE_GROUP_OTHER)
            || now - st.st_mtime < STALE_AFTER) continue;
        snprintf(lock, sizeof lock, "%s/%s", path, lock_rel);
        int fd = open(lock, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            // tor holds an flock on it while it runs.
            int busy = flock(fd, LOCK_EX | LOCK_NB) != 0;
            close(fd);
            if (busy) continue;
        }
        platform_remove_tree(path);
    }
    closedir(d);
}
