// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#define _POSIX_C_SOURCE 200809L
// realpath, mkdtemp: X/Open, which musl only declares when asked for.
#define _XOPEN_SOURCE 700
// syscall (renameat2), which glibc and musl declare only beyond POSIX.
#define _DEFAULT_SOURCE

#include "platform/platform.h"
#include "common/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/resource.h>
#include <termios.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <poll.h>
#include <dirent.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/file.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

void platform_harden_process(void) {

    struct rlimit no_core = { 0, 0 };
    setrlimit(RLIMIT_CORE, &no_core);

#ifdef PR_SET_DUMPABLE

    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
#ifdef PR_SET_NO_NEW_PRIVS
    // chat only runs curl, notify-send and tor, and none of them need to gain privileges through exec.
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif

    struct rlimit ml;
    if (getrlimit(RLIMIT_MEMLOCK, &ml) == 0 && ml.rlim_cur != ml.rlim_max) {
        ml.rlim_cur = ml.rlim_max;
        setrlimit(RLIMIT_MEMLOCK, &ml);
    }

    // A write to a pipe whose reader has gone (--simple into a pager that quit, for example) should
    // be an error to handle, not a signal that kills chat before its sessions say bye.
    signal(SIGPIPE, SIG_IGN);
}

int platform_env_take(const char *name, char *out, size_t outlen) {
    char *v = getenv(name);
    if (!v) { if (outlen) out[0] = '\0'; return -1; }
    copy_str(out, v, outlen);

    volatile char *p = v;
    while (*p) *p++ = 0;
    unsetenv(name);
    return 0;
}

int term_is_tty(void) { return isatty(STDIN_FILENO); }
int term_stdout_is_tty(void) { return isatty(STDOUT_FILENO); }

extern char **environ;

// How chat runs curl and notify-send: standard handles on /dev/null, every signal reset to its
// default (chat ignores SIGPIPE) and none blocked. path is absolute and never searched for.
static int spawn_quiet(pid_t *pid, const char *path, char *const argv[]) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    sigset_t none, all;
    sigemptyset(&none);
    sigfillset(&all);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setsigdefault(&attr, &all);
    int rc = posix_spawn(pid, path, &fa, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&fa);
    return rc;
}

#define NOTIFY_MAX_INFLIGHT 4

typedef struct { char title[160]; char body[1400]; } notify_job_t;

static int g_notify_inflight;
// notify-send, looked for once (on the main thread, before any notification thread reads it).
static char g_notify_prog[4096];
static int g_notify_found;   // 0 not looked for yet, 1 found, -1 not installed

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

static void notify_run(void *arg) {
    notify_job_t *j = (notify_job_t *)arg;
    // Transient: shown, but not kept in the desktop's notification history, which would otherwise
    // record when messages came in (and, with previews on, what they said) after chat has exited.
    char *argv[] = { (char *)"notify-send", (char *)"--app-name=chat", (char *)"--hint=int:transient:1", (char *)"--",
                     j->title, j->body, NULL };
    pid_t pid;
    if (spawn_quiet(&pid, g_notify_prog, argv) == 0)
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    free(j);
    __atomic_sub_fetch(&g_notify_inflight, 1, __ATOMIC_RELAXED);
}

void platform_notify(const char *title, const char *body) {
    if (!g_notify_found)
        g_notify_found = platform_find_program("notify-send", NULL, g_notify_prog, sizeof g_notify_prog) == 0 ? 1 : -1;
    if (g_notify_found < 0) return;
    if (__atomic_add_fetch(&g_notify_inflight, 1, __ATOMIC_RELAXED) > NOTIFY_MAX_INFLIGHT) {
        __atomic_sub_fetch(&g_notify_inflight, 1, __ATOMIC_RELAXED);
        return;
    }
    notify_job_t *j = malloc(sizeof *j);
    if (!j) { __atomic_sub_fetch(&g_notify_inflight, 1, __ATOMIC_RELAXED); return; }
    copy_str(j->title, title, sizeof j->title);
    markup_escape(body, j->body, sizeof j->body);
    if (platform_spawn_thread(notify_run, j) != 0) {
        free(j);
        __atomic_sub_fetch(&g_notify_inflight, 1, __ATOMIC_RELAXED);
    }
}

void platform_notify_shutdown(void) {}

int term_ansi_ok(void) {
    return isatty(STDOUT_FILENO);
}

static struct termios g_orig_termios;
static int g_raw_active = 0;

int term_raw_enable(void) {
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) != 0) return -1;
    struct termios raw = g_orig_termios;
    raw.c_lflag &= ~(tcflag_t)(ECHO | ICANON);
    raw.c_iflag &= ~(tcflag_t)(IXON | ICRNL);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return -1;
    g_raw_active = 1;
    return 0;
}

void term_raw_disable(void) {
    if (g_raw_active) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios); g_raw_active = 0; }
}

long term_read_raw(uint8_t *buf, size_t cap) {
    ssize_t n = read(STDIN_FILENO, buf, cap);
    return n > 0 ? (long)n : (n == 0 ? -1 : 0);
}

void platform_write_stdout(const char *buf, size_t len) {
    fflush(stdout);
    while (len > 0) {
        ssize_t n = write(STDOUT_FILENO, buf, len);
        // A resize (SIGWINCH) mid-frame mustn't cut the frame short.
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return;
        buf += n; len -= (size_t)n;
    }
}

static volatile sig_atomic_t g_winch = 0;
static void on_winch(int sig) { (void)sig; g_winch = 1; }

void term_get_size(int *rows, int *cols) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        *rows = ws.ws_row; *cols = ws.ws_col;
    } else { *rows = 24; *cols = 80; }
}

void term_watch_resize(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_winch;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, NULL);
}

int term_resized(void) {
    if (g_winch) { g_winch = 0; return 1; }
    return 0;
}

void platform_wait(const sock_t *socks, int n, int *ready, int *stdin_ready, int timeout_ms) {
    if (n > PLATFORM_WAIT_MAX) n = PLATFORM_WAIT_MAX;
    for (int i = 0; i < n; i++) ready[i] = 0;
    *stdin_ready = 0;
    struct pollfd pfds[1 + PLATFORM_WAIT_MAX];
    pfds[0].fd = STDIN_FILENO; pfds[0].events = POLLIN; pfds[0].revents = 0;
    for (int i = 0; i < n; i++) { pfds[1 + i].fd = socks[i]; pfds[1 + i].events = POLLIN; pfds[1 + i].revents = 0; }
    poll(pfds, (nfds_t)(1 + n), timeout_ms);
    *stdin_ready = (pfds[0].revents & (POLLIN | POLLHUP)) != 0;
    for (int i = 0; i < n; i++) ready[i] = (pfds[1 + i].revents & POLLIN) != 0;
}

static int read_line_stdin(char *out, size_t outlen) {
    if (!fgets(out, (int)outlen, stdin)) return -1;
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    return 0;
}

int term_read_line(const char *prompt, char *out, size_t outlen) {
    if (prompt) { fputs(prompt, stdout); fflush(stdout); }
    return read_line_stdin(out, outlen);
}

int term_read_password(const char *prompt, char *out, size_t outlen) {
    if (prompt) { fputs(prompt, stdout); fflush(stdout); }
    if (!term_is_tty()) return read_line_stdin(out, outlen);
    struct termios old, raw;
    tcgetattr(STDIN_FILENO, &old);
    raw = old;
    raw.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    int rc = read_line_stdin(out, outlen);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fputc('\n', stdout);
    return rc;
}

  typedef pthread_mutex_t mutex_t;
  #define mutex_init(m)   pthread_mutex_init(m, NULL)
  #define mutex_lock(m)   pthread_mutex_lock(m)
  #define mutex_unlock(m) pthread_mutex_unlock(m)
  #define READER_FN static void *
  #define READER_RET NULL

#define QUEUE_SLOTS 16
#define READER_LINE_MAX 1024

struct stdin_reader {
    mutex_t lock;
    char lines[QUEUE_SLOTS][READER_LINE_MAX];
    int head, tail, count;
    int eof;
    volatile int stop;
};

READER_FN reader_main(void *arg) {
    stdin_reader_t *r = (stdin_reader_t *)arg;
    char buf[READER_LINE_MAX];
    while (!r->stop) {
        if (read_line_stdin(buf, sizeof buf) != 0) {
            mutex_lock(&r->lock);
            r->eof = 1;
            mutex_unlock(&r->lock);
            break;
        }
        mutex_lock(&r->lock);
        if (r->count < QUEUE_SLOTS) {
            copy_str(r->lines[r->tail], buf, sizeof r->lines[r->tail]);
            r->tail = (r->tail + 1) % QUEUE_SLOTS;
            r->count++;
        }
        mutex_unlock(&r->lock);
    }
    return READER_RET;
}

stdin_reader_t *stdin_reader_start(void) {
    stdin_reader_t *r = calloc(1, sizeof *r);
    if (!r) return NULL;
    mutex_init(&r->lock);
    pthread_t th;
    if (pthread_create(&th, NULL, reader_main, r) != 0) { pthread_mutex_destroy(&r->lock); free(r); return NULL; }
    pthread_detach(th);
    return r;
}

void stdin_reader_stop(stdin_reader_t *r) {

    if (r) r->stop = 1;
}

int stdin_reader_poll(stdin_reader_t *r, char *line, size_t linelen) {
    if (!r) return -1;
    mutex_lock(&r->lock);
    int ret = 0;
    if (r->count > 0) {
        copy_str(line, r->lines[r->head], linelen);
        r->head = (r->head + 1) % QUEUE_SLOTS;
        r->count--;
        ret = 1;
    } else if (r->eof) {
        ret = -1;
    }
    mutex_unlock(&r->lock);
    return ret;
}

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

const char *platform_home_dir(void) {
    const char *h = getenv("HOME");
    return (h && h[0]) ? h : NULL;
}

int platform_machine_id(char *out, size_t cap) {
    static const char *const PATHS[] = { "/etc/machine-id", "/var/lib/dbus/machine-id" };
    for (size_t i = 0; i < sizeof PATHS / sizeof PATHS[0]; i++) {
        FILE *f = fopen(PATHS[i], "r");
        if (!f) continue;
        char line[64];
        char *got = fgets(line, sizeof line, f);
        fclose(f);
        if (!got) continue;
        line[strcspn(line, "\r\n")] = '\0';
        // 32 hex digits; systemd writes "uninitialized" there until the first boot is done.
        if (strlen(line) == 32 && strspn(line, "0123456789abcdef") == 32 && cap > 32) {
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

    int fd = open(utf8_path, flags | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return NULL;

    fchmod(fd, 0600);
    FILE *f = fdopen(fd, mode);
    if (!f) close(fd);
    return f;
}

long platform_read_file(const char *utf8_path, void *buf, size_t cap) {
    int fd = open(utf8_path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
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
    if (mkdir(out, 0700) != 0 && errno != EEXIST) return -1;
    struct stat st;
    return stat(out, &st) == 0 && S_ISDIR(st.st_mode) ? 0 : -1;
}

FILE *platform_create_new(const char *utf8_path) {
    int fd = open(utf8_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "wb");
    if (!f) close(fd);
    return f;
}

int platform_move_new(const char *from, const char *to) {
    // A hard link fails if the name is taken, so nothing is ever replaced.
    if (link(from, to) == 0) { unlink(from); return 0; }
    if (errno == EEXIST) return -1;
#ifdef SYS_renameat2
    // A filesystem without hard links (FAT, some FUSE ones): use a rename that won't replace.
    if (syscall(SYS_renameat2, AT_FDCWD, from, AT_FDCWD, to, 1u /* RENAME_NOREPLACE */) == 0) return 0;
#endif
    return -1;
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
    if (mkdir(base, 0700) != 0 && errno != EEXIST) return -1;
    if (mkdir(out, 0700) != 0 && errno != EEXIST) return -1;
    // Not a link to somewhere else.
    struct stat st;
    if (lstat(out, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid()) return -1;
    return (st.st_mode & 077) && chmod(out, 0700) != 0 ? -1 : 0;
}

int platform_write_private(const char *utf8_path, const void *data, size_t len) {
    char tmp[4096];
    int n = snprintf(tmp, sizeof tmp, "%s.new", utf8_path);
    if (n <= 0 || (size_t)n >= sizeof tmp) return -1;
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC, 0600);
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
    char dir[4096];
    copy_str(dir, utf8_path, sizeof dir);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
    }
    return 0;
}

double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void current_hhmm(char out[6]) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    snprintf(out, 6, "%02d:%02d", tmv.tm_hour, tmv.tm_min);
}

typedef struct { void (*fn)(void *); void *arg; } thread_boot_t;

static void *thread_tramp(void *p) {
    thread_boot_t b = *(thread_boot_t *)p;
    free(p);
    b.fn(b.arg);
    return NULL;
}

int platform_spawn_thread(void (*fn)(void *), void *arg) {
    thread_boot_t *b = malloc(sizeof *b);
    if (!b) return -1;
    b->fn = fn; b->arg = arg;
    pthread_t t;
    if (pthread_create(&t, NULL, thread_tramp, b) != 0) { free(b); return -1; }
    pthread_detach(t);
    return 0;
}

int platform_remove(const char *utf8_path) {
    return unlink(utf8_path);
}

int platform_exe_path(char *out, size_t cap) {
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0 || (size_t)n >= cap - 1) return -1;
    out[n] = '\0';
    // The kernel appends " (deleted)" once the file we were started from is replaced (rebuilt, for
    // example). The path without it is where the executable is now.
    static const char suffix[] = " (deleted)";
    size_t slen = sizeof suffix - 1;
    if ((size_t)n > slen && strcmp(out + n - slen, suffix) == 0) out[n - slen] = '\0';
    return 0;
}

int platform_run_quiet(const char *const argv[]) {
    // Found the same way as tor: from an absolute PATH entry or a standard folder, and only a program
    // that root or this user can change. posix_spawnp would also try relative entries, including ".".
    char path[4096];
    if (platform_find_program(argv[0], NULL, path, sizeof path) != 0) return -1;
    pid_t pid;
    int status = -1;
    if (spawn_quiet(&pid, path, (char *const *)argv) != 0) return -1;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

int platform_replace_exe(const char *new_path, const char *exe_path) {
    struct stat st;
    mode_t mode = (stat(exe_path, &st) == 0) ? (st.st_mode & 07777) : 0755;
    if (chmod(new_path, mode | 0100) != 0) return -1;
    return rename(new_path, exe_path);
}

int platform_default_gateway(uint8_t ip[4]) {
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
        if (dest != 0 || mask != 0 || !(flags & 0x2) || !(flags & 0x1) || gw == 0) continue;
        if (found == 0 && metric >= best_metric) continue;
        memcpy(ip, &gw, 4);
        best_metric = metric;
        found = 0;
    }
    fclose(f);
    return found;
}

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
    for (size_t i = 0; i < sizeof BUNDLES / sizeof BUNDLES[0]; i++)
        if (add_file(ctx, BUNDLES[i]) == 0) return;
}

// Owned by root or this user, and writable by no one else: no other user, and no group except
// root's or this user's own (any other group could include anyone).
static int only_ours(const struct stat *st) {
    if (st->st_uid != 0 && st->st_uid != geteuid()) return 0;
    if (st->st_mode & S_IWOTH) return 0;
    return !(st->st_mode & S_IWGRP) || st->st_gid == 0 || st->st_gid == getegid();
}

// A program chat will run: a regular executable file nobody else can replace, in a folder nobody
// else can write to.
static int program_ok(const char *path, char *out, size_t cap) {
    char real[4096];
    if (path[0] != '/' || !realpath(path, real)) return -1;
    struct stat st;
    if (stat(real, &st) != 0 || !S_ISREG(st.st_mode) || access(real, X_OK) != 0 || !only_ours(&st)) return -1;
    char dir[4096];
    copy_str(dir, real, sizeof dir);
    char *slash = strrchr(dir, '/');
    if (!slash) return -1;
    if (slash == dir) slash[1] = '\0'; else *slash = '\0';
    struct stat ds;
    if (stat(dir, &ds) != 0 || !only_ours(&ds)) return -1;
    if (strlen(real) >= cap) return -1;
    copy_str(out, real, cap);
    return 0;
}

int platform_find_program(const char *name, const char *path, char *out, size_t cap) {
    if (path && path[0]) return program_ok(path, out, cap);
    char cand[4096];
    const char *env = getenv("PATH");
    if (env) {
        char list[8192];
        copy_str(list, env, sizeof list);
        for (char *save = NULL, *dir = strtok_r(list, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
            // A relative entry ("." or "bin") would run whatever is in the current folder.
            if (dir[0] != '/') continue;
            snprintf(cand, sizeof cand, "%s/%s", dir, name);
            if (program_ok(cand, out, cap) == 0) return 0;
        }
    }
    static const char *const DIRS[] = { "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin" };
    for (size_t i = 0; i < sizeof DIRS / sizeof DIRS[0]; i++) {
        snprintf(cand, sizeof cand, "%s/%s", DIRS[i], name);
        if (program_ok(cand, out, cap) == 0) return 0;
    }
    return -1;
}

static int private_dir_ok(const char *dir) {
    struct stat st;
    return dir && dir[0] == '/' && stat(dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid()
        && (st.st_mode & 077) == 0;
}

static const char *tempdir_base(void) {
    // XDG_RUNTIME_DIR belongs to this user only and is usually in memory. /tmp is the fallback,
    // where mkdtemp still creates the folder as 0700 with a name nobody can guess.
    const char *base = getenv("XDG_RUNTIME_DIR");
    return private_dir_ok(base) ? base : "/tmp";
}

int platform_private_tempdir(const char *prefix, char *out, size_t cap) {
    const char *base = tempdir_base();
    char tmpl[4096];
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
    if (depth < 16) {
        int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        DIR *d = fd >= 0 ? fdopendir(fd) : NULL;
        if (!d && fd >= 0) close(fd);
        // Deleting while reading can skip entries, so repeat until a pass finds none.
        for (int pass = 0; d && pass < 4; pass++) {
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

struct platform_proc { pid_t pid; int exited, code; };

platform_proc_t *platform_spawn(const char *const argv[], const char *out_path) {
    if (!argv[0] || argv[0][0] != '/') return NULL;
    platform_proc_t *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (out_path) posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, out_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    else posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    // Its own process group, so Ctrl+C in the terminal goes to chat, which then stops it.
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    posix_spawnattr_setpgroup(&attr, 0);
    sigset_t none, all;
    sigemptyset(&none);
    sigfillset(&all);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setsigdefault(&attr, &all);
    // Our environment, minus systemd's hand-over variables. Otherwise a program started from a
    // service or a desktop session would report to (or take sockets from) chat's supervisor.
    size_t n = 0;
    while (environ[n]) n++;
    char **env = calloc(n + 1, sizeof *env);
    if (!env) { posix_spawnattr_destroy(&attr); posix_spawn_file_actions_destroy(&fa); free(p); return NULL; }
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        const char *e = environ[i];
        if (strncmp(e, "NOTIFY_SOCKET=", 14) == 0 || strncmp(e, "LISTEN_PID=", 11) == 0
            || strncmp(e, "LISTEN_FDS=", 11) == 0 || strncmp(e, "LISTEN_FDNAMES=", 15) == 0) continue;
        env[k++] = environ[i];
    }
    int rc = posix_spawn(&p->pid, argv[0], &fa, &attr, (char *const *)argv, env);
    free(env);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) { free(p); return NULL; }
    return p;
}

int platform_proc_exited(platform_proc_t *p, int *code) {
    if (!p->exited) {
        int status;
        pid_t r = waitpid(p->pid, &status, WNOHANG);
        if (r == p->pid) { p->exited = 1; p->code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0); }
        else if (r < 0 && errno == ECHILD) { p->exited = 1; p->code = -1; }
    }
    if (p->exited && code) *code = p->code;
    return p->exited;
}

void platform_sleep_ms(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

void platform_proc_stop(platform_proc_t *p, int wait_ms) {
    if (!p) return;
    if (!platform_proc_exited(p, NULL)) {
        kill(p->pid, SIGTERM);
        for (int waited = 0; waited < wait_ms && !platform_proc_exited(p, NULL); waited += 20) platform_sleep_ms(20);
        if (!platform_proc_exited(p, NULL)) {
            kill(p->pid, SIGKILL);
            int status;
            waitpid(p->pid, &status, 0);
        }
    }
    free(p);
}

long platform_pid(void) { return (long)getpid(); }

void platform_remove_stale_tempdirs(const char *prefix, const char *lock_rel) {
    const char *base = tempdir_base();
    DIR *d = opendir(base);
    if (!d) return;
    size_t pl = strlen(prefix);
    struct dirent *e;
    time_t now = time(NULL);
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, pl) != 0 || e->d_name[pl] != '-') continue;
        char path[4096], lock[4200];
        snprintf(path, sizeof path, "%s/%s", base, e->d_name);
        struct stat st;
        // Only ours, created by mkdtemp (0700), and not one another chat is in the middle of setting up.
        if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)
            || now - st.st_mtime < 60) continue;
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
