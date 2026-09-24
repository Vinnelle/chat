// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#define _POSIX_C_SOURCE 200809L

#include "platform.h"
#include "util.h"
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
#ifdef __linux__
#include <sys/prctl.h>
#endif

void platform_harden_process(void) {

    struct rlimit no_core = { 0, 0 };
    setrlimit(RLIMIT_CORE, &no_core);

#ifdef PR_SET_DUMPABLE

    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

    struct rlimit ml;
    if (getrlimit(RLIMIT_MEMLOCK, &ml) == 0 && ml.rlim_cur != ml.rlim_max) {
        ml.rlim_cur = ml.rlim_max;
        setrlimit(RLIMIT_MEMLOCK, &ml);
    }
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

#define NOTIFY_MAX_INFLIGHT 4

typedef struct { char title[160]; char body[1400]; } notify_job_t;

static int g_notify_inflight;

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
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    char *argv[] = { (char *)"notify-send", (char *)"--app-name=chat", (char *)"--", j->title, j->body, NULL };
    pid_t pid;
    if (posix_spawnp(&pid, "notify-send", &fa, NULL, argv, environ) == 0)
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    posix_spawn_file_actions_destroy(&fa);
    free(j);
    __atomic_sub_fetch(&g_notify_inflight, 1, __ATOMIC_RELAXED);
}

void platform_notify(const char *title, const char *body) {
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
    sigaction(SIGWINCH, &sa, NULL);
}

int term_resized(void) {
    if (g_winch) { g_winch = 0; return 1; }
    return 0;
}

void platform_wait(const sock_t *socks, int n, int *ready, int *stdin_ready, int timeout_ms) {
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++) ready[i] = 0;
    *stdin_ready = 0;
    struct pollfd pfds[1 + 64];
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
    return 0;
}

int platform_run_quiet(const char *const argv[]) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    pid_t pid;
    int status = -1;
    int rc = posix_spawnp(&pid, argv[0], &fa, NULL, (char *const *)argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) return -1;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

int platform_replace_exe(const char *new_path, const char *exe_path) {
    struct stat st;
    mode_t mode = (stat(exe_path, &st) == 0) ? (st.st_mode & 07777) : 0755;
    if (chmod(new_path, mode | 0100) != 0) return -1;
    return rename(new_path, exe_path);
}
