// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The process: hardening it, the secrets in its environment, its arguments, the clock, threads, the
// executable, and the programs and processes it starts.
#include "posix.h"
#include "crypto/crypto.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#if __has_include(<sys/ptrace.h>)
#include <sys/ptrace.h>
#else
// zig's macOS headers leave it out, but libSystem has it.
int ptrace(int request, pid_t pid, char *addr, int data);
#define PT_DENY_ATTACH 31
#endif
#endif

#define SECRET_ENV_MAX 4
#define SECRET_ENV_VALUE_MAX 512
// A program's permission bits.
#define MODE_PROGRAM 0755
#define STOP_POLL_MS 20
// A process killed by a signal exits with this plus the signal's number, as shells report it.
#define SIGNAL_EXIT_BASE 128

static struct { const char *name; int set; char value[SECRET_ENV_VALUE_MAX]; } g_secret_env[SECRET_ENV_MAX];

// Zeroes a string in place, so it doesn't stay readable in our memory.
static void wipe_string(char *s) {
    for (volatile char *p = s; *p; p++) *p = 0;
}

static int env_take_now(const char *name, char *out, size_t outlen) {
    char *v = getenv(name);
    if (!v) { if (outlen) out[0] = '\0'; return -1; }
    copy_str(out, v, outlen);
    wipe_string(v);
    unsetenv(name);
    return 0;
}

void platform_harden_process(const char *const secret_env[]) {
    struct rlimit no_core = { 0, 0 };
    setrlimit(RLIMIT_CORE, &no_core);

#ifdef PR_SET_DUMPABLE
    // Also makes /proc/PID's mem, environ, fd, maps and io root's alone, and refuses ptrace to
    // anything without CAP_SYS_PTRACE.
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
#ifdef PR_SET_NO_NEW_PRIVS
    // chat only runs curl and tor, and neither needs to gain privileges through exec.
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif
#ifdef __APPLE__
    // No debugger attaches from then on, and one already attached ends chat.
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
#endif

    struct rlimit ml;
    if (getrlimit(RLIMIT_MEMLOCK, &ml) == 0 && ml.rlim_cur != ml.rlim_max) {
        ml.rlim_cur = ml.rlim_max;
        setrlimit(RLIMIT_MEMLOCK, &ml);
    }

    // A write to a pipe whose reader has gone (--simple into a pager that quit, for example) should
    // be an error to handle, not a signal that kills chat before its sessions say bye.
    signal(SIGPIPE, SIG_IGN);

    crypto_lock(g_secret_env, sizeof g_secret_env);
    for (int i = 0; i < SECRET_ENV_MAX && secret_env && secret_env[i]; i++) {
        g_secret_env[i].name = secret_env[i];
        g_secret_env[i].set = env_take_now(secret_env[i], g_secret_env[i].value, sizeof g_secret_env[i].value) == 0;
    }
}

int platform_env_take(const char *name, char *out, size_t outlen) {
    for (int i = 0; i < SECRET_ENV_MAX && g_secret_env[i].name; i++) {
        if (strcmp(g_secret_env[i].name, name) != 0) continue;
        int set = g_secret_env[i].set;
        if (set) copy_str(out, g_secret_env[i].value, outlen);
        else if (outlen) out[0] = '\0';
        crypto_wipe(g_secret_env[i].value, sizeof g_secret_env[i].value);
        g_secret_env[i].set = 0;
        return set ? 0 : -1;
    }
    return env_take_now(name, out, outlen);
}

// /proc/PID/cmdline (what ps shows) is read from the argument strings in our own memory, so
// zeroing them blanks it for everyone. Only their total length still shows.
void platform_hide_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) wipe_string(argv[i]);
}

extern char **environ;

// Where posix_spawn can't start a session, a process group of its own is enough to keep the
// terminal's hang-up from reaching it.
#ifdef POSIX_SPAWN_SETSID
#define SPAWN_OWN_SESSION POSIX_SPAWN_SETSID
#else
#define SPAWN_OWN_SESSION POSIX_SPAWN_SETPGROUP
#endif

// How chat runs curl: standard handles on /dev/null, every signal reset to its default (chat
// ignores SIGPIPE) and none blocked. path is absolute and never searched for.
static int spawn_quiet(pid_t *pid, const char *path, char *const argv[], int own_session) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, (short)(POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | (own_session ? SPAWN_OWN_SESSION : 0)));
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

double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void current_hhmm(char out[HHMM_LEN]) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    snprintf(out, HHMM_LEN, "%02d:%02d", tmv.tm_hour, tmv.tm_min);
}

void stamp_at(long long at, char out[STAMP_LEN]) {
    time_t t = (time_t)at;
    struct tm tmv;
    localtime_r(&t, &tmv);
    if (strftime(out, STAMP_LEN, "%Y-%m-%d %H:%M", &tmv) != STAMP_LEN - 1) out[0] = '\0';
}

void current_stamp(char out[STAMP_LEN]) { stamp_at((long long)time(NULL), out); }

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

int platform_exe_path(char *out, size_t cap) {
#ifdef __APPLE__
    char found[PATH_BUF], real[PATH_BUF];
    uint32_t len = sizeof found;
    if (_NSGetExecutablePath(found, &len) != 0 || !realpath(found, real) || strlen(real) >= cap) return -1;
    copy_str(out, real, cap);
    return 0;
#endif
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
    char path[PATH_BUF];
    if (platform_find_program(argv[0], NULL, path, sizeof path) != 0) return -1;
    pid_t pid;
    int status = -1;
    if (spawn_quiet(&pid, path, (char *const *)argv, 0) != 0) return -1;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

// sh starts it in the background and exits, so it isn't left as chat's child (xdg-open can run the
// browser until it's closed), in a session of its own, so closing the terminal doesn't end it.
int posix_run_detached(const char *path, const char *arg) {
    char sh[PATH_BUF];
    if (platform_find_program("sh", NULL, sh, sizeof sh) != 0) return ENOENT;
    const char *const argv[] = { "sh", "-c", "\"$0\" \"$1\" &", path, arg, NULL };
    pid_t pid;
    int status = -1, rc = spawn_quiet(&pid, sh, (char *const *)argv, 1);
    if (rc != 0) return rc;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return errno;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : ECHILD;
}

int platform_replace_exe(const char *new_path, const char *exe_path) {
    struct stat st;
    mode_t mode = (stat(exe_path, &st) == 0) ? (st.st_mode & MODE_BITS) : MODE_PROGRAM;
    if (chmod(new_path, mode | S_IXUSR) != 0) return -1;
    return rename(new_path, exe_path);
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
    char real[PATH_BUF];
    if (path[0] != '/' || !realpath(path, real)) return -1;
    struct stat st;
    if (stat(real, &st) != 0 || !S_ISREG(st.st_mode) || access(real, X_OK) != 0 || !only_ours(&st)) return -1;
    char dir[PATH_BUF];
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
    char cand[PATH_BUF];
    const char *env = getenv("PATH");
    if (env) {
        char list[PATH_LIST_MAX];
        copy_str(list, env, sizeof list);
        for (char *save = NULL, *dir = strtok_r(list, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
            // A relative entry ("." or "bin") would run whatever is in the current folder.
            if (dir[0] != '/') continue;
            snprintf(cand, sizeof cand, "%s/%s", dir, name);
            if (program_ok(cand, out, cap) == 0) return 0;
        }
    }
    static const char *const DIRS[] = { "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin",
                                        "/opt/homebrew/bin" };
    for (size_t i = 0; i < COUNT_OF(DIRS); i++) {
        snprintf(cand, sizeof cand, "%s/%s", DIRS[i], name);
        if (program_ok(cand, out, cap) == 0) return 0;
    }
    return -1;
}

// Its own process group, so Ctrl+C in the terminal goes to chat, which then stops it.
int spawn_grouped(pid_t *pid, const char *path, const char *const argv[], const posix_spawn_file_actions_t *fa) {
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
    if (!env) { posix_spawnattr_destroy(&attr); return ENOMEM; }
    static const char *const SYSTEMD_VARS[] = { "NOTIFY_SOCKET=", "LISTEN_PID=", "LISTEN_FDS=", "LISTEN_FDNAMES=" };
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        int skip = 0;
        for (size_t j = 0; j < COUNT_OF(SYSTEMD_VARS) && !skip; j++) skip = starts_with(environ[i], SYSTEMD_VARS[j]);
        if (!skip) env[k++] = environ[i];
    }
    int rc = posix_spawn(pid, path, fa, &attr, (char *const *)argv, env);
    free(env);
    posix_spawnattr_destroy(&attr);
    return rc;
}

platform_proc_t *platform_spawn(const char *const argv[], const char *out_path) {
    if (!argv[0] || argv[0][0] != '/') return NULL;
    platform_proc_t *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (out_path)
        posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, out_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, MODE_PRIVATE_FILE);
    else posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    int rc = spawn_grouped(&p->pid, argv[0], argv, &fa);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) { free(p); return NULL; }
    return p;
}

int platform_proc_exited(platform_proc_t *p, int *code) {
    if (!p->exited) {
        int status;
        pid_t r = waitpid(p->pid, &status, WNOHANG);
        if (r == p->pid) {
            p->exited = 1;
            p->code = WIFEXITED(status) ? WEXITSTATUS(status) : SIGNAL_EXIT_BASE + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        }
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
        for (int waited = 0; waited < wait_ms && !platform_proc_exited(p, NULL); waited += STOP_POLL_MS)
            platform_sleep_ms(STOP_POLL_MS);
        if (!platform_proc_exited(p, NULL)) {
            kill(p->pid, SIGKILL);
            int status;
            waitpid(p->pid, &status, 0);
        }
    }
    free(p);
}

long platform_pid(void) { return (long)getpid(); }
