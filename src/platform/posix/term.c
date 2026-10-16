// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The terminal: whether there is one, raw mode, its size, reading keys and lines, writing to it, and
// waiting on it and the sockets together.
#include "posix.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEFAULT_ROWS 24
#define DEFAULT_COLS 80

int term_is_tty(void) { return isatty(STDIN_FILENO); }
int term_stdout_is_tty(void) { return isatty(STDOUT_FILENO); }

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
    // Ctrl+C comes in as a key, so chat can ask before quitting. As a signal it would also reach the
    // programs chat runs in its process group, and stop an update's curl even if you stay. The same
    // for Ctrl+\ (SIGQUIT), so it's a key the panic setting can choose or leave alone.
    raw.c_cc[VINTR] = _POSIX_VDISABLE;
    raw.c_cc[VQUIT] = _POSIX_VDISABLE;
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
    } else { *rows = DEFAULT_ROWS; *cols = DEFAULT_COLS; }
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

#define QUEUE_SLOTS 16
#define READER_LINE_MAX 1024

struct stdin_reader {
    pthread_mutex_t lock;
    char lines[QUEUE_SLOTS][READER_LINE_MAX];
    int head, tail, count;
    int eof;
    volatile int stop;
};

static void *reader_main(void *arg) {
    stdin_reader_t *r = (stdin_reader_t *)arg;
    char buf[READER_LINE_MAX];
    while (!r->stop) {
        if (read_line_stdin(buf, sizeof buf) != 0) {
            pthread_mutex_lock(&r->lock);
            r->eof = 1;
            pthread_mutex_unlock(&r->lock);
            break;
        }
        pthread_mutex_lock(&r->lock);
        if (r->count < QUEUE_SLOTS) {
            copy_str(r->lines[r->tail], buf, sizeof r->lines[r->tail]);
            r->tail = (r->tail + 1) % QUEUE_SLOTS;
            r->count++;
        }
        pthread_mutex_unlock(&r->lock);
    }
    return NULL;
}

stdin_reader_t *stdin_reader_start(void) {
    stdin_reader_t *r = calloc(1, sizeof *r);
    if (!r) return NULL;
    pthread_mutex_init(&r->lock, NULL);
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
    pthread_mutex_lock(&r->lock);
    int ret = 0;
    if (r->count > 0) {
        copy_str(line, r->lines[r->head], linelen);
        r->head = (r->head + 1) % QUEUE_SLOTS;
        r->count--;
        ret = 1;
    } else if (r->eof) {
        ret = -1;
    }
    pthread_mutex_unlock(&r->lock);
    return ret;
}
