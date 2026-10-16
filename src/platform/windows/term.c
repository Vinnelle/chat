// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The terminal: whether there is one, raw mode, its size, reading keys and lines, writing to it, and
// waiting on it and the sockets together.
#include "win.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <process.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif

static HANDLE hin(void) { return GetStdHandle(STD_INPUT_HANDLE); }
static HANDLE hout(void) { return GetStdHandle(STD_OUTPUT_HANDLE); }
int term_is_tty(void) { DWORD m; return GetConsoleMode(hin(), &m) != 0; }
int term_stdout_is_tty(void) { DWORD m; return GetConsoleMode(hout(), &m) != 0; }

static int g_vt_out = -1;
static DWORD g_out_orig, g_in_orig;
static UINT g_cp_out_orig;
static int g_out_saved, g_in_saved, g_cp_saved, g_binary_saved = -1;

static int enable_vt_out(void) {
    if (g_vt_out >= 0) return g_vt_out;
    DWORD m;
    HANDLE h = hout();
    if (!GetConsoleMode(h, &m)) return g_vt_out = 0;
    g_out_orig = m; g_out_saved = 1;
    if (!(m & ENABLE_VIRTUAL_TERMINAL_PROCESSING) &&
        !SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        return g_vt_out = 0;
    g_cp_out_orig = GetConsoleOutputCP(); g_cp_saved = 1;
    SetConsoleOutputCP(CP_UTF8);
    return g_vt_out = 1;
}

int term_ansi_ok(void) {
    return enable_vt_out();
}

#define DEFAULT_ROWS 24
#define DEFAULT_COLS 80

static volatile int g_resized;
static int g_rows = DEFAULT_ROWS, g_cols = DEFAULT_COLS;

int term_raw_enable(void) {
    HANDLE i = hin();
    if (!GetConsoleMode(i, &g_in_orig)) return -1;
    if (!enable_vt_out()) return -1;
    DWORD m = g_in_orig;
    m &= ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_MOUSE_INPUT);
    m |= ENABLE_PROCESSED_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_WINDOW_INPUT;
    if (!SetConsoleMode(i, m)) return -1;
    g_in_saved = 1;

    fflush(stdout);
    g_binary_saved = _setmode(_fileno(stdout), _O_BINARY);
    return 0;
}

void term_raw_disable(void) {
    fflush(stdout);
    if (g_in_saved) { SetConsoleMode(hin(), g_in_orig); g_in_saved = 0; }
    if (g_out_saved) { SetConsoleMode(hout(), g_out_orig); g_out_saved = 0; }
    if (g_cp_saved) { SetConsoleOutputCP(g_cp_out_orig); g_cp_saved = 0; }
    if (g_binary_saved >= 0) { _setmode(_fileno(stdout), g_binary_saved); g_binary_saved = -1; }
    g_vt_out = -1;
}

#define INPUT_BATCH 64

long term_read_raw(uint8_t *buf, size_t cap) {
    HANDLE i = hin();
    DWORD avail = 0, got = 0;
    if (!GetNumberOfConsoleInputEvents(i, &avail)) return -1;
    if (avail == 0) return 0;
    INPUT_RECORD rec[INPUT_BATCH];
    if (avail > INPUT_BATCH) avail = INPUT_BATCH;
    if (!ReadConsoleInputW(i, rec, avail, &got)) return -1;

    static wchar_t high;
    size_t out = 0;
    for (DWORD k = 0; k < got; k++) {
        if (rec[k].EventType == WINDOW_BUFFER_SIZE_EVENT) { g_resized = 1; continue; }
        if (rec[k].EventType != KEY_EVENT || !rec[k].Event.KeyEvent.bKeyDown) continue;
        wchar_t ch = rec[k].Event.KeyEvent.uChar.UnicodeChar;
        if (!ch) continue;
        uint32_t cp = ch;
        if (IS_HIGH_SURROGATE(ch)) { high = ch; continue; }
        if (IS_LOW_SURROGATE(ch)) {
            if (!high) continue;
            cp = 0x10000 + (((uint32_t)high - HIGH_SURROGATE_START) << 10) + ((uint32_t)ch - LOW_SURROGATE_START);
        }
        high = 0;
        int reps = rec[k].Event.KeyEvent.wRepeatCount; if (reps < 1) reps = 1;
        for (int r = 0; r < reps; r++) {
            if (out + UTF8_CHAR_MAX > cap) return (long)out;
            out += utf8_put(cp, (char *)buf + out);
        }
    }
    return (long)out;
}

// The most written to the console at once, and how far back from a cut an escape sequence may start.
#define WRITE_CHUNK 30000
#define ESC_SEQ_MAX 40

void platform_write_stdout(const char *buf, size_t len) {
    fflush(stdout);
    HANDLE h = hout();
    while (len > 0) {
        size_t n = len < WRITE_CHUNK ? len : WRITE_CHUNK;
        if (n < len) {
            while (n > 0 && utf8_is_cont(buf[n])) n--;
            for (size_t back = 1; back <= ESC_SEQ_MAX && back < n; back++)
                if (buf[n - back] == '\x1b') { n -= back; break; }
            if (n == 0) n = WRITE_CHUNK;
        }
        DWORD wrote = 0;
        if (!WriteFile(h, buf, (DWORD)n, &wrote, NULL) || wrote == 0) return;
        buf += wrote; len -= wrote;
    }
}

void term_get_size(int *rows, int *cols) {
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (GetConsoleScreenBufferInfo(hout(), &ci)) {
        *cols = ci.srWindow.Right - ci.srWindow.Left + 1;
        *rows = ci.srWindow.Bottom - ci.srWindow.Top + 1;
    } else { *rows = DEFAULT_ROWS; *cols = DEFAULT_COLS; }
}

void term_watch_resize(void) {
    term_get_size(&g_rows, &g_cols);
}

int term_resized(void) {
    int r, c;
    term_get_size(&r, &c);
    if (r != g_rows || c != g_cols || g_resized) { g_rows = r; g_cols = c; g_resized = 0; return 1; }
    return 0;
}

// WSAPoll can't wait on the console, so sockets are polled this long at a time between looks at it.
#define CONSOLE_POLL_MS 15

void platform_wait(const sock_t *socks, int n, int *ready, int *stdin_ready, int timeout_ms) {
    if (n > PLATFORM_WAIT_MAX) n = PLATFORM_WAIT_MAX;
    for (int i = 0; i < n; i++) ready[i] = 0;
    *stdin_ready = 0;
    WSAPOLLFD pfds[PLATFORM_WAIT_MAX];
    for (int i = 0; i < n; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLRDNORM; pfds[i].revents = 0; }

    static int is_console = -1;
    if (is_console < 0) is_console = term_is_tty();

    DWORD start = GetTickCount();
    for (;;) {
        if (is_console && WaitForSingleObject(hin(), 0) == WAIT_OBJECT_0) *stdin_ready = 1;
        int left = timeout_ms - (int)(GetTickCount() - start);
        int slice = (*stdin_ready || left <= 0) ? 0 : (left < CONSOLE_POLL_MS ? left : CONSOLE_POLL_MS);
        int hit = 0;
        if (n > 0) {
            for (int i = 0; i < n; i++) pfds[i].revents = 0;
            if (WSAPoll(pfds, (ULONG)n, slice) > 0)
                for (int i = 0; i < n; i++)
                    if (pfds[i].revents & (POLLRDNORM | POLLERR | POLLHUP)) { ready[i] = 1; hit = 1; }
        } else if (slice > 0) {
            Sleep((DWORD)slice);
        }
        if (*stdin_ready || hit || left <= slice) return;
    }
}

#define CONSOLE_LINE_MAX 1024

static int read_line_stdin(char *out, size_t outlen) {
    if (term_is_tty()) {
        wchar_t w[CONSOLE_LINE_MAX];
        DWORD n = 0;
        if (!ReadConsoleW(hin(), w, CONSOLE_LINE_MAX - 1, &n, NULL) || n == 0) return -1;
        while (n > 0 && (w[n - 1] == L'\n' || w[n - 1] == L'\r')) n--;
        int len = WideCharToMultiByte(CP_UTF8, 0, w, (int)n, out, (int)outlen - 1, NULL, NULL);
        out[len > 0 ? len : 0] = '\0';
        return 0;
    }
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
    DWORD old = 0;
    GetConsoleMode(hin(), &old);
    SetConsoleMode(hin(), old & ~(DWORD)ENABLE_ECHO_INPUT);
    int rc = read_line_stdin(out, outlen);
    SetConsoleMode(hin(), old);
    fputc('\n', stdout);
    return rc;
}

#define QUEUE_SLOTS 16
#define READER_LINE_MAX 1024

struct stdin_reader {
    CRITICAL_SECTION lock;
    char lines[QUEUE_SLOTS][READER_LINE_MAX];
    int head, tail, count;
    int eof;
    volatile int stop;
};

static unsigned __stdcall reader_main(void *arg) {
    stdin_reader_t *r = (stdin_reader_t *)arg;
    char buf[READER_LINE_MAX];
    while (!r->stop) {
        if (read_line_stdin(buf, sizeof buf) != 0) {
            EnterCriticalSection(&r->lock);
            r->eof = 1;
            LeaveCriticalSection(&r->lock);
            break;
        }
        EnterCriticalSection(&r->lock);
        if (r->count < QUEUE_SLOTS) {
            copy_str(r->lines[r->tail], buf, sizeof r->lines[r->tail]);
            r->tail = (r->tail + 1) % QUEUE_SLOTS;
            r->count++;
        }
        LeaveCriticalSection(&r->lock);
    }
    return 0;
}

stdin_reader_t *stdin_reader_start(void) {
    stdin_reader_t *r = calloc(1, sizeof *r);
    if (!r) return NULL;
    InitializeCriticalSection(&r->lock);
    uintptr_t th = _beginthreadex(thread_sa(), 0, reader_main, r, 0, NULL);
    if (!th) { DeleteCriticalSection(&r->lock); free(r); return NULL; }
    CloseHandle((HANDLE)th);
    return r;
}

void stdin_reader_stop(stdin_reader_t *r) {
    if (r) r->stop = 1;
}

int stdin_reader_poll(stdin_reader_t *r, char *line, size_t linelen) {
    if (!r) return -1;
    EnterCriticalSection(&r->lock);
    int ret = 0;
    if (r->count > 0) {
        copy_str(line, r->lines[r->head], linelen);
        r->head = (r->head + 1) % QUEUE_SLOTS;
        r->count--;
        ret = 1;
    } else if (r->eof) {
        ret = -1;
    }
    LeaveCriticalSection(&r->lock);
    return ret;
}
