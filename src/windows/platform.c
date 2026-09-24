// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "platform.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <shellapi.h>
#include <io.h>
#include <fcntl.h>
#include <process.h>
#include <wchar.h>
#include <time.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif

#ifndef PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_DEFINED
typedef struct { DWORD Flags; } chat_extension_point_policy_t;
#endif
#define CHAT_ProcessExtensionPointDisablePolicy 6

typedef BOOL (WINAPI *set_mitigation_fn)(int policy, PVOID buf, SIZE_T len);

void platform_harden_process(void) {

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32) {
        set_mitigation_fn set_policy = (set_mitigation_fn)(void *)GetProcAddress(k32, "SetProcessMitigationPolicy");
        if (set_policy) {
            chat_extension_point_policy_t pol;
            pol.Flags = 1;
            set_policy(CHAT_ProcessExtensionPointDisablePolicy, &pol, sizeof pol);
        }
    }
}

int platform_env_take(const char *name, char *out, size_t outlen) {
    char *v = getenv(name);
    if (!v) { if (outlen) out[0] = '\0'; return -1; }
    copy_str(out, v, outlen);
    volatile char *p = v;
    while (*p) *p++ = 0;
    char buf[256];
    snprintf(buf, sizeof buf, "%s=", name);
    _putenv(buf);
    return 0;
}

static HANDLE hin(void) { return GetStdHandle(STD_INPUT_HANDLE); }
static HANDLE hout(void) { return GetStdHandle(STD_OUTPUT_HANDLE); }
int term_is_tty(void) { DWORD m; return GetConsoleMode(hin(), &m) != 0; }
int term_stdout_is_tty(void) { DWORD m; return GetConsoleMode(hout(), &m) != 0; }

#define WM_CHAT_NOTIFY (WM_APP + 1)
#define NOTIFY_ICON_ID 1

typedef struct { wchar_t title[64]; wchar_t body[256]; } notify_job_t;

static HWND g_notify_hwnd;
static int g_notify_state;

static void utf8_to_wide_trunc(const char *in, wchar_t *out, int cap) {
    int n = MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
    wchar_t *tmp = n > 0 ? malloc((size_t)n * sizeof *tmp) : NULL;
    out[0] = L'\0';
    if (!tmp) return;
    if (MultiByteToWideChar(CP_UTF8, 0, in, -1, tmp, n) > 0) {
        int len = n - 1 < cap - 1 ? n - 1 : cap - 1;
        if (len > 0 && tmp[len - 1] >= 0xD800 && tmp[len - 1] <= 0xDBFF) len--;
        memcpy(out, tmp, (size_t)len * sizeof *out);
        out[len] = L'\0';
    }
    free(tmp);
}

static void notify_icon_init(NOTIFYICONDATAW *nid) {
    memset(nid, 0, sizeof *nid);
    nid->cbSize = sizeof *nid;
    nid->hWnd = g_notify_hwnd;
    nid->uID = NOTIFY_ICON_ID;
}

static DWORD WINAPI notify_thread(LPVOID ready) {
    WNDCLASSW wc;
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"chat_notify";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"chat", 0, 0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
    if (hwnd) {
        g_notify_hwnd = hwnd;
        NOTIFYICONDATAW nid;
        notify_icon_init(&nid);
        nid.uFlags = NIF_ICON | NIF_TIP;
        nid.hIcon = LoadIconW(NULL, MAKEINTRESOURCEW(32512));
        wcscpy(nid.szTip, L"chat");
        if (Shell_NotifyIconW(NIM_ADD, &nid)) {
            nid.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &nid);
        } else {
            DestroyWindow(hwnd);
            g_notify_hwnd = hwnd = NULL;
        }
    }
    SetEvent((HANDLE)ready);
    if (!hwnd) return 0;

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (m.message == WM_CHAT_NOTIFY) {
            notify_job_t *j = (notify_job_t *)m.lParam;
            NOTIFYICONDATAW nid;
            notify_icon_init(&nid);
            nid.uFlags = NIF_INFO;
            nid.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
            wcscpy(nid.szInfoTitle, j->title);
            wcscpy(nid.szInfo, j->body);
            Shell_NotifyIconW(NIM_MODIFY, &nid);
            free(j);
            continue;
        }
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}

static int notify_start(void) {
    if (g_notify_state) return g_notify_state > 0;
    g_notify_state = -1;
    HANDLE ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ready) return 0;
    HANDLE th = CreateThread(NULL, 0, notify_thread, ready, 0, NULL);
    if (th) {
        WaitForSingleObject(ready, 5000);
        CloseHandle(th);
    }
    CloseHandle(ready);
    if (g_notify_hwnd) g_notify_state = 1;
    return g_notify_state > 0;
}

void platform_notify(const char *title, const char *body) {
    if (!notify_start()) return;
    notify_job_t *j = malloc(sizeof *j);
    if (!j) return;
    utf8_to_wide_trunc(title, j->title, (int)(sizeof j->title / sizeof j->title[0]));
    utf8_to_wide_trunc(body && body[0] ? body : " ", j->body, (int)(sizeof j->body / sizeof j->body[0]));
    if (!PostMessageW(g_notify_hwnd, WM_CHAT_NOTIFY, 0, (LPARAM)j)) free(j);
}

void platform_notify_shutdown(void) {
    if (g_notify_state <= 0) return;
    NOTIFYICONDATAW nid;
    notify_icon_init(&nid);
    Shell_NotifyIconW(NIM_DELETE, &nid);
    g_notify_state = -1;
}

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

static volatile int g_resized;
static int g_rows = 24, g_cols = 80;

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

static size_t utf8_encode(uint32_t cp, uint8_t *out) {
    if (cp < 0x80) { out[0] = (uint8_t)cp; return 1; }
    if (cp < 0x800) { out[0] = (uint8_t)(0xC0 | (cp >> 6)); out[1] = (uint8_t)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) {
        out[0] = (uint8_t)(0xE0 | (cp >> 12)); out[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (uint8_t)(0x80 | (cp & 0x3F)); return 3;
    }
    out[0] = (uint8_t)(0xF0 | (cp >> 18)); out[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F)); out[3] = (uint8_t)(0x80 | (cp & 0x3F));
    return 4;
}

long term_read_raw(uint8_t *buf, size_t cap) {
    HANDLE i = hin();
    DWORD avail = 0, got = 0;
    if (!GetNumberOfConsoleInputEvents(i, &avail)) return -1;
    if (avail == 0) return 0;
    INPUT_RECORD rec[64];
    if (avail > 64) avail = 64;
    if (!ReadConsoleInputW(i, rec, avail, &got)) return -1;

    static wchar_t high;
    size_t out = 0;
    for (DWORD k = 0; k < got; k++) {
        if (rec[k].EventType == WINDOW_BUFFER_SIZE_EVENT) { g_resized = 1; continue; }
        if (rec[k].EventType != KEY_EVENT || !rec[k].Event.KeyEvent.bKeyDown) continue;
        wchar_t ch = rec[k].Event.KeyEvent.uChar.UnicodeChar;
        if (!ch) continue;
        uint32_t cp = ch;
        if (ch >= 0xD800 && ch <= 0xDBFF) { high = ch; continue; }
        if (ch >= 0xDC00 && ch <= 0xDFFF) {
            if (!high) continue;
            cp = 0x10000 + (((uint32_t)high - 0xD800) << 10) + ((uint32_t)ch - 0xDC00);
        }
        high = 0;
        int reps = rec[k].Event.KeyEvent.wRepeatCount; if (reps < 1) reps = 1;
        for (int r = 0; r < reps; r++) {
            if (out + 4 > cap) return (long)out;
            out += utf8_encode(cp, buf + out);
        }
    }
    return (long)out;
}

void platform_write_stdout(const char *buf, size_t len) {
    fflush(stdout);
    HANDLE h = hout();

    const size_t MAXW = 30000;
    while (len > 0) {
        size_t n = len < MAXW ? len : MAXW;
        if (n < len) {
            while (n > 0 && (((unsigned char)buf[n]) & 0xC0) == 0x80) n--;
            for (size_t back = 1; back <= 40 && back < n; back++)
                if (buf[n - back] == 0x1b) { n -= back; break; }
            if (n == 0) n = len < MAXW ? len : MAXW;
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
    } else { *rows = 24; *cols = 80; }
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

void platform_wait(const sock_t *socks, int n, int *ready, int *stdin_ready, int timeout_ms) {
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++) ready[i] = 0;
    *stdin_ready = 0;
    WSAPOLLFD pfds[64];
    for (int i = 0; i < n; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLRDNORM; pfds[i].revents = 0; }

    static int is_console = -1;
    if (is_console < 0) is_console = term_is_tty();

    DWORD start = GetTickCount();
    for (;;) {

        if (is_console && WaitForSingleObject(hin(), 0) == WAIT_OBJECT_0) *stdin_ready = 1;
        int left = timeout_ms - (int)(GetTickCount() - start);
        int slice = (*stdin_ready || left <= 0) ? 0 : (left < 15 ? left : 15);
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

static int read_line_stdin(char *out, size_t outlen) {
    if (term_is_tty()) {
        wchar_t w[1024];
        DWORD n = 0;
        if (!ReadConsoleW(hin(), w, 1023, &n, NULL) || n == 0) return -1;
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

  typedef CRITICAL_SECTION mutex_t;
  #define mutex_init(m)   InitializeCriticalSection(m)
  #define mutex_lock(m)   EnterCriticalSection(m)
  #define mutex_unlock(m) LeaveCriticalSection(m)
  #define READER_FN static unsigned __stdcall
  #define READER_RET 0

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
    uintptr_t th = _beginthreadex(NULL, 0, reader_main, r, 0, NULL);
    if (!th) { free(r); return NULL; }
    CloseHandle((HANDLE)th);
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

static int to_wide(const char *utf8, wchar_t *out, int cap) {
    return MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, cap) > 0;
}

int platform_list_dir(const char *path, dir_entry_cb cb, void *ctx) {
    char pat[1400];
    size_t pl = strlen(path);
    snprintf(pat, sizeof pat, (pl > 0 && path[pl - 1] == '/') ? "%s*" : "%s/*", path);
    wchar_t wpat[1400];
    if (!to_wide(pat, wpat, 1400)) return -1;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpat, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    do {
        if (wcscmp(fd.cFileName, L".") == 0) continue;
        char name[600];
        if (WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, name, sizeof name, NULL, NULL) <= 0) continue;
        cb(ctx, name, (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return 0;
}

const char *platform_home_dir(void) {
    static char home[900];
    wchar_t *w = _wgetenv(L"USERPROFILE");
    if (!w || !w[0]) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, w, -1, home, sizeof home, NULL, NULL) <= 0) return NULL;
    for (char *p = home; *p; p++) if (*p == '\\') *p = '/';
    return home;
}

FILE *platform_fopen(const char *utf8_path, const char *mode) {
    wchar_t wp[1400], wm[16];
    if (!to_wide(utf8_path, wp, 1400) || !to_wide(mode, wm, 16)) return NULL;
    return _wfopen(wp, wm);
}

FILE *platform_fopen_private(const char *utf8_path, const char *mode) {

    return platform_fopen(utf8_path, mode);
}

double now_seconds(void) {
    static LARGE_INTEGER freq;
    LARGE_INTEGER now;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart / (double)freq.QuadPart;
}

void current_hhmm(char out[6]) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_s(&tmv, &t);
    snprintf(out, 6, "%02d:%02d", tmv.tm_hour, tmv.tm_min);
}

typedef struct { void (*fn)(void *); void *arg; } thread_boot_t;

static DWORD WINAPI thread_tramp(LPVOID p) {
    thread_boot_t b = *(thread_boot_t *)p;
    free(p);
    b.fn(b.arg);
    return 0;
}

int platform_spawn_thread(void (*fn)(void *), void *arg) {
    thread_boot_t *b = malloc(sizeof *b);
    if (!b) return -1;
    b->fn = fn; b->arg = arg;
    HANDLE h = CreateThread(NULL, 0, thread_tramp, b, 0, NULL);
    if (!h) { free(b); return -1; }
    CloseHandle(h);
    return 0;
}
