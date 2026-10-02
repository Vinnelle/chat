// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "platform/platform.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <iphlpapi.h>
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

// A crash ends the process immediately. With the default handler, Windows Error Reporting may
// write a dump of its memory, keys and messages included, to disk.
static LONG WINAPI die_quietly(EXCEPTION_POINTERS *info) {
    (void)info;
    TerminateProcess(GetCurrentProcess(), 3);
    return EXCEPTION_EXECUTE_HANDLER;
}

void platform_harden_process(void) {

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    SetUnhandledExceptionFilter(die_quietly);

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

int platform_file_info(const char *utf8_path, file_info_t *out) {
    wchar_t wp[1400];
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!to_wide(utf8_path, wp, 1400) || !GetFileAttributesExW(wp, GetFileExInfoStandard, &fa)) return -1;
    out->is_dir = (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    out->is_link = (fa.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    out->size = (uint64_t)fa.nFileSizeHigh << 32 | fa.nFileSizeLow;
    // FILETIME counts 100 ns steps from 1601.
    uint64_t t = (uint64_t)fa.ftLastWriteTime.dwHighDateTime << 32 | fa.ftLastWriteTime.dwLowDateTime;
    time_t secs = (time_t)((int64_t)(t / 10000000ULL) - 11644473600LL);
    struct tm tmv;
    if (localtime_s(&tmv, &secs) == 0) strftime(out->modified, sizeof out->modified, "%Y-%m-%d %H:%M", &tmv);
    else out->modified[0] = '\0';
    out->mode = -1;
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

int platform_machine_id(char *out, size_t cap) {
    wchar_t w[64];
    DWORD size = sizeof w;
    // The 64-bit registry view, so a 32-bit build reads the same value.
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                     RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, NULL, w, &size) != ERROR_SUCCESS) return -1;
    if (!w[0] || WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL) <= 0) return -1;
    return 0;
}

FILE *platform_fopen(const char *utf8_path, const char *mode) {
    wchar_t wp[1400], wm[16];
    if (!to_wide(utf8_path, wp, 1400) || !to_wide(mode, wm, 16)) return NULL;
    return _wfopen(wp, wm);
}

FILE *platform_fopen_private(const char *utf8_path, const char *mode) {

    return platform_fopen(utf8_path, mode);
}

long platform_read_file(const char *utf8_path, void *buf, size_t cap) {
    wchar_t wp[1400];
    if (!to_wide(utf8_path, wp, 1400)) return -1;
    // A folder won't open without FILE_FLAG_BACKUP_SEMANTICS, and a pipe or device isn't FILE_TYPE_DISK.
    HANDLE h = CreateFileW(wp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    long got = -1;
    if (GetFileType(h) == FILE_TYPE_DISK) {
        size_t n = 0;
        while (n < cap) {
            DWORD want = cap - n > 65536 ? 65536 : (DWORD)(cap - n), r = 0;
            if (!ReadFile(h, (char *)buf + n, want, &r, NULL) || r == 0) break;
            n += r;
        }
        got = (long)n;
    }
    CloseHandle(h);
    return got;
}

FILE *platform_open_regular(const char *utf8_path, uint64_t *size) {
    wchar_t wp[1400];
    if (!to_wide(utf8_path, wp, 1400)) return NULL;
    HANDLE h = CreateFileW(wp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    if (GetFileType(h) != FILE_TYPE_DISK || !GetFileSizeEx(h, &sz) || sz.QuadPart < 0) { CloseHandle(h); return NULL; }
    int fd = _open_osfhandle((intptr_t)h, _O_RDONLY | _O_BINARY);
    if (fd < 0) { CloseHandle(h); return NULL; }
    FILE *f = _fdopen(fd, "rb");
    if (!f) { _close(fd); return NULL; }
    *size = (uint64_t)sz.QuadPart;
    return f;
}

int platform_downloads_dir(char *out, size_t cap) {
    const char *home = platform_home_dir();
    if (!home) return -1;
    int n = snprintf(out, cap, "%s/Downloads", home);
    if (n <= 0 || (size_t)n >= cap) return -1;
    wchar_t wp[1400];
    if (!to_wide(out, wp, 1400)) return -1;
    CreateDirectoryW(wp, NULL);
    DWORD a = GetFileAttributesW(wp);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) ? 0 : -1;
}

FILE *platform_create_new(const char *utf8_path) {
    wchar_t wp[1400];
    if (!to_wide(utf8_path, wp, 1400)) return NULL;
    HANDLE h = CreateFileW(wp, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    int fd = _open_osfhandle((intptr_t)h, _O_WRONLY | _O_BINARY);
    if (fd < 0) { CloseHandle(h); return NULL; }
    FILE *f = _fdopen(fd, "wb");
    if (!f) _close(fd);
    return f;
}

int platform_move_new(const char *from, const char *to) {
    wchar_t wf[1400], wt[1400];
    if (!to_wide(from, wf, 1400) || !to_wide(to, wt, 1400)) return -1;
    // Without MOVEFILE_REPLACE_EXISTING it fails when the name is taken.
    return MoveFileExW(wf, wt, 0) ? 0 : -1;
}

int platform_config_dir(char *out, size_t cap, int create) {
    // Local, not Roaming. A roaming profile would copy it to other machines and a server.
    wchar_t *w = _wgetenv(L"LOCALAPPDATA");
    char base[900];
    if (!w || !w[0] || WideCharToMultiByte(CP_UTF8, 0, w, -1, base, sizeof base, NULL, NULL) <= 0) return -1;
    for (char *p = base; *p; p++) if (*p == '\\') *p = '/';
    int n = snprintf(out, cap, "%s/chat", base);
    if (n <= 0 || (size_t)n >= cap) return -1;
    return create ? platform_private_dir(out) : 0;
}

int platform_private_dir(const char *utf8_path) {
    wchar_t wp[1400];
    if (!to_wide(utf8_path, wp, 1400)) return -1;
    CreateDirectoryW(wp, NULL);
    DWORD a = GetFileAttributesW(wp);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT) ? 0 : -1;
}

int platform_write_private(const char *utf8_path, const void *data, size_t len) {
    char tmp[1100];
    int n = snprintf(tmp, sizeof tmp, "%s.new", utf8_path);
    wchar_t wt[1400], wp[1400];
    if (n <= 0 || (size_t)n >= sizeof tmp || !to_wide(tmp, wt, 1400) || !to_wide(utf8_path, wp, 1400)) return -1;
    HANDLE h = CreateFileW(wt, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    const char *p = data;
    BOOL ok = TRUE;
    for (size_t left = len; ok && left > 0; ) {
        DWORD chunk = left > 65536 ? 65536 : (DWORD)left, wrote = 0;
        ok = WriteFile(h, p, chunk, &wrote, NULL) && wrote > 0;
        p += wrote;
        left -= wrote;
    }
    ok = ok && FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok || !MoveFileExW(wt, wp, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { DeleteFileW(wt); return -1; }
    return 0;
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

int platform_remove(const char *utf8_path) {
    wchar_t wp[1400];
    if (!to_wide(utf8_path, wp, 1400)) return -1;
    return DeleteFileW(wp) ? 0 : -1;
}

int platform_exe_path(char *out, size_t cap) {
    wchar_t w[1024];
    DWORD n = GetModuleFileNameW(NULL, w, 1024);
    if (n == 0 || n >= 1024) return -1;
    if (WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL) <= 0) return -1;
    for (char *p = out; *p; p++) if (*p == '\\') *p = '/';
    return 0;
}

static int append_quoted(wchar_t *cmd, size_t cap, size_t *pos, const char *arg) {
    wchar_t w[1400];
    if (!to_wide(arg, w, 1400)) return -1;
    size_t need = 3 + wcslen(w) * 2;
    if (*pos + need + 1 >= cap) return -1;
    if (*pos) cmd[(*pos)++] = L' ';
    cmd[(*pos)++] = L'"';
    size_t slashes = 0;
    for (const wchar_t *c = w; *c; c++) {
        if (*c == L'\\') { slashes++; cmd[(*pos)++] = L'\\'; continue; }
        if (*c == L'"') { while (slashes--) cmd[(*pos)++] = L'\\'; cmd[(*pos)++] = L'\\'; }
        slashes = 0;
        cmd[(*pos)++] = *c;
    }
    while (slashes--) cmd[(*pos)++] = L'\\';
    cmd[(*pos)++] = L'"';
    cmd[*pos] = L'\0';
    return 0;
}

int platform_run_quiet(const char *const argv[]) {
    // Run argv[0] from System32 only. When searching, CreateProcess tries the exe's own folder and the
    // current folder first, so a curl.exe left next to chat.exe (in Downloads, for example) would run.
    wchar_t app[MAX_PATH + 64], name[64];
    UINT sl = GetSystemDirectoryW(app, MAX_PATH);
    if (sl == 0 || sl >= MAX_PATH || strpbrk(argv[0], "/\\:") || !to_wide(argv[0], name, 56)) return -1;
    wcscat(app, L"\\");
    wcscat(app, name);
    wcscat(app, L".exe");

    wchar_t cmd[8192];
    size_t pos = 0;
    cmd[0] = L'\0';
    for (int i = 0; argv[i]; i++)
        if (append_quoted(cmd, sizeof cmd / sizeof cmd[0], &pos, argv[i]) != 0) return -1;

    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &sa, OPEN_EXISTING, 0, NULL);
    if (nul == INVALID_HANDLE_VALUE) return -1;
    // The child only inherits NUL for its standard handles, even if other handles in this process
    // are inheritable.
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = attr_size ? malloc(attr_size) : NULL;
    if (!attrs || !InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) {
        free(attrs);
        CloseHandle(nul);
        return -1;
    }
    BOOL ok = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &nul, sizeof nul, NULL, NULL);
    STARTUPINFOEXW si;
    memset(&si, 0, sizeof si);
    si.StartupInfo.cb = sizeof si;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = si.StartupInfo.hStdOutput = si.StartupInfo.hStdError = nul;
    si.lpAttributeList = attrs;
    PROCESS_INFORMATION pi;
    if (ok) ok = CreateProcessW(app, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                                NULL, NULL, &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(attrs);
    free(attrs);
    CloseHandle(nul);
    if (!ok) return -1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0 ? 0 : -1;
}

int platform_replace_exe(const char *new_path, const char *exe_path) {
    wchar_t wnew[1400], wexe[1400], wold[1400];
    char old[1100];
    snprintf(old, sizeof old, "%s.old", exe_path);
    if (!to_wide(new_path, wnew, 1400) || !to_wide(exe_path, wexe, 1400) || !to_wide(old, wold, 1400)) return -1;
    DeleteFileW(wold);
    if (!MoveFileExW(wexe, wold, MOVEFILE_REPLACE_EXISTING)) return -1;
    if (!MoveFileExW(wnew, wexe, 0)) { MoveFileExW(wold, wexe, 0); return -1; }
    return 0;
}

int platform_default_gateway(uint8_t ip[4]) {
    ULONG size = 0;
    if (GetIpForwardTable(NULL, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER || size == 0) return -1;
    MIB_IPFORWARDTABLE *table = malloc(size);
    if (!table) return -1;
    int found = -1;
    DWORD best_metric = ~0u;
    if (GetIpForwardTable(table, &size, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_IPFORWARDROW *r = &table->table[i];
            if (r->dwForwardDest != 0 || r->dwForwardMask != 0 || r->dwForwardNextHop == 0) continue;
            if (found == 0 && r->dwForwardMetric1 >= best_metric) continue;
            memcpy(ip, &r->dwForwardNextHop, 4);
            best_metric = r->dwForwardMetric1;
            found = 0;
        }
    }
    free(table);
    return found;
}

void platform_ca_roots(void (*add_der)(void *ctx, const uint8_t *der, size_t len),
                       int (*add_file)(void *ctx, const char *path), void *ctx) {
    (void)add_file;
    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) return;
    const CERT_CONTEXT *cert = NULL;
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL)
        add_der(ctx, cert->pbCertEncoded, cert->cbCertEncoded);
    CertCloseStore(store, 0);
}

static int from_wide(const wchar_t *w, char *out, size_t cap) {
    return WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL) > 0 ? 0 : -1;
}

int platform_full_path(const char *utf8_path, char *out, size_t cap) {
    wchar_t wp[1400], full[1400];
    if (!to_wide(utf8_path, wp, 1400)) return -1;
    DWORD n = GetFullPathNameW(wp, 1400, full, NULL);
    if (n == 0 || n >= 1400 || from_wide(full, out, cap) != 0) return -1;
    for (char *c = out; *c; c++) if (*c == '\\') *c = '/';
    return 0;
}

static int wide_is_absolute(const wchar_t *p) {
    return (p[0] && p[1] == L':' && (p[2] == L'\\' || p[2] == L'/')) || (p[0] == L'\\' && p[1] == L'\\');
}

static int program_ok_w(const wchar_t *path, char *out, size_t cap) {
    wchar_t full[MAX_PATH * 2];
    if (!wide_is_absolute(path) || !GetFullPathNameW(path, MAX_PATH * 2, full, NULL)) return -1;
    DWORD a = GetFileAttributesW(full);
    if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY)) return -1;
    return from_wide(full, out, cap);
}

int platform_find_program(const char *name, const char *path, char *out, size_t cap) {
    wchar_t w[MAX_PATH * 2];
    if (path && path[0]) return to_wide(path, w, MAX_PATH * 2) ? program_ok_w(w, out, cap) : -1;
    wchar_t exe[64];
    if (!to_wide(name, exe, 56)) return -1;
    wcscat(exe, L".exe");
    // Only absolute PATH entries, since CreateProcess style searching would try the current folder first.
    static wchar_t env[32768];
    DWORD n = GetEnvironmentVariableW(L"PATH", env, 32768);
    if (n > 0 && n < 32768) {
        for (wchar_t *save = NULL, *dir = wcstok(env, L";", &save); dir; dir = wcstok(NULL, L";", &save)) {
            if (!wide_is_absolute(dir) || wcslen(dir) + wcslen(exe) + 2 >= MAX_PATH * 2) continue;
            swprintf(w, MAX_PATH * 2, L"%ls\\%ls", dir, exe);
            if (program_ok_w(w, out, cap) == 0) return 0;
        }
    }
    // Tor Browser's own tor, where its installer puts it by default.
    wchar_t home[MAX_PATH];
    if (GetEnvironmentVariableW(L"USERPROFILE", home, MAX_PATH) > 0) {
        swprintf(w, MAX_PATH * 2, L"%ls\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\%ls", home, exe);
        if (program_ok_w(w, out, cap) == 0) return 0;
    }
    return -1;
}

int platform_private_tempdir(const char *prefix, char *out, size_t cap) {
    // The user's own temp folder. Its permissions keep other users out, and a random name that must
    // not exist yet stops a folder someone else created from being used.
    wchar_t base[MAX_PATH + 1], wp[64], dir[MAX_PATH * 2];
    DWORD n = GetTempPathW(MAX_PATH + 1, base);
    if (n == 0 || n > MAX_PATH || !to_wide(prefix, wp, 48)) return -1;
    for (int tries = 0; tries < 8; tries++) {
        unsigned char r[8];
        gen_random(r, sizeof r);
        swprintf(dir, MAX_PATH * 2, L"%ls%ls-%02x%02x%02x%02x%02x%02x%02x%02x", base, wp,
                 r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
        if (CreateDirectoryW(dir, NULL)) return from_wide(dir, out, cap);
        if (GetLastError() != ERROR_ALREADY_EXISTS) return -1;
    }
    return -1;
}

static int remove_tree_w(const wchar_t *path, int depth) {
    DWORD a = GetFileAttributesW(path);
    if (a == INVALID_FILE_ATTRIBUTES) return -1;
    if (a & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(path, a & ~(DWORD)FILE_ATTRIBUTE_READONLY);
    if (!(a & FILE_ATTRIBUTE_DIRECTORY)) return DeleteFileW(path) ? 0 : -1;
    // A link (junction, symlink) is deleted, not what it points to.
    if (!(a & FILE_ATTRIBUTE_REPARSE_POINT) && depth < 16) {
        wchar_t pat[MAX_PATH * 2];
        swprintf(pat, MAX_PATH * 2, L"%ls\\*", path);
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(pat, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                wchar_t child[MAX_PATH * 2];
                swprintf(child, MAX_PATH * 2, L"%ls\\%ls", path, fd.cFileName);
                remove_tree_w(child, depth + 1);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
    return RemoveDirectoryW(path) ? 0 : -1;
}

int platform_remove_tree(const char *path) {
    wchar_t w[MAX_PATH * 2];
    return to_wide(path, w, MAX_PATH * 2) ? remove_tree_w(w, 0) : -1;
}

struct platform_proc { HANDLE process, job; };

platform_proc_t *platform_spawn(const char *const argv[], const char *out_path) {
    wchar_t app[MAX_PATH * 2];
    if (!argv[0] || !to_wide(argv[0], app, MAX_PATH * 2) || !wide_is_absolute(app)) return NULL;
    static wchar_t cmd[16384];
    size_t pos = 0;
    cmd[0] = L'\0';
    for (int i = 0; argv[i]; i++)
        if (append_quoted(cmd, sizeof cmd / sizeof cmd[0], &pos, argv[i]) != 0) return NULL;

    platform_proc_t *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    // In a job that ends when chat exits, however it exits.
    p->job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim;
    memset(&lim, 0, sizeof lim);
    lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!p->job || !SetInformationJobObject(p->job, JobObjectExtendedLimitInformation, &lim, sizeof lim)) {
        if (p->job) CloseHandle(p->job);
        free(p);
        return NULL;
    }
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &sa, OPEN_EXISTING, 0, NULL);
    HANDLE out = nul;
    wchar_t wout[MAX_PATH * 2];
    if (out_path) {
        out = to_wide(out_path, wout, MAX_PATH * 2)
            ? CreateFileW(wout, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)
            : INVALID_HANDLE_VALUE;
    }
    HANDLE inherit[2] = { nul, out };
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = attr_size ? malloc(attr_size) : NULL;
    BOOL ok = nul != INVALID_HANDLE_VALUE && out != INVALID_HANDLE_VALUE && attrs
              && InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size);
    if (ok) ok = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                           out == nul ? sizeof nul : sizeof inherit, NULL, NULL);
    STARTUPINFOEXW si;
    memset(&si, 0, sizeof si);
    si.StartupInfo.cb = sizeof si;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nul;
    si.StartupInfo.hStdOutput = si.StartupInfo.hStdError = out;
    si.lpAttributeList = attrs;
    PROCESS_INFORMATION pi;
    if (ok) ok = CreateProcessW(app, cmd, NULL, NULL, TRUE,
                                CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                                NULL, NULL, &si.StartupInfo, &pi);
    if (attrs) { DeleteProcThreadAttributeList(attrs); free(attrs); }
    if (out != nul && out != INVALID_HANDLE_VALUE) CloseHandle(out);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) { CloseHandle(p->job); free(p); return NULL; }
    if (!AssignProcessToJobObject(p->job, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(p->job);
        free(p);
        return NULL;
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    p->process = pi.hProcess;
    return p;
}

int platform_proc_exited(platform_proc_t *p, int *code) {
    if (WaitForSingleObject(p->process, 0) != WAIT_OBJECT_0) return 0;
    DWORD c = 1;
    GetExitCodeProcess(p->process, &c);
    if (code) *code = (int)c;
    return 1;
}

void platform_proc_stop(platform_proc_t *p, int wait_ms) {
    if (!p) return;
    if (WaitForSingleObject(p->process, 0) != WAIT_OBJECT_0) {
        TerminateProcess(p->process, 0);
        WaitForSingleObject(p->process, (DWORD)wait_ms);
    }
    CloseHandle(p->process);
    CloseHandle(p->job);
    free(p);
}

long platform_pid(void) { return (long)GetCurrentProcessId(); }

void platform_sleep_ms(int ms) { Sleep((DWORD)ms); }

void platform_remove_stale_tempdirs(const char *prefix, const char *lock_rel) {
    wchar_t base[MAX_PATH + 1], wp[64], pat[MAX_PATH * 2], wl[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH + 1, base);
    if (n == 0 || n > MAX_PATH || !to_wide(prefix, wp, 48) || !to_wide(lock_rel, wl, MAX_PATH)) return;
    swprintf(pat, MAX_PATH * 2, L"%ls%ls-*", base, wp);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULONGLONG now = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        ULONGLONG made = ((ULONGLONG)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime;
        if (now - made < 60ULL * 10000000ULL) continue;
        wchar_t dir[MAX_PATH * 2], lock[MAX_PATH * 3];
        swprintf(dir, MAX_PATH * 2, L"%ls%ls", base, fd.cFileName);
        swprintf(lock, MAX_PATH * 3, L"%ls\\%ls", dir, wl);
        // A running tor keeps its lock file open, so it can't be deleted.
        if (!DeleteFileW(lock) && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) continue;
        remove_tree_w(dir, 0);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}
