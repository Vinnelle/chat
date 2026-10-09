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
#include <aclapi.h>
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
#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#define PROC_THREAD_ATTRIBUTE_JOB_LIST 0x0002000D
#endif
#ifndef SECURITY_CREATOR_OWNER_RIGHTS_RID
#define SECURITY_CREATOR_OWNER_RIGHTS_RID 0x00000004L
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

// SetProcessMitigationPolicy's ProcessExtensionPointDisablePolicy, and its DisableExtensionPoints flag.
#define EXTENSION_POINT_POLICY 6
#define DISABLE_EXTENSION_POINTS 0x1

typedef BOOL (WINAPI *set_mitigation_fn)(int policy, PVOID buf, SIZE_T len);

#define CRASH_EXIT 3
#define ACL_DWORDS 16
#define WORKING_SET_MIN ((SIZE_T)32 << 20)
#define WORKING_SET_MAX ((SIZE_T)128 << 20)

// A crash ends the process immediately. With the default handler, Windows Error Reporting may
// write a dump of its memory, keys and messages included, to disk.
static LONG WINAPI die_quietly(EXCEPTION_POINTERS *info) {
    (void)info;
    TerminateProcess(GetCurrentProcess(), CRASH_EXIT);
    return EXCEPTION_EXECUTE_HANDLER;
}

// Other programs, even ones running as this user, can only see that chat runs, wait for it and end
// it: not read or change its memory, run code in it, suspend its threads or copy its handles. The
// ACE is for OWNER RIGHTS, which also takes away what an owner otherwise always keeps, the right
// to rewrite the DACL. Administrators with the debug privilege, and SYSTEM, are still let in.
static DWORD g_thread_acl[ACL_DWORDS];
static SECURITY_DESCRIPTOR g_thread_sd;
static SECURITY_ATTRIBUTES g_thread_sa;

static int owner_only_acl(DWORD *acl, DWORD cap, DWORD rights) {
    SID_IDENTIFIER_AUTHORITY creator = SECURITY_CREATOR_SID_AUTHORITY;
    PSID owner_rights = NULL;
    if (!AllocateAndInitializeSid(&creator, 1, SECURITY_CREATOR_OWNER_RIGHTS_RID, 0, 0, 0, 0, 0, 0, 0, &owner_rights))
        return -1;
    BOOL ok = InitializeAcl((PACL)acl, cap, ACL_REVISION) && AddAccessAllowedAce((PACL)acl, ACL_REVISION, rights, owner_rights);
    FreeSid(owner_rights);
    return ok ? 0 : -1;
}

// The threads chat starts are made with that DACL, rather than given it once they run.
static SECURITY_ATTRIBUTES *thread_sa(void) { return g_thread_sa.nLength ? &g_thread_sa : NULL; }

#define SECRET_ENV_MAX 4
#define SECRET_ENV_VALUE_MAX 512

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
    char buf[256];
    snprintf(buf, sizeof buf, "%s=", name);
    _putenv(buf);
    return 0;
}

void platform_harden_process(const char *const secret_env[]) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    SetUnhandledExceptionFilter(die_quietly);

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32) {
        set_mitigation_fn set_policy = (set_mitigation_fn)(void *)GetProcAddress(k32, "SetProcessMitigationPolicy");
        if (set_policy) {
            DWORD flags = DISABLE_EXTENSION_POINTS;
            set_policy(EXTENSION_POINT_POLICY, &flags, sizeof flags);
        }
    }

    // VirtualLock locks no more than the minimum working set, about 200 KB by default: too little
    // for the keys and conversation crypto_lock keeps out of the page file.
    SetProcessWorkingSetSize(GetCurrentProcess(), WORKING_SET_MIN, WORKING_SET_MAX);

    DWORD acl[ACL_DWORDS];
    if (owner_only_acl(acl, sizeof acl, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE) == 0)
        SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, (PACL)acl, NULL);
    if (owner_only_acl(g_thread_acl, sizeof g_thread_acl, THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE) == 0
        && InitializeSecurityDescriptor(&g_thread_sd, SECURITY_DESCRIPTOR_REVISION)
        && SetSecurityDescriptorDacl(&g_thread_sd, TRUE, (PACL)g_thread_acl, FALSE)) {
        g_thread_sa.nLength = sizeof g_thread_sa;
        g_thread_sa.lpSecurityDescriptor = &g_thread_sd;
        g_thread_sa.bInheritHandle = FALSE;
        SetSecurityInfo(GetCurrentThread(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, (PACL)g_thread_acl, NULL);
    }

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

// Task Manager and the like read the command line from this process's own copy, the one
// GetCommandLineW returns, so overwriting it blanks it for them.
void platform_hide_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) wipe_string(argv[i]);
    wchar_t *w = GetCommandLineW();
    if (!w) return;
    // Past the program's name, quoted or not.
    if (*w == L'"') { w++; while (*w && *w != L'"') w++; if (*w) w++; }
    else while (*w && *w != L' ' && *w != L'\t') w++;
    for (volatile wchar_t *q = w; *q; q++) *q = L' ';
}

static HANDLE hin(void) { return GetStdHandle(STD_INPUT_HANDLE); }
static HANDLE hout(void) { return GetStdHandle(STD_OUTPUT_HANDLE); }
int term_is_tty(void) { DWORD m; return GetConsoleMode(hin(), &m) != 0; }
int term_stdout_is_tty(void) { DWORD m; return GetConsoleMode(hout(), &m) != 0; }

#define WM_CHAT_NOTIFY (WM_APP + 1)
#define NOTIFY_ICON_ID 1
#define NOTIFY_START_WAIT_MS 5000
// The sizes of NOTIFYICONDATAW's szInfoTitle and szInfo, which a notification is copied into.
#define NOTIFY_TITLE_MAX 64
#define NOTIFY_BODY_MAX 256

typedef struct { wchar_t title[NOTIFY_TITLE_MAX]; wchar_t body[NOTIFY_BODY_MAX]; } notify_job_t;

static HWND g_notify_hwnd;
static int g_notify_state;

static void utf8_to_wide_trunc(const char *in, wchar_t *out, int cap) {
    int n = MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
    wchar_t *tmp = n > 0 ? malloc((size_t)n * sizeof *tmp) : NULL;
    out[0] = L'\0';
    if (!tmp) return;
    if (MultiByteToWideChar(CP_UTF8, 0, in, -1, tmp, n) > 0) {
        int len = n - 1 < cap - 1 ? n - 1 : cap - 1;
        if (len > 0 && IS_HIGH_SURROGATE(tmp[len - 1])) len--;
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
        nid.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
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
    HANDLE th = CreateThread(thread_sa(), 0, notify_thread, ready, 0, NULL);
    if (th) {
        WaitForSingleObject(ready, NOTIFY_START_WAIT_MS);
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
    utf8_to_wide_trunc(title, j->title, (int)COUNT_OF(j->title));
    utf8_to_wide_trunc(body && body[0] ? body : " ", j->body, (int)COUNT_OF(j->body));
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

// A path, as UTF-8 or as UTF-16, which never takes more units than UTF-8 takes bytes.
#define WPATH_MAX 1400
// A folder from the environment, short enough for paths under it to fit in WPATH_MAX.
#define BASE_DIR_MAX 900
#define IO_CHUNK 65536

static int to_wide(const char *utf8, wchar_t *out, size_t cap) {
    return MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, (int)cap) > 0;
}

static int from_wide(const wchar_t *w, char *out, size_t cap) {
    return WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL) > 0 ? 0 : -1;
}

// As from_wide, with '/' between folders as the rest of chat writes paths.
static int from_wide_path(const wchar_t *w, char *out, size_t cap) {
    if (from_wide(w, out, cap) != 0) return -1;
    for (char *c = out; *c; c++) if (*c == '\\') *c = '/';
    return 0;
}

int platform_list_dir(const char *path, dir_entry_cb cb, void *ctx) {
    char pat[WPATH_MAX];
    size_t pl = strlen(path);
    snprintf(pat, sizeof pat, (pl > 0 && path[pl - 1] == '/') ? "%s*" : "%s/*", path);
    wchar_t wpat[WPATH_MAX];
    if (!to_wide(pat, wpat, COUNT_OF(wpat))) return -1;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpat, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    do {
        if (wcscmp(fd.cFileName, L".") == 0) continue;
        // cFileName's MAX_PATH UTF-16 units take at most 3 bytes each in UTF-8.
        char name[MAX_PATH * 3];
        if (from_wide(fd.cFileName, name, sizeof name) != 0) continue;
        cb(ctx, name, (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return 0;
}

// FILETIME counts 100 ns steps from 1601, FILETIME_UNIX_EPOCH seconds before 1970.
#define FILETIME_PER_SECOND 10000000ULL
#define FILETIME_UNIX_EPOCH 11644473600LL

static uint64_t filetime_value(FILETIME ft) { return (uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime; }

int platform_file_info(const char *utf8_path, file_info_t *out) {
    wchar_t wp[WPATH_MAX];
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!to_wide(utf8_path, wp, COUNT_OF(wp)) || !GetFileAttributesExW(wp, GetFileExInfoStandard, &fa)) return -1;
    out->is_dir = (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    out->is_link = (fa.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    out->size = (uint64_t)fa.nFileSizeHigh << 32 | fa.nFileSizeLow;
    time_t secs = (time_t)((int64_t)(filetime_value(fa.ftLastWriteTime) / FILETIME_PER_SECOND) - FILETIME_UNIX_EPOCH);
    struct tm tmv;
    if (localtime_s(&tmv, &secs) == 0) strftime(out->modified, sizeof out->modified, "%Y-%m-%d %H:%M", &tmv);
    else out->modified[0] = '\0';
    out->mode = -1;
    return 0;
}

const char *platform_home_dir(void) {
    static char home[BASE_DIR_MAX];
    wchar_t *w = _wgetenv(L"USERPROFILE");
    return w && w[0] && from_wide_path(w, home, sizeof home) == 0 ? home : NULL;
}

int platform_machine_id(char *out, size_t cap) {
    wchar_t w[64];
    DWORD size = sizeof w;
    // The 64-bit registry view, so a 32-bit build reads the same value.
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                     RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, NULL, w, &size) != ERROR_SUCCESS) return -1;
    return w[0] ? from_wide(w, out, cap) : -1;
}

FILE *platform_fopen(const char *utf8_path, const char *mode) {
    wchar_t wp[WPATH_MAX], wm[16];
    if (!to_wide(utf8_path, wp, COUNT_OF(wp)) || !to_wide(mode, wm, COUNT_OF(wm))) return NULL;
    return _wfopen(wp, wm);
}

FILE *platform_fopen_private(const char *utf8_path, const char *mode) {
    return platform_fopen(utf8_path, mode);
}

long platform_read_file(const char *utf8_path, void *buf, size_t cap) {
    wchar_t wp[WPATH_MAX];
    if (!to_wide(utf8_path, wp, COUNT_OF(wp))) return -1;
    // A folder won't open without FILE_FLAG_BACKUP_SEMANTICS, and a pipe or device isn't FILE_TYPE_DISK.
    HANDLE h = CreateFileW(wp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    long got = -1;
    if (GetFileType(h) == FILE_TYPE_DISK) {
        size_t n = 0;
        while (n < cap) {
            DWORD want = cap - n > IO_CHUNK ? IO_CHUNK : (DWORD)(cap - n), r = 0;
            if (!ReadFile(h, (char *)buf + n, want, &r, NULL) || r == 0) break;
            n += r;
        }
        got = (long)n;
    }
    CloseHandle(h);
    return got;
}

FILE *platform_open_regular(const char *utf8_path, uint64_t *size) {
    wchar_t wp[WPATH_MAX];
    if (!to_wide(utf8_path, wp, COUNT_OF(wp))) return NULL;
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
    wchar_t wp[WPATH_MAX];
    if (!to_wide(out, wp, COUNT_OF(wp))) return -1;
    CreateDirectoryW(wp, NULL);
    DWORD a = GetFileAttributesW(wp);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) ? 0 : -1;
}

FILE *platform_create_new(const char *utf8_path) {
    wchar_t wp[WPATH_MAX];
    if (!to_wide(utf8_path, wp, COUNT_OF(wp))) return NULL;
    HANDLE h = CreateFileW(wp, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    int fd = _open_osfhandle((intptr_t)h, _O_WRONLY | _O_BINARY);
    if (fd < 0) { CloseHandle(h); return NULL; }
    FILE *f = _fdopen(fd, "wb");
    if (!f) _close(fd);
    return f;
}

int platform_move_new(const char *from, const char *to) {
    wchar_t wf[WPATH_MAX], wt[WPATH_MAX];
    if (!to_wide(from, wf, COUNT_OF(wf)) || !to_wide(to, wt, COUNT_OF(wt))) return -1;
    // Without MOVEFILE_REPLACE_EXISTING it fails when the name is taken.
    return MoveFileExW(wf, wt, 0) ? 0 : -1;
}

int platform_config_dir(char *out, size_t cap, int create) {
    // Local, not Roaming. A roaming profile would copy it to other machines and a server.
    wchar_t *w = _wgetenv(L"LOCALAPPDATA");
    char base[BASE_DIR_MAX];
    if (!w || !w[0] || from_wide_path(w, base, sizeof base) != 0) return -1;
    int n = snprintf(out, cap, "%s/chat", base);
    if (n <= 0 || (size_t)n >= cap) return -1;
    return create ? platform_private_dir(out) : 0;
}

int platform_private_dir(const char *utf8_path) {
    wchar_t wp[WPATH_MAX];
    if (!to_wide(utf8_path, wp, COUNT_OF(wp))) return -1;
    CreateDirectoryW(wp, NULL);
    DWORD a = GetFileAttributesW(wp);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT) ? 0 : -1;
}

int platform_write_private(const char *utf8_path, const void *data, size_t len) {
    char tmp[WPATH_MAX];
    int n = snprintf(tmp, sizeof tmp, "%s.new", utf8_path);
    wchar_t wt[WPATH_MAX], wp[WPATH_MAX];
    if (n <= 0 || (size_t)n >= sizeof tmp || !to_wide(tmp, wt, COUNT_OF(wt))
        || !to_wide(utf8_path, wp, COUNT_OF(wp))) return -1;
    HANDLE h = CreateFileW(wt, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    const char *p = data;
    BOOL ok = TRUE;
    for (size_t left = len; ok && left > 0; ) {
        DWORD chunk = left > IO_CHUNK ? IO_CHUNK : (DWORD)left, wrote = 0;
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

void current_hhmm(char out[HHMM_LEN]) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_s(&tmv, &t);
    snprintf(out, HHMM_LEN, "%02d:%02d", tmv.tm_hour, tmv.tm_min);
}

void current_stamp(char out[STAMP_LEN]) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_s(&tmv, &t);
    if (strftime(out, STAMP_LEN, "%Y-%m-%d %H:%M", &tmv) != STAMP_LEN - 1) out[0] = '\0';
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
    HANDLE h = CreateThread(thread_sa(), 0, thread_tramp, b, 0, NULL);
    if (!h) { free(b); return -1; }
    CloseHandle(h);
    return 0;
}

int platform_remove(const char *utf8_path) {
    wchar_t wp[WPATH_MAX];
    if (!to_wide(utf8_path, wp, COUNT_OF(wp))) return -1;
    return DeleteFileW(wp) ? 0 : -1;
}

int platform_exe_path(char *out, size_t cap) {
    wchar_t w[WPATH_MAX];
    DWORD n = GetModuleFileNameW(NULL, w, WPATH_MAX);
    return n == 0 || n >= WPATH_MAX ? -1 : from_wide_path(w, out, cap);
}

static int append_quoted(wchar_t *cmd, size_t cap, size_t *pos, const char *arg) {
    wchar_t w[WPATH_MAX];
    if (!to_wide(arg, w, COUNT_OF(w))) return -1;
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

#define EXE_NAME_MAX 64
// The command lines of programs chat waits for, and of the ones it leaves running.
#define RUN_CMD_MAX 8192
#define SPAWN_CMD_MAX 16384

static int command_line(const char *const argv[], wchar_t *cmd, size_t cap) {
    size_t pos = 0;
    cmd[0] = L'\0';
    for (int i = 0; argv[i]; i++)
        if (append_quoted(cmd, cap, &pos, argv[i]) != 0) return -1;
    return 0;
}

// A program's name with ".exe" after it.
static int exe_name(const char *name, wchar_t out[EXE_NAME_MAX]) {
    static const wchar_t suffix[] = L".exe";
    if (!to_wide(name, out, EXE_NAME_MAX - (COUNT_OF(suffix) - 1))) return 0;
    wcscat(out, suffix);
    return 1;
}

static HANDLE open_nul(SECURITY_ATTRIBUTES *sa) {
    return CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, sa, OPEN_EXISTING,
                       0, NULL);
}

// Starts app with its input from nul and its output to out, and in job if there is one. The child
// only inherits those handles, even if other handles in this process are inheritable.
static BOOL start_process(const wchar_t *app, wchar_t *cmd, HANDLE nul, HANDLE out, HANDLE *job,
                          PROCESS_INFORMATION *pi) {
    HANDLE inherit[2] = { nul, out };
    DWORD attr_count = job ? 2 : 1;
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, attr_count, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = attr_size ? malloc(attr_size) : NULL;
    if (!attrs || !InitializeProcThreadAttributeList(attrs, attr_count, 0, &attr_size)) { free(attrs); return FALSE; }
    BOOL ok = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                        out == nul ? sizeof nul : sizeof inherit, NULL, NULL);
    // The child starts in the job (Windows 10 1607 and later), so it doesn't have to be created
    // suspended and resumed once it's been assigned.
    if (ok && job) ok = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, job, sizeof *job, NULL, NULL);
    STARTUPINFOEXW si;
    memset(&si, 0, sizeof si);
    si.StartupInfo.cb = sizeof si;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nul;
    si.StartupInfo.hStdOutput = si.StartupInfo.hStdError = out;
    si.lpAttributeList = attrs;
    if (ok) ok = CreateProcessW(app, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                                NULL, NULL, &si.StartupInfo, pi);
    DeleteProcThreadAttributeList(attrs);
    free(attrs);
    return ok;
}

int platform_run_quiet(const char *const argv[]) {
    // Run argv[0] from System32 only. When searching, CreateProcess tries the exe's own folder and the
    // current folder first, so a curl.exe left next to chat.exe (in Downloads, for example) would run.
    wchar_t app[MAX_PATH + EXE_NAME_MAX], name[EXE_NAME_MAX], cmd[RUN_CMD_MAX];
    UINT sl = GetSystemDirectoryW(app, MAX_PATH);
    if (sl == 0 || sl >= MAX_PATH || strpbrk(argv[0], "/\\:") || !exe_name(argv[0], name)
        || command_line(argv, cmd, COUNT_OF(cmd)) != 0) return -1;
    wcscat(app, L"\\");
    wcscat(app, name);

    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE nul = open_nul(&sa);
    if (nul == INVALID_HANDLE_VALUE) return -1;
    PROCESS_INFORMATION pi;
    BOOL ok = start_process(app, cmd, nul, nul, NULL, &pi);
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
    wchar_t wnew[WPATH_MAX], wexe[WPATH_MAX], wold[WPATH_MAX];
    char old[WPATH_MAX];
    int n = snprintf(old, sizeof old, "%s.old", exe_path);
    if (n <= 0 || (size_t)n >= sizeof old || !to_wide(new_path, wnew, COUNT_OF(wnew))
        || !to_wide(exe_path, wexe, COUNT_OF(wexe)) || !to_wide(old, wold, COUNT_OF(wold))) return -1;
    DeleteFileW(wold);
    if (!MoveFileExW(wexe, wold, MOVEFILE_REPLACE_EXISTING)) return -1;
    if (!MoveFileExW(wnew, wexe, 0)) { MoveFileExW(wold, wexe, 0); return -1; }
    return 0;
}

int platform_default_gateway(uint8_t ip[IP4_LEN]) {
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
            memcpy(ip, &r->dwForwardNextHop, IP4_LEN);
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

int platform_full_path(const char *utf8_path, char *out, size_t cap) {
    wchar_t wp[WPATH_MAX], full[WPATH_MAX];
    if (!to_wide(utf8_path, wp, COUNT_OF(wp))) return -1;
    DWORD n = GetFullPathNameW(wp, WPATH_MAX, full, NULL);
    return n == 0 || n >= WPATH_MAX ? -1 : from_wide_path(full, out, cap);
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

// The longest an environment variable's value can be, with its NUL.
#define ENV_VALUE_MAX 32768

int platform_find_program(const char *name, const char *path, char *out, size_t cap) {
    wchar_t w[MAX_PATH * 2];
    if (path && path[0]) return to_wide(path, w, COUNT_OF(w)) ? program_ok_w(w, out, cap) : -1;
    wchar_t exe[EXE_NAME_MAX];
    if (!exe_name(name, exe)) return -1;
    // Only absolute PATH entries, since CreateProcess style searching would try the current folder first.
    static wchar_t env[ENV_VALUE_MAX];
    DWORD n = GetEnvironmentVariableW(L"PATH", env, ENV_VALUE_MAX);
    if (n > 0 && n < ENV_VALUE_MAX) {
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

#define TEMP_PREFIX_MAX 48
#define TEMPDIR_TRIES 8
#define REMOVE_DEPTH_MAX 16
// A temporary folder younger than this may still be being set up by another chat.
#define STALE_AFTER 60

int platform_private_tempdir(const char *prefix, char *out, size_t cap) {
    // The user's own temp folder. Its permissions keep other users out, and a random name that must
    // not exist yet stops a folder someone else created from being used.
    wchar_t base[MAX_PATH + 1], wp[TEMP_PREFIX_MAX], dir[MAX_PATH * 2];
    DWORD n = GetTempPathW(MAX_PATH + 1, base);
    if (n == 0 || n > MAX_PATH || !to_wide(prefix, wp, COUNT_OF(wp))) return -1;
    for (int tries = 0; tries < TEMPDIR_TRIES; tries++) {
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
    if (!(a & FILE_ATTRIBUTE_REPARSE_POINT) && depth < REMOVE_DEPTH_MAX) {
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
    return to_wide(path, w, COUNT_OF(w)) ? remove_tree_w(w, 0) : -1;
}

struct platform_proc { HANDLE process, job; };

platform_proc_t *platform_spawn(const char *const argv[], const char *out_path) {
    wchar_t app[MAX_PATH * 2];
    static wchar_t cmd[SPAWN_CMD_MAX];
    if (!argv[0] || !to_wide(argv[0], app, COUNT_OF(app)) || !wide_is_absolute(app)
        || command_line(argv, cmd, COUNT_OF(cmd)) != 0) return NULL;

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
    HANDLE nul = open_nul(&sa), out = nul;
    wchar_t wout[MAX_PATH * 2];
    if (out_path) {
        out = to_wide(out_path, wout, COUNT_OF(wout))
            ? CreateFileW(wout, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)
            : INVALID_HANDLE_VALUE;
    }
    PROCESS_INFORMATION pi;
    BOOL ok = nul != INVALID_HANDLE_VALUE && out != INVALID_HANDLE_VALUE
              && start_process(app, cmd, nul, out, &p->job, &pi);
    if (out != nul && out != INVALID_HANDLE_VALUE) CloseHandle(out);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) { CloseHandle(p->job); free(p); return NULL; }
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
    wchar_t base[MAX_PATH + 1], wp[TEMP_PREFIX_MAX], pat[MAX_PATH * 2], wl[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH + 1, base);
    if (n == 0 || n > MAX_PATH || !to_wide(prefix, wp, COUNT_OF(wp)) || !to_wide(lock_rel, wl, COUNT_OF(wl))) return;
    swprintf(pat, MAX_PATH * 2, L"%ls%ls-*", base, wp);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t now = filetime_value(ft);
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        if (now - filetime_value(fd.ftLastWriteTime) < STALE_AFTER * FILETIME_PER_SECOND) continue;
        wchar_t dir[MAX_PATH * 2], lock[MAX_PATH * 3];
        swprintf(dir, MAX_PATH * 2, L"%ls%ls", base, fd.cFileName);
        swprintf(lock, MAX_PATH * 3, L"%ls\\%ls", dir, wl);
        // A running tor keeps its lock file open, so it can't be deleted.
        if (!DeleteFileW(lock) && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) continue;
        remove_tree_w(dir, 0);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}
