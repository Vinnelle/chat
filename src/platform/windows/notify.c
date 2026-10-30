// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Notifications, the clipboard, and opening links.
#include "win.h"
#include "crypto/crypto.h"
#include <stdlib.h>
#include <string.h>
#include <shellapi.h>
#include <wchar.h>

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

// The clipboard's sequence number once chat put text there, or 0.
static DWORD g_clip_seq;

static HGLOBAL global_copy(const void *data, size_t len) {
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, len);
    void *p = h ? GlobalLock(h) : NULL;
    if (!p) { if (h) GlobalFree(h); return NULL; }
    memcpy(p, data, len);
    GlobalUnlock(h);
    return h;
}

// A clipboard format that tells Windows what to do with the rest: once it's set, the clipboard owns h.
static void clipboard_flag(const wchar_t *name, DWORD value) {
    UINT fmt = RegisterClipboardFormatW(name);
    HGLOBAL h = fmt ? global_copy(&value, sizeof value) : NULL;
    if (h && !SetClipboardData(fmt, h)) GlobalFree(h);
}

// Clipboard history (Win+V) and cloud clipboard keep what's copied, and clipboard managers read it:
// these formats keep the text out of all three.
int platform_clipboard_set(const char *text) {
    int wn = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    if (wn <= 0) return -1;
    wchar_t *w = malloc((size_t)wn * sizeof *w);
    if (!w) return -1;
    MultiByteToWideChar(CP_UTF8, 0, text, -1, w, wn);
    HGLOBAL h = global_copy(w, (size_t)wn * sizeof *w);
    crypto_wipe(w, (size_t)wn * sizeof *w);
    free(w);
    if (!h) return -1;
    if (!OpenClipboard(NULL)) { GlobalFree(h); return -1; }
    EmptyClipboard();
    if (!SetClipboardData(CF_UNICODETEXT, h)) { CloseClipboard(); GlobalFree(h); return -1; }
    clipboard_flag(L"ExcludeClipboardContentFromMonitorProcessing", 0);
    clipboard_flag(L"CanIncludeInClipboardHistory", 0);
    clipboard_flag(L"CanUploadToCloudClipboard", 0);
    CloseClipboard();
    g_clip_seq = GetClipboardSequenceNumber();
    return 0;
}

int platform_clipboard_clear(void) {
    if (!g_clip_seq) return -1;
    DWORD seq = g_clip_seq;
    g_clip_seq = 0;
    if (GetClipboardSequenceNumber() != seq) return 0;
    if (!OpenClipboard(NULL)) return -1;
    EmptyClipboard();
    CloseClipboard();
    return 1;
}

int platform_open_url(const char *url, char *why, size_t cap) {
    wchar_t w[LINK_URL_MAX];
    if (!to_wide(url, w, COUNT_OF(w))) { copy_str(why, "Windows couldn't read it", cap); return -1; }
    if ((INT_PTR)ShellExecuteW(NULL, L"open", w, NULL, NULL, SW_SHOWNORMAL) > 32) return 0;
    copy_str(why, "Windows has no browser set to open it with", cap);
    return -1;
}
