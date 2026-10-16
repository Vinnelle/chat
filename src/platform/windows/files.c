// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Files and folders: listing, reading and writing them, the folders chat keeps its files in,
// temporary folders, and what chat reads from the system (the machine id, the default gateway, the
// CA roots).
#include "win.h"
#include "crypto/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <io.h>
#include <fcntl.h>
#include <wchar.h>
#include <time.h>

// A folder from the environment, short enough for paths under it to fit in WPATH_MAX.
#define BASE_DIR_MAX 900
#define IO_CHUNK 65536

int to_wide(const char *utf8, wchar_t *out, size_t cap) {
    return MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, (int)cap) > 0;
}

int from_wide(const wchar_t *w, char *out, size_t cap) {
    return WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL) > 0 ? 0 : -1;
}

// As from_wide, with '/' between folders as the rest of chat writes paths.
int from_wide_path(const wchar_t *w, char *out, size_t cap) {
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

int platform_remove(const char *utf8_path) {
    wchar_t wp[WPATH_MAX];
    if (!to_wide(utf8_path, wp, COUNT_OF(wp))) return -1;
    return DeleteFileW(wp) ? 0 : -1;
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
