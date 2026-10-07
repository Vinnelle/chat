// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the tests need of the system that chat itself never asks for. Windows' headers stay here, out
// of the tests, whose names they'd clash with.
#include "test_os.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int test_temp_dir(const char *what, char *out, size_t cap) {
#ifdef _WIN32
    wchar_t wbase[MAX_PATH + 1];
    char base[MAX_PATH * 3], hex[13];
    uint8_t r[6];
    DWORD n = GetTempPathW(MAX_PATH + 1, wbase);
    if (n == 0 || n > MAX_PATH || WideCharToMultiByte(CP_UTF8, 0, wbase, -1, base, sizeof base, NULL, NULL) <= 0) return -1;
    gen_random(r, sizeof r);
    hex_encode(r, sizeof r, hex);
    int len = snprintf(out, cap, "%schat-%s-%s", base, what, hex);
    if (len <= 0 || (size_t)len >= cap) return -1;
    for (char *p = out; *p; p++) if (*p == '\\') *p = '/';
    return platform_private_dir(out);
#else
    int len = snprintf(out, cap, "/tmp/chat-%s-XXXXXX", what);
    return len > 0 && (size_t)len < cap && mkdtemp(out) ? 0 : -1;
#endif
}

void test_set_env(const char *name, const char *value) {
#ifdef _WIN32
    wchar_t wn[64], wv[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, wn, 64) > 0 && MultiByteToWideChar(CP_UTF8, 0, value, -1, wv, 1024) > 0)
        _wputenv_s(wn, wv);
#else
    setenv(name, value, 1);
#endif
}
