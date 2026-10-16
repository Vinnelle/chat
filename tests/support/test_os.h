// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TEST_OS_H
#define CHAT_TEST_OS_H

#include <stddef.h>

// What points chat's home and config folders elsewhere, as each system names it.
#ifdef _WIN32
#define TEST_HOME_VAR "USERPROFILE"
#define TEST_CONFIG_VAR "LOCALAPPDATA"
#else
#define TEST_HOME_VAR "HOME"
#define TEST_CONFIG_VAR "XDG_CONFIG_HOME"
#endif

// A new folder of the test's own in the system's temporary folder, with what in its name. 0 or -1.
int test_temp_dir(const char *what, char *out, size_t cap);
void test_set_env(const char *name, const char *value);

#endif
