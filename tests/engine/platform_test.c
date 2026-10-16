// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The platform code: reading only regular files, and the sandbox.
#include "harness.h"

// Key files and Tor's cookie are read without blocking, and only from regular files: a FIFO
// would otherwise hang chat. Windows has no FIFOs in folders.
void test_read_file(double *t) {
    (void)t;
    char dir[256], file[300], buf[64];
    if (test_temp_dir("test", dir, sizeof dir) != 0) { CHECK(0, "no temporary folder for the file test"); return; }
    snprintf(file, sizeof file, "%s/key", dir);
#ifndef _WIN32
    char fifo[300];
    snprintf(fifo, sizeof fifo, "%s/fifo", dir);
    CHECK(mkfifo(fifo, 0600) == 0, "couldn't make a FIFO");
    CHECK(platform_read_file(fifo, buf, sizeof buf) == -1, "a FIFO was read as a file");
    identity_keypair_t id;
    CHECK(age_import_secret_key(fifo, &id) != 0 && pgp_import_secret_key(fifo, &id) != 0, "a key loaded from a FIFO");
#endif
    FILE *f = fopen(file, "wb");
    if (f) { fputs("hello", f); fclose(f); }
    CHECK(platform_read_file(file, buf, sizeof buf) == 5 && memcmp(buf, "hello", 5) == 0, "a regular file didn't read back");
    CHECK(platform_read_file(file, buf, 3) == 3, "a read past cap");
    CHECK(platform_read_file(dir, buf, sizeof buf) == -1, "a folder was read as a file");
    platform_remove_tree(dir);
}

// The sandbox, in a child with a home folder of its own: a dotfile, a dot-folder and a folder on
// PATH stay out of reach, a home folder and chat's own folder don't, nothing runs, and ptrace is
// refused. Skipped on a kernel without Landlock.
void test_sandbox(double *t) {
    (void)t;
#ifdef __linux__
    static char home[256];
    CHECK(test_temp_dir("sandbox", home, sizeof home) == 0, "no temporary folder");
    char path[700];
    static const char *const DIRS[] = { "Documents", ".config", ".config/chat", "bin" };
    for (size_t i = 0; i < COUNT_OF(DIRS); i++) {
        snprintf(path, sizeof path, "%s/%s", home, DIRS[i]);
        mkdir(path, 0700);
    }
    snprintf(path, sizeof path, "%s/.bashrc", home);
    FILE *f = fopen(path, "w");
    if (f) fclose(f);
    enum { SKIP = 77, DOTFILE = 1, DOTDIR = 2, ON_PATH = 4, HOME_DIR = 8, OWN_DIR = 16, RAN = 32, TRACED = 64 };
    pid_t pid = fork();
    if (pid == 0) {
        setenv("HOME", home, 1);
        unsetenv("XDG_CONFIG_HOME");
        snprintf(path, sizeof path, "%s/bin:/usr/bin:/bin", home);
        setenv("PATH", path, 1);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        char why[160];
        unsigned up = (unsigned)platform_sandbox(NULL, 0, NULL, why, sizeof why);
        if (!(up & PLATFORM_SANDBOX_FILES)) _exit(SKIP);
        int bad = 0, fd;
        snprintf(path, sizeof path, "%s/.bashrc", home);
        if ((fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC)) >= 0 || errno != EACCES) bad |= DOTFILE;
        snprintf(path, sizeof path, "%s/.config/autostart", home);
        if (mkdir(path, 0700) == 0 || errno != EACCES) bad |= DOTDIR;
        snprintf(path, sizeof path, "%s/bin/ls", home);
        if ((fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0700)) >= 0 || errno != EACCES) bad |= ON_PATH;
        snprintf(path, sizeof path, "%s/Documents/note", home);
        if ((fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600)) < 0) bad |= HOME_DIR;
        snprintf(path, sizeof path, "%s/.config/chat/settings", home);
        if ((fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600)) < 0) bad |= OWN_DIR;
        pid_t child;
        char *const argv[] = { (char *)"true", NULL }, *const envp[] = { NULL };
        if (posix_spawn(&child, "/bin/true", NULL, NULL, argv, envp) == 0) { waitpid(child, NULL, 0); bad |= RAN; }
        if ((up & PLATFORM_SANDBOX_CALLS) && (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0 || errno != EPERM)) bad |= TRACED;
        _exit(bad);
    }
    int status = 0;
    CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status), "the sandboxed child didn't finish");
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 0;
    if (code == SKIP) {
        if (verbose) printf("  skip  this kernel has no Landlock\n");
        return;
    }
    CHECK(!(code & DOTFILE), "a dotfile in the home folder could still be written");
    CHECK(!(code & DOTDIR), "a folder could still be made in a dot-folder (~/.config/autostart)");
    CHECK(!(code & ON_PATH), "a folder on PATH could still be written");
    CHECK(!(code & HOME_DIR), "a folder in the home folder couldn't be written");
    CHECK(!(code & OWN_DIR), "chat's own folder couldn't be written");
    CHECK(!(code & RAN), "a program it wasn't given still ran");
    CHECK(!(code & TRACED), "ptrace wasn't refused");

    // The updater's: only the executable's folder, even on PATH, where it can replace chat.
    enum { REPLACED = 1, ELSEWHERE = 2 };
    snprintf(path, sizeof path, "%s/bin/chat", home);
    f = fopen(path, "w");
    if (f) fclose(f);
    pid = fork();
    if (pid == 0) {
        char why[160], dir[600], from[700];
        snprintf(dir, sizeof dir, "%s/bin", home);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if (!(platform_sandbox(NULL, 0, dir, why, sizeof why) & PLATFORM_SANDBOX_FILES)) _exit(SKIP);
        int bad = 0, fd;
        snprintf(from, sizeof from, "%s/bin/chat.download", home);
        if ((fd = open(from, O_WRONLY | O_CREAT | O_CLOEXEC, 0700)) < 0 || rename(from, path) != 0) bad |= REPLACED;
        snprintf(from, sizeof from, "%s/Documents/other", home);
        if ((fd = open(from, O_WRONLY | O_CREAT | O_CLOEXEC, 0600)) >= 0 || errno != EACCES) bad |= ELSEWHERE;
        _exit(bad);
    }
    CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status), "the updater's sandboxed child didn't finish");
    code = WIFEXITED(status) ? WEXITSTATUS(status) : 0;
    CHECK(!(code & REPLACED), "the updater couldn't replace chat in its own folder");
    CHECK(!(code & ELSEWHERE), "the updater could write outside the executable's folder");
#endif
}
