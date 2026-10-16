// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The process: hardening it, the secrets in its environment, its arguments, the clock, threads, the
// executable, and the programs and processes it starts.
#include "win.h"
#include "crypto/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <wchar.h>
#include <time.h>

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
SECURITY_ATTRIBUTES *thread_sa(void) { return g_thread_sa.nLength ? &g_thread_sa : NULL; }

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

void stamp_at(long long at, char out[STAMP_LEN]) {
    time_t t = (time_t)at;
    struct tm tmv;
    localtime_s(&tmv, &t);
    if (strftime(out, STAMP_LEN, "%Y-%m-%d %H:%M", &tmv) != STAMP_LEN - 1) out[0] = '\0';
}

void current_stamp(char out[STAMP_LEN]) { stamp_at((long long)time(NULL), out); }

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
