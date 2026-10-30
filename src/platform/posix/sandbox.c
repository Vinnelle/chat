// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The sandbox: Landlock for what chat writes and runs, seccomp for the system calls it makes. And the
// child pictures are decoded in, behind a tighter filter of its own. Both are Linux only: elsewhere,
// the stubs at the end.
#include "posix.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef __linux__
#include <elf.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif

#ifdef __linux__
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#endif
// Landlock's rights and structures, as linux/landlock.h has them (older systems don't have it).
#define LL_EXECUTE       (1ull << 0)
#define LL_WRITE_FILE    (1ull << 1)
#define LL_REMOVE_DIR    (1ull << 4)
#define LL_REMOVE_FILE   (1ull << 5)
#define LL_MAKE_CHAR     (1ull << 6)
#define LL_MAKE_DIR      (1ull << 7)
#define LL_MAKE_REG      (1ull << 8)
#define LL_MAKE_SOCK     (1ull << 9)
#define LL_MAKE_FIFO     (1ull << 10)
#define LL_MAKE_BLOCK    (1ull << 11)
#define LL_MAKE_SYM      (1ull << 12)
#define LL_REFER         (1ull << 13)
#define LL_TRUNCATE      (1ull << 14)
#define LL_SCOPE_SIGNAL  (1ull << 1)
#define LL_ABI_REFER 2
#define LL_ABI_TRUNCATE 3
#define LL_ABI_SCOPE 6
#define LL_CREATE_RULESET_VERSION 1u
#define LL_RULE_PATH_BENEATH 1
#define SANDBOX_RUN_MAX 8
#define SANDBOX_INTERP_DEPTH 2

struct ll_ruleset { uint64_t handled_fs, handled_net, scoped; };
struct ll_beneath { uint64_t allowed; int32_t parent_fd; } __attribute__((packed));

static struct {
    int abi, layers, err;
    int broad_config;   // chat's folder wasn't there yet, so the folder it goes in was let in instead
    char run[SANDBOX_RUN_MAX][PATH_BUF];
    int n_run;
    char write_only[PATH_BUF];
} g_sb;

static int ll_add(int ruleset, const char *path, uint64_t allowed) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return -1;
    struct ll_beneath b = { allowed, fd };
    int rc = (int)syscall(SYS_landlock_add_rule, ruleset, LL_RULE_PATH_BENEATH, &b, 0);
    close(fd);
    return rc;
}

static int path_under(const char *path, const char *dir) {
    size_t n = strlen(dir);
    if (n == 1 && dir[0] == '/') return 1;
    return strncmp(path, dir, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

// Writing under a folder holding a PATH entry could put a program where a shell would run it.
static int holds_path_entry(const char *real) {
    const char *env = getenv("PATH");
    if (!env) return 0;
    char list[PATH_LIST_MAX], entry[PATH_BUF];
    copy_str(list, env, sizeof list);
    for (char *save = NULL, *dir = strtok_r(list, ":", &save); dir; dir = strtok_r(NULL, ":", &save))
        if (dir[0] == '/' && realpath(dir, entry) && path_under(entry, real)) return 1;
    return 0;
}

// The folders directly in $HOME that aren't hidden, unless one is a link to $HOME or above it, or
// to a hidden folder, or holds a PATH entry. Dotfiles and dot-folders (.bashrc, .config/autostart,
// .ssh, .local/bin) stay out of reach.
static void ll_add_home(int ruleset, uint64_t write) {
    const char *env = getenv("HOME");
    char home[PATH_BUF];
    if (!env || env[0] != '/' || !realpath(env, home)) return;
    DIR *d = opendir(home);
    if (!d) return;
    size_t hl = strlen(home);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char path[PATH_BUF], real[PATH_BUF];
        struct stat st;
        int n = snprintf(path, sizeof path, "%s/%s", home, e->d_name);
        if (e->d_name[0] == '.' || n <= 0 || (size_t)n >= sizeof path) continue;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode) || !realpath(path, real)) continue;
        if (path_under(home, real) || holds_path_entry(real)) continue;
        if (path_under(real, home) && strstr(real + hl, "/.")) continue;
        ll_add(ruleset, real, write);
    }
    closedir(d);
}

// chat's own folder, or until the first :install makes it, the folder it goes in.
static void ll_add_config(int ruleset, uint64_t write) {
    char dir[PATH_BUF];
    struct stat st;
    if (platform_config_dir(dir, sizeof dir, 0) != 0) return;
    if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (ll_add(ruleset, dir, write) == 0) g_sb.broad_config = 0;
        return;
    }
    char *slash = strrchr(dir, '/');
    if (!slash || slash == dir) return;
    *slash = '\0';
    if (mkdir(dir, MODE_PRIVATE_DIR) != 0 && errno != EEXIST) return;
    if (ll_add(ruleset, dir, write) == 0) g_sb.broad_config = 1;
}

// What execve also opens to run path: its #! line's program, or an ELF program's loader (ld-linux).
static int exec_interp(const char *path, char *out, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC), rc = -1;
    if (fd < 0) return -1;
    unsigned char head[EI_NIDENT];
    ssize_t got = pread(fd, head, sizeof head, 0);
    if (got >= 2 && head[0] == '#' && head[1] == '!') {
        char line[PATH_BUF];
        ssize_t n = pread(fd, line, sizeof line - 1, 2);
        if (n > 0) {
            line[n] = '\0';
            char *s = line + strspn(line, " \t");
            s[strcspn(s, " \t\r\n")] = '\0';
            if (s[0] == '/' && strlen(s) < cap) { copy_str(out, s, cap); rc = 0; }
        }
    } else if (got == (ssize_t)sizeof head && memcmp(head, ELFMAG, SELFMAG) == 0) {
        int is64 = head[EI_CLASS] == ELFCLASS64;
        uint64_t phoff = 0;
        unsigned phnum = 0, phentsize = 0;
        Elf64_Ehdr e64;
        Elf32_Ehdr e32;
        if (is64 && pread(fd, &e64, sizeof e64, 0) == (ssize_t)sizeof e64) {
            phoff = e64.e_phoff; phnum = e64.e_phnum; phentsize = e64.e_phentsize;
        } else if (!is64 && pread(fd, &e32, sizeof e32, 0) == (ssize_t)sizeof e32) {
            phoff = e32.e_phoff; phnum = e32.e_phnum; phentsize = e32.e_phentsize;
        }
        for (unsigned i = 0; i < phnum && rc != 0; i++) {
            uint64_t type = 0, offset = 0, size = 0;
            off_t at = (off_t)(phoff + (uint64_t)i * phentsize);
            Elf64_Phdr p64;
            Elf32_Phdr p32;
            if (is64 && pread(fd, &p64, sizeof p64, at) == (ssize_t)sizeof p64) {
                type = p64.p_type; offset = p64.p_offset; size = p64.p_filesz;
            } else if (!is64 && pread(fd, &p32, sizeof p32, at) == (ssize_t)sizeof p32) {
                type = p32.p_type; offset = p32.p_offset; size = p32.p_filesz;
            } else {
                break;
            }
            if (type != PT_INTERP || size < 2 || size > cap) continue;
            if (pread(fd, out, (size_t)size, (off_t)offset) != (ssize_t)size) break;
            out[size - 1] = '\0';
            rc = out[0] == '/' ? 0 : -1;
            break;
        }
    }
    close(fd);
    return rc;
}

static void sb_run(const char *path, int depth) {
    char real[PATH_BUF], interp[PATH_BUF];
    if (g_sb.n_run >= SANDBOX_RUN_MAX || !realpath(path, real)) return;
    for (int i = 0; i < g_sb.n_run; i++) if (strcmp(g_sb.run[i], real) == 0) return;
    copy_str(g_sb.run[g_sb.n_run++], real, PATH_BUF);
    if (depth < SANDBOX_INTERP_DEPTH && exec_interp(real, interp, sizeof interp) == 0) sb_run(interp, depth + 1);
}

// One more layer: an access gets through only if every layer lets it, so a later one can only narrow.
static int ll_apply(void) {
    uint64_t write = LL_WRITE_FILE | LL_REMOVE_DIR | LL_REMOVE_FILE | LL_MAKE_DIR | LL_MAKE_REG;
    uint64_t handled = write | LL_EXECUTE | LL_MAKE_CHAR | LL_MAKE_SOCK | LL_MAKE_FIFO | LL_MAKE_BLOCK | LL_MAKE_SYM;
    if (g_sb.abi >= LL_ABI_REFER) { handled |= LL_REFER; write |= LL_REFER; }
    if (g_sb.abi >= LL_ABI_TRUNCATE) { handled |= LL_TRUNCATE; write |= LL_TRUNCATE; }
    // Not signals to processes outside the sandbox either. Abstract sockets stay open: a D-Bus
    // session bus can be one.
    struct ll_ruleset attr = { handled, 0, g_sb.abi >= LL_ABI_SCOPE ? LL_SCOPE_SIGNAL : 0 };
    int rs = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (rs < 0) { g_sb.err = errno; return -1; }
    if (g_sb.write_only[0]) {
        ll_add(rs, g_sb.write_only, write);
    } else {
        ll_add_home(rs, write);
        char downloads[PATH_BUF];
        if (platform_downloads_dir(downloads, sizeof downloads) == 0) ll_add(rs, downloads, write);
        ll_add_config(rs, write);
        ll_add(rs, tempdir_base(), write);
    }
    // Opening a device to write to it: /dev/null, a security key's hidraw, the TPM.
    ll_add(rs, "/dev", LL_WRITE_FILE | (g_sb.abi >= LL_ABI_TRUNCATE ? LL_TRUNCATE : 0));
    for (int i = 0; i < g_sb.n_run; i++) ll_add(rs, g_sb.run[i], LL_EXECUTE);
    int rc = (int)syscall(SYS_landlock_restrict_self, rs, 0);
    if (rc != 0) g_sb.err = errno;
    close(rs);
    if (rc == 0) g_sb.layers++;
    return rc;
}

#if defined(__x86_64__)
#define SB_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SB_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#define SB_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__arm__) && !defined(__ARMEB__)
#define SB_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__riscv) && __riscv_xlen == 64
#define SB_AUDIT_ARCH AUDIT_ARCH_RISCV64
#endif

#ifdef SB_AUDIT_ARCH
// Calls chat never makes, refused for it and what it runs: tracing and reading other processes,
// BPF, io_uring, keyrings, mounts and namespaces, kernel modules, and setting the clock.
static const unsigned SB_DENY[] = {
#ifdef __NR_ptrace
    __NR_ptrace,
#endif
#ifdef __NR_process_vm_readv
    __NR_process_vm_readv,
#endif
#ifdef __NR_process_vm_writev
    __NR_process_vm_writev,
#endif
#ifdef __NR_kcmp
    __NR_kcmp,
#endif
#ifdef __NR_perf_event_open
    __NR_perf_event_open,
#endif
#ifdef __NR_bpf
    __NR_bpf,
#endif
#ifdef __NR_userfaultfd
    __NR_userfaultfd,
#endif
#ifdef __NR_io_uring_setup
    __NR_io_uring_setup,
#endif
#ifdef __NR_io_uring_enter
    __NR_io_uring_enter,
#endif
#ifdef __NR_io_uring_register
    __NR_io_uring_register,
#endif
#ifdef __NR_keyctl
    __NR_keyctl,
#endif
#ifdef __NR_add_key
    __NR_add_key,
#endif
#ifdef __NR_request_key
    __NR_request_key,
#endif
#ifdef __NR_mount
    __NR_mount,
#endif
#ifdef __NR_umount2
    __NR_umount2,
#endif
#ifdef __NR_pivot_root
    __NR_pivot_root,
#endif
#ifdef __NR_chroot
    __NR_chroot,
#endif
#ifdef __NR_open_tree
    __NR_open_tree,
#endif
#ifdef __NR_move_mount
    __NR_move_mount,
#endif
#ifdef __NR_fsopen
    __NR_fsopen,
#endif
#ifdef __NR_fsconfig
    __NR_fsconfig,
#endif
#ifdef __NR_fsmount
    __NR_fsmount,
#endif
#ifdef __NR_fspick
    __NR_fspick,
#endif
#ifdef __NR_mount_setattr
    __NR_mount_setattr,
#endif
#ifdef __NR_unshare
    __NR_unshare,
#endif
#ifdef __NR_setns
    __NR_setns,
#endif
#ifdef __NR_init_module
    __NR_init_module,
#endif
#ifdef __NR_finit_module
    __NR_finit_module,
#endif
#ifdef __NR_delete_module
    __NR_delete_module,
#endif
#ifdef __NR_kexec_load
    __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
    __NR_kexec_file_load,
#endif
#ifdef __NR_reboot
    __NR_reboot,
#endif
#ifdef __NR_swapon
    __NR_swapon,
#endif
#ifdef __NR_swapoff
    __NR_swapoff,
#endif
#ifdef __NR_acct
    __NR_acct,
#endif
#ifdef __NR_quotactl
    __NR_quotactl,
#endif
#ifdef __NR_open_by_handle_at
    __NR_open_by_handle_at,
#endif
#ifdef __NR_name_to_handle_at
    __NR_name_to_handle_at,
#endif
#ifdef __NR_lookup_dcookie
    __NR_lookup_dcookie,
#endif
#ifdef __NR_vhangup
    __NR_vhangup,
#endif
#ifdef __NR_syslog
    __NR_syslog,
#endif
#ifdef __NR_settimeofday
    __NR_settimeofday,
#endif
#ifdef __NR_clock_settime
    __NR_clock_settime,
#endif
#ifdef __NR_clock_adjtime
    __NR_clock_adjtime,
#endif
#ifdef __NR_adjtimex
    __NR_adjtimex,
#endif
#ifdef __NR_uselib
    __NR_uselib,
#endif
#ifdef __NR_iopl
    __NR_iopl,
#endif
#ifdef __NR_ioperm
    __NR_ioperm,
#endif
#ifdef __NR_modify_ldt
    __NR_modify_ldt,
#endif
};
#endif

// Refused calls get EPERM rather than a kill, so a library that tries one just sees it fail.
static int sc_apply(void) {
#ifdef SB_AUDIT_ARCH
    enum { N = (int)COUNT_OF(SB_DENY) };
    struct sock_filter f[N + 8];
    int n = 0;
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    // Another architecture's numbers (32-bit calls on a 64-bit kernel) would get past the list.
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SB_AUDIT_ARCH, 1, 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
    // So would x32's, which are the same numbers with this bit set.
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, (unsigned char)(N + 1), 0);
#endif
    for (int i = 0; i < N; i++)
        f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SB_DENY[i], (unsigned char)(N - i), 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    struct sock_fprog prog = { (unsigned short)n, f };
#if defined(SYS_seccomp) && !defined(__ANDROID__)
    // Every thread, if the kernel can. An Android app's own filter may kill a process for this call,
    // so there it's prctl's, for this thread and the ones it starts.
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) == 0) return 0;
#endif
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0 ? 0 : -1;
#else
    return -1;
#endif
}

unsigned platform_sandbox(const char *const run[], int n_run, const char *write_only, char *why, size_t cap) {
    if (cap) why[0] = '\0';
    copy_str(g_sb.write_only, write_only ? write_only : "", sizeof g_sb.write_only);
    g_sb.n_run = 0;
    for (int i = 0; i < n_run; i++) if (run[i] && run[i][0]) sb_run(run[i], 0);
    unsigned up = 0;
#ifdef __ANDROID__
    // An Android app's own seccomp filter, which chat runs under, kills a process for Landlock's calls.
    g_sb.abi = 0;
    snprintf(why, cap, "Android apps can't use Landlock");
#else
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LL_CREATE_RULESET_VERSION);
    g_sb.abi = abi > 0 ? (int)abi : 0;
    if (!g_sb.abi) snprintf(why, cap, "this kernel has no Landlock (it needs Linux 5.13 or later, with Landlock on)");
    else if (ll_apply() == 0) up |= PLATFORM_SANDBOX_FILES;
    else snprintf(why, cap, "Landlock refused its rules (%s)", strerror(g_sb.err));
#endif
    if (sc_apply() == 0) up |= PLATFORM_SANDBOX_CALLS;
    else if (cap && !why[0]) snprintf(why, cap, "seccomp refused its filter (%s)", strerror(errno));
    return up;
}

void platform_sandbox_narrow(void) {
    char dir[PATH_BUF];
    struct stat st;
    if (!g_sb.layers || !g_sb.broad_config) return;
    if (platform_config_dir(dir, sizeof dir, 0) == 0 && stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) ll_apply();
}

platform_proc_t *platform_spawn_self(const char *name, const char *arg, int *link) {
    int sv[2];
    platform_proc_t *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) { free(p); return NULL; }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, sv[1], STDIN_FILENO);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    const char *const argv[] = { name, arg, NULL };
    // The file this process was started from, even if it has been replaced since: the same build.
    // The kernel names the new process after it ("exe") until it calls platform_set_name.
    int rc = spawn_grouped(&p->pid, "/proc/self/exe", argv, &fa);
    posix_spawn_file_actions_destroy(&fa);
    close(sv[1]);
    if (rc != 0) { close(sv[0]); free(p); return NULL; }
    *link = sv[0];
    return p;
}

int platform_parent_link(void) {
    int type = 0;
    socklen_t len = sizeof type;
    if (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_TYPE, &type, &len) != 0 || type != SOCK_SEQPACKET) return -1;
    return STDIN_FILENO;
}

void platform_set_name(const char *name) { prctl(PR_SET_NAME, name, 0, 0, 0); }

int platform_link_send(int link, const void *msg, size_t len) {
    ssize_t n;
    while ((n = send(link, msg, len, MSG_NOSIGNAL)) < 0 && errno == EINTR) {}
    return n == (ssize_t)len ? 0 : -1;
}

int platform_link_recv(int link, void *msg, size_t len) {
    ssize_t n;
    // MSG_TRUNC returns a longer message's whole length, so it isn't taken for one that fits.
    while ((n = recv(link, msg, len, MSG_TRUNC)) < 0 && errno == EINTR) {}
    return n == (ssize_t)len ? 0 : -1;
}

void platform_link_close(int link) { close(link); }

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000u
#endif
// The child's own exit code when it couldn't put its filter up.
#define ISOLATE_NO_FILTER 3
#if defined(__ANDROID__) && !defined(PR_SET_VMA)
#define PR_SET_VMA 0x53564d41
#endif

#ifdef SB_AUDIT_ARCH
// What the child may call: the memory calls malloc makes, never for executable memory, write to its
// pipe alone, and exit. Anything else kills it.
static const unsigned ISOLATE_ALLOW[] = {
    __NR_brk, __NR_munmap, __NR_mremap, __NR_madvise, __NR_exit, __NR_exit_group, __NR_rt_sigreturn, __NR_futex,
#ifdef __NR_getrandom
    __NR_getrandom,
#endif
#ifdef __NR_sigreturn
    __NR_sigreturn,
#endif
};

static int isolate_filter(int fd) {
    enum { N = (int)COUNT_OF(ISOLATE_ALLOW) };
    struct sock_filter f[N + 24];
    int n = 0;
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SB_AUDIT_ARCH, 1, 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 4);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)fd, 0, 1);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#ifdef __ANDROID__
    // Bionic's malloc names the memory it maps, and that's all prctl may do here.
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 4);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_VMA, 0, 1);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif
#ifdef __NR_mmap2
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap2, 2, 0);
#else
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 2, 0);
#endif
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 1, 0);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 4);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 1, 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    for (int i = 0; i < N; i++)
        f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ISOLATE_ALLOW[i], (unsigned char)(N - i), 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog prog = { (unsigned short)n, f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0 ? 0 : -1;
}

static double mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

// A fork, not a new process: the data is already in the copy, so nothing has to be sent to it. The
// copy has the keys too, which is why the filter only lets it write to the pipe, whose other end
// only takes as much as the caller expects.
long platform_isolated(void (*fn)(void *arg, int fd), void *arg, void *out, size_t cap, int timeout_ms) {
    int pp[2];
    if (pipe2(pp, O_CLOEXEC) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pp[0]); close(pp[1]); return -1; }
    if (pid == 0) {
        close(pp[0]);
        if (isolate_filter(pp[1]) != 0) _exit(ISOLATE_NO_FILTER);
        fn(arg, pp[1]);
        _exit(0);
    }
    close(pp[1]);
    size_t got = 0;
    int timed_out = 0;
    double end = mono_ms() + timeout_ms;
    while (got < cap) {
        int left = (int)(end - mono_ms());
        if (left <= 0) { timed_out = 1; break; }
        struct pollfd pf = { pp[0], POLLIN, 0 };
        int r = poll(&pf, 1, left);
        if (r < 0 && errno == EINTR) continue;
        if (r == 0) { timed_out = 1; break; }
        if (r < 0) break;
        ssize_t k = read(pp[0], (char *)out + got, cap - got);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        got += (size_t)k;
    }
    close(pp[0]);
    // One that wrote all it may still runs until its write returns, and gets SIGPIPE if there's more.
    if (timed_out || got == cap) kill(pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (timed_out) return -2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == ISOLATE_NO_FILTER) return -1;
    if (got == cap && got > 0) return (long)got;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? (long)got : -2;
}
#else
long platform_isolated(void (*fn)(void *arg, int fd), void *arg, void *out, size_t cap, int timeout_ms) {
    (void)fn; (void)arg; (void)out; (void)cap; (void)timeout_ms;
    return -1;
}
#endif

int platform_isolated_put(int fd, const void *data, size_t len) {
    const char *p = data;
    while (len) {
        ssize_t k = write(fd, p, len);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return -1;
        p += k;
        len -= (size_t)k;
    }
    return 0;
}
#else
unsigned platform_sandbox(const char *const run[], int n_run, const char *write_only, char *why, size_t cap) {
    (void)run; (void)n_run; (void)write_only;
    copy_str(why, "it's only on Linux", cap);
    return 0;
}

void platform_sandbox_narrow(void) {}

platform_proc_t *platform_spawn_self(const char *name, const char *arg, int *link) {
    (void)name; (void)arg; (void)link;
    return NULL;
}
int platform_parent_link(void) { return -1; }
void platform_set_name(const char *name) { (void)name; }
int platform_link_send(int link, const void *msg, size_t len) { (void)link; (void)msg; (void)len; return -1; }
int platform_link_recv(int link, void *msg, size_t len) { (void)link; (void)msg; (void)len; return -1; }
void platform_link_close(int link) { (void)link; }
long platform_isolated(void (*fn)(void *arg, int fd), void *arg, void *out, size_t cap, int timeout_ms) {
    (void)fn; (void)arg; (void)out; (void)cap; (void)timeout_ms;
    return -1;
}
int platform_isolated_put(int fd, const void *data, size_t len) { (void)fd; (void)data; (void)len; return -1; }
#endif
