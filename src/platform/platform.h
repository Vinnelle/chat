// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_PLATFORM_H
#define CHAT_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include "platform/net.h"
#include "common/util.h"

// Called first. Other programs, even ones running as this user, can't read chat's memory or
// attach to it, and it's never dumped. The variables named in secret_env (passwords) leave the
// environment straight away, so the programs chat runs never inherit them; platform_env_take
// hands each one out once.
void platform_harden_process(const char *const secret_env[]);

int platform_env_take(const char *name, char *out, size_t outlen);

// Blanks the arguments where other programs read a process's command line (ps, /proc, Task
// Manager), so a session id, peer or save named there doesn't stay readable. argv's strings are
// wiped: copy them first.
void platform_hide_args(int argc, char **argv);

int term_is_tty(void);
int term_stdout_is_tty(void);

int term_ansi_ok(void);

void platform_notify(const char *title, const char *body);

void platform_notify_shutdown(void);

int term_read_line(const char *prompt, char *out, size_t outlen);

int term_read_password(const char *prompt, char *out, size_t outlen);

typedef struct stdin_reader stdin_reader_t;
stdin_reader_t *stdin_reader_start(void);
void stdin_reader_stop(stdin_reader_t *r);

int stdin_reader_poll(stdin_reader_t *r, char *line, size_t linelen);

int term_raw_enable(void);
void term_raw_disable(void);

long term_read_raw(uint8_t *buf, size_t cap);

void platform_write_stdout(const char *buf, size_t len);

void term_get_size(int *rows, int *cols);

void term_watch_resize(void);

int term_resized(void);

#define PLATFORM_WAIT_MAX 128
void platform_wait(const sock_t *socks, int n, int *ready, int *stdin_ready, int timeout_ms);

typedef void (*dir_entry_cb)(void *ctx, const char *name, int is_dir);
int platform_list_dir(const char *path, dir_entry_cb cb, void *ctx);

// What the file browser shows about an entry. A link is followed, and is_link says it was one.
// mode is the POSIX permission bits, or -1 on Windows. Returns -1 if there's nothing at path.
typedef struct {
    int is_dir, is_link;
    uint64_t size;
    char modified[STAMP_LEN];   // when it was last changed, local time: "YYYY-MM-DD HH:MM"
    int mode;
} file_info_t;
int platform_file_info(const char *utf8_path, file_info_t *out);

const char *platform_home_dir(void);

// This OS install's machine id, as text: /etc/machine-id on Linux, MachineGuid on Windows. The
// OS creates it on install and keeps it until it's reinstalled. It isn't secret, since any
// program on the machine can read it. Returns -1 if there isn't one.
int platform_machine_id(char *out, size_t cap);

// A secret sealed to this device, for a save locked to it. Ids like the machine id are no use for
// that, since anything that can read the files can read them too: the device has to hold a key it
// never lets out. On Linux that's systemd's credential service (systemd 256 or later), which seals
// it with this computer's TPM 2.0 and systemd's own key (only root can read it), for this user
// only. On Windows it's an RSA key the TPM makes for it and never lets out. Without a TPM it's
// systemd's key alone, or DPAPI on Windows. The sealed form is kept with the save, and nothing
// anywhere else can unseal it.
#define DEVICE_SECRET_LEN 32
#define DEVICE_SEALED_MAX 8192
typedef enum { DEVICE_NONE, DEVICE_TPM, DEVICE_OS } device_kind_t;
// What sealing would use here, checked without sealing anything. For DEVICE_NONE, why says what's
// missing.
device_kind_t platform_device_kind(char *why, size_t why_cap);
// What a sealed form uses: DEVICE_NONE if it isn't one this system makes.
device_kind_t platform_device_sealed_kind(const uint8_t *sealed, size_t len);
// What a kind uses here, for the box that turns the lock on.
const char *platform_device_uses(device_kind_t kind);
// What wipes what this device keeps for a save locked this way, and with it the save, for good:
// up to max short phrases for a list ("the TPM is cleared: ..."). Returns how many.
#define DEVICE_LOSSES_MAX 6
int platform_device_losses(device_kind_t kind, const char **out, int max);
// Seals secret, then unseals it again to be sure it comes back. Returns the sealed form's length,
// or -1 with why set.
long platform_device_seal(const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why, size_t why_cap);
// 0, or -1 with why set.
int platform_device_unseal(const uint8_t *sealed, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap);
// Destroys what this device keeps for it (on Windows, its TPM key), so it can't be unsealed again.
void platform_device_forget(const uint8_t *sealed, size_t len);

// A FIDO2 security key, for a save that needs one. Its credential's secret never leaves it: after a
// touch, it gives back an HMAC of a salt (CTAP's hmac-secret). These wait for a key to be plugged in
// and then touched, for up to SECKEY_WAIT_S, so they run on a thread of their own: w->stage says
// what they're waiting for, and setting w->cancel stops them. On Linux chat speaks CTAP itself, over
// /dev/hidraw; on Windows it asks Windows (webauthn.dll), whose own window takes the PIN and touch.
#define SECKEY_CRED_MAX 1024
#define SECKEY_SALT_LEN 32
#define SECKEY_SECRET_LEN 32
#define SECKEY_PIN -2         // it needs its PIN, or the one given is wrong
#define SECKEY_NO_CRED -3     // the security key plugged in isn't one the credentials are on
#define SECKEY_CANCELLED -4
#define SECKEY_WAIT_S 60
typedef enum { SECKEY_LOOKING, SECKEY_BUSY, SECKEY_TOUCH } seckey_stage_t;
typedef struct {
    int cancel;    // set by the caller, read with __atomic builtins
    int stage;     // seckey_stage_t, set as it goes
    int touches;   // touches it has had
} seckey_wait_t;
// 0 if security keys can be used here, or -1 with why.
int platform_seckey_usable(char *why, size_t why_cap);
// A credential the security key keeps nothing of, then its secret for salt: two touches. uv gets
// whether the secret needed the PIN, as it will each time. 0, SECKEY_PIN, SECKEY_CANCELLED or -1,
// with why set.
int platform_seckey_make(const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t cred[SECKEY_CRED_MAX],
                         size_t *cred_len, int *uv, uint8_t secret[SECKEY_SECRET_LEN], seckey_wait_t *w, char *why,
                         size_t why_cap);
// The secret for salt from whichever of the credentials the security key plugged in has: a touch.
// uv, for each, as platform_seckey_make gave it. Returns that credential's index, or SECKEY_PIN,
// SECKEY_NO_CRED, SECKEY_CANCELLED or -1, with why set.
int platform_seckey_secret(const uint8_t *const *creds, const size_t *lens, const int *uv, int n,
                           const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t secret[SECKEY_SECRET_LEN],
                           seckey_wait_t *w, char *why, size_t why_cap);

int platform_spawn_thread(void (*fn)(void *), void *arg);

#include <stdio.h>
FILE *platform_fopen(const char *utf8_path, const char *mode);

FILE *platform_fopen_private(const char *utf8_path, const char *mode);

// Reads up to cap bytes of a regular file without blocking. A FIFO, a device or a folder is
// refused, since a path picked in the key browser or given by a Tor control port could be one
// (and a FIFO would hang chat). Returns the bytes read, or -1.
long platform_read_file(const char *utf8_path, void *buf, size_t cap);

int platform_remove(const char *utf8_path);

// path as a full path, taken from the current folder if it's relative. Links aren't followed, so a
// path saved from it keeps pointing where the user said. Returns -1 if it doesn't fit.
int platform_full_path(const char *utf8_path, char *out, size_t cap);

// For sending a file. Opens it for reading only if it's a regular file (never a FIFO, device or
// folder, which could hang chat or never end), with its size in *size. NULL if not.
FILE *platform_open_regular(const char *utf8_path, uint64_t *size);
// The user's Downloads folder. Created if it doesn't exist, and then only this user can open it.
int platform_downloads_dir(char *out, size_t cap);
// Creates a new file only this user can read, and only if nothing (not even a link) has that name.
FILE *platform_create_new(const char *utf8_path);
// Renames a finished download to its real name, only if nothing has that name. Never replaces a file.
int platform_move_new(const char *from, const char *to);
// $XDG_CONFIG_HOME/chat, otherwise ~/.config/chat, or %LOCALAPPDATA%\chat on Windows. With create,
// it's created if it doesn't exist, and only this user can open it.
int platform_config_dir(char *out, size_t cap, int create);
// Creates a folder only this user can open, if it doesn't exist. -1 if it can't, or if what's
// there is a link or isn't this user's folder.
int platform_private_dir(const char *utf8_path);
// Written to a private file next to path, flushed, then renamed over it, so a crash leaves either
// the old file or the new one.
int platform_write_private(const char *utf8_path, const void *data, size_t len);

int platform_exe_path(char *out, size_t cap);

int platform_run_quiet(const char *const argv[]);

int platform_replace_exe(const char *new_path, const char *exe_path);

// Finds a program: path itself if given (not empty), otherwise name on PATH (absolute entries
// only) and the usual install folders. It has to be a regular executable that only its owner
// (root or this user) can change. Writes the full path, or returns -1 if there isn't one.
int platform_find_program(const char *name, const char *path, char *out, size_t cap);

// Creates a new folder only this user can open, in the per-user runtime folder (kept in memory on
// most Linux systems) or the temp folder. Writes its path.
int platform_private_tempdir(const char *prefix, char *out, size_t cap);
// Deletes a folder and everything in it, never following links out of it.
int platform_remove_tree(const char *path);
// Deletes this user's platform_private_tempdir(prefix) folders left behind by a crash: those older
// than a minute, where lock_rel inside isn't held by a running program.
void platform_remove_stale_tempdirs(const char *prefix, const char *lock_rel);

// Starts a background process. argv[0] is a full path and is never searched for. It gets no
// terminal and none of our handles, and on Windows it ends with this process. Its output goes to
// out_path (a new file only this user can read), or nowhere if that's NULL.
typedef struct platform_proc platform_proc_t;
platform_proc_t *platform_spawn(const char *const argv[], const char *out_path);
// 1 once it has exited (its code in *code), 0 while it runs.
int platform_proc_exited(platform_proc_t *p, int *code);
// Asks it to stop, waits up to wait_ms, then kills it, and frees p.
void platform_proc_stop(platform_proc_t *p, int wait_ms);
long platform_pid(void);
void platform_sleep_ms(int ms);

// The IPv4 default gateway. Returns -1 when there is none.
int platform_default_gateway(uint8_t ip[IP4_LEN]);

// Passes the system's trusted root certificates to one of the callbacks: add_der for each
// certificate in a store, add_file for a PEM bundle (it returns 0 once one loads).
void platform_ca_roots(void (*add_der)(void *ctx, const uint8_t *der, size_t len),
                       int (*add_file)(void *ctx, const char *path), void *ctx);

#endif
