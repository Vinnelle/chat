// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#define _POSIX_C_SOURCE 200809L

#include "platform/platform.h"
#include "common/json.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include "tpm2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/un.h>

// systemd's credential service runs as root, so it can use the TPM for users who can't open
// /dev/tpmrm0 (only the tss group can, on most systems). A user-scoped credential also takes in
// this user's id and name and the machine id, and the service only unseals it for that user. It
// binds to no PCRs (unless a UKI's signed PCR key is installed, which systemd then adds), so
// firmware and kernel updates don't lose it, and since systemd 262 it pins the TPM's storage key,
// so a chip spliced onto the bus can't pose as the TPM. Without the service
// (runit, OpenRC, s6, systemd before 256), chat speaks to the TPM itself: see tpm2.h.
#define CREDS_SOCKET "/run/systemd/io.systemd.Credentials"
#define CRED_NAME "chat-save"
// The sealed form: this, 'T' (TPM and systemd's key) or 'H' (systemd's key), then the credential
// in base64, as systemd gave it.
#define SEALED_MAGIC "SYSD"
#define SEALED_HEAD 5
#define REQUEST_MAX (DEVICE_SEALED_MAX + 512)
#define REPLY_MAX 65536
// The first call starts the service, and some TPMs are slow.
#define CALL_TIMEOUT_MS 60000
#define NO_SERVICE "there's no systemd credential service (systemd 256 or later has one)"
#define TPM_DEVICE "/dev/tpmrm0"
// The sealed form when chat speaks to the TPM itself: this, then tpm2_seal's.
#define DIRECT_MAGIC "TPMD"

_Static_assert(TPM2_SECRET_LEN == DEVICE_SECRET_LEN, "the TPM seals the device's secret");

static char g_request[REQUEST_MAX], g_reply[REPLY_MAX];
static js_arena g_arena;

static int have_service(void) {
    struct stat st;
    return stat(CREDS_SOCKET, &st) == 0 && S_ISSOCK(st.st_mode);
}

// systemd makes a machine id for each boot when /etc can't keep one: it mounts one from /run over
// /etc/machine-id, or all of /etc is in memory. Unless it's told the same one each time, the id is
// new after a restart, and so is the key of everything sealed for this user.
static int machine_id_transient(void) {
    struct stat id, etc;
    struct statfs fs;
    if (stat("/etc/machine-id", &id) != 0 || stat("/etc", &etc) != 0) return 0;
    if (id.st_dev != etc.st_dev) return 1;
    return statfs("/etc/machine-id", &fs) == 0 && (unsigned long)fs.f_type == 0x01021994UL;   // tmpfs
}

// The kernel's resource manager is only there for a TPM 2.0.
static int have_tpm2(void) {
    struct stat st;
    return stat("/sys/class/tpmrm/tpmrm0", &st) == 0;
}

typedef enum { M_NONE, M_SYSTEMD_TPM, M_SYSTEMD_HOST, M_DIRECT } mechanism_t;

// Why the TPM can't be opened, and what would fix that.
static void tpm_closed(char *why, size_t why_cap) {
    struct stat st;
    if (stat(TPM_DEVICE, &st) != 0) {
        snprintf(why, why_cap, have_tpm2() ? "the TPM's device, " TPM_DEVICE ", is missing"
                                           : "there's no TPM 2.0 here, and " NO_SERVICE);
        return;
    }
    const struct group *g = st.st_gid != 0 && (st.st_mode & 060) == 060 ? getgrgid(st.st_gid) : NULL;
    const char *user = getenv("USER");
    if (g)
        snprintf(why, why_cap, TPM_DEVICE ", the TPM, is only open to the %s group: join it (as root, usermod -aG %s %s) "
                 "and log in again", g->gr_name, g->gr_name, user && user[0] ? user : "YOU");
    else
        snprintf(why, why_cap, TPM_DEVICE ", the TPM, is only open to root here: tpm2-tss's udev rule opens it to the "
                 "tss group, which you can then join");
}

// systemd's service where it's open to this user, since it adds systemd's own key and the user's id
// and needs no tss group. Without it, the TPM itself. Checked without connecting to the service,
// since each connection starts it, and the journal says so.
static mechanism_t mechanism(char *why, size_t why_cap) {
    if (have_service() && access(CREDS_SOCKET, W_OK) == 0) return have_tpm2() ? M_SYSTEMD_TPM : M_SYSTEMD_HOST;
    if (access(TPM_DEVICE, R_OK | W_OK) == 0) return M_DIRECT;
    tpm_closed(why, why_cap);
    return M_NONE;
}

device_kind_t platform_device_kind(char *why, size_t why_cap) {
    switch (mechanism(why, why_cap)) {
        case M_SYSTEMD_TPM:
        case M_DIRECT:       return DEVICE_TPM;
        case M_SYSTEMD_HOST: return DEVICE_OS;
        default:             return DEVICE_NONE;
    }
}

device_kind_t platform_device_sealed_kind(const uint8_t *sealed, size_t len) {
    if (len > 4 && memcmp(sealed, DIRECT_MAGIC, 4) == 0) return DEVICE_TPM;
    if (len <= SEALED_HEAD || memcmp(sealed, SEALED_MAGIC, 4) != 0) return DEVICE_NONE;
    return sealed[4] == 'T' ? DEVICE_TPM : sealed[4] == 'H' ? DEVICE_OS : DEVICE_NONE;
}

// What sealing here would use: the kind alone doesn't say whether systemd's service is there.
const char *platform_device_uses(device_kind_t kind) {
    char why[200];
    (void)kind;
    switch (mechanism(why, sizeof why)) {
        case M_DIRECT:
            return "this computer's TPM 2.0, which chat speaks to itself (" TPM_DEVICE "), with no systemd "
                   "credential service here: the secret is sealed under a key the TPM never lets out, and crosses the "
                   "TPM's bus encrypted";
        case M_SYSTEMD_HOST:
            return "systemd's credential service, with systemd's own key, which only root can read. There's no TPM "
                   "2.0 here, so root, or anyone with a copy of the whole disk, could get past the device part, "
                   "leaving only the passphrase";
        default:
            return "this computer's TPM 2.0, through systemd's credential service: it takes the TPM, systemd's own "
                   "key (only root can read it) and your user id to unseal";
    }
}

int platform_device_losses(device_kind_t kind, const char **out, int max) {
    static const char *const TPM[] = {
        "the TPM is cleared: in the firmware settings, by a tool like tpm2_clear, or by a firmware update (some "
        "BIOS and TPM updates clear it)",
        "the motherboard is replaced, or the CPU where the TPM is part of it (AMD's fTPM), or the firmware "
        "switches to another TPM",
    };
    // The credential takes in systemd's key, the user's name and id, and the machine id.
    static const char *const SYSTEM[] = {
        "the OS is reinstalled, or systemd's key, /var/lib/systemd/credential.secret, is deleted",
        "your user name, your user id or the machine id (/etc/machine-id) changes",
    };
    // Sealed by the TPM alone, the save only needs the TPM: none of systemd's or the OS's parts.
    char why[200];
    mechanism_t m = mechanism(why, sizeof why);
    int n = 0;
    (void)kind;
    if (m != M_DIRECT && machine_id_transient() && n < max)
        out[n++] = "the computer restarts: its machine id is made anew at each boot (/etc/machine-id is kept in "
                   "memory here), so unless it's set to the same one every time, the next restart loses the save";
    for (int i = 0; m != M_SYSTEMD_HOST && i < 2 && n < max; i++) out[n++] = TPM[i];
    for (int i = 0; m != M_DIRECT && i < 2 && n < max; i++) out[n++] = SYSTEM[i];
    return n;
}

// Base64 only, so a damaged or planted file can't add anything to the request around it.
static int blob_ok(const char *s, size_t n) {
    if (n == 0 || n > DEVICE_SEALED_MAX - SEALED_HEAD) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
            return 0;
    }
    return 1;
}

// One varlink call: the request and a NUL, then the reply up to its NUL. Returns the reply's
// length, or -1.
static long creds_call(const char *request, char *reply, size_t cap, char *why, size_t why_cap) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    copy_str(sa.sun_path, CREDS_SOCKET, sizeof sa.sun_path);
    if (fd < 0 || connect(fd, (const struct sockaddr *)&sa, sizeof sa) != 0) {
        snprintf(why, why_cap, "can't reach systemd's credential service (%s)", strerror(errno));
        if (fd >= 0) close(fd);
        return -1;
    }
    size_t len = strlen(request) + 1, sent = 0, n = 0;
    while (sent < len) {
        ssize_t w = send(fd, request + sent, len - sent, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) break;
        sent += (size_t)w;
    }
    int done = 0;
    while (sent == len && !done && n < cap) {
        struct pollfd p = { fd, POLLIN, 0 };
        int r = poll(&p, 1, CALL_TIMEOUT_MS);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        ssize_t got = recv(fd, reply + n, cap - n, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        const char *nul = memchr(reply + n, '\0', (size_t)got);
        n += (size_t)got;
        if (nul) { done = 1; n = (size_t)(nul - reply); }
    }
    close(fd);
    if (!done) {
        snprintf(why, why_cap, sent == len ? "systemd's credential service didn't answer" : "couldn't ask systemd's credential service");
        return -1;
    }
    return (long)n;
}

static void creds_error(const char *err, const js_value *params, int unsealing, char *why, size_t why_cap) {
    const char *errno_name = params ? js_str(js_obj_get(params, "errnoName")) : NULL;
    if (strcmp(err, "org.varlink.service.MethodNotFound") == 0 || strcmp(err, "org.varlink.service.InterfaceNotFound") == 0
        || strcmp(err, "org.varlink.service.InvalidParameter") == 0)
        snprintf(why, why_cap, "this systemd's credential service is too old to seal for one user (systemd 256 or later can)");
    else if (strcmp(err, "io.systemd.Credentials.BadScope") == 0 || strcmp(err, "io.systemd.Credentials.NoSuchUser") == 0)
        snprintf(why, why_cap, "it was sealed for another user");
    else if (strcmp(err, "io.systemd.Credentials.BadFormat") == 0 || strcmp(err, "io.systemd.Credentials.NameMismatch") == 0
             || strcmp(err, "io.systemd.Credentials.NullKeyNotAllowed") == 0)
        snprintf(why, why_cap, "it isn't a credential chat sealed");
    else if (strcmp(err, "org.varlink.service.PermissionDenied") == 0
             || strcmp(err, "io.systemd.InteractiveAuthenticationRequired") == 0)
        snprintf(why, why_cap, "systemd wants an administrator's permission for it");
    else if (unsealing)
        snprintf(why, why_cap, "systemd couldn't unseal it (%.40s): it was sealed on another device, or this one's TPM or "
                 "systemd's key has changed since", errno_name ? errno_name : err);
    else
        snprintf(why, why_cap, "systemd couldn't seal it (%.40s)", errno_name ? errno_name : err);
}

// The reply's parameters, or NULL with why set.
static const js_value *creds_reply(const char *reply, size_t len, js_arena *arena, int unsealing, char *why, size_t why_cap) {
    const js_value *root = js_parse(reply, len, arena);
    if (!root || root->type != JS_OBJ) {
        snprintf(why, why_cap, "systemd's credential service gave an answer chat can't read");
        return NULL;
    }
    const js_value *params = js_obj_get(root, "parameters");
    const char *err = js_str(js_obj_get(root, "error"));
    if (err) {
        creds_error(err, params && params->type == JS_OBJ ? params : NULL, unsealing, why, why_cap);
        return NULL;
    }
    if (!params || params->type != JS_OBJ) {
        snprintf(why, why_cap, "systemd's credential service gave an answer chat can't read");
        return NULL;
    }
    return params;
}

static int systemd_unseal(const uint8_t *sealed, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap) {
    if (len <= SEALED_HEAD || memcmp(sealed, SEALED_MAGIC, 4) != 0
        || !blob_ok((const char *)sealed + SEALED_HEAD, len - SEALED_HEAD)) {
        snprintf(why, why_cap, "it isn't sealed in a way chat on Linux knows");
        return -1;
    }
    if (!have_service()) {
        snprintf(why, why_cap, NO_SERVICE);
        return -1;
    }
    // Only a credential sealed for this user, and never one sealed with no key at all.
    snprintf(g_request, sizeof g_request, "{\"method\":\"io.systemd.Credentials.Decrypt\",\"parameters\":{\"name\":\"" CRED_NAME
             "\",\"blob\":\"%.*s\",\"scope\":\"user\",\"allowNull\":false}}", (int)(len - SEALED_HEAD),
             (const char *)sealed + SEALED_HEAD);
    long got = creds_call(g_request, g_reply, sizeof g_reply, why, why_cap);
    int rc = -1;
    const js_value *p = got >= 0 ? creds_reply(g_reply, (size_t)got, &g_arena, 1, why, why_cap) : NULL;
    if (p) {
        const js_value *data = js_obj_get(p, "data");
        if (data && data->type == JS_STR && base64_decode_strict(data->s, data->slen, secret, DEVICE_SECRET_LEN) == DEVICE_SECRET_LEN)
            rc = 0;
        else
            snprintf(why, why_cap, "systemd unsealed something that isn't chat's");
    }
    if (rc != 0) crypto_wipe(secret, DEVICE_SECRET_LEN);
    crypto_wipe(&g_arena, sizeof g_arena);
    crypto_wipe(g_reply, sizeof g_reply);
    return rc;
}

static long systemd_seal(int tpm, const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why,
                         size_t why_cap) {
    char data[64];
    base64_encode(secret, DEVICE_SECRET_LEN, data);
    // No withKey: given one, even "auto", systemd 262 seals for the whole system whatever the scope, and
    // unsealing for this user then fails with BadScope. Left to itself, a user-scoped credential takes
    // systemd's own key, and the TPM where systemd can use one.
    snprintf(g_request, sizeof g_request, "{\"method\":\"io.systemd.Credentials.Encrypt\",\"parameters\":{\"name\":\"" CRED_NAME
             "\",\"data\":\"%s\",\"scope\":\"user\"}}", data);
    crypto_wipe(data, sizeof data);
    long got = creds_call(g_request, g_reply, sizeof g_reply, why, why_cap);
    crypto_wipe(g_request, sizeof g_request);
    long len = -1;
    const js_value *p = got >= 0 ? creds_reply(g_reply, (size_t)got, &g_arena, 0, why, why_cap) : NULL;
    if (p) {
        const js_value *blob = js_obj_get(p, "blob");
        if (!blob || blob->type != JS_STR || !blob_ok(blob->s, blob->slen) || SEALED_HEAD + blob->slen > cap) {
            snprintf(why, why_cap, "systemd's credential service gave back something chat can't keep");
        } else {
            memcpy(out, SEALED_MAGIC, 4);
            out[4] = tpm ? 'T' : 'H';
            memcpy(out + SEALED_HEAD, blob->s, blob->slen);
            len = (long)(SEALED_HEAD + blob->slen);
        }
    }
    crypto_wipe(&g_arena, sizeof g_arena);
    crypto_wipe(g_reply, sizeof g_reply);
    return len;
}

static long tpm_io(void *ctx, const uint8_t *cmd, size_t len, uint8_t *rsp, size_t cap) {
    int fd = *(const int *)ctx;
    ssize_t n;
    do n = write(fd, cmd, len); while (n < 0 && errno == EINTR);
    if (n != (ssize_t)len) return -1;
    do n = read(fd, rsp, cap); while (n < 0 && errno == EINTR);
    return (long)n;
}

static long direct_seal(const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why, size_t why_cap) {
    int fd = open(TPM_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0) { tpm_closed(why, why_cap); return -1; }
    long n = cap > 4 ? tpm2_seal(tpm_io, &fd, secret, out + 4, cap - 4, why, why_cap) : -1;
    close(fd);
    if (n < 0) return -1;
    memcpy(out, DIRECT_MAGIC, 4);
    return n + 4;
}

static int direct_unseal(const uint8_t *sealed, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap) {
    int fd = open(TPM_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0) { tpm_closed(why, why_cap); return -1; }
    int rc = tpm2_unseal(tpm_io, &fd, sealed + 4, len - 4, secret, why, why_cap);
    close(fd);
    return rc;
}

int platform_device_unseal(const uint8_t *sealed, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap) {
    if (len > 4 && memcmp(sealed, DIRECT_MAGIC, 4) == 0) return direct_unseal(sealed, len, secret, why, why_cap);
    return systemd_unseal(sealed, len, secret, why, why_cap);
}

long platform_device_seal(const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why, size_t why_cap) {
    mechanism_t m = mechanism(why, why_cap);
    long len = m == M_NONE ? -1
             : m == M_DIRECT ? direct_seal(secret, out, cap, why, why_cap)
             : systemd_seal(m == M_SYSTEMD_TPM, secret, out, cap, why, why_cap);
    if (len < 0) return -1;
    uint8_t back[DEVICE_SECRET_LEN];
    int rc = platform_device_unseal(out, (size_t)len, back, why, why_cap);
    int same = rc == 0 && crypto_equal(back, secret, DEVICE_SECRET_LEN) == 0;
    crypto_wipe(back, sizeof back);
    if (rc == 0 && !same) snprintf(why, why_cap, "unsealing gave back something other than what was sealed");
    return same ? len : -1;
}

void platform_device_forget(const uint8_t *sealed, size_t len) {
    // Nothing is kept for one save, by systemd or the TPM: the sealed form is all there is.
    (void)sealed;
    (void)len;
}
