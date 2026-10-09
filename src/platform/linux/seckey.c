// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#define _POSIX_C_SOURCE 200809L

#include "platform/platform.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include "ctap2.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <poll.h>
#include <unistd.h>

// A security key is a HID device whose report descriptor has the FIDO Alliance's usage page, and
// /dev/hidrawN reads and writes its 64-byte reports. udev opens them to the user at the screen
// (systemd's uaccess rule for FIDO tokens, or libfido2's), with no group to join. CTAPHID frames
// each message: a channel from INIT, then the message cut into reports.
#define HIDRAW_SYS "/sys/class/hidraw"
#define REPORT 64
#define HID_INIT 0x86
#define HID_CBOR 0x90
#define HID_CANCEL 0x91
#define HID_KEEPALIVE 0xbb
#define HID_ERROR 0xbf
#define CAP_CBOR 0x04
#define BROADCAST 0xffffffffu
#define KEEPALIVE_TOUCH 2
#define MAX_KEYS 8
// A message's first report: the channel, the command, the message's length, then data. The rest:
// the channel, a sequence number from 0 to SEQ_MAX, then data. INIT's answer has the nonce sent,
// the new channel and the device's capabilities.
#define CMD_AT 4
#define BCNT_AT 5
#define INIT_HEAD 7
#define CONT_HEAD 5
#define SEQ_MAX 127
#define INIT_NONCE_LEN 8
#define INIT_CID_AT 15
#define INIT_CAPS_AT 23
// Report descriptors: a long item, and a short one's type and tag (usage page, usage).
#define HID_LONG_ITEM 0xfe
enum { ITEM_GLOBAL = 1, ITEM_LOCAL = 2, TAG_USAGE_PAGE = 0, TAG_USAGE = 0 };
#define FIDO_USAGE_PAGE 0xf1d0
#define FIDO_USAGE_CTAPHID 1
#define DEV_PATH_MAX 32
#define HIDRAW_NAME_MAX 16
#define DESCRIPTOR_MAX 4096
#define POLL_MS 100
#define CONT_TIMEOUT_MS 1000
#define INIT_POLL_MS 200
#define INIT_WAIT 2.0
#define LOOK_EVERY_MS 250

_Static_assert(CTAP2_CRED_MAX == SECKEY_CRED_MAX && CTAP2_SECRET_LEN == SECKEY_SECRET_LEN
               && CTAP2_SALT_LEN == SECKEY_SALT_LEN, "the platform's sizes are CTAP's");

typedef struct {
    int fd;
    uint32_t cid;
    seckey_wait_t *w;
    double give_up;
} hid_t;

static int cancelled(const seckey_wait_t *w) { return __atomic_load_n(&w->cancel, __ATOMIC_ACQUIRE) != 0; }
static void set_stage(seckey_wait_t *w, int stage) { __atomic_store_n(&w->stage, stage, __ATOMIC_RELEASE); }

// The FIDO usage page (0xf1d0) with usage 1, CTAPHID.
static int is_fido(const uint8_t *d, size_t n) {
    uint32_t page = 0;
    for (size_t i = 0; i < n;) {
        uint8_t b = d[i];
        if (b == HID_LONG_ITEM) {
            if (i + 1 >= n) return 0;
            i += 3 + (size_t)d[i + 1];
            continue;
        }
        size_t sz = (b & 3) == 3 ? 4 : (size_t)(b & 3);
        if (i + 1 + sz > n) return 0;
        uint32_t v = 0;
        for (size_t k = 0; k < sz; k++) v |= (uint32_t)d[i + 1 + k] << (8 * k);
        int type = (b >> 2) & 3, tag = b >> 4;
        if (type == ITEM_GLOBAL && tag == TAG_USAGE_PAGE) {
            page = v;
        } else if (type == ITEM_LOCAL && tag == TAG_USAGE) {
            // A 4-byte usage carries its own page in the high half.
            uint32_t pg = sz == 4 ? v >> 16 : page, usage = sz == 4 ? v & 0xffff : v;
            if (pg == FIDO_USAGE_PAGE && usage == FIDO_USAGE_CTAPHID) return 1;
        }
        i += 1 + sz;
    }
    return 0;
}

static int list_keys(char paths[MAX_KEYS][DEV_PATH_MAX]) {
    DIR *d = opendir(HIDRAW_SYS);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < MAX_KEYS) {
        if (!starts_with(e->d_name, "hidraw") || strlen(e->d_name) > HIDRAW_NAME_MAX) continue;
        char path[96];
        uint8_t desc[DESCRIPTOR_MAX];
        snprintf(path, sizeof path, HIDRAW_SYS "/%.16s/device/report_descriptor", e->d_name);
        long len = platform_read_file(path, desc, sizeof desc);
        if (len > 0 && is_fido(desc, (size_t)len)) snprintf(paths[n++], DEV_PATH_MAX, "/dev/%.16s", e->d_name);
    }
    closedir(d);
    return n;
}


static int hid_write(hid_t *h, const uint8_t pkt[REPORT]) {
    uint8_t buf[REPORT + 1];
    buf[0] = 0;   // FIDO devices have no report ids
    memcpy(buf + 1, pkt, REPORT);
    ssize_t n;
    do n = write(h->fd, buf, sizeof buf); while (n < 0 && errno == EINTR);
    return n == (ssize_t)sizeof buf ? 0 : -1;
}

// 1 with a report, 0 if none came within ms, -1 if the device went away.
static int hid_read(hid_t *h, uint8_t pkt[REPORT], int ms) {
    struct pollfd p = { h->fd, POLLIN, 0 };
    int r;
    do r = poll(&p, 1, ms); while (r < 0 && errno == EINTR);
    if (r < 0 || (r > 0 && (p.revents & (POLLERR | POLLHUP | POLLNVAL)))) return -1;
    if (r == 0) return 0;
    ssize_t n;
    do n = read(h->fd, pkt, REPORT); while (n < 0 && errno == EINTR);
    return n == REPORT ? 1 : -1;
}

static int hid_send(hid_t *h, uint8_t cmd, const uint8_t *data, size_t len) {
    uint8_t pkt[REPORT];
    memset(pkt, 0, sizeof pkt);
    store_be32(pkt, h->cid);
    pkt[CMD_AT] = cmd;
    store_be16(pkt + BCNT_AT, (uint16_t)len);
    size_t n = len < REPORT - INIT_HEAD ? len : REPORT - INIT_HEAD, off = n;
    memcpy(pkt + INIT_HEAD, data, n);
    int rc = hid_write(h, pkt);
    for (int seq = 0; rc == 0 && off < len; seq++) {
        if (seq > SEQ_MAX) { rc = -1; break; }
        memset(pkt, 0, sizeof pkt);
        store_be32(pkt, h->cid);
        pkt[CMD_AT] = (uint8_t)seq;
        n = len - off < REPORT - CONT_HEAD ? len - off : REPORT - CONT_HEAD;
        memcpy(pkt + CONT_HEAD, data + off, n);
        off += n;
        rc = hid_write(h, pkt);
    }
    crypto_wipe(pkt, sizeof pkt);
    return rc;
}

// The answer to cmd: its length, or a CTAP2_ code with why set. Keepalives say whether it's waiting
// for a touch. Cancelling sends CTAPHID_CANCEL, which the key answers by giving up the request.
static long hid_recv(hid_t *h, uint8_t cmd, uint8_t *out, size_t cap, char *why, size_t why_cap) {
    uint8_t pkt[REPORT];
    for (;;) {
        if (cancelled(h->w)) {
            uint8_t c[REPORT] = { 0 };
            store_be32(c, h->cid);
            c[CMD_AT] = HID_CANCEL;
            hid_write(h, c);
            return CTAP2_CANCELLED;
        }
        if (now_seconds() > h->give_up) {
            snprintf(why, why_cap, "the security key didn't answer in time");
            return CTAP2_IO;
        }
        int r = hid_read(h, pkt, POLL_MS);
        if (r < 0) {
            snprintf(why, why_cap, "the security key was unplugged");
            return CTAP2_IO;
        }
        if (r == 0 || load_be32(pkt) != h->cid) continue;
        if (pkt[CMD_AT] == HID_KEEPALIVE) {
            set_stage(h->w, pkt[INIT_HEAD] == KEEPALIVE_TOUCH ? SECKEY_TOUCH : SECKEY_BUSY);
            continue;
        }
        if (pkt[CMD_AT] == HID_ERROR) {
            snprintf(why, why_cap, "the security key's HID error 0x%02x", pkt[INIT_HEAD]);
            return CTAP2_IO;
        }
        if (pkt[CMD_AT] != cmd) continue;
        set_stage(h->w, SECKEY_BUSY);
        size_t len = load_be16(pkt + BCNT_AT);
        if (len > cap) {
            snprintf(why, why_cap, "the security key's answer is too long");
            return CTAP2_IO;
        }
        size_t n = len < REPORT - INIT_HEAD ? len : REPORT - INIT_HEAD, off = n;
        memcpy(out, pkt + INIT_HEAD, n);
        for (int seq = 0; off < len; seq++) {
            do r = hid_read(h, pkt, CONT_TIMEOUT_MS); while (r > 0 && load_be32(pkt) != h->cid);
            if (r <= 0 || pkt[CMD_AT] != seq) {
                snprintf(why, why_cap, "the security key's answer was cut short");
                return CTAP2_IO;
            }
            n = len - off < REPORT - CONT_HEAD ? len - off : REPORT - CONT_HEAD;
            memcpy(out + off, pkt + CONT_HEAD, n);
            off += n;
        }
        crypto_wipe(pkt, sizeof pkt);
        return (long)len;
    }
}

static long ctap_io(void *ctx, const uint8_t *msg, size_t len, uint8_t *rsp, size_t cap, char *why, size_t why_cap) {
    hid_t *h = ctx;
    if (hid_send(h, HID_CBOR, msg, len) != 0) {
        snprintf(why, why_cap, "couldn't write to the security key");
        return CTAP2_IO;
    }
    return hid_recv(h, HID_CBOR, rsp, cap, why, why_cap);
}

// Opens the security key and gets a channel of its own on it. 0, or -1 with why.
static int hid_open(hid_t *h, const char *path, seckey_wait_t *w, char *why, size_t why_cap) {
    h->w = w;
    h->fd = open(path, O_RDWR | O_CLOEXEC);
    if (h->fd < 0) {
        if (errno == EACCES || errno == EPERM)
            snprintf(why, why_cap, "%s, the security key, isn't open to you: a udev rule (systemd's for FIDO tokens, or "
                     "libfido2's 70-u2f.rules) opens security keys to whoever's at the screen", path);
        else
            snprintf(why, why_cap, "can't open the security key (%s)", strerror(errno));
        return -1;
    }
    uint8_t nonce[INIT_NONCE_LEN], pkt[REPORT];
    gen_random(nonce, sizeof nonce);
    h->cid = BROADCAST;
    if (hid_send(h, HID_INIT, nonce, sizeof nonce) == 0) {
        double until = now_seconds() + INIT_WAIT;
        while (now_seconds() < until) {
            int r = hid_read(h, pkt, INIT_POLL_MS);
            if (r < 0) break;
            if (r == 0 || load_be32(pkt) != BROADCAST || pkt[CMD_AT] != HID_INIT
                || memcmp(pkt + INIT_HEAD, nonce, sizeof nonce) != 0)
                continue;
            if (!(pkt[INIT_CAPS_AT] & CAP_CBOR)) {
                snprintf(why, why_cap, "it's an old U2F security key, without FIDO2");
                close(h->fd);
                return -1;
            }
            h->cid = load_be32(pkt + INIT_CID_AT);
            return 0;
        }
    }
    snprintf(why, why_cap, "the security key didn't answer");
    close(h->fd);
    return -1;
}

int platform_seckey_usable(char *why, size_t why_cap) {
    DIR *d = opendir(HIDRAW_SYS);
    if (d) { closedir(d); return 0; }
    snprintf(why, why_cap, "this system has no hidraw devices, which chat reads security keys through");
    return -1;
}

// Waits until a security key is plugged in. Returns how many there are, or a negative code.
static int wait_for_keys(char paths[MAX_KEYS][DEV_PATH_MAX], seckey_wait_t *w, double give_up, char *why, size_t why_cap) {
    for (;;) {
        int n = list_keys(paths);
        if (n > 0) return n;
        set_stage(w, SECKEY_LOOKING);
        if (cancelled(w)) return SECKEY_CANCELLED;
        if (now_seconds() > give_up) {
            snprintf(why, why_cap, "no security key was plugged in");
            return -1;
        }
        platform_sleep_ms(LOOK_EVERY_MS);
    }
}

static int code_of(int rc) {
    return rc == CTAP2_PIN ? SECKEY_PIN : rc == CTAP2_NO_CRED ? SECKEY_NO_CRED : rc == CTAP2_CANCELLED ? SECKEY_CANCELLED : -1;
}

int platform_seckey_make(const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t cred[SECKEY_CRED_MAX],
                         size_t *cred_len, int *uv, uint8_t secret[SECKEY_SECRET_LEN], seckey_wait_t *w, char *why,
                         size_t why_cap) {
    char paths[MAX_KEYS][DEV_PATH_MAX];
    double give_up = now_seconds() + SECKEY_WAIT_S;
    int n = wait_for_keys(paths, w, give_up, why, why_cap);
    if (n < 0) return n;
    if (n > 1) {
        snprintf(why, why_cap, "more than one security key is plugged in: unplug all but the one to register");
        return -1;
    }
    hid_t h = { .give_up = give_up };
    if (hid_open(&h, paths[0], w, why, why_cap) != 0) return -1;
    set_stage(w, SECKEY_BUSY);
    ctap2_info_t info;
    int rc = ctap2_get_info(ctap_io, &h, &info, why, why_cap);
    // The secret needs the PIN only where the key needs it for everything: one with the PIN is a
    // different secret, so it has to be the same choice each time.
    *uv = info.always_uv;
    if (rc == 0) rc = ctap2_make(ctap_io, &h, &info, pin, cred, cred_len, why, why_cap);
    if (rc == 0) {
        __atomic_add_fetch(&w->touches, 1, __ATOMIC_RELEASE);
        const uint8_t *creds[1] = { cred };
        int which;
        rc = ctap2_secret(ctap_io, &h, &info, creds, cred_len, 1, salt, *uv, pin, secret, &which, why, why_cap);
        if (rc == 0) __atomic_add_fetch(&w->touches, 1, __ATOMIC_RELEASE);
    }
    close(h.fd);
    return rc == 0 ? 0 : code_of(rc);
}

int platform_seckey_secret(const uint8_t *const *creds, const size_t *lens, const int *uv, int n,
                           const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t secret[SECKEY_SECRET_LEN],
                           seckey_wait_t *w, char *why, size_t why_cap) {
    char paths[MAX_KEYS][DEV_PATH_MAX];
    double give_up = now_seconds() + SECKEY_WAIT_S;
    int keys = wait_for_keys(paths, w, give_up, why, why_cap);
    if (keys < 0) return keys;
    set_stage(w, SECKEY_BUSY);
    // Asked without a touch first, so only the security key that has one of the credentials blinks.
    // A key that can't say without a touch is tried after, one credential at a time.
    int rc = CTAP2_NO_CRED;
    snprintf(why, why_cap, "the security key plugged in isn't one the save was locked with");
    for (int pass = 0; pass < 2 && rc == CTAP2_NO_CRED; pass++)
        for (int k = 0; k < keys && rc == CTAP2_NO_CRED; k++) {
            hid_t h = { .give_up = give_up };
            ctap2_info_t info;
            char err[200];
            if (hid_open(&h, paths[k], w, err, sizeof err) != 0) {
                if (keys == 1) { copy_str(why, err, why_cap); rc = CTAP2_IO; }
                continue;
            }
            if (ctap2_get_info(ctap_io, &h, &info, err, sizeof err) != 0) {
                close(h.fd);
                if (keys == 1) { copy_str(why, err, why_cap); rc = CTAP2_IO; }
                continue;
            }
            int which = -1, has = ctap2_probe(ctap_io, &h, creds, lens, n, &which, err, sizeof err);
            if ((has == 1 && pass == 0) || (has < 0 && pass == 1)) {
                int first = has == 1 ? which : 0, last = has == 1 ? which : n - 1;
                for (int c = first; c <= last; c++) {
                    const uint8_t *one[1] = { creds[c] };
                    size_t one_len[1] = { lens[c] };
                    int got;
                    rc = ctap2_secret(ctap_io, &h, &info, one, one_len, 1, salt, uv[c], pin, secret, &got, why, why_cap);
                    if (rc == 0) {
                        close(h.fd);
                        __atomic_add_fetch(&w->touches, 1, __ATOMIC_RELEASE);
                        return c;
                    }
                    if (rc != CTAP2_NO_CRED) break;
                }
            }
            close(h.fd);
            if (cancelled(w)) return SECKEY_CANCELLED;
        }
    return code_of(rc);
}
