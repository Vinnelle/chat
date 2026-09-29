// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/update.h"
#include "core/chat.h"
#include "platform/platform.h"
#include "common/util.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef CHAT_VERSION
#define CHAT_VERSION "0.0.0"
#endif

#define UPDATE_REPO "Vinnelle/chat"
#define UPDATE_MAX_BYTES "67108864"

#if defined(__x86_64__) || defined(_M_X64)
#define UPDATE_ARCH "x86_64"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define UPDATE_ARCH "aarch64"
#endif

#ifdef UPDATE_ARCH
#ifdef _WIN32
#define UPDATE_ASSET "chat-windows-" UPDATE_ARCH ".exe"
#else
#define UPDATE_ASSET "chat-linux-" UPDATE_ARCH
#endif
#endif

enum { UPD_IDLE = 0, UPD_RUNNING = 1, UPD_DONE = 2 };
static int g_state = UPD_IDLE;
static char g_msg[UPDATE_MSG_MAX];
static int g_ok;

static char g_proxy[64];

void update_set_proxy(const char *socks) { copy_str(g_proxy, socks ? socks : "", sizeof g_proxy); }

// headers_path, if not NULL, gets the response headers, for fetch_missing.
static int fetch(const char *url, const char *out_path, int api, const char *headers_path) {
    // -q must come first: it stops curl reading a .curlrc that could turn off TLS checks or add a proxy.
    // --socks5-hostname leaves name lookups to the proxy, so Tor resolves GitHub, not local DNS.
    const char *argv[24] = {
        "curl", "-q", "-fsL", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
        "--max-time", "300", "--max-filesize", UPDATE_MAX_BYTES,
        "-H", api ? "Accept: application/vnd.github+json" : "Accept: application/octet-stream",
        "-o", out_path, url,
    };
    int n = 0;
    while (argv[n]) n++;
    if (headers_path) { argv[n++] = "-D"; argv[n++] = headers_path; }
    char user[24];
    if (g_proxy[0]) {
        // Made-up SOCKS credentials give each download circuits of its own (Tor isolates by them),
        // so the exit can't tie one download to another, or to chat's own streams.
        uint8_t r[8];
        randombytes_buf(r, sizeof r);
        hex_encode(r, sizeof r, user);
        copy_str(user + 16, ":x", sizeof user - 16);
        argv[n++] = "--socks5-hostname"; argv[n++] = g_proxy;
        argv[n++] = "--proxy-user"; argv[n++] = user;
    }
    return platform_run_quiet(argv);
}

static char *slurp(const char *path, size_t max, size_t *len_out) {
    FILE *f = platform_fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(max + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, max, f);
    fclose(f);
    buf[n] = '\0';
    if (len_out) *len_out = n;
    return buf;
}

static int parse_tag(const char *json, char *tag, size_t cap) {
    const char *p = strstr(json, "\"tag_name\"");
    if (!p) return -1;
    p += strlen("\"tag_name\"");
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p++ != ':') return -1;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p++ != '"') return -1;
    size_t n = 0;
    for (; *p && *p != '"'; p++) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' && *p != '_') return -1;
        if (n + 1 >= cap) return -1;
        tag[n++] = *p;
    }
    if (*p != '"' || n == 0) return -1;
    tag[n] = '\0';
    return 0;
}

static void parse_version(const char *s, long v[3]) {
    v[0] = v[1] = v[2] = 0;
    if (*s == 'v' || *s == 'V') s++;
    for (int i = 0; i < 3 && isdigit((unsigned char)*s); i++) {
        v[i] = strtol(s, (char **)&s, 10);
        if (*s != '.') break;
        s++;
    }
}

static int version_newer(const char *remote, const char *local) {
    long r[3], l[3];
    parse_version(remote, r);
    parse_version(local, l);
    for (int i = 0; i < 3; i++)
        if (r[i] != l[i]) return r[i] > l[i];
    return 0;
}

static int sums_lookup(const char *sums, const char *name, uint8_t hash[crypto_hash_sha256_BYTES]) {
    size_t nlen = strlen(name);
    const char *line = sums;
    while (*line) {
        const char *end = strchr(line, '\n');
        size_t llen = end ? (size_t)(end - line) : strlen(line);
        if (llen > 0 && line[llen - 1] == '\r') llen--;
        if (llen >= 66 && (line[64] == ' ' || line[64] == '\t')) {
            const char *fname = line + 65;
            if (*fname == ' ' || *fname == '*') fname++;
            size_t flen = llen - (size_t)(fname - line);
            if (flen == nlen && memcmp(fname, name, nlen) == 0) {
                char hex[65];
                memcpy(hex, line, 64); hex[64] = '\0';
                return hex_decode(hex, 64, hash);
            }
        }
        if (!end) break;
        line = end + 1;
    }
    return -1;
}

#ifdef CHAT_RELEASE_PUBKEY
static const char RELEASE_PUBKEY[] = CHAT_RELEASE_PUBKEY;
#else
static const char RELEASE_PUBKEY[] = "";
#endif

// Checks a minisign signature (the SHA256SUMS.minisig next to SHA256SUMS) against the release key
// built in from minisign.pub. The trusted comment must be "chat <tag>", so a signed SHA256SUMS from
// an older release can't be passed off as a newer one.
static int minisign_ok(const char *msg, size_t msg_len, const char *sig_text, const char *tag) {
    uint8_t pk[2 + 8 + crypto_sign_PUBLICKEYBYTES];
    if (base64_decode_strict(RELEASE_PUBKEY, strlen(RELEASE_PUBKEY), pk, sizeof pk) != (long)sizeof pk || memcmp(pk, "Ed", 2) != 0)
        return -1;

    // Four lines: untrusted comment, signature, trusted comment, global signature.
    const char *lines[4]; size_t lens[4];
    const char *p = sig_text;
    for (int i = 0; i < 4; i++) {
        const char *end = strchr(p, '\n');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n > 0 && p[n - 1] == '\r') n--;
        lines[i] = p; lens[i] = n;
        if (!end) { if (i < 3) return -1; } else p = end + 1;
    }
    static const char TC[] = "trusted comment: ";
    if (lens[2] < sizeof TC - 1 || memcmp(lines[2], TC, sizeof TC - 1) != 0) return -1;
    const char *comment = lines[2] + sizeof TC - 1;
    size_t comment_len = lens[2] - (sizeof TC - 1);

    char want[64];
    int want_len = snprintf(want, sizeof want, "chat %s", tag);
    if (want_len < 0 || (size_t)want_len != comment_len || memcmp(comment, want, comment_len) != 0) return -1;

    uint8_t sig[2 + 8 + crypto_sign_BYTES], global[crypto_sign_BYTES];
    if (base64_decode_strict(lines[1], lens[1], sig, sizeof sig) != (long)sizeof sig) return -1;
    if (base64_decode_strict(lines[3], lens[3], global, sizeof global) != (long)sizeof global) return -1;
    if (memcmp(sig + 2, pk + 2, 8) != 0) return -1;

    const uint8_t *key = pk + 10, *s = sig + 10;
    int ok;
    if (memcmp(sig, "ED", 2) == 0) {
        // minisign's default: the signature covers BLAKE2b-512 of the file.
        uint8_t h[crypto_generichash_BYTES_MAX];
        crypto_generichash(h, sizeof h, (const unsigned char *)msg, msg_len, NULL, 0);
        ok = crypto_sign_verify_detached(s, h, sizeof h, key) == 0;
    } else if (memcmp(sig, "Ed", 2) == 0) {
        ok = crypto_sign_verify_detached(s, (const unsigned char *)msg, msg_len, key) == 0;
    } else {
        return -1;
    }
    if (!ok) return -1;

    uint8_t signed_comment[crypto_sign_BYTES + 64];
    memcpy(signed_comment, s, crypto_sign_BYTES);
    memcpy(signed_comment + crypto_sign_BYTES, comment, comment_len);
    return crypto_sign_verify_detached(global, signed_comment, crypto_sign_BYTES + comment_len, key) == 0 ? 0 : -1;
}

static int hash_file(const char *path, uint8_t out[crypto_hash_sha256_BYTES], long *size_out) {
    FILE *f = platform_fopen(path, "rb");
    if (!f) return -1;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    uint8_t buf[16384];
    size_t n;
    long total = 0;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        crypto_hash_sha256_update(&st, buf, n);
        total += (long)n;
    }
    int err = ferror(f);
    fclose(f);
    if (err) return -1;
    crypto_hash_sha256_final(&st, out);
    if (size_out) *size_out = total;
    return 0;
}

static void finish(const char *fmt, const char *arg) {
    snprintf(g_msg, sizeof g_msg, fmt, arg);
    __atomic_store_n(&g_state, UPD_DONE, __ATOMIC_RELEASE);
}

static void succeed(const char *fmt, const char *arg) {
    g_ok = 1;
    finish(fmt, arg);
}

static void update_thread(void *unused) {
    (void)unused;
#if !defined(UPDATE_ASSET)
    finish("* update: no release builds exist for this CPU architecture%s", "");
#else
    if (!RELEASE_PUBKEY[0]) {
        finish("* update: this build has no release signing key (minisign.pub), so it can't check a release%s", "");
        return;
    }
    char exe[1024], tmp_json[1100], tmp_sums[1100], tmp_sig[1100], tmp_bin[1100], url[512];
    if (platform_exe_path(exe, sizeof exe) != 0) { finish("* update: could not locate the running executable%s", ""); return; }
    snprintf(tmp_json, sizeof tmp_json, "%s.release", exe);
    snprintf(tmp_sums, sizeof tmp_sums, "%s.sums", exe);
    snprintf(tmp_sig, sizeof tmp_sig, "%s.sums.minisig", exe);
    snprintf(tmp_bin, sizeof tmp_bin, "%s.download", exe);

    if (fetch("https://api.github.com/repos/" UPDATE_REPO "/releases/latest", tmp_json, 1, NULL) != 0) {
        platform_remove(tmp_json);
        finish("* update: could not reach GitHub (is curl installed, and is %s's folder writable?)", exe);
        return;
    }
    char *json = slurp(tmp_json, 1 << 20, NULL);
    platform_remove(tmp_json);
    char tag[40];
    int ok = json && parse_tag(json, tag, sizeof tag) == 0;
    free(json);
    if (!ok) { finish("* update: GitHub's reply had no usable release tag%s", ""); return; }
    if (!version_newer(tag, CHAT_VERSION)) { succeed("* update: already up to date (v" CHAT_VERSION ", latest is %s)", tag); return; }

    snprintf(url, sizeof url, "https://github.com/" UPDATE_REPO "/releases/download/%s/SHA256SUMS", tag);
    if (fetch(url, tmp_sums, 0, NULL) != 0) {
        platform_remove(tmp_sums);
        finish("* update: release %s has no SHA256SUMS - refusing to install it", tag);
        return;
    }
    size_t sums_len = 0;
    char *sums = slurp(tmp_sums, 1 << 16, &sums_len);
    platform_remove(tmp_sums);

    // SHA256SUMS comes from the same place as the binary, so on its own it only catches corruption.
    // The signature, made offline with the release key, is what vouches for it.
    snprintf(url, sizeof url, "https://github.com/" UPDATE_REPO "/releases/download/%s/SHA256SUMS.minisig", tag);
    char *sig = NULL;
    if (fetch(url, tmp_sig, 0, NULL) == 0) sig = slurp(tmp_sig, 4096, NULL);
    platform_remove(tmp_sig);
    int signed_ok = sums && sig && minisign_ok(sums, sums_len, sig, tag) == 0;
    free(sig);
    if (!signed_ok) {
        free(sums);
        finish("* update: release %s has no valid release-key signature - refusing to install it", tag);
        return;
    }

    uint8_t want[crypto_hash_sha256_BYTES];
    ok = sums_lookup(sums, UPDATE_ASSET, want) == 0;
    free(sums);
    if (!ok) { finish("* update: SHA256SUMS lists no " UPDATE_ASSET " for %s - nothing installed", tag); return; }

    snprintf(url, sizeof url, "https://github.com/" UPDATE_REPO "/releases/download/%s/" UPDATE_ASSET, tag);
    if (fetch(url, tmp_bin, 0, NULL) != 0) {
        platform_remove(tmp_bin);
        finish("* update: downloading " UPDATE_ASSET " from %s failed - nothing installed", tag);
        return;
    }
    uint8_t got[crypto_hash_sha256_BYTES];
    long size = 0;
    if (hash_file(tmp_bin, got, &size) != 0 || size == 0 || memcmp(got, want, sizeof got) != 0) {
        platform_remove(tmp_bin);
        finish("* update: SHA-256 of the %s download does NOT match SHA256SUMS - discarded, nothing installed", tag);
        return;
    }
    if (platform_replace_exe(tmp_bin, exe) != 0) {
        platform_remove(tmp_bin);
        finish("* update: verified %s but could not replace the executable (permissions?)", tag);
        return;
    }
    succeed("* update: installed %s (signature and SHA-256 verified) - restart chat to run it", tag);
#endif
}

int update_start(void) {
    int idle = UPD_IDLE;
    if (!__atomic_compare_exchange_n(&g_state, &idle, UPD_RUNNING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -1;
    if (platform_spawn_thread(update_thread, NULL) != 0) {
        __atomic_store_n(&g_state, UPD_IDLE, __ATOMIC_RELEASE);
        return -1;
    }
    return 0;
}

int update_poll(char *msg, size_t cap) {
    if (__atomic_load_n(&g_state, __ATOMIC_ACQUIRE) != UPD_DONE) return 0;
    copy_str(msg, g_msg, cap);
    __atomic_store_n(&g_state, UPD_IDLE, __ATOMIC_RELEASE);
    return 1;
}

int update_run(char *msg, size_t cap) {
    g_ok = 0;
    update_thread(NULL);
    update_poll(msg, cap);
    return g_ok ? 0 : -1;
}

// ---- official builds, to check the build a peer says it runs ----

int update_self_hash(uint8_t out[BUILD_HASH_LEN]) {
#ifdef __linux__
    // The file this process was started from, even if an update has replaced it since.
    return hash_file("/proc/self/exe", out, NULL);
#else
    char exe[1024];
    if (platform_exe_path(exe, sizeof exe) != 0) return -1;
    return hash_file(exe, out, NULL);
#endif
}

// A version a release could have: MAJOR.MINOR.PATCH, as `just release` takes it.
static int release_version(const char *v) {
    for (int part = 0; part < 3; part++) {
        int digits = 0;
        while (isdigit((unsigned char)*v)) { v++; if (++digits > 5) return 0; }
        if (digits == 0 || (part < 2 && *v++ != '.')) return 0;
    }
    return *v == '\0';
}

static int sums_all(const char *sums, uint8_t hashes[][BUILD_HASH_LEN], int max) {
    int n = 0;
    for (const char *line = sums; *line && n < max; ) {
        const char *end = strchr(line, '\n');
        size_t llen = end ? (size_t)(end - line) : strlen(line);
        if (llen >= 66 && (line[64] == ' ' || line[64] == '\t')) {
            char hex[65];
            memcpy(hex, line, 64); hex[64] = '\0';
            if (hex_decode(hex, 64, hashes[n]) == 0) n++;
        }
        if (!end) break;
        line = end + 1;
    }
    return n;
}

// Whether a failed fetch failed because there's no such file: the last status line in its
// headers (after any redirects) is a 404.
static int fetch_missing(const char *headers_path) {
    char *h = slurp(headers_path, 1 << 16, NULL);
    if (!h) return 0;
    int status = 0;
    for (const char *line = h; line && *line; ) {
        if (strncmp(line, "HTTP/", 5) == 0) {
            const char *sp = strchr(line, ' ');
            status = sp ? atoi(sp + 1) : 0;
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    free(h);
    return status == 404;
}

static int fetch_official(const char *version, uint8_t hashes[][BUILD_HASH_LEN], int max) {
    if (!release_version(version)) return CHAT_BUILDS_NONE;
    if (!RELEASE_PUBKEY[0]) return CHAT_BUILDS_UNKNOWN;
    char dir[900], sums_path[1000], sig_path[1000], hdr_path[1000], tag[24], url[512];
    // Not next to the executable, as :update does: that folder may not be writable, and these are
    // fetched without anyone asking.
    if (platform_private_tempdir("chat-sums", dir, sizeof dir) != 0) return CHAT_BUILDS_UNKNOWN;
    snprintf(sums_path, sizeof sums_path, "%s/SHA256SUMS", dir);
    snprintf(sig_path, sizeof sig_path, "%s/SHA256SUMS.minisig", dir);
    snprintf(hdr_path, sizeof hdr_path, "%s/headers", dir);
    snprintf(tag, sizeof tag, "v%s", version);

    int result = CHAT_BUILDS_UNKNOWN;
    snprintf(url, sizeof url, "https://github.com/" UPDATE_REPO "/releases/download/%s/SHA256SUMS", tag);
    if (fetch(url, sums_path, 0, hdr_path) != 0) {
        if (fetch_missing(hdr_path)) result = CHAT_BUILDS_NONE;
    } else {
        snprintf(url, sizeof url, "https://github.com/" UPDATE_REPO "/releases/download/%s/SHA256SUMS.minisig", tag);
        if (fetch(url, sig_path, 0, hdr_path) != 0) {
            // Every release since peers began sending "v" is signed.
            if (fetch_missing(hdr_path)) result = CHAT_BUILDS_NONE;
        } else {
            size_t sums_len = 0;
            char *sums = slurp(sums_path, 1 << 16, &sums_len), *sig = slurp(sig_path, 4096, NULL);
            // A bad signature says nothing about the peer, only that this download went wrong.
            if (sums && sig && minisign_ok(sums, sums_len, sig, tag) == 0) result = sums_all(sums, hashes, max);
            free(sums);
            free(sig);
        }
    }
    platform_remove_tree(dir);
    return result;
}

#define BUILDS_VERSIONS 8
// How long before a lookup that couldn't get an answer (offline, tor not up yet) is tried again.
#define BUILDS_RETRY 300.0

enum { BJ_EMPTY = 0, BJ_FETCHING = 1, BJ_DONE = 2 };

// One version's lookup. The thread fetching it owns everything but state until state is BJ_DONE.
typedef struct {
    int state;
    char version[MAX_VERSION + 1];
    int result;
    uint8_t hashes[CHAT_BUILDS_MAX][BUILD_HASH_LEN];
    double done_at;
} build_job_t;

static build_job_t g_builds[BUILDS_VERSIONS];

static void builds_thread(void *arg) {
    build_job_t *j = arg;
    j->result = fetch_official(j->version, j->hashes, CHAT_BUILDS_MAX);
    j->done_at = now_seconds();
    __atomic_store_n(&j->state, BJ_DONE, __ATOMIC_RELEASE);
}

static int builds_start(build_job_t *j) {
    __atomic_store_n(&j->state, BJ_FETCHING, __ATOMIC_RELEASE);
    if (platform_spawn_thread(builds_thread, j) == 0) return CHAT_BUILDS_PENDING;
    j->result = CHAT_BUILDS_UNKNOWN;
    j->done_at = now_seconds();
    __atomic_store_n(&j->state, BJ_DONE, __ATOMIC_RELEASE);
    return CHAT_BUILDS_UNKNOWN;
}

int update_official_hashes(const char *version, uint8_t hashes[][BUILD_HASH_LEN], int max) {
    if (!release_version(version)) return CHAT_BUILDS_NONE;
    build_job_t *free_job = NULL;
    for (int i = 0; i < BUILDS_VERSIONS; i++) {
        build_job_t *j = &g_builds[i];
        int state = __atomic_load_n(&j->state, __ATOMIC_ACQUIRE);
        if (state == BJ_EMPTY) { if (!free_job) free_job = j; continue; }
        if (strcmp(j->version, version) != 0) continue;
        if (state == BJ_FETCHING) return CHAT_BUILDS_PENDING;
        if (j->result == CHAT_BUILDS_UNKNOWN && now_seconds() - j->done_at > BUILDS_RETRY) return builds_start(j);
        int n = j->result < max ? j->result : max;
        if (n > 0) memcpy(hashes, j->hashes, (size_t)n * BUILD_HASH_LEN);
        return n;
    }
    // A peer can name any version: only so many are looked up in one run.
    if (!free_job) return CHAT_BUILDS_UNKNOWN;
    copy_str(free_job->version, version, sizeof free_job->version);
    return builds_start(free_job);
}

void update_cleanup_stale(void) {
    char exe[1024], old[1100];
    if (platform_exe_path(exe, sizeof exe) != 0) return;
    snprintf(old, sizeof old, "%s.old", exe);
    platform_remove(old);
}
