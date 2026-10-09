// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "core/files.h"
#include "common/util.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define KIB 1024u
#define MIB (1024u * KIB)
#define GIB (1024u * MIB)
// Digits after the point past the sixth make no difference to a size.
#define FRAC_LIMIT 1000000
#define MIN_PER_HOUR 60
#define MIN_PER_DAY (24 * MIN_PER_HOUR)
#define YEAR_SECONDS (60.0 * MIN_PER_DAY * 365)

const char *file_basename(const char *path) {
    const char *b = path;
    for (const char *p = path; *p; p++) if (*p == '/' || *p == '\\') b = p + 1;
    return b;
}

static int bad_byte(unsigned char ch) {
    return ch < 0x20 || ch == 0x7F || strchr("/\\:*?\"<>|", ch) != NULL;
}

// Windows treats these as devices whatever comes after a dot: "nul.txt" is NUL.
static int device_name(const char *s) {
    static const char *const NAMES[] = { "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" };
    size_t n = strcspn(s, ".");
    while (n > 0 && s[n - 1] == ' ') n--;
    char up[8];
    if (n == 0 || n >= sizeof up) return 0;
    for (size_t i = 0; i < n; i++) up[i] = (char)toupper((unsigned char)s[i]);
    up[n] = '\0';
    for (size_t i = 0; i < COUNT_OF(NAMES); i++) if (strcmp(up, NAMES[i]) == 0) return 1;
    // COM1-9 and LPT1-9, and the superscript digits Windows also takes.
    if (strncmp(up, "COM", 3) != 0 && strncmp(up, "LPT", 3) != 0) return 0;
    if (n == 4 && up[3] >= '0' && up[3] <= '9') return 1;
    return n == 5 && (unsigned char)s[3] == 0xC2
           && ((unsigned char)s[4] == 0xB9 || (unsigned char)s[4] == 0xB2 || (unsigned char)s[4] == 0xB3);
}

void file_clean_name(const char *in, char out[FILE_NAME_MAX + 1]) {
    // Control, C1 and bidi characters go first (a right-to-left override can make "txt.exe"
    // read as "exe.txt"), and broken UTF-8 with them.
    char clean[4 * FILE_NAME_MAX + 1];
    clean_text(in, clean, sizeof clean - 1);
    // Only the last part of a path, so a name can't point into another folder.
    const char *s = file_basename(clean);
    size_t o = 0, len = strlen(s);
    for (size_t i = 0; s[i] && o < FILE_NAME_MAX; ) {
        size_t adv = 1;
        utf8_decode(s, len, i, &adv);
        if (adv == 1 && bad_byte((unsigned char)s[i])) { i++; out[o++] = '_'; continue; }
        if (o + adv > FILE_NAME_MAX) break;
        memcpy(out + o, s + i, adv);
        o += adv;
        i += adv;
    }
    out[o] = '\0';
    // No leading dots or spaces (a hidden file, or ".." itself), no trailing dots or spaces
    // (Windows drops them, so "a.exe." would be "a.exe").
    size_t lead = 0;
    while (out[lead] == '.' || out[lead] == ' ') lead++;
    if (lead) memmove(out, out + lead, strlen(out + lead) + 1);
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '.' || out[n - 1] == ' ')) out[--n] = '\0';
    if (n == 0) { copy_str(out, "file", FILE_NAME_MAX + 1); return; }
    if (device_name(out)) {
        char tmp[FILE_NAME_MAX + 2];
        snprintf(tmp, sizeof tmp, "_%s", out);
        // Cut back to a whole character if the underscore pushed it over.
        size_t t = strlen(tmp);
        if (t > FILE_NAME_MAX) {
            t = FILE_NAME_MAX;
            while (t > 0 && utf8_is_cont(tmp[t])) t--;
            tmp[t] = '\0';
        }
        copy_str(out, tmp, FILE_NAME_MAX + 1);
    }
}

int file_parse_size(const char *s, uint64_t *out) {
    while (*s == ' ') s++;
    if (!isdigit((unsigned char)*s)) return -1;
    uint64_t whole = 0, frac = 0, frac_div = 1;
    while (isdigit((unsigned char)*s)) {
        if (whole > (UINT64_MAX - 9) / 10) return -1;
        whole = whole * 10 + (uint64_t)(*s++ - '0');
    }
    if (*s == '.') {
        s++;
        while (isdigit((unsigned char)*s)) {
            if (frac_div < FRAC_LIMIT) { frac = frac * 10 + (uint64_t)(*s - '0'); frac_div *= 10; }
            s++;
        }
    }
    while (*s == ' ') s++;
    uint64_t mult = 1;
    switch (toupper((unsigned char)*s)) {
        case 'K': mult = KIB; s++; break;
        case 'M': mult = MIB; s++; break;
        case 'G': mult = GIB; s++; break;
        default: break;
    }
    if (toupper((unsigned char)*s) == 'B') s++;
    while (*s == ' ') s++;
    if (*s) return -1;
    if (whole > UINT64_MAX / mult) return -1;
    *out = whole * mult + frac * mult / frac_div;
    return 0;
}

void file_format_size(uint64_t n, char *out, size_t cap) {
    if (n < KIB) snprintf(out, cap, "%u bytes", (unsigned)n);
    else if (n < MIB) snprintf(out, cap, "%.0f KB", (double)n / KIB);
    else if (n < GIB) snprintf(out, cap, "%.1f MB", (double)n / MIB);
    else snprintf(out, cap, "%.1f GB", (double)n / GIB);
}

void file_format_size_exact(uint64_t n, char *out, size_t cap) {
    static const struct { uint64_t per; const char *unit; } UNITS[] = { { GIB, "G" }, { MIB, "M" }, { KIB, "K" }, { 1, "" } };
    size_t i = 0;
    while (n % UNITS[i].per != 0) i++;
    snprintf(out, cap, "%llu%s", (unsigned long long)(n / UNITS[i].per), UNITS[i].unit);
}

void file_format_duration(double seconds, char *out, size_t cap) {
    if (!(seconds < YEAR_SECONDS)) seconds = YEAR_SECONDS;   // NaN too
    long min = (long)(seconds / 60.0 + 0.5);
    if (seconds < 60.0) snprintf(out, cap, "under a minute");
    else if (min < MIN_PER_HOUR) snprintf(out, cap, "about %ld min", min);
    else if (min >= 2 * MIN_PER_DAY) snprintf(out, cap, "about %ld days", (min + MIN_PER_DAY / 2) / MIN_PER_DAY);
    else if (min % MIN_PER_HOUR == 0 || min >= 10 * MIN_PER_HOUR)
        snprintf(out, cap, "about %ld h", (min + MIN_PER_HOUR / 2) / MIN_PER_HOUR);
    else snprintf(out, cap, "about %ld h %ld min", min / MIN_PER_HOUR, min % MIN_PER_HOUR);
}
