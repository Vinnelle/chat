// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "core/files.h"
#include "common/util.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

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
    for (size_t i = 0; i < sizeof NAMES / sizeof NAMES[0]; i++) if (strcmp(up, NAMES[i]) == 0) return 1;
    // COM1-9 and LPT1-9, and the superscript digits Windows also takes.
    if (n == 4 && (strncmp(up, "COM", 3) == 0 || strncmp(up, "LPT", 3) == 0) && up[3] >= '0' && up[3] <= '9') return 1;
    if (n == 5 && (strncmp(up, "COM", 3) == 0 || strncmp(up, "LPT", 3) == 0) && (unsigned char)s[3] == 0xC2
        && ((unsigned char)s[4] == 0xB9 || (unsigned char)s[4] == 0xB2 || (unsigned char)s[4] == 0xB3)) return 1;
    return 0;
}

void file_clean_name(const char *in, char out[FILE_NAME_MAX + 1]) {
    // Control, C1 and bidi characters go first (a right-to-left override can make "txt.exe"
    // read as "exe.txt"), and broken UTF-8 with them.
    char clean[4 * FILE_NAME_MAX + 1];
    clean_text(in, clean, sizeof clean - 1);
    // Only the last part of a path, so a name can't point into another folder.
    const char *s = file_basename(clean);
    size_t o = 0;
    for (size_t i = 0; s[i] && o < FILE_NAME_MAX; ) {
        size_t adv = 1;
        uint32_t cp = utf8_decode(s, strlen(s), i, &adv);
        (void)cp;
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
            while (t > 0 && ((unsigned char)tmp[t] & 0xC0) == 0x80) t--;
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
            if (frac_div < 1000000) { frac = frac * 10 + (uint64_t)(*s - '0'); frac_div *= 10; }
            s++;
        }
    }
    while (*s == ' ') s++;
    uint64_t mult = 1;
    switch (toupper((unsigned char)*s)) {
        case 'K': mult = 1024; s++; break;
        case 'M': mult = 1024 * 1024; s++; break;
        case 'G': mult = 1024u * 1024 * 1024; s++; break;
        default: break;
    }
    if (mult > 1 && toupper((unsigned char)*s) == 'B') s++;
    else if (mult == 1 && toupper((unsigned char)*s) == 'B') s++;
    while (*s == ' ') s++;
    if (*s) return -1;
    if (whole > UINT64_MAX / mult) return -1;
    *out = whole * mult + frac * mult / frac_div;
    return 0;
}

void file_format_size(uint64_t n, char *out, size_t cap) {
    if (n < 1024) snprintf(out, cap, "%u bytes", (unsigned)n);
    else if (n < 1024 * 1024) snprintf(out, cap, "%.0f KB", (double)n / 1024.0);
    else if (n < 1024u * 1024 * 1024) snprintf(out, cap, "%.1f MB", (double)n / (1024.0 * 1024.0));
    else snprintf(out, cap, "%.1f GB", (double)n / (1024.0 * 1024.0 * 1024.0));
}

void file_format_duration(double seconds, char *out, size_t cap) {
    if (!(seconds < 60.0 * 60 * 24 * 365)) seconds = 60.0 * 60 * 24 * 365;   // NaN too
    long min = (long)(seconds / 60.0 + 0.5);
    if (seconds < 60.0) snprintf(out, cap, "under a minute");
    else if (min < 60) snprintf(out, cap, "about %ld min", min);
    else if (min >= 48 * 60) snprintf(out, cap, "about %ld days", (min + 720) / 1440);
    else if (min % 60 == 0 || min >= 600) snprintf(out, cap, "about %ld h", (min + 30) / 60);
    else snprintf(out, cap, "about %ld h %ld min", min / 60, min % 60);
}
