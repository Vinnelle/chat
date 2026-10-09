// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "core/trust.h"
#include "common/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static trust_entry_t g_list[TRUST_MAX];
static int g_n;
static void (*g_changed)(void);
static int g_saved;

static const char *const SOURCE_NAMES[] = { "none", "key", "age", "pgp" };
#define KEY_HEX_LEN (ID_SIGN_PUB_LEN * 2)

static void changed(void) { if (g_changed) g_changed(); }

int trust_count(void) { return g_n; }

const trust_entry_t *trust_at(int i) { return i >= 0 && i < g_n ? &g_list[i] : NULL; }

const trust_entry_t *trust_by_key(const uint8_t pub[ID_SIGN_PUB_LEN]) {
    for (int i = 0; i < g_n; i++) if (memcmp(g_list[i].pub, pub, ID_SIGN_PUB_LEN) == 0) return &g_list[i];
    return NULL;
}

int trust_find_nick(const char *skel, int from) {
    for (int i = from < 0 ? 0 : from; i < g_n; i++) if (strcmp(g_list[i].nick_skel, skel) == 0) return i;
    return -1;
}

static void set_nick(trust_entry_t *e, identity_source_t source, const char *clean) {
    e->source = source;
    copy_str(e->nick, clean, sizeof e->nick);
    chat_nick_skeleton(e->nick, e->nick_skel, sizeof e->nick_skel);
}

static int add(identity_source_t source, const uint8_t pub[ID_SIGN_PUB_LEN], const char *nick) {
    char clean[MAX_NICK + 1];
    chat_clean_nick(nick, clean);
    for (int i = 0; i < g_n; i++) {
        trust_entry_t *e = &g_list[i];
        if (memcmp(e->pub, pub, ID_SIGN_PUB_LEN) != 0) continue;
        if (strcmp(e->nick, clean) == 0 && e->source == source) return 0;
        set_nick(e, source, clean);
        return 1;
    }
    if (g_n == TRUST_MAX) {
        memmove(&g_list[0], &g_list[1], (TRUST_MAX - 1) * sizeof g_list[0]);
        g_n--;
    }
    trust_entry_t *e = &g_list[g_n++];
    memset(e, 0, sizeof *e);
    memcpy(e->pub, pub, ID_SIGN_PUB_LEN);
    set_nick(e, source, clean);
    return 1;
}

int trust_add(identity_source_t source, const uint8_t pub[ID_SIGN_PUB_LEN], const char *nick) {
    int r = add(source, pub, nick);
    if (r) changed();
    return r;
}

void trust_remove(int i) {
    if (i < 0 || i >= g_n) return;
    memmove(&g_list[i], &g_list[i + 1], (size_t)(g_n - i - 1) * sizeof g_list[0]);
    g_n--;
    changed();
}

void trust_clear(void) {
    memset(g_list, 0, sizeof g_list);
    g_n = 0;
}

int trust_text(char *out, size_t cap) {
    size_t pos = 0;
    for (int i = 0; i < g_n; i++) {
        const trust_entry_t *e = &g_list[i];
        char hex[KEY_HEX_LEN + 1];
        hex_encode(e->pub, ID_SIGN_PUB_LEN, hex);
        int src = e->source >= IDENT_NONE && e->source <= IDENT_PGP ? (int)e->source : 0;
        int n = snprintf(out + pos, cap - pos, "%s %s %s\n", SOURCE_NAMES[src], hex, e->nick);
        if (n < 0 || (size_t)n >= cap - pos) return -1;
        pos += (size_t)n;
    }
    if (pos >= cap) return -1;
    out[pos] = '\0';
    return 0;
}

// One line as trust_text writes it. 0 if it can't be read.
static int load_line(const char *line, size_t len) {
    char buf[TRUST_LINE_MAX + 1];
    if (len >= sizeof buf) return 0;
    memcpy(buf, line, len);
    buf[len] = '\0';
    char *sp1 = strchr(buf, ' ');
    char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (!sp1 || !sp2 || sp2 - sp1 - 1 != KEY_HEX_LEN || !sp2[1]) return 0;
    *sp1 = *sp2 = '\0';
    int src = -1;
    for (int k = IDENT_NATIVE; k <= IDENT_PGP; k++) if (strcmp(buf, SOURCE_NAMES[k]) == 0) src = k;
    uint8_t pub[ID_SIGN_PUB_LEN];
    if (src <= 0 || hex_decode(sp1 + 1, KEY_HEX_LEN, pub) != 0) return 0;
    if (!trust_by_key(pub)) add((identity_source_t)src, pub, sp2 + 1);
    return 1;
}

int trust_load(const char *text) {
    int bad = 0;
    for (const char *line = text, *end; line && *line; line = end ? end + 1 : NULL) {
        end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len > 0 && !load_line(line, len)) bad++;
    }
    return bad;
}

void trust_on_change(void (*fn)(void)) { g_changed = fn; }
void trust_set_saved(int saved) { g_saved = saved; }
int trust_saved(void) { return g_saved; }
