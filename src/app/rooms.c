// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/rooms.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include <stdio.h>
#include <string.h>

#define START_WORD "start"

static room_t g_rooms[ROOMS_MAX];
static int g_n, g_locked;

static void lock_rooms(void) {
    if (g_locked) return;
    crypto_lock(g_rooms, sizeof g_rooms);
    g_locked = 1;
}

int rooms_count(void) { return g_n; }

const room_t *room_at(int i) { return i >= 0 && i < g_n ? &g_rooms[i] : NULL; }

int rooms_find(const char *id) {
    for (int i = 0; i < g_n; i++) if (strcmp(g_rooms[i].id, id) == 0) return i;
    return -1;
}

int rooms_keep(const char *label, const char *id, const char *password) {
    lock_rooms();
    if (!id[0] || strlen(id) > MAX_SESSION_NAME || has_control_chars(id) || strlen(password) > MAX_PASSWORD)
        return -1;
    int i = rooms_find(id);
    if (i < 0) {
        if (g_n >= ROOMS_MAX) return -1;
        i = g_n++;
        memset(&g_rooms[i], 0, sizeof g_rooms[i]);
        copy_str(g_rooms[i].id, id, sizeof g_rooms[i].id);
    }
    room_t *r = &g_rooms[i];
    // The label is drawn on screen, so nothing in it may move the cursor or turn text around.
    if (!clean_text(label, r->label, ROOM_LABEL_MAX)) clean_text(id, r->label, ROOM_LABEL_MAX);
    copy_str(r->password, password, sizeof r->password);
    return i;
}

void rooms_forget(int i) {
    if (i < 0 || i >= g_n) return;
    memmove(&g_rooms[i], &g_rooms[i + 1], sizeof g_rooms[0] * (size_t)(g_n - i - 1));
    g_n--;
    crypto_wipe(&g_rooms[g_n], sizeof g_rooms[g_n]);
}

void rooms_set_start(int i, int on) {
    if (i >= 0 && i < g_n) g_rooms[i].at_start = on != 0;
}

void rooms_clear(void) {
    crypto_wipe(g_rooms, sizeof g_rooms);
    g_n = 0;
}

int rooms_load(const toml_value *v) {
    if (v->type != TOML_ARRAY || v->n < 3 || v->n > 4 || (v->n == 4 && strcmp(v->items[3], START_WORD) != 0))
        return -1;
    int i = rooms_keep(v->items[0], v->items[1], v->items[2]);
    if (i < 0) return -1;
    rooms_set_start(i, v->n == 4);
    return 0;
}

static size_t put(char *out, size_t p, size_t cap, const char *s) {
    size_t n = strlen(s);
    if (p >= cap || n >= cap - p) return cap;
    memcpy(out + p, s, n + 1);
    return p + n;
}

size_t rooms_text(char *out, size_t p, size_t cap) {
    if (!g_n) return p;
    p = put(out, p, cap, p ? "\n[rooms]\n" : "[rooms]\n");
    for (int i = 0; i < g_n; i++) {
        const room_t *r = &g_rooms[i];
        char key[16];
        snprintf(key, sizeof key, "%d = [", i + 1);
        p = put(out, p, cap, key);
        p = toml_put_str(out, p, cap, r->label);
        p = put(out, p, cap, ", ");
        p = toml_put_str(out, p, cap, r->id);
        p = put(out, p, cap, ", ");
        p = toml_put_str(out, p, cap, r->password);
        if (r->at_start) {
            p = put(out, p, cap, ", ");
            p = toml_put_str(out, p, cap, START_WORD);
        }
        p = put(out, p, cap, "]\n");
    }
    return p;
}
