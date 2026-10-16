// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Paths, and the folder browser the key, send and save pages use.
#include "app/app.h"

// Folders first, then files. In each, hidden ones (starting with '.') last.
static int entry_cmp(const void *a, const void *b) {
    const dir_entry_t *ea = a, *eb = b;
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir;
    int ha = ea->name[0] == '.', hb = eb->name[0] == '.';
    if (ha != hb) return ha - hb;
    return strcasecmp(ea->name, eb->name);
}

int path_is_root(const char *p) {
    size_t n = strlen(p);
    return strcmp(p, "/") == 0 || (n == 2 && p[1] == ':') || (n == 3 && p[1] == ':' && p[2] == '/');
}

void path_join(char *out, size_t cap, const char *dir, const char *name) {
    size_t n = strlen(dir);
    snprintf(out, cap, (n > 0 && dir[n - 1] == '/') ? "%s%s" : "%s/%s", dir, name);
}

void path_parent(char *p) {
    if (path_is_root(p)) return;
    size_t n = strlen(p);
    while (n > 1 && p[n - 1] == '/') p[--n] = '\0';
    char *slash = strrchr(p, '/');
    if (!slash) return;
    if (slash == p) p[1] = '\0';
    else if (slash == p + 2 && p[1] == ':') slash[1] = '\0';
    else *slash = '\0';
}

static void browser_add(void *ctx, const char *name, int is_dir) {
    browser_t *b = ctx;
    if (b->n_items >= MAX_DIR_ITEMS) return;
    // Names are written straight to the terminal, and one containing escape sequences could control it.
    if (has_control_chars(name)) return;
    // The tree above the entries shows the parent folders, and h goes up.
    if (strcmp(name, "..") == 0) return;
    dir_entry_t *item = &b->items[b->n_items++];
    snprintf(item->name, sizeof item->name, "%s%s", name, is_dir ? "/" : "");
    item->is_dir = is_dir;
}

int browser_load(browser_t *b, const char *path) {
    static browser_t tmp;
    memset(&tmp, 0, sizeof tmp);
    copy_str(tmp.path, path, sizeof tmp.path);
    if (platform_list_dir(tmp.path, browser_add, &tmp) != 0) return -1;
    qsort(tmp.items, (size_t)tmp.n_items, sizeof(dir_entry_t), entry_cmp);
    *b = tmp;
    return 0;
}

// Selects the entry called name (a folder's without its '/'), if it's there.
void browser_select(browser_t *b, const char *name) {
    size_t n = strlen(name);
    if (!n) return;
    for (int i = 0; i < b->n_items; i++) {
        const char *e = b->items[i].name;
        if (strncmp(e, name, n) == 0 && (e[n] == '\0' || (e[n] == '/' && e[n + 1] == '\0'))) { b->selected = i; return; }
    }
}

// The path of an entry in the folder the browser shows, without a folder's trailing '/'.
void browser_entry_path(const browser_t *b, const dir_entry_t *e, char *out, size_t cap) {
    char name[sizeof e->name];
    copy_str(name, e->name, sizeof name);
    size_t n = strlen(name);
    if (n > 0 && name[n - 1] == '/') name[n - 1] = '\0';
    path_join(out, cap, b->path, name);
}
