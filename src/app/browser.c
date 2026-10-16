// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The folder browser the key, send and save pages use: paths, what it lists, the keys on its
// pages, and drawing them.
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

// ---- the keys on its pages ----

// Up to the parent folder, with the folder just left selected.
static void browser_up(void) {
    char up[APP_PATH_MAX], name[sizeof g_app.browser.items[0].name] = "";
    copy_str(up, g_app.browser.path, sizeof up);
    size_t n = strlen(up);
    while (n > 1 && up[n - 1] == '/') up[--n] = '\0';
    const char *slash = strrchr(up, '/');
    if (slash) copy_str(name, slash + 1, sizeof name);
    path_parent(up);
    if (browser_load(&g_app.browser, up) == 0) browser_select(&g_app.browser, name);
}

static void browser_home(void) {
    const char *home = platform_home_dir();
    if (home) browser_load(&g_app.browser, home);
}

// Besides the list keys: / types a path instead, starting with the file selected or the folder
// shown, and ~ goes to the home folder.
void browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && (key->ch[0] == '/' || key->ch[0] == '~')) {
        if (key->ch[0] == '~') { browser_home(); g_app.dirty = 1; return; }
        char start[1200];
        if (b->n_items > 0 && !b->items[b->selected].is_dir) browser_entry_path(b, &b->items[b->selected], start, sizeof start);
        else path_join(start, sizeof start, b->path, "");
        begin_key_path(g_app.key.load_kind, start, 1);
        return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_LEFT: browser_up(); break;
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            if (b->n_items == 0) break;
            const dir_entry_t *sel = &b->items[b->selected];
            if (sel->is_dir) {
                char next[1200]; browser_entry_path(b, sel, next, sizeof next);
                browser_load(b, next);
            } else if (try_load_key_from_browser() == 0) {
                g_app.mode = MODE_SETTINGS;
            }
            break;
        }
        case LIST_BACK:  g_app.mode = MODE_SIGN_CHOICE; break;
        case LIST_CLOSE: settings_done(); break;
        default: list_move(k, &b->selected, b->n_items); break;
    }
    g_app.dirty = 1;
}

// :send without a path: the file is picked here, starting where the last one came from.
void begin_send_browse(int asis) {
    if (g_app.mode != MODE_CHAT && g_app.mode != MODE_FILES) return;
    g_app.files.send_asis = asis;
    const char *home = platform_home_dir();
    if ((!g_app.files.send_dir[0] || browser_load(&g_app.browser, g_app.files.send_dir) != 0)
        && (!home || browser_load(&g_app.browser, home) != 0))
        browser_load(&g_app.browser, "/");
    g_app.files.browse_back = g_app.mode;
    g_app.mode = MODE_SEND_BROWSE;
    g_app.dirty = 1;
}

void send_browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && key->ch[0] == '~') { browser_home(); g_app.dirty = 1; return; }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_LEFT: browser_up(); break;
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            if (b->n_items == 0) break;
            const dir_entry_t *sel = &b->items[b->selected];
            char full[1200]; browser_entry_path(b, sel, full, sizeof full);
            if (sel->is_dir) {
                browser_load(b, full);
            } else if (k == LIST_CHOOSE) {
                g_app.mode = g_app.files.browse_back;
                if (!g_app.selected || g_app.selected->initialising) {
                    note("no session to send %.80s to", sel->name);
                    break;
                }
                copy_str(g_app.files.send_dir, b->path, sizeof g_app.files.send_dir);
                chat_t *e = &g_app.selected->engine;
                int was = e->file_seq;
                g_echo = 1;
                chat_send_file(e, full, g_app.files.send_asis);
                g_echo = 0;
                if (e->file_seq != was) g_app.files.num = e->file_seq;
            }
            break;
        }
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = g_app.files.browse_back; break;
        default: list_move(k, &b->selected, b->n_items); break;
    }
    g_app.dirty = 1;
}

// :saveto N: the folder to save file N in is picked here, starting where the last one went, or in
// Downloads.
void begin_save_browse(int num, int anyway) {
    if (g_app.mode != MODE_CHAT && g_app.mode != MODE_FILES && g_app.mode != MODE_FILE_VIEW) return;
    char dl[600];
    const char *home = platform_home_dir();
    if ((!g_app.files.save_dir[0] || browser_load(&g_app.browser, g_app.files.save_dir) != 0)
        && (platform_downloads_dir(dl, sizeof dl) != 0 || browser_load(&g_app.browser, dl) != 0)
        && (!home || browser_load(&g_app.browser, home) != 0))
        browser_load(&g_app.browser, "/");
    g_app.files.save_num = num;
    g_app.files.save_anyway = anyway;
    g_app.files.browse_back = g_app.mode;
    g_app.mode = MODE_SAVE_BROWSE;
    g_app.dirty = 1;
}

// Enter opens the selected folder and s saves in the one shown.
void save_browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && key->ch[0] == '~') { browser_home(); g_app.dirty = 1; return; }
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && key->ch[0] == 's') {
        g_app.mode = g_app.files.browse_back;
        g_app.dirty = 1;
        if (!g_app.selected || g_app.selected->initialising) { note("no session to save file %d from", g_app.files.save_num); return; }
        copy_str(g_app.files.save_dir, b->path, sizeof g_app.files.save_dir);
        g_echo = 1;
        chat_file_fetch(&g_app.selected->engine, g_app.files.save_num, 0, g_app.files.save_anyway, b->path);
        g_echo = 0;
        return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_LEFT: browser_up(); break;
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            if (b->n_items == 0) break;
            const dir_entry_t *sel = &b->items[b->selected];
            if (!sel->is_dir) break;
            char full[1200]; browser_entry_path(b, sel, full, sizeof full);
            browser_load(b, full);
            break;
        }
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = g_app.files.browse_back; break;
        default: list_move(k, &b->selected, b->n_items); break;
    }
    g_app.dirty = 1;
}

// ---- drawing its pages ----

// The browser as a tree: the folder shown and the folders above it, one level per row, then its
// folders (drawn like rows that open a page) and files one level further in. As many levels get
// their own row as leave room for the names at this width. The levels above those are joined
// into the top row's path. The intro says what's in the folder.
#define TREE_MAX_LEVELS 32

#define TREE_INDENT 3        // columns per level

#define TREE_NAME_ROOM 14    // columns kept for the names

// Before an entry in the tree, and before the last one: "├─ " and "└─ ".
#define TREE_MID "\xe2\x94\x9c\xe2\x94\x80 "
#define TREE_LAST "\xe2\x94\x94\xe2\x94\x80 "
#define ELLIPSIS "\xe2\x80\xa6"

// s, or if it's longer than room bytes its end after an ellipsis: the end of a path says where it is.
static void tail_ellipsis(const char *s, size_t room, char *out, size_t cap) {
    size_t len = strlen(s);
    if (len <= room) { copy_str(out, s, cap); return; }
    const char *tail = s + len - (room - 1);
    while (utf8_is_cont(*tail)) tail++;
    snprintf(out, cap, ELLIPSIS "%s", tail);
}

static tui_row_t g_browser_rows[TREE_MAX_LEVELS + MAX_DIR_ITEMS];

static char g_browser_labels[MAX_DIR_ITEMS][200];

static int g_browser_levels;   // rows above the entries

// The parent folder's entries for the column left of the tree, read again only when the folder
// shown changes. room: the columns its path gets.
// Returns 0 at the root, which has no parent.
static int parent_nav(const browser_t *b, int room, const char **nav, int *n, int *sel, char *title, size_t cap) {
    static browser_t parent;
    static char of[APP_PATH_MAX], name[sizeof b->items[0].name];
    static int ok;
    if (strcmp(of, b->path) != 0) {
        copy_str(of, b->path, sizeof of);
        char up[APP_PATH_MAX];
        copy_str(up, b->path, sizeof up);
        size_t len = strlen(up);
        while (len > 1 && up[len - 1] == '/' && !path_is_root(up)) up[--len] = '\0';
        const char *slash = strrchr(up, '/');
        copy_str(name, slash ? slash + 1 : "", sizeof name);
        ok = !path_is_root(up) && name[0];
        path_parent(up);
        ok = ok && browser_load(&parent, up) == 0;
    }
    if (!ok) return 0;
    *n = 0;
    *sel = -1;
    for (int i = 0; i < parent.n_items && *n < MAX_DIR_ITEMS; i++) {
        const char *e = parent.items[i].name;
        size_t nl = strlen(name);
        if (strncmp(e, name, nl) == 0 && e[nl] == '/' && e[nl + 1] == '\0') *sel = *n;
        nav[(*n)++] = e;
    }
    // Its path, cut from the left to fit.
    char shown[APP_PATH_MAX];
    tilde_path(parent.path, shown, sizeof shown);
    if (room > 4) tail_ellipsis(shown, (size_t)room, title, cap);
    else copy_str(title, shown, cap);
    return 1;
}

static void browser_rows(const browser_t *b, int row_cols, int list_rows, char *intro, size_t cap) {
    static char shown[APP_PATH_MAX], head[APP_PATH_MAX], level_pre[TREE_MAX_LEVELS][TREE_MAX_LEVELS * TREE_INDENT + 8];
    static char mid_pre[TREE_MAX_LEVELS * TREE_INDENT + 8], last_pre[TREE_MAX_LEVELS * TREE_INDENT + 8];
    tilde_path(b->path, shown, sizeof shown);
    size_t len = strlen(shown);
    while (len > 1 && shown[len - 1] == '/' && !path_is_root(shown)) shown[--len] = '\0';

    // The folder's path split at each '/', where the first part is "" if it starts at the root.
    const char *parts[256];
    int n = 0;
    static char split[APP_PATH_MAX];
    copy_str(split, shown, sizeof split);
    for (char *at = split; n < (int)COUNT_OF(parts); ) {
        parts[n++] = at;
        char *slash = strchr(at, '/');
        if (!slash) break;
        *slash = '\0';
        at = slash + 1;
    }
    if (n > 1 && !parts[n - 1][0]) n--;   // "/" or "C:/": the root alone

    // The names and their tree lines get half the row when there's a value column (tui_render_page).
    int levels = (row_cols / 2 - TREE_NAME_ROOM) / TREE_INDENT;
    if (levels < 1) levels = 1;
    if (levels > TREE_MAX_LEVELS) levels = TREE_MAX_LEVELS;
    if (levels > n) levels = n;
    // And room under them for a few entries, so the top of the tree isn't scrolled away.
    enum { ENTRIES_BELOW = 3 };
    int below = b->n_items < ENTRIES_BELOW ? b->n_items : ENTRIES_BELOW;
    if (levels > list_rows - below) levels = list_rows - below > 1 ? list_rows - below : 1;
    // The top row: every part not given a row of its own.
    int joined = n - (levels - 1);
    size_t p = 0;
    head[0] = '\0';
    for (int i = 0; i < joined && p < sizeof head - 1; i++)
        p += (size_t)snprintf(head + p, sizeof head - p, "%s%s", i ? "/" : "", parts[i]);
    if (!head[0] || (joined == 1 && n > 1 && !parts[0][0])) copy_str(head, "/", sizeof head);
    // Too long for its room: its end, which says where it is, after an ellipsis.
    int room = row_cols / 2 - 3;
    if (room > 8 && strlen(head) > (size_t)room) {
        char cut[APP_PATH_MAX];
        tail_ellipsis(head, (size_t)room, cut, sizeof cut);
        copy_str(head, cut, sizeof head);
    }
    g_browser_rows[0] = (tui_row_t){ NULL, head, NULL, TUI_V_TEXT, NULL, NULL, 0, 0 };
    for (int i = 1; i < levels; i++) {
        snprintf(level_pre[i], sizeof level_pre[i], "%*s" TREE_LAST, (i - 1) * TREE_INDENT, "");
        g_browser_rows[i] = (tui_row_t){ NULL, parts[joined + i - 1], NULL, TUI_V_TEXT, NULL, level_pre[i], 0, 0 };
    }
    g_browser_levels = levels;

    snprintf(mid_pre, sizeof mid_pre, "%*s" TREE_MID, (levels - 1) * TREE_INDENT, "");
    snprintf(last_pre, sizeof last_pre, "%*s" TREE_LAST, (levels - 1) * TREE_INDENT, "");
    int folders = 0, files = 0;
    for (int i = 0; i < b->n_items; i++) {
        const dir_entry_t *e = &b->items[i];
        copy_str(g_browser_labels[i], e->name, sizeof g_browser_labels[i]);
        size_t ln = strlen(g_browser_labels[i]);
        if (e->is_dir && ln > 1 && g_browser_labels[i][ln - 1] == '/') g_browser_labels[i][ln - 1] = '\0';
        if (e->is_dir) folders++; else files++;
        g_browser_rows[levels + i] = (tui_row_t){ NULL, g_browser_labels[i], e->is_dir ? "" : NULL, TUI_V_LINK, NULL,
                                                  i == b->n_items - 1 ? last_pre : mid_pre, 0, 0 };
    }
    char f[24] = "", g[24] = "";
    if (folders) snprintf(f, sizeof f, "%d folder%s", folders, folders == 1 ? "" : "s");
    if (files) snprintf(g, sizeof g, "%s%d file%s", folders ? DOT_SEP : "", files, files == 1 ? "" : "s");
    snprintf(intro, cap, "%s%s", folders || files ? f : "empty", g);
}

// The help for the selected entry when it's a folder, or when there's none. Returns 0 for a file.
static int browser_folder_help(const browser_t *b, char *out, size_t cap) {
    if (b->n_items == 0) { snprintf(out, cap, "Nothing here. h goes up a folder."); return 1; }
    const dir_entry_t *e = &b->items[b->selected];
    if (!e->is_dir) return 0;
    snprintf(out, cap, "Enter opens %s. h goes up a folder.", g_browser_labels[b->selected]);
    return 1;
}

// What the sidebar says about the selected entry: its name, then what it is, its size (or for a
// folder, how many entries it has), when it was changed and who can read it. In the key browser
// (kind AGE or PGP), a small file is also read to say whether it holds a secret key. Worked out
// again only when the selection changes.
static void count_cb(void *ctx, const char *name, int is_dir) {
    (void)is_dir;
    if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) (*(int *)ctx)++;
}

#define INFO_LINES 16
// A file bigger than this isn't read to see if it holds a key: no key file is that big.
#define KEY_FILE_MAX 65536

static int browser_info(const browser_t *b, identity_source_t kind, const char **lines) {
    static char of[1200], text[INFO_LINES][120];
    static identity_source_t of_kind;
    static int n;
    if (b->n_items == 0) return 0;
    char full[1200];
    browser_entry_path(b, &b->items[b->selected], full, sizeof full);
    if (strcmp(full, of) == 0 && kind == of_kind) goto done;
    copy_str(of, full, sizeof of);
    of_kind = kind;
    n = 0;
    copy_str(text[n++], g_browser_labels[b->selected], sizeof text[0]);
    text[n++][0] = '\0';
    file_info_t fi;
    if (platform_file_info(full, &fi) != 0) {
        copy_str(text[n++], "can't be read", sizeof text[0]);
        goto done;
    }
    if (fi.is_dir) {
        int count = 0;
        copy_str(text[n++], fi.is_link ? "link to a folder" : "folder", sizeof text[0]);
        if (platform_list_dir(full, count_cb, &count) == 0)
            snprintf(text[n++], sizeof text[0], "%d entr%s", count, count == 1 ? "y" : "ies");
        else
            copy_str(text[n++], "can't be opened", sizeof text[0]);
    } else {
        copy_str(text[n++], fi.is_link ? "link to a file" : "file", sizeof text[0]);
        file_format_size(fi.size, text[n++], sizeof text[0]);
    }
    if (fi.modified[0]) {
        // "YYYY-MM-DD HH:MM" on two rows, to fit the sidebar.
        text[n++][0] = '\0';
        copy_str(text[n++], "changed", sizeof text[0]);
        snprintf(text[n++], sizeof text[0], "%.*s", DATE_LEN, fi.modified);
        copy_str(text[n++], fi.modified + DATE_LEN + 1, sizeof text[0]);
    }
    if (fi.mode >= 0) {
        static const char RWX[] = "rwxrwxrwx";
        char perm[sizeof RWX];
        for (size_t i = 0; i < sizeof RWX - 1; i++) perm[i] = fi.mode & (0400 >> i) ? RWX[i] : '-';
        perm[sizeof RWX - 1] = '\0';
        snprintf(text[n++], sizeof text[0], "%s %03o", perm, fi.mode & 0777);
    }
    if (kind != IDENT_NONE && !fi.is_dir) {
        text[n++][0] = '\0';
        static char head[16384];
        long got = fi.size <= KEY_FILE_MAX ? platform_read_file(full, head, sizeof head - 1) : -1;
        int found = 0;
        if (got >= 0) {
            head[got] = '\0';
            if (strstr(head, AGE_SECRET_KEY_PREFIX)) found = IDENT_AGE;
            else if (strstr(head, PGP_PRIVATE_BEGIN)) found = IDENT_PGP;
            crypto_wipe(head, sizeof head);
        }
        if (fi.size > KEY_FILE_MAX) copy_str(text[n++], "too big for a key", sizeof text[0]);
        else if (got < 0) copy_str(text[n++], "can't be read", sizeof text[0]);
        else if (!found) copy_str(text[n++], "no secret key", sizeof text[0]);
        else snprintf(text[n++], sizeof text[0], "%s secret key", found == IDENT_AGE ? "AGE" : "PGP");
        if (found && found != (int)kind)
            snprintf(text[n++], sizeof text[0], "but this is %s", kind == IDENT_AGE ? "AGE" : "PGP");
        // Readable by more than its owner.
        if (found && fi.mode >= 0 && (fi.mode & 077)) {
            copy_str(text[n++], "not private:", sizeof text[0]);
            copy_str(text[n++], "chmod 600 it", sizeof text[0]);
        }
    }
done:
    for (int i = 0; i < n; i++) lines[i] = text[i];
    return n;
}

// A file browser's page, laid out by browser_lay_out: the parent folder's entries in a column left
// of the tree when there's room, and what browser_info says about the selected entry in the nav.
typedef struct {
    char intro[1000], side_title[APP_PATH_MAX];
    const char *side[MAX_DIR_ITEMS], *info[INFO_LINES];
    int n_side, side_sel, columns, n_info;
} browser_page_t;

// The rows the page takes besides the tree's.
#define BROWSER_CHROME_ROWS 12

static void browser_lay_out(browser_page_t *v, int rows_n, int cols_n, identity_source_t kind) {
    const browser_t *b = &g_app.browser;
    int sw = tui_side_width(cols_n, 1);
    v->n_side = 0;
    v->side_sel = -1;
    v->columns = sw && parent_nav(b, sw - 4, v->side, &v->n_side, &v->side_sel, v->side_title, sizeof v->side_title);
    browser_rows(b, tui_page_row_cols(cols_n, 1) - (v->columns ? sw : 0), rows_n - BROWSER_CHROME_ROWS, v->intro,
                 sizeof v->intro);
    v->n_info = browser_info(b, kind, v->info);
}

static void browser_render(const browser_page_t *v, int rows_n, int cols_n, const char *title, const char *clock,
                           const char *help, const char *usage, const tui_bar_t *bar) {
    const browser_t *b = &g_app.browser;
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .intro = v->intro,
        .nav = v->info, .n_nav = v->n_info, .nav_sel = 0,
        .side = v->columns ? v->side : NULL, .n_side = v->n_side, .side_sel = v->side_sel, .side_title = v->side_title,
        .rows = g_browser_rows, .n_rows = g_browser_levels + b->n_items, .selected = g_browser_levels + b->selected,
        .help = help, .usage = usage,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

void render_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const browser_t *b = &g_app.browser;
    int age = g_app.key.load_kind == IDENT_AGE;
    static browser_page_t v;
    browser_lay_out(&v, rows_n, cols_n, g_app.key.load_kind);
    char help[700], usage[1100] = "";
    if (!browser_folder_help(b, help, sizeof help)) {
        char full[1200], shown[1200];
        browser_entry_path(b, &b->items[b->selected], full, sizeof full);
        tilde_path(full, shown, sizeof shown);
        snprintf(help, sizeof help, "Enter uses %s as your %s key. " WHY_SECRET "It stays in memory and isn't sent. "
                 ":install saves this file's path, not the key.", g_browser_labels[b->selected], age ? "AGE" : "PGP");
        snprintf(usage, sizeof usage, ":set sign %s:%s", age ? "age" : "pgp", shown);
    }
    browser_render(&v, rows_n, cols_n,
                   age ? "Settings" CRUMB "Profile" CRUMB "Signing identity" CRUMB "AGE key file"
                       : "Settings" CRUMB "Profile" CRUMB "Signing identity" CRUMB "PGP key file",
                   clock, help, usage[0] ? usage : NULL, bar);
}

void render_send_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const browser_t *b = &g_app.browser;
    static browser_page_t v;
    browser_lay_out(&v, rows_n, cols_n, IDENT_NONE);
    char help[700];
    if (!browser_folder_help(b, help, sizeof help))
        snprintf(help, sizeof help, "Enter offers %s to everyone in this session. Nobody gets it unless they fetch it.",
                 g_browser_labels[b->selected]);
    browser_render(&v, rows_n, cols_n, "Send a file", clock, help, NULL, bar);
}

void render_save_browser(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const browser_t *b = &g_app.browser;
    static browser_page_t v;
    browser_lay_out(&v, rows_n, cols_n, IDENT_NONE);
    char help[1400], title[160];
    const file_entry_t *f = g_app.selected ? chat_file(&g_app.selected->engine, g_app.files.save_num) : NULL;
    char what[FILE_NAME_MAX + 48];
    if (f) {
        char sz[32]; file_format_size(f->size, sz, sizeof sz);
        snprintf(what, sizeof what, "%s (%s)", f->name, sz);
    } else {
        snprintf(what, sizeof what, "file %d", g_app.files.save_num);
    }
    snprintf(title, sizeof title, "Save file %d", g_app.files.save_num);
    char open_help[700] = "";
    if (b->n_items > 0 && b->items[b->selected].is_dir) browser_folder_help(b, open_help, sizeof open_help);
    snprintf(help, sizeof help, "s saves %s in %s.%s%s", what, b->path, open_help[0] ? " " : "", open_help);
    browser_render(&v, rows_n, cols_n, title, clock, help, NULL, bar);
}
