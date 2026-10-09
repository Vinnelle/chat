// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"
#include "changelog.h"

// The keys every list page shares: j/k or up/down move, g/G or Home/End go to the ends,
// Tab/Shift+Tab or PgDn/PgUp go to the next or previous section, Enter or space chooses, h/l or
// left/right go sideways (Backspace too, like vim's h), Esc goes back a level, and q or Ctrl+S
// closes the page.
list_key_t list_key(const tui_key_t *key) {
    switch (key->type) {
        case TUI_KEY_UP:        return LIST_UP;
        case TUI_KEY_DOWN:      return LIST_DOWN;
        case TUI_KEY_HOME:      return LIST_FIRST;
        case TUI_KEY_END:       return LIST_LAST;
        case TUI_KEY_TAB:
        case TUI_KEY_PAGE_DOWN: return LIST_NEXT_SECTION;
        case TUI_KEY_BACKTAB:
        case TUI_KEY_PAGE_UP:   return LIST_PREV_SECTION;
        case TUI_KEY_ENTER:     return LIST_CHOOSE;
        case TUI_KEY_LEFT:
        case TUI_KEY_BACKSPACE: return LIST_LEFT;
        case TUI_KEY_RIGHT:     return LIST_RIGHT;
        case TUI_KEY_ESCAPE:    return LIST_BACK;
        case TUI_KEY_SETTINGS:  return LIST_CLOSE;
        case TUI_KEY_CHAR:      break;
        default:                return LIST_NONE;
    }
    if (key->ch_len != 1) return LIST_NONE;
    switch (key->ch[0]) {
        case 'k': return LIST_UP;
        case 'j': return LIST_DOWN;
        case 'g': return LIST_FIRST;
        case 'G': return LIST_LAST;
        case ' ': return LIST_CHOOSE;
        case 'h': return LIST_LEFT;
        case 'l': return LIST_RIGHT;
        case 'q': return LIST_CLOSE;
        default:  return LIST_NONE;
    }
}

// 1 to 9 on a page with sections: the section, from 0, or -1 for any other key.
int section_digit(const tui_key_t *key) {
    if (key->type != TUI_KEY_CHAR || key->ch_len != 1 || key->ch[0] < '1' || key->ch[0] > '9') return -1;
    return key->ch[0] - '1';
}

void list_move(list_key_t k, int *sel, int n) {
    if (k == LIST_UP && *sel > 0) (*sel)--;
    else if (k == LIST_DOWN && *sel < n - 1) (*sel)++;
    else if (k == LIST_FIRST) *sel = 0;
    else if (k == LIST_LAST) *sel = n > 0 ? n - 1 : 0;
}

// Left/right on a row changes its value. On the Signing identity row, right opens the picker.
void settings_key(const tui_key_t *key) {
    const setting_def_t *d = g_app.settings_sel < N_SETTINGS ? &SETTINGS[g_app.settings_sel] : NULL;
    const char *const *names;
    int n;
    int steps = d && (setting_options(d->id, &names, &n) >= 0 || d->id == SET_COLOUR);
    int s = section_digit(key);
    if (s >= 0 && s < settings_n_sections()) settings_go_section(s);
    if (s >= 0) { g_app.dirty = 1; return; }
    switch (list_key(key)) {
        case LIST_UP:    settings_step(-1); break;
        case LIST_DOWN:  settings_step(1); break;
        case LIST_FIRST: settings_select(section_row(g_app.settings_page, 1)); break;
        case LIST_LAST:  g_app.settings_sel = SETTINGS_DONE; break;
        case LIST_NEXT_SECTION: settings_section_step(1); break;
        case LIST_PREV_SECTION: settings_section_step(-1); break;
        case LIST_LEFT:  if (steps) setting_step(d->id, -1); break;
        case LIST_RIGHT:
            if (steps) setting_step(d->id, 1);
            else if (d && d->id == SET_SIGN) begin_sign();
            else if (d && d->id == SET_SHADOW) begin_shadow();
            break;
        case LIST_CHOOSE:
            if (!d) settings_done();
            else if (steps && d->id != SET_COLOUR) setting_step(d->id, 1);
            else if (d->kind == K_TEXT || d->kind == K_SECRET) begin_setting_edit(d->id);
            else if (d->id == SET_SIGN) begin_sign();
            else if (d->id == SET_SHADOW) begin_shadow();
            else if (d->id == SET_AGE_RECIPIENT) copy_age_recipient();
            else if (d->id == SET_PGP_PUBKEY) copy_pgp_public_key();
            break;
        case LIST_BACK:
        case LIST_CLOSE: settings_done(); break;
        default: break;
    }
    settings_fix_sel();
    g_app.dirty = 1;
}

void sign_picker_key(const tui_key_t *key) {
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT:
            sign_pick(g_app.sign_sel);
            if (g_app.mode == MODE_SIGN_CHOICE) g_app.mode = MODE_SETTINGS;
            break;
        case LIST_LEFT:
        case LIST_BACK:  g_app.mode = MODE_SETTINGS; break;
        case LIST_CLOSE: settings_done(); break;
        default: list_move(k, &g_app.sign_sel, N_PICKS); break;
    }
    g_app.dirty = 1;
}

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
        begin_key_path(g_app.load_kind, start, 1);
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
void begin_send_browse(void) {
    if (g_app.mode != MODE_CHAT && g_app.mode != MODE_FILES) return;
    const char *home = platform_home_dir();
    if ((!g_app.send_dir[0] || browser_load(&g_app.browser, g_app.send_dir) != 0)
        && (!home || browser_load(&g_app.browser, home) != 0))
        browser_load(&g_app.browser, "/");
    g_app.browse_back = g_app.mode;
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
                g_app.mode = g_app.browse_back;
                if (!g_app.selected || g_app.selected->initialising) {
                    note("no session to send %.80s to", sel->name);
                    break;
                }
                copy_str(g_app.send_dir, b->path, sizeof g_app.send_dir);
                chat_t *e = &g_app.selected->engine;
                int was = e->file_seq;
                g_echo = 1;
                chat_send_file(e, full);
                g_echo = 0;
                if (e->file_seq != was) g_app.file_num = e->file_seq;
            }
            break;
        }
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = g_app.browse_back; break;
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
    if ((!g_app.save_dir[0] || browser_load(&g_app.browser, g_app.save_dir) != 0)
        && (platform_downloads_dir(dl, sizeof dl) != 0 || browser_load(&g_app.browser, dl) != 0)
        && (!home || browser_load(&g_app.browser, home) != 0))
        browser_load(&g_app.browser, "/");
    g_app.save_num = num;
    g_app.save_anyway = anyway;
    g_app.browse_back = g_app.mode;
    g_app.mode = MODE_SAVE_BROWSE;
    g_app.dirty = 1;
}

// Enter opens the selected folder and s saves in the one shown.
void save_browser_key(const tui_key_t *key) {
    browser_t *b = &g_app.browser;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && key->ch[0] == '~') { browser_home(); g_app.dirty = 1; return; }
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && key->ch[0] == 's') {
        g_app.mode = g_app.browse_back;
        g_app.dirty = 1;
        if (!g_app.selected || g_app.selected->initialising) { note("no session to save file %d from", g_app.save_num); return; }
        copy_str(g_app.save_dir, b->path, sizeof g_app.save_dir);
        g_echo = 1;
        chat_file_fetch(&g_app.selected->engine, g_app.save_num, 0, g_app.save_anyway, b->path);
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
        case LIST_CLOSE: g_app.mode = g_app.browse_back; break;
        default: list_move(k, &b->selected, b->n_items); break;
    }
    g_app.dirty = 1;
}

// Everything except Esc is the paste arriving, one key at a time.
void paste_key(const tui_key_t *key) {
    if (key->type == TUI_KEY_ESCAPE) {
        paste_clear();
        g_app.mode = MODE_SIGN_CHOICE;
        g_app.dirty = 1;
        return;
    }
    size_t room = sizeof g_app.paste_buf - 1 - g_app.paste_len;
    if (key->type == TUI_KEY_CHAR && room >= (size_t)key->ch_len) {
        memcpy(g_app.paste_buf + g_app.paste_len, key->ch, (size_t)key->ch_len);
        g_app.paste_len += (size_t)key->ch_len;
    } else if ((key->type == TUI_KEY_ENTER || key->type == TUI_KEY_JOIN_SESSION) && room >= 1) {
        g_app.paste_buf[g_app.paste_len++] = '\n';
    } else if (key->type == TUI_KEY_BACKSPACE && g_app.paste_len > 0) {
        g_app.paste_len--;
    } else {
        return;
    }
    g_app.paste_buf[g_app.paste_len] = '\0';
    snprintf(g_app.paste_status, sizeof g_app.paste_status, "%zu bytes so far", g_app.paste_len);
    g_app.dirty = 1;
    int age = g_app.load_kind == IDENT_AGE;
    if (age) {
        // Read when the key's last line ends, so a pasted file's own newline doesn't end up on the settings page.
        const char *at = strstr(g_app.paste_buf, AGE_SECRET_KEY_PREFIX);
        if (!at || g_app.paste_buf[g_app.paste_len - 1] != '\n'
            || g_app.paste_len - 1 - (size_t)(at - g_app.paste_buf) < AGE_SECRET_KEY_STRLEN) return;
    } else {
        // Only look at the end, where the END line will be.
        size_t el = sizeof PGP_PRIVATE_END - 1;
        if (g_app.paste_len < el || memcmp(g_app.paste_buf + g_app.paste_len - el, PGP_PRIVATE_END, el) != 0) return;
    }
    int rc = age ? age_import_secret_key_text(g_app.paste_buf, &g_app.identity)
                 : pgp_import_secret_key_text(g_app.paste_buf, &g_app.identity);
    paste_clear();
    if (rc == 0) {
        g_app.identity_source = g_app.load_kind;
        g_app.key_origin = KEY_PASTED;
        identity_chosen();
        g_app.mode = MODE_SETTINGS;
    } else if (age) {
        note("that isn't an AGE secret key - paste another, or Esc");
    } else {
        note("that isn't an unencrypted EdDSA/Ed25519 secret key - paste another, or Esc");
    }
}

// ---- drawing the pages ----

#define CRUMB " \xe2\x80\xba "   // between the levels of a page's title

// Under its group's heading, a label doesn't repeat it: "Tor SOCKS port" under Tor is "SOCKS port".
static const char *page_label(const char *label, const char *group, char *out, size_t cap) {
    size_t n = group ? strlen(group) : 0;
    if (!n || strncmp(label, group, n) != 0 || label[n] != ' ') return label;
    copy_str(out, label + n + 1, cap);
    out[0] = (char)toupper((unsigned char)out[0]);
    return out;
}

void render_settings(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    tui_row_t rows[N_SETTINGS];
    char values[N_SETTINGS][160], labels[N_SETTINGS][64];
    int n_rows = 0, sel_row = -1, s = g_app.settings_page, end = section_begin(s + 1);
    const char *group = NULL, *heading = NULL;
    for (int i = section_begin(s); i < end; i++) {
        const setting_def_t *d = &SETTINGS[i];
        if (d->group) group = heading = d->group;   // the heading goes on its group's first listed row
        if (!setting_shown(d->id)) continue;
        if (i == g_app.settings_sel) sel_row = n_rows;
        setting_value(d->id, values[n_rows], sizeof values[n_rows]);
        int greyed = row_greyed(d->id);
        if (greyed) copy_str(values[n_rows], "can't be used here", sizeof values[n_rows]);
        rows[n_rows] = (tui_row_t){ heading, page_label(d->label, group, labels[n_rows], sizeof labels[n_rows]),
                                    values[n_rows], setting_kind(d), d->id == SET_COLOUR ? g_app.color : NULL,
                                    NULL, 0, greyed };
        heading = NULL;
        n_rows++;
    }
    if (g_app.settings_sel == SETTINGS_DONE) sel_row = n_rows;   // the Done button
    const setting_def_t *d = g_app.settings_sel < N_SETTINGS ? &SETTINGS[g_app.settings_sel] : NULL;
    char help[600], usage[96] = "";
    if (!d) {
        if (g_app.onboarding)
            snprintf(help, sizeof help, "Go on to your sessions: Ctrl+N creates one, Ctrl+J joins one. Everything here "
                     "applies at once%s", g_app.installed && g_app.autosave
                     ? ", and what you change is saved where :install put it."
                     : g_app.installed ? ", and with autosave off, lasts until chat exits unless you :save."
                     : g_app.locked ? " and isn't saved: what :install saved stays sealed until :install opens it."
                     : " and lasts until chat exits. It's only written to disk if you :install.");
        else
            snprintf(help, sizeof help, "Back to your sessions. Everything here already applies%s",
                     !g_app.installed ? "." : g_app.autosave ? ", and is saved." : ". Autosave is off: :save saves it.");
        copy_str(usage, "ctrl+s or :set brings this page back", sizeof usage);
    } else {
        // The row cuts off a recipient on a narrow screen, and not every terminal supports OSC 52.
        char recipient[AGE_RECIPIENT_STRLEN + 3] = "";
        if (d->id == SET_AGE_RECIPIENT && g_app.identity_source == IDENT_AGE) {
            age_export_recipient(&g_app.identity, recipient);
            strcat(recipient, ": ");
        }
        int greyed = row_greyed(d->id);
        if (greyed && d->id == SET_SECURITY_KEY)
            snprintf(help, sizeof help, "Can't be used here: %s. A security key's secret is only given after a touch, "
                     "and chat needs a way to ask it for one.", g_app.seckey_why);
        else if (greyed)
            snprintf(help, sizeof help, "Can't be used here: %s. The device lock makes the save unlock only on this "
                     "device, by sealing a secret with something the device keeps to itself: its TPM, on Linux "
                     "through systemd's credential service or /dev/tpmrm0. Without that, there's nothing to seal it "
                     "with.",
                     g_app.device_why);
        else
            snprintf(help, sizeof help, "%s%s", recipient, d->help);
        if (d->values && !greyed) snprintf(usage, sizeof usage, ":set %s %s", d->key, d->values);
        else if (d->kind == K_SECRET) snprintf(usage, sizeof usage, ":set %s", d->key);
    }
    const char *nav[8];
    char title[64];
    snprintf(title, sizeof title, "Settings" CRUMB "%s", SETTINGS[section_begin(s)].section);
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .intro = g_app.onboarding
            ? "chat is an end-to-end encrypted chat with no server. Check how it reaches peers, then press "
              "Start chatting. Nothing goes on the network before that."
            : NULL,
        .nav = nav, .n_nav = settings_sections(nav, 8), .nav_sel = s,
        .rows = rows, .n_rows = n_rows, .selected = sel_row,
        .help = help, .usage = usage[0] ? usage : NULL,
        .button = g_app.onboarding ? "Start chatting" : "Done",
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

void render_sign_picker(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    tui_row_t rows[N_PICKS];
    int in_use = sign_row_in_use();
    for (int i = 0; i < N_PICKS; i++) {
        rows[i] = (tui_row_t){ SIGN_PICKS[i].section, SIGN_PICKS[i].label, NULL, TUI_V_TEXT, NULL, NULL, 0, 0 };
        if (i == in_use) { rows[i].value = "in use"; rows[i].kind = TUI_V_ON; }
    }
    char help[600], usage[32] = "";
    char now[160]; setting_value(SET_SIGN, now, sizeof now);
    snprintf(help, sizeof help, "%s Now: %s.", SIGN_PICKS[g_app.sign_sel].help, now);
    static const char *const SET[N_PICKS] = { "off", "age", "age:PATH", "age:PATH", NULL, "pgp", "pgp:PATH", "pgp:PATH", NULL };
    if (SET[g_app.sign_sel]) snprintf(usage, sizeof usage, ":set sign %s", SET[g_app.sign_sel]);
    const char *nav[8];
    tui_page_t page = {
        .title = "Settings" CRUMB "Profile" CRUMB "Signing identity",
        .clock = clock,
        .nav = nav, .n_nav = settings_sections(nav, 8), .nav_sel = settings_section_index(SET_SIGN),
        .rows = rows, .n_rows = N_PICKS, .selected = g_app.sign_sel,
        .help = help, .usage = usage[0] ? usage : NULL,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

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
    int age = g_app.load_kind == IDENT_AGE;
    static browser_page_t v;
    browser_lay_out(&v, rows_n, cols_n, g_app.load_kind);
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
    const file_entry_t *f = g_app.selected ? chat_file(&g_app.selected->engine, g_app.save_num) : NULL;
    char what[FILE_NAME_MAX + 48];
    if (f) {
        char sz[32]; file_format_size(f->size, sz, sizeof sz);
        snprintf(what, sizeof what, "%s (%s)", f->name, sz);
    } else {
        snprintf(what, sizeof what, "file %d", g_app.save_num);
    }
    snprintf(title, sizeof title, "Save file %d", g_app.save_num);
    char open_help[700] = "";
    if (b->n_items > 0 && b->items[b->selected].is_dir) browser_folder_help(b, open_help, sizeof open_help);
    snprintf(help, sizeof help, "s saves %s in %s.%s%s", what, b->path, open_help[0] ? " " : "", open_help);
    browser_render(&v, rows_n, cols_n, title, clock, help, NULL, bar);
}

typedef enum { FS_NEW, FS_OVER, FS_COMING, FS_QUEUED, FS_FAILED, FS_SAVED, FS_HERE, FS_BROKEN, FS_MINE } file_state_t;

// ---- the files page, and a picture on a page of its own ----

// What a y/n box over the files page or the picture asks.
enum { ASK_VIEW = 1, ASK_SHOW, ASK_FETCH, ASK_RETRY, ASK_SAVETO, ASK_STOP, ASK_UNOFFER };

static const pic_t *pic_of(const session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used && s->pics[i].num == num) return &s->pics[i];
    return NULL;
}

static file_state_t file_state(const session_slot_t *s, const file_entry_t *f) {
    if (f->mine) return FS_MINE;
    if (f->dl == DL_ACTIVE) return FS_COMING;
    if (f->dl == DL_QUEUED) return FS_QUEUED;
    if (f->dl == DL_FAILED) return FS_FAILED;
    if (f->saved[0]) return FS_SAVED;
    const pic_t *p = pic_of(s, f->num);
    if (f->cache || (p && p->th.rgb)) return FS_HERE;
    if (p && p->why[0]) return FS_BROKEN;
    return f->size > chat_file_cap(&s->engine) ? FS_OVER : FS_NEW;
}

// Fetching f now would take it past the size limit: it's over, and there's no copy here to use instead.
static int file_needs_anyway(const session_slot_t *s, const file_entry_t *f) {
    return !f->mine && f->size > chat_file_cap(&s->engine) && !f->cache && !f->saved[0] && f->dl != DL_ACTIVE && f->dl != DL_QUEUED;
}

static int file_cmp(const void *a, const void *b) {
    const file_entry_t *x = *(const file_entry_t *const *)a, *y = *(const file_entry_t *const *)b;
    return x->mine != y->mine ? x->mine - y->mine : y->num - x->num;
}

// The session's files in the page's order: those offered to you, then yours, newest first.
static int files_list(const session_slot_t *s, const file_entry_t **l) {
    int n = 0;
    for (int i = 0; s && !s->initialising && i < FILE_OFFERS_MAX; i++)
        if (s->engine.files[i].used) l[n++] = &s->engine.files[i];
    qsort(l, (size_t)n, sizeof *l, file_cmp);
    return n;
}

static int files_sel(const file_entry_t *const *l, int n) {
    for (int i = 0; i < n; i++) if (l[i]->num == g_app.file_num) return i;
    return 0;
}

static const file_entry_t *selected_file(void) {
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(g_app.selected, l);
    return n ? l[files_sel(l, n)] : NULL;
}

static void file_owner_name(const chat_t *e, const file_entry_t *f, char out[CHAT_NAME_LEN]) {
    if (f->mine) { copy_str(out, "you", CHAT_NAME_LEN); return; }
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        const peer_t *p = &e->peers[i];
        if (p->used && memcmp(p->id, f->owner, ID_LEN) == 0) { chat_peer_name(e, p, out); return; }
    }
    copy_str(out, "someone who left", CHAT_NAME_LEN);
}

static tui_value_kind_t file_value(const session_slot_t *s, const file_entry_t *f, char *out, size_t cap, int *permille) {
    char sz[32]; file_format_size(f->size, sz, sizeof sz);
    *permille = 0;
    switch (file_state(s, f)) {
        case FS_MINE: {
            char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
            int pm, n = chat_file_sending(&s->engine, f, now_seconds(), name, &pm);
            chat_file_sent_to(f, to, sizeof to);
            if (n) {
                *permille = pm;
                snprintf(out, cap, "%d%%" DOT_SEP "sending to %s%s", pm / 10, name, n > 1 ? " and others" : "");
                return TUI_V_PROGRESS;
            }
            if (to[0]) { snprintf(out, cap, "sent to %s", to); return TUI_V_ON; }
            if (!f->fp) { snprintf(out, cap, "no longer offered"); return TUI_V_MUTED; }
            snprintf(out, cap, "offered" DOT_SEP "%s", sz);
            return TUI_V_TEXT;
        }
        case FS_COMING:
        case FS_QUEUED: *permille = fetch_progress(&s->engine, f, out, cap); return TUI_V_PROGRESS;
        case FS_FAILED: snprintf(out, cap, "%s", f->why[0] ? f->why : "it didn't finish"); return TUI_V_BAD;
        case FS_SAVED:  snprintf(out, cap, "saved" DOT_SEP "%s", sz); return TUI_V_ON;
        case FS_HERE: {
            const pic_t *p = pic_of(s, f->num);
            snprintf(out, cap, "%s" DOT_SEP "%s", p && p->shown && p->th.rgb ? "shown" : "here, hidden", sz);
            return TUI_V_ON;
        }
        case FS_BROKEN: snprintf(out, cap, "can't be shown"); return TUI_V_BAD;
        case FS_OVER:   snprintf(out, cap, "%s" DOT_SEP "over your size limit", sz); return TUI_V_OFF;
        default:        snprintf(out, cap, "%s" DOT_SEP "%s", f->image ? "picture" : "file", sz); return TUI_V_OFF;
    }
}

#define DETAIL_LINES 24
#define DETAIL_LINE_MAX 128

static int add_wrapped(char lines[][DETAIL_LINE_MAX], int n, const char *t, int width) {
    size_t len = strlen(t);
    if (len == 0 && n < DETAIL_LINES) lines[n++][0] = '\0';
    while (len > 0 && n < DETAIL_LINES) {
        size_t fit = utf8_fit_cols(t, len, width, NULL);
        if (fit == 0) utf8_char_cols(t, len, 0, &fit);
        if (fit < len) {
            size_t sp = fit;
            while (sp > 0 && t[sp] != ' ') sp--;
            if (sp > 0) fit = sp;
        }
        snprintf(lines[n++], DETAIL_LINE_MAX, "%.*s", (int)(fit < DETAIL_LINE_MAX - 1 ? fit : DETAIL_LINE_MAX - 1), t);
        t += fit;
        len -= fit;
        while (len > 0 && *t == ' ') { t++; len--; }
    }
    return n;
}

static int file_details(const session_slot_t *s, const file_entry_t *f, int width, const char **out) {
    static char lines[DETAIL_LINES][DETAIL_LINE_MAX];
    char t[900], sz[32], who[CHAT_NAME_LEN];
    int n = 0;
    if (width < 8) return 0;
    file_format_size(f->size, sz, sizeof sz);
    file_owner_name(&s->engine, f, who);
    n = add_wrapped(lines, n, f->name, width);
    n = add_wrapped(lines, n, "", width);
    snprintf(t, sizeof t, "%s" DOT_SEP "%s", f->image ? "picture" : "file", sz);
    n = add_wrapped(lines, n, t, width);
    if (f->mine) copy_str(t, "yours", sizeof t);
    else snprintf(t, sizeof t, "from %s", who);
    n = add_wrapped(lines, n, t, width);
    snprintf(t, sizeof t, "file %d, at %s", f->num, f->at[0] ? f->at : "--:--");
    n = add_wrapped(lines, n, t, width);
    n = add_wrapped(lines, n, "", width);
    char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
    int pm;
    switch (file_state(s, f)) {
        case FS_MINE:
            chat_file_sent_to(f, to, sizeof to);
            if (chat_file_sending(&s->engine, f, now_seconds(), name, &pm)) snprintf(t, sizeof t, "sending to %s: %d%%", name, pm / 10);
            else snprintf(t, sizeof t, "%s", f->fp ? "offered to everyone here" : "no longer offered");
            n = add_wrapped(lines, n, t, width);
            if (to[0]) { snprintf(t, sizeof t, "sent to %s", to); n = add_wrapped(lines, n, t, width); }
            break;
        case FS_COMING:
        case FS_QUEUED: {
            fetch_progress(&s->engine, f, t, sizeof t);
            for (char *part = t, *next; part; part = next) {
                next = strstr(part, DOT_SEP);
                if (next) { *next = '\0'; next += sizeof DOT_SEP - 1; }
                n = add_wrapped(lines, n, part, width);
            }
            break;
        }
        case FS_FAILED:
            snprintf(t, sizeof t, "failed: %s", f->why[0] ? f->why : "it didn't finish");
            n = add_wrapped(lines, n, t, width);
            break;
        case FS_SAVED: {
            char where[sizeof f->saved];
            tilde_path(f->saved, where, sizeof where);
            char *slash = strrchr(where, '/');
            n = add_wrapped(lines, n, "saved in", width);
            if (slash) { *slash = '\0'; n = add_wrapped(lines, n, where[0] ? where : "/", width); }
            snprintf(t, sizeof t, "as %s", slash ? slash + 1 : where);
            n = add_wrapped(lines, n, t, width);
            break;
        }
        case FS_HERE: {
            const pic_t *p = pic_of(s, f->num);
            n = add_wrapped(lines, n, p && p->shown && p->th.rgb ? "shown in the chat" : "here, hidden in the chat", width);
            n = add_wrapped(lines, n, "only in memory", width);
            break;
        }
        case FS_BROKEN:
            snprintf(t, sizeof t, "can't be shown: %s", pic_why(s, f->num));
            n = add_wrapped(lines, n, t, width);
            break;
        case FS_OVER: {
            char lim[32]; file_format_size(chat_file_cap(&s->engine), lim, sizeof lim);
            snprintf(t, sizeof t, "not fetched, and over your %s limit", lim);
            n = add_wrapped(lines, n, t, width);
            break;
        }
        default:
            n = add_wrapped(lines, n, "not fetched yet", width);
            break;
    }
    for (int i = 0; i < n; i++) out[i] = lines[i];
    return n;
}

// What Enter does with f, for the bottom row, or NULL for nothing.
static const char *file_enter(const session_slot_t *s, const file_entry_t *f) {
    file_state_t st = file_state(s, f);
    if (f->image && st != FS_BROKEN) return st == FS_NEW || st == FS_OVER || st == FS_FAILED ? "show" : "view";
    if (st == FS_NEW || st == FS_OVER) return "download";
    return st == FS_FAILED ? "retry" : NULL;
}

// usage gets the command that does what Enter does.
static void file_help(const session_slot_t *s, const file_entry_t *f, char *help, size_t cap, char *usage, size_t ucap) {
    char who[CHAT_NAME_LEN], where[sizeof f->saved] = "";
    file_owner_name(&s->engine, f, who);
    if (f->saved[0]) tilde_path(f->saved, where, sizeof where);
    const char *save = "d saves it in Downloads, s in a folder you pick.";
    usage[0] = '\0';
    switch (file_state(s, f)) {
        case FS_MINE:
            if (!f->fp) snprintf(help, cap, "Yours, and no longer offered. :send offers it again, as a new file.");
            else snprintf(help, cap, "Yours, offered to everyone here%s.%s x stops offering it.",
                          s->engine.verify_required ? " whose verify code you've compared" : "",
                          f->image ? " Enter shows it big." : "");
            if (f->fp) snprintf(usage, ucap, ":cancel %d", f->num);
            return;
        case FS_COMING:
        case FS_QUEUED:
            snprintf(help, cap, "%s%s x stops it.", f->dl == DL_QUEUED ? "Queued: one file comes from each sender at a time." : "On its way.",
                     f->image ? " Enter shows how far it's got, then the picture." : "");
            snprintf(usage, ucap, ":cancel %d", f->num);
            return;
        case FS_FAILED:
            snprintf(help, cap, "Failed: %s. Enter tries again. %s", f->why[0] ? f->why : "it stopped", save);
            snprintf(usage, ucap, ":%s %d", f->image ? "show" : "download", f->num);
            return;
        case FS_SAVED:
            snprintf(help, cap, "Saved as %s.%s y copies where it is, s saves a copy in another folder.", where,
                     f->image ? " Enter shows it big, v in the chat." : "");
            snprintf(usage, ucap, ":saveto %d", f->num);
            return;
        case FS_HERE:
            snprintf(help, cap, "Enter shows it big, v shows or hides it in the chat. It's only in memory: %s", save);
            snprintf(usage, ucap, ":download %d", f->num);
            return;
        case FS_BROKEN:
            snprintf(help, cap, "chat can't show it (%s). d saves it in Downloads, to open with something else.", pic_why(s, f->num));
            snprintf(usage, ucap, ":download %d", f->num);
            return;
        default: {
            const char *over = file_state(s, f) == FS_OVER ? " It's over your file size limit, so chat asks first." : "";
            if (f->image)
                snprintf(help, cap, "%s offers it. Enter fetches it and shows it big, and in the chat under the offer. %s%s",
                         who, save, over);
            else
                snprintf(help, cap, "%s offers it. Enter saves it in Downloads, s in a folder you pick. Nothing is fetched until "
                         "you ask.%s", who, over);
            snprintf(usage, ucap, ":%s %d%s", f->image ? "show" : "download", f->num, *over ? " anyway" : "");
            return;
        }
    }
}

void file_ask(int what, const file_entry_t *f) {
    g_app.file_ask = what;
    g_app.file_ask_num = f->num;
    g_app.file_back = g_app.mode;
    g_app.mode = MODE_FILE_ASK;
}

// The engine's reply goes on the bottom bar, since the page covers the console.
int echo_fetch(session_slot_t *s, int num, int view, int anyway, const char *dir) {
    g_echo = 1;
    int r = chat_file_fetch(&s->engine, num, view, anyway, dir);
    g_echo = 0;
    return r;
}

static void echo_cancel(session_slot_t *s, int num) {
    char cmd[32];
    snprintf(cmd, sizeof cmd, "cancel %d", num);
    g_echo = 1;
    chat_run_command(&s->engine, cmd);
    g_echo = 0;
}

static void file_download(session_slot_t *s, const file_entry_t *f) {
    if (f->mine) note("file %d is yours", f->num);
    else if (file_needs_anyway(s, f)) file_ask(ASK_FETCH, f);
    else echo_fetch(s, f->num, 0, 0, NULL);
}

static void file_save_in(session_slot_t *s, const file_entry_t *f) {
    if (f->mine) note("file %d is yours", f->num);
    else if (file_needs_anyway(s, f)) file_ask(ASK_SAVETO, f);
    else begin_save_browse(f->num, 0);
}

static void file_toggle_shown(session_slot_t *s, const file_entry_t *f) {
    if (!f->image) { note("only pictures are shown in the chat - d saves %s", f->name); return; }
    pic_t *p = pic_find(s, f->num);
    if (p && p->th.rgb) {
        p->shown = !p->shown;
        note(p->shown ? "file %d is shown in the chat" : "file %d is hidden in the chat - v shows it again", f->num);
    } else if (file_needs_anyway(s, f)) {
        file_ask(ASK_SHOW, f);
    } else {
        echo_fetch(s, f->num, 1, 0, NULL);
    }
}

static void file_stop(session_slot_t *s, const file_entry_t *f) {
    if (f->mine && f->fp) file_ask(ASK_UNOFFER, f);
    else if (f->mine) note("file %d isn't offered any more", f->num);
    else if (f->dl == DL_ACTIVE) file_ask(ASK_STOP, f);
    else if (f->dl == DL_QUEUED) echo_cancel(s, f->num);
    else note("file %d isn't on its way - there's nothing to stop", f->num);
}

static void file_copy_path(const file_entry_t *f) {
    if (!f->saved[0]) { note(f->mine ? "file %d is yours, not a copy chat saved" : "file %d isn't saved - d saves it", f->num); return; }
    osc52_copy(f->saved);
    char where[sizeof f->saved];
    tilde_path(f->saved, where, sizeof where);
    note("copied %s to the clipboard (OSC 52)", where);
}

// The keys the files page and the picture share. Returns 1 if ch is one of them.
static int file_action(char ch, session_slot_t *s, const file_entry_t *f) {
    switch (ch) {
        case 'd': file_download(s, f); return 1;
        case 's': file_save_in(s, f); return 1;
        case 'v': file_toggle_shown(s, f); return 1;
        case 'x': file_stop(s, f); return 1;
        case 'y': file_copy_path(f); return 1;
        default:  return 0;
    }
}

// Enter: a picture opens on a page of its own, fetched first if it isn't here. A file is saved in
// Downloads, or where it was going if that failed.
static void file_open(session_slot_t *s, const file_entry_t *f) {
    file_state_t st = file_state(s, f);
    if (f->image && st != FS_BROKEN) {
        if (st == FS_NEW || st == FS_OVER || st == FS_FAILED) {
            if (file_needs_anyway(s, f)) { file_ask(ASK_VIEW, f); return; }
            if (echo_fetch(s, f->num, 1, 0, NULL) != 0) return;
        }
        g_app.mode = MODE_FILE_VIEW;
        return;
    }
    switch (st) {
        case FS_MINE:   note("file %d is yours - x stops offering it", f->num); break;
        case FS_BROKEN: note("chat can't show it (%s) - d saves it", pic_why(s, f->num)); break;
        case FS_COMING: note("file %d is on its way - x stops it", f->num); break;
        case FS_QUEUED: note("file %d is queued - x takes it off the queue", f->num); break;
        case FS_SAVED: {
            char where[sizeof f->saved];
            tilde_path(f->saved, where, sizeof where);
            note("saved as %s - y copies where it is", where);
            break;
        }
        case FS_FAILED:
            if (file_needs_anyway(s, f)) file_ask(ASK_RETRY, f);
            else echo_fetch(s, f->num, 0, 0, f->save_dir);
            break;
        default: file_download(s, f); break;
    }
}

void file_ask_yes(void) {
    session_slot_t *s = g_app.selected;
    int num = g_app.file_ask_num;
    g_app.mode = g_app.file_back;
    g_app.dirty = 1;
    const file_entry_t *f = s && !s->initialising ? chat_file(&s->engine, num) : NULL;
    if (!f) return;
    switch (g_app.file_ask) {
        case ASK_VIEW:    if (echo_fetch(s, num, 1, 1, NULL) == 0) g_app.mode = MODE_FILE_VIEW; break;
        case ASK_SHOW:    echo_fetch(s, num, 1, 1, NULL); break;
        case ASK_FETCH:   echo_fetch(s, num, 0, 1, NULL); break;
        case ASK_RETRY: {
            char dir[sizeof f->save_dir];
            copy_str(dir, f->save_dir, sizeof dir);
            echo_fetch(s, num, 0, 1, dir);
            break;
        }
        case ASK_SAVETO:  begin_save_browse(num, 1); break;
        case ASK_STOP:
        case ASK_UNOFFER: echo_cancel(s, num); break;
        default: break;
    }
}

void file_ask_no(void) {
    g_app.mode = g_app.file_back;
    g_app.dirty = 1;
}

int file_ask_paras(tui_para_t *paras, const char **title, const char **keys) {
    static char text[900];
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = s && !s->initialising ? chat_file(&s->engine, g_app.file_ask_num) : NULL;
    if (!f) { *title = "FILES"; *keys = "n back"; return add_para(paras, 0, TUI_P_TEXT, "That file isn't here any more."); }
    char sz[32], lim[32];
    file_format_size(f->size, sz, sizeof sz);
    file_format_size(chat_file_cap(&s->engine), lim, sizeof lim);
    switch (g_app.file_ask) {
        case ASK_STOP: {
            char got[32]; file_format_size(chat_file_got(f), got, sizeof got);
            *title = "STOP";
            *keys = "y stop" DOT_SEP "n keep it coming";
            snprintf(text, sizeof text, "Stop fetching `%s`? The %s that's come so far is thrown away, and fetching it again "
                     "starts from the beginning.", f->name, got);
            break;
        }
        case ASK_UNOFFER:
            *title = "STOP";
            *keys = "y stop offering" DOT_SEP "n keep offering";
            snprintf(text, sizeof text, "Stop offering `%s`? Nobody can fetch it after this, and anyone fetching it now stops. "
                     "`:send` offers it again, as a new file.", f->name);
            break;
        default: {
            char eta[48], took[160] = "";
            double left = chat_file_eta(&s->engine, f, now_seconds());
            if (left >= 0.0) {
                char who[CHAT_NAME_LEN];
                file_owner_name(&s->engine, f, who);
                file_format_duration(left, eta, sizeof eta);
                snprintf(took, sizeof took, " At chat's normal rate it takes %s to come, less if %s has fast transfers on.", eta, who);
            }
            int ask = g_app.file_ask;
            *title = "OVER YOUR LIMIT";
            *keys = "y fetch it" DOT_SEP "n cancel";
            snprintf(text, sizeof text, "`%s` is %s, over your %s file size limit. Fetch it anyway%s?%s", f->name, sz, lim,
                     ask == ASK_SAVETO ? ", into a folder you pick" : ask == ASK_VIEW || ask == ASK_SHOW ? ", to show it" : "", took);
            break;
        }
    }
    return add_para(paras, 0, TUI_P_TEXT, text);
}

const char *files_hint(void) {
    static char hint[200];
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = selected_file();
    if (!f) return "n send a file" DOT_SEP "esc close";
    const char *enter = file_enter(s, f);
    file_state_t st = file_state(s, f);
    snprintf(hint, sizeof hint, "%s%s%s%s%s%sn send" DOT_SEP "esc close", enter ? "enter " : "", enter ? enter : "",
             enter ? DOT_SEP : "", f->saved[0] ? "y copy path" DOT_SEP : "",
             f->mine ? "" : "d download" DOT_SEP "s save in" DOT_SEP,
             (f->mine && f->fp) || st == FS_COMING || st == FS_QUEUED ? "x stop" DOT_SEP : "");
    return hint;
}

void begin_files(void) {
    if (g_app.mode != MODE_CHAT) return;
    session_slot_t *s = g_app.selected;
    if (!s || s->initialising) { note("no session open - ctrl+n starts one, ctrl+j joins one"); return; }
    // The newest file, since that's usually the one to do something with.
    g_app.file_num = s->engine.file_seq;
    g_app.mode = MODE_FILES;
    g_app.dirty = 1;
}

void render_files(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    static tui_row_t rows[FILE_OFFERS_MAX];
    static char values[FILE_OFFERS_MAX][160], prefix[FILE_OFFERS_MAX][24];
    static char title[MAX_SESSION_NAME + 16], intro[200], help[1200], usage[64];
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n), digits = 1, theirs = 0, coming = 0;
    snprintf(title, sizeof title, "%s" CRUMB "Files", s ? s->name : "");
    for (int i = 0; i < n; i++) {
        char d[12];
        int w = snprintf(d, sizeof d, "%d", l[i]->num);
        if (w > digits) digits = w;
        theirs += !l[i]->mine;
        coming += l[i]->dl == DL_ACTIVE || l[i]->dl == DL_QUEUED;
    }
    for (int i = 0; i < n; i++) {
        int pm;
        tui_value_kind_t kind = file_value(s, l[i], values[i], sizeof values[i], &pm);
        snprintf(prefix[i], sizeof prefix[i], "%*d  ", digits, l[i]->num);
        const char *section = i == 0 || l[i]->mine != l[i - 1]->mine ? (l[i]->mine ? "Yours" : "Offered to you") : NULL;
        rows[i] = (tui_row_t){ section, l[i]->name, values[i], kind, NULL, prefix[i], pm, 0 };
    }
    char parts[3][40];
    int np = 0;
    if (theirs) snprintf(parts[np++], sizeof parts[0], "%d offered to you", theirs);
    if (coming) snprintf(parts[np++], sizeof parts[0], "%d on the way", coming);
    if (n - theirs) snprintf(parts[np++], sizeof parts[0], "%d yours", n - theirs);
    if (!n) snprintf(intro, sizeof intro, "Nothing's been offered here yet.");
    else snprintf(intro, sizeof intro, "%s%s%s%s%s", parts[0], np > 1 ? DOT_SEP : "", np > 1 ? parts[1] : "",
                  np > 2 ? DOT_SEP : "", np > 2 ? parts[2] : "");
    const char *nav[DETAIL_LINES];
    int n_nav = 0;
    usage[0] = '\0';
    if (n) {
        n_nav = file_details(s, l[sel], tui_nav_text_cols(cols_n), nav);
        file_help(s, l[sel], help, sizeof help, usage, sizeof usage);
    } else {
        snprintf(help, sizeof help, "n picks a file to send, or :send PATH. What others offer shows up here, and nothing is "
                 "fetched until you ask.");
    }
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .intro = intro,
        .nav = n_nav ? nav : NULL, .n_nav = n_nav, .nav_sel = 0,
        .rows = rows, .n_rows = n, .selected = sel,
        .help = help, .usage = usage[0] ? usage : NULL,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

void files_key(const tui_key_t *key) {
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n);
    const file_entry_t *f = n ? l[sel] : NULL;
    g_app.dirty = 1;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1) {
        if (key->ch[0] == 'n') { begin_send_browse(); return; }
        if (f && file_action(key->ch[0], s, f)) return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT: if (f) file_open(s, f); break;
        case LIST_LEFT:
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = MODE_CHAT; break;
        case LIST_NEXT_SECTION:
        case LIST_PREV_SECTION:
            for (int i = 0; i < n; i++) if (l[i]->mine != (f && f->mine)) { g_app.file_num = l[i]->num; break; }
            break;
        default:
            list_move(k, &sel, n);
            if (n) g_app.file_num = l[sel]->num;
            break;
    }
}

// The picture on its own page, decoded to fit the screen. It's decoded again for another file or
// size, or when its bytes may have come.
typedef struct {
    const session_slot_t *s;
    int num, w, h;
    unsigned sig;
    image_thumb_t th;
    tui_image_t ti;
    char why[160];
} picture_view_t;

static picture_view_t g_view;

static void view_drop(void) {
    thumb_free(&g_view.th);
    memset(&g_view, 0, sizeof g_view);
}

void view_forget(const session_slot_t *s) {
    if (g_view.s == s) view_drop();
}

// What the picture page shows for f depends on: its download's state, in the bits below SIG_CACHED, and these.
enum { SIG_CACHED = 8, SIG_SAVED = 16, SIG_OFFERED = 32 };

static unsigned view_sig(const file_entry_t *f) {
    return (unsigned)f->dl | (f->cache ? SIG_CACHED : 0u) | (f->saved[0] ? SIG_SAVED : 0u) | (f->fp ? SIG_OFFERED : 0u);
}

static void view_update(session_slot_t *s, const file_entry_t *f, int w, int h) {
    if (g_view.s == s && g_view.num == f->num && g_view.w == w && g_view.h == h && g_view.sig == view_sig(f)) return;
    view_drop();
    g_view.s = s;
    g_view.num = f->num;
    g_view.w = w;
    g_view.h = h;
    const uint8_t *b = f->dl == DL_ACTIVE || f->dl == DL_QUEUED ? NULL : chat_file_bytes(&s->engine, f->num);
    static const uint8_t bg[3] = { 0, 0, 0 };
    if (b && image_thumbnail(b, (size_t)f->size, w, h, bg, &g_view.th, g_view.why, sizeof g_view.why) == 0)
        g_view.ti = (tui_image_t){ g_view.th.w, g_view.th.h, g_view.th.rgb };
    g_view.sig = view_sig(f);
}

void render_viewer(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    static char title[MAX_SESSION_NAME + FILE_NAME_MAX + 32], caption[400], text[700];
    static tui_progress_t pg;
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = selected_file();
    tui_picture_t pic = { .title = title, .clock = clock, .caption = caption };
    caption[0] = '\0';
    if (!f || !f->image) {
        snprintf(title, sizeof title, "%s" CRUMB "Files", s ? s->name : "");
        pic.note = "That picture isn't here any more\nesc goes back to the files";
        tui_render_picture(rows_n, cols_n, &pic, bar, g_app.color_enabled);
        return;
    }
    snprintf(title, sizeof title, "%s" CRUMB "Files" CRUMB "%s", s->name, f->name);
    int w, h;
    tui_picture_room(rows_n, cols_n, &w, &h);
    view_update(s, f, w, h);

    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), at = 0, pics = 0;
    for (int i = 0; i < n; i++) if (l[i]->image) { pics++; if (l[i] == f) at = pics; }
    char sz[32], who[CHAT_NAME_LEN], dims[32] = "", of[40] = "";
    file_format_size(f->size, sz, sizeof sz);
    file_owner_name(&s->engine, f, who);
    const pic_t *small = pic_of(s, f->num);
    file_state_t st = file_state(s, f);
    if (g_view.th.rgb) {
        pic.image = &g_view.ti;
        snprintf(dims, sizeof dims, "%d\xc3\x97%d" DOT_SEP, g_view.th.src_w, g_view.th.src_h);
    } else if (small && small->th.rgb && st != FS_COMING && st != FS_QUEUED) {
        // Only the small copy the chat shows is left: what was fetched has been dropped from memory.
        pic.image = &small->ti;
        snprintf(dims, sizeof dims, "small copy" DOT_SEP);
    }
    if (pics > 1) snprintf(of, sizeof of, DOT_SEP "%d of %d", at, pics);
    snprintf(caption, sizeof caption, "%s" DOT_SEP "%s%s" DOT_SEP "%s%s%s", f->name, dims, sz, f->mine ? "yours" : "from ",
             f->mine ? "" : who, of);
    if (!pic.image) {
        memset(&pg, 0, sizeof pg);
        switch (st) {
            case FS_COMING:
            case FS_QUEUED: {
                snprintf(text, sizeof text, "On its way\n%s from %s", sz, who);
                pg.permille = fetch_progress(&s->engine, f, pg.text, sizeof pg.text);
                // The bar has the percentage already.
                char *after = f->dl == DL_ACTIVE ? strstr(pg.text, DOT_SEP) : NULL;
                if (after) memmove(pg.text, after + sizeof DOT_SEP - 1, strlen(after + sizeof DOT_SEP - 1) + 1);
                pic.progress = &pg;
                break;
            }
            case FS_FAILED:
                snprintf(text, sizeof text, "It didn't finish\n%s\nenter tries again", f->why[0] ? f->why : "it stopped");
                break;
            case FS_OVER:
                snprintf(text, sizeof text, "Not fetched yet\n%s, over your file size limit\nenter fetches it, after asking", sz);
                break;
            case FS_NEW:
                snprintf(text, sizeof text, "Not fetched yet\n%s from %s\nenter fetches it" DOT_SEP "d saves it in Downloads", sz, who);
                break;
            case FS_MINE:
                snprintf(text, sizeof text, "It can't be shown\n%s", g_view.why[0] ? g_view.why
                         : f->fp ? "it's changed since you offered it" : "it isn't offered any more");
                break;
            default:
                if (g_view.why[0] || st == FS_BROKEN)
                    snprintf(text, sizeof text, "chat can't show this picture\n%s\nd saves it, to open with something else",
                             g_view.why[0] ? g_view.why : pic_why(s, f->num));
                else
                    snprintf(text, sizeof text, "It isn't here any more\nthe copy shown was dropped from memory, or the "
                             "saved one has changed\nenter fetches it again");
                break;
        }
        pic.note = text;
    }
    tui_render_picture(rows_n, cols_n, &pic, bar, g_app.color_enabled);
}

static void view_fetch(session_slot_t *s, const file_entry_t *f) {
    if (g_view.th.rgb && g_view.num == f->num) return;
    file_state_t st = file_state(s, f);
    if (st == FS_COMING || st == FS_QUEUED) note("on its way - it's shown here once it's come");
    else if (st == FS_MINE) note("it can't be shown - it's changed since you offered it, or isn't offered any more");
    else if (st == FS_BROKEN || g_view.why[0]) note("chat can't show it - d saves it");
    else if (file_needs_anyway(s, f)) file_ask(ASK_SHOW, f);
    else echo_fetch(s, f->num, 1, 0, NULL);
}

// The picture page: j and k go to the next and previous picture in the files page's order.
void viewer_key(const tui_key_t *key) {
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n);
    const file_entry_t *f = n ? l[sel] : NULL;
    g_app.dirty = 1;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && f && file_action(key->ch[0], s, f)) return;
    int pics[FILE_OFFERS_MAX], np = 0, at = -1;
    for (int i = 0; i < n; i++) if (l[i]->image) { if (i == sel) at = np; pics[np++] = i; }
    switch (list_key(key)) {
        case LIST_DOWN:  if (at + 1 < np) g_app.file_num = l[pics[at + 1]]->num; break;
        case LIST_UP:    if (at > 0) g_app.file_num = l[pics[at - 1]]->num; break;
        case LIST_FIRST: if (np) g_app.file_num = l[pics[0]]->num; break;
        case LIST_LAST:  if (np) g_app.file_num = l[pics[np - 1]]->num; break;
        case LIST_CHOOSE:
        case LIST_RIGHT: if (f) view_fetch(s, f); break;
        case LIST_LEFT:
        case LIST_BACK:  view_drop(); g_app.mode = MODE_FILES; break;
        case LIST_CLOSE: view_drop(); g_app.mode = MODE_CHAT; break;
        default: break;
    }
}

const char *viewer_hint(void) {
    static char hint[200];
    const file_entry_t *f = selected_file();
    if (!f) return "esc back";
    file_state_t st = file_state(g_app.selected, f);
    int fetch = !(g_view.th.rgb && g_view.num == f->num) && st != FS_MINE && st != FS_COMING && st != FS_QUEUED && st != FS_BROKEN;
    snprintf(hint, sizeof hint, "%sj/k next/previous" DOT_SEP "%sv in chat" DOT_SEP "esc back", fetch ? "enter fetch" DOT_SEP : "",
             f->mine ? "x stop offering" DOT_SEP : "d download" DOT_SEP "s save in" DOT_SEP);
    return hint;
}

// ---- :changelog ----

// The changelog built into this binary, as paragraphs of Markdown for the page to lay out:
// headings, list items (nested by their indent), numbered items, quotes, fenced code and rules,
// with a paragraph's continuation lines joined. The inline marks stay in the text.
static int changelog_paras(const tui_para_t **out) {
    static tui_para_t paras[1024];
    static char *text;
    static int n = -1;
    if (n >= 0) { *out = paras; return n; }
    n = 0;
    size_t len = strlen(CHANGELOG_TEXT);
    text = malloc(len + 1);
    if (!text) { *out = paras; return 0; }
    memcpy(text, CHANGELOG_TEXT, len + 1);
    const int max = (int)(sizeof paras / sizeof paras[0]) - 1;
    char *para = NULL;   // the paragraph a next line may join, if any
    int fenced = 0;
    for (char *line = text; line && n < max; ) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';
        char *next = eol ? eol + 1 : NULL;
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll - 1] == '\r' || (!fenced && line[ll - 1] == ' '))) line[--ll] = '\0';
        int indent = 0;
        while (line[indent] == ' ') indent++;
        char *raw = line, *t = line + indent;
        line = next;
        if (strncmp(t, "```", 3) == 0 || strncmp(t, "~~~", 3) == 0) {
            fenced = !fenced;
            para = NULL;
            continue;
        }
        if (fenced) {
            paras[n++] = (tui_para_t){ .kind = TUI_P_CODE, .text = raw };
            continue;
        }
        if (*t == '\0') {
            if (n > 0 && paras[n - 1].kind != TUI_P_BLANK) paras[n++] = (tui_para_t){ .kind = TUI_P_BLANK, .text = "" };
            para = NULL;
            continue;
        }
        int hashes = 0;
        while (t[hashes] == '#') hashes++;
        if (hashes > 0 && hashes <= 6 && t[hashes] == ' ') {
            para = NULL;
            if (hashes == 1) continue;   // the file's own title: the page has its own
            paras[n++] = (tui_para_t){ .kind = hashes == 2 ? TUI_P_HEADING : TUI_P_SUBHEADING, .text = t + hashes + 1 };
            continue;
        }
        // A rule: three or more of one of - * _, nothing else but spaces.
        if (*t == '-' || *t == '*' || *t == '_') {
            int marks = 0, other = 0;
            for (const char *p = t; *p; p++) {
                if (*p == *t) marks++;
                else if (*p != ' ') other = 1;
            }
            if (marks >= 3 && !other) {
                paras[n++] = (tui_para_t){ .kind = TUI_P_RULE, .text = "" };
                para = NULL;
                continue;
            }
        }
        if ((*t == '-' || *t == '*' || *t == '+') && t[1] == ' ') {
            para = t + 2;
            paras[n++] = (tui_para_t){ .kind = TUI_P_BULLET, .text = para, .level = indent / 2 };
            continue;
        }
        int digits = 0;
        while (t[digits] >= '0' && t[digits] <= '9') digits++;
        if (digits > 0 && digits <= 6 && (t[digits] == '.' || t[digits] == ')') && t[digits + 1] == ' ') {
            tui_para_t p = { .kind = TUI_P_NUMBERED, .level = indent / 3 };
            memcpy(p.marker, t, (size_t)digits + 1);
            p.marker[digits + 1] = '\0';
            para = t + digits + 2;
            p.text = para;
            paras[n++] = p;
            continue;
        }
        int quote = *t == '>';
        if (quote) { t++; while (*t == ' ') t++; }
        // A line under a paragraph continues it (a quote only continues under a quote). The NUL that
        // ended the paragraph becomes a space.
        if (para && *t && (!quote || paras[n - 1].kind == TUI_P_QUOTE)) {
            size_t pl = strlen(para);
            memmove(para + pl + 1, t, strlen(t) + 1);
            para[pl] = ' ';
            continue;
        }
        para = t;
        paras[n++] = (tui_para_t){ .kind = quote ? TUI_P_QUOTE : TUI_P_TEXT, .text = para };
    }
    while (n > 0 && paras[n - 1].kind == TUI_P_BLANK) n--;
    if (n > 0 && paras[0].kind == TUI_P_BLANK) { memmove(paras, paras + 1, sizeof paras[0] * (size_t)(n - 1)); n--; }
    *out = paras;
    return n;
}

void begin_changelog(void) {
    if (g_app.mode != MODE_CHAT) return;
    g_app.mode = MODE_CHANGELOG;
    g_app.changelog_scroll = 0;
    g_app.dirty = 1;
}

void render_changelog(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const tui_para_t *paras;
    int n = changelog_paras(&paras);
    char title[48];
    snprintf(title, sizeof title, "Changelog (v%s here)", CHAT_VERSION);
    g_app.changelog_most = tui_render_text(rows_n, cols_n, title, clock, paras, n, &g_app.changelog_scroll, bar,
                                           g_app.color_enabled);
}

void changelog_key(const tui_key_t *key) {
    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);
    int page = rows_n > 6 ? rows_n - 4 : 1;
    int *s = &g_app.changelog_scroll;
    switch (key->type) {
        case TUI_KEY_UP:        (*s)--; break;
        case TUI_KEY_DOWN:      (*s)++; break;
        case TUI_KEY_PAGE_UP:   *s -= page; break;
        case TUI_KEY_PAGE_DOWN: *s += page; break;
        case TUI_KEY_HOME:      *s = 0; break;
        case TUI_KEY_END:       *s = g_app.changelog_most; break;
        case TUI_KEY_ESCAPE:
        case TUI_KEY_HELP:      g_app.mode = MODE_CHAT; break;
        case TUI_KEY_CHAR:
            if (key->ch_len != 1) break;
            switch (key->ch[0]) {
                case 'k': (*s)--; break;
                case 'j': (*s)++; break;
                case ' ': *s += page; break;
                case 'b': *s -= page; break;
                case 'g': *s = 0; break;
                case 'G': *s = g_app.changelog_most; break;
                case 'q': g_app.mode = MODE_CHAT; break;
                default: break;
            }
            break;
        default: break;
    }
    if (*s < 0) *s = 0;
    if (*s > g_app.changelog_most) *s = g_app.changelog_most;
    g_app.dirty = 1;
}

// Tab and Shift+Tab: the first row of the next or previous section, round from the last to the first.
int page_section_step(const tui_row_t *rows, int n, int sel, int dir) {
    while (sel > 0 && !rows[sel].section) sel--;
    for (int k = 1; k < n; k++) {
        int i = ((sel + dir * k) % n + n) % n;
        if (rows[i].section) return i;
    }
    return sel;
}

// The first row of the nth section, or -1 if there aren't that many.
int page_section_nth(const tui_row_t *rows, int n, int nth) {
    for (int i = 0; i < n; i++) if (rows[i].section && nth-- == 0) return i;
    return -1;
}
