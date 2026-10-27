// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The list pages' keys, the settings page and the signing identity's picker, the key paste box, and
// :changelog.
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
    const setting_def_t *d = g_app.settings.sel < N_SETTINGS ? &SETTINGS[g_app.settings.sel] : NULL;
    const char *const *names;
    int n;
    int steps = d && (setting_options(d->id, &names, &n) >= 0 || d->id == SET_COLOUR);
    int s = section_digit(key);
    if (s >= 0 && s < settings_n_sections()) settings_go_section(s);
    if (s >= 0) { g_app.dirty = 1; return; }
    switch (list_key(key)) {
        case LIST_UP:    settings_step(-1); break;
        case LIST_DOWN:  settings_step(1); break;
        case LIST_FIRST: settings_select(section_row(g_app.settings.page, 1)); break;
        case LIST_LAST:  g_app.settings.sel = SETTINGS_DONE; break;
        case LIST_NEXT_SECTION: settings_section_step(1); break;
        case LIST_PREV_SECTION: settings_section_step(-1); break;
        case LIST_LEFT:  if (steps) setting_step(d->id, -1); break;
        case LIST_RIGHT:
            if (steps) setting_step(d->id, 1);
            else if (d && d->id == SET_SIGN) begin_sign();
            else if (d && d->id == SET_SHADOW) begin_shadow();
            else if (d && d->id == SET_EXPORT_KEY) begin_key_export();
            break;
        case LIST_CHOOSE:
            if (!d) settings_done();
            else if (steps && d->id != SET_COLOUR) setting_step(d->id, 1);
            else if (d->kind == K_TEXT || d->kind == K_SECRET) begin_setting_edit(d->id);
            else if (d->id == SET_SIGN) begin_sign();
            else if (d->id == SET_SHADOW) begin_shadow();
            else if (d->id == SET_AGE_RECIPIENT) copy_age_recipient();
            else if (d->id == SET_PGP_PUBKEY) copy_pgp_public_key();
            else if (d->id == SET_EXPORT_KEY) begin_key_export();
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
            sign_pick(g_app.key.sel);
            if (g_app.mode == MODE_SIGN_CHOICE) g_app.mode = MODE_SETTINGS;
            break;
        case LIST_LEFT:
        case LIST_BACK:  g_app.mode = MODE_SETTINGS; break;
        case LIST_CLOSE: settings_done(); break;
        default: list_move(k, &g_app.key.sel, N_PICKS); break;
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
    size_t room = sizeof g_app.paste.buf - 1 - g_app.paste.len;
    if (key->type == TUI_KEY_CHAR && room >= (size_t)key->ch_len) {
        memcpy(g_app.paste.buf + g_app.paste.len, key->ch, (size_t)key->ch_len);
        g_app.paste.len += (size_t)key->ch_len;
    } else if ((key->type == TUI_KEY_ENTER || key->type == TUI_KEY_JOIN_SESSION) && room >= 1) {
        g_app.paste.buf[g_app.paste.len++] = '\n';
    } else if (key->type == TUI_KEY_BACKSPACE && g_app.paste.len > 0) {
        g_app.paste.len--;
    } else {
        return;
    }
    g_app.paste.buf[g_app.paste.len] = '\0';
    snprintf(g_app.paste.status, sizeof g_app.paste.status, "%zu bytes so far", g_app.paste.len);
    g_app.dirty = 1;
    int age = g_app.key.load_kind == IDENT_AGE;
    if (age) {
        // Read when the key's last line ends, so a pasted file's own newline doesn't end up on the settings page.
        const char *at = strstr(g_app.paste.buf, AGE_SECRET_KEY_PREFIX);
        if (!at || g_app.paste.buf[g_app.paste.len - 1] != '\n'
            || g_app.paste.len - 1 - (size_t)(at - g_app.paste.buf) < AGE_SECRET_KEY_STRLEN) return;
    } else {
        // Only look at the end, where the END line will be.
        size_t el = sizeof PGP_PRIVATE_END - 1;
        if (g_app.paste.len < el || memcmp(g_app.paste.buf + g_app.paste.len - el, PGP_PRIVATE_END, el) != 0) return;
    }
    int rc = age ? age_import_secret_key_text(g_app.paste.buf, &g_app.identity)
                 : pgp_import_secret_key_text(g_app.paste.buf, &g_app.identity);
    paste_clear();
    if (rc == 0) {
        g_app.identity_source = g_app.key.load_kind;
        g_app.key.origin = KEY_PASTED;
        identity_chosen();
        g_app.mode = MODE_SETTINGS;
    } else if (age) {
        note("that isn't an AGE secret key - paste another, or Esc");
    } else {
        note("that isn't an unencrypted EdDSA/Ed25519 secret key - paste another, or Esc");
    }
}

// ---- drawing the pages ----

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
    int n_rows = 0, sel_row = -1, s = g_app.settings.page, end = section_begin(s + 1);
    const char *group = NULL, *heading = NULL;
    for (int i = section_begin(s); i < end; i++) {
        const setting_def_t *d = &SETTINGS[i];
        if (d->group) group = heading = d->group;   // the heading goes on its group's first listed row
        if (!setting_shown(d->id)) continue;
        if (i == g_app.settings.sel) sel_row = n_rows;
        setting_value(d->id, values[n_rows], sizeof values[n_rows]);
        int greyed = row_greyed(d->id);
        if (greyed) copy_str(values[n_rows], "can't be used here", sizeof values[n_rows]);
        rows[n_rows] = (tui_row_t){ heading, page_label(d->label, group, labels[n_rows], sizeof labels[n_rows]),
                                    values[n_rows], setting_kind(d), d->id == SET_COLOUR ? g_app.color : NULL,
                                    NULL, 0, greyed };
        heading = NULL;
        n_rows++;
    }
    if (g_app.settings.sel == SETTINGS_DONE) sel_row = n_rows;   // the Done button
    const setting_def_t *d = g_app.settings.sel < N_SETTINGS ? &SETTINGS[g_app.settings.sel] : NULL;
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
                     "and chat needs a way to ask it for one.", g_app.factor.seckey_why);
        else if (greyed)
            snprintf(help, sizeof help, "Can't be used here: %s. The device lock makes the save unlock only on this "
                     "device, by sealing a secret with something the device keeps to itself: its TPM, on Linux "
                     "through systemd's credential service or /dev/tpmrm0. Without that, there's nothing to seal it "
                     "with.",
                     g_app.device.why);
        else
            snprintf(help, sizeof help, "%s%s", recipient, d->help);
        if (d->values && !greyed) snprintf(usage, sizeof usage, ":set %s %s", d->key, d->values);
        else if (d->kind == K_SECRET) snprintf(usage, sizeof usage, ":set %s", d->key);
        else if (d->id == SET_EXPORT_KEY) copy_str(usage, ":exportkey", sizeof usage);
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
    snprintf(help, sizeof help, "%s Now: %s.", SIGN_PICKS[g_app.key.sel].help, now);
    static const char *const SET[N_PICKS] = { "off", "age", "age:PATH", "age:PATH", NULL, "pgp", "pgp:PATH", "pgp:PATH", NULL };
    if (SET[g_app.key.sel]) snprintf(usage, sizeof usage, ":set sign %s", SET[g_app.key.sel]);
    const char *nav[8];
    tui_page_t page = {
        .title = "Settings" CRUMB "Profile" CRUMB "Signing identity",
        .clock = clock,
        .nav = nav, .n_nav = settings_sections(nav, 8), .nav_sel = settings_section_index(SET_SIGN),
        .rows = rows, .n_rows = N_PICKS, .selected = g_app.key.sel,
        .help = help, .usage = usage[0] ? usage : NULL,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
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
    g_app.changelog.scroll = 0;
    g_app.dirty = 1;
}

void render_changelog(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    const tui_para_t *paras;
    int n = changelog_paras(&paras);
    char title[48];
    snprintf(title, sizeof title, "Changelog (v%s here)", CHAT_VERSION);
    g_app.changelog.most = tui_render_text(rows_n, cols_n, title, clock, paras, n, &g_app.changelog.scroll, bar,
                                           g_app.color_enabled);
}

void changelog_key(const tui_key_t *key) {
    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);
    int page = rows_n > 6 ? rows_n - 4 : 1;
    int *s = &g_app.changelog.scroll;
    switch (key->type) {
        case TUI_KEY_UP:        (*s)--; break;
        case TUI_KEY_DOWN:      (*s)++; break;
        case TUI_KEY_PAGE_UP:   *s -= page; break;
        case TUI_KEY_PAGE_DOWN: *s += page; break;
        case TUI_KEY_HOME:      *s = 0; break;
        case TUI_KEY_END:       *s = g_app.changelog.most; break;
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
                case 'G': *s = g_app.changelog.most; break;
                case 'q': g_app.mode = MODE_CHAT; break;
                default: break;
            }
            break;
        default: break;
    }
    if (*s < 0) *s = 0;
    if (*s > g_app.changelog.most) *s = g_app.changelog.most;
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
