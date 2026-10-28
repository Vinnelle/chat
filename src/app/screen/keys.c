// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What each key does: in each mode (MODE_KEYS), on the chat screen, and in the boxes that take a
// line.
#include "app/app.h"

static void submit_prompt(void) {
    tui_input_t *input = &g_app.input;
    switch (g_app.mode) {
        case MODE_NEW_PASSWORD: {
            char session_id[MAX_SESSION_NAME + 1], pw[sizeof input->buf];
            random_session_id(session_id, SESSION_ID_LEN);
            copy_str(pw, input->buf, sizeof pw);
            end_prompt();
            start_session(session_id, pw, 1, 0, NULL, 0);
            crypto_wipe(pw, sizeof pw);
            break;
        }
        case MODE_JOIN_ID: {
            if (input->len == 0) break;
            char session_id[MAX_SESSION_NAME + 1], pw[MAX_PASSWORD + 1];
            int invite = chat_invite_parse(input->buf, session_id, pw);
            if (invite < 0) {
                note("that invite is mistyped or cut off: its check doesn't match - copy it again, or type the id");
                break;
            }
            if (invite > 0) {
                end_prompt();
                start_session(session_id, pw, 0, 0, NULL, 0);
                crypto_wipe(pw, sizeof pw);
                break;
            }
            copy_str(g_app.pending_session_id, input->buf, sizeof g_app.pending_session_id);
            tui_input_clear(input);
            g_app.mode = MODE_JOIN_PASSWORD;
            g_app.dirty = 1;
            break;
        }
        case MODE_JOIN_PASSWORD: {
            char session_id[MAX_SESSION_NAME + 1], pw[sizeof input->buf];
            copy_str(session_id, g_app.pending_session_id, sizeof session_id);
            copy_str(pw, input->buf, sizeof pw);
            end_prompt();
            start_session(session_id, pw, 0, 0, NULL, 0);
            crypto_wipe(pw, sizeof pw);
            break;
        }
        default:
            break;
    }
}

// The random password goes as a whole: a key that edits it clears it first, so what's typed is a
// password of your own, and moving the cursor keeps it to edit.
static void new_password_key(const tui_key_t *key) {
    if (g_app.pw_suggested) {
        switch (key->type) {
            case TUI_KEY_CHAR: case TUI_KEY_BACKSPACE: case TUI_KEY_DELETE: case TUI_KEY_DELETE_WORD: case TUI_KEY_CTRL_U:
                crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
                g_app.input.len = g_app.input.cursor = 0;
                g_app.pw_suggested = 0;
                g_app.dirty = 1;
                if (key->type != TUI_KEY_CHAR) return;
                break;
            case TUI_KEY_LEFT: case TUI_KEY_RIGHT: case TUI_KEY_HOME: case TUI_KEY_END:
                g_app.pw_suggested = 0;
                break;
            default:
                break;
        }
    }
    field_key(key, submit_prompt, end_prompt);
}

static void submit_chat_line(void) {
    tui_input_t *input = &g_app.input;
    g_app.dirty = 1;

    if (input->mode == TUI_IMODE_COMMAND) {
        char line[sizeof input->cmd];
        copy_str(line, input->cmd, sizeof line);
        // Enter on a line the menu would complete runs what the menu has selected, so ":se" runs ":set",
        // as the menu shows.
        tui_suggestion_t s;
        size_t n = strlen(line);
        if ((n > 0 || input->menu_sel > 0) && tui_input_completion(input, &s)) copy_str(line, s.line, sizeof line);
        // Completing an argument leaves a space for the next one, which ":verify NICK " would take as
        // part of the nick.
        n = strlen(line);
        while (n > 0 && line[n - 1] == ' ') line[--n] = '\0';
        // If opened by typing '/', a line that turns out not to be a command is the start of a message.
        // It goes back in the input as text, for Enter to send.
        char word[CMD_WORD_MAX];
        cmd_parse(line, word);
        if (input->cmd_as_text && line[0] && !command_word(word, 1)) {
            tui_input_command_to_text(input);
            crypto_wipe(line, sizeof line);
            return;
        }
        tui_input_end_command(input);
        crypto_wipe(input->cmd, sizeof input->cmd);
        run_command(line);
        crypto_wipe(line, sizeof line);
        return;
    }

    const char *text = input->buf;
    while (*text == ' ') text++;
    if (!text[0]) return;
    if (!g_app.selected) {
        note("no session yet - ctrl+n starts one, ctrl+j joins one");
        return;
    }
    if (!session_ready(g_app.selected)) {
        note(g_app.selected->initialising ? "still starting - hold on a moment"
                                          : "not connected yet - your text is kept until someone answers");
        return;
    }
    // Over the limit the end would be cut off when sent. The count under the box is red, and this
    // explains why Enter didn't send.
    if (input->len > MAX_TEXT) {
        note("too long to send by %d - a message holds %d bytes", input->len - MAX_TEXT, MAX_TEXT);
        return;
    }
    chat_send_text(g_app.selected->engine, input->buf, now_seconds());
    tui_input_clear(input);
    g_app.selected->scroll = 0;
    // Sending a reply counts as reading, so the new messages line is removed.
    g_app.selected->has_new = 0;
}

static int chat_page(void) {
    int rows_n, cols_n;
    term_get_size(&rows_n, &cols_n);
    return rows_n / 3 > 1 ? rows_n / 3 : 1;
}

// PgUp and PgDn (Ctrl+U and Ctrl+D in NORMAL) scroll the chat by a third of the screen's rows, and Up
// and Down, which the mouse wheel sends, by a message. G goes back to the newest.
static void scroll_chat(int dir, int step) {
    session_slot_t *s = g_app.selected;
    if (!s) return;
    long v = dir == 0 ? 0 : (long)s->scroll + (long)dir * step;
    if (v > s->sb.count - 1) v = s->sb.count - 1;
    if (v < 0) v = 0;
    s->scroll = (int)v;
    g_app.dirty = 1;
}

// The wheel over the console scrolls it by a line, as far as the last frame showed it could go.
static void scroll_console(int dir) {
    int *scroll = g_app.selected ? &g_app.selected->console_scroll : &g_app.log_scroll;
    int most = tui_area_most(TUI_AREA_CONSOLE);
    int v = dir == 0 ? 0 : (*scroll < most ? *scroll : most) + dir;
    *scroll = v < 0 ? 0 : v > most ? most : v;
    g_app.dirty = 1;
}

// The boxes that take text, where a paste can go.
// How each mode takes keys: with a function of its own, or as a field (Enter, Esc), a question (y, n)
// or a choice (y, n, Esc), and what each of those does. field: text is typed there, so a paste goes in.
// The chat's keys are handle_key's own.
typedef enum { KEYS_CHAT = 0, KEYS_OWN, KEYS_FIELD, KEYS_QUESTION, KEYS_CHOICE } keys_kind_t;
typedef struct {
    keys_kind_t kind;
    void (*own)(const tui_key_t *key);
    void (*yes)(void), (*no)(void), (*esc)(void);
    int field;
} mode_keys_t;

#define OWN(f) { KEYS_OWN, f, NULL, NULL, NULL, 0 }
#define OWN_FIELD(f) { KEYS_OWN, f, NULL, NULL, NULL, 1 }
#define FIELD(enter, esc) { KEYS_FIELD, NULL, enter, esc, NULL, 1 }
#define QUESTION(y, n) { KEYS_QUESTION, NULL, y, n, NULL, 0 }
#define CHOICE(y, n, esc) { KEYS_CHOICE, NULL, y, n, esc, 0 }

static const mode_keys_t MODE_KEYS[] = {
    [MODE_HELP]              = OWN(help_key),
    [MODE_CHANGELOG]         = OWN(changelog_key),
    [MODE_SETTINGS]          = OWN(settings_key),
    [MODE_SETTINGS_EDIT]     = FIELD(commit_setting_edit, end_setting_edit),
    [MODE_SETTINGS_SEARCH]   = OWN_FIELD(settings_search_key),
    [MODE_SIGN_CHOICE]       = OWN(sign_picker_key),
    [MODE_SIGN_BROWSE]       = OWN(browser_key),
    [MODE_SEND_BROWSE]       = OWN(send_browser_key),
    [MODE_SAVE_BROWSE]       = OWN(save_browser_key),
    [MODE_EXPORT_BROWSE]     = OWN(export_browser_key),
    [MODE_FILES]             = OWN(files_key),
    [MODE_FILE_VIEW]         = OWN(viewer_key),
    [MODE_FILE_ASK]          = QUESTION(file_ask_yes, file_ask_no),
    [MODE_EXPORT_ASK]        = QUESTION(export_key_yes, export_key_no),
    [MODE_SIGN_PASTE]        = OWN(paste_key),
    [MODE_SIGN_PASSWORD]     = FIELD(commit_sign_password, end_sign_password),
    [MODE_SIGN_PATH]         = FIELD(commit_key_path, end_key_path),
    [MODE_CHAT]              = { KEYS_CHAT, NULL, NULL, NULL, NULL, 0 },
    [MODE_NEW_PASSWORD]      = OWN_FIELD(new_password_key),
    [MODE_JOIN_ID]           = FIELD(submit_prompt, end_prompt),
    [MODE_JOIN_PASSWORD]     = FIELD(submit_prompt, end_prompt),
    [MODE_INSTALL]           = QUESTION(install_confirmed, cancel_install),
    [MODE_INSTALL_PASS]      = FIELD(commit_install_pass, cancel_install),
    [MODE_INSTALL_PASS2]     = FIELD(commit_install_pass2, cancel_install),
    [MODE_INSTALL_UNLOCK]    = FIELD(commit_install_unlock, back_from_install_unlock),
    [MODE_INSTALL_EXISTING]  = CHOICE(install_use_existing, install_new_save, cancel_install),
    [MODE_INSTALL_PICK]      = OWN(install_pick_key),
    [MODE_INSTALL_OVERWRITE] = QUESTION(install_overwrite_yes, cancel_install),
    [MODE_INSTALL_NAME]      = FIELD(commit_install_name, back_from_install_name),
    [MODE_INSTALL_FIRST]     = QUESTION(install_first_yes, install_first_no),
    [MODE_UNINSTALL]         = QUESTION(uninstall_confirmed, cancel_uninstall),
    [MODE_SAVES]             = OWN(saves_key),
    [MODE_UNLOCK]            = FIELD(commit_unlock, back_from_unlock),
    [MODE_DEVICE_LOCK]       = QUESTION(device_lock_yes, device_lock_no),
    [MODE_FACTOR]            = QUESTION(factor_yes, factor_no),
    [MODE_CODE_SETUP]        = OWN_FIELD(code_setup_key),
    [MODE_KEY_WAIT]          = OWN(key_wait_key),
    [MODE_KEY_PIN]           = FIELD(commit_key_pin, cancel_key_pin),
    [MODE_UNLOCK_CODE]       = FIELD(commit_unlock_code, back_from_unlock_code),
    [MODE_SHADOW_PASS]       = FIELD(commit_shadow_pass, cancel_shadow_pass),
    [MODE_SHADOW_PASS2]      = FIELD(commit_shadow_pass2, cancel_shadow_pass),
    [MODE_UPDATE]            = OWN(update_key),
    [MODE_MOVE]              = QUESTION(move_yes, move_no),
    [MODE_MOVE_ASK]          = OWN(move_ask_key),
    [MODE_TOR_STATE]         = QUESTION(tor_state_yes, tor_state_no),
    [MODE_OPEN_LINK]         = OWN(open_link_key),
    [MODE_ROOMS]             = OWN(rooms_key),
};
_Static_assert(COUNT_OF(MODE_KEYS) == MODE_ROOMS + 1, "every mode says how it takes keys");

static int field_mode(app_mode_t m) { return MODE_KEYS[m].field; }

// A paste only goes where text is typed. Anywhere else, its letters would be keys: a y answering a
// question, or q closing a page. A line's end in it only goes to the chat's input, as a space, and to
// the key being pasted, so a paste never presses Enter.
static int paste_wanted(const tui_key_t *key) {
    if (g_app.lock.on || g_app.lock.pin_step) return key->type == TUI_KEY_CHAR;
    if (g_app.asking_quit) return 0;
    if (g_app.mode == MODE_SIGN_PASTE || g_app.mode == MODE_CHAT) return 1;
    if (key->type == TUI_KEY_ENTER) return g_app.mode == MODE_SETTINGS_EDIT && setting_edit_separator();
    return key->type == TUI_KEY_CHAR && field_mode(g_app.mode);
}

// Bridge lines come one to a line, and stay apart in the field.
static void paste_separator(void) {
    tui_input_t *in = &g_app.input;
    const char *sep = setting_edit_separator();
    if (!sep || in->cursor == 0 || in->buf[in->cursor - 1] == ' ' || in->buf[in->cursor - 1] == ';') return;
    tui_key_t k = { .type = TUI_KEY_CHAR, .ch_len = 1, .pasted = 1 };
    for (; *sep; sep++) {
        k.ch[0] = *sep;
        if (!tui_input_paste(in, &k)) g_app.paste.cut = 1;
    }
    g_app.dirty = 1;
}

void handle_key(const tui_key_t *key) {
    tui_input_t *input = &g_app.input;

    // The terminal's reports aren't keys, so they don't clear the bar's message.
    if (key->type == TUI_KEY_BG_REPORT) {
        tui_set_background((const uint8_t *)key->ch);
        g_app.dirty = 1;
        return;
    }
    if (key->type == TUI_KEY_THEME_CHANGED) {
        platform_write_stdout(TUI_THEME_QUERY, sizeof TUI_THEME_QUERY - 1);
        g_app.dirty = 1;
        return;
    }
    if (key->type == TUI_KEY_MOUSE) return;
    if (key->type == TUI_KEY_PASTE_START) { g_app.paste.cut = 0; return; }
    if (key->type == TUI_KEY_PASTE_END) {
        if (g_app.paste.cut) note("the rest of the paste didn't fit");
        return;
    }
    if (key->pasted && !paste_wanted(key)) return;

    // A message is the result of the previous key, so this key resets the bar.
    if (g_app.message[0]) { g_app.message[0] = '\0'; g_app.dirty = 1; }
    lock_saw_key();

    if (panic_key_is(key)) { panic(PANIC_KEY); return; }
    if (g_app.lock.on) { locked_key(key); return; }
    if (!g_app.lock.pin_step && lock_key_is(key)) { lock_screen(); return; }
    if (key->type == TUI_KEY_CTRL_C && !g_app.asking_quit) { g_app.asking_quit = 1; g_app.dirty = 1; return; }
    if (g_app.asking_quit) { quit_key(key); return; }
    if (g_app.lock.pin_step) { pin_key(key); return; }

    if (key->pasted && key->type == TUI_KEY_ENTER && g_app.mode == MODE_SETTINGS_EDIT) { paste_separator(); return; }

    // The pages draw their fields in their rows, so a key there redraws the page.
    const mode_keys_t *k = &MODE_KEYS[g_app.mode];
    switch (k->kind) {
        case KEYS_OWN:      k->own(key); return;
        case KEYS_FIELD:    field_key(key, k->yes, k->no); return;
        case KEYS_QUESTION: confirm_key(key, k->yes, k->no); return;
        case KEYS_CHOICE:   choice_key(key, k->yes, k->no, k->esc); return;
        case KEYS_CHAT:     break;
    }

    // The wheel scrolls the console, or the sessions or peers while they don't all fit, if it's over
    // them. Anywhere else it's Up and Down.
    tui_area_t area = key->wheel && input->mode != TUI_IMODE_COMMAND ? tui_area_at(key->row, key->col) : TUI_AREA_NONE;
    if (area == TUI_AREA_CONSOLE) {
        scroll_console(key->type == TUI_KEY_UP ? 1 : -1);
        return;
    }
    if (area != TUI_AREA_NONE) {
        tui_scroll_list(area, key->type == TUI_KEY_UP ? -1 : 1);
        g_app.dirty = 1;
        return;
    }

    tui_input_mode_t was = input->mode;
    if (key->pasted) {
        if (!tui_input_paste(input, key)) g_app.paste.cut = 1;
        if (was == TUI_IMODE_COMMAND || input->mode == TUI_IMODE_COMMAND || was != input->mode) g_app.dirty = 1;
        else g_app.input_dirty = 1;
        return;
    }
    if (tui_input_feed(input, key)) {
        // The menu above the COMMAND line covers part of the chat, so it needs a full frame.
        if (was == TUI_IMODE_COMMAND || input->mode == TUI_IMODE_COMMAND) g_app.dirty = 1;
        else g_app.input_dirty = 1;
        return;
    }

    // NORMAL leaves these to the app: j and k switch sessions, like moving through a list, G goes back
    // to the newest message and console line, ? opens the help, f the files, o the newest link, and c,
    // C and s show or hide the console, the chat and the sidebar.
    if (key->type == TUI_KEY_CHAR && input->mode == TUI_IMODE_NORMAL) {
        switch (key->ch[0]) {
            case 'j': select_step(1); break;
            case 'k': select_step(-1); break;
            case 'G': scroll_chat(0, 0); scroll_console(0); break;
            case '?': begin_help(); break;
            case 'f': begin_files(); break;
            case 'o': app_open(NULL, ""); break;
            case 'c': g_app.show.console = !g_app.show.console; g_app.dirty = 1; break;
            case 'C': g_app.show.chat = !g_app.show.chat; g_app.dirty = 1; break;
            case 's': g_app.show.sidebar = !g_app.show.sidebar; g_app.dirty = 1; break;
            default: break;
        }
        return;
    }

    switch (key->type) {
        case TUI_KEY_TAB:            select_step(1); break;
        case TUI_KEY_BACKTAB:        select_step(-1); break;
        case TUI_KEY_NEW_SESSION:    begin_new_session(); break;
        case TUI_KEY_JOIN_SESSION:   begin_rooms(); break;
        case TUI_KEY_TOGGLE_SIDEBAR: g_app.show.sidebar = !g_app.show.sidebar; g_app.dirty = 1; break;
        case TUI_KEY_TOGGLE_CONSOLE: g_app.show.console = !g_app.show.console; g_app.dirty = 1; break;
        case TUI_KEY_TOGGLE_CHAT:    g_app.show.chat = !g_app.show.chat; g_app.dirty = 1; break;
        case TUI_KEY_SETTINGS:       begin_settings(); break;
        case TUI_KEY_HELP:           begin_help(); break;
        case TUI_KEY_FILES:          begin_files(); break;
        case TUI_KEY_PAGE_UP:
        case TUI_KEY_CTRL_U:         scroll_chat(1, chat_page()); break;
        case TUI_KEY_PAGE_DOWN:
        case TUI_KEY_CTRL_D:         scroll_chat(-1, chat_page()); break;
        case TUI_KEY_UP:             scroll_chat(1, 1); break;
        case TUI_KEY_DOWN:           scroll_chat(-1, 1); break;
        case TUI_KEY_ENTER:          submit_chat_line(); break;
        default: break;
    }
}
