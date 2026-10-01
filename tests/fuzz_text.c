// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Text that reaches the terminal (message and nick cleaning, column widths), the input line
// editor fed with arbitrary key bytes, and file names from peers on their way to the disk.
#define _POSIX_C_SOURCE 200809L
#include "core/chat.h"
#include "app/tui.h"
#include "common/util.h"
#include "core/files.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void check(int ok) { if (!ok) abort(); }

// Well-formed UTF-8 with nothing clean_text strips.
static void check_clean(const char *s) {
    size_t n = strlen(s);
    for (size_t i = 0, adv; i < n; i += adv) {
        uint32_t cp = utf8_decode(s, n, i, &adv);
        check(!(adv == 1 && cp >= 0x80));
    }
    check(!has_control_chars(s));
}

// Three suggestions for anything typed: it with one, two and three letters more, the last too long
// for the line.
static int fuzz_suggest(const char *typed, int nth, tui_suggestion_t *out) {
    if (nth > 2) return 0;
    memset(out, 0, sizeof *out);
    size_t n = strlen(typed);
    if (n > sizeof out->line - 4) n = sizeof out->line - 4;
    memcpy(out->line, typed, n);
    memset(out->line + n, 'x', (size_t)nth + 1);
    if (nth == 2) memset(out->line, 'y', sizeof out->line - 1);
    copy_str(out->name, out->line, sizeof out->name);
    copy_str(out->help, typed, sizeof out->help);
    return 1;
}

// "set" and "quit" are commands, and "q" an alias.
static int fuzz_command(const char *word, int whole) {
    static const char *const WORDS[] = { "set", "quit", "q" };
    for (size_t i = 0; i < sizeof WORDS / sizeof WORDS[0]; i++)
        if (whole ? strcmp(WORDS[i], word) == 0 : strncmp(WORDS[i], word, strlen(word)) == 0) return 1;
    return 0;
}

static void fuzz_editor(const uint8_t *data, size_t size) {
    tui_input_t in;
    memset(&in, 0, sizeof in);
    tui_input_clear(&in);
    in.modal = size > 0 && (data[0] & 1);
    in.suggest = size > 0 && (data[0] & 2) ? fuzz_suggest : NULL;
    in.is_command = size > 0 && (data[0] & 4) ? fuzz_command : NULL;
    size_t off = 0;
    while (off < size) {
        tui_key_t key;
        size_t used = tui_decode_key(data + off, size - off, &key);
        check(used >= 1 && used <= size - off);
        off += used;
        if (key.type == TUI_KEY_CHAR) {
            size_t adv;
            check(key.ch_len >= 1 && key.ch_len <= 4);
            uint32_t cp = utf8_decode(key.ch, (size_t)key.ch_len, 0, &adv);
            check((int)adv == key.ch_len && !(adv == 1 && cp >= 0x80));
        }
        tui_input_feed(&in, &key);
        check(in.len >= 0 && in.len < (int)sizeof in.buf && in.buf[in.len] == '\0');
        check(in.cursor >= 0 && in.cursor <= in.len);
        check(in.cmd_len >= 0 && in.cmd_len < (int)sizeof in.cmd && in.cmd[in.cmd_len] == '\0');
        check((size_t)in.len == strlen(in.buf));
        check(in.menu_sel >= 0 && in.menu_sel < 3);
    }
}

// A picture of whatever size the input says, drawn under the lines that offer file 1.
static uint8_t g_pic_rgb[TUI_IMAGE_MAX_W * TUI_IMAGE_MAX_H * 3];
static tui_image_t g_pic;
static const tui_image_t *fuzz_image(const void *ctx, int file) {
    (void)ctx;
    return file == 1 && g_pic.w > 0 ? &g_pic : NULL;
}

// The same file on its way, how far along and what's said beside the bar as the input says.
static tui_progress_t g_progress;
static const tui_progress_t *fuzz_progress(const void *ctx, int file) {
    (void)ctx;
    return file == 1 && g_progress.text[0] ? &g_progress : NULL;
}

// The frames go to /dev/null; this is for the sanitizers' benefit.
static void fuzz_render(const char *s, const uint8_t *data, size_t size) {
    static tui_scrollback_t sb, console;
    static const uint8_t rgb[3] = { 200, 100, 50 };
    int rows = size > 2 ? 6 + data[2] % 60 : 24, cols = size > 3 ? 30 + data[3] % 200 : 80;
    int flags = size > 4 ? data[4] : 0;
    tui_scrollback_push(&sb, "12:34", s, (flags & 1) ? rgb : NULL, (flags & 2) != 0, (int)(strlen(s) / 3));
    tui_scrollback_push(&console, "12:34", s, NULL, 0, 0);
    g_pic.w = size > 6 ? 1 + data[6] % TUI_IMAGE_MAX_W : 0;
    g_pic.h = size > 7 ? 1 + data[7] % TUI_IMAGE_MAX_H : 0;
    for (size_t i = 0; i < sizeof g_pic_rgb; i++) g_pic_rgb[i] = (uint8_t)(i * 31 + (size ? data[i % size] : 0));
    g_pic.rgb = g_pic_rgb;
    if (flags & 4) tui_scrollback_mark_file(&sb, 1);
    // A name ending in ':' where the colour ends, as chat lines have it.
    char line[TUI_LINE_MAX];
    snprintf(line, sizeof line, "%.*s: %s", (int)(strlen(s) % 40), s, s);
    int head = (int)(strlen(s) % 40) + 1;
    tui_scrollback_push(&sb, "12:34", (flags & 32) ? line : s, (flags & 1) ? rgb : NULL, (flags & 2) != 0,
                        (flags & 32) ? head : (int)(strlen(s) / 3));
    tui_scrollback_push(&console, "12:34", s, (flags & 1) ? rgb : NULL, 0, 0);
    if (size > 5) tui_set_background((const uint8_t[3]){ data[5], data[5], (uint8_t)(data[5] ^ 0x80) });
    tui_session_row_t session = { .online = 3, .unread = size > 8 ? data[8] : 0, .mention = flags & 1,
                                  .state = (tui_session_state_t)(flags % 3) };
    copy_str(session.label, s, sizeof session.label);
    tui_peer_row_t peer = { .verify = flags % 3, .modified = (flags & 8) != 0, .you = (flags & 16) != 0 };
    copy_str(peer.nick, s, sizeof peer.nick);
    copy_str(peer.tag, s, sizeof peer.tag);
    memcpy(peer.color, rgb, 3);
    tui_input_t in;
    memset(&in, 0, sizeof in);
    tui_input_clear(&in);
    copy_str(in.buf, s, sizeof in.buf);
    in.len = (int)strlen(in.buf);
    in.cursor = in.len;
    in.modal = 1;
    in.suggest = fuzz_suggest;
    if (flags & 128) { in.mode = TUI_IMODE_COMMAND; copy_str(in.cmd, s, sizeof in.cmd); in.cmd_len = (int)strlen(in.cmd); }
    // The nick that's lit where it's mentioned: the start of the text, so it's there to find.
    char self[MAX_NICK + 1];
    copy_str(self, s, size > 9 ? 1 + data[9] % MAX_NICK : sizeof self);
    g_progress.permille = size > 11 ? (int)data[11] * 5 - 100 : 0;   // a little out of range either side too
    copy_str(g_progress.text, (flags & 1) ? s : "", sizeof g_progress.text);
    tui_view_t view = { (flags & 4) != 0, (flags & 8) != 0, (flags & 16) != 0, (flags & 2) ? s : NULL, s,
                        (tui_session_state_t)(flags % 3), s, (flags & 4) ? s : NULL, flags % 5, fuzz_image, NULL,
                        (flags & 8) ? self : NULL, size > 10 ? data[10] % 4 : 0, flags % 7, flags & 1, fuzz_progress,
                        (flags & 32) ? s : NULL };
    const tui_kv_t net[1] = { { s, s } };
    // A dialog over the screen, with the text as its title, paragraphs, field, status and note.
    tui_input_t field = in;
    field.modal = 0;
    field.mode = TUI_IMODE_INSERT;
    const tui_para_t paras[3] = { { .kind = (tui_para_kind_t)(flags % 9), .text = s, .level = flags % 4, .marker = "1." },
                                  { .kind = TUI_P_BLANK, .text = "" }, { .kind = TUI_P_BULLET, .text = s } };
    tui_dialog_t dialog = { .title = s, .text = paras, .n_text = (flags & 2) ? 3 : 0,
                            .input = (flags & 4) ? NULL : &field, .mask = (flags & 8) != 0, .placeholder = s,
                            .status = (flags & 4) ? s : NULL, .note = (flags & 1) ? s : NULL, .keys = s };
    tui_bar_t bar = { .chip = s, .tone = (tui_tone_t)(flags % 5), .input = &in,
                      .mask_input = (flags & 128) != 0, .message = (flags & 2) ? s : NULL, .hint = s,
                      .badge = (tui_identity_badge_t)(flags % 4), .nick = s, .nick_color = rgb, .placeholder = s,
                      .limit = flags % 300, .warn = (flags & 16) ? s : NULL, .dialog = (flags & 32) ? &dialog : NULL };
    tui_render(rows, cols, &session, 1, 0, &peer, 1, net, 1, &sb, &console, &view, &bar, (flags & 64) != 0);
    tui_render_bar(rows, cols, &view, &bar, (flags & 64) != 0);
    tui_row_t row[2] = { { s, s, (flags & 1) ? s : NULL, (tui_value_kind_t)(flags % 6), (flags & 4) ? rgb : NULL },
                         { NULL, s, NULL, TUI_V_TEXT, NULL } };
    const char *nav[2] = { s, s };
    tui_page_t page = { .title = s, .clock = s, .intro = (flags & 2) ? s : NULL, .nav = (flags & 4) ? nav : NULL,
                        .n_nav = 2, .nav_sel = flags % 3, .rows = row, .n_rows = 2, .selected = flags % 3,
                        .help = s, .usage = (flags & 1) ? s : NULL, .button = (flags & 8) ? s : NULL,
                        .keys = (flags & 16) != 0 };
    in.mode = TUI_IMODE_INSERT;
    bar.input = (flags & 16) ? &in : NULL;
    tui_render_page(rows, cols, &page, &bar, (flags & 64) != 0);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0) abort();
    close(fd);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *s = malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = '\0';

    char out[MAX_TEXT + 1];
    size_t max = size > 0 ? data[0] % (MAX_TEXT + 1) : MAX_TEXT;
    size_t n = clean_text(s, out, max);
    check(n <= max && n == strlen(out));
    check_clean(out);

    char nick[MAX_NICK + 1];
    chat_clean_nick(s, nick);
    check(nick[0] && strlen(nick) <= MAX_NICK && !strpbrk(nick, "()#:@"));
    check_clean(nick);

    int cols;
    int want = size > 1 ? data[1] % 90 : 10;
    size_t fit = utf8_fit_cols(s, size, want, &cols);
    check(fit <= size && cols >= 0 && cols <= want);
    size_t wrapped = fit;
    utf8_fit_cols(s, wrapped, 1 << 20, &cols);
    check(cols <= want);

    uint8_t rgb[3];
    parse_color(s, rgb);
    uint8_t bin[64];
    base64_decode_strict(s, size, bin, sizeof bin);
    hex_decode(s, 32, bin);
    has_control_chars(s);

    // A peer's file name: never a path, a hidden file, a device, or anything the terminal acts on.
    char fname[FILE_NAME_MAX + 1];
    file_clean_name(s, fname);
    size_t fl = strlen(fname);
    check(fl >= 1 && fl <= FILE_NAME_MAX && fname[0] != '.' && fname[0] != ' ' && fname[fl - 1] != '.' && fname[fl - 1] != ' ');
    check(!strpbrk(fname, "/\\:*?\"<>|"));
    check_clean(fname);
    uint64_t sz;
    file_parse_size(s, &sz);

    fuzz_editor(data, size);
    fuzz_render(s, data, size);
    free(s);
    return 0;
}
