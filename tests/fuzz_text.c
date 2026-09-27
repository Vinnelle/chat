// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Text that reaches the terminal (message and nick cleaning, column widths) and the input line
// editor fed with arbitrary key bytes.
#define _POSIX_C_SOURCE 200809L
#include "core/chat.h"
#include "app/tui.h"
#include "common/util.h"
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

static void fuzz_editor(const uint8_t *data, size_t size) {
    tui_input_t in;
    memset(&in, 0, sizeof in);
    tui_input_clear(&in);
    in.modal = size > 0 && (data[0] & 1);
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
    }
}

// The frames go to /dev/null; this is for the sanitizers' benefit.
static void fuzz_render(const char *s, const uint8_t *data, size_t size) {
    static tui_scrollback_t sb, console;
    static const uint8_t rgb[3] = { 200, 100, 50 };
    int rows = size > 2 ? 6 + data[2] % 60 : 24, cols = size > 3 ? 30 + data[3] % 200 : 80;
    int flags = size > 4 ? data[4] : 0;
    tui_scrollback_push(&sb, "12:34", s, (flags & 1) ? rgb : NULL, (flags & 2) != 0, (int)(strlen(s) / 3));
    tui_scrollback_push(&console, "12:34", s, NULL, 0, 0);
    tui_session_row_t session = { .online = 3 };
    copy_str(session.label, s, sizeof session.label);
    tui_peer_row_t peer;
    copy_str(peer.label, s, sizeof peer.label);
    tui_input_t in;
    memset(&in, 0, sizeof in);
    tui_input_clear(&in);
    copy_str(in.buf, s, sizeof in.buf);
    in.len = (int)strlen(in.buf);
    in.cursor = in.len;
    tui_view_t view = { (flags & 4) != 0, (flags & 8) != 0, (flags & 16) != 0, s };
    const char *net[1] = { s };
    tui_render(rows, cols, &session, 1, 0, &peer, 1, &sb, &console, &view, s, (flags & 32) ? s : NULL,
               &in, (flags & 64) != 0, (flags & 128) != 0, TUI_ID_AGE, s, net, 1);
    tui_list_item_t item = { .is_dir = flags & 1 };
    copy_str(item.label, s, sizeof item.label);
    tui_render_list(rows, cols, &session, 1, 0, s, &item, 1, 0, s, (flags & 64) != 0);
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

    fuzz_editor(data, size);
    fuzz_render(s, data, size);
    free(s);
    return 0;
}
