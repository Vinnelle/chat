// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The clipboard: public text through the terminal (OSC 52), secrets cleared again after a while.
#include "app/app.h"

// Asks the terminal to put text (up to OSC52_MAX bytes) on the clipboard. A terminal that doesn't allow OSC 52 ignores it.
#define OSC52_MAX 1024   // a PGP public key fits

static void osc52_put(const char *text) {
    size_t n = strlen(text);
    if (n > OSC52_MAX) n = OSC52_MAX;
    char b64[BASE64_LEN(OSC52_MAX) + 1];
    base64_encode((const uint8_t *)text, n, b64);
    char osc[sizeof b64 + 16];
    snprintf(osc, sizeof osc, "\x1b]52;c;%s\x07", b64);
    platform_write_stdout(osc, strlen(osc));
    crypto_wipe(b64, sizeof b64);
    crypto_wipe(osc, sizeof osc);
}

// When the secret copied last comes off the clipboard (0: none is due to), and whether chat put it
// there itself rather than the terminal.
static double g_clip_clear_at;
static int g_clip_native;

void osc52_copy(const char *text) {
    g_clip_clear_at = 0;
    osc52_put(text);
}

void copy_secret(const char *text) {
    g_clip_native = platform_clipboard_set(text) == 0;
    if (!g_clip_native) osc52_put(text);
    g_clip_clear_at = now_seconds() + CLIPBOARD_CLEAR_SECONDS;
}

// The terminal can't say what's on the clipboard now (reading it is usually off), so this can also
// clear something copied since.
void clipboard_clear_now(void) {
    if (!g_clip_clear_at) return;
    g_clip_clear_at = 0;
    if (g_clip_native) { platform_clipboard_clear(); return; }
    // xterm empties it on a payload that isn't base64, others on an empty one.
    static const char clear[] = "\x1b]52;c;!\x07\x1b]52;c;\x07";
    platform_write_stdout(clear, sizeof clear - 1);
}

void clipboard_tick(double now) {
    if (g_clip_clear_at && now >= g_clip_clear_at) clipboard_clear_now();
}

void copy_session_id(session_slot_t *s) {
    if (!s) { note("no session selected - nothing to copy"); return; }
    const char *sid = s->engine.session_name;
    copy_secret(sid);
    note("session id copied to the clipboard: %s - it comes off in %d s", sid, CLIPBOARD_CLEAR_SECONDS);
}

// It holds the password, so it's never shown: only copied.
void copy_invite(session_slot_t *s) {
    if (!s) { note("no session selected - nothing to copy"); return; }
    if (s->contact) { note("a call is only for you and the key you called - nobody else can join it"); return; }
    char invite[INVITE_MAX];
    if (chat_invite(s->engine.session_name, s->password, invite, sizeof invite) != 0) {
        note("this session's id has a ':' in it, so it can't go in an invite - :copyid copies the id, and the "
             "password goes separately");
        return;
    }
    copy_secret(invite);
    crypto_wipe(invite, sizeof invite);
    note("invite copied to the clipboard, and it comes off in %d s - it holds the password, so only pass it to "
         "whoever you're inviting", CLIPBOARD_CLEAR_SECONDS);
}
