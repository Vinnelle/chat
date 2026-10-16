// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The lock screen, and the PIN that unlocks it while no save is open.
#include "app/app.h"

const char *const LOCK_AFTER_NAMES[N_LOCK_AFTER] = { "off", "1m", "5m", "15m", "30m" };
const int LOCK_AFTER_SECONDS[N_LOCK_AFTER] = { 0, 60, 300, 900, 1800 };
const char *const LOCK_KEY_NAMES[N_LOCK_KEYS] = { "off", "ctrl+l", "ctrl+g", "ctrl+k", "f9" };

static const tui_keytype_t LOCK_KEYS[N_LOCK_KEYS] = {
    TUI_KEY_NONE, TUI_KEY_CTRL_L, TUI_KEY_CTRL_G, TUI_KEY_CTRL_K, TUI_KEY_F9
};

#define PIN_MIN 4

// The lock screen's reply to what was typed, on its bar in place of the app's message, which
// something carrying on behind it can set ("opening the save NAME...").
static char g_lock_note[96];

const char *lock_note(void) { return g_lock_note; }

// The PIN as a lock made from it with a salt of its own, and the first of the two times it's typed.
static struct {
    pass_lock_t pin, tried;
    int set;
    char first[INSTALL_PASS_MAX];
} g_lock;

static void pin_memory(void) {
    static int pinned;
    if (pinned) return;
    crypto_lock(&g_lock, sizeof g_lock);
    pinned = 1;
}

int lock_by_passphrase(void) { return g_app.installed && !g_app.locked; }

static int lock_possible(void) { return lock_by_passphrase() || g_lock.set; }

int lock_key_is(const tui_key_t *key) { return g_app.lock.key > 0 && key->type == LOCK_KEYS[g_app.lock.key]; }

// Wall time, so a computer asleep past lock.after locks as it wakes: Linux's monotonic clock doesn't
// count sleep.
void lock_saw_key(void) { g_app.lock.last_key = (double)time(NULL); }

static void field_clear(void) {
    crypto_wipe(g_app.lock.input.buf, sizeof g_app.lock.input.buf);
    tui_input_clear(&g_app.lock.input);
    g_app.lock.input.modal = 0;
}

static void begin_pin(int then) {
    pin_memory();
    field_clear();
    g_app.lock.pin_step = 1;
    g_app.lock.pin_then = then;
    g_app.dirty = 1;
}

static void end_pin(void) {
    field_clear();
    crypto_wipe(g_lock.first, sizeof g_lock.first);
    g_app.lock.pin_step = 0;
    g_app.dirty = 1;
}

void lock_screen(void) {
    if (g_plain || g_app.lock.on || g_app.lock.pin_step) return;
    if (!lock_possible()) { begin_pin(-1); return; }
    field_clear();
    clipboard_clear_now();
    g_app.lock.on = 1;
    g_lock_note[0] = '\0';
    g_app.dirty = 1;
}

static void say_lock_after(void) {
    int m = g_app.lock.after / 60;
    if (!m) note("Auto-lock: off");
    else note("Auto-lock: after %d minute%s without a key - %s unlocks it", m, m == 1 ? "" : "s",
              lock_by_passphrase() ? "the save's passphrase" : "the PIN you set");
}

// With no save open, turning it on asks for a PIN first.
void lock_after_choose(int i) {
    int s = LOCK_AFTER_SECONDS[i];
    if (s && !lock_possible() && !g_plain) { begin_pin(s); return; }
    g_app.lock.after = s;
    lock_saw_key();
    say_lock_after();
}

void lock_tick(void) {
    static int told;
    if (!g_app.lock.after || g_app.lock.on || g_app.lock.pin_step || g_plain) return;
    if ((double)time(NULL) - g_app.lock.last_key < g_app.lock.after) return;
    if (!lock_possible()) {
        if (!told) push_log("* auto-lock: with no save open there's nothing to unlock with - :lock sets a PIN");
        told = 1;
        return;
    }
    told = 0;
    lock_screen();
}

static int unlock_with(const char *typed) {
    if (lock_by_passphrase()) return install_lock_try(typed);
    if (!g_lock.set) return PASS_WRONG;
    int rc = pass_lock_like(typed, &g_lock.pin, &g_lock.tried);
    if (rc == 0 && crypto_equal(g_lock.tried.base, g_lock.pin.base, sizeof g_lock.pin.base) != 0) rc = PASS_WRONG;
    crypto_wipe(&g_lock.tried, sizeof g_lock.tried);
    return rc;
}

static void try_unlock(void) {
    char typed[sizeof g_app.lock.input.buf];
    copy_str(typed, g_app.lock.input.buf, sizeof typed);
    field_clear();
    if (!typed[0]) return;
    int passphrase = lock_by_passphrase();
    // Argon2id takes a second or two, so the box says so before it starts.
    g_app.lock.checking = 1;
    render();
    int rc = unlock_with(typed);
    crypto_wipe(typed, sizeof typed);
    g_app.lock.checking = 0;
    g_app.dirty = 1;
    if (rc == 0) {
        g_app.lock.on = 0;
        lock_saw_key();
    } else if (rc == INSTALL_DECOY || rc == INSTALL_DESTROYED) {
        g_app.installed = 0;
        panic(rc == INSTALL_DECOY ? PANIC_DECOY : PANIC_DESTROYED);
    } else if (rc == PASS_NOMEM) {
        copy_str(g_lock_note, "checking it needs 512 MiB of free memory for a moment - try again", sizeof g_lock_note);
    } else {
        snprintf(g_lock_note, sizeof g_lock_note, "that's not the %s", passphrase ? "passphrase" : "PIN");
    }
}

void locked_key(const tui_key_t *key) {
    if (g_lock_note[0]) { g_lock_note[0] = '\0'; g_app.dirty = 1; }
    if (key->type == TUI_KEY_ENTER) try_unlock();
    else if (key->type == TUI_KEY_ESCAPE) { field_clear(); g_app.dirty = 1; }
    else if (tui_input_feed(&g_app.lock.input, key)) g_app.dirty = 1;
}

void pin_key(const tui_key_t *key) {
    if (key->type == TUI_KEY_ESCAPE) {
        int then = g_app.lock.pin_then;
        end_pin();
        note(then < 0 ? "not locked - with no save open, it needs a PIN to unlock with"
                      : "Auto-lock: off - with no save open, it needs a PIN to unlock with");
        return;
    }
    if (key->type != TUI_KEY_ENTER) {
        if (tui_input_feed(&g_app.lock.input, key)) g_app.dirty = 1;
        return;
    }
    const char *typed = g_app.lock.input.buf;
    if (g_app.lock.pin_step == 1) {
        if (strlen(typed) < PIN_MIN) { note("a PIN is at least %d characters", PIN_MIN); return; }
        copy_str(g_lock.first, typed, sizeof g_lock.first);
        field_clear();
        g_app.lock.pin_step = 2;
        g_app.dirty = 1;
        return;
    }
    if (strcmp(typed, g_lock.first) != 0) {
        crypto_wipe(g_lock.first, sizeof g_lock.first);
        field_clear();
        g_app.lock.pin_step = 1;
        note("the two weren't the same - type the PIN again");
        return;
    }
    int rc = pass_lock_new(typed, &g_lock.pin), then = g_app.lock.pin_then;
    end_pin();
    if (rc != 0) { note("setting it needs 512 MiB of free memory for a moment - try again"); return; }
    g_lock.set = 1;
    if (then < 0) {
        lock_screen();
        return;
    }
    g_app.lock.after = then;
    lock_saw_key();
    say_lock_after();
}

void lock_forget(void) {
    crypto_wipe(&g_lock, sizeof g_lock);
    crypto_wipe(&g_app.lock.input, sizeof g_app.lock.input);
}

cmd_result_t app_lock(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    lock_screen();
    return CMD_OK;
}
