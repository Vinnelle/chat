// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Sessions: their slots, opening them, what the engine tells the app about them, the NEW and JOIN
// prompts, kept rooms, reopening, and calls.
#include "app/app.h"
#include "common/bytewords.h"

// This build as reported to peers, read at startup before :update can replace the file.
chat_build_t g_self_build;

// What every session takes from the settings: notifications, files, colour and signing identity.
// Then what peers are told about this build ("v"), and the key used to check the builds they report.
void app_session_opts(chat_opts_t *o) {
    o->notify_mode = g_app.notify_mode;
    o->notify_preview = g_app.notify_preview;
    o->verify_optional = g_app.verify_optional;
    o->file_cap = g_app.file_cap;
    o->fast_files = g_app.fast_files;
    o->picture_noise = g_app.picture_noise;
    o->has_color = 1;
    memcpy(o->color, g_app.color, 3);
    o->identity_source = g_app.identity_source;
    if (g_app.identity_source != IDENT_NONE) o->identity = g_app.identity;
    o->build = g_self_build;
    copy_str(o->release_key, update_release_key(), sizeof o->release_key);
    copy_str(o->release_backup_key, update_release_backup_key(), sizeof o->release_backup_key);
}

// move: the room :move made or was asked to, which gets a port of its own while the room being left
// keeps ours, and is said to be new and where it came from.
static session_slot_t *open_session(const char *session_name, const char *password, int created, uint16_t port,
                                    const addr_t *peers, int n_peers, const chat_move_to_t *move) {
    session_slot_t *s = find_free_slot();
    if (!s) { push_log("* too many sessions open already"); return NULL; }
    int idx = slot_index(s);
    memset(s, 0, sizeof *s);
    lock_scrollbacks(s);
    copy_str(s->name, session_name, sizeof s->name);

    char pw[MAX_PASSWORD + 1];
    copy_str(pw, password, sizeof pw);
    copy_str(s->password, password, sizeof s->password);

    s->initialising = 1;
    g_app.used[idx] = 1;
    select_session(s);
    console_note(s, "chat build %s - initialising session '%s', deriving keys...", CHAT_BUILD_STAMP, s->name);
    render();
    g_app.dirty = 0;

    chat_opts_t o; memset(&o, 0, sizeof o);
    copy_str(o.nick, g_app.nick, sizeof o.nick);
    copy_str(o.session_name, session_name, sizeof o.session_name);
    copy_str(o.password, pw, sizeof o.password);
    crypto_wipe(pw, sizeof pw);
    o.port = move ? 0 : port ? port : g_app.default_port;
    if (n_peers > 0) { memcpy(o.peers, peers, sizeof(addr_t) * (size_t)n_peers); o.n_peers = n_peers; }
    o.route = g_app.route;
    if (o.route.mode == ROUTE_TOR) {
        // The tor found or started for Tor mode. Until there is one, the session waits for it.
        tor_link_ensure(now_seconds());
        copy_str(o.route.tor.socks, g_tor.state == TL_READY ? g_tor.socks : "", sizeof o.route.tor.socks);
        copy_str(o.route.tor.control, g_tor.state == TL_READY ? g_tor.control : "", sizeof o.route.tor.control);
    }
    o.created = created;
    app_session_opts(&o);
    if (move) { o.moved = 1; o.moved_key = move->key; }
    o.file_view = session_file_view;
    o.delivery = session_delivery;

    chat_init(&s->engine, &o, session_print, session_notify, s, now_seconds());
    crypto_wipe(&o, sizeof o);
    if (!chat_started(&s->engine)) {
        const char *why = chat_start_error(&s->engine);
        chat_shutdown(&s->engine);
        release_scrollbacks(s);
        g_app.used[idx] = 0;
        g_app.selected = NULL;
        select_session(first_session());
        push_log("* couldn't start that session: %s", why);
        return NULL;
    }
    // The session's routing holds the password for a running tor, not the one chat's own tor takes.
    if (chat_route_mode(&s->engine) == ROUTE_TOR && g_tor.state == TL_READY && g_tor.proc)
        chat_tor_set_ports(&s->engine, g_tor.socks, g_tor.control, torproc_password(g_tor.proc));
    chat_set_net_log(&s->engine, g_app.net_log);
    s->initialising = 0;
    g_app.dirty = 1;
    // Before anyone can connect, so peers hear of it in the handshake.
    if (g_app.history && history_possible()) history_start(s, 1);
    chat_set_history(&s->engine, s->hist != NULL);

    char idhex[SHORT_ID_HEX + 1]; hex_encode(chat_my_id(&s->engine), SHORT_ID_LEN, idhex);
    if (move) {
        console_note(s, "moved here from '%s' as %s (peer %s) - %s. Codes compared there count here as each peer arrives",
                     move->from, chat_nick(&s->engine), idhex, created ? "the peers asked along come once they say yes"
                                                                 : "chat opens once someone here answers");
        // Nobody typed them, and nothing else shows them.
        console_note(s, "this room's id is %s and its password \"%s\" - this is the only time they're shown: :invite "
                        "copies them, to pass on, and :keep keeps the room", chat_session_name(&s->engine), move->password);
    } else if (created) {
        console_note(s, "new session '%s' - :invite copies its id and password, to pass on. you are %s (peer %s)",
                     chat_session_name(&s->engine), chat_nick(&s->engine), idhex);
    } else {
        console_note(s, "joining '%s' as %s (peer %s) - chat opens once someone answers",
                     chat_session_name(&s->engine), chat_nick(&s->engine), idhex);
    }
    if (g_app.route.mode == ROUTE_TOR && g_app.net_log != NET_LOG_OFF)
        console_note(s, "* routing: %s - connecting takes a little longer", route_label());
    return s;
}

session_slot_t *start_session(const char *session_name, const char *password, int created, uint16_t port,
                              const addr_t *peers, int n_peers) {
    return open_session(session_name, password, created, port, peers, n_peers, NULL);
}

session_slot_t *start_moved_session(const chat_move_to_t *to) {
    return open_session(to->session_name, to->password, to->created, 0, NULL, 0, to);
}

// New/join prompts use the input line. The draft is saved and restored when the prompt ends.
void begin_prompt(app_mode_t mode) {
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_app.mode = mode;
    g_app.dirty = 1;
}

// The id is often passed around in the open, so the password carries the weight against guessing: the
// field starts with a random one, unmasked since it has to be passed on.
void begin_new_session(void) {
    begin_prompt(MODE_NEW_PASSWORD);
    uint8_t pw[MOVE_PASSWORD_BYTES];
    gen_random(pw, sizeof pw);
    bytewords_plain(pw, sizeof pw, g_app.input.buf);
    crypto_wipe(pw, sizeof pw);
    g_app.input.len = g_app.input.cursor = (int)strlen(g_app.input.buf);
    g_app.pw_suggested = 1;
}

void end_prompt(void) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    crypto_wipe(g_app.pending_session_id, sizeof g_app.pending_session_id);
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.pw_suggested = 0;
    g_app.mode = MODE_CHAT;
    g_app.dirty = 1;
}

cmd_result_t app_new(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_new_session();
    return CMD_OK;
}

cmd_result_t app_join(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_rooms();
    return CMD_OK;
}

// ---- kept rooms ----

static session_slot_t *open_room(const char *id) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_app.used[i] && !g_app.sessions[i].leaving && strcmp(g_app.sessions[i].name, id) == 0)
            return &g_app.sessions[i];
    return NULL;
}

// The kept rooms written to the open save, then done said.
static void rooms_saved(const char *done) {
    char where[APP_PATH_MAX] = "";
    install_where(install_current(), where, sizeof where);
    if (settings_write() != 0) note("couldn't write that to %s/settings - it lasts until chat exits", where);
    else note("%s", done);
}

// The room on screen, kept in the open save under a label (its id unless one's given, or the one it
// has), for Ctrl+J to join it again. "forget" lets it go.
cmd_result_t app_keep(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    if (!s || s->initialising) { note("no room on screen to keep"); return CMD_OK; }
    if (s->contact) { note("a call's room changes every day - :call finds it again"); return CMD_OK; }
    int at = rooms_find(s->name);
    char label[ROOM_LABEL_MAX + 1], done[160];
    const char *shown = install_shown_name(install_current());
    if (strcmp(arg, "forget") == 0) {
        if (at < 0) { note("this room isn't kept"); return CMD_OK; }
        snprintf(done, sizeof done, "%s: no longer kept in the save %s", room_at(at)->label, shown);
        rooms_forget(at);
        rooms_saved(done);
        return CMD_OK;
    }
    if (!g_app.installed || g_app.locked) { note("a room is kept in a save - :install makes one"); return CMD_OK; }
    if (at < 0 && rooms_count() >= ROOMS_MAX) {
        note("%d rooms are kept already - :keep forget one", ROOMS_MAX);
        return CMD_OK;
    }
    copy_str(label, arg[0] ? arg : at >= 0 ? room_at(at)->label : s->name, sizeof label);
    int i = rooms_keep(label, s->name, s->password);
    if (i < 0) { note("this room can't be kept"); return CMD_OK; }
    snprintf(done, sizeof done, "%s: %s in the save %s" DOT_SEP "Ctrl+J joins it", room_at(i)->label,
             at < 0 ? "kept" : "kept, with that label,", shown);
    rooms_saved(done);
    return CMD_OK;
}

// With rooms kept, Ctrl+J lists them, and "another room" under them asks for an id as before.
void begin_rooms(void) {
    if (!rooms_count()) { begin_prompt(MODE_JOIN_ID); return; }
    if (g_app.rooms.sel > rooms_count()) g_app.rooms.sel = 0;
    g_app.rooms.forgetting = 0;
    begin_prompt(MODE_ROOMS);
}

static void join_room(int i) {
    const room_t *r = room_at(i);
    if (!r) return;
    session_slot_t *s = open_room(r->id);
    end_prompt();
    if (s) { select_session(s); note("%s is open already", r->label); return; }
    char id[MAX_SESSION_NAME + 1], pw[MAX_PASSWORD + 1];
    copy_str(id, r->id, sizeof id);
    copy_str(pw, r->password, sizeof pw);
    start_session(id, pw, 0, 0, NULL, 0);
    crypto_wipe(pw, sizeof pw);
}

void rooms_key(const tui_key_t *key) {
    int n = rooms_count(), i = g_app.rooms.sel;
    if (g_app.rooms.forgetting) {
        int yes = key->type == TUI_KEY_CHAR && key->ch_len == 1 && (key->ch[0] == 'y' || key->ch[0] == 'Y');
        int no = key->type == TUI_KEY_ESCAPE
              || (key->type == TUI_KEY_CHAR && key->ch_len == 1 && strchr("nNq", key->ch[0]));
        if (!yes && !no) return;
        g_app.rooms.forgetting = 0;
        g_app.dirty = 1;
        if (no) return;
        char done[160];
        snprintf(done, sizeof done, "%s: no longer kept in the save %s", room_at(i)->label,
                 install_shown_name(install_current()));
        rooms_forget(i);
        if (g_app.rooms.sel > 0 && g_app.rooms.sel >= rooms_count()) g_app.rooms.sel--;
        if (!rooms_count()) end_prompt();
        rooms_saved(done);
        return;
    }
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && i < n && (key->ch[0] == 'd' || key->ch[0] == 's')) {
        if (key->ch[0] == 'd') { g_app.rooms.forgetting = 1; g_app.dirty = 1; return; }
        char done[160];
        rooms_set_start(i, !room_at(i)->at_start);
        snprintf(done, sizeof done, "%s: %s", room_at(i)->label,
                 room_at(i)->at_start ? "joined as chat starts" : "not joined as chat starts");
        rooms_saved(done);
        g_app.dirty = 1;
        return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT:
            if (i < n) { join_room(i); return; }
            end_prompt();
            begin_prompt(MODE_JOIN_ID);
            return;
        case LIST_LEFT:
        case LIST_BACK:
        case LIST_CLOSE:
            end_prompt();
            return;
        default:
            list_move(k, &g_app.rooms.sel, n + 1);
            g_app.dirty = 1;
            return;
    }
}

// The rooms marked to, once chat starts reaching the network.
void rooms_join_at_start(void) {
    if (!g_app.installed || g_app.locked) return;
    for (int i = 0; i < rooms_count(); i++) {
        const room_t *r = room_at(i);
        if (!r || !r->at_start || open_room(r->id)) continue;
        char id[MAX_SESSION_NAME + 1], pw[MAX_PASSWORD + 1];
        copy_str(id, r->id, sizeof id);
        copy_str(pw, r->password, sizeof pw);
        start_session(id, pw, 0, 0, NULL, 0);
        crypto_wipe(pw, sizeof pw);
    }
}

// ---- reopening sessions ----

// Only once the row's saved, so with autosave off nothing goes in the save before :save.
static int reopen_saving(void) {
    return g_app.reopen && !g_app.quit_leaving && g_app.installed && !g_app.locked
           && strcmp(g_saved_rows[settings_index(SET_REOPEN)], "on") == 0;
}

// Calls aren't kept: :call finds the day's room again.
int session_kept(const session_slot_t *s) {
    return reopen_saving() && !g_app.reopen_due && !s->leaving && !s->contact && !s->initialising;
}

// The sessions kept in a save that's just opened, once chat reaches the network. One that can't open
// (a port in use, say) stays kept for the next start.
void reopen_tick(void) {
    if (!g_app.reopen_due || g_app.onboarding || !g_app.installed || g_app.locked) return;
    g_app.reopen_due = 0;
    if (!reopen_saving()) return;
    for (int i = 0; i < reopen_count(); i++) {
        const room_t *r = reopen_at(i);
        if (!r || open_room(r->id)) continue;
        char id[MAX_SESSION_NAME + 1], pw[MAX_PASSWORD + 1];
        copy_str(id, r->id, sizeof id);
        copy_str(pw, r->password, sizeof pw);
        if (!start_session(id, pw, 0, 0, NULL, 0)) reopen_failed(i);
        crypto_wipe(pw, sizeof pw);
    }
}

// Before every frame, like the settings: the open save keeps the sessions open as they open and close.
void keep_sessions_saved(void) {
    if (g_app.reopen_due || g_app.onboarding || !g_app.installed || g_app.locked) return;
    reopen_begin();
    if (reopen_saving()) {
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (g_app.used[i] && session_kept(&g_app.sessions[i]))
                reopen_add(g_app.sessions[i].name, g_app.sessions[i].password, 0);
        for (int i = 0; i < reopen_count(); i++) {
            const room_t *r = reopen_at(i);
            if (r->unopened && !open_room(r->id)) reopen_add(r->id, r->password, 1);
        }
    }
    if (reopen_end() && settings_write() != 0) {
        char where[APP_PATH_MAX] = "";
        install_where(install_current(), where, sizeof where);
        note("couldn't write the sessions to reopen to %s/settings", where);
    }
}

// ---- calls ----

static session_slot_t *open_call(const uint8_t pub[ID_SIGN_PUB_LEN]) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_slot_t *s = &g_app.sessions[i];
        if (g_app.used[i] && !s->leaving && s->contact && memcmp(s->contact_pub, pub, ID_SIGN_PUB_LEN) == 0) return s;
    }
    return NULL;
}

// Only the verified key gets anything there, whatever :set verify says.
static session_slot_t *call_open(const trust_entry_t *t, uint64_t day) {
    char id[SESSION_ID_LEN + 1], pw[CONTACT_PASSWORD_LEN + 1], nick[MAX_NICK + 1];
    uint8_t pub[ID_SIGN_PUB_LEN];
    memcpy(pub, t->pub, sizeof pub);
    copy_str(nick, t->nick, sizeof nick);
    if (chat_contact_room(&g_app.identity, pub, day, id, pw) != 0) {
        note("no room can be worked out with %s's key", nick);
        return NULL;
    }
    session_slot_t *s = start_session(id, pw, 0, 0, NULL, 0);
    crypto_wipe(pw, sizeof pw);
    if (!s) return NULL;
    s->contact = 1;
    memcpy(s->contact_pub, pub, sizeof s->contact_pub);
    s->contact_day = day;
    snprintf(s->name, sizeof s->name, "@%s", nick);
    chat_set_verify_required(&s->engine, 1);
    console_note(s, "* calling %s: a room only your signing key and theirs can work out, for today (UTC). They "
                    "have to :call you too, and nothing goes to anyone there but the key you verified", nick);
    return s;
}

// :call NICK: the room of a verified key's, which they open with :call too.
cmd_result_t app_call(void *ctx, const char *arg) {
    (void)ctx;
    if (!arg[0]) { note("call whom? :call NICK, for a key :verified lists"); return CMD_OK; }
    if (g_app.identity_source == IDENT_NONE) {
        note("a call needs a signing identity of yours, which they've verified - :set sign");
        return CMD_OK;
    }
    char skel[NICK_SKEL_LEN];
    chat_nick_skeleton(arg, skel, sizeof skel);
    int at = trust_find_nick(skel, 0);
    if (at < 0) { note("no verified key goes by %.40s - :verified lists them", arg); return CMD_OK; }
    if (trust_find_nick(skel, at + 1) >= 0) {
        note("more than one verified key goes by %.40s - :verified forget the one that's gone", arg);
        return CMD_OK;
    }
    const trust_entry_t *t = trust_at(at);
    session_slot_t *s = open_call(t->pub);
    if (s) { select_session(s); note("the call with %s is open already", t->nick); return CMD_OK; }
    call_open(t, chat_contact_day());
    return CMD_OK;
}

// A call nobody's in moves to the new day's room as the day changes, so two who :call either side of
// midnight (UTC), or with clocks a little apart, still meet.
void contacts_tick(void) {
    uint64_t day = chat_contact_day();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_slot_t *s = &g_app.sessions[i], *sel = g_app.selected;
        if (!g_app.used[i] || s->leaving || !s->contact || s->initialising || s->contact_day == day
            || chat_online_count(&s->engine) > 0)
            continue;
        const trust_entry_t *t = trust_by_key(s->contact_pub);
        char name[sizeof s->name];
        copy_str(name, s->name, sizeof name);
        close_session(s);
        if (!t) { push_log("* the call %s ended: their key isn't verified any more", name); continue; }
        if (call_open(t, day) && sel != s && sel && g_app.used[slot_index(sel)]) select_session(sel);
    }
}

// While set, the first line a session prints to its console goes on the bottom bar too: the reply to
// a file action, which would otherwise only reach a console that may be hidden, or not on screen.
int g_echo;

void session_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                          unsigned flags, int color_len, int file) {
    session_slot_t *s = (session_slot_t *)ui;
    if ((flags & LINE_CHAT) && s->hist) history_add(s, text, rgb, (flags & LINE_MENTION) != 0, color_len);
    if (g_echo == 1 && !(flags & LINE_CHAT) && s == g_app.selected) {
        copy_str(g_app.message, strncmp(text, "* ", 2) == 0 ? text + 2 : text, sizeof g_app.message);
        g_echo = 2;
    }
    // A warning goes in the chat too, since the console can be hidden.
    if (flags & LINE_WARN) {
        tui_scrollback_push(&s->sb, hhmm, text, NULL, 0, 0);
        if (s != g_app.selected) { s->unread++; s->mentioned = 1; }
        if (s->scroll > 0 && s->scroll < s->sb.count - 1) s->scroll++;
    }
    if (flags & LINE_CHAT) {
        tui_scrollback_push(&s->sb, hhmm, text, rgb, (flags & LINE_MENTION) != 0, color_len);
        if (file) tui_scrollback_mark_file(&s->sb, file);
        if (flags & LINE_OWN) tui_scrollback_mark_own(&s->sb, chat_own_seq(&s->engine));
        if (chat_line_quote(&s->engine)) tui_scrollback_mark_quote(&s->sb, chat_line_quote(&s->engine));
        if (s != g_app.selected) {
            s->unread++;
            if (flags & LINE_MENTION) s->mentioned = 1;
        }
        // When scrolled back, the chat stays on the messages in view.
        if (s->scroll > 0 && s->scroll < s->sb.count - 1) s->scroll++;
    } else {
        push_console(&s->console, &s->console_scroll, hhmm, text, rgb);
    }
    g_app.dirty = 1;
}

void session_delivery(void *ui, unsigned own, chat_delivery_t what, const char *name) {
    session_slot_t *s = ui;
    if (tui_scrollback_delivery(&s->sb, own, what == CHAT_MISSED ? name : NULL) && s == g_app.selected) g_app.dirty = 1;
}

int session_ready(const session_slot_t *s) { return !s->initialising && chat_ready(&s->engine); }

// Each session's message timer: what came before it goes from the chat, the pictures shown with it
// go too, and so does that much of its history.
void timers_tick(double now) {
    static double next;
    if (now < next) return;
    next = now + 1.0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_slot_t *s = &g_app.sessions[i];
        if (!g_app.used[i] || s->initialising) continue;
        unsigned timer = chat_timer(&s->engine, NULL, 0);
        if (!timer) continue;
        int files[TUI_SCROLLBACK], n_files = 0;
        int gone = tui_scrollback_expire(&s->sb, now - timer, files, &n_files, TUI_SCROLLBACK);
        for (int k = 0; k < n_files; k++) {
            pic_t *pic = pic_find(s, files[k]);
            if (pic) pic_free(pic);
        }
        if (s->scroll > s->sb.count - 1) s->scroll = s->sb.count > 0 ? s->sb.count - 1 : 0;
        history_expire(s, timer);
        if (gone) g_app.dirty = 1;
    }
}

// That a message came in, plus who sent it and what it says only if the preview setting let the
// engine pass them on (otherwise nick and text are NULL). Never the session, since desktops keep a
// history of notifications (Windows writes it to disk), and with a blank password a session's id
// is all someone needs to join it.
void send_notification(const char *nick, const char *text, int mentioned) {
    char title[CHAT_NAME_LEN * 2 + 48], body[MAX_TEXT + CHAT_NAME_LEN * 2 + 48];
    // Locked, whatever preview says.
    if (g_app.lock.on) nick = text = NULL;
    if (nick && text) {
        snprintf(title, sizeof title, mentioned ? "%s mentioned you" : "%s", nick);
        copy_str(body, text, sizeof body);
    } else if (nick) {
        copy_str(title, "chat", sizeof title);
        snprintf(body, sizeof body, mentioned ? "%s mentioned you" : "new message from %s", nick);
    } else {
        copy_str(title, "chat", sizeof title);
        copy_str(body, mentioned ? "you were mentioned" : "new message", sizeof body);
    }
    platform_notify(title, body);
    crypto_wipe(body, sizeof body);
}

void session_notify(void *ui, const char *nick, const char *text, int mentioned) {
    (void)ui;
    send_notification(nick, text, mentioned);
}

int slot_index(session_slot_t *s) { return (int)(s - g_app.sessions); }

session_slot_t *find_free_slot(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) if (!g_app.used[i]) return &g_app.sessions[i];
    return NULL;
}

// The conversation and console on screen are kept out of swap, like the keys. Best effort: beyond
// RLIMIT_MEMLOCK they're just kept in memory as normal.
void lock_scrollbacks(session_slot_t *s) {
    crypto_lock(&s->sb, sizeof s->sb);
    crypto_lock(&s->console, sizeof s->console);
    crypto_lock(s->password, sizeof s->password);
}

// Zeroes them as it unlocks them, and the room's password.
void release_scrollbacks(session_slot_t *s) {
    crypto_unlock(&s->sb, sizeof s->sb);
    crypto_unlock(&s->console, sizeof s->console);
    crypto_wipe(s->password, sizeof s->password);
}

// Puts s on screen (or none). The session being left loses its new messages line, and s gets one
// above what arrived while it was away, which then counts as read.
void select_session(session_slot_t *s) {
    if (g_app.selected && g_app.selected != s) g_app.selected->has_new = 0;
    g_app.selected = s;
    g_app.dirty = 1;
    if (!s) return;
    if (s->unread > 0 && !s->has_new) {
        s->has_new = 1;
        s->new_at = s->sb.total - (unsigned)s->unread;
    }
    s->unread = 0;
    s->mentioned = 0;
}

// The first open session, or NULL.
session_slot_t *first_session(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i] && !g_app.sessions[i].leaving) return &g_app.sessions[i];
    return NULL;
}

void close_session(session_slot_t *s) {
    if (!s) return;
    int idx = slot_index(s);
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) chat_move_unlink(&g_app.sessions[i].engine, &s->engine);
    view_forget(s);
    history_stop(s, 1);
    chat_shutdown(&s->engine);
    pics_free(s);
    release_scrollbacks(s);
    g_app.used[idx] = 0;
    if (g_app.selected == s) {
        g_app.selected = NULL;
        select_session(first_session());
    }
    g_app.dirty = 1;
}

void select_step(int dir) {
    session_slot_t *vis[MAX_SESSIONS]; int n = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i] && !g_app.sessions[i].leaving) vis[n++] = &g_app.sessions[i];
    if (n == 0) { select_session(NULL); return; }
    int cur = 0;
    for (int i = 0; i < n; i++) if (vis[i] == g_app.selected) { cur = i; break; }
    select_session(vis[(cur + dir + n) % n]);
}

void console_note(session_slot_t *s, const char *fmt, ...) {
    char msg[300];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    char hhmm[HHMM_LEN]; current_hhmm(hhmm);
    push_console(&s->console, &s->console_scroll, hhmm, msg, NULL);
    g_app.dirty = 1;
}
