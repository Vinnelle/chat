// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// --simple: a line-by-line UI, for terminals that can't do the full screen and for scripts.
#include "app/app.h"
#include "changelog.h"

// The session of --simple mode, which isn't in the session list.
chat_t *g_plain_engine;

// ---- routing: asked at the start of --simple; the full-screen UI opens on the settings page ----

static const char *const ROUTE_CHOICE_LINES[] = {
    "* how should chat reach people?",
    ("*   [1] UDP (recommended): straight to peers, found through the BitTorrent DHT (IPv4 and IPv6), your "
     "LAN and a router port mapping. Peers see your IP address"),
    ("*   [2] Tor: onion services, which hide your IP address from peers and everyone else. Uses tor or Tor "
     "Browser if one is running, else starts its own; connecting takes longer"),
    ("* either way, public Nostr relays carry the traffic, encrypted and padded, when the route can't, and "
     "UDP and Tor members meet there (--nostr off turns them off)"),
};

// --simple: a picture requested with :show is printed at the current point in the conversation,
// two pixel rows per line of half blocks.
static void plain_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
    (void)ui; (void)name;
    static const uint8_t bg[3] = { 0, 0, 0 };
    image_thumb_t th;
    char why[160];
    const file_entry_t *f = g_plain_engine ? chat_file(g_plain_engine, num) : NULL;
    if (!term_ansi_ok()) {
        // One you've just sent isn't worth a note.
        if (!(f && f->mine)) printf("* file %d came, but showing a picture needs a terminal with colour - :download %d saves it\n", num, num);
        return;
    }
    if (thumb_decode(data, len, TUI_IMAGE_MAX_W, TUI_IMAGE_MAX_H, bg, &th, why, sizeof why) != 0) {
        printf("* can't show file %d: %s - :download %d saves it\n", num, why, num);
        return;
    }
    for (int y = 0; y < th.h; y += 2) {
        fputs("  ", stdout);
        for (int x = 0; x < th.w; x++) {
            const uint8_t *t = th.rgb + ((size_t)y * (size_t)th.w + (size_t)x) * 3;
            if (y + 1 < th.h) {
                const uint8_t *b = t + (size_t)th.w * 3;
                printf("\x1b[38;2;%u;%u;%u;48;2;%u;%u;%um\xe2\x96\x80", t[0], t[1], t[2], b[0], b[1], b[2]);
            } else {
                printf("\x1b[0;38;2;%u;%u;%um\xe2\x96\x80", t[0], t[1], t[2]);
            }
        }
        fputs("\x1b[0m\n", stdout);
    }
    printf("* file %d (%dx%d)\n", num, th.src_w, th.src_h);
    fflush(stdout);
    thumb_free(&th);
}

static void plain_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                        unsigned flags, int color_len, int file) {
    (void)ui;
    (void)file;
    int mention = (flags & LINE_MENTION) != 0;
    int ansi = term_ansi_ok();
    if (ansi && mention) printf("[%s] \x1b[1m\x1b[48;2;110;70;10m%s\x1b[0m\n", hhmm, text);
    else if (ansi && (flags & LINE_WARN)) printf("[%s] \x1b[1;33m%s\x1b[0m\n", hhmm, text);
    else if (ansi && rgb && color_len > 0 && (size_t)color_len < strlen(text))
        printf("[%s] \x1b[38;2;%d;%d;%dm%.*s\x1b[0m%s\n", hhmm, rgb[0], rgb[1], rgb[2], color_len, text, text + color_len);
    else if (ansi && rgb) printf("[%s] \x1b[38;2;%d;%d;%dm%s\x1b[0m\n", hhmm, rgb[0], rgb[1], rgb[2], text);
    else printf("[%s] %s\n", hhmm, text);
    fflush(stdout);
}

static void plain_notify(void *ui, const char *nick, const char *text, int mentioned) {
    (void)ui;
    send_notification(nick, text, mentioned);
}

static void plain_delivery(void *ui, unsigned own, chat_delivery_t what, const char *name) {
    (void)ui; (void)own;
    if (what == CHAT_MISSED) { printf("* not reached: %s\n", name); fflush(stdout); }
}

// A room :move left prints nothing while it closes.
static void plain_quiet(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len,
                        int file) {
    (void)ui; (void)hhmm; (void)text; (void)rgb; (void)flags; (void)color_len; (void)file;
}

// --simple's :move opens the new room in whichever engine isn't in use. A room an earlier move left, if
// it's still closing, closes first. Returns the new room, or NULL after saying why it didn't open.
static chat_t *plain_move(chat_t *c, chat_t **left, chat_t engines[2], const chat_move_to_t *to) {
    if (*left) { chat_shutdown(*left); *left = NULL; }
    chat_t *n = c == &engines[0] ? &engines[1] : &engines[0];
    chat_opts_t o; memset(&o, 0, sizeof o);
    copy_str(o.nick, c->nick, sizeof o.nick);
    copy_str(o.session_name, to->session_name, sizeof o.session_name);
    copy_str(o.password, to->password, sizeof o.password);
    o.created = to->created;
    o.route = g_app.route;
    if (o.route.mode == ROUTE_TOR) {
        copy_str(o.route.tor.socks, g_tor.state == TL_READY ? g_tor.socks : "", sizeof o.route.tor.socks);
        copy_str(o.route.tor.control, g_tor.state == TL_READY ? g_tor.control : "", sizeof o.route.tor.control);
    }
    app_session_opts(&o);
    memcpy(o.color, c->my_color, 3);
    o.moved = 1;
    o.moved_key = to->key;
    push_log("* moving to a new room - deriving its keys...");
    chat_init(n, &o, plain_print, plain_notify, NULL, now_seconds());
    crypto_wipe(&o, sizeof o);
    if (!chat_started(n)) {
        push_log("* couldn't open the new room: %s", chat_start_error(n));
        chat_shutdown(n);
        return NULL;
    }
    if (n->route.mode == ROUTE_TOR && g_tor.state == TL_READY && g_tor.proc)
        chat_tor_set_ports(n, g_tor.socks, g_tor.control, torproc_password(g_tor.proc));
    n->file_view = plain_file_view;
    n->delivery = plain_delivery;
    n->net_verbose = c->net_verbose;
    n->net_quiet = c->net_quiet;
    chat_move_go(c, to, n, now_seconds());
    c->print = plain_quiet;
    push_log("* moved here from '%s' - %s. Codes compared there count here as each peer arrives", to->from,
             to->created ? "the peers asked along come once they say yes" : "chat opens once someone here answers");
    push_log("* this room's id is %s and its password \"%s\" - this is the only time they're shown, so keep them if you "
             "want to come back or invite someone", n->session_name, to->password);
    return n;
}

// The session --simple opens, from what was given and what's asked for. 0, or what chat exits with.
static int plain_opts(chat_opts_t *o, const char *session_name, const char *password, uint16_t port,
                      const char peer_args[][PEER_ARG_LEN], int n_peer_args) {
    int tty = term_is_tty();
    memset(o, 0, sizeof *o);
    copy_str(o->nick, g_app.nick[0] ? g_app.nick : "anon", sizeof o->nick);

    if (session_name) {
        copy_str(o->session_name, session_name, sizeof o->session_name);
    } else if (tty) {
        char line[MAX_SESSION_NAME + 1];
        if (term_read_line("session id (blank = start a new one): ", line, sizeof line) != 0) return 1;
        copy_str(o->session_name, line, sizeof o->session_name);
    }
    if (!o->session_name[0]) {
        // Without a terminal too: no fixed default, since a well known id with a blank password would
        // be a room anyone can join.
        random_session_id(o->session_name, SESSION_ID_LEN);
        o->created = 1;
        printf("new session id: %s  (share this and the password)\n", o->session_name);
    }

    if (password) copy_str(o->password, password, sizeof o->password);
    else if (platform_env_take("CHAT_PASSWORD", o->password, sizeof o->password) != 0 && tty
             && term_read_password(o->created ? "create password: " : "password: ", o->password, sizeof o->password) != 0)
        return 1;

    o->port = port;
    if (!g_app.route_chosen) {
        route_mode_t m = ROUTE_UDP;
        if (tty) {
            // Without the "* " the log puts first.
            for (size_t i = 0; i < COUNT_OF(ROUTE_CHOICE_LINES); i++)
                printf("%s\n", ROUTE_CHOICE_LINES[i] + 2);
            char line[16];
            if (term_read_line("routing [1/2, Enter = 1]: ", line, sizeof line) != 0) return 1;
            if (line[0] == '2') m = ROUTE_TOR;
        }
        choose_route(m);
    }
    sandbox_up();
    // --peer names are only looked up once the routing is decided, and never for Tor, where the lookup
    // would bypass it.
    if (n_peer_args > 0 && g_app.route.mode == ROUTE_TOR) {
        fprintf(stderr, "chat: --peer can't be used with Tor routing\n");
        crypto_wipe(o, sizeof *o);
        return 1;
    }
    for (int i = 0; i < n_peer_args && o->n_peers < (int)COUNT_OF(o->peers); i++) {
        if (addr_parse_hostport(peer_args[i], &o->peers[o->n_peers]) != 0) {
            fprintf(stderr, "chat: can't use --peer %s\n", peer_args[i]);
            crypto_wipe(o, sizeof *o);
            return 1;
        }
        o->n_peers++;
    }
    sync_update_proxy();
    o->route = g_app.route;
    if (o->route.mode == ROUTE_TOR) {
        tor_link_ensure(now_seconds());
        o->route.tor.socks[0] = o->route.tor.control[0] = '\0';
    }
    app_session_opts(o);

    return 0;
}

static void plain_banner(chat_t *c) {
    chat_set_net_log(c, g_app.net_log);
    char idhex[SHORT_ID_HEX + 1]; hex_encode(c->my_id, SHORT_ID_LEN, idhex);
    if (c->route.mode == ROUTE_TOR)
        printf("session '%s', you are %s (peer %s). encrypted, over Tor only. :quit or EOF to stop.\n",
               c->session_name, c->nick, idhex);
    else
        printf("session '%s', you are %s (peer %s). encrypted, udp/%u, routing: %s. :quit or EOF to stop.\n",
               c->session_name, c->nick, idhex, (unsigned)c->port, route_label());
}

// A line typed, or EOF: 0 once it's time to stop.
static int plain_input(chat_t *c, stdin_reader_t *reader, double now) {
    char line[MAX_TEXT + 1];
    int rc = stdin_reader_poll(reader, line, sizeof line);
    static const char show[] = ":show ";
    int show_anyway, show_n = rc == 1 && starts_with(line, show) ? file_arg(line + sizeof show - 1, &show_anyway) : 0;
    if (rc == 1 && (strcmp(line, ":changelog") == 0 || strcmp(line, ":news") == 0)) { fputs(CHANGELOG_TEXT, stdout); fflush(stdout); }
    else if (rc == 1 && strcmp(line, ":newtor") == 0) { app_newtor(NULL, NULL); push_log("* %s", g_app.message); g_app.message[0] = '\0'; }
    else if (show_n) chat_file_fetch(c, show_n, 1, show_anyway, NULL);
    else if (rc == 1) return chat_submit_line(c, line, now);
    else if (rc == -1) return 0;
    return 1;
}

static _Noreturn void plain_quit(chat_t *c, chat_t *left, stdin_reader_t *reader) {
    if (g_panic) panic_saves();
    if (left) chat_shutdown(left);
    chat_shutdown(c);
    g_plain_engine = NULL;
    tor_link_stop();
    if (reader) stdin_reader_stop(reader);
    term_raw_disable();
    net_shutdown();
    platform_notify_shutdown();
    fflush(stdout);
    _exit(0);
}

int run_plain(const char *session_name, const char *password, uint16_t port,
              const char peer_args[][PEER_ARG_LEN], int n_peer_args) {
    g_plain = 1;
    say_saved_notes();
    chat_opts_t o;
    if (plain_opts(&o, session_name, password, port, peer_args, n_peer_args) != 0) return 1;

    // Two, so a room :move left can close while the new one runs.
    static chat_t engines[2];
    chat_t *c = &engines[0], *left = NULL;
    chat_init(c, &o, plain_print, plain_notify, NULL, now_seconds());
    c->file_view = plain_file_view;
    c->delivery = plain_delivery;
    g_plain_engine = c;
    crypto_wipe(&o, sizeof o);
    if (!chat_started(c)) {
        fprintf(stderr, "chat: %s\n", chat_start_error(c));
        chat_shutdown(c);
        g_plain_engine = NULL;
        tor_link_stop();
        return 1;
    }
    plain_banner(c);

    catch_quit_signals();
    stdin_reader_t *reader = stdin_reader_start();
    int alive = 1;
    // No box to ask in here, so a second press within CTRL_C_AGAIN seconds confirms. From a script,
    // Ctrl+C still quits at once.
    enum { CTRL_C_AGAIN = 3 };
    double ctrl_c_at = -CTRL_C_AGAIN;
    while (alive && !g_interrupted) {
        sock_t socks[2 * CHAT_MAX_SOCKS];
        int nc = chat_sockets(c, socks), ns = nc + (left ? chat_sockets(left, socks + nc) : 0);
        int ready[2 * CHAT_MAX_SOCKS] = {0};
        net_wait(socks, ready, ns, WAIT_MS);
        double now = now_seconds();
        if (g_ctrl_c) {
            g_ctrl_c = 0;
            if (!term_is_tty() || now - ctrl_c_at < CTRL_C_AGAIN) break;
            ctrl_c_at = now;
            push_log("* Ctrl+C again within %d seconds leaves the session and quits (so does :quit)", CTRL_C_AGAIN);
        }
        if (g_sigquit) {
            g_sigquit = 0;
            if (g_app.panic.key) panic(PANIC_KEY);
            break;
        }
        for (int i = 0; i < ns; i++) if (ready[i]) chat_on_socket_readable(i < nc ? c : left, socks[i], now);
        alive = plain_input(c, reader, now);
        chat_move_to_t to;
        if (alive && chat_move_staged(c, &to)) {
            chat_t *n = plain_move(c, &left, engines, &to);
            if (n) { left = c; c = n; g_plain_engine = c; }
            crypto_wipe(&to, sizeof to);
        }
        tor_link_ensure(now);
        tor_link_step(now);
        chat_tick(c, now_seconds());
        if (left) {
            chat_tick(left, now_seconds());
            if (chat_move_finished(left, now_seconds())) { chat_shutdown(left); left = NULL; }
        }
    }
    plain_quit(c, left, reader);
}
