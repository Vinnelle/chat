// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The commands a session takes (CHAT_COMMANDS).
#include "core/engine.h"

static cmd_result_t cmd_help(void *ctx, const char *arg) {
    chat_t *c = ctx; (void)arg;
    ui_print(c, "* commands - anything not starting with : is sent to the room:");
    for (const command_t *cmd = CHAT_COMMANDS; cmd->name; cmd++) {
        char line[160]; cmd_format_help(cmd, ':', line, sizeof line);
        ui_print(c, "%s", line);
    }
    return CMD_OK;
}

static cmd_result_t cmd_peers(void *ctx, const char *arg) {
    chat_t *c = ctx; (void)arg;
    int n = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        if (n++ == 0) ui_print(c, "* online: %s (you), and:", c->nick);
        char idhex[SHORT_ID_HEX + 1]; short_id(p->id, idhex);
        char vfyhex[HEX_GROUPS_LEN(VERIFY_LEN)]; hex_groups(p->vfy, VERIFY_LEN, vfyhex);
        char build[64]; chat_build_label(p, build, sizeof build);
        static const char *const CODE[] = { "", ", code not compared", ", code compared", ", CODES DIFFER", ", KEY CHANGED" };
        ui_print(c, "*   %s#%s (verify %s%s, %s, %s%s%s)", p->nick, idhex, vfyhex, CODE[chat_code_state(c, p)],
                 chat_verify_label(p->identity_state), build, p->persists ? ", keeps history" : "",
                 chat_ignored(c, p->id) ? ", ignored" : "");
    }
    if (n == 0) ui_print(c, "* nobody else yet");
    return CMD_OK;
}

// The online peer an argument refers to: a nick, or NICK#ID (a prefix of the id :peers shows) when
// nicks look alike. NULL if none, or (*ambiguous) more than one.
static peer_t *peer_by_name(chat_t *c, const char *arg, int *ambiguous) {
    char name[CHAT_NAME_LEN];
    copy_str(name, arg, sizeof name);
    char *hash = strchr(name, '#');
    const char *prefix = "";
    if (hash) { *hash = '\0'; prefix = hash + 1; }
    peer_t *found = NULL;
    *ambiguous = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok || !nick_ieq(p->nick, name)) continue;
        char idhex[ID_LEN * 2 + 1]; hex_encode(p->id, ID_LEN, idhex);
        if (strlen(prefix) > sizeof idhex - 1 || strncmp(idhex, prefix, strlen(prefix)) != 0) continue;
        if (found) { *ambiguous = 1; return NULL; }
        found = p;
    }
    return found;
}

// :ignore, :ignore NICK, :ignore NICK off. Only on this screen: nothing is sent, so nobody can tell.
static cmd_result_t cmd_ignore(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char who[MAX_TEXT + 1];
    copy_str(who, arg, sizeof who);
    char *sp = strrchr(who, ' ');
    int off = sp && strcmp(sp + 1, "off") == 0;
    if (off) {
        while (sp > who && sp[-1] == ' ') sp--;
        *sp = '\0';
    }
    if (!who[0]) {
        char names[MAX_PEERS * (CHAT_NAME_LEN + 2) + 1] = "";
        size_t at = 0;
        for (int i = 0; i < c->peer_hi; i++) {
            peer_t *p = &c->peers[i];
            if (!p->used || !p->ok || !chat_ignored(c, p->id)) continue;
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            int n = snprintf(names + at, sizeof names - at, "%s%s", at ? ", " : "", name);
            if (n > 0 && (size_t)n < sizeof names - at) at += (size_t)n;
        }
        if (at) ui_print(c, "* ignored here: %s", names);
        else ui_print(c, "* nobody online here is ignored - :ignore NICK hides what someone says");
        if (ignore_count()) {
            names[0] = '\0';
            at = 0;
            for (int i = 0; i < ignore_count(); i++) {
                int n = snprintf(names + at, sizeof names - at, "%s%s", at ? ", " : "", ignore_at(i)->nick);
                if (n > 0 && (size_t)n < sizeof names - at) at += (size_t)n;
            }
            ui_print(c, "* signing keys ignored in every session: %s", names);
        }
        return CMD_OK;
    }
    int ambiguous;
    peer_t *p = peer_by_name(c, who, &ambiguous);
    if (!p && ambiguous) {
        ui_print(c, "* more than one peer is called %s - add the #id :peers shows (:ignore %s#1a2b...)", who, who);
        return CMD_OK;
    }
    if (!p) {
        char skel[NICK_SKEL_LEN];
        chat_nick_skeleton(who, skel, sizeof skel);
        int i = off ? ignore_find_nick(skel) : -1;
        if (i >= 0) {
            ui_print(c, "* the signing key ignored as %s isn't ignored any more", ignore_at(i)->nick);
            ignore_remove(i);
        } else {
            ui_print(c, "* no online peer named '%s'", who);
        }
        return CMD_OK;
    }
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    int signs = p->identity_state == VERIFY_VERIFIED;
    if (off) {
        int was = chat_ignored(c, p->id);
        set_ignored(c, p->id, 0);
        const trust_entry_t *k = signs ? ignore_by_key(p->identity_pub) : NULL;
        if (k) ignore_remove((int)(k - ignore_at(0)));
        if (was || k) ui_print(c, "* %s isn't ignored any more - what they say shows from now on, not what they said meanwhile", name);
        else ui_print(c, "* %s isn't ignored", name);
        return CMD_OK;
    }
    if (chat_ignored(c, p->id)) {
        ui_print(c, "* %s is ignored already - :ignore %s off shows what they say again", name, name);
        return CMD_OK;
    }
    set_ignored(c, p->id, 1);
    if (signs) ignore_add(p->identity_source, p->identity_pub, p->nick);
    ui_print(c, "* %s is ignored: what they say, send you directly or offer doesn't show, and doesn't notify you. "
                "Nothing tells them, and what they say still goes on to everyone else. %s", name,
             !signs ? "They have no valid signing key, so this lasts for this session only"
             : trust_saved() ? "Their signing key is ignored in every session too, and kept in the save"
             : "Their signing key is ignored in every session too, until chat exits; :install keeps it");
    return CMD_OK;
}

// Adds p's signing key to the verified keys. If p was warned about for having the nick of another
// verified key, the entries with that nick are replaced: the user compared codes with this key.
static void pin_identity(peer_t *p) {
    if (p->identity_state != VERIFY_VERIFIED) return;
    if (p->trust == TRUST_OTHER_KEY)
        for (int i = trust_find_nick(p->nick_skel, 0); i >= 0; i = trust_find_nick(p->nick_skel, i))
            trust_remove(i);
    trust_add(p->identity_source, p->identity_pub, p->nick);
    p->trust = TRUST_KEY;
}

static cmd_result_t cmd_verify(void *ctx, const char *arg) {
    chat_t *c = ctx;
    // "NICK", "NICK ok" or "NICK no". The verdict is the last word, since a nick can contain spaces.
    char who[MAX_TEXT + 1], verdict[8] = "";
    copy_str(who, arg, sizeof who);
    char *sp = strrchr(who, ' ');
    if (sp && (strcmp(sp + 1, "ok") == 0 || strcmp(sp + 1, "yes") == 0 || strcmp(sp + 1, "no") == 0)) {
        copy_str(verdict, sp + 1, sizeof verdict);
        while (sp > who && sp[-1] == ' ') sp--;
        *sp = '\0';
    }
    if (!who[0]) {
        ui_print(c, "* usage: :verify NICK shows the code to compare with them; :verify NICK ok once it matches theirs, "
                    ":verify NICK no if it doesn't");
        return CMD_OK;
    }
    int ambiguous;
    peer_t *p = peer_by_name(c, who, &ambiguous);
    if (!p) {
        if (ambiguous) ui_print(c, "* more than one peer is called %s - add the #id :peers shows (:verify %s#1a2b...)", who, who);
        else ui_print(c, "* no online peer named '%s'", who);
        return CMD_OK;
    }
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    char code[HEX_GROUPS_LEN(VERIFY_LEN)]; hex_groups(p->vfy, VERIFY_LEN, code);
    if (verdict[0] == 'n') {
        p->code_ok = CODE_DIFFERENT;
        ui_print(c, "* %s: the codes differ - someone with this room's password may be between you. Nothing you send goes "
                    "to them now. Leave this session and start a new one, with a new password shared over a channel you trust",
                 name);
    } else if (verdict[0]) {
        int was = p->code_ok, replaced = p->trust == TRUST_OTHER_KEY;
        p->code_ok = CODE_SAME;
        pin_identity(p);
        if (was != CODE_SAME) file_offer_all(c, p);
        const char *kept = p->identity_state != VERIFY_VERIFIED
            ? ". They have no valid signing key, so this lasts for this session only"
            : trust_saved() ? ". Their signing key is saved as verified (:verified lists them)"
            : ". Their signing key counts as verified until chat exits; :install saves it";
        ui_print(c, "* %s: verify code confirmed - what you send reaches them%s%s", name, kept,
                 replaced && p->identity_state == VERIFY_VERIFIED ? ". It replaces the key verified for this nick before" : "");
    } else {
        static const char *const STATE[] = { "", " - not compared yet", " - compared", " - you said it differs",
                                             " - not compared, and they sign with another key than the one verified for this nick" };
        char words[BYTEWORDS_LEN(VERIFY_LEN)]; bytewords(p->vfy, VERIFY_LEN, words);
        ui_print(c, "* %s: verify code %s (in hex %s)%s", name, words, code, STATE[chat_code_state(c, p)]);
        if (p->identity_source != IDENT_NONE) {
            char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(p->identity_fp, ID_FP_LEN, fphex);
            ui_print(c, "* %s: signing identity fingerprint %s (%s)", name, fphex, chat_verify_label(p->identity_state));
        }
        ui_print(c, "* read the code out to them over another channel (in person, a call); if theirs is the same, "
                    ":verify %s ok - if not, :verify %s no", name, name);
    }
    return CMD_OK;
}

// ":verified" lists the verified keys, ":verified forget NICK" removes the ones with that nick,
// ":verified forget all" removes every one.
static cmd_result_t cmd_verified(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char word[CMD_WORD_MAX];
    const char *rest = cmd_parse(arg, word);
    if (strcmp(word, "forget") == 0) {
        char who[MAX_TEXT + 1];
        copy_str(who, rest, sizeof who);
        size_t wl = strlen(who);
        while (wl > 0 && who[wl - 1] == ' ') who[--wl] = '\0';
        if (!who[0]) { ui_print(c, "* usage: :verified forget NICK, or :verified forget all"); return CMD_OK; }
        int removed = 0;
        if (strcmp(who, "all") == 0) {
            while (trust_count() > 0) { trust_remove(trust_count() - 1); removed++; }
        } else {
            char nick[MAX_NICK + 1], skel[NICK_SKEL_LEN];
            chat_clean_nick(who, nick);
            nick_skeleton(nick, skel, sizeof skel);
            for (int i = trust_find_nick(skel, 0); i >= 0; i = trust_find_nick(skel, i)) { trust_remove(i); removed++; }
        }
        if (!removed) { ui_print(c, "* no verified key has the nick %s - :verified lists them", who); return CMD_OK; }
        // Peers here keep what was compared in this session, but are checked against the list again.
        for (int i = 0; i < c->peer_hi; i++)
            if (c->peers[i].used && c->peers[i].trust == TRUST_KEY) c->peers[i].trust = TRUST_UNKNOWN;
        ui_print(c, "* removed %d verified key%s%s", removed, removed == 1 ? "" : "s",
                 trust_saved() ? " from what :install saved" : "");
        return CMD_OK;
    }
    if (word[0]) { ui_print(c, "* usage: :verified lists the verified keys; :verified forget NICK removes one"); return CMD_OK; }
    int n = trust_count();
    if (n == 0) {
        ui_print(c, "* no verified keys yet. :verify NICK ok adds the signing key of a peer whose code you compared");
        return CMD_OK;
    }
    ui_print(c, "* %d verified key%s%s:", n, n == 1 ? "" : "s",
             trust_saved() ? ", saved with what :install saved" : ", kept until chat exits (:install saves them)");
    for (int i = 0; i < n; i++) {
        const trust_entry_t *t = trust_at(i);
        uint8_t fp[ID_FP_LEN]; identity_fingerprint(t->pub, fp);
        char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(fp, ID_FP_LEN, fphex);
        static const char *const SRC[] = { "", "key", "AGE", "PGP" };
        ui_print(c, "*   %s  %s (%s)", t->nick, fphex, SRC[t->source >= IDENT_NATIVE && t->source <= IDENT_PGP ? t->source : 0]);
    }
    return CMD_OK;
}

static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };
static const char *const PREVIEW_NAMES[] = { "off", "nick", "message" };
static const char *const NET_LOG_NAMES[] = { "normal", "verbose", "off" };

static int net_log_level(const chat_t *c) {
    return c->net_quiet ? NET_LOG_OFF : c->net_verbose ? NET_LOG_VERBOSE : NET_LOG_NORMAL;
}

static int name_index(const char *const *names, int n, const char *s) {
    for (int i = 0; i < n; i++) if (strcmp(names[i], s) == 0) return i;
    return -1;
}

// The --simple :set, for the settings a session holds itself. The full-screen UI handles :set
// itself, using the settings page.
static cmd_result_t cmd_set(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char key[CMD_WORD_MAX];
    const char *value = cmd_parse(arg, key);
    char hex[COLOR_HEX_LEN + 1]; color_to_hex(c->my_color, hex);
    if (!key[0]) {
        ui_print(c, "* nick %s, colour #%s, notify %s, preview %s, net %s - :set NAME VALUE changes one", c->nick, hex,
                 NOTIFY_NAMES[c->notify_mode], PREVIEW_NAMES[c->notify_preview], NET_LOG_NAMES[net_log_level(c)]);
    } else if (strcmp(key, "nick") == 0) {
        if (!value[0]) ui_print(c, "* nick: %s. usage: :set nick NAME", c->nick);
        else chat_set_nick(c, value);
    } else if (strcmp(key, "colour") == 0 || strcmp(key, "color") == 0) {
        uint8_t rgb[3];
        if (!value[0]) {
            char list[512]; size_t pos = 0;
            for (int i = 0; i < COLOR_PALETTE_N; i++)
                pos += (size_t)snprintf(list + pos, sizeof(list) - pos, "%s%s", i ? ", " : "", COLOR_PALETTE[i].name);
            ui_print(c, "* colour: #%s. usage: :set colour NAME|#RRGGBB. names: %s", hex, list);
        } else if (parse_color(value, rgb) != 0) {
            ui_print(c, "* unknown colour '%s' - try a name or #RRGGBB", value);
        } else {
            chat_set_colour(c, rgb);
        }
    } else if (strcmp(key, "notify") == 0) {
        int m = name_index(NOTIFY_NAMES, (int)COUNT_OF(NOTIFY_NAMES), value);
        if (m < 0) {
            ui_print(c, "* notify: %s. usage: :set notify all|mentions|none", NOTIFY_NAMES[c->notify_mode]);
        } else {
            c->notify_mode = (notify_mode_t)m;
            ui_print(c, "* notify: %s", NOTIFY_NAMES[m]);
        }
    } else if (strcmp(key, "preview") == 0) {
        int m = name_index(PREVIEW_NAMES, (int)COUNT_OF(PREVIEW_NAMES), value);
        if (m < 0) {
            ui_print(c, "* preview: %s. usage: :set preview off|nick|message - what a notification shows besides "
                        "that a message came (desktops keep notifications)", PREVIEW_NAMES[c->notify_preview]);
        } else {
            c->notify_preview = (notify_preview_t)m;
            ui_print(c, "* preview: %s", PREVIEW_NAMES[m]);
        }
    } else if (strcmp(key, "net") == 0) {
        int v = name_index(NET_LOG_NAMES, (int)COUNT_OF(NET_LOG_NAMES), value);
        if (v < 0) {
            ui_print(c, "* net: %s. usage: :set net normal|verbose|off", NET_LOG_NAMES[net_log_level(c)]);
        } else {
            chat_set_net_log(c, v);
            ui_print(c, v == NET_LOG_VERBOSE ? "* net: verbose - every handshake packet now gets its own console line"
                      : v == NET_LOG_OFF ? "* net: off - only the network's problems get a console line" : "* net: normal");
        }
    } else {
        ui_print(c, "* no setting %s here - :set lists them", key);
    }
    return CMD_OK;
}

static cmd_result_t cmd_net(void *ctx, const char *arg) {
    (void)arg;
    net_report(ctx);
    return CMD_OK;
}

static cmd_result_t cmd_port(void *ctx, const char *arg) {
    chat_t *c = ctx;
    if (c->route.mode != ROUTE_UDP) {
        ui_print(c, "* this session runs over Tor and has no udp port of its own");
        return CMD_OK;
    }
    if (!arg[0]) {
        ui_print(c, "* udp port: %u. usage: :port N (0 picks a free one)", (unsigned)c->port);
        return CMD_OK;
    }
    char *end;
    long want = strtol(arg, &end, 10);
    if (*end || want < 0 || want > UINT16_MAX) {
        ui_print(c, "* not a port: %s. usage: :port N (0-65535, 0 picks a free one)", arg);
        return CMD_OK;
    }
    if (want != 0 && want == c->port) {
        ui_print(c, "* already on udp port %u", (unsigned)c->port);
        return CMD_OK;
    }
    uint16_t got = 0;
    sock_t s = net_udp_open((uint16_t)want, NET_DUAL, &got);
    if (s == SOCK_INVALID) {
        ui_print(c, "* cannot bind udp port %ld - staying on %u", want, (unsigned)c->port);
        return CMD_OK;
    }
    net_close(c->sock);
    c->sock = s;
    c->port = got;
    // Peers follow the source address of our next hi, and the DHT announces again from the new socket.
    c->next_alive = 0;
    c->next_lan = 0;
    if (c->dht_on) { c->dht.my_port = got; c->dht.explicit_port = 0; c->dht.next_lookup = 0; }
    // The old mapping pointed at the old port.
    if (c->pm) { portmap_free(c->pm); c->pm = portmap_new(c->port, module_log, c); }
    ui_print(c, "* now on udp port %u", (unsigned)got);
    return CMD_OK;
}

// The peer ":msg NICK TEXT" is for: the longest start of arg, up to a space, that names an online
// peer, since a nick can hold spaces. *text is what follows it.
static peer_t *peer_at_start(chat_t *c, const char *arg, const char **text, int *ambiguous) {
    char name[CHAT_NAME_LEN];
    peer_t *found = NULL;
    *ambiguous = 0;
    for (const char *sp = strchr(arg, ' '); sp; sp = strchr(sp + 1, ' ')) {
        size_t n = (size_t)(sp - arg);
        if (n == 0 || n >= sizeof name) continue;
        memcpy(name, arg, n);
        name[n] = '\0';
        int amb;
        peer_t *p = peer_by_name(c, name, &amb);
        if (p || amb) { found = p; *ambiguous = amb; *text = sp + 1; }
    }
    return found;
}

// A direct message goes only to the peer named, never through anyone else, and only to one whose
// build reads it: an older one would drop it without a word.
static cmd_result_t cmd_msg(void *ctx, const char *arg) {
    chat_t *c = ctx;
    const char *rest = "";
    int ambiguous;
    peer_t *p = peer_at_start(c, arg, &rest, &ambiguous);
    char line[MAX_TEXT + 1], name[CHAT_NAME_LEN];
    clean_text(rest, line, MAX_TEXT);
    if (!p && ambiguous) {
        ui_print(c, "* more than one peer has that nick - add the #id :peers shows (:msg NICK#1a2b... TEXT)");
        return CMD_OK;
    }
    if (!p) {
        size_t w = strcspn(arg, " ");
        if (!arg[0] || !arg[w]) ui_print(c, "* usage: :msg NICK TEXT sends TEXT to that peer alone");
        else ui_print(c, "* nobody called %.*s is connected to you - a direct message only goes straight to them, "
                         "never through someone else", (int)w, arg);
        return CMD_OK;
    }
    chat_peer_name(c, p, name);
    if (!line[0]) { ui_print(c, "* usage: :msg %s TEXT sends TEXT to them alone", name); return CMD_OK; }
    if (!p->can_pm) { ui_print(c, "* %s's chat is too old for direct messages", name); return CMD_OK; }
    if (!peer_trusted(c, p)) {
        if (p->code_ok == CODE_DIFFERENT) ui_print(c, "* your verify codes with %s differ - nothing you send reaches them", name);
        else ui_print(c, "* compare verify codes with %s first - :verify %s shows the code", name, name);
        return CMD_OK;
    }
    char mid[MID_HEX + 1], record[MSG_LINE_LEN], shown[CHAT_NAME_LEN + MAX_NICK + 48];
    gen_mid(mid);
    seen_add(c, mid);
    snprintf(record, sizeof record, "pm\t%s\t%s", mid, line);
    if (send_peer(c, p, record) != 0) { ui_print(c, "* couldn't send that to %s", name); return CMD_OK; }
    unsigned own = ++c->own_seq;
    track_message(c, p, mid, record, own, c->now);
    snprintf(shown, sizeof shown, "%s (" DM_ARROW " %s) (you)", c->nick, name);
    c->line = (chat_line_t){ mid, c->my_id, c->nick, p };
    ui_direct(c, c->my_color, 0, shown, line);
    c->line = (chat_line_t){ 0 };
    return CMD_OK;
}

// ":timer" says which message timer is kept to here, ":timer 10m" asks for one, ":timer off" stops.
static cmd_result_t cmd_timer(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char d[16], who[CHAT_NAME_LEN];
    unsigned seconds;
    if (!arg[0]) {
        unsigned t = chat_timer(c, who, sizeof who);
        chat_format_timer(t, d, sizeof d);
        if (t) ui_print(c, "* messages here go after %s, as %s asked", d, who);
        else ui_print(c, "* no message timer here - :timer 10m (or 2h, 1d) asks for one");
        return CMD_OK;
    }
    if (chat_parse_timer(arg, &seconds) != 0) {
        ui_print(c, "* usage: :timer 10m (or 2h, 1d: from a minute to a week), or :timer off");
        return CMD_OK;
    }
    if (seconds == c->timer) {
        chat_format_timer(seconds, d, sizeof d);
        if (seconds) ui_print(c, "* you ask for messages here to go after %s already", d);
        else ui_print(c, "* you don't ask for a timer here");
        return CMD_OK;
    }
    chat_set_timer(c, seconds);
    return CMD_OK;
}

// ":reply NICK TEXT" answers NICK's last message in the room, quoting the start of it.
static cmd_result_t cmd_reply(void *ctx, const char *arg) {
    chat_t *c = ctx;
    const char *rest = "";
    int ambiguous;
    peer_t *p = peer_at_start(c, arg, &rest, &ambiguous);
    const recent_msg_t *r = p ? recent_from(c, p->id, NULL, &rest) : NULL;
    if (!p && ambiguous) {
        ui_print(c, "* more than one peer has that nick - add the #id :peers shows (:reply NICK#1a2b... TEXT)");
        return CMD_OK;
    }
    if (!p) r = recent_from(c, NULL, arg, &rest);
    if (!r) {
        size_t w = strcspn(arg, " ");
        if (!arg[0]) ui_print(c, "* usage: :reply NICK TEXT answers NICK's last message, quoting it");
        else ui_print(c, "* nothing from %.*s to reply to yet", (int)w, arg);
        return CMD_OK;
    }
    if (!rest[0]) {
        ui_print(c, "* usage: :reply %s TEXT answers their last message, quoting it", r->nick);
        return CMD_OK;
    }
    recent_msg_t answered = *r;
    send_text(c, rest, &answered, c->now);
    crypto_wipe(&answered, sizeof answered);
    return CMD_OK;
}

// --simple's :move: who would come, or the request waiting. "yes" goes, "no" stays. The full-screen
// UI asks in a box instead.
static cmd_result_t cmd_move(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char word[CMD_WORD_MAX];
    cmd_parse(arg, word);
    int yes = strcmp(word, "yes") == 0, no = strcmp(word, "no") == 0;
    const chat_move_ask_t *a = chat_move_asked(c);
    if (a && yes) {
        if (chat_move_accept(c, &c->move_staged) == 0) c->move_staged_set = 1;
    } else if (a && no) {
        chat_move_decline(c);
    } else if (a) {
        ui_print(c, "* %s asks you to move this room to a new one%s%s (at %s) - :move yes goes there and leaves this "
                    "room, :move no stays", a->from, a->coming ? ", with " : "", a->coming_names, a->at);
    } else if (no) {
        ui_print(c, "* nobody has asked you to move");
    } else if (yes) {
        if (chat_move_begin(c, &c->move_staged) == 0) c->move_staged_set = 1;
    } else {
        chat_move_plan_t plan;
        chat_move_plan(c, &plan);
        if (!plan.coming) say_nobody_moves(c, &plan);
        else ui_print(c, "* :move yes moves to a new room with %s, each asked first%s%s. Nothing tells anyone left behind "
                         "where you went", plan.coming_names, plan.left ? " - left behind: " : "", plan.left_names);
    }
    return CMD_OK;
}

static cmd_result_t cmd_quit(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    return CMD_QUIT;
}

const command_t CHAT_COMMANDS[] = {
    { "help",       NULL,     NULL,              "list commands",                                   cmd_help },
    { "peers",      NULL,     NULL,              "who is online, with verify codes and builds",     cmd_peers },
    { "verify",     NULL,     "NICK [ok|no]",    "compare a peer's verify code; ok once it matches", cmd_verify },
    { "verified",   NULL,     "[forget NICK]",   "list the signing keys you verified, or remove one", cmd_verified },
    { "ignore",     NULL,     "[NICK [off]]",    "hide what a peer says, here and wherever they sign with that key; off shows it again", cmd_ignore },
    { "msg",        "dm",     "NICK TEXT",       "a direct message to one peer you're connected to; nobody else gets it", cmd_msg },
    { "reply",      "re",     "NICK TEXT",       "answer NICK's last message, quoting the start of it", cmd_reply },
    { "timer",      NULL,     "[off|10m|2h|1d]", "messages here go from every screen that keeps to it after this long; alone, says which", cmd_timer },
    { "move",       NULL,     "[yes|no]",        "move to a new room with the peers whose codes you compared; yes goes, no stays", cmd_move },
    { "net",        NULL,     NULL,              "network report and diagnosis",                    cmd_net },
    { "port",       NULL,     "[N]",             "show or change this session's udp port",          cmd_port },
    { "set",        NULL,     "[NAME [VALUE]]",  "show or change nick, colour, notify, preview, net", cmd_set },
    { "send",       NULL,     "[asis] [PATH]",   "offer a file; nobody gets it unless they fetch it, and a picture goes cleaned unless asis", cmd_send },
    { "files",      NULL,     NULL,              "the files offered here, and how they're coming",   cmd_files },
    { "download",   "dl",     "[N] [anyway] [FOLDER]", "save file N (the newest if left out) in Downloads or FOLDER", cmd_download },
    { "cancel",     NULL,     "N",               "stop fetching or queueing file N, or stop offering yours", cmd_cancel },
    { "quit",       "q exit", NULL,              "leave the session",                               cmd_quit },
    { NULL, NULL, NULL, NULL, NULL }
};

cmd_result_t chat_run_command(chat_t *c, const char *line_in) {
    char line[MAX_TEXT + 1];
    clean_text(line_in, line, MAX_TEXT);
    char word[CMD_WORD_MAX];
    const char *arg = cmd_parse(line, word);
    const command_t *cmd = cmd_find(CHAT_COMMANDS, word);
    if (!cmd) {
        ui_print(c, "* unknown command :%s - try :help", word);
        return CMD_UNKNOWN;
    }
    return cmd->run(c, arg);
}
