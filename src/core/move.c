// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Moving the room (:move), as chat.h describes it.
#include "core/engine.h"

// Our key for moves, made the first time one needs it.
static const identity_keypair_t *own_move_key(chat_t *c) {
    if (!c->move_key_set) { gen_identity_keypair(&c->move_key); c->move_key_set = 1; }
    return &c->move_key;
}

static int move_comes(const peer_t *p) { return p->used && p->ok && p->code_ok == CODE_SAME && p->can_move; }

// Whether id is in a list of the starts of ids, as "mv" gives them.
static int in_id_list(const char *list, const uint8_t id[ID_LEN]) {
    char want[SHORT_ID_HEX + 1]; short_id(id, want);
    for (const char *s = list; *s; ) {
        size_t len = strcspn(s, ",");
        if (len == SHORT_ID_HEX && memcmp(s, want, SHORT_ID_HEX) == 0) return 1;
        s += len;
        if (*s) s++;
    }
    return 0;
}

// A room's id or password as "mv" may give them: printable ASCII, with spaces only in a password.
static int move_text_ok(const char *s, size_t max, int spaces) {
    size_t n = strlen(s);
    if (n == 0 || n > max) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch < (spaces ? ' ' : '!') || ch > '~') return 0;
    }
    return 1;
}

// Names as a sentence: "bob", "bob and carol", "bob, carol and dave", naming MOVE_NAMED at most and
// counting the rest.
typedef struct { int n; char named[MOVE_NAMED][MOVE_NAME_LEN]; } names_t;

static void names_add(names_t *l, const char *name) {
    if (l->n < MOVE_NAMED) copy_str(l->named[l->n], name, MOVE_NAME_LEN);
    l->n++;
}

static void names_text(const names_t *l, char *out, size_t cap) {
    int shown = l->n <= MOVE_NAMED ? l->n : MOVE_NAMED - 1;
    size_t pos = 0;
    out[0] = '\0';
    for (int i = 0; i < shown && pos < cap; i++)
        pos += (size_t)snprintf(out + pos, cap - pos, "%s%s", i == 0 ? "" : i == l->n - 1 ? " and " : ", ", l->named[i]);
    if (shown < l->n && pos < cap) snprintf(out + pos, cap - pos, " and %d others", l->n - shown);
}

// "mk": our key for the move, to a peer moving with us, acked and retried like a message.
static void send_move_key(chat_t *c, peer_t *q, double now) {
    if (q->key_sent || q->code_ok == CODE_DIFFERENT) return;
    q->key_sent = 1;
    char mid[MID_HEX + 1]; gen_mid(mid);
    char keyhex[ID_SIGN_PUB_LEN * 2 + 1]; hex_encode(own_move_key(c)->pub, ID_SIGN_PUB_LEN, keyhex);
    char rec[8 + MID_HEX + ID_SIGN_PUB_LEN * 2];
    snprintf(rec, sizeof rec, "mk\t%s\t%s", mid, keyhex);
    if (send_peer(c, q, rec) == 0) track_message(c, q, mid, rec, 0, now);
}

// The peers a request asks along, by our names for them, leaving out us and its sender.
static void move_coming_names(chat_t *c, const move_req_t *r, const peer_t *from, chat_move_ask_t *a) {
    names_t with = { 0 };
    int strangers = 0;
    char mine[SHORT_ID_HEX + 1], theirs[SHORT_ID_HEX + 1];
    short_id(c->my_id, mine);
    short_id(from->id, theirs);
    for (const char *s = r->coming; *s; ) {
        size_t len = strcspn(s, ",");
        if (len == SHORT_ID_HEX && memcmp(s, mine, len) != 0 && memcmp(s, theirs, len) != 0) {
            peer_t *q = NULL;
            for (int i = 0; i < c->peer_hi && !q; i++) {
                char h[SHORT_ID_HEX + 1]; short_id(c->peers[i].id, h);
                if (c->peers[i].used && c->peers[i].ok && memcmp(s, h, len) == 0) q = &c->peers[i];
            }
            if (q) { char name[CHAT_NAME_LEN]; chat_peer_name(c, q, name); names_add(&with, name); }
            else strangers++;
        }
        s += len;
        if (*s) s++;
    }
    char t[48];
    if (strangers == 1) names_add(&with, "a peer you aren't connected to");
    else if (strangers) { snprintf(t, sizeof t, "%d peers you aren't connected to", strangers); names_add(&with, t); }
    a->coming = with.n;
    names_text(&with, a->coming_names, sizeof a->coming_names);
}

// Shows the request to move once its sender's code was compared, and sends our key to the sender and
// the others it asks along, so codes compared here count in the new room whatever we answer. Until
// then it says to compare codes. It's dropped if they differ, or the sender leaves first.
void move_ask_now(chat_t *c, double now) {
    move_req_t *r = &c->move_req;
    if (!r->used || r->asked) return;
    peer_t *from = find_peer_by_id(c, r->from);
    if (!from || !from->ok || from->code_ok == CODE_DIFFERENT) {
        ui_print(c, "* %s's request to move this room is dropped: %s", r->name,
                 from && from->ok ? "your verify codes differ" : "they left before you compared verify codes with them");
        crypto_wipe(r, sizeof *r);
        return;
    }
    chat_peer_name(c, from, r->name);
    if (from->code_ok != CODE_SAME) {
        if (!r->told)
            ui_warn(c, "* %s wants to move this room to a new one, but you haven't compared verify codes with them. Compare "
                       "them soon (:verify %s), while they're still here, and you'll be asked whether to go", r->name, r->name);
        r->told = 1;
        return;
    }
    r->asked = 1;
    chat_move_ask_t *a = &c->move_ask;
    unsigned seq = a->seq + 1;
    memset(a, 0, sizeof *a);
    a->seq = seq;
    snprintf(a->from, sizeof a->from, "%s%s", r->name, code_mark(c, from));
    copy_str(a->at, r->at, sizeof a->at);
    move_coming_names(c, r, from, a);
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *q = &c->peers[i];
        if (q->used && q->ok && (q == from || in_id_list(r->coming, q->id))) send_move_key(c, q, now);
    }
    ui_warn(c, "* %s wants to move this room to a new one%s%s - :move to answer", r->name, a->coming ? ", with " : "",
            a->coming_names);
}

// "mv": p moves the room, and asks us along.
void on_move(chat_t *c, peer_t *p, char **f, double now) {
    uint8_t key[ID_SIGN_PUB_LEN];
    if (!ack_record(c, p, f[1]) || seen_has(c, f[1])) return;
    seen_add(c, f[1]);
    if (c->move_leaving || p->code_ok == CODE_DIFFERENT || !move_text_ok(f[2], MAX_SESSION_NAME, 0)
        || !move_text_ok(f[3], MAX_PASSWORD, 1) || strlen(f[4]) != ID_SIGN_PUB_LEN * 2
        || hex_decode(f[4], ID_SIGN_PUB_LEN * 2, key) != 0 || strlen(f[5]) >= MOVE_COMING_LEN) return;
    memcpy(p->move_pub, key, ID_SIGN_PUB_LEN);
    p->move_pub_set = 1;
    p->move_passed = 0;
    move_req_t *r = &c->move_req;
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    if (r->used && memcmp(r->from, p->id, ID_LEN) != 0) ui_print(c, "* %s's request to move replaces %s's", name, r->name);
    crypto_wipe(r, sizeof *r);
    r->used = 1;
    memcpy(r->from, p->id, ID_LEN);
    copy_str(r->name, name, sizeof r->name);
    current_hhmm(r->at);
    copy_str(r->session_name, f[2], sizeof r->session_name);
    copy_str(r->password, f[3], sizeof r->password);
    copy_str(r->coming, f[5], sizeof r->coming);
    move_ask_now(c, now);
}

void tell_came_with(chat_t *c, peer_t *p) {
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    const char *was = c->came_with[p->came_with - 1].nick;
    if (strcmp(was, p->nick) == 0)
        ui_print(c, "* %s came along from the room you moved from, where you compared verify codes - no need to compare "
                    "them again", name);
    else
        ui_print(c, "* %s is %s from the room you moved from, where you compared verify codes - no need to compare them "
                    "again", name, was);
}

// A peer that signs its session here ("mp") with a key shown to us in the room we moved from, by a peer
// whose code we had compared there, is that peer: its code counts as compared here too.
void check_came_with(chat_t *c, peer_t *p) {
    if (!p->move_sig_set || p->code_ok != CODE_NOT_COMPARED) return;
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!c->came_with[i].used
            || check_session_sig(c, p, move_verify, c->came_with[i].pub, p->move_sig) != 0) continue;
        p->code_ok = CODE_SAME;
        p->came_with = i + 1;
        if (p->announced) { tell_came_with(c, p); file_offer_all(c, p); }
        return;
    }
}

static void expect_came_with(chat_t *c, const uint8_t pub[ID_SIGN_PUB_LEN], const char *nick) {
    int at = -1;
    for (int i = 0; i < MAX_PEERS; i++) {
        if (c->came_with[i].used && memcmp(c->came_with[i].pub, pub, ID_SIGN_PUB_LEN) == 0) return;
        if (!c->came_with[i].used && at < 0) at = i;
    }
    if (at < 0) return;
    c->came_with[at].used = 1;
    memcpy(c->came_with[at].pub, pub, ID_SIGN_PUB_LEN);
    copy_str(c->came_with[at].nick, nick, sizeof c->came_with[at].nick);
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok) check_came_with(c, &c->peers[i]);
}

// The room we moved to gets the keys shown to us here by peers whose codes we compared, as they come.
void pass_move_keys(chat_t *c) {
    for (int i = 0; c->move_to && i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok || !p->move_pub_set || p->move_passed || p->code_ok != CODE_SAME) continue;
        expect_came_with(c->move_to, p->move_pub, p->nick);
        p->move_passed = 1;
    }
}

void chat_move_plan(chat_t *c, chat_move_plan_t *plan) {
    names_t coming = { 0 }, left = { 0 };
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
        if (move_comes(p)) { names_add(&coming, name); continue; }
        char why[MOVE_NAME_LEN];
        snprintf(why, sizeof why, "%s (%s)", name, p->code_ok == CODE_DIFFERENT ? "codes differ"
                 : p->code_ok != CODE_SAME ? "code not compared" : "an older version");
        names_add(&left, why);
    }
    plan->coming = coming.n;
    plan->left = left.n;
    names_text(&coming, plan->coming_names, sizeof plan->coming_names);
    names_text(&left, plan->left_names, sizeof plan->left_names);
}

void say_nobody_moves(chat_t *c, const chat_move_plan_t *plan) {
    if (plan->left) ui_print(c, "* nobody can move with you yet - compare verify codes with them first (:peers lists them, "
                                ":verify NICK ok once a code matches)");
    else ui_print(c, "* nobody else is here to move with");
}

_Static_assert(BYTEWORDS_LEN(MOVE_PASSWORD_BYTES) <= MAX_PASSWORD + 1, "a new room's password fits");

int chat_move_begin(chat_t *c, chat_move_to_t *to) {
    chat_move_plan_t plan;
    chat_move_plan(c, &plan);
    if (!plan.coming) { say_nobody_moves(c, &plan); return -1; }
    memset(to, 0, sizeof *to);
    random_session_id(to->session_name, SESSION_ID_LEN);
    uint8_t pw[MOVE_PASSWORD_BYTES];
    gen_random(pw, sizeof pw);
    bytewords_plain(pw, sizeof pw, to->password);
    crypto_wipe(pw, sizeof pw);
    copy_str(to->from, c->session_name, sizeof to->from);
    to->key = *own_move_key(c);
    to->created = 1;
    return 0;
}

const chat_move_ask_t *chat_move_asked(const chat_t *c) {
    return c->move_req.used && c->move_req.asked ? &c->move_ask : NULL;
}

int chat_move_accept(chat_t *c, chat_move_to_t *to) {
    const move_req_t *r = &c->move_req;
    if (!chat_move_asked(c)) return -1;
    memset(to, 0, sizeof *to);
    copy_str(to->session_name, r->session_name, sizeof to->session_name);
    copy_str(to->password, r->password, sizeof to->password);
    copy_str(to->from, c->session_name, sizeof to->from);
    to->key = *own_move_key(c);
    return 0;
}

void chat_move_decline(chat_t *c) {
    if (!c->move_req.used) return;
    ui_print(c, "* you stay in this room - where %s moved it is forgotten", c->move_req.name);
    crypto_wipe(&c->move_req, sizeof c->move_req);
}

int chat_move_staged(chat_t *c, chat_move_to_t *to) {
    if (!c->move_staged_set) return 0;
    *to = c->move_staged;
    crypto_wipe(&c->move_staged, sizeof c->move_staged);
    c->move_staged_set = 0;
    return 1;
}

void chat_move_go(chat_t *c, const chat_move_to_t *to, chat_t *moved_to, double now) {
    if (to->created) {
        // Everyone asked gets the whole list, and names the others from it as it knows them.
        char coming[MOVE_COMING_LEN] = "", keyhex[ID_SIGN_PUB_LEN * 2 + 1];
        size_t pos = 0;
        for (int i = 0; i < c->peer_hi && pos < sizeof coming; i++) {
            if (!move_comes(&c->peers[i])) continue;
            char h[SHORT_ID_HEX + 1]; short_id(c->peers[i].id, h);
            pos += (size_t)snprintf(coming + pos, sizeof coming - pos, "%s%s", pos ? "," : "", h);
        }
        hex_encode(to->key.pub, ID_SIGN_PUB_LEN, keyhex);
        for (int i = 0; i < c->peer_hi; i++) {
            peer_t *p = &c->peers[i];
            if (!move_comes(p)) continue;
            char mid[MID_HEX + 1]; gen_mid(mid);
            char rec[RECORD_MAX + 1];
            snprintf(rec, sizeof rec, "mv\t%s\t%s\t%s\t%s\t%s", mid, to->session_name, to->password, keyhex, coming);
            if (send_peer(c, p, rec) == 0) track_message(c, p, mid, rec, 0, now);
            crypto_wipe(rec, sizeof rec);
            p->move_with = p->key_sent = 1;
        }
    } else {
        const move_req_t *r = &c->move_req;
        for (int i = 0; i < c->peer_hi; i++) {
            peer_t *p = &c->peers[i];
            if (p->used && p->ok && (memcmp(p->id, r->from, ID_LEN) == 0 || in_id_list(r->coming, p->id))) p->move_with = 1;
        }
        crypto_wipe(&c->move_req, sizeof c->move_req);
    }
    c->move_to = moved_to;
    c->move_leaving = 1;
    c->move_since = now;
    // It's been left: what still comes in here isn't for the desktop.
    c->notify = NULL;
    pass_move_keys(c);
}

void chat_move_unlink(chat_t *c, const chat_t *moved_to) {
    if (c->move_to == moved_to) c->move_to = NULL;
}

int chat_move_finished(const chat_t *c, double now) {
    if (!c->move_leaving) return 0;
    if (now - c->move_since > MOVE_LINGER) return 1;
    for (int i = 0; i < MAX_PENDING_MSGS; i++) {
        const pending_msg_t *pm = &c->pending[i];
        const peer_t *p = &c->peers[pm->peer_slot];
        if (pm->used && p->used && p->ok && (starts_with(pm->text, "mv\t") || starts_with(pm->text, "mk\t"))) return 0;
    }
    for (int i = 0; i < c->peer_hi; i++) {
        const peer_t *p = &c->peers[i];
        if (p->used && p->ok && p->move_with && !p->move_pub_set) return 0;
    }
    return 1;
}
