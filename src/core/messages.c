// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Messages: their ids, the ones seen lately, acks and resends, replies, and sending what's typed.
#include "core/engine.h"

void gen_mid(char out[MID_HEX + 1]) {
    uint8_t b[MID_LEN];
    gen_random(b, MID_LEN);
    hex_encode(b, MID_LEN, out);
}

static uint32_t mid_key(const char *mid) {
    uint32_t v = 0;
    for (int i = 0; i < MID_HEX; i++) {
        int h = hex_value(mid[i]);
        if (h < 0) break;
        v = (v << 4) | (uint32_t)h;
    }
    return v;
}

int seen_has(chat_t *c, const char *mid) {
    uint32_t key = mid_key(mid);
    for (int i = 0; i < c->seen_count; i++) {
        int idx = (c->seen_head - 1 - i + SEEN_MIDS) % SEEN_MIDS;
        if (c->seen_mids[idx] == key) return 1;
    }
    return 0;
}
void seen_add(chat_t *c, const char *mid) {
    c->seen_mids[c->seen_head] = mid_key(mid);
    c->seen_head = (c->seen_head + 1) % SEEN_MIDS;
    if (c->seen_count < SEEN_MIDS) c->seen_count++;
}

int chat_ignored(const chat_t *c, const uint8_t id[ID_LEN]) {
    for (int i = 0; i < c->n_ignored; i++) if (memcmp(c->ignored[i], id, ID_LEN) == 0) return 1;
    return 0;
}

void set_ignored(chat_t *c, const uint8_t id[ID_LEN], int on) {
    for (int i = 0; i < c->n_ignored; i++) {
        if (memcmp(c->ignored[i], id, ID_LEN) != 0) continue;
        if (!on) {
            memmove(c->ignored[i], c->ignored[i + 1], (size_t)(c->n_ignored - i - 1) * ID_LEN);
            c->n_ignored--;
        }
        return;
    }
    if (!on) return;
    if (c->n_ignored == IGNORED_MAX) {
        memmove(c->ignored[0], c->ignored[1], (IGNORED_MAX - 1) * ID_LEN);
        c->n_ignored--;
    }
    memcpy(c->ignored[c->n_ignored++], id, ID_LEN);
}

#define REPLY_ARROW "\xe2\x86\xaa"
#define REPLY_DOT "\xc2\xb7"

// "mr" has its reply's id on top of what "m" has, and has to fit a frame all the same.
#define MAX_REPLY_TEXT (MAX_TEXT - MID_HEX - 2)

void recent_add(chat_t *c, const char *mid, const uint8_t origin[ID_LEN], const char *nick, const char *text,
                double now) {
    recent_msg_t *r = &c->recent[c->recent_next];
    c->recent_next = (c->recent_next + 1) % RECENT_MAX;
    crypto_wipe(r, sizeof *r);
    r->used = 1;
    copy_str(r->mid, mid, sizeof r->mid);
    memcpy(r->origin, origin, ID_LEN);
    copy_str(r->nick, nick, sizeof r->nick);
    size_t n = strlen(text);
    int cut = n > QUOTE_MAX;
    if (cut) {
        n = QUOTE_MAX;
        while (n > 0 && utf8_is_cont((unsigned char)text[n])) n--;
    }
    memcpy(r->quote, text, n);
    if (cut) { memcpy(r->quote + n, "\xe2\x80\xa6", 3); n += 3; }
    r->quote[n] = '\0';
    r->at = now;
}

const recent_msg_t *recent_find(const chat_t *c, const char *mid) {
    for (int i = 0; i < RECENT_MAX; i++)
        if (c->recent[i].used && strcmp(c->recent[i].mid, mid) == 0) return &c->recent[i];
    return NULL;
}

// The newest message from origin, or with origin NULL, from whoever's nick starts arg: the longest
// such nick, up to a space or the end, since nicks can hold spaces. *rest is what follows it.
const recent_msg_t *recent_from(const chat_t *c, const uint8_t *origin, const char *arg, const char **rest) {
    const recent_msg_t *best = NULL;
    size_t best_len = 0;
    for (int k = 1; k <= RECENT_MAX; k++) {
        const recent_msg_t *r = &c->recent[(c->recent_next - k + RECENT_MAX) % RECENT_MAX];
        if (!r->used || memcmp(r->origin, c->my_id, ID_LEN) == 0) continue;
        if (origin) {
            if (memcmp(r->origin, origin, ID_LEN) == 0) return r;
            continue;
        }
        size_t n = strlen(r->nick);
        if (n <= best_len || strncasecmp(arg, r->nick, n) != 0 || (arg[n] && arg[n] != ' ')) continue;
        best = r;
        best_len = n;
    }
    if (best) {
        *rest = arg + best_len;
        while (**rest == ' ') (*rest)++;
    }
    return best;
}

// Who said what a reply answers, and the start of it.
void reply_prefix(const chat_t *c, const char *reply_mid, char *out, size_t cap) {
    const recent_msg_t *r = recent_find(c, reply_mid);
    if (r) snprintf(out, cap, REPLY_ARROW " %s: %s " REPLY_DOT " ", r->nick, r->quote);
    else snprintf(out, cap, REPLY_ARROW " a message you don't have " REPLY_DOT " ");
}

void pending_clear(pending_msg_t *pm) { crypto_wipe(pm, sizeof *pm); }

// Once nothing waits for an ack of our message own, the UI hears it's settled.
void own_settled(chat_t *c, unsigned own) {
    if (!own || !c->delivery) return;
    for (int i = 0; i < MAX_PENDING_MSGS; i++) if (c->pending[i].used && c->pending[i].own == own) return;
    c->delivery(c->ui, own, CHAT_SETTLED, NULL);
}

// p never acked pm: given up on after its last try, or gone.
void own_missed(chat_t *c, peer_t *p, pending_msg_t *pm) {
    unsigned own = pm->own;
    if (own && c->delivery) {
        char name[CHAT_NAME_LEN];
        chat_peer_name(c, p, name);
        c->delivery(c->ui, own, CHAT_MISSED, name);
    }
    pending_clear(pm);
    own_settled(c, own);
}

// A message resend waits for the ack's round trip: the message waits for a slot here, the ack for
// a slot there, and relays take a lot longer than UDP.
#define RELAY_ROUND_TRIP 4.0
#define UDP_ROUND_TRIP 1.0
double resend_delay(chat_t *c, const peer_t *p) {
    double slots = 2.0 * cover_interval(c, p) * (1.0 + JITTER);
    return slots + (p->addr.kind == ADDR_NOSTR ? RELAY_ROUND_TRIP + jitter(RELAY_ROUND_TRIP / 4)
                                               : UDP_ROUND_TRIP + jitter(UDP_ROUND_TRIP / 2));
}

_Static_assert(2 + MID_HEX + 1 + ID_LEN * 2 + 1 + MAX_NICK + 1 + MAX_TEXT <= RECORD_MAX, "a message's record fits one frame");

// A part's id, the same whoever splits the message, so a part passed on by more than one peer is
// still only shown once.
void part_mid(const char *mid, int i, char out[MID_HEX + 1]) {
    char in[16];
    uint8_t h[SHA256_LEN];
    int n = snprintf(in, sizeof in, "%s/%d", mid, i);
    sha256_hash(in, (size_t)n, h);
    hex_encode(h, MID_LEN, out);
}

// How much of text goes in a part of at most max bytes: up to a space in its second half if there's
// one, so a word isn't split, otherwise to the end of a character.
static size_t part_len(const char *text, size_t len, size_t max) {
    if (len <= max) return len;
    size_t cut = max;
    while (cut > 0 && utf8_is_cont(text[cut])) cut--;
    for (size_t i = cut; i > max / 2; i--)
        if (text[i] == ' ') return i;
    return cut;
}

// With every retry slot taken a message still goes out once, just without retries.
void track_message(chat_t *c, peer_t *p, const char *mid, const char *record, unsigned own, double now) {
    for (int s = 0; s < MAX_PENDING_MSGS; s++) {
        pending_msg_t *pm = &c->pending[s];
        if (pm->used) continue;
        pm->used = 1;
        pm->own = own;
        copy_str(pm->mid, mid, sizeof pm->mid);
        pm->peer_slot = peer_slot(c, p);
        copy_str(pm->text, record, sizeof pm->text);
        pm->tries = 1;
        pm->next_retry = now + resend_delay(c, p);
        return;
    }
}

// An "m" to q: the text whole, or for a peer that reads no more than OLD_MAX_TEXT, in parts, each a
// message with an id of its own. own: our message's number, and each part is kept for retries until q
// acks it (0: passed on, not kept). 1 if any went.
int send_message(chat_t *c, peer_t *q, const char *mid, const char *idhex, const char *nick, const char *text,
                 unsigned own, double now) {
    char record[MSG_LINE_LEN];
    size_t len = strlen(text), pos = 0;
    int sent = 0;
    for (int i = 0; i < MAX_TEXT_PARTS && pos < len; i++) {
        size_t n = q->long_text ? len : part_len(text + pos, len - pos, OLD_MAX_TEXT);
        char pmid[MID_HEX + 1];
        if (n == len) copy_str(pmid, mid, sizeof pmid);
        else part_mid(mid, i, pmid);
        snprintf(record, sizeof record, "m\t%s\t%s\t%s\t%.*s", pmid, idhex, nick, (int)n, text + pos);
        if (send_peer(c, q, record) == 0) {
            sent = 1;
            if (own) track_message(c, q, pmid, record, own, now);
        }
        pos += n;
        while (pos < len && text[pos] == ' ') pos++;
    }
    return sent;
}

// A reply to q: "mr" to a peer that reads it, otherwise an "m" with the quote in front.
int send_reply(chat_t *c, peer_t *q, const char *mid, const char *reply_mid, const char *idhex,
               const char *nick, const char *text, const char *prefix, unsigned own, double now) {
    if (!q->can_reply) {
        char joined[REPLY_PREFIX_MAX + MAX_TEXT + 1], line[MAX_TEXT + 1];
        snprintf(joined, sizeof joined, "%s%s", prefix, text);
        clean_text(joined, line, MAX_TEXT);
        return send_message(c, q, mid, idhex, nick, line, own, now);
    }
    char record[MSG_LINE_LEN];
    snprintf(record, sizeof record, "mr\t%s\t%s\t%s\t%s\t%s", mid, reply_mid, idhex, nick, text);
    if (send_peer(c, q, record) != 0) return 0;
    if (own) track_message(c, q, mid, record, own, now);
    return 1;
}

// Acks a record that carries a MID, if it's one. 1 if it was.
int ack_record(chat_t *c, peer_t *p, const char *mid) {
    uint8_t raw[MID_LEN];
    if (strlen(mid) != MID_HEX || hex_decode(mid, MID_HEX, raw) != 0) return 0;
    char ack[16]; snprintf(ack, sizeof ack, "a\t%s", mid);
    send_peer(c, p, ack);
    return 1;
}

// The peers a message is held back from that are named.
#define HELD_NAMES 3

// A message from us, or with reply, an answer to that one.
void send_text(chat_t *c, const char *text_in, const recent_msg_t *reply, double now) {
    char line[MAX_TEXT + 1], prefix[REPLY_PREFIX_MAX] = "", shown_text[REPLY_PREFIX_MAX + MAX_TEXT + 1];
    clean_text(text_in, line, reply ? MAX_REPLY_TEXT : MAX_TEXT);
    if (!line[0]) return;
    if (!chat_ready(c)) {
        ui_print(c, "* not connected yet - message not sent, chat opens once someone answers");
        return;
    }
    char mid[MID_HEX + 1], reply_mid[MID_HEX + 1] = "";
    gen_mid(mid);
    seen_add(c, mid);
    if (reply) {
        copy_str(reply_mid, reply->mid, sizeof reply_mid);
        reply_prefix(c, reply_mid, prefix, sizeof prefix);
    }
    char who[MAX_NICK + 8]; snprintf(who, sizeof who, "%s (you)", c->nick);
    unsigned own = ++c->own_seq;
    snprintf(shown_text, sizeof shown_text, "%s%s", prefix, line);
    c->line_quote = (int)strlen(prefix);
    ui_own(c, who, shown_text);
    c->line_quote = 0;
    recent_add(c, mid, c->my_id, c->nick, line, now);
    int sent = 0, held = 0;
    char held_names[HELD_NAMES * CHAT_NAME_LEN] = "";
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        // A peer whose code wasn't compared may be someone in the middle: it gets nothing.
        if (!peer_trusted(c, p)) {
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            if (held < HELD_NAMES)
                snprintf(held_names + strlen(held_names), sizeof held_names - strlen(held_names), "%s%s", held ? ", " : "", name);
            held++;
            continue;
        }
        if (reply_mid[0]) sent += send_reply(c, p, mid, reply_mid, c->my_idhex, c->nick, line, prefix, own, now);
        else sent += send_message(c, p, mid, c->my_idhex, c->nick, line, own, now);
    }
    if (sent) own_settled(c, own);
    if (held)
        ui_print(c, "* not sent to %s%s: compare verify codes first (:peers lists them, :verify NICK ok once they match)",
                 held_names, held > HELD_NAMES ? " and others" : "");
    else if (!sent) ui_print(c, "* nobody else is here yet, message not delivered");
}

void chat_send_text(chat_t *c, const char *text_in, double now) {
    c->now = now;
    send_text(c, text_in, NULL, now);
}

int chat_submit_line(chat_t *c, const char *line_in, double now) {
    c->now = now;
    char line[MAX_TEXT + 1];
    clean_text(line_in, line, MAX_TEXT);
    if (line[0] == ':') return chat_run_command(c, line + 1) != CMD_QUIT;
    chat_send_text(c, line, now);
    return 1;
}
