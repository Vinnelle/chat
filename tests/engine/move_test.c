// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Verified keys, :move with them, and the room left behind going offline: in that order, each on the
// state the one before leaves.
#include "harness.h"

static peer_t *peer_with_id(chat_t *c, const uint8_t id[ID_LEN]) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok && memcmp(c->peers[i].id, id, ID_LEN) == 0) return &c->peers[i];
    return NULL;
}

// Verified signing keys: saved by :verify NICK ok, written and read back as text, a peer with a
// verified nick but another key warned about, a new key replacing the old one once compared, and
// a known key that needs no comparing.
void test_trust(double *t) {
    trust_clear();
    identity_keypair_t id_bob, id_new;
    gen_identity_keypair(&id_bob);
    gen_identity_keypair(&id_new);
    chat_set_identity(&B, IDENT_AGE, &id_bob);
    peer_t *pb = peer_with_id(&A, B.my_id), *pc = peer_with_id(&A, C.my_id);
    RUN_UNTIL(t, 10, pb && pb->identity_state == VERIFY_VERIFIED && memcmp(pb->identity_pub, id_bob.pub, ID_SIGN_PUB_LEN) == 0);
    CHECK(pb && pb->identity_state == VERIFY_VERIFIED, "alice didn't see bob's signing key");
    CHECK(pc != NULL, "alice has no carol");
    if (!pb || !pc) return;
    chat_run_command(&A, "verify bob ok");
    const trust_entry_t *e = trust_by_key(id_bob.pub);
    CHECK(trust_count() == 1 && e && strcmp(e->nick, "bob") == 0, "verifying bob didn't save his key");

    static char text[TRUST_TEXT_MAX];
    CHECK(trust_text(text, sizeof text) == 0, "the verified keys didn't fit as text");
    trust_clear();
    CHECK(trust_load(text) == 0 && trust_count() == 1 && trust_by_key(id_bob.pub), "the verified keys didn't read back");
    CHECK(trust_load("pgp 00zz bob\nkey\n\n") == 2 && trust_count() == 1, "bad lines weren't counted, or were added");

    // Carol takes bob's nick, with no signing key.
    int warned = log_a.key_warnings;
    chat_set_nick(&C, "b0b");
    RUN_UNTIL(t, 10, log_a.key_warnings > warned);
    CHECK(log_a.key_warnings == warned + 1 && pc->trust == 2, "carol with bob's nick wasn't warned about (%d)", log_a.key_warnings - warned);
    chat_set_nick(&C, "carol");
    RUN_UNTIL(t, 10, strcmp(pc->nick, "carol") == 0);
    CHECK(pc->trust == 0, "carol is still taken for bob");

    // Bob's key changes: one warning, and comparing codes again replaces the saved key.
    warned = log_a.key_warnings;
    chat_set_identity(&B, IDENT_AGE, &id_new);
    RUN_UNTIL(t, 10, memcmp(pb->identity_pub, id_new.pub, ID_SIGN_PUB_LEN) == 0 && log_a.key_warnings > warned);
    CHECK(log_a.key_warnings == warned + 1 && pb->trust == 2, "bob's new key wasn't warned about once (%d)", log_a.key_warnings - warned);
    pb->code_ok = 0;
    CHECK(chat_code_state(&A, pb) == 4, "bob's new key doesn't show as changed");
    chat_run_command(&A, "verify bob ok");
    CHECK(trust_count() == 1 && trust_by_key(id_new.pub) && !trust_by_key(id_bob.pub), "bob's new key didn't replace the old one");

    // A known key needs no comparing.
    pb->code_ok = 0;
    pb->trust = 0;
    int known = log_a.known_keys;
    chat_set_identity(&B, IDENT_AGE, &id_new);
    RUN_UNTIL(t, 10, log_a.known_keys > known);
    CHECK(pb->code_ok == 1 && pb->trust == 1, "bob's verified key still needed comparing");

    // Both rekey with bob's k on its way: it signs the session it was sent in, not a changed key.
    warned = log_a.key_warnings;
    uint32_t gen_a = A.keygen, gen_b = B.keygen;
    chat_set_identity(&B, IDENT_AGE, &id_new);
    A.next_rekey = B.next_rekey = 0;
    RUN_UNTIL(t, 90, A.keygen == gen_a + 1 && B.keygen == gen_b + 1 && rekeyed(&A, "bob") && rekeyed(&B, "alice"));
    RUN_FOR(t, K_SENDS * K_EVERY);
    CHECK(log_a.key_warnings == warned && pb->identity_state == VERIFY_VERIFIED && pb->trust == 1,
          "a rekey with bob's k on its way warned about his key (%d warnings, state %d, trust %d)",
          log_a.key_warnings - warned, pb->identity_state, pb->trust);

    chat_run_command(&A, "verified forget bob");
    CHECK(trust_count() == 0, "forgetting bob left %d keys", trust_count());
    chat_set_identity(&B, IDENT_NONE, NULL);
    RUN_FOR(t, 2);
}

// The room a move goes to, opened as the app opens it.
static void start_moved(chat_t *c, log_t *l, const char *nick, uint16_t port, const uint16_t *peer_ports, int n,
                        const chat_move_to_t *to) {
    chat_opts_t o;
    base_opts(&o, nick, port, peer_ports, n, to->created);
    copy_str(o.session_name, to->session_name, sizeof o.session_name);
    copy_str(o.password, to->password, sizeof o.password);
    o.moved = 1;
    o.moved_key = to->key;
    chat_init(c, &o, on_print, NULL, l, g_now);
}

// Whether x waits for y's ack of a record that starts with prefix.
static int awaits_ack(const chat_t *x, const peer_t *y, const char *prefix) {
    for (int i = 0; i < MAX_PENDING_MSGS; i++)
        if (x->pending[i].used && x->pending[i].peer_slot == (int)(y - x->peers) && starts_with(x->pending[i].text, prefix))
            return 1;
    return 0;
}

// Alice moves the room. Bob, whose code she compared, is asked, says yes and meets her in the new room,
// where the codes they compared still count. Carol runs a build that can't move (as far as alice
// knows), so she's left behind: she never gets "mv", and the new room's id and password never reach
// her. Who'd be left behind for a code not compared is checked too.
void test_move(double *t) {
    for (int k = 0; k < 3; k++) ALL[k]->next_rekey = *t + 1000.0;
    peer_t *ab = peer_named(&A, "bob"), *ac = peer_named(&A, "carol");
    CHECK(ab && ac && ab->code_ok == CODE_SAME && ab->can_move, "alice hasn't compared codes with bob, or he can't move");
    if (!ab || !ac) return;
    chat_move_plan_t plan;
    ac->code_ok = CODE_NOT_COMPARED;
    chat_move_plan(&A, &plan);
    CHECK(plan.coming == 1 && plan.left == 1 && strstr(plan.left_names, "carol (code not compared)"),
          "the plan with carol's code not compared: %d coming, %d left (%s)", plan.coming, plan.left, plan.left_names);
    ac->code_ok = CODE_SAME;
    ac->can_move = 0;
    chat_move_plan(&A, &plan);
    CHECK(plan.coming == 1 && strcmp(plan.coming_names, "bob") == 0 && strstr(plan.left_names, "carol (an older version)"),
          "the plan with carol on an older build: %s, leaving %s", plan.coming_names, plan.left_names);

    chat_move_to_t ta, tb;
    CHECK(chat_move_begin(&A, &ta) == 0 && ta.created && ta.session_name[0] && ta.password[0],
          "alice couldn't begin the move");
    start_moved(&A2, &log_a2, "alice", 40011, NULL, 0, &ta);
    CHECK(chat_started(&A2), "alice's new room didn't open");
    chat_move_go(&A, &ta, &A2, *t);
    live_mask |= 1 << 3;
    CHECK(awaits_ack(&A, ab, "mv\t") && !awaits_ack(&A, ac, "mv\t"), "\"mv\" didn't go to bob alone");

    RUN_UNTIL(t, 30, chat_move_asked(&B) != NULL);
    const chat_move_ask_t *ask = chat_move_asked(&B);
    CHECK(ask && strstr(ask->from, "alice") && ask->coming == 0, "bob wasn't asked to move with alice alone");
    // Bob's key goes to alice as he's asked, and reading the box takes longer than it takes to arrive.
    peer_t *ba = peer_named(&B, "alice");
    RUN_UNTIL(t, 10, ba && !awaits_ack(&B, ba, "mk\t") && ab->move_pub_set);
    CHECK(ab->move_pub_set, "alice never got bob's key for the move");
    CHECK(chat_move_accept(&B, &tb) == 0 && !tb.created && strcmp(tb.session_name, ta.session_name) == 0
          && strcmp(tb.password, ta.password) == 0, "bob's answer doesn't lead to alice's new room");
    uint16_t to_a2[1] = { 40011 };
    start_moved(&B2, &log_b2, "bob", 40012, to_a2, 1, &tb);
    CHECK(chat_started(&B2), "bob's new room didn't open");
    chat_move_go(&B, &tb, &B2, *t);
    live_mask |= 1 << 4;
    double went = *t;

    peer_t *a2b = NULL, *b2a = NULL;
    RUN_UNTIL(t, 60, (a2b = peer_named(&A2, "bob")) && (b2a = peer_named(&B2, "alice")) && a2b->announced
                     && b2a->announced && a2b->code_ok == CODE_SAME && b2a->code_ok == CODE_SAME);
    CHECK(a2b && a2b->code_ok == CODE_SAME, "in the new room, alice's code with bob doesn't count as compared");
    CHECK(b2a && b2a->code_ok == CODE_SAME, "in the new room, bob's code with alice doesn't count as compared");
    CHECK(log_a2.compare_prompts == 0 && log_b2.compare_prompts == 0 && log_a2.came_along == 1 && log_b2.came_along == 1,
          "the new room asked to compare codes (%d, %d) or didn't say they came along (%d, %d)", log_a2.compare_prompts,
          log_b2.compare_prompts, log_a2.came_along, log_b2.came_along);
    chat_send_text(&A2, "in the new room", *t);
    RUN_UNTIL(t, 10, log_count(&log_b2, "alice (code compared): in the new room") == 1);
    CHECK(log_count(&log_b2, "alice (code compared): in the new room") == 1,
          "bob didn't get alice's message in the new room");

    RUN_UNTIL(t, MOVE_LINGER + 5, chat_move_finished(&A, *t) && chat_move_finished(&B, *t));
    CHECK(chat_move_finished(&A, *t) && chat_move_finished(&B, *t) && *t - went < MOVE_LINGER,
          "the room they left didn't finish before MOVE_LINGER");
    CHECK(chat_move_asked(&C) == NULL && log_c.move_asks == 0, "carol was asked to move");
    CHECK(!find_bytes((const uint8_t *)&C, sizeof C, ta.session_name) && !find_bytes((const uint8_t *)&C, sizeof C, ta.password),
          "the new room's id or password reached carol");
    crypto_wipe(&ta, sizeof ta);
    crypto_wipe(&tb, sizeof tb);
}

// The room alice and bob moved out of closes as chat would close a session kept to reopen: carol
// reads "off", so alice shows as going offline, but bob takes her for an older build and says bye.
void test_offline(double *t) {
    peer_t *ac = peer_named(&A, "carol"), *bc = peer_named(&B, "carol");
    CHECK(ac && bc && ac->can_offline && bc->can_offline, "alice or bob doesn't see carol, or her k has no o");
    if (bc) bc->can_offline = 0;
    int offline = log_c.offline, lefts = log_c.lefts;
    A.coming_back = B.coming_back = 1;
    chat_shutdown(&A);
    chat_shutdown(&B);
    live_mask &= ~0x3;
    RUN_UNTIL(t, 10, chat_online_count(&C) == 0);
    CHECK(chat_online_count(&C) == 0, "carol still sees %d of the peers that left", chat_online_count(&C));
    CHECK(log_c.offline - offline == 1 && log_c.lefts - lefts == 1, "carol saw %d go offline and %d leave, want one each",
          log_c.offline - offline, log_c.lefts - lefts);
}
