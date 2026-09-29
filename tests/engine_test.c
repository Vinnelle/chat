// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Two (or three) sessions talking over fake_net: handshake, delivery, loss, rekey, junk.
#include "core/chat.h"
#include "fake_net.h"
#include "common/json.h"
#include "transport/portmap.h"
#include "common/util.h"
#include "crypto/age.h"
#include "crypto/pgp.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_LINES 512

typedef struct {
    const char *who;
    char lines[LOG_LINES][320];
    int n;
    int modified_warnings;
    int anon_joins;   // "* anon ... joined": a peer announced before its nick came
    int joining, unheralded_joins;   // "joining" lines not yet followed by "joined", and "joined" without one
} log_t;

static chat_t A, B, C;
static log_t log_a = { .who = "alice" }, log_b = { .who = "bob" }, log_c = { .who = "carol" };
static int checks, failures;
// -v: everything the sessions print, and every check as written, pass or fail.
static int verbose;

#define CHECK(cond, ...) do { \
    checks++; \
    if (cond) { if (verbose) printf("  pass  %s\n", #cond); } \
    else { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); \
           if (verbose) printf("  fail  %s\n", #cond); } \
} while (0)

static void on_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len) {
    log_t *l = ui;
    (void)hhmm; (void)rgb; (void)color_len;
    if (verbose) printf("  [%s%s] %s\n", l->who, (flags & LINE_CHAT) ? " chat" : "", text);
    if (!(flags & LINE_CHAT)) {
        if (strstr(text, "runs a modified client")) l->modified_warnings++;
        if (strncmp(text, "* anon", 6) == 0 && strstr(text, " joined (")) l->anon_joins++;
        if (strncmp(text, "* joining: peer ", 16) == 0) l->joining++;
        else if (strstr(text, " joined (")) { if (l->joining > 0) l->joining--; else l->unheralded_joins++; }
        return;
    }
    if (l->n < LOG_LINES) copy_str(l->lines[l->n++], text, sizeof l->lines[0]);
}

static int log_count(const log_t *l, const char *needle) {
    int k = 0;
    for (int i = 0; i < l->n; i++) if (strstr(l->lines[i], needle)) k++;
    return k;
}

// Release 1.2.3 is alice's and bob's binaries: its list, signed with a release key of the test's
// own as `just release` signs it, names them. Carol's is a build from source, with no list.
static const uint8_t BUILD_ALICE[BUILD_HASH_LEN] = { 1 }, BUILD_BOB[BUILD_HASH_LEN] = { 2 },
                     BUILD_CAROL[BUILD_HASH_LEN] = { 3 };
static char release_pub[64], release_list[BUILD_LIST_LEN + 1], release_sig[MINISIGN_SIG_B64_LEN + 1];

static void make_release(void) {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES], key[MINISIGN_KEY_LEN];
    crypto_sign_keypair(pk, sk);
    memcpy(key, "Ed", 2);
    gen_random(key + 2, 8);
    memcpy(key + 10, pk, sizeof pk);
    base64_encode(key, sizeof key, release_pub);

    char a[BUILD_HASH_LEN * 2 + 1], b[BUILD_HASH_LEN * 2 + 1], content[256];
    hex_encode(BUILD_ALICE, BUILD_HASH_LEN, a);
    hex_encode(BUILD_BOB, BUILD_HASH_LEN, b);
    snprintf(release_list, sizeof release_list, "%s,%s", a, b);
    int len = snprintf(content, sizeof content, "chat v1.2.3\n%s\n%s\n", a, b);
    // minisign's default signature: "ED", the key id, and Ed25519 over BLAKE2b-512 of the file.
    uint8_t h[64], sig[MINISIGN_SIG_LEN];
    crypto_generichash(h, sizeof h, (const uint8_t *)content, (size_t)len, NULL, 0);
    memcpy(sig, "ED", 2);
    memcpy(sig + 2, key + 2, 8);
    crypto_sign_detached(sig + 10, NULL, h, sizeof h, sk);
    base64_encode(sig, sizeof sig, release_sig);
}

static void start(chat_t *c, log_t *l, const char *nick, uint16_t port, const uint16_t *peer_ports, int n, int created,
                  const uint8_t build[BUILD_HASH_LEN], int released) {
    chat_opts_t o;
    memset(&o, 0, sizeof o);
    copy_str(o.nick, nick, sizeof o.nick);
    copy_str(o.session_name, "TESTSESSION", sizeof o.session_name);
    copy_str(o.password, "correct horse", sizeof o.password);
    o.port = port;
    for (int i = 0; i < n; i++) o.peers[i] = fake_net_addr(peer_ports[i]);
    o.n_peers = n;
    o.created = created;
    o.notify_mode = NOTIFY_NONE;
    o.build.ok = 1;
    copy_str(o.build.version, "1.2.3", sizeof o.build.version);
    memcpy(o.build.hash, build, BUILD_HASH_LEN);
    if (released) {
        copy_str(o.build.list, release_list, sizeof o.build.list);
        copy_str(o.build.list_sig, release_sig, sizeof o.build.list_sig);
    }
    copy_str(o.release_key, release_pub, sizeof o.release_key);
    chat_init(c, &o, on_print, NULL, l);
}

static chat_t *const ALL[] = { &A, &B, &C };
static const log_t *const ALL_LOGS[] = { &log_a, &log_b, &log_c };
static int n_live = 2;

// Delivers everything queued and ticks every session, `rounds` times, at time t.
static void pump(int rounds, double t) {
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < n_live; i++) chat_on_socket_readable(ALL[i], ALL[i]->sock, t);
        for (int i = 0; i < n_live; i++) chat_tick(ALL[i], t);
    }
}

static peer_t *peer_named(chat_t *c, const char *nick) {
    for (int i = 0; i < c->peer_hi; i++)
        if (c->peers[i].used && c->peers[i].ok && strcmp(c->peers[i].nick, nick) == 0) return &c->peers[i];
    return NULL;
}

static int pending_msgs(const chat_t *c) {
    int n = 0;
    for (int i = 0; i < MAX_PENDING_MSGS; i++) n += c->pending[i].used;
    return n;
}

// Drops the next session frame (the only kind this size) from one port to another.
typedef struct { int armed; uint16_t from, to; int dropped; } drop_t;

static int drop_one(void *ctx, addr_t from, addr_t to, const void *data, size_t len) {
    drop_t *d = ctx;
    (void)data;
    if (!d->armed || from.port != d->from || to.port != d->to) return 0;
    if (!sealed_len_ok(len, SESSION_HEADER_LEN, SESSION_PAD_TARGET)) return 0;
    d->armed = 0;
    d->dropped++;
    return 1;
}

static void test_connect(double *t) {
    for (int i = 0; i < 40 && !(chat_online_count(&A) == 1 && chat_online_count(&B) == 1); i++) {
        *t += 0.05;
        pump(4, *t);
    }
    CHECK(chat_online_count(&A) == 1, "alice sees %d peers, want 1", chat_online_count(&A));
    CHECK(chat_online_count(&B) == 1, "bob sees %d peers, want 1", chat_online_count(&B));
    CHECK(peer_named(&A, "bob") != NULL, "alice has no peer called bob");
    CHECK(peer_named(&B, "alice") != NULL, "bob has no peer called alice");
    peer_t *pa = peer_named(&A, "bob"), *pb = peer_named(&B, "alice");
    if (pa && pb) CHECK(memcmp(pa->vfy, pb->vfy, VERIFY_LEN) == 0, "verify codes differ");
}

static void test_message(double *t) {
    chat_send_text(&A, "hello there", *t);
    pump(4, *t);
    CHECK(log_count(&log_b, "alice: hello there") == 1, "bob didn't get alice's message once");
    CHECK(pending_msgs(&A) == 0, "alice still waits on %d acks", pending_msgs(&A));
}

// The message itself is lost and a later frame (a cover nop) gets through first, so the peer's
// chain has moved past the message's index: the retry has to be sealed afresh to be readable.
static void test_lost_message(double *t) {
    drop_t d = { 1, A.port, B.port, 0 };
    fake_net_filter = drop_one;
    fake_net_filter_ctx = &d;
    chat_send_text(&A, "lost then found", *t);
    fake_net_filter = NULL;
    CHECK(d.dropped == 1, "the message frame wasn't dropped");

    peer_t *pb = peer_named(&A, "bob");
    if (pb) pb->next_cover = 1.0;
    pump(2, *t);
    CHECK(log_count(&log_b, "lost then found") == 0, "bob got a message that was dropped");

    *t += 2.0;
    pump(4, *t);
    CHECK(log_count(&log_b, "lost then found") == 1, "bob got the retried message %d times, want 1",
          log_count(&log_b, "lost then found"));
    CHECK(pending_msgs(&A) == 0, "alice still waits on %d acks", pending_msgs(&A));
}

static void test_rekey(double *t) {
    uint32_t gen_a = A.keygen, gen_b = B.keygen;
    A.next_rekey = 0;
    B.next_rekey = 0;
    for (int i = 0; i < 40; i++) { *t += 0.05; pump(4, *t); }
    CHECK(A.keygen == gen_a + 1 && B.keygen == gen_b + 1, "no rekey happened");
    CHECK(chat_online_count(&A) == 1 && chat_online_count(&B) == 1, "a rekey dropped the peer");
    peer_t *pa = peer_named(&A, "bob"), *pb = peer_named(&B, "alice");
    CHECK(pa && pa->keygen == A.keygen && pa->chain_confirmed, "alice didn't re-handshake with bob");
    CHECK(pb && pb->keygen == B.keygen && pb->chain_confirmed, "bob didn't re-handshake with alice");
    chat_send_text(&B, "after the rekey", *t);
    pump(4, *t);
    CHECK(log_count(&log_a, "bob: after the rekey") == 1, "alice didn't get bob's message after the rekey");
}

// Junk from outside the room, some of it sized like real frames or chunks: nothing may break.
static void test_junk(double *t) {
    addr_t stranger = fake_net_addr(5555), a_addr = fake_net_addr(A.port);
    static const size_t sizes[] = { 0, 1, 4, 27, 428, 492, 1008, 2600, 2664, 3000 };
    uint8_t junk[3000];
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        for (int rep = 0; rep < 4; rep++) {
            gen_random(junk, sizeof junk);
            if (rep == 1 && sizes[k] >= 8) { junk[0] = CHUNK_MAGIC0; junk[1] = CHUNK_MAGIC1; junk[6] = 0; junk[7] = 3; }
            if (rep == 2 && sizes[k] >= 1) junk[0] = 'd';
            if (rep == 3 && sizes[k] >= 4) memset(junk, 0, 4);
            fake_net_inject(stranger, a_addr, junk, sizes[k]);
        }
    }
    unsigned other_before = A.st.other;
    pump(2, *t);
    CHECK(A.st.other > other_before, "junk wasn't counted as unreadable");
    CHECK(chat_online_count(&A) == 1, "junk dropped a peer");
    chat_send_text(&A, "still here", *t);
    pump(4, *t);
    CHECK(log_count(&log_b, "still here") == 1, "messages stopped after junk");
}

static void test_lookalike_nick(double *t) {
    chat_set_nick(&B, "ALlCE");
    pump(4, *t);
    peer_t *pb = peer_named(&A, "ALlCE");
    CHECK(pb != NULL, "alice didn't see bob's new nick");
    if (pb) {
        char name[CHAT_NAME_LEN];
        chat_peer_name(&A, pb, name);
        CHECK(strchr(name, '#') != NULL, "a nick that looks like alice's own shows as '%s', without an id", name);
    }
    chat_set_nick(&B, "bob");
    pump(4, *t);
}

// Carol joins through alice only: bob hears about her from alice (px) and connects directly.
// Carol's first session frame to alice, her nick and identity ("k"), is lost, so her next one
// gets through first. Alice still has to say carol joined, not an "anon".
static void test_third_peer(double *t) {
    uint16_t via_alice[1] = { A.port };
    start(&C, &log_c, "carol", 40003, via_alice, 1, 0, BUILD_CAROL, 0);
    n_live = 3;
    drop_t d = { 1, 40003, A.port, 0 };
    fake_net_filter = drop_one;
    fake_net_filter_ctx = &d;
    for (int i = 0; i < 60 && (chat_online_count(&C) < 2 || chat_online_count(&B) < 2); i++) { *t += 0.05; pump(4, *t); }
    fake_net_filter = NULL;
    for (int i = 0; i < 40 && !peer_named(&A, "carol"); i++) { *t += 0.05; pump(4, *t); }
    CHECK(d.dropped == 1, "carol's first frame to alice wasn't dropped");
    CHECK(chat_online_count(&C) == 2, "carol sees %d peers, want 2", chat_online_count(&C));
    CHECK(chat_online_count(&B) == 2, "bob sees %d peers, want 2", chat_online_count(&B));
    CHECK(peer_named(&A, "carol") != NULL, "alice never learned carol's nick");
    CHECK(log_a.anon_joins == 0 && log_b.anon_joins == 0, "a peer joined as anon (alice %d, bob %d)",
          log_a.anon_joins, log_b.anon_joins);
    for (int i = 0; i < n_live; i++) {
        const log_t *l = ALL_LOGS[i];
        CHECK(l->unheralded_joins == 0 && l->joining == 0, "%s printed %d joined without joining first, and %d "
              "joining without joined after", l->who, l->unheralded_joins, l->joining);
    }
    chat_send_text(&C, "hi all", *t);
    pump(4, *t);
    CHECK(log_count(&log_a, "carol: hi all") == 1, "alice didn't get carol's message once");
    CHECK(log_count(&log_b, "carol: hi all") == 1, "bob didn't get carol's message once");
}

// A peer already connected is no candidate: the keepalive's static peers stop being tried.
static void test_candidates_settle(double *t) {
    *t += KEEPALIVE + 4.0;
    pump(4, *t);
    CHECK(chat_candidate_count(&A) == 0, "alice still tries %d candidates she's connected to", chat_candidate_count(&A));
    CHECK(chat_online_count(&A) == 2, "alice lost a peer");
}

// Rekeys carol, which sends her "v" again with whatever her build now says.
static void resend_carol(double *t) {
    C.next_rekey = 0;
    for (int i = 0; i < 40; i++) { *t += 0.05; pump(4, *t); }
}

// Each peer's "v" against the signed list it came with.
static void test_builds(double *t) {
    for (int i = 0; i < 10; i++) { *t += 0.05; pump(2, *t); }
    peer_t *ab = peer_named(&A, "bob"), *ba = peer_named(&B, "alice"), *ca = peer_named(&C, "alice");
    peer_t *ac = peer_named(&A, "carol"), *bc = peer_named(&B, "carol");
    CHECK(ab && ab->build_state == BUILD_OFFICIAL, "alice doesn't see bob's build as official");
    CHECK(ba && ba->build_state == BUILD_OFFICIAL, "bob doesn't see alice's build as official");
    CHECK(ca && ca->build_state == BUILD_OFFICIAL, "carol doesn't see alice's build as official");
    CHECK(ac && ac->build_state == BUILD_MODIFIED, "alice doesn't see carol's build as modified");
    CHECK(bc && bc->build_state == BUILD_MODIFIED, "bob doesn't see carol's build as modified");
    CHECK(log_a.modified_warnings == 1 && log_b.modified_warnings == 1, "carol's build was warned about %d and %d times, want once each",
          log_a.modified_warnings, log_b.modified_warnings);
    CHECK(log_c.modified_warnings == 0, "carol was warned about a release build");
    char label[64];
    if (ab) chat_build_label(ab, label, sizeof label);
    CHECK(ab && strcmp(label, "says official v1.2.3") == 0, "bob's build shows as '%s'", ab ? label : "");

    // A rekey sends the same "v" again: no second warning.
    A.next_rekey = B.next_rekey = 0;
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_MODIFIED, "carol's build isn't modified after the rekey");
    CHECK(log_a.modified_warnings == 1, "a rekey warned about carol's build again");

    // Alice's list, passed on: carol's own hash still isn't in it.
    copy_str(C.build.list, release_list, sizeof C.build.list);
    copy_str(C.build.list_sig, release_sig, sizeof C.build.list_sig);
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_MODIFIED, "carol passed with someone else's list");

    // The list is signed for 1.2.3: under another version, even a hash in it doesn't pass.
    copy_str(C.build.version, "9.9.9", sizeof C.build.version);
    memcpy(C.build.hash, BUILD_ALICE, BUILD_HASH_LEN);
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_MODIFIED && strcmp(ac->build_version, "9.9.9") == 0,
          "1.2.3's list passed for 9.9.9");
    CHECK(log_a.modified_warnings == 2, "alice warned %d times about carol, want 2", log_a.modified_warnings);
    if (ac) chat_build_label(ac, label, sizeof label);
    CHECK(ac && strcmp(label, "modified client (says v9.9.9)") == 0, "carol's build shows as '%s'", ac ? label : "");

    // What no check can catch: carol says she runs alice's binary, and sends its list.
    copy_str(C.build.version, "1.2.3", sizeof C.build.version);
    resend_carol(t);
    ac = peer_named(&A, "carol");
    CHECK(ac && ac->build_state == BUILD_OFFICIAL, "a peer lying with an official hash wasn't taken at its word");
}

// What comes from relays, routers and Tor, taken apart without a network.
static void test_identity_keys(double *t) {
    (void)t;
    // An identity file age-keygen wrote, and the recipient it gave for it.
    static const char age_file[] =
        "# created: 2026-09-29T12:00:00+02:00\n"
        "# public key: age18t0t9tvw7r6at489p6jm9ngptg3j7tcyps5pn47fgvvzayc82dmsnghjje\n"
        "AGE-SECRET-KEY-1DRRXFHJCPKR2T7VJRQ4A4XR2P8NTDCT4J5GMQL3DRVRWMNVU90PST53ZSA\n";
    identity_keypair_t id;
    memset(&id, 0, sizeof id);
    CHECK(age_import_secret_key_text(age_file, &id) == 0 && id.scalar, "an age-keygen key didn't load");
    char recipient[AGE_RECIPIENT_STRLEN + 1];
    age_export_recipient(&id, recipient);
    CHECK(strcmp(recipient, "age18t0t9tvw7r6at489p6jm9ngptg3j7tcyps5pn47fgvvzayc82dmsnghjje") == 0,
          "the AGE key's recipient came out as %s", recipient);

    uint8_t eph_a[PUB_LEN], id_a[ID_LEN], eph_b[PUB_LEN], id_b[ID_LEN], sig[ID_SIGN_LEN];
    gen_random(eph_a, sizeof eph_a); gen_random(id_a, sizeof id_a);
    gen_random(eph_b, sizeof eph_b); gen_random(id_b, sizeof id_b);
    identity_sign(&id, eph_a, id_a, eph_b, id_b, sig);
    CHECK(identity_verify(id.pub, sig, eph_a, id_a, eph_b, id_b) == 0, "a signature by the AGE key didn't verify");
    sig[40] ^= 1;
    CHECK(identity_verify(id.pub, sig, eph_a, id_a, eph_b, id_b) != 0, "a tampered signature verified");

    char typo[sizeof age_file];
    memcpy(typo, age_file, sizeof typo);
    char *c = strstr(typo, "AGE-SECRET-KEY-1") + 30;
    *c = *c == 'Q' ? 'P' : 'Q';
    identity_keypair_t before = id;
    CHECK(age_import_secret_key_text(typo, &id) != 0, "an AGE key with a typo loaded");
    CHECK(memcmp(&id, &before, sizeof id) == 0, "a key that failed to load changed the identity");

    // The scalar signer against libsodium's: a seed key, put as its scalar and nonce key, has to
    // sign the same bytes.
    identity_keypair_t seeded, split;
    gen_identity_keypair(&seeded);
    uint8_t h[64], wide[64] = {0};
    crypto_hash_sha512(h, seeded.priv, 32);
    memcpy(wide, h, 32);
    wide[0] &= 248; wide[31] &= 127; wide[31] |= 64;
    memcpy(split.pub, seeded.pub, sizeof split.pub);
    crypto_core_ed25519_scalar_reduce(split.priv, wide);
    memcpy(split.priv + 32, h + 32, 32);
    split.scalar = 1;
    uint8_t msg[200], want[ID_SIGN_LEN], got[ID_SIGN_LEN];
    gen_random(msg, sizeof msg);
    identity_sign_bytes(&seeded, msg, sizeof msg, want);
    identity_sign_bytes(&split, msg, sizeof msg, got);
    CHECK(memcmp(want, got, sizeof want) == 0, "the scalar signer and libsodium signed differently");

    char armor[PGP_ARMOR_MAX];
    uint8_t fp[PGP_FP_LEN], fp2[PGP_FP_LEN];
    pgp_export_public_key(&seeded, "alice", 1790000000u, armor, sizeof armor, fp);
    pgp_export_public_key(&seeded, "alice", 1790000000u, armor, sizeof armor, fp2);
    CHECK(memcmp(fp, fp2, sizeof fp) == 0, "the same PGP key exported twice changed fingerprint");
    CHECK(strstr(armor, "-----END PGP PUBLIC KEY BLOCK-----") != NULL, "the PGP public key has no END line");

    // A key made from a password has to come out the same on every run and in every version, or
    // everyone's established identity changes. The answer is from Python's cryptography package:
    // Argon2id (4 passes, 512 MiB, one lane) over a BLAKE2b-128 salt of the label and device id.
    static const char device[] = "0123456789abcdef0123456789abcdef";
    identity_keypair_t derived, other;
    CHECK(identity_from_password("correct horse battery staple", device, &derived) == 0 && !derived.scalar,
          "no key came from a password");
    char pubhex[ID_SIGN_PUB_LEN * 2 + 1];
    hex_encode(derived.pub, ID_SIGN_PUB_LEN, pubhex);
    CHECK(strcmp(pubhex, "044354ed8bd36257adf234b893510d040769ba720f4e886431c27211e3b5dec2") == 0,
          "the key from a password came out as %s", pubhex);
    CHECK(identity_from_password("correct horse battery staple", "0123456789abcdef0123456789abcdee", &other) == 0
          && memcmp(derived.pub, other.pub, sizeof derived.pub) != 0, "another device made the same key");
    identity_sign_bytes(&derived, msg, sizeof msg, got);
    CHECK(crypto_sign_verify_detached(got, msg, sizeof msg, derived.pub) == 0, "the key from a password can't sign");
}

static void test_parsers(double *t) {
    (void)t;
    // An address Tor itself handed out, and the same with one character changed.
    CHECK(onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpyd"), "a real onion address fails its checksum");
    CHECK(!onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpye"), "a mistyped onion address passes");
    CHECK(!onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpy"), "a short onion address passes");

    static js_arena arena;
    const char *msg = "[\"EVENT\",\"ab\",{\"kind\":21000,\"tags\":[[\"e\",\"x\\u00e9\\n\"]],\"content\":\"a\\\"b\"}]";
    const js_value *v = js_parse(msg, strlen(msg), &arena);
    CHECK(v && v->type == JS_ARR && v->n == 3, "a relay message didn't parse");
    if (v && v->n == 3) {
        const js_value *ev = &v->items[2];
        const js_value *kind = js_obj_get(ev, "kind");
        CHECK(kind && kind->is_int && kind->i == 21000, "event kind came out wrong");
        const char *content = js_str(js_obj_get(ev, "content"));
        CHECK(content && strcmp(content, "a\"b") == 0, "escaped content came out as '%s'", content ? content : "");
        const js_value *tags = js_obj_get(ev, "tags");
        const char *tag = tags && tags->n == 1 ? js_str(&tags->items[0].items[1]) : NULL;
        CHECK(tag && strcmp(tag, "x\xc3\xa9\n") == 0, "a \\u escape didn't decode to UTF-8");
        char out[64];
        size_t n = tag ? js_put_str(out, 0, sizeof out, tag, strlen(tag)) : 0;
        CHECK(n > 0 && strcmp(out, "\"x\xc3\xa9\\n\"") == 0, "NIP-01 escaping gave %s", n ? out : "nothing");
    }
    CHECK(js_parse("[1,]", 4, &arena) == NULL, "a trailing comma parsed");
    CHECK(js_parse("[\"\\ud800\"]", 10, &arena) == NULL, "a lone surrogate parsed");

    const char *xml = "<root><service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>"
                      "<controlURL>/ppp</controlURL></service><service><serviceType>"
                      "urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL> /ctl/ip </controlURL>"
                      "</service></root>";
    char service[96], url[256];
    CHECK(portmap_parse_control_url(xml, strlen(xml), service, sizeof service, url, sizeof url) == 0
          && strcmp(url, "/ctl/ip") == 0 && strstr(service, "WANIPConnection:1"),
          "UPnP control URL came out wrong");
    const char *resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    char body[64];
    int status = 0;
    CHECK(portmap_http_body(resp, strlen(resp), &status, body, sizeof body) == 0 && status == 200
          && strcmp(body, "hello world") == 0, "a chunked reply came out as '%s'", body);

    uint8_t key[NOSTR_KEY_LEN], plain[NOSTR_WRAP_PLAIN], back[NOSTR_WRAP_PLAIN], sealed[NOSTR_WRAP_LEN], sealed2[NOSTR_WRAP_LEN];
    gen_random(key, sizeof key);
    gen_random(plain, sizeof plain);
    nostr_wrap(key, plain, sealed);
    nostr_wrap(key, plain, sealed2);
    CHECK(nostr_unwrap(key, sealed, sizeof sealed, back) == 0 && memcmp(back, plain, sizeof plain) == 0, "a wrapped event didn't open");
    CHECK(memcmp(sealed, sealed2, sizeof sealed) != 0, "the same datagram wrapped twice came out the same");
    sealed[100] ^= 1;
    CHECK(nostr_unwrap(key, sealed, sizeof sealed, back) != 0, "a tampered event opened");
}

int main(int argc, char **argv) {
    verbose = argc > 1 && (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0);
    double t_start = now_seconds();
    crypto_setup();
    net_startup();
    uint16_t to_b[1] = { 40002 }, to_a[1] = { 40001 };
    printf("deriving session keys (Argon2id, 512 MiB each)...\n");
    make_release();
    start(&A, &log_a, "alice", 40001, to_b, 1, 1, BUILD_ALICE, 1);
    start(&B, &log_b, "bob", 40002, to_a, 1, 0, BUILD_BOB, 1);
    double t = now_seconds();

    struct { const char *name; void (*fn)(double *); } tests[] = {
        { "connect", test_connect }, { "message", test_message }, { "lost message", test_lost_message },
        { "rekey", test_rekey }, { "junk", test_junk }, { "lookalike nick", test_lookalike_nick },
        { "third peer", test_third_peer }, { "candidates settle", test_candidates_settle }, { "builds", test_builds },
        { "parsers", test_parsers }, { "identity keys", test_identity_keys },
    };
    size_t n_tests = sizeof tests / sizeof tests[0];
    int failed[sizeof tests / sizeof tests[0]], n_failed = 0;
    for (size_t i = 0; i < n_tests; i++) {
        int before = failures;
        double t0 = now_seconds();
        if (verbose) printf("\n== %s\n", tests[i].name);
        tests[i].fn(&t);
        int ok = failures == before;
        if (!ok) failed[n_failed++] = (int)i;
        printf("%s %-16s %6.0f ms\n", ok ? "ok  " : "FAIL", tests[i].name, (now_seconds() - t0) * 1000.0);
    }
    for (int i = 0; i < n_live; i++) chat_shutdown(ALL[i]);

    printf("\n%zu tests: %zu passed, %d failed | %d checks, %d failed | %.1f s\n",
           n_tests, n_tests - (size_t)n_failed, n_failed, checks, failures, now_seconds() - t_start);
    if (n_failed) {
        printf("failed:");
        for (int i = 0; i < n_failed; i++) printf("%s %s", i ? "," : "", tests[failed[i]].name);
        printf("\n");
    }
    return failures ? 1 : 0;
}
