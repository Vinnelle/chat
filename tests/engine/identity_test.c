// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Signing identities (AGE and PGP keys), the room :call works out from two of them, and invites.
#include "harness.h"

// A call's room: both ends work out the same id and password, whichever form their keys take, and
// another key, another day or your own key doesn't.
void test_contact_room(double *t) {
    (void)t;
    identity_keypair_t alice, bob, carol;
    uint8_t x[PRIV_LEN];
    char id[SESSION_ID_LEN + 1], pw[CONTACT_PASSWORD_LEN + 1], id2[SESSION_ID_LEN + 1], pw2[CONTACT_PASSWORD_LEN + 1];
    static const uint8_t small_order[ID_SIGN_PUB_LEN] = { 0 };
    const uint64_t day = 20373;
    gen_identity_keypair(&alice);
    gen_identity_keypair(&carol);
    randombytes_buf(x, sizeof x);
    CHECK(identity_from_x25519(x, &bob) == 0, "an AGE key didn't make an identity");
    CHECK(chat_contact_room(&alice, bob.pub, day, id, pw) == 0 && chat_contact_room(&bob, alice.pub, day, id2, pw2) == 0
          && strcmp(id, id2) == 0 && strcmp(pw, pw2) == 0, "alice and bob didn't work out the same room");
    CHECK(strlen(id) == SESSION_ID_LEN && strspn(id, "23456789ABCDEFGHJKMNPQRSTVWXYZ") == SESSION_ID_LEN
          && strlen(pw) == CONTACT_PASSWORD_LEN, "the room's id or password doesn't look like one: %s", id);
    CHECK(chat_contact_room(&carol, bob.pub, day, id2, pw2) == 0 && strcmp(id2, id) != 0 && strcmp(pw2, pw) != 0,
          "carol worked out alice and bob's room");
    CHECK(chat_contact_room(&alice, bob.pub, day + 1, id2, pw2) == 0 && strcmp(id2, id) != 0 && strcmp(pw2, pw) != 0,
          "the next day's room is the same");
    CHECK(chat_contact_room(&carol, alice.pub, day, id2, pw2) == 0
          && chat_contact_room(&alice, carol.pub, day, id, pw) == 0 && strcmp(id, id2) == 0 && strcmp(pw, pw2) == 0, "two keys from seeds didn't work out the same room");
    CHECK(chat_contact_room(&alice, alice.pub, day, id2, pw2) != 0, "a room with your own key was worked out");
    CHECK(chat_contact_room(&alice, small_order, day, id2, pw2) != 0, "a room with a small-order point was worked out");
    sodium_memzero(&alice, sizeof alice);
    sodium_memzero(&bob, sizeof bob);
    sodium_memzero(&carol, sizeof carol);
    sodium_memzero(x, sizeof x);
}

void test_invite(double *t) {
    (void)t;
    char inv[INVITE_MAX], id[MAX_SESSION_NAME + 1], pw[MAX_PASSWORD + 1];
    CHECK(chat_invite("K7M2Q9XRT4", "plum orbit: lantern", inv, sizeof inv) == 0
          && strncmp(inv, "chat:K7M2Q9XRT4:plum orbit: lantern:", 36) == 0 && strlen(inv) == 36 + INVITE_CHECK_LEN * 2,
          "an invite isn't chat:ID:PASSWORD:CHECK: %s", inv);
    CHECK(chat_invite_parse(inv, id, pw) == 1 && strcmp(id, "K7M2Q9XRT4") == 0 && strcmp(pw, "plum orbit: lantern") == 0,
          "an invite didn't give back its id and password");
    char spaced[INVITE_MAX + 4];
    snprintf(spaced, sizeof spaced, "  CHAT%s ", inv + 4);
    CHECK(chat_invite_parse(spaced, id, pw) == 1 && strcmp(pw, "plum orbit: lantern") == 0,
          "an invite with spaces round it, or the prefix in capitals, wasn't taken");
    char bad[INVITE_MAX];
    copy_str(bad, inv, sizeof bad);
    bad[16] = bad[16] == 'p' ? 'q' : 'p';
    CHECK(chat_invite_parse(bad, id, pw) == -1, "a mistyped invite was taken");
    copy_str(bad, inv, sizeof bad);
    bad[strlen(bad) - 1] = '\0';
    CHECK(chat_invite_parse(bad, id, pw) == -1, "a cut off invite was taken");
    CHECK(chat_invite_parse("chat:K7M2Q9XRT4", id, pw) == -1 && chat_invite_parse("chat:", id, pw) == -1,
          "an invite with no password or check was taken");
    CHECK(chat_invite_parse("K7M2Q9XRT4", id, pw) == 0, "a plain id was taken for an invite");
    CHECK(chat_invite("K7M2Q9XRT4", "", inv, sizeof inv) == 0 && chat_invite_parse(inv, id, pw) == 1 && pw[0] == '\0',
          "an invite with a blank password didn't round trip");
    CHECK(chat_invite("room:2", "pw", inv, sizeof inv) != 0, "an id with ':' in it got an invite");
    CHECK(chat_invite("K7M2Q9XRT4", "pw", inv, 12) != 0, "an invite was cut to fit");
}

void test_identity_keys(double *t) {
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

    // :exportkey's keys read back as the same key, an AGE key in either form.
    uint8_t x_seed[PRIV_LEN], x_split[PRIV_LEN];
    identity_to_x25519(&seeded, x_seed);
    identity_to_x25519(&split, x_split);
    CHECK(memcmp(x_seed, x_split, sizeof x_seed) == 0, "a key's scalar form didn't give back its X25519 secret");
    char age_key[AGE_SECRET_KEY_STRLEN + 1];
    identity_keypair_t back;
    age_export_secret_key(&seeded, age_key);
    CHECK(strlen(age_key) == AGE_SECRET_KEY_STRLEN && age_import_secret_key_text(age_key, &back) == 0
          && memcmp(back.pub, seeded.pub, sizeof back.pub) == 0, "a key from a seed didn't come back as an AGE key");
    age_export_secret_key(&id, age_key);
    CHECK(age_import_secret_key_text(age_key, &back) == 0 && memcmp(back.pub, id.pub, sizeof back.pub) == 0,
          "an age-keygen key didn't come back as an AGE key");
    CHECK(pgp_export_secret_key(&seeded, "alice", 1790000000u, armor, sizeof armor, fp2) == 0
          && memcmp(fp, fp2, sizeof fp) == 0, "the PGP secret key's fingerprint isn't its public key's");
    CHECK(strstr(armor, PGP_PRIVATE_END) != NULL && pgp_import_secret_key_text(armor, &back) == 0
          && memcmp(&back, &seeded, sizeof back) == 0, "the PGP secret key didn't come back");
    CHECK(pgp_export_secret_key(&split, "alice", 1790000000u, armor, sizeof armor, fp2) != 0,
          "a key with no seed was written as a PGP secret key");
    sodium_memzero(x_seed, sizeof x_seed);
    sodium_memzero(x_split, sizeof x_split);
    sodium_memzero(age_key, sizeof age_key);
    sodium_memzero(&back, sizeof back);
    sodium_memzero(armor, sizeof armor);

    // A key made from a password has to come out the same on every run and in every version, or
    // everyone's established identity changes. The answers are from Python's cryptography package:
    // Argon2id (4 passes, 512 MiB, one lane) over a BLAKE2b-128 salt of the label and device id, and
    // with a nick, of the nick's label, the device id, a NUL and the nick.
    static const char device[] = "0123456789abcdef0123456789abcdef";
    identity_keypair_t derived, other, nicked;
    CHECK(identity_from_password("correct horse battery staple", device, NULL, &derived) == 0 && !derived.scalar,
          "no key came from a password");
    char pubhex[ID_SIGN_PUB_LEN * 2 + 1];
    hex_encode(derived.pub, ID_SIGN_PUB_LEN, pubhex);
    CHECK(strcmp(pubhex, "044354ed8bd36257adf234b893510d040769ba720f4e886431c27211e3b5dec2") == 0,
          "the key from a password came out as %s", pubhex);
    CHECK(identity_from_password("correct horse battery staple", "0123456789abcdef0123456789abcdee", NULL, &other) == 0
          && memcmp(derived.pub, other.pub, sizeof derived.pub) != 0, "another device made the same key");
    CHECK(identity_from_password("correct horse battery staple", device, "alice", &nicked) == 0 && !nicked.scalar,
          "no key came from a password and a nick");
    hex_encode(nicked.pub, ID_SIGN_PUB_LEN, pubhex);
    CHECK(strcmp(pubhex, "d40cacd97fd54f890a1ec92813c6c8b98bc8dc175f300f60d84714532e0dbdec") == 0,
          "the key from a password and a nick came out as %s", pubhex);
    CHECK(identity_from_password("correct horse battery staple", device, "alicf", &other) == 0
          && memcmp(nicked.pub, other.pub, sizeof nicked.pub) != 0, "another nick made the same key");
    identity_sign_bytes(&derived, msg, sizeof msg, got);
    CHECK(crypto_sign_verify_detached(got, msg, sizeof msg, derived.pub) == 0, "the key from a password can't sign");
}
