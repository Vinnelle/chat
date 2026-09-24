// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "crypto.h"
#include <sodium.h>
#include <oqs/kem_ml_kem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PLAIN (KEM_PUB_LEN * 2 + 256)

void crypto_setup(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "chat: libsodium failed to initialize\n");
        exit(1);
    }
}

void gen_random(uint8_t *out, size_t len) { randombytes_buf(out, len); }

void crypto_wipe(void *buf, size_t len) { sodium_memzero(buf, len); }

int crypto_equal(const void *a, const void *b, size_t len) {
    return sodium_memcmp(a, b, len) == 0 ? 0 : -1;
}

int crypto_lock(void *buf, size_t len) { return sodium_mlock(buf, len) == 0 ? 0 : -1; }

void crypto_unlock(void *buf, size_t len) {

    if (sodium_munlock(buf, len) != 0) sodium_memzero(buf, len);
}

void gen_keypair(keypair_t *kp) {
    gen_random(kp->priv, PRIV_LEN);
    static const uint8_t basepoint[32] = {9};
    if (crypto_scalarmult(kp->pub, kp->priv, basepoint) != 0) {
        fprintf(stderr, "chat: keypair generation failed\n");
        exit(1);
    }
}

static void kh(uint8_t *out, size_t outlen, const uint8_t *key, size_t keylen,
               const void *data, size_t datalen) {
    crypto_generichash(out, outlen, (const unsigned char *)data, datalen, key, keylen);
}

void derive_master(const char *password, const char *session_id, uint8_t master[MASTER_LEN]) {

    uint8_t salt[crypto_pwhash_SALTBYTES];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, sizeof salt);
    crypto_generichash_update(&st, (const unsigned char *)KDF_LABEL, sizeof(KDF_LABEL) - 1);
    crypto_generichash_update(&st, (const unsigned char *)session_id, strlen(session_id));
    crypto_generichash_final(&st, salt, sizeof salt);
    sodium_memzero(&st, sizeof st);

    if (crypto_pwhash(master, MASTER_LEN, password, strlen(password), salt,
                       KDF_OPSLIMIT, KDF_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {

        fprintf(stderr, "chat: could not derive the session key - this needs %u MiB of free "
                         "memory for a few seconds\n", (unsigned)(KDF_MEMLIMIT / (1024u * 1024u)));
        exit(1);
    }
}

void derive_room_key(const uint8_t master[MASTER_LEN], uint8_t room_key[ROOM_KEY_LEN]) {
    kh(room_key, ROOM_KEY_LEN, master, MASTER_LEN, "room", 4);
}

void derive_dht_infohash(const uint8_t master[MASTER_LEN], uint8_t infohash[DHT_INFOHASH_LEN]) {
    uint8_t full[32];
    kh(full, 32, master, MASTER_LEN, "dht", 3);
    memcpy(infohash, full, DHT_INFOHASH_LEN);
}

void derive_fingerprint(const uint8_t master[MASTER_LEN], uint8_t fp[FP_LEN]) {
    uint8_t full[32];
    kh(full, 32, master, MASTER_LEN, "fp", 2);
    memcpy(fp, full, FP_LEN);
}

int ecdh_shared(const keypair_t *mine, const uint8_t their_pub[PUB_LEN], uint8_t shared[32]) {
    return crypto_scalarmult(shared, mine->priv, their_pub);
}

void session_prk(const uint8_t master[MASTER_LEN], const uint8_t shared[32],
                  const uint8_t my_pub[PUB_LEN], const uint8_t my_id[ID_LEN],
                  const uint8_t their_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                  uint8_t prk[32]) {
    uint8_t mine[PUB_LEN + ID_LEN], theirs[PUB_LEN + ID_LEN];
    memcpy(mine, my_pub, PUB_LEN); memcpy(mine + PUB_LEN, my_id, ID_LEN);
    memcpy(theirs, their_pub, PUB_LEN); memcpy(theirs + PUB_LEN, their_id, ID_LEN);
    const uint8_t *lo = mine, *hi = theirs;
    if (memcmp(mine, theirs, sizeof mine) > 0) { lo = theirs; hi = mine; }
    uint8_t buf[32 + sizeof(mine) + sizeof(theirs)];
    memcpy(buf, shared, 32);
    memcpy(buf + 32, lo, sizeof(mine));
    memcpy(buf + 32 + sizeof(mine), hi, sizeof(theirs));
    kh(prk, 32, master, MASTER_LEN, buf, sizeof(buf));
}

void kem_gen_keypair(kem_keypair_t *kp) {
    if (OQS_KEM_ml_kem_768_keypair(kp->pub, kp->priv) != OQS_SUCCESS) {
        fprintf(stderr, "chat: ML-KEM-768 keypair generation failed\n");
        exit(1);
    }
}

int kem_encapsulate(const uint8_t their_pub[KEM_PUB_LEN], uint8_t ct[KEM_CT_LEN], uint8_t ss[KEM_SS_LEN]) {
    return OQS_KEM_ml_kem_768_encaps(ct, ss, their_pub) == OQS_SUCCESS ? 0 : -1;
}

int kem_decapsulate(const kem_keypair_t *mine, const uint8_t ct[KEM_CT_LEN], uint8_t ss[KEM_SS_LEN]) {
    return OQS_KEM_ml_kem_768_decaps(ss, ct, mine->priv) == OQS_SUCCESS ? 0 : -1;
}

void session_prk_finish(const uint8_t prk_partial[32], const uint8_t kem_ss[KEM_SS_LEN], uint8_t prk_final[32]) {
    kh(prk_final, 32, prk_partial, 32, kem_ss, KEM_SS_LEN);
}

void session_verify_code(const uint8_t prk[32], uint8_t code[VERIFY_LEN]) {
    uint8_t full[32];
    kh(full, 32, prk, 32, "vfy", 3);
    memcpy(code, full, VERIFY_LEN);
}

void ratchet_seed(const uint8_t prk[32], const uint8_t owner_pub[PUB_LEN], ratchet_t *r) {
    uint8_t buf[5 + PUB_LEN];
    memcpy(buf, "chain", 5);
    memcpy(buf + 5, owner_pub, PUB_LEN);
    kh(r->key, CHAIN_LEN, prk, 32, buf, sizeof(buf));
    r->index = 0;
    r->started = 1;
}

int ratchet_peek(const ratchet_t *r, uint32_t target_index, uint8_t message_key[32], ratchet_t *result) {
    if (!r->started) return -1;
    if (target_index < r->index) return -1;
    if ((uint64_t)target_index - r->index > RATCHET_MAX_SKIP) return -1;
    uint8_t cur[CHAIN_LEN], next[CHAIN_LEN];
    memcpy(cur, r->key, CHAIN_LEN);
    uint32_t idx = r->index;
    while (1) {
        if (idx == target_index) kh(message_key, 32, cur, CHAIN_LEN, "msg", 3);
        kh(next, CHAIN_LEN, cur, CHAIN_LEN, "step", 4);
        sodium_memzero(cur, CHAIN_LEN);
        memcpy(cur, next, CHAIN_LEN);
        idx++;
        if (idx > target_index) break;
    }
    result->started = 1;
    result->index = idx;
    memcpy(result->key, cur, CHAIN_LEN);
    sodium_memzero(next, CHAIN_LEN);
    sodium_memzero(cur, CHAIN_LEN);
    return 0;
}

int ratchet_derive(ratchet_t *r, uint32_t target_index, uint8_t message_key[32]) {
    ratchet_t result;
    if (ratchet_peek(r, target_index, message_key, &result) != 0) return -1;
    *r = result;
    return 0;
}

static size_t padded_body(size_t plain_len, size_t min_body) {
    size_t body = plain_len + 2;
    body += (PAD_BLOCK - body % PAD_BLOCK) % PAD_BLOCK;
    return body < min_body ? min_body : body;
}

size_t sealed_len(size_t plain_len, size_t header_len, size_t min_body) {
    return header_len + padded_body(plain_len, min_body) + AEAD_TAG_LEN;
}

static int seal_common(const uint8_t key[32], const uint8_t *ad, size_t adlen,
                        const void *data, size_t len, size_t min_body, size_t *ct_len,
                        uint8_t nonce_out[AEAD_NONCE_LEN], uint8_t *ct_out, size_t ct_cap) {
    if (len > MAX_PLAIN - 2) return -1;
    size_t body = padded_body(len, min_body);
    if (body > MAX_PLAIN) return -1;
    if (body + AEAD_TAG_LEN > ct_cap) return -1;
    uint8_t plain[MAX_PLAIN];
    memset(plain, 0, body);
    plain[0] = (uint8_t)(len >> 8); plain[1] = (uint8_t)len;
    memcpy(plain + 2, data, len);
    gen_random(nonce_out, AEAD_NONCE_LEN);
    unsigned long long ctlen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ct_out, &ctlen, plain, body, ad, adlen, NULL, nonce_out, key);
    *ct_len = (size_t)ctlen;
    sodium_memzero(plain, body);
    return 0;
}

static int unseal_common(const uint8_t key[32], const uint8_t *ad, size_t adlen,
                          const uint8_t *nonce, const uint8_t *ct, size_t ctlen,
                          uint8_t *data, size_t data_cap, size_t *data_len) {
    uint8_t plain[MAX_PLAIN];
    if (ctlen < AEAD_TAG_LEN || ctlen - AEAD_TAG_LEN > sizeof(plain)) return -1;
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain, &plen, NULL, ct, ctlen, ad, adlen, nonce, key) != 0)
        return -1;
    if (plen < 2) return -1;
    size_t n = ((size_t)plain[0] << 8) | plain[1];
    if (n > plen - 2) return -1;
    if (n > data_cap) return -1;
    memcpy(data, plain + 2, n);
    *data_len = n;
    sodium_memzero(plain, (size_t)plen);
    return 0;
}

int room_seal(const uint8_t room_key[ROOM_KEY_LEN], const void *data, size_t len,
              uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t ct_len;
    if (out_cap < AEAD_NONCE_LEN) return -1;
    if (seal_common(room_key, NULL, 0, data, len, ROOM_PAD_TARGET, &ct_len, out, out + AEAD_NONCE_LEN,
                     out_cap - AEAD_NONCE_LEN) != 0) return -1;
    *out_len = AEAD_NONCE_LEN + ct_len;
    return 0;
}

int room_unseal(const uint8_t room_key[ROOM_KEY_LEN], const uint8_t *frame, size_t frame_len,
                 uint8_t *data, size_t data_cap, size_t *data_len) {
    if (frame_len < AEAD_NONCE_LEN + AEAD_TAG_LEN) return -1;
    return unseal_common(room_key, NULL, 0, frame, frame + AEAD_NONCE_LEN, frame_len - AEAD_NONCE_LEN,
                          data, data_cap, data_len);
}

int session_seal(const uint8_t message_key[32], uint32_t index, const void *data, size_t len,
                  uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t idx_be[4] = { (uint8_t)(index >> 24), (uint8_t)(index >> 16), (uint8_t)(index >> 8), (uint8_t)index };
    size_t ct_len;
    if (out_cap < SESSION_HEADER_LEN) return -1;
    if (seal_common(message_key, idx_be, 4, data, len, SESSION_PAD_TARGET, &ct_len, out + 4,
                     out + 4 + AEAD_NONCE_LEN, out_cap - SESSION_HEADER_LEN) != 0) return -1;
    memcpy(out, idx_be, 4);
    *out_len = 4 + AEAD_NONCE_LEN + ct_len;
    return 0;
}

int session_unseal(const uint8_t message_key[32], uint32_t index, const uint8_t *frame, size_t frame_len,
                    uint8_t *data, size_t data_cap, size_t *data_len) {
    if (frame_len < SESSION_HEADER_LEN + AEAD_TAG_LEN) return -1;
    uint8_t idx_be[4] = { (uint8_t)(index >> 24), (uint8_t)(index >> 16), (uint8_t)(index >> 8), (uint8_t)index };
    const uint8_t *nonce = frame + 4, *ct = frame + SESSION_HEADER_LEN;
    return unseal_common(message_key, idx_be, 4, nonce, ct, frame_len - SESSION_HEADER_LEN,
                          data, data_cap, data_len);
}

void cookie_compute(const uint8_t secret[32], const char *addr, const uint8_t peer_id[ID_LEN],
                     const uint8_t pub[PUB_LEN], uint8_t cookie[COOKIE_LEN]) {
    uint8_t buf[128 + ID_LEN + PUB_LEN] = {0};
    size_t alen = strlen(addr);
    if (alen > 128) alen = 128;
    memcpy(buf, addr, alen);
    memcpy(buf + alen, peer_id, ID_LEN);
    memcpy(buf + alen + ID_LEN, pub, PUB_LEN);
    uint8_t full[32];
    kh(full, 32, secret, 32, buf, alen + ID_LEN + PUB_LEN);
    memcpy(cookie, full, COOKIE_LEN);
}

void gen_identity_keypair(identity_keypair_t *kp) {
    crypto_sign_keypair(kp->pub, kp->priv);
}

void identity_fingerprint(const uint8_t id_pub[ID_SIGN_PUB_LEN], uint8_t fp[ID_FP_LEN]) {
    uint8_t full[32];
    crypto_generichash(full, sizeof full, id_pub, ID_SIGN_PUB_LEN, NULL, 0);
    memcpy(fp, full, ID_FP_LEN);
}

#define SIGN_MSG_LEN (2 * (PUB_LEN + ID_LEN))

static void sign_message(uint8_t buf[SIGN_MSG_LEN], const uint8_t a_pub[PUB_LEN], const uint8_t a_id[ID_LEN],
                          const uint8_t b_pub[PUB_LEN], const uint8_t b_id[ID_LEN]) {
    memcpy(buf, a_pub, PUB_LEN);
    memcpy(buf + PUB_LEN, a_id, ID_LEN);
    memcpy(buf + PUB_LEN + ID_LEN, b_pub, PUB_LEN);
    memcpy(buf + PUB_LEN + ID_LEN + PUB_LEN, b_id, ID_LEN);
}

void identity_sign(const identity_keypair_t *idkp,
                    const uint8_t my_eph_pub[PUB_LEN], const uint8_t my_id[ID_LEN],
                    const uint8_t their_eph_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                    uint8_t sig[ID_SIGN_LEN]) {
    uint8_t buf[SIGN_MSG_LEN];
    sign_message(buf, my_eph_pub, my_id, their_eph_pub, their_id);
    unsigned long long siglen;
    crypto_sign_detached(sig, &siglen, buf, SIGN_MSG_LEN, idkp->priv);
}

int identity_verify(const uint8_t id_pub[ID_SIGN_PUB_LEN], const uint8_t sig[ID_SIGN_LEN],
                     const uint8_t their_eph_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                     const uint8_t my_eph_pub[PUB_LEN], const uint8_t my_id[ID_LEN]) {

    uint8_t buf[SIGN_MSG_LEN];
    sign_message(buf, their_eph_pub, their_id, my_eph_pub, my_id);
    return crypto_sign_verify_detached(sig, buf, SIGN_MSG_LEN, id_pub) == 0 ? 0 : -1;
}
