// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "crypto/crypto.h"
#include "common/util.h"
#include <sodium.h>
#include <oqs/kem_ml_kem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PLAIN SEAL_MAX_BODY

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
    if (crypto_scalarmult_base(kp->pub, kp->priv) != 0) {
        fprintf(stderr, "chat: keypair generation failed\n");
        exit(1);
    }
}

static void kh(uint8_t *out, size_t outlen, const uint8_t *key, size_t keylen,
               const void *data, size_t datalen) {
    crypto_generichash(out, outlen, (const unsigned char *)data, datalen, key, keylen);
}

int derive_master(const char *password, const char *session_id, uint8_t master[MASTER_LEN]) {

    uint8_t salt[crypto_pwhash_SALTBYTES];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, sizeof salt);
    crypto_generichash_update(&st, (const unsigned char *)KDF_LABEL, sizeof(KDF_LABEL) - 1);
    crypto_generichash_update(&st, (const unsigned char *)session_id, strlen(session_id));
    crypto_generichash_final(&st, salt, sizeof salt);
    sodium_memzero(&st, sizeof st);

    // Running out of memory stops this session from starting, but shouldn't take the others down.
    return crypto_pwhash(master, MASTER_LEN, password, strlen(password), salt,
                         KDF_OPSLIMIT, KDF_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) == 0 ? 0 : -1;
}

void derive_room_key(const uint8_t master[MASTER_LEN], uint8_t room_key[ROOM_KEY_LEN]) {
    kh(room_key, ROOM_KEY_LEN, master, MASTER_LEN, "room", 4);
}

void derive_dht_key(const uint8_t master[MASTER_LEN], uint8_t key[DHT_KEY_LEN]) {
    kh(key, DHT_KEY_LEN, master, MASTER_LEN, "dht-key", 7);
}

// Keyed hash truncated to outlen, without leaving the untruncated rest on the stack.
static void kh_trunc(uint8_t *out, size_t outlen, const uint8_t *key, size_t keylen,
                     const void *data, size_t datalen) {
    uint8_t full[32];
    kh(full, sizeof full, key, keylen, data, datalen);
    memcpy(out, full, outlen);
    sodium_memzero(full, sizeof full);
}

void dht_epoch_infohash(const uint8_t key[DHT_KEY_LEN], long long epoch, uint8_t infohash[DHT_INFOHASH_LEN]) {
    uint8_t msg[9 + 8];
    memcpy(msg, "dht-epoch", 9);
    for (int i = 0; i < 8; i++) msg[9 + i] = (uint8_t)((unsigned long long)epoch >> (56 - 8 * i));
    kh_trunc(infohash, DHT_INFOHASH_LEN, key, DHT_KEY_LEN, msg, sizeof msg);
}

void derive_udp_key(const uint8_t master[MASTER_LEN], uint8_t key[UDP_KEY_LEN]) {
    kh(key, UDP_KEY_LEN, master, MASTER_LEN, "udp-mask", 8);
}

int udp_mask(const uint8_t key[UDP_KEY_LEN], uint8_t *d, size_t len) {
    // The rest has to be long enough that the IV is never part of a header.
    if (len < 2 * UDP_MASK_IV_LEN) return -1;
    uint8_t nonce[crypto_stream_xchacha20_NONCEBYTES] = { 0 };
    memcpy(nonce, d + len - UDP_MASK_IV_LEN, UDP_MASK_IV_LEN);
    crypto_stream_xchacha20_xor(d, d, len - UDP_MASK_IV_LEN, nonce, key);
    return 0;
}

uint16_t derive_lan_port(const uint8_t master[MASTER_LEN]) {
    uint8_t h[2];
    kh_trunc(h, sizeof h, master, MASTER_LEN, "lan-port", 8);
    return (uint16_t)(49152u + ((((unsigned)h[0] << 8) | h[1]) % 16384u));
}

void derive_nostr_keys(const uint8_t master[MASTER_LEN], uint8_t tag_key[NOSTR_KEY_LEN], uint8_t wrap_key[NOSTR_KEY_LEN]) {
    kh_trunc(tag_key, NOSTR_KEY_LEN, master, MASTER_LEN, "nostr-tag", 9);
    kh_trunc(wrap_key, NOSTR_KEY_LEN, master, MASTER_LEN, "nostr-wrap", 10);
}

static const uint8_t NOSTR_WRAP_AD[] = "chat nostr wrap v1";

void nostr_wrap(const uint8_t key[NOSTR_KEY_LEN], const uint8_t plain[NOSTR_WRAP_PLAIN], uint8_t out[NOSTR_WRAP_LEN]) {
    randombytes_buf(out, AEAD_NONCE_LEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(out + AEAD_NONCE_LEN, NULL, plain, NOSTR_WRAP_PLAIN,
                                               NOSTR_WRAP_AD, sizeof NOSTR_WRAP_AD - 1, NULL, out, key);
}

int nostr_unwrap(const uint8_t key[NOSTR_KEY_LEN], const uint8_t *in, size_t len, uint8_t plain[NOSTR_WRAP_PLAIN]) {
    if (len != NOSTR_WRAP_LEN) return -1;
    return crypto_aead_xchacha20poly1305_ietf_decrypt(plain, NULL, NULL, in + AEAD_NONCE_LEN, len - AEAD_NONCE_LEN,
                                                      NOSTR_WRAP_AD, sizeof NOSTR_WRAP_AD - 1, in, key) == 0 ? 0 : -1;
}

void derive_tor_room_key(const uint8_t master[MASTER_LEN], int slot, uint8_t expanded[64], uint8_t pub[32]) {
    uint8_t seed[32], label[4] = { 't', 'o', 'r', (uint8_t)slot };
    kh_trunc(seed, sizeof seed, master, MASTER_LEN, label, sizeof label);
    // Tor takes an ed25519 key in its expanded form: SHA-512 of the seed, the scalar half clamped.
    crypto_hash_sha512(expanded, seed, sizeof seed);
    sodium_memzero(seed, sizeof seed);
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;
    crypto_scalarmult_ed25519_base_noclamp(pub, expanded);
}

int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t len, uint8_t out[32]) {
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, key, keylen) != 0) return -1;
    crypto_auth_hmacsha256_update(&st, data, len);
    crypto_auth_hmacsha256_final(&st, out);
    sodium_memzero(&st, sizeof st);
    return 0;
}

_Static_assert(sizeof(crypto_hash_sha256_state) <= sizeof(((sha256_ctx_t *)0)->state), "sha256_ctx_t too small");

void sha256_init(sha256_ctx_t *h) { crypto_hash_sha256_init((crypto_hash_sha256_state *)(void *)h->state); }
void sha256_update(sha256_ctx_t *h, const void *data, size_t len) {
    crypto_hash_sha256_update((crypto_hash_sha256_state *)(void *)h->state, data, len);
}
void sha256_final(sha256_ctx_t *h, uint8_t out[32]) {
    crypto_hash_sha256_final((crypto_hash_sha256_state *)(void *)h->state, out);
}

void sha256_hash(const void *data, size_t len, uint8_t out[32]) {
    crypto_hash_sha256(out, data, len);
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
    sodium_memzero(buf, sizeof buf);
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
    kh_trunc(code, VERIFY_LEN, prk, 32, "vfy", 3);
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
    // The chain can't go past the last index, since the index would wrap to 0.
    if (target_index == UINT32_MAX) return -1;
    uint8_t cur[CHAIN_LEN], next[CHAIN_LEN];
    memcpy(cur, r->key, CHAIN_LEN);
    for (uint32_t idx = r->index; idx <= target_index; idx++) {
        if (idx == target_index) kh(message_key, 32, cur, CHAIN_LEN, "msg", 3);
        kh(next, CHAIN_LEN, cur, CHAIN_LEN, "step", 4);
        memcpy(cur, next, CHAIN_LEN);
    }
    result->started = 1;
    result->index = target_index + 1;
    memcpy(result->key, cur, CHAIN_LEN);
    sodium_memzero(next, CHAIN_LEN);
    sodium_memzero(cur, CHAIN_LEN);
    return 0;
}

static size_t padded_body(size_t plain_len, size_t min_body) {
    size_t body = plain_len + 2;
    body += (PAD_BLOCK - body % PAD_BLOCK) % PAD_BLOCK;
    return body < min_body ? min_body : body;
}

int sealed_len_ok(size_t frame_len, size_t header_len, size_t min_body) {
    if (frame_len < header_len + AEAD_TAG_LEN) return 0;
    size_t body = frame_len - header_len - AEAD_TAG_LEN;
    return body >= min_body && body <= MAX_PLAIN && body % PAD_BLOCK == 0;
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
    int rc = -1;
    size_t n = plen >= 2 ? ((size_t)plain[0] << 8) | plain[1] : 0;
    if (plen >= 2 && n <= plen - 2 && n <= data_cap) {
        memcpy(data, plain + 2, n);
        *data_len = n;
        rc = 0;
    }
    sodium_memzero(plain, (size_t)plen);
    return rc;
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
    if (!sealed_len_ok(frame_len, ROOM_HEADER_LEN, ROOM_PAD_TARGET)) return -1;
    return unseal_common(room_key, NULL, 0, frame, frame + AEAD_NONCE_LEN, frame_len - AEAD_NONCE_LEN,
                          data, data_cap, data_len);
}

int session_seal_padded(const uint8_t message_key[32], uint32_t index, const void *data, size_t len, size_t min_body,
                        uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t idx_be[4] = { (uint8_t)(index >> 24), (uint8_t)(index >> 16), (uint8_t)(index >> 8), (uint8_t)index };
    size_t ct_len;
    if (out_cap < SESSION_HEADER_LEN) return -1;
    if (seal_common(message_key, idx_be, 4, data, len, min_body, &ct_len, out + 4,
                     out + 4 + AEAD_NONCE_LEN, out_cap - SESSION_HEADER_LEN) != 0) return -1;
    memcpy(out, idx_be, 4);
    *out_len = 4 + AEAD_NONCE_LEN + ct_len;
    return 0;
}

int session_seal(const uint8_t message_key[32], uint32_t index, const void *data, size_t len,
                  uint8_t *out, size_t out_cap, size_t *out_len) {
    return session_seal_padded(message_key, index, data, len, SESSION_PAD_TARGET, out, out_cap, out_len);
}

int session_unseal(const uint8_t message_key[32], uint32_t index, const uint8_t *frame, size_t frame_len,
                    uint8_t *data, size_t data_cap, size_t *data_len) {
    if (!sealed_len_ok(frame_len, SESSION_HEADER_LEN, SESSION_MIN_BODY)) return -1;
    uint8_t idx_be[4] = { (uint8_t)(index >> 24), (uint8_t)(index >> 16), (uint8_t)(index >> 8), (uint8_t)index };
    const uint8_t *nonce = frame + 4, *ct = frame + SESSION_HEADER_LEN;
    return unseal_common(message_key, idx_be, 4, nonce, ct, frame_len - SESSION_HEADER_LEN,
                          data, data_cap, data_len);
}

void cookie_compute(const uint8_t secret[32], const char *addr, const uint8_t peer_id[ID_LEN],
                     const uint8_t pub[PUB_LEN], uint8_t cookie[COOKIE_LEN]) {
    // Only this host checks its cookies, so the layout is free to change. The address is
    // length-prefixed so it can't run into the id.
    size_t alen = strlen(addr);
    if (alen > 255) alen = 255;
    uint8_t alen_byte = (uint8_t)alen;
    crypto_generichash_state st;
    crypto_generichash_init(&st, secret, 32, COOKIE_LEN);
    crypto_generichash_update(&st, &alen_byte, 1);
    crypto_generichash_update(&st, (const unsigned char *)addr, alen);
    crypto_generichash_update(&st, peer_id, ID_LEN);
    crypto_generichash_update(&st, pub, PUB_LEN);
    crypto_generichash_final(&st, cookie, COOKIE_LEN);
    sodium_memzero(&st, sizeof st);
}

void build_proof(const uint8_t exe_sha256[BUILD_HASH_LEN], const uint8_t from_id[ID_LEN],
                  const uint8_t to_id[ID_LEN], uint8_t proof[BUILD_HASH_LEN]) {
    static const char LABEL[] = "chat build v1";
    crypto_generichash_state st;
    crypto_generichash_init(&st, exe_sha256, BUILD_HASH_LEN, BUILD_HASH_LEN);
    crypto_generichash_update(&st, (const unsigned char *)LABEL, sizeof LABEL - 1);
    crypto_generichash_update(&st, from_id, ID_LEN);
    crypto_generichash_update(&st, to_id, ID_LEN);
    crypto_generichash_final(&st, proof, BUILD_HASH_LEN);
    sodium_memzero(&st, sizeof st);
}

int minisign_pubkey(const char *b64, uint8_t key[MINISIGN_KEY_LEN]) {
    if (base64_decode_strict(b64, strlen(b64), key, MINISIGN_KEY_LEN) != MINISIGN_KEY_LEN) return -1;
    return memcmp(key, "Ed", 2) == 0 ? 0 : -1;
}

int minisign_verify(const uint8_t key[MINISIGN_KEY_LEN], const void *msg, size_t len,
                     const char *sig_b64, size_t sig_b64_len, uint8_t sig_out[64]) {
    uint8_t sig[MINISIGN_SIG_LEN];
    if (base64_decode_strict(sig_b64, sig_b64_len, sig, sizeof sig) != (long)sizeof sig) return -1;
    if (memcmp(sig + 2, key + 2, 8) != 0) return -1;
    const uint8_t *pk = key + 10, *s = sig + 10;
    int ok;
    if (memcmp(sig, "ED", 2) == 0) {
        // minisign's default: the signature covers BLAKE2b-512 of the file.
        uint8_t h[crypto_generichash_BYTES_MAX];
        crypto_generichash(h, sizeof h, (const unsigned char *)msg, len, NULL, 0);
        ok = crypto_sign_verify_detached(s, h, sizeof h, pk) == 0;
    } else if (memcmp(sig, "Ed", 2) == 0) {
        ok = crypto_sign_verify_detached(s, (const unsigned char *)msg, len, pk) == 0;
    } else {
        return -1;
    }
    if (!ok) return -1;
    if (sig_out) memcpy(sig_out, s, 64);
    return 0;
}

void gen_identity_keypair(identity_keypair_t *kp) {
    crypto_sign_keypair(kp->pub, kp->priv);
    kp->scalar = 0;
}

int identity_from_password(const char *password, const char *device_id, identity_keypair_t *idkp) {
    uint8_t salt[crypto_pwhash_SALTBYTES];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, sizeof salt);
    crypto_generichash_update(&st, (const unsigned char *)ID_KDF_LABEL, sizeof(ID_KDF_LABEL) - 1);
    crypto_generichash_update(&st, (const unsigned char *)device_id, strlen(device_id));
    crypto_generichash_final(&st, salt, sizeof salt);
    sodium_memzero(&st, sizeof st);

    uint8_t seed[crypto_sign_SEEDBYTES];
    if (crypto_pwhash(seed, sizeof seed, password, strlen(password), salt,
                      KDF_OPSLIMIT, KDF_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) return -1;
    identity_keypair_t kp;
    crypto_sign_seed_keypair(kp.pub, kp.priv, seed);
    kp.scalar = 0;
    *idkp = kp;
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(&kp, sizeof kp);
    return 0;
}

// The header: "chatkey1" ("chatdev1" for a lock that needs a device), Argon2id's opslimit and
// memlimit (KiB, big-endian), salt. Then each secret sealed: the header, a nonce, the sealed secret.
#define PASS_MAGIC "chatkey1"
#define PASS_DEVICE_MAGIC "chatdev1"

static int known_magic(const uint8_t *h) {
    return memcmp(h, PASS_MAGIC, 8) == 0 || memcmp(h, PASS_DEVICE_MAGIC, 8) == 0;
}

// A lock that needs a device seals and opens nothing until it has the device's secret.
static int lock_ready(const pass_lock_t *lk) {
    if (memcmp(lk->header, PASS_MAGIC, 8) == 0) return !lk->device;
    return memcmp(lk->header, PASS_DEVICE_MAGIC, 8) == 0 && lk->device;
}

// Limits above these mean a tampered file, which could otherwise ask for any amount of memory.
static int derive_lock_key(const char *passphrase, pass_lock_t *lk) {
    const uint8_t *h = lk->header;
    uint32_t ops = (uint32_t)h[8] << 24 | (uint32_t)h[9] << 16 | (uint32_t)h[10] << 8 | h[11];
    uint32_t mem_kib = (uint32_t)h[12] << 24 | (uint32_t)h[13] << 16 | (uint32_t)h[14] << 8 | h[15];
    if (ops < 1 || ops > 16 || mem_kib < 8 || mem_kib > 1024u * 1024u) return PASS_FORMAT;
    lk->device = 0;
    sodium_memzero(lk->key, sizeof lk->key);
    if (crypto_pwhash(lk->base, sizeof lk->base, passphrase, strlen(passphrase), h + 16, ops, (size_t)mem_kib * 1024u,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) return PASS_NOMEM;
    if (memcmp(h, PASS_MAGIC, 8) == 0) memcpy(lk->key, lk->base, sizeof lk->key);
    return 0;
}

int pass_needs_device(const uint8_t *sealed, size_t len) {
    return len >= 8 && memcmp(sealed, PASS_DEVICE_MAGIC, 8) == 0;
}

void pass_lock_device(pass_lock_t *lk, const uint8_t secret[PASS_DEVICE_SECRET_LEN]) {
    static const char LABEL[] = "chat device lock v1";
    memcpy(lk->header, PASS_DEVICE_MAGIC, 8);
    // Keyed with the passphrase's key: without either one, the key can't be worked out.
    crypto_generichash_state st;
    crypto_generichash_init(&st, lk->base, sizeof lk->base, sizeof lk->key);
    crypto_generichash_update(&st, (const unsigned char *)LABEL, sizeof LABEL - 1);
    crypto_generichash_update(&st, lk->header + 8, PASS_HEADER_LEN - 8);
    crypto_generichash_update(&st, secret, PASS_DEVICE_SECRET_LEN);
    crypto_generichash_final(&st, lk->key, sizeof lk->key);
    sodium_memzero(&st, sizeof st);
    lk->device = 1;
}

void pass_lock_portable(pass_lock_t *lk) {
    memcpy(lk->header, PASS_MAGIC, 8);
    memcpy(lk->key, lk->base, sizeof lk->key);
    lk->device = 0;
}

int pass_lock_new(const char *passphrase, pass_lock_t *lk) {
    memcpy(lk->header, PASS_MAGIC, 8);
    const uint32_t ops = KDF_OPSLIMIT, mem_kib = KDF_MEMLIMIT / 1024u;
    for (int i = 0; i < 4; i++) {
        lk->header[8 + i] = (uint8_t)(ops >> (24 - 8 * i));
        lk->header[12 + i] = (uint8_t)(mem_kib >> (24 - 8 * i));
    }
    randombytes_buf(lk->header + 16, PASS_HEADER_LEN - 16);
    return derive_lock_key(passphrase, lk);
}

int pass_lock_of(const char *passphrase, const uint8_t *sealed, size_t len, pass_lock_t *lk) {
    if (len < PASS_SEAL_OVERHEAD || !known_magic(sealed)) return PASS_FORMAT;
    memcpy(lk->header, sealed, PASS_HEADER_LEN);
    return derive_lock_key(passphrase, lk);
}

int pass_seal(const pass_lock_t *lk, const void *plain, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    if (cap < len + PASS_SEAL_OVERHEAD || !lock_ready(lk)) return PASS_FORMAT;
    memcpy(out, lk->header, PASS_HEADER_LEN);
    uint8_t *nonce = out + PASS_HEADER_LEN;
    randombytes_buf(nonce, AEAD_NONCE_LEN);
    unsigned long long ct_len;
    crypto_aead_xchacha20poly1305_ietf_encrypt(nonce + AEAD_NONCE_LEN, &ct_len, plain, len, out, PASS_HEADER_LEN,
                                               NULL, nonce, lk->key);
    *out_len = PASS_HEADER_LEN + AEAD_NONCE_LEN + (size_t)ct_len;
    return 0;
}

int pass_unseal(const pass_lock_t *lk, const uint8_t *in, size_t len, void *plain, size_t cap, size_t *plain_len) {
    if (len < PASS_SEAL_OVERHEAD || !known_magic(in)) return PASS_FORMAT;
    if (cap < len - PASS_SEAL_OVERHEAD) return PASS_FORMAT;
    if (memcmp(in, lk->header, PASS_HEADER_LEN) != 0 || !lock_ready(lk)) return PASS_WRONG;
    unsigned long long n;
    const uint8_t *nonce = in + PASS_HEADER_LEN;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain, &n, NULL, nonce + AEAD_NONCE_LEN,
                                                   len - PASS_HEADER_LEN - AEAD_NONCE_LEN, in, PASS_HEADER_LEN,
                                                   nonce, lk->key) != 0)
        return PASS_WRONG;
    *plain_len = (size_t)n;
    return 0;
}

int identity_from_x25519(const uint8_t secret[32], identity_keypair_t *idkp) {
    static const char NONCE_KEY_TAG[] = "chat identity nonce key";
    // X25519 clamps the secret before multiplying, so the Ed25519 side has to use the same scalar.
    uint8_t wide[64] = {0};
    memcpy(wide, secret, 32);
    wide[0] &= 248; wide[31] &= 127; wide[31] |= 64;
    identity_keypair_t kp;
    kp.scalar = 1;
    crypto_core_ed25519_scalar_reduce(kp.priv, wide);
    crypto_generichash(kp.priv + 32, 32, (const uint8_t *)NONCE_KEY_TAG, sizeof NONCE_KEY_TAG - 1, secret, 32);
    uint8_t x_pub[32], x_from_ed[32];
    int rc = -1;
    if (crypto_scalarmult_ed25519_base_noclamp(kp.pub, kp.priv) == 0
        && crypto_scalarmult_base(x_pub, secret) == 0
        && crypto_sign_ed25519_pk_to_curve25519(x_from_ed, kp.pub) == 0
        && sodium_memcmp(x_pub, x_from_ed, 32) == 0) {
        *idkp = kp;
        rc = 0;
    }
    sodium_memzero(wide, sizeof wide);
    sodium_memzero(&kp, sizeof kp);
    return rc;
}

// RFC 8032's signing, from the scalar and nonce key where libsodium would derive both from a seed.
static void sign_with_scalar(const identity_keypair_t *idkp, const uint8_t *msg, size_t len,
                             uint8_t sig[ID_SIGN_LEN]) {
    crypto_hash_sha512_state st;
    uint8_t h[64], r[32], k[32], ka[32];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, idkp->priv + 32, 32);
    crypto_hash_sha512_update(&st, msg, len);
    crypto_hash_sha512_final(&st, h);
    crypto_core_ed25519_scalar_reduce(r, h);
    if (crypto_scalarmult_ed25519_base_noclamp(sig, r) != 0) {
        // r is zero (odds 2^-252). Return no signature rather than one that leaks the scalar.
        memset(sig, 0, ID_SIGN_LEN);
    } else {
        crypto_hash_sha512_init(&st);
        crypto_hash_sha512_update(&st, sig, 32);
        crypto_hash_sha512_update(&st, idkp->pub, ID_SIGN_PUB_LEN);
        crypto_hash_sha512_update(&st, msg, len);
        crypto_hash_sha512_final(&st, h);
        crypto_core_ed25519_scalar_reduce(k, h);
        crypto_core_ed25519_scalar_mul(ka, k, idkp->priv);
        crypto_core_ed25519_scalar_add(sig + 32, r, ka);
    }
    sodium_memzero(&st, sizeof st);
    sodium_memzero(h, sizeof h);
    sodium_memzero(r, sizeof r);
    sodium_memzero(ka, sizeof ka);
}

void identity_sign_bytes(const identity_keypair_t *idkp, const uint8_t *msg, size_t len, uint8_t sig[ID_SIGN_LEN]) {
    if (idkp->scalar) sign_with_scalar(idkp, msg, len, sig);
    else crypto_sign_detached(sig, NULL, msg, len, idkp->priv);
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
    identity_sign_bytes(idkp, buf, SIGN_MSG_LEN, sig);
}

int identity_verify(const uint8_t id_pub[ID_SIGN_PUB_LEN], const uint8_t sig[ID_SIGN_LEN],
                     const uint8_t their_eph_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                     const uint8_t my_eph_pub[PUB_LEN], const uint8_t my_id[ID_LEN]) {

    uint8_t buf[SIGN_MSG_LEN];
    sign_message(buf, their_eph_pub, their_id, my_eph_pub, my_id);
    return crypto_sign_verify_detached(sig, buf, SIGN_MSG_LEN, id_pub) == 0 ? 0 : -1;
}
