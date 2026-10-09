// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "crypto/crypto.h"
#include "common/util.h"
#include <sodium.h>
#include <oqs/kem_ml_kem.h>
#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PLAIN SEAL_MAX_BODY
// A sealed body starts with the length of what's in it (big-endian), and the rest is padding.
#define BODY_LEN_PREFIX 2
#define AEAD_KEY_LEN crypto_aead_xchacha20poly1305_ietf_KEYBYTES

// A string literal as data to hash: its bytes, without the NUL.
#define LIT(s) (s), sizeof(s) - 1

void crypto_setup(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "chat: libsodium failed to initialize\n");
        exit(1);
    }
}

void gen_random(uint8_t *out, size_t len) { randombytes_buf(out, len); }

uint32_t gen_uniform(uint32_t upper) { return randombytes_uniform(upper); }

int crypto_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    randombytes_buf(out, len);
    return 0;
}

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

// Keyed hash truncated to outlen, without leaving the untruncated rest on the stack.
static void kh_trunc(uint8_t *out, size_t outlen, const uint8_t *key, size_t keylen,
                     const void *data, size_t datalen) {
    uint8_t full[crypto_generichash_BYTES];
    kh(full, sizeof full, key, keylen, data, datalen);
    memcpy(out, full, outlen);
    sodium_memzero(full, sizeof full);
}

static void hash_str(crypto_generichash_state *st, const char *s) {
    crypto_generichash_update(st, (const unsigned char *)s, strlen(s));
}

// Argon2id's salt for a password: the label and what the password is for, hashed.
static void pwhash_salt(const char *label, const char *what, uint8_t salt[crypto_pwhash_SALTBYTES]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, crypto_pwhash_SALTBYTES);
    hash_str(&st, label);
    hash_str(&st, what);
    crypto_generichash_final(&st, salt, crypto_pwhash_SALTBYTES);
    sodium_memzero(&st, sizeof st);
}

static int pwhash(uint8_t *out, size_t outlen, const char *password, const uint8_t salt[crypto_pwhash_SALTBYTES]) {
    return crypto_pwhash(out, outlen, password, strlen(password), salt, KDF_OPSLIMIT, KDF_MEMLIMIT,
                         crypto_pwhash_ALG_ARGON2ID13) == 0 ? 0 : -1;
}

// As X25519 and Ed25519 clamp a scalar: a multiple of the cofactor, below 2^255, with bit 254 set.
static void clamp(uint8_t s[32]) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

int derive_master(const char *password, const char *session_id, uint8_t master[MASTER_LEN]) {
    uint8_t salt[crypto_pwhash_SALTBYTES];
    pwhash_salt(CHAT_KDF_LABEL, session_id, salt);
    // Running out of memory stops this session from starting, but shouldn't take the others down.
    return pwhash(master, MASTER_LEN, password, salt);
}

void derive_room_key(const uint8_t master[MASTER_LEN], uint8_t room_key[ROOM_KEY_LEN]) {
    kh(room_key, ROOM_KEY_LEN, master, MASTER_LEN, LIT("room"));
}

void derive_dht_key(const uint8_t master[MASTER_LEN], uint8_t key[DHT_KEY_LEN]) {
    kh(key, DHT_KEY_LEN, master, MASTER_LEN, LIT("dht-key"));
}

void dht_epoch_infohash(const uint8_t key[DHT_KEY_LEN], long long epoch, uint8_t infohash[DHT_INFOHASH_LEN]) {
    static const char EPOCH[] = "dht-epoch";
    uint8_t msg[sizeof EPOCH - 1 + sizeof(uint64_t)];
    memcpy(msg, EPOCH, sizeof EPOCH - 1);
    store_be64(msg + sizeof EPOCH - 1, (uint64_t)epoch);
    kh_trunc(infohash, DHT_INFOHASH_LEN, key, DHT_KEY_LEN, msg, sizeof msg);
}

void derive_udp_key(const uint8_t master[MASTER_LEN], uint8_t key[UDP_KEY_LEN]) {
    kh(key, UDP_KEY_LEN, master, MASTER_LEN, LIT("udp-mask"));
}

int udp_mask(const uint8_t key[UDP_KEY_LEN], uint8_t *d, size_t len) {
    // The rest has to be long enough that the IV is never part of a header.
    if (len < 2 * UDP_MASK_IV_LEN) return -1;
    uint8_t nonce[crypto_stream_xchacha20_NONCEBYTES] = { 0 };
    memcpy(nonce, d + len - UDP_MASK_IV_LEN, UDP_MASK_IV_LEN);
    crypto_stream_xchacha20_xor(d, d, len - UDP_MASK_IV_LEN, nonce, key);
    return 0;
}

// The dynamic ports, 49152 to 65535.
#define LAN_PORT_FIRST 49152u
#define LAN_PORTS 16384u

uint16_t derive_lan_port(const uint8_t master[MASTER_LEN]) {
    uint8_t h[2];
    kh_trunc(h, sizeof h, master, MASTER_LEN, LIT("lan-port"));
    return (uint16_t)(LAN_PORT_FIRST + load_be16(h) % LAN_PORTS);
}

void derive_nostr_keys(const uint8_t master[MASTER_LEN], uint8_t tag_key[NOSTR_KEY_LEN], uint8_t wrap_key[NOSTR_KEY_LEN]) {
    kh_trunc(tag_key, NOSTR_KEY_LEN, master, MASTER_LEN, LIT("nostr-tag"));
    kh_trunc(wrap_key, NOSTR_KEY_LEN, master, MASTER_LEN, LIT("nostr-wrap"));
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

void derive_tor_room_key(const uint8_t master[MASTER_LEN], int slot, uint8_t expanded[TOR_KEY_LEN], uint8_t pub[TOR_PUB_LEN]) {
    uint8_t seed[crypto_sign_SEEDBYTES], label[4] = { 't', 'o', 'r', (uint8_t)slot };
    kh_trunc(seed, sizeof seed, master, MASTER_LEN, label, sizeof label);
    // Tor takes an ed25519 key in its expanded form: SHA-512 of the seed, the scalar half clamped.
    crypto_hash_sha512(expanded, seed, sizeof seed);
    sodium_memzero(seed, sizeof seed);
    clamp(expanded);
    crypto_scalarmult_ed25519_base_noclamp(pub, expanded);
}

int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t len, uint8_t out[SHA256_LEN]) {
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
void sha256_final(sha256_ctx_t *h, uint8_t out[SHA256_LEN]) {
    crypto_hash_sha256_final((crypto_hash_sha256_state *)(void *)h->state, out);
}

void sha256_hash(const void *data, size_t len, uint8_t out[SHA256_LEN]) {
    crypto_hash_sha256(out, data, len);
}

void sha1_hash(const void *data, size_t len, uint8_t out[SHA1_LEN]) {
    if (mbedtls_sha1(data, len, out) != 0) memset(out, 0, SHA1_LEN);
}

int ecdh_shared(const keypair_t *mine, const uint8_t their_pub[PUB_LEN], uint8_t shared[SHARED_LEN]) {
    return crypto_scalarmult(shared, mine->priv, their_pub);
}

void session_prk(const uint8_t master[MASTER_LEN], const uint8_t shared[SHARED_LEN],
                  const uint8_t my_pub[PUB_LEN], const uint8_t my_id[ID_LEN],
                  const uint8_t their_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                  uint8_t prk[PRK_LEN]) {
    uint8_t mine[PUB_LEN + ID_LEN], theirs[PUB_LEN + ID_LEN];
    memcpy(mine, my_pub, PUB_LEN); memcpy(mine + PUB_LEN, my_id, ID_LEN);
    memcpy(theirs, their_pub, PUB_LEN); memcpy(theirs + PUB_LEN, their_id, ID_LEN);
    const uint8_t *lo = mine, *hi = theirs;
    if (memcmp(mine, theirs, sizeof mine) > 0) { lo = theirs; hi = mine; }
    uint8_t buf[SHARED_LEN + sizeof(mine) + sizeof(theirs)];
    memcpy(buf, shared, SHARED_LEN);
    memcpy(buf + SHARED_LEN, lo, sizeof(mine));
    memcpy(buf + SHARED_LEN + sizeof(mine), hi, sizeof(theirs));
    kh(prk, PRK_LEN, master, MASTER_LEN, buf, sizeof(buf));
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

void session_prk_finish(const uint8_t prk_partial[PRK_LEN], const uint8_t kem_ss[KEM_SS_LEN], uint8_t prk_final[PRK_LEN]) {
    kh(prk_final, PRK_LEN, prk_partial, PRK_LEN, kem_ss, KEM_SS_LEN);
}

void session_verify_code(const uint8_t prk[PRK_LEN], uint8_t code[VERIFY_LEN]) {
    kh_trunc(code, VERIFY_LEN, prk, PRK_LEN, LIT("vfy"));
}

void ratchet_seed(const uint8_t prk[PRK_LEN], const uint8_t owner_pub[PUB_LEN], ratchet_t *r) {
    static const char CHAIN[] = "chain";
    uint8_t buf[sizeof CHAIN - 1 + PUB_LEN];
    memcpy(buf, CHAIN, sizeof CHAIN - 1);
    memcpy(buf + sizeof CHAIN - 1, owner_pub, PUB_LEN);
    kh(r->key, CHAIN_LEN, prk, PRK_LEN, buf, sizeof(buf));
    r->index = 0;
    r->started = 1;
}

int ratchet_peek(const ratchet_t *r, uint32_t target_index, uint8_t message_key[MSG_KEY_LEN], ratchet_t *result) {
    if (!r->started) return -1;
    if (target_index < r->index) return -1;
    if ((uint64_t)target_index - r->index > RATCHET_MAX_SKIP) return -1;
    // The chain can't go past the last index, since the index would wrap to 0.
    if (target_index == UINT32_MAX) return -1;
    uint8_t cur[CHAIN_LEN], next[CHAIN_LEN];
    memcpy(cur, r->key, CHAIN_LEN);
    for (uint32_t idx = r->index; idx <= target_index; idx++) {
        if (idx == target_index) kh(message_key, MSG_KEY_LEN, cur, CHAIN_LEN, LIT("msg"));
        kh(next, CHAIN_LEN, cur, CHAIN_LEN, LIT("step"));
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
    size_t body = plain_len + BODY_LEN_PREFIX;
    body += (PAD_BLOCK - body % PAD_BLOCK) % PAD_BLOCK;
    return body < min_body ? min_body : body;
}

int sealed_len_ok(size_t frame_len, size_t header_len, size_t min_body) {
    if (frame_len < header_len + AEAD_TAG_LEN) return 0;
    size_t body = frame_len - header_len - AEAD_TAG_LEN;
    return body >= min_body && body <= MAX_PLAIN && body % PAD_BLOCK == 0;
}

static int seal_common(const uint8_t key[AEAD_KEY_LEN], const uint8_t *ad, size_t adlen,
                        const void *data, size_t len, size_t min_body, size_t *ct_len,
                        uint8_t nonce_out[AEAD_NONCE_LEN], uint8_t *ct_out, size_t ct_cap) {
    if (len > MAX_PLAIN - BODY_LEN_PREFIX) return -1;
    size_t body = padded_body(len, min_body);
    if (body > MAX_PLAIN) return -1;
    if (body + AEAD_TAG_LEN > ct_cap) return -1;
    uint8_t plain[MAX_PLAIN];
    memset(plain, 0, body);
    store_be16(plain, (uint16_t)len);
    memcpy(plain + BODY_LEN_PREFIX, data, len);
    gen_random(nonce_out, AEAD_NONCE_LEN);
    unsigned long long ctlen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ct_out, &ctlen, plain, body, ad, adlen, NULL, nonce_out, key);
    *ct_len = (size_t)ctlen;
    sodium_memzero(plain, body);
    return 0;
}

static int unseal_common(const uint8_t key[AEAD_KEY_LEN], const uint8_t *ad, size_t adlen,
                          const uint8_t *nonce, const uint8_t *ct, size_t ctlen,
                          uint8_t *data, size_t data_cap, size_t *data_len) {
    uint8_t plain[MAX_PLAIN];
    if (ctlen < AEAD_TAG_LEN || ctlen - AEAD_TAG_LEN > sizeof(plain)) return -1;
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain, &plen, NULL, ct, ctlen, ad, adlen, nonce, key) != 0)
        return -1;
    int rc = -1;
    size_t n = plen >= BODY_LEN_PREFIX ? load_be16(plain) : 0;
    if (plen >= BODY_LEN_PREFIX && n <= plen - BODY_LEN_PREFIX && n <= data_cap) {
        memcpy(data, plain + BODY_LEN_PREFIX, n);
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

int session_seal_padded(const uint8_t message_key[MSG_KEY_LEN], uint32_t index, const void *data, size_t len, size_t min_body,
                        uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t idx_be[SESSION_INDEX_LEN];
    store_be32(idx_be, index);
    size_t ct_len;
    if (out_cap < SESSION_HEADER_LEN) return -1;
    if (seal_common(message_key, idx_be, SESSION_INDEX_LEN, data, len, min_body, &ct_len, out + SESSION_INDEX_LEN,
                     out + SESSION_HEADER_LEN, out_cap - SESSION_HEADER_LEN) != 0) return -1;
    memcpy(out, idx_be, SESSION_INDEX_LEN);
    *out_len = SESSION_HEADER_LEN + ct_len;
    return 0;
}

int session_seal(const uint8_t message_key[MSG_KEY_LEN], uint32_t index, const void *data, size_t len,
                  uint8_t *out, size_t out_cap, size_t *out_len) {
    return session_seal_padded(message_key, index, data, len, SESSION_PAD_TARGET, out, out_cap, out_len);
}

int session_unseal(const uint8_t message_key[MSG_KEY_LEN], uint32_t index, const uint8_t *frame, size_t frame_len,
                    uint8_t *data, size_t data_cap, size_t *data_len) {
    if (!sealed_len_ok(frame_len, SESSION_HEADER_LEN, SESSION_MIN_BODY)) return -1;
    uint8_t idx_be[SESSION_INDEX_LEN];
    store_be32(idx_be, index);
    const uint8_t *nonce = frame + SESSION_INDEX_LEN, *ct = frame + SESSION_HEADER_LEN;
    return unseal_common(message_key, idx_be, SESSION_INDEX_LEN, nonce, ct, frame_len - SESSION_HEADER_LEN,
                          data, data_cap, data_len);
}

void cookie_compute(const uint8_t secret[COOKIE_SECRET_LEN], const char *addr, const uint8_t peer_id[ID_LEN],
                     const uint8_t pub[PUB_LEN], uint8_t cookie[COOKIE_LEN]) {
    // Only this host checks its cookies, so the layout is free to change. The address is
    // length-prefixed so it can't run into the id.
    size_t alen = strlen(addr);
    if (alen > UINT8_MAX) alen = UINT8_MAX;
    uint8_t alen_byte = (uint8_t)alen;
    crypto_generichash_state st;
    crypto_generichash_init(&st, secret, COOKIE_SECRET_LEN, COOKIE_LEN);
    crypto_generichash_update(&st, &alen_byte, 1);
    crypto_generichash_update(&st, (const unsigned char *)addr, alen);
    crypto_generichash_update(&st, peer_id, ID_LEN);
    crypto_generichash_update(&st, pub, PUB_LEN);
    crypto_generichash_final(&st, cookie, COOKIE_LEN);
    sodium_memzero(&st, sizeof st);
}

void build_proof(const uint8_t exe_sha256[BUILD_HASH_LEN], const uint8_t from_id[ID_LEN],
                  const uint8_t to_id[ID_LEN], uint8_t proof[BUILD_HASH_LEN]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, exe_sha256, BUILD_HASH_LEN, BUILD_HASH_LEN);
    hash_str(&st, "chat build v1");
    crypto_generichash_update(&st, from_id, ID_LEN);
    crypto_generichash_update(&st, to_id, ID_LEN);
    crypto_generichash_final(&st, proof, BUILD_HASH_LEN);
    sodium_memzero(&st, sizeof st);
}

_Static_assert(MINISIGN_KEY_LEN == MINISIGN_BODY + crypto_sign_PUBLICKEYBYTES, "a minisign public key");
_Static_assert(MINISIGN_SIG_LEN == MINISIGN_BODY + crypto_sign_BYTES, "a minisign signature");

int minisign_pubkey(const char *b64, uint8_t key[MINISIGN_KEY_LEN]) {
    if (base64_decode_strict(b64, strlen(b64), key, MINISIGN_KEY_LEN) != MINISIGN_KEY_LEN) return -1;
    return memcmp(key, "Ed", MINISIGN_ALG_LEN) == 0 ? 0 : -1;
}

int minisign_verify(const uint8_t key[MINISIGN_KEY_LEN], const void *msg, size_t len,
                     const char *sig_b64, size_t sig_b64_len, uint8_t sig_out[ID_SIGN_LEN]) {
    uint8_t sig[MINISIGN_SIG_LEN];
    if (base64_decode_strict(sig_b64, sig_b64_len, sig, sizeof sig) != (long)sizeof sig) return -1;
    if (memcmp(sig + MINISIGN_ALG_LEN, key + MINISIGN_ALG_LEN, MINISIGN_ID_LEN) != 0) return -1;
    const uint8_t *pk = key + MINISIGN_BODY, *s = sig + MINISIGN_BODY;
    int ok;
    if (memcmp(sig, "ED", MINISIGN_ALG_LEN) == 0) {
        // minisign's default: the signature covers BLAKE2b-512 of the file.
        uint8_t h[crypto_generichash_BYTES_MAX];
        crypto_generichash(h, sizeof h, (const unsigned char *)msg, len, NULL, 0);
        ok = crypto_sign_verify_detached(s, h, sizeof h, pk) == 0;
    } else if (memcmp(sig, "Ed", MINISIGN_ALG_LEN) == 0) {
        ok = crypto_sign_verify_detached(s, (const unsigned char *)msg, len, pk) == 0;
    } else {
        return -1;
    }
    if (!ok) return -1;
    if (sig_out) memcpy(sig_out, s, crypto_sign_BYTES);
    return 0;
}

void gen_identity_keypair(identity_keypair_t *kp) {
    crypto_sign_keypair(kp->pub, kp->priv);
    kp->scalar = 0;
}

int identity_from_password(const char *password, const char *device_id, identity_keypair_t *idkp) {
    uint8_t salt[crypto_pwhash_SALTBYTES];
    pwhash_salt(ID_KDF_LABEL, device_id, salt);

    uint8_t seed[crypto_sign_SEEDBYTES];
    if (pwhash(seed, sizeof seed, password, salt) != 0) return -1;
    identity_keypair_t kp;
    crypto_sign_seed_keypair(kp.pub, kp.priv, seed);
    kp.scalar = 0;
    *idkp = kp;
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(&kp, sizeof kp);
    return 0;
}

// The header: "chatkey1" for the passphrase alone, "chatdev1" for it and a device, otherwise "chatmfa"
// and a byte of the factors it needs; then Argon2id's opslimit and memlimit (KiB, big-endian), salt.
// Then each secret sealed: the header, a nonce, the sealed secret.
#define PASS_MAGIC "chatkey1"
#define PASS_DEVICE_MAGIC "chatdev1"
#define PASS_FACTORS_MAGIC "chatmfa"
#define PASS_MAGIC_LEN (sizeof PASS_MAGIC - 1)
#define PASS_FACTORS_AT (sizeof PASS_FACTORS_MAGIC - 1)
#define PASS_OPS_AT 8
#define PASS_MEM_AT 12
#define PASS_SALT_AT 16
_Static_assert(sizeof PASS_DEVICE_MAGIC - 1 == PASS_MAGIC_LEN && PASS_FACTORS_AT + 1 == PASS_MAGIC_LEN, "magics");
_Static_assert(PASS_HEADER_LEN - PASS_SALT_AT == crypto_pwhash_SALTBYTES, "the header ends with the salt");
#define PASS_OPS_MAX 16
#define PASS_MEM_KIB_MIN 8
#define PASS_MEM_KIB_MAX (1024u * 1024u)

// The factors a header needs, or -1 if chat didn't write it. A device alone is always "chatdev1", so
// each set of factors has the one header.
static int header_needs(const uint8_t *h) {
    if (memcmp(h, PASS_MAGIC, PASS_MAGIC_LEN) == 0) return 0;
    if (memcmp(h, PASS_DEVICE_MAGIC, PASS_MAGIC_LEN) == 0) return (int)PASS_NEEDS_DEVICE;
    uint8_t needs = h[PASS_FACTORS_AT];
    if (memcmp(h, PASS_FACTORS_MAGIC, PASS_FACTORS_AT) != 0 || (needs & ~PASS_NEEDS_ALL) || !(needs & (PASS_NEEDS_KEY | PASS_NEEDS_CODE)))
        return -1;
    return needs;
}

static int known_magic(const uint8_t *h) { return header_needs(h) >= 0; }

static void set_magic(uint8_t h[PASS_HEADER_LEN], unsigned needs) {
    if (!needs) {
        memcpy(h, PASS_MAGIC, PASS_MAGIC_LEN);
    } else if (needs == PASS_NEEDS_DEVICE) {
        memcpy(h, PASS_DEVICE_MAGIC, PASS_MAGIC_LEN);
    } else {
        memcpy(h, PASS_FACTORS_MAGIC, PASS_FACTORS_AT);
        h[PASS_FACTORS_AT] = (uint8_t)needs;
    }
}

static void new_header(uint8_t h[PASS_HEADER_LEN]) {
    set_magic(h, 0);
    store_be32(h + PASS_OPS_AT, KDF_OPSLIMIT);
    store_be32(h + PASS_MEM_AT, KDF_MEMLIMIT / 1024u);
    randombytes_buf(h + PASS_SALT_AT, PASS_HEADER_LEN - PASS_SALT_AT);
}

static unsigned long g_derivations;

unsigned long pass_derivations(void) { return g_derivations; }

// A lock that needs more than the passphrase seals and opens nothing until it has their secrets.
static int lock_ready(const pass_lock_t *lk) {
    int needs = header_needs(lk->header);
    return needs >= 0 && (unsigned)needs == lk->needs;
}

// Limits above these mean a tampered file, which could otherwise ask for any amount of memory.
static int derive_lock_key(const char *passphrase, pass_lock_t *lk) {
    const uint8_t *h = lk->header;
    uint32_t ops = load_be32(h + PASS_OPS_AT), mem_kib = load_be32(h + PASS_MEM_AT);
    if (ops < 1 || ops > PASS_OPS_MAX || mem_kib < PASS_MEM_KIB_MIN || mem_kib > PASS_MEM_KIB_MAX) return PASS_FORMAT;
    lk->needs = 0;
    sodium_memzero(lk->key, sizeof lk->key);
    g_derivations++;
    if (crypto_pwhash(lk->base, sizeof lk->base, passphrase, strlen(passphrase), h + PASS_SALT_AT, ops,
                      (size_t)mem_kib * 1024u, crypto_pwhash_ALG_ARGON2ID13) != 0) return PASS_NOMEM;
    if (memcmp(h, PASS_MAGIC, PASS_MAGIC_LEN) == 0) memcpy(lk->key, lk->base, sizeof lk->key);
    return 0;
}

unsigned pass_needs(const uint8_t *sealed, size_t len) {
    int needs = len >= PASS_MAGIC_LEN ? header_needs(sealed) : -1;
    return needs > 0 ? (unsigned)needs : 0;
}

// Keyed with the passphrase's key: without it, or any of the secrets, the key can't be worked out.
void pass_lock_set(pass_lock_t *lk, unsigned needs, const uint8_t device[PASS_DEVICE_SECRET_LEN],
                   const uint8_t key[PASS_KEY_SECRET_LEN]) {
    needs &= PASS_NEEDS_ALL;
    lk->needs = needs;
    set_magic(lk->header, needs);
    if (!needs) {
        memcpy(lk->key, lk->base, sizeof lk->key);
        return;
    }
    crypto_generichash_state st;
    crypto_generichash_init(&st, lk->base, sizeof lk->base, sizeof lk->key);
    if (needs == PASS_NEEDS_DEVICE) {
        // As the device lock was first written, so saves locked then still open.
        hash_str(&st, "chat device lock v1");
        crypto_generichash_update(&st, lk->header + PASS_MAGIC_LEN, PASS_HEADER_LEN - PASS_MAGIC_LEN);
    } else {
        hash_str(&st, "chat factors v1");
        crypto_generichash_update(&st, lk->header, PASS_HEADER_LEN);
    }
    if (needs & PASS_NEEDS_DEVICE) crypto_generichash_update(&st, device, PASS_DEVICE_SECRET_LEN);
    if (needs & PASS_NEEDS_KEY) crypto_generichash_update(&st, key, PASS_KEY_SECRET_LEN);
    crypto_generichash_final(&st, lk->key, sizeof lk->key);
    sodium_memzero(&st, sizeof st);
}

int pass_lock_new(const char *passphrase, pass_lock_t *lk) {
    new_header(lk->header);
    return derive_lock_key(passphrase, lk);
}

void pass_chaff(unsigned needs, size_t plain_len, uint8_t *out) {
    new_header(out);
    set_magic(out, needs & PASS_NEEDS_ALL);
    randombytes_buf(out + PASS_HEADER_LEN, PASS_SEAL_OVERHEAD - PASS_HEADER_LEN + plain_len);
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

static void wrap_key(const uint8_t kek[WRAP_KEK_LEN], uint8_t key[AEAD_KEY_LEN]) {
    kh(key, AEAD_KEY_LEN, kek, WRAP_KEK_LEN, LIT("chat secret wrap v1"));
}

void secret_wrap(const uint8_t kek[WRAP_KEK_LEN], const uint8_t *ad, size_t ad_len, const uint8_t secret[WRAP_SECRET_LEN],
                 uint8_t out[WRAP_LEN]) {
    uint8_t key[AEAD_KEY_LEN];
    wrap_key(kek, key);
    randombytes_buf(out, AEAD_NONCE_LEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(out + AEAD_NONCE_LEN, NULL, secret, WRAP_SECRET_LEN, ad, ad_len, NULL, out, key);
    sodium_memzero(key, sizeof key);
}

int secret_unwrap(const uint8_t kek[WRAP_KEK_LEN], const uint8_t *ad, size_t ad_len, const uint8_t in[WRAP_LEN],
                  uint8_t secret[WRAP_SECRET_LEN]) {
    uint8_t key[AEAD_KEY_LEN];
    wrap_key(kek, key);
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(secret, NULL, NULL, in + AEAD_NONCE_LEN, WRAP_SECRET_LEN + AEAD_TAG_LEN,
                                                        ad, ad_len, in, key);
    sodium_memzero(key, sizeof key);
    return rc == 0 ? 0 : -1;
}

#define TOTP_MODULUS 1000000u   // 10 to the power of TOTP_DIGITS

// 1000000, which no code is, if HMAC-SHA1 can't be worked out.
uint32_t totp_code(const uint8_t *secret, size_t len, uint64_t step) {
    uint8_t msg[sizeof(uint64_t)], mac[SHA1_LEN];
    store_be64(msg, step);
    const mbedtls_md_info_t *sha1 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (!sha1 || mbedtls_md_hmac(sha1, secret, len, msg, sizeof msg, mac) != 0) return TOTP_MODULUS;
    // RFC 4226's dynamic truncation: 31 bits from where the last byte's low 4 bits say.
    int off = mac[SHA1_LEN - 1] & 15;
    uint32_t bin = load_be32(mac + off) & 0x7fffffffu;
    sodium_memzero(mac, sizeof mac);
    return bin % TOTP_MODULUS;
}

// With scalar set, an identity's priv is the scalar, then the key its signatures' nonces come from.
// A signature is the point R, then the scalar S.
#define SCALAR_LEN crypto_core_ed25519_SCALARBYTES
#define NONCE_KEY_LEN (ID_SIGN_PRIV_LEN - SCALAR_LEN)
#define POINT_LEN crypto_core_ed25519_BYTES

int identity_from_x25519(const uint8_t secret[PRIV_LEN], identity_keypair_t *idkp) {
    static const char NONCE_KEY_TAG[] = "chat identity nonce key";
    // X25519 clamps the secret before multiplying, so the Ed25519 side has to use the same scalar.
    uint8_t wide[crypto_core_ed25519_NONREDUCEDSCALARBYTES] = {0};
    memcpy(wide, secret, PRIV_LEN);
    clamp(wide);
    identity_keypair_t kp;
    kp.scalar = 1;
    crypto_core_ed25519_scalar_reduce(kp.priv, wide);
    crypto_generichash(kp.priv + SCALAR_LEN, NONCE_KEY_LEN, (const uint8_t *)NONCE_KEY_TAG, sizeof NONCE_KEY_TAG - 1,
                       secret, PRIV_LEN);
    uint8_t x_pub[PUB_LEN], x_from_ed[PUB_LEN];
    int rc = -1;
    if (crypto_scalarmult_ed25519_base_noclamp(kp.pub, kp.priv) == 0
        && crypto_scalarmult_base(x_pub, secret) == 0
        && crypto_sign_ed25519_pk_to_curve25519(x_from_ed, kp.pub) == 0
        && sodium_memcmp(x_pub, x_from_ed, PUB_LEN) == 0) {
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
    uint8_t h[crypto_hash_sha512_BYTES], r[SCALAR_LEN], k[SCALAR_LEN], ka[SCALAR_LEN];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, idkp->priv + SCALAR_LEN, NONCE_KEY_LEN);
    crypto_hash_sha512_update(&st, msg, len);
    crypto_hash_sha512_final(&st, h);
    crypto_core_ed25519_scalar_reduce(r, h);
    if (crypto_scalarmult_ed25519_base_noclamp(sig, r) != 0) {
        // r is zero (odds 2^-252). Return no signature rather than one that leaks the scalar.
        memset(sig, 0, ID_SIGN_LEN);
    } else {
        crypto_hash_sha512_init(&st);
        crypto_hash_sha512_update(&st, sig, POINT_LEN);
        crypto_hash_sha512_update(&st, idkp->pub, ID_SIGN_PUB_LEN);
        crypto_hash_sha512_update(&st, msg, len);
        crypto_hash_sha512_final(&st, h);
        crypto_core_ed25519_scalar_reduce(k, h);
        crypto_core_ed25519_scalar_mul(ka, k, idkp->priv);
        crypto_core_ed25519_scalar_add(sig + POINT_LEN, r, ka);
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
    kh_trunc(fp, ID_FP_LEN, NULL, 0, id_pub, ID_SIGN_PUB_LEN);
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
