// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_CRYPTO_H
#define CHAT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define PUB_LEN 32
#define PRIV_LEN 32
#define ID_LEN 16
#define MASTER_LEN 32
#define ROOM_KEY_LEN 32
#define CHAIN_LEN 32

#define VERIFY_LEN 8
#define FP_LEN 2
#define DHT_INFOHASH_LEN 20
#define COOKIE_LEN 16
#define AEAD_NONCE_LEN 24
#define AEAD_TAG_LEN 16
#define PAD_BLOCK 64
#define RATCHET_MAX_SKIP 200

#define SESSION_PAD_TARGET 384

#define ROOM_PAD_TARGET 2560

#define ROOM_HEADER_LEN AEAD_NONCE_LEN
#define SESSION_HEADER_LEN (4 + AEAD_NONCE_LEN)
size_t sealed_len(size_t plain_len, size_t header_len, size_t min_body);

typedef struct {
    uint8_t priv[PRIV_LEN];
    uint8_t pub[PUB_LEN];
} keypair_t;

typedef struct {
    uint8_t key[CHAIN_LEN];
    uint32_t index;
    int started;
} ratchet_t;

void crypto_setup(void);
void gen_keypair(keypair_t *kp);
void gen_random(uint8_t *out, size_t len);

void crypto_wipe(void *buf, size_t len);

int crypto_equal(const void *a, const void *b, size_t len);

int crypto_lock(void *buf, size_t len);
void crypto_unlock(void *buf, size_t len);

#define KDF_OPSLIMIT 4
#define KDF_MEMLIMIT (512u * 1024u * 1024u)
#define KDF_LABEL "chat-kdf-v2"
void derive_master(const char *password, const char *session_id, uint8_t master[MASTER_LEN]);
void derive_room_key(const uint8_t master[MASTER_LEN], uint8_t room_key[ROOM_KEY_LEN]);
void derive_dht_infohash(const uint8_t master[MASTER_LEN], uint8_t infohash[DHT_INFOHASH_LEN]);
void derive_fingerprint(const uint8_t master[MASTER_LEN], uint8_t fp[FP_LEN]);

int ecdh_shared(const keypair_t *mine, const uint8_t their_pub[PUB_LEN], uint8_t shared[32]);

void session_prk(const uint8_t master[MASTER_LEN], const uint8_t shared[32],
                  const uint8_t my_pub[PUB_LEN], const uint8_t my_id[ID_LEN],
                  const uint8_t their_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                  uint8_t prk[32]);
void session_verify_code(const uint8_t prk[32], uint8_t code[VERIFY_LEN]);

void ratchet_seed(const uint8_t prk[32], const uint8_t owner_pub[PUB_LEN], ratchet_t *r);

int ratchet_derive(ratchet_t *r, uint32_t target_index, uint8_t message_key[32]);

int ratchet_peek(const ratchet_t *r, uint32_t target_index, uint8_t message_key[32], ratchet_t *result);

int room_seal(const uint8_t room_key[ROOM_KEY_LEN], const void *data, size_t len,
              uint8_t *out, size_t out_cap, size_t *out_len);
int room_unseal(const uint8_t room_key[ROOM_KEY_LEN], const uint8_t *frame, size_t frame_len,
                 uint8_t *data, size_t data_cap, size_t *data_len);
int session_seal(const uint8_t message_key[32], uint32_t index, const void *data, size_t len,
                  uint8_t *out, size_t out_cap, size_t *out_len);
int session_unseal(const uint8_t message_key[32], uint32_t index, const uint8_t *frame, size_t frame_len,
                    uint8_t *data, size_t data_cap, size_t *data_len);

void cookie_compute(const uint8_t secret[32], const char *addr, const uint8_t peer_id[ID_LEN],
                     const uint8_t pub[PUB_LEN], uint8_t cookie[COOKIE_LEN]);

#define KEM_PUB_LEN 1184
#define KEM_PRIV_LEN 2400
#define KEM_CT_LEN 1088
#define KEM_SS_LEN 32

typedef struct {
    uint8_t pub[KEM_PUB_LEN];
    uint8_t priv[KEM_PRIV_LEN];
} kem_keypair_t;

void kem_gen_keypair(kem_keypair_t *kp);

int kem_encapsulate(const uint8_t their_pub[KEM_PUB_LEN], uint8_t ct[KEM_CT_LEN], uint8_t ss[KEM_SS_LEN]);

int kem_decapsulate(const kem_keypair_t *mine, const uint8_t ct[KEM_CT_LEN], uint8_t ss[KEM_SS_LEN]);

void session_prk_finish(const uint8_t prk_partial[32], const uint8_t kem_ss[KEM_SS_LEN], uint8_t prk_final[32]);

#define ID_SIGN_PUB_LEN 32
#define ID_SIGN_PRIV_LEN 64
#define ID_SIGN_LEN 64

#define ID_FP_LEN 8

typedef struct {
    uint8_t pub[ID_SIGN_PUB_LEN];
    uint8_t priv[ID_SIGN_PRIV_LEN];
} identity_keypair_t;

void gen_identity_keypair(identity_keypair_t *kp);

void identity_fingerprint(const uint8_t id_pub[ID_SIGN_PUB_LEN], uint8_t fp[ID_FP_LEN]);

void identity_sign(const identity_keypair_t *idkp,
                    const uint8_t my_eph_pub[PUB_LEN], const uint8_t my_id[ID_LEN],
                    const uint8_t their_eph_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                    uint8_t sig[ID_SIGN_LEN]);
int identity_verify(const uint8_t id_pub[ID_SIGN_PUB_LEN], const uint8_t sig[ID_SIGN_LEN],
                     const uint8_t their_eph_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                     const uint8_t my_eph_pub[PUB_LEN], const uint8_t my_id[ID_LEN]);

#endif
