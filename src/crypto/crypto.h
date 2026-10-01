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

// 128 bits: a room member in the middle picks both handshakes' keys, so it could search two sets
// of codes for a match, which 64 bits would let it find in time. The first 8 bytes are what 0.1.9
// and earlier show, so codes still compare with theirs.
#define VERIFY_LEN 16
#define DHT_INFOHASH_LEN 20
#define DHT_KEY_LEN 32
#define COOKIE_LEN 16
#define AEAD_NONCE_LEN 24
#define AEAD_TAG_LEN 16
#define PAD_BLOCK 64
#define RATCHET_MAX_SKIP 200

// Every session frame is sealed this big (a whole UDP cell), and read if it's at least
// SESSION_MIN_BODY, what 0.1.10 and earlier seal.
#define SESSION_PAD_TARGET 960
#define SESSION_MIN_BODY 384
// The biggest body anything is sealed with or read at: a handshake's two KEM keys and change.
#define SEAL_MAX_BODY (KEM_PUB_LEN * 2 + 256)

#define ROOM_PAD_TARGET 2560

#define ROOM_HEADER_LEN AEAD_NONCE_LEN
#define SESSION_HEADER_LEN (4 + AEAD_NONCE_LEN)
// True if frame_len is a length the sealer can produce (padding to PAD_BLOCK, at least min_body):
// a free check that turns most junk away before any key is derived or tag checked.
int sealed_len_ok(size_t frame_len, size_t header_len, size_t min_body);

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
// 0, or -1 when the memory for it isn't free.
int derive_master(const char *password, const char *session_id, uint8_t master[MASTER_LEN]);
void derive_room_key(const uint8_t master[MASTER_LEN], uint8_t room_key[ROOM_KEY_LEN]);
// The room's DHT key, and the lookup key it gives for one hour (epoch: Unix time / DHT_EPOCH). The
// lookup key changes every hour, so nothing the DHT sees stays the same for the room's lifetime.
#define DHT_EPOCH 3600
void derive_dht_key(const uint8_t master[MASTER_LEN], uint8_t key[DHT_KEY_LEN]);
void dht_epoch_infohash(const uint8_t key[DHT_KEY_LEN], long long epoch, uint8_t infohash[DHT_INFOHASH_LEN]);

// Everything chat sends over UDP is masked with a key of the room's, so that to anyone else each
// datagram is random bytes: no ratchet counter, no chunk header, nothing the same from one packet
// to the next. udp_mask XORs all but the last UDP_MASK_IV_LEN bytes with a keystream those bytes
// pick; they're always an AEAD tag or ciphertext, random already, so it costs no extra bytes. It
// runs in place, masking twice unmasks, and it returns -1 for a datagram too short to mask.
#define UDP_KEY_LEN 32
#define UDP_MASK_IV_LEN 16
void derive_udp_key(const uint8_t master[MASTER_LEN], uint8_t key[UDP_KEY_LEN]);
int udp_mask(const uint8_t key[UDP_KEY_LEN], uint8_t *d, size_t len);
// The UDP port the room's LAN beacons go to, 49152-65535: one of the room's own, where a fixed
// port would tell anyone on the network that chat is running.
uint16_t derive_lan_port(const uint8_t master[MASTER_LEN]);

// Nostr: tag_key makes the rotating tag room members' events carry, wrap_key seals each event's
// whole payload (addressing, datagram and padding) under a fresh nonce.
#define NOSTR_KEY_LEN 32
#define NOSTR_WRAP_PLAIN 2800
#define NOSTR_WRAP_LEN (AEAD_NONCE_LEN + NOSTR_WRAP_PLAIN + AEAD_TAG_LEN)
void derive_nostr_keys(const uint8_t master[MASTER_LEN], uint8_t tag_key[NOSTR_KEY_LEN], uint8_t wrap_key[NOSTR_KEY_LEN]);
void nostr_wrap(const uint8_t key[NOSTR_KEY_LEN], const uint8_t plain[NOSTR_WRAP_PLAIN], uint8_t out[NOSTR_WRAP_LEN]);
int nostr_unwrap(const uint8_t key[NOSTR_KEY_LEN], const uint8_t *in, size_t len, uint8_t plain[NOSTR_WRAP_PLAIN]);
// One of the room's onion service keys, the same for every member: the expanded ed25519 secret
// key ADD_ONION takes, and its public key.
void derive_tor_room_key(const uint8_t master[MASTER_LEN], int slot, uint8_t expanded[64], uint8_t pub[32]);

int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t len, uint8_t out[32]);
void sha256_hash(const void *data, size_t len, uint8_t out[32]);
// SHA-256 a piece at a time (libsodium's state, kept opaque here).
typedef struct { _Alignas(16) uint8_t state[128]; } sha256_ctx_t;
void sha256_init(sha256_ctx_t *h);
void sha256_update(sha256_ctx_t *h, const void *data, size_t len);
void sha256_final(sha256_ctx_t *h, uint8_t out[32]);

int ecdh_shared(const keypair_t *mine, const uint8_t their_pub[PUB_LEN], uint8_t shared[32]);

void session_prk(const uint8_t master[MASTER_LEN], const uint8_t shared[32],
                  const uint8_t my_pub[PUB_LEN], const uint8_t my_id[ID_LEN],
                  const uint8_t their_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                  uint8_t prk[32]);
void session_verify_code(const uint8_t prk[32], uint8_t code[VERIFY_LEN]);

void ratchet_seed(const uint8_t prk[32], const uint8_t owner_pub[PUB_LEN], ratchet_t *r);

int ratchet_peek(const ratchet_t *r, uint32_t target_index, uint8_t message_key[32], ratchet_t *result);

int room_seal(const uint8_t room_key[ROOM_KEY_LEN], const void *data, size_t len,
              uint8_t *out, size_t out_cap, size_t *out_len);
int room_unseal(const uint8_t room_key[ROOM_KEY_LEN], const uint8_t *frame, size_t frame_len,
                 uint8_t *data, size_t data_cap, size_t *data_len);
int session_seal(const uint8_t message_key[32], uint32_t index, const void *data, size_t len,
                  uint8_t *out, size_t out_cap, size_t *out_len);
// As session_seal, with a body of at least min_body (up to SEAL_MAX_BODY) instead of SESSION_PAD_TARGET.
int session_seal_padded(const uint8_t message_key[32], uint32_t index, const void *data, size_t len, size_t min_body,
                        uint8_t *out, size_t out_cap, size_t *out_len);
int session_unseal(const uint8_t message_key[32], uint32_t index, const uint8_t *frame, size_t frame_len,
                    uint8_t *data, size_t data_cap, size_t *data_len);

void cookie_compute(const uint8_t secret[32], const char *addr, const uint8_t peer_id[ID_LEN],
                     const uint8_t pub[PUB_LEN], uint8_t cookie[COOKIE_LEN]);

#define BUILD_HASH_LEN 32
// An executable's SHA-256 as one session shows it to another. It is keyed with both session ids,
// so a build that matches no release can't be recognised from one session or peer to the next.
void build_proof(const uint8_t exe_sha256[BUILD_HASH_LEN], const uint8_t from_id[ID_LEN],
                  const uint8_t to_id[ID_LEN], uint8_t proof[BUILD_HASH_LEN]);

// minisign: a public key ("Ed", key id, Ed25519 key) and a signature ("ED" or "Ed", key id,
// Ed25519 signature), as base64 in the .pub file and on the second line of a .minisig.
#define MINISIGN_KEY_LEN 42
#define MINISIGN_SIG_LEN 74
#define MINISIGN_SIG_B64_LEN 100
// Returns -1 if b64 isn't a minisign public key.
int minisign_pubkey(const char *b64, uint8_t key[MINISIGN_KEY_LEN]);
// Checks a signature line over msg. On success, sig_out (if not NULL) gets the raw Ed25519
// signature, which the .minisig's trusted comment is signed along with.
int minisign_verify(const uint8_t key[MINISIGN_KEY_LEN], const void *msg, size_t len,
                     const char *sig_b64, size_t sig_b64_len, uint8_t sig_out[64]);

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

// 128 bits, so no one can make a key that shows the same. The first 8 bytes are 0.1.9's.
#define ID_FP_LEN 16

// priv is libsodium's secret key (the seed, then the public key). With scalar set, it's instead
// the signing scalar, reduced mod L, then a key for the nonces: the form an AGE key takes, since
// an X25519 secret has no Ed25519 seed behind it.
typedef struct {
    uint8_t pub[ID_SIGN_PUB_LEN];
    uint8_t priv[ID_SIGN_PRIV_LEN];
    int scalar;
} identity_keypair_t;

void gen_identity_keypair(identity_keypair_t *kp);

// The identity a password makes on one device: the same password and device id always give the
// same key, and a different either gives another. The device id isn't secret (any program can
// read it), so the password is all that keeps the key: Argon2id, as for a session, makes each
// guess slow. idkp changes only on success; -1 when the memory for it isn't free.
#define ID_KDF_LABEL "chat-identity-v1"
int identity_from_password(const char *password, const char *device_id, identity_keypair_t *idkp);

// Secrets kept on disk under one passphrase. A lock is the key Argon2id makes from it with a
// salt, and its header (format, limits, salt); XChaCha20-Poly1305 seals each secret under that key,
// with the header as associated data. Everything sealed under a lock carries its header, so one
// Argon2id run opens it all, and sealing more takes none.
#define PASS_HEADER_LEN 32
#define PASS_SEAL_OVERHEAD (PASS_HEADER_LEN + AEAD_NONCE_LEN + AEAD_TAG_LEN)
#define PASS_WRONG  -1   // or sealed under another lock, or changed since it was sealed
#define PASS_NOMEM  -2
#define PASS_FORMAT -3
typedef struct {
    uint8_t header[PASS_HEADER_LEN];
    uint8_t key[32];
} pass_lock_t;
// A new lock, with a salt of its own: 0 or PASS_NOMEM.
int pass_lock_new(const char *passphrase, pass_lock_t *lk);
// The lock sealed was sealed under, if passphrase is its passphrase, which only pass_unseal can
// tell: 0, PASS_FORMAT or PASS_NOMEM.
int pass_lock_of(const char *passphrase, const uint8_t *sealed, size_t len, pass_lock_t *lk);
int pass_seal(const pass_lock_t *lk, const void *plain, size_t len, uint8_t *out, size_t cap, size_t *out_len);
int pass_unseal(const pass_lock_t *lk, const uint8_t *in, size_t len, void *plain, size_t cap, size_t *plain_len);

// An X25519 secret (an AGE key's) as an Ed25519 identity: the public key converts back to the same
// X25519 public key, so the AGE recipient shown is the key's own. idkp changes only on success.
int identity_from_x25519(const uint8_t secret[32], identity_keypair_t *idkp);

// Ed25519 over msg, from either form of key.
void identity_sign_bytes(const identity_keypair_t *idkp, const uint8_t *msg, size_t len, uint8_t sig[ID_SIGN_LEN]);

void identity_fingerprint(const uint8_t id_pub[ID_SIGN_PUB_LEN], uint8_t fp[ID_FP_LEN]);

void identity_sign(const identity_keypair_t *idkp,
                    const uint8_t my_eph_pub[PUB_LEN], const uint8_t my_id[ID_LEN],
                    const uint8_t their_eph_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                    uint8_t sig[ID_SIGN_LEN]);
int identity_verify(const uint8_t id_pub[ID_SIGN_PUB_LEN], const uint8_t sig[ID_SIGN_LEN],
                     const uint8_t their_eph_pub[PUB_LEN], const uint8_t their_id[ID_LEN],
                     const uint8_t my_eph_pub[PUB_LEN], const uint8_t my_id[ID_LEN]);

#endif
