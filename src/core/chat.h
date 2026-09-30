// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_CHAT_H
#define CHAT_CHAT_H

#include "platform/net.h"
#include "crypto/crypto.h"
#include "transport/dht.h"
#include "core/cmd.h"
#include "transport/nostr.h"
#include "transport/tor.h"
#include "transport/portmap.h"
#include <stdint.h>
#include <stdio.h>

#define MAX_PEERS 50
#define MAX_PENDING_PEERS 64
#define MAX_CANDS 64
#define MAX_PENDING_MSGS 128
#define MAX_NICK 24
#define MAX_TEXT 250
#define MAX_SESSION_NAME 64
#define KEEPALIVE 10.0
#define PEER_TIMEOUT 40.0
#define PENDING_TTL 45.0
#define LONELY_HINT_AFTER 15.0

#define CAND_MAX_TRIES 12
// A candidate hello is ~2.6 KB to an address nobody vouched for. These keep chat from being a
// traffic reflector: few candidates per host, and a global rate.
#define CAND_PER_HOST 4
#define PROBE_RATE 4.0
#define PROBE_BURST 16.0
// A cookie challenge is as big as the hi it answers, and anyone who recorded a hi can replay it
// with a forged source address: a rate keeps chat from being a reflector for those.
#define CK_RATE 8.0
#define CK_BURST 32.0
// A session frame from an address no peer has is tried against every peer's chain. Real ones
// (a peer that moved) are rare; a rate keeps junk of the right size from eating the CPU.
#define ROAM_RATE 50.0
#define ROAM_BURST 100.0

#define RK_RESEND 2.0
#define HELLO_MAX_BACKOFF 5
#define RETRY_BASE 2.0
#define RETRY_CAP 32.0

#define HANDSHAKE_BUF_LEN 2700

// A room frame over UDP goes in pieces: magic, id (4), index, count, then up to CHUNK_PAYLOAD of
// the frame. Like everything chat sends over UDP they're masked (udp_mask), so the magic only
// shows once unmasked with the room's key. Relays and Tor carry frames whole.
#define CHUNK_MAGIC0 0xC5
#define CHUNK_MAGIC1 0x7A
#define CHUNK_HDR 8
#define CHUNK_PAYLOAD 1000
#define CHUNK_MAX 4

// Ratchet skip allowed when a frame arrives from an address that isn't the peer's. Trial decryption
// runs against every peer, so the full RATCHET_MAX_SKIP here would let junk packets burn CPU.
#define ROAM_MAX_SKIP 16

#define REASM_SLOTS 32
#define REASM_TTL 5.0

#ifndef REKEY_INTERVAL
#define REKEY_INTERVAL 300.0
#endif

#define REKEY_DRAIN_GRACE 20.0

#define REKEY_OVERLAP 20.0
#define JOIN_WAIT 5.0

#define COVER_INTERVAL 1.5
#define COVER_MAX_RATE 8.0

// Relays rate-limit, and every member receives every event: cover traffic to a peer reached
// through them is sparser, still well inside PEER_TIMEOUT.
#define NOSTR_COVER_INTERVAL 10.0
// A peer's UDP path counts as broken after this long without a frame; its traffic moves to the relays.
#define UDP_STALE 25.0
#define NOSTR_BEACON_ALONE 20.0
#define NOSTR_BEACON_CONNECTED 90.0
// A joiner in Tor mode that hasn't reached anyone by then publishes the room's onion itself.
#define TOR_HOST_AFTER 120.0

typedef enum { ROUTE_DIRECT = 0, ROUTE_TOR = 1 } route_mode_t;

// How a session reaches peers. Direct: UDP, found through the DHT (IPv4, IPv6), LAN broadcast
// and relays, with a router port mapping to let more of them in, and Nostr relays carrying
// traffic when UDP can't. Tor: onion services only; nothing else touches the network.
typedef struct {
    route_mode_t mode;
    int dht4, dht6, lan, portmap, nostr;
    char relays[NOSTR_MAX_RELAYS][NOSTR_URL_MAX];
    int n_relays;
    tor_opts_t tor;
} routing_t;

void routing_defaults(routing_t *r);
const char *routing_mode_name(route_mode_t m);

typedef struct {
    unsigned rx;
    unsigned rx_chunks, rx_chunk_done;
    unsigned room_ok;
    unsigned hi, ck, hi2, hi2_bad, kx, lan;
    unsigned session_ok;
    unsigned other;
    unsigned connects;
    addr_t src[6];
    unsigned src_n[6];
    int n_src;
} net_stats_t;

typedef struct {
    int used;
    addr_t from;
    uint8_t id[4];
    int count;
    unsigned got;
    size_t last_len;
    double born;
    uint8_t buf[CHUNK_MAX * CHUNK_PAYLOAD];
} reasm_t;

typedef enum { NOTIFY_NONE = 0, NOTIFY_MENTIONS = 1, NOTIFY_ALL = 2 } notify_mode_t;
// What a desktop notification shows: only that a message came (the default), who it's from, or
// who and what it says. Never the session: its id is all it takes to join one with a blank
// password, and desktops keep notifications.
typedef enum { PREVIEW_OFF = 0, PREVIEW_NICK = 1, PREVIEW_MESSAGE = 2 } notify_preview_t;
typedef enum { IDENT_NONE = 0, IDENT_NATIVE = 1, IDENT_AGE = 2, IDENT_PGP = 3 } identity_source_t;

typedef enum { VERIFY_UNVERIFIED = 0, VERIFY_VERIFIED = 1, VERIFY_FAILED = 2 } verify_state_t;

// What a peer's "v" says about the build it runs. A peer can lie about its hash, so OFFICIAL is
// only its word; MODIFIED is a build that doesn't claim to be a release's.
typedef enum {
    BUILD_UNKNOWN = 0,   // it sent none: a build from before "v"
    BUILD_UNCHECKED,     // this build has no release key to check it with
    BUILD_OFFICIAL,
    BUILD_MODIFIED       // not a binary of the release it names, or with no signed list of it
} build_state_t;

#define MAX_VERSION 15

// A release binary ends with a list of that release's binaries (the SHA-256 of each, without the
// list) signed with the release key: `just release` appends it. A build sends peers its own list
// in "v", so they check it with no one else to ask. Three hashes keep "v" inside one
// normal-sized session frame.
#define BUILD_LIST_MAX 3
#define BUILD_LIST_LEN (BUILD_LIST_MAX * (BUILD_HASH_LEN * 2 + 1))

// This program's build, as it tells peers.
typedef struct {
    int ok;   // 0 if the executable couldn't be read: nothing is sent
    char version[MAX_VERSION + 1];
    uint8_t hash[BUILD_HASH_LEN];
    char list[BUILD_LIST_LEN + 1];              // the list's hashes, hex, comma-separated; "" if none
    char list_sig[MINISIGN_SIG_B64_LEN + 1];    // the list's signature line
} chat_build_t;

// What a nick looks like once lookalikes, case and invisible characters are folded away.
#define NICK_SKEL_LEN (4 * MAX_NICK + 1)

typedef struct {
    int used;
    uint8_t id[ID_LEN];
    char nick[MAX_NICK + 1];
    char nick_skel[NICK_SKEL_LEN];
    addr_t addr;
    // The address before addr: frames from a peer that just moved, or that come over two Tor
    // streams at once, keep turning up there too.
    addr_t prev_addr;
    double seen, born, next_hello;
    int hello_tries;
    int ok;
    // The join is announced once "k" has brought the nick and identity (k_seen), or JOIN_WAIT
    // after the first frame opened (ok_since) if it never does, so nobody joins unannounced.
    double ok_since;
    int k_seen, announced;
    uint8_t pub[PUB_LEN];
    ratchet_t send_chain;
    ratchet_t recv_chain;
    uint8_t vfy[VERIFY_LEN];
    uint8_t color[3];
    int persists;
    identity_source_t identity_source;
    verify_state_t identity_state;
    uint8_t identity_pub[ID_SIGN_PUB_LEN];
    uint8_t identity_fp[ID_FP_LEN];

    char build_version[MAX_VERSION + 1];
    build_state_t build_state;
    int build_warn;   // a MODIFIED verdict to tell once the join is announced

    // When a frame last came over each kind of path (by addr_kind_t), and (Tor) the onion
    // address the peer said it has.
    double path_seen[3];
    char onion[TOR_ADDR_LEN + 1];

    uint8_t kem_pub[KEM_PUB_LEN];
    uint8_t prk_partial[32];
    uint8_t kem_ct[KEM_CT_LEN];

    uint32_t keygen;
    double next_cover;
    int vfy_set;
    // Set once a frame opens on the current recv_chain. Until then a replayed kx can't lock in bad chains.
    int chain_confirmed;
    // Responder only: kem_ct holds a kx that came before its re-handshake did, for do_hello to use.
    int kx_early;

    // The peer's k says it announces each new key over the current session ("rk") before it
    // rekeys. For such a peer, a re-handshake with a key it never announced is refused.
    int announces_rekey;
    uint8_t next_pub[PUB_LEN];
    int next_pub_set;
    double rk_refused_since, next_rk_warn;
    double next_rk;   // when to re-send our own rk until the peer re-handshakes with our new key

    ratchet_t old_send, old_recv;
    double old_until;
} peer_t;

typedef struct {
    int used;
    addr_t addr;
    int tries;
    double next_try;
} cand_t;

// "m\t" MID "\t" ORIGIN "\t" NICK "\t" TEXT, with room to spare.
#define MSG_LINE_LEN (16 + ID_LEN * 2 + MAX_NICK + MAX_TEXT + 16)

// A message waiting for its ack. It keeps the text, not the sealed frame: each retry is sealed
// afresh on the peer's current chain, since the peer can no longer open an old index once any
// later frame (a cover nop, say) has reached it.
typedef struct {
    int used;
    char mid[9];
    int peer_slot;
    char text[MSG_LINE_LEN];
    int tries;
    double next_retry;
} pending_msg_t;

typedef void (*chat_print_fn)(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                              unsigned flags, int color_len);

#define LINE_CHAT 1u
#define LINE_MENTION 2u

// A message worth a notification. nick and text are NULL unless the session's notify_preview
// lets the notification show them.
typedef void (*chat_notify_fn)(void *ui, const char *nick, const char *text, int mentioned);

typedef struct {

    char nick[MAX_NICK + 1];
    char nick_skel[NICK_SKEL_LEN];
    char session_name[MAX_SESSION_NAME + 1];
    uint8_t my_id[ID_LEN];

    keypair_t keys;
    kem_keypair_t kem_keys;
    uint8_t master[MASTER_LEN];
    uint8_t room_key[ROOM_KEY_LEN];
    uint8_t udp_key[UDP_KEY_LEN];
    uint8_t cookie_secret[32];
    int created;
    uint8_t my_color[3];

    identity_source_t identity_source;
    identity_keypair_t identity;

    int persist;
    FILE *log_fp;

    notify_mode_t notify_mode;
    notify_preview_t notify_preview;

    chat_build_t build;
    int has_release_key;
    uint8_t release_key[MINISIGN_KEY_LEN];

    int once, once_used;

    int net_verbose;

    sock_t sock, lan_sock;
    uint16_t port, lan_port;

    routing_t route;
    int started;
    const char *start_error;   // why it didn't start, when it didn't
    nostr_t *nostr;
    tor_t *tor;
    portmap_t *pm;
    double next_beacon;
    int tor_hosting;
    double tor_republish_at;
    char told_onion[TOR_ADDR_LEN + 1];

    peer_t peers[MAX_PEERS + MAX_PENDING_PEERS];
    int peer_hi;
    cand_t cands[MAX_CANDS];
    addr_t static_peers[16];
    int n_static;
    pending_msg_t pending[MAX_PENDING_MSGS];
    addr_t self_addrs[8];
    int n_self_addrs;

    int dht_on;
    dht_state_t dht;

    double start, next_alive, next_lan;
    uint32_t keygen;
    double next_rekey;
    double rekey_due;

    int warned_lonely, ever_connected, dht_summary_printed;

    uint32_t seen_mids[2048];
    int seen_head, seen_count;

    // Verify codes of peers that dropped: a peer that comes back gets a new one, and says so.
    struct { int used; uint8_t id[ID_LEN]; uint8_t vfy[VERIFY_LEN]; } gone[16];
    int gone_head;

    // Token buckets: hellos to candidates, which come from the DHT and other peers unchecked;
    // cookie challenges; and session frames tried against every peer (see CK_RATE, ROAM_RATE).
    double probe_tokens, probe_at;
    double ck_tokens, ck_at;
    double roam_tokens, roam_at;

    char my_idhex[ID_LEN * 2 + 1];
    char hi_msg[HANDSHAKE_BUF_LEN];

    reasm_t reasm[REASM_SLOTS];
    net_stats_t st;

    chat_print_fn print;
    chat_notify_fn notify;
    void *ui;
} chat_t;

typedef struct {
    char nick[MAX_NICK + 1];
    char session_name[MAX_SESSION_NAME + 1];
    char password[256];
    uint16_t port;
    addr_t peers[16];
    int n_peers;
    routing_t route;
    int created;
    int once;
    notify_mode_t notify_mode;
    notify_preview_t notify_preview;
    int persist;
    char log_path[512];

    identity_source_t identity_source;
    identity_keypair_t identity;
    int has_color;
    uint8_t color[3];

    // What peers are told about this build, and the release key (minisign, base64) their builds'
    // lists are checked with; "" leaves them unchecked.
    chat_build_t build;
    char release_key[64];
} chat_opts_t;

void chat_init(chat_t *c, const chat_opts_t *o, chat_print_fn print, chat_notify_fn notify, void *ui);
void chat_shutdown(chat_t *c);

void chat_tick(chat_t *c, double now);
void chat_on_socket_readable(chat_t *c, sock_t which, double now);

// Plain-mode entry point: ":name args" runs a command, anything else is sent. Returns 0 on :quit.
int chat_submit_line(chat_t *c, const char *line, double now);

// Runs "name args" (no leading ':') from CHAT_COMMANDS against this session.
cmd_result_t chat_run_command(chat_t *c, const char *line);
void chat_send_text(chat_t *c, const char *text, double now);

extern const command_t CHAT_COMMANDS[];

void chat_set_nick(chat_t *c, const char *nick);
void chat_set_colour(chat_t *c, const uint8_t rgb[3]);

// Cleans a nick and drops the characters the UI puts around nicks ("(verified)", "#id", "name:"),
// including lookalikes such as fullwidth brackets, and invisible characters, so no nick can fake
// them. Never empty: falls back to "anon".
void chat_clean_nick(const char *in, char out[MAX_NICK + 1]);

// A peer's nick as shown, with "#" and its id prefix added when another peer's nick, or ours,
// looks the same (case and common lookalike letters ignored).
#define CHAT_NAME_LEN (MAX_NICK + 10)
void chat_peer_name(const chat_t *c, const peer_t *p, char out[CHAT_NAME_LEN]);

void chat_set_identity(chat_t *c, identity_source_t source, const identity_keypair_t *idkp);

#define CHAT_MAX_SOCKS 12
int chat_sockets(chat_t *c, sock_t out[CHAT_MAX_SOCKS]);
// Whether the session is up: its keys could be made, and its UDP socket (direct) or its Tor link
// (Tor). If not, chat_start_error says why.
int chat_started(const chat_t *c);
const char *chat_start_error(const chat_t *c);
// Applies changed routing toggles to a running session. The mode and the Tor settings only
// apply to sessions opened afterwards; returns 1 if those differ from this session's.
int chat_apply_routing(chat_t *c, const routing_t *r);
// Moves a Tor session to the tor at these ports (the one chat started, or found running).
void chat_tor_set_ports(chat_t *c, const char *socks, const char *control);
// One line on how this session reaches peers, for the sidebar.
void chat_route_summary(const chat_t *c, char *out, size_t cap);
int chat_online_count(const chat_t *c);
int chat_pending_count(const chat_t *c);
int chat_candidate_count(const chat_t *c);

int chat_ready(const chat_t *c);
const char *chat_verify_label(verify_state_t s);
// What p runs, for :peers: "says official v0.3.1", "modified client (says v0.3.1)" and so on.
void chat_build_label(const peer_t *p, char *out, size_t cap);

typedef struct { const char *name; uint8_t r, g, b; } named_color_t;
extern const named_color_t COLOR_PALETTE[];
extern const int COLOR_PALETTE_N;

int parse_color(const char *text, uint8_t rgb[3]);

#endif
