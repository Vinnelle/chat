// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What a session holds: chat_t and peer_t, the queues and tables in them, and the protocol's timings
// and sizes. The engine's own: the app goes through chat.h's functions.
#ifndef CHAT_STATE_H
#define CHAT_STATE_H

#include "core/chat.h"
#include "transport/dht.h"
#include "transport/portmap.h"

#define MAX_CANDS 64
#define MAX_PENDING_MSGS 128

// What a peer without "l" in its "k" reads of a message: older versions cut a longer one off there,
// so it goes to them in parts, each a message of its own, at most MAX_TEXT_PARTS of them.
#define OLD_MAX_TEXT 250
#define MAX_TEXT_PARTS 8

#define MAX_SELF_ADDRS 8
// A peer that has sent nothing for this long gets a hi, in case it has lost the session.
#define KEEPALIVE 10.0
#define PEER_TIMEOUT 40.0
#define PENDING_TTL 45.0
#define LONELY_HINT_AFTER 15.0

#define CAND_MAX_TRIES 12
// A candidate hello is ~2.6 KB sent to an address nobody has confirmed. These stop chat being
// used as a traffic reflector: a few candidates per host, and a global rate limit.
#define CAND_PER_HOST 4
#define PROBE_RATE 4.0
#define PROBE_BURST 16.0
// A cookie challenge is as big as the hi it answers, and anyone who recorded a hi can replay it
// with a forged source address. A rate limit stops chat being used as a reflector for those.
#define CK_RATE 8.0
#define CK_BURST 32.0
// A session frame from an address no peer has is tried against every peer's chain. Real ones
// (a peer that moved) are rare, and a rate limit stops junk of the right size using up the CPU.
#define ROAM_RATE 50.0
#define ROAM_BURST 100.0

#define RK_RESEND 6.0
#define HELLO_MAX_BACKOFF 5
#define RETRY_BASE 2.0
#define RETRY_CAP 32.0
// A connected peer that hasn't re-handshaken with our new keys gets our hi again this often.
#define REHELLO_EVERY 20.0

#define HANDSHAKE_BUF_LEN 2700

// Every datagram chat sends over UDP is one cell of this size, the size of a session frame. A
// session frame fills one, and a room frame is split into pieces, each padded to a whole cell. A
// piece is the magic, an id (4), its index, the count, the whole frame's length (2), then up to
// CHUNK_PAYLOAD of the frame. Like everything chat sends over UDP they're masked (udp_mask), so
// the magic is only visible after unmasking with the room's key. Relays and Tor carry whole frames.
#define UDP_CELL (SESSION_HEADER_LEN + SESSION_PAD_TARGET + AEAD_TAG_LEN)
#define CHUNK_MAGIC0 0xC5
#define CHUNK_MAGIC1 0x7B
enum { CHUNK_ID_AT = 2, CHUNK_ID_LEN = 4, CHUNK_INDEX_AT = 6, CHUNK_COUNT_AT = 7, CHUNK_LEN_AT = 8, CHUNK_HDR = 10 };
#define CHUNK_PAYLOAD (UDP_CELL - CHUNK_HDR)
#define CHUNK_MAX 4
#define ROOM_FRAME_MAX (CHUNK_MAX * CHUNK_PAYLOAD)

// The most one session frame can carry: a record (one line of the protocol), or several joined by
// newlines for a peer whose "k" says it can read them ("b").
#define RECORD_MAX (SESSION_PAD_TARGET - 2)

// Through the relays a frame can be bigger, since every event is sealed to the same size whatever
// is in it. A peer that reads several records per frame gets frames there as big as it can read,
// all that size, which fits two file chunks.
#define RELAY_FRAME (SESSION_HEADER_LEN + SEAL_MAX_BODY + AEAD_TAG_LEN)
#define RELAY_RECORD_MAX (SEAL_MAX_BODY - 2)

// Ratchet skip allowed when a frame arrives from an address that isn't the peer's. Trial decryption
// runs against every peer, so the full RATCHET_MAX_SKIP here would let junk packets waste CPU.
#define ROAM_MAX_SKIP 16

#define REASM_SLOTS 32
// A room frame's pieces go one per slot, so it takes a few seconds for all of them to arrive.
#define REASM_TTL 30.0

#ifndef REKEY_INTERVAL
#define REKEY_INTERVAL 300.0
#endif

#define REKEY_DRAIN_GRACE 20.0
// A rekey also waits, up to this long, while a re-handshake with anyone is still in progress, ours
// or theirs. One that overlapped it would restart with keys the other side hasn't seen, and through
// the relays, where a re-handshake takes most of a minute, they kept overlapping until the session
// timed out.
#define REKEY_DEFER_MAX 120.0

// A re-handshake goes through slots one piece at a time, so the old chains are kept this long for it.
#define REKEY_OVERLAP 90.0
#define JOIN_WAIT 5.0
#define K_SENDS 3
#define K_EVERY 2.0

// Each peer has a slot this often (plus up to a quarter more, at random), and every slot sends
// exactly one datagram, whether or not there's anything to send: queued lines, a piece of a room
// frame, or a "nop". Nothing goes to a connected peer outside its slots, so the timing and amount
// of traffic says nothing about what was said.
#define COVER_INTERVAL 1.5
#define COVER_MAX_RATE 8.0

// Relays rate limit, and every member receives every event, so slots to a peer reached through
// them are further apart, and further still with more such peers.
#define NOSTR_COVER_INTERVAL 5.0
#define NOSTR_MAX_RATE 0.33
// Fast transfers can't burst through the relays. Instead, slots for a transfer we're sending come
// as often as the relays allow: at most NOSTR_FAST_RATE a second for all relayed peers together (a
// relay takes 0.5 events a second from a connection), and never closer than NOSTR_FAST_INTERVAL.
#define NOSTR_FAST_RATE 0.4
#define NOSTR_FAST_INTERVAL 2.5
// A peer's UDP path counts as broken after this long without a frame, and its traffic moves to the relays.
#define UDP_STALE 25.0
// With the relays on fallback, they're only connected while something needs them: nobody reached
// yet, a peer only reachable through them, or a peer whose own path has gone quiet. They're
// disconnected this long after.
#define RELAY_LINGER 60.0
#define NOSTR_BEACON_ALONE 20.0
#define NOSTR_BEACON_CONNECTED 90.0
// A joiner in Tor mode that hasn't reached anyone by then publishes the room's onion itself.
#define TOR_HOST_AFTER 120.0

// A chunk's bytes, base64'd into one record: "fd" FID OFFSET DATA.
#define FILE_CHUNK 690
#define FILE_WINDOW 64
#define FILE_FAST_INTERVAL 0.005

#define FILE_RETRIES 8
// A fetch waits up to this long for its sender to come back (a Tor circuit or a relay can stall a
// peer), and continues from where it was if they do.
#define FILE_OWNER_GRACE 120.0
// One of ours counts as being fetched by a peer until it has gone this long without asking for
// more, since its requests come a window at a time.
#define FILE_SENDING_QUIET 30.0

// A message's id: random, as hex.
#define MID_LEN 4
#define MID_HEX (2 * MID_LEN)

// The addresses the most datagrams came from, for the network log.
#define NET_SOURCES 6

typedef struct {
    unsigned rx;
    unsigned rx_chunks, rx_chunk_done;
    unsigned room_ok;
    unsigned hi, ck, hi2, hi2_bad, kx, lan;
    unsigned session_ok;
    unsigned dht;      // DHT messages on the room's port, apart from what can't be read at all (other)
    unsigned other;
    unsigned connects;
    addr_t src[NET_SOURCES];
    unsigned src_n[NET_SOURCES];
    int n_src;
} net_stats_t;

typedef struct {
    int used;
    addr_t from;
    uint8_t id[CHUNK_ID_LEN];
    int count;
    unsigned got;
    size_t total;   // the whole frame's length, as each piece says it
    double born;
    uint8_t buf[CHUNK_MAX * CHUNK_PAYLOAD];
} reasm_t;

// The user's comparison of a peer's verify code (peer_t.code_ok).
enum { CODE_DIFFERENT = -1, CODE_NOT_COMPARED = 0, CODE_SAME = 1 };
// Its signing key against the verified keys (peer_t.trust).
enum { TRUST_UNKNOWN = 0, TRUST_KEY = 1, TRUST_OTHER_KEY = 2 };

struct peer_s {
    int used;
    uint8_t id[ID_LEN];
    char nick[MAX_NICK + 1];
    char nick_skel[NICK_SKEL_LEN];
    addr_t addr;
    // The address before addr. Frames from a peer that just moved, or that come over two Tor streams
    // at once, keep arriving there too.
    addr_t prev_addr;
    double seen, born, next_hello;
    int hello_tries;
    int ok;
    // The join is announced once "k" has brought the nick and identity (k_seen), and in a room we
    // moved to, "mp" too, or JOIN_WAIT after the first frame opened (ok_since) if they never come,
    // so nobody joins unannounced.
    double ok_since;
    int k_seen, announced;
    // Our own k is sent to a new peer K_SENDS times, a little apart, since nothing acks it and the
    // first can be lost.
    int k_sent;
    double next_k;
    // Consecutive slots used for records while one of its room frames was waiting.
    int room_waited;
    uint8_t pub[PUB_LEN];
    ratchet_t send_chain;
    ratchet_t recv_chain;
    uint8_t vfy[VERIFY_LEN];
    uint8_t color[3];
    int persists;
    // Its "k" has "t": it keeps to message timers, and asks for timer seconds (0: none).
    int can_timer;
    unsigned timer;
    identity_source_t identity_source;
    verify_state_t identity_state;
    uint8_t identity_pub[ID_SIGN_PUB_LEN];
    uint8_t identity_fp[ID_FP_LEN];

    char build_version[MAX_VERSION + 1];
    build_state_t build_state;
    int build_warn;   // a MODIFIED verdict to tell once the join is announced

    // When a frame last came over each kind of path (by addr_kind_t), and (Tor) the onion
    // address the peer said it has.
    double path_seen[ADDR_KINDS];
    char onion[TOR_ADDR_LEN + 1];

    uint8_t prk_partial[PRK_LEN];
    uint8_t kem_ct[KEM_CT_LEN];

    uint32_t keygen;
    double next_cover;
    int vfy_set;
    // Set once a frame opens on the current recv_chain. Until then a replayed kx can't lock in bad chains.
    int chain_confirmed;
    // Responder only: kem_ct holds a kx that arrived before its re-handshake, for do_hello to use.
    int kx_early;

    // The peer's k says it announces each new key over the current session ("rk") before it
    // rekeys. For such a peer, a re-handshake with a key it never announced is refused.
    int announces_rekey;
    uint8_t next_pub[PUB_LEN];
    int next_pub_set;
    double rk_refused_since, next_rk_warn;
    double next_rk;   // when to re-send our own rk until the peer re-handshakes with our new key
    double next_rehello;   // when a hi may go to it again (keepalive, or a re-handshake stuck)
    // Its k says it reads several records in one frame, joined by newlines ("b").
    int batches;
    // Its k says it reads a message up to MAX_TEXT long ("l"), not just OLD_MAX_TEXT.
    int long_text;
    // Its k says it can move to a new room with us ("m"), and reads direct messages ("p").
    int can_move, can_pm, can_reply;
    // Its k says it reads "off" ("o"), so it can be told we went offline rather than that we left.
    int can_offline;
    // :move, in the room being left. move_pub: the key it showed us for the move ("mv" or "mk"), and
    // whether the room we moved to has it (move_passed). move_with: it moves with us, so this room
    // waits for its key before closing. key_sent: it has ours.
    uint8_t move_pub[ID_SIGN_PUB_LEN];
    int move_pub_set, move_passed, move_with, key_sent;
    // In the room moved to: its last "mp", kept until a key it can be checked with arrives, and which
    // of those it matched (came_with, plus one).
    uint8_t move_sig[ID_SIGN_LEN];
    int move_sig_set, came_with;

    // The result of the user comparing the verify code with this peer over another channel: 0 not
    // yet, 1 the same, -1 different. When comparing is required, only 1 gets what's sent.
    int code_ok;
    // Its signing key against the verified keys (core/trust.h): 0 no entry has its nick or key, 1 its
    // key is one of them, 2 an entry has its nick but another key (warned once).
    int trust;

    ratchet_t old_send, old_recv;
    double old_until;
    // The keys "k" and "mp" sign: ours of this session (c->keys moves on at our rekey, before p has
    // re-handshaken), and both of the session before, which a record signed before the re-handshake
    // can still arrive under.
    uint8_t my_pub[PUB_LEN], prev_pub[PUB_LEN], prev_my_pub[PUB_LEN];
    int prev_set;

    // Chunks of one of our files this peer asked for, sent in slots that would carry a nop, and when
    // it last asked or was sent one.
    int serving;
    uint8_t serve_fid[FILE_ID_LEN];
    uint64_t serve_next, serve_end;
    double serve_at;
};

// A record waiting for its peer's next slot. old_chain: sealed on the chain the peer still reads
// from before our rekey (an "rk" re-sent during the overlap).
#define SENDQ_MAX 128
typedef struct {
    int used;
    int peer_slot;
    uint32_t seq;
    int old_chain;
    char text[RECORD_MAX + 1];
} sendq_t;

// A room frame for a connected peer (a re-handshake's hi, ck, hi2 or kx), sent in its slots: over
// UDP one piece per slot, over the relays or Tor as a whole.
#define ROOMQ_MAX 24

typedef struct {
    int used;
    int peer_slot;
    uint32_t seq;
    addr_t to;
    uint8_t id[CHUNK_ID_LEN];
    int next_piece, pieces;
    size_t len;
    uint8_t frame[ROOM_FRAME_MAX];
} roomq_t;

typedef struct {
    int used;
    addr_t addr;
    int tries;
    double next_try;
} cand_t;

// The message ids seen lately, so a message forwarded by more than one peer is shown once.
#define SEEN_MIDS 2048
// Peers that dropped whose verify codes are remembered.
#define GONE_MAX 16
// Members ignored in a session, the oldest forgotten past this.
#define IGNORED_MAX 64

// "m\t" MID "\t" ORIGIN "\t" NICK "\t" TEXT, with room to spare.
#define MSG_LINE_LEN (16 + ID_LEN * 2 + MAX_NICK + MAX_TEXT + 16)

// A message waiting for its ack. It keeps the text, not the sealed frame. Each retry is sealed
// again on the peer's current chain, since the peer can't open an old index once any later frame
// (a cover nop, for example) has reached it.
typedef struct {
    int used;
    char mid[MID_HEX + 1];
    int peer_slot;
    char text[MSG_LINE_LEN];
    int tries;
    double next_retry;
    unsigned own;   // the number of our message it carries (chat_t's own_seq), or 0
} pending_msg_t;

// The room's recent messages, ours too, for :reply to pick one and a reply to quote: its id, who
// sent it, and the start of it. Direct messages aren't kept, so a reply in the room can't quote one.
#define RECENT_MAX 64
#define QUOTE_MAX 80
typedef struct {
    int used;
    char mid[MID_HEX + 1];
    uint8_t origin[ID_LEN];
    char nick[MAX_NICK + 1];
    char quote[QUOTE_MAX + 4];
    double at;
} recent_msg_t;

// The peers asked along, as "mv" lists them: the start of each one's id, comma-separated.
#define MOVE_COMING_LEN (MAX_PEERS * (SHORT_ID_HEX + 1) + 1)

// A request to move that came: who from (their name too, for once they've gone), and where to. asked:
// it's shown, since the sender's code was compared. told: we said to compare codes first.
typedef struct {
    int used, asked, told;
    uint8_t from[ID_LEN];
    char name[CHAT_NAME_LEN];
    char at[HHMM_LEN];
    char session_name[MAX_SESSION_NAME + 1];
    char password[MAX_PASSWORD + 1];
    char coming[MOVE_COMING_LEN];
} move_req_t;

struct chat_s {
    char nick[MAX_NICK + 1];
    char nick_skel[NICK_SKEL_LEN];
    char session_name[MAX_SESSION_NAME + 1];
    uint8_t my_id[ID_LEN];

    keypair_t keys;
    kem_keypair_t kem_keys;
    uint8_t master[MASTER_LEN];
    uint8_t room_key[ROOM_KEY_LEN];
    uint8_t udp_key[UDP_KEY_LEN];
    uint8_t cookie_secret[COOKIE_SECRET_LEN];
    int created;
    uint8_t my_color[3];

    identity_source_t identity_source;
    identity_keypair_t identity;

    // :move. move_key: the key shown to those moving with us; moved_key: the one shown in the room we
    // moved here from (moved), which signs our "mp" here. move_req: a request to move that came.
    // move_staged: where --simple's ":move yes" goes, until it's opened.
    identity_keypair_t move_key, moved_key;
    int move_key_set, moved;
    move_req_t move_req;
    chat_move_to_t move_staged;
    int move_staged_set;

    // We keep a history of this session, which our "k" tells peers.
    int persist;
    // Our message timer (chat_set_timer), which our "k" tells peers too.
    unsigned timer;

    notify_mode_t notify_mode;
    notify_preview_t notify_preview;

    chat_build_t build;
    int has_release_key, has_backup_key;
    uint8_t release_key[MINISIGN_KEY_LEN], backup_key[MINISIGN_KEY_LEN];

    int once, once_used;

    // The console's network lines (chat_set_net_log): every handshake packet too, or none but problems.
    int net_verbose, net_quiet;

    // Nothing that's sent goes to a peer until the user has compared its verify code (code_ok).
    int verify_required;

    sock_t sock, lan_sock;
    uint16_t port, lan_port;

    routing_t route;
    int started;
    const char *start_error;   // why it didn't start, when it didn't
    nostr_t *nostr;
    double relays_until;   // the relays stay on until then (fallback)
    tor_t *tor;
    portmap_t *pm;
    double next_beacon;
    int tor_hosting;
    double tor_republish_at;
    char told_onion[TOR_ADDR_LEN + 1];

    peer_t peers[MAX_PEERS + MAX_PENDING_PEERS];
    int peer_hi;
    cand_t cands[MAX_CANDS];
    addr_t static_peers[MAX_STATIC_PEERS];
    int n_static;
    pending_msg_t pending[MAX_PENDING_MSGS];
    recent_msg_t recent[RECENT_MAX];
    int recent_next;
    // While a reply's line is printed: how much of its text, from the start, is the quote.
    int line_quote;
    sendq_t sendq[SENDQ_MAX];
    roomq_t roomq[ROOMQ_MAX];
    uint32_t queue_seq;
    addr_t self_addrs[MAX_SELF_ADDRS];
    int n_self_addrs;

    int dht_on;
    dht_state_t dht;

    double start, next_alive, next_lan;
    // The time the caller gave with its latest call (chat_tick and the like), for what isn't given one,
    // such as commands: a session keeps to its caller's clock.
    double now;
    uint32_t keygen;
    double next_rekey;
    double rekey_due;

    int warned_lonely, ever_connected, dht_summary_printed;

    uint32_t seen_mids[SEEN_MIDS];
    int seen_head, seen_count;

    // Verify codes of peers that dropped. A peer that comes back gets a new one, and chat says so.
    struct { int used; uint8_t id[ID_LEN]; uint8_t vfy[VERIFY_LEN]; } gone[GONE_MAX];
    int gone_head;

    // Members ignored here (:ignore), by id, so what others pass on from them is hidden too.
    uint8_t ignored[IGNORED_MAX][ID_LEN];
    int n_ignored;

    // Token buckets for: hellos to candidates, which come unchecked from the DHT and other peers;
    // cookie challenges; and session frames tried against every peer (see CK_RATE, ROAM_RATE).
    double probe_tokens, probe_at;
    double ck_tokens, ck_at;
    double roam_tokens, roam_at;

    char my_idhex[ID_LEN * 2 + 1];
    char hi_msg[HANDSHAKE_BUF_LEN];

    reasm_t reasm[REASM_SLOTS];
    net_stats_t st;

    file_entry_t files[FILE_OFFERS_MAX];
    int file_seq;
    uint64_t file_cap;      // offers bigger than this need "anyway" to fetch
    int fast_files;         // our slots speed up while a transfer runs
    int picture_noise;      // a JPEG offered gets noise nobody can see (common/image/clean.h)
    chat_file_fn file_view;
    unsigned own_seq;
    chat_delivery_fn delivery;
    // The session is kept to come back to (Reopen sessions), so chat_shutdown tells the peers that read
    // "off" that we went offline, not that we left.
    int coming_back;

    // Moving out (:move): the session we moved to, which is given the keys that come after, and since
    // when this one has only stayed for them. move_ask: the request that's shown.
    struct chat_s *move_to;
    int move_leaving;
    double move_since;
    chat_move_ask_t move_ask;
    // Keys shown to us in the room we moved here from, by peers whose codes we compared there, with their
    // nick there. A peer here that signs its session with one ("mp") counts as compared.
    struct { int used; uint8_t pub[ID_SIGN_PUB_LEN]; char nick[MAX_NICK + 1]; } came_with[MAX_PEERS];

    chat_print_fn print;
    chat_notify_fn notify;
    void *ui;
};

#endif
