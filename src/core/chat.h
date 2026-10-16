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
#include "core/files.h"
#include "common/util.h"
#include <stdint.h>
#include <stdio.h>

#define MAX_PEERS 50
#define MAX_PENDING_PEERS 64
#define MAX_CANDS 64
#define MAX_PENDING_MSGS 128
#define MAX_NICK 24
#define MAX_TEXT 880
// What a peer without "l" in its "k" reads of a message: older versions cut a longer one off there,
// so it goes to them in parts, each a message of its own, at most MAX_TEXT_PARTS of them.
#define OLD_MAX_TEXT 250
#define MAX_TEXT_PARTS 8
#define MAX_SESSION_NAME 64
// A new session's id: this many characters from random_session_id.
#define SESSION_ID_LEN 10
#define MAX_PASSWORD 255
#define MAX_STATIC_PEERS 16
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

// ---- files ----
//
// A file is offered to the connected peers ("fo"). Nothing else is sent until someone decides to
// fetch it. They then ask for a window of chunks at a time ("fg") and the sender sends them in
// the slots that would otherwise carry a nop ("fd"), so a transfer looks the same as normal
// traffic. Through the relays it's two per slot. With fast transfers on, a peer's slots come much
// closer together during a transfer: faster, but visible as a burst (through the relays, only as
// close as they allow). Each chunk goes in its place in the window, and a run of missing chunks is
// requested again. A complete window is written in order and hashed, and the file is only kept if
// the hash matches the offer.
#define FILE_HARD_MAX (1024ull * 1024 * 1024)
#define FILE_CAP_DEFAULT (8ull * 1024 * 1024)
#define FILE_OFFERS_MAX 64
#define FILE_ID_LEN 8
// A chunk's bytes, base64'd into one record: "fd" FID OFFSET DATA.
#define FILE_CHUNK 690
#define FILE_WINDOW 64
#define FILE_FAST_INTERVAL 0.005
// A file fetched to be shown rather than saved is held in memory, up to this size.
#define FILE_VIEW_MAX (64u * 1024 * 1024)
// Pictures that were shown stay in memory, up to this much in all (the oldest are dropped first), so
// :show and :download use them instead of fetching them again.
#define FILE_CACHE_MAX (128u * 1024 * 1024)
#define FILE_RETRIES 8
// A fetch waits up to this long for its sender to come back (a Tor circuit or a relay can stall a
// peer), and continues from where it was if they do.
#define FILE_OWNER_GRACE 120.0
// One of ours counts as being fetched by a peer until it has gone this long without asking for
// more, since its requests come a window at a time.
#define FILE_SENDING_QUIET 30.0
// The peers one of ours went to in full that are named, beyond those it's only counted.
#define FILE_SENT_MAX 4
// A folder a file is saved in, where it was saved, and the hidden file it's written to until then.
#define FILE_DIR_MAX 600
#define FILE_SAVED_MAX 800
#define FILE_PART_MAX 640
// The highest file number a command takes.
#define FILE_NUM_MAX 1000000

// A peer's nick as shown (chat_peer_name), with "#" and the start of its id if another looks the same.
#define SHORT_ID_LEN 4
#define SHORT_ID_HEX (2 * SHORT_ID_LEN)
#define CHAT_NAME_LEN (MAX_NICK + 2 + SHORT_ID_HEX)

// A message's id: random, as hex.
#define MID_LEN 4
#define MID_HEX (2 * MID_LEN)

typedef enum { ROUTE_UDP = 0, ROUTE_TOR = 1 } route_mode_t;

// The relays, the same in both routes: off, only while something needs them, or always.
enum { NOSTR_OFF = 0, NOSTR_FALLBACK = 1, NOSTR_ALWAYS = 2 };

// How a session reaches peers. UDP: straight between peers, found through the DHT (IPv4, IPv6),
// LAN broadcast and relays, with a router port mapping so more of them can connect. Tor: onion
// services. Either way, Nostr relays carry traffic when the route can't, through Tor in Tor
// routing. Nothing else goes on the network.
typedef struct {
    route_mode_t mode;
    int dht4, dht6, lan, portmap, nostr;
    char relays[NOSTR_MAX_RELAYS][NOSTR_URL_MAX];
    int n_relays;
    tor_opts_t tor;
} routing_t;

void routing_defaults(routing_t *r);
const char *routing_mode_name(route_mode_t m);

// The addresses the most datagrams came from, for the network log.
#define NET_SOURCES 6

typedef struct {
    unsigned rx;
    unsigned rx_chunks, rx_chunk_done;
    unsigned room_ok;
    unsigned hi, ck, hi2, hi2_bad, kx, lan;
    unsigned session_ok;
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

typedef enum { NOTIFY_NONE = 0, NOTIFY_MENTIONS = 1, NOTIFY_ALL = 2 } notify_mode_t;
// What a desktop notification shows: only that a message came in (the default), who it's from, or
// who and what it says. Never the session, since its id is all someone needs to join one with a
// blank password, and desktops keep notifications.
typedef enum { PREVIEW_OFF = 0, PREVIEW_NICK = 1, PREVIEW_MESSAGE = 2 } notify_preview_t;
typedef enum { IDENT_NONE = 0, IDENT_NATIVE = 1, IDENT_AGE = 2, IDENT_PGP = 3 } identity_source_t;

typedef enum { VERIFY_UNVERIFIED = 0, VERIFY_VERIFIED = 1, VERIFY_FAILED = 2 } verify_state_t;

// The user's comparison of a peer's verify code (peer_t.code_ok).
enum { CODE_DIFFERENT = -1, CODE_NOT_COMPARED = 0, CODE_SAME = 1 };
// Its signing key against the verified keys (peer_t.trust).
enum { TRUST_UNKNOWN = 0, TRUST_KEY = 1, TRUST_OTHER_KEY = 2 };
// A peer's verify code as the sidebar shows it (chat_code_state).
enum { CODE_NOTHING = 0, CODE_TO_COMPARE = 1, CODE_COMPARED = 2, CODE_DIFFERS = 3, CODE_KEY_CHANGED = 4 };

// What a peer's "v" says about the build it runs. A peer can lie about its hash, so OFFICIAL is
// only its claim. MODIFIED is a build that doesn't claim to be from a release.
typedef enum {
    BUILD_UNKNOWN = 0,   // it sent none: a build from before "v"
    BUILD_UNCHECKED,     // this build has no release key to check it with
    BUILD_OFFICIAL,
    BUILD_MODIFIED       // not a binary of the release it names, or with no signed list of it
} build_state_t;

#define MAX_VERSION 15

// A release binary ends with a list of that release's binaries (the SHA-256 of each, without the
// list), signed with the release key. `just release` appends it. A build sends peers its own list
// in "v", so they can check it without asking anyone else. Three hashes keep "v" inside one
// normal sized session frame.
#define BUILD_LIST_MAX 3
#define BUILD_LIST_LEN (BUILD_LIST_MAX * (BUILD_HASH_LEN * 2 + 1))

// This program's build, as reported to peers.
typedef struct {
    int ok;   // 0 if the executable couldn't be read: nothing is sent
    char version[MAX_VERSION + 1];
    uint8_t hash[BUILD_HASH_LEN];
    char list[BUILD_LIST_LEN + 1];              // the list's hashes, hex, comma-separated; "" if none
    char list_sig[MINISIGN_SIG_B64_LEN + 1];    // the list's signature line
} chat_build_t;

// A nick with lookalike characters, case and invisible characters normalised away.
#define NICK_SKEL_LEN (4 * MAX_NICK + 1)

typedef struct {
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
    // The join is announced once "k" has brought the nick and identity (k_seen), or JOIN_WAIT
    // after the first frame opened (ok_since) if it never does, so nobody joins unannounced.
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
} peer_t;

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
// DL_QUEUED: asked for while another file from the same sender is coming. It starts after that one.
typedef enum { DL_NONE = 0, DL_ACTIVE, DL_DONE, DL_FAILED, DL_QUEUED } dl_state_t;

typedef struct {
    int used;
    int num;                     // what it's called in commands: :download NUM
    int mine;
    uint8_t owner[ID_LEN];       // who offered it
    uint8_t fid[FILE_ID_LEN];
    uint64_t size;
    uint8_t sha[SHA256_LEN];
    char name[FILE_NAME_MAX + 1];
    int image;                   // offered as a PNG, JPEG or GIF (only decoding it says it is one)
    FILE *fp;                    // ours: open for its chunks, so the file offered is the one sent
    uint8_t *clean;              // ours, cleaned (common/clean.h): the bytes offered, from memory in fp's place

    dl_state_t dl;
    int view;                    // fetched to show (into mem), not to save (to out)
    int also_show, also_save;    // asked for the other way while on its way: shown or saved too once it's here
    char save_dir[FILE_DIR_MAX]; // the folder to save it in, "" for Downloads
    char saved[FILE_SAVED_MAX];  // where it was last saved, "" if it wasn't
    uint8_t *cache;              // a picture shown here: its bytes, checked against sha, for :show and :download
    FILE *out;
    char part_path[FILE_PART_MAX];
    uint8_t *mem;
    uint64_t done;               // bytes in order, written and hashed
    sha256_ctx_t hash;
    uint64_t win_off;            // the window asked for: win_n chunks from win_off
    int win_n;
    uint64_t win_got;            // which of them have come
    int req_end;                 // the chunk after the run of the window last asked for
    uint8_t *win;
    double retry_at;
    int retries;
    double since;                // when the fetch started
    double gone_since;           // when its sender left, while it's away
    char at[HHMM_LEN];           // when it was offered, HH:MM
    char why[64];                // why the last fetch failed
    // Ours: who it went to in full.
    int n_sent;
    uint8_t sent_id[FILE_SENT_MAX][ID_LEN];
    char sent_name[FILE_SENT_MAX][CHAT_NAME_LEN];
} file_entry_t;

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

// file: the number of the file a line offers (an image can be shown under it), else 0.
typedef void (*chat_print_fn)(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                              unsigned flags, int color_len, int file);

#define LINE_CHAT 1u
#define LINE_MENTION 2u
// A warning the user must see, such as a verified peer's key changing: shown in the chat as well
// as the console.
#define LINE_WARN 4u
// A message of ours, numbered chat_t's own_seq as it's printed, for chat_delivery_fn.
#define LINE_OWN 8u

// What became of a message of ours: a peer it went to never acked it (name says who), or there's
// nothing left to hear about it. Settled with nobody missed, every peer it went to has it. Copies
// passed on by others aren't acked back, so that's the peers we're connected to.
typedef enum { CHAT_MISSED, CHAT_SETTLED } chat_delivery_t;
typedef void (*chat_delivery_fn)(void *ui, unsigned own, chat_delivery_t what, const char *name);

// A file fetched to be shown has arrived, complete and matching the offer. Its bytes are only
// valid during the call.
typedef void (*chat_file_fn)(void *ui, int num, const char *name, const uint8_t *data, size_t len);

// A message that should get a notification. nick and text are NULL unless the session's
// notify_preview allows the notification to show them.
typedef void (*chat_notify_fn)(void *ui, const char *nick, const char *text, int mentioned);

// ---- moving the room (:move) ----
//
// With no server, nobody can be put out of a room, and a password that leaked can't be changed. :move
// instead takes the peers whose verify codes were compared, and whose builds can move, to a new room
// with an id and password made up on the spot, and leaves everyone else in this one. Each of them is
// sent the new room over its session ("mv"), and asked whether to go. Everyone moving shows the others
// a key of its own for the move, over the sessions here ("mk", or in "mv"), and signs its sessions in
// the new room with it ("mp"), so codes compared here count there.

// The longest the room being left stays open, waiting for the keys of those moving with us.
#define MOVE_LINGER 90.0
// The new room's password: this many random bytes, as words.
#define MOVE_PASSWORD_BYTES 8
// How many names a list of peers spells out before it counts the rest.
#define MOVE_NAMED 6
#define MOVE_NAME_LEN (CHAT_NAME_LEN + 32)
#define MOVE_NAMES_LEN (MOVE_NAMED * (MOVE_NAME_LEN + 5) + 32)
// The peers asked along, as "mv" lists them: the start of each one's id, comma-separated.
#define MOVE_COMING_LEN (MAX_PEERS * (SHORT_ID_HEX + 1) + 1)

// Who :move would take along, and who it would leave behind (with why).
typedef struct {
    int coming, left;
    char coming_names[MOVE_NAMES_LEN], left_names[MOVE_NAMES_LEN];
} chat_move_plan_t;

// Where a move goes, to open the new session with: its id and password, the room it's from, and the
// key shown there, which signs our sessions in the new one. created: we're the one moving the room.
typedef struct {
    char session_name[MAX_SESSION_NAME + 1];
    char password[MAX_PASSWORD + 1];
    char from[MAX_SESSION_NAME + 1];
    identity_keypair_t key;
    int created;
} chat_move_to_t;

// A request to move, as it's shown: who asks (with their code's mark), who else is asked along, and
// when it came. seq is new for each request.
typedef struct {
    unsigned seq;
    char from[MOVE_NAME_LEN];
    char coming_names[MOVE_NAMES_LEN];
    int coming;
    char at[HHMM_LEN];
} chat_move_ask_t;

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

typedef struct chat_s {
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
    int picture_noise;      // a JPEG offered gets noise nobody can see (common/clean.h)
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
} chat_t;

typedef struct {
    char nick[MAX_NICK + 1];
    char session_name[MAX_SESSION_NAME + 1];
    char password[MAX_PASSWORD + 1];
    uint16_t port;
    addr_t peers[MAX_STATIC_PEERS];
    int n_peers;
    routing_t route;
    int created;
    int once;
    notify_mode_t notify_mode;
    notify_preview_t notify_preview;
    // Send to peers whose verify code wasn't compared (the default is not to).
    int verify_optional;
    int persist;   // keeps a history (chat_set_history)

    identity_source_t identity_source;
    identity_keypair_t identity;
    int has_color;
    uint8_t color[3];

    uint64_t file_cap;      // 0: FILE_CAP_DEFAULT
    int fast_files, picture_noise;

    // What peers are told about this build, and the release key (minisign, base64) used to check
    // their builds' lists, and its backup. "" leaves them unchecked.
    chat_build_t build;
    char release_key[64];
    char release_backup_key[64];

    // The session moved here from another room (:move), and moved_key signs our sessions here.
    int moved;
    identity_keypair_t moved_key;
} chat_opts_t;

void chat_init(chat_t *c, const chat_opts_t *o, chat_print_fn print, chat_notify_fn notify, void *ui, double now);
void chat_shutdown(chat_t *c);

void chat_tick(chat_t *c, double now);
void chat_on_socket_readable(chat_t *c, sock_t which, double now);

// Plain-mode entry point: ":name args" runs a command, anything else is sent. Returns 0 on :quit.
int chat_submit_line(chat_t *c, const char *line, double now);

// Runs "name args" (no leading ':') from CHAT_COMMANDS against this session.
cmd_result_t chat_run_command(chat_t *c, const char *line);
void chat_send_text(chat_t *c, const char *text, double now);
// Offers the file at path (used as is: ~ and quotes aren't expanded) to everyone here, like :send.
// A picture offered is cleaned first (common/clean.h), unless asis.
void chat_send_file(chat_t *c, const char *path, int asis);

extern const command_t CHAT_COMMANDS[];

void chat_set_nick(chat_t *c, const char *nick);

// Files. chat_file_fetch gets file num, either to show (view, passed to c->file_view once it's
// here) or to save in dir (NULL or "" for Downloads). A picture already shown, or a file already
// saved, is used instead of fetching it again if it still matches the offer. While another file
// from the same sender is coming, it's queued and starts after that one. anyway: fetch even if
// over the size limit. Returns 0, or -1 after saying why.
int chat_file_fetch(chat_t *c, int num, int view, int anyway, const char *dir);
const file_entry_t *chat_file(const chat_t *c, int num);
// A queued file: the number of the file from the same sender it waits for, or 0.
int chat_file_queued_after(const chat_t *c, const file_entry_t *e);
// A file being fetched: the bytes received, including any in the window not written yet, and
// roughly how many seconds the rest will take, at the rate so far or, before there is one, at the
// rate its path allows. ETA_AWAY while its sender is away, ETA_UNVERIFIED while their verify code
// needs comparing again (they came back with a new one).
#define ETA_AWAY (-1.0)
#define ETA_UNVERIFIED (-2.0)
uint64_t chat_file_got(const file_entry_t *e);
double chat_file_eta(const chat_t *c, const file_entry_t *e, double now);
// A picture's bytes, checked against its offer: kept from when it was shown, a saved copy, or ours.
// NULL if there's none here. Only valid until the next call into the session.
const uint8_t *chat_file_bytes(chat_t *c, int num);
// One of ours: how many peers are fetching it now, the one furthest along (into name) and how far
// they've got, in thousandths.
int chat_file_sending(const chat_t *c, const file_entry_t *e, double now, char name[CHAT_NAME_LEN], int *permille);
// Who one of ours went to in full: "bob", "bob and carol", "bob and 2 others", or "".
void chat_file_sent_to(const file_entry_t *e, char *out, size_t cap);
void chat_set_file_options(chat_t *c, uint64_t cap, int fast);
// The size over which a file needs "anyway" to be fetched.
uint64_t chat_file_cap(const chat_t *c);
void chat_set_colour(chat_t *c, const uint8_t rgb[3]);

// Cleans a nick and removes the characters the UI puts around nicks ("(verified)", "#id", "name:"),
// including lookalikes such as fullwidth brackets, and invisible characters, so no nick can fake
// them. Never empty: uses "anon" if nothing is left.
void chat_clean_nick(const char *in, char out[MAX_NICK + 1]);
// A nick normalised for comparing (lookalikes, case and invisible characters ignored), as used to
// tell nicks apart. out holds NICK_SKEL_LEN.
void chat_nick_skeleton(const char *nick, char *out, size_t cap);

// A peer's nick as shown, with "#" and its id prefix added when another peer's nick, or ours,
// looks the same (case and common lookalike letters ignored).
void chat_peer_name(const chat_t *c, const peer_t *p, char out[CHAT_NAME_LEN]);

void chat_set_identity(chat_t *c, identity_source_t source, const identity_keypair_t *idkp);

// Whether we keep a history of the session: peers' "k" is sent again so they're told straight away.
void chat_set_history(chat_t *c, int on);

// How much of the network the console shows, as :set net names it: its news, every handshake packet
// too, or only its problems.
enum { NET_LOG_NORMAL = 0, NET_LOG_VERBOSE, NET_LOG_OFF };
void chat_set_net_log(chat_t *c, int level);

// The message timer (:timer): messages older than this go from the screen and from memory, and a
// history keeps no longer. Ours goes to peers in "k", like history, and every chat that keeps to
// timers ("t") keeps to the shortest anyone in the session asks for. It's a request: a modified chat,
// or a screenshot, can keep anything. In seconds, 0 for none.
#define TIMER_MIN 60u
#define TIMER_MAX (7u * 24 * 3600)
void chat_set_timer(chat_t *c, unsigned seconds);
// The one kept to, and who asked for it ("you", or a peer's name) in who if it's given.
unsigned chat_timer(const chat_t *c, char *who, size_t cap);
// "10m", "2h", "1d" or "90s" for seconds, and back (0, or -1 for something else).
void chat_format_timer(unsigned seconds, char *out, size_t cap);
int chat_parse_timer(const char *s, unsigned *seconds);
// What names the session's history: from its key, the same each time it's joined with the same id
// and password, and nothing anyone else can work out.
#define CHAT_HISTORY_ID_LEN 16
void chat_history_id(const chat_t *c, uint8_t out[CHAT_HISTORY_ID_LEN]);

// A call (:call): the room only this identity and a verified key can work out, for a day (UTC days
// since 1970, chat_contact_day), as its id and password. 0, or -1 if that key can't make one.
#define CONTACT_PASSWORD_LEN 64
#define DAY_SECONDS 86400
int chat_contact_room(const identity_keypair_t *mine, const uint8_t their_pub[ID_SIGN_PUB_LEN], uint64_t day,
                      char id[SESSION_ID_LEN + 1], char password[CONTACT_PASSWORD_LEN + 1]);
uint64_t chat_contact_day(void);

// Whether the member with this id is ignored here (:ignore): what it says, sends directly and offers
// isn't shown, though what it says is still passed on to others.
int chat_ignored(const chat_t *c, const uint8_t id[ID_LEN]);

// An invite (:invite): a room's id and password as one string, "chat:ID:PASSWORD:CHECK", CHECK being
// invite_check in hex. The password can hold ':', since the id ends at the first and the check
// starts after the last, but an id with ':' in it can't have one. chat_invite: 0, or -1 if the id
// can't go in one or it doesn't fit in cap (INVITE_MAX does).
#define INVITE_PREFIX "chat:"
#define INVITE_MAX (sizeof INVITE_PREFIX + MAX_SESSION_NAME + MAX_PASSWORD + INVITE_CHECK_LEN * 2 + 2)
int chat_invite(const char *id, const char *password, char *out, size_t cap);
// Whether text starts as an invite does, and chat_invite_parse takes it apart: 1 for an invite, with
// its id and password; 0 if text isn't one; -1 if it is, but it's mistyped or cut off, so its check
// doesn't match.
int chat_is_invite(const char *text);
int chat_invite_parse(const char *text, char id[MAX_SESSION_NAME + 1], char password[MAX_PASSWORD + 1]);

// :move. Who it would take along: peers whose code was compared, whose builds can move.
void chat_move_plan(chat_t *c, chat_move_plan_t *plan);
// The one moving the room: a new id and password into to. 0, or -1 after saying why (nobody can come).
int chat_move_begin(chat_t *c, chat_move_to_t *to);
// The request to move that's waiting for an answer, or NULL. One from a peer whose code wasn't compared
// waits for that first.
const chat_move_ask_t *chat_move_asked(const chat_t *c);
// The answer to it: yes fills to (0, or -1 if there's no request), no forgets it.
int chat_move_accept(chat_t *c, chat_move_to_t *to);
void chat_move_decline(chat_t *c);
// Where --simple's ":move yes" goes, once: 1, with to filled.
int chat_move_staged(chat_t *c, chat_move_to_t *to);
// The new session opened (moved_to): the one moving the room now asks those coming. This session gives
// moved_to the keys it's shown, now and as they come, and stays open only until chat_move_finished.
// moved_to has to outlive it, or be unlinked first.
void chat_move_go(chat_t *c, const chat_move_to_t *to, chat_t *moved_to, double now);
void chat_move_unlink(chat_t *c, const chat_t *moved_to);
// A session that moved out has done its part: those moving with us have our key and we theirs, or
// MOVE_LINGER has passed. It can be closed.
int chat_move_finished(const chat_t *c, double now);

#define CHAT_MAX_SOCKS 12
int chat_sockets(chat_t *c, sock_t out[CHAT_MAX_SOCKS]);
// Whether the session started: its keys were made, and its UDP socket (DHT) or its Tor link (Tor)
// opened. If not, chat_start_error says why.
int chat_started(const chat_t *c);
const char *chat_start_error(const chat_t *c);
// Applies changed routing toggles to a running session. The mode and the Tor settings only apply
// to sessions opened afterwards. Returns 1 if those differ from this session's.
int chat_apply_routing(chat_t *c, const routing_t *r);
// Moves a Tor session to the tor at these ports (the one chat started, or found running). password
// is what chat's own tor takes; NULL for a running tor, which takes the session's torpassword.
void chat_tor_set_ports(chat_t *c, const char *socks, const char *control, const char *password);
// That tor has connected to the Tor network, so relays that failed while it was connecting are retried.
void chat_tor_connected(chat_t *c);
// New Tor circuits for the session, its relay connections' too, and a new onion address for its
// peers (tor_refresh).
void chat_tor_refresh(chat_t *c);
int chat_online_count(const chat_t *c);
int chat_pending_count(const chat_t *c);
int chat_candidate_count(const chat_t *c);

int chat_ready(const chat_t *c);
const char *chat_verify_label(verify_state_t s);
// A peer's verify code as the sidebar shows it: 0 nothing to do, 1 to be compared, 2 compared,
// 3 different, 4 to be compared because it signs with another key than the one verified for its nick.
int chat_code_state(const chat_t *c, const peer_t *p);
// What p runs, for :peers: "says official v0.3.1", "modified client (says v0.3.1)" and so on.
void chat_build_label(const peer_t *p, char *out, size_t cap);

typedef struct { const char *name; uint8_t r, g, b; } named_color_t;
extern const named_color_t COLOR_PALETTE[];
extern const int COLOR_PALETTE_N;
// One of the palette's, at random.
void chat_random_colour(uint8_t rgb[3]);

int parse_color(const char *text, uint8_t rgb[3]);

#endif
