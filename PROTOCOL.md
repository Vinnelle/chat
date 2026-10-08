# chat's wire protocol

This is what chat sends over the network as of 0.5.0. It's written for anyone reviewing chat's
design or checking what it puts on the wire. The code is the reference: where this document and
the code disagree, the document is wrong. The relevant code is in
[src/core/chat.c](src/core/chat.c), [src/crypto/crypto.c](src/crypto/crypto.c) and
[src/transport/](src/transport/). [SECURITY.md](SECURITY.md) describes what the protocol is meant
to protect against, and what it doesn't.

> Neither the protocol nor its implementation has been independently reviewed.

## Notation

- `H(k, x)` is BLAKE2b keyed with `k`, with a 32-byte output (libsodium's `crypto_generichash`).
  `H(k, x)[:n]` is the first `n` bytes of that output. That isn't the same as BLAKE2b with an
  `n`-byte output.
- `‖` joins byte strings. Labels in quotes are ASCII, with no terminating zero.
- `BE16`, `BE32` and `BE64` are big-endian integers of 2, 4 and 8 bytes.
- `AEAD(k, nonce, ad, plain)` is XChaCha20-Poly1305 (IETF), with a 24-byte nonce and a 16-byte
  tag. Every nonce is random.
- Hex is lowercase.
- A **record** is one line of ASCII fields separated by tabs. Its first field is its name, like
  `hi` or `m`.

## 1. Room keys

A session (a room) is a session id and a password. The password may be blank. Everyone with both
derives the same master key:

```
salt   = BLAKE2b("chat-kdf-v2" ‖ session id)       unkeyed, 16-byte output
master = Argon2id v1.3(password, salt, ops 4, 512 MiB) 32 bytes
```

Everything else the room shares comes from the master key:

| Name | Derivation | Used for |
| --- | --- | --- |
| room key | `H(master, "room")` | sealing room frames (§3.1) |
| DHT key | `H(master, "dht-key")` | the hourly lookup key (§4.1) |
| UDP key | `H(master, "udp-mask")` | masking every UDP datagram (§3.3) |
| LAN port | `49152 + BE16(H(master, "lan-port")[:2]) mod 16384` | the LAN beacon (§4.2) |
| Nostr tag key | `H(master, "nostr-tag")` | the event tag for each ten minutes (§4.3) |
| Nostr wrap key | `H(master, "nostr-wrap")` | sealing relay events (§4.3) |
| Tor room key *i* (0 ≤ *i* < 6) | an Ed25519 key from the seed `H(master, "tor" ‖ byte(i))` (SHA-512 of the seed, with the scalar half clamped) | the room's onion services (§4.4) |

Every member has all of these keys. They keep outsiders out, but they can't authenticate one
member to another.

## 2. A member's own keys

Each time chat joins a session, it makes these:

- an **id**: 16 random bytes, kept for the whole session. Members tell peers apart by their ids.
  An id isn't reused, so it doesn't link one session to the next.
- an **X25519** key pair and an **ML-KEM-768** key pair;
- a 32-byte **cookie secret**.

A rekey (§6) replaces the key pairs and the cookie secret, and keeps the id. None of these are
kept after the session ends.

## 3. Frames

Everything chat sends is a **frame**. Relays and Tor streams carry each frame whole. UDP carries a
frame as one or more 1004-byte cells.

### 3.1 Room frames

The handshake and the beacons are records sent to the room, sealed with the room key:

```
room frame = nonce(24) ‖ AEAD(room key, nonce, no ad, body)
body       = BE16(record length) ‖ record ‖ zeros
```

The zeros pad the body to a multiple of 64 bytes, and to at least 2560 bytes. Every room frame
chat sends is 2600 bytes. A receiver accepts a body that's a multiple of 64, from 2560 to 2624
bytes.

### 3.2 Session frames

Records between two members are sealed on that pair's chains (§5.3):

```
session frame = BE32(index) ‖ nonce(24) ‖ AEAD(message key(index), nonce, BE32(index), body)
```

The body is padded the same way as a room frame's.

- **Over UDP**, the body is always 960 bytes, so a session frame fills one 1004-byte cell.
- **Through the relays**, a peer that has `b` in its `k` record (§7) gets 2624-byte bodies, which
  hold as many records as fit. Other peers get 960-byte bodies.

A receiver accepts a body that's a multiple of 64, from 384 to 2624 bytes. The body holds one
record. For a peer with `b`, it can hold several, joined by `\n`.

A receiver tries each incoming frame in this order:

1. as a room frame;
2. on the chains of the peer at the frame's source address;
3. for a peer whose address changed, on every other peer's chains. These tries are limited to 50
   a second, and the chain may skip at most 16 frames ahead.

### 3.3 UDP

Every UDP datagram is exactly 1004 bytes, and is masked with the UDP key:

```
nonce        = d[len-16 : len] ‖ zeros(8)
d[0 : len-16] ^= XChaCha20(UDP key, nonce)
```

The last 16 bytes aren't masked, but they always look random. In a session frame they're the
Poly1305 tag. In a cell they're random padding or ciphertext. Without the UDP key, a datagram is
1004 random bytes, with no index, magic number or length showing.

A session frame goes as it is. A room frame is split into up to four cells:

```
cell = C5 7B ‖ frame id(4) ‖ piece index(1) ‖ piece count(1) ‖ BE16(frame length) ‖ piece(994)
```

- The frame id is random for each frame.
- The last piece is padded with random bytes.
- A 2600-byte room frame takes three cells.

After unmasking, a datagram that starts with `C5 7B` is a cell, and anything else is a session
frame. Pieces wait 30 seconds to be reassembled. To a connected peer, each cell takes one of that
peer's slots (§8), like everything else.

## 4. Finding each other

### 4.1 BitTorrent DHT

Each hour has its own lookup key:

```
epoch    = floor(unix time / 3600)
infohash = H(DHT key, "dht-epoch" ‖ BE64(epoch))[:20]
```

- chat sends `get_peers` and `announce_peer` for the infohash on the IPv4 DHT, and on the IPv6 DHT
  too (BEP 32).
- Near the change of hour, it also looks up and announces under the other hour's key.
- Every query sets `"ro": 1` (BEP 43). chat doesn't answer queries.
- Its node id is new every hour.

Each address a lookup returns becomes a candidate, and chat sends it a `hi` (§5.1).

### 4.2 LAN

Every 5 to 7 seconds, chat sends a room frame holding `lan ID PORT` to the LAN port (§1), on both
the local broadcast address and loopback. ID is its id in hex, and PORT is the session's UDP
port. The frame is masked and split like any other room frame. Another member that receives it
adds the sender's address, with that port, as a candidate. A `lan` record only counts when it
arrives over UDP.

### 4.3 Nostr relays

Each datagram for the relays becomes one event. It's sent to every relay that has a connection
for the current ten minutes:

```
tag   = hex(HMAC-SHA256(Nostr tag key, BE64(floor(unix time / 600))))
plain = sender id(16) ‖ recipient id(16) ‖ BE16(len) ‖ datagram ‖ random bytes   (2800 bytes)
wrap  = nonce(24) ‖ AEAD(Nostr wrap key, nonce, "chat nostr wrap v1", plain)
event = kind:       random, 20000-29999
        pubkey:     a new key for each event
        created_at: now, minus 0 to 29 seconds
        tags:       [["e", tag]]
        content:    base64(wrap)
```

- The recipient id is all zeros for a datagram to the whole room.
- Each event is signed (BIP-340) with a secp256k1 key made for that event and then thrown away.
- The kind is never one of the few ephemeral kinds that relays act on.
- The datagram is a whole frame, up to 2766 bytes, and isn't masked.

A connection subscribes to one tag only, with `["REQ", SUBID, {"#e": [tag], "since": now - 120}]`.
Each relay gets a new connection for every ten-minute period. It opens at a random time 60 to 120
seconds before the period starts (120 to 240 seconds through Tor), and closes as long after the
period ends.

A receiver drops an event if:

- its kind is out of range;
- its content doesn't unwrap;
- it has seen the same content before (this drops the relays' copies of its own events);
- it's addressed to another id.

chat doesn't check the event signatures. The wrap is what shows that an event came from a member.

On the relays, a peer's address is its id. A member announces itself by sending the whole room a
room frame holding `nb ID`, every 20 seconds while it's alone and every 90 once it's connected.
Members that don't already hear from it directly send it a `hi`.

### 4.4 Tor

Each session publishes its own onion service, with a new key every time, on port 7474. It also
publishes one of the room's six onion services, whose keys come from the room (§1):

- The member that created the session publishes slot 0.
- A member that joined publishes a slot where nobody answered. It does this once it has reached
  someone, or after 120 seconds if it hasn't.

Everyone keeps trying the slots they don't publish. From whoever answers, they learn the members'
own onion addresses (`ta` and `px`, §7) and connect to those. Frames go over Tor streams, each
after its BE16 length, and are at most 4096 bytes. They aren't masked, since Tor encrypts the
stream.

## 5. Handshake

### 5.1 Hello and cookie

These records go in room frames:

```
A → B   hi   ID PUB KEM
B → A   ck   ID COOKIE
A → B   hi2  ID PUB KEM COOKIE
```

- ID is A's id (32 hex digits).
- PUB is A's X25519 public key (64 hex digits).
- KEM is A's ML-KEM-768 public key (2368 hex digits).
- In `ck`, ID is the id of the `hi`'s sender.

COOKIE is 16 bytes in hex, made by B as
`BLAKE2b(key: cookie secret, byte(len(addr)) ‖ addr ‖ A's id ‖ A's PUB)` with a 16-byte output,
where addr is A's address as text. Only B ever checks the cookie, so its layout is B's own
business.

The cookie stops someone who recorded a `hi` from replaying it from another address. A `hi` is
taken without a cookie only when it changes nothing: the peer is already known, with the same key,
and either connected or at the same address. Anything else gets a `ck`. `ck` replies are limited
to 8 a second, with bursts of 32, so chat can't be used as a reflector.

Once B has checked the cookie, it creates the peer and sends A its own `hi`. A then goes through
the same steps with B.

### 5.2 Key exchange

Each side computes:

```
shared      = X25519(own private key, their PUB)
lo, hi      = (PUB ‖ id) of each side, sorted bytewise
prk_partial = H(master, shared ‖ lo ‖ hi)
```

The member with the lower id (compared bytewise) is the **initiator**. It encapsulates to the
other member's ML-KEM key, then sends `kx ID CT` in a room frame. ID is its own id, and CT is the
1088-byte ciphertext in hex. It sends `kx` again until a session frame from the peer opens on the
new chains. A recorded `kx` can be replayed, so the responder replaces a `kx` with a different one
until the peer's frames show which chains are right.

### 5.3 Chains

Both sides then compute:

```
prk            = H(prk_partial, ML-KEM shared secret)
send chain(0)  = H(prk, "chain" ‖ own PUB)
recv chain(0)  = H(prk, "chain" ‖ their PUB)
message key(i) = H(chain(i), "msg")
chain(i+1)     = H(chain(i), "step")
verify code    = H(prk, "vfy")[:16]
```

The frame with index *i* on a chain uses message key *i*. A receiver moves its chain forward to
the frame's index, at most 200 frames ahead, and never moves it back. There are no keys kept for
skipped frames: a frame that arrives after a later one is dropped, and acks and retries cover the
loss. A chain stops before index 2³²−1.

The verify code is the one users compare (shown as Bytewords and as hex). It's kept from a peer's
first handshake in the session, through every rekey.

The first session records each side sends are `k` and `v` (§7). A peer counts as connected once a
frame from it opens on the new chains.

## 6. Rekey

Every 300 seconds, each member makes new X25519 and ML-KEM key pairs and a new cookie secret. It
waits, for up to 120 seconds, while a re-handshake with anyone is still running. Then, for each
connected peer, it does the following:

1. It sends `rk PUB` over the current session, where PUB is its new X25519 key. It sends `rk`
   again every 6 seconds until the peer has re-handshaken with the new key.
2. It sends a `hi` with the new keys, queued after the `rk`, and the handshake runs as in §5. A
   peer that hasn't re-handshaken with the new keys gets the `hi` again every 20 seconds.
3. Both sides keep the old chains for 90 seconds, and drop them once a frame opens on the new
   ones.
4. Messages still waiting for an ack are sent again on the new chains.

A peer that has `r` in its `k` refuses a new key for an existing peer unless it was announced in
`rk`. After 10 seconds it warns about it. This stops a room member in the middle swapping in its
own key at a rekey, since it can't change what goes over the current session.

## 7. Session records

Records go in session frames. A `k` and a `v` come first after each handshake.

| Record | Fields | Meaning |
| --- | --- | --- |
| `k` | NICK COLOUR FLAGS IDTYPE IDPUB SIG | Who the sender is (see below). |
| `v` | VERSION PROOF LIST LISTSIG | Which build the sender runs (see below). |
| `m` | MID ORIGIN NICK TEXT | A message (see below). |
| `a` | MID | Acknowledges an `m` or `fo`. |
| `n` | NICK | A new nick. |
| `c` | COLOUR | A new colour. |
| `rk` | PUB | The sender's next X25519 key (§6). |
| `px` | ADDR,ADDR,... | Other members' addresses: numeric `IP:PORT`, or `NAME.onion` in Tor mode. A new member is sent everyone's, and everyone is sent the new member's. Members reached only through the relays aren't listed. |
| `ta` | ONION | The sender's own onion address (56 characters, no `.onion`). |
| `fo` | MID FID SIZE SHA256 KIND NAME | Offers a file. FID is 8 bytes in hex. KIND is `image` or `file`. NAME is at most 100 bytes. It's acked and retried like `m`. |
| `fg` | FID OFFSET COUNT | Asks for COUNT chunks (at most 64) starting at byte OFFSET. |
| `fd` | FID OFFSET DATA | One chunk: up to 690 bytes, in base64. |
| `fx` | FID | The file isn't offered any more. |
| `nop` | | Cover: sent when a slot has nothing else to carry. |
| `bye` | | The sender is leaving. Sent straight away, outside the slots. |

**`k`** says who the sender is:

- NICK is at most 24 bytes.
- COLOUR is six hex digits (RGB).
- FLAGS is `1` if the sender keeps a history of the chat, otherwise `0`. Capability letters
  follow, which older builds ignore:
  - `r`: announces rekeys with `rk`;
  - `b`: reads several records in one frame;
  - `l`: reads messages longer than 250 bytes.
- IDTYPE is the signing identity: `0` none, `1` native, `2` AGE, `3` PGP. With `0`, IDPUB and
  SIG are empty.
- IDPUB is an Ed25519 public key (64 hex digits).
- SIG (128 hex digits) is IDPUB's signature over the sender's X25519 key, the sender's id, the
  receiver's X25519 key and the receiver's id. The signature doesn't cover either side's ML-KEM
  key.

An identity's fingerprint is `BLAKE2b(IDPUB)[:16]`, unkeyed. A receiver that has IDPUB as a
verified key doesn't need the verify code compared again.

**`v`** says which build the sender runs:

- VERSION is the release.
- PROOF is `BLAKE2b(key: SHA-256 of the executable, "chat build v1" ‖ sender id ‖ receiver id)`.
  The hash leaves out the signed list that a release appends to its binaries.
- LIST is the comma-separated SHA-256 hashes of the release's binaries.
- LISTSIG is a minisign signature over `"chat vVERSION\n"` followed by each hash on its own line.

The receiver checks LISTSIG against the release key built into chat, then looks for a hash in the
list that gives PROOF. This only shows that the sender knows a release binary's hash. Any client
can claim to be a release binary.

**`m`** is a message:

- MID is 8 hex digits (4 random bytes).
- ORIGIN is the author's id.
- NICK is the author's nick.
- TEXT is up to 880 bytes of UTF-8.

The receiver acks every `m` with `a MID`. The sender sends it up to five times until it's acked.

Each message is also passed on to the receiver's other connected peers, so members that can't
reach each other directly still hear each other. A message is only passed on to peers the
receiver's own messages would go to, and never back to its origin. A receiver drops a MID it has
already seen, and a copy passed on for an origin it's connected to directly, since that origin's
own copy will arrive. Only the peer a frame came from is authenticated. ORIGIN and NICK in a
message that was passed on are whatever the peer that passed it on says.

A peer without `l` gets text longer than 250 bytes as up to eight parts. Each part is an `m` of
its own, with the MID `hex(SHA-256(MID ‖ "/" ‖ i)[:4])`, where *i* is the part's number in
decimal.

**Files** go in the slots that would otherwise carry a `nop`. The receiver asks for a window of
chunks at a time with `fg`, and asks again for any run of chunks that's missing. It keeps the file
only if its SHA-256 matches the one in the offer.

## 8. Slots and traffic shape

A connected peer gets one **slot** every 1.5 seconds, plus up to a quarter more at random. With
more than 12 peers connected, the interval grows to keep the total near 8 datagrams a second.
Through the relays, the slots are at least 5 seconds apart, and further apart with more peers on
the relays, so the total stays near 0.33 events a second.

Each slot sends exactly one datagram. It carries the oldest of whatever is waiting: a cell of a
room frame, or a record and, for a peer with `b`, as many of the following records as fit. If
nothing is waiting, it carries a `nop`. Records may go ahead of a waiting room frame, but for no
more than two slots in a row.

These are sent outside the slots:

- room frames to addresses that aren't connected peers (handshakes with candidates, and beacons);
- DHT messages;
- `bye`;
- a `nop` sent over a better path to test it (UDP after the relays, for example);
- fast file transfers, when the sender turns them on. Slots to the peer it's sending to then come
  every 5 ms. Through the relays they come no closer than 2.5 seconds, and at most 0.4 a second
  across all the peers there.

## 9. Timers and limits

| What | Value |
| --- | --- |
| A quiet peer gets a `hi` after | 10 s |
| A peer is dropped after | 40 s without a frame |
| UDP counts as broken, and traffic moves to the relays, after | 25 s without a frame |
| Relays stay connected after they were last needed (DHT routing) | 60 s |
| Rekey interval | 300 s, put off by up to 120 s |
| Old chains kept after a rekey | 90 s |
| Connected peers | at most 50, plus 64 handshaking |
| Ratchet skip | at most 200, or 16 from a new address |
| Candidates | at most 4 per host, at most 12 tries each |
| Hellos to candidates | 4 a second, bursts of 16 |
| Cookie replies | 8 a second, bursts of 32 |
| Trying frames from unknown addresses against every peer | 50 a second, bursts of 100 |

## 10. Older versions

- 0.3.1 and older sent UDP datagrams of other sizes, so they can't reach newer versions over UDP.
  They can still meet them through the relays, or over Tor.
- 0.3.0 sends `v` with only VERSION and PROOF, and chat checks those against 0.3.0's published
  hashes, which are built in.
- Builds without `l` cut longer messages off at 250 bytes. That's why messages to them go in parts.
- Builds before 0.5.0 called the first character of FLAGS the logging flag, and show it as
  `[logging chat locally]`.
