# Changelog

## Unreleased

### Security
- Desktop notifications on Linux are transient: the desktop shows them but keeps them out of
  its notification history, which recorded when messages came (and, with previews on, what
  they said) after chat had exited.
- Every datagram chat sends a connected peer goes in a slot of that peer's, one every 1.5 to
  1.9 seconds whether or not there's anything to say. A message, its ack, a message passed on
  to other members, a nick change and a re-handshake's pieces all wait for a slot, so when and
  how much goes no longer shows when anyone typed, or who first sent what in a group. Sending
  a message to several members no longer goes out to all of them at the same instant. A
  message takes up to two slots to arrive, and its ack as long to come back.
- Every UDP datagram is one 1004-byte cell: a session frame fills one, and a room frame goes in
  pieces padded to whole cells. Session frames were 428 bytes and pieces 1008, 1008 and 608,
  a pattern that picked chat out of other traffic.
- The `hi` every 10 seconds to every connected peer is gone: it was three pieces that marked
  chat's traffic as clearly as any header. A peer gets a `hi` only when it has gone quiet, or
  hasn't re-handshaken with new keys.
- Nothing you send reaches a peer until you've compared its verify code with them over another
  channel and said so with `:verify NICK ok`. Anyone with a session's id and password could sit
  between two members and read what they said; the code is the same on both ends only if
  nobody does. When a peer joins, chat shows the code to compare. `:verify NICK no` marks one
  that differs, which then gets nothing. Messages from a peer not compared show
  `(code not compared)`, and the sidebar says `compare code` until it is. A peer whose signing
  identity was confirmed this way and comes back with a fresh handshake signed by the same key
  needs no second comparison. **Compare verify codes** on the settings page (`:set verify
  optional`, `--verify-optional`) sends to everyone, compared or not.
- DHT routing goes to the Nostr relays only while it needs them: while nobody is reached
  yet, while a peer is reached only through them, or while one's UDP has gone quiet. It leaves
  them a minute after. Before, every DHT-routed member's address stayed connected to the
  relays for the whole session. `:set nostr always` (or `--nostr-always`) keeps the old way, for
  rooms with Tor members, who meet DHT members only on the relays.
- Each ten minutes' relay tag has connections of its own, asking for that tag alone: a new one
  to each relay a minute or two before the ten minutes start, and the last one closed a minute
  or two after they end. Each connection asked for the previous, current and next tags and
  moved on under the same subscription, which chained every ten minutes to the next for the
  relay. A relay still sees the address a connection comes from.
- The DHT node id changes with the lookup key, each hour: the same id for a whole session tied
  one hour's key to the next for every node that saw both. Around the hour's change, each
  hour's key is looked up under its own id.
- DHT queries say `ro` (BEP 43): chat is a read-only node, which never answered queries, and
  now other nodes don't expect it to.
- A DHT lookup starts from the nodes that answered earlier ones, and asks the bootstrap servers
  only while it knows fewer than eight. Every lookup, every 30 seconds while alone, went to
  the same four bootstrap servers with the room's lookup key.

### Added
- `:send` without a path opens a file browser to pick the file to offer.
- **Files and pictures**: `:send PATH` offers a file to the session; nothing moves until someone
  fetches it with `:download N` (saved in `~/Downloads`), or, for a PNG or JPEG, `:show N`,
  which draws it in the chat under the line that offered it (`:hide N` tucks it away). `:files`
  lists them and `:cancel N` stops one. A file is kept only if its SHA-256 matches the offer,
  is saved under a cleaned-up name without ever replacing anything, and a picture shown is never
  written to disk. Files move in chat's steady slots, invisible on the wire but slow; **Fast
  file transfers** (`:set fastfiles on`, `--fast-files`) sends them in quick bursts instead.
  **File size limit** (`:set filelimit`, `--file-limit`, 8 MB by default) is the most fetched
  without saying `anyway`; files go up to 1 GB. Pictures are decoded by chat's own PNG and
  baseline JPEG readers, which never hold the full-size image.
- `:changelog` (or `:news`) shows this changelog on a page of its own, built into chat so it
  reads offline, with its Markdown rendered: headings, bold, italic and `code`, links, nested
  lists, numbered items, quotes, code blocks and rules. In `--simple` it prints it.

### Changed
- Direct routing is now called DHT routing: `--routing dht+nostr` and `--routing dht`, and
  `dht` on the settings page. `--routing direct+nostr` and `--routing direct` still work.
- This version and 0.1.10 can't reach each other over UDP: the datagrams are a new size and
  room frames' pieces have a new header. They meet through the Nostr relays, or over Tor, and
  read each other's session frames there.
- A handshake takes a few seconds, and a re-handshake up to half a minute, going a slot at a
  time.
- `just build` takes what to build: `just build linux` (was `just build-static`),
  `just build windows` or `win` (was `build-win`), `just build all` (was `all`) and
  `just build test [all|linux|windows]` (was `test-build`). Build directories keep their names.

### Fixed
- `--nonostr` and `--nostr-always` were undone by the routing choice: `--simple` without a
  terminal, or `--routing dht+nostr` given after them, went back to the relay fallback, so
  `--nonostr` still connected to the Nostr relays. They now hold whatever the routing, and
  `--simple --nonostr` without a terminal routes DHT only. The routing line says when the
  relays are always on.

## 0.1.10

### Security
- Verify codes and identity fingerprints are 128 bits, shown in groups of four hex digits. A
  room member between two peers picks both handshakes' keys, so it could search two sets of
  64-bit codes for a pair that match. The first 16 digits are still what 0.1.9 shows.
- chat logs in to a tor control port with SAFECOOKIE or a password only. The old COOKIE login
  sent the cookie file's bytes to whatever answered on the port, and while tor isn't running
  any local program can listen there and name any file chat can read. The cookie file is read
  only if it's a regular file of a cookie's size.
- On Linux, `:update` runs curl and notifications run notify-send only from an absolute `PATH`
  entry or a usual folder, and only a program no one but root or you can change, as for tor.
  A relative `PATH` entry such as `.` could run one from the current folder. A program or
  folder writable by a group other than root's or yours is refused too.
- Desktop notifications only say that a message came, or that you were mentioned. They showed
  the sender, the text and the session's id; desktops keep notifications (Windows writes them
  to disk), and with a blank password the id is all it takes to join. **Notification preview**
  on the settings page (`:set preview off|nick|message`, also in `--simple`) brings back the
  sender, or the sender and the text, for whoever wants them. A notification never names the
  session.
- Everything chat sends over UDP is masked with a key made from the session id and password,
  so on the network each datagram is random bytes. The ratchet counter at the front of every
  session frame, and the marker, id and numbering at the front of every piece of a handshake,
  went in the clear: enough to pick chat's traffic out of anything else, and to follow a peer
  from one address to the next by its counter. What still shows is addresses, ports, sizes and
  timing. The relays and Tor already hide what they carry, and carry it as before.
- LAN beacons go to a UDP port of the room's own (49152-65535, made from its id and password),
  not to 47474, which told everyone on the network that chat was running.
- The DHT lookup key changes every hour. It was the same for a room's whole life, so anyone
  who saw it once, a DHT node or a crawler, could watch who joined the room for as long as it
  was used. For ten minutes either side of the hour, the other hour's key is looked up too.
- With the three changes above, 0.1.9 and this version can't find each other through the DHT
  or on the LAN, or reach each other over UDP. They meet through the Nostr relays, on by
  default, or over Tor, which work between them as before.
- Each connection to a relay subscribes under an id of its own. The same id at every relay,
  kept through reconnections, let relays that compare notes tie one member's connections
  together, Tor circuits included.
- Mbed TLS is built as a TLS client with forward-secret key exchanges only: no server or DTLS
  code, no renegotiation, no static RSA or DH key exchange, no legacy ciphers, and no PSA key
  store, which would keep keys in files.
- The conversation and console as shown, and the screen's buffers, are locked in memory like
  the keys, so they aren't written to swap (as far as `RLIMIT_MEMLOCK` allows).
- On Windows, a crash ends chat at once, so Windows Error Reporting can't write a dump of its
  memory to disk.
- Cookie challenges are rate-limited, so hellos replayed from a forged address can't make chat
  a traffic reflector. A session frame from an address no peer has is tried against every
  peer's keys at a limited rate, so junk of the right size can't use up the CPU.
- LAN beacons are only taken from real broadcasts, not from room members over the relays or
  Tor.

### Fixed
- A message sent just before a peer rekeyed or rejoined could be lost: the re-handshake threw
  away its retries.
- Joining or creating a session without the 512 MiB of free memory its key takes quit chat on
  the spot, leaving the terminal in raw mode and the other sessions without a goodbye. The
  session now doesn't start, and chat says why.
- In Tor mode, a long session could no longer reach new members once it had heard of 58 onion
  addresses. The one used longest ago now makes room.
- The DHT's bootstrap lookup, which runs on a thread, could write into a session after it
  closed.
- A key file, or a Tor cookie file, that was a FIFO or a device hung chat.
- A native build (`just build`, `just test-build`) used the build machine's CPU features in
  liboqs unconditionally, so a copy could crash on a CPU without them. It picks AVX2 code at run
  time now.
- `--simple` writing into a pipe that closes no longer kills chat before its sessions leave,
  and a terminal resize no longer cuts a frame short.
- libsodium's build started a compiler per file at once, which could run a small machine out
  of memory.

### Added
- A page of every key and command: `F1`, `?` in NORMAL, or `:help`. `Enter` on a command puts it
  on the command line.
- The command line shows a menu of the commands that match what's typed, the settings (with
  their values now) after `set `, and a setting's values after its name. `Up` / `Down` pick,
  `Tab` completes, and `Enter` on a name only started runs what the menu has picked. After a
  command that takes a nick (`verify `), it lists the peers online that match, with each one's
  verify state, and shows the rest of the picked one dimmed, as `@` does.
- `/` on an empty line, in INSERT or NORMAL, opens the command line, as in other chat programs.
  A line that can't be a command (`/shrug`, `/usr/bin`) turns back into text as it's typed and
  is sent as a message, never refused as an unknown command; `//` does the same straight away.
- `PgUp` / `PgDn` scroll the chat back and forward (`Ctrl+U` / `Ctrl+D` in NORMAL, `G` back to
  the newest), and the chat's edge says how many newer messages are below.
- In NORMAL, `s`, `c` and `C` show or hide the sidebar, the console and the chat, as `Ctrl+B`,
  `Ctrl+O` and `Ctrl+T` do.
- `Tab` / `Shift+Tab` jump between sections on the settings and help pages.
- `Ctrl+U` in INSERT deletes everything before the cursor.
- `NO_COLOR` keeps the UI to bold, faint and reverse.

### Changed
- `just test-build` names each binary after its build id, as `chat-<build id>-<system>-<arch>`:
  the source it was built from (`git describe`) and when, in UTC, as `chat --version` shows.
- The full-screen UI is redrawn as one rounded frame split by lines, each part titled in its
  border: a sidebar with the sessions, their peers and how the selected one reaches them, the
  console over the chat, and the input under it, outlined in the mode's colour. A bottom row
  shows the mode, whether you sign, your nick and what the keys do.
- The UI draws in the terminal's own colours, so it takes on the terminal's theme, light or
  dark, and follows it when it changes (where the terminal reports that). Peers' colours stay
  exact, but are eased toward readable on the terminal's background once it has told chat what
  that is.
- The chat lines up in columns (time, nick, text); a run of messages from one peer in one
  minute shows the time and nick once. A new session, one still connecting, and one with no
  messages yet say so, and what to do next.
- The peers list shows whether each is verified, and a modified client, in words while they
  fit; a lookalike's `#id` and its state are never cut for its nick.
- The settings page lists its sections on the left, draws switches and choices as such, and
  shows each row's `:set` under its help. Text rows are edited in place. The page chat opens on
  ends in **Start chatting**.
- Release binaries are less than half the size: Linux 1.3 MB instead of 2.9 MB, Windows 1.2 MB
  instead of 3.0 MB. libsecp256k1 keeps only its signing tables, Mbed TLS only a client,
  unused code in every dependency is left out when linking, and builds are stripped as they're
  linked.
- The full-screen UI sends nothing to the terminal while the screen stays the same. It redrew
  the whole screen every second, which over SSH was a steady stream.

## 0.1.9

### Changed
- Checking a peer's build no longer contacts GitHub. Each release binary carries a list of that
  release's binaries, signed with the release key, and sends it along with its hash; peers
  check the list against the release key built into chat. A build without a signed list, such
  as one from source, shows as modified. 0.1.8 peers are checked against 0.1.8's published
  hashes, which are built in. 0.1.8 shows newer peers' builds as unknown.
- `just release` signs the list and appends it to each binary before making `SHA256SUMS`, so it
  asks for the release key's password twice.
- `:peers` shows a build that checks out as "says official v0.1.9": a client altered to lie
  about its hash still passes, so that's only the peer's word.

## 0.1.8

### Added
- A native AGE or PGP signing key is made from a password and this OS install's machine id,
  so the same password on the same device and OS always gives the same key and fingerprint,
  without storing anything. Always use the same password to keep an established signing
  identity. The settings picker asks for it after **Native**, and `--identity age|pgp` asks
  at startup or takes `CHAT_SIGN_PASSWORD`. A blank password makes a new random key, as
  before. `:set sign age|pgp` opens the picker to type it there, where it's hidden.
- Peers tell each other which version they run and the SHA-256 of their executable, and each
  checks it against the signed `SHA256SUMS` of that version's release. A peer that isn't
  running one of that release's binaries, or names a version with no signed release, is marked
  modified: a warning when it's found, `modified` next to its name, and its build in `:peers`.
  The first time a version comes up, its checksums are fetched from GitHub, through Tor in Tor
  mode. A client altered to lie about its hash still passes.

### Changed
- Commands only run from COMMAND mode: `Esc`, then `:name`. Everything typed in INSERT is sent
  as a message, including lines that start with `/` or `:`. `--simple` takes `:name` instead
  of `/name`.
- Commands do things and settings hold values. Every setting is a row on the settings page,
  and `:set NAME VALUE` sets one without opening it (`:set nick bob`, `:set net verbose`);
  `:set` opens the page and `:set NAME` opens it on that row. `:nick`, `:colour`, `:notify`,
  `:netverbose`, `:sign` and `:settings` are gone. `--simple` has `:set` for `nick`, `colour`,
  `notify` and `net`.
- The network log setting is `normal` or `verbose`, and "Start chat's own tor" is `auto`,
  `always` or `never`, matching `--tor-launch`.
- The settings page, the signing identity picker and the key file browser take the same keys:
  `j`/`k` move, `g`/`G` go to the ends, `Enter` chooses, `h`/`l` change a value or go out of /
  into a page, `Esc` goes back, `q` closes. `Tab` no longer moves down a list. The picker and
  browser show where they are in the title (settings › signing identity › folder) and explain
  the selected choice under the list.
- The bottom bar is the same on every screen: a chip saying where you are, what the keys do,
  and the reply to what you just did until the next key. Settings changes and `:set` answer
  there, instead of on a line of the settings page.
- The time is at the right end of the top bar instead of the bottom bar.
- The signing identity picker lists Off, then AGE and PGP, each with Native, a key file and a
  key paste. Your own AGE key (as `age-keygen` writes it) can sign now, from a file, pasted in,
  or with `--identity age:KEYFILE`, and keeps its `age1...` recipient. `pgp` (`--identity pgp`,
  `:set sign pgp`) makes a new PGP key, whose public key the settings copy for `gpg --import`.
  The plain native key is gone: `--identity native` and `:set sign native` are refused.
- `Ctrl+W` deletes the word before the cursor, as in vim and readline, instead of closing the
  session; `:q` closes it. In NORMAL, `j` and `k` switch sessions.
- The input line starts in NORMAL; `i` (or `a`, `I`, `A`) starts typing.
- Nothing reaches the network while the settings page chat opens on is up: a tor is looked for
  or started, and `--peer` names are looked up, only after **Done**, whatever the page is
  switched to. In Tor mode a `--peer` name isn't looked up at all, since the lookup would go
  around Tor. With `--simple`, the lookup waits for the routing answer.
- chat opens on the settings page, so everything is set up in one place before the first
  session, and a **Done** button at the bottom (or `Esc`) goes on to the sessions. This
  replaces the routing question at startup; `--routing` presets the page.
- The signing identity is chosen on the settings page itself instead of at the input line:
  off, a new native or AGE key, or a PGP key picked in a file browser or pasted in. A native
  key used to need `--identity native`. `:set sign` opens the same choice. A key file that
  doesn't load, or a paste that doesn't parse, says so on the page.
- An **AGE recipient** row in settings shows the `age1...` string and copies it to the
  clipboard.
- Settings that don't apply right now are left off the page instead of greyed out: the DHT,
  LAN and port mapping switches in Tor mode, the Tor ones in direct mode, the relay list while
  the relays are off, and the AGE recipient without an AGE identity.

### Fixed
- A peer could join as `anon (unverified)` in the console while the sidebar showed its real
  nick as verified: the join was announced on the peer's first frame to open, and when the one
  carrying its nick and signing identity was lost or overtaken, another got there first. Now
  `* joining: peer ID` shows as soon as the connection is made, and the usual `joined` line
  follows once the nick and identity are in (or after 5 seconds, so nobody joins unannounced).
  The modified-client warning waits for the join.
- `:colour`, `:notify` and `:netverbose` changed only the session you were in, while the
  settings rows of the same names changed every session, so the page could show a value the
  session didn't have, and a new session went back to the old one. Both now go through the
  same setting.
- The version on the bottom bar could run into the prompt.

## 0.1.7

### Added
- chat asks at startup how sessions should reach people: direct with a Nostr relay fallback,
  direct only, or Tor. `--routing direct+nostr|direct|tor` answers ahead of time.
- IPv6 DHT (BEP 32). Lookups run on the IPv4 and IPv6 DHTs side by side, and IPv6 peers
  connect directly. `--noipv6` turns it off.
- Router port mapping: chat asks the router to forward the session's UDP port (PCP, then
  NAT-PMP, then UPnP-IGD), renews it, tells the DHT the forwarded port, and removes the
  mapping when the session ends. `--noportmap` turns it off.
- Nostr relay fallback: when UDP between two peers can't get through, public Nostr relays
  carry their traffic. Each event is signed with its own one-off key, has a random ephemeral
  kind and a timestamp a few seconds off, and holds one fixed-size payload encrypted under a
  fresh nonce. It carries a room tag that changes every ten minutes. Relays that rate-limit get
  fewer events, and relays whose policy refuses throwaway keys are only read from. `--relay`
  picks relays; `--nonostr` turns it off.
- Tor routing: onion services. Each session publishes its own onion service and one of six room
  onion services derived from the session id and password. In Tor mode chat sends no UDP and
  connects nowhere directly.
- Tor and direct members of a room meet on the Nostr relays, the only place they can: both
  need the relays on. A Tor session reaches them only
  through Tor's SOCKS port, with a circuit per relay and the relay's name resolved at the exit,
  and doesn't connect to any relay until it has a tor. Between Tor members the traffic moves to
  their onion services once those connect. The **Nostr relays** setting and `--nonostr` now
  apply in both modes. When nobody answers and relays are off, chat says members using the
  other routing can't reach this session.
- Tor mode uses a tor that's already running (system service or Tor Browser) when its control
  port lets chat log in, since that one keeps its entry guards and bridges. Otherwise chat
  starts its own: tor from `PATH`, or `--tor-path`, provided no one but root or the user can
  change it. It runs with an empty configuration, on random 127.0.0.1 ports with cookie login,
  in a private temporary folder (in memory under `$XDG_RUNTIME_DIR` where there is one). chat
  deletes the folder on exit, tor quits by itself if chat crashes, and the next chat deletes
  what a crash left. `--tor-launch auto|always|never` chooses. `--tor-socks` and
  `--tor-control` say where to look for a running tor.
- A settings page (`Ctrl+S` or `/settings`): routing and each part of it, the relays and Tor
  ports, nickname, colour, signing identity, notifications, the network log, the UDP port for
  new sessions, and the layout. Routing toggles apply to open sessions at once. The mode and
  the Tor settings apply to sessions opened afterwards. Nothing is written to disk.
- `--nolan` turns off LAN discovery.
- `/net` reports port mapping, relay and Tor status, and IPv4 and IPv6 lookups separately.
- A fuzz target for relay JSON and UPnP gateway replies (`just fuzz json`).
- `just test-build [all|linux|windows]` builds the Linux and Windows binaries, or one of them,
  into `test-builds/<date>-<time>/`. It builds this system's natively and cross-builds the
  other with zig, then offers to run this system's when there's a terminal to ask on, passing
  it any further arguments.

### Changed
- In Tor mode, `/update` and `--update` download through Tor's SOCKS port.
- Peers are reached on the best path that works: direct UDP, then Tor, then the relays. A
  worse path takes over only once the better one goes quiet. When a connected peer's hello
  arrives over a better path (UDP punched through, or a Tor stream, after the relays), chat
  answers with an encrypted frame on it, so both sides move there once it's proven.
- `--nodht` now turns off both DHTs.
- Candidate addresses stop getting hellos once their peer is connected.
- Mbed TLS 3.6.7 and libsecp256k1 0.7.1 are fetched and linked statically, and on Windows
  chat also links crypt32 (the system root certificates) and iphlpapi (the default gateway).

### Fixed
- A second Ctrl+C, SIGTERM or SIGHUP soon after the first killed chat on the spot, before
  sessions said bye, keys were wiped and the terminal was restored: the quit handler was reset
  after the first signal (glibc's `signal()` does that with `_POSIX_C_SOURCE`, and the Windows
  C runtime always does). The handler now stays in place.
- Cross builds passed a relative toolchain path to the dependencies' builds, which only
  worked with an existing build directory.

## 0.1.6

### Security
- Importing a PGP key could read past the end of a buffer when the key block decoded to more
  than 4 KiB. The armor is now parsed properly: header lines are skipped and the CRC-24
  checksum line is checked.
- A PGP key that failed to import could overwrite the secret half of the current signing key
  but not the public half, so signatures stopped verifying. A failed import now leaves the
  current key as it was.
- Text from peers is decoded as strict UTF-8. Overlong forms, surrogates and stray bytes are
  dropped. Before, an overlong sequence could carry a byte that an 8-bit terminal reads as the
  start of a control sequence. The Arabic letter mark (U+061C), a bidi control, is now stripped
  like the other bidi controls.
- Programs that chat starts (curl for `/update`, notify-send) no longer inherit its sockets. On
  Windows, curl inherits only its standard handles. On Linux, chat sets no_new_privs.
- Packets with a length that chat never sends are dropped before any decryption is tried, so
  junk packets cost less CPU.
- More key material is wiped after use, and each peer's chain keys, the signing key and typed
  passwords are locked in memory where the memory lock limit allows.
- Stack variables start zeroed where the compiler supports it (`-ftrivial-auto-var-init=zero`).
- New session ids are uniformly random. Before, some characters were slightly more likely than
  others.
- A peer can no longer fill the list of chat's own addresses with replays of chat's own hi.
- Messages with a malformed message id are ignored.
- SIGTERM and SIGHUP now shut chat down like Ctrl+C does: sessions say bye, keys are wiped and
  the terminal is restored.

### Fixed
- A message whose first packet was lost could never be delivered if any later packet (cover
  traffic, say) reached the peer first, because each retry resent a frame the peer could no
  longer open. Each retry is now encrypted again with the next message key.
- If every retry slot was taken, a message wasn't sent at all to the remaining peers. It is now
  sent once, without retries.
- Bencode lists that contained lists or dictionaries were read wrongly.
- Non-ASCII text in the full-screen UI: line wrapping, padding and the cursor position now count
  screen columns, not bytes, and wide characters (CJK, most emoji) take two columns. Leftover
  characters no longer show at the ends of rows.
- The input line scrolls sideways when the text is longer than the screen, so the cursor stays
  visible. Password prompts show one dot per character, not per byte.
- Ctrl+arrow keys, function keys and other unknown key sequences are ignored instead of typing
  part of the sequence into the input line. Esc followed quickly by another key still counts
  as Esc.
- Leaving the full-screen UI restores the cursor's shape and visibility.
- A session whose socket couldn't be opened left its LAN socket open.
- `--port` rejects values outside 0-65535 instead of wrapping them. More than 16 `--peer`
  options is an error instead of the extras being dropped silently.

### Changed
- A pasted PGP key is checked for its END line only at the end of the paste so far, so long
  pastes no longer slow down.
- Redrawing the peer list no longer recomputes every nick's lookalike form for every peer.
- `just test` runs the new engine test, and `just fuzz` runs the new fuzz targets (see the
  README).
- `just release` releases the Unreleased section of this changelog: it names the section after
  the new version (the next patch unless one is given), sets that version in `CMakeLists.txt`,
  commits and tags it, and pushes only once the release is signed.

## 0.1.5

### Security
- `/peers` could overflow a stack buffer once about 25 peers were online.
- A room member could make a message appear to come from someone else. A message now shows
  the nick of the peer that sent it. A message passed on for a peer you aren't connected to
  shows as `nick (via relayer)`. A passed-on copy of a message from a peer you are connected
  to is ignored, because that peer's own copy arrives directly.
- Nicks can no longer contain `(`, `)`, `#`, `:` or `@`, so a nick can't fake "(verified)",
  "(you)" or an id. The sidebar shortens a long nick instead of hiding a peer's status.
- chat warns when a peer's signing identity changes, disappears or stops verifying after a
  re-handshake.
- Peer addresses shared by other peers must be IP addresses. Before, a room member could
  make everyone look up any hostname.
- The PGP key browser hides file names that contain terminal control characters.
- On Windows, `/update` runs `curl.exe` from `System32` only. Before, a `curl.exe` in the
  same folder as `chat.exe` or in the current folder would run instead.
- `/update` makes curl ignore `.curlrc`.
- The peer verify code is 16 hex digits instead of 8. The first 8 still match the code that
  older versions show.
- Hardening against outsiders who replay recorded packets or send junk: re-handshakes with
  new keys, or from a new address mid-handshake, must answer a cookie first. A replayed
  `kx` can no longer lock in bad keys. Junk packets from unknown addresses cost less CPU.
- Releases are signed. `/update` and `--update` install a release only if its `SHA256SUMS`
  carries a valid minisign signature from the release key built into chat, made for that
  release's tag. Control of the GitHub account alone is no longer enough to push an update.
- Before a peer rekeys, it announces its new key over the current session. A new key that a
  peer never announced is refused, so a room member between two peers can't swap in its own
  key at a rekey. This works between peers that both run this version.
- When a peer drops and comes back, chat says if its verify code changed.
- Nicks that look alike (case, `l`/`I`/`1`, `0`/`O`, Cyrillic or Greek letters, fullwidth
  forms) show with `#` and the peer's id. Invisible characters are removed from nicks.
- Candidate addresses from the DHT and from other peers are rate-limited, at most 4 per
  host, so chat can't be used to flood an address with handshake traffic.
- `--simple` without `--session` on a non-terminal starts a new random session instead of
  joining the fixed `lobby` session, which anyone could join.

### Changed
- `/peers` prints one line per peer.
- Releases are built and published with `just release`. CI builds every push but no longer
  publishes releases.

## 0.1.4

### Added
- `--update` installs the latest release from the shell and exits, without opening chat.
  It exits with status 1 if the update fails, so `sudo chat --update` works for a copy
  in a system folder.

### Changed
- The Linux release binary is statically linked against musl, so it runs on any x86_64
  Linux distribution without depending on the system's glibc version.
- Building with [just](https://github.com/casey/just) is supported: `just build`,
  `just run`, and `just dist` for release binaries.
- chat is deliberately not packaged, to leave no trace beyond the executable. The README
  explains where to keep it so updates keep working.

## 0.1.3

### Added
- `/port [N]` shows this session's UDP port, or moves the session to port `N` without
  leaving it (`0` picks a free one). Connected peers follow the new port automatically.

## 0.1.2

### Fixed
- On Linux, `:update` saved the new binary as `chat (deleted)` instead of replacing
  `chat` when the executable had been replaced (for example rebuilt) while chat was running.

## 0.1.1

### Added
- `@` nick completion: typing `@` and the start of an online peer's nick shows the rest
  dimmed; `Tab` completes it.
- The version number is shown in the status bar, after the identity badge.
- `/help` lists every command with its arguments.

### Changed
- Every command works both as `/name` in INSERT and as `:name` in COMMAND mode, from one
  shared command table, so `/new`, `/join`, `/sign`, `/copyid`, `/update` and `/quitall`
  (`/qa`) now work typed too.
- `/nick` changes your nickname in every open session.
- `/quit` (`/q`) leaves the current session and quits when none is left open.
- `/colour`, `/notify` and `/netverbose` without an argument show the current setting.
- Password and session-id prompts are plain fields (`Enter` confirms, `Esc` cancels), and
  the draft you were typing comes back afterwards.

## 0.1.0

First versioned release.

- `:update` checks the GitHub releases page, downloads the binary for your platform,
  verifies its SHA-256 against `SHA256SUMS`, and replaces the executable.
- `--version` prints the version number.
