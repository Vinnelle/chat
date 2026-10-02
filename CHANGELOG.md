# Changelog

## Unreleased

### Added
- `:save` saves what's in use now to the save that's open, after asking, command line options
  included. With no save open, it does what `:install` does.
- An `autosave` setting, off by default. On, a setting you change, and a key you verify or
  forget, is saved as you change it. Off, they last until chat exits, and the reply to a
  setting you change ends in `· not saved (autosave is off)`. `:save` saves them, and turning
  autosave on saves the ones changed meanwhile. The `autosave` row is always saved itself, so
  turning it on lasts. Either way, the signing key is only saved by `:save` or `:install`.

### Changed
- The Windows exe has version information and a manifest (Properties, Details shows them).
  Antivirus heuristics count an exe without them against it, and Malwarebytes flagged
  0.4.0-beta.2 as Malware.Heuristic.2062.
- On Windows, tor starts inside the job that ends it with chat, instead of being started
  suspended, added to the job, then resumed. This needs Windows 10 1607 or later.
- After `:install`, a setting you change or a key you verify or forget isn't saved straight
  away any more: `:save` saves it, or `:set autosave on` saves each change as before. A save
  from an earlier version has no `autosave` row, so it opens with autosave off.
- `Ctrl+C` asks before quitting, in a box that says how many sessions and peers are open, and
  what quitting loses: files still downloading, settings or a signing key that aren't saved,
  and an update that's still running. `y` quits, and `n` or `Esc` stays. In `--simple`, a
  second `Ctrl+C` within 3 seconds quits, and from a script it still quits at once.

## 0.4.0-beta.2

### Changed
- **Compare verify codes** on the settings page is now `optional` by default. What you send
  goes to every peer, whether you've compared codes or not. `:set verify required`, or the new
  `--verify-required`, holds messages back from a peer until you've marked its code as matching
  (`:verify NICK ok`). `--verify-optional` still works.
- `:update` opens a box over the chat that shows the update while it runs. At the top is a
  console with each step: what it fetched from GitHub, the signature and SHA-256 checks, and
  where it installed. Under that is a progress bar for the download, then a line saying what
  it's doing now ("Checking GitHub for a newer release", "Release v0.4.0 found",
  "Downloading v0.4.0", "Installing v0.4.0"). Esc hides the box and the update keeps going.
  `:update` shows it again. The result still goes to the console.
- For a signing key from a file, `:install` now saves the file's path instead of the key, and
  chat reads the file again each time it starts. If the file is gone, or holds a different key,
  the console says so. A key file that an earlier `:install` saved as the key keeps loading as
  before, and is saved as a path the next time you pick it and run `:install`. A pasted key
  has no file, so `:install` still seals the key itself.
- The signing identity picker has a **Type a key file path** row under AGE and PGP, for when
  you'd rather not use the file browser. In the browser, `/` does the same, starting with the
  selected file. `:set sign age:PATH` and `:set sign pgp:PATH` work too. `~` is your home folder.
- The picker, the browser, the path field and the paste box say why chat needs your secret key:
  it signs your handshakes, and only the secret key can make a signature. It stays in memory and
  is never sent.
- The file browser (for a key file, and for `:send`) is drawn as a tree: the folder you're in
  and the folders above it, one level per row, with its folders and then its files under it.
  Hidden ones come last, and there's no `..` row (`h` goes up). How many levels get their own row
  depends on the terminal's width. The levels above those are joined into the top row's path,
  cut from the left with `…` if it's still too long. The top line says how many folders and files
  there are. On a wide terminal, a column left of the tree lists the parent folder, with the
  folder you're in selected and the parent's path above it. The sidebar shows the selected
  entry: whether it's a file, folder or link, its size or number of entries, when it was changed
  and its permissions. In the key file browser it also says whether a small file holds an AGE or
  PGP secret key, and if one does but others can read the file, says to `chmod 600` it. Going up
  selects the folder you came from, and `~` goes to the home folder. The key file browser opens
  in the folder of the key file in use.
- `:install` while nothing saved is open (`Esc` at the start) asks whether to use what's saved.
  Yes asks for its passphrase, after picking a save from a list when there's more than one, and
  from then on that save is in use, as if it had been opened at the start. Settings changed
  before that which it doesn't have, and keys verified before that, are kept and saved to it.
  A command line option doesn't undo a setting changed in that run, and keys from a save
  uninstalled in that run are left out.
  No makes a new save, with a name and a passphrase of its own. Before, the only choice was to
  save what's in use over it. `:install NAME` for another save while one is open asks whether to
  save over it, then asks for that save's passphrase.
- A picture that was shown is kept in memory (up to 128 MB in all, the oldest dropped first)
  and wiped when the session closes. `:download N` saves it from there straight away, and
  `:show N` draws it again, without fetching it a second time.
- `:download N` for a file that's already saved says where it is instead of fetching it again,
  as long as the saved file still matches the offer. `:show N` of a picture saved earlier draws
  it from the saved file.
- `:download N FOLDER` saves in a folder other than Downloads, copying from an earlier save or a
  shown picture when there is one. `:saveto N` picks the folder in a file browser: Enter opens a
  folder and `s` saves in the one shown.
- `:download` without a number takes the newest file that isn't saved yet.
- Asking for a second file from a sender while one is coming queues it, and it starts by itself
  once the first is done, instead of being refused. The row under its offer and `:files` say
  what it's waiting for, and `:cancel N` takes it off the queue.
- `:download N` while a picture is coming to be shown, or `:show N` while it's coming to be
  saved, does both once it's here.
- `:files` says where each file was saved, and the message when a file is saved gives its size
  and how long it took.

### Fixed
- `:install` could keep the old signing key after you picked a different one, and said a key that
  was saved wasn't. It compared the keys the wrong way round.

### Added
- More than one save. `:install NAME` saves your settings and signing key as a save called
  NAME, in `~/.config/chat/saves/NAME`, with its own passphrase. `:install` alone keeps using
  the save in use, and the save in `~/.config/chat` itself is called `default`.
  `:uninstall NAME` deletes that save. With more than one save, chat lists them when it starts,
  with what each one holds and when it was last saved, and you pick the one to open before its
  passphrase is asked for. Esc on the passphrase goes back to the list. `--simple` and `--update`
  list them in the terminal and take a number or a name. `--save NAME` opens that save without
  the list, and if there's no save called NAME yet, chat starts from its defaults and
  `:install` makes it. Without `--save`, `CHAT_INSTALL_PASSWORD` opens the first save it fits.
  With only one save, chat asks for its passphrase straight away, as before.
- Verified keys. For a peer that signs with an identity, `:verify NICK ok` keeps its signing
  key and nick as verified, for every session in the run. A peer that signs a later handshake
  with a verified key needs no code comparing. `:install` saves the keys in a `verified` file,
  sealed with the settings of the save in use, and each change after that is saved. `:verified` lists them with
  their fingerprints, and `:verified forget NICK` (or `all`) removes them.
- When a peer has the nick of a verified key but signs with another key, or none, chat prints
  a warning in the chat (bold yellow, and in yellow in `--simple`) as well as the console, and
  the sidebar shows `key changed`. The peer counts as not compared until you compare codes
  again. `:verify NICK ok` then replaces the key kept for that nick.

## 0.4.0-beta.1

### Security
- Verify codes and identity fingerprints are 128 bits, shown in groups of four hex digits. A
  room member between two peers picks the keys for both handshakes, so it could search two sets
  of 64-bit codes for a matching pair. The first 16 digits are the same as what 0.3.1 shows.
- chat only logs in to a tor control port with SAFECOOKIE or a password. The old COOKIE login
  sent the cookie file's contents to whatever answered on the port, and while tor isn't running
  any local program can listen there and name any file chat can read. The cookie file is only
  read if it's a regular file of the right size.
- On Linux, `:update` only runs curl, and notifications only run notify-send, from an absolute
  `PATH` entry or a standard folder, and only if the program can't be changed by anyone but root
  or you, the same as for tor. A relative `PATH` entry such as `.` could run one from the
  current folder. A program or folder writable by a group other than root's or yours is also
  refused.
- Desktop notifications only say that a message came in, or that you were mentioned. They used
  to show the sender, the text and the session id. Desktops keep notifications (Windows writes
  them to disk), and with a blank password the id is all someone needs to join.
  **Notification preview** on the settings page (`:set preview off|nick|message`, also in
  `--simple`) shows the sender, or the sender and the text, if you want them. A notification
  never names the session.
- Everything chat sends over UDP is masked with a key made from the session id and password, so
  on the network each datagram is random bytes. Before, the ratchet counter at the start of
  every session frame, and the marker, id and numbering at the start of every handshake piece,
  were sent in the clear. That was enough to pick out chat's traffic, and to follow a peer from
  one address to the next by its counter. Addresses, ports, sizes and timing are still visible.
  The relays and Tor already hide what they carry, and carry it as before.
- LAN beacons go to a UDP port specific to the room (49152-65535, made from its id and
  password), not to 47474, which told everyone on the network that chat was running.
- The DHT lookup key changes every hour. It used to stay the same for as long as the room
  existed, so anyone who saw it once, such as a DHT node or a crawler, could watch who joined
  the room for as long as it was used. For ten minutes either side of the hour, the other
  hour's key is looked up as well.
- Because of the three changes above, 0.3.1 and this version can't find each other through the
  DHT or on the LAN, or reach each other over UDP. They can still meet through the Nostr relays,
  which are on by default, or over Tor.
- Each relay connection subscribes under its own id. Using the same id at every relay, kept
  across reconnections, let relays that share data link one member's connections together,
  including over Tor circuits.
- Mbed TLS is built as a TLS client with forward secret key exchanges only. There's no server or
  DTLS code, no renegotiation, no static RSA or DH key exchange, no legacy ciphers, and no PSA
  key store, which would keep keys in files.
- The conversation and console on screen, and the screen buffers, are locked in memory like the
  keys, so they aren't written to swap (as far as `RLIMIT_MEMLOCK` allows).
- On Windows, a crash ends chat immediately, so Windows Error Reporting can't write a dump of
  its memory to disk.
- Cookie challenges are rate limited, so hellos replayed from a forged address can't turn chat
  into a traffic reflector. A session frame from an address no peer has is tried against every
  peer's keys at a limited rate, so junk of the right size can't use up the CPU.
- LAN beacons are only accepted from real broadcasts, not from room members over the relays or
  Tor.
- Desktop notifications on Linux are transient. The desktop shows them but doesn't keep them in
  its notification history, which used to record when messages came in (and, with previews on,
  what they said) after chat had exited.
- Every datagram chat sends to a connected peer goes in one of that peer's slots, one every 1.5
  to 1.9 seconds, whether or not there's anything to send. Messages, acks, messages passed on to
  other members, nick changes and re-handshake pieces all wait for a slot. This means the
  timing and size of traffic no longer show when someone typed, or who sent a message first in
  a group. A message sent to several members no longer goes out to all of them at the same
  moment. A message takes up to two slots to arrive, and its ack the same to come back.
- Every UDP datagram is one 1004-byte cell. A session frame fills one cell, and a room frame is
  split into pieces padded to whole cells. Before, session frames were 428 bytes and pieces were
  1008, 1008 and 608, which made chat easy to pick out from other traffic.
- The `hi` sent to every connected peer every 10 seconds is gone. It was three pieces, and it
  marked chat's traffic as clearly as a header would. A peer now only gets a `hi` when it has
  gone quiet, or hasn't re-handshaken with new keys.
- Nothing you send goes to a peer until you've compared its verify code with them over another
  channel and marked it with `:verify NICK ok`. Anyone with a session's id and password could
  sit between two members and read what they said. The code only matches on both ends if
  nobody is in the middle. When a peer joins, chat shows the code to compare. `:verify NICK no`
  marks a code that didn't match, and that peer then gets nothing. Messages from a peer you
  haven't compared show `(code not compared)`, and the sidebar says `compare code` until you do.
  If a peer's signing identity was confirmed this way and it comes back with a fresh handshake
  signed by the same key, you don't need to compare again. **Compare verify codes** on the
  settings page (`:set verify optional`, `--verify-optional`) sends to everyone, compared or
  not.
- DHT routing only connects to the Nostr relays while it needs them: before anyone is reached,
  while a peer is only reachable through them, or while a peer's UDP has gone quiet. It
  disconnects a minute after. Before, every DHT-routed member's address stayed connected to
  the relays for the whole session. `:set nostr always` (or `--nostr-always`) keeps the old
  behaviour, for rooms with Tor members, who can only meet DHT members on the relays.
- Each ten-minute relay tag gets its own connections, which only ask for that tag. A new
  connection to each relay opens a minute or two before the ten minutes start, and the last one
  closes a minute or two after they end. Before, each connection asked for the previous,
  current and next tags and moved on under the same subscription, which let a relay link each
  ten minutes to the next. A relay still sees the address a connection comes from.
- The DHT node id changes with the lookup key every hour. Using the same id for a whole session
  linked one hour's key to the next for every node that saw both. Around the change of hour,
  each hour's key is looked up under its own id.
- DHT queries set `ro` (BEP 43). chat is a read-only node and never answered queries, and now
  other nodes don't expect it to.
- A DHT lookup starts from the nodes that answered earlier lookups, and only asks the bootstrap
  servers while it knows fewer than eight. Before, every lookup (every 30 seconds while alone)
  went to the same four bootstrap servers with the room's lookup key.

### Fixed
- A message sent just before a peer rekeyed or rejoined could be lost, because the re-handshake
  discarded its retries.
- Joining or creating a session without the 512 MiB of free memory its key needs quit chat
  immediately, leaving the terminal in raw mode and the other sessions without a goodbye. The
  session now doesn't start, and chat says why.
- In Tor mode, a long session stopped reaching new members once it had seen 58 onion addresses.
  The least recently used one is now dropped to make room.
- The DHT bootstrap lookup, which runs on a thread, could write into a session after it closed.
- A key file or Tor cookie file that was a FIFO or a device made chat hang.
- A native build (`just build`, `just build test`) always used the build machine's CPU features
  in liboqs, so a copy could crash on a CPU without them. It now picks AVX2 code at run time.
- `--simple` writing to a pipe that closes no longer kills chat before its sessions leave, and a
  terminal resize no longer cuts a frame short.
- libsodium's build started a compiler for every file at once, which could run a small machine
  out of memory.
- `--nonostr` and `--nostr-always` were overridden by the routing choice. `--simple` without a
  terminal, or `--routing dht+nostr` given after them, went back to the relay fallback, so
  `--nonostr` still connected to the Nostr relays. They now apply whatever the routing, and
  `--simple --nonostr` without a terminal uses DHT only. The routing line says when the relays
  are always on.
- `Enter` on a message over the 250-byte limit sent it with the end cut off. It now stays in the
  box, where the count is already red, and the bottom row says how far over the limit it is.

### Added
- A page listing every key and command: `F1`, `?` in NORMAL, or `:help`. `Enter` on a command
  puts it on the command line.
- The command line shows a menu of commands that match what's typed, the settings (with their
  current values) after `set `, and a setting's values after its name. `Up` / `Down` pick,
  `Tab` completes, and `Enter` on a partly typed name runs what the menu has selected. After a
  command that takes a nick (`verify `), it lists the online peers that match, with each one's
  verify state, and shows the rest of the selected nick dimmed, like `@` does.
- `/` on an empty line, in INSERT or NORMAL, opens the command line, like other chat programs.
  A line that can't be a command (`/shrug`, `/usr/bin`) turns back into text as you type and is
  sent as a message, rather than refused as an unknown command. `//` does the same straight
  away.
- `PgUp` / `PgDn` scroll the chat back and forward (`Ctrl+U` / `Ctrl+D` in NORMAL, `G` back to
  the newest), and the edge of the chat shows how many newer messages are below.
- In NORMAL, `s`, `c` and `C` show or hide the sidebar, the console and the chat, like `Ctrl+B`,
  `Ctrl+O` and `Ctrl+T`.
- `Tab` / `Shift+Tab` move between sections on the settings and help pages.
- `Ctrl+U` in INSERT deletes everything before the cursor.
- `NO_COLOR` limits the UI to bold, faint and reverse.
- `:install` saves your settings and signing key so they're there the next time chat starts.
  It asks first, and says what it leaves on disk, which shows chat is used on that machine. The
  settings you've changed go in `~/.config/chat/settings` (`%LOCALAPPDATA%\chat` on Windows),
  using the names `:set` uses, and the key goes in `~/.config/chat/key`. Both are sealed with
  one passphrase you choose (Argon2id, XChaCha20-Poly1305), which it asks for even with no key
  to save, and nothing in them is stored in the clear. A key installed later is sealed under
  the same passphrase without asking for it again. After that, a setting is saved when you
  change it, and chat starts on your sessions instead of the settings page. On startup it asks
  for the passphrase, or reads it from `CHAT_INSTALL_PASSWORD`, and says so if it's wrong.
  Command line options override what's saved, for that run. `:uninstall` deletes it all.
  Sessions, messages, peers and files are never saved.
- `:send` without a path opens a file browser to pick the file to offer.
- **Files and pictures**: `:send PATH` offers a file to the session. Nothing is transferred
  until someone fetches it with `:download N` (saved in `~/Downloads`), or, for a PNG or JPEG,
  `:show N`, which draws it in the chat under the line that offered it (`:hide N` hides it).
  `:files` lists them and `:cancel N` stops one. A file is only kept if its SHA-256 matches the
  offer. It's saved under a cleaned up name and never replaces an existing file. A picture
  that's shown is never written to disk. Files are sent in chat's regular slots, so they don't
  show up as a transfer on the network, but this is slow (about 25 KB a minute). **Fast file
  transfers** (`:set fastfiles on`, `--fast-files`) sends your files in quick bursts instead.
  Through the relays, where Tor and DHT members meet, a slot carries two chunks, since every
  relay event is sealed to the same size anyway. Fast transfers there go as often as the relays
  allow, about twice the normal rate. While a file downloads, a row under the line that offered
  it shows progress and roughly how long is left. Lost chunks are requested again once the rest
  of their run has arrived, a transfer continues through rekeys, and a fetch waits up to two
  minutes for a sender who drops out, then resumes if they come back.
  **File size limit** (`:set filelimit`, `--file-limit`, 8 MB by default) is the largest file
  fetched without adding `anyway`. Files can be up to 1 GB. Pictures are decoded by chat's own
  PNG and baseline JPEG decoders, which never hold the full size image in memory.
- `:changelog` (or `:news`) shows this changelog on its own page. It's built into chat so it
  works offline, and the Markdown is rendered: headings, bold, italic and `code`, links, nested
  lists, numbered items, quotes, code blocks and rules. In `--simple` it's printed.
- **Unread counts**: a session with messages you haven't seen shows how many next to its name
  in the sidebar. It's yellow with an `@` when one of them mentions you. With the sidebar
  hidden, the chat title shows how many new messages there are in other sessions. When you go
  back to a session, a `N new` line marks where the new messages start, until you leave it or
  send something.
- Your nick is highlighted wherever a message mentions it (`@nick`), not just the time next to
  it.
- While a peer's verify code hasn't been compared, the input box says your messages aren't
  being sent to them, and that `:verify NICK` shows the code. Before, only the console said so,
  once per message.

### Changed
- `just build test` names each binary after its build id, as `chat-<build id>-<system>-<arch>`.
  The build id is the source it was built from (`git describe`) and the build time in UTC, as
  shown by `chat --version`.
- The full-screen UI is drawn as one rounded frame split by lines, with each part titled in its
  border. There's a sidebar with the sessions, their peers and how the selected one reaches
  them, the console above the chat, and the input below it, outlined in the mode's colour. A
  bottom row shows the mode, whether you sign, your nick and what the keys do.
- The UI uses the terminal's own colours, so it matches the terminal's theme, light or dark,
  and follows it when it changes (if the terminal reports that). Peers' colours stay the same,
  but are adjusted to be readable on the terminal's background once the terminal has reported
  what that is.
- The chat is laid out in columns (time, nick, text). A run of messages from one peer in the
  same minute shows the time and nick once. A new session, one still connecting, and one with no
  messages yet say so, and what to do next.
- The peers list shows whether each peer is verified, and whether it's a modified client, in
  words while there's room. A lookalike's `#id` and its state are never cut off to fit its nick.
- The settings page lists its sections on the left, draws switches and choices as such, and
  shows each row's `:set` command under its help text. Text rows are edited in place. The
  settings page chat opens on ends with **Start chatting**.
- Release binaries are less than half the size: Linux is 1.3 MB instead of 2.9 MB, and Windows
  1.2 MB instead of 3.0 MB. libsecp256k1 keeps only its signing tables, Mbed TLS only the client,
  unused code in every dependency is left out at link time, and builds are stripped when
  linked.
- The full-screen UI sends nothing to the terminal while the screen hasn't changed. It used to
  redraw the whole screen every second, which was a constant stream of data over SSH.
- Every prompt now opens in a box over the screen, titled with what it's for and with its keys
  shown in the bottom edge. This covers a new session's password, the id and password to join
  one, a setting's new value, a native key's password, a pasted key, and `:install`'s
  questions. Before, these used the input box at the bottom, or a field in the row being
  changed.
- The settings page no longer has a Layout section. `Ctrl+B`, `Ctrl+O` and `Ctrl+T` (`s`, `c`
  and `C` in NORMAL) show and hide the sidebar, the console and the chat. `:set sidebar`,
  `console` and `chat` are gone.
- The input box grows one row at a time as the text wraps, up to six rows (fewer on a short
  terminal), instead of scrolling the line sideways.
- Direct routing is now called DHT routing: `--routing dht+nostr` and `--routing dht`, and
  `dht` on the settings page. `--routing direct+nostr` and `--routing direct` still work.
- A handshake takes a few seconds, and a re-handshake up to half a minute, since each step waits
  for a slot. Through the relays it takes about a minute. A rekey waits for any re-handshake
  still in progress, so two can't overlap (when they did, they broke each other's cookies), and
  a peer in the middle of one gets extra time before it's dropped for going quiet.
- Binaries from `just build test` say so: `testing <build id>` on the right of the console's top
  edge, and in `--version`.
- `just build` takes what to build: `just build linux` (was `just build-static`),
  `just build windows` or `win` (was `build-win`), `just build all` (was `all`) and
  `just build test [all|linux|windows]` (was `test-build`). Build directories keep their names.

## 0.3.1

### Changed
- Checking a peer's build no longer contacts GitHub. Each release binary carries a list of that
  release's binaries, signed with the release key, and sends it along with its hash; peers
  check the list against the release key built into chat. A build without a signed list, such
  as one from source, shows as modified. 0.3.0 peers are checked against 0.3.0's published
  hashes, which are built in. 0.3.0 shows newer peers' builds as unknown.
- `just release` signs the list and appends it to each binary before making `SHA256SUMS`, so it
  asks for the release key's password twice.
- `:peers` shows a build that checks out as "says official v0.3.1": a client altered to lie
  about its hash still passes, so that's only the peer's word.

## 0.3.0

### Added
- Sessions reach people direct with a Nostr relay fallback, direct only, or over Tor, chosen
  on the settings page chat opens on. `--routing direct+nostr|direct|tor` presets it.
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
- A settings page (`Ctrl+S` or `:set`): routing and each part of it, the relays and Tor
  ports, nickname, colour, signing identity, notifications, the network log, the UDP port for
  new sessions, and the layout. Routing toggles apply to open sessions at once. The mode and
  the Tor settings apply to sessions opened afterwards. Nothing is written to disk.
- `--nolan` turns off LAN discovery.
- `:net` reports port mapping, relay and Tor status, and IPv4 and IPv6 lookups separately.
- A fuzz target for relay JSON and UPnP gateway replies (`just fuzz json`).
- `just test-build [all|linux|windows]` builds the Linux and Windows binaries, or one of them,
  into `test-builds/<date>-<time>/`. It builds this system's natively and cross-builds the
  other with zig, then offers to run this system's when there's a terminal to ask on, passing
  it any further arguments.
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
- In Tor mode, `:update` and `--update` download through Tor's SOCKS port.
- Peers are reached on the best path that works: direct UDP, then Tor, then the relays. A
  worse path takes over only once the better one goes quiet. When a connected peer's hello
  arrives over a better path (UDP punched through, or a Tor stream, after the relays), chat
  answers with an encrypted frame on it, so both sides move there once it's proven.
- `--nodht` now turns off both DHTs.
- Candidate addresses stop getting hellos once their peer is connected.
- Mbed TLS 3.6.7 and libsecp256k1 0.7.1 are fetched and linked statically, and on Windows
  chat also links crypt32 (the system root certificates) and iphlpapi (the default gateway).
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
  session, and a **Done** button at the bottom (or `Esc`) goes on to the sessions.
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
- A second Ctrl+C, SIGTERM or SIGHUP soon after the first killed chat immediately, before
  sessions said bye, keys were wiped and the terminal was restored: the quit handler was reset
  after the first signal (glibc's `signal()` does that with `_POSIX_C_SOURCE`, and the Windows
  C runtime always does). The handler now stays in place.
- Cross builds passed a relative toolchain path to the dependencies' builds, which only
  worked with an existing build directory.
- A peer could join as `anon (unverified)` in the console while the sidebar showed its real
  nick as verified: the join was announced on the peer's first frame to open, and when the one
  carrying its nick and signing identity was lost or overtaken, another got there first. Now
  `* joining: peer ID` shows as soon as the connection is made, and the usual `joined` line
  follows once the nick and identity are in (or after 5 seconds, so nobody joins unannounced).
  The modified-client warning waits for the join.
- The version on the bottom bar could run into the prompt.

## 0.2.1

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

## 0.2.0

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

### Added
- `/port [N]` shows this session's UDP port, or moves the session to port `N` without
  leaving it (`0` picks a free one). Connected peers follow the new port automatically.
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
- `/peers` prints one line per peer.
- Releases are built and published with `just release`. CI builds every push, but doesn't
  publish releases.

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
