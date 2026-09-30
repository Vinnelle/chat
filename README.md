# chat

A serverless, end-to-end encrypted group chat for the terminal. No accounts, no servers —
peers find each other over the BitTorrent DHT (IPv4 and IPv6) and UDP broadcast (LAN), then
talk directly. When a NAT is in the way, chat asks the router to forward a port, and public
Nostr relays can carry the traffic. Or everything can go through Tor instead. Nothing
touches disk unless you ask.

> This README was written by AI.

> Eventually, I will rewrite this myself, when I have more time.

Written in C, cross-platform (Linux and Windows), and links only static crypto libraries.

## Security

Messages are encrypted with a hybrid, post-quantum construction:

- **X25519 + ML-KEM-768** key agreement (classical + post-quantum, hybrid)
- **XChaCha20-Poly1305** authenticated encryption
- a **per-message forward-secrecy ratchet**

A session's **id + password** together key both the encryption and the DHT lookup, so only
people who hold both can find and read each other. A blank password still encrypts.

**Compare verify codes.** The id and password only prove someone is a member of the room, so
any member could sit between two others and read what they say. When a peer joins, chat shows
a verify code to compare with them over another channel (in person, a call); it's the same on
both ends only if nobody is in between. Nothing you send reaches a peer until you've said it
matched with `:verify NICK ok` (`:verify NICK no` if it didn't: that peer then gets nothing).
Messages from a peer whose code you haven't compared show `(code not compared)`, and the
sidebar says `compare code`. If the peer signs with an identity (below), its code needs
comparing once per session: back with a fresh handshake signed by the same key, it's trusted
again. **Compare verify codes** on the settings page (`:set verify optional`,
`--verify-optional`) sends to everyone, compared or not.

Optional **identity signing** lets peers verify who they're talking to. Choose it under
**Signing identity** on the settings page (or `:set sign`), or with `--identity`:

- `age` — an Ed25519 identity made from a password, with an `age1...` recipient string others
  can `age -r` encrypt files to (settings shows it and copies it to the clipboard)
- `pgp` — the same as a PGP key; settings copies its public key for others to `gpg --import`
- `age:KEYFILE` — sign with your own AGE key, as `age-keygen` writes it; your `age1...`
  recipient stays the same
- `pgp:KEYFILE` — sign with an unencrypted armored EdDSA secret key exported from real gpg

In settings, the picker lists **Off**, then **AGE** and **PGP**, each with **Native** (a key
made there), a key file (picked in a browser) and a key paste. A key of your own is never
written to disk.

A **Native** key asks for a password (`--identity age` or `pgp` asks at startup, or takes it
from `CHAT_SIGN_PASSWORD`). The key is made from that password and this OS install's machine
id (`/etc/machine-id`, or `MachineGuid` on Windows) with Argon2id, so the same password on
the same device and OS always makes the same key and fingerprint, and nothing is stored.
**Always use the same password if you want to keep an established signing identity**: a
different password, or a typo, makes a different key, and peers see a new fingerprint. The
same password makes the same key whether you pick AGE or PGP. Reinstalling the OS changes the
machine id, and with it the key.

The machine id isn't secret, since any program on the device can read it, so the password is
what protects the key. Anyone who has your machine id can guess passwords against the
public key you show peers, so use a long one. A blank password makes a new random key that
lasts until chat exits instead.

`:verify NICK` shows a peer's verify code and identity fingerprint to compare out-of-band.
Identity fingerprints and the verify codes `:peers` shows are 128 bits, in groups of four hex
digits; 0.3.1 and earlier show the first 16 digits of the same codes.

Each peer rekeys every few minutes. Before it does, it announces its new key over the current
encrypted session, so a room member sitting between two peers can't swap in its own key at a
rekey. If a peer drops and comes back, chat tells you its verify code changed.

**Modified clients.** Each client tells its peers, over the encrypted session, which version it
runs and the SHA-256 of its own executable. That hash is keyed with both peers' session ids, so
a build that isn't a release can't be recognised from one session or peer to the next. Each
release binary also carries a list of that release's binaries, signed with the release key, and
sends it along. Peers check the list against the release key built into chat, and look for the
hash in it. Nothing is downloaded and nobody else is asked, so the check shows no one that you
met a peer. A peer whose hash isn't in its release's list, or that has no signed list (a build
from source, for one), is marked **modified**: a warning follows its join, the sidebar shows
`modified` next to its name, and `:peers` says `modified client`. One that passes shows as
`says official`, since that is only its word.

> This is not perfect as a client can be modified to send the correct SHA and will be marked as unmodified. I am working on a better solution for this

0.3.0 sent its hash without a list. Chat has 0.3.0's published hashes built in and checks those
peers against them. 0.3.0 itself can't read the list, so it shows newer peers' builds as
unknown.

Keys, and the conversation as it's shown, are locked in memory so they aren't written to swap,
as far as the system's memory-lock limit allows. Core dumps are off, and on Windows a crash ends
chat before Windows Error Reporting can dump its memory. Desktop notifications only say that a
message came, unless **Notification preview** (`:set preview nick` or `message`) lets them
show who sent it, or who and what they said. Desktops keep notifications (Windows writes them
to disk), so that's off by default, and a notification never names the session: its id is all
it takes to join one with a blank password.

> **Note:** the cryptography here has not been independently audited.

## Routing

chat opens on its settings page, and **Routing** heads it. `--routing` presets it, and
`Ctrl+S` or `:set` brings the page back later.

1. **DHT + Nostr fallback** (recommended). Peers talk over UDP, straight to each other.
2. **DHT only.** The same without relays. Some peers behind strict NATs won't connect, and
   neither can members who use Tor.
3. **Tor.** Onion services, plus the Nostr relays reached through Tor, so members who use
   DHT routing can still meet you. Nothing else touches the network.

DHT routing uses these, and each one can be turned off:

| Part | What it does | Who sees what |
| --- | --- | --- |
| BitTorrent DHT (IPv4) | finds peers on the internet | DHT nodes see your IP and port next to a lookup key only room members can compute but anyone who sees it can look up for the rest of the hour: see below |
| IPv6 DHT ([BEP 32](https://www.bittorrent.org/beps/bep_0032.html)) | the same on the IPv6 DHT, where there's usually no NAT to punch through | as above, with your IPv6 address, which often stays the same longer than an IPv4 one |
| Router port mapping | asks the router (PCP, NAT-PMP or UPnP-IGD) to forward the session's UDP port, so peers behind NATs that can't be hole-punched still get in; removed when the session ends | your router, which may log it, and any device on the LAN that asks it |
| LAN discovery | an encrypted broadcast beacon on the local network, to a UDP port of the room's own (made from its id and password, 49152-65535) | the local network sees that something broadcasts, and the same port for every member of the room |
| Nostr relay fallback | public relays carry the traffic when UDP can't get through | the relays: see below |

Chat prefers direct UDP. A peer moves to the relays only while UDP to it stays quiet, and
moves back as soon as UDP works again. With DHT routing chat goes to the relays only while
it needs them: until someone is reached, while a peer is reached only through them, or while
one's UDP has gone quiet, and it leaves them a minute after. Tor members meet DHT members
only on the relays, so a room whose DHT members all reach each other can't be found by one;
**Nostr relays** set to `always` (`:set nostr always`, `--nostr-always`) keeps them connected.

**What the network sees of UDP.** Everything chat sends over UDP is masked with a key made from
the session id and password, so to anyone else every datagram is random bytes: no ratchet
counter that could follow a peer from one address to the next, no header on the pieces of a
handshake, nothing the same from one packet to the next. Every datagram is the same size, 1004
bytes: a session frame fills one, and a handshake goes in pieces padded to it. And every
datagram to a connected peer goes in a slot of that peer's, one every 1.5 to 1.9 seconds,
whether or not there's anything to say: a message, its ack, a message passed on to others and
a re-handshake all wait for one, so when datagrams go and how many says nothing about when
anyone typed. What still shows is the addresses and ports, that two addresses exchange a
steady stream of equal datagrams (which a determined observer can recognise as chat), when a
session starts and ends, a few seconds of handshake pieces when someone joins, and a
re-handshake every five minutes or so. The BitTorrent DHT's own messages are ordinary DHT
traffic, from the same port. 0.3.1 and earlier sent other sizes, so they and this version
can't reach each other over UDP; they still meet through the Nostr relays, or over Tor.

**What the DHT sees.** Each lookup asks nodes for peers under the hour's lookup key, and
announces this session's address under it. Only room members can compute the key, but a node
that sees it can ask for it too, for the rest of the hour, and get the addresses announced
under it. The key changes every hour, and so does the node id chat asks under, so nothing in
the DHT's messages ties one hour's lookups to the next; the address they come from still does.
Queries say they're from a read-only node (BEP 43). A lookup starts from nodes that answered
before, and asks the four bootstrap servers (router.bittorrent.com, dht.transmissionbt.com,
router.utorrent.com, dht.libtorrent.org) only while it knows fewer than eight.

**What a Nostr relay sees.** Each datagram is one ephemeral event, so relays pass it on
without storing it. Every event is signed with a key made for that event alone, has a random
ephemeral kind and a timestamp a few seconds off, and carries one tag. The tag changes every
ten minutes, and only room members can compute it. The content is always the same size: the
sender, the recipient, the datagram and random padding, sealed together with XChaCha20-Poly1305
under a key derived from the session id and password, with a fresh nonce each time. So a relay
can't tell which events come from the same person, who they're for, or what kind of message
they hold. Each ten minutes' tag has connections of its own: a new one to each relay, under a
new subscription id and, through Tor, a new circuit, asking for that tag alone. It opens a minute
or two before the ten minutes start and closes a minute or two after they end, so clocks can
differ that much. A relay still sees the address each connection comes from (the same one each
ten minutes, unless it's a Tor exit), when events come and go, and the
tag, which every member of the room asks for. Events have a size and shape of their own, so
anyone who can subscribe to a relay can tell chat's events from others, and count them per tag.
The defaults are `wss://relay.primal.net`, `wss://nostr.mom` and `wss://relay.nostr.net`.
`--relay` or the settings page picks others. A relay that rate-limits gets fewer events. A
relay whose policy refuses throwaway keys (web of trust, payment, proof of work) is only read
from.

**Tor** needs tor installed (Arch: `sudo pacman -S tor`, Debian/Ubuntu: `sudo apt install
tor`, Windows: the Tor Expert Bundle) or Tor Browser. Nothing else needs setting up. chat picks
the tor to use like this (`--tor-launch`, or **Start chat's own tor** in settings):

- **when none is running** (the default): chat first looks for a tor that's already running,
  such as the system service on 9050/9051 or Tor Browser on 9150/9151, whose control port lets
  it log in. It logs in with tor's cookie file if it can read it (SAFECOOKIE only, where tor
  proves it read the cookie before chat shows anything), a password from the settings page, or
  no login if tor allows that. Such a tor is the better one to use. It keeps its entry
  guards from run to run, and any bridges its torrc sets up. If there's none, chat starts a tor
  of its own.
- **always**: chat's own tor every time, kept apart from any other. It picks new entry guards
  each run and ignores your torrc, bridges included.
- **never**: only a tor that's already running.

chat's own tor is the program found on `PATH` or in the usual folders, or given with
`--tor-path`. Only root or you may be able to change it, and chat refuses one anyone else
could have swapped. It runs with an empty configuration, so nothing from `/etc/tor/torrc`
applies. Its SOCKS and control ports are random ports on 127.0.0.1, and its control port only
takes the cookie in its own folder. That folder holds its data and log. On Linux it lives
under `$XDG_RUNTIME_DIR`, which is only yours and kept in memory; otherwise it's a new 0700
folder in `/tmp`, or your temporary folder on Windows. chat deletes the folder when it stops
tor. If chat crashes, tor notices and quits within seconds. On Windows a job object ends it at
once. The next chat deletes the folder the crash left. A fresh private tor downloads the Tor
network's directory each time, so it can take a minute or more before it connects.

> **Note:** Tor and DHT members of a room can only reach each other through the Nostr
> relays, so both need them on: a DHT member with option 1 (DHT + Nostr fallback), and a
> Tor member with the relays left on, as they are by default. With option 2 (DHT only) or
> `--nonostr` on either side, the room splits in two, and neither half sees the other.

**Tor and DHT members in one room** can't reach each other over onion services or UDP. They
meet on the Nostr relays: a Tor session connects to the same relays as DHT ones, but only
through Tor's SOCKS port. Each relay gets a circuit of its own, and Tor looks the relay's name
up at the exit, so nothing asks local DNS. Until chat has a tor, it connects to no relay at all.
The relays see a Tor exit, never your address, and the events look the same whoever sends them.
Between two Tor members, chat moves the traffic to their onion services as soon as those
connect, and keeps the relays as a fallback. It turns the relays off with the **Nostr relays**
setting (or `--nonostr`). Then only other Tor members can reach you, and chat says so if nobody
answers.

Each session publishes an onion service of its own and one of six room onion services, whose
keys come from the session id and password. Joiners knock on those
to find the room, then connect to each member's own onion service. All of them go away when
the session ends. Each session's streams get their own Tor circuits. In Tor mode chat never
sends UDP, never connects anywhere directly, and never resolves an `.onion` name, or a relay's,
through DNS. Connecting takes a minute or two
while the onion services are published and found.

Settings last until chat exits. Like everything else, they're never written to disk.

## Download

Prebuilt Linux and Windows x86_64 binaries are on the
[releases page](https://github.com/Vinnelle/chat/releases), with a `SHA256SUMS` file and its
[minisign](https://jedisct1.github.io/minisign/) signature. Check the signature against
[`minisign.pub`](minisign.pub), then the hashes:

```sh
minisign -Vm SHA256SUMS -p minisign.pub
sha256sum -c --ignore-missing SHA256SUMS
```

## Installation

chat is deliberately not packaged or installable. The point is to leave no trace: apart
from the executable itself, nothing should persist on the machine. A package manager would
record the install and add files outside your control, so no packages (AUR or otherwise)
are provided.

Where you keep the executable is up to you. The recommended place is a user-owned folder
on your `PATH`, such as `~/.local/bin`, because updating replaces the executable in place
and needs write access to its folder. Some systems already have an unrelated program called
`chat` (for example the modem dialer from `ppp`), so rename the file if it would clash:

```sh
install -Dm755 chat-linux-x86_64 ~/.local/bin/chat   # or another name, e.g. ~/.local/bin/e2chat
```

If you put it in a system folder such as `/usr/local/bin` or `/usr/bin` instead, you will
most likely need root to update it:

```sh
sudo chat --update
```

This may differ on your system, and it doesn't matter if you never intend to update.

Opt-in persistence may be added later, for example:

- **chat history**, with other members of the session told that you are saving it
- **config**, so options like nick and colour survive a restart

Both would stay off unless you turn them on.

## Build

Requires CMake ≥ 3.15 and a C compiler. libsodium (1.0.20), liboqs (0.16.0, ML-KEM-768
only), Mbed TLS (3.6.7, for the relays' `wss://` connections) and libsecp256k1 (0.7.1, for
Nostr's Schnorr signatures) are fetched and built statically by CMake. TLS certificates are
checked against the system's root store. Mbed TLS is configured as a TLS client with
forward-secret key exchanges only ([`cmake/mbedtls-config.h`](cmake/mbedtls-config.h)), and
libsecp256k1 keeps only what signing needs, since chat never verifies Nostr signatures.

```sh
cmake -B build
cmake --build build
./build/chat --nick you
```

### Windows cross-build

`cmake/zig-*` wrap [zig](https://ziglang.org/) as a cross toolchain (its bundled
mingw-w64), so libsodium's autotools and liboqs's CMake share one compiler path. With
`zig` on `PATH`:

```sh
cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/zig-windows.cmake
cmake --build build-win
```

### With just

A [`justfile`](justfile) wraps the commands above:

```sh
just build              # native binary in build/
just build-win          # Windows binary in build-win/ (needs zig)
just run --nick you     # build, then run
just test-build         # Linux and Windows binaries in test-builds/<date>-<time>/, offer to run this system's
just test-build linux   # the same for one system (or: windows); the other system's needs zig
just clean              # remove build directories
```

Test builds are named `chat-<build id>-<system>-<arch>`, such as
`chat-v0.3.1-3-g1a2b3c4-20260929-141502-linux-x86_64`. The build id is the source it came from
(`git describe`) and when it was built, in UTC, the same two things `chat --version` prints, so
a copy taken to another machine still says which build it is.

### Tests

`tests/` runs real sessions against each other over an in-memory network: handshake, the
verify-code gate, message delivery with a lost packet, rekey (and a message lost just as the
peer rekeys), replayed hellos and junk from outside the room, a third peer joining, that nothing
goes over UDP unmasked, that every datagram is one cell sent in a slot however many messages
are sent, and that the DHT asks as a read-only node and stops starting from the bootstrap
servers once it knows enough nodes. It also checks the parsers for what relays, routers and Tor send, the hourly DHT
keys, and that key files are only read from regular files. The fuzz targets (libFuzzer, so
clang) cover bencode and DHT replies (IPv4 and IPv6), relay JSON and UPnP gateway replies,
PGP and AGE key import, text cleaning and the input line, and everything a session receives,
including messages from a room member or a connected peer, and datagrams that unmask to
anything at all. GitHub Actions runs the engine test, and each fuzz target for a minute, on
every push and pull request.

```sh
just test               # build and run the engine test
just test -v            # the same, printing every session line and every check before the summary
just fuzz engine 600    # fuzz one target (bencode, json, pgp, text, engine) for 600 seconds
```

### Releases

```sh
just dist               # static musl Linux + Windows binaries and SHA256SUMS in dist/ (needs zig)
just release            # release CHANGELOG.md's Unreleased section: tag, dist, sign, publish (needs minisign, gh)
just release 1.0.0      # the same, as a version other than the next patch
```

Changes go under `## Unreleased` at the top of [CHANGELOG.md](CHANGELOG.md). `just release`
turns that heading into the new version, sets the version in `CMakeLists.txt`, commits both as
`Release VERSION` and tags `vVERSION`. It pushes the branch and tag only after `SHA256SUMS` is
signed; if a step fails, run it again and it carries on from the tag.

It signs twice, so minisign asks for the key's password twice. First it signs the list of the
release's binaries (`dist/BUILDS`) and appends it to each binary, for peers to check builds
with. Then it signs `SHA256SUMS` of the binaries as published, list included, for downloads and
`:update`.

Releases are signed offline with the release key, never in CI, so someone who takes over the
GitHub account still can't publish an update that chat will install. `just keygen` makes the
key: commit `minisign.pub`, and keep the secret key backed up and off GitHub.

## Usage

```
chat [--nick NAME] [--colour NAME|#HEX] [--identity age|pgp[:KEYFILE]] [--simple]
     [--routing dht+nostr|dht|tor] [--nodht] [--noipv6] [--nolan]
     [--noportmap] [--nonostr] [--nostr-always] [--relay wss://HOST ...]
     [--tor-socks HOST:PORT] [--tor-control HOST:PORT] [--verify-optional]
     [--session ID --port UDP_PORT --peer HOST:PORT ...]
```

On a real terminal, `chat` opens a full-screen UI. On the left, a sidebar lists your sessions

> NOTE: This TUI was heavily assisted by UI, as I have mentioned across most my projects, I hate, and suck at, UI / Front-End development. If any front-end devs would like to improve the functionality, performance, and/or aesthetic of this, be my guest!

(switch with Tab / Shift+Tab), the peers in the selected one with how each is verified, and how
that session reaches them: route, port or tor, relays, port mapping, DHT and traffic. The
selected session's chat fills the rest, with its console over it, and you type in the box at
the bottom.

It draws in the terminal's own colours (its foreground, background and 16-colour palette), so
it takes on whatever theme the terminal has, light or dark, and follows it when it changes.
Peers' colours are exact; chat asks the terminal for its background colour and eases any that
wouldn't read on it. `NO_COLOR` keeps it to bold, faint and reverse.

It starts on the settings page, so routing, nickname, colour, signing identity and the rest
are set up in one place. **Start chatting** at the bottom (or `Esc`) goes on to your sessions.
Nothing reaches the network before that: no tor is looked for or started, and no `--peer` name
is looked up (in Tor mode it never is, since the lookup would go around Tor).

| Key | Action |
| --- | --- |
| `Ctrl+N` | create a new session (asks for a password) |
| `Ctrl+J` | join an existing session (id, then password) |
| `Tab` / `Shift+Tab` | next / previous session (`j` / `k` in NORMAL too) |
| `PgUp` / `PgDn` | scroll the chat back / forward (`Ctrl+U` / `Ctrl+D` in NORMAL, `G` the newest) |
| `Ctrl+B` / `Ctrl+O` / `Ctrl+T` | toggle sidebar / console / chat pane (`s` / `c` / `C` in NORMAL) |
| `Ctrl+S` | settings |
| `F1` | every key and command on one page (`?` in NORMAL, and `:help`, too) |
| `Ctrl+C` | quit (every session leaves cleanly first) |

The row at the bottom is the same on every screen: a chip saying where you are (`INSERT`,
`NORMAL`, `COMMAND`, `SETTINGS`, …), whether you sign, your nick, the reply to what you just
did (until your next key), and what the keys do there.

The input line is a small vim. It starts in NORMAL (`h`/`l` move, `0`/`$` ends, `x` delete,
`j`/`k` switch session, `s`/`c`/`C` toggle the sidebar/console/chat); `i`/`a`/`I`/`A` go to INSERT, where Enter sends, `Ctrl+W` deletes the
word before the cursor and `Ctrl+U` everything before it, and `Esc` goes back to NORMAL. The input box's
border takes the mode's colour. Password and session-id prompts are plain fields: `Enter`
confirms, `Esc` cancels, and your draft comes back afterwards.

Typing `@` and the start of a nick shows the rest of the name dimmed; `Tab` completes it.

`/` on an empty line, in INSERT or NORMAL (or `:` in NORMAL), opens the command line, with a
menu of the commands that match what's typed. After `set ` it lists the settings with their
values now, and after `set NAME ` the values that setting takes. After a command that takes a
nick (`verify `) it lists the peers online whose nick starts with what's typed, the rest shown
dimmed as with `@`. `Up` / `Down` pick from the menu, `Tab` completes, `Enter` runs (a command
name only started runs what the menu has picked, so `/se` runs `/set`) and `Esc` goes back. A line started with `/` that can't be a command (`/shrug`, `/usr/bin`)
turns back into text as you type it, and `Enter` sends it like any other message; `//` does the
same straight away. Anything else is sent as a message. `:help` opens a page with every key and
command; `Enter` on a command there puts it on the command line.

| Command | Action |
| --- | --- |
| `:new`, `:join` | create / join a session (same as `Ctrl+N` / `Ctrl+J`) |
| `:quit` (`:q`) | leave this session; quits when none is open |
| `:quitall` (`:qa`) | leave every session and quit |
| `:set [NAME [VALUE]]` | change a setting (see below); alone, opens the settings page (`Ctrl+S`) |
| `:verify NICK [ok\|no]` | show a peer's verify code and identity fingerprint; `ok` once the code matches theirs, `no` if it doesn't |
| `:peers` | who is online, with verify codes and builds |
| `:net` | network report and diagnosis |
| `:port [N]` | show or move this session's UDP port (`0` picks a free one) |
| `:copyid` | copy the session id to the clipboard |
| `:update` | install the latest release |

### Settings

Every setting is a row on the settings page, and applies at once to every open session and the
ones you open after. `:set NAME VALUE` sets a row without opening the page, and `:set NAME`
opens the page on that row. The command line's menu lists the names after `:set `, and the
values after a name. Under each row's help, the page shows the `:set` that does the same.

| Name | Values |
| --- | --- |
| `routing` | `dht`, `tor` |
| `dht`, `dht6`, `portmap`, `lan` | `on`, `off` |
| `nostr` | `on` (only while needed), `always`, `off` |
| `relays` | up to 6 `wss://` URLs |
| `torlaunch` | `auto`, `always`, `never` |
| `torpath`, `torsocks`, `torcontrol` | a path, `HOST:PORT`, `HOST:PORT` |
| `torpassword` | only on the page, where it's hidden |
| `nick`, `colour` | a name; a colour name or `#RRGGBB` |
| `sign` | `off`, or an `age` or `pgp` key made from a password typed on the page; a key file or pasted key is chosen there too |
| `verify` | `required` (nothing reaches a peer until you've compared its code), `optional` |
| `notify` | `all`, `mentions`, `none` |
| `preview` | what a notification shows: `off` (only that a message came), `nick` (who from), `message` (who, and what); never the session |
| `net` | `normal`, `verbose` (every handshake packet, relay and Tor event) |
| `port` | the UDP port for new sessions (`0` picks a free one) |
| `sidebar`, `console`, `chat` | `on`, `off` |

The settings page, the pages under it (the signing identity picker and the key file browser)
and the help page all take the same keys: `j`/`k` move, `g`/`G` go to the ends, `Tab` /
`Shift+Tab` to the next / previous section, `Enter` chooses, `h`/`l` change a value or go out of
/ into a page, `Esc` goes back and `q` closes the page.

With `--simple`, `:set` covers `nick`, `colour`, `notify`, `preview` and `net`.

### Updating

`:update` inside chat, or `chat --update` from the shell without opening chat, checks the
[latest GitHub release](https://github.com/Vinnelle/chat/releases/latest). If it is newer
than the running build, chat checks that the release's `SHA256SUMS` carries a valid signature
from the release key built into chat, downloads the binary for your platform, checks its
SHA-256 against `SHA256SUMS`, and replaces the executable in place. A release without a valid
signature is refused. Restart chat to
run the new version. `chat --update` exits with status 1 if the update failed. It needs `curl` (on `PATH` on Linux; on Windows, the one built into Windows 10+ in `System32`) and
write access to the folder that holds the executable.

### Options

| Option | Meaning |
| --- | --- |
| `--nick NAME` | Display name (random `swift-otter42`-style if omitted) |
| `--colour NAME\|#HEX` | Display colour (random by default; `--color` too) |
| `--routing` | `dht+nostr`, `dht` or `tor` (`direct+nostr` and `direct` still work), preset on the settings page (see [Routing](#routing)) |
| `--nodht` | Skip the BitTorrent DHT (IPv4 and IPv6) |
| `--noipv6` | Skip the IPv6 DHT only |
| `--nolan` | Skip LAN broadcast discovery |
| `--noportmap` | Don't ask the router to forward a port |
| `--nonostr` | No Nostr relay fallback |
| `--nostr-always` | Stay on the relays all the time, not only while they're needed |
| `--verify-optional` | Send to peers whose verify code you haven't compared |
| `--relay URL` | A Nostr relay (`wss://...`) to use instead of the defaults; up to 6 |
| `--tor-launch auto\|always\|never` | Which tor Tor mode uses: a running one if possible, else chat's own (`auto`); always chat's own; or only a running one |
| `--tor-path PATH` | The tor program chat starts (default: `tor` on `PATH` or in the usual folders) |
| `--tor-socks`, `--tor-control` | Where to look for a running tor's SOCKS and control ports (`HOST:PORT`) |
| `--identity ...` | `age` or `pgp` for a key made from a password (asked for, or `CHAT_SIGN_PASSWORD`), or `age:KEYFILE` or `pgp:KEYFILE` for your own (see [Security](#security)) |
| `--simple` | Plain `[HH:MM] ...` lines, one session, stdin, `:name` runs a command — the automatic fallback when stdout isn't a tty |
| `--session ID` | Join a session at startup (with `--port`, `--peer`) |
| `--update` | Install the latest release and exit, without opening chat (see [Updating](#updating)) |
| `--version` | Print the version and exit |

## License

[GPL-3.0-only](LICENSE). Copyright © 2026 finlay@tuta.com.
