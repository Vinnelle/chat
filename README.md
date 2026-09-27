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

Optional **identity signing** lets peers verify who they're talking to:

- `native` — a fresh Ed25519 identity
- `age` — same, plus an `age1...` recipient string others can `age -r` encrypt files to
- `pgp:KEYFILE` — sign with an unencrypted armored EdDSA secret key exported from real gpg

Use `/verify NICK` to compare a peer's identity out-of-band.

Each peer rekeys every few minutes. Before it does, it announces its new key over the current
encrypted session, so a room member sitting between two peers can't swap in its own key at a
rekey. If a peer drops and comes back, chat tells you its verify code changed.

> **Note:** the cryptography here has not been independently audited.

## Routing

When chat starts, it asks how sessions should reach people. `--routing` answers ahead of
time, and the settings page (`Ctrl+S` or `/settings`) changes it later.

1. **Direct + Nostr fallback** (recommended). Peers talk over UDP, straight to each other.
2. **Direct only.** The same without relays. Some peers behind strict NATs won't connect, and
   neither can members who use Tor.
3. **Tor.** Onion services, plus the Nostr relays reached through Tor, so members who use
   direct routing can still meet you. Nothing else touches the network.

Direct routing uses these, and each one can be turned off:

| Part | What it does | Who sees what |
| --- | --- | --- |
| BitTorrent DHT (IPv4) | finds peers on the internet | DHT nodes see your IP next to a lookup key only room members can compute |
| IPv6 DHT ([BEP 32](https://www.bittorrent.org/beps/bep_0032.html)) | the same on the IPv6 DHT, where there's usually no NAT to punch through | as above |
| Router port mapping | asks the router (PCP, NAT-PMP or UPnP-IGD) to forward the session's UDP port, so peers behind NATs that can't be hole-punched still get in; removed when the session ends | your router, which may log it |
| LAN discovery | an encrypted broadcast beacon on the local network | the local network sees that something broadcasts |
| Nostr relay fallback | public relays carry the traffic when UDP can't get through | the relays: see below |

Chat prefers direct UDP. A peer moves to the relays only while UDP to it stays quiet, and
moves back as soon as UDP works again.

**What a Nostr relay sees.** Each datagram is one ephemeral event, so relays pass it on
without storing it. Every event is signed with a key made for that event alone, has a random
ephemeral kind and a timestamp a few seconds off, and carries one tag. The tag changes every
ten minutes, and only room members can compute it. The content is always the same size: the
sender, the recipient, the datagram and random padding, sealed together with XChaCha20-Poly1305
under a key derived from the session id and password, with a fresh nonce each time. So a relay
can't tell which events come from the same person, who they're for, or what kind of message
they hold. It can't link a room's traffic from one ten minutes to the next. It still sees
your IP address, when you send and receive, and which tags your connection asks for. The
defaults are `wss://relay.primal.net`, `wss://nostr.mom` and `wss://relay.nostr.net`.
`--relay` or the settings page picks others. A relay that rate-limits gets fewer events. A
relay whose policy refuses throwaway keys (web of trust, payment, proof of work) is only read
from.

**Tor** needs tor installed (Arch: `sudo pacman -S tor`, Debian/Ubuntu: `sudo apt install
tor`, Windows: the Tor Expert Bundle) or Tor Browser. Nothing else needs setting up. chat picks
the tor to use like this (`--tor-launch`, or **Start chat's own tor** in settings):

- **when none is running** (the default): chat first looks for a tor that's already running,
  such as the system service on 9050/9051 or Tor Browser on 9150/9151, whose control port lets
  it log in. It logs in with tor's cookie file if it can read it, a password from the settings
  page, or no login if tor allows that. Such a tor is the better one to use. It keeps its entry
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

> **Note:** Tor and direct members of a room can only reach each other through the Nostr
> relays, so both need them on: a direct member with option 1 (direct + Nostr fallback), and a
> Tor member with the relays left on, as they are by default. With option 2 (direct only) or
> `--nonostr` on either side, the room splits in two, and neither half sees the other.

**Tor and direct members in one room** can't reach each other over onion services or UDP. They
meet on the Nostr relays: a Tor session connects to the same relays as direct ones, but only
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
checked against the system's root store.

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

### Tests

`tests/` runs real sessions against each other over an in-memory network: handshake, message
delivery with a lost packet, rekey, junk from outside the room, and a third peer joining. It
also checks the parsers for what relays, routers and Tor send. The fuzz targets (libFuzzer,
so clang) cover bencode and DHT replies (IPv4 and IPv6), relay JSON and UPnP gateway replies,
PGP key import, text cleaning and the input line, and everything a session receives,
including messages from a room member or a connected peer.

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

Releases are signed offline with the release key, never in CI, so someone who takes over the
GitHub account still can't publish an update that chat will install. `just keygen` makes the
key: commit `minisign.pub`, and keep the secret key backed up and off GitHub.

## Usage

```
chat [--nick NAME] [--colour NAME|#HEX] [--identity native|age|pgp:KEYFILE] [--simple]
     [--routing direct+nostr|direct|tor] [--nodht] [--noipv6] [--nolan] [--noportmap]
     [--nonostr] [--relay wss://HOST ...] [--tor-socks HOST:PORT] [--tor-control HOST:PORT]
     [--session ID --port UDP_PORT --peer HOST:PORT ...]
```

On a real terminal, `chat` opens a full-screen UI: a session list on the left (switch with
Tab / Shift+Tab), the selected conversation and its console filling the rest, an input line
at the bottom.

| Key | Action |
| --- | --- |
| `Ctrl+N` | create a new session (asks for a password) |
| `Ctrl+J` | join an existing session (id, then password) |
| `Ctrl+W` | leave the current session |
| `Tab` / `Shift+Tab` | next / previous session |
| `Ctrl+B` / `Ctrl+O` / `Ctrl+T` | toggle sidebar / console / chat pane |
| `Ctrl+S` | settings |
| `Ctrl+C` | quit (every session leaves cleanly first) |

The input line is a small vim. It starts in INSERT, where Enter sends. `Esc` drops to NORMAL
(`h`/`l` move, `0`/`$` ends, `x` delete, `i`/`a`/`I`/`A` back to INSERT); `:` opens
COMMAND (`Tab` completes, `Enter` runs, `Esc` cancels). Password and session-id prompts are
plain fields: `Enter` confirms, `Esc` cancels, and your draft comes back afterwards.

Typing `@` and the start of a nick shows the rest of the name dimmed; `Tab` completes it.

Every command works as `/name` in INSERT or `:name` in COMMAND. `/help` lists them all.

| Command | Action |
| --- | --- |
| `/new`, `/join` | create / join a session (same as `Ctrl+N` / `Ctrl+J`) |
| `/quit` (`/q`) | leave this session; quits when none is open |
| `/quitall` (`/qa`) | leave every session and quit |
| `/nick [NAME]` | show or change your nickname in every session |
| `/colour [NAME\|#HEX]` | show or change your colour |
| `/sign` | set up, replace or turn off your signing key |
| `/verify NICK` | show a peer's identity fingerprint |
| `/peers` | who is online, with verify codes |
| `/notify [all\|mentions\|none]` | show or change desktop notifications |
| `/net`, `/netverbose [on\|off]` | network report / per-packet logging |
| `/settings` | routing, identity, notifications and layout (same as `Ctrl+S`) |
| `/port [N]` | show or change this session's UDP port (`0` picks a free one) |
| `/copyid` | copy the session id to the clipboard |
| `/update` | install the latest release |

### Updating

`/update` inside chat, or `chat --update` from the shell without opening chat, checks the
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
| `--routing` | `direct+nostr`, `direct` or `tor`, instead of asking at startup (see [Routing](#routing)) |
| `--nodht` | Skip the BitTorrent DHT (IPv4 and IPv6) |
| `--noipv6` | Skip the IPv6 DHT only |
| `--nolan` | Skip LAN broadcast discovery |
| `--noportmap` | Don't ask the router to forward a port |
| `--nonostr` | No Nostr relay fallback |
| `--relay URL` | A Nostr relay (`wss://...`) to use instead of the defaults; up to 6 |
| `--tor-launch auto\|always\|never` | Which tor Tor mode uses: a running one if possible, else chat's own (`auto`); always chat's own; or only a running one |
| `--tor-path PATH` | The tor program chat starts (default: `tor` on `PATH` or in the usual folders) |
| `--tor-socks`, `--tor-control` | Where to look for a running tor's SOCKS and control ports (`HOST:PORT`) |
| `--identity ...` | `native`, `age`, or `pgp:KEYFILE` (see [Security](#security)) |
| `--simple` | Plain `[HH:MM] ...` lines, one session, stdin — the automatic fallback when stdout isn't a tty |
| `--session ID` | Join a session at startup (with `--port`, `--peer`) |
| `--update` | Install the latest release and exit, without opening chat (see [Updating](#updating)) |
| `--version` | Print the version and exit |

## License

[GPL-3.0-only](LICENSE). Copyright © 2026 finlay@tuta.com.
