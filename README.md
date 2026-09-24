# chat

A serverless, end-to-end encrypted group chat for the terminal. No accounts, no servers —
peers find each other over the BitTorrent DHT (internet) and UDP broadcast (LAN), then
talk directly. Nothing touches disk unless you ask.

> This README was written by AI.

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

> **Note:** the cryptography here has not been independently audited.

## Download

Prebuilt Linux and Windows x86_64 binaries are on the
[releases page](https://github.com/Vinnelle/chat/releases), with a `SHA256SUMS` file:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

## Build

Requires CMake ≥ 3.15 and a C compiler. libsodium (1.0.20) and liboqs (0.16.0, ML-KEM-768
only) are fetched and built statically by CMake.

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

## Usage

```
chat [--nick NAME] [--colour NAME|#HEX] [--nodht] [--identity native|age|pgp:KEYFILE]
     [--simple] [--session ID --port UDP_PORT --peer HOST:PORT ...]
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
| `/copyid` | copy the session id to the clipboard |
| `/update` | install the latest release |

### Updating

`/update` checks the [latest GitHub release](https://github.com/Vinnelle/chat/releases/latest).
If it is newer than the running build, chat downloads the binary for your platform, checks
its SHA-256 against the release's `SHA256SUMS`, and replaces the executable in place.
Restart chat to run the new version. It needs `curl` on `PATH` (built into Windows 10+) and
write access to the folder that holds the executable.

### Options

| Option | Meaning |
| --- | --- |
| `--nick NAME` | Display name (random `swift-otter42`-style if omitted) |
| `--colour NAME\|#HEX` | Display colour (random by default; `--color` too) |
| `--nodht` | Skip internet discovery, LAN broadcast only |
| `--identity ...` | `native`, `age`, or `pgp:KEYFILE` (see [Security](#security)) |
| `--simple` | Plain `[HH:MM] ...` lines, one session, stdin — the automatic fallback when stdout isn't a tty |
| `--session ID` | Join a session at startup (with `--port`, `--peer`) |

## License

[GPL-3.0-only](LICENSE). Copyright © 2026 finlay@tuta.com.
