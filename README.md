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

Use `/verify NICK` (or `:verify NICK`) to compare a peer's identity out-of-band.

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
at the bottom. The input line is a small vim: it starts in INSERT; Esc drops to NORMAL
(h/l move, i/a/I/A insert, x delete); `:` opens a command line.

| Key | Action |
| --- | --- |
| `Ctrl+N` | create a new session (asks for a password) |
| `Ctrl+J` | join an existing session (id, then password) |
| `Ctrl+W` | leave/close the current session |
| `Tab` / `Shift+Tab` | next / previous session |
| `Ctrl+B` / `Ctrl+O` / `Ctrl+T` | toggle sidebar / console / chat pane |
| `Ctrl+C` | quit (every session leaves cleanly first) |

Commands work typed (`/peers`, `/nick`, `/verify NICK`, `/net`, `/help`, ...) or as `:`
commands (`:new`, `:join`, `:sign`, `:copyid`, `:update`, `:q`, `:qa`, ...).

### Updating

`:update` checks the [latest GitHub release](https://github.com/Vinnelle/chat/releases/latest).
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
