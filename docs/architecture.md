# Architecture

How chat's source is laid out, for anyone reading or changing it. [Building](building.md) has how to
build it and run the tests.

## Layers

chat is C11, in `src/`, with libsodium, liboqs, Mbed TLS and libsecp256k1 linked statically. Each
folder only uses the ones above it in this table, apart from the AGE and PGP code, which reads key
files through `platform/`.

| Folder | What's there |
| --- | --- |
| [`src/common/`](../src/common/) | Code with no I/O: text and UTF-8 (`util.c`), the JSON, TOML and bencode parsers, QR codes, Bytewords, and lookups on a thread (`job.h`). In `image/`, chat's own PNG, JPEG and GIF readers (`image.c`, over `png.c`, `jpeg.c` and `gif.c`), and pictures cleaned before they're sent (`clean.c`) |
| [`src/crypto/`](../src/crypto/) | Keys, sealing, ratchets, Argon2id, signatures and save locks (`crypto.c`), and AGE and PGP keys (`age.c`, `pgp.c`) |
| [`src/platform/`](../src/platform/) | The operating system, behind `platform.h` (terminal, files, processes, notifications, the sandbox, the device lock, security keys) and `net.h` (sockets): `posix/` for Linux and macOS, `windows/`, and `linux/` and `macos/` for the device lock and security keys |
| [`src/transport/`](../src/transport/) | How sessions reach each other: the BitTorrent DHT (`dht.c`), Nostr relays (`nostr.c`, over `tls.c`), Tor's control port, SOCKS and onion services (`tor.c`), chat's own tor (`torproc.c`), and router port mapping (`portmap.c`) |
| [`src/core/`](../src/core/) | The engine: one session, from the first hello to messages, files and `:move`, with no terminal in it. `chat.h` is what the app uses |
| [`src/tui/`](../src/tui/) | The full-screen UI's drawing and keys, a library the app hands what to show (`tui.h`) |
| [`src/app/`](../src/app/) | The program: the main loop, sessions on screen, pages and boxes, settings, saves and updates |

## The engine

A session is a `chat_t`, which the app only knows through `chat.h`'s functions: what it holds is in
`state.h`, which only the engine and the tests see. The app gets one from `chat_new` and starts it
with `chat_init`, then calls `chat_tick` and `chat_on_socket_readable` with the time, and the engine
calls back to print a line, notify, or hand over a file. It never reads the clock itself: it keeps
to the time it's given. `chat_shutdown` and `chat_free` end it.

| File | What's there |
| --- | --- |
| `chat.c` | A session's life: starting and stopping it, each tick's steps, its sockets and routing, and what the app sets |
| `names.c` | Nicks and how a peer's name is shown, colours, labels, timers as text, invites, and the room a call goes to |
| `messages.c` | Message ids, the ones seen lately, acks and resends, replies, and sending what's typed |
| `send.c` | Each peer's slots, the records and room frames queued for them, and a frame's way out |
| `handshake.c` | Candidates, the handshake (hello, cookie, key exchange), `k`, peer exchange and builds |
| `receive.c` | Datagrams and relayed frames, opened, and each record a session carries (`on_session`) |
| `move.c` | Moving the room (`:move`) |
| `transfer.c` | Files: offers, fetches, and the chunks sent in slots |
| `commands.c` | The commands a session takes (`CHAT_COMMANDS`) |
| `trust.c`, `files.c`, `cmd.c` | Verified and ignored keys, file names and sizes, and command tables |
| `engine.h` | What the engine's files share with each other |
| `state.h` | What a session holds: `chat_t`, `peer_t`, their queues and tables, and the protocol's timings and sizes |

## The TUI

| File | What's there |
| --- | --- |
| `tui.c` | Scrollbacks, and what every screen is drawn with: styles, boxes, the grid and the frame |
| `tui_input.c` | Keys as the terminal sends them, and the input line they edit |
| `tui_chat.c` | The chat screen: the messages, the console, the sidebar |
| `tui_bar.c` | The input box, the command menu over it, the bottom row, and the box drawn over the screen |
| `tui_pages.c` | List pages (settings, help), a page of text, a picture, and the empty screen under a box |
| `tui_draw.h` | What those files share |

## The app

The app's state is one `app_t`, `g_app` (`app.h`), grouped by what each part is for:
`g_app.install`, `g_app.factor`, `g_app.lock`, and so on. Each screen is a mode: `MODE_KEYS`
(`keys.c`) says how it takes keys, and `page_of` and `BOXES` (`screen.c`) which page it shows and
what its box holds.

| File | What's there |
| --- | --- |
| `main.c` | Starting up, the full-screen UI's main loop, and the panic key |
| `sessions.c` | Session slots, opening sessions, what the engine tells the app, the NEW and JOIN boxes, kept rooms, reopening and calls |
| `plain.c` | `--simple` |
| `commands.c` | The app's own commands, `:move`'s boxes, the help page, and running a command |
| `cmdline.c` | The command line: completing commands, nicks and arguments, and the menu over the input box |
| `keys.c` | What each key does, in each mode and on the chat screen |
| `screen.c` | What goes on screen: each mode's box, which page it shows, the chat pane and its input, and the bottom row |
| `pages.c` | The list pages' keys, the settings page and the signing identity's picker, and the changelog |
| `files_page.c` | The files page, and a picture on a page of its own |
| `settings.c` | The settings rows, `:set`, and the settings file |
| `identity.c` | The signing identity: made from a password, or read from a key file or a paste |
| `saves/` | The save files (`saves.c`), their spare, a decoy or chaff (`spare.c`), and their factors (`factors.c`), which share `store.h`: the rest of chat uses `saves.h`. `:install`'s boxes and unlocking (`install.c`) |
| `torlink.c` | Which tor Tor mode uses, chat's own tor, and its bridges |
| `lock.c`, `history.c`, `rooms.c`, `update.c` | The lock screen, histories, kept rooms, and `:update` |
| `pics.c`, `clipboard.c`, `browser.c` | Pictures under the lines that offered them, the clipboard, and the folder browser and its pages |

## The platform

`posix/` and `windows/` have the same files, each with its part of `platform.h` and `net.h`, and
`os.h`. Linux and macOS both build `posix/`, which guards what only one of them has. `linux/` and
`macos/` have the rest: `device.c` and `seckey.c`.

| File | What's there |
| --- | --- |
| `process.c` | Hardening the process, the secrets in its environment, its arguments, the clock, threads, the executable, and the programs and processes it starts |
| `term.c` | The terminal: raw mode, its size, keys and lines, writing to it, and waiting on it and the sockets together |
| `notify.c` | Notifications, and the clipboard |
| `files.c` | Files and folders, temporary folders, and what chat reads from the system: the machine id, the default gateway, the CA roots |
| `sandbox.c` | Landlock and seccomp, and the child pictures are decoded in: Linux only, stubs elsewhere |
| `net.c` | Sockets (`net.h`) |
| `device.c`, `seckey.c` | The device lock and security keys, over `tpm2.c` and `ctap2.c` on Linux |
| `posix.h`, `win.h` | What the files in each folder share |

## A message, end to end

1. `Enter` in the input box: `handle_key` (`app/commands.c`) hands the line to `chat_send_text`,
   which makes an `m` record for each peer and queues it (`queue_record`, `core/send.c`).
2. At the peer's next slot, `run_slot` seals the queued records on the peer's chain, with padding
   to a fixed size, and sends the frame (`xmit`).
3. On the other side, `chat_on_socket_readable` (`core/receive.c`) opens the frame on the sender's
   chain, and `on_session` reads each record: `on_message` acks it, shows it, and passes it on to
   the peers it's connected to.
4. The engine's print callback (`session_print`, `app/sessions.c`) puts the line in the session's
   scrollback, and the next frame draws it.

What goes on the wire, byte by byte, is in [Protocol](protocol.md).

## Tests

| Folder | What's there |
| --- | --- |
| [`tests/engine/`](../tests/engine/) | The engine test: real sessions against each other over an in-memory network (`harness.c`), with a file for each area. `engine_test.c` runs them in order |
| [`tests/fuzz/`](../tests/fuzz/) | libFuzzer targets, with their seeds and dictionary |
| [`tests/interop/`](../tests/interop/) | This build and an older release as two peers in one room |
| [`tests/support/`](../tests/support/) | The in-memory network and the fakes the tests share |

## Conventions

- New behaviour on the wire goes behind a capability letter in `k`, so older peers are never sent
  what they can't read ([Protocol](protocol.md), sections 7 and 10).
- Builds have no warnings with the flags in `CMakeLists.txt`. printf-like functions are marked
  `PRINTF_LIKE`, so the compiler checks every call.
- Comments say why, where that isn't obvious from the code.
