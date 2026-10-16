# Architecture

How chat's source is laid out, for anyone reading or changing it. [Building](building.md) has how to
build it and run the tests.

## Layers

chat is C11, in `src/`, with libsodium, liboqs, Mbed TLS and libsecp256k1 linked statically. Each
folder only uses the ones above it in this table, apart from the AGE and PGP code, which reads key
files through `platform/`.

| Folder | What's there |
| --- | --- |
| [`src/common/`](../src/common/) | Code with no I/O: text and UTF-8 (`util.c`), the JSON, TOML and bencode parsers, chat's own PNG, JPEG and GIF readers (`image.c`), pictures cleaned before they're sent (`clean.c`), QR codes, Bytewords, and lookups on a thread (`job.h`) |
| [`src/crypto/`](../src/crypto/) | Keys, sealing, ratchets, Argon2id, signatures and save locks (`crypto.c`), and AGE and PGP keys (`age.c`, `pgp.c`) |
| [`src/platform/`](../src/platform/) | The operating system, behind `platform.h` (terminal, files, processes, notifications, the sandbox, the device lock, security keys) and `net.h` (sockets): `linux/`, `windows/`, and `macos/`, which shares the rest with the Linux code |
| [`src/transport/`](../src/transport/) | How sessions reach each other: the BitTorrent DHT (`dht.c`), Nostr relays (`nostr.c`, over `tls.c`), Tor's control port, SOCKS and onion services (`tor.c`), chat's own tor (`torproc.c`), and router port mapping (`portmap.c`) |
| [`src/core/`](../src/core/) | The engine: one session, from the first hello to messages, files and `:move`, with no terminal in it. `chat.h` is what the app uses |
| [`src/tui/`](../src/tui/) | The full-screen UI's drawing and keys, a library the app hands what to show (`tui.h`) |
| [`src/app/`](../src/app/) | The program: the main loop, sessions on screen, pages and boxes, settings, saves and updates |

## The engine

A session is a `chat_t` (`chat.h`). The app makes one with `chat_init`, then calls `chat_tick` and
`chat_on_socket_readable` with the time, and the engine calls back to print a line, notify, or hand
over a file. It never reads the clock itself: it keeps to the time it's given.

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
(`commands.c`) says how it takes keys, `page_of` which page it shows, and `BOXES` (`screen.c`) what
its box holds.

| File | What's there |
| --- | --- |
| `main.c` | Starting up, the full-screen UI's main loop, and the panic key |
| `sessions.c` | Session slots, opening sessions, what the engine tells the app, the NEW and JOIN boxes, kept rooms, reopening and calls |
| `plain.c` | `--simple` |
| `commands.c` | The app's commands, the help page, the command line's menu, and what each key does |
| `screen.c` | What goes on screen: each mode's box and the bottom row |
| `pages.c` | The settings page and the pages under it, the files page, a picture's page, and the changelog |
| `settings.c` | The settings rows, `:set`, the settings file, and the signing identity |
| `saves.c`, `install.c` | `:install`'s boxes and unlocking (`saves.c`), and the save files themselves (`install.c`) |
| `torlink.c` | Which tor Tor mode uses, chat's own tor, and its bridges |
| `lock.c`, `history.c`, `rooms.c`, `update.c` | The lock screen, histories, kept rooms, and `:update` |
| `pics.c`, `clipboard.c`, `browser.c` | Pictures under the lines that offered them, the clipboard, and the folder browser |

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
| [`tests/engine/`](../tests/engine/) | The engine test: real sessions against each other over an in-memory network, and the parsers, saves and pictures |
| [`tests/fuzz/`](../tests/fuzz/) | libFuzzer targets, with their seeds and dictionary |
| [`tests/interop/`](../tests/interop/) | This build and an older release as two peers in one room |
| [`tests/support/`](../tests/support/) | The in-memory network and the fakes the tests share |

## Conventions

- New behaviour on the wire goes behind a capability letter in `k`, so older peers are never sent
  what they can't read ([Protocol](protocol.md), sections 7 and 10).
- Builds have no warnings with the flags in `CMakeLists.txt`. printf-like functions are marked
  `PRINTF_LIKE`, so the compiler checks every call.
- Comments say why, where that isn't obvious from the code.
