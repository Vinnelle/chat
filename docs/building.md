# Building

You need CMake ≥ 3.15 and a C compiler. CMake fetches and statically builds libsodium
(1.0.20), liboqs (0.16.0, ML-KEM-768 only), Mbed TLS (3.6.7, for the relays' `wss://`
connections) and libsecp256k1 (0.7.1, for Nostr's Schnorr signatures). TLS certificates are
checked against the system root store. Mbed TLS is set up as a TLS client with forward secret
key exchanges only ([`cmake/mbedtls-config.h`](../cmake/mbedtls-config.h)), and libsecp256k1 only
keeps what's needed for signing, since chat never verifies Nostr signatures.

```sh
cmake -B build
cmake --build build
./build/chat --nick you
```

## Windows cross-build

`cmake/toolchains/zig-*` use [zig](https://ziglang.org/) as a cross toolchain (with its bundled
mingw-w64), so libsodium's autotools and liboqs's CMake use the same compiler. With `zig` on
`PATH`:

```sh
cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/zig-windows.cmake
cmake --build build-win
```

## macOS

zig cross-builds chat for macOS too, Apple silicon (`aarch64`) and Intel (`x86_64`), for macOS 11
and later, without Apple's SDK: it links only the system library, and zig signs the result ad hoc,
which Apple silicon needs to run it.

```sh
cmake -B build-macos-aarch64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/zig-macos-aarch64.cmake
cmake --build build-macos-aarch64
```

It builds the platform code Linux uses too (`src/platform/posix/`), which keeps to POSIX apart from
what it guards. GitHub Actions runs the engine test and starts chat on a Mac on every push, but it
hasn't been used on one beyond that, and releases don't include it yet. What doesn't work there yet,
since it needs Apple's frameworks: locking a save to the device (the Secure Enclave), security keys,
desktop notifications, and asking the router for a port over PCP or NAT-PMP (UPnP still works). The
settings page greys the first two out and says why. A debugger can't attach to chat there
(`PT_DENY_ATTACH`), and the machine id a native signing key is made with is the Mac's hardware UUID.

## With just

The [`justfile`](../justfile) wraps the commands above:

```sh
just build              # native binary in build/
just build windows      # Windows binary in build-win/ (needs zig)
just build macos        # macOS binaries in build-macos-aarch64/ and build-macos-x86_64/ (needs zig)
just run --nick you     # build, then run
just build test         # Linux and Windows binaries in test-builds/<date>-<time>/, offer to run this system's
just build test linux   # the same for one system (or: windows); the other system's needs zig
                        # (a test build says "testing <build id>" over its console, and in --version)
just clean              # remove build directories and test builds
```

Test builds are called `chat-<build id>-<system>-<arch>`, for example
`chat-v0.3.1-3-g1a2b3c4-20260929-141502-linux-x86_64`. The build id is the source it was built from
(`git describe`) and when, in UTC. That's the same as `chat --version` prints, so a copy on another
machine still tells you which build it is.

## Tests

`tests/` runs real sessions against each other over an in-memory network. It covers the handshake,
the verify code gate, verified keys and the warning when one changes, message delivery with a
dropped packet, rekeys (and a message lost right as the peer rekeys), replayed hellos and junk from
outside the room, a third peer joining, that nothing goes over UDP unmasked, that every datagram is
one cell sent in a slot no matter how many messages are sent, and that the DHT queries as a read
only node and stops using the bootstrap servers once it knows enough nodes. It also tests the
parsers for what relays, routers and Tor send, the hourly DHT keys, that key files are only read
from regular files, the PNG, JPEG and GIF readers (and what they reject), file names from peers, and
files end to end: offered, saved next to a file with the same name, over the size limit, shown from
memory, shown to whoever sent it, changed after being offered (thrown away, saying why), sent fast,
followed by its sender, cancelled and withdrawn. The fuzz targets (libFuzzer, so clang) cover
bencode and DHT replies (IPv4 and IPv6), relay JSON and UPnP gateway replies, PGP and AGE key
import, PNG, JPEG and GIF images, text cleaning, file names, the input line, pictures drawn in the
chat and on a page of their own, the settings file as a hand could have edited it, a save's
securitykey file and sealed headers as anyone who can write to its folder could leave them, whatever
a security key or a TPM answers (and the device file the TPM's sealed form is kept in), and
everything a session receives, including messages from a room member or a connected peer, and
datagrams that unmask to anything at all. GitHub Actions runs the engine test, as built and again
under AddressSanitizer and UndefinedBehaviorSanitizer, and each fuzz target for a minute, on every
push and pull request. It also runs the engine test on Windows and on macOS (Apple silicon),
cross-built with zig as releases are, and starts chat on each to open a session and quit, so their
start-up runs there. And it checks each push against the latest release and the newest beta:
`tests/interop/interop.sh` runs the build and an older one as two peers in one room on the same
computer, and checks what [the protocol](protocol.md) says an older version gets: messages both
ways, a long one, a reply, a direct message (or that it's refused), a file each way and a leave.

```sh
just test               # build and run the engine test
just test -v            # the same, printing every session line and every check before the summary
just test-sanitized     # the engine test under AddressSanitizer and UndefinedBehaviorSanitizer (needs clang)
just interop OLD        # this build against OLD, an older chat executable, as two peers in one room
just fuzz engine 600    # fuzz one target (bencode, json, pgp, text, engine, image, toml, save, ctap2, tpm2) for 600 seconds
```
