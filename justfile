version := `sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt`

# List recipes
default:
    @just --list

# Configure and build the native binary
build:
    cmake -B build
    cmake --build build -j {{num_cpus()}}

# Build a static musl Linux binary (needs zig on PATH)
build-static:
    cmake -B build-static -DCMAKE_TOOLCHAIN_FILE=cmake/zig-linux-musl.cmake
    cmake --build build-static -j {{num_cpus()}}

# Cross-build the Windows binary (needs zig on PATH)
build-win:
    cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/zig-windows.cmake
    cmake --build build-win -j {{num_cpus()}}

# Build native and Windows binaries
all: build build-win

# Build, then run chat with the given arguments
[positional-arguments]
run *args: build
    ./build/chat "$@"

# Build, then keep a copy in test-builds/ named after its build id (the one `chat --version` shows)
test-build: build
    #!/bin/sh
    set -eu
    id=$(sed -n 's/^#define CHAT_BUILD_ID "\(.*\)"$/\1/p' build/build_stamp.h)
    test -n "$id" || { echo "no CHAT_BUILD_ID in build/build_stamp.h" >&2; exit 1; }
    mkdir -p test-builds
    cp build/chat "test-builds/chat-$id"
    echo "test-builds/chat-$id"

# Put standalone release binaries and SHA256SUMS in dist/
dist: build-static build-win
    rm -rf dist
    mkdir dist
    cp build-static/chat dist/chat-linux-x86_64
    cp build-win/chat.exe dist/chat-windows-x86_64.exe
    strip dist/chat-linux-x86_64
    cd dist && sha256sum chat-linux-x86_64 chat-windows-x86_64.exe > SHA256SUMS
    @echo "dist/ ready for v{{version}}"

# minisign.pub gets committed; the password-protected secret key stays offline and backed up,
# never in the repo. Set CHAT_SIGNING_KEY to keep it somewhere other than ~/.minisign.
# Make the release signing key
keygen:
    #!/bin/sh
    set -eu
    key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}"
    if [ -e minisign.pub ] || [ -e "$key" ]; then echo "minisign.pub or $key already exists" >&2; exit 1; fi
    mkdir -p "$(dirname "$key")"
    minisign -G -p minisign.pub -s "$key"
    echo "commit minisign.pub; back up $key somewhere safe"

# Tag and push vVERSION first. Signing happens here, offline, so a compromised GitHub
# account can't publish an update that chat will install.
# Build, sign and publish this version's release (needs zig, minisign, gh)
release:
    #!/bin/sh
    set -eu
    key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}"
    test -e minisign.pub || { echo "no minisign.pub - run just keygen" >&2; exit 1; }
    test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }
    test "$(git rev-parse HEAD)" = "$(git rev-parse "v{{version}}^{commit}")" || { echo "HEAD is not tag v{{version}}" >&2; exit 1; }
    if gh release view "v{{version}}" >/dev/null 2>&1; then
        echo "release v{{version}} is already published - bump the version in CMakeLists.txt for a new one" >&2; exit 1
    fi
    just dist
    minisign -S -s "$key" -m dist/SHA256SUMS -t "chat v{{version}}"
    minisign -V -p minisign.pub -m dist/SHA256SUMS
    awk -v v="{{version}}" '$0 == "## " v { on = 1; next } on && /^## / { exit } on { print }' CHANGELOG.md > dist/notes.md
    grep -q '[^[:space:]]' dist/notes.md || { echo "CHANGELOG.md has no section for {{version}}" >&2; exit 1; }
    {
        echo
        echo 'Check a download with `minisign -Vm SHA256SUMS -p minisign.pub`, then `sha256sum -c --ignore-missing SHA256SUMS`.'
        echo
        echo '```'
        cat dist/SHA256SUMS
        echo '```'
    } >> dist/notes.md
    gh release create "v{{version}}" --title "v{{version}}" --notes-file dist/notes.md --verify-tag \
        dist/chat-linux-x86_64 dist/chat-windows-x86_64.exe dist/SHA256SUMS dist/SHA256SUMS.minisig

# Remove build directories and release output
clean:
    rm -rf build build-static build-win dist
