set positional-arguments

version := `sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt`

# List recipes
default:
    @just --list --unsorted

# ---------------------------------------------------------------------------------------------
# Build

#   just build                       native binary in build/
#   just build linux                 static musl Linux binary in build-static/ (needs zig)
#   just build windows               Windows binary in build-win/ (needs zig; win works too)
#   just build all                   native and Windows binaries
#   just build test [system] [args]  test builds, see _build-test
# Build chat: native (default), linux, windows, all, or test [all|linux|windows]
[group('build')]
build what="native" *args:
    #!/bin/sh
    set -eu
    what="$1"
    shift
    just={{quote(just_executable())}}
    if [ "$what" != test ] && [ $# -gt 0 ]; then echo "just build $what takes no further arguments" >&2; exit 1; fi
    case "$what" in
        native)
            cmake -B build
            cmake --build build -j {{num_cpus()}}
            ;;
        linux)
            cmake -B build-static -DCMAKE_TOOLCHAIN_FILE=cmake/zig-linux-musl.cmake
            cmake --build build-static -j {{num_cpus()}}
            ;;
        windows|win)
            cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/zig-windows.cmake
            cmake --build build-win -j {{num_cpus()}}
            ;;
        all)
            "$just" build
            "$just" build windows
            ;;
        test) exec "$just" _build-test "$@" ;;
        *) echo "just build takes native, linux, windows, all or test, not $what" >&2; exit 1 ;;
    esac

# just build test [all|linux|windows] [chat args], all by default. This system's binary builds
# natively, the other is cross-built with zig. With all, a failed cross build only leaves that binary out. Only with a
# terminal to answer on does it ask; any further arguments go to chat if it runs. Each binary is
# chat-<build id>-<system>-<arch>, the build id saying which source it's from and when it was built.
# Each says "testing <build id>" over its console.
# Build into test-builds/<date>-<time>/ (all, linux or windows), then offer to run this system's binary
_build-test target="all" *args:
    #!/bin/sh
    set -eu
    export CHAT_TEST_BUILD=1
    target="$1"
    shift
    case "$target" in
        win) target=windows ;;
        all|linux|windows) ;;
        *) echo "just build test takes all, linux or windows, not $target" >&2; exit 1 ;;
    esac
    just={{quote(just_executable())}}
    host={{os()}}
    dir="test-builds/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dir"
    native=
    have_zig() {
        command -v "${ZIG:-zig}" >/dev/null 2>&1 || { echo "no zig on PATH - can't cross-build for $1" >&2; return 1; }
    }
    # Copies $2, built in $1, into $dir as chat-<build id>-$3 and leaves its path in $out. The
    # build id is CHAT_BUILD_ID from that build's stamp.
    keep() {
        id=$(sed -n 's/^#define CHAT_BUILD_ID "\(.*\)"$/\1/p' "$1/build_stamp.h")
        [ -n "$id" ] || { echo "no CHAT_BUILD_ID in $1/build_stamp.h" >&2; return 1; }
        out="$dir/chat-$id-$3"
        cp "$2" "$out"
    }
    build_linux() {
        if [ "$host" = linux ]; then
            "$just" build || return 1
            keep build build/chat linux-{{arch()}} || return 1
            native="$out"
        else
            have_zig Linux && "$just" build linux || return 1
            keep build-static build-static/chat linux-x86_64 || return 1
        fi
    }
    build_windows() {
        if [ "$host" = windows ]; then
            "$just" build || return 1
            # A multi-config generator (Visual Studio) puts it under Release/.
            for exe in build/chat.exe build/Release/chat.exe; do
                if [ -f "$exe" ]; then
                    keep build "$exe" windows-{{arch()}}.exe || return 1
                    native="$out"
                    return 0
                fi
            done
            echo "no chat.exe in build/" >&2
            return 1
        else
            have_zig Windows && "$just" build windows || return 1
            keep build-win build-win/chat.exe windows-x86_64.exe || return 1
        fi
    }
    fail() { echo "$1" >&2; rmdir "$dir" 2>/dev/null || true; exit 1; }
    case "$target" in
        linux)   build_linux || fail "the Linux build failed" ;;
        windows) build_windows || fail "the Windows build failed" ;;
        all)
            # This system's first: without it there's nothing to run.
            if [ "$host" = windows ]; then
                build_windows || fail "the Windows build failed"
                build_linux || echo "the Linux build failed - $dir only has the Windows binary" >&2
            else
                build_linux || fail "the Linux build failed"
                build_windows || echo "the Windows build failed - $dir only has the Linux binary" >&2
            fi
            ;;
    esac
    echo
    ls -1 "$dir" | sed "s|^|$dir/|"
    if [ -n "$native" ] && [ -t 0 ] && [ -t 1 ]; then
        printf 'run %s now? [y/N] ' "$native"
        read -r answer || answer=
        case "$answer" in
            [yY]|[yY][eE][sS]) exec "$native" "$@" ;;
        esac
    fi

# Build, then run chat with the given arguments
[group('build')]
run *args: build
    ./build/chat "$@"

# Remove build directories, test builds and release output
[group('build')]
clean:
    rm -rf build build-static build-win build-test build-fuzz test-builds dist

# ---------------------------------------------------------------------------------------------
# Test

# Sessions handshake and chat over an in-memory network. -v also prints every session line and
# check, then the summary.
# Build and run the engine test (-v for everything)
[group('test')]
test *flags:
    cmake -B build-test -DCHAT_TESTS=ON
    cmake --build build-test -j {{num_cpus()}} --target engine_test
    ./build-test/tests/engine_test "$@"

# Fuzz one target (bencode, json, pgp, text, engine, image or toml) for a number of seconds (needs clang)
[group('test')]
fuzz target="engine" seconds="300":
    cmake -B build-fuzz -DCHAT_FUZZ=ON -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug
    cmake --build build-fuzz -j {{num_cpus()}} --target fuzz_{{target}}
    mkdir -p fuzz-corpus/{{target}}
    ASAN_OPTIONS=detect_leaks=0 ./build-fuzz/tests/fuzz_{{target}} fuzz-corpus/{{target}} \
        $(test -d tests/seeds/{{target}} && echo tests/seeds/{{target}}) -dict=tests/fuzz.dict -max_total_time={{seconds}}

# ---------------------------------------------------------------------------------------------
# Release

# minisign.pub gets committed; the password-protected secret key stays offline and backed up,
# never in the repo. Set CHAT_SIGNING_KEY to keep it somewhere other than ~/.minisign.
# Make the release signing key
[group('release')]
keygen:
    #!/bin/sh
    set -eu
    key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}"
    if [ -e minisign.pub ] || [ -e "$key" ]; then echo "minisign.pub or $key already exists" >&2; exit 1; fi
    mkdir -p "$(dirname "$key")"
    minisign -G -p minisign.pub -s "$key"
    echo "commit minisign.pub; back up $key somewhere safe"

# Put standalone release binaries and SHA256SUMS in dist/
[group('release')]
dist: (build "linux") (build "windows")
    rm -rf dist
    mkdir dist
    cp build-static/chat dist/chat-linux-x86_64
    cp build-win/chat.exe dist/chat-windows-x86_64.exe
    strip dist/chat-linux-x86_64
    cd dist && sha256sum chat-linux-x86_64 chat-windows-x86_64.exe > SHA256SUMS
    cd dist && { echo "chat v{{version}}"; sha256sum chat-linux-x86_64 chat-windows-x86_64.exe | cut -c1-64; } > BUILDS
    @echo "dist/ ready for v{{version}}"

# Peers send each other this list to check each other's builds with (README.md, "Modified
# clients"), so it may name 3 binaries at most. Chat reads it from its own end: the list, its
# signature line, then the length of both in 8 digits and CHATBLD1.
# Append BUILDS, signed (BUILDS.minisig), to the binaries in a folder
_append-list dir:
    #!/bin/sh
    set -eu
    cd {{quote(dir)}}
    test "$(wc -l < BUILDS)" -le 4 || { echo "BUILDS names more than 3 binaries" >&2; exit 1; }
    sig=$(sed -n 2p BUILDS.minisig)
    len=$(( $(wc -c < BUILDS) + ${#sig} + 1 ))
    for f in chat-linux-x86_64 chat-windows-x86_64.exe; do
        { cat BUILDS; printf '%s\n%08dCHATBLD1' "$sig" "$len"; } >> "$f"
    done

# Releases what's under "## Unreleased" in CHANGELOG.md as VERSION: that heading becomes
# "## VERSION", CMakeLists.txt gets the version, and both are committed and tagged vVERSION.
# VERSION defaults to the one in CMakeLists.txt, or the patch after it once that one is published.
# Nothing is pushed until SHA256SUMS is signed; if a later step fails, running this again picks up
# from the tag. Signing happens here, offline, so a compromised GitHub account can't publish an
# update that chat will install.
# Build, sign and publish a release (needs zig, minisign, gh)
[group('release')]
release version="":
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}"
    test -e minisign.pub || { echo "no minisign.pub - run just keygen" >&2; exit 1; }
    test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }
    gh auth status >/dev/null 2>&1 || { echo "gh isn't logged in - run gh auth login" >&2; exit 1; }
    cmake_version() { sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt; }
    published() { gh release view "v$1" >/dev/null 2>&1; }
    v="${1:-}"
    if [ -z "$v" ]; then
        v=$(cmake_version)
        if published "$v"; then v=$(echo "$v" | awk -F. '{ print $1 "." $2 "." $3 + 1 }'); fi
    fi
    echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "not a version: $v (want MAJOR.MINOR.PATCH)" >&2; exit 1; }
    if published "$v"; then echo "release v$v is already published" >&2; exit 1; fi
    older=$(printf '%s\n%s\n' "$v" "$(cmake_version)" | sort -V | head -n 1)
    if [ "$older" = "$v" ] && [ "$v" != "$(cmake_version)" ]; then
        echo "v$v is older than $(cmake_version), the version in CMakeLists.txt" >&2; exit 1
    fi

    if grep -q '^## Unreleased$' CHANGELOG.md; then
        if git rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
            echo "tag v$v already exists, but CHANGELOG.md still has an Unreleased section" >&2; exit 1
        fi
        if grep -q "^## $v\$" CHANGELOG.md; then echo "CHANGELOG.md already has a section for $v" >&2; exit 1; fi
        awk '$0 == "## Unreleased" { on = 1; next } on && /^## / { exit } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
            CHANGELOG.md || { echo "the Unreleased section of CHANGELOG.md is empty" >&2; exit 1; }
        echo "releasing the Unreleased changes as v$v"
        awk -v v="$v" '$0 == "## Unreleased" && !done { print "## " v; done = 1; next } { print }' CHANGELOG.md > CHANGELOG.md.tmp
        mv CHANGELOG.md.tmp CHANGELOG.md
        sed "s/^project(chat VERSION [0-9.]*/project(chat VERSION $v/" CMakeLists.txt > CMakeLists.txt.tmp
        mv CMakeLists.txt.tmp CMakeLists.txt
        git commit -q -m "Release $v" CHANGELOG.md CMakeLists.txt
        git tag "v$v"
    fi
    git rev-parse -q --verify "refs/tags/v$v" >/dev/null \
        || { echo "no tag v$v and no Unreleased section in CHANGELOG.md to release" >&2; exit 1; }
    test "$(cmake_version)" = "$v" || { echo "CMakeLists.txt says $(cmake_version), not $v" >&2; exit 1; }
    test "$(git rev-parse HEAD)" = "$(git rev-parse "v$v^{commit}")" || { echo "HEAD is not tag v$v" >&2; exit 1; }

    "$just" dist
    # Each binary gets the signed list of this release's binaries, which peers check builds with.
    # SHA256SUMS then covers the binaries as published, list included. Two signatures: two prompts.
    minisign -S -s "$key" -m dist/BUILDS -t "chat builds v$v"
    minisign -V -p minisign.pub -m dist/BUILDS
    "$just" _append-list dist
    (cd dist && sha256sum chat-linux-x86_64 chat-windows-x86_64.exe > SHA256SUMS)
    minisign -S -s "$key" -m dist/SHA256SUMS -t "chat v$v"
    minisign -V -p minisign.pub -m dist/SHA256SUMS
    awk -v v="$v" '$0 == "## " v { on = 1; next } on && /^## / { exit } on { print }' CHANGELOG.md > dist/notes.md
    grep -q '[^[:space:]]' dist/notes.md || { echo "CHANGELOG.md has no section for $v" >&2; exit 1; }
    {
        echo
        echo 'Check a download with `minisign -Vm SHA256SUMS -p minisign.pub`, then `sha256sum -c --ignore-missing SHA256SUMS`.'
        echo
        echo '```'
        cat dist/SHA256SUMS
        echo '```'
    } >> dist/notes.md

    # The branch goes too when there is one, so the release commit is on GitHub, not just its tag.
    branch=$(git symbolic-ref -q --short HEAD || true)
    git push --atomic origin ${branch:+"$branch"} "refs/tags/v$v"
    gh release create "v$v" --title "v$v" --notes-file dist/notes.md --verify-tag \
        dist/chat-linux-x86_64 dist/chat-windows-x86_64.exe dist/SHA256SUMS dist/SHA256SUMS.minisig
