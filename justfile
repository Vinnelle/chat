set positional-arguments

version := `sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p; s/^set(CHAT_PRERELEASE "\(.*\)")$/\1/p' CMakeLists.txt | tr -d '\n'`

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

# Release preconditions
_can-release:
    #!/bin/sh
    set -eu
    test -e minisign.pub || { echo "no minisign.pub - run just keygen" >&2; exit 1; }
    test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }
    gh auth status >/dev/null 2>&1 || { echo "gh isn't logged in - run gh auth login" >&2; exit 1; }

#   just release                  the next version: the one in CMakeLists.txt, or the patch after it
#   just release 1.0.0            another version
#   just release beta [VERSION]   a beta of the next version, or of VERSION, see _release-beta
# Releases the sections at the top of CHANGELOG.md, "## Unreleased" and those of the betas since
# the last release, as VERSION: they become one "## VERSION" (see _fold-changelog), CMakeLists.txt
# gets the version, and both are committed and tagged vVERSION. VERSION defaults to the one in
# CMakeLists.txt, or the patch after it once that one is published. Nothing is pushed until
# SHA256SUMS is signed; if a later step fails, running this again picks up from the tag.
# Build, sign and publish a release: [VERSION], or beta [VERSION] (needs zig, minisign, gh)
[group('release')]
release what="" *args: _can-release
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    if [ "${1:-}" = beta ]; then
        shift
        if [ $# -gt 1 ]; then echo "just release beta takes one version at most, not $*" >&2; exit 1; fi
        exec "$just" _release-beta "$@"
    fi
    if [ $# -gt 1 ]; then echo "just release takes a version or beta [VERSION], not $*" >&2; exit 1; fi
    cmake_version() { sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt; }
    published() { gh release view "v$1" >/dev/null 2>&1; }
    pending() { awk '/^## [0-9]+\.[0-9]+\.[0-9]+$/ { exit } /^## / { printf "%s%s", (n++ ? ", " : ""), substr($0, 4) }' CHANGELOG.md; }
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

    if [ -n "$(pending)" ]; then
        if git rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
            echo "tag v$v already exists, but CHANGELOG.md still has $(pending) above it" >&2; exit 1
        fi
        if grep -q "^## $v\$" CHANGELOG.md; then echo "CHANGELOG.md already has a section for $v" >&2; exit 1; fi
        awk '/^## [0-9]+\.[0-9]+\.[0-9]+$/ { exit } /^## / { on = 1; next } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
            CHANGELOG.md || { echo "CHANGELOG.md's $(pending) has nothing in it" >&2; exit 1; }
        echo "releasing CHANGELOG.md's $(pending) as v$v"
        "$just" _fold-changelog "$v"
        sed -e "s/^project(chat VERSION [0-9.]*/project(chat VERSION $v/" -e 's/^set(CHAT_PRERELEASE ".*")$/set(CHAT_PRERELEASE "")/' \
            CMakeLists.txt > CMakeLists.txt.tmp
        mv CMakeLists.txt.tmp CMakeLists.txt
        git commit -q -m "Release $v" CHANGELOG.md CMakeLists.txt
        git tag "v$v"
    fi
    git rev-parse -q --verify "refs/tags/v$v" >/dev/null \
        || { echo "no tag v$v and no Unreleased section in CHANGELOG.md to release" >&2; exit 1; }
    exec "$just" _publish "$v"

# A beta is for testers: tagged vVERSION-beta.N, signed and published like a release, but as a
# GitHub pre-release, which :update only installs with betas on (:set betas on). Testers turn
# that on or download it, and :update takes them on to VERSION once it's released. Releasing
# VERSION deletes its betas' GitHub releases, but not their tags. VERSION defaults to the one
# `just release` would release next, and N counts up from 1 (or picks up a beta whose publishing failed). "## Unreleased" becomes
# "## VERSION-beta.N" and CMakeLists.txt gets the version, with "-beta.N" as CHAT_PRERELEASE.
# Build, sign and publish a beta of the next release, or of VERSION
_release-beta version="":
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    cmake_version() { sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt; }
    published() { gh release view "v$1" >/dev/null 2>&1; }
    base="${1:-}"
    if [ -z "$base" ]; then
        base=$(cmake_version)
        if published "$base"; then base=$(echo "$base" | awk -F. '{ print $1 "." $2 "." $3 + 1 }'); fi
    fi
    echo "$base" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "not a version: $base (want MAJOR.MINOR.PATCH)" >&2; exit 1; }
    if published "$base"; then echo "v$base is already released" >&2; exit 1; fi
    older=$(printf '%s\n%s\n' "$base" "$(cmake_version)" | sort -V | head -n 1)
    if [ "$older" = "$base" ] && [ "$base" != "$(cmake_version)" ]; then
        echo "v$base is older than $(cmake_version), the version in CMakeLists.txt" >&2; exit 1
    fi
    n=0
    for t in $(git tag -l "v$base-beta.*"); do
        m=${t#"v$base-beta."}
        case "$m" in ''|*[!0-9]*) continue ;; esac
        if [ "$m" -gt "$n" ]; then n=$m; fi
    done
    if [ "$n" -eq 0 ] || published "$base-beta.$n"; then n=$((n + 1)); fi
    v="$base-beta.$n"
    # Peers drop a version longer than MAX_VERSION (src/core/chat.h), and with it the build check.
    test ${#v} -le 15 || { echo "$v is longer than the 15 characters peers take" >&2; exit 1; }

    if grep -q '^## Unreleased$' CHANGELOG.md; then
        if git rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
            echo "tag v$v already exists, but CHANGELOG.md still has an Unreleased section" >&2; exit 1
        fi
        awk '$0 == "## Unreleased" { on = 1; next } on && /^## / { exit } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
            CHANGELOG.md || { echo "the Unreleased section of CHANGELOG.md is empty" >&2; exit 1; }
        echo "releasing the Unreleased changes as beta v$v"
        awk -v v="$v" '$0 == "## Unreleased" && !done { print "## " v; done = 1; next } { print }' CHANGELOG.md > CHANGELOG.md.tmp
        mv CHANGELOG.md.tmp CHANGELOG.md
        sed -e "s/^project(chat VERSION [0-9.]*/project(chat VERSION $base/" -e "s/^set(CHAT_PRERELEASE \".*\")\$/set(CHAT_PRERELEASE \"-beta.$n\")/" \
            CMakeLists.txt > CMakeLists.txt.tmp
        mv CMakeLists.txt.tmp CMakeLists.txt
        git commit -q -m "Release $v" CHANGELOG.md CMakeLists.txt
        git tag "v$v"
    fi
    git rev-parse -q --verify "refs/tags/v$v" >/dev/null \
        || { echo "no tag v$v and no Unreleased section in CHANGELOG.md to release" >&2; exit 1; }
    exec "$just" _publish "$v"

# The sections above the last release's, newest first, become one "## VERSION" holding each
# section's lines from the oldest on, under each ### heading once: Security, Added, Changed,
# Deprecated, Removed and Fixed in that order, then any others. Every line is kept, so a later
# beta's fix to something an earlier one added lists both: tidy their sections before releasing.
# A lone section is only renamed.
# Fold CHANGELOG.md's Unreleased and beta sections into one for VERSION
_fold-changelog version:
    #!/bin/sh
    set -eu
    awk -v v="$1" '
        function blank(s) { return s !~ /[^[:space:]]/ }
        function add(k, a, b,    i) {
            while (a <= b && blank(line[a])) a++
            while (b >= a && blank(line[b])) b--
            if (a > b) return
            if (!(k in body) && k != "") order[++kinds] = k
            for (i = a; i <= b; i++) body[k] = (k in body) ? body[k] "\n" line[i] : line[i]
        }
        function put(k) {
            if (!(k in body) || (k in done)) return
            done[k] = 1
            print ""
            print "### " k
            print body[k]
        }
        { line[NR] = $0 }
        END {
            for (first = 1; first <= NR && line[first] !~ /^## /; first++) print line[first]
            for (stop = first; stop <= NR && line[stop] !~ /^## [0-9]+\.[0-9]+\.[0-9]+$/; stop++)
                if (line[stop] ~ /^## /) head[++heads] = stop
            if (heads < 2) {
                for (i = first; i <= NR; i++) print (i == first && heads ? "## " v : line[i])
                exit
            }
            head[heads + 1] = stop
            for (h = heads; h >= 1; h--) {
                k = ""
                from = head[h] + 1
                for (i = from; i < head[h + 1]; i++)
                    if (line[i] ~ /^### /) { add(k, from, i - 1); k = substr(line[i], 5); from = i + 1 }
                add(k, from, head[h + 1] - 1)
            }
            print "## " v
            if ("" in body) { print ""; print body[""] }
            n = split("Security Added Changed Deprecated Removed Fixed", known, " ")
            for (j = 1; j <= n; j++) put(known[j])
            for (j = 1; j <= kinds; j++) put(order[j])
            for (i = stop; i <= NR; i++) { if (i == stop) print ""; print line[i] }
        }
    ' CHANGELOG.md > CHANGELOG.md.tmp
    mv CHANGELOG.md.tmp CHANGELOG.md

# Signing happens here, offline, so a compromised GitHub account can't publish an update that chat
# will install.
# Build, sign and publish tag vVERSION, which HEAD must be at, as a GitHub release
_publish version:
    #!/bin/sh
    set -eu
    v="$1"
    just={{quote(just_executable())}}
    key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}"
    test {{quote(version)}} = "$v" || { echo "CMakeLists.txt says {{version}}, not $v" >&2; exit 1; }
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
    case "$v" in *-*) pre=--prerelease ;; *) pre= ;; esac
    gh release create "v$v" --title "v$v" --notes-file dist/notes.md --verify-tag ${pre:+"$pre"} \
        dist/chat-linux-x86_64 dist/chat-windows-x86_64.exe dist/SHA256SUMS dist/SHA256SUMS.minisig
    # The release replaces its betas as a download. Their tags stay, as the history of the release.
    if [ -z "$pre" ]; then
        for t in $(git tag -l "v$v-beta.*"); do
            if gh release view "$t" >/dev/null 2>&1; then gh release delete "$t" --yes; fi
        done
    fi
