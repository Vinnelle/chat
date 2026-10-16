#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
#
# Two chats on this computer, this build and an older one, in one room over UDP on 127.0.0.1, with
# --simple. Checks what docs/protocol.md section 10 promises an older version: messages both ways, a long
# one (in parts for a build that only reads short ones), a reply (a quoted message for one that
# can't read replies), a direct message (refused for one that can't read them, never lost), a file
# each way, and a leave.
#
#   tests/interop/interop.sh NEW OLD     two chat executables; NEW is the one being tested
#
# Each gets a HOME of its own in a temporary folder, so nothing of yours is read or written.
set -euo pipefail

new_bin=$(realpath "$1")
old_bin=$(realpath "$2")
work=$(mktemp -d)
pids=()
fails=0

cleanup() {
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    if [ "$fails" -gt 0 ] || [ -n "${KEEP:-}" ]; then echo "logs kept in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT

# The options both sides need, as this binary spells them: 0.5.0 and older took --nonostr.
flags_for() {
    local help
    help=$("$1" --help 2>&1 || true)
    local f=(--simple --session INTEROPTEST --nodht --noportmap --nolan)
    if grep -q -- '--nostr off' <<<"$help"; then f+=(--nostr off); else f+=(--nonostr); fi
    if grep -q -- '--fast-files' <<<"$help"; then f+=(--fast-files); fi
    echo "${f[@]}"
}

# start NAME BIN PORT PEER_PORT FD
start() {
    local dir="$work/$1"
    mkdir -p "$dir/home/Downloads" "$dir/config"
    mkfifo "$dir/in"
    # shellcheck disable=SC2046
    HOME="$dir/home" XDG_CONFIG_HOME="$dir/config" CHAT_PASSWORD=interop \
        "$2" $(flags_for "$2") --nick "$1" --port "$3" --peer "127.0.0.1:$4" <"$dir/in" >"$dir/out" 2>&1 &
    pids+=($!)
    eval "exec $5>\"\$dir/in\""
}

say_new() { printf '%s\n' "$1" >&7; }
say_old() { printf '%s\n' "$1" >&8; }

# wait_for NAME TEXT SECONDS: whether TEXT shows in NAME's output within that long.
wait_for() {
    local end=$((SECONDS + $3))
    while [ "$SECONDS" -lt "$end" ]; do
        grep -qF -- "$2" "$work/$1/out" && return 0
        sleep 0.2
    done
    return 1
}

# The same for an extended regular expression.
wait_re() {
    local end=$((SECONDS + $3))
    while [ "$SECONDS" -lt "$end" ]; do
        grep -qE -- "$2" "$work/$1/out" && return 0
        sleep 0.2
    done
    return 1
}

check() {
    if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi
}

# send_file FROM TO: FROM offers a file, TO downloads it, and the copy has to match.
send_file() {
    local from=$1 to=$2 say_from=say_$1 say_to=say_$2
    head -c 20000 /dev/urandom >"$work/$from/home/from-$from.bin"
    "$say_from" ":send ~/from-$from.bin"
    if ! wait_for "$to" "from-$from.bin" 30; then return 1; fi
    local n
    n=$(grep -F "from-$from.bin" "$work/$to/out" | grep -o ':download [0-9]*' | head -1 | cut -d' ' -f2)
    [ -n "$n" ] || return 1
    "$say_to" ":download $n"
    local end=$((SECONDS + 90)) got="$work/$to/home/Downloads/from-$from.bin"
    while [ "$SECONDS" -lt "$end" ]; do
        if [ -f "$got" ] && cmp -s "$got" "$work/$from/home/from-$from.bin"; then return 0; fi
        sleep 0.5
    done
    return 1
}

echo "new: $("$new_bin" --version | head -1)"
echo "old: $("$old_bin" --version | head -1)"
start new "$new_bin" 41001 41002 7
start old "$old_bin" 41002 41001 8

check "they meet" 'wait_re new "\* old .*joined" 90 && wait_re old "\* new .*joined" 30'

say_new "hello from the new build"
check "a message from the new build" 'wait_for old "hello from the new build" 20'
say_old "hello from the old build"
check "a message from the old build" 'wait_for new "hello from the old build" 20'

long="start-of-the-long-one $(printf 'word%.0s ' $(seq 110)) end-of-the-long-one"
say_new "$long"
check "a long message, whole or in parts" 'wait_for old "start-of-the-long-one" 20 && wait_for old "end-of-the-long-one" 20'

say_old "a question from the old build"
wait_for new "a question from the old build" 20 || true
say_new ":reply old an answer from the new build"
check "a reply, or a quoted message for a build without replies" 'wait_for old "an answer from the new build" 20'

say_new ":msg old a direct message"
check "a direct message, or refused for a build without them" \
    'wait_for old "a direct message" 20 || grep -qF "too old for direct messages" "$work/new/out"'

# Files only go to peers whose code was compared.
say_new ":verify old ok"
say_old ":verify new ok"
check "a file from the new build" 'send_file new old'
check "a file from the old build" 'send_file old new'

say_new ":quit"
check "the new build leaves, and the old one says so" 'wait_re old "\* new .*left" 20'

echo
if [ "$fails" -gt 0 ]; then echo "$fails failed"; exit 1; fi
echo "all passed"
