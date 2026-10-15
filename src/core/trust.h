// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TRUST_H
#define CHAT_TRUST_H

#include "core/chat.h"

// Signing keys of peers whose verify code the user compared (:verify NICK ok), with the nick they
// had. One list for every session in this run. A peer that signs its handshake with one of these
// keys doesn't need its code compared again. A peer with the nick of one, signing with another
// key or none, gets a warning. The app saves the list with what :install saved and loads it when
// that is opened.

#define TRUST_MAX 128
// One line of trust_text: "age <64 hex> nick\n".
#define TRUST_LINE_MAX (8 + ID_SIGN_PUB_LEN * 2 + MAX_NICK * 4 + 4)
#define TRUST_TEXT_MAX (TRUST_MAX * TRUST_LINE_MAX + 64)

typedef struct {
    identity_source_t source;
    uint8_t pub[ID_SIGN_PUB_LEN];
    char nick[MAX_NICK + 1];
    char nick_skel[NICK_SKEL_LEN];
} trust_entry_t;

int trust_count(void);
const trust_entry_t *trust_at(int i);
// The entry for this key, or NULL.
const trust_entry_t *trust_by_key(const uint8_t pub[ID_SIGN_PUB_LEN]);
// The index of the first entry from `from` whose nick looks the same as this skeleton
// (chat_nick_skeleton), or -1.
int trust_find_nick(const char *skel, int from);

// Adds the key, or updates its nick if it's there. When full, the oldest entry is dropped.
// Returns 1 if the list changed.
int trust_add(identity_source_t source, const uint8_t pub[ID_SIGN_PUB_LEN], const char *nick);
void trust_remove(int i);
void trust_clear(void);

// The list as text, one entry per line. 0, or -1 if it doesn't fit.
int trust_text(char *out, size_t cap);
// Adds the entries in text to the list (keys already there keep their entry). Returns the number
// of lines it couldn't read.
int trust_load(const char *text);

// Called after each change made by trust_add or trust_remove, so the app can save the list.
void trust_on_change(void (*fn)(void));
// Whether the list is being saved (chat is installed and what it saved is open). Only changes
// what chat says when a key is added.
void trust_set_saved(int saved);
int trust_saved(void);

// Signing keys of peers the user ignores (:ignore NICK), with the nick they had. What a peer signing
// with one says isn't shown, in any session. Saved with what :install saved too, in its settings, as
// trust_saved says; the app does that from ignore_on_change.
#define IGNORE_MAX 64
int ignore_count(void);
const trust_entry_t *ignore_at(int i);
const trust_entry_t *ignore_by_key(const uint8_t pub[ID_SIGN_PUB_LEN]);
// The first entry whose nick looks the same as this skeleton, or -1.
int ignore_find_nick(const char *skel);
// Adds the key, or updates its nick. When full, the oldest entry is dropped. 1 if the list changed.
int ignore_add(identity_source_t source, const uint8_t pub[ID_SIGN_PUB_LEN], const char *nick);
void ignore_remove(int i);
void ignore_clear(void);
// "age", "pgp" or "key" for an entry's source, and back (-1 if it isn't one).
const char *trust_source_name(identity_source_t source);
int trust_source_from(const char *name);
void ignore_on_change(void (*fn)(void));

#endif
