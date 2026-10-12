// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_ROOMS_H
#define CHAT_ROOMS_H

#include "core/chat.h"
#include "common/toml.h"

// The rooms kept in the open save (:keep): each one's label, session id and password, and whether
// chat joins it as it starts. They're kept in the save's settings file, as its [rooms] table, so the
// save's files don't say it keeps any. In locked memory, wiped by rooms_clear.

#define ROOMS_MAX 16
#define ROOM_LABEL_MAX 32

typedef struct {
    char label[ROOM_LABEL_MAX + 1];
    char id[MAX_SESSION_NAME + 1];
    char password[MAX_PASSWORD + 1];
    int at_start;
} room_t;

int rooms_count(void);
const room_t *room_at(int i);
// The kept room with this session id, or -1.
int rooms_find(const char *id);
// Keeps a room, or gives the one kept with that id this label and password. Its place, or -1 once
// ROOMS_MAX are kept.
int rooms_keep(const char *label, const char *id, const char *password);
void rooms_forget(int i);
void rooms_set_start(int i, int on);
void rooms_clear(void);
// One entry of the [rooms] table: ["LABEL", "ID", "PASSWORD"], then "start" for one joined at
// start. 0, or -1 if it isn't one.
int rooms_load(const toml_value *v);
// The [rooms] table, appended at p as settings_text writes the rest. The new length, or cap if it
// didn't fit.
size_t rooms_text(char *out, size_t p, size_t cap);

#endif
