// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "cmd.h"
#include <stdio.h>
#include <string.h>

const char *cmd_parse(const char *line, char word[CMD_WORD_MAX]) {
    while (*line == ' ') line++;
    size_t n = strcspn(line, " ");
    size_t keep = n < CMD_WORD_MAX - 1 ? n : CMD_WORD_MAX - 1;
    memcpy(word, line, keep);
    word[keep] = '\0';
    const char *arg = line + n;
    while (*arg == ' ') arg++;
    return arg;
}

static int alias_match(const char *aliases, const char *word) {
    size_t wlen = strlen(word);
    for (const char *p = aliases; p && *p; ) {
        size_t n = strcspn(p, " ");
        if (n == wlen && strncmp(p, word, n) == 0) return 1;
        p += n;
        while (*p == ' ') p++;
    }
    return 0;
}

const command_t *cmd_find(const command_t *table, const char *word) {
    if (!word[0]) return NULL;
    for (const command_t *c = table; c->name; c++)
        if (strcmp(c->name, word) == 0 || alias_match(c->aliases, word)) return c;
    return NULL;
}

const char *cmd_complete(const command_t *const *tables, const char *typed) {
    if (!typed[0] || strchr(typed, ' ')) return NULL;
    size_t tlen = strlen(typed);
    for (; *tables; tables++)
        for (const command_t *c = *tables; c->name; c++)
            if (strlen(c->name) > tlen && strncmp(c->name, typed, tlen) == 0) return c->name;
    return NULL;
}

void cmd_format_help(const command_t *cmd, char prefix, char *out, size_t cap) {
    char synopsis[64];
    snprintf(synopsis, sizeof synopsis, "%c%s%s%s", prefix, cmd->name, cmd->args ? " " : "", cmd->args ? cmd->args : "");
    size_t pos = (size_t)snprintf(out, cap, "*   %-30s %s", synopsis, cmd->help);
    const char *sep = " (also";
    for (const char *p = cmd->aliases; p && *p && pos < cap; ) {
        size_t n = strcspn(p, " ");
        pos += (size_t)snprintf(out + pos, cap - pos, "%s %c%.*s", sep, prefix, (int)n, p);
        sep = ",";
        p += n;
        while (*p == ' ') p++;
    }
    if (cmd->aliases && pos < cap) snprintf(out + pos, cap - pos, ")");
}
