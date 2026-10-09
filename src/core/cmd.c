// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "core/cmd.h"
#include <stdio.h>
#include <string.h>

#define SYNOPSIS_MAX 64
#define SYNOPSIS_WIDTH 30   // the help lines up after it

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

void cmd_format_help(const command_t *cmd, char prefix, char *out, size_t cap) {
    char synopsis[SYNOPSIS_MAX];
    snprintf(synopsis, sizeof synopsis, "%c%s%s%s", prefix, cmd->name, cmd->args ? " " : "", cmd->args ? cmd->args : "");
    size_t pos = (size_t)snprintf(out, cap, "*   %-*s %s", SYNOPSIS_WIDTH, synopsis, cmd->help);
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
