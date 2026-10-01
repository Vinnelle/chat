// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_FILES_H
#define CHAT_FILES_H

#include <stddef.h>
#include <stdint.h>

// A file's name as it's shown and saved: at most this many bytes.
#define FILE_NAME_MAX 100

// A name from a peer, made safe to show and to save under: no folders, nothing the terminal or
// the filesystem would read as more than a name (control and bidi characters, / \ : * ? " < > |),
// no leading dots (a hidden file) or trailing dots and spaces, not a Windows device name (CON,
// NUL, COM1, ...), and never empty. out holds FILE_NAME_MAX + 1 bytes.
void file_clean_name(const char *in, char out[FILE_NAME_MAX + 1]);

// The last part of a path, as the name a file is offered under.
const char *file_basename(const char *path);

// "8M", "512K", "2G", "1048576" or "8 MB": bytes. 0, or -1 if it isn't a size.
int file_parse_size(const char *s, uint64_t *out);
// "230 KB", "8.0 MB".
void file_format_size(uint64_t n, char *out, size_t cap);

#endif
