// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_OS_H
#define CHAT_OS_H

#include <winsock2.h>
#include <stdlib.h>

#define strcasecmp _stricmp

typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
#endif
