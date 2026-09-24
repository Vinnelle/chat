// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_AGE_H
#define CHAT_AGE_H

#include "crypto.h"
#include <stddef.h>
#include <stdint.h>

#define AGE_RECIPIENT_STRLEN 62

void age_export_recipient(const identity_keypair_t *idkp, char out[AGE_RECIPIENT_STRLEN + 1]);

#endif
