// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Android keeps a secret only this phone can unseal in its Keystore, which only an app's Java side
// reaches, not a program it starts. A save can't be locked to the device here: an app that runs chat
// (--json) seals what it keeps itself.
#include "platform/platform.h"
#include "common/util.h"

static const char WHY[] = "Android: chat can't reach the Keystore itself, so a save can't be locked to this phone";

device_kind_t platform_device_kind(char *why, size_t why_cap) {
    copy_str(why, WHY, why_cap);
    return DEVICE_NONE;
}

device_kind_t platform_device_sealed_kind(const uint8_t *sealed, size_t len) {
    (void)sealed; (void)len;
    return DEVICE_NONE;
}

const char *platform_device_uses(device_kind_t kind) {
    (void)kind;
    return "nothing on Android";
}

int platform_device_losses(device_kind_t kind, const char **out, int max) {
    (void)kind; (void)out; (void)max;
    return 0;
}

long platform_device_seal(const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why, size_t why_cap) {
    (void)secret; (void)out; (void)cap;
    copy_str(why, WHY, why_cap);
    return -1;
}

int platform_device_unseal(const uint8_t *sealed, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap) {
    (void)sealed; (void)len; (void)secret;
    copy_str(why, "it was locked to another computer: this phone can't unseal it", why_cap);
    return -1;
}

void platform_device_forget(const uint8_t *sealed, size_t len) { (void)sealed; (void)len; }
