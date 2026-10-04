// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "platform/platform.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <ncrypt.h>

#ifndef MS_PLATFORM_CRYPTO_PROVIDER
#define MS_PLATFORM_CRYPTO_PROVIDER L"Microsoft Platform Crypto Provider"
#endif

// The sealed forms. "NCPT": the padding (an index into PADS), the length of the TPM key's name,
// the name, the ciphertext's length (2 bytes, big-endian) and the ciphertext. "DPAP": a DPAPI blob.
#define KEY_PREFIX "chat-"
#define KEY_NAME_LEN (5 + 32)
#define CT_MAX 512

typedef struct { DWORD flag; const wchar_t *hash; } pad_t;
// TPMs and their drivers differ in which paddings they take, so the first one that works both
// ways is kept.
static const pad_t PADS[] = {
    { NCRYPT_PAD_OAEP_FLAG, BCRYPT_SHA256_ALGORITHM },
    { NCRYPT_PAD_OAEP_FLAG, BCRYPT_SHA1_ALGORITHM },
    { NCRYPT_PAD_PKCS1_FLAG, NULL },
};
#define N_PADS ((int)(sizeof PADS / sizeof PADS[0]))

static const char DPAPI_LABEL[] = "chat device lock v1";

typedef struct {
    int pad;
    wchar_t name[KEY_NAME_LEN + 1];
    const uint8_t *ct;
    DWORD ct_len;
} tpm_sealed_t;

// The provider, if there's a TPM behind it: without one, opening it can still work.
static int open_tpm(NCRYPT_PROV_HANDLE *prov) {
    if (NCryptOpenStorageProvider(prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS) return 0;
    BYTE type[256];
    DWORD n = 0;
    if (NCryptGetProperty(*prov, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, type, sizeof type, &n, 0) == ERROR_SUCCESS && n > 0)
        return 1;
    NCryptFreeObject(*prov);
    return 0;
}

device_kind_t platform_device_kind(char *why, size_t why_cap) {
    (void)why; (void)why_cap;
    NCRYPT_PROV_HANDLE prov;
    if (!open_tpm(&prov)) return DEVICE_OS;
    NCryptFreeObject(prov);
    return DEVICE_TPM;
}

static int key_name_ok(const char *name, size_t n) {
    if (n != KEY_NAME_LEN || memcmp(name, KEY_PREFIX, 5) != 0) return 0;
    for (size_t i = 5; i < n; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return 0;
    return 1;
}

// Only a name chat made is ever opened, so a planted file can't point it at another program's key.
static int parse_tpm(const uint8_t *s, size_t len, tpm_sealed_t *t) {
    if (len < 8 || memcmp(s, "NCPT", 4) != 0 || s[4] >= N_PADS) return -1;
    size_t nl = s[5];
    if (len < 8 + nl || !key_name_ok((const char *)s + 6, nl)) return -1;
    size_t cl = (size_t)s[6 + nl] << 8 | s[7 + nl];
    if (cl == 0 || cl > CT_MAX || len != 8 + nl + cl) return -1;
    t->pad = s[4];
    for (size_t i = 0; i < nl; i++) t->name[i] = (wchar_t)s[6 + i];
    t->name[nl] = L'\0';
    t->ct = s + 8 + nl;
    t->ct_len = (DWORD)cl;
    return 0;
}

device_kind_t platform_device_sealed_kind(const uint8_t *sealed, size_t len) {
    tpm_sealed_t t;
    if (parse_tpm(sealed, len, &t) == 0) return DEVICE_TPM;
    return len > 4 && memcmp(sealed, "DPAP", 4) == 0 ? DEVICE_OS : DEVICE_NONE;
}

const char *platform_device_uses(device_kind_t kind) {
    return kind == DEVICE_TPM
        ? "this computer's TPM: a key it makes for this save and never lets out, kept for your Windows account"
        : "DPAPI, which ties it to your Windows account on this computer. There's no TPM here, so an administrator, "
          "or anyone with a copy of the disk and your Windows password, could get past the device part, leaving "
          "only the passphrase";
}

int platform_device_losses(device_kind_t kind, const char **out, int max) {
    static const char *const TPM[] = {
        "the TPM is cleared: in the firmware settings, from Windows (Clear TPM, in Windows Security), or by a "
        "firmware update (some BIOS and TPM updates clear it)",
        "the motherboard is replaced, or the CPU where the TPM is part of it (AMD's fTPM), or the firmware "
        "switches to another TPM",
        "Windows is reinstalled or reset, or your Windows profile is deleted",
    };
    // DPAPI's keys are sealed with the account's password, which an administrator's reset doesn't know.
    static const char *const DPAPI[] = {
        "Windows is reinstalled or reset, or your Windows profile is deleted",
        "an administrator resets your Windows password (changing it yourself is fine)",
    };
    const char *const *list = kind == DEVICE_TPM ? TPM : DPAPI;
    int total = kind == DEVICE_TPM ? 3 : 2, n = 0;
    for (int i = 0; i < total && n < max; i++) out[n++] = list[i];
    return n;
}

static void say_status(char *why, size_t why_cap, const char *what, SECURITY_STATUS s) {
    snprintf(why, why_cap, "%s (0x%08lx)", what, (unsigned long)s);
}

// With the key's public half, outside the TPM: the TPM is only needed to unseal.
static SECURITY_STATUS rsa_encrypt(NCRYPT_KEY_HANDLE key, const pad_t *pad, const uint8_t *in, ULONG n,
                                   uint8_t *out, ULONG cap, ULONG *out_len) {
    BYTE pub[1024];
    DWORD pub_len = 0;
    SECURITY_STATUS s = NCryptExportKey(key, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, pub, sizeof pub, &pub_len, 0);
    if (s != ERROR_SUCCESS) return s;
    BCRYPT_ALG_HANDLE alg;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) return (SECURITY_STATUS)st;
    BCRYPT_KEY_HANDLE bk;
    st = BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPUBLIC_BLOB, &bk, pub, pub_len, 0);
    if (BCRYPT_SUCCESS(st)) {
        BCRYPT_OAEP_PADDING_INFO oaep = { pad->hash, NULL, 0 };
        st = BCryptEncrypt(bk, (PUCHAR)in, n, pad->hash ? &oaep : NULL, NULL, 0, out, cap, out_len, pad->flag);
        BCryptDestroyKey(bk);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return BCRYPT_SUCCESS(st) ? ERROR_SUCCESS : (SECURITY_STATUS)st;
}

static SECURITY_STATUS tpm_decrypt(NCRYPT_KEY_HANDLE key, const pad_t *pad, const uint8_t *ct, DWORD ct_len,
                                   uint8_t secret[DEVICE_SECRET_LEN]) {
    BCRYPT_OAEP_PADDING_INFO oaep = { pad->hash, NULL, 0 };
    BYTE plain[CT_MAX];
    DWORD n = 0;
    SECURITY_STATUS s = NCryptDecrypt(key, (PBYTE)ct, ct_len, pad->hash ? &oaep : NULL, plain, sizeof plain, &n,
                                      pad->flag | NCRYPT_SILENT_FLAG);
    if (s == ERROR_SUCCESS && n != DEVICE_SECRET_LEN) s = NTE_BAD_DATA;
    if (s == ERROR_SUCCESS) memcpy(secret, plain, DEVICE_SECRET_LEN);
    SecureZeroMemory(plain, sizeof plain);
    return s;
}

static int dpapi_unseal(const uint8_t *s, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap) {
    DATA_BLOB in = { (DWORD)(len - 4), (BYTE *)s + 4 }, entropy = { sizeof DPAPI_LABEL - 1, (BYTE *)DPAPI_LABEL };
    DATA_BLOB plain = { 0, NULL };
    if (!CryptUnprotectData(&in, NULL, &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
        snprintf(why, why_cap, "DPAPI couldn't unseal it (error %lu): it was sealed on another device or Windows "
                 "account", (unsigned long)GetLastError());
        return -1;
    }
    int ok = plain.cbData == DEVICE_SECRET_LEN;
    if (ok) memcpy(secret, plain.pbData, DEVICE_SECRET_LEN);
    else snprintf(why, why_cap, "DPAPI unsealed something that isn't chat's");
    SecureZeroMemory(plain.pbData, plain.cbData);
    LocalFree(plain.pbData);
    return ok ? 0 : -1;
}

int platform_device_unseal(const uint8_t *sealed, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap) {
    if (platform_device_sealed_kind(sealed, len) == DEVICE_OS) return dpapi_unseal(sealed, len, secret, why, why_cap);
    tpm_sealed_t t;
    if (parse_tpm(sealed, len, &t) != 0) {
        snprintf(why, why_cap, "it isn't sealed in a way chat on Windows knows");
        return -1;
    }
    NCRYPT_PROV_HANDLE prov;
    if (!open_tpm(&prov)) {
        snprintf(why, why_cap, "it was sealed with a TPM, and there's none here");
        return -1;
    }
    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS s = NCryptOpenKey(prov, &key, t.name, 0, NCRYPT_SILENT_FLAG);
    if (s != ERROR_SUCCESS) {
        say_status(why, why_cap, "its TPM key isn't here: it was sealed on another device or Windows account, or "
                   "the TPM or the key is gone", s);
    } else {
        s = tpm_decrypt(key, &PADS[t.pad], t.ct, t.ct_len, secret);
        NCryptFreeObject(key);
        if (s != ERROR_SUCCESS) say_status(why, why_cap, "the TPM couldn't unseal it", s);
    }
    NCryptFreeObject(prov);
    if (s != ERROR_SUCCESS) SecureZeroMemory(secret, DEVICE_SECRET_LEN);
    return s == ERROR_SUCCESS ? 0 : -1;
}

static long dpapi_seal(const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why, size_t why_cap) {
    DATA_BLOB in = { DEVICE_SECRET_LEN, (BYTE *)secret }, entropy = { sizeof DPAPI_LABEL - 1, (BYTE *)DPAPI_LABEL };
    DATA_BLOB blob = { 0, NULL };
    if (!CryptProtectData(&in, NULL, &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &blob)) {
        snprintf(why, why_cap, "DPAPI couldn't seal it (error %lu)", (unsigned long)GetLastError());
        return -1;
    }
    long n = -1;
    if (4 + (size_t)blob.cbData <= cap) {
        memcpy(out, "DPAP", 4);
        memcpy(out + 4, blob.pbData, blob.cbData);
        n = (long)(4 + blob.cbData);
    } else {
        snprintf(why, why_cap, "DPAPI's sealed form is too big to keep");
    }
    LocalFree(blob.pbData);
    return n;
}

// A key the TPM makes and never lets out, then the first padding it unseals with.
static long tpm_seal(NCRYPT_PROV_HANDLE prov, const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap,
                     char *why, size_t why_cap) {
    uint8_t rnd[16];
    char name[KEY_NAME_LEN + 1];
    gen_random(rnd, sizeof rnd);
    memcpy(name, KEY_PREFIX, 5);
    hex_encode(rnd, sizeof rnd, name + 5);
    wchar_t wname[KEY_NAME_LEN + 1];
    for (int i = 0; i <= KEY_NAME_LEN; i++) wname[i] = (wchar_t)name[i];
    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS s = NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM, wname, 0, 0);
    if (s != ERROR_SUCCESS) { say_status(why, why_cap, "the TPM couldn't make a key", s); return -1; }
    // The provider never lets a TPM key's private half out, so there's no export policy to set.
    DWORD bits = 2048, usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    s = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof bits, 0);
    if (s == ERROR_SUCCESS) s = NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage, sizeof usage, 0);
    if (s == ERROR_SUCCESS) s = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG);
    if (s != ERROR_SUCCESS) {
        NCryptFreeObject(key);
        say_status(why, why_cap, "the TPM couldn't make a key", s);
        return -1;
    }
    uint8_t ct[CT_MAX];
    ULONG ct_len = 0;
    int pad = -1;
    SECURITY_STATUS last = NTE_NOT_SUPPORTED;
    for (int i = 0; i < N_PADS && pad < 0; i++) {
        uint8_t back[DEVICE_SECRET_LEN];
        last = rsa_encrypt(key, &PADS[i], secret, DEVICE_SECRET_LEN, ct, sizeof ct, &ct_len);
        if (last == ERROR_SUCCESS) last = tpm_decrypt(key, &PADS[i], ct, ct_len, back);
        if (last == ERROR_SUCCESS && crypto_equal(back, secret, DEVICE_SECRET_LEN) == 0) pad = i;
        SecureZeroMemory(back, sizeof back);
    }
    size_t n = 8 + KEY_NAME_LEN + ct_len;
    if (pad < 0 || ct_len > CT_MAX || n > cap) {
        NCryptDeleteKey(key, NCRYPT_SILENT_FLAG);
        say_status(why, why_cap, "the TPM's key couldn't unseal what it sealed", last);
        return -1;
    }
    NCryptFreeObject(key);
    memcpy(out, "NCPT", 4);
    out[4] = (uint8_t)pad;
    out[5] = (uint8_t)KEY_NAME_LEN;
    memcpy(out + 6, name, KEY_NAME_LEN);
    out[6 + KEY_NAME_LEN] = (uint8_t)(ct_len >> 8);
    out[7 + KEY_NAME_LEN] = (uint8_t)ct_len;
    memcpy(out + 8 + KEY_NAME_LEN, ct, ct_len);
    return (long)n;
}

long platform_device_seal(const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why, size_t why_cap) {
    NCRYPT_PROV_HANDLE prov;
    long n;
    // With a TPM there, its failing is an error, never a reason to fall back to DPAPI.
    if (open_tpm(&prov)) {
        n = tpm_seal(prov, secret, out, cap, why, why_cap);
        NCryptFreeObject(prov);
    } else {
        n = dpapi_seal(secret, out, cap, why, why_cap);
    }
    if (n < 0) return -1;
    // Again from the start, the way it's unsealed when the save is opened.
    uint8_t back[DEVICE_SECRET_LEN];
    int rc = platform_device_unseal(out, (size_t)n, back, why, why_cap);
    int same = rc == 0 && crypto_equal(back, secret, DEVICE_SECRET_LEN) == 0;
    SecureZeroMemory(back, sizeof back);
    if (same) return n;
    if (rc == 0) snprintf(why, why_cap, "unsealing gave back something other than what was sealed");
    platform_device_forget(out, (size_t)n);
    return -1;
}

void platform_device_forget(const uint8_t *sealed, size_t len) {
    tpm_sealed_t t;
    NCRYPT_PROV_HANDLE prov;
    if (parse_tpm(sealed, len, &t) != 0 || NCryptOpenStorageProvider(&prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS)
        return;
    NCRYPT_KEY_HANDLE key;
    if (NCryptOpenKey(prov, &key, t.name, 0, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) NCryptDeleteKey(key, NCRYPT_SILENT_FLAG);
    NCryptFreeObject(prov);
}
