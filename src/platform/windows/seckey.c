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
#include <wchar.h>

#include <windows.h>
#include <webauthn.h>

// Since Windows 10 1903 only administrators can open a security key directly, so chat asks Windows
// to, through webauthn.dll, whose window takes the PIN and asks for the touch. Reading hmac-secret
// with a salt of chat's own came in its API version 4 (assertion options version 6), newer than the
// headers chat builds with, so those parts are declared here, as Microsoft's webauthn.h has them.
#define RP_ID L"chat"
#define API_FOR_SALTS 4
#define GA_OPTIONS_VERSION_6 6
#define ASSERTION_VERSION_3 3
// The salts go to the security key as they are, rather than hashed as WebAuthn's PRF would.
#define HMAC_SECRET_VALUES_FLAG 0x00100000
// Authenticator data: the RP id's hash, then the flags.
#define AD_FLAGS_AT 32
#define FLAG_UV 0x04

#define WAIT_MS (SECKEY_WAIT_S * 1000)
#define USER_ID_LEN 16
#define CREDS_MAX 8
#define CHALLENGE_LEN 16
#define CLIENT_DATA_MAX 96
// How often the watcher looks at w->cancel, and how long ending a watch gives it to stop.
#define CANCEL_POLL_MS 100
#define WATCH_STOP_MS 150

typedef struct {
    DWORD cbFirst;
    PBYTE pbFirst;
    DWORD cbSecond;
    PBYTE pbSecond;
} hmac_salt_t;

typedef struct {
    DWORD cbCredID;
    PBYTE pbCredID;
    hmac_salt_t *pHmacSecretSalt;
} cred_salt_t;

typedef struct {
    hmac_salt_t *pGlobalHmacSalt;
    DWORD cCredWithHmacSecretSaltList;
    cred_salt_t *pCredWithHmacSecretSaltList;
} salt_values_t;

typedef struct {
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS v5;
    salt_values_t *pHmacSecretSaltValues;
    BOOL bBrowserInPrivateMode;
} ga_options_t;

typedef struct {
    WEBAUTHN_ASSERTION v2;
    hmac_salt_t *pHmacSecret;
} assertion_t;

typedef DWORD (WINAPI *version_fn)(void);
typedef HRESULT (WINAPI *make_fn)(HWND, PCWEBAUTHN_RP_ENTITY_INFORMATION, PCWEBAUTHN_USER_ENTITY_INFORMATION,
                                  PCWEBAUTHN_COSE_CREDENTIAL_PARAMETERS, PCWEBAUTHN_CLIENT_DATA,
                                  PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, PWEBAUTHN_CREDENTIAL_ATTESTATION *);
typedef HRESULT (WINAPI *get_fn)(HWND, LPCWSTR, PCWEBAUTHN_CLIENT_DATA, PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
                                 PWEBAUTHN_ASSERTION *);
typedef void (WINAPI *free_att_fn)(PWEBAUTHN_CREDENTIAL_ATTESTATION);
typedef void (WINAPI *free_assert_fn)(PWEBAUTHN_ASSERTION);
typedef HRESULT (WINAPI *cancel_id_fn)(GUID *);
typedef HRESULT (WINAPI *cancel_fn)(const GUID *);
typedef PCWSTR (WINAPI *error_name_fn)(HRESULT);

static struct {
    int loaded;
    version_fn version;
    make_fn make;
    get_fn get;
    free_att_fn free_att;
    free_assert_fn free_assert;
    cancel_id_fn cancel_id;
    cancel_fn cancel;
    error_name_fn error_name;
} g_wa;

static int load(char *why, size_t why_cap) {
    if (!g_wa.loaded) {
        HMODULE m = LoadLibraryExW(L"webauthn.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (m) {
            g_wa.version = (version_fn)(void *)GetProcAddress(m, "WebAuthNGetApiVersionNumber");
            g_wa.make = (make_fn)(void *)GetProcAddress(m, "WebAuthNAuthenticatorMakeCredential");
            g_wa.get = (get_fn)(void *)GetProcAddress(m, "WebAuthNAuthenticatorGetAssertion");
            g_wa.free_att = (free_att_fn)(void *)GetProcAddress(m, "WebAuthNFreeCredentialAttestation");
            g_wa.free_assert = (free_assert_fn)(void *)GetProcAddress(m, "WebAuthNFreeAssertion");
            g_wa.cancel_id = (cancel_id_fn)(void *)GetProcAddress(m, "WebAuthNGetCancellationId");
            g_wa.cancel = (cancel_fn)(void *)GetProcAddress(m, "WebAuthNCancelCurrentOperation");
            g_wa.error_name = (error_name_fn)(void *)GetProcAddress(m, "WebAuthNGetErrorName");
        }
        g_wa.loaded = 1 + (m && g_wa.version && g_wa.make && g_wa.get && g_wa.free_att && g_wa.free_assert);
    }
    if (g_wa.loaded != 2) {
        snprintf(why, why_cap, "this Windows has no WebAuthn (webauthn.dll), which chat reads security keys through");
        return -1;
    }
    DWORD v = g_wa.version();
    if (v < API_FOR_SALTS) {
        snprintf(why, why_cap, "this Windows's WebAuthn (version %lu) can't give chat a security key's hmac-secret: "
                 "version %d, in newer releases of Windows 11, can", (unsigned long)v, API_FOR_SALTS);
        return -1;
    }
    return 0;
}

int platform_seckey_usable(char *why, size_t why_cap) { return load(why, why_cap); }

static int say_error(HRESULT hr, const char *doing, char *why, size_t why_cap) {
    if (hr == NTE_USER_CANCELLED || hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) return SECKEY_CANCELLED;
    char name[64] = "";
    PCWSTR w = g_wa.error_name ? g_wa.error_name(hr) : NULL;
    if (w) WideCharToMultiByte(CP_UTF8, 0, w, -1, name, sizeof name, NULL, NULL);
    // Windows says NotAllowedError for a cancelled window, a timeout, and a key without the credential.
    if (strcmp(name, "NotAllowedError") == 0)
        snprintf(why, why_cap, "Windows stopped %s: its window was closed, it timed out, or the security key isn't "
                 "the one the save was locked with", doing);
    else
        snprintf(why, why_cap, "Windows couldn't %s (%s, 0x%08lx)", doing, name[0] ? name : "error", (unsigned long)hr);
    return -1;
}

// Windows's window can't see w->cancel, so this asks it to close when that's set.
static GUID g_cancel_id;
static int g_have_cancel_id, g_watching;
static seckey_wait_t *g_watch;

static void watch_cancel(void *arg) {
    (void)arg;
    while (__atomic_load_n(&g_watching, __ATOMIC_ACQUIRE)) {
        if (__atomic_load_n(&g_watch->cancel, __ATOMIC_ACQUIRE) && g_have_cancel_id && g_wa.cancel) {
            g_wa.cancel(&g_cancel_id);
            break;
        }
        Sleep(CANCEL_POLL_MS);
    }
}

static void begin_watch(seckey_wait_t *w) {
    g_have_cancel_id = g_wa.cancel_id && g_wa.cancel_id(&g_cancel_id) == S_OK;
    g_watch = w;
    __atomic_store_n(&g_watching, 1, __ATOMIC_RELEASE);
    if (platform_spawn_thread(watch_cancel, NULL) != 0) __atomic_store_n(&g_watching, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&w->stage, SECKEY_TOUCH, __ATOMIC_RELEASE);
}

static void end_watch(void) {
    __atomic_store_n(&g_watching, 0, __ATOMIC_RELEASE);
    Sleep(WATCH_STOP_MS);
}

// A random challenge in client data Windows only hashes: nothing checks this assertion's signature.
static void client_data(WEBAUTHN_CLIENT_DATA *cd, char json[CLIENT_DATA_MAX]) {
    uint8_t challenge[CHALLENGE_LEN];
    char hex[CHALLENGE_LEN * 2 + 1];
    gen_random(challenge, sizeof challenge);
    hex_encode(challenge, sizeof challenge, hex);
    snprintf(json, CLIENT_DATA_MAX, "{\"type\":\"chat\",\"challenge\":\"%s\"}", hex);
    *cd = (WEBAUTHN_CLIENT_DATA){ WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, (DWORD)strlen(json), (PBYTE)json,
                                  WEBAUTHN_HASH_ALGORITHM_SHA_256 };
}

static int get_secret(WEBAUTHN_CREDENTIAL *list, int n, const uint8_t salt[SECKEY_SALT_LEN], int uv,
                      uint8_t secret[SECKEY_SECRET_LEN], int *which, int *used_uv, seckey_wait_t *w, char *why,
                      size_t why_cap) {
    hmac_salt_t s = { SECKEY_SALT_LEN, (PBYTE)salt, 0, NULL };
    salt_values_t values = { &s, 0, NULL };
    ga_options_t o;
    memset(&o, 0, sizeof o);
    o.v5.dwVersion = GA_OPTIONS_VERSION_6;
    o.v5.dwTimeoutMilliseconds = WAIT_MS;
    o.v5.CredentialList.cCredentials = (DWORD)n;
    o.v5.CredentialList.pCredentials = list;
    o.v5.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    o.v5.dwUserVerificationRequirement = uv ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                                            : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
    o.v5.dwFlags = HMAC_SECRET_VALUES_FLAG;
    o.pHmacSecretSaltValues = &values;
    WEBAUTHN_CLIENT_DATA cd;
    char json[CLIENT_DATA_MAX];
    client_data(&cd, json);
    begin_watch(w);
    o.v5.pCancellationId = g_have_cancel_id ? &g_cancel_id : NULL;
    PWEBAUTHN_ASSERTION a = NULL;
    HRESULT hr = g_wa.get(GetForegroundWindow(), RP_ID, &cd, (PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS)(void *)&o, &a);
    end_watch();
    if (hr != S_OK || !a) return say_error(hr, "read the security key", why, why_cap);
    const assertion_t *ax = (const assertion_t *)(const void *)a;
    int rc = -1;
    *which = -1;
    for (int i = 0; i < n; i++)
        if (a->Credential.cbId == list[i].cbId && memcmp(a->Credential.pbId, list[i].pbId, list[i].cbId) == 0) *which = i;
    if (a->dwVersion >= ASSERTION_VERSION_3 && ax->pHmacSecret && ax->pHmacSecret->cbFirst == SECKEY_SECRET_LEN
        && ax->pHmacSecret->pbFirst && *which >= 0) {
        memcpy(secret, ax->pHmacSecret->pbFirst, SECKEY_SECRET_LEN);
        if (used_uv) *used_uv = a->cbAuthenticatorData > AD_FLAGS_AT && (a->pbAuthenticatorData[AD_FLAGS_AT] & FLAG_UV);
        rc = 0;
    } else {
        snprintf(why, why_cap, "Windows gave back no hmac-secret from the security key");
    }
    g_wa.free_assert(a);
    return rc;
}

int platform_seckey_make(const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t cred[SECKEY_CRED_MAX],
                         size_t *cred_len, int *uv, uint8_t secret[SECKEY_SECRET_LEN], seckey_wait_t *w, char *why,
                         size_t why_cap) {
    (void)pin;
    if (load(why, why_cap) != 0) return -1;
    uint8_t uid[USER_ID_LEN];
    gen_random(uid, sizeof uid);
    WEBAUTHN_RP_ENTITY_INFORMATION rp = { WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, RP_ID, L"chat", NULL };
    WEBAUTHN_USER_ENTITY_INFORMATION user = { WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION, sizeof uid, uid, L"chat",
                                              NULL, L"chat" };
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg = { WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                                               WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 };
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS params = { 1, &alg };
    BOOL on = TRUE;
    WEBAUTHN_EXTENSION ext = { WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET, sizeof on, &on };
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS o;
    memset(&o, 0, sizeof o);
    o.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4;
    o.dwTimeoutMilliseconds = WAIT_MS;
    o.Extensions.cExtensions = 1;
    o.Extensions.pExtensions = &ext;
    o.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    o.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
    o.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    WEBAUTHN_CLIENT_DATA cd;
    char json[CLIENT_DATA_MAX];
    client_data(&cd, json);
    begin_watch(w);
    o.pCancellationId = g_have_cancel_id ? &g_cancel_id : NULL;
    PWEBAUTHN_CREDENTIAL_ATTESTATION att = NULL;
    HRESULT hr = g_wa.make(GetForegroundWindow(), &rp, &user, &params, &cd, &o, &att);
    end_watch();
    if (hr != S_OK || !att) return say_error(hr, "register the security key", why, why_cap);
    int hmac_on = 0;
    if (att->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2)
        for (DWORD i = 0; i < att->Extensions.cExtensions; i++) {
            const WEBAUTHN_EXTENSION *e = &att->Extensions.pExtensions[i];
            if (wcscmp(e->pwszExtensionIdentifier, WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET) == 0 && e->cbExtension == sizeof(BOOL)
                && e->pvExtension)
                hmac_on = *(const BOOL *)e->pvExtension != FALSE;
        }
    int ok = att->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 && att->cbCredentialId > 0
          && att->cbCredentialId <= SECKEY_CRED_MAX && hmac_on;
    if (ok) {
        memcpy(cred, att->pbCredentialId, att->cbCredentialId);
        *cred_len = att->cbCredentialId;
    }
    g_wa.free_att(att);
    if (!ok) {
        snprintf(why, why_cap, hmac_on ? "Windows gave back no credential" : "this security key doesn't have hmac-secret, "
                 "which chat needs");
        return -1;
    }
    __atomic_add_fetch(&w->touches, 1, __ATOMIC_RELEASE);
    WEBAUTHN_CREDENTIAL one = { WEBAUTHN_CREDENTIAL_CURRENT_VERSION, (DWORD)*cred_len, cred, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY };
    int which, rc = get_secret(&one, 1, salt, 0, secret, &which, uv, w, why, why_cap);
    if (rc == 0) __atomic_add_fetch(&w->touches, 1, __ATOMIC_RELEASE);
    return rc;
}

int platform_seckey_secret(const uint8_t *const *creds, const size_t *lens, const int *uv, int n,
                           const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t secret[SECKEY_SECRET_LEN],
                           seckey_wait_t *w, char *why, size_t why_cap) {
    (void)pin;
    if (load(why, why_cap) != 0) return -1;
    WEBAUTHN_CREDENTIAL list[CREDS_MAX];
    int any_uv = 0;
    if (n > CREDS_MAX) n = CREDS_MAX;
    for (int i = 0; i < n; i++) {
        list[i] = (WEBAUTHN_CREDENTIAL){ WEBAUTHN_CREDENTIAL_CURRENT_VERSION, (DWORD)lens[i], (PBYTE)creds[i],
                                         WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY };
        any_uv |= uv[i];
    }
    int which, rc = get_secret(list, n, salt, any_uv, secret, &which, NULL, w, why, why_cap);
    if (rc != 0) return rc;
    __atomic_add_fetch(&w->touches, 1, __ATOMIC_RELEASE);
    return which;
}
