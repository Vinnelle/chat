// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"

const setting_def_t SETTINGS[] = {
    { SET_ROUTING, "Network", NULL, "routing", "Routing", K_CHOICE, "dht|tor",
      "dht: UDP directly between peers, found using the options below. tor: onion services, plus the Nostr "
      "relays through Tor to meet DHT members. Hides your IP address from everyone. Uses a running tor or "
      "starts chat's own, and connecting takes longer. Applies to sessions you open from now on." },
    { SET_DHT4, NULL, "DHT", "dht", "BitTorrent DHT (IPv4)", K_TOGGLE, "on|off",
      "Finds peers on the internet through the public BitTorrent DHT. DHT nodes see your IP address next to a "
      "lookup key only room members can work out, and a node id that changes with it every hour." },
    { SET_DHT6, NULL, NULL, "dht6", "IPv6 DHT", K_TOGGLE, "on|off",
      "Also looks for peers on the IPv6 DHT (BEP 32). IPv6 usually has no NAT to punch through, so peers there "
      "connect more reliably." },
    { SET_PORTMAP, NULL, NULL, "portmap", "Router port mapping", K_TOGGLE, "on|off",
      "Asks your router to forward this session's UDP port (PCP, NAT-PMP or UPnP-IGD), so peers behind NATs that "
      "can't be hole punched can still reach you. Removed when the session ends. The router may log it." },
    { SET_LAN, NULL, NULL, "lan", "LAN discovery", K_TOGGLE, "on|off",
      "Broadcasts an encrypted beacon on your local network, so room members on it can find you without the "
      "internet." },
    { SET_TOR_LAUNCH, NULL, "Tor", "torlaunch", "Start chat's own tor", K_CHOICE, "auto|always|never",
      "auto: use a tor that's already running if its control port lets chat log in (it keeps its entry guards "
      "and any bridges), otherwise start chat's own. always: chat's own, separate from any other tor, but with "
      "new entry guards each run and nothing from your torrc. never: only a running tor. Chat's own tor uses "
      "random 127.0.0.1 ports, a cookie login and a private temporary folder deleted on exit." },
    { SET_TOR_PATH, NULL, NULL, "torpath", "Tor program", K_TEXT, "PATH",
      "The tor program chat starts: a full path, or empty for tor on PATH or in the usual folders. It must be a "
      "program that only root or you can change." },
    { SET_TOR_SOCKS, NULL, NULL, "torsocks", "Tor SOCKS port", K_TEXT, "HOST:PORT",
      "Where to look for a running tor's SOCKS port (host:port). With the defaults, Tor Browser's "
      "127.0.0.1:9150 is tried too. Applies to sessions you open from now on." },
    { SET_TOR_CONTROL, NULL, NULL, "torcontrol", "Tor control port", K_TEXT, "HOST:PORT",
      "Where to look for a running tor's control port (host:port). It needs ControlPort on, and chat has to be "
      "able to read its cookie file (or have its password). Applies to sessions you open from now on." },
    { SET_TOR_PASSWORD, NULL, NULL, "torpassword", "Tor control password", K_SECRET, NULL,
      "Only for a tor set up with HashedControlPassword. Kept in memory only. Applies to sessions you open from now on." },
    // After both modes' rows: the relays apply in both, so they stay put when the mode changes.
    { SET_NOSTR, NULL, "Relays", "nostr", "Nostr relays", K_CHOICE, "off|on|always",
      "on: DHT routing only connects to the relays while it needs them (nobody reached yet, or a peer UDP can't"
      " reach) and disconnects a minute after. always: stays connected, so Tor members can find a room whose "
      "members all reach each other directly (they only meet on the relays). Tor routing reaches them through "
      "Tor and always stays connected. Each event has a one-off key, a random kind, a fixed size and fresh "
      "encryption, under a tag that changes every 10 minutes, with a new connection for each tag." },
    { SET_RELAYS, NULL, NULL, "relays", "Relay list", K_TEXT, "wss://URL ... (up to 6)",
      "The relays the fallback uses: up to 6 wss:// URLs, separated by spaces or commas." },
    { SET_PORT, NULL, "Advanced", "port", "UDP port for new sessions", K_TEXT, "N",
      "The UDP port new sessions listen on. 0 picks a free one each time. :port moves an open session to another." },
    { SET_NET, NULL, NULL, "net", "Network log", K_CHOICE, "normal|verbose",
      "How much of the network the console shows, in every session. verbose adds every handshake packet, relay "
      "and Tor event." },
    { SET_NICK, "Profile", NULL, "nick", "Nickname", K_TEXT, "NAME", "Your name in every session." },
    { SET_COLOUR, NULL, NULL, "colour", "Colour", K_TEXT, "NAME|#RRGGBB",
      "Your colour in every session. h/l step through the palette, and Enter takes a name or #RRGGBB." },
    { SET_SIGN, NULL, "Keys", "sign", "Signing identity", K_ACTION, "off|age|pgp|age:PATH|pgp:PATH",
      "A key that signs your handshakes so peers can check it's you. Either an AGE or PGP key made here from a "
      "password, or your own key from a file or pasted in. Enter picks one, replaces it or turns signing off. "
      "Kept in memory only, unless :install saves it: a key file's path, or any other key sealed to disk." },
    { SET_AGE_RECIPIENT, NULL, NULL, "agerecipient", "AGE recipient", K_ACTION, NULL,
      "The age1... string others give to age -r to encrypt files to you. Enter copies it to the clipboard." },
    { SET_PGP_PUBKEY, NULL, NULL, "pgpkey", "PGP public key", K_ACTION, NULL,
      "The public half of the PGP key made here, shown by its fingerprint, for others to gpg --import. Enter "
      "copies it to the clipboard. It's in the console too." },
    { SET_AUTOSAVE, "Security", NULL, "autosave", "Autosave", K_TOGGLE, "on|off",
      "Once chat is installed: on saves a setting you change, and a key you verify or forget, as you change it. "
      "off keeps changes until chat exits, unless :save saves them. The signing key is only saved by :save or "
      ":install either way, so a key you're trying out isn't kept by accident." },
    { SET_DEVICE_LOCK, NULL, "Unlocking", "devicelock", "Device lock", K_TOGGLE, "on|off",
      "Requires a secret this device keeps (in its TPM, where there's one) to unlock the save, so it can't be "
      "unlocked anywhere else." },
    { SET_SECURITY_KEY, NULL, NULL, "securitykey", "Security key", K_TOGGLE, "on|off",
      "Requires your FIDO2 security key (a YubiKey, say) to unlock the save: a touch each time, and its PIN if it "
      "has one." },
    { SET_AUTHENTICATOR, NULL, NULL, "authenticator", "Authenticator app", K_TOGGLE, "on|off",
      "Requires the 6-digit code from an authenticator app (Aegis, Google Authenticator, 2FAS...) to unlock the "
      "save." },
    { SET_DESTROY, NULL, "Duress", "destroy", "Self-destruct", K_CHOICE, "off|3|5|10",
      "Deletes what :install saves after this many wrong passphrases in a row, so a found or taken device can't "
      "be guessed at forever. The count and the limit are kept next to the save, not sealed (they have to be read "
      "before the passphrase opens anything), so anyone who can read the files sees them, and someone who copies "
      "the files first can reset the count: this stops guessing at the keyboard, not a forensic copy. A right "
      "passphrase clears the count." },
    { SET_SHADOW, NULL, NULL, "shadow", "Shadow password", K_ACTION, "on|off",
      "A second passphrase that opens a decoy, a clean save with no key or verified peers, in place of the real "
      "one, whose files it replaces or deletes. The decoy needs the same security key, device and code, every "
      "passphrase takes as long, and every save has a decoy's file, filled with random bytes when there's no "
      "decoy, so neither the files nor the time it takes say which passphrase opened it. Deleting isn't erasing: "
      "a copy made before, a backup or the disk itself can still hold the real save, sealed under its own "
      "passphrase. Enter sets or removes it. Only while a save is open, and it needs the save's own factors to "
      "hand." },
    { SET_VERIFY, "Chat", NULL, "verify", "Compare verify codes", K_CHOICE, "required|optional",
      "Anyone with a session's id and password could sit between two members and read what they say. When a peer "
      "joins, chat shows a code to compare with them over another channel. It only matches on both ends if "
      "nobody is in the middle. required: nothing you send goes to a peer until you mark it as matching "
      "(:verify NICK ok). optional: messages go to everyone, compared or not." },
    { SET_NOTIFY, NULL, NULL, "notify", "Notifications", K_CHOICE, "all|mentions|none",
      "Desktop notifications, for open and new sessions: every message, mentions of your nick, or none." },
    { SET_PREVIEW, NULL, NULL, "preview", "Notification preview", K_CHOICE, "off|nick|message",
      "What a notification shows. off: only that a message came in. nick: who it's from. message: who, and what "
      "they said. Desktops keep notifications (Windows writes them to disk), so what they show can outlast chat. "
      "The session is never shown, since its id is all someone needs to join one with a blank password." },
    { SET_HISTORY, NULL, "History", "history", "Keep history", K_TOGGLE, "on|off",
      "Keeps each session's messages, sealed in the save that's open (so it needs :install), and shows them when "
      "you join that session again with the same id and password. Everyone in the session is told while you keep "
      "it, and you're told when they do. Only the full-screen UI keeps it. :history forget deletes this "
      "session's, :history forget all every session's." },
    { SET_FILE_LIMIT, NULL, "Files", "filelimit", "File size limit", K_TEXT, "SIZE (8M, 500K, 1G)",
      "The largest file chat fetches when you ask. An offer over the limit says so, and :download N anyway (or "
      ":show N anyway) fetches it regardless. Nothing is fetched until you ask. Files can be up to 1 GB." },
    { SET_FAST_FILES, NULL, NULL, "fastfiles", "Fast file transfers", K_TOGGLE, "on|off",
      "off: files are sent in chat's regular slots, so a transfer doesn't show up on the network, but it's slow: "
      "about 25 KB a minute, half that through the relays (where Tor and DHT members meet). on: while you send a "
      "file, your slots to that peer come every few milliseconds. It takes seconds instead of minutes, but anyone "
      "watching the network sees a burst about the size of the file. Through the relays it goes as often as they "
      "allow, about twice the normal rate, and the relays can see that. Only the sender's setting matters." },
    { SET_BETAS, NULL, "Updates", "betas", "Beta releases", K_TOGGLE, "on|off",
      "on: :update installs betas too, the test builds of the next release. They're signed and checked like a "
      "release, but have had less testing. off: only releases, so a beta you're on stays until its release is "
      "out, and :update then takes you on to that." },
};

_Static_assert(N_SETTINGS == N_SETTING_IDS, "every setting has a row");

static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };

static const char *const PREVIEW_NAMES[] = { "off", "nick", "message" };

static const char *const ON_OFF[] = { "off", "on" };

static const char *const ROUTE_NAMES[] = { "dht", "tor" };

static const char *const NOSTR_NAMES[] = { "off", "on", "always" };

static const char *const VERIFY_NAMES[] = { "required", "optional" };

static const char *const NET_LOG_NAMES[] = { "normal", "verbose" };

static const char *const DESTROY_NAMES[] = { "off", "3", "5", "10" };

static const int DESTROY_VALS[] = { 0, 3, 5, 10 };

setting_id_t g_edit_id;

int settings_index(setting_id_t id) {
    for (int i = 0; i < N_SETTINGS; i++) if (SETTINGS[i].id == id) return i;
    return 0;
}

const setting_def_t *setting_def(setting_id_t id) { return &SETTINGS[settings_index(id)]; }

const setting_def_t *setting_by_key(const char *key) {
    if (strcmp(key, "color") == 0) key = "colour";
    for (int i = 0; i < N_SETTINGS; i++) if (strcmp(SETTINGS[i].key, key) == 0) return &SETTINGS[i];
    return NULL;
}

static int dht_setting(setting_id_t id) { return id == SET_DHT4 || id == SET_DHT6; }

static int dht_routing_only_setting(setting_id_t id) { return id == SET_PORTMAP || id == SET_LAN; }

static int tor_only_setting(setting_id_t id) {
    return id == SET_TOR_LAUNCH || id == SET_TOR_PATH || id == SET_TOR_SOCKS || id == SET_TOR_CONTROL
        || id == SET_TOR_PASSWORD;
}

// Settings that don't apply right now aren't listed: the DHT ones in Tor mode, the Tor ones in
// DHT mode, the relay list with relays off, the AGE recipient without an AGE identity, and the
// PGP public key without a PGP key made here.
int setting_shown(setting_id_t id) {
    route_mode_t m = g_app.route.mode;
    if (m != ROUTE_DHT && dht_routing_only_setting(id)) return 0;
    if (m == ROUTE_TOR && dht_setting(id)) return 0;
    if (m != ROUTE_TOR && tor_only_setting(id)) return 0;
    if (id == SET_RELAYS && !g_app.route.nostr) return 0;
    if (id == SET_AGE_RECIPIENT && g_app.identity_source != IDENT_AGE) return 0;
    if (id == SET_PGP_PUBKEY && !pgp_key_made_here()) return 0;
    return 1;
}

static const char *setting_hidden_why(setting_id_t id) {
    if (dht_routing_only_setting(id)) return "it only applies with dht routing";
    if (dht_setting(id)) return "it doesn't apply with tor routing";
    if (tor_only_setting(id)) return "it only applies with tor routing";
    if (id == SET_RELAYS) return "it only applies with the Nostr relays on";
    if (id == SET_PGP_PUBKEY) return "it needs a PGP signing key made here";
    return "it needs an AGE signing identity";
}

// A toggle or choice row's values, in the order h/l steps through them, and the index of the
// current one. Other rows have none, and get -1.
int setting_options(setting_id_t id, const char *const **names, int *n) {
    const routing_t *r = &g_app.route;
    *names = ON_OFF;
    *n = 2;
    switch (id) {
        case SET_ROUTING:    *names = ROUTE_NAMES; *n = 2; return (int)r->mode;
        case SET_DHT4:       return r->dht4 != 0;
        case SET_DHT6:       return r->dht6 != 0;
        case SET_PORTMAP:    return r->portmap != 0;
        case SET_LAN:        return r->lan != 0;
        case SET_NOSTR:      *names = NOSTR_NAMES; *n = 3; return r->nostr;
        case SET_VERIFY:     *names = VERIFY_NAMES; return g_app.verify_optional != 0;
        case SET_FAST_FILES: return g_app.fast_files != 0;
        case SET_HISTORY:    return g_app.history != 0;
        case SET_BETAS:      return g_app.betas != 0;
        case SET_AUTOSAVE:   return g_app.autosave != 0;
        case SET_DEVICE_LOCK: return g_app.device_lock != 0;
        case SET_SECURITY_KEY: return g_app.key_factor != 0;
        case SET_AUTHENTICATOR: return g_app.code_factor != 0;
        case SET_DESTROY: {
            *names = DESTROY_NAMES; *n = 4;
            for (int i = 0; i < 4; i++) if (DESTROY_VALS[i] == g_app.destroy_limit) return i;
            return 0;
        }
        case SET_TOR_LAUNCH: *names = TOR_LAUNCH_NAMES; *n = 3; return g_app.tor_launch;
        case SET_NOTIFY:     *names = NOTIFY_NAMES; *n = 3; return (int)g_app.notify_mode;
        case SET_PREVIEW:    *names = PREVIEW_NAMES; *n = 3; return (int)g_app.notify_preview;
        case SET_NET:        *names = NET_LOG_NAMES; return g_app.net_verbose != 0;
        default:             *names = NULL; *n = 0; return -1;
    }
}

static const char *const SIGN_NAMES[] = { "off", "age", "pgp" };

// What :set takes for a row, for the command line's menu: its values, and the signing identity's
// kinds (age:PATH and pgp:PATH, for a key file, are typed in full, and a pasted key is only chosen on
// the page).
int setting_choices(setting_id_t id, const char *const **names, int *n) {
    if (id != SET_SIGN) return setting_options(id, names, n);
    *names = SIGN_NAMES;
    *n = 3;
    return g_app.identity_source == IDENT_AGE ? 1 : g_app.identity_source == IDENT_PGP ? 2 : 0;
}

// How the page draws a row's value: a switch, a choice h/l steps through, a way into another
// page, or text.
tui_value_kind_t setting_kind(const setting_def_t *d) {
    const char *const *names;
    int n, cur = setting_options(d->id, &names, &n);
    if (d->kind == K_TOGGLE) return cur > 0 ? TUI_V_ON : TUI_V_OFF;
    if (d->kind == K_CHOICE) return TUI_V_CHOICE;
    if (d->id == SET_SIGN || d->id == SET_SHADOW) return TUI_V_LINK;
    if (d->kind == K_SECRET) return TUI_V_MUTED;
    return TUI_V_TEXT;
}

void setting_value(setting_id_t id, char *out, size_t cap) {
    const char *const *names;
    int n, cur = setting_options(id, &names, &n);
    if (cur >= 0) { snprintf(out, cap, "%s", names[cur]); return; }
    const routing_t *r = &g_app.route;
    switch (id) {
        case SET_RELAYS: {
            size_t p = 0;
            out[0] = '\0';
            for (int i = 0; i < r->n_relays && p < cap; i++)
                p += (size_t)snprintf(out + p, cap - p, "%s%s", i ? " " : "", r->relays[i] + 6);
            if (r->n_relays == 0) snprintf(out, cap, "none");
            break;
        }
        case SET_TOR_PATH: {
            char found[1024];
            if (g_app.tor_path[0]) snprintf(out, cap, "%s", g_app.tor_path);
            else if (platform_find_program("tor", NULL, found, sizeof found) == 0) snprintf(out, cap, "found %s", found);
            else snprintf(out, cap, "not installed");
            break;
        }
        case SET_FILE_LIMIT:   file_format_size(g_app.file_cap ? g_app.file_cap : FILE_CAP_DEFAULT, out, cap); break;
        case SET_TOR_SOCKS:    snprintf(out, cap, "%s", r->tor.socks); break;
        case SET_TOR_CONTROL:  snprintf(out, cap, "%s", r->tor.control); break;
        case SET_TOR_PASSWORD: snprintf(out, cap, "%s", r->tor.password[0] ? "set" : "not set (cookie or no login)"); break;
        case SET_NICK:         snprintf(out, cap, "%s", g_app.nick); break;
        case SET_COLOUR: {
            const char *name = NULL;
            for (int i = 0; i < COLOR_PALETTE_N; i++)
                if (COLOR_PALETTE[i].r == g_app.color[0] && COLOR_PALETTE[i].g == g_app.color[1] && COLOR_PALETTE[i].b == g_app.color[2])
                    name = COLOR_PALETTE[i].name;
            if (name) snprintf(out, cap, "%s", name);
            else snprintf(out, cap, "#%02x%02x%02x", g_app.color[0], g_app.color[1], g_app.color[2]);
            break;
        }
        case SET_SIGN: {
            if (g_app.identity_source == IDENT_NONE) { snprintf(out, cap, "off"); break; }
            uint8_t fp[ID_FP_LEN]; identity_fingerprint(g_app.identity.pub, fp);
            char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(fp, ID_FP_LEN, fphex);
            snprintf(out, cap, "%s%s, fingerprint %s", g_app.identity_source == IDENT_AGE ? "age" : "pgp",
                     g_app.key_origin == KEY_DERIVED ? " from password" : "", fphex);
            break;
        }
        case SET_AGE_RECIPIENT: {
            if (g_app.identity_source != IDENT_AGE) { snprintf(out, cap, "none"); break; }
            char recipient[AGE_RECIPIENT_STRLEN + 1];
            age_export_recipient(&g_app.identity, recipient);
            snprintf(out, cap, "%s", recipient);
            break;
        }
        case SET_PGP_PUBKEY: {
            if (!pgp_key_made_here()) { snprintf(out, cap, "none"); break; }
            char armor[PGP_ARMOR_MAX]; uint8_t fp[PGP_FP_LEN];
            pgp_public_key(armor, fp);
            char fphex[PGP_FP_LEN * 2 + 1]; hex_encode(fp, PGP_FP_LEN, fphex);
            snprintf(out, cap, "%s", fphex);
            break;
        }
        case SET_PORT:
            if (g_app.default_port) snprintf(out, cap, "%u", (unsigned)g_app.default_port);
            else snprintf(out, cap, "0 (a free one)");
            break;
        case SET_SHADOW:
            snprintf(out, cap, "%s", g_app.installed && !g_app.locked && install_has_shadow() ? "on" : "off");
            break;
        default:
            out[0] = '\0';
            break;
    }
}

// A row's value in the form :set takes. 0 for a secret, or a value that comes from the signing key.
int setting_text(setting_id_t id, char *out, size_t cap) {
    const setting_def_t *d = setting_def(id);
    // What a save needs to open is how it's sealed, not a setting in it.
    if (d->kind == K_SECRET || d->kind == K_ACTION || id == SET_DEVICE_LOCK || id == SET_SECURITY_KEY
        || id == SET_AUTHENTICATOR || id == SET_DESTROY)
        return 0;
    const routing_t *r = &g_app.route;
    switch (id) {
        case SET_RELAYS: {
            size_t p = 0;
            out[0] = '\0';
            for (int i = 0; i < r->n_relays && p < cap; i++)
                p += (size_t)snprintf(out + p, cap - p, "%s%s", i ? " " : "", r->relays[i]);
            break;
        }
        case SET_PORT:     snprintf(out, cap, "%u", (unsigned)g_app.default_port); break;
        case SET_TOR_PATH: copy_str(out, g_app.tor_path, cap); break;
        case SET_FILE_LIMIT: {
            uint64_t v = g_app.file_cap ? g_app.file_cap : FILE_CAP_DEFAULT;
            const char *unit = v % (1024u * 1024 * 1024) == 0 ? "G" : v % (1024 * 1024) == 0 ? "M" : v % 1024 == 0 ? "K" : "";
            uint64_t per = unit[0] == 'G' ? 1024u * 1024 * 1024 : unit[0] == 'M' ? 1024 * 1024 : unit[0] == 'K' ? 1024 : 1;
            snprintf(out, cap, "%llu%s", (unsigned long long)(v / per), unit);
            break;
        }
        default: setting_value(id, out, cap); break;
    }
    return 1;
}

// A row is only saved while it isn't the default, so if a later version changes a default you
// still get it. Once installed, a row changed in chat is saved, but one set by a command line
// option isn't. With autosave off, a changed row waits in g_unsaved_rows for autosave or :save.
char g_setting_defaults[N_SETTINGS][ROW_TEXT_MAX];

char g_saved_rows[N_SETTINGS][ROW_TEXT_MAX];

char g_seen_rows[N_SETTINGS][ROW_TEXT_MAX];

int g_unsaved_rows[N_SETTINGS];

void note_setting_defaults(void) {
    for (int i = 0; i < N_SETTINGS; i++)
        if (!setting_text(SETTINGS[i].id, g_setting_defaults[i], sizeof g_setting_defaults[i])) g_setting_defaults[i][0] = '\0';
    memcpy(g_saved_rows, g_setting_defaults, sizeof g_saved_rows);
}

void note_settings_seen(void) {
    for (int i = 0; i < N_SETTINGS; i++)
        if (!setting_text(SETTINGS[i].id, g_seen_rows[i], sizeof g_seen_rows[i])) g_seen_rows[i][0] = '\0';
    memset(g_unsaved_rows, 0, sizeof g_unsaved_rows);
}

// Rows that have moved to another section keep their table, so files saved before still load.
const char *setting_table(setting_id_t id) {
    return id < SET_NICK ? "network" : id < SET_VERIFY ? "profile" : "chat";
}

size_t put_text(char *out, size_t p, size_t cap, const char *s) {
    size_t n = strlen(s);
    if (p >= cap || n >= cap - p) return cap;
    memcpy(out + p, s, n + 1);
    return p + n;
}

static size_t put_row_value(int i, const char *v, char *out, size_t p, size_t cap) {
    if (SETTINGS[i].kind == K_TOGGLE) return put_text(out, p, cap, strcmp(v, "on") == 0 ? "true" : "false");
    if (SETTINGS[i].id == SET_PORT) return put_text(out, p, cap, v);
    if (SETTINGS[i].id != SET_RELAYS) return toml_put_str(out, p, cap, v);
    char urls[ROW_TEXT_MAX];
    copy_str(urls, v, sizeof urls);
    p = put_text(out, p, cap, "[");
    int first = 1;
    for (char *url = strtok(urls, " "); url; url = strtok(NULL, " "), first = 0) {
        if (!first) p = put_text(out, p, cap, ", ");
        p = toml_put_str(out, p, cap, url);
    }
    return put_text(out, p, cap, "]");
}

// -1 if it doesn't fit.
int settings_text(char *out, size_t cap) {
    size_t p = 0;
    const char *table = "";
    out[0] = '\0';
    for (int id = 0; id < N_SETTING_IDS; id++) {
        int i = settings_index((setting_id_t)id);
        if (strcmp(g_saved_rows[i], g_setting_defaults[i]) == 0) continue;
        const char *t = setting_table((setting_id_t)id);
        if (strcmp(t, table) != 0) {
            p = put_text(out, p, cap, p ? "\n[" : "[");
            p = put_text(out, p, cap, t);
            p = put_text(out, p, cap, "]\n");
            table = t;
        }
        p = put_text(out, p, cap, SETTINGS[i].key);
        p = put_text(out, p, cap, " = ");
        p = put_row_value(i, g_saved_rows[i], out, p, cap);
        p = put_text(out, p, cap, "\n");
    }
    return p < cap ? 0 : -1;
}

// Checked before every frame, so any change to a row (from the page or :set) is picked up. The
// autosave row itself is always saved, so turning it on or off lasts.
void keep_settings_saved(void) {
    if (!g_app.installed) return;
    int changed = 0, held = 0;
    for (int i = 0; i < N_SETTINGS; i++) {
        char v[ROW_TEXT_MAX];
        if (!setting_text(SETTINGS[i].id, v, sizeof v)) continue;
        int fresh = strcmp(v, g_seen_rows[i]) != 0;
        if (fresh) {
            copy_str(g_seen_rows[i], v, sizeof g_seen_rows[i]);
            g_unsaved_rows[i] = strcmp(v, g_saved_rows[i]) != 0;
        }
        if (!g_unsaved_rows[i]) continue;
        if (!g_app.autosave && SETTINGS[i].id != SET_AUTOSAVE) { held |= fresh; continue; }
        copy_str(g_saved_rows[i], v, sizeof g_saved_rows[i]);
        g_unsaved_rows[i] = 0;
        changed = 1;
    }
    size_t n = strlen(g_app.message);
    if (held && n > 0) snprintf(g_app.message + n, sizeof g_app.message - n, " \xc2\xb7 not saved (autosave is off)");
    if (!changed) return;
    static char text[INSTALL_SETTINGS_MAX];
    if (settings_text(text, sizeof text) != 0 || install_write_settings(text) != 0) {
        char where[900] = "";
        install_where(install_current(), where, sizeof where);
        note("couldn't save that in %s/settings - it lasts until chat exits", where);
        return;
    }
    n = strlen(g_app.message);
    if (n > 0 && !held) snprintf(g_app.message + n, sizeof g_app.message - n, " \xc2\xb7 saved");
}

// Pushes the routing settings to the open sessions, where the toggles take effect immediately. On
// the startup settings page nothing goes on the network before Done, so settings_done does it then.
// While a save opened mid-run loads, its rows aren't sent to open sessions one by one: they get the
// final values once it's loaded (settings_to_sessions), so peers don't see a nick go and come back.
int g_hold_sessions;

static int takes_settings(int i) {
    return g_app.used[i] && !g_app.sessions[i].initialising && !g_hold_sessions;
}

void settings_to_sessions(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!takes_settings(i)) continue;
        chat_t *e = &g_app.sessions[i].engine;
        chat_apply_routing(e, &g_app.route);
        chat_set_file_options(e, g_app.file_cap, g_app.fast_files);
        e->verify_required = !g_app.verify_optional;
        e->notify_mode = g_app.notify_mode;
        e->notify_preview = g_app.notify_preview;
        e->net_verbose = g_app.net_verbose;
        if (strcmp(e->nick, g_app.nick) != 0) chat_set_nick(e, g_app.nick);
        if (memcmp(e->my_color, g_app.color, 3) != 0) chat_set_colour(e, g_app.color);
    }
}

static void routing_changed(setting_id_t id) {
    int later = 0, any = 0;
    if (!g_app.onboarding) {
        sync_update_proxy();
        tor_link_ensure(now_seconds());
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!takes_settings(i)) continue;
        later |= chat_apply_routing(&g_app.sessions[i].engine, &g_app.route);
        any = 1;
    }
    char v[160]; setting_value(id, v, sizeof v);
    const char *label = setting_def(id)->label;
    if (id == SET_ROUTING || tor_only_setting(id) || (later && !dht_routing_only_setting(id)))
        note("%s: %s - for sessions you open from now on%s", label, v, any ? "; open ones keep their routing" : "");
    else
        note("%s: %s%s", label, v, any ? " - applied to open sessions too" : "");
}

static void set_colour_all(void) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (takes_settings(i)) chat_set_colour(&g_app.sessions[i].engine, g_app.color);
}

// Security keys too.
void device_check(void) {
    g_app.device_why[0] = g_app.seckey_why[0] = '\0';
    g_app.device_kind = platform_device_kind(g_app.device_why, sizeof g_app.device_why);
    g_app.seckey_ok = platform_seckey_usable(g_app.seckey_why, sizeof g_app.seckey_why) == 0;
}

const char DEVICE_REMINDER[] =
    "* device lock: before you clear the TPM, update the firmware, replace the motherboard or reinstall the OS, "
    ":set devicelock off first, and lock it again after - or the save is gone for good";

const char KEY_REMINDER[] =
    "* security key: if it's lost, broken or reset, the save is gone for good - :set securitykey off before you "
    "reset it or stop using it";

// Turning the lock off never needs the device, so a save locked to it, or a lock already chosen,
// stays usable. The same for a security key.
static int device_lock_greyed(void) { return g_app.device_kind == DEVICE_NONE && !g_app.device_lock; }

static int security_key_greyed(void) { return !g_app.seckey_ok && !g_app.key_factor; }

int row_greyed(setting_id_t id) {
    return (id == SET_DEVICE_LOCK && device_lock_greyed()) || (id == SET_SECURITY_KEY && security_key_greyed());
}

// It's sealed in a save, so without one open there's nowhere to keep it.
static void history_choose(int on) {
    if (on && (!g_app.installed || g_app.locked)) {
        note("Keep history: it's kept sealed in a save, so it needs one open - :install makes one");
        return;
    }
    g_app.history = on;
    history_sync(now_seconds());
    if (on) note("Keep history: on - each session's is sealed in the save %s, and everyone in it is told",
                 install_shown_name(install_current()));
    else note("Keep history: off - what was kept stays in the save until :history forget");
}

// Sets a toggle or choice row to its i-th value, wherever it applies.
void setting_choose(setting_id_t id, int i) {
    routing_t *r = &g_app.route;
    switch (id) {
        case SET_ROUTING: r->mode = (route_mode_t)i; routing_changed(id); return;
        case SET_DHT4:    r->dht4 = i; routing_changed(id); return;
        case SET_DHT6:    r->dht6 = i; routing_changed(id); return;
        case SET_PORTMAP: r->portmap = i; routing_changed(id); return;
        case SET_LAN:     r->lan = i; routing_changed(id); return;
        case SET_NOSTR:   r->nostr = i; routing_changed(id); return;
        case SET_VERIFY:
            g_app.verify_optional = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) g_app.sessions[s].engine.verify_required = !i;
            break;
        case SET_TOR_LAUNCH:
            g_app.tor_launch = i;
            note("Start chat's own tor: %s - for the next tor chat looks for; a tor already in use stays",
                 TOR_LAUNCH_NAMES[i]);
            return;
        case SET_NOTIFY:
            g_app.notify_mode = (notify_mode_t)i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) g_app.sessions[s].engine.notify_mode = g_app.notify_mode;
            break;
        case SET_PREVIEW:
            g_app.notify_preview = (notify_preview_t)i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) g_app.sessions[s].engine.notify_preview = g_app.notify_preview;
            break;
        case SET_NET:
            g_app.net_verbose = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) g_app.sessions[s].engine.net_verbose = i;
            break;
        case SET_FAST_FILES:
            g_app.fast_files = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) chat_set_file_options(&g_app.sessions[s].engine, g_app.file_cap, i);
            break;
        case SET_BETAS:
            g_app.betas = i;
            break;
        case SET_AUTOSAVE:
            g_app.autosave = i;
            autosave_changed();
            break;
        case SET_DEVICE_LOCK: device_lock_choose(i); return;
        case SET_SECURITY_KEY: factor_choose(INSTALL_FACTOR_KEY, i); return;
        case SET_AUTHENTICATOR: factor_choose(INSTALL_FACTOR_CODE, i); return;
        case SET_DESTROY: destroy_choose(DESTROY_VALS[i]); return;
        case SET_HISTORY: history_choose(i); return;
        default: return;
    }
    char v[32]; setting_value(id, v, sizeof v);
    note("%s: %s", setting_def(id)->label, v);
}

// h/l on a row: the next or previous value, wrapping around. The colour steps through the palette.
void setting_step(setting_id_t id, int dir) {
    if (id == SET_COLOUR) {
        int cur = -1;
        for (int i = 0; i < COLOR_PALETTE_N; i++)
            if (COLOR_PALETTE[i].r == g_app.color[0] && COLOR_PALETTE[i].g == g_app.color[1] && COLOR_PALETTE[i].b == g_app.color[2]) cur = i;
        int next = cur < 0 ? 0 : (cur + (dir < 0 ? COLOR_PALETTE_N - 1 : 1)) % COLOR_PALETTE_N;
        g_app.color[0] = COLOR_PALETTE[next].r; g_app.color[1] = COLOR_PALETTE[next].g; g_app.color[2] = COLOR_PALETTE[next].b;
        set_colour_all();
        note("Colour: %s", COLOR_PALETTE[next].name);
        return;
    }
    const char *const *names;
    int n, cur = setting_options(id, &names, &n);
    if (cur >= 0) setting_choose(id, (cur + (dir < 0 ? n - 1 : 1)) % n);
}

void begin_setting_edit(setting_id_t id) {
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_edit_id = id;
    // A secret starts empty, and what's typed replaces it.
    char v[1024];
    if (setting_text(id, v, sizeof v)) {
        copy_str(g_app.input.buf, v, sizeof g_app.input.buf);
        g_app.input.len = g_app.input.cursor = (int)strlen(g_app.input.buf);
    }
    g_app.mode = MODE_SETTINGS_EDIT;
    g_app.dirty = 1;
}

void end_setting_edit(void) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = MODE_SETTINGS;
    g_app.dirty = 1;
}

int valid_host_port(const char *s) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || !colon[1] || strlen(s) >= TOR_HOST_MAX) return 0;
    for (const char *p = colon + 1; *p; p++) if (*p < '0' || *p > '9') return 0;
    long port = strtol(colon + 1, NULL, 10);
    for (const char *p = s; p < colon; p++)
        if (!isalnum((unsigned char)*p) && !strchr(".-[]:", *p)) return 0;
    return port > 0 && port <= 65535;
}

// Sets a text row from what was typed for it, on the page or after :set NAME.
void setting_apply_text(setting_id_t id, const char *typed) {
    char text[sizeof g_app.input.buf];
    copy_str(text, typed, sizeof text);
    routing_t *r = &g_app.route;
    switch (id) {
        case SET_RELAYS: {
            char urls[NOSTR_MAX_RELAYS][NOSTR_URL_MAX];
            int n = 0;
            for (char *tok = strtok(text, " ,"); tok; tok = strtok(NULL, " ,")) {
                if (nostr_url_ok(tok) != 0) { note("not a relay chat can use: %.80s (wss://host[:port][/path])", tok); return; }
                if (n >= NOSTR_MAX_RELAYS) { note("at most %d relays", NOSTR_MAX_RELAYS); return; }
                copy_str(urls[n++], tok, NOSTR_URL_MAX);
            }
            memcpy(r->relays, urls, sizeof urls);
            r->n_relays = n;
            routing_changed(id);
            return;
        }
        case SET_TOR_SOCKS:
        case SET_TOR_CONTROL:
            if (!valid_host_port(text)) { note("that isn't host:port"); return; }
            copy_str(id == SET_TOR_SOCKS ? r->tor.socks : r->tor.control, text, TOR_HOST_MAX);
            routing_changed(id);
            return;
        case SET_TOR_PATH: {
            char found[1024];
            if (text[0] && platform_find_program("tor", text, found, sizeof found) != 0) {
                note("can't use %.100s - it has to be a full path to a program only root or you can change", text);
                return;
            }
            copy_str(g_app.tor_path, text[0] ? found : "", sizeof g_app.tor_path);
            note("Tor program: %s", g_app.tor_path[0] ? g_app.tor_path : "search PATH and the usual folders");
            return;
        }
        case SET_FILE_LIMIT: {
            uint64_t v;
            if (file_parse_size(text, &v) != 0 || v == 0 || v > FILE_HARD_MAX) { note("that isn't a size from 1 byte to 1 GB (8M, 500K, 1G)"); return; }
            g_app.file_cap = v;
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (takes_settings(i)) chat_set_file_options(&g_app.sessions[i].engine, v, g_app.fast_files);
            char sz[32]; file_format_size(v, sz, sizeof sz);
            note("File size limit: %s - for open sessions too", sz);
            return;
        }
        case SET_TOR_PASSWORD:
            copy_str(r->tor.password, text, sizeof r->tor.password);
            crypto_wipe(text, sizeof text);
            routing_changed(id);
            return;
        case SET_NICK:
            if (!text[0]) return;
            chat_clean_nick(text, g_app.nick);
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (takes_settings(i)) chat_set_nick(&g_app.sessions[i].engine, g_app.nick);
            note("Nickname: %s", g_app.nick);
            return;
        case SET_COLOUR: {
            uint8_t rgb[3];
            if (parse_color(text, rgb) != 0) { note("unknown colour %.40s - try a name or #RRGGBB", text); return; }
            memcpy(g_app.color, rgb, 3);
            set_colour_all();
            note("Colour: #%02x%02x%02x", rgb[0], rgb[1], rgb[2]);
            return;
        }
        case SET_PORT: {
            char *end;
            long port = strtol(text, &end, 10);
            if (!text[0] || *end || port < 0 || port > 65535) { note("not a port: %.20s (0-65535, 0 picks a free one)", text); return; }
            g_app.default_port = (uint16_t)port;
            note("UDP port for new sessions: %ld%s", port, port ? "" : " (a free one)");
            return;
        }
        default:
            return;
    }
}

void commit_setting_edit(void) {
    char text[sizeof g_app.input.buf];
    copy_str(text, g_app.input.buf, sizeof text);
    setting_id_t id = g_edit_id;
    end_setting_edit();
    setting_apply_text(id, text);
    crypto_wipe(text, sizeof text);
}

// The settings' sections, for the list on the left of the pages.
int settings_sections(const char **out, int cap) {
    int n = 0;
    for (int i = 0; i < N_SETTINGS && n < cap; i++) if (SETTINGS[i].section) out[n++] = SETTINGS[i].section;
    return n;
}

int settings_section_index(setting_id_t id) {
    int n = -1;
    for (int i = 0; i < N_SETTINGS; i++) {
        if (SETTINGS[i].section) n++;
        if (SETTINGS[i].id == id) return n;
    }
    return n;
}

// Section s's first row, or N_SETTINGS after the last section.
int section_begin(int s) {
    for (int i = 0, n = 0; i < N_SETTINGS; i++)
        if (SETTINGS[i].section && n++ == s) return i;
    return N_SETTINGS;
}

// Section s's first listed row, or its last for dir < 0, or the Done button if none is listed.
int section_row(int s, int dir) {
    int a = section_begin(s), b = section_begin(s + 1);
    for (int i = dir > 0 ? a : b - 1; i >= a && i < b; i += dir)
        if (setting_shown(SETTINGS[i].id)) return i;
    return SETTINGS_DONE;
}

int settings_n_sections(void) {
    int n = 0;
    while (section_begin(n) < N_SETTINGS) n++;
    return n;
}

void settings_select(int sel) {
    g_app.settings_sel = sel;
    if (sel >= N_SETTINGS) return;
    g_app.settings_page = settings_section_index(SETTINGS[sel].id);
    g_app.settings_rows[g_app.settings_page] = sel;
}

// Section s, on the row selected there last if it's still listed, otherwise its first.
void settings_go_section(int s) {
    int i = g_app.settings_rows[s];
    if (i < section_begin(s) || i >= section_begin(s + 1) || !setting_shown(SETTINGS[i].id)) i = section_row(s, 1);
    g_app.settings_page = s;
    settings_select(i);
}

// j/k go through the sections in turn, each one's listed rows and then its Done button.
void settings_step(int dir) {
    int sel = g_app.settings_sel, s = g_app.settings_page;
    int a = section_begin(s), b = section_begin(s + 1);
    if (sel == SETTINGS_DONE) {
        if (dir < 0) settings_select(section_row(s, -1));
        else if (b < N_SETTINGS) settings_select(section_row(s + 1, 1));
        return;
    }
    for (int i = sel + dir; i >= a && i < b; i += dir)
        if (setting_shown(SETTINGS[i].id)) { settings_select(i); return; }
    if (dir < 0 && s == 0) return;
    if (dir < 0) g_app.settings_page = s - 1;
    g_app.settings_sel = SETTINGS_DONE;
}

// Moves the selection off a row that stopped being listed, to the next one up in its section, or
// down.
void settings_fix_sel(void) {
    int sel = g_app.settings_sel;
    if (sel >= N_SETTINGS || setting_shown(SETTINGS[sel].id)) return;
    int s = settings_section_index(SETTINGS[sel].id), a = section_begin(s), b = section_begin(s + 1), i = sel - 1;
    while (i >= a && !setting_shown(SETTINGS[i].id)) i--;
    if (i < a) for (i = sel + 1; i < b && !setting_shown(SETTINGS[i].id); i++) {}
    settings_select(i >= a && i < b ? i : SETTINGS_DONE);
}

// Tab and Shift+Tab: the next or previous section, round from the last to the first.
void settings_section_step(int dir) {
    int n = settings_n_sections();
    settings_go_section((g_app.settings_page + dir + n) % n);
}

void begin_settings(void) {
    if (g_app.mode != MODE_CHAT) return;
    device_check();
    g_app.mode = MODE_SETTINGS;
    if (g_app.settings_sel == SETTINGS_DONE) settings_go_section(g_app.settings_page);
    settings_fix_sel();
    g_app.dirty = 1;
}

// Opens the page on a row, or says why the row isn't on it right now.
void settings_open_at(setting_id_t id) {
    begin_settings();
    if (setting_shown(id)) settings_select(settings_index(id));
    else note("%s isn't on the page right now: %s", setting_def(id)->label, setting_hidden_why(id));
}

// The Done button. Esc, q and Ctrl+S do the same. On the startup settings page, this is where chat
// starts. Until then nothing goes on the network, not even a tor or a --peer name lookup.
void settings_done(void) {
    g_app.mode = MODE_CHAT;
    if (g_app.onboarding) {
        g_app.onboarding = 0;
        push_log("* routing: %s", route_label());
        sync_update_proxy();
        tor_link_ensure(now_seconds());
        finish_onboarding();
    }
    g_app.dirty = 1;
}

// What the keys do on the selected row, with the main action first.
const char *settings_hint(void) {
    const setting_def_t *d = g_app.settings_sel < N_SETTINGS ? &SETTINGS[g_app.settings_sel] : NULL;
    const char *act;
    if (!d) act = g_app.onboarding ? "enter start" : "enter done";
    else if (d->id == SET_COLOUR) act = "h/l step \xc2\xb7 enter type one";
    else if (d->kind == K_TEXT || d->kind == K_SECRET) act = "enter edit";
    else if (d->id == SET_SIGN) act = "enter choose";
    else if (d->id == SET_SHADOW) act = "enter set";
    else if (d->id == SET_AGE_RECIPIENT || d->id == SET_PGP_PUBKEY) act = "enter copy";
    else if (row_greyed(d->id)) act = NULL;
    else act = "h/l change";
    static char hint[160];
    snprintf(hint, sizeof hint, "%s%sj/k move \xc2\xb7 tab/1-%d section \xc2\xb7 esc %s", act ? act : "",
             act ? " \xc2\xb7 " : "", settings_n_sections(), g_app.onboarding ? "start" : "done");
    return hint;
}

const sign_pick_row_t SIGN_PICKS[N_PICKS] = {
    { NULL, "Off", "Don't sign. Peers see you as unverified." },
    { "AGE", "Native", "A key made here, with an age1... recipient others can encrypt files to you with "
                       "(age -r). Enter asks for a password: the same password on this device and OS always makes "
                       "the same key, so always use the same one to keep an established signing identity. Blank "
                       "makes a new key that lasts until chat exits." },
    { NULL, "Pick a key file", "Your own AGE key, picked in a file browser: the file age-keygen writes. "
                               WHY_SECRET "It stays in memory and isn't sent. :install saves the file's path, not "
                               "the key." },
    { NULL, "Type a key file path", "Your own AGE key from a file whose path you type, such as "
                                    "~/.config/age/key.txt. " WHY_SECRET ":install saves the path, not the key." },
    { NULL, "Paste a key", "Your own AGE key pasted in: the AGE-SECRET-KEY-1... line. " WHY_SECRET "There's no "
                           "file to point to, so :install seals the key itself to disk." },
    { "PGP", "Native", "A PGP key made here, whose public key is in the settings and the console for others "
                       "to import. Enter asks for a password: the same password on this device and OS always makes "
                       "the same key, so always use the same one to keep an established signing identity. Blank "
                       "makes a new key that lasts until chat exits." },
    { NULL, "Pick a key file", "Your own key, picked in a file browser: an unencrypted EdDSA/Ed25519 secret key, "
                               "armored, as gpg --export-secret-keys --armor writes it. " WHY_SECRET ":install "
                               "saves the file's path, not the key." },
    { NULL, "Type a key file path", "Your own key from a file whose path you type: an unencrypted, armored "
                                    "EdDSA/Ed25519 secret key. " WHY_SECRET ":install saves the path, not the key." },
    { NULL, "Paste a key", "Your own key pasted in, armored. " WHY_SECRET "There's no file to point to, so "
                           ":install seals the key itself to disk." },
};

// Why chat asks for your secret key, and what happens to it, for the pages that take one.
const char KEY_WHY[] =
    "**Why the secret key:** chat signs the handshake of every session you join, so peers can check it's "
    "you. Only the secret key can make a signature; the public key can only check one. The key is kept in "
    "memory and never sent: peers get your public key and the signatures.";

const char KEY_FILE_SAVED[] =
    "**What :install keeps:** this file's path, not the key. chat reads the file again each time it starts, "
    "so leave it where it is.";

const char KEY_PASTE_SAVED[] =
    "**What :install keeps:** with no file to point to, the key itself, sealed with your passphrase. Until "
    "then it's only in memory. To keep it out of chat's files, save it to a file and pick that instead.";

const char AGE_PASTE_HELP[] =
    "Paste your AGE secret key now: the AGE-SECRET-KEY-1... line, or the whole file age-keygen wrote. It's read "
    "when its line ends (Enter, if the paste didn't end it).";

const char PGP_PASTE_HELP[] =
    "Paste your armored PGP private key now, BEGIN line to END line. It's read as soon as the END line "
    "arrives. It has to be an unencrypted EdDSA/Ed25519 key (gpg --export-secret-keys --armor, from a key "
    "with no passphrase).";

const char AGE_PATH_HELP[] =
    "Type the path to your AGE key file, as age-keygen writes it. ~ is your home folder.";

const char PGP_PATH_HELP[] =
    "Type the path to your PGP key file: an unencrypted, armored EdDSA/Ed25519 secret key, as gpg "
    "--export-secret-keys --armor writes it from a key with no passphrase. ~ is your home folder.";

const char SIGN_PASSWORD_HELP[] =
    "Type the password to make your key from. The same password on this device and OS always makes the same "
    "key and fingerprint, so always use the same password to keep an established signing identity: a different "
    "one, or a typo, makes a different key. Make it long, since anyone who learns this device's id can guess at "
    "it. Blank makes a new key that lasts until chat exits. Nothing is written to disk unless you :install.";

int sign_row_in_use(void) {
    int age = g_app.identity_source == IDENT_AGE;
    if (!age && g_app.identity_source != IDENT_PGP) return PICK_OFF;
    switch (g_app.key_origin) {
        case KEY_FILE:   return age ? PICK_AGE_FILE : PICK_PGP_FILE;
        case KEY_PASTED: return age ? PICK_AGE_PASTE : PICK_PGP_PASTE;
        default:         return age ? PICK_AGE_MADE : PICK_PGP_MADE;
    }
}

// Opens the picker from the Signing identity row, on the choice in use.
void begin_sign(void) {
    g_app.sign_sel = sign_row_in_use();
    g_app.mode = MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

// Passes the identity just chosen to every open session.
void identity_chosen(void) {
    int any = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_set_identity(&g_app.sessions[i].engine, g_app.identity_source, &g_app.identity);
        any = 1;
    }
    show_identity_result();
    say_key_saved_state();
    char v[160]; setting_value(SET_SIGN, v, sizeof v);
    note("Signing identity: %s%s", v, any ? " - applied to open sessions too" : "");
}

// Whether the key in use is the one saved, once a save is open.
void say_key_saved_state(void) {
    if (g_app.installed && g_app.identity_source != IDENT_NONE && !key_in_use_saved())
        push_log("* this signing key isn't saved: :save %s with your settings' passphrase%s",
                 g_app.key_origin == KEY_FILE && g_app.key_path[0] ? "saves its file's path, sealed" : "seals it",
                 install_has_key(install_current()) ? ", in place of the saved one" : "");
    else if (g_app.installed && g_app.identity_source == IDENT_NONE && install_has_key(install_current()))
        push_log("* the saved signing key stays saved, and signs again the next time chat starts");
}

// A key of kind (AGE or PGP) made here: from password and this device's id, the same every time,
// or a new random one if password is empty. Returns NULL once it's the identity in use, otherwise
// the reason it isn't, and the current identity stays.
const char *make_identity(identity_source_t kind, const char *password) {
    if (!password[0]) {
        gen_identity_keypair(&g_app.identity);
        g_app.key_origin = KEY_MADE;
        g_app.pgp_created = (uint32_t)time(NULL);
    } else {
        char device[128];
        if (platform_machine_id(device, sizeof device) != 0)
            return "this system has no machine id to make the key with - leave the password blank for a new key";
        if (identity_from_password(password, device, &g_app.identity) != 0)
            return "couldn't make the key - it needs 512 MiB of free memory for a moment";
        g_app.key_origin = KEY_DERIVED;
        g_app.pgp_created = DERIVED_PGP_CREATED;
    }
    g_app.identity_source = kind;
    return NULL;
}

// The password a native key is made from, typed on the bottom bar with the picker still up.
static void begin_sign_password(identity_source_t kind) {
    g_app.load_kind = kind;
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_app.mode = MODE_SIGN_PASSWORD;
    g_app.dirty = 1;
}

void end_sign_password(void) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

void commit_sign_password(void) {
    char pw[sizeof g_app.input.buf];
    copy_str(pw, g_app.input.buf, sizeof pw);
    end_sign_password();
    if (pw[0]) {
        // Argon2id takes a few seconds, so say so before the screen freezes.
        note("making your key from the password...");
        render();
    }
    const char *why = make_identity(g_app.load_kind, pw);
    crypto_wipe(pw, sizeof pw);
    if (why) { note("%s", why); return; }
    identity_chosen();
    g_app.mode = MODE_SETTINGS;
}

// A typed path with a leading ~ (alone, or followed by /) as the home folder.
static void expand_home(const char *path, char *out, size_t cap) {
    const char *home = platform_home_dir();
    if (home && path[0] == '~' && (path[1] == '\0' || path[1] == '/')) snprintf(out, cap, "%s%s", home, path + 1);
    else copy_str(out, path, cap);
}

// path with the home folder as ~, to show.
void tilde_path(const char *path, char *out, size_t cap) {
    const char *home = platform_home_dir();
    size_t hl = home ? strlen(home) : 0;
    if (hl > 1 && strncmp(path, home, hl) == 0 && (path[hl] == '/' || path[hl] == '\0'))
        snprintf(out, cap, "~%s", path + hl);
    else copy_str(out, path, cap);
}

// kind's key (AGE or PGP) from the file at path, into kp. Its full path goes in full, for :install to
// save. Returns 0, or -1 if the file isn't such a key.
int read_key_file(identity_source_t kind, const char *path, identity_keypair_t *kp, char *full, size_t cap) {
    char p[KEY_PATH_MAX];
    expand_home(path, p, sizeof p);
    int rc = kind == IDENT_AGE ? age_import_secret_key(p, kp) : pgp_import_secret_key(p, kp);
    if (rc != 0) return -1;
    if (platform_full_path(p, full, cap) != 0) copy_str(full, p, cap);
    return 0;
}

// kind's key (AGE or PGP) from the file at path. Returns 0 once it's the identity in use.
int load_key_file(identity_source_t kind, const char *path) {
    identity_keypair_t kp;
    char full[KEY_PATH_MAX];
    int rc = read_key_file(kind, path, &kp, full, sizeof full);
    if (rc == 0) {
        g_app.identity = kp;
        g_app.identity_source = kind;
        g_app.key_origin = KEY_FILE;
        copy_str(g_app.key_path, full, sizeof g_app.key_path);
    }
    crypto_wipe(&kp, sizeof kp);
    return rc;
}

// The key file in use, if it's kind's, for the browser and the path field to start at.
static const char *key_path_of(identity_source_t kind) {
    return g_app.key_origin == KEY_FILE && g_app.identity_source == kind && g_app.key_path[0] ? g_app.key_path : NULL;
}

// Opens in the folder of the key file in use, if there is one, otherwise the home folder.
static void begin_key_browse(identity_source_t kind) {
    g_app.load_kind = kind;
    const char *home = platform_home_dir();
    char dir[KEY_PATH_MAX] = "", name[200] = "";
    if (key_path_of(kind)) {
        copy_str(dir, g_app.key_path, sizeof dir);
        const char *slash = strrchr(g_app.key_path, '/');
        if (slash) copy_str(name, slash + 1, sizeof name);
        path_parent(dir);
    }
    if (dir[0] && browser_load(&g_app.browser, dir) == 0) browser_select(&g_app.browser, name);
    else if (!home || browser_load(&g_app.browser, home) != 0) browser_load(&g_app.browser, "/");
    g_app.mode = MODE_SIGN_BROWSE;
    g_app.dirty = 1;
}

// The field for a key file's path, on the picker or the browser, starting with start (or empty).
void begin_key_path(identity_source_t kind, const char *start, int from_browser) {
    g_app.load_kind = kind;
    g_app.path_from_browser = from_browser;
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    if (start) {
        char shown[sizeof g_app.input.buf];
        tilde_path(start, shown, sizeof shown);
        copy_str(g_app.input.buf, shown, sizeof g_app.input.buf);
        g_app.input.len = g_app.input.cursor = (int)strlen(g_app.input.buf);
    }
    g_app.mode = MODE_SIGN_PATH;
    g_app.dirty = 1;
}

void end_key_path(void) {
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = g_app.path_from_browser ? MODE_SIGN_BROWSE : MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

// A path that isn't a key stays in the field to be fixed.
void commit_key_path(void) {
    char path[sizeof g_app.input.buf];
    copy_str(path, g_app.input.buf, sizeof path);
    if (!path[0]) { note("type the key file's path - or Esc to go back"); return; }
    if (load_key_file(g_app.load_kind, path) != 0) {
        if (g_app.load_kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", path);
        else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", path);
        return;
    }
    end_key_path();
    identity_chosen();
    g_app.mode = MODE_SETTINGS;
}

void paste_clear(void) {
    crypto_wipe(g_app.paste_buf, sizeof g_app.paste_buf);
    g_app.paste_len = 0;
    copy_str(g_app.paste_status, "waiting for the paste", sizeof g_app.paste_status);
}

static void begin_key_paste(identity_source_t kind) {
    g_app.load_kind = kind;
    paste_clear();
    g_app.mode = MODE_SIGN_PASTE;
    g_app.dirty = 1;
}

// Loads the key file picked in the browser. Returns 0 once it's the identity in use.
int try_load_key_from_browser(void) {
    const dir_entry_t *sel = &g_app.browser.items[g_app.browser.selected];
    char full[1200]; browser_entry_path(&g_app.browser, sel, full, sizeof full);
    if (load_key_file(g_app.load_kind, full) != 0) {
        if (g_app.load_kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", sel->name);
        else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", sel->name);
        return -1;
    }
    identity_chosen();
    return 0;
}

// Off takes effect immediately. A key made here asks for its password first, and a key file or
// paste opens its own page.
void sign_pick(int pick) {
    switch (pick) {
        case PICK_OFF:
            g_app.identity_source = IDENT_NONE;
            crypto_wipe(&g_app.identity, sizeof g_app.identity);
            identity_chosen();
            return;
        case PICK_AGE_MADE:  begin_sign_password(IDENT_AGE); return;
        case PICK_PGP_MADE:  begin_sign_password(IDENT_PGP); return;
        case PICK_AGE_FILE:  begin_key_browse(IDENT_AGE); return;
        case PICK_AGE_PATH:  begin_key_path(IDENT_AGE, key_path_of(IDENT_AGE), 0); return;
        case PICK_AGE_PASTE: begin_key_paste(IDENT_AGE); return;
        case PICK_PGP_FILE:  begin_key_browse(IDENT_PGP); return;
        case PICK_PGP_PATH:  begin_key_path(IDENT_PGP, key_path_of(IDENT_PGP), 0); return;
        case PICK_PGP_PASTE: begin_key_paste(IDENT_PGP); return;
        default: return;
    }
}

void copy_age_recipient(void) {
    if (g_app.identity_source != IDENT_AGE) return;
    char recipient[AGE_RECIPIENT_STRLEN + 1];
    age_export_recipient(&g_app.identity, recipient);
    osc52_copy(recipient);
    note("AGE recipient copied to the clipboard (OSC 52)");
}

void copy_pgp_public_key(void) {
    if (!pgp_key_made_here()) return;
    char armor[PGP_ARMOR_MAX]; uint8_t fp[PGP_FP_LEN];
    pgp_public_key(armor, fp);
    osc52_copy(armor);
    note("PGP public key copied to the clipboard (OSC 52)");
}
