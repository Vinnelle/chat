// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The settings: their rows, values and sections, changing them, the settings file, and leaving the
// first-run page for the chat.
#include "app/app.h"

const setting_def_t SETTINGS[] = {
    { SET_ROUTING, "Network", NULL, "routing", "Routing", K_CHOICE, "udp|tor",
      "udp: UDP straight between peers, found using the options below. Peers see your IP address. tor: onion "
      "services, which hide your IP address from everyone. Uses a running tor or starts chat's own, and "
      "connecting takes longer. UDP and Tor members only meet on the Nostr relays. Applies to sessions you open "
      "from now on." },
    { SET_DHT4, NULL, "UDP", "dht", "BitTorrent DHT (IPv4)", K_TOGGLE, "on|off",
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
      "auto: a running tor if its control port lets chat log in, otherwise chat's own, as always with bridges set. "
      "always: chat's own, ignoring your torrc. never: only a running tor. Chat's own tor gets random 127.0.0.1 "
      "ports, a control password made at random each run that only chat knows (tor only gets its hash), and a "
      "private temporary folder deleted on exit, and new entry guards each run unless Keep tor's guards is on." },
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
    { SET_BRIDGES, NULL, NULL, "bridges", "Bridges", K_TEXT, "LINE; LINE ...",
      "Bridge lines for chat's own tor, from bridges.torproject.org or a friend, separated by ;. With any set, "
      "chat starts its own tor, which reaches the Tor network only through them: they go to it over its control "
      "port, never on its command line or on disk. Sealed in the save, never shown in the console. obfs4, "
      "webtunnel and meek_lite need lyrebird, snowflake needs snowflake-client (Transport programs)." },
    { SET_TRANSPORTS, NULL, NULL, "transports", "Transport programs", K_TEXT, "FOLDER",
      "The folder with lyrebird and snowflake-client, for bridges. Empty: next to tor (the Tor Expert Bundle and "
      "Tor Browser keep them in a folder beside it), then on PATH and in the usual folders. They must be programs "
      "only root or you can change, in a path without spaces. With the sandbox up, only those found as it went up "
      "can run." },
    { SET_TOR_STATE, NULL, NULL, "torguards", "Keep tor's guards", K_TOGGLE, "on|off",
      "on: when chat's own tor stops, its entry guards and its copy of the Tor directory are sealed into the open "
      "save, and the next one starts from them: the same guards each run, as Tor's design expects, and connected "
      "in seconds. It adds tens of MB to the save, and anyone who opens the save sees which guards you use. Its "
      "decoy gets none. off: deletes them. Needs a save; a tor already running keeps its own." },
    // After both modes' rows: the relays apply in both, so they stay put when the mode changes.
    { SET_NOSTR, NULL, "Relays", "nostr", "Nostr relays", K_CHOICE, "off|fallback|always",
      "Public relays that carry traffic the route can't, and where UDP and Tor members meet. Tor routing reaches "
      "them through Tor. fallback: connected only while needed (nobody reached yet, or a peer the route can't "
      "reach), until a minute after. always: stays connected, so members on the other route can find a room "
      "whose members all reach each other. Each event has a one-off key, a random kind, a fixed size and fresh "
      "encryption." },
    { SET_RELAYS, NULL, NULL, "relays", "Relay list", K_TEXT, "wss://URL ... (up to 6)",
      "The relays the fallback uses: up to 6 wss:// URLs, separated by spaces or commas." },
    { SET_PORT, NULL, "Advanced", "port", "UDP port for new sessions", K_TEXT, "N",
      "The UDP port new sessions listen on. 0 picks a free one each time. :port moves an open session to another." },
    { SET_NET, NULL, NULL, "net", "Network log", K_CHOICE, "normal|verbose|off",
      "How much of the network the console shows, in every session. verbose adds every handshake packet, relay "
      "and Tor event. off leaves out its news too (lookups, relays dropping and coming back, Tor starting up), "
      "showing only problems that keep a session from connecting." },
    { SET_NICK, "Profile", NULL, "nick", "Nickname", K_TEXT, "NAME", "Your name in every session." },
    { SET_COLOUR, NULL, NULL, "colour", "Colour", K_TEXT, "NAME|#RRGGBB",
      "Your colour in every session. h/l step through the palette, and Enter takes a name or #RRGGBB." },
    { SET_SIGN, NULL, "Keys", "sign", "Signing identity", K_ACTION, "off|age|pgp|age-nonick|pgp-nonick|age:PATH|pgp:PATH",
      "A key that signs your handshakes so peers can check it's you. Either an AGE or PGP key made here from a "
      "password, or your own key from a file or pasted in. Enter picks one, replaces it or turns signing off. "
      "Kept in memory only, unless :install saves it: a key file's path, or any other key sealed to disk." },
    { SET_AGE_RECIPIENT, NULL, NULL, "agerecipient", "AGE recipient", K_ACTION, NULL,
      "The age1... string others give to age -r to encrypt files to you. Enter copies it to the clipboard." },
    { SET_PGP_PUBKEY, NULL, NULL, "pgpkey", "PGP public key", K_ACTION, NULL,
      "The public half of the PGP key made here, shown by its fingerprint, for others to gpg --import. Enter "
      "copies it to the clipboard. It's in the console too." },
    { SET_EXPORT_KEY, NULL, NULL, "exportkey", "Export signing key", K_ACTION, NULL,
      "Writes your signing key, unencrypted, to a new file in a folder you pick, after asking: to load it on "
      "another device, or keep a key made here. An AGE key comes out as age-keygen writes one, a PGP key made here "
      "armored, as gpg --export-secret-keys writes it. Anyone who reads the file can sign as you." },
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
    { SET_LOCK, NULL, "Lock screen", "lock", "Auto-lock", K_CHOICE, "off|1m|5m|15m|30m",
      "Locks the screen after this long without a key, as the lock key and :lock do at once. Locked, chat draws "
      "nothing but a box for the open save's passphrase, or with no save open, a PIN it asks for first, kept "
      "hashed in memory until chat exits. Sessions carry on behind it, and notifications show no preview. Wrong "
      "passphrases count toward self-destruct, and the shadow passphrase panics, leaving the decoy in the save's "
      "place. Each try takes a second or two." },
    { SET_LOCK_KEY, NULL, NULL, "lockkey", "Lock key", K_CHOICE, "off|ctrl+l|ctrl+g|ctrl+k|f9",
      "The key that locks the screen at once, from anywhere in chat. off leaves :lock and auto-lock." },
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
    { SET_PANIC_KEY, NULL, NULL, "panickey", "Panic key", K_CHOICE, "off|ctrl+\\|ctrl+q|ctrl+x|f12",
      "A key that, from anywhere in chat (the lock screen too), clears the screen and quits at once, without "
      "asking: every session says bye (one kept to reopen goes offline), memory is wiped and chat's own tor "
      "stops. Nothing is saved but what the rows below keep. Anyone at the keyboard can press it. Ctrl+\\ is "
      "awkward on some keyboards, so there are others. In --simple, the terminal's Ctrl+\\ panics unless this is "
      "off." },
    { SET_PANIC_WIPE, NULL, NULL, "panicwipe", "Panic deletes the save", K_TOGGLE, "on|off",
      "on: the panic key also deletes the open save, as :uninstall does but without asking: its settings, signing "
      "key, verified keys and history. Deleting isn't erasing: the disk and its backups can keep traces of the "
      "files. The shadow passphrase on the lock screen leaves the decoy instead." },
    { SET_PANIC_HISTORY, NULL, NULL, "panichistory", "Panic writes history", K_TOGGLE, "on|off",
      "on: the panic key writes the history kept for each session before it quits. off: it isn't written, so "
      "each history loses up to its last 30 seconds." },
    { SET_SANDBOX, NULL, "Sandbox", "sandbox", "Sandbox", K_TOGGLE, "on|off",
      "on: once chat reaches the network, it can only write to your home's folders that aren't hidden or on PATH, "
      "its own and the temporary ones, and only run tor and its transport programs. Calls it never makes (ptrace, "
      "mount, bpf...) are refused, for tor too. A bug can't plant anything that runs later (.bashrc, ~/.local/bin), "
      "and saving elsewhere fails, though :update still works through the updater. Linux 5.13 or later. From the next start." },
    { SET_UPDATER, NULL, NULL, "updater", "Updater", K_TOGGLE, "on|off",
      "on: just before the sandbox goes up, chat starts chat-updater, a second process that :update asks to "
      "replace chat, since chat can't once it's sandboxed. It holds none of chat's keys, saves or messages, can "
      "only write in chat's executable's folder and run curl, and installs only what the release key signed. off: "
      "no second process, and :update sends you to chat --update. off stops it now, on waits for the next start." },
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
    { SET_REOPEN, NULL, NULL, "reopen", "Reopen sessions", K_TOGGLE, "on|off",
      "on: keeps the sessions you have open, their ids and passwords sealed in the save that's open (so it "
      "needs :install), and opens them again when chat starts. Ctrl+C then quits without leaving them: peers "
      "see you go offline, or leave on older versions. :quit leaves one for good, :quitall every one. Calls "
      "aren't kept. Only the full-screen UI keeps them." },
    { SET_FILE_LIMIT, NULL, "Files", "filelimit", "File size limit", K_TEXT, "SIZE (8M, 500K, 1G)",
      "The largest file chat fetches when you ask. An offer over the limit says so, and :download N anyway (or "
      ":show N anyway) fetches it regardless. Nothing is fetched until you ask. Files can be up to 1 GB." },
    { SET_FAST_FILES, NULL, NULL, "fastfiles", "Fast file transfers", K_TOGGLE, "on|off",
      "off: files are sent in chat's regular slots, so a transfer doesn't show up on the network, but it's slow: "
      "about 25 KB a minute, half that through the relays (where Tor and UDP members meet). on: while you send a "
      "file, your slots to that peer come every few milliseconds. It takes seconds instead of minutes, but anyone "
      "watching the network sees a burst about the size of the file. Through the relays it goes as often as they "
      "allow, about twice the normal rate, and the relays can see that. Only the sender's setting matters." },
    { SET_NOISE, NULL, NULL, "noise", "Noise in pictures", K_TOGGLE, "on|off",
      "on: a JPEG you send also gets noise nobody can see, on top of what's always taken out (where, when and "
      "with what it was made): some coefficients move a step, so no two copies are the same bytes or pixels, even "
      "of one photo sent twice. It doesn't hide which camera took it from someone who studies its sensor's noise, "
      "or stop it being recognised. Baseline JPEGs only (most photos). :send asis sends a file as it is." },
    { SET_BETAS, NULL, "Updates", "betas", "Beta releases", K_TOGGLE, "on|off",
      "on: :update installs betas too, the test builds of the next release. They're signed and checked like a "
      "release, but have had less testing. off: only releases, so a beta you're on stays until its release is "
      "out, and :update then takes you on to that." },
};

_Static_assert(N_SETTINGS == N_SETTING_IDS, "every setting has a row");

static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };

static const char *const PREVIEW_NAMES[] = { "off", "nick", "message" };

static const char *const ON_OFF[] = { "off", "on" };

const char *const ROUTE_NAMES[] = { "udp", "tor" };

const char *const NOSTR_NAMES[] = { "off", "fallback", "always" };

static const char *const VERIFY_NAMES[] = { "required", "optional" };

static const char *const NET_LOG_NAMES[] = { "normal", "verbose", "off" };

static const char *const DESTROY_NAMES[] = { "off", "3", "5", "10" };

static const int DESTROY_VALS[] = { 0, 3, 5, 10 };

setting_id_t g_edit_id;

static uint64_t file_cap(void) { return g_app.file_cap ? g_app.file_cap : FILE_CAP_DEFAULT; }

// The colour's place in the palette, or -1 if it isn't one of its colours.
static int palette_index(const uint8_t rgb[3]) {
    int at = -1;
    for (int i = 0; i < COLOR_PALETTE_N; i++)
        if (COLOR_PALETTE[i].r == rgb[0] && COLOR_PALETTE[i].g == rgb[1] && COLOR_PALETTE[i].b == rgb[2]) at = i;
    return at;
}

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

static int udp_routing_only_setting(setting_id_t id) { return id == SET_PORTMAP || id == SET_LAN; }

static int tor_only_setting(setting_id_t id) {
    return id == SET_TOR_LAUNCH || id == SET_TOR_PATH || id == SET_TOR_SOCKS || id == SET_TOR_CONTROL
        || id == SET_TOR_PASSWORD || id == SET_BRIDGES || id == SET_TRANSPORTS || id == SET_TOR_STATE;
}

// Settings that don't apply right now aren't listed: the UDP ones in Tor mode, the Tor ones in
// UDP mode, the relay list with relays off, the AGE recipient without an AGE identity, the PGP
// public key without a PGP key made here, and the export without a key it can write.
int setting_shown(setting_id_t id) {
    route_mode_t m = g_app.route.mode;
    if (m != ROUTE_UDP && udp_routing_only_setting(id)) return 0;
    if (m == ROUTE_TOR && dht_setting(id)) return 0;
    if (m != ROUTE_TOR && tor_only_setting(id)) return 0;
    if (id == SET_RELAYS && !g_app.route.nostr) return 0;
    if (id == SET_AGE_RECIPIENT && g_app.identity_source != IDENT_AGE) return 0;
    if (id == SET_PGP_PUBKEY && !pgp_key_made_here()) return 0;
    if (id == SET_EXPORT_KEY && key_export_refusal()) return 0;
#ifndef __linux__
    if (id == SET_SANDBOX || id == SET_UPDATER) return 0;
#endif
    if (id == SET_UPDATER && !g_app.sandbox && !(g_app.sandboxed & PLATFORM_SANDBOX_FILES)) return 0;
    return 1;
}

static const char *setting_hidden_why(setting_id_t id) {
    if (udp_routing_only_setting(id)) return "it only applies with udp routing";
    if (dht_setting(id)) return "it doesn't apply with tor routing";
    if (tor_only_setting(id)) return "it only applies with tor routing";
    if (id == SET_RELAYS) return "it only applies with the Nostr relays on";
    if (id == SET_PGP_PUBKEY) return "it needs a PGP signing key made here";
    if (id == SET_EXPORT_KEY) return "it needs an AGE signing key, or a PGP key made here";
#ifndef __linux__
    if (id == SET_SANDBOX || id == SET_UPDATER) return "the sandbox is only on Linux";
#endif
    if (id == SET_UPDATER) return "it only applies with the sandbox on";
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
        case SET_NOISE:      return g_app.picture_noise != 0;
        case SET_HISTORY:    return g_app.history != 0;
        case SET_REOPEN:     return g_app.reopen != 0;
        case SET_BETAS:      return g_app.betas != 0;
        case SET_AUTOSAVE:   return g_app.autosave != 0;
        case SET_DEVICE_LOCK: return g_app.device.lock != 0;
        case SET_SECURITY_KEY: return g_app.factor.key != 0;
        case SET_AUTHENTICATOR: return g_app.factor.code != 0;
        case SET_DESTROY: {
            *names = DESTROY_NAMES; *n = 4;
            for (int i = 0; i < 4; i++) if (DESTROY_VALS[i] == g_app.install.destroy_limit) return i;
            return 0;
        }
        case SET_LOCK: {
            *names = LOCK_AFTER_NAMES; *n = N_LOCK_AFTER;
            for (int i = 0; i < N_LOCK_AFTER; i++) if (LOCK_AFTER_SECONDS[i] == g_app.lock.after) return i;
            return 0;
        }
        case SET_LOCK_KEY:   *names = LOCK_KEY_NAMES; *n = N_LOCK_KEYS; return g_app.lock.key;
        case SET_PANIC_KEY:  *names = PANIC_KEY_NAMES; *n = N_PANIC_KEYS; return g_app.panic.key;
        case SET_PANIC_WIPE: return g_app.panic.wipe != 0;
        case SET_PANIC_HISTORY: return g_app.panic.history != 0;
        case SET_SANDBOX:    return g_app.sandbox != 0;
        case SET_UPDATER:    return g_app.updater != 0;
        case SET_TOR_STATE:  return g_app.tor.keep_state != 0;
        case SET_TOR_LAUNCH: *names = TOR_LAUNCH_NAMES; *n = 3; return g_app.tor.launch;
        case SET_NOTIFY:     *names = NOTIFY_NAMES; *n = 3; return (int)g_app.notify_mode;
        case SET_PREVIEW:    *names = PREVIEW_NAMES; *n = 3; return (int)g_app.notify_preview;
        case SET_NET:        *names = NET_LOG_NAMES; *n = 3; return g_app.net_log;
        default:             *names = NULL; *n = 0; return -1;
    }
}

static const char *const SIGN_NAMES[] = { "off", "age", "pgp", "age-nonick", "pgp-nonick" };

// What :set takes for a row, for the command line's menu: its values, and the signing identity's
// kinds (age:PATH and pgp:PATH, for a key file, are typed in full, and a pasted key is only chosen on
// the page).
int setting_choices(setting_id_t id, const char *const **names, int *n) {
    if (id != SET_SIGN) return setting_options(id, names, n);
    *names = SIGN_NAMES;
    *n = (int)COUNT_OF(SIGN_NAMES);
    if (g_app.identity_source == IDENT_NONE) return 0;
    int age = g_app.identity_source == IDENT_AGE;
    if (g_app.key.origin == KEY_DERIVED) return age ? 3 : 4;
    return age ? 1 : 2;
}

// How the page draws a row's value: a switch, a choice h/l steps through, a way into another
// page, or text.
tui_value_kind_t setting_kind(const setting_def_t *d) {
    const char *const *names;
    int n, cur = setting_options(d->id, &names, &n);
    if (d->kind == K_TOGGLE) return cur > 0 ? TUI_V_ON : TUI_V_OFF;
    if (d->kind == K_CHOICE) return TUI_V_CHOICE;
    if (d->id == SET_SIGN || d->id == SET_SHADOW || d->id == SET_EXPORT_KEY) return TUI_V_LINK;
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
            char found[TOR_PATH_MAX];
            if (g_app.tor.path[0]) snprintf(out, cap, "%s", g_app.tor.path);
            else if (platform_find_program("tor", NULL, found, sizeof found) == 0) snprintf(out, cap, "found %s", found);
            else snprintf(out, cap, "not installed");
            break;
        }
        case SET_BRIDGES: {
            char kinds[80];
            int bridges = bridge_count(g_app.tor.bridges, kinds, sizeof kinds);
            if (bridges) snprintf(out, cap, "%d (%s)", bridges, kinds);
            else snprintf(out, cap, "none");
            break;
        }
        case SET_TRANSPORTS:   transport_line(out, cap); break;
        case SET_FILE_LIMIT:   file_format_size(file_cap(), out, cap); break;
        case SET_TOR_SOCKS:    snprintf(out, cap, "%s", r->tor.socks); break;
        case SET_TOR_CONTROL:  snprintf(out, cap, "%s", r->tor.control); break;
        case SET_TOR_PASSWORD: snprintf(out, cap, "%s", r->tor.password[0] ? "set" : "not set (cookie or no login)"); break;
        case SET_NICK:         snprintf(out, cap, "%s", g_app.nick); break;
        case SET_COLOUR: {
            int at = palette_index(g_app.color);
            if (at >= 0) snprintf(out, cap, "%s", COLOR_PALETTE[at].name);
            else snprintf(out, cap, "#%02x%02x%02x", g_app.color[0], g_app.color[1], g_app.color[2]);
            break;
        }
        case SET_SIGN: {
            if (g_app.identity_source == IDENT_NONE) { snprintf(out, cap, "off"); break; }
            uint8_t fp[ID_FP_LEN]; identity_fingerprint(g_app.identity.pub, fp);
            char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(fp, ID_FP_LEN, fphex);
            char from[MAX_NICK + 32] = "";
            if (g_app.key.origin == KEY_DERIVED) copy_str(from, " from password, without nick", sizeof from);
            else if (g_app.key.origin == KEY_DERIVED_NICK)
                snprintf(from, sizeof from, " from password and nick %s", g_app.key.nick);
            snprintf(out, cap, "%s%s, fingerprint %s", g_app.identity_source == IDENT_AGE ? "age" : "pgp", from, fphex);
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
        case SET_EXPORT_KEY:   snprintf(out, cap, "%s", key_export_refusal() ? "none" : key_export_name()); break;
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
        case SET_TOR_PATH: copy_str(out, g_app.tor.path, cap); break;
        case SET_BRIDGES:  copy_str(out, g_app.tor.bridges, cap); break;
        case SET_TRANSPORTS: copy_str(out, g_app.tor.pt_dir, cap); break;
        case SET_FILE_LIMIT: file_format_size_exact(file_cap(), out, cap); break;
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
    if (SETTINGS[i].id != SET_RELAYS && SETTINGS[i].id != SET_BRIDGES) return toml_put_str(out, p, cap, v);
    // A list: relays are separated by spaces, bridges (which have spaces) by "; ".
    char items[ROW_TEXT_MAX];
    copy_str(items, v, sizeof items);
    p = put_text(out, p, cap, "[");
    int first = 1;
    for (char *s = strtok(items, SETTINGS[i].id == SET_RELAYS ? " " : ";"); s;
         s = strtok(NULL, SETTINGS[i].id == SET_RELAYS ? " " : ";"), first = 0) {
        while (*s == ' ') s++;
        if (!first) p = put_text(out, p, cap, ", ");
        p = toml_put_str(out, p, cap, s);
    }
    crypto_wipe(items, sizeof items);
    return put_text(out, p, cap, "]");
}

// The signing keys ignored (core/trust.h), as the [ignored] table: ["SOURCE", "KEY", "NICK"].
static size_t ignored_text(char *out, size_t p, size_t cap) {
    if (!ignore_count()) return p;
    p = put_text(out, p, cap, p ? "\n[ignored]\n" : "[ignored]\n");
    for (int i = 0; i < ignore_count(); i++) {
        const trust_entry_t *e = ignore_at(i);
        char key[16], hex[ID_SIGN_PUB_LEN * 2 + 1];
        snprintf(key, sizeof key, "%d = [", i + 1);
        hex_encode(e->pub, ID_SIGN_PUB_LEN, hex);
        p = put_text(out, p, cap, key);
        p = toml_put_str(out, p, cap, trust_source_name(e->source));
        p = put_text(out, p, cap, ", ");
        p = toml_put_str(out, p, cap, hex);
        p = put_text(out, p, cap, ", ");
        p = toml_put_str(out, p, cap, e->nick);
        p = put_text(out, p, cap, "]\n");
    }
    return p;
}

int ignored_load(const toml_value *v) {
    uint8_t pub[ID_SIGN_PUB_LEN];
    int source;
    if (v->type != TOML_ARRAY || v->n != 3 || (source = trust_source_from(v->items[0])) < 0
        || strlen(v->items[1]) != ID_SIGN_PUB_LEN * 2 || hex_decode(v->items[1], ID_SIGN_PUB_LEN * 2, pub) != 0)
        return -1;
    ignore_add((identity_source_t)source, pub, v->items[2]);
    return 0;
}

// Saved as the verified keys are: as they change with autosave on, or by :save.
void save_ignored(void) {
    if (g_loading_settings || !trust_saved() || !g_app.installed || g_app.locked) return;
    if (settings_write() != 0) push_log("* couldn't save the ignored keys - they last until chat exits");
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
    p = rooms_text(out, p, cap);
    p = reopen_text(out, p, cap);
    p = ignored_text(out, p, cap);
    return p < cap ? 0 : -1;
}

// The rows saved so far, the kept rooms and the sessions to reopen, written to the open save. 0 or -1.
int settings_write(void) {
    static char text[INSTALL_SETTINGS_MAX];
    int rc = settings_text(text, sizeof text) == 0 && install_write_settings(text) == 0 ? 0 : -1;
    crypto_wipe(text, sizeof text);
    return rc;
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
    if (held && n > 0) snprintf(g_app.message + n, sizeof g_app.message - n, DOT_SEP "not saved (autosave is off)");
    if (!changed) return;
    if (settings_write() != 0) {
        char where[APP_PATH_MAX] = "";
        install_where(install_current(), where, sizeof where);
        note("couldn't save that in %s/settings - it lasts until chat exits", where);
        return;
    }
    n = strlen(g_app.message);
    if (n > 0 && !held) snprintf(g_app.message + n, sizeof g_app.message - n, DOT_SEP "saved");
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
        chat_t *e = g_app.sessions[i].engine;
        chat_apply_routing(e, &g_app.route);
        chat_set_file_options(e, g_app.file_cap, g_app.fast_files);
        chat_set_picture_noise(e, g_app.picture_noise);
        chat_set_verify_required(e, !g_app.verify_optional || g_app.sessions[i].contact);
        chat_set_notify_mode(e, g_app.notify_mode);
        chat_set_notify_preview(e, g_app.notify_preview);
        chat_set_net_log(e, g_app.net_log);
        if (strcmp(chat_nick(e), g_app.nick) != 0) chat_set_nick(e, g_app.nick);
        if (memcmp(chat_colour(e), g_app.color, 3) != 0) chat_set_colour(e, g_app.color);
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
        later |= chat_apply_routing(g_app.sessions[i].engine, &g_app.route);
        any = 1;
    }
    char v[160]; setting_value(id, v, sizeof v);
    const char *label = setting_def(id)->label;
    if (id == SET_ROUTING || tor_only_setting(id) || (later && !udp_routing_only_setting(id)))
        note("%s: %s - for sessions you open from now on%s", label, v, any ? "; open ones keep their routing" : "");
    else
        note("%s: %s%s", label, v, any ? " - applied to open sessions too" : "");
}

static void set_colour_all(void) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (takes_settings(i)) chat_set_colour(g_app.sessions[i].engine, g_app.color);
}

// Security keys too.
void device_check(void) {
    g_app.device.why[0] = g_app.factor.seckey_why[0] = '\0';
    g_app.device.kind = platform_device_kind(g_app.device.why, sizeof g_app.device.why);
    g_app.factor.seckey_ok = platform_seckey_usable(g_app.factor.seckey_why, sizeof g_app.factor.seckey_why) == 0;
}

const char DEVICE_REMINDER[] =
    "* device lock: before you clear the TPM, update the firmware, replace the motherboard or reinstall the OS, "
    ":set devicelock off first, and lock it again after - or the save is gone for good";

const char KEY_REMINDER[] =
    "* security key: if it's lost, broken or reset, the save is gone for good - :set securitykey off before you "
    "reset it or stop using it";

// Turning the lock off never needs the device, so a save locked to it, or a lock already chosen,
// stays usable. The same for a security key.
static int device_lock_greyed(void) { return g_app.device.kind == DEVICE_NONE && !g_app.device.lock; }

static int security_key_greyed(void) { return !g_app.factor.seckey_ok && !g_app.factor.key; }

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

static void reopen_choose(int on) {
    if (on && (!g_app.installed || g_app.locked)) {
        note("Reopen sessions: they're kept sealed in a save, so it needs one open - :install makes one");
        return;
    }
    g_app.reopen = on;
    if (on) note("Reopen sessions: on - the sessions open are kept in the save %s, and open again when chat starts",
                 install_shown_name(install_current()));
    else note("Reopen sessions: off - the save forgets the sessions it kept");
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
                if (takes_settings(s)) chat_set_verify_required(g_app.sessions[s].engine, !i);
            break;
        case SET_TOR_LAUNCH:
            g_app.tor.launch = i;
            note("Start chat's own tor: %s - for the next tor chat looks for; a tor already in use stays",
                 TOR_LAUNCH_NAMES[i]);
            return;
        case SET_NOTIFY:
            g_app.notify_mode = (notify_mode_t)i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) chat_set_notify_mode(g_app.sessions[s].engine, g_app.notify_mode);
            break;
        case SET_PREVIEW:
            g_app.notify_preview = (notify_preview_t)i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) chat_set_notify_preview(g_app.sessions[s].engine, g_app.notify_preview);
            break;
        case SET_NET:
            g_app.net_log = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) chat_set_net_log(g_app.sessions[s].engine, i);
            break;
        case SET_FAST_FILES:
            g_app.fast_files = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) chat_set_file_options(g_app.sessions[s].engine, g_app.file_cap, i);
            break;
        case SET_NOISE:
            g_app.picture_noise = i;
            for (int s = 0; s < MAX_SESSIONS; s++)
                if (takes_settings(s)) chat_set_picture_noise(g_app.sessions[s].engine, i);
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
        case SET_REOPEN: reopen_choose(i); return;
        case SET_LOCK: lock_after_choose(i); return;
        case SET_LOCK_KEY: g_app.lock.key = i; break;
        case SET_PANIC_KEY: g_app.panic.key = i; break;
        case SET_PANIC_WIPE:
            g_app.panic.wipe = i;
            if (i) { note("Panic deletes the save: on - the panic key deletes the open save too, without asking"); return; }
            break;
        case SET_PANIC_HISTORY: g_app.panic.history = i; break;
        case SET_TOR_STATE: tor_state_choose(i); return;
        case SET_SANDBOX:
            g_app.sandbox = i;
            // It goes up at Start chatting, and can't come down once it's up.
            if (!g_app.onboarding) { note("Sandbox: %s - from the next start", i ? "on" : "off"); return; }
            break;
        case SET_UPDATER: {
            int was = update_helper_running();
            g_app.updater = i;
            update_helper_enable(i);
            if (!i && was) {
                note("Updater: off - %s", update_helper_running() ? "it stops once this update is done" : "stopped");
                return;
            }
            // It can only start before the sandbox goes up.
            if (i && !was && (g_app.sandboxed & PLATFORM_SANDBOX_FILES)) { note("Updater: on - from the next start"); return; }
            break;
        }
        default: return;
    }
    char v[32]; setting_value(id, v, sizeof v);
    note("%s: %s", setting_def(id)->label, v);
}

// h/l on a row: the next or previous value, wrapping around. The colour steps through the palette.
void setting_step(setting_id_t id, int dir) {
    if (id == SET_COLOUR) {
        int cur = palette_index(g_app.color);
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
    return port > 0 && port <= UINT16_MAX;
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
        case SET_BRIDGES: {
            char lines[sizeof g_app.tor.bridges], why[200], kinds[80];
            int rc = bridges_parse(text, lines, sizeof lines, why, sizeof why);
            crypto_wipe(text, sizeof text);
            if (rc != 0) { note("Bridges: %s", why); return; }
            int changed = strcmp(lines, g_app.tor.bridges) != 0;
            copy_str(g_app.tor.bridges, lines, sizeof g_app.tor.bridges);
            crypto_wipe(lines, sizeof lines);
            int n = bridge_count(g_app.tor.bridges, kinds, sizeof kinds);
            if (n) note("Bridges: %d (%s) - chat's own tor reaches the Tor network only through them", n, kinds);
            else note("Bridges: none");
            if (changed) tor_link_restart();
            return;
        }
        case SET_TRANSPORTS: {
            char full[TOR_PATH_MAX], line[TOR_PATH_MAX + 80];
            if (text[0] && platform_full_path(text, full, sizeof full) != 0) { note("that path is too long"); return; }
            if (text[0] && strchr(full, ' ')) { note("tor can't run a program from a path with spaces in it"); return; }
            copy_str(g_app.tor.pt_dir, text[0] ? full : "", sizeof g_app.tor.pt_dir);
            transport_line(line, sizeof line);
            // The sandbox only lets chat, and tor, run what was found as it went up.
            note("Transport programs: %s%s", line, g_app.sandboxed & PLATFORM_SANDBOX_FILES
                 ? " - with the sandbox up, programs it didn't find as it went up run from the next start" : "");
            if (g_app.tor.bridges[0]) tor_link_restart();
            return;
        }
        case SET_TOR_SOCKS:
        case SET_TOR_CONTROL:
            if (!valid_host_port(text)) { note("that isn't host:port"); return; }
            copy_str(id == SET_TOR_SOCKS ? r->tor.socks : r->tor.control, text, TOR_HOST_MAX);
            routing_changed(id);
            return;
        case SET_TOR_PATH: {
            char found[TOR_PATH_MAX];
            if (text[0] && platform_find_program("tor", text, found, sizeof found) != 0) {
                note("can't use %.100s - it has to be a full path to a program only root or you can change", text);
                return;
            }
            copy_str(g_app.tor.path, text[0] ? found : "", sizeof g_app.tor.path);
            note("Tor program: %s", g_app.tor.path[0] ? g_app.tor.path : "search PATH and the usual folders");
            return;
        }
        case SET_FILE_LIMIT: {
            uint64_t v;
            if (file_parse_size(text, &v) != 0 || v == 0 || v > FILE_HARD_MAX) { note("that isn't a size from 1 byte to 1 GB (8M, 500K, 1G)"); return; }
            g_app.file_cap = v;
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (takes_settings(i)) chat_set_file_options(g_app.sessions[i].engine, v, g_app.fast_files);
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
                if (takes_settings(i)) chat_set_nick(g_app.sessions[i].engine, g_app.nick);
            note("Nickname: %s", g_app.nick);
            if (!g_loading_settings) nick_changed();
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
            if (!text[0] || *end || port < 0 || port > UINT16_MAX) { note("not a port: %.20s (0-65535, 0 picks a free one)", text); return; }
            g_app.default_port = (uint16_t)port;
            note("UDP port for new sessions: %ld%s", port, port ? "" : " (a free one)");
            return;
        }
        default:
            return;
    }
}

const char *setting_edit_separator(void) {
    return g_edit_id == SET_BRIDGES ? "; " : g_edit_id == SET_RELAYS ? " " : NULL;
}

void commit_setting_edit(void) {
    char text[sizeof g_app.input.buf];
    copy_str(text, g_app.input.buf, sizeof text);
    setting_id_t id = g_edit_id;
    end_setting_edit();
    setting_apply_text(id, text);
    crypto_wipe(text, sizeof text);
}

// Where setting i is on the page: its section, and the group it's in, if any.
void setting_place(int i, char *out, size_t cap) {
    const char *section = "", *group = NULL;
    for (int k = 0; k <= i && k < N_SETTINGS; k++) {
        if (SETTINGS[k].section) { section = SETTINGS[k].section; group = NULL; }
        if (SETTINGS[k].group) group = SETTINGS[k].group;
    }
    if (group) snprintf(out, cap, "%s" CRUMB "%s", section, group);
    else copy_str(out, section, cap);
}

static int starts_a_word(const char *s, const char *word, size_t n) {
    for (const char *p = s; *p; p++)
        if ((p == s || !isalnum((unsigned char)p[-1])) && strncasecmp(p, word, n) == 0) return 1;
    return 0;
}

static int has_nocase(const char *s, const char *word, size_t n) {
    for (; s && *s; s++) if (strncasecmp(s, word, n) == 0) return 1;
    return 0;
}

// How well setting i matches a word of a search, lower being better, or -1: its label starting with
// it, then a word of its label or its :set name starting with it, either holding it, its place on
// the page holding it, and last its help.
static int word_rank(int i, const char *word, size_t n) {
    const setting_def_t *d = &SETTINGS[i];
    char place[96];
    setting_place(i, place, sizeof place);
    if (strncasecmp(d->label, word, n) == 0) return 0;
    if (starts_a_word(d->label, word, n) || strncasecmp(d->key, word, n) == 0) return 1;
    if (has_nocase(d->label, word, n) || has_nocase(d->key, word, n)) return 2;
    if (has_nocase(place, word, n)) return 3;
    return has_nocase(d->help, word, n) ? 4 : -1;
}

// The settings that match every word of query, best first and otherwise in the page's order, with
// the ones that aren't listed right now after the rest. An empty query matches them all.
int settings_search(const char *query, int *out, int cap) {
    int idx[N_SETTINGS], rank[N_SETTINGS], n = 0;
    for (int i = 0; i < N_SETTINGS; i++) {
        int r = setting_shown(SETTINGS[i].id) ? 0 : 100;
        for (const char *w = query; r >= 0 && *w; ) {
            while (*w == ' ') w++;
            size_t len = strcspn(w, " ");
            if (len) {
                int k = word_rank(i, w, len);
                r = k < 0 ? -1 : r + k;
            }
            w += len;
        }
        if (r < 0) continue;
        int j = n++;
        for (; j > 0 && rank[j - 1] > r; j--) { idx[j] = idx[j - 1]; rank[j] = rank[j - 1]; }
        idx[j] = i;
        rank[j] = r;
    }
    if (n > cap) n = cap;
    memcpy(out, idx, (size_t)n * sizeof *out);
    return n;
}

// The settings' sections and the Done page after them, for the list on the left of the pages.
int settings_sections(const char **out, int cap) {
    int n = 0;
    for (int i = 0; i < N_SETTINGS && n < cap; i++) if (SETTINGS[i].section) out[n++] = SETTINGS[i].section;
    if (n < cap) out[n++] = g_app.onboarding ? "Start" : "Done";
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

// The sections, and the Done page.
int settings_n_sections(void) {
    int n = 0;
    while (section_begin(n) < N_SETTINGS) n++;
    return n + 1;
}

int settings_done_page(void) { return settings_n_sections() - 1; }

// Selects a row on its section's page, or the Done button on the Done page.
void settings_select(int sel) {
    g_app.settings.sel = sel;
    if (sel >= N_SETTINGS) { g_app.settings.page = settings_done_page(); return; }
    g_app.settings.page = settings_section_index(SETTINGS[sel].id);
    g_app.settings.rows[g_app.settings.page] = sel;
}

// Section s, on the row selected there last if it's still listed, otherwise its first. The Done
// page always opens on its button, so Tab then Enter leaves.
void settings_go_section(int s) {
    if (s == settings_done_page()) { settings_select(SETTINGS_DONE); return; }
    int i = g_app.settings.rows[s];
    if (i < section_begin(s) || i >= section_begin(s + 1) || !setting_shown(SETTINGS[i].id)) i = section_row(s, 1);
    g_app.settings.page = s;
    settings_select(i);
}

// The Done page's next listed row after sel, or before it for dir < 0, or -1 if there isn't one.
static int done_page_row(int sel, int dir) {
    for (int i = sel + dir; i >= 0 && i < N_SETTINGS; i += dir)
        if (setting_shown(SETTINGS[i].id)) return i;
    return -1;
}

// j/k go through the sections' listed rows in turn, then the Done page's button and its rows.
void settings_step(int dir) {
    int sel = g_app.settings.sel, s = g_app.settings.page;
    if (s == settings_done_page()) {
        int i = sel == SETTINGS_DONE ? (dir > 0 ? done_page_row(-1, 1) : -1) : done_page_row(sel, dir);
        if (i >= 0) g_app.settings.sel = i;
        else if (sel == SETTINGS_DONE && dir < 0) settings_select(section_row(s - 1, -1));
        else if (dir < 0) g_app.settings.sel = SETTINGS_DONE;
        return;
    }
    int a = section_begin(s), b = section_begin(s + 1);
    for (int i = sel + dir; i >= a && i < b; i += dir)
        if (setting_shown(SETTINGS[i].id)) { settings_select(i); return; }
    if (dir > 0) settings_select(section_row(s + 1, 1));
    else if (s > 0) settings_select(section_row(s - 1, -1));
}

// g and G: the page's first or last row, the Done page's button being its first.
void settings_go_end(int last) {
    int s = g_app.settings.page;
    if (s != settings_done_page()) settings_select(section_row(s, last ? -1 : 1));
    else if (!last || done_page_row(N_SETTINGS, -1) < 0) g_app.settings.sel = SETTINGS_DONE;
    else g_app.settings.sel = done_page_row(N_SETTINGS, -1);
}

// Moves the selection off a row that stopped being listed, to the next one up in its section, or
// down. On the Done page, back to the button.
void settings_fix_sel(void) {
    int sel = g_app.settings.sel;
    if (sel >= N_SETTINGS || setting_shown(SETTINGS[sel].id)) return;
    if (g_app.settings.page == settings_done_page()) { g_app.settings.sel = SETTINGS_DONE; return; }
    int s = settings_section_index(SETTINGS[sel].id), a = section_begin(s), b = section_begin(s + 1), i = sel - 1;
    while (i >= a && !setting_shown(SETTINGS[i].id)) i--;
    if (i < a) for (i = sel + 1; i < b && !setting_shown(SETTINGS[i].id); i++) {}
    settings_select(i >= a && i < b ? i : SETTINGS_DONE);
}

// Tab and Shift+Tab: the next or previous section, round from the last to the first.
void settings_section_step(int dir) {
    int n = settings_n_sections();
    settings_go_section((g_app.settings.page + dir + n) % n);
}

void begin_settings(void) {
    if (g_app.mode != MODE_CHAT) return;
    device_check();
    g_app.mode = MODE_SETTINGS;
    if (g_app.settings.page == settings_done_page()) settings_go_section(0);
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
        if (g_app.net_log != NET_LOG_OFF) push_log("* routing: %s", route_label());
        sandbox_up();
        sync_update_proxy();
        tor_link_ensure(now_seconds());
        finish_onboarding();
    }
    g_app.dirty = 1;
}

// What the keys do on the selected row, with the main action first.
const char *settings_hint(void) {
    const setting_def_t *d = g_app.settings.sel < N_SETTINGS ? &SETTINGS[g_app.settings.sel] : NULL;
    const char *act;
    if (!d) act = g_app.onboarding ? "enter start" : "enter done";
    else if (g_app.settings.page == settings_done_page()) act = "enter open";
    else if (d->id == SET_COLOUR) act = "h/l step" DOT_SEP "enter type one";
    else if (d->kind == K_TEXT || d->kind == K_SECRET) act = "enter edit";
    else if (d->id == SET_SIGN) act = "enter choose";
    else if (d->id == SET_SHADOW) act = "enter set";
    else if (d->id == SET_AGE_RECIPIENT || d->id == SET_PGP_PUBKEY) act = "enter copy";
    else if (d->id == SET_EXPORT_KEY) act = "enter export";
    else if (row_greyed(d->id)) act = NULL;
    else act = "h/l change";
    static char hint[160];
    snprintf(hint, sizeof hint, "%s%sj/k move" DOT_SEP "tab/1-%d section" DOT_SEP "/ search" DOT_SEP "esc %s",
             act ? act : "", act ? DOT_SEP : "", settings_n_sections(), g_app.onboarding ? "start" : "done");
    return hint;
}

void finish_onboarding(void) {
    g_app.mode = MODE_CHAT;

    if (g_app.autostart.session[0]) {
        addr_t peers[MAX_PEER_ARGS];
        int n_peers = 0;
        if (g_app.autostart.n_peers > 0 && g_app.route.mode == ROUTE_TOR) {
            // Looking a name up here would go around Tor.
            push_log("* --peer left out: Tor mode never reaches peers over UDP, so their addresses aren't looked up");
        } else {
            for (int i = 0; i < g_app.autostart.n_peers; i++) {
                if (addr_parse_hostport(g_app.autostart.peer_args[i], &peers[n_peers]) == 0) n_peers++;
                else push_log("* --peer %s left out: can't find that address", g_app.autostart.peer_args[i]);
            }
        }
        start_session(g_app.autostart.session, g_app.autostart.password, 0,
                      g_app.autostart.port, peers, n_peers);
        crypto_wipe(g_app.autostart.password, sizeof g_app.autostart.password);
        g_app.autostart.session[0] = '\0';
    }
    rooms_join_at_start();
    g_app.dirty = 1;
}
