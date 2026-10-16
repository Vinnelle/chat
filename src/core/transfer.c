// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Files, as chat.h describes them: offers, fetches, and the chunks sent in slots.
#include "core/engine.h"

const file_entry_t *chat_file(const chat_t *c, int num) {
    for (int i = 0; i < FILE_OFFERS_MAX; i++) if (c->files[i].used && c->files[i].num == num) return &c->files[i];
    return NULL;
}

static file_entry_t *file_by_num(chat_t *c, int num) { return (file_entry_t *)chat_file(c, num); }

static file_entry_t *file_by_fid(chat_t *c, const uint8_t owner[ID_LEN], const uint8_t fid[FILE_ID_LEN]) {
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        file_entry_t *e = &c->files[i];
        if (e->used && memcmp(e->owner, owner, ID_LEN) == 0 && memcmp(e->fid, fid, FILE_ID_LEN) == 0) return e;
    }
    return NULL;
}

static peer_t *file_owner(chat_t *c, const file_entry_t *e) {
    peer_t *p = find_peer_by_id(c, e->owner);
    return p && p->ok ? p : NULL;
}

uint64_t chat_file_got(const file_entry_t *e) {
    uint64_t got = e->done;
    for (int i = 0; i < e->win_n && i < FILE_WINDOW; i++) {
        if (!(e->win_got >> i & 1)) continue;
        uint64_t off = e->win_off + (uint64_t)i * FILE_CHUNK;
        got += off < e->size && e->size - off < FILE_CHUNK ? e->size - off : FILE_CHUNK;
    }
    return got < e->size ? got : e->size;
}

// The bytes p sends in an otherwise empty slot: one chunk over UDP or Tor, two through the relays.
static double file_slot_bytes(const peer_t *p) {
    return (p->batches && p->addr.kind == ADDR_NOSTR ? 2.0 : 1.0) * FILE_CHUNK;
}

#define ETA_MIN_CHUNKS 4

double chat_file_eta(const chat_t *cc, const file_entry_t *e, double now) {
    chat_t *c = (chat_t *)cc;
    peer_t *p = file_owner(c, e);
    if (!p) return ETA_AWAY;
    if (!peer_trusted(c, p)) return ETA_UNVERIFIED;
    uint64_t got = chat_file_got(e);
    double left = (double)(e->size - got), took = now - e->since;
    // The rate so far, once there are enough chunks to measure it. Until then, chat's normal rate on
    // its path: a slot comes up to a quarter of its interval late, an eighth on average.
    if (got >= ETA_MIN_CHUNKS * FILE_CHUNK && took > 0.0) return left * took / (double)got;
    return left / file_slot_bytes(p) * cover_interval(c, p) * (1.0 + JITTER / 2);
}

// A whole file in memory, at least a byte so an empty one isn't NULL.
static uint8_t *file_mem_alloc(uint64_t size) { return malloc(size ? (size_t)size : 1); }

static void file_mem_free(uint8_t **mem, uint64_t size) {
    if (!*mem) return;
    crypto_wipe(*mem, size ? (size_t)size : 1);
    free(*mem);
    *mem = NULL;
}

// Stops a download: deletes the partial file and wipes anything in memory.
static void file_stop_download(file_entry_t *e, dl_state_t to) {
    if (e->out) { fclose(e->out); e->out = NULL; }
    if (e->part_path[0]) { platform_remove(e->part_path); e->part_path[0] = '\0'; }
    file_mem_free(&e->mem, e->size);
    if (e->win) { crypto_wipe(e->win, (size_t)FILE_WINDOW * FILE_CHUNK); free(e->win); e->win = NULL; }
    e->done = e->win_off = e->win_got = 0;
    e->win_n = 0;
    e->dl = to;
}

static void file_fail(file_entry_t *e, const char *why) {
    file_stop_download(e, DL_FAILED);
    copy_str(e->why, why, sizeof e->why);
}

static void file_cache_drop(file_entry_t *e) { file_mem_free(&e->cache, e->size); }

// Keeps e->mem (a whole file, checked) as e's cache, dropping the oldest others to stay within
// FILE_CACHE_MAX.
static void file_cache_keep(chat_t *c, file_entry_t *e) {
    uint8_t *m = e->mem;
    e->mem = NULL;
    if (!m) return;
    file_cache_drop(e);
    if (e->size > FILE_CACHE_MAX) { file_mem_free(&m, e->size); return; }
    for (;;) {
        uint64_t total = e->size;
        file_entry_t *old = NULL;
        for (int i = 0; i < FILE_OFFERS_MAX; i++) {
            file_entry_t *o = &c->files[i];
            if (!o->used || !o->cache || o == e) continue;
            total += o->size;
            if (!old || o->num < old->num) old = o;
        }
        if (total <= FILE_CACHE_MAX || !old) break;
        file_cache_drop(old);
    }
    e->cache = m;
}

void file_free(file_entry_t *e) {
    file_stop_download(e, DL_NONE);
    file_cache_drop(e);
    if (e->fp) { fclose(e->fp); e->fp = NULL; }
    file_mem_free(&e->clean, e->size);
    crypto_wipe(e, sizeof *e);
}

// A free slot, or the oldest one that isn't ours and isn't being transferred. A peer over
// FILE_OFFERS_PER_PEER replaces its own oldest instead, so nobody can push out everyone else's offers.
#define FILE_OFFERS_PER_PEER 16
static file_entry_t *file_new(chat_t *c, const uint8_t *owner) {
    file_entry_t *pick = NULL;
    int theirs = 0;
    for (int i = 0; owner && i < FILE_OFFERS_MAX; i++)
        theirs += c->files[i].used && !c->files[i].mine && memcmp(c->files[i].owner, owner, ID_LEN) == 0;
    for (int i = 0; i < FILE_OFFERS_MAX && !pick && theirs < FILE_OFFERS_PER_PEER; i++) if (!c->files[i].used) pick = &c->files[i];
    for (int i = 0; i < FILE_OFFERS_MAX && !pick; i++) {
        file_entry_t *e = &c->files[i];
        if (e->mine || e->dl == DL_ACTIVE || e->dl == DL_QUEUED) continue;
        if (theirs >= FILE_OFFERS_PER_PEER && memcmp(e->owner, owner, ID_LEN) != 0) continue;
        if (!pick || e->num < pick->num) pick = e;
    }
    if (!pick) return NULL;
    file_free(pick);
    pick->used = 1;
    pick->num = ++c->file_seq;
    return pick;
}

static void file_desc(const file_entry_t *e, char *out, size_t cap) {
    char sz[32];
    file_format_size(e->size, sz, sizeof sz);
    snprintf(out, cap, "%s (%s%s)", e->name, sz, e->image ? ", image" : "");
}

int file_downloading_from(const chat_t *c, const peer_t *p) {
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        const file_entry_t *e = &c->files[i];
        if (e->used && e->dl == DL_ACTIVE && memcmp(e->owner, p->id, ID_LEN) == 0) return 1;
    }
    return 0;
}

static void file_send_offer(chat_t *c, peer_t *p, const file_entry_t *e, double now) {
    char mid[MID_HEX + 1]; gen_mid(mid);
    char fidhex[FILE_ID_LEN * 2 + 1], shahex[SHA256_LEN * 2 + 1];
    hex_encode(e->fid, FILE_ID_LEN, fidhex);
    hex_encode(e->sha, SHA256_LEN, shahex);
    char rec[MSG_LINE_LEN];
    snprintf(rec, sizeof rec, "fo\t%s\t%s\t%llu\t%s\t%s\t%s", mid, fidhex, (unsigned long long)e->size, shahex,
             e->image ? "image" : "file", e->name);
    // Retried until acked, like a message.
    if (send_peer(c, p, rec) == 0) track_message(c, p, mid, rec, 0, now);
}

// Our offers, to a peer that has just joined or whose code was just compared.
void file_offer_all(chat_t *c, peer_t *p) {
    if (!p->ok || !peer_trusted(c, p)) return;
    for (int i = 0; i < FILE_OFFERS_MAX; i++)
        if (c->files[i].used && c->files[i].mine && c->files[i].fp) file_send_offer(c, p, &c->files[i], now_seconds());
}

// A path typed in a command: trailing spaces and the quotes file managers copy paths with are
// removed, and a leading ~ is the home folder.
#define TYPED_PATH_MAX 1024
static void typed_path(const char *in, char *path, size_t cap) {
    while (*in == ' ') in++;
    copy_str(path, in, cap);
    size_t pl = strlen(path);
    while (pl > 0 && path[pl - 1] == ' ') path[--pl] = '\0';
    if (pl >= 2 && (path[0] == '"' || path[0] == '\'') && path[pl - 1] == path[0]) { memmove(path, path + 1, pl - 2); path[pl - 2] = '\0'; }
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char *home = platform_home_dir();
        char full[TYPED_PATH_MAX];
        if (home) { snprintf(full, sizeof full, "%s%s", home, path + 1); copy_str(path, full, cap); }
    }
}

// "asis" first, since a path can hold spaces.
cmd_result_t cmd_send(void *ctx, const char *arg) {
    chat_t *c = ctx;
    char path[TYPED_PATH_MAX];
    while (*arg == ' ') arg++;
    int asis = strncmp(arg, "asis", 4) == 0 && (arg[4] == ' ' || arg[4] == '\0');
    typed_path(asis ? arg + 4 : arg, path, sizeof path);
    if (!path[0]) {
        ui_print(c, "* usage: :send [asis] PATH - offers a file to everyone here; nobody gets it unless they fetch it. A "
                    "picture goes without what could tell where, when or with what it was made, unless asis");
        return CMD_OK;
    }
    chat_send_file(c, path, asis);
    return CMD_OK;
}

// What went from a picture offered, and what was done to it.
static void say_cleaned(chat_t *c, int num, unsigned took, const char *old_name) {
    static const struct { unsigned flag; const char *what; } WENT[] = {
        { CLEAN_LOCATION, "where it was taken" }, { CLEAN_CAMERA, "camera details and when" },
        { CLEAN_XMP, "editing details" }, { CLEAN_IPTC, "captions and names" }, { CLEAN_COMMENT, "comments" },
        { CLEAN_EXTRA, "a picture or video tucked in with it" }, { CLEAN_TIME, "when it was saved" },
        { CLEAN_OTHER, "other hidden data" },
    };
    char what[512] = "";
    size_t p = 0;
    int n = 0;
    for (size_t i = 0; i < COUNT_OF(WENT); i++) {
        if (!(took & WENT[i].flag) || p >= sizeof what) continue;
        int w = snprintf(what + p, sizeof what - p, "%s%s", n++ ? ", " : "", WENT[i].what);
        if (w > 0) p += (size_t)w;
    }
    if (old_name && p < sizeof what) {
        int w = snprintf(what + p, sizeof what - p, "%sits name (%s)", n++ ? ", " : "", old_name);
        if (w > 0) p += (size_t)w;
    }
    const char *noise = took & CLEAN_NOISE ? "; added noise nobody can see, so it matches no other copy" : "";
    if (n) ui_print(c, "* file %d: took out %s%s - :send asis offers a picture as it is", num, what, noise);
    else ui_print(c, "* file %d: nothing in it to take out%s", num, noise);
}

void chat_send_file(chat_t *c, const char *path, int asis) {
    uint64_t size = 0;
    FILE *f = platform_open_regular(path, &size);
    if (!f) { ui_print(c, "* can't send %s: not a file chat can read", path); return; }
    if (size > FILE_HARD_MAX) {
        fclose(f);
        char lim[32]; file_format_size(FILE_HARD_MAX, lim, sizeof lim);
        ui_print(c, "* can't send %s: files go up to %s", path, lim);
        return;
    }
    // Hashed while it's read now. Chunks are read from the same open file later, so a file changed
    // since then gives a hash that doesn't match, and nothing else is ever sent in its place.
    sha256_ctx_t h;
    sha256_init(&h);
    uint8_t buf[65536], head[CLEAN_HEAD] = { 0 };
    uint64_t total = 0;
    size_t n;
    uint8_t *mem = NULL;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (total < sizeof head) memcpy(head + total, buf, n < sizeof head - total ? n : sizeof head - total);
        // A picture is kept as it's read, to show it here.
        if (total == 0 && size <= FILE_VIEW_MAX && image_kind(buf, n)) mem = file_mem_alloc(size);
        if (mem && n <= size - total) memcpy(mem + total, buf, n);
        sha256_update(&h, buf, n);
        total += n;
        if (total > size) break;
    }
    crypto_wipe(buf, sizeof buf);
    size_t got_head = total < sizeof head ? (size_t)total : sizeof head;
    const char *kind = image_kind(head, got_head);
    int image = kind != NULL;
    if (ferror(f) || total != size) {
        file_mem_free(&mem, size);
        fclose(f);
        ui_print(c, "* can't send %s: it changed while it was read", path);
        return;
    }
    // A picture goes without what could tell where, when or with what it was made, unless it's asked
    // for as it is.
    uint8_t *clean = NULL;
    size_t clean_len = 0;
    int took = -1;
    if (image && !asis) {
        if (!mem) {
            fclose(f);
            ui_print(c, "* not sent: %s is a picture too big to clean of where and when it was taken (over 64 MB) - "
                        ":send asis %s sends it as it is", path, path);
            return;
        }
        uint8_t seed[CLEAN_SEED_LEN];
        gen_random(seed, sizeof seed);
        took = image_clean(mem, (size_t)size, c->picture_noise, seed, &clean, &clean_len);
        crypto_wipe(seed, sizeof seed);
        if (took < 0) {
            file_mem_free(&mem, size);
            fclose(f);
            ui_print(c, "* not sent: %s doesn't read as a whole picture, so what it holds can't be taken out - :send "
                        "asis %s sends it as it is", path, path);
            return;
        }
    }
    file_entry_t *e = file_new(c, NULL);
    if (!e) {
        file_mem_free(&mem, size);
        file_mem_free(&clean, clean_len);
        fclose(f);
        ui_print(c, "* can't offer more files at once - :cancel one you offered first");
        return;
    }
    e->mine = 1;
    memcpy(e->owner, c->my_id, ID_LEN);
    gen_random(e->fid, FILE_ID_LEN);
    char old_name[FILE_NAME_MAX + 1];
    file_clean_name(file_basename(path), old_name);
    copy_str(e->name, old_name, sizeof e->name);
    int renamed = 0;
    if (clean) {
        // Offered from memory from now on, and shown here as the peers get it.
        file_mem_free(&mem, size);
        e->clean = clean;
        size = clean_len;
        sha256_init(&h);
        sha256_update(&h, clean, clean_len);
        if (clean_name_tells(old_name)) {
            copy_str(e->name, strcmp(kind, "jpeg") == 0 ? "photo.jpg" : strcmp(kind, "png") == 0 ? "image.png" : "image.gif",
                     sizeof e->name);
            renamed = 1;
        }
        if ((mem = file_mem_alloc(size)) != NULL) memcpy(mem, clean, clean_len);
    } else if (!image) {
        file_mem_free(&mem, size);
    }
    e->size = size;
    sha256_final(&h, e->sha);
    e->image = image;
    e->fp = f;
    current_hhmm(e->at);
    if (mem) { e->mem = mem; file_cache_keep(c, e); }
    char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
    char who[MAX_NICK + 8]; snprintf(who, sizeof who, "%s (you)", c->nick);
    char text[FILE_NAME_MAX + 96];
    snprintf(text, sizeof text, "offered %s as file %d", desc, e->num);
    ui_chat_file(c, c->my_color, 0, who, text, e->num);
    if (clean) say_cleaned(c, e->num, (unsigned)took, renamed ? old_name : NULL);
    const char *cannot = image ? NULL : clean_cannot(head, got_head, old_name);
    if (cannot)
        ui_print(c, "* file %d is a %s, which chat can't clean: it may say where, when and with what it was made", e->num,
                 cannot);
    int sent = 0, held = 0;
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used || !p->ok) continue;
        if (!peer_trusted(c, p)) { held++; continue; }
        file_send_offer(c, p, e, now_seconds());
        sent++;
    }
    if (held) ui_print(c, "* not offered to %d peer%s whose verify code you haven't compared", held, held == 1 ? "" : "s");
    else if (!sent) ui_print(c, "* nobody else is here yet - it's offered to whoever joins");
    if (e->image) ui_print(c, "* it's offered as a picture: others see it hidden until they choose :show %d", e->num);
    if (e->cache && c->file_view) c->file_view(c->ui, e->num, e->name, e->cache, (size_t)e->size);
}

// When a window's request is sent again if nothing comes: after a few slots, and some seconds more.
static double file_retry_at(double now, double slot_interval) { return now + 6.0 * slot_interval + 4.0; }

// Asks p for the first run of the window that hasn't arrived (the whole window at the start).
// Anything that arrived after the run isn't requested again.
static void file_request(chat_t *c, file_entry_t *e, peer_t *p, double now) {
    if (e->win_n == 0) {
        uint64_t left = e->size - e->win_off;
        uint64_t chunks = (left + FILE_CHUNK - 1) / FILE_CHUNK;
        e->win_n = chunks > FILE_WINDOW ? FILE_WINDOW : (int)chunks;
        e->win_got = 0;
    }
    int first = 0;
    while (first < e->win_n && (e->win_got >> first & 1)) first++;
    int end = first;
    while (end < e->win_n && !(e->win_got >> end & 1)) end++;
    e->req_end = end;
    char fidhex[FILE_ID_LEN * 2 + 1]; hex_encode(e->fid, FILE_ID_LEN, fidhex);
    char rec[96];
    snprintf(rec, sizeof rec, "fg\t%s\t%llu\t%d", fidhex, (unsigned long long)(e->win_off + (uint64_t)first * FILE_CHUNK),
             end - first);
    send_peer(c, p, rec);
    double iv = c->fast_files && p->addr.kind != ADDR_NOSTR ? FILE_FAST_INTERVAL : cover_interval(c, p);
    e->retry_at = file_retry_at(now, iv);
}

// The folder file e is saved in: the one asked for, else Downloads.
static int file_dir(const file_entry_t *e, char *dir, size_t cap) {
    if (e->save_dir[0]) { copy_str(dir, e->save_dir, cap); return 0; }
    return platform_downloads_dir(dir, cap);
}

// The same folder, as messages name it.
static void file_dir_name(const file_entry_t *e, char *out, size_t cap) {
    copy_str(out, e->save_dir[0] ? e->save_dir : "Downloads", cap);
}

// A new hidden file in e's folder to write it to, under a name nothing else will use. file_save_as
// gives it its real name once its hash matches.
#define PART_ID_LEN 6
static FILE *file_open_part(file_entry_t *e) {
    char dir[FILE_DIR_MAX];
    if (file_dir(e, dir, sizeof dir) != 0) return NULL;
    uint8_t r[PART_ID_LEN]; gen_random(r, sizeof r);
    char rh[PART_ID_LEN * 2 + 1]; hex_encode(r, sizeof r, rh);
    snprintf(e->part_path, sizeof e->part_path, "%s/.chat-%s.part", dir, rh);
    FILE *f = platform_create_new(e->part_path);
    if (!f) e->part_path[0] = '\0';
    return f;
}

// Renames the part file to e's name in its folder: name, otherwise "name (2).ext" and so on.
// Sets e->saved.
#define SAVE_NAME_TRIES 100
static int file_save_as(file_entry_t *e) {
    char dir[FILE_DIR_MAX], saved[sizeof e->saved];
    if (file_dir(e, dir, sizeof dir) != 0) return -1;
    const char *dot = strrchr(e->name, '.');
    size_t stem = dot && dot != e->name ? (size_t)(dot - e->name) : strlen(e->name);
    for (int k = 1; k < SAVE_NAME_TRIES; k++) {
        if (k == 1) snprintf(saved, sizeof saved, "%s/%s", dir, e->name);
        else snprintf(saved, sizeof saved, "%s/%.*s (%d)%s", dir, (int)stem, e->name, k, e->name + stem);
        if (platform_move_new(e->part_path, saved) == 0) {
            e->part_path[0] = '\0';
            copy_str(e->saved, saved, sizeof e->saved);
            return 0;
        }
    }
    return -1;
}

// Reads f to the end, hashing it, and writing it to out and mem if given. Returns 1 if it's
// exactly e's size and matches its hash, 0 if not, -1 if out couldn't be written.
static int file_copy_checked(const file_entry_t *e, FILE *f, FILE *out, uint8_t *mem) {
    sha256_ctx_t h;
    sha256_init(&h);
    uint8_t buf[65536];
    uint64_t total = 0;
    size_t n;
    int match = 1, ok = 1;
    while (ok && (n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (n > e->size - total) { match = 0; break; }
        sha256_update(&h, buf, n);
        if (mem) memcpy(mem + total, buf, n);
        if (out) ok = fwrite(buf, 1, n, out) == n;
        total += n;
    }
    crypto_wipe(buf, sizeof buf);
    uint8_t got[SHA256_LEN];
    sha256_final(&h, got);
    if (ferror(f) || total != e->size || crypto_equal(got, e->sha, SHA256_LEN) != 0) match = 0;
    return !ok ? -1 : match;
}

// Whether the file e was saved as is still there and still matches the offer. With mem, its
// bytes are put in *mem (for one up to FILE_VIEW_MAX). Returns 0 if it matches.
static int file_check_saved(const file_entry_t *e, uint8_t **mem) {
    if (mem) *mem = NULL;
    if (!e->saved[0] || (mem && e->size > FILE_VIEW_MAX)) return -1;
    uint64_t size = 0;
    FILE *f = platform_open_regular(e->saved, &size);
    if (!f) return -1;
    uint8_t *m = NULL;
    if (size != e->size || (mem && !(m = file_mem_alloc(size)))) { fclose(f); return -1; }
    int match = file_copy_checked(e, f, NULL, m);
    fclose(f);
    if (match != 1) {
        file_mem_free(&m, size);
        return -1;
    }
    if (mem) *mem = m;
    return 0;
}

// One of ours as it is now, if it's still what was offered.
static int file_read_own(const file_entry_t *e, uint8_t **mem) {
    *mem = NULL;
    if (e->clean) {
        if (!(*mem = file_mem_alloc(e->size))) return -1;
        memcpy(*mem, e->clean, (size_t)e->size);
        return 0;
    }
    if (!e->fp || e->size > FILE_VIEW_MAX || fseek(e->fp, 0, SEEK_SET) != 0) return -1;
    uint8_t *m = file_mem_alloc(e->size);
    if (!m) return -1;
    if (file_copy_checked(e, e->fp, NULL, m) != 1) { file_mem_free(&m, e->size); return -1; }
    *mem = m;
    return 0;
}

const uint8_t *chat_file_bytes(chat_t *c, int num) {
    file_entry_t *e = file_by_num(c, num);
    if (!e || !e->image || e->size > FILE_VIEW_MAX) return NULL;
    if (!e->cache) {
        uint8_t *m = NULL;
        int coming = e->dl == DL_ACTIVE || e->dl == DL_QUEUED;
        if (e->mine ? file_read_own(e, &m) == 0 : !coming && file_check_saved(e, &m) == 0) {
            e->mem = m;
            file_cache_keep(c, e);
        }
    }
    return e->cache;
}

int chat_file_sending(const chat_t *c, const file_entry_t *e, double now, char name[CHAT_NAME_LEN], int *permille) {
    int n = 0;
    uint64_t best = 0;
    name[0] = '\0';
    *permille = 0;
    for (int i = 0; e->mine && e->fp && i < c->peer_hi; i++) {
        const peer_t *p = &c->peers[i];
        if (!p->used || !p->ok || memcmp(p->serve_fid, e->fid, FILE_ID_LEN) != 0 || p->serve_next >= e->size) continue;
        if (!p->serving && now - p->serve_at > FILE_SENDING_QUIET) continue;
        if (n++ == 0 || p->serve_next > best) { best = p->serve_next; chat_peer_name(c, p, name); }
    }
    if (n) *permille = e->size ? (int)(best * 1000 / e->size) : 1000;
    return n;
}

void chat_file_sent_to(const file_entry_t *e, char *out, size_t cap) {
    if (cap == 0) return;
    if (e->n_sent <= 0) out[0] = '\0';
    else if (e->n_sent == 1) snprintf(out, cap, "%s", e->sent_name[0]);
    else if (e->n_sent == 2) snprintf(out, cap, "%s and %s", e->sent_name[0], e->sent_name[1]);
    else snprintf(out, cap, "%s and %d others", e->sent_name[0], e->n_sent - 1);
}

// p has been sent the last of one of ours. Peers past FILE_SENT_MAX are only counted, so one of them
// fetching it again counts twice.
static void file_sent(chat_t *c, file_entry_t *e, const peer_t *p) {
    for (int i = 0; i < e->n_sent && i < FILE_SENT_MAX; i++) if (memcmp(e->sent_id[i], p->id, ID_LEN) == 0) return;
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    if (e->n_sent < FILE_SENT_MAX) {
        memcpy(e->sent_id[e->n_sent], p->id, ID_LEN);
        copy_str(e->sent_name[e->n_sent], name, sizeof e->sent_name[0]);
    }
    e->n_sent++;
    ui_print(c, "* sent all of file %d (%s) to %s", e->num, e->name, name);
}

// Saves file e in its folder without fetching it: from mem (its bytes, already checked), or as a
// copy of where it was saved before, checked as it's read. Returns 0 once saved, 1 if there's no
// copy that still matches, -1 if it couldn't be written (after saying why).
static int file_save_local(chat_t *c, file_entry_t *e, const uint8_t *mem) {
    FILE *src = NULL;
    uint64_t size = 0;
    if (!mem) {
        if (!e->saved[0] || !(src = platform_open_regular(e->saved, &size))) { e->saved[0] = '\0'; return 1; }
        if (size != e->size) { fclose(src); e->saved[0] = '\0'; return 1; }
    }
    char where[FILE_DIR_MAX]; file_dir_name(e, where, sizeof where);
    FILE *out = file_open_part(e);
    if (!out) {
        if (src) fclose(src);
        ui_print(c, "* can't write a file in %s", where);
        return -1;
    }
    int r = 1;
    if (mem) r = fwrite(mem, 1, (size_t)e->size, out) == (size_t)e->size ? 1 : -1;
    else { r = file_copy_checked(e, src, out, NULL); fclose(src); }
    if (fflush(out) != 0) r = -1;
    if (fclose(out) != 0) r = -1;
    if (r == 1 && file_save_as(e) == 0) return 0;
    platform_remove(e->part_path);
    e->part_path[0] = '\0';
    if (r == 0) { e->saved[0] = '\0'; return 1; }
    ui_print(c, "* couldn't save file %d in %s", e->num, where);
    return -1;
}

static void file_finish(chat_t *c, file_entry_t *e) {
    uint8_t got[SHA256_LEN];
    sha256_final(&e->hash, got);
    char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
    if (crypto_equal(got, e->sha, SHA256_LEN) != 0) {
        file_fail(e, "didn't match the offer, so it was thrown away");
        ui_print(c, "* file %d (%s) didn't match what was offered - it was thrown away", e->num, desc);
        return;
    }
    if (e->view) {
        if (c->file_view) c->file_view(c->ui, e->num, e->name, e->mem, (size_t)e->size);
        if (e->also_save && file_save_local(c, e, e->mem) == 0) ui_print(c, "* saved file %d to %s", e->num, e->saved);
        e->also_save = 0;
        // Kept, so :show and :download don't fetch it again.
        file_cache_keep(c, e);
        file_stop_download(e, DL_DONE);
        return;
    }
    char took[48]; file_format_duration(now_seconds() - e->since, took, sizeof took);
    int ok = e->out && fflush(e->out) == 0;
    if (e->out) { if (fclose(e->out) != 0) ok = 0; e->out = NULL; }
    if (!ok || file_save_as(e) != 0) {
        char where[FILE_DIR_MAX]; file_dir_name(e, where, sizeof where);
        char why[sizeof e->why]; snprintf(why, sizeof why, "couldn't be saved in %.40s", where);
        file_fail(e, why);
        ui_print(c, "* file %d (%s) downloaded, but couldn't be saved in %s", e->num, desc, where);
        return;
    }
    file_stop_download(e, DL_DONE);
    char sz[32]; file_format_size(e->size, sz, sizeof sz);
    ui_print(c, "* saved file %d to %s (%s, took %s)", e->num, e->saved, sz, took);
    if (e->also_show) {
        e->also_show = 0;
        if (file_check_saved(e, &e->mem) != 0) { ui_print(c, "* can't show file %d: it changed after it was saved", e->num); return; }
        if (c->file_view) c->file_view(c->ui, e->num, e->name, e->mem, (size_t)e->size);
        file_cache_keep(c, e);
    }
}

int chat_file_queued_after(const chat_t *c, const file_entry_t *e) {
    if (e->dl != DL_QUEUED) return 0;
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        const file_entry_t *o = &c->files[i];
        if (o->used && o->dl == DL_ACTIVE && memcmp(o->owner, e->owner, ID_LEN) == 0) return o->num;
    }
    return 0;
}

// Starts fetching e from p, to show or to save as e->view says. Returns 0, or -1 after saying why.
static int file_start(chat_t *c, file_entry_t *e, peer_t *p) {
    e->done = e->win_off = 0;
    e->win_n = e->req_end = 0;
    e->retries = 0;
    e->gone_since = 0.0;
    e->why[0] = '\0';
    e->win = malloc((size_t)FILE_WINDOW * FILE_CHUNK);
    if (e->view) e->mem = file_mem_alloc(e->size);
    if (!e->win || (e->view && !e->mem)) { file_fail(e, "out of memory"); ui_print(c, "* out of memory"); return -1; }
    if (!e->view && !(e->out = file_open_part(e))) {
        char where[FILE_DIR_MAX]; file_dir_name(e, where, sizeof where);
        char why[sizeof e->why]; snprintf(why, sizeof why, "couldn't write a file in %.36s", where);
        file_fail(e, why);
        ui_print(c, "* can't write a file in %s", where);
        return -1;
    }
    sha256_init(&e->hash);
    e->dl = DL_ACTIVE;
    e->since = now_seconds();
    if (e->size == 0) { file_finish(c, e); return 0; }
    file_request(c, e, p, e->since);
    // How long it takes depends on the sender. Fast transfers only speed up what you send.
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    char sz[32]; file_format_size(e->size, sz, sizeof sz);
    char eta[48]; file_format_duration(chat_file_eta(c, e, e->since), eta, sizeof eta);
    if (p->addr.kind == ADDR_NOSTR)
        ui_print(c, "* fetching file %d (%s) from %s through the relays: %s at chat's normal rate, up to half that if "
                    "%s has fast transfers on", e->num, sz, name, eta, name);
    else
        ui_print(c, "* fetching file %d (%s) from %s: %s at chat's normal rate, seconds if %s has fast transfers on",
                 e->num, sz, name, eta, name);
    return 0;
}

int chat_file_fetch(chat_t *c, int num, int view, int anyway, const char *dir) {
    file_entry_t *e = file_by_num(c, num);
    if (!e) { ui_print(c, "* there's no file %d - :files lists them", num); return -1; }
    if (e->mine && (!view || !e->image)) { ui_print(c, "* file %d is yours", num); return -1; }
    if (view && !e->image) { ui_print(c, "* file %d isn't offered as a picture - :download %d saves it instead", num, num); return -1; }
    char sz[32]; file_format_size(e->size, sz, sizeof sz);
    if (view && e->size > FILE_VIEW_MAX) {
        if (e->mine) ui_print(c, "* file %d is too big to show (%s)", num, sz);
        else ui_print(c, "* file %d is too big to show (%s) - :download %d saves it instead", num, sz, num);
        return -1;
    }
    if (e->mine) {
        const uint8_t *b = chat_file_bytes(c, num);
        if (!b) { ui_print(c, "* can't show file %d: %s", num, e->fp ? "it changed after you offered it" : "it isn't offered any more"); return -1; }
        if (c->file_view) c->file_view(c->ui, e->num, e->name, b, (size_t)e->size);
        return 0;
    }
    int coming = e->dl == DL_ACTIVE || e->dl == DL_QUEUED;
    if (view) {
        // Shown before, or saved: no need to fetch it again.
        uint8_t *m = NULL;
        if (!e->cache && !coming && file_check_saved(e, &m) == 0) { e->mem = m; file_cache_keep(c, e); }
        if (e->cache) {
            if (!coming) { e->dl = DL_DONE; e->why[0] = '\0'; }
            if (c->file_view) c->file_view(c->ui, e->num, e->name, e->cache, (size_t)e->size);
            return 0;
        }
        if (coming) {
            if (e->view) { ui_print(c, "* file %d is already on its way (:files shows how far)", num); return -1; }
            e->also_show = 1;
            ui_print(c, "* file %d is on its way to be saved, and is shown too once it's here", num);
            return 0;
        }
    } else {
        char want[FILE_DIR_MAX] = "";
        if (dir) copy_str(want, dir, sizeof want);
        size_t wl = strlen(want);
        while (wl > 1 && (want[wl - 1] == '/' || want[wl - 1] == '\\')) want[--wl] = '\0';
        if (coming) {
            if (!e->view) { ui_print(c, "* file %d is already on its way (:files shows how far)", num); return -1; }
            e->also_save = 1;
            copy_str(e->save_dir, want, sizeof e->save_dir);
            ui_print(c, "* file %d is on its way to be shown, and is saved too once it's here", num);
            return 0;
        }
        if (!want[0] && e->saved[0]) {
            if (file_check_saved(e, NULL) == 0) {
                ui_print(c, "* file %d is already saved at %s - :download %d FOLDER saves another copy", num, e->saved, num);
                return 0;
            }
            e->saved[0] = '\0';
        }
        copy_str(e->save_dir, want, sizeof e->save_dir);
        // Shown before, or saved somewhere else: copied from there instead of fetched again.
        if (e->cache || e->saved[0]) {
            int r = file_save_local(c, e, e->cache);
            if (r == 0) {
                e->dl = DL_DONE;
                e->why[0] = '\0';
                ui_print(c, "* saved file %d to %s, from the copy already here", num, e->saved);
                return 0;
            }
            if (r < 0) return -1;
        }
    }
    peer_t *p = file_owner(c, e);
    if (!p) { ui_print(c, "* whoever offered file %d isn't here now - try again once they're back", num); return -1; }
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    if (!peer_trusted(c, p)) {
        ui_print(c, "* compare verify codes with %s first (:verify %s): until then someone in the middle could be sending it", name, name);
        return -1;
    }
    uint64_t cap = chat_file_cap(c);
    char lim[32]; file_format_size(cap, lim, sizeof lim);
    if (e->size > cap && !anyway) {
        ui_print(c, "* file %d is %s, over your %s limit - :%s %d anyway fetches it regardless", num, sz, lim,
                 view ? "show" : "download", num);
        return -1;
    }
    e->view = view;
    e->also_show = e->also_save = 0;
    // One file at a time from each sender. The others wait their turn in files_tick.
    if (file_downloading_from(c, p)) {
        e->dl = DL_QUEUED;
        ui_print(c, "* file %d is queued: it starts once file %d from %s is done", num, chat_file_queued_after(c, e), name);
        return 0;
    }
    return file_start(c, e, p);
}

// :download [N] [anyway] [FOLDER]. Without N, the newest file offered that isn't saved or on its way.
cmd_result_t cmd_download(void *ctx, const char *arg) {
    chat_t *c = ctx;
    while (*arg == ' ') arg++;
    long num = 0;
    if (*arg >= '0' && *arg <= '9') {
        char *end;
        num = strtol(arg, &end, 10);
        if ((*end && *end != ' ') || num > FILE_NUM_MAX) num = -1;
        arg = end;
    }
    while (*arg == ' ') arg++;
    static const char ANYWAY[] = "anyway";
    size_t al = sizeof ANYWAY - 1;
    int anyway = strncmp(arg, ANYWAY, al) == 0 && (arg[al] == '\0' || arg[al] == ' ');
    if (anyway) arg += al;
    char dir[FILE_DIR_MAX];
    typed_path(arg, dir, sizeof dir);
    if (num < 0) {
        ui_print(c, "* usage: :download [N] [anyway] [FOLDER] - N from :files (the newest if left out), FOLDER instead of Downloads");
        return CMD_OK;
    }
    if (num == 0) {
        const file_entry_t *pick = NULL;
        for (int i = 0; i < FILE_OFFERS_MAX; i++) {
            const file_entry_t *e = &c->files[i];
            if (!e->used || e->mine || e->saved[0] || e->dl == DL_ACTIVE || e->dl == DL_QUEUED) continue;
            if (!pick || e->num > pick->num) pick = e;
        }
        if (!pick) { ui_print(c, "* no file to download - :files lists what's been offered"); return CMD_OK; }
        num = pick->num;
    }
    chat_file_fetch(c, (int)num, 0, anyway, dir);
    return CMD_OK;
}

cmd_result_t cmd_cancel(void *ctx, const char *arg) {
    chat_t *c = ctx;
    file_entry_t *e = file_by_num(c, atoi(arg));
    if (!e) { ui_print(c, "* usage: :cancel N - stops fetching file N, or stops offering one of yours"); return CMD_OK; }
    if (e->mine) {
        if (e->fp) { fclose(e->fp); e->fp = NULL; }
        file_mem_free(&e->clean, e->size);
        for (int i = 0; i < c->peer_hi; i++)
            if (c->peers[i].used && c->peers[i].serving && memcmp(c->peers[i].serve_fid, e->fid, FILE_ID_LEN) == 0) c->peers[i].serving = 0;
        ui_print(c, "* file %d is no longer offered", e->num);
    } else if (e->dl == DL_ACTIVE) {
        file_stop_download(e, DL_NONE);
        ui_print(c, "* stopped fetching file %d", e->num);
    } else if (e->dl == DL_QUEUED) {
        e->dl = DL_NONE;
        ui_print(c, "* file %d is no longer queued", e->num);
    } else {
        ui_print(c, "* file %d isn't being fetched", e->num);
    }
    return CMD_OK;
}

cmd_result_t cmd_files(void *ctx, const char *arg) {
    chat_t *c = ctx;
    (void)arg;
    int any = 0;
    for (int n = 1; n <= c->file_seq; n++) {
        file_entry_t *e = file_by_num(c, n);
        if (!e) continue;
        any = 1;
        char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
        char who[CHAT_NAME_LEN] = "you";
        peer_t *p = e->mine ? NULL : find_peer_by_id(c, e->owner);
        if (!e->mine) { if (p) chat_peer_name(c, p, who); else copy_str(who, "someone who left", sizeof who); }
        char state[1024] = "";
        if (e->mine) {
            char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
            int pm, fetching = chat_file_sending(c, e, now_seconds(), name, &pm);
            chat_file_sent_to(e, to, sizeof to);
            if (fetching) snprintf(state, sizeof state, "sending to %s%s, %d%%", name, fetching > 1 ? " and others" : "", pm / 10);
            else if (to[0]) snprintf(state, sizeof state, "sent to %s%s", to, e->fp ? "" : ", no longer offered");
            else copy_str(state, e->fp ? "offered" : "no longer offered", sizeof state);
        }
        else if (e->dl == DL_ACTIVE) {
            uint64_t got = chat_file_got(e);
            double s = chat_file_eta(c, e, now_seconds());
            char gs[32], eta[48];
            file_format_size(got, gs, sizeof gs);
            if (s >= 0.0) { file_format_duration(s, eta, sizeof eta); strcat(eta, " left"); }
            else copy_str(eta, s < -1.0 ? "waiting until verify codes are compared" : "waiting for its sender", sizeof eta);
            snprintf(state, sizeof state, "fetching, %d%% (%s), %s%s", e->size ? (int)(got * 100 / e->size) : 100, gs, eta,
                     e->also_save ? ", saved too once it's here" : e->also_show ? ", shown too once it's here" : "");
        }
        else if (e->dl == DL_QUEUED) {
            int after = chat_file_queued_after(c, e);
            if (after) snprintf(state, sizeof state, "queued, starts after file %d", after);
            else copy_str(state, "queued, waiting for its sender", sizeof state);
        }
        else if (e->saved[0]) snprintf(state, sizeof state, "saved to %s", e->saved);
        else if (e->cache) snprintf(state, sizeof state, "shown - :download %d saves it without fetching it again", e->num);
        else if (e->dl == DL_DONE) copy_str(state, "shown", sizeof state);
        else if (e->dl == DL_FAILED)
            snprintf(state, sizeof state, "failed%s%s%s - :%s %d tries again", e->why[0] ? " (" : "", e->why,
                     e->why[0] ? ")" : "", e->view ? "show" : "download", e->num);
        else copy_str(state, e->image ? ":show or :download" : ":download", sizeof state);
        ui_print(c, "* file %d from %s: %s - %s", e->num, who, desc, state);
    }
    if (!any) ui_print(c, "* no files yet - :send PATH offers one");
    return CMD_OK;
}

_Static_assert(FILE_WINDOW <= 64, "win_got has a bit for each chunk of the window");

// The next chunk p asked for, as a record after the *pos bytes of text already there (instead of a
// nop if there are none), if it fits in cap. Returns 1 if it was added.
int file_next_chunk(chat_t *c, peer_t *p, char *text, size_t *pos, size_t cap) {
    file_entry_t *e = file_by_fid(c, c->my_id, p->serve_fid);
    if (!e || !e->fp || p->serve_next >= p->serve_end) { p->serving = 0; return 0; }
    size_t want = p->serve_end - p->serve_next < FILE_CHUNK ? (size_t)(p->serve_end - p->serve_next) : FILE_CHUNK;
    char fidhex[FILE_ID_LEN * 2 + 1]; hex_encode(e->fid, FILE_ID_LEN, fidhex);
    char head[64];
    int hl = snprintf(head, sizeof head, "%sfd\t%s\t%llu\t", *pos ? "\n" : "", fidhex, (unsigned long long)p->serve_next);
    if (hl < 0 || *pos + (size_t)hl + BASE64_LEN(want) > cap) return 0;
    uint8_t buf[FILE_CHUNK];
    if (e->clean) memcpy(buf, e->clean + p->serve_next, want);
    else if (fseek(e->fp, (long)p->serve_next, SEEK_SET) != 0 || fread(buf, 1, want, e->fp) != want) { p->serving = 0; return 0; }
    memcpy(text + *pos, head, (size_t)hl);
    *pos += (size_t)hl;
    *pos += base64_encode(buf, want, text + *pos);
    crypto_wipe(buf, sizeof buf);
    p->serve_next += want;
    if (p->serve_next >= p->serve_end) p->serving = 0;
    if (p->serve_next >= e->size) file_sent(c, e, p);
    return 1;
}

// Digits a number may have: any 19 fit in a uint64_t.
#define U64_DIGITS 19
static int parse_u64(const char *s, uint64_t *out) {
    if (!*s || strlen(s) > U64_DIGITS) return -1;
    uint64_t v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (uint64_t)(*s - '0');
    }
    *out = v;
    return 0;
}

// A file record from p: an offer, a request for chunks of one of ours, a chunk, or "not offered".
void file_on_record(chat_t *c, peer_t *p, char **f, int n, double now) {
    uint8_t fid[FILE_ID_LEN];
    if (n == 7 && strcmp(f[0], "fo") == 0) {
        uint8_t mid_raw[MID_LEN], sha[SHA256_LEN];
        uint64_t size;
        if (hex_decode(f[1], MID_HEX, mid_raw) != 0 || strlen(f[2]) != FILE_ID_LEN * 2 || hex_decode(f[2], FILE_ID_LEN * 2, fid) != 0
            || parse_u64(f[3], &size) != 0 || strlen(f[4]) != SHA256_LEN * 2 || hex_decode(f[4], SHA256_LEN * 2, sha) != 0) return;
        char ack[16]; snprintf(ack, sizeof ack, "a\t%s", f[1]);
        send_peer(c, p, ack);
        if (chat_ignored(c, p->id)) return;
        if (size > FILE_HARD_MAX || (strcmp(f[5], "image") != 0 && strcmp(f[5], "file") != 0)) return;
        if (file_by_fid(c, p->id, fid)) return;   // a retry of one we have
        file_entry_t *e = file_new(c, p->id);
        if (!e) return;
        memcpy(e->owner, p->id, ID_LEN);
        memcpy(e->fid, fid, FILE_ID_LEN);
        e->size = size;
        memcpy(e->sha, sha, SHA256_LEN);
        e->image = strcmp(f[5], "image") == 0;
        file_clean_name(f[6], e->name);
        current_hhmm(e->at);
        char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
        uint64_t cap = chat_file_cap(c);
        char lim[32]; file_format_size(cap, lim, sizeof lim);
        char text[FILE_NAME_MAX + 200], shown[CHAT_NAME_LEN + 32];
        int over = size > cap;
        if (e->image)
            snprintf(text, sizeof text, "offers %s - :show %d%s to see it, :download %d%s to save it%s", desc, e->num,
                     over ? " anyway" : "", e->num, over ? " anyway" : "", over ? " (over your limit)" : "");
        else
            snprintf(text, sizeof text, "offers %s - :download %d%s to save it%s", desc, e->num, over ? " anyway" : "",
                     over ? " (over your limit)" : "");
        char via[CHAT_NAME_LEN]; chat_peer_name(c, p, via);
        snprintf(shown, sizeof shown, "%s%s", via, code_mark(c, p));
        ui_chat_file(c, p->color, 0, shown, text, e->num);
        if (c->notify && c->notify_mode == NOTIFY_ALL)
            c->notify(c->ui, c->notify_preview >= PREVIEW_NICK ? shown : NULL,
                      c->notify_preview == PREVIEW_MESSAGE ? "offered a file" : NULL, 0);
    } else if (n == 4 && strcmp(f[0], "fg") == 0) {
        uint64_t off, count;
        if (strlen(f[1]) != FILE_ID_LEN * 2 || hex_decode(f[1], FILE_ID_LEN * 2, fid) != 0 || parse_u64(f[2], &off) != 0
            || parse_u64(f[3], &count) != 0) return;
        file_entry_t *e = file_by_fid(c, c->my_id, fid);
        // Only our files, still offered, to someone who would have been offered them. A file of ours that
        // isn't offered any more gets "fx". One that never was gets nothing, so made up ids can't fill the
        // queue every peer shares.
        if (!e) return;
        if (!e->fp || !peer_trusted(c, p)) {
            char rec[40]; snprintf(rec, sizeof rec, "fx\t%s", f[1]);
            send_peer(c, p, rec);
            return;
        }
        if (count < 1 || count > FILE_WINDOW || off % FILE_CHUNK != 0 || off >= e->size) return;
        p->serving = 1;
        memcpy(p->serve_fid, fid, FILE_ID_LEN);
        p->serve_next = off;
        p->serve_end = off + count * FILE_CHUNK < e->size ? off + count * FILE_CHUNK : e->size;
        p->serve_at = now;
    } else if (n == 4 && strcmp(f[0], "fd") == 0) {
        uint64_t off;
        if (strlen(f[1]) != FILE_ID_LEN * 2 || hex_decode(f[1], FILE_ID_LEN * 2, fid) != 0 || parse_u64(f[2], &off) != 0) return;
        file_entry_t *e = file_by_fid(c, p->id, fid);
        if (!e || e->dl != DL_ACTIVE || off < e->win_off || off % FILE_CHUNK != 0) return;
        uint64_t idx = (off - e->win_off) / FILE_CHUNK;
        if (idx >= (uint64_t)e->win_n || (e->win_got >> idx & 1)) return;
        size_t want = e->size - off < FILE_CHUNK ? (size_t)(e->size - off) : FILE_CHUNK;
        uint8_t buf[FILE_CHUNK + 3];
        if (strlen(f[3]) != BASE64_LEN(want) || base64_decode_strict(f[3], strlen(f[3]), buf, sizeof buf) != (long)want) return;
        memcpy(e->win + idx * FILE_CHUNK, buf, want);
        e->win_got |= 1ull << idx;
        e->retries = 0;
        double iv = c->fast_files && p->addr.kind != ADDR_NOSTR ? FILE_FAST_INTERVAL : cover_interval(c, p);
        e->retry_at = file_retry_at(now, iv);
        uint64_t full = e->win_n == (int)(8 * sizeof e->win_got) ? ~0ull : (1ull << e->win_n) - 1;
        if (e->win_got != full) {
            // The last of the requested run has arrived and the window still has a gap. Whatever is in it was
            // lost (or never requested), so it's requested now instead of when the retry is due. Through the
            // relays that saves half a minute.
            if ((int)idx + 1 == e->req_end) file_request(c, e, p, now);
            return;
        }
        // The window is complete: write it in order to the file (or memory), and add it to the hash.
        size_t bytes = e->size - e->win_off < (uint64_t)e->win_n * FILE_CHUNK ? (size_t)(e->size - e->win_off)
                                                                              : (size_t)e->win_n * FILE_CHUNK;
        if (e->view) memcpy(e->mem + e->done, e->win, bytes);
        else if (fwrite(e->win, 1, bytes, e->out) != bytes) {
            char desc[FILE_NAME_MAX + 48]; file_desc(e, desc, sizeof desc);
            file_fail(e, "couldn't be written - is the disk full?");
            ui_print(c, "* couldn't write file %d (%s) - is the disk full?", e->num, desc);
            return;
        }
        sha256_update(&e->hash, e->win, bytes);
        e->done += bytes;
        e->win_off += bytes;
        e->win_n = 0;
        if (e->done >= e->size) file_finish(c, e);
        else file_request(c, e, p, now);
    } else if (n == 2 && strcmp(f[0], "fx") == 0) {
        if (strlen(f[1]) != FILE_ID_LEN * 2 || hex_decode(f[1], FILE_ID_LEN * 2, fid) != 0) return;
        file_entry_t *e = file_by_fid(c, p->id, fid);
        if (!e || e->dl != DL_ACTIVE) return;
        file_fail(e, "isn't offered any more");
        char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
        ui_print(c, "* %s no longer offers file %d", name, e->num);
    }
}

#define REHANDSHAKE_RECHECK 1.0

void files_tick(chat_t *c, double now) {
    // Queued files start once nothing else is coming from their sender, the oldest first.
    for (;;) {
        file_entry_t *next = NULL;
        for (int i = 0; i < FILE_OFFERS_MAX; i++) {
            file_entry_t *e = &c->files[i];
            if (!e->used || e->dl != DL_QUEUED) continue;
            peer_t *p = file_owner(c, e);
            if (!p || !peer_trusted(c, p) || file_downloading_from(c, p)) continue;
            if (!next || e->num < next->num) next = e;
        }
        if (!next) break;
        file_start(c, next, file_owner(c, next));
    }
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        file_entry_t *e = &c->files[i];
        if (!e->used || e->dl != DL_ACTIVE) continue;
        peer_t *p = file_owner(c, e);
        // Its sender may only have stalled for a moment (a Tor circuit, a relay). The fetch waits for
        // them, and if they come back with a new verify code, for that to be compared again.
        if (!p || !peer_trusted(c, p)) {
            if (p || e->gone_since == 0.0) e->gone_since = now;
            if (p || now - e->gone_since < FILE_OWNER_GRACE) continue;
            file_fail(e, "its sender left before it finished");
            ui_print(c, "* whoever offered file %d left before it finished - fetch it again once they're back", e->num);
            continue;
        }
        // Back after a short time away. What it was sending was lost with its old session, so it's
        // requested again from where it stopped.
        if (e->gone_since > 0.0) {
            e->gone_since = 0.0;
            e->retries = 0;
            file_request(c, e, p, now);
            continue;
        }
        if (now < e->retry_at) continue;
        // During a re-handshake with its sender, our request may use keys it can't read yet, so the retry
        // waits for it to finish instead of being used up. If it never finishes the peer times out.
        if (rehandshaking_with(c, p)) { e->retry_at = now + REHANDSHAKE_RECHECK; continue; }
        if (++e->retries > FILE_RETRIES) {
            char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
            file_fail(e, "stopped coming");
            ui_print(c, "* file %d stopped downloading from %s - try again later", e->num, name);
            continue;
        }
        file_request(c, e, p, now);
    }
}

void chat_set_file_options(chat_t *c, uint64_t cap, int fast) {
    c->file_cap = cap ? cap : FILE_CAP_DEFAULT;
    c->fast_files = fast != 0;
}

uint64_t chat_file_cap(const chat_t *c) { return c->file_cap ? c->file_cap : FILE_CAP_DEFAULT; }
