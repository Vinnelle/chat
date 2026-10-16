// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Pictures shown under the line that offered them, decoded in a child process.
#include "app/app.h"

pic_t *pic_find(session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used && s->pics[i].num == num) return &s->pics[i];
    return NULL;
}

void pic_free(pic_t *p) {
    thumb_free(&p->th);
    memset(p, 0, sizeof *p);
}

void pics_free(session_slot_t *s) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used) pic_free(&s->pics[i]);
}

const tui_image_t *pic_for(const void *ctx, int file) {
    const session_slot_t *s = ctx;
    for (int i = 0; i < MAX_PICS; i++)
        if (s->pics[i].used && s->pics[i].num == file && s->pics[i].shown && s->pics[i].th.rgb) return &s->pics[i].ti;
    return NULL;
}

const char *pic_why(const session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++)
        if (s->pics[i].used && s->pics[i].num == num && !s->pics[i].th.rgb && s->pics[i].why[0]) return s->pics[i].why;
    return NULL;
}

// The progress of a fetch, as its row in the chat and the picture page say it.
int fetch_progress(const chat_t *e, const file_entry_t *f, char *text, size_t cap) {
    if (f->dl == DL_QUEUED) {
        int after = chat_file_queued_after(e, f);
        if (after) snprintf(text, cap, "queued" DOT_SEP "starts after file %d", after);
        else snprintf(text, cap, "queued" DOT_SEP "waiting for its sender");
        return 0;
    }
    uint64_t got = chat_file_got(f);
    int permille = f->size ? (int)(got * 1000 / f->size) : 1000;
    char gs[32], all[32], eta[64];
    file_format_size(got, gs, sizeof gs);
    file_format_size(f->size, all, sizeof all);
    double left = chat_file_eta(e, f, now_seconds());
    if (left >= 0.0) { file_format_duration(left, eta, sizeof eta); strcat(eta, " left"); }
    else copy_str(eta, left < ETA_AWAY ? "waiting until verify codes are compared" : "waiting for its sender", sizeof eta);
    snprintf(text, cap, "%d%%" DOT_SEP "%s of %s" DOT_SEP "%s", permille / 10, gs, all, eta);
    return permille;
}

// The row under the line that offered a file: how a fetch is going (through the relays it can take
// a long time), where it was saved or why it failed, and for one of ours, who's fetching it or has.
const tui_progress_t *progress_for(const void *ctx, int file) {
    static tui_progress_t pg;
    const session_slot_t *s = ctx;
    const file_entry_t *f = chat_file(s->engine, file);
    if (!f) return NULL;
    memset(&pg, 0, sizeof pg);
    if (f->mine) {
        char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
        int pm, n = chat_file_sending(s->engine, f, now_seconds(), name, &pm);
        chat_file_sent_to(f, to, sizeof to);
        if (n) {
            pg.permille = pm;
            snprintf(pg.text, sizeof pg.text, "%d%%" DOT_SEP "sending to %s%s", pm / 10, name, n > 1 ? " and others" : "");
        } else if (to[0]) {
            pg.kind = TUI_PROGRESS_DONE;
            snprintf(pg.text, sizeof pg.text, "sent to %s%s", to, f->fp ? "" : DOT_SEP "no longer offered");
        } else if (!f->fp) {
            pg.kind = TUI_PROGRESS_NOTE;
            copy_str(pg.text, "no longer offered", sizeof pg.text);
        } else {
            return NULL;
        }
        return &pg;
    }
    if (f->dl == DL_ACTIVE || f->dl == DL_QUEUED) {
        pg.permille = fetch_progress(s->engine, f, pg.text, sizeof pg.text);
        return &pg;
    }
    if (f->dl == DL_FAILED) {
        pg.kind = TUI_PROGRESS_FAILED;
        snprintf(pg.text, sizeof pg.text, "%s" DOT_SEP ":%s %d tries again", f->why[0] ? f->why : "it didn't finish",
                 f->view ? "show" : "download", f->num);
        return &pg;
    }
    if (f->saved[0]) {
        char where[sizeof f->saved];
        tilde_path(f->saved, where, sizeof where);
        pg.kind = TUI_PROGRESS_DONE;
        snprintf(pg.text, sizeof pg.text, "saved to %.150s", where);
        return &pg;
    }
    const char *why = pic_why(s, file);
    if (why) {
        pg.kind = TUI_PROGRESS_FAILED;
        snprintf(pg.text, sizeof pg.text, "can't show it: %s" DOT_SEP ":download %d saves it", why, f->num);
        return &pg;
    }
    return NULL;
}

static pic_t *pic_slot(session_slot_t *s, int num) {
    pic_t *p = pic_find(s, num);
    if (!p) for (int i = 0; i < MAX_PICS && !p; i++) if (!s->pics[i].used) p = &s->pics[i];
    if (!p) {
        p = &s->pics[0];
        for (int i = 1; i < MAX_PICS; i++) if (s->pics[i].num < p->num) p = &s->pics[i];
    }
    pic_free(p);
    p->used = 1;
    p->num = num;
    return p;
}

// Pictures come from peers, and chat's own readers decode them, so a bug there is the easiest way in.
// On Linux each is decoded in a child process that can only write the thumbnail back (see
// platform_isolated), which is checked before it's used.
#define PICTURE_DECODE_MS 10000

typedef struct {
    const uint8_t *data;
    size_t len;
    int max_w, max_h;
    uint8_t bg[3];
} thumb_job_t;

typedef struct {
    int32_t rc, w, h, src_w, src_h;
    char why[160];
} thumb_head_t;

static void thumb_child(void *arg, int fd) {
    const thumb_job_t *j = arg;
    thumb_head_t h;
    image_thumb_t th;
    memset(&h, 0, sizeof h);
    h.rc = image_thumbnail(j->data, j->len, j->max_w, j->max_h, j->bg, &th, h.why, sizeof h.why);
    if (h.rc == 0) { h.w = th.w; h.h = th.h; h.src_w = th.src_w; h.src_h = th.src_h; }
    if (platform_isolated_put(fd, &h, sizeof h) == 0 && h.rc == 0)
        platform_isolated_put(fd, th.rgb, (size_t)th.w * (size_t)th.h * 3);
}

int thumb_decode(const uint8_t *data, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
                 char *why, size_t why_cap) {
    thumb_job_t j = { data, len, max_w, max_h, { bg[0], bg[1], bg[2] } };
    size_t cap = sizeof(thumb_head_t) + (size_t)max_w * (size_t)max_h * 3;
    uint8_t *buf = max_w > 0 && max_h > 0 ? malloc(cap) : NULL;
    if (!buf) return image_thumbnail(data, len, max_w, max_h, bg, out, why, why_cap);
    long n = platform_isolated(thumb_child, &j, buf, cap, PICTURE_DECODE_MS);
    if (n == -1) {
        free(buf);
        return image_thumbnail(data, len, max_w, max_h, bg, out, why, why_cap);
    }
    thumb_head_t h;
    int rc = -1;
    if (n < (long)sizeof h) {
        copy_str(why, n == -2 ? "chat's picture reader stopped on it: it took too long, or tried something it isn't "
                                "allowed to, so it may be damaged, or made to break the reader"
                              : "chat's picture reader stopped on it", why_cap);
    } else {
        memcpy(&h, buf, sizeof h);
        h.why[sizeof h.why - 1] = '\0';
        size_t px = h.rc == 0 && h.w > 0 && h.h > 0 && h.w <= max_w && h.h <= max_h ? (size_t)h.w * (size_t)h.h * 3 : 0;
        if (h.rc != 0) {
            // From the child, so no more trusted than the picture: no control characters reach the screen.
            if (!why_cap || !clean_text(h.why, why, why_cap - 1)) copy_str(why, "chat's picture reader couldn't read it", why_cap);
        } else if (!px || (size_t)n != sizeof h + px || h.src_w <= 0 || h.src_h <= 0 || h.src_w > IMAGE_MAX_SIDE
                   || h.src_h > IMAGE_MAX_SIDE || !(out->rgb = malloc(px))) {
            copy_str(why, "chat's picture reader gave back something that isn't a picture", why_cap);
        } else {
            memcpy(out->rgb, buf + sizeof h, px);
            out->w = h.w;
            out->h = h.h;
            out->src_w = h.src_w;
            out->src_h = h.src_h;
            rc = 0;
        }
    }
    free(buf);
    return rc;
}

// A picture fetched to show has arrived. It's decoded into a thumbnail here, then the bytes are discarded.
void session_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
    session_slot_t *s = ui;
    (void)name;
    static const uint8_t bg[3] = { 0, 0, 0 };
    image_thumb_t th;
    char why[160];
    if (thumb_decode(data, len, TUI_IMAGE_MAX_W, TUI_IMAGE_MAX_H, bg, &th, why, sizeof why) != 0) {
        const file_entry_t *f = chat_file(s->engine, num);
        copy_str(pic_slot(s, num)->why, why, sizeof s->pics[0].why);
        if (f && f->mine) console_note(s, "* can't show file %d: %s", num, why);
        else console_note(s, "* can't show file %d: %s - :download %d saves it", num, why, num);
        return;
    }
    pic_t *p = pic_slot(s, num);
    p->shown = 1;
    p->th = th;
    p->ti = (tui_image_t){ th.w, th.h, th.rgb };
    console_note(s, "* file %d shown (%dx%d) - :hide %d hides it", num, th.src_w, th.src_h, num);
    g_app.dirty = 1;
}
