// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_CLEAN_H
#define CHAT_CLEAN_H

#include <stddef.h>
#include <stdint.h>

// What image_clean took out of a picture, or did to it.
#define CLEAN_LOCATION 1u     // Exif's GPS: where it was taken
#define CLEAN_CAMERA   2u     // the rest of the Exif: make, model, settings, serial numbers, when
#define CLEAN_XMP      4u     // XMP: editing history, and sometimes the place
#define CLEAN_IPTC     8u     // IPTC and Photoshop's: captions, names, places
#define CLEAN_COMMENT  16u    // comments, and PNG's text
#define CLEAN_EXTRA    32u    // more pictures or a video in it or after it: thumbnails, MPF, motion photos
#define CLEAN_TIME     64u    // PNG's tIME: when it was last changed
#define CLEAN_OTHER    128u   // other segments, chunks or extensions
#define CLEAN_NOISE    256u   // noise added (a baseline JPEG)
#define CLEAN_SEED_LEN 16

// A PNG, JPEG or GIF without what could tell where, when or with what it was made, in *out
// (malloc'd, *out_len bytes). Only what drawing it needs is kept: in a JPEG its tables and scans,
// a JFIF header, an ICC colour profile and Adobe's colour marker, and an Orientation other than 1,
// alone, so a portrait photo still shows upright. With noise, a baseline JPEG also has some of its
// coefficients moved one step within their size class, chosen from seed: the same symbols, so the
// same tables encode them, and nothing a viewer can see, but no two copies are the same bytes or
// pixels. Returns what it took out or did (CLEAN_, 0 for nothing, with out set all the same), or
// -1 if it isn't a picture chat can clean, or is damaged.
int image_clean(const uint8_t *in, size_t len, int noise, const uint8_t seed[CLEAN_SEED_LEN], uint8_t **out,
                size_t *out_len);

// For a file chat can't clean that usually says where and when it was made (photos and videos in
// other formats, PDFs, office documents), what it is ("HEIC picture"), from its first bytes (16 are
// enough) and its name. NULL for anything else.
#define CLEAN_HEAD 16
const char *clean_cannot(const uint8_t *head, size_t len, const char *name);

// Whether a file name is the kind cameras, phones and screenshot tools give, which says when it was
// taken (IMG_20261012_143022, Screenshot 2026-10-12 at 14.30.22) or ties pictures together (DSC_0412).
int clean_name_tells(const char *name);

#endif
