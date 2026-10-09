// SPDX-License-Identifier: GPL-3.0-only AND BSD-2-Clause-Patent
// Copyright (C) 2026 finlay@tuta.com
//
// The word list is Bytewords (BCR-2020-012, © 2020 Blockchain Commons), under this license:
//
// Copyright © 2019 Blockchain Commons, LLC
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of
//    conditions and the following disclaimer in the documentation and/or other materials provided
//    with the distribution.
//
// Subject to the terms and conditions of this license, each copyright holder and contributor hereby
// grants to those receiving rights under this license a perpetual, worldwide, non-exclusive,
// no-charge, royalty-free, irrevocable (except for failure to satisfy the conditions of this license)
// patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer this
// software, where such license applies only to those patent claims, already acquired or hereafter
// acquired, licensable by such copyright holder or contributor that are necessarily infringed by:
//
// (a) their Contribution(s) (the licensed copyrights of copyright holders and non-copyrightable
//     additions of contributors, in source or binary form) alone; or
// (b) combination of their Contribution(s) with the work of authorship to which such Contribution(s)
//     was added by such copyright holder or contributor, if, at the time the Contribution is added,
//     such addition causes such combination to be necessarily infringed. The patent license shall
//     not apply to any other combinations which include the Contribution.
//
// Except as expressly stated above, no rights or licenses from any copyright holder or contributor is
// granted under this license, whether expressly, by implication, estoppel or otherwise.
//
// DISCLAIMER
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#include "common/bytewords.h"
#include "common/util.h"
#include <string.h>

#define WORD_LEN 4
#define GROUP 4

// Four letters each, so a word only ever needs its place in this string.
static const char WORDS[] =
    "ableacidalsoapexaquaarchatomaunt" "awayaxisbackbaldbarnbeltbetabias"
    "bluebodybragbrewbulbbuzzcalmcash" "catschefcityclawcodecolacookcost"
    "cruxcurlcuspcyandarkdatadaysdeli" "dicedietdoordowndrawdropdrumdull"
    "dutyeacheasyechoedgeepicevenexam" "exiteyesfactfairfernfigsfilmfish"
    "fizzflapflewfluxfoxyfreefrogfuel" "fundgalagamegeargemsgiftgirlglow"
    "goodgraygrimgurugushgyrohalfhang" "hardhawkheathelphighhillholyhope"
    "hornhutsicedideaidleinchinkyinto" "irisironitemjadejazzjoinjoltjowl"
    "judojugsjumpjunkjurykeepkenokept" "keyskickkilnkingkitekiwiknoblamb"
    "lavalazyleaflegsliarlimplionlist" "logoloudloveluaulucklungmainmany"
    "mathmazememomenumeowmildmintmiss" "monknailnavyneednewsnextnoonnote"
    "numbobeyoboeomitonyxopenovalowls" "paidpartpeckplaypluspoempoolpose"
    "puffpumapurrquadquizracerampreal" "redorichroadrockroofrubyruinruns"
    "rustsafesagascarsetssilkskewslot" "soapsolosongstubsurfswantacotask"
    "taxitenttiedtimetinytoiltombtoys" "triptunatwinuglyundouniturgeuser"
    "vastveryvetovialvibeviewvisavoid" "vowswallwandwarmwaspwavewaxywebs"
    "whatwhenwhizwolfworkyankyawnyell" "yogayurtzapszerozestzinczonezoom";
_Static_assert(sizeof WORDS == 256 * WORD_LEN + 1, "a word of four letters for each byte");

void bytewords(const uint8_t *in, size_t len, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        const char *sep = i == 0 ? "" : i % GROUP == 0 ? DOT_SEP : " ";
        size_t n = strlen(sep);
        memcpy(out + o, sep, n);
        memcpy(out + o + n, WORDS + in[i] * WORD_LEN, WORD_LEN);
        o += n + WORD_LEN;
    }
    out[o] = '\0';
}
