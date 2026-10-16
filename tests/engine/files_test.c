// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Files: offering, fetching, showing and saving them, and their names.
#include "harness.h"

static struct { int calls, num; size_t len; uint8_t data[65536]; } g_viewed;

static void on_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
    (void)ui; (void)name;
    g_viewed.calls++;
    g_viewed.num = num;
    g_viewed.len = len;
    memcpy(g_viewed.data, data, len < sizeof g_viewed.data ? len : sizeof g_viewed.data);
}

static int offer_named(chat_t *c, const char *name) {
    for (int n = c->file_seq; n >= 1; n--) {
        const file_entry_t *e = chat_file(c, n);
        if (e && !e->mine && strcmp(e->name, name) == 0) return n;
    }
    return 0;
}

static int mine_named(chat_t *c, const char *name) {
    for (int n = c->file_seq; n >= 1; n--) {
        const file_entry_t *e = chat_file(c, n);
        if (e && e->mine && strcmp(e->name, name) == 0) return n;
    }
    return 0;
}

static int same_file(const char *path, const uint8_t *data, size_t len) {
    static uint8_t buf[300000];
    long n = platform_read_file(path, buf, sizeof buf);
    return n == (long)len && memcmp(buf, data, len) == 0;
}

// How file n's fetch stands, or -1 if there's no file n: an offer that never came fails a check
// rather than the whole test.
static int dl_state(chat_t *c, int n) {
    const file_entry_t *e = n > 0 ? chat_file(c, n) : NULL;
    return e ? (int)e->dl : -1;
}

static int dl_over(chat_t *c, int n) {
    const file_entry_t *e = chat_file(c, n);
    return !e || e->dl == DL_DONE || e->dl == DL_FAILED;
}

// Changes a byte of the file at path.
static void f_flip(const char *path) {
    FILE *f = fopen(path, "r+b");
    if (!f) return;
    int ch = fgetc(f);
    fseek(f, 0, SEEK_SET);
    fputc(ch ^ 1, f);
    fclose(f);
}

static void count_part(void *ctx, const char *name, int is_dir) {
    (void)is_dir;
    if (strncmp(name, ".chat-", 6) == 0) (*(int *)ctx)++;
}

static int part_files_left(const char *dir) {
    int n = 0;
    platform_list_dir(dir, count_part, &n);
    return n > 0;
}

void test_files(double *t) {
    // Downloads of the test's own.
    static char home[256];
    CHECK(test_temp_dir("files", home, sizeof home) == 0, "no temporary folder");
    test_set_env(TEST_HOME_VAR, home);
    char dl[600], path[600], cmd[700], want[700];
    snprintf(dl, sizeof dl, "%s/Downloads", home);
    A.file_view = B.file_view = on_view;
    static uint8_t data[200000];
    gen_random(data, sizeof data);

    // A file offered, and nothing moves until bob asks.
    snprintf(path, sizeof path, "%s/notes.txt", home);
    write_file(path, data, 5000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "notes.txt") > 0);
    int n = offer_named(&B, "notes.txt");
    CHECK(n > 0 && log_count(&log_b, "offers notes.txt (5 KB) - :download") == 1, "bob didn't see the offer");
    CHECK(n > 0 && chat_file(&B, n)->size == 5000 && chat_file(&B, n)->dl == DL_NONE, "the offer came wrong, or started by itself");
    CHECK(chat_file_fetch(&B, n, 1, 0, NULL) != 0, "a file not offered as a picture was fetched to show");

    // Saved, whole, under its name. Asked for again, it's already there and isn't fetched. Into
    // another folder, it's copied from there. Once the saved one changes, it's fetched again, under
    // the next name. No partial file is left at any point.
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch notes.txt");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/notes.txt", dl);
    CHECK(dl_state(&B, n) == DL_DONE && same_file(want, data, 5000), "notes.txt didn't arrive whole");
    int sent = mine_named(&A, "notes.txt");
    char to[CHAT_NAME_LEN * 2 + 16] = "";
    if (sent) chat_file_sent_to(chat_file(&A, sent), to, sizeof to);
    CHECK(sent && strcmp(to, "bob") == 0, "alice doesn't know notes.txt went to bob");
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0 && dl_state(&B, n) == DL_DONE, "notes.txt was fetched again while saved");
    char other[400];
    snprintf(other, sizeof other, "%s/other", home);
    platform_private_dir(other);
    CHECK(chat_file_fetch(&B, n, 0, 0, other) == 0 && dl_state(&B, n) == DL_DONE, "notes.txt wasn't copied to another folder");
    snprintf(path, sizeof path, "%s/notes.txt", other);
    CHECK(same_file(path, data, 5000) && strcmp(chat_file(&B, n)->saved, path) == 0, "the copy in another folder is wrong");
    f_flip(path);
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0 && dl_state(&B, n) == DL_ACTIVE, "a changed copy wasn't fetched again");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/notes (2).txt", dl);
    CHECK(same_file(want, data, 5000), "the second copy wasn't saved beside the first");
    CHECK(!part_files_left(dl) && !part_files_left(other), "a partial file was left behind");
    platform_remove(want);

    // Past bob's limit only with "anyway".
    chat_set_file_options(&B, 1000, 0);
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) != 0, "a file over the limit was fetched");
    CHECK(chat_file_fetch(&B, n, 0, 1, NULL) == 0, "anyway didn't fetch past the limit");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/notes (2).txt", dl);
    CHECK(same_file(want, data, 5000), "the file fetched anyway didn't arrive");
    chat_set_file_options(&B, 0, 0);

    // A picture: its sender sees it straight away, and can show it again from what was offered.
    snprintf(path, sizeof path, "%s/pic.png", home);
    write_file(path, PNG_4X2, sizeof PNG_4X2);
    snprintf(cmd, sizeof cmd, "send %s", path);
    g_viewed.calls = 0;
    chat_run_command(&A, cmd);
    int own = mine_named(&A, "pic.png");
    CHECK(own && g_viewed.calls == 1 && g_viewed.num == own && g_viewed.len == sizeof PNG_4X2,
          "alice wasn't shown the picture she sent");
    CHECK(own && chat_file_fetch(&A, own, 1, 0, NULL) == 0 && g_viewed.calls == 2 && chat_file_bytes(&A, own) != NULL,
          "alice couldn't show her own picture again");
    CHECK(own && chat_file_fetch(&A, own, 0, 0, NULL) != 0, "alice downloaded her own file");

    // Fetched to show: handed over whole, never saved.
    RUN_UNTIL(t, 20, offer_named(&B, "pic.png") > 0);
    n = offer_named(&B, "pic.png");
    CHECK(n > 0 && chat_file(&B, n)->image && log_count(&log_b, ":show") >= 1, "the picture wasn't offered as one");
    g_viewed.calls = 0;
    CHECK(chat_file_fetch(&B, n, 1, 0, NULL) == 0, "bob couldn't fetch the picture to show");
    RUN_UNTIL(t, 60, g_viewed.calls > 0);
    CHECK(g_viewed.calls == 1 && g_viewed.num == n && g_viewed.len == sizeof PNG_4X2
          && memcmp(g_viewed.data, PNG_4X2, sizeof PNG_4X2) == 0, "the picture wasn't handed over whole");
    snprintf(want, sizeof want, "%s/pic.png", dl);
    CHECK(platform_read_file(want, data + 199000, 10) < 0, "a picture fetched to show was saved");

    // Shown again, and then saved, from the copy kept in memory: nothing is fetched again.
    CHECK(chat_file(&B, n)->cache != NULL, "the picture shown wasn't kept");
    CHECK(chat_file_fetch(&B, n, 1, 0, NULL) == 0 && g_viewed.calls == 2 && dl_state(&B, n) == DL_DONE,
          "the picture wasn't shown again from memory");
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0 && dl_state(&B, n) == DL_DONE && same_file(want, PNG_4X2, sizeof PNG_4X2),
          "the picture shown wasn't saved from memory");
    CHECK(!part_files_left(dl), "saving from memory left a partial file");

    // Shown and saved in one fetch: :download while it's coming to be shown.
    snprintf(path, sizeof path, "%s/pic2.png", home);
    write_file(path, PNG_4X2, sizeof PNG_4X2);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "pic2.png") > 0);
    n = offer_named(&B, "pic2.png");
    g_viewed.calls = 0;
    CHECK(chat_file_fetch(&B, n, 1, 0, NULL) == 0 && chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't ask for pic2.png");
    RUN_UNTIL(t, 60, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/pic2.png", dl);
    CHECK(g_viewed.calls == 1 && same_file(want, PNG_4X2, sizeof PNG_4X2), "pic2.png wasn't both shown and saved");

    // Two files from the same sender: the second waits for the first, then starts by itself.
    // :download without a number takes the newest.
    snprintf(path, sizeof path, "%s/one.bin", home);
    write_file(path, data, 4000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    snprintf(path, sizeof path, "%s/two.bin", home);
    write_file(path, data + 4000, 3000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "one.bin") > 0 && offer_named(&B, "two.bin") > 0);
    int one = offer_named(&B, "one.bin"), two = offer_named(&B, "two.bin");
    chat_run_command(&B, "download");
    CHECK(dl_state(&B, two) == DL_ACTIVE, ":download alone didn't take the newest file");
    CHECK(chat_file_fetch(&B, one, 0, 0, NULL) == 0 && dl_state(&B, one) == DL_QUEUED, "one.bin wasn't queued");
    RUN_UNTIL(t, 200, dl_over(&B, one));
    snprintf(want, sizeof want, "%s/two.bin", dl);
    char got1[700];
    snprintf(got1, sizeof got1, "%s/one.bin", dl);
    CHECK(same_file(want, data + 4000, 3000) && same_file(got1, data, 4000), "the queued file didn't follow the first");

    // Changed after it was offered: thrown away, not saved.
    snprintf(path, sizeof path, "%s/changing.bin", home);
    write_file(path, data, 3000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "changing.bin") > 0);
    n = offer_named(&B, "changing.bin");
    FILE *f = fopen(path, "r+b");
#ifdef _WIN32
    // Windows keeps a file chat has open, as it has one it offers, from being written to.
    CHECK(!f, "a file being offered could be written to");
    if (f) fclose(f);
#else
    if (f) { fputc(data[0] ^ 1, f); fclose(f); }
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch changing.bin");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/changing.bin", dl);
    CHECK(dl_state(&B, n) == DL_FAILED && log_b.mismatched == 1
          && platform_read_file(want, data + 199000, 10) < 0 && !part_files_left(dl), "a changed file was kept");
    CHECK(n > 0 && strstr(chat_file(&B, n)->why, "didn't match") != NULL, "a changed file failed without saying why");
#endif

    // Every fifth of alice's frames to bob lost while 20 KB comes: a run of chunks that didn't come
    // is asked for again as soon as the rest of its run has, so it comes whole, not long after.
    snprintf(path, sizeof path, "%s/lossy.bin", home);
    write_file(path, data, 20000);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "lossy.bin") > 0);
    n = offer_named(&B, "lossy.bin");
    lossy_t lossy = { A.port, B.port, 0, 0 };
    fake_net_filter = drop_fifth;
    fake_net_filter_ctx = &lossy;
    // No rekeys meanwhile: this is about chunks, and re-handshakes are the rekey tests'. After it,
    // they come at their usual spacing again, not all at once.
    for (int k = 0; k < 3; k++) ALL[k]->next_rekey = *t + 1000.0;
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch lossy.bin");
    RUN_UNTIL(t, 300, dl_over(&B, n));
    for (int k = 0; k < 3; k++) ALL[k]->next_rekey = *t + REKEY_INTERVAL * (0.5 + 0.2 * k);
    fake_net_filter = NULL;
    fake_net_filter_ctx = NULL;
    snprintf(want, sizeof want, "%s/lossy.bin", dl);
    CHECK(lossy.dropped > 0 && same_file(want, data, 20000), "20 KB with some of its chunks lost didn't come whole");

    // Fast transfers: the same file in a fraction of the time.
    snprintf(path, sizeof path, "%s/big.bin", home);
    write_file(path, data, 40000);
    chat_set_file_options(&A, 0, 1);
    chat_set_file_options(&B, 0, 1);
    snprintf(cmd, sizeof cmd, "send %s", path);
    chat_run_command(&A, cmd);
    RUN_UNTIL(t, 20, offer_named(&B, "big.bin") > 0);
    n = offer_named(&B, "big.bin");
    double began = *t;
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch big.bin");
    RUN_UNTIL(t, 120, dl_over(&B, n));
    snprintf(want, sizeof want, "%s/big.bin", dl);
    CHECK(same_file(want, data, 40000) && *t - began < 15.0, "40 KB took %.1f s with fast transfers", *t - began);
    chat_set_file_options(&A, 0, 0);
    chat_set_file_options(&B, 0, 0);

    // Stopped part way: nothing left behind. Meanwhile its sender sees who's fetching it.
    platform_remove(want);
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't fetch big.bin again");
    int mine = mine_named(&A, "big.bin"), pm = 0;
    char who[CHAT_NAME_LEN] = "";
    RUN_UNTIL(t, 20, !mine || (chat_file_sending(&A, chat_file(&A, mine), *t, who, &pm) == 1 && pm > 0));
    CHECK(mine && chat_file_sending(&A, chat_file(&A, mine), *t, who, &pm) == 1 && strcmp(who, "bob") == 0 && pm > 0 && pm < 1000,
          "alice didn't see bob fetching big.bin");
    snprintf(cmd, sizeof cmd, "cancel %d", n);
    chat_run_command(&B, cmd);
    CHECK(dl_state(&B, n) == DL_NONE && !part_files_left(dl), "a cancelled download left something");
    // Bob doesn't say he stopped, so alice sends the rest of what he asked for, then gives up on him.
    RUN_UNTIL(t, 200, !mine || chat_file_sending(&A, chat_file(&A, mine), *t, who, &pm) == 0);
    CHECK(mine && chat_file_sending(&A, chat_file(&A, mine), *t, who, &pm) == 0, "alice still thinks bob is fetching big.bin");

    // No longer offered: a fetch is told so.
    snprintf(cmd, sizeof cmd, "cancel %d", mine);
    chat_run_command(&A, cmd);
    CHECK(chat_file_fetch(&B, n, 0, 0, NULL) == 0, "bob couldn't ask for big.bin");
    RUN_UNTIL(t, 60, dl_over(&B, n));
    CHECK(dl_state(&B, n) == DL_FAILED && log_b.withdrawn == 1, "a withdrawn file wasn't refused");
    CHECK(strcmp(chat_file(&B, n)->why, "isn't offered any more") == 0, "a withdrawn file failed without saying why");

    if (platform_remove_tree(home) != 0) printf("couldn't remove %s\n", home);
}

void test_file_names(double *t) {
    (void)t;
    static const char *const CASES[][2] = {
        { "photo.jpg", "photo.jpg" },
        { "../../etc/passwd", "passwd" },
        { "C:\\Windows\\evil.exe", "evil.exe" },
        { "..", "file" },
        { ".bashrc", "bashrc" },
        { "   ", "file" },
        { "a\x1b[2Jb.txt", "a[2Jb.txt" },
        { "invoice\xe2\x80\xaegpj.exe", "invoicegpj.exe" },   // a right-to-left override, gone
        { "what?.txt", "what_.txt" },
        { "con.txt", "_con.txt" },
        { "NUL", "_NUL" },
        { "LPT1.log", "_LPT1.log" },
        { "trailing. ", "trailing" },
        { "na\tme", "name" },
        { "", "file" },
    };
    char out[FILE_NAME_MAX + 1];
    for (size_t i = 0; i < sizeof CASES / sizeof CASES[0]; i++) {
        file_clean_name(CASES[i][0], out);
        CHECK(strcmp(out, CASES[i][1]) == 0, "name '%s' became '%s', not '%s'", CASES[i][0], out, CASES[i][1]);
    }
    char longname[400];
    memset(longname, 'x', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    file_clean_name(longname, out);
    CHECK(strlen(out) == FILE_NAME_MAX, "a long name came out %zu bytes", strlen(out));
    uint64_t v;
    CHECK(file_parse_size("8M", &v) == 0 && v == 8u * 1024 * 1024 && file_parse_size("512 KB", &v) == 0 && v == 512 * 1024
          && file_parse_size("1.5G", &v) == 0 && v == 1610612736ull && file_parse_size("100", &v) == 0 && v == 100
          && file_parse_size("x", &v) != 0 && file_parse_size("5Q", &v) != 0 && file_parse_size("-1", &v) != 0, "sizes parse wrong");
}
