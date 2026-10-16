// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the rest of the app uses of install.c: :install's boxes, and unlocking. app.h includes it, after
// the types it uses. The save files themselves are behind saves.h.
#ifndef CHAT_APP_INSTALL_H
#define CHAT_APP_INSTALL_H

#include "app/app.h"

// install.c
void saved_note(const char *fmt, ...) PRINTF_LIKE(1, 2);
void say_saved_notes(void);
int key_saved_as_path(void);
void save_verified(void);
void autosave_changed(void);
void factors_text(unsigned f, char *out, size_t cap);
void save_detail(const install_save_t *sv, char *out, size_t cap);
int save_to_pick(void);
void unlock_at_start(int in_box);
int key_in_use_saved(void);
int is_current_save(const char *name);
int save_exists(const char *name);
void pick_random_save_name(void);
int install_resaves(void);
void cancel_install(void);
void install_confirmed(void);
void install_use_existing(void);
void install_new_save(void);
void back_from_install_name(void);
void install_pick_key(const tui_key_t *key);
void install_overwrite_yes(void);
void back_from_install_unlock(void);
void choice_key(const tui_key_t *key, void (*yes)(void), void (*no)(void), void (*esc)(void));
void commit_install_name(void);
void commit_install_pass(void);
void commit_install_pass2(void);
void commit_install_unlock(void);
void uninstall_confirmed(void);
void settle_start(void);
void commit_unlock(void);
void back_from_unlock(void);
void saves_key(const tui_key_t *key);
void cancel_uninstall(void);
void install_first_yes(void);
void install_first_no(void);
void device_lock_choose(int on);
void device_lock_yes(void);
void device_lock_no(void);
void factor_choose(unsigned factor, int on);
void factor_yes(void);
void factor_no(void);
void destroy_choose(int limit);
void shadow_off(void);
void begin_shadow(void);
void commit_shadow_pass(void);
void commit_shadow_pass2(void);
void cancel_shadow_pass(void);
void commit_key_pin(void);
void cancel_key_pin(void);
void key_wait_key(const tui_key_t *key);
void key_wait_tick(void);
void unlock_go(key_purpose_t why);
void commit_unlock_code(void);
void back_from_unlock_code(void);
void confirm_key(const tui_key_t *key, void (*yes)(void), void (*no)(void));
void quit_key(const tui_key_t *key);
void field_key(const tui_key_t *key, void (*enter)(void), void (*esc)(void));
void code_setup_key(const tui_key_t *key);

#endif
