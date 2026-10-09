// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_JOB_H
#define CHAT_JOB_H

// A lookup run on a thread, which whoever started it may give up on before it finishes. The thread
// only writes to its job, and whichever side finishes last frees it.
#if defined(__STDC_NO_ATOMICS__)
typedef volatile int job_state_t;
#define JOB_ATOMIC 0
#else
#include <stdatomic.h>
typedef _Atomic int job_state_t;
#define JOB_ATOMIC 1
#endif
enum { JOB_RUNNING, JOB_DONE, JOB_ABANDONED };

// The thread has finished: 1 if it was given up on, so the thread frees the job.
static inline int job_finish(job_state_t *state) {
#if JOB_ATOMIC
    return atomic_exchange(state, JOB_DONE) == JOB_ABANDONED;
#else
    *state = JOB_DONE;
    return 0;
#endif
}

// Gives up on it: 1 if it had finished, so the caller frees the job.
static inline int job_abandon(job_state_t *state) {
#if JOB_ATOMIC
    return atomic_exchange(state, JOB_ABANDONED) == JOB_DONE;
#else
    if (*state == JOB_DONE) return 1;
    *state = JOB_ABANDONED;   // abandoned: without atomics, never freed
    return 0;
#endif
}

static inline int job_done(job_state_t *state) {
#if JOB_ATOMIC
    return atomic_load(state) == JOB_DONE;
#else
    return *state == JOB_DONE;
#endif
}

#endif
