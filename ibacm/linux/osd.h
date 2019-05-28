/*
 * Copyright (c) 2009 Intel Corporation.  All rights reserved.
 * Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(OSD_H)
#define OSD_H

#include <config.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <ccan/minmax.h>

#define ACM_ADDR_FILE "ibacm_addr.cfg"
#define ACM_OPTS_FILE "ibacm_opts.cfg"

#if DEFINE_ATOMICS
typedef struct { pthread_mutex_t mut; int val; } atomic_t;
static inline int atomic_inc(atomic_t *atomic)
{
	int v;

	pthread_mutex_lock(&atomic->mut);
	v = ++(atomic->val);
	pthread_mutex_unlock(&atomic->mut);
	return v;
}
static inline int atomic_dec(atomic_t *atomic)
{
	int v;

	pthread_mutex_lock(&atomic->mut);
	v = --(atomic->val);
	pthread_mutex_unlock(&atomic->mut);
	return v;
}
static inline void atomic_init(atomic_t *atomic)
{
	pthread_mutex_init(&atomic->mut, NULL);
	atomic->val = 0;
}
#else
typedef struct { volatile int val; } atomic_t;
#define atomic_inc(v) (__sync_add_and_fetch(&(v)->val, 1))
#define atomic_dec(v) (__sync_sub_and_fetch(&(v)->val, 1))
#define atomic_init(v) ((v)->val = 0)
#endif
#define atomic_get(v) ((v)->val)
#define atomic_set(v, s) ((v)->val = s)

typedef struct { pthread_cond_t cond; pthread_mutex_t mutex; } event_t;
static inline void event_init(event_t *e)
{
	pthread_condattr_t attr;

	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&e->cond, &attr);
	pthread_mutex_init(&e->mutex, NULL);
}
#define event_signal(e)	pthread_cond_signal(&(e)->cond)
#define ONE_SEC_IN_NSEC  1000000000ULL
static inline int event_wait(event_t *e, unsigned int timeout)
{
	struct timespec wait;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &wait);
	wait.tv_sec = wait.tv_sec + timeout / 1000;
	wait.tv_nsec = wait.tv_nsec + (timeout % 1000) * 1000000;
	if (wait.tv_nsec > ONE_SEC_IN_NSEC) {
		wait.tv_sec++;
		wait.tv_nsec -= ONE_SEC_IN_NSEC;
	}
	pthread_mutex_lock(&e->mutex);
	ret = pthread_cond_timedwait(&e->cond, &e->mutex, &wait);
	pthread_mutex_unlock(&e->mutex);
	return ret;
}

static inline uint64_t time_stamp_us(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (t.tv_sec * ONE_SEC_IN_NSEC + t.tv_nsec) / 1000;
}

#define time_stamp_ms()  (time_stamp_us() / (uint64_t) 1000)
#define time_stamp_sec() (time_stamp_ms() / (uint64_t) 1000)
#define time_stamp_min() (time_stamp_sec() / (uint64_t) 60)

#endif /* OSD_H */
