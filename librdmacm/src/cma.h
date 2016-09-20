/*
 * Copyright (c) 2005-2014 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#if !defined(CMA_H)
#define CMA_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <errno.h>
#include <endian.h>
#include <byteswap.h>
#include <semaphore.h>

#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>

#ifdef INCLUDE_VALGRIND
#   include <valgrind/memcheck.h>
#   ifndef VALGRIND_MAKE_MEM_DEFINED
#       warning "Valgrind requested, but VALGRIND_MAKE_MEM_DEFINED undefined"
#   endif
#endif

#ifndef VALGRIND_MAKE_MEM_DEFINED
#   define VALGRIND_MAKE_MEM_DEFINED(addr,len)
#endif

#define PFX "librdmacm: "

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#else
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#endif

#define max(a, b) ((a) > (b) ? a : b)
#define min(a, b) ((a) < (b) ? a : b)

#ifndef container_of
#define container_of(ptr, type, field) \
	((type *) ((void *)ptr - offsetof(type, field)))
#endif


/*
 * Fast synchronization for low contention locking.
 */
#if DEFINE_ATOMICS
#define fastlock_t pthread_mutex_t
#define fastlock_init(lock) pthread_mutex_init(lock, NULL)
#define fastlock_destroy(lock) pthread_mutex_destroy(lock)
#define fastlock_acquire(lock) pthread_mutex_lock(lock)
#define fastlock_release(lock) pthread_mutex_unlock(lock)

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
typedef struct {
	sem_t sem;
	volatile int cnt;
} fastlock_t;
static inline void fastlock_init(fastlock_t *lock)
{
	sem_init(&lock->sem, 0, 0);
	lock->cnt = 0;
}
static inline void fastlock_destroy(fastlock_t *lock)
{
	sem_destroy(&lock->sem);
}
static inline void fastlock_acquire(fastlock_t *lock)
{
	if (__sync_add_and_fetch(&lock->cnt, 1) > 1)
		sem_wait(&lock->sem);
}
static inline void fastlock_release(fastlock_t *lock)
{
	if (__sync_sub_and_fetch(&lock->cnt, 1) > 0)
		sem_post(&lock->sem);
}

typedef struct { volatile int val; } atomic_t;
#define atomic_inc(v) (__sync_add_and_fetch(&(v)->val, 1))
#define atomic_dec(v) (__sync_sub_and_fetch(&(v)->val, 1))
#define atomic_init(v) ((v)->val = 0)
#endif /* DEFINE_ATOMICS */
#define atomic_get(v) ((v)->val)
#define atomic_set(v, s) ((v)->val = s)

uint16_t ucma_get_port(struct sockaddr *addr);
int ucma_addrlen(struct sockaddr *addr);
void ucma_set_sid(enum rdma_port_space ps, struct sockaddr *addr,
		  struct sockaddr_ib *sib);
int ucma_max_qpsize(struct rdma_cm_id *id);
int ucma_complete(struct rdma_cm_id *id);
int ucma_shutdown(struct rdma_cm_id *id);

static inline int ERR(int err)
{
	errno = err;
	return -1;
}

int ucma_init(void);
extern int af_ib_support;

#define RAI_ROUTEONLY		0x01000000

void ucma_ib_init();
void ucma_ib_cleanup();
void ucma_ib_resolve(struct rdma_addrinfo **rai, struct rdma_addrinfo *hints);

struct ib_connect_hdr {
	uint8_t  cma_version;
	uint8_t  ip_version; /* IP version: 7:4 */
	uint16_t port;
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
#define cma_src_ip4 src_addr[3]
#define cma_src_ip6 src_addr[0]
#define cma_dst_ip4 dst_addr[3]
#define cma_dst_ip6 dst_addr[0]
};

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif
#ifndef RDMADIR
#define RDMADIR "rdma"
#endif
#define RDMA_CONF_DIR  SYSCONFDIR "/" RDMADIR
#define RS_CONF_DIR RDMA_CONF_DIR "/rsocket"

#endif /* CMA_H */
