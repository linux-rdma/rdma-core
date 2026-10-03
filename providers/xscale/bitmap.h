/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef BITMAP_H
#define BITMAP_H

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <linux/errno.h>
#include <util/util.h>
#include "xscale.h"

/* Only ia64 requires this */
#ifdef __ia64__
#define XSC_SHM_ADDR ((void *)0x8000000000000000UL)
#define XSC_SHMAT_FLAGS (SHM_RND)
#else
#define XSC_SHM_ADDR NULL
#define XSC_SHMAT_FLAGS 0
#endif

#define BITS_PER_LONG		(8 * sizeof(long))

#ifndef HPAGE_SIZE
#define HPAGE_SIZE		(2UL * 1024 * 1024)
#endif

#define XSC_SHM_LENGTH		HPAGE_SIZE
#define XSC_Q_CHUNK_SIZE	32768
#define XSC_SHM_NUM_REGION	64

static inline unsigned long xsc_ffz(uint32_t word)
{
	return __builtin_ffs(~word) - 1;
}

static inline uint32_t xsc_find_first_zero_bit(const unsigned long *addr,
					 uint32_t size)
{
	const unsigned long *p = addr;
	uint32_t result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG - 1)) {
		tmp = *(p++);
		if (~tmp)
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) | (~0UL << size);
	if (tmp == (uint32_t)~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found:
	return result + xsc_ffz(tmp);
}

static inline void xsc_set_bit(unsigned int nr, unsigned long *addr)
{
	addr[(nr / BITS_PER_LONG)] |= (1 << (nr % BITS_PER_LONG));
}

static inline void xsc_clear_bit(unsigned int nr,  unsigned long *addr)
{
	addr[(nr / BITS_PER_LONG)] &= ~(1 << (nr % BITS_PER_LONG));
}

static inline int xsc_test_bit(unsigned int nr, const unsigned long *addr)
{
	return !!(addr[(nr / BITS_PER_LONG)] & (1 <<  (nr % BITS_PER_LONG)));
}

#endif
