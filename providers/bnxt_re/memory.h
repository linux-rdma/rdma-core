/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: Implements data-struture to allocate page-aligned
 *              memory buffer.
 */

#ifndef __MEMORY_H__
#define __MEMORY_H__

#include <pthread.h>

struct bnxt_re_queue {
	void *va;
	uint32_t bytes; /* for munmap */
	uint32_t depth; /* no. of entries */
	uint32_t head;
	uint32_t tail;
	uint32_t stride;
	/* Represents the difference between the real queue depth allocated in
	 * HW and the user requested queue depth and is used to correctly flag
	 * queue full condition based on user supplied queue depth.
	 * This value can vary depending on the type of queue and any HW
	 * requirements that mandate keeping a fixed gap between the producer
	 * and the consumer indices in the queue
	 */
	uint32_t diff;
	uint32_t esize;
	uint32_t max_slots;
	pthread_spinlock_t qlock;
};

static inline unsigned long get_aligned(uint32_t size, uint32_t al_size)
{
	return (unsigned long)(size + al_size - 1) & ~(al_size - 1);
}

static inline unsigned long roundup_pow_of_two(unsigned long val)
{
	unsigned long roundup = 1;

	if (val == 1)
		return (roundup << 1);

	while (roundup < val)
		roundup <<= 1;

	return roundup;
}

int bnxt_re_alloc_aligned(struct bnxt_re_queue *que, uint32_t pg_size);
void bnxt_re_free_aligned(struct bnxt_re_queue *que);

/* Basic queue operation */
static inline void *bnxt_re_get_hwqe(struct bnxt_re_queue *que, uint32_t idx)
{
	idx += que->tail;
	if (idx >= que->depth)
		idx -= que->depth;
	return (void *)(que->va + (idx << 4));
}

static inline void *bnxt_re_get_hwqe_hdr(struct bnxt_re_queue *que)
{
	return (void *)(que->va + ((que->tail) << 4));
}

static inline uint32_t bnxt_re_is_que_full(struct bnxt_re_queue *que,
					   uint32_t slots)
{
	int32_t avail, head, tail;

	head = que->head;
	tail = que->tail;
	avail = head - tail;
	if (head <= tail)
		avail += que->depth;
	return avail <= (slots + que->diff);
}

static inline uint32_t bnxt_re_is_que_empty(struct bnxt_re_queue *que)
{
	return que->tail == que->head;
}

static inline void bnxt_re_incr_tail(struct bnxt_re_queue *que, uint8_t cnt)
{
	que->tail += cnt;
	if (que->tail >= que->depth)
		que->tail %= que->depth;
}

static inline void bnxt_re_incr_head(struct bnxt_re_queue *que, uint8_t cnt)
{
	que->head += cnt;
	if (que->head >= que->depth)
		que->head %= que->depth;
}

#endif
