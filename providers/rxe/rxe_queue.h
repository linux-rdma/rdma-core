/*
 * Copyright (c) 2009 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2009 System Fabric Works, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the fileA
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

/* implements a simple circular buffer with sizes a power of 2 */

#ifndef H_RXE_PCQ
#define H_RXE_PCQ

#include <stdint.h>
#include <stdatomic.h>

/* MUST MATCH kernel struct rxe_pqc in rxe_queue.h */
struct rxe_queue {
	uint32_t		log2_elem_size;
	uint32_t		index_mask;
	uint32_t		pad_1[30];
	_Atomic(uint32_t)	producer_index;
	uint32_t		pad_2[31];
	_Atomic(uint32_t)	consumer_index;
	uint32_t		pad_3[31];
	uint8_t			data[0];
};

static inline int next_index(struct rxe_queue *q, int index)
{
	return (index + 1) & q->index_mask;
}

static inline int queue_empty(struct rxe_queue *q)
{
	/* Must hold consumer_index lock */
	return ((atomic_load(&q->producer_index) -
		 atomic_load_explicit(&q->consumer_index,
				      memory_order_relaxed)) &
		q->index_mask) == 0;
}

static inline int queue_full(struct rxe_queue *q)
{
	/* Must hold producer_index lock */
	return ((atomic_load_explicit(&q->producer_index,
				      memory_order_relaxed) +
		 1 - atomic_load(&q->consumer_index)) &
		q->index_mask) == 0;
}

static inline void advance_producer(struct rxe_queue *q)
{
	/* Must hold producer_index lock */
	atomic_thread_fence(memory_order_release);
	atomic_store(
	    &q->producer_index,
	    (atomic_load_explicit(&q->producer_index, memory_order_relaxed) +
	     1) &
		q->index_mask);
}

static inline void advance_consumer(struct rxe_queue *q)
{
	/* Must hold consumer_index lock */
	atomic_store(
	    &q->consumer_index,
	    (atomic_load_explicit(&q->consumer_index, memory_order_relaxed) +
	     1) &
		q->index_mask);
}

static inline void *producer_addr(struct rxe_queue *q)
{
	/* Must hold producer_index lock */
	return q->data + ((atomic_load_explicit(&q->producer_index,
						memory_order_relaxed) &
			   q->index_mask)
			  << q->log2_elem_size);
}

static inline void *consumer_addr(struct rxe_queue *q)
{
	/* Must hold consumer_index lock */
	return q->data + ((atomic_load_explicit(&q->consumer_index,
						memory_order_relaxed) &
			   q->index_mask)
			  << q->log2_elem_size);
}

static inline void *addr_from_index(struct rxe_queue *q, unsigned int index)
{
	return q->data + ((index & q->index_mask)
				<< q->log2_elem_size);
}

static inline unsigned int index_from_addr(const struct rxe_queue *q, const void *addr)
{
	return (((uint8_t *)addr - q->data) >> q->log2_elem_size) & q->index_mask;
}

#endif /* H_RXE_PCQ */
