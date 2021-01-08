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

#ifndef H_RXE_QUEUE
#define H_RXE_QUEUE

#include <stdint.h>
#include <stdatomic.h>

#include "rxe.h"

/* N.B. producer_index and consumer_index always lie in the range
 * [0, index_mask] masking is only required when computing a new value.
 * Below, 'consumer_index lock' is cq->lock
 * and, 'producer_index lock' is one of rq, sq or srq->lock.
 * In the code below the only memory ordering required is between the
 * kernel driver (rdma_rxe) and the user provider library. Ordering between
 * user space threads is addressed by spinlocks which provide memory
 * barriers.
 */

typedef _Atomic(__u32) _atomic_t;

static inline _atomic_t *producer(struct rxe_queue_buf *q)
{
	return (_atomic_t *)&q->producer_index;
}

static inline _atomic_t *consumer(struct rxe_queue_buf *q)
{
	return (_atomic_t *)&q->consumer_index;
}

/* Must hold consumer_index lock (used by CQ only) */
static inline int queue_empty(struct rxe_queue_buf *q)
{
	__u32 prod;
	__u32 cons;

	prod = atomic_load_explicit(producer(q), memory_order_acquire);
	cons = atomic_load_explicit(consumer(q), memory_order_relaxed);

	return (prod == cons);
}

/* Must hold producer_index lock (used by SQ, RQ, SRQ only) */
static inline int queue_full(struct rxe_queue_buf *q)
{
	__u32 prod;
	__u32 cons;

	prod = atomic_load_explicit(producer(q), memory_order_relaxed);
	cons = atomic_load_explicit(consumer(q), memory_order_acquire);

	return (cons == ((prod + 1) & q->index_mask));
}

/* Must hold producer_index lock */
static inline void advance_producer(struct rxe_queue_buf *q)
{
	__u32 prod;

	prod = atomic_load_explicit(producer(q), memory_order_relaxed);
	prod = (prod + 1) & q->index_mask;

	atomic_store_explicit(producer(q), prod, memory_order_release);
}

/* Must hold consumer_index lock */
static inline void advance_consumer(struct rxe_queue_buf *q)
{
	__u32 cons;

	cons = atomic_load_explicit(consumer(q), memory_order_relaxed);
	cons = (cons + 1) & q->index_mask;

	atomic_store_explicit(consumer(q), cons, memory_order_release);
}

/* Must hold producer_index lock */
static inline __u32 load_producer_index(struct rxe_queue_buf *q)
{
	return atomic_load_explicit(producer(q), memory_order_relaxed);
}

/* Must hold producer_index lock */
static inline void store_producer_index(struct rxe_queue_buf *q, __u32 index)
{
	/* flush writes to work queue before moving index */
	atomic_store_explicit(producer(q), index, memory_order_release);
}

/* Must hold consumer_index lock */
static inline __u32 load_consumer_index(struct rxe_queue_buf *q)
{
	return atomic_load_explicit(consumer(q), memory_order_relaxed);
}

/* Must hold consumer_index lock */
static inline void store_consumer_index(struct rxe_queue_buf *q, __u32 index)
{
	/* complete reads from completion queue before moving index */
	atomic_store_explicit(consumer(q), index, memory_order_release);
}

/* Must hold producer_index lock */
static inline void *producer_addr(struct rxe_queue_buf *q)
{
	__u32 prod;

	prod = atomic_load_explicit(producer(q), memory_order_relaxed);

	return q->data + (prod << q->log2_elem_size);
}

/* Must hold consumer_index lock */
static inline void *consumer_addr(struct rxe_queue_buf *q)
{
	__u32 cons;

	cons = atomic_load_explicit(consumer(q), memory_order_relaxed);

	return q->data + (cons << q->log2_elem_size);
}

static inline void *addr_from_index(struct rxe_queue_buf *q,
				    unsigned int index)
{
	index &= q->index_mask;

	return q->data + (index << q->log2_elem_size);
}

static inline unsigned int index_from_addr(const struct rxe_queue_buf *q,
					   const void *addr)
{
	return (((__u8 *)addr - q->data) >> q->log2_elem_size) &
		q->index_mask;
}

static inline void advance_cq_cur_index(struct rxe_cq *cq)
{
	struct rxe_queue_buf *q = cq->queue;

	cq->cur_index = (cq->cur_index + 1) & q->index_mask;
}

static inline int check_cq_queue_empty(struct rxe_cq *cq)
{
	struct rxe_queue_buf *q = cq->queue;
	__u32 prod;

	prod = atomic_load_explicit(producer(q), memory_order_acquire);

	return (cq->cur_index == prod);
}

static inline void advance_qp_cur_index(struct rxe_qp *qp)
{
	struct rxe_queue_buf *q = qp->sq.queue;

	qp->cur_index = (qp->cur_index + 1) & q->index_mask;
}

static inline int check_qp_queue_full(struct rxe_qp *qp)
{
	struct rxe_queue_buf *q = qp->sq.queue;
	uint32_t cons;

	cons = atomic_load_explicit(consumer(q), memory_order_acquire);

	if (qp->err)
		goto err;

	if (cons == ((qp->cur_index + 1) % q->index_mask))
		qp->err = ENOSPC;
err:
	return qp->err;
}

#endif /* H_RXE_QUEUE */
