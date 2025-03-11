/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2024, Microsoft Corporation. All rights reserved.
 */

#ifndef _SHADOW_QUEUE_H_
#define _SHADOW_QUEUE_H_

#include <stdio.h>
#include <linux/types.h>
#include <endian.h>
#include <infiniband/verbs.h>
#include <sys/mman.h>
#include <util/util.h>
#include <stdatomic.h>

typedef _Atomic(uint64_t) _atomic_t;

#define MANA_NO_SIGNAL_WC (0xff)

struct shadow_wqe_header {
	/* ibv_wc_opcode */
	uint64_t opcode : 8;
	/* ibv_wc_flags or MANA_NO_SIGNAL_WC */
	uint64_t flags : 8;
	uint64_t posted_wqe_size_in_bu : 8;
	/* ibv_wc_status */
	uint64_t vendor_error : 12;
	uint64_t unmasked_queue_offset : 28;
	uint64_t wr_id;
};

struct rc_sq_shadow_wqe {
	struct  shadow_wqe_header header;
	uint32_t end_psn;
	uint32_t read_posted_wqe_size_in_bu;
};

struct rc_rq_shadow_wqe {
	struct shadow_wqe_header header;
	uint32_t byte_len;
	uint32_t imm_or_rkey;
};

struct shadow_queue {
	uint64_t prod_idx;
	uint64_t cons_idx;
	uint64_t next_to_complete_idx;
	uint64_t next_to_signal_idx;
	uint32_t length;
	uint32_t stride;
	void *buffer;
};

static inline void reset_shadow_queue(struct shadow_queue *queue)
{
	queue->prod_idx = 0;
	queue->cons_idx = 0;
	queue->next_to_complete_idx = 0;
	queue->next_to_signal_idx = 0;
}

static inline int create_shadow_queue(struct shadow_queue *queue, uint32_t length, uint32_t stride)
{
	length = roundup_pow_of_two(length);
	stride = align(stride, 8);

	void *buffer = mmap(NULL, stride * length, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (buffer == MAP_FAILED)
		return -1;

	queue->length = length;
	queue->stride = stride;
	reset_shadow_queue(queue);
	queue->buffer = buffer;
	return 0;
}

static inline void destroy_shadow_queue(struct shadow_queue *queue)
{
	if (queue->buffer) {
		munmap(queue->buffer, queue->stride * queue->length);
		queue->buffer = NULL;
	}
}

static inline _atomic_t *producer(struct shadow_queue *queue)
{
	return (_atomic_t *)&queue->prod_idx;
}

static inline _atomic_t *consumer(struct shadow_queue *queue)
{
	return (_atomic_t *)&queue->cons_idx;
}

static inline struct shadow_wqe_header *
shadow_queue_get_element(struct shadow_queue *queue, uint64_t unmasked_index)
{
	uint32_t index = unmasked_index & (queue->length - 1);

	return (struct shadow_wqe_header *)((uint8_t *)queue->buffer + index * queue->stride);
}

static inline bool shadow_queue_full(struct shadow_queue *queue)
{
	uint64_t prod_idx = atomic_load_explicit(producer(queue), memory_order_relaxed);
	uint64_t cons_idx = atomic_load_explicit(consumer(queue), memory_order_acquire);

	return (prod_idx - cons_idx) >= queue->length;
}

static inline struct shadow_wqe_header *
shadow_queue_producer_entry(struct shadow_queue *queue)
{
	uint64_t prod_idx = atomic_load_explicit(producer(queue), memory_order_relaxed);

	return shadow_queue_get_element(queue, prod_idx);
}

static inline void shadow_queue_advance_producer(struct shadow_queue *queue)
{
	uint64_t prod_idx = atomic_load_explicit(producer(queue), memory_order_relaxed);

	atomic_store_explicit(producer(queue), prod_idx + 1, memory_order_release);
}

static inline void shadow_queue_advance_consumer(struct shadow_queue *queue)
{
	uint64_t cons_idx = atomic_load_explicit(consumer(queue), memory_order_relaxed);

	atomic_store_explicit(consumer(queue), cons_idx + 1, memory_order_release);
}

static inline struct shadow_wqe_header *
shadow_queue_get_next_to_consume(struct shadow_queue *queue)
{
	uint64_t cons_idx = atomic_load_explicit(consumer(queue), memory_order_relaxed);

	if (cons_idx == queue->next_to_complete_idx)
		return NULL;

	return shadow_queue_get_element(queue, cons_idx);
}

static inline struct shadow_wqe_header *
shadow_queue_get_next_to_complete(struct shadow_queue *queue)
{
	uint64_t prod_idx = atomic_load_explicit(producer(queue), memory_order_acquire);

	if (queue->next_to_complete_idx == prod_idx)
		return NULL;

	return shadow_queue_get_element(queue, queue->next_to_complete_idx);
}

static inline void shadow_queue_advance_next_to_complete(struct shadow_queue *queue)
{
	queue->next_to_complete_idx++;
}

static inline struct shadow_wqe_header *
shadow_queue_get_next_to_signal(struct shadow_queue *queue)
{
	uint64_t prod_idx = atomic_load_explicit(producer(queue), memory_order_acquire);
	struct shadow_wqe_header *wqe = NULL;

	queue->next_to_signal_idx = max(queue->next_to_signal_idx, queue->next_to_complete_idx);
	while (queue->next_to_signal_idx < prod_idx) {
		wqe = shadow_queue_get_element(queue, queue->next_to_signal_idx);
		queue->next_to_signal_idx++;
		if (wqe->flags != MANA_NO_SIGNAL_WC)
			return wqe;
	}

	return NULL;
}

#endif //_SHADOW_QUEUE_H_
