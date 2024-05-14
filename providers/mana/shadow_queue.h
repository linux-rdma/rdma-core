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

#define MANA_NO_SIGNAL_WC (0xff)

struct shadow_wqe_header {
	/* ibv_wc_opcode */
	uint8_t opcode;
	/* ibv_wc_flags or MANA_NO_SIGNAL_WC */
	uint8_t flags;
	/* ibv_wc_status */
	uint8_t vendor_error_code;
	uint8_t posted_wqe_size_in_bu;
	uint32_t unmasked_queue_offset;
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
	uint32_t length;
	uint32_t stride;
	void *buffer;
};

static inline void reset_shadow_queue(struct shadow_queue *queue)
{
	queue->prod_idx = 0;
	queue->cons_idx = 0;
	queue->next_to_complete_idx = 0;
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

static inline struct shadow_wqe_header *
shadow_queue_get_element(const struct shadow_queue *queue, uint64_t unmasked_index)
{
	uint32_t index = unmasked_index & (queue->length - 1);

	return (struct shadow_wqe_header *)((uint8_t *)queue->buffer + index * queue->stride);
}

static inline bool shadow_queue_full(struct shadow_queue *queue)
{
	return (queue->prod_idx - queue->cons_idx) >= queue->length;
}

static inline struct shadow_wqe_header *
shadow_queue_producer_entry(struct shadow_queue *queue)
{
	return shadow_queue_get_element(queue, queue->prod_idx);
}

static inline void shadow_queue_advance_producer(struct shadow_queue *queue)
{
	queue->prod_idx++;
}

static inline void shadow_queue_retreat_producer(struct shadow_queue *queue)
{
	queue->prod_idx--;
}

static inline void shadow_queue_advance_consumer(struct shadow_queue *queue)
{
	queue->cons_idx++;
}

static inline bool shadow_queue_empty(struct shadow_queue *queue)
{
	return queue->prod_idx == queue->cons_idx;
}

static inline uint32_t shadow_queue_get_pending_wqe_count(struct shadow_queue *queue)
{
	return (uint32_t)(queue->prod_idx - queue->next_to_complete_idx);
}

static inline struct shadow_wqe_header *
shadow_queue_get_next_to_consume(const struct shadow_queue *queue)
{
	if (queue->cons_idx == queue->next_to_complete_idx)
		return NULL;

	return shadow_queue_get_element(queue, queue->cons_idx);
}

static inline struct shadow_wqe_header *
shadow_queue_get_next_to_complete(struct shadow_queue *queue)
{
	if (queue->next_to_complete_idx == queue->prod_idx)
		return NULL;

	return shadow_queue_get_element(queue, queue->next_to_complete_idx);
}

static inline void shadow_queue_advance_next_to_complete(struct shadow_queue *queue)
{
	queue->next_to_complete_idx++;
}

#endif //_SHADOW_QUEUE_H_
