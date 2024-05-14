/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2024, Microsoft Corporation. All rights reserved.
 */

#ifndef _DOORBELLS_H_
#define _DOORBELLS_H_

#include <util/udma_barrier.h>
#include <util/mmio.h>
#include "mana.h"

#define GDMA_CQE_OWNER_BITS 3
#define CQ_OWNER_MASK ((1 << (GDMA_CQE_OWNER_BITS)) - 1)

#define DOORBELL_OFFSET_SQ		0x0
#define DOORBELL_OFFSET_RQ		0x400
#define DOORBELL_OFFSET_RQ_CLIENT	0x408
#define DOORBELL_OFFSET_CQ		0x800

union gdma_doorbell_entry {
	uint64_t     as_uint64;
	struct {
		uint64_t id   : 24;
		uint64_t reserved    : 8;
		uint64_t prod_idx    : 31;
		uint64_t arm     : 1;
	} cq;
	struct {
		uint32_t id   : 24;
		uint32_t wqe_cnt     : 8;
		uint32_t prod_idx;
	} rx;
	struct {
		uint32_t id   : 24;
		uint32_t reserved    : 8;
		uint32_t prod_idx;
	} tx;
	struct {
		uint64_t id : 24;
		uint64_t high : 8;
		uint64_t low : 32;
	} rqe_client;
}; /* HW DATA */

static inline void gdma_ring_recv_doorbell(struct mana_gdma_queue *wq, uint8_t wqe_cnt)
{
	union gdma_doorbell_entry e;

	e.as_uint64 = 0;
	e.rx.id = wq->id;
	e.rx.prod_idx = wq->prod_idx * GDMA_WQE_ALIGNMENT_UNIT_SIZE;
	e.rx.wqe_cnt = wqe_cnt;

	udma_to_device_barrier();
	mmio_write64(wq->db_page + DOORBELL_OFFSET_RQ, e.as_uint64);
	mmio_flush_writes();
}

static inline void gdma_ring_send_doorbell(struct mana_gdma_queue *wq)
{
	union gdma_doorbell_entry e;

	e.as_uint64 = 0;
	e.tx.id = wq->id;
	e.tx.prod_idx = wq->prod_idx * GDMA_WQE_ALIGNMENT_UNIT_SIZE;

	udma_to_device_barrier();
	mmio_write64(wq->db_page + DOORBELL_OFFSET_SQ, e.as_uint64);
	mmio_flush_writes();
}

static inline void gdma_arm_normal_cqe(struct mana_gdma_queue *wq, uint32_t psn)
{
	union gdma_doorbell_entry e;

	e.as_uint64 = 0;
	e.rqe_client.id = wq->id;
	e.rqe_client.high = 1;
	e.rqe_client.low = psn;

	udma_to_device_barrier();
	mmio_write64(wq->db_page + DOORBELL_OFFSET_RQ_CLIENT, e.as_uint64);
	mmio_flush_writes();
}

static inline void gdma_ring_cq_doorbell(struct mana_cq *cq)
{
	union gdma_doorbell_entry e;

	// To address the use-case of ibv that re-arms the CQ without polling
	if (cq->last_armed_head == cq->head)
		cq->last_armed_head = cq->head + 1;
	else
		cq->last_armed_head = cq->head;

	e.as_uint64 = 0;
	e.cq.id = cq->cqid;
	e.cq.prod_idx = cq->last_armed_head % (cq->cqe << GDMA_CQE_OWNER_BITS);
	e.cq.arm = 1;

	udma_to_device_barrier();
	mmio_write64(cq->db_page + DOORBELL_OFFSET_CQ, e.as_uint64);
	mmio_flush_writes();
}

#endif //_DOORBELLS_H_
