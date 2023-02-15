/* SPDX-License-Identifier: GPL-2.0 or OpenIB.org BSD (MIT) See COPYING file */
/*
 * Authors: Cheng Xu <chengyou@linux.alibaba.com>
 * Copyright (c) 2020-2021, Alibaba Group.
 */

#ifndef __ERDMA_VERBS_H__
#define __ERDMA_VERBS_H__

#include <pthread.h>
#include <inttypes.h>
#include <stddef.h>

#include "erdma.h"
#include "erdma_hw.h"

#define ERDMA_MAX_SEND_SGE 6
#define ERDMA_MAX_RECV_SGE 1

struct erdma_queue {
	void *qbuf;
	void *db;

	uint16_t rsvd0;
	uint16_t depth;
	uint32_t size;

	uint16_t pi;
	uint16_t ci;

	uint32_t rsvd1;
	uint64_t *wr_tbl;

	void *db_record;
};

struct erdma_qp {
	struct ibv_qp base_qp;
	struct erdma_device *erdma_dev;

	uint32_t id; /* qpn */

	pthread_spinlock_t sq_lock;
	pthread_spinlock_t rq_lock;

	int sq_sig_all;

	struct erdma_queue sq;
	struct erdma_queue rq;

	void *qbuf;
	size_t qbuf_size;
	uint64_t *db_records;
};

struct erdma_cq {
	struct ibv_cq base_cq;
	struct erdma_device *erdma_dev;
	uint32_t id;

	uint32_t event_stats;

	uint32_t depth;
	uint32_t ci;
	struct erdma_cqe *queue;

	void *db;
	uint16_t db_offset;

	void *db_record;
	uint32_t cmdsn;
	uint32_t comp_vector;
	uint32_t db_index;

	pthread_spinlock_t lock;
};

static inline struct erdma_qp *to_eqp(struct ibv_qp *base)
{
	return container_of(base, struct erdma_qp, base_qp);
}

static inline struct erdma_cq *to_ecq(struct ibv_cq *base)
{
	return container_of(base, struct erdma_cq, base_cq);
}

static inline void *get_sq_wqebb(struct erdma_qp *qp, uint16_t idx)
{
	idx &= (qp->sq.depth - 1);
	return qp->sq.qbuf + (idx << SQEBB_SHIFT);
}

static inline void __kick_sq_db(struct erdma_qp *qp, uint16_t pi)
{
	uint64_t db_data;

	db_data = FIELD_PREP(ERDMA_SQE_HDR_QPN_MASK, qp->id) |
		  FIELD_PREP(ERDMA_SQE_HDR_WQEBB_INDEX_MASK, pi);

	*(__le64 *)qp->sq.db_record = htole64(db_data);
	udma_to_device_barrier();
	mmio_write64_le(qp->sq.db, htole64(db_data));
}

struct ibv_pd *erdma_alloc_pd(struct ibv_context *ctx);
int erdma_free_pd(struct ibv_pd *pd);

int erdma_query_device(struct ibv_context *ctx,
		       const struct ibv_query_device_ex_input *input,
		       struct ibv_device_attr_ex *attr, size_t attr_size);
int erdma_query_port(struct ibv_context *ctx, uint8_t port,
		     struct ibv_port_attr *attr);

struct ibv_mr *erdma_reg_mr(struct ibv_pd *pd, void *addr, size_t len,
			    uint64_t hca_va, int access);
int erdma_dereg_mr(struct verbs_mr *vmr);

struct ibv_qp *erdma_create_qp(struct ibv_pd *pd,
			       struct ibv_qp_init_attr *attr);
int erdma_modify_qp(struct ibv_qp *base_qp, struct ibv_qp_attr *attr,
		    int attr_mask);
int erdma_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		   struct ibv_qp_init_attr *init_attr);
int erdma_post_send(struct ibv_qp *base_qp, struct ibv_send_wr *wr,
		    struct ibv_send_wr **bad_wr);
int erdma_post_recv(struct ibv_qp *base_qp, struct ibv_recv_wr *wr,
		    struct ibv_recv_wr **bad_wr);
int erdma_destroy_qp(struct ibv_qp *base_qp);

void erdma_free_context(struct ibv_context *ibv_ctx);

struct ibv_cq *erdma_create_cq(struct ibv_context *ctx, int num_cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector);
int erdma_destroy_cq(struct ibv_cq *base_cq);
int erdma_notify_cq(struct ibv_cq *ibcq, int solicited);
void erdma_cq_event(struct ibv_cq *ibcq);
int erdma_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc);

#endif
