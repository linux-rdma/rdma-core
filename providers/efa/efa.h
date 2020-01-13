/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef __EFA_H__
#define __EFA_H__

#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>

#include "efa-abi.h"
#include "efa_io_defs.h"

struct efa_context {
	struct verbs_context ibvctx;
	uint32_t cmds_supp_udata_mask;
	uint16_t sub_cqs_per_cq;
	uint16_t inline_buf_size;
	uint32_t max_llq_size;
	size_t cqe_size;
	struct efa_qp **qp_table;
	unsigned int qp_table_sz_m1;
	pthread_spinlock_t qp_table_lock;
};

struct efa_pd {
	struct ibv_pd ibvpd;
	uint16_t pdn;
};

struct efa_sub_cq {
	uint16_t consumed_cnt;
	int phase;
	uint8_t *buf;
	int qmask;
	int cqe_size;
	uint32_t ref_cnt;
};

struct efa_cq {
	struct ibv_cq ibvcq;
	uint32_t cqn;
	size_t cqe_size;
	uint8_t *buf;
	size_t buf_size;
	uint16_t num_sub_cqs;
	/* Index of next sub cq idx to poll. This is used to guarantee fairness for sub cqs */
	uint16_t next_poll_idx;
	pthread_spinlock_t lock;
	struct efa_sub_cq sub_cq_arr[0];
};

struct efa_wq {
	uint64_t *wrid;
	/* wrid_idx_pool: Pool of free indexes in the wrid array, used to select the
	 * wrid entry to be used to hold the next tx packet's context.
	 * At init time, entry N will hold value N, as OOO tx-completions arrive,
	 * the value stored in a given entry might not equal the entry's index.
	 */
	uint32_t *wrid_idx_pool;
	uint32_t wqe_cnt;
	uint32_t wqe_posted;
	uint32_t wqe_completed;
	uint16_t desc_idx;
	uint16_t desc_mask;
	/* wrid_idx_pool_next: Index of the next entry to use in wrid_idx_pool. */
	uint16_t wrid_idx_pool_next;
	int max_sge;
	int phase;
	pthread_spinlock_t wqlock;
};

struct efa_rq {
	struct efa_wq wq;
	uint32_t *db;
	uint8_t *buf;
	size_t buf_size;
	uint16_t sub_cq_idx;
};

struct efa_sq {
	struct efa_wq wq;
	uint32_t *db;
	uint8_t *desc;
	uint32_t desc_offset;
	size_t desc_ring_mmap_size;
	size_t max_inline_data;
	size_t max_wr_rdma_sge;
	uint16_t sub_cq_idx;

	/* Buffer for pending WR entries in the current session */
	uint8_t *local_queue;
	/* Number of WR entries posted in the current session */
	uint32_t num_wqe_pending;
	/* Phase before current session */
	int phase_rb;
	/* Current wqe being built */
	struct efa_io_tx_wqe *curr_tx_wqe;
};

struct efa_qp {
	struct verbs_qp verbs_qp;
	struct efa_sq sq;
	struct efa_rq rq;
	int page_size;
	struct efa_cq *rcq;
	struct efa_cq *scq;
	int sq_sig_all;
	int wr_session_err;
};

struct efa_mr {
	struct verbs_mr vmr;
};

struct efa_ah {
	struct ibv_ah ibvah;
	uint16_t efa_ah;
};

struct efa_dev {
	struct verbs_device vdev;
	uint32_t pg_sz;
	uint32_t device_caps;
	uint32_t max_sq_wr;
	uint32_t max_rq_wr;
	uint16_t max_sq_sge;
	uint16_t max_rq_sge;
	uint32_t max_rdma_size;
	uint16_t max_wr_rdma_sge;
};

static inline bool is_rdma_read_cap(struct efa_dev *dev)
{
	return dev->device_caps & EFA_QUERY_DEVICE_CAPS_RDMA_READ;
}

static inline struct efa_dev *to_efa_dev(struct ibv_device *ibvdev)
{
	return container_of(ibvdev, struct efa_dev, vdev.device);
}

static inline struct efa_context *to_efa_context(struct ibv_context *ibvctx)
{
	return container_of(ibvctx, struct efa_context, ibvctx.context);
}

static inline struct efa_pd *to_efa_pd(struct ibv_pd *ibvpd)
{
	return container_of(ibvpd, struct efa_pd, ibvpd);
}

static inline struct efa_cq *to_efa_cq(struct ibv_cq *ibvcq)
{
	return container_of(ibvcq, struct efa_cq, ibvcq);
}

static inline struct efa_qp *to_efa_qp(struct ibv_qp *ibvqp)
{
	return container_of(ibvqp, struct efa_qp, verbs_qp.qp);
}

static inline struct efa_qp *to_efa_qp_ex(struct ibv_qp_ex *ibvqpx)
{
	return container_of(ibvqpx, struct efa_qp, verbs_qp.qp_ex);
}

static inline struct efa_ah *to_efa_ah(struct ibv_ah *ibvah)
{
	return container_of(ibvah, struct efa_ah, ibvah);
}

bool is_efa_dev(struct ibv_device *device);

#endif /* __EFA_H__ */
