/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#ifndef IONIC_H
#define IONIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <endian.h>
#include <pthread.h>

#include <infiniband/driver.h>
#include <infiniband/verbs.h>
#include <util/udma_barrier.h>
#include <ccan/list.h>

#include "ionic-abi.h"

#include "ionic_memory.h"
#include "ionic_queue.h"
#include "ionic_table.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>

#define IONIC_MIN_RDMA_VERSION	1
#define IONIC_MAX_RDMA_VERSION	2

#define IONIC_META_LAST ((void *)1ul)
#define IONIC_META_POSTED ((void *)2ul)

#define IONIC_CQ_GRACE 100
#define IONIC_PAGE_SIZE 4096

#define IONIC_QUEUE_DEPTH_MAX 0xFFFF
#define IONIC_QUEUE_STRIDE_MAX 0x10000

/** IONIC_PD_TAG - tag used for parent domain resource allocation. */
#define IONIC_PD_TAG	((uint64_t)RDMA_DRIVER_IONIC << 32)
#define IONIC_PD_TAG_CQ	(IONIC_PD_TAG | 1)
#define IONIC_PD_TAG_SQ	(IONIC_PD_TAG | 2)
#define IONIC_PD_TAG_RQ	(IONIC_PD_TAG | 3)

enum {
	IONIC_CQ_SUPPORTED_WC_FLAGS =
	    IBV_WC_EX_WITH_BYTE_LEN       |
	    IBV_WC_EX_WITH_IMM            |
	    IBV_WC_EX_WITH_QP_NUM         |
	    IBV_WC_EX_WITH_SRC_QP         |
	    IBV_WC_EX_WITH_SLID           |
	    IBV_WC_EX_WITH_SL             |
	    IBV_WC_EX_WITH_DLID_PATH_BITS
};

struct ionic_ctx {
	struct verbs_context	vctx;

	int			spec;
	uint32_t		pg_shift;

	int			version;
	uint8_t			opcodes;

	uint8_t			sq_qtype;
	uint8_t			rq_qtype;
	uint8_t			cq_qtype;

	uint8_t			max_stride;

	uint8_t			udma_count;
	uint8_t			expdb_mask;
	bool			sq_expdb;
	bool			rq_expdb;

	void			*dbpage_page;
	uint64_t		*dbpage;

	pthread_mutex_t		mut;
	struct ionic_tbl_root	qp_tbl;

	FILE			*dbg_file;
};

struct ionic_pd {
	struct ibv_pd		ibpd;
	struct ibv_pd		*root_ibpd;

	uint8_t			udma_mask;
	uint8_t			sq_cmb;
	uint8_t			rq_cmb;

	void *(*alloc)(struct ibv_pd *pd, void *pd_context, size_t size,
		       size_t alignment, uint64_t resource_type);
	void (*free)(struct ibv_pd *pd, void *pd_context, void *ptr,
		     uint64_t resource_type);
	void *pd_context;
};

struct ionic_cq {
	struct ionic_vcq	*vcq;

	uint32_t		cqid;

	pthread_spinlock_t	lock;
	unsigned long		cqseq;

	struct list_head	poll_sq;
	struct list_head	poll_rq;
	bool			flush;
	struct list_head	flush_sq;
	struct list_head	flush_rq;
	struct ionic_queue	q;
	bool			color;
	bool			deferred_arm;
	bool			deferred_arm_sol_only;
	bool			lockfree;
	int			reserve;
	int			reserve_pending;
	uint16_t		arm_any_prod;
	uint16_t		arm_sol_prod;
};

struct ionic_vcq {
	struct verbs_cq		vcq;
	struct ionic_cq		cq[2];
	uint8_t			udma_mask;
	uint8_t			poll_idx;
	struct ibv_wc		cur_wc; /* for use with start_poll/next_poll */
};

struct ionic_sq_meta {
	uint64_t		wrid;
	uint32_t		len;
	uint16_t		seq;
	uint8_t			ibop;
	uint8_t			ibsts;
	bool			remote;
	bool			signal;
	bool			local_comp;
};

struct ionic_rq_meta {
	struct ionic_rq_meta	*next;
	uint64_t		wrid;
};

struct ionic_rq {
	pthread_spinlock_t	lock;
	struct ionic_queue	queue;

	void			*cmb_ptr;
	struct ionic_rq_meta	*meta;
	struct ionic_rq_meta	*meta_head;
	uint16_t		*meta_idx;

	int			spec;
	uint16_t		old_prod;
	uint16_t		cmb_prod;
	uint8_t			cmb;
	bool			flush;
};

struct ionic_sq {
	pthread_spinlock_t	lock;
	struct ionic_queue	queue;

	void			*cmb_ptr;
	struct ionic_sq_meta	*meta;
	uint16_t		*msn_idx;

	int			spec;
	uint16_t		old_prod;
	uint16_t		msn_prod;
	uint16_t		msn_cons;
	uint16_t		cmb_prod;
	uint8_t			cmb;

	bool			flush;
	bool			flush_rcvd;
	bool			color;
};

struct ionic_qp {
	struct verbs_qp		vqp;

	uint32_t		qpid;
	uint8_t			udma_idx;
	bool			has_sq;
	bool			has_rq;
	bool			lockfree;

	struct list_node	cq_poll_sq;
	struct list_node	cq_poll_rq;
	struct list_node	cq_flush_sq;
	struct list_node	cq_flush_rq;

	struct ionic_sq		sq;
	struct ionic_rq		rq;
};

struct ionic_ah {
	struct ibv_ah		ibah;
	uint32_t		ahid;
};

struct ionic_dev {
	struct verbs_device	vdev;
	int			abi_ver;
};

bool is_ionic_ctx(struct ibv_context *ibctx);

static inline bool is_ionic_pd(struct ibv_pd *ibpd)
{
	return is_ionic_ctx(ibpd->context);
}

static inline bool is_ionic_cq(struct ibv_cq *ibcq)
{
	return is_ionic_ctx(ibcq->context);
}

static inline bool is_ionic_qp(struct ibv_qp *ibqp)
{
	return is_ionic_ctx(ibqp->context);
}

static inline struct ionic_dev *to_ionic_dev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct ionic_dev, vdev.device);
}

static inline struct ionic_ctx *to_ionic_ctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct ionic_ctx, vctx.context);
}

static inline struct ionic_pd *to_ionic_pd(struct ibv_pd *ibpd)
{
	return container_of(ibpd, struct ionic_pd, ibpd);
}

static inline struct ibv_pd *ionic_root_ibpd(struct ionic_pd *pd)
{
	return pd->root_ibpd;
}

static inline struct ibv_pd *to_ionic_root_ibpd(struct ibv_pd *ibpd)
{
	return ionic_root_ibpd(to_ionic_pd(ibpd));
}

static inline struct ionic_vcq *to_ionic_vcq_ex(struct ibv_cq_ex *ibcq)
{
	return container_of(ibcq, struct ionic_vcq, vcq.cq_ex);
}

static inline struct ionic_vcq *to_ionic_vcq(struct ibv_cq *ibcq)
{
	return container_of(ibcq, struct ionic_vcq, vcq.cq);
}

static inline struct ionic_cq *to_ionic_vcq_cq(struct ibv_cq *ibcq,
					       uint8_t udma_idx)
{
	return &to_ionic_vcq(ibcq)->cq[udma_idx];
}

static inline struct ionic_qp *to_ionic_qp(struct ibv_qp *ibqp)
{
	return container_of(ibqp, struct ionic_qp, vqp.qp);
}

static inline struct ionic_ah *to_ionic_ah(struct ibv_ah *ibah)
{
	return container_of(ibah, struct ionic_ah, ibah);
}

static inline bool ionic_ibop_is_local(enum ibv_wr_opcode op)
{
	return op == IBV_WR_LOCAL_INV || op == IBV_WR_BIND_MW;
}

static inline uint8_t ionic_ctx_udma_mask(struct ionic_ctx *ctx)
{
	return BIT(ctx->udma_count) - 1;
}

static inline void ionic_dbg_xdump(struct ionic_ctx *ctx, const char *str,
				   const void *ptr, size_t size)
{
	const uint8_t *ptr8 = ptr;
	int i;

	for (i = 0; i < size; i += 8)
		verbs_debug(&ctx->vctx,
			    "%s: %02x %02x %02x %02x %02x %02x %02x %02x", str,
			    ptr8[i + 0], ptr8[i + 1], ptr8[i + 2], ptr8[i + 3],
			    ptr8[i + 4], ptr8[i + 5], ptr8[i + 6], ptr8[i + 7]);
}

/* ionic_verbs.h */
void ionic_verbs_set_ops(struct ionic_ctx *ctx);

#endif /* IONIC_H */
