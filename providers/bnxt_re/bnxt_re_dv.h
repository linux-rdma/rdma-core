/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2026, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#ifndef __BNXT_RE_DV_H__
#define __BNXT_RE_DV_H__

#include <stdint.h>
#include <infiniband/verbs.h>
#ifdef __cplusplus
extern "C" {
#endif

struct bnxt_re_dv_db_region_attr {
	uint32_t handle;
	uint32_t dpi;
	uint64_t *dbr;
};

struct bnxt_re_dv_cq_init_attr {
	struct ibv_buf *umem_handle;	/* handle from ibv_alloc_user_buf() */
	uint64_t umem_offset;		/* offset into umem_handle */
	uint32_t ncqe;			/* num cq entries */
};

struct bnxt_re_dv_qp_init_attr {
	/* Standard ibv params */
	enum ibv_qp_type qp_type;
	uint32_t max_send_wr;
	uint32_t max_recv_wr;
	uint32_t max_send_sge;
	uint32_t max_recv_sge;
	uint32_t max_inline_data;
	struct ibv_cq *send_cq;
	struct ibv_cq *recv_cq;
	struct ibv_srq *srq;

	/* DV params */
	uint64_t qp_handle;	/* to match with cqe */
	void *dbr_handle;	/* dbr_handle from alloc_dbr */
	struct ibv_buf *sq_umem_handle;	/* handle from ibv_alloc_user_buf() */
	uint64_t sq_umem_offset;	/* offset into umem */
	uint32_t sq_len;	/* sq length including MSN area */
	uint32_t sq_slots;	/* sq length in slots */
	struct ibv_buf *rq_umem_handle;	/* handle from ibv_alloc_user_buf() */
	uint64_t rq_umem_offset;	/* offset into umem */
	uint32_t sq_npsn;       /* sq num psn entries */
	uint32_t rq_len;	/* rq length */
	uint64_t comp_mask;	/* compatibility mask for future updates */
};

struct bnxt_re_dv_db_region_attr *
bnxt_re_dv_alloc_db_region(struct ibv_context *ctx);
int bnxt_re_dv_free_db_region(struct ibv_context *ctx,
			      struct bnxt_re_dv_db_region_attr *attr);
int bnxt_re_dv_get_default_db_region(struct ibv_context *ibvctx,
				     struct bnxt_re_dv_db_region_attr *out);
struct ibv_cq *bnxt_re_dv_create_cq(struct ibv_context *ibvctx,
				    struct bnxt_re_dv_cq_init_attr *cq_attr);
struct ibv_qp *bnxt_re_dv_create_qp(struct ibv_pd *pd,
				    struct bnxt_re_dv_qp_init_attr *qp_attr);
#ifdef __cplusplus
}
#endif
#endif /* __BNXT_RE_DV_H__ */
