/*
 * Copyright (C) 2008-2013 Emulex.  All rights reserved.
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __OCRDMA_MAIN_H__
#define __OCRDMA_MAIN_H__

#include <inttypes.h>
#include <stddef.h>
#include <endian.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>

#include <ccan/list.h>

#define ocrdma_err(format, arg...) printf(format, ##arg)

#define OCRDMA_DPP_PAGE_SIZE (4096)

#define ROUND_UP_X(_val, _x) \
    (((unsigned long)(_val) + ((_x)-1)) & (long)~((_x)-1))

struct ocrdma_qp;

struct ocrdma_device {
	struct verbs_device ibv_dev;
	struct ocrdma_qp **qp_tbl;
	pthread_mutex_t dev_lock;
	pthread_spinlock_t flush_q_lock;
	int id;
	int gen;
	uint32_t wqe_size;
	uint32_t rqe_size;
	uint32_t dpp_wqe_size;
	uint32_t max_inline_data;
	uint8_t fw_ver[32];
};

struct ocrdma_devctx {
	struct verbs_context ibv_ctx;
	uint32_t *ah_tbl;
	uint32_t ah_tbl_len;
	pthread_mutex_t tbl_lock;
};

struct ocrdma_pd {
	struct ibv_pd ibv_pd;
	struct ocrdma_device *dev;
	struct ocrdma_devctx *uctx;
	void *dpp_va;
};

struct ocrdma_mr {
	struct verbs_mr vmr;
};

struct ocrdma_cq {
	struct ibv_cq ibv_cq;
	struct ocrdma_device *dev;
	uint16_t cq_id;
	uint16_t cq_dbid;
	uint16_t getp;
	pthread_spinlock_t cq_lock;
	uint32_t max_hw_cqe;
	uint32_t cq_mem_size;
	struct ocrdma_cqe *va;
	void *db_va;

	uint32_t db_size;

	uint32_t phase;
	int phase_change;

	uint8_t deferred_arm;
	uint8_t deferred_sol;
	uint8_t first_arm;
	struct list_head sq_head;
	struct list_head rq_head;
};

enum {
	OCRDMA_DPP_WQE_INDEX_MASK	= 0xFFFF,
	OCRDMA_DPP_CQE_VALID_BIT_SHIFT	= 31,
	OCRDMA_DPP_CQE_VALID_BIT_MASK	= 1 << 31
};

struct ocrdma_dpp_cqe {
	uint32_t wqe_idx_valid;
};

enum {
	OCRDMA_PD_MAX_DPP_ENABLED_QP = 16
};

struct ocrdma_qp_hwq_info {
	uint8_t *va;		/* virtual address */
	uint32_t max_sges;
	uint32_t free_cnt;

	uint32_t head, tail;
	uint32_t entry_size;
	uint32_t max_cnt;
	uint32_t max_wqe_idx;
	uint32_t len;
	uint16_t dbid;		/* qid, where to ring the doorbell. */
};

struct ocrdma_srq {
	struct ibv_srq ibv_srq;
	struct ocrdma_device *dev;
	void *db_va;
	uint32_t db_size;
	pthread_spinlock_t q_lock;

	struct ocrdma_qp_hwq_info rq;
	uint32_t max_rq_sges;
	uint32_t id;
	uint64_t *rqe_wr_id_tbl;
	uint32_t *idx_bit_fields;
	uint32_t bit_fields_len;
	uint32_t db_shift;
};

enum {
	OCRDMA_CREATE_QP_REQ_DPP_CREDIT_LIMIT = 1
};

enum ocrdma_qp_state {
	OCRDMA_QPS_RST 		= 0,
	OCRDMA_QPS_INIT 	= 1,
	OCRDMA_QPS_RTR 		= 2,
	OCRDMA_QPS_RTS 		= 3,
	OCRDMA_QPS_SQE 		= 4,
	OCRDMA_QPS_SQ_DRAINING 	= 5,
	OCRDMA_QPS_ERR 		= 6,
	OCRDMA_QPS_SQD 		= 7
};

struct ocrdma_qp {
	struct ibv_qp ibv_qp;
	struct ocrdma_device *dev;
	pthread_spinlock_t q_lock;

	struct ocrdma_qp_hwq_info sq;
	struct ocrdma_cq *sq_cq;
	struct {
		uint64_t wrid;
		uint16_t dpp_wqe_idx;
		uint16_t dpp_wqe;
		uint8_t  signaled;
		uint8_t  rsvd[3];
	} *wqe_wr_id_tbl;
	struct ocrdma_qp_hwq_info dpp_q;
	int dpp_enabled;

	struct ocrdma_qp_hwq_info rq;
	struct ocrdma_cq *rq_cq;
	uint64_t *rqe_wr_id_tbl;
	void *db_va;
	void *db_sq_va;
	void *db_rq_va;
	uint32_t max_inline_data;

	struct ocrdma_srq *srq;
	struct ocrdma_cq *dpp_cq;

	uint32_t db_size;
	uint32_t max_ord;
	uint32_t max_ird;
	uint32_t dpp_prev_indx;

	enum ibv_qp_type qp_type;
	enum ocrdma_qp_state state;
	struct list_node sq_entry;
	struct list_node rq_entry;
	uint16_t id;
	uint16_t rsvd;
	uint32_t db_shift;
	int	signaled;	/* signaled QP */
};

enum {
	OCRDMA_AH_ID_MASK               = 0x3FF,
	OCRDMA_AH_VLAN_VALID_MASK       = 0x01,
	OCRDMA_AH_VLAN_VALID_SHIFT      = 0x1F,
	OCRDMA_AH_L3_TYPE_MASK		= 0x03,
	OCRDMA_AH_L3_TYPE_SHIFT		= 0x1D
};

struct ocrdma_ah {
	struct ibv_ah ibv_ah;
	struct ocrdma_pd *pd;
	uint16_t id;
	uint8_t isvlan;
	uint8_t hdr_type;
};

#define get_ocrdma_xxx(xxx, type)                                              \
	container_of(ib##xxx, struct ocrdma_##type, ibv_##xxx)

static inline struct ocrdma_devctx *get_ocrdma_ctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct ocrdma_devctx, ibv_ctx.context);
}

static inline struct ocrdma_device *get_ocrdma_dev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct ocrdma_device, ibv_dev.device);
}

static inline struct ocrdma_qp *get_ocrdma_qp(struct ibv_qp *ibqp)
{
	return get_ocrdma_xxx(qp, qp);
}

static inline struct ocrdma_srq *get_ocrdma_srq(struct ibv_srq *ibsrq)
{
	return get_ocrdma_xxx(srq, srq);
}

static inline struct ocrdma_pd *get_ocrdma_pd(struct ibv_pd *ibpd)
{
	return get_ocrdma_xxx(pd, pd);
}

static inline struct ocrdma_cq *get_ocrdma_cq(struct ibv_cq *ibcq)
{
	return get_ocrdma_xxx(cq, cq);
}

static inline struct ocrdma_ah *get_ocrdma_ah(struct ibv_ah *ibah)
{
	return get_ocrdma_xxx(ah, ah);
}

void ocrdma_init_ahid_tbl(struct ocrdma_devctx *ctx);
int ocrdma_query_device(struct ibv_context *, struct ibv_device_attr *);
int ocrdma_query_port(struct ibv_context *, uint8_t, struct ibv_port_attr *);
struct ibv_pd *ocrdma_alloc_pd(struct ibv_context *);
int ocrdma_free_pd(struct ibv_pd *);
struct ibv_mr *ocrdma_reg_mr(struct ibv_pd *pd, void *addr, size_t len,
			     uint64_t hca_va, int access);
int ocrdma_dereg_mr(struct verbs_mr *vmr);

struct ibv_cq *ocrdma_create_cq(struct ibv_context *, int,
				struct ibv_comp_channel *, int);
int ocrdma_resize_cq(struct ibv_cq *, int);
int ocrdma_destroy_cq(struct ibv_cq *);
int ocrdma_poll_cq(struct ibv_cq *, int, struct ibv_wc *);
int ocrdma_arm_cq(struct ibv_cq *, int);

struct ibv_qp *ocrdma_create_qp(struct ibv_pd *, struct ibv_qp_init_attr *);
int ocrdma_modify_qp(struct ibv_qp *, struct ibv_qp_attr *,
		     int ibv_qp_attr_mask);
int ocrdma_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		    struct ibv_qp_init_attr *init_attr);
int ocrdma_destroy_qp(struct ibv_qp *);
int ocrdma_post_send(struct ibv_qp *, struct ibv_send_wr *,
		     struct ibv_send_wr **);
int ocrdma_post_recv(struct ibv_qp *, struct ibv_recv_wr *,
		     struct ibv_recv_wr **);

struct ibv_srq *ocrdma_create_srq(struct ibv_pd *, struct ibv_srq_init_attr *);
int ocrdma_modify_srq(struct ibv_srq *, struct ibv_srq_attr *, int);
int ocrdma_destroy_srq(struct ibv_srq *);
int ocrdma_query_srq(struct ibv_srq *ibsrq, struct ibv_srq_attr *attr);
int ocrdma_post_srq_recv(struct ibv_srq *, struct ibv_recv_wr *,
			 struct ibv_recv_wr **);
struct ibv_ah *ocrdma_create_ah(struct ibv_pd *, struct ibv_ah_attr *);
int ocrdma_destroy_ah(struct ibv_ah *);
int ocrdma_attach_mcast(struct ibv_qp *, const union ibv_gid *, uint16_t);
int ocrdma_detach_mcast(struct ibv_qp *, const union ibv_gid *, uint16_t);
void ocrdma_async_event(struct ibv_async_event *event);

#endif				/* __OCRDMA_MAIN_H__ */
