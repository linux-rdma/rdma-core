/*
 * Copyright (c) 2015-2016  QLogic Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
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
 *        disclaimer in the documentation and /or other materials
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
 */

#ifndef __QELR_H__
#define __QELR_H__

#include <inttypes.h>
#include <stddef.h>
#include <endian.h>
#include <stdio.h>
#include <endian.h>
#include <ccan/minmax.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>

#define writel(b, p) (*(uint32_t *)(p) = (b))
#define writeq(b, p) (*(uint64_t *)(p) = (b))

#include "qelr_abi.h"
#include "qelr_hsi.h"
#include "qelr_chain.h"

#define qelr_err(format, arg...) printf(format, ##arg)

extern uint32_t qelr_dp_level;
extern uint32_t qelr_dp_module;

enum DP_MODULE {
	QELR_MSG_CQ		= 0x10000,
	QELR_MSG_RQ		= 0x20000,
	QELR_MSG_SQ		= 0x40000,
	QELR_MSG_QP		= (QELR_MSG_SQ | QELR_MSG_RQ),
	QELR_MSG_MR		= 0x80000,
	QELR_MSG_INIT		= 0x100000,
	QELR_MSG_SRQ		= 0x200000,
	/* to be added...up to 0x8000000 */
};

enum DP_LEVEL {
	QELR_LEVEL_VERBOSE	= 0x0,
	QELR_LEVEL_INFO		= 0x1,
	QELR_LEVEL_NOTICE	= 0x2,
	QELR_LEVEL_ERR		= 0x3,
};

#define DP_ERR(fd, fmt, ...)					\
do {								\
	fprintf(fd, "[%s:%d]" fmt,				\
		__func__, __LINE__,				\
		##__VA_ARGS__);					\
	fflush(fd); \
} while (0)

#define DP_NOTICE(fd, fmt, ...)					\
do {								\
	if (qelr_dp_level <= QELR_LEVEL_NOTICE)	{\
		fprintf(fd, "[%s:%d]" fmt,			\
		      __func__, __LINE__,			\
		      ##__VA_ARGS__);				\
		      fflush(fd); }				\
} while (0)

#define DP_INFO(fd, fmt, ...)					\
do {								\
	if (qelr_dp_level <= QELR_LEVEL_INFO)	{		\
		fprintf(fd, "[%s:%d]" fmt,			\
		      __func__, __LINE__,			\
		      ##__VA_ARGS__); fflush(fd);		\
	}							\
} while (0)

#define DP_VERBOSE(fd, module, fmt, ...)			\
do {								\
	if ((qelr_dp_level <= QELR_LEVEL_VERBOSE) &&		\
		     (qelr_dp_module & (module))) {		\
		fprintf(fd, "[%s:%d]" fmt,			\
		      __func__, __LINE__,			\
		      ##__VA_ARGS__);	fflush(fd); }		\
} while (0)

struct qelr_buf {
	void		*addr;
	size_t		len;		/* a 64 uint is used as s preparation
					 * for double layer pbl.
					 */
};

#define IS_IWARP(_dev)		(_dev->node_type == IBV_NODE_RNIC)
#define IS_ROCE(_dev)		(_dev->node_type == IBV_NODE_CA)

struct qelr_device {
	struct verbs_device ibv_dev;
};

enum qelr_dpm_flags {
	QELR_DPM_FLAGS_ENHANCED = (1 << 0),
	QELR_DPM_FLAGS_LEGACY	= (1 << 1),
};

struct qelr_devctx {
	struct verbs_context	ibv_ctx;
	FILE			*dbg_fp;
	void			*db_addr;
	uint64_t		db_pa;
	struct qedr_user_db_rec	db_rec_addr_dummy;
	uint32_t		db_size;
	enum qelr_dpm_flags	dpm_flags;
	uint32_t		kernel_page_size;
	uint16_t		ldpm_limit_size;
	uint8_t			edpm_trans_size;

	uint32_t		max_send_wr;
	uint32_t		max_recv_wr;
	uint32_t		max_srq_wr;
	uint32_t		sges_per_send_wr;
	uint32_t		sges_per_recv_wr;
	uint32_t		sges_per_srq_wr;
	int			max_cqes;
};

struct qelr_pd {
	struct ibv_pd		ibv_pd;
	uint32_t		pd_id;
};

struct qelr_mr {
	struct verbs_mr		vmr;
};

union db_prod64 {
	struct rdma_pwm_val32_data data;
	uint64_t raw;
};

struct qelr_cq {
	struct ibv_cq		ibv_cq;	/* must be first */

	struct qelr_chain	chain;

	void			*db_addr;
	union db_prod64		db;
	/* Doorbell recovery entry address */
	void			*db_rec_map;
	struct qedr_user_db_rec *db_rec_addr;

	uint8_t			chain_toggle;
	union rdma_cqe		*latest_cqe;
	union rdma_cqe		*toggle_cqe;

	uint8_t			arm_flags;
};

enum qelr_qp_state {
	QELR_QPS_RST,
	QELR_QPS_INIT,
	QELR_QPS_RTR,
	QELR_QPS_RTS,
	QELR_QPS_SQD,
	QELR_QPS_ERR,
	QELR_QPS_SQE
};

union db_prod32 {
	struct rdma_pwm_val16_data	data;
	uint32_t			raw;
};

struct qelr_qp_hwq_info {
	/* WQE */
	struct qelr_chain			chain;
	uint8_t					max_sges;

	/* WQ */
	uint16_t				prod;
	uint16_t				wqe_cons;
	uint16_t				cons;
	uint16_t				max_wr;

	/* DB */
	void					*db;      /* Doorbell address */
	void					*edpm_db;
	union db_prod32				db_data;  /* Doorbell data */
	/* Doorbell recovery entry address */
	void					*db_rec_map;
	struct qedr_user_db_rec			*db_rec_addr;
	void					*iwarp_db2;
	union db_prod32				iwarp_db2_data;

	uint16_t				icid;
};

struct qelr_rdma_ext {
	__be64	remote_va;
	__be32	remote_key;
	__be32	dma_length;
};

/* rdma extension, invalidate / immediate data + padding, inline data... */
#define QELR_MAX_DPM_PAYLOAD (sizeof(struct qelr_rdma_ext) + sizeof(uint64_t) +\
			       ROCE_REQ_MAX_INLINE_DATA_SIZE)
struct qelr_dpm {
	uint8_t			is_edpm;
	uint8_t			is_ldpm;
	union {
		struct db_roce_dpm_data	data;
		uint64_t raw;
	} msg;

	uint8_t			payload[QELR_MAX_DPM_PAYLOAD];
	uint32_t		payload_size;
	uint32_t		payload_offset;

	struct qelr_rdma_ext    *rdma_ext;
};

struct qelr_srq_hwq_info {
	uint32_t max_sges;
	uint32_t max_wr;
	struct qelr_chain chain;
	uint32_t wqe_prod;     /* WQE prod index in HW ring */
	uint32_t sge_prod;     /* SGE prod index in HW ring */
	uint32_t wr_prod_cnt;  /* wr producer count */
	uint32_t wr_cons_cnt;  /* wr consumer count */
	uint32_t num_elems;

	void  *virt_prod_pair_addr;  /* producer pair virtual address */
};

struct qelr_srq {
	struct ibv_srq ibv_srq;
	struct qelr_srq_hwq_info hw_srq;
	uint16_t srq_id;
	pthread_spinlock_t lock;
};

struct qelr_qp {
	struct ibv_qp				ibv_qp;
	pthread_spinlock_t			q_lock;
	enum qelr_qp_state			state;   /*  QP state */

	struct qelr_qp_hwq_info			sq;
	struct qelr_qp_hwq_info			rq;
	struct {
		uint64_t wr_id;
		enum ibv_wc_opcode opcode;
		uint32_t bytes_len;
		uint8_t wqe_size;
		uint8_t signaled;
	} *wqe_wr_id;

	struct {
		uint64_t wr_id;
		uint8_t wqe_size;
	} *rqe_wr_id;

	uint8_t					prev_wqe_size;
	uint32_t				max_inline_data;
	uint32_t				qp_id;
	int					sq_sig_all;
	int					atomic_supported;
	uint8_t					edpm_disabled;
	struct qelr_srq				*srq;
};

static inline struct qelr_devctx *get_qelr_ctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct qelr_devctx, ibv_ctx.context);
}

static inline struct qelr_device *get_qelr_dev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct qelr_device, ibv_dev.device);
}

static inline struct qelr_qp *get_qelr_qp(struct ibv_qp *ibqp)
{
	return container_of(ibqp, struct qelr_qp, ibv_qp);
}

static inline struct qelr_pd *get_qelr_pd(struct ibv_pd *ibpd)
{
	return container_of(ibpd, struct qelr_pd, ibv_pd);
}

static inline struct qelr_cq *get_qelr_cq(struct ibv_cq *ibcq)
{
	return container_of(ibcq, struct qelr_cq, ibv_cq);
}

static inline struct qelr_srq *get_qelr_srq(struct ibv_srq *ibsrq)
{
	return container_of(ibsrq, struct qelr_srq, ibv_srq);
}

#define SET_FIELD(value, name, flag)				\
	do {							\
		(value) &= ~(name ## _MASK << name ## _SHIFT);	\
		(value) |= ((flag) << (name ## _SHIFT));	\
	} while (0)

#define SET_FIELD2(value, name, flag)				\
		((value) |= ((flag) << (name ## _SHIFT)))

#define GET_FIELD(value, name) \
	(((value) >> (name ## _SHIFT)) & name ## _MASK)

#define ROCE_WQE_ELEM_SIZE	sizeof(struct rdma_sq_sge)
#define RDMA_WQE_BYTES		(16)

#define QELR_RESP_IMM (RDMA_CQE_RESPONDER_IMM_FLG_MASK <<	\
			RDMA_CQE_RESPONDER_IMM_FLG_SHIFT)
#define QELR_RESP_INV	(RDMA_CQE_RESPONDER_INV_FLG_MASK << \
			 RDMA_CQE_RESPONDER_INV_FLG_SHIFT)
#define QELR_RESP_RDMA (RDMA_CQE_RESPONDER_RDMA_FLG_MASK <<	\
			RDMA_CQE_RESPONDER_RDMA_FLG_SHIFT)
#define QELR_RESP_RDMA_IMM (QELR_RESP_IMM | QELR_RESP_RDMA)

#define TYPEPTR_ADDR_SET(type_ptr, field, vaddr)			\
	do {								\
		(type_ptr)->field.hi = htole32(U64_HI(vaddr));	\
		(type_ptr)->field.lo = htole32(U64_LO(vaddr));	\
	} while (0)

#define RQ_SGE_SET(sge, vaddr, vlength, vflags)			\
	do {							\
		TYPEPTR_ADDR_SET(sge, addr, vaddr);		\
		(sge)->length = htole32(vlength);		\
		(sge)->flags = htole32(vflags);		\
	} while (0)

#define SRQ_HDR_SET(hdr, vwr_id, num_sge)			\
	do {							\
		TYPEPTR_ADDR_SET(hdr, wr_id, vwr_id);		\
		(hdr)->num_sges = num_sge;			\
	} while (0)

#define SRQ_SGE_SET(sge, vaddr, vlength, vlkey)			\
	do {							\
		TYPEPTR_ADDR_SET(sge, addr, vaddr);		\
		(sge)->length = htole32(vlength);		\
		(sge)->l_key = htole32(vlkey);		\
	} while (0)

#define U64_HI(val) ((uint32_t)(((uint64_t)(uintptr_t)(val)) >> 32))
#define U64_LO(val) ((uint32_t)(((uint64_t)(uintptr_t)(val)) & 0xffffffff))
#define HILO_U64(hi, lo) ((uintptr_t)((((uint64_t)(hi)) << 32) + (lo)))

#define QELR_MAX_RQ_WQE_SIZE (RDMA_MAX_SGE_PER_RQ_WQE)
#define QELR_MAX_SQ_WQE_SIZE (ROCE_REQ_MAX_SINGLE_SQ_WQE_SIZE /	\
			      ROCE_WQE_ELEM_SIZE)

#endif /* __QELR_H__ */
