/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: Basic device data structures needed for book-keeping
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <endian.h>
#include <pthread.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>

#include "bnxt_re-abi.h"
#include "memory.h"
#include "flush.h"

#define DEV	"bnxt_re : "

#define BNXT_RE_UD_QP_HW_STALL	0x400000

#define CHIP_NUM_57508		0x1750
#define CHIP_NUM_57504		0x1751
#define CHIP_NUM_57502		0x1752

struct bnxt_re_chip_ctx {
	__u16 chip_num;
	__u8 chip_rev;
	__u8 chip_metal;
};

struct bnxt_re_dpi {
	__u32 dpindx;
	__u64 *dbpage;
};

struct bnxt_re_pd {
	struct ibv_pd ibvpd;
	uint32_t pdid;
};

struct bnxt_re_cq {
	struct ibv_cq ibvcq;
	uint32_t cqid;
	struct bnxt_re_queue cqq;
	struct bnxt_re_dpi *udpi;
	struct list_head sfhead;
	struct list_head rfhead;
	uint32_t cqe_size;
	uint8_t  phase;
	int deferred_arm_flags;
	bool first_arm;
	bool deferred_arm;
};

struct bnxt_re_wrid {
	struct bnxt_re_psns_ext *psns_ext;
	struct bnxt_re_psns *psns;
	uint64_t wrid;
	uint32_t bytes;
	int next_idx;
	uint8_t sig;
};

struct bnxt_re_qpcap {
	uint32_t max_swr;
	uint32_t max_rwr;
	uint32_t max_ssge;
	uint32_t max_rsge;
	uint32_t max_inline;
	uint8_t	sqsig;
};

struct bnxt_re_srq {
	struct ibv_srq ibvsrq;
	struct ibv_srq_attr cap;
	struct bnxt_re_queue *srqq;
	struct bnxt_re_wrid *srwrid;
	struct bnxt_re_dpi *udpi;
	uint32_t srqid;
	int start_idx;
	int last_idx;
	bool arm_req;
};

struct bnxt_re_qp {
	struct ibv_qp ibvqp;
	struct bnxt_re_chip_ctx *cctx;
	struct bnxt_re_queue *sqq;
	struct bnxt_re_wrid *swrid;
	struct bnxt_re_queue *rqq;
	struct bnxt_re_wrid *rwrid;
	struct bnxt_re_srq *srq;
	struct bnxt_re_cq *scq;
	struct bnxt_re_cq *rcq;
	struct bnxt_re_dpi *udpi;
	struct bnxt_re_qpcap cap;
	struct bnxt_re_fque_node snode;
	struct bnxt_re_fque_node rnode;
	uint32_t qpid;
	uint32_t tbl_indx;
	uint32_t sq_psn;
	uint32_t pending_db;
	uint64_t wqe_cnt;
	uint16_t mtu;
	uint16_t qpst;
	uint8_t qptyp;
	/* irdord? */
};

struct bnxt_re_mr {
	struct verbs_mr vmr;
};

struct bnxt_re_ah {
	struct ibv_ah ibvah;
	uint32_t avid;
};

struct bnxt_re_dev {
	struct verbs_device vdev;
	uint8_t abi_version;
	uint32_t pg_size;

	uint32_t cqe_size;
	uint32_t max_cq_depth;
};

struct bnxt_re_context {
	struct verbs_context ibvctx;
	uint32_t dev_id;
	uint32_t max_qp;
	struct bnxt_re_chip_ctx cctx;
	uint32_t max_srq;
	struct bnxt_re_dpi udpi;
	void *shpg;
	pthread_mutex_t shlock;
	pthread_spinlock_t fqlock;
};

/* Chip context related functions */
bool bnxt_re_is_chip_gen_p5(struct bnxt_re_chip_ctx *cctx);

/* DB ring functions used internally*/
void bnxt_re_ring_rq_db(struct bnxt_re_qp *qp);
void bnxt_re_ring_sq_db(struct bnxt_re_qp *qp);
void bnxt_re_ring_srq_arm(struct bnxt_re_srq *srq);
void bnxt_re_ring_srq_db(struct bnxt_re_srq *srq);
void bnxt_re_ring_cq_db(struct bnxt_re_cq *cq);
void bnxt_re_ring_cq_arm_db(struct bnxt_re_cq *cq, uint8_t aflag);

/* pointer conversion functions*/
static inline struct bnxt_re_dev *to_bnxt_re_dev(struct ibv_device *ibvdev)
{
	return container_of(ibvdev, struct bnxt_re_dev, vdev.device);
}

static inline struct bnxt_re_context *to_bnxt_re_context(
		struct ibv_context *ibvctx)
{
	return container_of(ibvctx, struct bnxt_re_context, ibvctx.context);
}

static inline struct bnxt_re_pd *to_bnxt_re_pd(struct ibv_pd *ibvpd)
{
	return container_of(ibvpd, struct bnxt_re_pd, ibvpd);
}

static inline struct bnxt_re_cq *to_bnxt_re_cq(struct ibv_cq *ibvcq)
{
	return container_of(ibvcq, struct bnxt_re_cq, ibvcq);
}

static inline struct bnxt_re_qp *to_bnxt_re_qp(struct ibv_qp *ibvqp)
{
	return container_of(ibvqp, struct bnxt_re_qp, ibvqp);
}

static inline struct bnxt_re_srq *to_bnxt_re_srq(struct ibv_srq *ibvsrq)
{
	return container_of(ibvsrq, struct bnxt_re_srq, ibvsrq);
}

static inline struct bnxt_re_ah *to_bnxt_re_ah(struct ibv_ah *ibvah)
{
        return container_of(ibvah, struct bnxt_re_ah, ibvah);
}

static inline uint32_t bnxt_re_get_sqe_sz(void)
{
	return sizeof(struct bnxt_re_bsqe) +
	       sizeof(struct bnxt_re_send) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_sqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_bsqe) + sizeof(struct bnxt_re_send);
}

static inline uint32_t bnxt_re_get_rqe_sz(void)
{
	return sizeof(struct bnxt_re_brqe) +
	       sizeof(struct bnxt_re_rqe) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_rqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_brqe) + sizeof(struct bnxt_re_rqe);
}

static inline uint32_t bnxt_re_get_srqe_sz(void)
{
	return sizeof(struct bnxt_re_brqe) +
	       sizeof(struct bnxt_re_srqe) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_srqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_brqe) + sizeof(struct bnxt_re_srqe);
}

static inline uint32_t bnxt_re_get_cqe_sz(void)
{
	return sizeof(struct bnxt_re_req_cqe) + sizeof(struct bnxt_re_bcqe);
}

static inline uint8_t bnxt_re_ibv_to_bnxt_wr_opcd(uint8_t ibv_opcd)
{
	uint8_t bnxt_opcd;

	switch (ibv_opcd) {
	case IBV_WR_SEND:
		bnxt_opcd = BNXT_RE_WR_OPCD_SEND;
		break;
	case IBV_WR_SEND_WITH_IMM:
		bnxt_opcd = BNXT_RE_WR_OPCD_SEND_IMM;
		break;
	case IBV_WR_RDMA_WRITE:
		bnxt_opcd = BNXT_RE_WR_OPCD_RDMA_WRITE;
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		bnxt_opcd = BNXT_RE_WR_OPCD_RDMA_WRITE_IMM;
		break;
	case IBV_WR_RDMA_READ:
		bnxt_opcd = BNXT_RE_WR_OPCD_RDMA_READ;
		break;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
		bnxt_opcd = BNXT_RE_WR_OPCD_ATOMIC_CS;
		break;
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		bnxt_opcd = BNXT_RE_WR_OPCD_ATOMIC_FA;
		break;
		/* TODO: Add other opcodes */
	default:
		bnxt_opcd = BNXT_RE_WR_OPCD_INVAL;
		break;
	};

	return bnxt_opcd;
}

static inline uint8_t bnxt_re_ibv_wr_to_wc_opcd(uint8_t wr_opcd)
{
	uint8_t wc_opcd;

	switch (wr_opcd) {
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_SEND:
		wc_opcd = IBV_WC_SEND;
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
	case IBV_WR_RDMA_WRITE:
		wc_opcd = IBV_WC_RDMA_WRITE;
		break;
	case IBV_WR_RDMA_READ:
		wc_opcd = IBV_WC_RDMA_READ;
		break;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
		wc_opcd = IBV_WC_COMP_SWAP;
		break;
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		wc_opcd = IBV_WC_FETCH_ADD;
		break;
	default:
		wc_opcd = 0xFF;
		break;
	}

	return wc_opcd;
}

static inline uint8_t bnxt_re_to_ibv_wc_status(uint8_t bnxt_wcst,
					       uint8_t is_req)
{
	uint8_t ibv_wcst;

	if (is_req) {
		switch (bnxt_wcst) {
		case BNXT_RE_REQ_ST_BAD_RESP:
			ibv_wcst = IBV_WC_BAD_RESP_ERR;
			break;
		case BNXT_RE_REQ_ST_LOC_LEN:
			ibv_wcst = IBV_WC_LOC_LEN_ERR;
			break;
		case BNXT_RE_REQ_ST_LOC_QP_OP:
			ibv_wcst = IBV_WC_LOC_QP_OP_ERR;
			break;
		case BNXT_RE_REQ_ST_PROT:
			ibv_wcst = IBV_WC_LOC_PROT_ERR;
			break;
		case BNXT_RE_REQ_ST_MEM_OP:
			ibv_wcst = IBV_WC_MW_BIND_ERR;
			break;
		case BNXT_RE_REQ_ST_REM_INVAL:
			ibv_wcst = IBV_WC_REM_INV_REQ_ERR;
			break;
		case BNXT_RE_REQ_ST_REM_ACC:
			ibv_wcst = IBV_WC_REM_ACCESS_ERR;
			break;
		case BNXT_RE_REQ_ST_REM_OP:
			ibv_wcst = IBV_WC_REM_OP_ERR;
			break;
		case BNXT_RE_REQ_ST_RNR_NAK_XCED:
			ibv_wcst = IBV_WC_RNR_RETRY_EXC_ERR;
			break;
		case BNXT_RE_REQ_ST_TRNSP_XCED:
			ibv_wcst = IBV_WC_RETRY_EXC_ERR;
			break;
		case BNXT_RE_REQ_ST_WR_FLUSH:
			ibv_wcst = IBV_WC_WR_FLUSH_ERR;
			break;
		default:
			ibv_wcst = IBV_WC_GENERAL_ERR;
			break;
		}
	} else {
		switch (bnxt_wcst) {
		case BNXT_RE_RSP_ST_LOC_ACC:
			ibv_wcst = IBV_WC_LOC_ACCESS_ERR;
			break;
		case BNXT_RE_RSP_ST_LOC_LEN:
			ibv_wcst = IBV_WC_LOC_LEN_ERR;
			break;
		case BNXT_RE_RSP_ST_LOC_PROT:
			ibv_wcst = IBV_WC_LOC_PROT_ERR;
			break;
		case BNXT_RE_RSP_ST_LOC_QP_OP:
			ibv_wcst = IBV_WC_LOC_QP_OP_ERR;
			break;
		case BNXT_RE_RSP_ST_MEM_OP:
			ibv_wcst = IBV_WC_MW_BIND_ERR;
			break;
		case BNXT_RE_RSP_ST_REM_INVAL:
			ibv_wcst = IBV_WC_REM_INV_REQ_ERR;
			break;
		case BNXT_RE_RSP_ST_WR_FLUSH:
			ibv_wcst = IBV_WC_WR_FLUSH_ERR;
			break;
		case BNXT_RE_RSP_ST_HW_FLUSH:
			ibv_wcst = IBV_WC_FATAL_ERR;
			break;
		default:
			ibv_wcst = IBV_WC_GENERAL_ERR;
			break;
		}
	}

	return ibv_wcst;
}

static inline uint8_t bnxt_re_is_cqe_valid(struct bnxt_re_cq *cq,
					   struct bnxt_re_bcqe *hdr)
{
	uint8_t valid = 0;

	valid = ((le32toh(hdr->flg_st_typ_ph) &
		  BNXT_RE_BCQE_PH_MASK) == cq->phase);
	udma_from_device_barrier();

	return valid;
}

static inline void bnxt_re_change_cq_phase(struct bnxt_re_cq *cq)
{
	if (!cq->cqq.head)
		cq->phase = (~cq->phase & BNXT_RE_BCQE_PH_MASK);
}
#endif
