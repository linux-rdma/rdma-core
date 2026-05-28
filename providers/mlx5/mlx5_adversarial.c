// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

/*
 * Adversarial data path for RC workloads using RDMA_WRITE,
 * RDMA_WRITE_WITH_IMM, RDMA_READ and ATOMIC_FETCH_AND_ADD with an
 * untrusted device.
 *
 * Each CQE field is read once and validated against what these
 * operations produce, and only the wc fields they need are reported.
 * wc->byte_len of RECV_RDMA_WITH_IMM is reported unchecked; applications
 * must bound it against their own buffer sizes.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <util/compiler.h>
#include <util/mmio.h>
#include <infiniband/opcode.h>

#include "mlx5.h"
#include "wqe.h"

/* Map the requester sub-opcode to a wc opcode; reject unsupported ones */
static inline bool adv_wc_opcode_from_req(uint8_t req_sub_opcode,
					  uint8_t *wc_opcode_out)
{
	switch (req_sub_opcode) {
	case MLX5_OPCODE_RDMA_WRITE:
	case MLX5_OPCODE_RDMA_WRITE_IMM:
		*wc_opcode_out = IBV_WC_RDMA_WRITE;
		return true;
	case MLX5_OPCODE_RDMA_READ:
		*wc_opcode_out = IBV_WC_RDMA_READ;
		return true;
	case MLX5_OPCODE_ATOMIC_FA:
		*wc_opcode_out = IBV_WC_FETCH_ADD;
		return true;
	default:
		return false;
	}
}

/* Resolve the CQE to its QP, checking type and qpn */
static inline struct mlx5_qp *
adv_lookup_qp(struct mlx5_context *mctx, uint32_t qpn, uint32_t srqn_uidx)
{
	struct mlx5_resource *rsc;
	struct mlx5_qp *qp;

	rsc = mctx->cqe_version ? mlx5_find_uidx(mctx, srqn_uidx) :
				  (struct mlx5_resource *)mlx5_find_qp(mctx, qpn);
	if (unlikely(!rsc))
		return NULL;
	if (unlikely(rsc->type != MLX5_RSC_TYPE_QP))
		return NULL;
	if (unlikely(rsc->rsn != (mctx->cqe_version ? srqn_uidx : qpn)))
		return NULL;
	qp = rsc_to_mqp(rsc);
	if (unlikely(qp->verbs_qp.qp.qp_num != qpn))
		return NULL;
	return qp;
}

/* Returns false if the CQE fails validation */
static bool adv_parse_cqe(struct mlx5_cq *cq, struct mlx5_cqe64 *cqe64,
			  struct ibv_wc *wc)
{
	struct mlx5_context *mctx = to_mctx(cq->verbs_cq.cq.context);
	struct mlx5_qp *qp;
	uint32_t sop_drop_qpn;
	uint32_t qpn;
	uint32_t srqn_uidx;
	uint16_t wqe_counter;
	uint16_t idx;
	uint8_t opcode;
	uint8_t wc_opcode;

	/* Read each CQE field once; the device may change the buffer */
	opcode		= cqe64->op_own >> 4;
	sop_drop_qpn	= be32toh(cqe64->sop_drop_qpn);
	qpn		= sop_drop_qpn & 0xffffff;
	srqn_uidx	= be32toh(cqe64->srqn_uidx) & 0xffffff;
	wqe_counter	= be16toh(cqe64->wqe_counter);

	qp = adv_lookup_qp(mctx, qpn, srqn_uidx);
	if (unlikely(!qp))
		return false;

	wc->wc_flags = 0;
	wc->qp_num = qpn;

	switch (opcode) {
	case MLX5_CQE_REQ:
		if (unlikely(!adv_wc_opcode_from_req(sop_drop_qpn >> 24,
						     &wc_opcode)))
			return false;
		idx		= wqe_counter & (qp->sq.wqe_cnt - 1);
		wc->status	= IBV_WC_SUCCESS;
		wc->opcode	= wc_opcode;
		switch (wc_opcode) {
		case IBV_WC_RDMA_READ:
			wc->byte_len = be32toh(cqe64->byte_cnt);
			break;
		case IBV_WC_FETCH_ADD:
			wc->byte_len = 8;
			break;
		default:
			wc->byte_len = 0;
			break;
		}
		wc->vendor_err	= 0;
		wc->wr_id	= qp->sq.wrid[idx];
		qp->sq.tail	= qp->sq.wqe_head[idx] + 1;
		return true;

	case MLX5_CQE_RESP_WR_IMM:
		/* No RQ: a RESP CQE is forged */
		if (unlikely(qp->rq.wqe_cnt == 0))
			return false;
		idx		= wqe_counter & (qp->rq.wqe_cnt - 1);
		wc->status	= IBV_WC_SUCCESS;
		wc->opcode	= IBV_WC_RECV_RDMA_WITH_IMM;
		wc->wc_flags	= IBV_WC_WITH_IMM;
		wc->imm_data	= cqe64->imm_inval_pkey;
		wc->byte_len	= be32toh(cqe64->byte_cnt);
		wc->vendor_err	= 0;
		wc->wr_id	= qp->rq.wrid[idx];
		++qp->rq.tail;
		return true;

	case MLX5_CQE_REQ_ERR: {
		struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe64;
		uint8_t syndrome = ecqe->syndrome;
		uint8_t vendor_err_synd = ecqe->vendor_err_synd;

		if (unlikely(!adv_wc_opcode_from_req(sop_drop_qpn >> 24,
						     &wc_opcode)))
			return false;
		idx		= wqe_counter & (qp->sq.wqe_cnt - 1);
		wc->status	= mlx5_handle_error_cqe(syndrome);
		wc->vendor_err	= vendor_err_synd;
		wc->opcode	= wc_opcode;
		wc->byte_len	= 0;
		wc->wr_id	= qp->sq.wrid[idx];
		qp->sq.tail	= qp->sq.wqe_head[idx] + 1;
		return true;
	}

	case MLX5_CQE_RESP_ERR: {
		struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe64;
		uint8_t syndrome = ecqe->syndrome;
		uint8_t vendor_err_synd = ecqe->vendor_err_synd;

		/* No RQ: a RESP CQE is forged */
		if (unlikely(qp->rq.wqe_cnt == 0))
			return false;
		idx		= wqe_counter & (qp->rq.wqe_cnt - 1);
		wc->status	= mlx5_handle_error_cqe(syndrome);
		wc->vendor_err	= vendor_err_synd;
		wc->opcode	= IBV_WC_RECV_RDMA_WITH_IMM;
		wc->byte_len	= 0;
		wc->wr_id	= qp->rq.wrid[idx];
		++qp->rq.tail;
		return true;
	}

	default:
		/* Not produced by this data path */
		return false;
	}
}

int mlx5_adversarial_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct mlx5_cq *cq = to_mcq(ibcq);
	int npolled = 0;
	bool err = false;

	mlx5_spin_lock(&cq->lock);

	while (npolled < ne) {
		struct mlx5_cqe64 *cqe64;
		void *cqe;

		cqe = mlx5_get_sw_cqe(cq, cq->cons_index);
		if (!cqe)
			break;
		cqe64 = (cq->cqe_sz == 64) ? cqe : cqe + 64;

		++cq->cons_index;

		/* Read the CQE only after the ownership check */
		udma_from_device_barrier();

		if (!adv_parse_cqe(cq, cqe64, &wc[npolled])) {
			err = true;
			break;
		}
		++npolled;
	}

	/* Update the consumer index even if a CQE was rejected */
	udma_to_device_barrier();
	cq->dbrec[MLX5_CQ_SET_CI] = htobe32(cq->cons_index & 0xffffff);

	mlx5_spin_unlock(&cq->lock);

	return err ? -1 : npolled;
}

int mlx5_adversarial_start_poll(struct ibv_cq_ex *ibcq,
				struct ibv_poll_cq_attr *attr)
{
	return EOPNOTSUPP;
}

int mlx5_adversarial_next_poll(struct ibv_cq_ex *ibcq)
{
	return EOPNOTSUPP;
}

void mlx5_adversarial_end_poll(struct ibv_cq_ex *ibcq)
{
}
