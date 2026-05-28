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
#include "mlx5_trace.h"
#include "wqe.h"

/* Map the SW-recorded MLX5_OPCODE_* to a wc opcode */
static inline bool adv_wc_opcode_from_mlx5(uint8_t mlx5_opcode,
					    enum ibv_wc_opcode *out)
{
	switch (mlx5_opcode) {
	case MLX5_OPCODE_RDMA_WRITE:
	case MLX5_OPCODE_RDMA_WRITE_IMM:
		*out = IBV_WC_RDMA_WRITE;
		return true;
	case MLX5_OPCODE_RDMA_READ:
		*out = IBV_WC_RDMA_READ;
		return true;
	case MLX5_OPCODE_ATOMIC_FA:
		*out = IBV_WC_FETCH_ADD;
		return true;
	default:
		return false;
	}
}

/*
 * Validate wqe_counter against the RQ state without changing it: a posted
 * slot on OOO_DP QPs, the next expected slot (rq.tail) otherwise. The slot
 * is released by adv_rq_commit() only after its wr_id is read, so a
 * concurrent post_recv cannot reuse it in between.
 */
static inline bool adv_rq_peek(struct mlx5_qp *qp, uint16_t wqe_counter,
			       uint16_t *idx_out)
{
	uint16_t mask;
	uint16_t idx;

	/* Reject a responder CQE when no receive is outstanding. Reading
	 * rq.head without rq.lock is safe: the CQE cannot exist before its
	 * post_recv rang the doorbell.
	 */
	if (unlikely(qp->rq.wqe_cnt == 0 || qp->rq.head == qp->rq.tail))
		return false;

	mask = qp->rq.wqe_cnt - 1;
	idx = wqe_counter & mask;

	if (qp->flags & MLX5_QP_FLAGS_OOO_DP) {
		if (unlikely(!qp->rq.in_flight[idx]))
			return false;
	} else {
		if (unlikely(idx != (qp->rq.tail & mask)))
			return false;
	}
	*idx_out = idx;
	return true;
}

/*
 * Release a slot validated by adv_rq_peek(). The release store orders
 * the rq.wrid[idx] read before a concurrent post_recv can see the slot
 * free.
 */
static inline void adv_rq_commit(struct mlx5_qp *qp, uint16_t idx)
{
	if (qp->flags & MLX5_QP_FLAGS_OOO_DP)
		__atomic_store_n(&qp->rq.in_flight[idx], 0, __ATOMIC_RELEASE);
	++qp->rq.tail;
}

/*
 * Find the oldest in-flight signaled WR in O(1) and check its wqe_counter.
 * Nothing is consumed until adv_sq_commit_signaled(), so a CQE failing a
 * later check does not retire the WR.
 */
static inline bool adv_sq_peek_signaled(struct mlx5_qp *qp,
					uint16_t wqe_counter,
					uint16_t *idx_out,
					unsigned *sig_counter_out)
{
	unsigned mask;
	unsigned sig_counter;

	/* Safe without sq.lock, as in adv_rq_peek() */
	if (unlikely(qp->sq.wqe_cnt == 0 ||
		     qp->sq.signaled_head == qp->sq.signaled_tail))
		return false;

	mask = qp->sq.wqe_cnt - 1;

	sig_counter = qp->sq.signaled_ring[qp->sq.signaled_tail & mask];
	if (unlikely(qp->sq.shadow_queue[sig_counter & mask] != wqe_counter))
		return false;

	*idx_out = wqe_counter & mask;
	*sig_counter_out = sig_counter;
	return true;
}

/*
 * Consume a signaled completion together with the unsignaled WRs posted
 * before it, and advance sq.tail as the generic poll_cq does.
 */
static inline void adv_sq_commit_signaled(struct mlx5_qp *qp, uint16_t idx,
					  unsigned sig_counter)
{
	qp->sq.shadow_tail = sig_counter + 1;
	qp->sq.signaled_tail++;
	qp->sq.tail = qp->sq.wqe_head[idx] + 1;
}

/*
 * On error the device may complete any in-flight WR, signaled or not, so
 * search all of shadow_queue. This runs only on the error path.
 */
static inline bool adv_sq_peek_any(struct mlx5_qp *qp,
				   uint16_t wqe_counter,
				   uint16_t *idx_out,
				   unsigned *match_i_out)
{
	unsigned mask = qp->sq.wqe_cnt - 1;
	unsigned i;

	/* Safe without sq.lock, as in adv_rq_peek() */
	for (i = qp->sq.shadow_tail; i != qp->sq.shadow_head; i++) {
		if (qp->sq.shadow_queue[i & mask] != wqe_counter)
			continue;
		*idx_out = wqe_counter & mask;
		*match_i_out = i;
		return true;
	}
	return false;
}

/*
 * Consume an error completion, drop the signaled_ring entries it passed,
 * and advance sq.tail as the generic poll_cq does.
 */
static inline void adv_sq_commit_any(struct mlx5_qp *qp, uint16_t idx,
				     unsigned match_i)
{
	unsigned mask = qp->sq.wqe_cnt - 1;

	qp->sq.shadow_tail = match_i + 1;
	while (qp->sq.signaled_tail != qp->sq.signaled_head &&
	       (int)(qp->sq.signaled_ring[qp->sq.signaled_tail & mask] -
		     qp->sq.shadow_tail) < 0)
		qp->sq.signaled_tail++;
	qp->sq.tail = qp->sq.wqe_head[idx] + 1;
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

/*
 * Called for every CQE that is inconsistent with the SW state. It only
 * rejects the CQE today; routing all checks here allows a stronger policy
 * later.
 */
static bool adv_nic_violation(struct mlx5_cq *cq, const char *reason)
{
	mlx5_dbg(to_mctx(cq->verbs_cq.cq.context)->dbg_fp, MLX5_DBG_CQ,
		 "adversarial poll_cq: rejecting CQE from untrusted NIC: %s\n",
		 reason);
	return false;
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

	/* Read each CQE field once; the device may change the buffer */
	opcode		= cqe64->op_own >> 4;
	sop_drop_qpn	= be32toh(cqe64->sop_drop_qpn);
	qpn		= sop_drop_qpn & 0xffffff;
	srqn_uidx	= be32toh(cqe64->srqn_uidx) & 0xffffff;
	wqe_counter	= be16toh(cqe64->wqe_counter);

	qp = adv_lookup_qp(mctx, qpn, srqn_uidx);
	if (unlikely(!qp))
		return adv_nic_violation(cq, "QP lookup / qpn mismatch");

	wc->wc_flags = 0;
	wc->qp_num = qpn;

	switch (opcode) {
	case MLX5_CQE_REQ: {
		unsigned sig_counter;
		uint8_t sw_opcode;

		/* Requester completions must be on the QP's send_cq */
		if (unlikely(to_mcq(qp->verbs_qp.qp.send_cq) != cq))
			return adv_nic_violation(cq,
				"REQ completion on a CQ that is not the QP's send_cq");

		/* Validate against the oldest in-flight signaled WR */
		if (unlikely(!adv_sq_peek_signaled(qp, wqe_counter, &idx,
						   &sig_counter)))
			return adv_nic_violation(cq,
				"REQ wqe_counter matches no in-flight signaled WR");
		sw_opcode = qp->sq.adv_mlx5_opcodes[idx];
		if (unlikely((sop_drop_qpn >> 24) != sw_opcode))
			return adv_nic_violation(cq,
				"REQ sub-opcode disagrees with SW-recorded opcode");
		/* A successful RDMA_READ transfers the full requested length */
		if (sw_opcode == MLX5_OPCODE_RDMA_READ &&
		    unlikely(be32toh(cqe64->byte_cnt) != qp->sq.adv_read_len[idx]))
			return adv_nic_violation(cq,
				"RDMA_READ byte_cnt != requested length");

		if (unlikely(!adv_wc_opcode_from_mlx5(sw_opcode, &wc->opcode)))
			return adv_nic_violation(cq,
				"SW-recorded opcode has no IBV_WC mapping");
		wc->status	= IBV_WC_SUCCESS;
		/* Report WRITE_WITH_IMM as the generic poll_cq does */
		if (sw_opcode == MLX5_OPCODE_RDMA_WRITE_IMM)
			wc->wc_flags |= IBV_WC_WITH_IMM;
		/* byte_len is defined only for RDMA_READ and atomics (IBA
		 * 11.4.2.1); never take it from the device.
		 */
		switch (sw_opcode) {
		case MLX5_OPCODE_ATOMIC_FA:
			wc->byte_len = 8;
			break;
		case MLX5_OPCODE_RDMA_READ:
			wc->byte_len = qp->sq.adv_read_len[idx];
			break;
		default:
			wc->byte_len = 0;
			break;
		}
		wc->vendor_err	= 0;
		wc->wr_id	= qp->sq.wrid[idx];
		/* Retire the WR only after reading its slot */
		adv_sq_commit_signaled(qp, idx, sig_counter);
		return true;
	}

	case MLX5_CQE_RESP_WR_IMM:
		/* Responder completions must be on the QP's recv_cq */
		if (unlikely(to_mcq(qp->verbs_qp.qp.recv_cq) != cq))
			return adv_nic_violation(cq,
				"RESP completion on a CQ that is not the QP's recv_cq");
		/* byte_len is unchecked; see the file header */
		if (unlikely(!adv_rq_peek(qp, wqe_counter, &idx)))
			return adv_nic_violation(cq,
				"RESP_WR_IMM wqe_counter / no outstanding recv");
		wc->status	= IBV_WC_SUCCESS;
		wc->opcode	= IBV_WC_RECV_RDMA_WITH_IMM;
		wc->wc_flags	= IBV_WC_WITH_IMM;
		wc->imm_data	= cqe64->imm_inval_pkey;
		wc->byte_len	= be32toh(cqe64->byte_cnt);
		wc->vendor_err	= 0;
		/* Read wr_id before releasing the slot */
		wc->wr_id	= qp->rq.wrid[idx];
		adv_rq_commit(qp, idx);
		return true;

	case MLX5_CQE_REQ_ERR: {
		struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe64;
		uint8_t syndrome = ecqe->syndrome;
		uint8_t vendor_err_synd = ecqe->vendor_err_synd;
		unsigned match_i;

		/* Requester error completion: only valid on send_cq. */
		if (unlikely(to_mcq(qp->verbs_qp.qp.send_cq) != cq))
			return adv_nic_violation(cq,
				"REQ_ERR completion on a CQ that is not the QP's send_cq");

		/* Error CQEs may complete unsignaled WRs too */
		if (unlikely(!adv_sq_peek_any(qp, wqe_counter, &idx, &match_i)))
			return adv_nic_violation(cq,
				"REQ_ERR wqe_counter matches no in-flight WR");
		if (unlikely((sop_drop_qpn >> 24) !=
			     qp->sq.adv_mlx5_opcodes[idx]))
			return adv_nic_violation(cq,
				"REQ_ERR sub-opcode disagrees with SW-recorded opcode");

		if (unlikely(!adv_wc_opcode_from_mlx5(qp->sq.adv_mlx5_opcodes[idx],
						       &wc->opcode)))
			return adv_nic_violation(cq,
				"REQ_ERR SW-recorded opcode has no IBV_WC mapping");
		wc->status	= mlx5_handle_error_cqe(syndrome);
		wc->vendor_err	= vendor_err_synd;
		wc->byte_len	= 0;
		wc->wr_id	= qp->sq.wrid[idx];
		/* Retire the WR only after reading its slot */
		adv_sq_commit_any(qp, idx, match_i);
		return true;
	}

	case MLX5_CQE_RESP_ERR: {
		struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe64;
		uint8_t syndrome = ecqe->syndrome;
		uint8_t vendor_err_synd = ecqe->vendor_err_synd;

		/* Responder error completion: only valid on recv_cq. */
		if (unlikely(to_mcq(qp->verbs_qp.qp.recv_cq) != cq))
			return adv_nic_violation(cq,
				"RESP_ERR completion on a CQ that is not the QP's recv_cq");

		if (unlikely(!adv_rq_peek(qp, wqe_counter, &idx)))
			return adv_nic_violation(cq,
				"RESP_ERR wqe_counter / no outstanding recv");
		wc->status	= mlx5_handle_error_cqe(syndrome);
		wc->vendor_err	= vendor_err_synd;
		wc->opcode	= IBV_WC_RECV_RDMA_WITH_IMM;
		wc->byte_len	= 0;
		/* Read wr_id before releasing the slot */
		wc->wr_id	= qp->rq.wrid[idx];
		adv_rq_commit(qp, idx);
		return true;
	}

	default:
		/* Not produced by this data path */
		return adv_nic_violation(cq, "unsupported top-level CQE opcode");
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

#define ADVERSARIAL_POST_RECV
#include "mlx5_post_recv_body.h"
#undef ADVERSARIAL_POST_RECV

int mlx5_adversarial_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
			       struct ibv_recv_wr **bad_wr)
{
	return _mlx5_post_recv_body(ibqp, wr, bad_wr);
}

#define ADVERSARIAL_POST_SEND
#include "mlx5_post_send_body.h"
#undef ADVERSARIAL_POST_SEND

int mlx5_adversarial_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			       struct ibv_send_wr **bad_wr)
{
	return _mlx5_post_send_body(ibqp, wr, bad_wr);
}
