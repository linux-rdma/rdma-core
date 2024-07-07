// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2024, Microsoft Corporation. All rights reserved.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <util/compiler.h>
#include <util/util.h>
#include <sys/mman.h>

#include <infiniband/driver.h>

#include <infiniband/kern-abi.h>
#include <rdma/mana-abi.h>
#include <kernel-abi/mana-abi.h>

#include "mana.h"
#include "gdma.h"
#include "doorbells.h"
#include "rollback.h"
#define INITIALIZED_OWNER_BIT(log2_num_entries) (1UL << (log2_num_entries))

DECLARE_DRV_CMD(mana_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		mana_ib_create_cq, mana_ib_create_cq_resp);

struct ibv_cq *mana_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel, int comp_vector)
{
	struct mana_context *ctx = to_mctx(context);
	struct mana_create_cq_resp resp = {};
	struct mana_ib_create_cq *cmd_drv;
	struct mana_create_cq cmd = {};
	struct mana_cq *cq;
	uint16_t flags = 0;
	size_t cq_size;
	int ret;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	cq_size = align_hw_size(cqe * COMP_ENTRY_SIZE);
	cq->db_page = ctx->db_page;
	list_head_init(&cq->send_qp_list);
	list_head_init(&cq->recv_qp_list);
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	cq->buf_external = ctx->extern_alloc.alloc && ctx->extern_alloc.free;
	if (!cq->buf_external)
		flags |= MANA_IB_CREATE_RNIC_CQ;

	if (cq->buf_external)
		cq->buf = ctx->extern_alloc.alloc(cq_size, ctx->extern_alloc.data);
	else
		cq->buf = mana_alloc_mem(cq_size);
	if (!cq->buf) {
		errno = ENOMEM;
		goto free_cq;
	}

	if (flags & MANA_IB_CREATE_RNIC_CQ)
		cq->cqe = cq_size / COMP_ENTRY_SIZE;
	else
		cq->cqe = cqe; // to preserve old behaviour for DPDK
	cq->head = INITIALIZED_OWNER_BIT(ilog32(cq->cqe) - 1);
	cq->last_armed_head = cq->head - 1;
	cq->ready_wcs = 0;

	cmd_drv = &cmd.drv_payload;
	cmd_drv->buf_addr = (uintptr_t)cq->buf;
	cmd_drv->flags = flags;
	resp.cqid = UINT32_MAX;

	ret = ibv_cmd_create_cq(context, cq->cqe, channel, comp_vector,
				&cq->ibcq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));

	if (ret) {
		verbs_err(verbs_get_ctx(context), "Failed to Create CQ\n");
		errno = ret;
		goto free_mem;
	}

	if (flags & MANA_IB_CREATE_RNIC_CQ) {
		cq->cqid = resp.cqid;
		if (cq->cqid == UINT32_MAX) {
			errno = ENODEV;
			goto destroy_cq;
		}
	}

	return &cq->ibcq;

destroy_cq:
	ibv_cmd_destroy_cq(&cq->ibcq);
free_mem:
	if (cq->buf_external)
		ctx->extern_alloc.free(cq->buf, ctx->extern_alloc.data);
	else
		munmap(cq->buf, cq_size);
free_cq:
	free(cq);
	return NULL;
}

int mana_destroy_cq(struct ibv_cq *ibcq)
{
	struct mana_cq *cq = container_of(ibcq, struct mana_cq, ibcq);
	struct mana_context *ctx = to_mctx(ibcq->context);
	int ret;

	pthread_spin_lock(&cq->lock);
	ret = ibv_cmd_destroy_cq(ibcq);
	if (ret) {
		verbs_err(verbs_get_ctx(ibcq->context),
			  "Failed to Destroy CQ\n");
		pthread_spin_unlock(&cq->lock);
		return ret;
	}
	pthread_spin_destroy(&cq->lock);

	if (cq->buf_external)
		ctx->extern_alloc.free(cq->buf, ctx->extern_alloc.data);
	else
		munmap(cq->buf, cq->cqe * COMP_ENTRY_SIZE);

	free(cq);

	return ret;
}

int mana_arm_cq(struct ibv_cq *ibcq, int solicited)
{
	struct mana_cq *cq = container_of(ibcq, struct mana_cq, ibcq);

	if (solicited)
		return -EOPNOTSUPP;
	if (cq->cqid == UINT32_MAX)
		return -EINVAL;

	gdma_ring_cq_doorbell(cq);
	return 0;
}

static inline uint32_t handle_rc_requester_cqe(struct mana_qp *qp, struct gdma_cqe *cqe)
{
	struct mana_gdma_queue *recv_queue = &qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER];
	struct mana_gdma_queue *send_queue = &qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER];
	uint32_t syndrome = cqe->rdma_cqe.rc_armed_completion.syndrome;
	uint32_t psn = cqe->rdma_cqe.rc_armed_completion.psn;
	struct rc_sq_shadow_wqe *shadow_wqe;
	uint32_t wcs = 0;

	if (!IB_IS_ACK(syndrome))
		return 0;

	if (!PSN_GT(psn, qp->rc_qp.sq_highest_completed_psn))
		return 0;

	qp->rc_qp.sq_highest_completed_psn = psn;

	if (!PSN_LT(psn, qp->rc_qp.sq_psn))
		return 0;

	while ((shadow_wqe = (struct rc_sq_shadow_wqe *)
		shadow_queue_get_next_to_complete(&qp->shadow_sq)) != NULL) {
		if (PSN_LT(psn, shadow_wqe->end_psn))
			break;

		send_queue->cons_idx += shadow_wqe->header.posted_wqe_size_in_bu;
		send_queue->cons_idx &= GDMA_QUEUE_OFFSET_MASK;

		recv_queue->cons_idx += shadow_wqe->read_posted_wqe_size_in_bu;
		recv_queue->cons_idx &= GDMA_QUEUE_OFFSET_MASK;

		uint32_t offset = shadow_wqe->header.unmasked_queue_offset +
				  shadow_wqe->header.posted_wqe_size_in_bu;
		mana_ib_update_shared_mem_left_offset(qp, offset & GDMA_QUEUE_OFFSET_MASK);

		shadow_queue_advance_next_to_complete(&qp->shadow_sq);
		if (shadow_wqe->header.flags != MANA_NO_SIGNAL_WC)
			wcs++;
	}

	uint32_t prev_psn = PSN_DEC(qp->rc_qp.sq_psn);

	if (qp->rc_qp.sq_highest_completed_psn == prev_psn)
		gdma_arm_normal_cqe(recv_queue, qp->rc_qp.sq_psn);
	else
		gdma_arm_normal_cqe(recv_queue, prev_psn);

	return wcs;
}

static inline uint32_t handle_rc_responder_cqe(struct mana_qp *qp, struct gdma_cqe *cqe)
{
	struct mana_gdma_queue *recv_queue = &qp->rc_qp.queues[USER_RC_RECV_QUEUE_RESPONDER];
	struct rc_rq_shadow_wqe *shadow_wqe;

	shadow_wqe = (struct rc_rq_shadow_wqe *)shadow_queue_get_next_to_complete(&qp->shadow_rq);
	if (!shadow_wqe)
		return 0;

	uint32_t offset_cqe = cqe->rdma_cqe.rc_recv.rx_wqe_offset / GDMA_WQE_ALIGNMENT_UNIT_SIZE;
	uint32_t offset_wqe = shadow_wqe->header.unmasked_queue_offset & GDMA_QUEUE_OFFSET_MASK;

	if (offset_cqe != offset_wqe)
		return 0;

	shadow_wqe->byte_len = cqe->rdma_cqe.rc_recv.msg_len;
	shadow_wqe->imm_or_rkey = cqe->rdma_cqe.rc_recv.imm_data;

	switch (cqe->rdma_cqe.cqe_type) {
	case CQE_TYPE_RC_WRITE_IMM:
		shadow_wqe->header.opcode = IBV_WC_RECV_RDMA_WITH_IMM;
		SWITCH_FALLTHROUGH;
	case CQE_TYPE_RC_SEND_IMM:
		shadow_wqe->header.flags |= IBV_WC_WITH_IMM;
		break;
	case CQE_TYPE_RC_SEND_INV:
		shadow_wqe->header.flags |= IBV_WC_WITH_INV;
		break;
	default:
		break;
	}

	recv_queue->cons_idx += shadow_wqe->header.posted_wqe_size_in_bu;
	recv_queue->cons_idx &= GDMA_QUEUE_OFFSET_MASK;

	shadow_queue_advance_next_to_complete(&qp->shadow_rq);
	return 1;
}

static inline uint32_t mana_handle_cqe(struct mana_context *ctx, struct gdma_cqe *cqe)
{
	struct mana_qp *qp;

	if (cqe->is_sq) // impossible for rc
		return 0;

	qp = mana_get_qp_from_rq(ctx, cqe->wqid);
	if (!qp)
		return 0;

	if (cqe->rdma_cqe.cqe_type == CQE_TYPE_ARMED_CMPL)
		return handle_rc_requester_cqe(qp, cqe);
	else
		return handle_rc_responder_cqe(qp, cqe);
}

static inline int gdma_read_cqe(struct mana_cq *cq, struct gdma_cqe *cqe)
{
	uint32_t new_entry_owner_bits;
	uint32_t old_entry_owner_bits;
	struct gdma_cqe *current_cqe;
	uint32_t owner_bits;

	current_cqe = ((struct gdma_cqe *)cq->buf) + (cq->head % cq->cqe);
	new_entry_owner_bits = (cq->head / cq->cqe) & CQ_OWNER_MASK;
	old_entry_owner_bits = (cq->head / cq->cqe - 1) & CQ_OWNER_MASK;
	owner_bits = current_cqe->owner_bits;

	if (owner_bits == old_entry_owner_bits)
		return 0; /* no new entry */
	if (owner_bits != new_entry_owner_bits)
		return -1; /*overflow detected*/

	udma_from_device_barrier();
	*cqe = *current_cqe;
	cq->head++;
	return 1;
}

static void fill_verbs_from_shadow_wqe(struct mana_qp *qp, struct ibv_wc *wc,
				       const struct shadow_wqe_header *shadow_wqe)
{
	const struct rc_rq_shadow_wqe *rc_wqe = (const struct rc_rq_shadow_wqe *)shadow_wqe;

	wc->wr_id = shadow_wqe->wr_id;
	wc->status = IBV_WC_SUCCESS;
	wc->opcode = shadow_wqe->opcode;
	wc->vendor_err = 0;
	wc->wc_flags = shadow_wqe->flags;
	wc->qp_num = qp->ibqp.qp.qp_num;
	wc->pkey_index = 0;

	if (shadow_wqe->opcode & IBV_WC_RECV) {
		wc->byte_len = rc_wqe->byte_len;
		wc->imm_data = htobe32(rc_wqe->imm_or_rkey);
	}
}

static int mana_process_completions(struct mana_cq *cq, int nwc, struct ibv_wc *wc)
{
	struct shadow_wqe_header *shadow_wqe;
	struct mana_qp *qp;
	int wc_index = 0;

	/* process send shadow queue completions  */
	list_for_each(&cq->send_qp_list, qp, send_cq_node) {
		while ((shadow_wqe = shadow_queue_get_next_to_consume(&qp->shadow_sq))
				!= NULL) {
			if (wc_index >= nwc && shadow_wqe->flags != MANA_NO_SIGNAL_WC)
				goto out;

			if (shadow_wqe->flags != MANA_NO_SIGNAL_WC) {
				fill_verbs_from_shadow_wqe(qp, &wc[wc_index], shadow_wqe);
				wc_index++;
			}
			shadow_queue_advance_consumer(&qp->shadow_sq);
		}
	}

	/* process recv shadow queue completions */
	list_for_each(&cq->recv_qp_list, qp, recv_cq_node) {
		while ((shadow_wqe = shadow_queue_get_next_to_consume(&qp->shadow_rq))
				!= NULL) {
			if (wc_index >= nwc)
				goto out;

			fill_verbs_from_shadow_wqe(qp, &wc[wc_index], shadow_wqe);
			wc_index++;
			shadow_queue_advance_consumer(&qp->shadow_rq);
		}
	}

out:
	return wc_index;
}

int mana_poll_cq(struct ibv_cq *ibcq, int nwc, struct ibv_wc *wc)
{
	struct mana_cq *cq = container_of(ibcq, struct mana_cq, ibcq);
	struct mana_context *ctx = to_mctx(ibcq->context);
	struct gdma_cqe gdma_cqe;
	int num_polled = 0;
	int ret;

	pthread_spin_lock(&cq->lock);

	while (cq->ready_wcs < nwc) {
		ret = gdma_read_cqe(cq, &gdma_cqe);
		if (ret < 0) {
			num_polled = -1;
			goto out;
		}
		if (ret == 0)
			break;
		cq->ready_wcs += mana_handle_cqe(ctx, &gdma_cqe);
	}

	num_polled = mana_process_completions(cq, nwc, wc);
	cq->ready_wcs -= num_polled;
out:
	pthread_spin_unlock(&cq->lock);

	return num_polled;
}
