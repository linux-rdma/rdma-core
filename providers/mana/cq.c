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

static inline bool get_next_signal_psn(struct mana_qp *qp, uint32_t *psn)
{
	struct rc_sq_shadow_wqe *shadow_wqe =
		(struct rc_sq_shadow_wqe *)shadow_queue_get_next_to_signal(&qp->shadow_sq);

	if (!shadow_wqe)
		return false;

	*psn = shadow_wqe->end_psn;
	return true;
}

static inline void advance_send_completions(struct mana_qp *qp, uint32_t psn)
{
	struct mana_gdma_queue *recv_queue = &qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER];
	struct mana_gdma_queue *send_queue = &qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER];
	struct rc_sq_shadow_wqe *shadow_wqe;

	if (!PSN_LT(psn, qp->rc_qp.sq_psn))
		return;

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
	}
}

static inline void handle_rc_requester_cqe(struct mana_qp *qp, struct gdma_cqe *cqe)
{
	struct mana_gdma_queue *recv_queue = &qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER];
	uint32_t syndrome = cqe->rdma_cqe.rc_armed_completion.syndrome;
	uint32_t psn = cqe->rdma_cqe.rc_armed_completion.psn;
	uint32_t arm_psn;

	if (!IB_IS_ACK(syndrome))
		return;

	advance_send_completions(qp, psn);

	if (!get_next_signal_psn(qp, &arm_psn))
		arm_psn = PSN_INC(psn);

	gdma_arm_normal_cqe(recv_queue, arm_psn);
}

static inline void handle_rc_responder_cqe(struct mana_qp *qp, struct gdma_cqe *cqe)
{
	struct mana_gdma_queue *recv_queue = &qp->rc_qp.queues[USER_RC_RECV_QUEUE_RESPONDER];
	struct rc_rq_shadow_wqe *shadow_wqe;

	shadow_wqe = (struct rc_rq_shadow_wqe *)shadow_queue_get_next_to_complete(&qp->shadow_rq);
	if (!shadow_wqe)
		return;

	uint32_t offset_cqe = cqe->rdma_cqe.rc_recv.rx_wqe_offset / GDMA_WQE_ALIGNMENT_UNIT_SIZE;
	uint32_t offset_wqe = shadow_wqe->header.unmasked_queue_offset & GDMA_QUEUE_OFFSET_MASK;

	if (offset_cqe != offset_wqe)
		return;

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
}

static inline bool error_cqe_is_send(struct mana_qp *qp, struct gdma_cqe *cqe)
{
	if (cqe->is_sq &&
	    qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER].id == cqe->wqid)
		return true;
	if (!cqe->is_sq &&
	    qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER].id == cqe->wqid)
		return true;

	return false;
}

static inline uint32_t error_cqe_get_psn(struct gdma_cqe *cqe)
{
	return cqe->rdma_cqe.error.psn;
}

static inline void handle_rc_error_cqe(struct mana_qp *qp, struct gdma_cqe *cqe)
{
	uint32_t vendor_error = cqe->rdma_cqe.error.vendor_error;
	bool is_send_error = error_cqe_is_send(qp, cqe);
	uint32_t psn = error_cqe_get_psn(cqe);
	struct shadow_queue *queue_with_error;
	struct shadow_wqe_header *shadow_wqe;

	mana_qp_move_flush_err(&qp->ibqp.qp);
	advance_send_completions(qp, psn);

	queue_with_error = is_send_error ? &qp->shadow_sq : &qp->shadow_rq;
	shadow_wqe = shadow_queue_get_next_to_complete(queue_with_error);

	if (shadow_wqe) {
		shadow_wqe->flags = 0;
		shadow_wqe->vendor_error = vendor_error;
		shadow_queue_advance_next_to_complete(queue_with_error);
	}
}

static inline void mana_handle_cqe(struct mana_context *ctx, struct gdma_cqe *cqe)
{
	struct mana_qp *qp = mana_get_qp(ctx, cqe->wqid, cqe->is_sq);

	if (!qp)
		return;

	if (cqe->rdma_cqe.cqe_type == CQE_TYPE_ERROR)
		handle_rc_error_cqe(qp, cqe);
	else if (cqe->rdma_cqe.cqe_type == CQE_TYPE_ARMED_CMPL)
		handle_rc_requester_cqe(qp, cqe);
	else
		handle_rc_responder_cqe(qp, cqe);
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

static enum ibv_wc_status vendor_error_to_wc_error(uint32_t vendor_error)
{
	switch (vendor_error) {
	case VENDOR_ERR_OK:
		return IBV_WC_SUCCESS;
	case VENDOR_ERR_RX_PKT_LEN:
	case VENDOR_ERR_RX_MSG_LEN_OVFL:
	case VENDOR_ERR_RX_READRESP_LEN_MISMATCH:
		return IBV_WC_LOC_LEN_ERR;
	case VENDOR_ERR_TX_GDMA_CORRUPTED_WQE:
	case VENDOR_ERR_TX_PCIE_WQE:
	case VENDOR_ERR_TX_PCIE_MSG:
	case VENDOR_ERR_RX_MALFORMED_WQE:
	case VENDOR_ERR_TX_GDMA_INVALID_STATE:
	case VENDOR_ERR_TX_MISBEHAVING_CLIENT:
	case VENDOR_ERR_TX_RDMA_MALFORMED_WQE_SIZE:
	case VENDOR_ERR_TX_RDMA_MALFORMED_WQE_FIELD:
	case VENDOR_ERR_TX_RDMA_WQE_UNSUPPORTED:
	case VENDOR_ERR_TX_RDMA_WQE_LEN_ERR:
	case VENDOR_ERR_TX_RDMA_MTU_ERR:
		return IBV_WC_LOC_QP_OP_ERR;
	case VENDOR_ERR_TX_ATB_MSG_ACCESS_VIOLATION:
	case VENDOR_ERR_TX_ATB_MSG_ADDR_RANGE:
	case VENDOR_ERR_TX_ATB_MSG_CONFIG_ERR:
	case VENDOR_ERR_TX_ATB_WQE_ACCESS_VIOLATION:
	case VENDOR_ERR_TX_ATB_WQE_ADDR_RANGE:
	case VENDOR_ERR_TX_ATB_WQE_CONFIG_ERR:
	case VENDOR_ERR_TX_RDMA_ATB_CMD_MISS:
	case VENDOR_ERR_TX_RDMA_ATB_CMD_IDX_ERROR:
	case VENDOR_ERR_TX_RDMA_ATB_CMD_TAG_MISMATCH_ERROR:
	case VENDOR_ERR_TX_RDMA_ATB_CMD_PDID_MISMATCH_ERROR:
	case VENDOR_ERR_TX_RDMA_ATB_CMD_AR_ERROR:
	case VENDOR_ERR_TX_RDMA_ATB_CMD_PT_OVF:
	case VENDOR_ERR_TX_RDMA_ATB_CMD_PT_LENGHT_MISMATCH:
	case VENDOR_ERR_TX_RDMA_ATB_CMD_ILLEGAL_CMD:
		return IBV_WC_LOC_PROT_ERR;
	case VENDOR_ERR_RX_ATB_SGE_MISSCONFIG:
	case VENDOR_ERR_RX_ATB_SGE_ADDR_RIGHT:
	case VENDOR_ERR_RX_ATB_SGE_ADDR_RANGE:
	case VENDOR_ERR_RX_GFID:
		return IBV_WC_LOC_ACCESS_ERR;
	case VENDOR_ERR_RX_OP_REQ:
		return IBV_WC_REM_INV_REQ_ERR;
	case VENDOR_ERR_RX_ATB_RKEY_MISCONFIG_ERR:
	case VENDOR_ERR_RX_ATB_RKEY_ADDR_RIGHT:
	case VENDOR_ERR_RX_ATB_RKEY_ADDR_RANGE:
	case VENDOR_ERR_RX_REMOTE_ACCESS_NAK:
		return IBV_WC_REM_ACCESS_ERR;
	case VENDOR_ERR_RX_INVALID_REQ_NAK:
	case VENDOR_ERR_RX_REMOTE_OP_ERR_NAK:
		return IBV_WC_REM_OP_ERR;
	case VENDOR_ERR_RX_MISBEHAVING_CLIENT:
	case VENDOR_ERR_RX_CLIENT_ID:
	case VENDOR_ERR_RX_PCIE:
	case VENDOR_ERR_RX_NO_AVAIL_WQE:
	case VENDOR_ERR_RX_ATB_WQE_MISCONFIG:
	case VENDOR_ERR_RX_ATB_WQE_ADDR_RIGHT:
	case VENDOR_ERR_RX_ATB_WQE_ADDR_RANGE:
	case VENDOR_ERR_TX_RDMA_INVALID_STATE:
	case VENDOR_ERR_TX_RDMA_INVALID_NPT:
	case VENDOR_ERR_TX_RDMA_INVALID_SGID:
	case VENDOR_ERR_TX_RDMA_VFID_MISMATCH:
		return IBV_WC_FATAL_ERR;
	case VENDOR_ERR_RX_NOT_EMPTY_ON_DISABLE:
	case VENDOR_ERR_SW_FLUSHED:
		return IBV_WC_WR_FLUSH_ERR;
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static void fill_verbs_from_shadow_wqe(struct mana_qp *qp, struct ibv_wc *wc,
				       const struct shadow_wqe_header *shadow_wqe)
{
	const struct rc_rq_shadow_wqe *rc_wqe = (const struct rc_rq_shadow_wqe *)shadow_wqe;

	wc->wr_id = shadow_wqe->wr_id;
	wc->status = vendor_error_to_wc_error(shadow_wqe->vendor_error);
	wc->opcode = shadow_wqe->opcode;
	wc->vendor_err = shadow_wqe->vendor_error;
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

static void mana_flush_completions(struct mana_cq *cq)
{
	struct shadow_wqe_header *shadow_wqe;
	struct mana_qp *qp;

	list_for_each(&cq->send_qp_list, qp, send_cq_node) {
		if (qp->ibqp.qp.state != IBV_QPS_ERR)
			continue;
		while ((shadow_wqe = shadow_queue_get_next_to_complete(&qp->shadow_sq))
				!= NULL) {
			shadow_wqe->vendor_error = VENDOR_ERR_SW_FLUSHED;
			shadow_wqe->flags = 0;
			shadow_queue_advance_next_to_complete(&qp->shadow_sq);
		}
	}

	list_for_each(&cq->recv_qp_list, qp, recv_cq_node) {
		if (qp->ibqp.qp.state != IBV_QPS_ERR)
			continue;
		while ((shadow_wqe = shadow_queue_get_next_to_complete(&qp->shadow_rq))
				!= NULL) {
			shadow_wqe->vendor_error = VENDOR_ERR_SW_FLUSHED;
			shadow_queue_advance_next_to_complete(&qp->shadow_rq);
		}
	}
}

int mana_poll_cq(struct ibv_cq *ibcq, int nwc, struct ibv_wc *wc)
{
	struct mana_cq *cq = container_of(ibcq, struct mana_cq, ibcq);
	struct mana_context *ctx = to_mctx(ibcq->context);
	struct gdma_cqe gdma_cqe;
	int num_polled = 0;
	int ret, i;

	pthread_spin_lock(&cq->lock);

	for (i = 0; i < nwc; i++) {
		ret = gdma_read_cqe(cq, &gdma_cqe);
		if (ret < 0) {
			num_polled = -1;
			goto out;
		}
		if (ret == 0)
			break;
		mana_handle_cqe(ctx, &gdma_cqe);
	}

	mana_flush_completions(cq);
	num_polled = mana_process_completions(cq, nwc, wc);

out:
	pthread_spin_unlock(&cq->lock);

	return num_polled;
}
