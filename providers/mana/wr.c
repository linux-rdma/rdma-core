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
#include "doorbells.h"
#include "rollback.h"
#include "gdma.h"

static inline void zero_wqe_content(struct gdma_wqe *wqe)
{
	memset(wqe->gdma_oob, 0, sizeof(union gdma_oob) + wqe->client_oob_size);
	memset(wqe->sgl1, 0, wqe->num_sge1 * sizeof(struct gdma_sge));
	if (wqe->sgl2)
		memset(wqe->sgl2, 0, wqe->num_sge2 * sizeof(struct gdma_sge));
}

static inline void gdma_advance_producer(struct mana_gdma_queue *wq, uint32_t size_in_bu)
{
	wq->prod_idx = (wq->prod_idx + size_in_bu) & GDMA_QUEUE_OFFSET_MASK;
}

static inline int
gdma_get_current_wqe(struct mana_gdma_queue *wq, uint32_t client_oob_size,
		     uint32_t wqe_size, struct gdma_wqe *wqe)
{
	uint32_t wq_size = wq->size;
	uint32_t used_entries = (wq->prod_idx - wq->cons_idx) & GDMA_QUEUE_OFFSET_MASK;
	uint32_t free_space = wq_size - (used_entries * GDMA_WQE_ALIGNMENT_UNIT_SIZE);

	if (wqe_size > free_space)
		return ENOMEM;

	uint32_t aligned_sgl_size = wqe_size - sizeof(union gdma_oob) - client_oob_size;
	uint32_t total_num_sges = aligned_sgl_size / sizeof(struct gdma_sge);
	uint32_t offset = (wq->prod_idx * GDMA_WQE_ALIGNMENT_UNIT_SIZE) & (wq_size - 1);

	wqe->unmasked_wqe_index = wq->prod_idx;
	wqe->size_in_bu = wqe_size / GDMA_WQE_ALIGNMENT_UNIT_SIZE;
	wqe->gdma_oob = (union gdma_oob *)((uint8_t *)wq->buffer + offset);
	wqe->client_oob = ((uint8_t *)wqe->gdma_oob) + sizeof(union gdma_oob);
	wqe->client_oob_size = client_oob_size;

	if (likely(wq_size - offset >= wqe_size)) {
		wqe->sgl1 = (struct gdma_sge *)((uint8_t *)wqe->client_oob + client_oob_size);
		wqe->num_sge1 = total_num_sges;
		wqe->sgl2 = NULL;
		wqe->num_sge2 = 0;
	} else {
		if (offset + sizeof(union gdma_oob) + client_oob_size == wq_size) {
			wqe->sgl1 = (struct gdma_sge *)wq->buffer;
			wqe->num_sge1 = total_num_sges;
			wqe->sgl2 = NULL;
			wqe->num_sge2 = 0;
		} else {
			wqe->sgl1 = (struct gdma_sge *)((uint8_t *)wqe->client_oob
							+ client_oob_size);
			wqe->num_sge1 = (wq_size - offset - sizeof(union gdma_oob)
					 - client_oob_size) / sizeof(struct gdma_sge);
			wqe->sgl2 = (struct gdma_sge *)wq->buffer;
			wqe->num_sge2 = total_num_sges - wqe->num_sge1;
		}
	}

	zero_wqe_content(wqe);
	return 0;
}

static inline void gdma_write_sge(struct gdma_wqe *wqe, void *oob_sge,
				  struct ibv_sge *sge, uint32_t num_sge)
{
	struct gdma_sge *gdma_sgl = wqe->sgl1;
	uint32_t num_sge1 = wqe->num_sge1;
	uint32_t i;

	if (oob_sge) {
		memcpy(gdma_sgl, oob_sge, sizeof(*gdma_sgl));
		gdma_sgl++;
		num_sge1--;
	}

	for (i = 0; i < num_sge; ++i, ++gdma_sgl) {
		if (i == num_sge1)
			gdma_sgl = wqe->sgl2;

		gdma_sgl->address = sge->addr;
		gdma_sgl->size = sge->length;
		gdma_sgl->mem_key = sge->lkey;
	}
}

static inline int
gdma_post_rq_wqe(struct mana_gdma_queue *wq, struct ibv_sge *sgl,  void *oob,
		 uint32_t num_sge, enum gdma_work_req_flags flags, struct gdma_wqe *wqe)
{
	uint32_t wqe_size = get_wqe_size(num_sge);
	int ret;

	ret = gdma_get_current_wqe(wq, INLINE_OOB_SMALL_SIZE, wqe_size, wqe);
	if (ret)
		return ret;

	wqe->gdma_oob->rx.num_sgl_entries = num_sge;
	wqe->gdma_oob->rx.inline_client_oob_size = INLINE_OOB_SMALL_SIZE / sizeof(uint32_t);
	wqe->gdma_oob->rx.check_sn = (flags & GDMA_WORK_REQ_CHECK_SN) != 0;
	if (oob)
		memcpy(wqe->client_oob, oob, INLINE_OOB_SMALL_SIZE);

	gdma_write_sge(wqe, NULL, sgl, num_sge);
	gdma_advance_producer(wq, wqe->size_in_bu);
	return 0;
}

static int mana_ib_rc_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
				struct ibv_recv_wr **bad_wr)
{
	struct mana_context *mc = container_of(verbs_get_ctx(ibqp->context),
					struct mana_context, ibv_ctx);
	struct mana_qp *qp = container_of(ibqp, struct mana_qp, ibqp.qp);
	struct mana_gdma_queue *wq = &qp->rc_qp.queues[USER_RC_RECV_QUEUE_RESPONDER];
	struct shadow_wqe_header *shadow_wqe;
	struct gdma_wqe wqe_info;
	uint8_t wqe_cnt = 0;
	int ret = 0;

	pthread_spin_lock(&qp->rq_lock);
	for (; wr; wr = wr->next) {
		if (shadow_queue_full(&qp->shadow_rq)) {
			verbs_err(&mc->ibv_ctx, "recv shadow queue full\n");
			ret = ENOMEM;
			goto cleanup;
		}

		ret = gdma_post_rq_wqe(wq, wr->sg_list, NULL, wr->num_sge,
				       GDMA_WORK_REQ_NONE, &wqe_info);
		if (ret) {
			verbs_err(&mc->ibv_ctx, "Failed to post RQ wqe , ret %d\n", ret);
			goto cleanup;
		}
		wqe_cnt++;

		shadow_wqe = shadow_queue_producer_entry(&qp->shadow_rq);
		memset(shadow_wqe, 0, sizeof(*shadow_wqe));
		shadow_wqe->opcode = IBV_WC_RECV;
		shadow_wqe->wr_id = wr->wr_id;
		shadow_wqe->unmasked_queue_offset = wqe_info.unmasked_wqe_index;
		shadow_wqe->posted_wqe_size_in_bu = wqe_info.size_in_bu;
		shadow_queue_advance_producer(&qp->shadow_rq);
	}

cleanup:
	if (wqe_cnt)
		gdma_ring_recv_doorbell(wq, wqe_cnt);
	pthread_spin_unlock(&qp->rq_lock);
	if (bad_wr && ret)
		*bad_wr = wr;
	return ret;
}

int mana_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad)
{
	switch (ibqp->qp_type) {
	case IBV_QPT_RC:
		return mana_ib_rc_post_recv(ibqp, wr, bad);
	default:
		verbs_err(verbs_get_ctx(ibqp->context), "QPT not supported %d\n", ibqp->qp_type);
		return EOPNOTSUPP;
	}
}

static inline bool is_opcode_supported(enum ibv_wr_opcode opcode)
{
	switch (opcode) {
	case IBV_WR_RDMA_READ:
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		return true;
	default:
		return false;
	}
}

static inline enum ibv_wc_opcode
	convert_wr_to_wc(enum ibv_wr_opcode opcode)
{
	switch (opcode) {
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_SEND:
		return IBV_WC_SEND;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
	case IBV_WR_RDMA_WRITE:
		return IBV_WC_RDMA_WRITE;
	case IBV_WR_RDMA_READ:
		return IBV_WC_RDMA_READ;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
		return IBV_WC_COMP_SWAP;
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		return IBV_WC_FETCH_ADD;
	default:
		return 0xFF;
	}
}

static inline int
gdma_post_sq_wqe(struct mana_gdma_queue *wq, struct ibv_sge *sgl, struct rdma_send_oob *send_oob,
		 void *oob_sge,  uint32_t num_sge, uint32_t mtu,
		 enum gdma_work_req_flags flags, struct gdma_wqe *wqe)
{
	struct ibv_sge dummy = {1, 0, 0};
	uint32_t total_sge, wqe_size;
	int ret;

	if (num_sge == 0) {
		num_sge = 1;
		sgl = &dummy;
	}

	total_sge = num_sge + (oob_sge ? 1 : 0);
	wqe_size = get_large_wqe_size(total_sge);

	ret = gdma_get_current_wqe(wq, INLINE_OOB_LARGE_SIZE, wqe_size, wqe);
	if (ret)
		return ret;

	wqe->gdma_oob->tx.num_padding_sgls = wqe->num_sge1 + wqe->num_sge2 - total_sge;
	wqe->gdma_oob->tx.num_sgl_entries = wqe->num_sge1 + wqe->num_sge2;
	wqe->gdma_oob->tx.inline_client_oob_size = INLINE_OOB_LARGE_SIZE / sizeof(uint32_t);
	if (flags & GDMA_WORK_REQ_EXTRA_LARGE_OOB) {
		/* the first SGE was a part of the extra large OOB */
		wqe->gdma_oob->tx.num_sgl_entries -= 1;
		wqe->gdma_oob->tx.inline_client_oob_size += 1;
	}
	wqe->gdma_oob->tx.client_oob_in_sgl = (flags & GDMA_WORK_REQ_OOB_IN_SGL) != 0;
	wqe->gdma_oob->tx.consume_credit = (flags & GDMA_WORK_REQ_CONSUME_CREDIT) != 0;
	wqe->gdma_oob->tx.fence = (flags & GDMA_WORK_REQ_FENCE) != 0;
	wqe->gdma_oob->tx.client_data_unit = mtu;
	wqe->gdma_oob->tx.check_sn = (flags & GDMA_WORK_REQ_CHECK_SN) != 0;
	wqe->gdma_oob->tx.sgl_direct = (flags & GDMA_WORK_REQ_SGL_DIRECT) != 0;

	memcpy(wqe->client_oob, send_oob, INLINE_OOB_LARGE_SIZE);

	gdma_write_sge(wqe, oob_sge, sgl, num_sge);
	gdma_advance_producer(wq, wqe->size_in_bu);
	return 0;
}

static inline int
mana_ib_rc_post_send_request(struct mana_qp *qp, struct ibv_send_wr *wr,
			     struct rc_sq_shadow_wqe *shadow_wqe)
{
	enum  gdma_work_req_flags flags = GDMA_WORK_REQ_NONE;
	struct extra_large_wqe extra_wqe = {0};
	struct rdma_send_oob send_oob = {0};
	struct gdma_wqe gdma_wqe = {0};
	uint32_t num_sge = wr->num_sge;
	void *oob_sge = NULL;
	uint32_t msg_sz = 0;
	int i, ret;

	for (i = 0; i < num_sge; i++)
		msg_sz += wr->sg_list[i].length;

	if (wr->opcode == IBV_WR_RDMA_READ) {
		struct rdma_recv_oob recv_oob = {0};

		recv_oob.psn_start = qp->rc_qp.sq_psn;
		ret = gdma_post_rq_wqe(&qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER], wr->sg_list,
				       &recv_oob, num_sge, GDMA_WORK_REQ_CHECK_SN, &gdma_wqe);
		if (ret) {
			verbs_err(verbs_get_ctx(qp->ibqp.qp.context),
				  "rc post Read data WQE error, ret %d\n", ret);
			goto cleanup;
		}
		shadow_wqe->read_posted_wqe_size_in_bu = gdma_wqe.size_in_bu;
		gdma_ring_recv_doorbell(&qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER], 1);
		// for reads no sge to use dummy sgl
		num_sge = 0;
	}

	send_oob.wqe_type = convert_wr_to_hw_opcode(wr->opcode);
	send_oob.fence = (wr->send_flags & IBV_SEND_FENCE) != 0;
	send_oob.signaled = (wr->send_flags & IBV_SEND_SIGNALED) != 0;
	send_oob.solicited = (wr->send_flags & IBV_SEND_SOLICITED) != 0;
	send_oob.psn = qp->rc_qp.sq_psn;
	send_oob.ssn = qp->rc_qp.sq_ssn;

	switch (wr->opcode) {
	case IBV_WR_SEND_WITH_INV:
		flags |= GDMA_WORK_REQ_CHECK_SN;
		send_oob.send.invalidate_key = wr->invalidate_rkey;
		break;
	case IBV_WR_SEND_WITH_IMM:
		send_oob.send.immediate = htole32(be32toh(wr->imm_data));
		SWITCH_FALLTHROUGH;
	case IBV_WR_SEND:
		flags |= GDMA_WORK_REQ_CHECK_SN;
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		flags |= GDMA_WORK_REQ_CHECK_SN;
		flags |= GDMA_WORK_REQ_EXTRA_LARGE_OOB;
		extra_wqe.immediate = htole32(be32toh(wr->imm_data));
		oob_sge = &extra_wqe;
		SWITCH_FALLTHROUGH;
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_READ:
		send_oob.rdma.address_hi = (uint32_t)(wr->wr.rdma.remote_addr >> 32);
		send_oob.rdma.address_low = (uint32_t)(wr->wr.rdma.remote_addr & 0xFFFFFFFF);
		send_oob.rdma.rkey = wr->wr.rdma.rkey;
		send_oob.rdma.dma_len = msg_sz;
		break;
	default:
		goto cleanup;
	}

	ret = gdma_post_sq_wqe(&qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER], wr->sg_list,
			       &send_oob, oob_sge, num_sge, MTU_SIZE(qp->mtu), flags, &gdma_wqe);
	if (ret) {
		verbs_err(verbs_get_ctx(qp->ibqp.qp.context),
			  "rc post send error, ret %d\n", ret);
		goto cleanup;
	}

	qp->rc_qp.sq_psn = PSN_ADD(qp->rc_qp.sq_psn, PSN_DELTA(msg_sz, qp->mtu));
	qp->rc_qp.sq_ssn = PSN_INC(qp->rc_qp.sq_ssn);

	shadow_wqe->header.wr_id = wr->wr_id;
	shadow_wqe->header.opcode = convert_wr_to_wc(wr->opcode);
	shadow_wqe->header.flags = (wr->send_flags & IBV_SEND_SIGNALED) ? 0 : MANA_NO_SIGNAL_WC;
	shadow_wqe->header.posted_wqe_size_in_bu = gdma_wqe.size_in_bu;
	shadow_wqe->header.unmasked_queue_offset = gdma_wqe.unmasked_wqe_index;
	shadow_wqe->end_psn = PSN_DEC(qp->rc_qp.sq_psn);

	return 0;

cleanup:
	return EINVAL;
}

static int mana_ib_rc_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
				struct ibv_send_wr **bad_wr)
{
	struct mana_qp *qp = container_of(ibqp, struct mana_qp, ibqp.qp);
	int ret = 0;
	bool ring = false;

	pthread_spin_lock(&qp->sq_lock);

	for (; wr; wr = wr->next) {
		if ((wr->send_flags & IBV_SEND_SIGNALED) && shadow_queue_full(&qp->shadow_sq)) {
			verbs_err(verbs_get_ctx(ibqp->context), "shadow queue full\n");
			ret = ENOMEM;
			goto cleanup;
		}

		if (!is_opcode_supported(wr->opcode)) {
			ret = EINVAL;
			goto cleanup;
		}

		/* Fill shadow queue data */
		struct rc_sq_shadow_wqe *shadow_wqe = (struct rc_sq_shadow_wqe *)
			shadow_queue_producer_entry(&qp->shadow_sq);
		memset(shadow_wqe, 0, sizeof(struct rc_sq_shadow_wqe));

		ret = mana_ib_rc_post_send_request(qp, wr, shadow_wqe);
		if (ret) {
			verbs_err(verbs_get_ctx(qp->ibqp.qp.context),
				  "Failed to post send request ret %d\n", ret);
			goto cleanup;
		}
		ring = true;

		shadow_queue_advance_producer(&qp->shadow_sq);
		mana_ib_update_shared_mem_right_offset(qp, shadow_wqe->header.unmasked_queue_offset);
	}

cleanup:
	if (ring)
		gdma_ring_send_doorbell(&qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER]);
	pthread_spin_unlock(&qp->sq_lock);
	if (bad_wr && ret)
		*bad_wr = wr;

	return ret;
}

int mana_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		   struct ibv_send_wr **bad)
{
	switch (ibqp->qp_type) {
	case IBV_QPT_RC:
		return mana_ib_rc_post_send(ibqp, wr, bad);
	default:
		verbs_err(verbs_get_ctx(ibqp->context), "QPT not supported %d\n", ibqp->qp_type);
		return EOPNOTSUPP;
	}
}
