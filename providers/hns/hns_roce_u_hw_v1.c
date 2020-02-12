/*
 * Copyright (c) 2016 Hisilicon Limited.
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
 *        disclaimer in the documentation and/or other materials
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

#include <stdio.h>
#include <string.h>
#include "hns_roce_u_db.h"
#include "hns_roce_u_hw_v1.h"
#include "hns_roce_u.h"

static inline void set_raddr_seg(struct hns_roce_wqe_raddr_seg *rseg,
				 uint64_t remote_addr, uint32_t rkey)
{
	rseg->raddr    = htole64(remote_addr);
	rseg->rkey     = htole32(rkey);
	rseg->len      = 0;
}

static void set_data_seg(struct hns_roce_wqe_data_seg *dseg, struct ibv_sge *sg)
{

	dseg->lkey = htole32(sg->lkey);
	dseg->addr = htole64(sg->addr);
	dseg->len = htole32(sg->length);
}

static void hns_roce_update_rq_head(struct hns_roce_context *ctx,
				    unsigned int qpn, unsigned int rq_head)
{
	struct hns_roce_rq_db rq_db;

	rq_db.u32_4 = 0;
	rq_db.u32_8 = 0;

	roce_set_field(rq_db.u32_4, RQ_DB_U32_4_RQ_HEAD_M,
		       RQ_DB_U32_4_RQ_HEAD_S, rq_head);
	roce_set_field(rq_db.u32_8, RQ_DB_U32_8_QPN_M, RQ_DB_U32_8_QPN_S, qpn);
	roce_set_field(rq_db.u32_8, RQ_DB_U32_8_CMD_M, RQ_DB_U32_8_CMD_S, 1);
	roce_set_bit(rq_db.u32_8, RQ_DB_U32_8_HW_SYNC_S, 1);

	udma_to_device_barrier();

	hns_roce_write64((uint32_t *)&rq_db, ctx, ROCEE_DB_OTHERS_L_0_REG);
}

static void hns_roce_update_sq_head(struct hns_roce_context *ctx,
				    unsigned int qpn, unsigned int port,
				    unsigned int sl, unsigned int sq_head)
{
	struct hns_roce_sq_db sq_db;

	sq_db.u32_4 = 0;
	sq_db.u32_8 = 0;

	roce_set_field(sq_db.u32_4, SQ_DB_U32_4_SQ_HEAD_M,
		       SQ_DB_U32_4_SQ_HEAD_S, sq_head);
	roce_set_field(sq_db.u32_4, SQ_DB_U32_4_PORT_M, SQ_DB_U32_4_PORT_S,
		       port);
	roce_set_field(sq_db.u32_4, SQ_DB_U32_4_SL_M, SQ_DB_U32_4_SL_S, sl);
	roce_set_field(sq_db.u32_8, SQ_DB_U32_8_QPN_M, SQ_DB_U32_8_QPN_S, qpn);
	roce_set_bit(sq_db.u32_8, SQ_DB_U32_8_HW_SYNC, 1);

	udma_to_device_barrier();

	hns_roce_write64((uint32_t *)&sq_db, ctx, ROCEE_DB_SQ_L_0_REG);
}

static void hns_roce_update_cq_cons_index(struct hns_roce_context *ctx,
					  struct hns_roce_cq *cq)
{
	struct hns_roce_cq_db cq_db;

	cq_db.u32_4 = 0;
	cq_db.u32_8 = 0;

	roce_set_bit(cq_db.u32_8, CQ_DB_U32_8_HW_SYNC_S, 1);
	roce_set_field(cq_db.u32_8, CQ_DB_U32_8_CMD_M, CQ_DB_U32_8_CMD_S, 3);
	roce_set_field(cq_db.u32_8, CQ_DB_U32_8_CMD_MDF_M,
		       CQ_DB_U32_8_CMD_MDF_S, 0);
	roce_set_field(cq_db.u32_8, CQ_DB_U32_8_CQN_M, CQ_DB_U32_8_CQN_S,
		       cq->cqn);
	roce_set_field(cq_db.u32_4, CQ_DB_U32_4_CONS_IDX_M,
		       CQ_DB_U32_4_CONS_IDX_S,
		       cq->cons_index & ((cq->cq_depth << 1) - 1));

	hns_roce_write64((uint32_t *)&cq_db, ctx, ROCEE_DB_OTHERS_L_0_REG);
}

static void hns_roce_handle_error_cqe(struct hns_roce_cqe *cqe,
				      struct ibv_wc *wc)
{
	fprintf(stderr, PFX "error cqe!\n");
	switch (roce_get_field(cqe->cqe_byte_4,
			       CQE_BYTE_4_STATUS_OF_THE_OPERATION_M,
			       CQE_BYTE_4_STATUS_OF_THE_OPERATION_S) &
		HNS_ROCE_CQE_STATUS_MASK) {
	case HNS_ROCE_CQE_SYNDROME_LOCAL_LENGTH_ERR:
		wc->status = IBV_WC_LOC_LEN_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_LOCAL_QP_OP_ERR:
		wc->status = IBV_WC_LOC_QP_OP_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_LOCAL_PROT_ERR:
		wc->status = IBV_WC_LOC_PROT_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_WR_FLUSH_ERR:
		wc->status = IBV_WC_WR_FLUSH_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_MEM_MANAGE_OPERATE_ERR:
		wc->status = IBV_WC_MW_BIND_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_BAD_RESP_ERR:
		wc->status = IBV_WC_BAD_RESP_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_LOCAL_ACCESS_ERR:
		wc->status = IBV_WC_LOC_ACCESS_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR:
		wc->status = IBV_WC_REM_INV_REQ_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_REMOTE_ACCESS_ERR:
		wc->status = IBV_WC_REM_ACCESS_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_REMOTE_OP_ERR:
		wc->status = IBV_WC_REM_OP_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR:
		wc->status = IBV_WC_RETRY_EXC_ERR;
		break;
	case HNS_ROCE_CQE_SYNDROME_RNR_RETRY_EXC_ERR:
		wc->status = IBV_WC_RNR_RETRY_EXC_ERR;
		break;
	default:
		wc->status = IBV_WC_GENERAL_ERR;
		break;
	}
}

static struct hns_roce_cqe *get_cqe(struct hns_roce_cq *cq, int entry)
{
	return cq->buf.buf + entry * HNS_ROCE_CQE_ENTRY_SIZE;
}

static void *get_sw_cqe(struct hns_roce_cq *cq, int n)
{
	struct hns_roce_cqe *cqe = get_cqe(cq, n & cq->ibv_cq.cqe);

	return (!!(roce_get_bit(cqe->cqe_byte_4, CQE_BYTE_4_OWNER_S)) ^
		!!(n & (cq->ibv_cq.cqe + 1))) ? cqe : NULL;
}

static struct hns_roce_cqe *next_cqe_sw(struct hns_roce_cq *cq)
{
	return get_sw_cqe(cq, cq->cons_index);
}

static void *get_recv_wqe(struct hns_roce_qp *qp, int n)
{
	if ((n < 0) || (n > qp->rq.wqe_cnt)) {
		printf("rq wqe index:%d,rq wqe cnt:%d\r\n", n, qp->rq.wqe_cnt);
		return NULL;
	}

	return qp->buf.buf + qp->rq.offset + (n << qp->rq.wqe_shift);
}

static void *get_send_wqe(struct hns_roce_qp *qp, int n)
{
	if ((n < 0) || (n > qp->sq.wqe_cnt)) {
		printf("sq wqe index:%d,sq wqe cnt:%d\r\n", n, qp->sq.wqe_cnt);
		return NULL;
	}

	return (void *)(qp->buf.buf + qp->sq.offset + (n << qp->sq.wqe_shift));
}

static int hns_roce_wq_overflow(struct hns_roce_wq *wq, int nreq,
				struct hns_roce_cq *cq)
{
	unsigned int cur;

	cur = wq->head - wq->tail;
	if (cur + nreq < wq->max_post)
		return 0;

	/* While the num of wqe exceeds cap of the device, cq will be locked */
	pthread_spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	pthread_spin_unlock(&cq->lock);

	printf("wq:(head = %d, tail = %d, max_post = %d), nreq = 0x%x\n",
		wq->head, wq->tail, wq->max_post, nreq);

	return cur + nreq >= wq->max_post;
}

static struct hns_roce_qp *hns_roce_find_qp(struct hns_roce_context *ctx,
					    uint32_t qpn)
{
	int tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;

	if (ctx->qp_table[tind].refcnt) {
		return ctx->qp_table[tind].table[qpn & ctx->qp_table_mask];
	} else {
		printf("hns_roce_find_qp fail!\n");
		return NULL;
	}
}

static void hns_roce_clear_qp(struct hns_roce_context *ctx, uint32_t qpn)
{
	int tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;

	if (!--ctx->qp_table[tind].refcnt)
		free(ctx->qp_table[tind].table);
	else
		ctx->qp_table[tind].table[qpn & ctx->qp_table_mask] = NULL;
}

static int hns_roce_v1_poll_one(struct hns_roce_cq *cq,
				struct hns_roce_qp **cur_qp, struct ibv_wc *wc)
{
	uint32_t qpn;
	int is_send;
	uint16_t wqe_ctr;
	uint32_t local_qpn;
	struct hns_roce_wq *wq = NULL;
	struct hns_roce_cqe *cqe = NULL;
	struct hns_roce_wqe_ctrl_seg *sq_wqe = NULL;

	/* According to CI, find the relative cqe */
	cqe = next_cqe_sw(cq);
	if (!cqe)
		return CQ_EMPTY;

	/* Get the next cqe, CI will be added gradually */
	++cq->cons_index;

	udma_from_device_barrier();

	qpn = roce_get_field(cqe->cqe_byte_16, CQE_BYTE_16_LOCAL_QPN_M,
			     CQE_BYTE_16_LOCAL_QPN_S);

	is_send = (roce_get_bit(cqe->cqe_byte_4, CQE_BYTE_4_SQ_RQ_FLAG_S) ==
		   HNS_ROCE_CQE_IS_SQ);

	local_qpn = roce_get_field(cqe->cqe_byte_16, CQE_BYTE_16_LOCAL_QPN_M,
				   CQE_BYTE_16_LOCAL_QPN_S);

	/* if qp is zero, it will not get the correct qpn */
	if (!*cur_qp ||
	    (local_qpn & HNS_ROCE_CQE_QPN_MASK) != (*cur_qp)->ibv_qp.qp_num) {

		*cur_qp = hns_roce_find_qp(to_hr_ctx(cq->ibv_cq.context),
					   qpn & 0xffffff);
		if (!*cur_qp) {
			fprintf(stderr, PFX "can't find qp!\n");
			return CQ_POLL_ERR;
		}
	}
	wc->qp_num = qpn & 0xffffff;

	if (is_send) {
		wq = &(*cur_qp)->sq;
		/*
		 * if sq_signal_bits is 1, the tail pointer first update to
		 * the wqe corresponding the current cqe
		 */
		if ((*cur_qp)->sq_signal_bits) {
			wqe_ctr = (uint16_t)(roce_get_field(cqe->cqe_byte_4,
						CQE_BYTE_4_WQE_INDEX_M,
						CQE_BYTE_4_WQE_INDEX_S));
			/*
			 * wq->tail will plus a positive number every time,
			 * when wq->tail exceeds 32b, it is 0 and acc
			 */
			wq->tail += (wqe_ctr - (uint16_t) wq->tail) &
				    (wq->wqe_cnt - 1);
		}
		/* write the wr_id of wq into the wc */
		wc->wr_id = wq->wrid[wq->tail & (wq->wqe_cnt - 1)];
		++wq->tail;
	} else {
		wq = &(*cur_qp)->rq;
		wc->wr_id = wq->wrid[wq->tail & (wq->wqe_cnt - 1)];
		++wq->tail;
	}

	/*
	 * HW maintains wc status, set the err type and directly return, after
	 * generated the incorrect CQE
	 */
	if (roce_get_field(cqe->cqe_byte_4,
	    CQE_BYTE_4_STATUS_OF_THE_OPERATION_M,
	    CQE_BYTE_4_STATUS_OF_THE_OPERATION_S) != HNS_ROCE_CQE_SUCCESS) {
		hns_roce_handle_error_cqe(cqe, wc);
		return CQ_OK;
	}
	wc->status = IBV_WC_SUCCESS;

	/*
	 * According to the opcode type of cqe, mark the opcode and other
	 * information of wc
	 */
	if (is_send) {
		/* Get opcode and flag before update the tail point for send */
		sq_wqe = (struct hns_roce_wqe_ctrl_seg *)
			 get_send_wqe(*cur_qp, roce_get_field(cqe->cqe_byte_4,
						CQE_BYTE_4_WQE_INDEX_M,
						CQE_BYTE_4_WQE_INDEX_S));
		switch (le32toh(sq_wqe->flag) & HNS_ROCE_WQE_OPCODE_MASK) {
		case HNS_ROCE_WQE_OPCODE_SEND:
			wc->opcode = IBV_WC_SEND;
			break;
		case HNS_ROCE_WQE_OPCODE_RDMA_READ:
			wc->opcode = IBV_WC_RDMA_READ;
			wc->byte_len = le32toh(cqe->byte_cnt);
			break;
		case HNS_ROCE_WQE_OPCODE_RDMA_WRITE:
			wc->opcode = IBV_WC_RDMA_WRITE;
			break;
		case HNS_ROCE_WQE_OPCODE_BIND_MW2:
			wc->opcode = IBV_WC_BIND_MW;
			break;
		default:
			wc->status = IBV_WC_GENERAL_ERR;
			break;
		}
		wc->wc_flags = (le32toh(sq_wqe->flag) & HNS_ROCE_WQE_IMM ?
				IBV_WC_WITH_IMM : 0);
	} else {
		/* Get opcode and flag in rq&srq */
		wc->byte_len = le32toh(cqe->byte_cnt);

		switch (roce_get_field(cqe->cqe_byte_4,
				       CQE_BYTE_4_OPERATION_TYPE_M,
				       CQE_BYTE_4_OPERATION_TYPE_S) &
			HNS_ROCE_CQE_OPCODE_MASK) {
		case HNS_ROCE_OPCODE_RDMA_WITH_IMM_RECEIVE:
			wc->opcode   = IBV_WC_RECV_RDMA_WITH_IMM;
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = htobe32(le32toh(cqe->immediate_data));
			break;
		case HNS_ROCE_OPCODE_SEND_DATA_RECEIVE:
			if (roce_get_bit(cqe->cqe_byte_4,
					 CQE_BYTE_4_IMMEDIATE_DATA_FLAG_S)) {
				wc->opcode   = IBV_WC_RECV;
				wc->wc_flags = IBV_WC_WITH_IMM;
				wc->imm_data =
					htobe32(le32toh(cqe->immediate_data));
			} else {
				wc->opcode   = IBV_WC_RECV;
				wc->wc_flags = 0;
			}
			break;
		default:
			wc->status = IBV_WC_GENERAL_ERR;
			break;
		}
	}

	return CQ_OK;
}

static int hns_roce_u_v1_poll_cq(struct ibv_cq *ibvcq, int ne,
				 struct ibv_wc *wc)
{
	int npolled;
	int err = CQ_OK;
	struct hns_roce_qp *qp = NULL;
	struct hns_roce_cq *cq = to_hr_cq(ibvcq);
	struct hns_roce_context *ctx = to_hr_ctx(ibvcq->context);
	struct hns_roce_device *dev = to_hr_dev(ibvcq->context->device);

	pthread_spin_lock(&cq->lock);

	for (npolled = 0; npolled < ne; ++npolled) {
		err = hns_roce_v1_poll_one(cq, &qp, wc + npolled);
		if (err != CQ_OK)
			break;
	}

	if (npolled) {
		if (dev->hw_version == HNS_ROCE_HW_VER1) {
			*cq->set_ci_db = (cq->cons_index &
					 ((cq->cq_depth << 1) - 1));
			mmio_ordered_writes_hack();
		}

		hns_roce_update_cq_cons_index(ctx, cq);
	}

	pthread_spin_unlock(&cq->lock);

	return err == CQ_POLL_ERR ? err : npolled;
}

/**
 * hns_roce_u_v1_arm_cq - request completion notification on a CQ
 * @ibvcq: The completion queue to request notification for.
 * @solicited: If non-zero, a event will be generated only for
 *	      the next solicited CQ entry. If zero, any CQ entry,
 *	      solicited or not, will generate an event
 */
static int hns_roce_u_v1_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	uint32_t ci;
	uint32_t solicited_flag;
	struct hns_roce_cq_db cq_db;
	struct hns_roce_cq *cq = to_hr_cq(ibvcq);

	ci  = cq->cons_index & ((cq->cq_depth << 1) - 1);
	solicited_flag = solicited ? HNS_ROCE_CQ_DB_REQ_SOL :
				     HNS_ROCE_CQ_DB_REQ_NEXT;

	cq_db.u32_4 = 0;
	cq_db.u32_8 = 0;

	roce_set_bit(cq_db.u32_8, CQ_DB_U32_8_HW_SYNC_S, 1);
	roce_set_field(cq_db.u32_8, CQ_DB_U32_8_CMD_M, CQ_DB_U32_8_CMD_S, 3);
	roce_set_field(cq_db.u32_8, CQ_DB_U32_8_CMD_MDF_M,
		       CQ_DB_U32_8_CMD_MDF_S, 1);
	roce_set_bit(cq_db.u32_8, CQ_DB_U32_8_NOTIFY_TYPE_S, solicited_flag);
	roce_set_field(cq_db.u32_8, CQ_DB_U32_8_CQN_M, CQ_DB_U32_8_CQN_S,
		       cq->cqn);
	roce_set_field(cq_db.u32_4, CQ_DB_U32_4_CONS_IDX_M,
		       CQ_DB_U32_4_CONS_IDX_S, ci);

	hns_roce_write64((uint32_t *)&cq_db, to_hr_ctx(ibvcq->context),
			  ROCEE_DB_OTHERS_L_0_REG);
	return 0;
}

static int hns_roce_u_v1_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
				   struct ibv_send_wr **bad_wr)
{
	void *wqe;
	int nreq;
	int ps_opcode, i;
	int ret = 0;
	struct hns_roce_wqe_ctrl_seg *ctrl = NULL;
	struct hns_roce_wqe_data_seg *dseg = NULL;
	struct hns_roce_qp *qp = to_hr_qp(ibvqp);
	struct hns_roce_context *ctx = to_hr_ctx(ibvqp->context);
	unsigned int wqe_idx;

	pthread_spin_lock(&qp->sq.lock);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (hns_roce_wq_overflow(&qp->sq, nreq,
					 to_hr_cq(qp->ibv_qp.send_cq))) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		wqe_idx = (qp->sq.head + nreq) & (qp->rq.wqe_cnt - 1);

		if (wr->num_sge > qp->sq.max_gs) {
			ret = -1;
			*bad_wr = wr;
			printf("wr->num_sge(<=%d) = %d, check failed!\r\n",
				qp->sq.max_gs, wr->num_sge);
			goto out;
		}

		ctrl = wqe = get_send_wqe(qp, wqe_idx);
		memset(ctrl, 0, sizeof(struct hns_roce_wqe_ctrl_seg));

		qp->sq.wrid[wqe_idx] = wr->wr_id;
		for (i = 0; i < wr->num_sge; i++)
			ctrl->msg_length = htole32(le32toh(ctrl->msg_length) +
						   wr->sg_list[i].length);

		ctrl->flag |= htole32(((wr->send_flags & IBV_SEND_SIGNALED) ?
				HNS_ROCE_WQE_CQ_NOTIFY : 0) |
			      (wr->send_flags & IBV_SEND_SOLICITED ?
				HNS_ROCE_WQE_SE : 0) |
			      ((wr->opcode == IBV_WR_SEND_WITH_IMM ||
			       wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM) ?
				HNS_ROCE_WQE_IMM : 0) |
			      (wr->send_flags & IBV_SEND_FENCE ?
				HNS_ROCE_WQE_FENCE : 0));

		if (wr->opcode == IBV_WR_SEND_WITH_IMM ||
		    wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
			ctrl->imm_data = htole32(be32toh(wr->imm_data));

		wqe += sizeof(struct hns_roce_wqe_ctrl_seg);

		/* set remote addr segment */
		switch (ibvqp->qp_type) {
		case IBV_QPT_RC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_READ:
				ps_opcode = HNS_ROCE_WQE_OPCODE_RDMA_READ;
				set_raddr_seg(wqe, wr->wr.rdma.remote_addr,
					      wr->wr.rdma.rkey);
				break;
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				ps_opcode = HNS_ROCE_WQE_OPCODE_RDMA_WRITE;
				set_raddr_seg(wqe, wr->wr.rdma.remote_addr,
					      wr->wr.rdma.rkey);
				break;
			case IBV_WR_SEND:
			case IBV_WR_SEND_WITH_IMM:
				ps_opcode = HNS_ROCE_WQE_OPCODE_SEND;
				break;
			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
			default:
				ps_opcode = HNS_ROCE_WQE_OPCODE_MASK;
				break;
			}
			ctrl->flag |= htole32(ps_opcode);
			wqe  += sizeof(struct hns_roce_wqe_raddr_seg);
			break;
		case IBV_QPT_UC:
		case IBV_QPT_UD:
		default:
			break;
		}

		dseg = wqe;

		/* Inline */
		if (wr->send_flags & IBV_SEND_INLINE && wr->num_sge) {
			if (le32toh(ctrl->msg_length) > qp->max_inline_data) {
				ret = -1;
				*bad_wr = wr;
				printf("inline data len(1-32)=%d, send_flags = 0x%x, check failed!\r\n",
					wr->send_flags, ctrl->msg_length);
				return ret;
			}

			for (i = 0; i < wr->num_sge; i++) {
				memcpy(wqe,
				     ((void *) (uintptr_t) wr->sg_list[i].addr),
				     wr->sg_list[i].length);
				wqe = wqe + wr->sg_list[i].length;
			}

			ctrl->flag |= htole32(HNS_ROCE_WQE_INLINE);
		} else {
			/* set sge */
			for (i = 0; i < wr->num_sge; i++)
				set_data_seg(dseg+i, wr->sg_list + i);

			ctrl->flag |=
			       htole32(wr->num_sge << HNS_ROCE_WQE_SGE_NUM_BIT);
		}
	}

out:
	/* Set DB return */
	if (likely(nreq)) {
		qp->sq.head += nreq;

		hns_roce_update_sq_head(ctx, qp->ibv_qp.qp_num,
				qp->port_num - 1, qp->sl,
				qp->sq.head & ((qp->sq.wqe_cnt << 1) - 1));
	}

	pthread_spin_unlock(&qp->sq.lock);

	return ret;
}

static void __hns_roce_v1_cq_clean(struct hns_roce_cq *cq, uint32_t qpn,
				   struct hns_roce_srq *srq)
{
	int nfreed = 0;
	uint32_t prod_index;
	uint8_t owner_bit = 0;
	struct hns_roce_cqe *cqe, *dest;
	struct hns_roce_context *ctx = to_hr_ctx(cq->ibv_cq.context);

	for (prod_index = cq->cons_index; get_sw_cqe(cq, prod_index);
	     ++prod_index)
		if (prod_index == cq->cons_index + cq->ibv_cq.cqe)
			break;

	while ((int) --prod_index - (int) cq->cons_index >= 0) {
		cqe = get_cqe(cq, prod_index & cq->ibv_cq.cqe);
		if ((roce_get_field(cqe->cqe_byte_16, CQE_BYTE_16_LOCAL_QPN_M,
			      CQE_BYTE_16_LOCAL_QPN_S) & 0xffffff) == qpn) {
			++nfreed;
		} else if (nfreed) {
			dest = get_cqe(cq,
				       (prod_index + nfreed) & cq->ibv_cq.cqe);
			owner_bit = roce_get_bit(dest->cqe_byte_4,
						 CQE_BYTE_4_OWNER_S);
			memcpy(dest, cqe, sizeof(*cqe));
			roce_set_bit(dest->cqe_byte_4, CQE_BYTE_4_OWNER_S,
				     owner_bit);
		}
	}

	if (nfreed) {
		cq->cons_index += nfreed;
		udma_to_device_barrier();
		hns_roce_update_cq_cons_index(ctx, cq);
	}
}

static void hns_roce_v1_cq_clean(struct hns_roce_cq *cq, unsigned int qpn,
				 struct hns_roce_srq *srq)
{
	pthread_spin_lock(&cq->lock);
	__hns_roce_v1_cq_clean(cq, qpn, srq);
	pthread_spin_unlock(&cq->lock);
}

static int hns_roce_u_v1_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
				   int attr_mask)
{
	int ret;
	struct ibv_modify_qp cmd = {};
	struct hns_roce_qp *hr_qp = to_hr_qp(qp);

	ret = ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));

	if (!ret && (attr_mask & IBV_QP_STATE) &&
	    attr->qp_state == IBV_QPS_RESET) {
		hns_roce_v1_cq_clean(to_hr_cq(qp->recv_cq), qp->qp_num,
				     qp->srq ? to_hr_srq(qp->srq) : NULL);
		if (qp->send_cq != qp->recv_cq)
			hns_roce_v1_cq_clean(to_hr_cq(qp->send_cq), qp->qp_num,
					     NULL);

		hns_roce_init_qp_indices(to_hr_qp(qp));
	}

	if (!ret && (attr_mask & IBV_QP_PORT)) {
		hr_qp->port_num = attr->port_num;
		printf("hr_qp->port_num= 0x%x\n", hr_qp->port_num);
	}

	hr_qp->sl = attr->ah_attr.sl;

	return ret;
}

static void hns_roce_lock_cqs(struct ibv_qp *qp)
{
	struct hns_roce_cq *send_cq = to_hr_cq(qp->send_cq);
	struct hns_roce_cq *recv_cq = to_hr_cq(qp->recv_cq);

	if (send_cq == recv_cq) {
		pthread_spin_lock(&send_cq->lock);
	} else if (send_cq->cqn < recv_cq->cqn) {
		pthread_spin_lock(&send_cq->lock);
		pthread_spin_lock(&recv_cq->lock);
	} else {
		pthread_spin_lock(&recv_cq->lock);
		pthread_spin_lock(&send_cq->lock);
	}
}

static void hns_roce_unlock_cqs(struct ibv_qp *qp)
{
	struct hns_roce_cq *send_cq = to_hr_cq(qp->send_cq);
	struct hns_roce_cq *recv_cq = to_hr_cq(qp->recv_cq);

	if (send_cq == recv_cq) {
		pthread_spin_unlock(&send_cq->lock);
	} else if (send_cq->cqn < recv_cq->cqn) {
		pthread_spin_unlock(&recv_cq->lock);
		pthread_spin_unlock(&send_cq->lock);
	} else {
		pthread_spin_unlock(&send_cq->lock);
		pthread_spin_unlock(&recv_cq->lock);
	}
}

static int hns_roce_u_v1_destroy_qp(struct ibv_qp *ibqp)
{
	int ret;
	struct hns_roce_qp *qp = to_hr_qp(ibqp);

	pthread_mutex_lock(&to_hr_ctx(ibqp->context)->qp_table_mutex);
	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		pthread_mutex_unlock(&to_hr_ctx(ibqp->context)->qp_table_mutex);
		return ret;
	}

	hns_roce_lock_cqs(ibqp);

	__hns_roce_v1_cq_clean(to_hr_cq(ibqp->recv_cq), ibqp->qp_num,
			       ibqp->srq ? to_hr_srq(ibqp->srq) : NULL);

	if (ibqp->send_cq != ibqp->recv_cq)
		__hns_roce_v1_cq_clean(to_hr_cq(ibqp->send_cq), ibqp->qp_num,
				       NULL);

	hns_roce_clear_qp(to_hr_ctx(ibqp->context), ibqp->qp_num);

	hns_roce_unlock_cqs(ibqp);
	pthread_mutex_unlock(&to_hr_ctx(ibqp->context)->qp_table_mutex);

	free(qp->sq.wrid);
	if (qp->rq.wqe_cnt)
		free(qp->rq.wrid);

	hns_roce_free_buf(&qp->buf);
	free(qp);

	return ret;
}

static int hns_roce_u_v1_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
				   struct ibv_recv_wr **bad_wr)
{
	int ret = 0;
	int nreq;
	struct ibv_sge *sg;
	struct hns_roce_rc_rq_wqe *rq_wqe;
	struct hns_roce_qp *qp = to_hr_qp(ibvqp);
	struct hns_roce_context *ctx = to_hr_ctx(ibvqp->context);
	unsigned int wqe_idx;

	pthread_spin_lock(&qp->rq.lock);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (hns_roce_wq_overflow(&qp->rq, nreq,
					 to_hr_cq(qp->ibv_qp.recv_cq))) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		wqe_idx = (qp->rq.head + nreq) & (qp->rq.wqe_cnt - 1);

		if (wr->num_sge > qp->rq.max_gs) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		rq_wqe = get_recv_wqe(qp, wqe_idx);
		if (wr->num_sge > HNS_ROCE_RC_RQ_WQE_MAX_SGE_NUM) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge == HNS_ROCE_RC_RQ_WQE_MAX_SGE_NUM) {
			roce_set_field(rq_wqe->u32_2,
				       RC_RQ_WQE_NUMBER_OF_DATA_SEG_M,
				       RC_RQ_WQE_NUMBER_OF_DATA_SEG_S,
				       HNS_ROCE_RC_RQ_WQE_MAX_SGE_NUM);
			sg = wr->sg_list;

			rq_wqe->va0 = htole64(sg->addr);
			rq_wqe->l_key0 = htole32(sg->lkey);
			rq_wqe->length0 = htole32(sg->length);

			sg = wr->sg_list + 1;

			rq_wqe->va1 = htole64(sg->addr);
			rq_wqe->l_key1 = htole32(sg->lkey);
			rq_wqe->length1 = htole32(sg->length);
		} else if (wr->num_sge == HNS_ROCE_RC_RQ_WQE_MAX_SGE_NUM - 1) {
			roce_set_field(rq_wqe->u32_2,
				       RC_RQ_WQE_NUMBER_OF_DATA_SEG_M,
				       RC_RQ_WQE_NUMBER_OF_DATA_SEG_S,
				       HNS_ROCE_RC_RQ_WQE_MAX_SGE_NUM - 1);
			sg = wr->sg_list;

			rq_wqe->va0 = htole64(sg->addr);
			rq_wqe->l_key0 = htole32(sg->lkey);
			rq_wqe->length0 = htole32(sg->length);

		} else if (wr->num_sge == HNS_ROCE_RC_RQ_WQE_MAX_SGE_NUM - 2) {
			roce_set_field(rq_wqe->u32_2,
				       RC_RQ_WQE_NUMBER_OF_DATA_SEG_M,
				       RC_RQ_WQE_NUMBER_OF_DATA_SEG_S,
				       HNS_ROCE_RC_RQ_WQE_MAX_SGE_NUM - 2);
		}

		qp->rq.wrid[wqe_idx] = wr->wr_id;
	}

out:
	if (nreq) {
		qp->rq.head += nreq;

		hns_roce_update_rq_head(ctx, qp->ibv_qp.qp_num,
				    qp->rq.head & ((qp->rq.wqe_cnt << 1) - 1));
	}

	pthread_spin_unlock(&qp->rq.lock);

	return ret;
}

const struct hns_roce_u_hw hns_roce_u_hw_v1 = {
	.hw_version = HNS_ROCE_HW_VER1,
	.hw_ops = {
		.poll_cq = hns_roce_u_v1_poll_cq,
		.req_notify_cq = hns_roce_u_v1_arm_cq,
		.post_send = hns_roce_u_v1_post_send,
		.post_recv = hns_roce_u_v1_post_recv,
		.modify_qp = hns_roce_u_v1_modify_qp,
		.destroy_qp = hns_roce_u_v1_destroy_qp,
	},
};
