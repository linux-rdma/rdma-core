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
#include <malloc.h>
#include "hns_roce_u_db.h"
#include "hns_roce_u_hw_v1.h"
#include "hns_roce_u.h"

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
	switch (roce_get_field(cqe->cqe_byte_4,
			       CQE_BYTE_4_STATUS_OF_THE_OPERATION_M,
			       CQE_BYTE_4_STATUS_OF_THE_OPERATION_S) &
		HNS_ROCE_CQE_STATUS_MASK) {
		fprintf(stderr, PFX "error cqe!\n");
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

static void *get_send_wqe(struct hns_roce_qp *qp, int n)
{
	if ((n < 0) || (n > qp->sq.wqe_cnt)) {
		printf("sq wqe index:%d,sq wqe cnt:%d\r\n", n, qp->sq.wqe_cnt);
		return NULL;
	}

	return (void *)(qp->buf.buf + qp->sq.offset + (n << qp->sq.wqe_shift));
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

	rmb();

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
		switch (sq_wqe->flag & HNS_ROCE_WQE_OPCODE_MASK) {
		case HNS_ROCE_WQE_OPCODE_SEND:
			wc->opcode = IBV_WC_SEND;
			break;
		case HNS_ROCE_WQE_OPCODE_RDMA_READ:
			wc->opcode = IBV_WC_RDMA_READ;
			wc->byte_len = cqe->byte_cnt;
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
		wc->wc_flags = (sq_wqe->flag & HNS_ROCE_WQE_IMM ?
				IBV_WC_WITH_IMM : 0);
	} else {
		/* Get opcode and flag in rq&srq */
		wc->byte_len = (cqe->byte_cnt);

		switch (roce_get_field(cqe->cqe_byte_4,
				       CQE_BYTE_4_OPERATION_TYPE_M,
				       CQE_BYTE_4_OPERATION_TYPE_S) &
			HNS_ROCE_CQE_OPCODE_MASK) {
		case HNS_ROCE_OPCODE_RDMA_WITH_IMM_RECEIVE:
			wc->opcode   = IBV_WC_RECV_RDMA_WITH_IMM;
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = cqe->immediate_data;
			break;
		case HNS_ROCE_OPCODE_SEND_DATA_RECEIVE:
			if (roce_get_bit(cqe->cqe_byte_4,
					 CQE_BYTE_4_IMMEDIATE_DATA_FLAG_S)) {
				wc->opcode   = IBV_WC_RECV;
				wc->wc_flags = IBV_WC_WITH_IMM;
				wc->imm_data = cqe->immediate_data;
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
			*cq->set_ci_db = (unsigned short)(cq->cons_index &
					 ((cq->cq_depth << 1) - 1));
			mb();
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
		wmb();
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
	struct ibv_modify_qp cmd;
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

struct hns_roce_u_hw hns_roce_u_hw_v1 = {
	.poll_cq = hns_roce_u_v1_poll_cq,
	.arm_cq = hns_roce_u_v1_arm_cq,
	.modify_qp = hns_roce_u_v1_modify_qp,
	.destroy_qp = hns_roce_u_v1_destroy_qp,
};
