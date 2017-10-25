/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
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
#include "hns_roce_u.h"
#include "hns_roce_u_db.h"
#include "hns_roce_u_hw_v2.h"

static void hns_roce_v2_handle_error_cqe(struct hns_roce_v2_cqe *cqe,
					 struct ibv_wc *wc)
{
	unsigned int status = roce_get_field(cqe->byte_4, CQE_BYTE_4_STATUS_M,
					     CQE_BYTE_4_STATUS_S);

	fprintf(stderr, PFX "error cqe!\n");
	switch (status & HNS_ROCE_V2_CQE_STATUS_MASK) {
	case HNS_ROCE_V2_CQE_LOCAL_LENGTH_ERR:
		wc->status = IBV_WC_LOC_LEN_ERR;
		break;
	case HNS_ROCE_V2_CQE_LOCAL_QP_OP_ERR:
		wc->status = IBV_WC_LOC_QP_OP_ERR;
		break;
	case HNS_ROCE_V2_CQE_LOCAL_PROT_ERR:
		wc->status = IBV_WC_LOC_PROT_ERR;
		break;
	case HNS_ROCE_V2_CQE_WR_FLUSH_ERR:
		wc->status = IBV_WC_WR_FLUSH_ERR;
		break;
	case HNS_ROCE_V2_CQE_MEM_MANAGERENT_OP_ERR:
		wc->status = IBV_WC_MW_BIND_ERR;
		break;
	case HNS_ROCE_V2_CQE_BAD_RESP_ERR:
		wc->status = IBV_WC_BAD_RESP_ERR;
		break;
	case HNS_ROCE_V2_CQE_LOCAL_ACCESS_ERR:
		wc->status = IBV_WC_LOC_ACCESS_ERR;
		break;
	case HNS_ROCE_V2_CQE_REMOTE_INVAL_REQ_ERR:
		wc->status = IBV_WC_REM_INV_REQ_ERR;
		break;
	case HNS_ROCE_V2_CQE_REMOTE_ACCESS_ERR:
		wc->status = IBV_WC_REM_ACCESS_ERR;
		break;
	case HNS_ROCE_V2_CQE_REMOTE_OP_ERR:
		wc->status = IBV_WC_REM_OP_ERR;
		break;
	case HNS_ROCE_V2_CQE_TRANSPORT_RETRY_EXC_ERR:
		wc->status = IBV_WC_RETRY_EXC_ERR;
		break;
	case HNS_ROCE_V2_CQE_RNR_RETRY_EXC_ERR:
		wc->status = IBV_WC_RNR_RETRY_EXC_ERR;
		break;
	case HNS_ROCE_V2_CQE_REMOTE_ABORTED_ERR:
		wc->status = IBV_WC_REM_ABORT_ERR;
		break;
	default:
		wc->status = IBV_WC_GENERAL_ERR;
		break;
	}
}

static struct hns_roce_v2_cqe *get_cqe_v2(struct hns_roce_cq *cq, int entry)
{
	return cq->buf.buf + entry * HNS_ROCE_CQE_ENTRY_SIZE;
}

static void *get_sw_cqe_v2(struct hns_roce_cq *cq, int n)
{
	struct hns_roce_v2_cqe *cqe = get_cqe_v2(cq, n & cq->ibv_cq.cqe);

	return (!!(roce_get_bit(cqe->byte_4, CQE_BYTE_4_OWNER_S)) ^
		!!(n & (cq->ibv_cq.cqe + 1))) ? cqe : NULL;
}

static struct hns_roce_v2_cqe *next_cqe_sw(struct hns_roce_cq *cq)
{
	return get_sw_cqe_v2(cq, cq->cons_index);
}

static void hns_roce_v2_update_cq_cons_index(struct hns_roce_context *ctx,
					     struct hns_roce_cq *cq)
{
	struct hns_roce_v2_cq_db cq_db;

	cq_db.byte_4 = 0;
	cq_db.parameter = 0;

	roce_set_field(cq_db.byte_4, DB_BYTE_4_TAG_M, DB_BYTE_4_TAG_S, cq->cqn);
	roce_set_field(cq_db.byte_4, DB_BYTE_4_CMD_M, DB_BYTE_4_CMD_S, 0x3);

	roce_set_field(cq_db.parameter, CQ_DB_PARAMETER_CQ_CONSUMER_IDX_M,
		       CQ_DB_PARAMETER_CQ_CONSUMER_IDX_S,
		       cq->cons_index & ((cq->cq_depth << 1) - 1));
	roce_set_field(cq_db.parameter, CQ_DB_PARAMETER_CMD_SN_M,
		       CQ_DB_PARAMETER_CMD_SN_S, 1);
	roce_set_bit(cq_db.parameter, CQ_DB_PARAMETER_NOTIFY_S, 0);

	hns_roce_write64((uint32_t *)&cq_db, ctx, ROCEE_VF_DB_CFG0_OFFSET);
}

static struct hns_roce_qp *hns_roce_v2_find_qp(struct hns_roce_context *ctx,
					       uint32_t qpn)
{
	int tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;

	if (ctx->qp_table[tind].refcnt)
		return ctx->qp_table[tind].table[qpn & ctx->qp_table_mask];
	else
		return NULL;
}

static void hns_roce_v2_clear_qp(struct hns_roce_context *ctx, uint32_t qpn)
{
	int tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;

	if (!--ctx->qp_table[tind].refcnt)
		free(ctx->qp_table[tind].table);
	else
		ctx->qp_table[tind].table[qpn & ctx->qp_table_mask] = NULL;
}

static int hns_roce_v2_poll_one(struct hns_roce_cq *cq,
				struct hns_roce_qp **cur_qp, struct ibv_wc *wc)
{
	uint32_t qpn;
	int is_send;
	uint16_t wqe_ctr;
	uint32_t local_qpn;
	struct hns_roce_wq *wq = NULL;
	struct hns_roce_v2_cqe *cqe = NULL;

	/* According to CI, find the relative cqe */
	cqe = next_cqe_sw(cq);
	if (!cqe)
		return V2_CQ_EMPTY;

	/* Get the next cqe, CI will be added gradually */
	++cq->cons_index;

	udma_from_device_barrier();

	qpn = roce_get_field(cqe->byte_16, CQE_BYTE_16_LCL_QPN_M,
			     CQE_BYTE_16_LCL_QPN_S);

	is_send = (roce_get_bit(cqe->byte_4, CQE_BYTE_4_S_R_S) ==
		   HNS_ROCE_V2_CQE_IS_SQ);

	local_qpn = roce_get_field(cqe->byte_16, CQE_BYTE_16_LCL_QPN_M,
				   CQE_BYTE_16_LCL_QPN_S);

	/* if qp is zero, it will not get the correct qpn */
	if (!*cur_qp ||
	   (local_qpn & HNS_ROCE_V2_CQE_QPN_MASK) != (*cur_qp)->ibv_qp.qp_num) {

		*cur_qp = hns_roce_v2_find_qp(to_hr_ctx(cq->ibv_cq.context),
					      qpn & 0xffffff);
		if (!*cur_qp) {
			fprintf(stderr, PFX "can't find qp!\n");
			return V2_CQ_POLL_ERR;
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
			wqe_ctr = (uint16_t)(roce_get_field(cqe->byte_4,
						CQE_BYTE_4_WQE_IDX_M,
						CQE_BYTE_4_WQE_IDX_S));
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
	if (roce_get_field(cqe->byte_4, CQE_BYTE_4_STATUS_M,
			   CQE_BYTE_4_STATUS_S) != HNS_ROCE_V2_CQE_SUCCESS) {
		hns_roce_v2_handle_error_cqe(cqe, wc);
		return V2_CQ_OK;
	}

	wc->status = IBV_WC_SUCCESS;

	/*
	 * According to the opcode type of cqe, mark the opcode and other
	 * information of wc
	 */
	if (is_send) {
		/* Get opcode and flag before update the tail point for send */
		switch (roce_get_field(cqe->byte_4, CQE_BYTE_4_OPCODE_M,
			CQE_BYTE_4_OPCODE_S) & HNS_ROCE_V2_CQE_OPCODE_MASK) {
		case HNS_ROCE_SQ_OP_SEND:
			wc->opcode = IBV_WC_SEND;
			wc->wc_flags = 0;
			break;

		case HNS_ROCE_SQ_OP_SEND_WITH_IMM:
			wc->opcode = IBV_WC_SEND;
			wc->wc_flags = IBV_WC_WITH_IMM;
			break;

		case HNS_ROCE_SQ_OP_SEND_WITH_INV:
			wc->opcode = IBV_WC_SEND;
			break;

		case HNS_ROCE_SQ_OP_RDMA_READ:
			wc->opcode = IBV_WC_RDMA_READ;
			wc->byte_len = cqe->byte_cnt;
			wc->wc_flags = 0;
			break;

		case HNS_ROCE_SQ_OP_RDMA_WRITE:
			wc->opcode = IBV_WC_RDMA_WRITE;
			wc->wc_flags = 0;
			break;

		case HNS_ROCE_SQ_OP_RDMA_WRITE_WITH_IMM:
			wc->opcode = IBV_WC_RDMA_WRITE;
			wc->wc_flags = IBV_WC_WITH_IMM;
			break;
		case HNS_ROCE_SQ_OP_LOCAL_INV:
			wc->opcode = IBV_WC_LOCAL_INV;
			wc->wc_flags = IBV_WC_WITH_INV;
			break;
		case HNS_ROCE_SQ_OP_ATOMIC_COMP_AND_SWAP:
			wc->opcode = IBV_WC_COMP_SWAP;
			wc->byte_len  = 8;
			wc->wc_flags = 0;
			break;
		case HNS_ROCE_SQ_OP_ATOMIC_FETCH_AND_ADD:
			wc->opcode = IBV_WC_FETCH_ADD;
			wc->byte_len  = 8;
			wc->wc_flags = 0;
			break;
		case HNS_ROCE_SQ_OP_BIND_MW:
			wc->opcode = IBV_WC_BIND_MW;
			wc->wc_flags = 0;
			break;
		default:
			wc->status = IBV_WC_GENERAL_ERR;
			wc->wc_flags = 0;
			break;
		}
	} else {
		/* Get opcode and flag in rq&srq */
		wc->byte_len = cqe->byte_cnt;
		switch (roce_get_field(cqe->byte_4, CQE_BYTE_4_OPCODE_M,
			CQE_BYTE_4_OPCODE_S) & HNS_ROCE_V2_CQE_OPCODE_MASK) {
		case HNS_ROCE_RECV_OP_RDMA_WRITE_IMM:
			wc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = cqe->rkey_immtdata;
			break;

		case HNS_ROCE_RECV_OP_SEND:
			wc->opcode = IBV_WC_RECV;
			wc->wc_flags = 0;
			break;

		case HNS_ROCE_RECV_OP_SEND_WITH_IMM:
			wc->opcode = IBV_WC_RECV;
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = cqe->rkey_immtdata;
			break;

		case HNS_ROCE_RECV_OP_SEND_WITH_INV:
			wc->opcode = IBV_WC_RECV;
			wc->wc_flags = IBV_WC_WITH_INV;
			wc->imm_data = cqe->rkey_immtdata;
			break;
		default:
			wc->status = IBV_WC_GENERAL_ERR;
			break;
		}
	}

	return V2_CQ_OK;
}

static int hns_roce_u_v2_poll_cq(struct ibv_cq *ibvcq, int ne,
				 struct ibv_wc *wc)
{
	int npolled;
	int err = V2_CQ_OK;
	struct hns_roce_qp *qp = NULL;
	struct hns_roce_cq *cq = to_hr_cq(ibvcq);
	struct hns_roce_context *ctx = to_hr_ctx(ibvcq->context);

	pthread_spin_lock(&cq->lock);

	for (npolled = 0; npolled < ne; ++npolled) {
		err = hns_roce_v2_poll_one(cq, &qp, wc + npolled);
		if (err != V2_CQ_OK)
			break;
	}

	if (npolled) {
		mmio_ordered_writes_hack();

		hns_roce_v2_update_cq_cons_index(ctx, cq);
	}

	pthread_spin_unlock(&cq->lock);

	return err == V2_CQ_POLL_ERR ? err : npolled;
}

static int hns_roce_u_v2_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	uint32_t ci;
	uint32_t solicited_flag;
	struct hns_roce_v2_cq_db cq_db;
	struct hns_roce_cq *cq = to_hr_cq(ibvcq);

	ci  = cq->cons_index & ((cq->cq_depth << 1) - 1);
	solicited_flag = solicited ? HNS_ROCE_V2_CQ_DB_REQ_SOL :
				     HNS_ROCE_V2_CQ_DB_REQ_NEXT;

	cq_db.byte_4 = 0;
	cq_db.parameter = 0;

	roce_set_field(cq_db.byte_4, DB_BYTE_4_TAG_M, DB_BYTE_4_TAG_S, cq->cqn);
	roce_set_field(cq_db.byte_4, DB_BYTE_4_CMD_M, DB_BYTE_4_CMD_S, 0x4);

	roce_set_field(cq_db.parameter, CQ_DB_PARAMETER_CQ_CONSUMER_IDX_M,
		       CQ_DB_PARAMETER_CQ_CONSUMER_IDX_S, ci);

	roce_set_field(cq_db.parameter, CQ_DB_PARAMETER_CMD_SN_M,
		       CQ_DB_PARAMETER_CMD_SN_S, 1);
	roce_set_bit(cq_db.parameter, CQ_DB_PARAMETER_NOTIFY_S, solicited_flag);

	hns_roce_write64((uint32_t *)&cq_db, to_hr_ctx(ibvcq->context),
			  ROCEE_VF_DB_CFG0_OFFSET);
	return 0;
}

static void __hns_roce_v2_cq_clean(struct hns_roce_cq *cq, uint32_t qpn,
				   struct hns_roce_srq *srq)
{
	int nfreed = 0;
	uint32_t prod_index;
	uint8_t owner_bit = 0;
	struct hns_roce_v2_cqe *cqe, *dest;
	struct hns_roce_context *ctx = to_hr_ctx(cq->ibv_cq.context);

	for (prod_index = cq->cons_index; get_sw_cqe_v2(cq, prod_index);
	     ++prod_index)
		if (prod_index == cq->cons_index + cq->ibv_cq.cqe)
			break;

	while ((int) --prod_index - (int) cq->cons_index >= 0) {
		cqe = get_cqe_v2(cq, prod_index & cq->ibv_cq.cqe);
		if ((roce_get_field(cqe->byte_16, CQE_BYTE_16_LCL_QPN_M,
			      CQE_BYTE_16_LCL_QPN_S) & 0xffffff) == qpn) {
			++nfreed;
		} else if (nfreed) {
			dest = get_cqe_v2(cq,
				       (prod_index + nfreed) & cq->ibv_cq.cqe);
			owner_bit = roce_get_bit(dest->byte_4,
						 CQE_BYTE_4_OWNER_S);
			memcpy(dest, cqe, sizeof(*cqe));
			roce_set_bit(dest->byte_4, CQE_BYTE_4_OWNER_S,
				     owner_bit);
		}
	}

	if (nfreed) {
		cq->cons_index += nfreed;
		udma_to_device_barrier();
		hns_roce_v2_update_cq_cons_index(ctx, cq);
	}
}

static void hns_roce_v2_cq_clean(struct hns_roce_cq *cq, unsigned int qpn,
				 struct hns_roce_srq *srq)
{
	pthread_spin_lock(&cq->lock);
	__hns_roce_v2_cq_clean(cq, qpn, srq);
	pthread_spin_unlock(&cq->lock);
}

static int hns_roce_u_v2_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
				   int attr_mask)
{
	int ret;
	struct ibv_modify_qp cmd;
	struct hns_roce_qp *hr_qp = to_hr_qp(qp);

	ret = ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));

	if (!ret && (attr_mask & IBV_QP_STATE) &&
	    attr->qp_state == IBV_QPS_RESET) {
		hns_roce_v2_cq_clean(to_hr_cq(qp->recv_cq), qp->qp_num,
				     qp->srq ? to_hr_srq(qp->srq) : NULL);
		if (qp->send_cq != qp->recv_cq)
			hns_roce_v2_cq_clean(to_hr_cq(qp->send_cq), qp->qp_num,
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

static int hns_roce_u_v2_destroy_qp(struct ibv_qp *ibqp)
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

	__hns_roce_v2_cq_clean(to_hr_cq(ibqp->recv_cq), ibqp->qp_num,
			       ibqp->srq ? to_hr_srq(ibqp->srq) : NULL);

	if (ibqp->send_cq != ibqp->recv_cq)
		__hns_roce_v2_cq_clean(to_hr_cq(ibqp->send_cq), ibqp->qp_num,
				       NULL);

	hns_roce_v2_clear_qp(to_hr_ctx(ibqp->context), ibqp->qp_num);

	hns_roce_unlock_cqs(ibqp);
	pthread_mutex_unlock(&to_hr_ctx(ibqp->context)->qp_table_mutex);

	free(qp->sq.wrid);
	if (qp->rq.wqe_cnt)
		free(qp->rq.wrid);

	hns_roce_free_buf(&qp->buf);
	free(qp);

	return ret;
}

struct hns_roce_u_hw hns_roce_u_hw_v2 = {
	.hw_version = HNS_ROCE_HW_VER2,
	.poll_cq = hns_roce_u_v2_poll_cq,
	.arm_cq = hns_roce_u_v2_arm_cq,
	.modify_qp = hns_roce_u_v2_modify_qp,
	.destroy_qp = hns_roce_u_v2_destroy_qp,
};
