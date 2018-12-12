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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "hns_roce_u.h"
#include "hns_roce_u_db.h"
#include "hns_roce_u_hw_v2.h"

static void set_data_seg_v2(struct hns_roce_v2_wqe_data_seg *dseg,
			 struct ibv_sge *sg)
{
	dseg->lkey = htole32(sg->lkey);
	dseg->addr = htole64(sg->addr);
	dseg->len = htole32(sg->length);
}

static void set_atomic_seg(struct hns_roce_wqe_atomic_seg *aseg,
			   struct ibv_send_wr *wr)
{
	if (wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
		aseg->fetchadd_swap_data = htole64(wr->wr.atomic.swap);
		aseg->cmp_data  = htole64(wr->wr.atomic.compare_add);
	} else {
		aseg->fetchadd_swap_data = htole64(wr->wr.atomic.compare_add);
		aseg->cmp_data  = 0;
	}
}

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

static struct hns_roce_v2_cqe *next_cqe_sw_v2(struct hns_roce_cq *cq)
{
	return get_sw_cqe_v2(cq, cq->cons_index);
}

static void *get_recv_wqe_v2(struct hns_roce_qp *qp, int n)
{
	if ((n < 0) || (n > qp->rq.wqe_cnt)) {
		printf("rq wqe index:%d,rq wqe cnt:%d\r\n", n, qp->rq.wqe_cnt);
		return NULL;
	}

	return qp->buf.buf + qp->rq.offset + (n << qp->rq.wqe_shift);
}

static void *get_send_wqe(struct hns_roce_qp *qp, int n)
{
	return qp->buf.buf + qp->sq.offset + (n << qp->sq.wqe_shift);
}

static void *get_send_sge_ex(struct hns_roce_qp *qp, int n)
{
	return qp->buf.buf + qp->sge.offset + (n << qp->sge.sge_shift);
}

static void *get_srq_wqe(struct hns_roce_srq *srq, int n)
{
	return srq->buf.buf + (n << srq->wqe_shift);
}

static int hns_roce_v2_wq_overflow(struct hns_roce_wq *wq, int nreq,
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

	return cur + nreq >= wq->max_post;
}

static void hns_roce_update_rq_db(struct hns_roce_context *ctx,
				  unsigned int qpn, unsigned int rq_head)
{
	struct hns_roce_db rq_db;

	rq_db.byte_4 = 0;
	rq_db.parameter = 0;

	roce_set_field(rq_db.byte_4, DB_BYTE_4_TAG_M, DB_BYTE_4_TAG_S, qpn);
	roce_set_field(rq_db.byte_4, DB_BYTE_4_CMD_M, DB_BYTE_4_CMD_S, 0x1);
	roce_set_field(rq_db.parameter, DB_PARAM_RQ_PRODUCER_IDX_M,
		       DB_PARAM_RQ_PRODUCER_IDX_S, rq_head);

	udma_to_device_barrier();

	hns_roce_write64((uint32_t *)&rq_db, ctx, ROCEE_VF_DB_CFG0_OFFSET);
}

static void hns_roce_update_sq_db(struct hns_roce_context *ctx,
				  unsigned int qpn, unsigned int sl,
				  unsigned int sq_head)
{
	struct hns_roce_db sq_db;

	sq_db.byte_4 = 0;

	/* In fact, the sq_head bits should be 15bit */
	sq_db.parameter = 0;

	/* cmd: 0 sq db; 1 rq db; 2; 2 srq db; 3 cq db ptr; 4 cq db ntr */
	roce_set_field(sq_db.byte_4, DB_BYTE_4_CMD_M, DB_BYTE_4_CMD_S, 0);
	roce_set_field(sq_db.byte_4, DB_BYTE_4_TAG_M, DB_BYTE_4_TAG_S, qpn);

	roce_set_field(sq_db.parameter, DB_PARAM_SQ_PRODUCER_IDX_M,
		       DB_PARAM_SQ_PRODUCER_IDX_S, sq_head);
	roce_set_field(sq_db.parameter, DB_PARAM_SL_M, DB_PARAM_SL_S, sl);

	udma_to_device_barrier();

	hns_roce_write64((uint32_t *)&sq_db, ctx, ROCEE_VF_DB_CFG0_OFFSET);
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

static int hns_roce_u_v2_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
				   int attr_mask);

static int hns_roce_v2_poll_one(struct hns_roce_cq *cq,
				struct hns_roce_qp **cur_qp, struct ibv_wc *wc)
{
	uint32_t qpn;
	int is_send;
	uint16_t wqe_ctr;
	uint32_t local_qpn;
	struct hns_roce_wq *wq = NULL;
	struct hns_roce_v2_cqe *cqe = NULL;
	struct hns_roce_rinl_sge *sge_list;
	uint32_t opcode;
	struct ibv_qp_attr attr;
	int attr_mask;
	int ret;

	/* According to CI, find the relative cqe */
	cqe = next_cqe_sw_v2(cq);
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

		/* flush cqe */
		if ((wc->status != IBV_WC_SUCCESS) &&
		    (wc->status != IBV_WC_WR_FLUSH_ERR)) {
			attr_mask = IBV_QP_STATE;
			attr.qp_state = IBV_QPS_ERR;
			ret = hns_roce_u_v2_modify_qp(&(*cur_qp)->ibv_qp,
						      &attr, attr_mask);
			if (ret)
				return ret;
		}
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
			wc->byte_len = le32toh(cqe->byte_cnt);
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
		wc->byte_len = le32toh(cqe->byte_cnt);

		opcode = roce_get_field(cqe->byte_4, CQE_BYTE_4_OPCODE_M,
			CQE_BYTE_4_OPCODE_S) & HNS_ROCE_V2_CQE_OPCODE_MASK;
		switch (opcode) {
		case HNS_ROCE_RECV_OP_RDMA_WRITE_IMM:
			wc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = htobe32(le32toh(cqe->immtdata));
			break;

		case HNS_ROCE_RECV_OP_SEND:
			wc->opcode = IBV_WC_RECV;
			wc->wc_flags = 0;
			break;

		case HNS_ROCE_RECV_OP_SEND_WITH_IMM:
			wc->opcode = IBV_WC_RECV;
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = htobe32(le32toh(cqe->immtdata));
			break;

		case HNS_ROCE_RECV_OP_SEND_WITH_INV:
			wc->opcode = IBV_WC_RECV;
			wc->wc_flags = IBV_WC_WITH_INV;
			wc->invalidated_rkey = le32toh(cqe->rkey);
			break;
		default:
			wc->status = IBV_WC_GENERAL_ERR;
			break;
		}

		if (((*cur_qp)->ibv_qp.qp_type == IBV_QPT_RC ||
		    (*cur_qp)->ibv_qp.qp_type == IBV_QPT_UC) &&
		    (opcode == HNS_ROCE_RECV_OP_SEND ||
		     opcode == HNS_ROCE_RECV_OP_SEND_WITH_IMM ||
		     opcode == HNS_ROCE_RECV_OP_SEND_WITH_INV) &&
		     (roce_get_bit(cqe->byte_4, CQE_BYTE_4_RQ_INLINE_S))) {
			uint32_t wr_num, wr_cnt, sge_num, data_len;
			uint8_t *wqe_buf;
			uint32_t sge_cnt, size;

			wr_num = (uint16_t)roce_get_field(cqe->byte_4,
						CQE_BYTE_4_WQE_IDX_M,
						CQE_BYTE_4_WQE_IDX_S) & 0xffff;
			wr_cnt = wr_num & ((*cur_qp)->rq.wqe_cnt - 1);

			sge_list =
				(*cur_qp)->rq_rinl_buf.wqe_list[wr_cnt].sg_list;
			sge_num =
				(*cur_qp)->rq_rinl_buf.wqe_list[wr_cnt].sge_cnt;
			wqe_buf = (uint8_t *)get_recv_wqe_v2(*cur_qp, wr_cnt);
			data_len = wc->byte_len;

			for (sge_cnt = 0; (sge_cnt < sge_num) && (data_len);
			     sge_cnt++) {
				size = sge_list[sge_cnt].len < data_len ?
				       sge_list[sge_cnt].len : data_len;

				memcpy((void *)sge_list[sge_cnt].addr,
					(void *)wqe_buf, size);
				data_len -= size;
				wqe_buf += size;
			}

			if (data_len) {
				wc->status = IBV_WC_LOC_LEN_ERR;
				return V2_CQ_POLL_ERR;
			}
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

		if (cq->flags & HNS_ROCE_SUPPORT_CQ_RECORD_DB)
			*cq->set_ci_db = (unsigned int)(cq->cons_index &
						((cq->cq_depth << 1) - 1));
		else
			hns_roce_v2_update_cq_cons_index(ctx, cq);
	}

	pthread_spin_unlock(&cq->lock);

	return err == V2_CQ_POLL_ERR ? err : npolled;
}

static int hns_roce_u_v2_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	uint32_t ci;
	uint32_t cmd_sn;
	uint32_t solicited_flag;
	struct hns_roce_v2_cq_db cq_db;
	struct hns_roce_cq *cq = to_hr_cq(ibvcq);

	ci  = cq->cons_index & ((cq->cq_depth << 1) - 1);
	cmd_sn = cq->arm_sn & HNS_ROCE_CMDSN_MASK;
	solicited_flag = solicited ? HNS_ROCE_V2_CQ_DB_REQ_SOL :
				     HNS_ROCE_V2_CQ_DB_REQ_NEXT;

	cq_db.byte_4 = 0;
	cq_db.parameter = 0;

	roce_set_field(cq_db.byte_4, DB_BYTE_4_TAG_M, DB_BYTE_4_TAG_S, cq->cqn);
	roce_set_field(cq_db.byte_4, DB_BYTE_4_CMD_M, DB_BYTE_4_CMD_S, 0x4);

	roce_set_field(cq_db.parameter, CQ_DB_PARAMETER_CQ_CONSUMER_IDX_M,
		       CQ_DB_PARAMETER_CQ_CONSUMER_IDX_S, ci);

	roce_set_field(cq_db.parameter, CQ_DB_PARAMETER_CMD_SN_M,
		       CQ_DB_PARAMETER_CMD_SN_S, cmd_sn);
	roce_set_bit(cq_db.parameter, CQ_DB_PARAMETER_NOTIFY_S, solicited_flag);

	hns_roce_write64((uint32_t *)&cq_db, to_hr_ctx(ibvcq->context),
			  ROCEE_VF_DB_CFG0_OFFSET);
	return 0;
}

int hns_roce_u_v2_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
			    struct ibv_send_wr **bad_wr)
{
	unsigned int sq_shift;
	unsigned int ind_sge;
	unsigned int ind;
	int nreq;
	int i;
	void *wqe;
	int ret = 0;
	struct hns_roce_qp *qp = to_hr_qp(ibvqp);
	struct hns_roce_context *ctx = to_hr_ctx(ibvqp->context);
	struct hns_roce_rc_sq_wqe *rc_sq_wqe;
	struct hns_roce_v2_wqe_data_seg *dseg;
	struct ibv_qp_attr attr;
	int attr_mask;

	pthread_spin_lock(&qp->sq.lock);

	/* check that state is OK to post send */
	ind = qp->sq.head;
	ind_sge = qp->next_sge;

	if (ibvqp->state == IBV_QPS_RESET || ibvqp->state == IBV_QPS_INIT ||
	    ibvqp->state == IBV_QPS_RTR) {
		pthread_spin_unlock(&qp->sq.lock);
		*bad_wr = wr;
		return EINVAL;
	}

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (hns_roce_v2_wq_overflow(&qp->sq, nreq,
					    to_hr_cq(qp->ibv_qp.send_cq))) {
			ret = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge > qp->sq.max_gs) {
			ret = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		wqe = get_send_wqe(qp, ind & (qp->sq.wqe_cnt - 1));
		rc_sq_wqe = wqe;

		memset(rc_sq_wqe, 0, sizeof(struct hns_roce_rc_sq_wqe));

		qp->sq.wrid[ind & (qp->sq.wqe_cnt - 1)] = wr->wr_id;
		for (i = 0; i < wr->num_sge; i++)
			rc_sq_wqe->msg_len =
					htole32(le32toh(rc_sq_wqe->msg_len) +
							wr->sg_list[i].length);

		if (wr->opcode == IBV_WR_SEND_WITH_IMM ||
		    wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
			rc_sq_wqe->immtdata = htole32(be32toh(wr->imm_data));

		roce_set_field(rc_sq_wqe->byte_16, RC_SQ_WQE_BYTE_16_SGE_NUM_M,
			       RC_SQ_WQE_BYTE_16_SGE_NUM_S, wr->num_sge);

		roce_set_field(rc_sq_wqe->byte_20,
			       RC_SQ_WQE_BYTE_20_MSG_START_SGE_IDX_S,
			       RC_SQ_WQE_BYTE_20_MSG_START_SGE_IDX_S,
			       0);

		roce_set_bit(rc_sq_wqe->byte_4, RC_SQ_WQE_BYTE_4_CQE_S,
			     (wr->send_flags & IBV_SEND_SIGNALED) ? 1 : 0);

		/* Set fence attr */
		roce_set_bit(rc_sq_wqe->byte_4, RC_SQ_WQE_BYTE_4_FENCE_S,
			     (wr->send_flags & IBV_SEND_FENCE) ? 1 : 0);

		/* Set solicited attr */
		roce_set_bit(rc_sq_wqe->byte_4, RC_SQ_WQE_BYTE_4_SE_S,
			     (wr->send_flags & IBV_SEND_SOLICITED) ? 1 : 0);

		for (sq_shift = 0; (1 << sq_shift) < qp->sq.wqe_cnt; ++sq_shift)
			;
		roce_set_bit(rc_sq_wqe->byte_4, RC_SQ_WQE_BYTE_4_OWNER_S,
			     ~(((qp->sq.head + nreq) >> sq_shift) & 0x1));

		wqe += sizeof(struct hns_roce_rc_sq_wqe);
		/* set remote addr segment */
		switch (ibvqp->qp_type) {
		case IBV_QPT_RC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_READ:
				roce_set_field(rc_sq_wqe->byte_4,
					       RC_SQ_WQE_BYTE_4_OPCODE_M,
					       RC_SQ_WQE_BYTE_4_OPCODE_S,
					       HNS_ROCE_WQE_OP_RDMA_READ);
				rc_sq_wqe->va =
					htole64(wr->wr.rdma.remote_addr);
				rc_sq_wqe->rkey = htole32(wr->wr.rdma.rkey);
				break;

			case IBV_WR_RDMA_WRITE:
				roce_set_field(rc_sq_wqe->byte_4,
					       RC_SQ_WQE_BYTE_4_OPCODE_M,
					       RC_SQ_WQE_BYTE_4_OPCODE_S,
					       HNS_ROCE_WQE_OP_RDMA_WRITE);
				rc_sq_wqe->va =
					htole64(wr->wr.rdma.remote_addr);
				rc_sq_wqe->rkey = htole32(wr->wr.rdma.rkey);
				break;

			case IBV_WR_RDMA_WRITE_WITH_IMM:
				roce_set_field(rc_sq_wqe->byte_4,
				       RC_SQ_WQE_BYTE_4_OPCODE_M,
				       RC_SQ_WQE_BYTE_4_OPCODE_S,
				       HNS_ROCE_WQE_OP_RDMA_WRITE_WITH_IMM);
				rc_sq_wqe->va =
					htole64(wr->wr.rdma.remote_addr);
				rc_sq_wqe->rkey = htole32(wr->wr.rdma.rkey);
				break;

			case IBV_WR_SEND:
				roce_set_field(rc_sq_wqe->byte_4,
					       RC_SQ_WQE_BYTE_4_OPCODE_M,
					       RC_SQ_WQE_BYTE_4_OPCODE_S,
					       HNS_ROCE_WQE_OP_SEND);
				break;
			case IBV_WR_SEND_WITH_INV:
				roce_set_field(rc_sq_wqe->byte_4,
					     RC_SQ_WQE_BYTE_4_OPCODE_M,
					     RC_SQ_WQE_BYTE_4_OPCODE_S,
					     HNS_ROCE_WQE_OP_SEND_WITH_INV);
				rc_sq_wqe->inv_key =
						htole32(wr->invalidate_rkey);
				break;
			case IBV_WR_SEND_WITH_IMM:
				roce_set_field(rc_sq_wqe->byte_4,
					RC_SQ_WQE_BYTE_4_OPCODE_M,
					RC_SQ_WQE_BYTE_4_OPCODE_S,
					HNS_ROCE_WQE_OP_SEND_WITH_IMM);
				break;

			case IBV_WR_LOCAL_INV:
				roce_set_field(rc_sq_wqe->byte_4,
					       RC_SQ_WQE_BYTE_4_OPCODE_M,
					       RC_SQ_WQE_BYTE_4_OPCODE_S,
					       HNS_ROCE_WQE_OP_LOCAL_INV);
				roce_set_bit(rc_sq_wqe->byte_4,
					     RC_SQ_WQE_BYTE_4_SO_S, 1);
				rc_sq_wqe->inv_key =
						htole32(wr->invalidate_rkey);
				break;
			case IBV_WR_ATOMIC_CMP_AND_SWP:
				roce_set_field(rc_sq_wqe->byte_4,
					RC_SQ_WQE_BYTE_4_OPCODE_M,
					RC_SQ_WQE_BYTE_4_OPCODE_S,
					HNS_ROCE_WQE_OP_ATOMIC_COM_AND_SWAP);
				rc_sq_wqe->rkey = htole32(wr->wr.atomic.rkey);
				rc_sq_wqe->va =
					htole64(wr->wr.atomic.remote_addr);
				break;

			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				roce_set_field(rc_sq_wqe->byte_4,
					RC_SQ_WQE_BYTE_4_OPCODE_M,
					RC_SQ_WQE_BYTE_4_OPCODE_S,
					HNS_ROCE_WQE_OP_ATOMIC_FETCH_AND_ADD);
				rc_sq_wqe->rkey = htole32(wr->wr.atomic.rkey);
				rc_sq_wqe->va =
					htole64(wr->wr.atomic.remote_addr);
				break;

			case IBV_WR_BIND_MW:
				roce_set_field(rc_sq_wqe->byte_4,
					RC_SQ_WQE_BYTE_4_OPCODE_M,
					RC_SQ_WQE_BYTE_4_OPCODE_S,
					HNS_ROCE_WQE_OP_BIND_MW_TYPE);
				roce_set_bit(rc_sq_wqe->byte_4,
					RC_SQ_WQE_BYTE_4_MW_TYPE_S,
					wr->bind_mw.mw->type - 1);
				roce_set_bit(rc_sq_wqe->byte_4,
					RC_SQ_WQE_BYTE_4_ATOMIC_S,
					wr->bind_mw.bind_info.mw_access_flags &
					IBV_ACCESS_REMOTE_ATOMIC ? 1 : 0);
				roce_set_bit(rc_sq_wqe->byte_4,
					RC_SQ_WQE_BYTE_4_RDMA_READ_S,
					wr->bind_mw.bind_info.mw_access_flags &
					IBV_ACCESS_REMOTE_READ ? 1 : 0);
				roce_set_bit(rc_sq_wqe->byte_4,
					RC_SQ_WQE_BYTE_4_RDMA_WRITE_S,
					wr->bind_mw.bind_info.mw_access_flags &
					IBV_ACCESS_REMOTE_WRITE ? 1 : 0);

				rc_sq_wqe->new_rkey = htole32(wr->bind_mw.rkey);
				rc_sq_wqe->byte_16 =
					  htole32(wr->bind_mw.bind_info.length &
						  0xffffffff);
				rc_sq_wqe->byte_20 =
					 htole32(wr->bind_mw.bind_info.length >>
						 32);
				rc_sq_wqe->rkey =
					htole32(wr->bind_mw.bind_info.mr->rkey);
				rc_sq_wqe->va =
					    htole64(wr->bind_mw.bind_info.addr);
				break;

			default:
				roce_set_field(rc_sq_wqe->byte_4,
					       RC_SQ_WQE_BYTE_4_OPCODE_M,
					       RC_SQ_WQE_BYTE_4_OPCODE_S,
					       HNS_ROCE_WQE_OP_MASK);
				printf("Not supported transport opcode %d\n",
				       wr->opcode);
				break;
			}

			break;
		case IBV_QPT_UC:
		case IBV_QPT_UD:
		default:
			break;
		}

		dseg = wqe;
		if (wr->opcode == IBV_WR_ATOMIC_FETCH_AND_ADD ||
		    wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
			set_data_seg_v2(dseg, wr->sg_list);
			wqe += sizeof(struct hns_roce_v2_wqe_data_seg);
			set_atomic_seg(wqe, wr);
		} else if (wr->send_flags & IBV_SEND_INLINE && wr->num_sge) {
			if (le32toh(rc_sq_wqe->msg_len) > qp->max_inline_data) {
				ret = EINVAL;
				*bad_wr = wr;
				printf("data len=%d, send_flags = 0x%x!\r\n",
					rc_sq_wqe->msg_len, wr->send_flags);
				goto out;
			}

			if (wr->opcode == IBV_WR_RDMA_READ) {
				ret = EINVAL;
				*bad_wr = wr;
				printf("Not supported inline data!\n");
				goto out;
			}

			for (i = 0; i < wr->num_sge; i++) {
				memcpy(wqe,
				     ((void *) (uintptr_t) wr->sg_list[i].addr),
				     wr->sg_list[i].length);
				wqe = wqe + wr->sg_list[i].length;
			}

			roce_set_bit(rc_sq_wqe->byte_4,
				     RC_SQ_WQE_BYTE_4_INLINE_S, 1);
		} else {
			/* set sge */
			if (wr->num_sge <= 2) {
				for (i = 0; i < wr->num_sge; i++)
					if (likely(wr->sg_list[i].length)) {
						set_data_seg_v2(dseg,
							       wr->sg_list + i);
						dseg++;
					}
			} else {
				roce_set_field(rc_sq_wqe->byte_20,
					RC_SQ_WQE_BYTE_20_MSG_START_SGE_IDX_M,
					RC_SQ_WQE_BYTE_20_MSG_START_SGE_IDX_S,
					ind_sge & (qp->sge.sge_cnt - 1));

				for (i = 0; i < 2; i++)
					if (likely(wr->sg_list[i].length)) {
						set_data_seg_v2(dseg,
							       wr->sg_list + i);
						dseg++;
					}

				dseg = get_send_sge_ex(qp, ind_sge &
						    (qp->sge.sge_cnt - 1));

				for (i = 0; i < wr->num_sge - 2; i++) {
					if (likely(wr->sg_list[i + 2].length)) {
						set_data_seg_v2(dseg,
							   wr->sg_list + 2 + i);
						dseg++;
						ind_sge++;
					}
				}
			}
		}

		ind++;
	}

out:
	if (likely(nreq)) {
		qp->sq.head += nreq;

		hns_roce_update_sq_db(ctx, qp->ibv_qp.qp_num, qp->sl,
				     qp->sq.head & ((qp->sq.wqe_cnt << 1) - 1));

		if (qp->flags & HNS_ROCE_SUPPORT_SQ_RECORD_DB)
			*(qp->sdb) = qp->sq.head & 0xffff;

		qp->next_sge = ind_sge;

		if (ibvqp->state == IBV_QPS_ERR) {
			attr_mask = IBV_QP_STATE;
			attr.qp_state = IBV_QPS_ERR;

			ret = hns_roce_u_v2_modify_qp(ibvqp, &attr, attr_mask);
			if (ret) {
				pthread_spin_unlock(&qp->sq.lock);
				*bad_wr = wr;
				return ret;
			}
		}
	}

	pthread_spin_unlock(&qp->sq.lock);

	return ret;
}

static int hns_roce_u_v2_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
				   struct ibv_recv_wr **bad_wr)
{
	int ret = 0;
	int nreq;
	int ind;
	struct hns_roce_qp *qp = to_hr_qp(ibvqp);
	struct hns_roce_context *ctx = to_hr_ctx(ibvqp->context);
	struct hns_roce_v2_wqe_data_seg *dseg;
	struct hns_roce_rinl_sge *sge_list;
	struct ibv_qp_attr attr;
	int attr_mask;
	void *wqe;
	int i;

	pthread_spin_lock(&qp->rq.lock);

	/* check that state is OK to post receive */
	ind = qp->rq.head & (qp->rq.wqe_cnt - 1);

	if (ibvqp->state == IBV_QPS_RESET) {
		pthread_spin_unlock(&qp->rq.lock);
		*bad_wr = wr;
		return -1;
	}

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (hns_roce_v2_wq_overflow(&qp->rq, nreq,
					    to_hr_cq(qp->ibv_qp.recv_cq))) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge > qp->rq.max_gs) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		wqe = get_recv_wqe_v2(qp, ind);
		dseg = (struct hns_roce_v2_wqe_data_seg *)wqe;

		for (i = 0; i < wr->num_sge; i++) {
			if (!wr->sg_list[i].length)
				continue;
			set_data_seg_v2(dseg, wr->sg_list + i);
			dseg++;
		}

		if (i < qp->rq.max_gs) {
			dseg->lkey = htole32(0x100);
			dseg->addr = 0;
		}

		/* QP support receive inline wqe */
		sge_list = qp->rq_rinl_buf.wqe_list[ind].sg_list;
		qp->rq_rinl_buf.wqe_list[ind].sge_cnt =
						(unsigned int)wr->num_sge;

		for (i = 0; i < wr->num_sge; i++) {
			sge_list[i].addr =
					(void *)(uintptr_t)wr->sg_list[i].addr;
			sge_list[i].len = wr->sg_list[i].length;
		}

		qp->rq.wrid[ind] = wr->wr_id;

		ind = (ind + 1) & (qp->rq.wqe_cnt - 1);
	}

out:
	if (nreq) {
		qp->rq.head += nreq;

		udma_to_device_barrier();

		if (qp->flags & HNS_ROCE_SUPPORT_RQ_RECORD_DB)
			*qp->rdb = qp->rq.head & 0xffff;
		else
			hns_roce_update_rq_db(ctx, qp->ibv_qp.qp_num,
				     qp->rq.head & ((qp->rq.wqe_cnt << 1) - 1));

		if (ibvqp->state == IBV_QPS_ERR) {
			attr_mask = IBV_QP_STATE;
			attr.qp_state = IBV_QPS_ERR;

			ret = hns_roce_u_v2_modify_qp(ibvqp, &attr, attr_mask);
			if (ret) {
				pthread_spin_unlock(&qp->rq.lock);
				*bad_wr = wr;
				return ret;
			}
		}
	}

	pthread_spin_unlock(&qp->rq.lock);

	return ret;
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

	if (qp->rq.max_gs)
		hns_roce_free_db(to_hr_ctx(ibqp->context), qp->rdb,
				 HNS_ROCE_QP_TYPE_DB);
	if (qp->sq.max_gs)
		hns_roce_free_db(to_hr_ctx(ibqp->context), qp->sdb,
				 HNS_ROCE_QP_TYPE_DB);

	hns_roce_free_buf(&qp->buf);
	if (qp->rq_rinl_buf.wqe_list) {
		if (qp->rq_rinl_buf.wqe_list[0].sg_list) {
			free(qp->rq_rinl_buf.wqe_list[0].sg_list);
			qp->rq_rinl_buf.wqe_list[0].sg_list = NULL;
		}

		free(qp->rq_rinl_buf.wqe_list);
		qp->rq_rinl_buf.wqe_list = NULL;
	}

	free(qp->sq.wrid);
	if (qp->rq.wqe_cnt)
		free(qp->rq.wrid);

	free(qp);

	return ret;
}

static void fill_idx_que(struct hns_roce_idx_que *idx_que,
			 int cur_idx, int wqe_idx)
{
	unsigned int *addr;

	addr = idx_que->buf.buf + cur_idx * idx_que->entry_sz;
	*addr = wqe_idx;
}

static int find_empty_entry(struct hns_roce_idx_que *idx_que)
{
	int bit_num;
	int i;

	/* bitmap[i] is set zero if all bits are allocated */
	for (i = 0; idx_que->bitmap[i] == 0; ++i)
		;
	bit_num = ffsl(idx_que->bitmap[i]);
	idx_que->bitmap[i] &= ~(1ULL << (bit_num - 1));

	return i * sizeof(uint64_t) * BIT_CNT_PER_BYTE + (bit_num - 1);
}

static int hns_roce_u_v2_post_srq_recv(struct ibv_srq *ib_srq,
				       struct ibv_recv_wr *wr,
				       struct ibv_recv_wr **bad_wr)
{
	struct hns_roce_context *ctx = to_hr_ctx(ib_srq->context);
	struct hns_roce_srq *srq = to_hr_srq(ib_srq);
	struct hns_roce_v2_wqe_data_seg *dseg;
	struct hns_roce_db srq_db;
	int ret = 0;
	int wqe_idx;
	void *wqe;
	int nreq;
	int ind;
	int i;

	pthread_spin_lock(&srq->lock);

	/* current idx of srqwq */
	ind = srq->head & (srq->max - 1);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (wr->num_sge > srq->max_gs) {
			ret = -1;
			*bad_wr = wr;
			break;
		}

		if (srq->head == srq->tail) {
			/* SRQ is full*/
			ret = -1;
			*bad_wr = wr;
			break;
		}

		wqe_idx = find_empty_entry(&srq->idx_que);
		fill_idx_que(&srq->idx_que, ind, wqe_idx);

		wqe = get_srq_wqe(srq, wqe_idx);
		dseg = (struct hns_roce_v2_wqe_data_seg *)wqe;

		for (i = 0; i < wr->num_sge; ++i) {
			dseg[i].len = htole32(wr->sg_list[i].length);
			dseg[i].lkey = htole32(wr->sg_list[i].lkey);
			dseg[i].addr = htole64(wr->sg_list[i].addr);
		}

		if (i < srq->max_gs) {
			dseg->len = 0;
			dseg->lkey = htole32(0x100);
			dseg->addr = 0;
		}

		srq->wrid[wqe_idx] = wr->wr_id;
		ind = (ind + 1) & (srq->max - 1);
	}

	if (nreq) {
		srq->head += nreq;

		/*
		 * Make sure that descriptors are written before
		 * we write doorbell record.
		 */
		udma_to_device_barrier();

		srq_db.byte_4 = htole32(2 << 24 | srq->srqn);
		srq_db.parameter = htole32(srq->head);

		hns_roce_write64((uint32_t *)&srq_db, ctx,
				 ROCEE_VF_DB_CFG0_OFFSET);
	}

	pthread_spin_unlock(&srq->lock);

	return ret;
}

const struct hns_roce_u_hw hns_roce_u_hw_v2 = {
	.hw_version = HNS_ROCE_HW_VER2,
	.hw_ops = {
		.poll_cq = hns_roce_u_v2_poll_cq,
		.req_notify_cq = hns_roce_u_v2_arm_cq,
		.post_send = hns_roce_u_v2_post_send,
		.post_recv = hns_roce_u_v2_post_recv,
		.modify_qp = hns_roce_u_v2_modify_qp,
		.destroy_qp = hns_roce_u_v2_destroy_qp,
		.post_srq_recv = hns_roce_u_v2_post_srq_recv,
	},
};
