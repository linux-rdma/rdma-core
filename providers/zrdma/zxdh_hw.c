// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "zxdh_status.h"
#include "zxdh_defs.h"
#include "zxdh_verbs.h"
#include "zxdh_zrdma.h"
#include <errno.h>
#include <ccan/container_of.h>
#include "private_verbs_cmd.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#define ERROR_CODE_VALUE 65


/**
 * zxdh_cq_resize - reset the cq buffer info
 * @cq: cq to resize
 * @cq_base: new cq buffer addr
 * @cq_size: number of cqes
 */
void zxdh_cq_resize(struct zxdh_cq *cq, void *cq_base, int cq_size)
{
	cq->cq_base = cq_base;
	cq->cq_size = cq_size;
	ZXDH_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;
}

/**
 * zxdh_cq_set_resized_cnt - record the count of the resized buffers
 * @cq: cq to resize
 * @cq_cnt: the count of the resized cq buffers
 */
void zxdh_cq_set_resized_cnt(struct zxdh_cq *cq, __u16 cq_cnt)
{
	__u64 temp_val;
	__u16 sw_cq_sel;
	__u8 arm_next;
	__u8 arm_seq_num;

	get_64bit_val(cq->shadow_area, 0, &temp_val);

	sw_cq_sel = (__u16)FIELD_GET(ZXDH_CQ_DBSA_SW_CQ_SELECT, temp_val);
	sw_cq_sel += cq_cnt;

	arm_seq_num = (__u8)FIELD_GET(ZXDH_CQ_DBSA_ARM_SEQ_NUM, temp_val);
	arm_next = (__u8)FIELD_GET(ZXDH_CQ_DBSA_ARM_NEXT, temp_val);
	cq->cqe_rd_cnt = 0;

	temp_val = FIELD_PREP(ZXDH_CQ_DBSA_ARM_SEQ_NUM, arm_seq_num) |
		   FIELD_PREP(ZXDH_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
		   FIELD_PREP(ZXDH_CQ_DBSA_ARM_NEXT, arm_next) |
		   FIELD_PREP(ZXDH_CQ_DBSA_CQEIDX, cq->cqe_rd_cnt);

	set_64bit_val(cq->shadow_area, 0, temp_val);
}

/**
 * zxdh_cq_request_notification - cq notification request (door bell)
 * @cq: hw cq
 * @cq_notify: notification type
 */
void zxdh_cq_request_notification(struct zxdh_cq *cq,
				  enum zxdh_cmpl_notify cq_notify)
{
	__u64 temp_val;
	__u16 sw_cq_sel;
	__u8 arm_next = 0;
	__u8 arm_seq_num;
	__u32 cqe_index;
	__u32 hdr;

	get_64bit_val(cq->shadow_area, 0, &temp_val);
	arm_seq_num = (__u8)FIELD_GET(ZXDH_CQ_DBSA_ARM_SEQ_NUM, temp_val);
	arm_seq_num++;
	sw_cq_sel = (__u16)FIELD_GET(ZXDH_CQ_DBSA_SW_CQ_SELECT, temp_val);
	cqe_index = (__u32)FIELD_GET(ZXDH_CQ_DBSA_CQEIDX, temp_val);

	if (cq_notify == ZXDH_CQ_COMPL_SOLICITED)
		arm_next = 1;
	temp_val = FIELD_PREP(ZXDH_CQ_DBSA_ARM_SEQ_NUM, arm_seq_num) |
		   FIELD_PREP(ZXDH_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
		   FIELD_PREP(ZXDH_CQ_DBSA_ARM_NEXT, arm_next) |
		   FIELD_PREP(ZXDH_CQ_DBSA_CQEIDX, cqe_index);

	set_64bit_val(cq->shadow_area, 0, temp_val);

	hdr = FIELD_PREP(ZXDH_CQ_ARM_DBSA_VLD, 0) |
	      FIELD_PREP(ZXDH_CQ_ARM_CQ_ID, cq->cq_id);

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	db_wr32(hdr, cq->cqe_alloc_db);
}

static inline void build_comp_status(__u32 cq_type,
				     struct zxdh_cq_poll_info *info)
{
	if (!info->error) {
		info->comp_status = ZXDH_COMPL_STATUS_SUCCESS;
		if (cq_type == ZXDH_CQE_QTYPE_RQ) {
			if (info->major_err != ERROR_CODE_VALUE &&
			    info->minor_err != ERROR_CODE_VALUE) {
				info->comp_status = ZXDH_COMPL_STATUS_UNKNOWN;
			}
		}
		return;
	}

	switch (info->major_err) {
	case ZXDH_RETRY_ACK_MAJOR_ERR:
		if (info->minor_err == ZXDH_RETRY_ACK_MINOR_ERR) {
			info->comp_status = ZXDH_COMPL_STATUS_RETRY_ACK_ERR;
			return;
		}
		if (info->minor_err == ZXDH_TX_WINDOW_QUERY_ITEM_MINOR_ERR) {
			info->comp_status =
				ZXDH_COMPL_STATUS_TX_WINDOW_QUERY_ITEM_ERR;
			return;
		}
		break;
	case ZXDH_FLUSH_MAJOR_ERR:
		info->comp_status = ZXDH_COMPL_STATUS_FLUSHED;
		return;
	default:
		info->comp_status = ZXDH_COMPL_STATUS_UNKNOWN;
		return;
	}
}

__le64 *get_current_cqe(struct zxdh_cq *cq)
{
	return ZXDH_GET_CURRENT_EXTENDED_CQ_ELEM(cq);
}

static inline void zxdh_get_cq_poll_info(struct zxdh_qp *qp,
					 struct zxdh_cq_poll_info *info,
					 __u64 qword2, __u64 qword3)
{
	__u8 qp_type;

	qp_type = qp->qp_type;

	info->imm_valid = (bool)FIELD_GET(ZXDH_CQ_IMMVALID, qword2);
	if (info->imm_valid) {
		info->imm_data = (__u32)FIELD_GET(ZXDH_CQ_IMMDATA, qword3);
		info->op_type = ZXDH_OP_TYPE_REC_IMM;
	} else {
		info->op_type = ZXDH_OP_TYPE_REC;
	}

	info->bytes_xfered = (__u32)FIELD_GET(ZXDHCQ_PAYLDLEN, qword3);

	if (likely(qp_type == ZXDH_QP_TYPE_ROCE_RC)) {
		if (qword2 & ZXDHCQ_STAG) {
			info->stag_invalid_set = true;
			info->inv_stag =
				(__u32)FIELD_GET(ZXDHCQ_INVSTAG, qword2);
		} else {
			info->stag_invalid_set = false;
		}
	} else if (qp_type == ZXDH_QP_TYPE_ROCE_UD) {
		info->ipv4 = (bool)FIELD_GET(ZXDHCQ_IPV4, qword2);
		info->ud_src_qpn = (__u32)FIELD_GET(ZXDHCQ_UDSRCQPN, qword2);
	}
}

static enum zxdh_status_code update_cq_poll_info(struct zxdh_qp *qp,
						 struct zxdh_cq_poll_info *info,
						 __u32 wqe_idx, __u64 qword0)
{
	info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
	if (!info->comp_status)
		info->bytes_xfered = qp->sq_wrtrk_array[wqe_idx].wr_len;
	info->op_type = (__u8)FIELD_GET(ZXDHCQ_OP, qword0);
	ZXDH_RING_SET_TAIL(qp->sq_ring,
			   wqe_idx + qp->sq_wrtrk_array[wqe_idx].quanta);
	return ZXDH_SUCCESS;
}

static enum zxdh_status_code
process_tx_window_query_item_err(struct zxdh_qp *qp,
				 struct zxdh_cq_poll_info *info)
{
	int ret;
	struct ibv_qp *ib_qp;
	struct zxdh_uqp *iwuqp;
	struct zxdh_rdma_qpc qpc = { 0 };

	iwuqp = container_of(qp, struct zxdh_uqp, qp);
	ib_qp = &iwuqp->vqp.qp;
	ret = zxdh_query_qpc(ib_qp, &qpc);
	if (ret) {
		zxdh_dbg(ZXDH_DBG_QP,
			 "process tx window query item query qpc failed:%d\n",
			 ret);
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	if (qpc.tx_last_ack_psn != qp->qp_last_ack_qsn)
		qp->qp_reset_cnt = 0;

	qp->qp_last_ack_qsn = qpc.tx_last_ack_psn;
	if (qp->qp_reset_cnt >= ZXDH_QP_RETRY_COUNT)
		return ZXDH_ERR_RETRY_ACK_ERR;

	ret = zxdh_reset_qp(ib_qp, ZXDH_RESET_RETRY_TX_ITEM_FLAG);
	if (ret) {
		zxdh_dbg(ZXDH_DBG_QP,
			 "process tx window query item reset qp failed:%d\n",
			 ret);
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	qp->qp_reset_cnt++;
	return ZXDH_ERR_RETRY_ACK_NOT_EXCEED_ERR;
}

static enum zxdh_status_code
process_retry_ack_err(struct zxdh_qp *qp, struct zxdh_cq_poll_info *info)
{
	int ret;
	struct ibv_qp *ib_qp;
	struct zxdh_uqp *iwuqp;
	struct zxdh_rdma_qpc qpc = { 0 };
	struct zxdh_rdma_qpc qpc_req_cmd = { 0 };

	iwuqp = container_of(qp, struct zxdh_uqp, qp);

	ib_qp = &iwuqp->vqp.qp;
	ret = zxdh_query_qpc(ib_qp, &qpc);
	if (ret) {
		zxdh_dbg(ZXDH_DBG_QP, "process retry ack query qpc failed:%d\n",
			 ret);
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	if (!(qpc.retry_cqe_sq_opcode >= ZXDH_RETRY_CQE_SQ_OPCODE_ERR &&
	      (qpc.recv_err_flag == ZXDH_RECV_ERR_FLAG_NAK_RNR_NAK ||
	       qpc.recv_err_flag == ZXDH_RECV_ERR_FLAG_READ_RESP))) {
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	if (qpc.tx_last_ack_psn != qp->cqe_last_ack_qsn)
		qp->cqe_retry_cnt = 0;

	qp->cqe_last_ack_qsn = qpc.tx_last_ack_psn;
	if (qp->cqe_retry_cnt >= ZXDH_QP_RETRY_COUNT)
		return ZXDH_ERR_RETRY_ACK_ERR;

	memcpy(&qpc_req_cmd, &qpc, sizeof(qpc));
	qpc_req_cmd.package_err_flag = 0;
	qpc_req_cmd.ack_err_flag = 0;
	qpc_req_cmd.err_flag = 0;
	qpc_req_cmd.retry_cqe_sq_opcode &= ZXDH_RESET_RETRY_CQE_SQ_OPCODE_ERR;
	qpc_req_cmd.cur_retry_count = qpc.retry_count;
	ret = zxdh_modify_qpc(ib_qp, &qpc_req_cmd,
			      ZXDH_PACKAGE_ERR_FLAG | ZXDH_ERR_FLAG_SET |
				      ZXDH_RETRY_CQE_SQ_OPCODE |
				      ZXDH_TX_READ_RETRY_FLAG_SET);
	if (ret) {
		zxdh_dbg(ZXDH_DBG_QP,
			 "process retry ack modify qpc failed:%d\n", ret);
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	qp->cqe_retry_cnt++;
	return ZXDH_ERR_RETRY_ACK_NOT_EXCEED_ERR;
}

static enum zxdh_status_code
zxdh_flush_sq_comp_info(struct zxdh_qp *qp, struct zxdh_cq_poll_info *info,
			bool *move_cq_head)
{
	if (!ZXDH_RING_MORE_WORK(qp->sq_ring)) {
		ZXDH_RING_INIT(qp->sq_ring, qp->sq_ring.size)
		return ZXDH_ERR_Q_EMPTY;
	}
	do {
		__le64 *sw_wqe;
		__u64 wqe_qword;
		__u64 wqe_idx;

		wqe_idx = qp->sq_ring.tail;
		sw_wqe = qp->sq_base[wqe_idx].elem;
		get_64bit_val(sw_wqe, 0, &wqe_qword);
		info->op_type = (__u8)FIELD_GET(ZXDHQPSQ_OPCODE, wqe_qword);
		ZXDH_RING_SET_TAIL(qp->sq_ring,
				   wqe_idx +
					   qp->sq_wrtrk_array[wqe_idx].quanta);

		if (info->op_type != ZXDH_OP_TYPE_NOP) {
			info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
			break;
		}
	} while (1);
	qp->sq_flush_seen = true;
	if (!ZXDH_RING_MORE_WORK(qp->sq_ring)) {
		qp->sq_flush_complete = true;
		ZXDH_RING_INIT(qp->sq_ring, qp->sq_ring.size)
	} else
		*move_cq_head = false;
	return ZXDH_SUCCESS;
}

static enum zxdh_status_code zxdh_sq_comp_info(struct zxdh_qp *qp,
					       struct zxdh_cq_poll_info *info,
					       __u32 wqe_idx, __u64 qword0,
					       bool *move_cq_head)
{
	enum zxdh_status_code status_code;

	switch (info->comp_status) {
	case ZXDH_COMPL_STATUS_SUCCESS:
	case ZXDH_COMPL_STATUS_UNKNOWN:
		break;
	case ZXDH_COMPL_STATUS_RETRY_ACK_ERR:
		if (qp->qp_type == ZXDH_QP_TYPE_ROCE_RC) {
			status_code = process_retry_ack_err(qp, info);
			return (status_code == ZXDH_ERR_RETRY_ACK_ERR) ?
				       update_cq_poll_info(qp, info, wqe_idx,
							   qword0) :
				       status_code;
		}
		break;
	case ZXDH_COMPL_STATUS_TX_WINDOW_QUERY_ITEM_ERR:
		if (qp->qp_type == ZXDH_QP_TYPE_ROCE_RC) {
			status_code =
				process_tx_window_query_item_err(qp, info);
			return (status_code == ZXDH_ERR_RETRY_ACK_ERR) ?
				       update_cq_poll_info(qp, info, wqe_idx,
							   qword0) :
				       status_code;
		}
		break;
	case ZXDH_COMPL_STATUS_FLUSHED:
		return zxdh_flush_sq_comp_info(qp, info, move_cq_head);
	default:
		break;
	}
	return update_cq_poll_info(qp, info, wqe_idx, qword0);
}

static enum zxdh_status_code zxdh_rq_comp_info(struct zxdh_qp *qp,
					       struct zxdh_cq_poll_info *info,
					       __u32 wqe_idx, __u64 qword2,
					       __u64 qword3, bool *move_cq_head)
{
	struct zxdh_uqp *iwuqp = NULL;
	struct zxdh_usrq *iwusrq = NULL;
	struct zxdh_srq *srq = NULL;

	if (qp->is_srq) {
		iwuqp = container_of(qp, struct zxdh_uqp, qp);
		iwusrq = iwuqp->srq;
		srq = &iwusrq->srq;
		zxdh_free_srq_wqe(srq, wqe_idx);
		info->wr_id = srq->srq_wrid_array[wqe_idx];
		zxdh_get_cq_poll_info(qp, info, qword2, qword3);
	} else {
		if (unlikely(info->comp_status == ZXDH_COMPL_STATUS_FLUSHED ||
			     info->comp_status == ZXDH_COMPL_STATUS_UNKNOWN)) {
			if (!ZXDH_RING_MORE_WORK(qp->rq_ring))
				return ZXDH_ERR_Q_EMPTY;

			wqe_idx = qp->rq_ring.tail;
		}
		info->wr_id = qp->rq_wrid_array[wqe_idx];
		zxdh_get_cq_poll_info(qp, info, qword2, qword3);
		ZXDH_RING_SET_TAIL(qp->rq_ring, wqe_idx + 1);
		if (info->comp_status == ZXDH_COMPL_STATUS_FLUSHED) {
			qp->rq_flush_seen = true;
			if (!ZXDH_RING_MORE_WORK(qp->rq_ring))
				qp->rq_flush_complete = true;
			else
				*move_cq_head = false;
		}
	}
	return ZXDH_SUCCESS;
}

/**
 * zxdh_cq_poll_cmpl - get cq completion info
 * @cq: hw cq
 * @info: cq poll information returned
 */
enum zxdh_status_code zxdh_cq_poll_cmpl(struct zxdh_cq *cq,
					struct zxdh_cq_poll_info *info)
{
	__u64 comp_ctx, qword0, qword2, qword3;
	__le64 *cqe;
	struct zxdh_qp *qp;
	struct zxdh_ring *pring = NULL;
	__u32 wqe_idx, q_type;
	int ret_code;
	bool move_cq_head = true;
	__u8 polarity;

	cqe = get_current_cqe(cq);

	get_64bit_val(cqe, 0, &qword0);
	polarity = (__u8)FIELD_GET(ZXDH_CQ_VALID, qword0);
	if (polarity != cq->polarity)
		return ZXDH_ERR_Q_EMPTY;

	/* Ensure CQE contents are read after valid bit is checked */
	udma_from_device_barrier();
	get_64bit_val(cqe, 8, &comp_ctx);
	get_64bit_val(cqe, 16, &qword2);
	get_64bit_val(cqe, 24, &qword3);

	qp = (struct zxdh_qp *)(unsigned long)comp_ctx;
	if (unlikely(!qp || qp->destroy_pending)) {
		ret_code = ZXDH_ERR_Q_DESTROYED;
		goto exit;
	}

	info->qp_handle = (zxdh_qp_handle)(unsigned long)qp;
	q_type = (__u8)FIELD_GET(ZXDH_CQ_SQ, qword0);
	info->solicited_event = (bool)FIELD_GET(ZXDHCQ_SOEVENT, qword0);
	wqe_idx = (__u32)FIELD_GET(ZXDH_CQ_WQEIDX, qword0);
	info->error = (bool)FIELD_GET(ZXDH_CQ_ERROR, qword0);
	info->major_err = FIELD_GET(ZXDH_CQ_MAJERR, qword0);
	info->minor_err = FIELD_GET(ZXDH_CQ_MINERR, qword0);

	/* Set the min error to standard flush error code for remaining cqes */
	if (unlikely(info->error && info->major_err == ZXDH_FLUSH_MAJOR_ERR &&
		     info->minor_err != FLUSH_GENERAL_ERR)) {
		qword0 &= ~ZXDH_CQ_MINERR;
		qword0 |= FIELD_PREP(ZXDH_CQ_MINERR, FLUSH_GENERAL_ERR);
		set_64bit_val(cqe, 0, qword0);
	}
	build_comp_status(q_type, info);

	info->qp_id = (__u32)FIELD_GET(ZXDHCQ_QPID, qword2);
	info->imm_valid = false;
	switch (q_type) {
	case ZXDH_CQE_QTYPE_SQ:
		ret_code = zxdh_sq_comp_info(qp, info, wqe_idx, qword0,
					     &move_cq_head);
		pring = &qp->sq_ring;
		break;
	case ZXDH_CQE_QTYPE_RQ:
		ret_code = zxdh_rq_comp_info(qp, info, wqe_idx, qword2, qword3,
					     &move_cq_head);
		pring = &qp->rq_ring;
		break;
	default:
		zxdh_dbg(ZXDH_DBG_CQ, "zxdh get cqe type unknown!\n");
		ret_code = ZXDH_ERR_Q_DESTROYED;
		break;
	}
exit:
	if (move_cq_head) {
		__u64 cq_shadow_temp;

		ZXDH_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
		if (!ZXDH_RING_CURRENT_HEAD(cq->cq_ring))
			cq->polarity ^= 1;

		ZXDH_RING_MOVE_TAIL(cq->cq_ring);
		cq->cqe_rd_cnt++;
		get_64bit_val(cq->shadow_area, 0, &cq_shadow_temp);
		cq_shadow_temp &= ~ZXDH_CQ_DBSA_CQEIDX;
		cq_shadow_temp |=
			FIELD_PREP(ZXDH_CQ_DBSA_CQEIDX, cq->cqe_rd_cnt);
		set_64bit_val(cq->shadow_area, 0, cq_shadow_temp);
	} else {
		qword0 &= ~ZXDH_CQ_WQEIDX;
		qword0 |= FIELD_PREP(ZXDH_CQ_WQEIDX, pring->tail);
		set_64bit_val(cqe, 0, qword0);
	}

	return ret_code;
}

/**
 * zxdh_cq_round_up - return round up cq wq depth
 * @wqdepth: wq depth in quanta to round up
 */
int zxdh_cq_round_up(__u32 wqdepth)
{
	int scount = 1;

	if (wqdepth == 0)
		return 0;

	for (wqdepth--; scount <= 16; scount *= 2)
		wqdepth |= wqdepth >> scount;

	return ++wqdepth;
}

/**
 * zxdh_cq_init - initialize shared cq (user and kernel)
 * @cq: hw cq
 * @info: hw cq initialization info
 */
enum zxdh_status_code zxdh_cq_init(struct zxdh_cq *cq,
				   struct zxdh_cq_init_info *info)
{
	cq->cq_base = info->cq_base;
	cq->cq_id = info->cq_id;
	cq->cq_size = info->cq_size;
	cq->cqe_alloc_db = info->cqe_alloc_db;
	cq->cq_ack_db = info->cq_ack_db;
	cq->shadow_area = info->shadow_area;
	cq->cqe_size = info->cqe_size;
	ZXDH_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;
	cq->cqe_rd_cnt = 0;

	return 0;
}

/**
 * zxdh_clean_cq - clean cq entries
 * @q: completion context
 * @cq: cq to clean
 */
void zxdh_clean_cq(void *q, struct zxdh_cq *cq)
{
	__le64 *cqe;
	__u64 qword0, comp_ctx;
	__u32 cq_head;
	__u8 polarity, temp;

	cq_head = cq->cq_ring.head;
	temp = cq->polarity;
	do {
		if (cq->cqe_size)
			cqe = ((struct zxdh_extended_cqe
					*)(cq->cq_base))[cq_head]
				      .buf;
		else
			cqe = cq->cq_base[cq_head].buf;
		get_64bit_val(cqe, 0, &qword0);
		polarity = (__u8)FIELD_GET(ZXDH_CQ_VALID, qword0);

		if (polarity != temp)
			break;

		get_64bit_val(cqe, 8, &comp_ctx);
		if ((void *)(uintptr_t)comp_ctx == q)
			set_64bit_val(cqe, 8, 0);

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			temp ^= 1;
	} while (true);
}

__le64 *zxdh_get_srq_wqe(struct zxdh_srq *srq, int wqe_index)
{
	__le64 *wqe;

	wqe = srq->srq_base[wqe_index * srq->srq_wqe_size_multiplier].elem;
	return wqe;
}

void zxdh_free_srq_wqe(struct zxdh_srq *srq, int wqe_index)
{
	struct zxdh_usrq *iwusrq;
	__le64 *wqe;
	__u64 hdr;

	iwusrq = container_of(srq, struct zxdh_usrq, srq);
	/* always called with interrupts disabled. */
	pthread_spin_lock(&iwusrq->lock);
	wqe = zxdh_get_srq_wqe(srq, srq->srq_ring.tail);
	srq->srq_ring.tail = wqe_index;
	hdr = FIELD_PREP(ZXDHQPSRQ_NEXT_WQE_INDEX, wqe_index);

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */
	set_64bit_val(wqe, 0, hdr);

	pthread_spin_unlock(&iwusrq->lock);
	zxdh_dbg(ZXDH_DBG_SRQ, "%s srq->srq_id:%d wqe_index:%d\n", __func__,
		 srq->srq_id, wqe_index);
}
