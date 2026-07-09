// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <util/compiler.h>
#include <infiniband/opcode.h>

#include "xscale.h"
#include "xsc_hw.h"

enum {
	CQ_OK					=  0,
	CQ_EMPTY				= -1,
	CQ_POLL_ERR				= -2
};

enum {
	XSC_CQE_APP_TAG_MATCHING = 1,
};

enum {
	XSC_CQE_APP_OP_TM_CONSUMED = 0x1,
	XSC_CQE_APP_OP_TM_EXPECTED = 0x2,
	XSC_CQE_APP_OP_TM_UNEXPECTED = 0x3,
	XSC_CQE_APP_OP_TM_NO_TAG = 0x4,
	XSC_CQE_APP_OP_TM_APPEND = 0x5,
	XSC_CQE_APP_OP_TM_REMOVE = 0x6,
	XSC_CQE_APP_OP_TM_NOOP = 0x7,
	XSC_CQE_APP_OP_TM_CONSUMED_SW_RDNV = 0x9,
	XSC_CQE_APP_OP_TM_CONSUMED_MSG = 0xA,
	XSC_CQE_APP_OP_TM_CONSUMED_MSG_SW_RDNV = 0xB,
	XSC_CQE_APP_OP_TM_MSG_COMPLETION_CANCELED = 0xC,
};

static const uint32_t xsc_cqe_opcode[] = {
	[XSC_OPCODE_RDMA_REQ_SEND]		= IBV_WC_SEND,
	[XSC_OPCODE_RDMA_REQ_SEND_IMMDT]	= IBV_WC_SEND,
	[XSC_OPCODE_RDMA_RSP_RECV]		= IBV_WC_RECV,
	[XSC_OPCODE_RDMA_RSP_RECV_IMMDT]	= IBV_WC_RECV,
	[XSC_OPCODE_RDMA_REQ_WRITE]		= IBV_WC_RDMA_WRITE,
	[XSC_OPCODE_RDMA_REQ_WRITE_IMMDT]	= IBV_WC_RDMA_WRITE,
	[XSC_OPCODE_RDMA_RSP_WRITE_IMMDT]	= IBV_WC_RECV_RDMA_WITH_IMM,
	[XSC_OPCODE_RDMA_REQ_READ]		= IBV_WC_RDMA_READ,
	[XSC_OPCODE_RDMA_CQE_RAW_SNF]		= IBV_WC_RECV,
	[XSC_OPCODE_RDMA_REQ_ATOMIC_CMP_AND_SWAP] = IBV_WC_COMP_SWAP,
	[XSC_OPCODE_RDMA_REQ_ATOMIC_FETCH_AND_ADD] = IBV_WC_FETCH_ADD,
};

static void xsc_stall_poll_cq(void)
{
	int i;

	for (i = 0; i < 60; i++)
		__asm__ volatile ("nop");
}

static inline int get_qp_ctx(struct xsc_context *xctx,
			     struct xsc_resource **cur_rsc,
			     uint32_t qpn)
			     ALWAYS_INLINE;
static inline int get_qp_ctx(struct xsc_context *xctx,
			     struct xsc_resource **cur_rsc,
			     uint32_t qpn)
{
	if (!*cur_rsc || (qpn != (*cur_rsc)->rsn)) {
		/*
		 * We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		*cur_rsc = (struct xsc_resource *)xsc_find_qp(xctx, qpn);
		if (unlikely(!*cur_rsc))
			return CQ_POLL_ERR;
	}

	return CQ_OK;
}

static inline uint8_t xsc_get_cqe_opcode(struct xsc_context *ctx,
					 struct xsc_resource **cur_rsc,
					 struct xsc_cqe *cqe) ALWAYS_INLINE;
static inline uint8_t xsc_get_cqe_opcode(struct xsc_context *ctx,
					 struct xsc_resource **cur_rsc,
					 struct xsc_cqe *cqe)
{
	uint8_t msg_opcode = xsc_hw_get_cqe_msg_opcode(ctx->device_id, cqe);
	struct xsc_qp *qp;
	uint8_t type;
	uint8_t with_immdt;
	int err;

	type = FIELD_GET(XSC_CQE_TYPE_MASK, cqe->data1);
	with_immdt = FIELD_GET(XSC_CQE_WITH_IMMDT_MASK, cqe->data1);
	if (xsc_hw_is_err_cqe(ctx->device_id, cqe))
		return type ? XSC_OPCODE_RDMA_RSP_ERROR : XSC_OPCODE_RDMA_REQ_ERROR;

	err = get_qp_ctx(ctx, cur_rsc, RD_LE_16(FIELD_GET(XSC_CQE_QP_ID_MASK, cqe->data1)));
	if (unlikely(err))
		goto msg_opcode_err_check;
	qp = rsc_to_xqp(*cur_rsc);
	if (qp->flags & XSC_QP_FLAG_RAWPACKET_SNIFFER)
		return XSC_OPCODE_RDMA_CQE_RAW_SNF;

msg_opcode_err_check:
	if (xsc_check_cqe_msg_opcode(ctx, msg_opcode)) {
		printf("rdma cqe msg code should be send/write/read/atomic\n");
		return XSC_OPCODE_RDMA_CQE_ERROR;
	}

	return ctx->msg2cqe[msg_opcode][type][with_immdt];
}

static void *get_cqe(struct xsc_cq *cq, int n)
{
	return cq->active_buf->buf + n * cq->cqe_sz;
}

static void *get_sw_cqe(struct xsc_cq *cq, int n)
{
	int cid = n & (cq->verbs_cq.cq_ex.cqe - 1);
	struct xsc_cqe *cqe = get_cqe(cq, cid);

	if (likely(xsc_get_cqe_sw_own(cqe, n, cq->log2_cq_ring_sz)))
		return cqe;
	else
		return NULL;
}

static void update_cons_index(struct xsc_cq *cq)
{
	struct xsc_context *ctx = to_xctx(ibv_cq_ex_to_cq(&cq->verbs_cq.cq_ex)->context);

	xsc_hw_set_cq_ci(ctx->device_id, cq->db, cq->cqn, cq->cons_index);
}

static inline void handle_good_req(struct ibv_wc *wc, struct xsc_cqe *cqe,
				   struct xsc_qp *qp, struct xsc_wq *wq,
				   uint8_t opcode)
{
	int idx;
	struct xsc_send_wqe_ctrl_seg *ctrl;

	wc->opcode = xsc_cqe_opcode[opcode];
	wc->status = IBV_WC_SUCCESS;
	idx = xsc_hw_get_wqe_id(to_xctx(qp->ibv_qp->context)->device_id, cqe);
	idx >>= (qp->sq.wqe_shift - XSC_BASE_WQE_SHIFT);
	idx &= (wq->wqe_cnt - 1);
	wc->wr_id = wq->wrid[idx];
	wq->tail = wq->wqe_head[idx] + 1;
	if (opcode == XSC_OPCODE_RDMA_REQ_READ) {
		ctrl = xsc_get_send_wqe(qp, idx);
		wc->byte_len = ctrl->msg_len;
	}
	wq->need_flush[idx] = 0;

	xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_CQ_CQE,
			"wqeid:%u, wq tail:%u\n", idx, wq->tail);
}

static inline void handle_good_responder(
	struct ibv_wc *wc, struct xsc_cqe *cqe, struct xsc_wq *wq, uint8_t opcode)
{
	uint16_t idx;
	struct xsc_qp *qp = container_of(wq, struct xsc_qp, rq);

	wc->byte_len = RD_LE_32(cqe->msg_len);
	wc->opcode = xsc_cqe_opcode[opcode];
	wc->status = IBV_WC_SUCCESS;

	idx = wq->tail & (wq->wqe_cnt - 1);
	wc->wr_id = wq->wrid[idx];
	++wq->tail;

	xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_CQ_CQE,
			"recv cqe idx:%u, len:%u\n", idx, wc->byte_len);
}

static void dump_cqe(void *buf)
{
	__le32 *p = buf;
	int i;

	for (i = 0; i < 8; i += 4)
		printf("0x%08x 0x%08x 0x%08x 0x%08x\n", p[i], p[i+1], p[i+2], p[i+3]);
}

static inline void handle_bad_req(
	struct xsc_context *xctx,
	struct ibv_wc *wc, struct xsc_cqe *cqe, struct xsc_qp *qp, struct xsc_wq *wq)
{
	int idx;

	wc->status = xsc_hw_cqe_err_status(xctx->device_id, cqe);
	wc->vendor_err = xsc_hw_get_cqe_err_code(xctx->device_id, cqe);
	idx = xsc_hw_get_wqe_id(xctx->device_id, cqe);
	idx >>= (qp->sq.wqe_shift - XSC_BASE_WQE_SHIFT);
	idx &= (wq->wqe_cnt - 1);
	wq->tail = wq->wqe_head[idx] + 1;
	wc->wr_id = wq->wrid[idx];
	wq->need_flush[idx] = 0;
	if (wc->status != IBV_WC_WR_FLUSH_ERR) {
		printf("%s: got completion with error:\n", xctx->hostname);
		dump_cqe(cqe);
	}
	if (xsc_need_modify_qp_to_err(xctx->device_id, cqe)) {
		qp->err_occurred = 1;
		xsc_err_state_qp(qp->ibv_qp, qp->ibv_qp->state, IBV_QPS_ERR);
	}
}

static inline bool xsc_need_report_rsp_err_cqe(struct xsc_context *ctx, struct xsc_cqe *cqe)
{
	uint8_t msg_opcode;
	bool with_immdt;

	switch (ctx->device_id) {
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		msg_opcode = xsc_diamond_get_cqe_msg_opcode(cqe);
		with_immdt = FIELD_GET(XSC_CQE_WITH_IMMDT_MASK, cqe->data1);
		xsc_dbg(ctx->dbg_fp, XSC_DBG_CQ_CQE, "msg_opcode:0x%x with_immdt:%u\n",
			msg_opcode, with_immdt);
		if (msg_opcode == XSC_MSG_OPCODE_SEND_DIAMOND_NEXT ||
			(msg_opcode == XSC_MSG_OPCODE_RDMA_WRITE && with_immdt))
			return true;
		else
			return false;
		break;
	default:
		return true;
	}
}

static inline void handle_bad_responder(
	struct xsc_context *xctx, struct ibv_wc *wc, struct xsc_cqe *cqe,
	struct xsc_qp *qp, struct xsc_wq *wq, uint8_t *cqe_valid)
{
	int idx;

	if (xsc_need_report_rsp_err_cqe(xctx, cqe)) {
		idx = wq->tail & (wq->wqe_cnt - 1);
		wc->wr_id = wq->wrid[idx];
		wc->status = xsc_hw_cqe_err_status(xctx->device_id, cqe);
		wc->vendor_err = xsc_hw_get_cqe_err_code(xctx->device_id, cqe);

		++wq->tail;
		if (wc->status != IBV_WC_WR_FLUSH_ERR) {
			printf("%s: got completion with error:\n", xctx->hostname);
			dump_cqe(cqe);
		}
	} else {
		*cqe_valid = 0;
	}

	if (xsc_need_modify_qp_to_err(xctx->device_id, cqe)) {
		qp->err_occurred = 1;
		xsc_err_state_qp(qp->ibv_qp, qp->ibv_qp->state, IBV_QPS_ERR);
	}
}

static inline int xsc_parse_cqe(struct xsc_cq *cq,
				struct xsc_cqe *cqe,
				struct xsc_resource **cur_rsc,
				struct ibv_wc *wc, uint8_t *cqe_valid)
				ALWAYS_INLINE;
static inline int xsc_parse_cqe(struct xsc_cq *cq,
				struct xsc_cqe *cqe,
				struct xsc_resource **cur_rsc,
				struct ibv_wc *wc, uint8_t *cqe_valid)
{
	struct xsc_wq *wq;
	uint32_t qp_id;
	uint8_t opcode;
	int err = 0;
	struct xsc_qp *xqp = NULL;
	struct xsc_context *xctx;

	*cqe_valid = 1;
	memset(wc, 0, sizeof(*wc));
	wc->wc_flags = 0;

	xctx = to_xctx(ibv_cq_ex_to_cq(&cq->verbs_cq.cq_ex)->context);
	qp_id = RD_LE_16(FIELD_GET(XSC_CQE_QP_ID_MASK, cqe->data1));
	wc->qp_num = qp_id;
	opcode = xsc_get_cqe_opcode(xctx, cur_rsc, cqe);

	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ_CQE, "opcode:0x%x qp_num:%u\n", opcode, qp_id);
	switch (opcode) {
	case XSC_OPCODE_RDMA_REQ_SEND_IMMDT:
	case XSC_OPCODE_RDMA_REQ_WRITE_IMMDT:
		wc->wc_flags |= IBV_WC_WITH_IMM;
		SWITCH_FALLTHROUGH;
	case XSC_OPCODE_RDMA_REQ_SEND:
	case XSC_OPCODE_RDMA_REQ_WRITE:
	case XSC_OPCODE_RDMA_REQ_READ:
	case XSC_OPCODE_RDMA_REQ_ATOMIC_CMP_AND_SWAP:
	case XSC_OPCODE_RDMA_REQ_ATOMIC_FETCH_AND_ADD:
	case XSC_OPCODE_RDMA_REQ_ATOMIC_8B_MASK_CS:
	case XSC_OPCODE_RDMA_REQ_ATOMIC_8B_MASK_FA:
	case XSC_OPCODE_RDMA_REQ_ATOMIC_4B_MASK_CS:
	case XSC_OPCODE_RDMA_REQ_ATOMIC_4B_MASK_FA:
		err = get_qp_ctx(xctx, cur_rsc, qp_id);
		if (unlikely(err))
			return CQ_EMPTY;
		xqp = rsc_to_xqp(*cur_rsc);
		wq = &xqp->sq;
		handle_good_req(wc, cqe, xqp, wq, opcode);
		break;
	case XSC_OPCODE_RDMA_RSP_RECV_IMMDT:
	case XSC_OPCODE_RDMA_RSP_WRITE_IMMDT:
		wc->wc_flags |= IBV_WC_WITH_IMM;
		WR_BE_32(wc->imm_data, RD_LE_32(cqe->imm_data));
		SWITCH_FALLTHROUGH;
	case XSC_OPCODE_RDMA_CQE_RAW_SNF:
	case XSC_OPCODE_RDMA_RSP_RECV:
		err = get_qp_ctx(xctx, cur_rsc, qp_id);
		if (unlikely(err))
			return CQ_EMPTY;
		xqp = rsc_to_xqp(*cur_rsc);
		wq = &xqp->rq;
		handle_good_responder(wc, cqe, wq, opcode);
		break;
	case XSC_OPCODE_RDMA_REQ_ERROR:
		err = get_qp_ctx(xctx, cur_rsc, qp_id);
		if (unlikely(err))
			return CQ_POLL_ERR;
		xqp = rsc_to_xqp(*cur_rsc);
		wq = &xqp->sq;
		handle_bad_req(xctx, wc, cqe, xqp, wq);
		break;
	case XSC_OPCODE_RDMA_RSP_ERROR:
		err = get_qp_ctx(xctx, cur_rsc, qp_id);
		if (unlikely(err))
			return CQ_POLL_ERR;
		xqp = rsc_to_xqp(*cur_rsc);
		wq = &xqp->rq;
		handle_bad_responder(xctx, wc, cqe, xqp, wq, cqe_valid);
		break;
	case XSC_OPCODE_RDMA_CQE_ERROR:
		printf("%s: got completion with cqe format error:\n", xctx->hostname);
		dump_cqe(cqe);
		SWITCH_FALLTHROUGH;
	default:
		return CQ_POLL_ERR;
	}
	return CQ_OK;
}

static inline int xsc_parse_cqe_lazy(struct xsc_cq *cq, struct xsc_cqe *cqe) ALWAYS_INLINE;
static inline int xsc_parse_cqe_lazy(struct xsc_cq *cq, struct xsc_cqe *cqe)
{
	struct xsc_resource *cur_rsc = NULL;
	struct xsc_qp *xqp = NULL;
	struct xsc_context *xctx;
	struct xsc_wq *wq;
	uint32_t qp_id;
	uint8_t opcode;
	int err = 0;
	int idx;

	cq->cqe = cqe;
	xctx = to_xctx(ibv_cq_ex_to_cq(&cq->verbs_cq.cq_ex)->context);
	qp_id = RD_LE_16(FIELD_GET(XSC_CQE_QP_ID_MASK, cqe->data1));
	opcode = xsc_get_cqe_opcode(xctx, &cur_rsc, cqe);

	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ_CQE, "opcode:0x%x qp_num:%u\n", opcode, qp_id);
	switch (opcode) {
	case XSC_OPCODE_RDMA_REQ_SEND_IMMDT:
	case XSC_OPCODE_RDMA_REQ_WRITE_IMMDT:
	case XSC_OPCODE_RDMA_REQ_SEND:
	case XSC_OPCODE_RDMA_REQ_WRITE:
	case XSC_OPCODE_RDMA_REQ_READ:
		cq->verbs_cq.cq_ex.status = IBV_WC_SUCCESS;
		err = get_qp_ctx(xctx, &cur_rsc, qp_id);
		if (unlikely(err))
			return CQ_EMPTY;
		xqp = rsc_to_xqp(cur_rsc);
		wq = &xqp->sq;
		idx = xsc_hw_get_wqe_id(xctx->device_id, cqe);
		idx >>= (wq->wqe_shift - XSC_BASE_WQE_SHIFT);
		idx &= (wq->wqe_cnt - 1);
		cq->verbs_cq.cq_ex.wr_id = wq->wrid[idx];
		wq->tail = wq->wqe_head[idx] + 1;
		wq->need_flush[idx] = 0;
		break;
	case XSC_OPCODE_RDMA_RSP_RECV_IMMDT:
	case XSC_OPCODE_RDMA_RSP_WRITE_IMMDT:
	case XSC_OPCODE_RDMA_RSP_RECV:
		cq->verbs_cq.cq_ex.status = IBV_WC_SUCCESS;
		err = get_qp_ctx(xctx, &cur_rsc, qp_id);
		if (unlikely(err))
			return CQ_EMPTY;
		xqp = rsc_to_xqp(cur_rsc);
		wq = &xqp->rq;
		idx = wq->tail & (wq->wqe_cnt - 1);
		cq->verbs_cq.cq_ex.wr_id = wq->wrid[idx];
		++wq->tail;
		break;
	case XSC_OPCODE_RDMA_REQ_ERROR:
		cq->verbs_cq.cq_ex.status = xsc_hw_cqe_err_status(xctx->device_id, cqe);
		err = get_qp_ctx(xctx, &cur_rsc, qp_id);
		if (unlikely(err))
			return CQ_POLL_ERR;
		xqp = rsc_to_xqp(cur_rsc);
		wq = &xqp->sq;
		idx = xsc_hw_get_wqe_id(xctx->device_id, cqe);
		idx >>= (wq->wqe_shift - XSC_BASE_WQE_SHIFT);
		idx &= (wq->wqe_cnt - 1);
		wq->tail = wq->wqe_head[idx] + 1;
		cq->verbs_cq.cq_ex.wr_id = wq->wrid[idx];
		wq->need_flush[idx] = 0;
		if (cq->verbs_cq.cq_ex.status != IBV_WC_WR_FLUSH_ERR) {
			printf("%s: got completion with error:\n", xctx->hostname);
			dump_cqe(cqe);
		}
		xqp->ibv_qp->state = IBV_QPS_ERR;
		break;
	case XSC_OPCODE_RDMA_RSP_ERROR:
		cq->verbs_cq.cq_ex.status = xsc_hw_cqe_err_status(xctx->device_id, cqe);
		err = get_qp_ctx(xctx, &cur_rsc, qp_id);
		if (unlikely(err))
			return CQ_POLL_ERR;
		xqp = rsc_to_xqp(cur_rsc);
		wq = &xqp->rq;

		++wq->tail;
		if (cq->verbs_cq.cq_ex.status != IBV_WC_WR_FLUSH_ERR) {
			printf("%s: got completion with error:\n", xctx->hostname);
			dump_cqe(cqe);
		}
		xqp->ibv_qp->state = IBV_QPS_ERR;
		break;
	case XSC_OPCODE_RDMA_CQE_ERROR:
		printf("%s: got completion with cqe format error:\n", xctx->hostname);
		dump_cqe(cqe);
		SWITCH_FALLTHROUGH;
	default:
		return CQ_POLL_ERR;
	}
	return CQ_OK;
}

static inline int xsc_poll_one(struct xsc_cq *cq,
				struct xsc_resource **cur_rsc,
				struct ibv_wc *wc,
				int lazy, uint8_t *cqe_valid)
				ALWAYS_INLINE;
static inline int xsc_poll_one(struct xsc_cq *cq,
				struct xsc_resource **cur_rsc,
				struct ibv_wc *wc,
				int lazy, uint8_t *cqe_valid)
{
	struct xsc_cqe *cqe = get_sw_cqe(cq, cq->cons_index);
	int err = 0;

	if (!cqe)
		return CQ_EMPTY;

	++cq->cons_index;

	/*
	 * Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	udma_from_device_barrier();
	if (!lazy)
		err = xsc_parse_cqe(cq, cqe, cur_rsc, wc, cqe_valid);
	else
		err = xsc_parse_cqe_lazy(cq, cqe);

	return err;
}

static inline void gen_flush_err_cqe(struct xsc_err_state_qp_node *err_node,
						uint32_t qp_id, struct xsc_wq *wq, uint32_t idx,
						struct ibv_wc *wc)
{
	memset(wc, 0, sizeof(*wc));
	if (err_node->is_sq) {
		switch (wq->wr_opcode[idx]) {
		case IBV_WR_SEND:
		case IBV_WR_SEND_WITH_IMM:
		case IBV_WR_SEND_WITH_INV:
			wc->opcode = IBV_WC_SEND;
			break;
		case IBV_WR_RDMA_WRITE:
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			wc->opcode = IBV_WC_RDMA_WRITE;
			break;
		case IBV_WR_RDMA_READ:
			wc->opcode = IBV_WC_RDMA_READ;
		}
	} else {
		wc->opcode = IBV_WC_RECV;
	}

	wc->qp_num = qp_id;
	wc->status = IBV_WC_WR_FLUSH_ERR;
	wc->vendor_err = XSC_ANDES_ERR_CODE_FLUSH;
	wc->wr_id = wq->wrid[idx];
	wq->tail++;
	if (err_node->is_sq)
		wq->need_flush[idx] = 0;
}

static inline int xsc_generate_flush_err_cqe(struct ibv_cq *ibcq,
				int ne, int *npolled, struct ibv_wc *wc)
{
	uint32_t qp_id = 0;
	int sw_npolled = 0;
	int ret = 0;
	uint32_t idx = 0;
	struct xsc_err_state_qp_node *err_qp_node, *tmp;
	struct xsc_resource *res = NULL;
	struct xsc_context *xctx = to_xctx(ibcq->context);
	struct xsc_cq *cq = to_xcq(ibcq);
	struct xsc_wq *wq;

	list_for_each_safe(&cq->err_state_qp_list, err_qp_node, tmp, entry) {
		if (!err_qp_node)
			break;

		sw_npolled = 0;
		qp_id = err_qp_node->qp_id;
		ret = get_qp_ctx(xctx, &res, qp_id);
		if (unlikely(ret))
			continue;
		wq = err_qp_node->is_sq ? &(rsc_to_xqp(res)->sq) : &(rsc_to_xqp(res)->rq);
		xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ_CQE, "is_sq %d, head %d, tail %d, ne %d, npolled %d, qp_id %d\n",
			err_qp_node->is_sq, wq->head, wq->tail, ne, *npolled, qp_id);

		while (wq->head != wq->tail) {
			idx = wq->tail & (wq->wqe_cnt - 1);
			if (err_qp_node->is_sq && !wq->need_flush[idx]) {
				wq->tail++;
				continue;
			} else {
				gen_flush_err_cqe(err_qp_node, err_qp_node->qp_id, wq,
					idx, wc + *npolled + sw_npolled);
				++sw_npolled;
				if (sw_npolled == (ne - *npolled))
					break;
			}
		}

		if (wq->head == wq->tail) {
			list_del(&err_qp_node->entry);
			free(err_qp_node);
		}
		*npolled += sw_npolled;
		if (*npolled == ne)
			return 0;
	}

	return 0;
}

static inline int poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc) ALWAYS_INLINE;
static inline int poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct xsc_cq *cq = to_xcq(ibcq);
	struct xsc_resource *rsc = NULL;
	int npolled = 0;
	int err = CQ_OK;
	uint32_t next_cid = cq->cons_index;
	uint8_t cqe_valid = 1;

	if (cq->stall_enable && cq->stall_next_poll) {
		cq->stall_next_poll = 0;
		xsc_stall_poll_cq();
	}

	xsc_spin_lock(&cq->lock);
	for (npolled = 0; npolled < ne; npolled += cqe_valid) {
		err = xsc_poll_one(cq, &rsc, wc + npolled, 0, &cqe_valid);
		if (err != CQ_OK)
			break;
	}

	if (err == CQ_EMPTY) {
		if (npolled < ne && !(list_empty(&cq->err_state_qp_list)))
			xsc_generate_flush_err_cqe(ibcq, ne, &npolled, wc);
	}

	udma_to_device_barrier();
	if (next_cid != cq->cons_index)
		update_cons_index(cq);
	xsc_spin_unlock(&cq->lock);

	if (cq->stall_enable && err == CQ_EMPTY)
		cq->stall_next_poll = 1;

	return err == CQ_POLL_ERR ? err : npolled;
}

int xsc_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	return poll_cq(ibcq, ne, wc);
}

static inline int xsc_start_poll(struct ibv_cq_ex *ibcq,
				 struct ibv_poll_cq_attr *attr)
				 ALWAYS_INLINE;
static inline int xsc_start_poll(struct ibv_cq_ex *ibcq,
				 struct ibv_poll_cq_attr *attr)
{
	struct xsc_cq *cq = to_xcq(ibv_cq_ex_to_cq(ibcq));
	int err;
	uint8_t cqe_valid = 1;

	xsc_spin_lock(&cq->lock);
	err = xsc_poll_one(cq, NULL, NULL, 1, &cqe_valid);
	if (err == CQ_EMPTY)
		xsc_spin_unlock(&cq->lock);

	return (err == CQ_EMPTY) ? ENOENT : err;
}

static inline void xsc_end_poll(struct ibv_cq_ex *ibcq)
				ALWAYS_INLINE;
static inline void xsc_end_poll(struct ibv_cq_ex *ibcq)
{
	struct xsc_cq *cq = to_xcq(ibv_cq_ex_to_cq(ibcq));

	udma_to_device_barrier();
	update_cons_index(cq);
	xsc_spin_unlock(&cq->lock);
}

static inline int xsc_next_poll(struct ibv_cq_ex *ibcq)
				ALWAYS_INLINE;
static inline int xsc_next_poll(struct ibv_cq_ex *ibcq)
{
	struct xsc_cq *cq = to_xcq(ibv_cq_ex_to_cq(ibcq));
	int err;
	uint8_t cqe_valid = 1;

	err = xsc_poll_one(cq, NULL, NULL, 1, &cqe_valid);

	return (err == CQ_EMPTY) ? ENOENT : err;
}

static inline enum ibv_wc_opcode xsc_wc_read_opcode(struct ibv_cq_ex *ibcq)
{
	struct xsc_cqe *cqe = to_xcq(ibv_cq_ex_to_cq(ibcq))->cqe;
	struct xsc_context *xctx = to_xctx(ibv_cq_ex_to_cq(ibcq)->context);
	uint8_t opcode = xsc_hw_get_cqe_msg_opcode(xctx->device_id, cqe);

	return xsc_cqe_opcode[opcode];
}

static inline uint32_t xsc_wc_read_qp_num(struct ibv_cq_ex *ibcq)
{
	struct xsc_cqe *cqe = to_xcq(ibv_cq_ex_to_cq(ibcq))->cqe;

	return le32toh(FIELD_GET(XSC_CQE_QP_ID_MASK, cqe->data1));
}

static inline unsigned int xsc_wc_read_flags(struct ibv_cq_ex *ibcq)
{
	struct xsc_cqe *cqe = to_xcq(ibv_cq_ex_to_cq(ibcq))->cqe;
	struct xsc_context *xctx = to_xctx(ibv_cq_ex_to_cq(ibcq)->context);
	uint8_t opcode = xsc_hw_get_cqe_msg_opcode(xctx->device_id, cqe);

	switch (opcode) {
	case XSC_OPCODE_RDMA_REQ_SEND_IMMDT:
	case XSC_OPCODE_RDMA_REQ_WRITE_IMMDT:
	case XSC_OPCODE_RDMA_RSP_RECV_IMMDT:
	case XSC_OPCODE_RDMA_RSP_WRITE_IMMDT:
		return IBV_WC_WITH_IMM;
	default:
		return 0;
	}
}

static inline uint32_t xsc_wc_read_byte_len(struct ibv_cq_ex *ibcq)
{
	struct xsc_cqe *cqe = to_xcq(ibv_cq_ex_to_cq(ibcq))->cqe;

	return le32toh(cqe->msg_len);
}

static inline uint32_t xsc_wc_read_vendor_err(struct ibv_cq_ex *ibcq)
{
	struct xsc_cqe *cqe = to_xcq(ibv_cq_ex_to_cq(ibcq))->cqe;
	struct xsc_context *xctx = to_xctx(ibv_cq_ex_to_cq(ibcq)->context);

	return xsc_hw_get_cqe_err_code(xctx->device_id, cqe);
}

static inline __be32 xsc_wc_read_imm_data(struct ibv_cq_ex *ibcq)
{
	struct xsc_cqe *cqe = to_xcq(ibv_cq_ex_to_cq(ibcq))->cqe;
	__be32 imm_data;

	WR_BE_32(imm_data, RD_LE_32(cqe->imm_data));

	return imm_data;
}

static inline uint64_t xsc_wc_read_completion_ts(struct ibv_cq_ex *ibcq)
{
	struct xsc_cqe *cqe = to_xcq(ibv_cq_ex_to_cq(ibcq))->cqe;

	return le64toh(FIELD_GET(XSC_CQE_TS_MASK, cqe->data2));
}

void xsc_cq_fill_pfns(struct xsc_cq *cq, const struct ibv_cq_init_attr_ex *cq_attr)
{

	cq->verbs_cq.cq_ex.start_poll = xsc_start_poll;
	cq->verbs_cq.cq_ex.next_poll = xsc_next_poll;
	cq->verbs_cq.cq_ex.end_poll = xsc_end_poll;

	cq->verbs_cq.cq_ex.read_opcode = xsc_wc_read_opcode;
	cq->verbs_cq.cq_ex.read_vendor_err = xsc_wc_read_vendor_err;
	cq->verbs_cq.cq_ex.read_wc_flags = xsc_wc_read_flags;
	if (cq_attr->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		cq->verbs_cq.cq_ex.read_byte_len = xsc_wc_read_byte_len;
	if (cq_attr->wc_flags & IBV_WC_EX_WITH_IMM)
		cq->verbs_cq.cq_ex.read_imm_data = xsc_wc_read_imm_data;
	if (cq_attr->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		cq->verbs_cq.cq_ex.read_qp_num = xsc_wc_read_qp_num;
	if (cq_attr->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP)
		cq->verbs_cq.cq_ex.read_completion_ts = xsc_wc_read_completion_ts;
}

int xsc_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	struct xsc_cq *cq = to_xcq(ibvcq);
	struct xsc_context *ctx = to_xctx(ibvcq->context);

	xsc_hw_update_cq_db(ctx->device_id, cq->armdb, cq->cqn, cq->cons_index, solicited);

	return 0;
}

void xsc_cq_event(struct ibv_cq *cq)
{
	to_xcq(cq)->arm_sn++;
}

static int is_equal_rsn(struct xsc_cqe *cqe, uint32_t rsn)
{
	uint32_t qp_id;

	qp_id = RD_LE_16(FIELD_GET(XSC_CQE_QP_ID_MASK, cqe->data1));
	return rsn == qp_id;
}

static inline int free_res_cqe(struct xsc_cqe *cqe, uint32_t rsn)
{
	if (is_equal_rsn(cqe, rsn))
		return 1;

	return 0;
}

void __xsc_cq_clean(struct xsc_cq *cq, uint32_t rsn)
{
	uint32_t prod_index;
	int nfreed = 0;
	struct xsc_cqe *cqe, *dest;
	uint8_t owner_bit;

	if (!cq || cq->flags & XSC_CQ_FLAGS_DV_OWNED)
		return;
	xsc_dbg(to_xctx(cq->verbs_cq.cq_ex.context)->dbg_fp, XSC_DBG_CQ, "\n");

	/*
	 * First we need to find the current producer index, so we
	 * know where to start cleaning from.  It doesn't matter if HW
	 * adds new entries after this loop -- the QP we're worried
	 * about is already in RESET, so the new entries won't come
	 * from our QP and therefore don't need to be checked.
	 */
	for (prod_index = cq->cons_index; get_sw_cqe(cq, prod_index); ++prod_index)
		if (prod_index == cq->cons_index + cq->verbs_cq.cq_ex.cqe)
			break;

	/*
	 * Now sweep backwards through the CQ, removing CQ entries
	 * that match our QP by copying older entries on top of them.
	 */
	while ((int) --prod_index - (int) cq->cons_index >= 0) {
		cqe = get_cqe(cq, prod_index & (cq->verbs_cq.cq_ex.cqe - 1));
		if (free_res_cqe(cqe, rsn)) {
			++nfreed;
		} else if (nfreed) {
			dest = get_cqe(cq, (prod_index + nfreed) & (cq->verbs_cq.cq_ex.cqe - 1));
			owner_bit = FIELD_GET(XSC_CQE_OWNER_MASK, dest->data3);
			memcpy(dest, cqe, cq->cqe_sz);
			dest->data3 |= FIELD_PREP(XSC_CQE_OWNER_MASK, owner_bit);
		}
	}

	if (nfreed) {
		cq->cons_index += nfreed;
		/*
		 * Make sure update of buffer contents is done before
		 * updating consumer index.
		 */
		udma_to_device_barrier();
		update_cons_index(cq);
	}
}

void xsc_cq_clean(struct xsc_cq *cq, uint32_t qpn)
{
	xsc_spin_lock(&cq->lock);
	__xsc_cq_clean(cq, qpn);
	xsc_spin_unlock(&cq->lock);
}

int xsc_use_huge(const char *key)
{
	char *e;

	e = getenv(key);
	if (e && !strcmp(e, "y"))
		return 1;

	return 0;
}

int xsc_alloc_cq_buf(struct xsc_context *xctx, struct xsc_cq *cq,
		      struct xsc_buf *buf, int nent, int cqe_sz,
		      struct xscdv_devx_umem_in *umem_in)
{
	struct xsc_device *xdev = to_xdev(xctx->ibv_ctx.context.device);
	int ret;
	enum xsc_alloc_type type;
	enum xsc_alloc_type default_type = XSC_ALLOC_TYPE_ANON;

	if (umem_in) {
		if (umem_in->comp_mask & XSCDV_UMEM_MASK_DMABUF) {
			if (umem_in->dmabuf_fd == -1) {
				xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ,
					"dmabuf_fd is invalid :%u\n",
					umem_in->dmabuf_fd);
				return -1;
			}
		}

		buf->type = XSC_ALLOC_TYPE_GPU;
		buf->buf = umem_in->addr;
		buf->length = umem_in->size;

		xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ,
			"cq_buf(%p),cq_buf_size=0x%lx is given by gpu memory,infact need size=0x%x.\n",
			buf->buf, buf->length, (nent * cqe_sz));
	} else {
		if (xsc_use_huge("HUGE_CQ"))
			default_type = XSC_ALLOC_TYPE_HUGE;

		xsc_get_alloc_type(xctx, XSC_CQ_PREFIX, &type, default_type);

		ret = xsc_alloc_prefered_buf(xctx, buf,
					     align(nent * cqe_sz, xdev->page_size),
					     xdev->page_size,
					     type,
					     XSC_CQ_PREFIX);

		if (ret)
			return -1;

		memset(buf->buf, 0, nent * cqe_sz);
	}

	return 0;
}

int xsc_free_cq_buf(struct xsc_context *ctx, struct xsc_buf *buf)
{
	if (buf->type != XSC_ALLOC_TYPE_GPU)
		return xsc_free_actual_buf(ctx, buf);
	else
		return 0;
}
