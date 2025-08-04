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
#include "xsc_hsi.h"

enum { CQ_OK = 0, CQ_EMPTY = -1, CQ_POLL_ERR = -2 };

static const u32 xsc_msg_opcode[][2][2] = {
	[XSC_MSG_OPCODE_SEND][XSC_REQ][XSC_WITHOUT_IMMDT] =
		XSC_OPCODE_RDMA_REQ_SEND,
	[XSC_MSG_OPCODE_SEND][XSC_REQ][XSC_WITH_IMMDT] =
		XSC_OPCODE_RDMA_REQ_SEND_IMMDT,
	[XSC_MSG_OPCODE_SEND][XSC_RSP][XSC_WITHOUT_IMMDT] =
		XSC_OPCODE_RDMA_RSP_RECV,
	[XSC_MSG_OPCODE_SEND][XSC_RSP][XSC_WITH_IMMDT] =
		XSC_OPCODE_RDMA_RSP_RECV_IMMDT,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_REQ][XSC_WITHOUT_IMMDT] =
		XSC_OPCODE_RDMA_REQ_WRITE,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_REQ][XSC_WITH_IMMDT] =
		XSC_OPCODE_RDMA_REQ_WRITE_IMMDT,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_RSP][XSC_WITHOUT_IMMDT] =
		XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_RSP][XSC_WITH_IMMDT] =
		XSC_OPCODE_RDMA_RSP_WRITE_IMMDT,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_REQ][XSC_WITHOUT_IMMDT] =
		XSC_OPCODE_RDMA_REQ_READ,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_REQ][XSC_WITH_IMMDT] =
		XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_RSP][XSC_WITHOUT_IMMDT] =
		XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_RSP][XSC_WITH_IMMDT] =
		XSC_OPCODE_RDMA_CQE_ERROR,
};

static const u32 xsc_cqe_opcode[] = {
	[XSC_OPCODE_RDMA_REQ_SEND] = IBV_WC_SEND,
	[XSC_OPCODE_RDMA_REQ_SEND_IMMDT] = IBV_WC_SEND,
	[XSC_OPCODE_RDMA_RSP_RECV] = IBV_WC_RECV,
	[XSC_OPCODE_RDMA_RSP_RECV_IMMDT] = IBV_WC_RECV,
	[XSC_OPCODE_RDMA_REQ_WRITE] = IBV_WC_RDMA_WRITE,
	[XSC_OPCODE_RDMA_REQ_WRITE_IMMDT] = IBV_WC_RDMA_WRITE,
	[XSC_OPCODE_RDMA_RSP_WRITE_IMMDT] = IBV_WC_RECV_RDMA_WITH_IMM,
	[XSC_OPCODE_RDMA_REQ_READ] = IBV_WC_RDMA_READ,
};

static inline u8 xsc_get_cqe_opcode(struct xsc_context *ctx,
				    struct xsc_cqe *cqe) ALWAYS_INLINE;
static inline u8 xsc_get_cqe_opcode(struct xsc_context *ctx,
				    struct xsc_cqe *cqe)
{
	u8 msg_opcode = ctx->hw_ops->get_cqe_msg_opcode(cqe);
	u8 type = FIELD_GET(CQE_DATA0_TYPE_MASK, le32toh(cqe->data0));
	u8 with_immdt = FIELD_GET(CQE_DATA0_WITH_IMMDT_MASK,
				  le32toh(cqe->data0));

	if (ctx->hw_ops->is_err_cqe(cqe))
		return type ? XSC_OPCODE_RDMA_RSP_ERROR :
				   XSC_OPCODE_RDMA_REQ_ERROR;
	if (msg_opcode > XSC_MSG_OPCODE_RDMA_READ) {
		printf("rdma cqe msg code should be send/write/read\n");
		return XSC_OPCODE_RDMA_CQE_ERROR;
	}
	return xsc_msg_opcode[msg_opcode][type][with_immdt];
}

static inline int get_qp_ctx(struct xsc_context *xctx,
			     struct xsc_resource **cur_rsc,
			     u32 qpn) ALWAYS_INLINE;
static inline int get_qp_ctx(struct xsc_context *xctx,
			     struct xsc_resource **cur_rsc, u32 qpn)
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
	struct xsc_context *ctx =
		to_xctx(ibv_cq_ex_to_cq(&cq->verbs_cq.cq_ex)->context);

	ctx->hw_ops->set_cq_ci(cq->db, cq->cqn, cq->cons_index);
}

static void dump_cqe(void *buf)
{
	__le32 *p = buf;
	int i;

	for (i = 0; i < 8; i += 4)
		printf("0x%08x 0x%08x 0x%08x 0x%08x\n", p[i], p[i + 1],
		       p[i + 2], p[i + 3]);
}

static enum ibv_wc_status xsc_cqe_error_code(u8 error_code)
{
	switch (error_code) {
	case XSC_ERR_CODE_NAK_RETRY:
		return IBV_WC_RETRY_EXC_ERR;
	case XSC_ERR_CODE_NAK_OPCODE:
		return IBV_WC_REM_INV_REQ_ERR;
	case XSC_ERR_CODE_NAK_MR:
		return IBV_WC_REM_ACCESS_ERR;
	case XSC_ERR_CODE_NAK_OPERATION:
		return IBV_WC_REM_OP_ERR;
	case XSC_ERR_CODE_NAK_RNR:
		return IBV_WC_RNR_RETRY_EXC_ERR;
	case XSC_ERR_CODE_LOCAL_MR:
		return IBV_WC_LOC_PROT_ERR;
	case XSC_ERR_CODE_LOCAL_LEN:
		return IBV_WC_LOC_LEN_ERR;
	case XSC_ERR_CODE_LEN_GEN_CQE:
		return IBV_WC_LOC_LEN_ERR;
	case XSC_ERR_CODE_OPERATION:
		return IBV_WC_LOC_ACCESS_ERR;
	case XSC_ERR_CODE_FLUSH:
		return IBV_WC_WR_FLUSH_ERR;
	case XSC_ERR_CODE_MALF_WQE_HOST:
	case XSC_ERR_CODE_STRG_ACC_GEN_CQE:
	case XSC_ERR_CODE_STRG_ACC:
		return IBV_WC_FATAL_ERR;
	case XSC_ERR_CODE_MR_GEN_CQE:
		return IBV_WC_LOC_PROT_ERR;
	case XSC_ERR_CODE_OPCODE_GEN_CQE:
	case XSC_ERR_CODE_LOCAL_OPCODE:
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static inline void handle_good_req(struct ibv_wc *wc, struct xsc_cqe *cqe,
				   struct xsc_qp *qp, struct xsc_wq *wq,
				   u8 opcode)
{
	int idx;
	struct xsc_send_wqe_ctrl_seg *ctrl;

	wc->opcode = xsc_cqe_opcode[opcode];
	wc->status = IBV_WC_SUCCESS;
	idx = FIELD_GET(CQE_DATA1_WQE_ID_MASK, le64toh(cqe->data1));
	idx >>= (qp->sq.wqe_shift - XSC_BASE_WQE_SHIFT);
	idx &= (wq->wqe_cnt - 1);
	wc->wr_id = wq->wrid[idx];
	wq->tail = wq->wqe_head[idx] + 1;
	if (opcode == XSC_OPCODE_RDMA_REQ_READ) {
		ctrl = xsc_get_send_wqe(qp, idx);
		wc->byte_len = le32toh(ctrl->msg_len);
	}
	wq->flush_wqe_cnt--;

	xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_CQ_CQE,
		"wqeid:%u, wq tail:%u\n", idx, wq->tail);
}

static inline void handle_good_responder(struct ibv_wc *wc, struct xsc_cqe *cqe,
					 struct xsc_wq *wq, u8 opcode)
{
	u16 idx;
	struct xsc_qp *qp = container_of(wq, struct xsc_qp, rq);

	wc->byte_len = le32toh(cqe->msg_len);
	wc->opcode = xsc_cqe_opcode[opcode];
	wc->status = IBV_WC_SUCCESS;

	idx = wq->tail & (wq->wqe_cnt - 1);
	wc->wr_id = wq->wrid[idx];
	++wq->tail;
	wq->flush_wqe_cnt--;

	xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_CQ_CQE,
		"recv cqe idx:%u, len:%u\n", idx, wc->byte_len);
}

static inline void handle_bad_req(struct xsc_context *xctx, struct ibv_wc *wc,
				  struct xsc_cqe *cqe, struct xsc_qp *qp,
				  struct xsc_wq *wq)
{
	int idx;
	u8 error_code = xctx->hw_ops->get_cqe_error_code(cqe);

	wc->status = xsc_cqe_error_code(error_code);
	wc->vendor_err = error_code;
	idx = FIELD_GET(CQE_DATA1_WQE_ID_MASK, le64toh(cqe->data1));
	idx >>= (qp->sq.wqe_shift - XSC_BASE_WQE_SHIFT);
	idx &= (wq->wqe_cnt - 1);
	wq->tail = wq->wqe_head[idx] + 1;
	wc->wr_id = wq->wrid[idx];
	wq->flush_wqe_cnt--;
	if (error_code != XSC_ERR_CODE_FLUSH) {
		printf("%s: got completion with error:\n", xctx->hostname);
		dump_cqe(cqe);
	}
	qp->ibv_qp->state = IBV_QPS_ERR;
}

static inline void handle_bad_responder(struct xsc_context *xctx,
					struct ibv_wc *wc, struct xsc_cqe *cqe,
					struct xsc_qp *qp, struct xsc_wq *wq)
{
	u8 error_code = xctx->hw_ops->get_cqe_error_code(cqe);

	wc->status = xsc_cqe_error_code(error_code);
	wc->vendor_err = error_code;

	++wq->tail;
	wq->flush_wqe_cnt--;
	if (error_code != XSC_ERR_CODE_FLUSH) {
		printf("%s: got completion with error:\n", xctx->hostname);
		dump_cqe(cqe);
	}
	qp->ibv_qp->state = IBV_QPS_ERR;
}

static inline int xsc_parse_cqe(struct xsc_cq *cq, struct xsc_cqe *cqe,
				struct xsc_resource **cur_rsc,
				struct ibv_wc *wc, int lazy)
{
	struct xsc_wq *wq;
	u32 qp_id;
	u8 opcode;
	int err = 0;
	struct xsc_qp *xqp = NULL;
	struct xsc_context *xctx;

	xctx = to_xctx(ibv_cq_ex_to_cq(&cq->verbs_cq.cq_ex)->context);
	qp_id = FIELD_GET(CQE_DATA0_QP_ID_MASK, le32toh(cqe->data0));
	wc->wc_flags = 0;
	wc->qp_num = qp_id;
	opcode = xsc_get_cqe_opcode(xctx, cqe);

	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ_CQE, "opcode:0x%x qp_num:%u\n", opcode,
		qp_id);
	switch (opcode) {
	case XSC_OPCODE_RDMA_REQ_SEND_IMMDT:
	case XSC_OPCODE_RDMA_REQ_WRITE_IMMDT:
		wc->wc_flags |= IBV_WC_WITH_IMM;
		SWITCH_FALLTHROUGH;
	case XSC_OPCODE_RDMA_REQ_SEND:
	case XSC_OPCODE_RDMA_REQ_WRITE:
	case XSC_OPCODE_RDMA_REQ_READ:
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
		wc->imm_data = htobe32(le32toh(cqe->imm_data));
		SWITCH_FALLTHROUGH;
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
		handle_bad_responder(xctx, wc, cqe, xqp, wq);
		break;
	case XSC_OPCODE_RDMA_CQE_ERROR:
		printf("%s: got completion with cqe format error:\n",
		       xctx->hostname);
		dump_cqe(cqe);
		SWITCH_FALLTHROUGH;
	default:
		return CQ_POLL_ERR;
	}
	return CQ_OK;
}

static inline int xsc_poll_one(struct xsc_cq *cq, struct xsc_resource **cur_rsc,
			       struct ibv_wc *wc) ALWAYS_INLINE;
static inline int xsc_poll_one(struct xsc_cq *cq, struct xsc_resource **cur_rsc,
			       struct ibv_wc *wc)
{
	struct xsc_cqe *cqe = get_sw_cqe(cq, cq->cons_index);

	if (!cqe)
		return CQ_EMPTY;

	memset(wc, 0, sizeof(*wc));

	++cq->cons_index;

	/*
	 * Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	udma_from_device_barrier();
	return xsc_parse_cqe(cq, cqe, cur_rsc, wc, 0);
}

static inline void gen_flush_err_cqe(struct xsc_err_state_qp_node *err_node,
				     u32 qp_id, struct xsc_wq *wq,
				     u32 idx, struct ibv_wc *wc)
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
	wc->vendor_err = XSC_ERR_CODE_FLUSH;
	wc->wr_id = wq->wrid[idx];
	wq->tail++;
	wq->flush_wqe_cnt--;
}

static inline int xsc_generate_flush_err_cqe(struct ibv_cq *ibcq, int ne,
					     int *npolled, struct ibv_wc *wc)
{
	u32 qp_id = 0;
	u32 flush_wqe_cnt = 0;
	int sw_npolled = 0;
	int ret = 0;
	u32 idx = 0;
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
		wq = err_qp_node->is_sq ? &(rsc_to_xqp(res)->sq) :
					  &(rsc_to_xqp(res)->rq);
		flush_wqe_cnt = wq->flush_wqe_cnt;
		xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ_CQE,
			"is_sq %d, flush_wq_cnt %d, ne %d, npolled %d, qp_id %d\n",
			err_qp_node->is_sq, wq->flush_wqe_cnt, ne, *npolled,
			qp_id);

		if (flush_wqe_cnt <= (ne - *npolled)) {
			while (sw_npolled < flush_wqe_cnt) {
				idx = wq->tail & (wq->wqe_cnt - 1);
				if (err_qp_node->is_sq &&
				    !wq->need_flush[idx]) {
					wq->tail++;
					continue;
				} else {
					gen_flush_err_cqe(err_qp_node,
							  err_qp_node->qp_id,
							  wq, idx,
							  wc + *npolled + sw_npolled);
					++sw_npolled;
				}
			}
			list_del(&err_qp_node->entry);
			free(err_qp_node);
			*npolled += sw_npolled;
		} else {
			while (sw_npolled < (ne - *npolled)) {
				idx = wq->tail & (wq->wqe_cnt - 1);
				if (err_qp_node->is_sq &&
				    !wq->need_flush[idx]) {
					wq->tail++;
					continue;
				} else {
					gen_flush_err_cqe(err_qp_node,
							  err_qp_node->qp_id,
							  wq, idx,
							  wc + *npolled + sw_npolled);
					++sw_npolled;
				}
			}
			*npolled = ne;
			break;
		}
	}

	return 0;
}

static inline int poll_cq(struct ibv_cq *ibcq, int ne,
			  struct ibv_wc *wc) ALWAYS_INLINE;
static inline int poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct xsc_cq *cq = to_xcq(ibcq);
	struct xsc_resource *rsc = NULL;
	int npolled = 0;
	int err = CQ_OK;
	u32 next_cid = cq->cons_index;

	xsc_spin_lock(&cq->lock);
	for (npolled = 0; npolled < ne; ++npolled) {
		err = xsc_poll_one(cq, &rsc, wc + npolled);
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

	return err == CQ_POLL_ERR ? err : npolled;
}

int xsc_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	return poll_cq(ibcq, ne, wc);
}

int xsc_alloc_cq_buf(struct xsc_context *xctx, struct xsc_cq *cq,
		     struct xsc_buf *buf, int nent, int cqe_sz)
{
	struct xsc_device *xdev = to_xdev(xctx->ibv_ctx.context.device);
	int ret;

	ret = xsc_alloc_buf(buf, align(nent * cqe_sz, xdev->page_size),
			    xdev->page_size);
	if (ret)
		return -1;

	memset(buf->buf, 0, nent * cqe_sz);
	return 0;
}

void xsc_free_cq_buf(struct xsc_context *ctx, struct xsc_buf *buf)
{
	return xsc_free_buf(buf);
}

void __xsc_cq_clean(struct xsc_cq *cq, u32 qpn)
{
	u32 prod_index;
	int nfreed = 0;
	void *cqe, *dest;

	if (!cq)
		return;
	xsc_dbg(to_xctx(cq->verbs_cq.cq_ex.context)->dbg_fp, XSC_DBG_CQ, "\n");

	/*
	 * First we need to find the current producer index, so we
	 * know where to start cleaning from.  It doesn't matter if HW
	 * adds new entries after this loop -- the QP we're worried
	 * about is already in RESET, so the new entries won't come
	 * from our QP and therefore don't need to be checked.
	 */
	for (prod_index = cq->cons_index; get_sw_cqe(cq, prod_index);
	     ++prod_index)
		if (prod_index == cq->cons_index + cq->verbs_cq.cq_ex.cqe)
			break;

	/*
	 * Now sweep backwards through the CQ, removing CQ entries
	 * that match our QP by copying older entries on top of them.
	 */
	while ((int)(--prod_index) - (int)cq->cons_index >= 0) {
		u32 qp_id;

		cqe = get_cqe(cq, prod_index & (cq->verbs_cq.cq_ex.cqe - 1));
		qp_id = FIELD_GET(CQE_DATA0_QP_ID_MASK,
				  le32toh(((struct xsc_cqe *)cqe)->data0));
		if (qpn == qp_id) {
			++nfreed;
		} else if (nfreed) {
			dest = get_cqe(cq,
				       (prod_index + nfreed) &
					       (cq->verbs_cq.cq_ex.cqe - 1));
			memcpy(dest, cqe, cq->cqe_sz);
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

