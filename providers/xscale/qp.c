// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <config.h>

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <util/compiler.h>

#include "xscale.h"
#include "xsc_hw.h"

static inline void *get_recv_wqe(struct xsc_qp *qp, int n)
{
	return qp->rq_start + (n << qp->rq.wqe_shift);
}

static inline void *get_seg_wqe(void *first, int n)
{
	return first + (n << XSC_BASE_WQE_SHIFT);
}

void xsc_init_qp_indices(struct xsc_qp *qp)
{
	qp->sq.head	 = 0;
	qp->sq.tail	 = 0;
	qp->rq.head	 = 0;
	qp->rq.tail	 = 0;
	qp->sq.cur_post  = 0;
	qp->has_trig_cq_evt = false;
}

static inline int xsc_wq_overflow(struct xsc_wq *wq, int nreq, struct xsc_cq *cq)
{
	uint32_t cur;

	cur = wq->head - wq->tail;
	if (cur + nreq < wq->max_post)
		return 0;

	xsc_spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	xsc_spin_unlock(&cq->lock);

	return cur + nreq >= wq->max_post;
}

static inline void set_data_seg_with_value(struct xsc_qp *qp, struct xsc_wqe_data_seg *data_seg,
					   uint64_t addr, uint32_t key, uint32_t length)
{
	struct xsc_context *ctx = to_xctx(qp->ibv_qp->context);

	xsc_hw_set_data_seg(ctx->device_id, data_seg, addr, key, length);
}

static inline void set_local_data_seg_from_sge(struct xsc_qp *qp, struct xsc_wqe_data_seg *data_seg,
					       const struct ibv_sge *sg)
{
	struct xsc_context *ctx = to_xctx(qp->ibv_qp->context);

	xsc_hw_set_data_seg(ctx->device_id, data_seg, sg->addr, sg->lkey, sg->length);
}

static inline void set_atomic_seg_with_value(struct xsc_qp *qp,
					     struct xsc_wqe_atomic_seg *atomic_seg,
					     int opcode, uint64_t swap, uint64_t compare_add)
{
	struct xsc_context *ctx = to_xctx(qp->ibv_qp->context);

	xsc_hw_set_atomic_seg(ctx->device_id, atomic_seg, opcode, swap, compare_add);
}

static void *get_addr_from_wr(const void *list, int idx)
{
	const struct ibv_send_wr *wr = list;

	return (void *)wr->sg_list[idx].addr;
}

static int get_len_from_wr(const void *list, int idx)
{
	const struct ibv_send_wr *wr = list;

	return wr->sg_list[idx].length;
}

static int _set_wqe_inline(void *data_seg, size_t num_buf, const void *list,
			   void *(*get_addr)(const void *, int),
			   int (*get_len)(const void *, int))
{
	int i;
	int offset = 0;
	int len = 0;
	void *addr;
	void *data_seg_base = data_seg;
	int seg_index = 0;
	const int ds_len = sizeof(struct xsc_wqe_data_seg);

	for (i = 0; i < num_buf; i++) {
		addr = get_addr(list, i);
		len = get_len(list, i);
		if (likely(len)) {
			if (offset) {
				int copy_len = min_t(int, len, ds_len - offset);

				memcpy(data_seg + offset, addr, copy_len);
				addr += copy_len;
				len -= copy_len;
				offset += copy_len;
				if (offset == ds_len)
					offset = 0;
				else
					continue;
			}

			while (len >= ds_len) {
				data_seg = get_seg_wqe(data_seg_base, seg_index);
				seg_index++;
				memcpy(data_seg, addr, ds_len);
				addr += ds_len;
				len -= ds_len;
			}

			if (len > 0) {
				data_seg = get_seg_wqe(data_seg_base, seg_index);
				seg_index++;
				memcpy(data_seg, addr, len);
				offset += len;
			}
		}
	}
	return seg_index;
}

static int set_wqe_inline_from_wr(struct xsc_qp *qp, struct ibv_send_wr *wr,
				  struct xsc_send_wqe_ctrl_seg *ctrl)
{
	void *data_seg;
	unsigned int seg_index;
	int msg_len = ctrl->msg_len;
	int filled_ds_num;

	if (wr->opcode == IBV_WR_SEND || wr->opcode == IBV_WR_SEND_WITH_IMM)
		seg_index = 1;
	else
		seg_index = 2;
	data_seg = get_seg_wqe(ctrl, seg_index);

	if (unlikely(msg_len > qp->max_inline_data))
		return ENOMEM;

	filled_ds_num = _set_wqe_inline(data_seg, wr->num_sge, wr,
					get_addr_from_wr,
					get_len_from_wr);
	ctrl->data0 |= FIELD_PREP(XSC_SWQE_CTRL_SEG_DS_DATA_NUM_MASK,
				  seg_index - 1 + filled_ds_num);

	return 0;
}

static inline void _zero_send_ds(int idx, struct xsc_qp *qp, int keep_ctrl)
{
	void *seg;
	uint64_t *p;
	int i;

	seg = (void *)xsc_get_send_wqe(qp, idx);
	for (i = keep_ctrl; i < qp->sq.seg_cnt; i++) {
		p = get_seg_wqe(seg, i);
		p[0] = p[1] = 0;
	}
}

static inline void clear_send_wqe(int idx, struct xsc_qp *qp)
{
	_zero_send_ds(idx, qp, 0);
}

static inline void clear_send_wqe_except_ctrl(int idx, struct xsc_qp *qp)
{
	_zero_send_ds(idx, qp, 1);
}

static void clear_recv_wqe(int idx, struct xsc_qp *qp)
{
	void *seg;
	uint64_t *p;
	int i;

	seg = (void *)get_recv_wqe(qp, idx);
	for (i = 0; i < qp->rq.seg_cnt; i++) {
		p = get_seg_wqe(seg, i);
		p[0] = p[1] = 0;
	}
}

#ifdef XSC_DEBUG
static void dump_wqe(int type, int idx, struct xsc_qp *qp)
{
	/* type0 send type1 recv */
	uint32_t *p;
	int i;
	void *seg;

	if (type == 0) {
		seg = (void *)xsc_get_send_wqe(qp, idx);
		xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_QP,
				"dump send wqe at %p\n", seg);
		for (i = 0; i < qp->sq.seg_cnt; i++) {
			p = get_seg_wqe(seg, i);
			xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_QP,
					"0x%08x 0x%08x 0x%08x 0x%08x\n", p[0], p[1], p[2], p[3]);
		}
	} else if (type == 1) {
		seg = (void *)get_recv_wqe(qp, idx);
		xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_QP,
				"dump recv wqe at %p\n", seg);
		for (i = 0; i < qp->rq.seg_cnt; i++) {
			p = get_seg_wqe(seg, i);
			xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_QP,
					"0x%08x 0x%08x 0x%08x 0x%08x\n", p[0], p[1], p[2], p[3]);
		}
	} else {
		xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_QP,
				"unknown type %d\n", type);
	}
}
#else
static inline void dump_wqe(int type, int idx, struct xsc_qp *qp) {};
#endif

static inline void xsc_post_send_db(struct xsc_qp *qp, int nreq)
{
	struct xsc_context *ctx = to_xctx(qp->ibv_qp->context);
	uint32_t next_pid;

	if (unlikely(!nreq))
		return;

	qp->sq.head += nreq;
	next_pid = qp->sq.head << (qp->sq.wqe_shift - XSC_BASE_WQE_SHIFT);
	xsc_dbg(to_xctx(qp->ibv_qp->context)->dbg_fp, XSC_DBG_QP_SEND, "nreq:%d\n", nreq);
	xsc_hw_ring_tx_doorbell(ctx->device_id, qp->sq.db, qp->sqn, next_pid);
}

static inline int _xsc_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
				  struct ibv_send_wr **bad_wr)
{
	struct xsc_qp *qp = to_xqp(ibqp);
	void *seg;
	struct xsc_send_wqe_ctrl_seg *ctrl;
	struct xsc_wqe_data_seg *data_seg;
	struct xsc_wqe_atomic_seg *atomic_seg;
	struct xsc_context *ctx = to_xctx(ibqp->context);
	int nreq;
	int err = 0;
	int i;
	unsigned int idx;
	unsigned int seg_index = 1;
	unsigned int msg_len = 0;

	if (unlikely(ibqp->state < IBV_QPS_RTS)) {
		xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
				"qp state is %u, should not post send\n", ibqp->state);
		err = EINVAL;
		*bad_wr = wr;
		return err;
	}

	xsc_spin_lock(&qp->sq.lock);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		seg_index = 1;
		msg_len = 0;
		if (unlikely(wr->opcode < 0 ||
			wr->opcode >= sizeof(ctx->wr2msg) / sizeof(ctx->wr2msg[0]))) {
			xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
					"bad opcode %d\n", wr->opcode);
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(xsc_wq_overflow(&qp->sq, nreq,
					      to_xcq(qp->ibv_qp->send_cq)))) {
			xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
					"send work queue overflow\n");
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->sq.max_gs)) {
			xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
					"max gs exceeded %d (max = %d)\n",
					wr->num_sge, qp->sq.max_gs);
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->opcode == IBV_WR_RDMA_READ && wr->num_sge > 1)) {
			xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
					"rdma read, max gs exceeded %d (max = 1)\n",
					wr->num_sge);
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		idx = qp->sq.cur_post & (qp->sq.wqe_cnt - 1);
		clear_send_wqe(idx, qp);
		ctrl = seg = xsc_get_send_wqe(qp, idx);
		ctrl->data0 |= FIELD_PREP(XSC_SWQE_CTRL_SEG_DS_DATA_NUM_MASK, 0) |
			       FIELD_PREP(XSC_SWQE_CTRL_SEG_WITH_IMMDT_MASK, 0);
		xsc_hw_set_wqe_id(to_xctx(ibqp->context)->device_id, ctrl,
			qp->sq.cur_post << (qp->sq.wqe_shift - XSC_BASE_WQE_SHIFT));
		ctrl->data1 |= FIELD_PREP(XSC_SWQE_CTRL_SEG_SE_MASK,
					  wr->send_flags & IBV_SEND_SOLICITED ? 1 : 0) |
			       FIELD_PREP(XSC_SWQE_CTRL_SEG_CE_MASK,
					  qp->sq_signal_bits ?
					  1 : (wr->send_flags & IBV_SEND_SIGNALED ? 1 : 0)) |
			       FIELD_PREP(XSC_SWQE_CTRL_SEG_IN_LINE_MASK,
					  wr->send_flags & IBV_SEND_INLINE ? 1 : 0) |
			       FIELD_PREP(XSC_SWQE_CTRL_SEG_FENCE_MODE_MASK,
					  wr->send_flags & IBV_SEND_FENCE ? 1 : 0) |
			       FIELD_PREP(XSC_SWQE_CTRL_SEG_MASK_MASK, 0);
		for (i = 0; i < wr->num_sge; ++i) {
			if (likely(wr->sg_list[i].length))
				msg_len += wr->sg_list[i].length;
		}
		ctrl->msg_len = msg_len;

		if (unlikely(wr->opcode == IBV_WR_RDMA_READ && msg_len == 0)) {
			xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
					"rdma read, msg len should not be 0\n");
			/* workaround, return success for posting zero-length read */
			err = 0;
			goto out;
		}

		switch (ibqp->qp_type) {
		case IBV_QPT_RC:
			switch (wr->opcode) {
			case IBV_WR_SEND_WITH_INV:
			case IBV_WR_SEND:
				break;
			case IBV_WR_SEND_WITH_IMM:
				ctrl->data0 |= FIELD_PREP(XSC_SWQE_CTRL_SEG_WITH_IMMDT_MASK, 1);
				WR_LE_32(ctrl->opcode_data, RD_BE_32(wr->imm_data));
				break;
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				ctrl->data0 |= FIELD_PREP(XSC_SWQE_CTRL_SEG_WITH_IMMDT_MASK, 1);
				WR_LE_32(ctrl->opcode_data, RD_BE_32(wr->imm_data));
				SWITCH_FALLTHROUGH;
			case IBV_WR_RDMA_READ:
			case IBV_WR_RDMA_WRITE:
				if (ctrl->msg_len == 0)
					break;
				data_seg = get_seg_wqe(ctrl, seg_index);
				set_data_seg_with_value(qp,
							data_seg,
							wr->wr.rdma.remote_addr,
							wr->wr.rdma.rkey,
							msg_len);
				seg_index++;
				break;
			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				if (unlikely(!qp->atomics_enabled)) {
					xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
						"atomic operations are not supported\n");
					err = EOPNOTSUPP;
					*bad_wr = wr;
					goto out;
				}

				ctrl->msg_len = 16;
				data_seg = get_seg_wqe(ctrl, seg_index);
				set_data_seg_with_value(qp,
							data_seg,
							wr->wr.atomic.remote_addr,
							wr->wr.atomic.rkey, 8);
				seg_index++;
				break;
			default:
				printf("debug: opcode:%u NOT supported\n", wr->opcode);
				err = EPERM;
				*bad_wr = wr;
				goto out;
			}
			break;
		default:
			xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
					"qp type:%u NOT supported\n", ibqp->qp_type);
			err = EPERM;
			*bad_wr = wr;
			goto out;
		}

		if ((wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP ||
		     wr->opcode == IBV_WR_ATOMIC_FETCH_AND_ADD) && qp->atomics_enabled) {
			ctrl->data1 |= FIELD_PREP(XSC_SWQE_CTRL_SEG_IN_LINE_MASK, 1);
			data_seg = get_seg_wqe(ctrl, seg_index);
			set_data_seg_with_value(qp,
						data_seg,
						wr->sg_list[0].addr,
						wr->sg_list[0].lkey,
						8);
			seg_index++;
			atomic_seg = get_seg_wqe(ctrl, seg_index);
			set_atomic_seg_with_value(qp,
						  atomic_seg,
						  wr->opcode,
						  wr->wr.atomic.swap,
						  wr->wr.atomic.compare_add);
			seg_index++;
		} else {
			if (wr->send_flags & IBV_SEND_INLINE && wr->num_sge) {
				err = set_wqe_inline_from_wr(qp, wr, ctrl);
				if (unlikely(err)) {
					*bad_wr = wr;
					xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP_SEND,
							"inline layout failed, err %d\n", err);
					goto out;
				}
			} else {
				for (i = 0; i < wr->num_sge; ++i, ++seg_index) {
					if (likely(wr->sg_list[i].length)) {
						data_seg = get_seg_wqe(ctrl, seg_index);
						set_local_data_seg_from_sge(qp, data_seg,
									    &wr->sg_list[i]);
					}
				}
			}
		}

		ctrl->msg_opcode = ctx->wr2msg[wr->opcode];
		if (ctrl->msg_len == 0) {
			ctrl->data0 |= FIELD_PREP(XSC_SWQE_CTRL_SEG_DS_DATA_NUM_MASK, 0);
			clear_send_wqe_except_ctrl(idx, qp);
		}
		ctrl->data0 |= FIELD_PREP(XSC_SWQE_CTRL_SEG_DS_DATA_NUM_MASK, seg_index - 1);
		qp->sq.wrid[idx] = wr->wr_id;
		qp->sq.wqe_head[idx] = qp->sq.head + nreq;
		qp->sq.cur_post += 1;
		if (FIELD_GET(XSC_SWQE_CTRL_SEG_CE_MASK, ctrl->data1))
			qp->sq.need_flush[idx] = 1;
		qp->sq.wr_opcode[idx] = wr->opcode;

		if (unlikely(xsc_debug_mask & XSC_DBG_QP_SEND))
			dump_wqe(0, idx, qp);
	}

out:
	xsc_post_send_db(qp, nreq);
	xsc_spin_unlock(&qp->sq.lock);

	return err;
}

int xsc_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		   struct ibv_send_wr **bad_wr)
{
	return _xsc_post_send(ibqp, wr, bad_wr);
}

int xsc_qp_fill_wr_pfns(struct xsc_context *ctx,
			struct xsc_qp *xqp,
			const struct ibv_qp_init_attr_ex *attr)
{
	return 0;
}

int xsc_post_recv_dump_wqe = 1;
int xsc_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	struct xsc_qp *qp = to_xqp(ibqp);
	struct xsc_wqe_data_seg *recv_head;
	struct xsc_wqe_data_seg *data_seg;
	int err = 0;
	uint32_t next_pid = 0;
	int nreq;
	uint16_t idx;
	int i;

	xsc_spin_lock(&qp->rq.lock);

	idx = qp->rq.head & (qp->rq.wqe_cnt - 1);

	clear_recv_wqe(idx, qp);
	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(xsc_wq_overflow(&qp->rq, nreq,
					to_xcq(qp->ibv_qp->recv_cq)))) {
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->rq.max_gs)) {
			printf("max gs exceeded %d (max = %d)\n",
				wr->num_sge, qp->rq.max_gs);
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		recv_head = get_recv_wqe(qp, idx);

		for (i = 0; i < wr->num_sge; ++i) {
			if (unlikely(!wr->sg_list[i].length))
				continue;
			data_seg = get_seg_wqe(recv_head, i);
			set_local_data_seg_from_sge(qp, data_seg, &wr->sg_list[i]);
		}

		qp->rq.wrid[idx] = wr->wr_id;

		if (xsc_post_recv_dump_wqe || (xsc_debug_mask & XSC_DBG_QP_RECV))
			dump_wqe(1, idx, qp);
		idx = (idx + 1) & (qp->rq.wqe_cnt - 1);
	}

out:
	if (likely(nreq)) {
		struct xsc_context *ctx = to_xctx(ibqp->context);

		qp->rq.head += nreq;
		next_pid = qp->rq.head << (qp->rq.wqe_shift - XSC_BASE_WQE_SHIFT);
		xsc_hw_ring_rx_doorbell(ctx->device_id, qp->rq.db, qp->rqn, next_pid);
	}

	xsc_spin_unlock(&qp->rq.lock);

	return err;
}

struct xsc_qp *xsc_find_qp(struct xsc_context *ctx, uint32_t qpn)
{
	int tind = qpn >> XSC_QP_TABLE_SHIFT;

	if (ctx->qp_table[tind].refcnt)
		return ctx->qp_table[tind].table[qpn & XSC_QP_TABLE_MASK];
	else
		return NULL;
}

int xsc_store_qp(struct xsc_context *ctx, uint32_t qpn, struct xsc_qp *qp)
{
	int tind = qpn >> XSC_QP_TABLE_SHIFT;

	if (!ctx->qp_table[tind].refcnt) {
		ctx->qp_table[tind].table = calloc(XSC_QP_TABLE_MASK + 1,
						   sizeof(struct xsc_qp *));
		if (!ctx->qp_table[tind].table)
			return -1;
	}

	++ctx->qp_table[tind].refcnt;
	ctx->qp_table[tind].table[qpn & XSC_QP_TABLE_MASK] = qp;
	return 0;
}

void xsc_clear_qp(struct xsc_context *ctx, uint32_t qpn)
{
	int tind = qpn >> XSC_QP_TABLE_SHIFT;

	if (!--ctx->qp_table[tind].refcnt)
		free(ctx->qp_table[tind].table);
	else
		ctx->qp_table[tind].table[qpn & XSC_QP_TABLE_MASK] = NULL;
}

int xsc_err_state_qp(struct ibv_qp *qp, enum ibv_qp_state cur_state,
			enum ibv_qp_state state)
{
	struct xsc_err_state_qp_node *tmp, *err_rq_node, *err_sq_node;
	struct xsc_qp *xqp = to_xqp(qp);
	struct ibv_qp_attr attr = {0};
	int attr_mask = 0;
	struct ibv_qp_init_attr init_attr = {0};

	xsc_dbg(to_xctx(qp->context)->dbg_fp, XSC_DBG_QP,
		"modify qp: qpid %d, cur_qp_state %d, qp_state %d\n",
		xqp->rsc.rsn, cur_state, state);
	if (cur_state == IBV_QPS_ERR && state != IBV_QPS_ERR) {
		if (qp->recv_cq) {
			list_for_each_safe(&to_xcq(qp->recv_cq)->err_state_qp_list,
					   err_rq_node, tmp, entry) {
				if (err_rq_node->qp_id == xqp->rsc.rsn) {
					list_del(&err_rq_node->entry);
					free(err_rq_node);
				}
			}
		}

		if (qp->send_cq) {
			list_for_each_safe(&to_xcq(qp->send_cq)->err_state_qp_list,
					   err_sq_node, tmp, entry) {
				if (err_sq_node->qp_id == xqp->rsc.rsn) {
					list_del(&err_sq_node->entry);
					free(err_sq_node);
				}
			}
		}
		return 0;
	}

	if (cur_state != IBV_QPS_ERR && state == IBV_QPS_ERR && !xqp->has_trig_cq_evt) {
		if (qp->recv_cq) {
			err_rq_node = calloc(1, sizeof(*err_rq_node));
			if (!err_rq_node)
				return ENOMEM;
			err_rq_node->qp_id = xqp->rsc.rsn;
			err_rq_node->is_sq = false;
			list_add_tail(&to_xcq(qp->recv_cq)->err_state_qp_list, &err_rq_node->entry);
		}

		if (qp->send_cq) {
			err_sq_node = calloc(1, sizeof(*err_sq_node));
			if (!err_sq_node)
				return ENOMEM;
			err_sq_node->qp_id = xqp->rsc.rsn;
			err_sq_node->is_sq = true;
			list_add_tail(&to_xcq(qp->send_cq)->err_state_qp_list, &err_sq_node->entry);

			if (qp->send_cq->channel) {
				attr_mask |= XSC_QP_FLUSH;
				xsc_query_qp(qp, &attr, attr_mask, &init_attr);
				xqp->has_trig_cq_evt = true;
			}
		}
	}
	return 0;
}
