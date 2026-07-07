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

int xsc_qp_fill_wr_pfns(struct xsc_context *ctx,
			struct xsc_qp *xqp,
			const struct ibv_qp_init_attr_ex *attr)
{
	return 0;
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
