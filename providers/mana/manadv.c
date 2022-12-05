// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022, Microsoft Corporation. All rights reserved.
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

int manadv_set_context_attr(struct ibv_context *ibv_ctx,
			    enum manadv_set_ctx_attr_type type, void *attr)
{
	struct mana_context *ctx = to_mctx(ibv_ctx);
	int ret;

	switch (type) {
	case MANADV_CTX_ATTR_BUF_ALLOCATORS:
		ctx->extern_alloc = *((struct manadv_ctx_allocators *)attr);
		ret = 0;
		break;
	default:
		verbs_err(verbs_get_ctx(ibv_ctx),
			  "Unsupported context type %d\n", type);
		ret = EOPNOTSUPP;
	}

	return ret;
}

int manadv_init_obj(struct manadv_obj *obj, uint64_t obj_type)
{
	if (obj_type & ~(MANADV_OBJ_QP | MANADV_OBJ_CQ | MANADV_OBJ_RWQ))
		return EINVAL;

	if (obj_type & MANADV_OBJ_QP) {
		struct ibv_qp *ibqp = obj->qp.in;
		struct mana_qp *qp =
			container_of(ibqp, struct mana_qp, ibqp.qp);

		struct ibv_context *context = ibqp->context;
		struct mana_context *ctx = to_mctx(context);

		obj->qp.out->sq_buf = qp->send_buf;
		obj->qp.out->sq_count = qp->send_wqe_count;
		obj->qp.out->sq_size = qp->send_buf_size;
		obj->qp.out->sq_id = qp->sqid;
		obj->qp.out->tx_vp_offset = qp->tx_vp_offset;
		obj->qp.out->db_page = ctx->db_page;
	}

	if (obj_type & MANADV_OBJ_CQ) {
		struct ibv_cq *ibcq = obj->cq.in;
		struct mana_cq *cq = container_of(ibcq, struct mana_cq, ibcq);

		obj->cq.out->buf = cq->buf;
		obj->cq.out->count = cq->cqe;
		obj->cq.out->cq_id = cq->cqid;
	}

	if (obj_type & MANADV_OBJ_RWQ) {
		struct ibv_wq *ibwq = obj->rwq.in;
		struct mana_wq *wq = container_of(ibwq, struct mana_wq, ibwq);

		struct ibv_context *context = ibwq->context;
		struct mana_context *ctx = to_mctx(context);

		obj->rwq.out->buf = wq->buf;
		obj->rwq.out->count = wq->wqe;
		obj->rwq.out->size = wq->buf_size;
		obj->rwq.out->wq_id = wq->wqid;
		obj->rwq.out->db_page = ctx->db_page;
	}

	return 0;
}
