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

DECLARE_DRV_CMD(mana_create_qp, IB_USER_VERBS_CMD_CREATE_QP, mana_ib_create_qp,
		mana_ib_create_qp_resp);

DECLARE_DRV_CMD(mana_create_qp_ex, IB_USER_VERBS_EX_CMD_CREATE_QP,
		mana_ib_create_qp_rss, mana_ib_create_qp_rss_resp);

static struct ibv_qp *mana_create_qp_raw(struct ibv_pd *ibpd,
					 struct ibv_qp_init_attr *attr)
{
	int ret;
	struct mana_cq *cq;
	struct mana_qp *qp;
	struct mana_pd *pd = container_of(ibpd, struct mana_pd, ibv_pd);
	struct mana_parent_domain *mpd;
	uint32_t port;

	struct mana_create_qp qp_cmd = {};
	struct mana_create_qp_resp qp_resp = {};
	struct mana_ib_create_qp *qp_cmd_drv;
	struct mana_ib_create_qp_resp *qp_resp_drv;

	struct mana_context *ctx = to_mctx(ibpd->context);

	/* This is a RAW QP, pd is a parent domain with port number */
	if (!pd->mprotection_domain) {
		verbs_err(verbs_get_ctx(ibpd->context),
			  "Create RAW QP should use parent domain\n");
		errno = EINVAL;
		return NULL;
	}

	mpd = container_of(pd, struct mana_parent_domain, mpd);
	port = (uint32_t)(uintptr_t)mpd->pd_context;

	cq = container_of(attr->send_cq, struct mana_cq, ibcq);

	if (attr->cap.max_send_wr > MAX_SEND_BUFFERS_PER_QUEUE) {
		verbs_err(verbs_get_ctx(ibpd->context),
			  "max_send_wr %d exceeds MAX_SEND_BUFFERS_PER_QUEUE\n",
			  attr->cap.max_send_wr);
		errno = EINVAL;
		return NULL;
	}

	if (get_wqe_size(attr->cap.max_send_sge) > MAX_TX_WQE_SIZE) {
		verbs_err(verbs_get_ctx(ibpd->context),
			  "max_send_sge %d exceeding queue size limits\n",
			  attr->cap.max_send_sge);
		errno = EINVAL;
		return NULL;
	}

	if (!ctx->extern_alloc.alloc || !ctx->extern_alloc.free) {
		verbs_err(verbs_get_ctx(ibpd->context),
			  "RAW QP requires extern alloc for buffers\n");
		errno = EINVAL;
		return NULL;
	}

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	qp->send_buf_size =
		attr->cap.max_send_wr * get_wqe_size(attr->cap.max_send_sge);
	qp->send_buf_size = align_hw_size(qp->send_buf_size);

	qp->send_buf = ctx->extern_alloc.alloc(qp->send_buf_size,
					       ctx->extern_alloc.data);
	if (!qp->send_buf) {
		errno = ENOMEM;
		goto free_qp;
	}

	qp_cmd_drv = &qp_cmd.drv_payload;
	qp_resp_drv = &qp_resp.drv_payload;

	qp_cmd_drv->sq_buf_addr = (uintptr_t)qp->send_buf;
	qp_cmd_drv->sq_buf_size = qp->send_buf_size;
	qp_cmd_drv->port = port;

	ret = ibv_cmd_create_qp(ibpd, &qp->ibqp.qp, attr, &qp_cmd.ibv_cmd,
				sizeof(qp_cmd), &qp_resp.ibv_resp,
				sizeof(qp_resp));
	if (ret) {
		verbs_err(verbs_get_ctx(ibpd->context), "Create QP failed\n");
		ctx->extern_alloc.free(qp->send_buf, ctx->extern_alloc.data);
		errno = ret;
		goto free_qp;
	}

	qp->sqid = qp_resp_drv->sqid;
	qp->tx_vp_offset = qp_resp_drv->tx_vp_offset;
	qp->send_wqe_count = attr->cap.max_send_wr;

	cq->cqid = qp_resp_drv->cqid;

	return &qp->ibqp.qp;

free_qp:
	free(qp);
	return NULL;
}

struct ibv_qp *mana_create_qp(struct ibv_pd *ibpd,
			      struct ibv_qp_init_attr *attr)
{
	switch (attr->qp_type) {
	case IBV_QPT_RAW_PACKET:
		return mana_create_qp_raw(ibpd, attr);
	default:
		verbs_err(verbs_get_ctx(ibpd->context),
			  "QP type %u is not supported\n", attr->qp_type);
		errno = EINVAL;
	}

	return NULL;
}

int mana_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	return EOPNOTSUPP;
}

int mana_destroy_qp(struct ibv_qp *ibqp)
{
	int ret;
	struct mana_qp *qp = container_of(ibqp, struct mana_qp, ibqp.qp);
	struct mana_context *ctx = to_mctx(ibqp->context);

	if (!ctx->extern_alloc.free) {
		/*
		 * This version of driver doesn't support allocating buffers
		 * in rdma-core.
		 */
		verbs_err(verbs_get_ctx(ibqp->context),
			  "Invalid context in Destroy QP\n");
		return -EINVAL;
	}

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		verbs_err(verbs_get_ctx(ibqp->context), "Destroy QP failed\n");
		return ret;
	}

	ctx->extern_alloc.free(qp->send_buf, ctx->extern_alloc.data);
	free(qp);

	return 0;
}

static struct ibv_qp *mana_create_qp_ex_raw(struct ibv_context *context,
					    struct ibv_qp_init_attr_ex *attr)
{
	struct mana_create_qp_ex cmd = {};
	struct mana_ib_create_qp_rss *cmd_drv;
	struct mana_create_qp_ex_resp resp = {};
	struct mana_ib_create_qp_rss_resp *cmd_resp;
	struct mana_qp *qp;
	struct mana_pd *pd = container_of(attr->pd, struct mana_pd, ibv_pd);
	struct mana_parent_domain *mpd;
	uint32_t port;
	int ret;

	cmd_drv = &cmd.drv_payload;
	cmd_resp = &resp.drv_payload;

	/* For a RAW QP, pd is a parent domain with port number */
	if (!pd->mprotection_domain) {
		verbs_err(verbs_get_ctx(context),
			  "RAW QP needs to be on a parent domain\n");
		errno = EINVAL;
		return NULL;
	}

	if (attr->rx_hash_conf.rx_hash_key_len !=
	    MANA_IB_TOEPLITZ_HASH_KEY_SIZE_IN_BYTES) {
		verbs_err(verbs_get_ctx(context),
			  "Invalid RX hash key length\n");
		errno = EINVAL;
		return NULL;
	}

	mpd = container_of(pd, struct mana_parent_domain, mpd);
	port = (uint32_t)(uintptr_t)mpd->pd_context;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	cmd_drv->rx_hash_fields_mask = attr->rx_hash_conf.rx_hash_fields_mask;
	cmd_drv->rx_hash_function = attr->rx_hash_conf.rx_hash_function;
	cmd_drv->rx_hash_key_len = attr->rx_hash_conf.rx_hash_key_len;
	if (cmd_drv->rx_hash_key_len)
		memcpy(cmd_drv->rx_hash_key, attr->rx_hash_conf.rx_hash_key,
		       cmd_drv->rx_hash_key_len);

	cmd_drv->port = port;

	ret = ibv_cmd_create_qp_ex2(context, &qp->ibqp, attr, &cmd.ibv_cmd,
				    sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (ret) {
		verbs_err(verbs_get_ctx(context), "Create QP EX failed\n");
		free(qp);
		errno = ret;
		return NULL;
	}

	if (attr->rwq_ind_tbl) {
		struct mana_rwq_ind_table *ind_table =
			container_of(attr->rwq_ind_tbl,
				     struct mana_rwq_ind_table, ib_ind_table);
		for (int i = 0; i < ind_table->ind_tbl_size; i++) {
			struct mana_wq *wq = container_of(ind_table->ind_tbl[i],
							  struct mana_wq, ibwq);
			struct mana_cq *cq =
				container_of(wq->ibwq.cq, struct mana_cq, ibcq);
			wq->wqid = cmd_resp->entries[i].wqid;
			cq->cqid = cmd_resp->entries[i].cqid;
		}
	}

	return &qp->ibqp.qp;
}

struct ibv_qp *mana_create_qp_ex(struct ibv_context *context,
				 struct ibv_qp_init_attr_ex *attr)
{
	switch (attr->qp_type) {
	case IBV_QPT_RAW_PACKET:
		return mana_create_qp_ex_raw(context, attr);
	default:
		verbs_err(verbs_get_ctx(context),
			  "QP type %u is not supported\n", attr->qp_type);
		errno = EINVAL;
	}

	return NULL;
}
