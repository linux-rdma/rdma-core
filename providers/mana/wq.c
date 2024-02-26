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

DECLARE_DRV_CMD(mana_create_wq, IB_USER_VERBS_EX_CMD_CREATE_WQ,
		mana_ib_create_wq, empty);

DECLARE_DRV_CMD(mana_create_rwq_ind_table,
		IB_USER_VERBS_EX_CMD_CREATE_RWQ_IND_TBL, empty, empty);

int mana_modify_wq(struct ibv_wq *ibwq, struct ibv_wq_attr *attr)
{
	return EOPNOTSUPP;
}

struct ibv_wq *mana_create_wq(struct ibv_context *context,
			      struct ibv_wq_init_attr *attr)
{
	int ret;
	struct mana_context *ctx = to_mctx(context);
	struct mana_wq *wq;
	struct mana_create_wq wq_cmd = {};
	struct mana_create_wq_resp wq_resp = {};
	struct mana_ib_create_wq *wq_cmd_drv;

	if (!ctx->extern_alloc.alloc || !ctx->extern_alloc.free) {
		verbs_err(verbs_get_ctx(context),
			  "WQ buffer needs to be externally allocated\n");
		errno = EINVAL;
		return NULL;
	}

	wq = calloc(1, sizeof(*wq));
	if (!wq)
		return NULL;

	wq->sge = attr->max_sge;
	wq->buf_size = attr->max_wr * get_wqe_size(attr->max_sge);
	wq->buf_size = align_hw_size(wq->buf_size);
	wq->buf = ctx->extern_alloc.alloc(wq->buf_size, ctx->extern_alloc.data);

	if (!wq->buf) {
		errno = ENOMEM;
		goto free_wq;
	}

	wq->wqe = attr->max_wr;

	wq_cmd_drv = &wq_cmd.drv_payload;
	wq_cmd_drv->wq_buf_addr = (uintptr_t)wq->buf;
	wq_cmd_drv->wq_buf_size = wq->buf_size;

	ret = ibv_cmd_create_wq(context, attr, &wq->ibwq, &wq_cmd.ibv_cmd,
				sizeof(wq_cmd), &wq_resp.ibv_resp,
				sizeof(wq_resp));

	if (ret) {
		verbs_err(verbs_get_ctx(context), "Failed to Create WQ\n");
		ctx->extern_alloc.free(wq->buf, ctx->extern_alloc.data);
		errno = ret;
		goto free_wq;
	}

	return &wq->ibwq;

free_wq:
	free(wq);
	return NULL;
}

int mana_destroy_wq(struct ibv_wq *ibwq)
{
	struct mana_wq *wq = container_of(ibwq, struct mana_wq, ibwq);
	struct mana_context *ctx = to_mctx(ibwq->context);
	int ret;

	if (!ctx->extern_alloc.free) {
		verbs_err(verbs_get_ctx(ibwq->context),
			  "WQ needs external alloc context\n");
		return EINVAL;
	}

	ret = ibv_cmd_destroy_wq(ibwq);
	if (ret) {
		verbs_err(verbs_get_ctx(ibwq->context),
			  "Failed to destroy WQ\n");
		return ret;
	}

	ctx->extern_alloc.free(wq->buf, ctx->extern_alloc.data);
	free(wq);

	return 0;
}

struct ibv_rwq_ind_table *
mana_create_rwq_ind_table(struct ibv_context *context,
			  struct ibv_rwq_ind_table_init_attr *init_attr)
{
	int ret;
	struct mana_rwq_ind_table *ind_table;
	struct mana_create_rwq_ind_table_resp resp = {};
	int i;

	ind_table = calloc(1, sizeof(*ind_table));
	if (!ind_table)
		return NULL;

	ret = ibv_cmd_create_rwq_ind_table(context, init_attr,
					   &ind_table->ib_ind_table,
					   &resp.ibv_resp, sizeof(resp));
	if (ret) {
		verbs_err(verbs_get_ctx(context),
			  "Failed to create RWQ IND table\n");
		errno = ret;
		goto free_ind_table;
	}

	ind_table->ind_tbl_size = 1 << init_attr->log_ind_tbl_size;
	ind_table->ind_tbl =
		calloc(ind_table->ind_tbl_size, sizeof(struct ibv_wq *));
	if (!ind_table->ind_tbl) {
		errno = ENOMEM;
		goto free_ind_table;
	}
	for (i = 0; i < ind_table->ind_tbl_size; i++)
		ind_table->ind_tbl[i] = init_attr->ind_tbl[i];

	return &ind_table->ib_ind_table;

free_ind_table:
	free(ind_table);
	return NULL;
}

int mana_destroy_rwq_ind_table(struct ibv_rwq_ind_table *rwq_ind_table)
{
	struct mana_rwq_ind_table *ind_table = container_of(
		rwq_ind_table, struct mana_rwq_ind_table, ib_ind_table);

	int ret;

	ret = ibv_cmd_destroy_rwq_ind_table(&ind_table->ib_ind_table);
	if (ret) {
		verbs_err(verbs_get_ctx(rwq_ind_table->context),
			  "Failed to destroy RWQ IND table\n");
		goto fail;
	}

	free(ind_table->ind_tbl);
	free(ind_table);

fail:
	return ret;
}
