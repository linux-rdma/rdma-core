// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2024, Microsoft Corporation. All rights reserved.
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

DECLARE_DRV_CMD(mana_create_cq, IB_USER_VERBS_CMD_CREATE_CQ, mana_ib_create_cq,
		empty);

struct ibv_cq *mana_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel, int comp_vector)
{
	struct mana_context *ctx = to_mctx(context);
	struct mana_cq *cq;
	struct mana_create_cq cmd = {};
	struct mana_create_cq_resp resp = {};
	struct mana_ib_create_cq *cmd_drv;
	int cq_size;
	int ret;

	if (!ctx->extern_alloc.alloc || !ctx->extern_alloc.free) {
		/*
		 * This version of driver doesn't support allocating buffers
		 * in rdma-core.
		 */
		verbs_err(verbs_get_ctx(context),
			  "Allocating core buffers for CQ is not supported\n");
		errno = EINVAL;
		return NULL;
	}

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	cq_size = cqe * COMP_ENTRY_SIZE;
	cq_size = roundup_pow_of_two(cq_size);
	cq_size = align(cq_size, MANA_PAGE_SIZE);

	cq->buf = ctx->extern_alloc.alloc(cq_size, ctx->extern_alloc.data);
	if (!cq->buf) {
		errno = ENOMEM;
		goto free_cq;
	}
	cq->cqe = cqe;

	cmd_drv = &cmd.drv_payload;
	cmd_drv->buf_addr = (uintptr_t)cq->buf;

	ret = ibv_cmd_create_cq(context, cq->cqe, channel, comp_vector,
				&cq->ibcq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));

	if (ret) {
		verbs_err(verbs_get_ctx(context), "Failed to Create CQ\n");
		ctx->extern_alloc.free(cq->buf, ctx->extern_alloc.data);
		errno = ret;
		goto free_cq;
	}

	return &cq->ibcq;

free_cq:
	free(cq);
	return NULL;
}

int mana_destroy_cq(struct ibv_cq *ibcq)
{
	int ret;
	struct mana_cq *cq = container_of(ibcq, struct mana_cq, ibcq);
	struct mana_context *ctx = to_mctx(ibcq->context);

	if (!ctx->extern_alloc.free) {
		/*
		 * This version of driver doesn't support allocating buffers
		 * in rdma-core. It's not possible to reach the code here.
		 */
		verbs_err(verbs_get_ctx(ibcq->context),
			  "Invalid external context in destroy CQ\n");
		return -EINVAL;
	}

	ret = ibv_cmd_destroy_cq(ibcq);
	if (ret) {
		verbs_err(verbs_get_ctx(ibcq->context),
			  "Failed to Destroy CQ\n");
		return ret;
	}

	ctx->extern_alloc.free(cq->buf, ctx->extern_alloc.data);
	free(cq);

	return ret;
}

int mana_poll_cq(struct ibv_cq *ibcq, int nwc, struct ibv_wc *wc)
{
	/* This version of driver supports RAW QP only.
	 * Polling CQ is done directly in the application.
	 */
	return EOPNOTSUPP;
}
