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

#define INITIALIZED_OWNER_BIT(log2_num_entries) (1UL << (log2_num_entries))

DECLARE_DRV_CMD(mana_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		mana_ib_create_cq, mana_ib_create_cq_resp);

struct ibv_cq *mana_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel, int comp_vector)
{
	struct mana_context *ctx = to_mctx(context);
	struct mana_create_cq_resp resp = {};
	struct mana_ib_create_cq *cmd_drv;
	struct mana_create_cq cmd = {};
	struct mana_cq *cq;
	uint16_t flags = 0;
	size_t cq_size;
	int ret;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	cq_size = align_hw_size(cqe * COMP_ENTRY_SIZE);
	cq->db_page = ctx->db_page;
	list_head_init(&cq->send_qp_list);
	list_head_init(&cq->recv_qp_list);
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	cq->buf_external = ctx->extern_alloc.alloc && ctx->extern_alloc.free;
	if (!cq->buf_external)
		flags |= MANA_IB_CREATE_RNIC_CQ;

	if (cq->buf_external)
		cq->buf = ctx->extern_alloc.alloc(cq_size, ctx->extern_alloc.data);
	else
		cq->buf = mana_alloc_mem(cq_size);
	if (!cq->buf) {
		errno = ENOMEM;
		goto free_cq;
	}

	if (flags & MANA_IB_CREATE_RNIC_CQ)
		cq->cqe = cq_size / COMP_ENTRY_SIZE;
	else
		cq->cqe = cqe; // to preserve old behaviour for DPDK
	cq->head = INITIALIZED_OWNER_BIT(ilog32(cq->cqe) - 1);
	cq->last_armed_head = cq->head - 1;
	cq->ready_wcs = 0;

	cmd_drv = &cmd.drv_payload;
	cmd_drv->buf_addr = (uintptr_t)cq->buf;
	cmd_drv->flags = flags;
	resp.cqid = UINT32_MAX;

	ret = ibv_cmd_create_cq(context, cq->cqe, channel, comp_vector,
				&cq->ibcq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));

	if (ret) {
		verbs_err(verbs_get_ctx(context), "Failed to Create CQ\n");
		errno = ret;
		goto free_mem;
	}

	if (flags & MANA_IB_CREATE_RNIC_CQ) {
		cq->cqid = resp.cqid;
		if (cq->cqid == UINT32_MAX) {
			errno = ENODEV;
			goto destroy_cq;
		}
	}

	return &cq->ibcq;

destroy_cq:
	ibv_cmd_destroy_cq(&cq->ibcq);
free_mem:
	if (cq->buf_external)
		ctx->extern_alloc.free(cq->buf, ctx->extern_alloc.data);
	else
		munmap(cq->buf, cq_size);
free_cq:
	free(cq);
	return NULL;
}

int mana_destroy_cq(struct ibv_cq *ibcq)
{
	struct mana_cq *cq = container_of(ibcq, struct mana_cq, ibcq);
	struct mana_context *ctx = to_mctx(ibcq->context);
	int ret;

	pthread_spin_lock(&cq->lock);
	ret = ibv_cmd_destroy_cq(ibcq);
	if (ret) {
		verbs_err(verbs_get_ctx(ibcq->context),
			  "Failed to Destroy CQ\n");
		pthread_spin_unlock(&cq->lock);
		return ret;
	}
	pthread_spin_destroy(&cq->lock);

	if (cq->buf_external)
		ctx->extern_alloc.free(cq->buf, ctx->extern_alloc.data);
	else
		munmap(cq->buf, cq->cqe * COMP_ENTRY_SIZE);

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
