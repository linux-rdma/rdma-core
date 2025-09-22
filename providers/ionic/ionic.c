// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>

#include "ionic.h"

static struct verbs_context *ionic_alloc_context(struct ibv_device *ibdev,
						 int cmd_fd,
						 void *private_data)
{
	struct ionic_ctx *ctx;
	struct uionic_ctx req = {};
	struct uionic_ctx_resp resp = {};
	uint64_t mask;
	int rc;

	ctx = verbs_init_and_alloc_context(ibdev, cmd_fd, ctx, vctx,
					   RDMA_DRIVER_IONIC);
	if (!ctx) {
		rc = errno;
		goto err_ctx;
	}

	rc = ibv_cmd_get_context(&ctx->vctx, &req.ibv_cmd, sizeof(req),
				 NULL, &resp.ibv_resp, sizeof(resp));
	if (rc)
		goto err_cmd;

	ctx->pg_shift = resp.page_shift;

	if (resp.version < IONIC_MIN_RDMA_VERSION) {
		verbs_err(&ctx->vctx, "ionic: Firmware RDMA Version %u\n",
			  resp.version);
		verbs_err(&ctx->vctx, "ionic: Driver Min RDMA Version %u\n",
			  IONIC_MIN_RDMA_VERSION);
		rc = EINVAL;
		goto err_cmd;
	}

	if (resp.version > IONIC_MAX_RDMA_VERSION) {
		verbs_err(&ctx->vctx, "ionic: Firmware RDMA Version %u\n",
			  resp.version);
		verbs_err(&ctx->vctx, "ionic: Driver Max RDMA Version %u\n",
			  IONIC_MAX_RDMA_VERSION);
		rc = EINVAL;
		goto err_cmd;
	}

	ctx->version = resp.version;
	ctx->opcodes = resp.qp_opcodes;
	if (ctx->version == 1 && ctx->opcodes <= IONIC_V1_OP_BIND_MW) {
		verbs_err(&ctx->vctx, "ionic: qp opcodes %d want min %d\n",
			  ctx->opcodes, IONIC_V1_OP_BIND_MW + 1);
		rc = EINVAL;
		goto err_cmd;
	}

	if (resp.udma_count != 1 && resp.udma_count != 2) {
		verbs_err(&ctx->vctx, "ionic: udma_count %d invalid\n",
			  resp.udma_count);
		rc = EINVAL;
		goto err_cmd;
	}
	ctx->udma_count = resp.udma_count;

	ctx->sq_qtype = resp.sq_qtype;
	ctx->rq_qtype = resp.rq_qtype;
	ctx->cq_qtype = resp.cq_qtype;

	ctx->max_stride = resp.max_stride;

	ctx->expdb_mask = resp.expdb_mask;
	ctx->sq_expdb = !!(resp.expdb_qtypes & IONIC_EXPDB_SQ);
	ctx->rq_expdb = !!(resp.expdb_qtypes & IONIC_EXPDB_RQ);

	mask = (1u << ctx->pg_shift) - 1;
	ctx->dbpage_page = ionic_map_device(1u << ctx->pg_shift, cmd_fd,
					    resp.dbell_offset & ~mask);
	if (!ctx->dbpage_page) {
		rc = errno;
		goto err_cmd;
	}
	ctx->dbpage = ctx->dbpage_page + (resp.dbell_offset & mask);

	pthread_mutex_init(&ctx->mut, NULL);
	ionic_tbl_init(&ctx->qp_tbl);

	ionic_verbs_set_ops(ctx);

	ctx->spec = resp.max_spec;
	if (ctx->spec < 0 || ctx->spec > 16)
		ctx->spec = 0;

	verbs_debug(&ctx->vctx, "Attached to ctx %p", ctx);
	return &ctx->vctx;

err_cmd:
	verbs_uninit_context(&ctx->vctx);
err_ctx:
	errno = rc;
	return NULL;
}

static const struct verbs_match_ent cna_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_IONIC),
	{}
};

static struct verbs_device *ionic_alloc_device(struct verbs_sysfs_dev *sdev)
{
	struct ionic_dev *dev;

	static_assert(sizeof(struct ionic_v1_cqe) == 32, "bad size");
	static_assert(sizeof(struct ionic_v1_base_hdr) == 16, "bad size");
	static_assert(sizeof(struct ionic_v1_recv_bdy) == 48, "bad size");
	static_assert(sizeof(struct ionic_v1_common_bdy) == 48, "bad size");
	static_assert(sizeof(struct ionic_v1_atomic_bdy) == 48, "bad size");
	static_assert(sizeof(struct ionic_v1_bind_mw_bdy) == 48, "bad size");
	static_assert(sizeof(struct ionic_v1_wqe) == 64, "bad size");

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->abi_ver = sdev->abi_ver;

	return &dev->vdev;
}

static void ionic_uninit_device(struct verbs_device *vdev)
{
	struct ionic_dev *dev = to_ionic_dev(&vdev->device);

	free(dev);
}

static const struct verbs_device_ops ionic_dev_ops = {
	.name			= "ionic",
	.match_min_abi_version	= IONIC_ABI_VERSION,
	.match_max_abi_version	= IONIC_ABI_VERSION,
	.match_table		= cna_table,
	.alloc_device		= ionic_alloc_device,
	.uninit_device		= ionic_uninit_device,
	.alloc_context		= ionic_alloc_context,
};

PROVIDER_DRIVER(ionic, ionic_dev_ops);
