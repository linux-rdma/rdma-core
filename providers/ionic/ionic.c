// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>

#include "ionic.h"

extern const struct verbs_context_ops ionic_ctx_ops;
struct ionic_global ionic_g;
FILE *IONIC_DEBUG_FILE;

static int ionic_env_val_def(const char *name, int def)
{
	const char *env = getenv(name);

	if (!env)
		return def;

	return atoi(env);
}

static int ionic_env_val(const char *name)
{
	return ionic_env_val_def(name, 0);
}

static int ionic_env_ovrd_cmb(const char *name)
{
	const char *env = getenv(name);
	int val;

	if (!env)
		return -1;

	/* flags can be represented as one number or as characters */
	val = atoi(env);
	if (strchr(env, 'e'))
		val |= IONIC_CMB_ENABLE;
	if (strchr(env, 'x'))
		val |= IONIC_CMB_ENABLE | IONIC_CMB_EXPDB;
	if (strchr(env, 'r'))
		val |= IONIC_CMB_REQUIRE;
	if (strchr(env, 'w'))
		val |= IONIC_CMB_WC;
	if (strchr(env, 'u'))
		val |= IONIC_CMB_UC;

	return val;
}

static int ionic_env_ovrd_sq_cmb(void)
{
	return ionic_env_ovrd_cmb("IONIC_SQ_CMB");
}

static int ionic_env_ovrd_rq_cmb(void)
{
	return ionic_env_ovrd_cmb("IONIC_RQ_CMB");
}

static int ionic_env_debug(void)
{
	if (!(IONIC_DEBUG))
		return 0;

	return ionic_env_val("IONIC_DEBUG");
}

static void ionic_debug_file_close(void)
{
	fclose(IONIC_DEBUG_FILE);
}

static void ionic_debug_file_open(void)
{
	const char *name = getenv("IONIC_DEBUG_FILE");

	pthread_mutex_init(&ionic_g.mut, NULL);
	list_head_init(&ionic_g.cq_list);
	list_head_init(&ionic_g.qp_list);
	ionic_g.init = true;

	if (!name)
		IONIC_DEBUG_FILE = IONIC_DEFAULT_DEBUG_FILE;
	else
		IONIC_DEBUG_FILE = fopen(name, "w");

	if (!IONIC_DEBUG_FILE) {
		perror("ionic debug file: ");
		return;
	}

	if (ionic_env_debug())
		_ionic_dbg(IONIC_DEBUG_FILE, "Initialized");

	atexit(ionic_debug_file_close);
}

static void ionic_debug_file_init(void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once(&once, ionic_debug_file_open);
}

static struct verbs_context *ionic_alloc_context(struct ibv_device *ibdev,
						 int cmd_fd,
						 void *private_data)
{
	struct ionic_dev *dev;
	struct ionic_ctx *ctx;
	struct uionic_ctx req = {};
	struct uionic_ctx_resp resp = {};
	uint64_t mask;
	int rc;

	ionic_debug_file_init();

	dev = to_ionic_dev(ibdev);
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
		fprintf(stderr, "ionic: Firmware RDMA Version %u\n",
			resp.version);
		fprintf(stderr, "ionic: Driver Min RDMA Version %u\n",
			IONIC_MIN_RDMA_VERSION);
		rc = EINVAL;
		goto err_cmd;
	}

	if (resp.version > IONIC_MAX_RDMA_VERSION) {
		fprintf(stderr, "ionic: Firmware RDMA Version %u\n",
			resp.version);
		fprintf(stderr, "ionic: Driver Max RDMA Version %u\n",
			IONIC_MAX_RDMA_VERSION);
		rc = EINVAL;
		goto err_cmd;
	}

	ctx->version = resp.version;
	ctx->opcodes = resp.qp_opcodes;
	if (ctx->version == 1 && ctx->opcodes <= IONIC_V1_OP_BIND_MW) {
		fprintf(stderr, "ionic: qp opcodes %d want min %d\n",
			ctx->opcodes, IONIC_V1_OP_BIND_MW + 1);
		rc = EINVAL;
		goto err_cmd;
	}

	if (resp.udma_count != 1 && resp.udma_count != 2) {
		fprintf(stderr, "ionic: udma_count %d invalid\n",
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

	ctx->ovrd_sq_cmb = ionic_env_ovrd_sq_cmb();
	ctx->ovrd_rq_cmb = ionic_env_ovrd_rq_cmb();

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

	verbs_set_ops(&ctx->vctx, &ionic_ctx_ops);

	if (dev->abi_ver <= 1) {
		ctx->spec = 0;
	} else {
		ctx->spec = resp.max_spec;
		if (ctx->spec < 0 || ctx->spec > 16)
			ctx->spec = 0;
	}

	if (ionic_env_debug()) {
		ctx->dbg_file = IONIC_DEBUG_FILE;
		ionic_dbg(ctx, "Attached to ctx %p", ctx);
	}

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
