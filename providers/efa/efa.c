// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <util/util.h>

#include "efa.h"
#include "verbs.h"

static void efa_free_context(struct ibv_context *ibvctx);

#define PCI_VENDOR_ID_AMAZON 0x1d0f

static const struct verbs_match_ent efa_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_EFA),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_AMAZON, 0xefa0, NULL),
	{}
};

static const struct verbs_context_ops efa_ctx_ops = {
	.alloc_pd = efa_alloc_pd,
	.create_ah = efa_create_ah,
	.create_cq = efa_create_cq,
	.create_qp = efa_create_qp,
	.create_qp_ex = efa_create_qp_ex,
	.dealloc_pd = efa_dealloc_pd,
	.dereg_mr = efa_dereg_mr,
	.destroy_ah = efa_destroy_ah,
	.destroy_cq = efa_destroy_cq,
	.destroy_qp = efa_destroy_qp,
	.modify_qp = efa_modify_qp,
	.poll_cq = efa_poll_cq,
	.post_recv = efa_post_recv,
	.post_send = efa_post_send,
	.query_device = efa_query_device,
	.query_device_ex = efa_query_device_ex,
	.query_port = efa_query_port,
	.query_qp = efa_query_qp,
	.reg_mr = efa_reg_mr,
	.free_context = efa_free_context,
};

static struct verbs_context *efa_alloc_context(struct ibv_device *vdev,
					       int cmd_fd,
					       void *private_data)
{
	struct efa_alloc_ucontext_resp resp = {};
	struct ibv_device_attr_ex attr;
	struct ibv_get_context cmd;
	unsigned int qp_table_sz;
	struct efa_context *ctx;
	int err;

	ctx = verbs_init_and_alloc_context(vdev, cmd_fd, ctx, ibvctx,
					   RDMA_DRIVER_EFA);
	if (!ctx)
		return NULL;

	if (ibv_cmd_get_context(&ctx->ibvctx, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp)))
		goto err_free_ctx;

	ctx->sub_cqs_per_cq = resp.sub_cqs_per_cq;
	ctx->cmds_supp_udata_mask = resp.cmds_supp_udata_mask;
	ctx->cqe_size = sizeof(struct efa_io_rx_cdesc);
	ctx->inline_buf_size = resp.inline_buf_size;
	ctx->max_llq_size = resp.max_llq_size;
	pthread_spin_init(&ctx->qp_table_lock, PTHREAD_PROCESS_PRIVATE);

	verbs_set_ops(&ctx->ibvctx, &efa_ctx_ops);

	err = efa_query_device_ex(&ctx->ibvctx.context, NULL, &attr,
				  sizeof(attr));
	if (err)
		goto err_free_spinlock;

	qp_table_sz = roundup_pow_of_two(attr.orig_attr.max_qp);
	ctx->qp_table_sz_m1 = qp_table_sz - 1;
	ctx->qp_table = calloc(qp_table_sz, sizeof(*ctx->qp_table));
	if (!ctx->qp_table)
		goto err_free_spinlock;

	return &ctx->ibvctx;

err_free_spinlock:
	pthread_spin_destroy(&ctx->qp_table_lock);
err_free_ctx:
	verbs_uninit_context(&ctx->ibvctx);
	free(ctx);
	return NULL;
}

static void efa_free_context(struct ibv_context *ibvctx)
{
	struct efa_context *ctx = to_efa_context(ibvctx);

	free(ctx->qp_table);
	pthread_spin_destroy(&ctx->qp_table_lock);
	verbs_uninit_context(&ctx->ibvctx);
	free(ctx);
}

static struct verbs_device *efa_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct efa_dev *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->pg_sz = sysconf(_SC_PAGESIZE);

	return &dev->vdev;
}

static void efa_uninit_device(struct verbs_device *verbs_device)
{
	struct efa_dev *dev = to_efa_dev(&verbs_device->device);

	free(dev);
}

static const struct verbs_device_ops efa_dev_ops = {
	.name = "efa",
	.match_min_abi_version = EFA_ABI_VERSION,
	.match_max_abi_version = EFA_ABI_VERSION,
	.match_table = efa_table,
	.alloc_device = efa_device_alloc,
	.uninit_device = efa_uninit_device,
	.alloc_context = efa_alloc_context,
};

bool is_efa_dev(struct ibv_device *device)
{
	struct verbs_device *verbs_device = verbs_get_device(device);

	return verbs_device->ops == &efa_dev_ops;
}
PROVIDER_DRIVER(efa, efa_dev_ops);
