// SPDX-License-Identifier: GPL-2.0 or OpenIB.org BSD (MIT) See COPYING file

// Authors: Cheng Xu <chengyou@linux.alibaba.com>
// Copyright (c) 2020-2021, Alibaba Group.

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <util/mmio.h>
#include <util/udma_barrier.h>
#include <util/util.h>

#include "erdma.h"
#include "erdma_abi.h"
#include "erdma_hw.h"
#include "erdma_verbs.h"

static const struct verbs_context_ops erdma_context_ops = {
	.alloc_pd = erdma_alloc_pd,
	.cq_event = erdma_cq_event,
	.create_cq = erdma_create_cq,
	.create_qp = erdma_create_qp,
	.dealloc_pd = erdma_free_pd,
	.dereg_mr = erdma_dereg_mr,
	.destroy_cq = erdma_destroy_cq,
	.destroy_qp = erdma_destroy_qp,
	.free_context = erdma_free_context,
	.modify_qp = erdma_modify_qp,
	.poll_cq = erdma_poll_cq,
	.post_recv = erdma_post_recv,
	.post_send = erdma_post_send,
	.query_device_ex = erdma_query_device,
	.query_port = erdma_query_port,
	.query_qp = erdma_query_qp,
	.reg_mr = erdma_reg_mr,
	.req_notify_cq = erdma_notify_cq,
};

static struct verbs_context *erdma_alloc_context(struct ibv_device *device,
						 int cmd_fd, void *private_data)
{
	struct erdma_cmd_alloc_context_resp resp = {};
	struct ibv_get_context cmd = {};
	struct erdma_context *ctx;
	int i;

	ctx = verbs_init_and_alloc_context(device, cmd_fd, ctx, ibv_ctx,
					   RDMA_DRIVER_ERDMA);
	if (!ctx)
		return NULL;

	pthread_mutex_init(&ctx->qp_table_mutex, NULL);
	for (i = 0; i < ERDMA_QP_TABLE_SIZE; ++i)
		ctx->qp_table[i].refcnt = 0;

	if (ibv_cmd_get_context(&ctx->ibv_ctx, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp)))
		goto err_out;

	verbs_set_ops(&ctx->ibv_ctx, &erdma_context_ops);
	ctx->dev_id = resp.dev_id;

	ctx->sdb_type = resp.sdb_type;
	ctx->sdb_offset = resp.sdb_offset;

	ctx->sdb = mmap(NULL, ERDMA_PAGE_SIZE, PROT_WRITE, MAP_SHARED, cmd_fd,
			resp.sdb);
	if (ctx->sdb == MAP_FAILED)
		goto err_out;

	ctx->rdb = mmap(NULL, ERDMA_PAGE_SIZE, PROT_WRITE, MAP_SHARED, cmd_fd,
			resp.rdb);
	if (ctx->rdb == MAP_FAILED)
		goto err_rdb_map;

	ctx->cdb = mmap(NULL, ERDMA_PAGE_SIZE, PROT_WRITE, MAP_SHARED, cmd_fd,
			resp.cdb);
	if (ctx->cdb == MAP_FAILED)
		goto err_cdb_map;

	ctx->page_size = ERDMA_PAGE_SIZE;
	list_head_init(&ctx->dbrecord_pages_list);
	pthread_mutex_init(&ctx->dbrecord_pages_mutex, NULL);

	return &ctx->ibv_ctx;

err_cdb_map:
	munmap(ctx->rdb, ERDMA_PAGE_SIZE);
err_rdb_map:
	munmap(ctx->sdb, ERDMA_PAGE_SIZE);
err_out:
	verbs_uninit_context(&ctx->ibv_ctx);
	free(ctx);

	return NULL;
}

static struct verbs_device *
erdma_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct erdma_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->ibv_dev;
}

static void erdma_device_free(struct verbs_device *vdev)
{
	struct erdma_device *dev =
		container_of(vdev, struct erdma_device, ibv_dev);

	free(dev);
}

static const struct verbs_match_ent match_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_ERDMA),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_ALIBABA, 0x107f, NULL),
	{},
};

static const struct verbs_device_ops erdma_dev_ops = {
	.name = "erdma",
	.match_min_abi_version = 0,
	.match_max_abi_version = ERDMA_ABI_VERSION,
	.match_table = match_table,
	.alloc_device = erdma_device_alloc,
	.uninit_device = erdma_device_free,
	.alloc_context = erdma_alloc_context,
};

PROVIDER_DRIVER(erdma, erdma_dev_ops);
