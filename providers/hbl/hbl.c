// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "hbl.h"
#include "hbldv.h"
#include "verbs.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static struct hbl_context *hbl_ctx;

static const struct verbs_match_ent hbl_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_HBL),
	VERBS_NAME_MATCH("hbl", NULL),
	{}
};

static void hbl_free_context(struct ibv_context *ibctx);
static int hbl_query_device_ex(struct ibv_context *context,
			       const struct ibv_query_device_ex_input *input,
			       struct ibv_device_attr_ex *attr, size_t attr_size);
static int hbl_query_port(struct ibv_context *ibctx, uint8_t port,
			  struct ibv_port_attr *port_attr);

static const struct verbs_context_ops hbl_ctx_ops = {
	.alloc_pd = hbl_alloc_pd,
	.dealloc_pd = hbl_dealloc_pd,
	.free_context = hbl_free_context,
	.query_device_ex = hbl_query_device_ex,
	.query_port = hbl_query_port,
	.create_qp = hbl_create_qp,
	.create_qp_ex = hbl_create_qp_ex,
	.destroy_qp = hbl_destroy_qp,
	.modify_qp = hbl_modify_qp,
	.create_cq = hbl_create_cq,
	.destroy_cq = hbl_destroy_cq,
	.query_qp = hbl_query_qp,
	.async_event = hbl_async_event,
};

static int hbl_query_port(struct ibv_context *ibctx, uint8_t port,
			  struct ibv_port_attr *port_attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(ibctx, port, port_attr, &cmd, sizeof(cmd));
}

static struct verbs_context *hbl_alloc_context(struct ibv_device *ibdev, int cmd_fd,
					       void *private_data)
{
	struct hbldv_ucontext_attr *attr = private_data;
	struct hbl_alloc_ucontext_resp resp = {};
	struct hbl_alloc_ucontext cmd = {};
	struct verbs_context *vctx;
	struct hbl_context *ctx;
	int rc, core_fd = 0;

	/* Only one customized context is allowed, i.e. DV context with non default value.
	 * For subsequent allocations of default contexts (DV context with default value or non DV
	 * context), return the same context and increment ref count.
	 */
	if (hbl_ctx && hbl_ctx->is_default_ctx && !attr) {
		__sync_fetch_and_add(&hbl_ctx->ref_cnt, 1);
		return &hbl_ctx->ibv_ctx;
	}

	ctx = verbs_init_and_alloc_context(ibdev, cmd_fd, ctx, ibv_ctx, RDMA_DRIVER_HBL);
	if (!ctx)
		return NULL;

	vctx = &ctx->ibv_ctx;

	if (attr) {
		cmd.ports_mask = attr->ports_mask;
		cmd.core_fd = attr->core_fd;
		cmd.use_dvs = true;

		ctx->core_fd = INT_MAX;
	} else {
		int core_dev_idx;
		char path[NAME_MAX] = {};

		if (sscanf(ibdev->name, "hbl_%d", &core_dev_idx) != 1) {
			verbs_err(vctx, "failed to get core device index from %s\n", ibdev->name);
			goto uninit_ctx;
		}

		snprintf(path, NAME_MAX, "/dev/accel/accel%d", core_dev_idx);

		core_fd = open(path, O_RDWR | O_CLOEXEC, 0);
		if (core_fd < 0) {
			rc = errno;
			verbs_err(vctx, "failed to open core FD, err %d\n", rc);
			goto uninit_ctx;
		}

		cmd.core_fd = core_fd;
		cmd.ports_mask = 0;

		ctx->core_fd = core_fd;
		ctx->is_default_ctx = true;
	}

	rc = ibv_cmd_get_context(vctx, &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (rc) {
		verbs_err(vctx, "get_context failed, rc %d\n", rc);
		goto close_core_fd;
	}

	ctx->ports_mask = resp.ports_mask;
	ctx->cap_mask = resp.cap_mask;

	verbs_set_ops(vctx, &hbl_ctx_ops);

	verbs_debug(vctx, "Allocated an IB context, ports mask 0x%lx\n", ctx->ports_mask);

	ctx->ref_cnt = 1;
	hbl_ctx = ctx;

	return vctx;

close_core_fd:
	if (!attr)
		close(core_fd);
uninit_ctx:
	verbs_uninit_context(&ctx->ibv_ctx);
	free(ctx);
	return NULL;
}

static void hbl_free_context(struct ibv_context *ibctx)
{
	struct hbl_context *context = to_hbl_ctx(ibctx);

	if (__sync_sub_and_fetch(&context->ref_cnt, 1))
		return;

	verbs_uninit_context(&context->ibv_ctx);

	if (context->core_fd != INT_MAX)
		close(context->core_fd);

	verbs_debug(verbs_get_ctx(ibctx), "IB context was freed\n");

	free(context);
	hbl_ctx = NULL;
}

int hbl_query_device_ex(struct ibv_context *context, const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct verbs_context *vctx = verbs_get_ctx(context);
	int err;

	err = ibv_cmd_query_device_any(context, input, attr, attr_size, NULL, NULL);
	if (err) {
		verbs_err(vctx, "ibv_cmd_query_device_any failed\n");
		return err;
	}

	verbs_debug(vctx, "Queried device\n");

	return 0;
}

static struct verbs_device *hbl_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct hbl_dev *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->vdev;
}

static void hbl_uninit_device(struct verbs_device *verbs_device)
{
	struct hbl_dev *dev = to_hbl_dev(&verbs_device->device);

	free(dev);
}

static const struct verbs_device_ops hbl_dev_ops = {
	.name = "hbl",
	.match_min_abi_version = HBL_IB_ABI_VERSION,
	.match_max_abi_version = HBL_IB_ABI_VERSION,
	.match_table = hbl_table,
	.alloc_device = hbl_device_alloc,
	.uninit_device = hbl_uninit_device,
	.alloc_context = hbl_alloc_context,
};

bool is_hbl_dev(struct ibv_device *device)
{
	struct verbs_device *verbs_device = verbs_get_device(device);

	return verbs_device->ops == &hbl_dev_ops;
}

struct ibv_context *hbldv_open_device(struct ibv_device *device, struct hbldv_ucontext_attr *attr)
{
	if (!is_hbl_dev(device)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return verbs_open_device(device, attr);
}

bool hbldv_is_supported(struct ibv_device *device)
{
	return is_hbl_dev(device);
}

PROVIDER_DRIVER(hbl, hbl_dev_ops);
