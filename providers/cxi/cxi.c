// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2025 HPE. All rights reserved.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>

#include <infiniband/driver.h>
#include <kernel-abi/cxiverbs-abi.h>
#include <rdma/cxiverbs-abi.h>
#include "cxiverbs-abi.h"
#include "cxi_verbs.h"
#include "cxi.h"

static const struct verbs_match_ent cxi_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_CXI),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_CRAY, PCI_DEVICE_ID_CASSINI_1, NULL),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_HPE, PCI_DEVICE_ID_CASSINI_1, NULL),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_HPE, PCI_DEVICE_ID_CASSINI_2, NULL),
	{}
};

static int cxi_query_qp_semantics(struct ibv_context *context, enum ibv_qp_type type, uint32_t port,
				  uint8_t sgid_index, struct ibv_qp_semantics *sem, size_t size)
{
	if (port != 1 || sgid_index)
		return EINVAL;
	return ibv_cmd_query_qp_semantics(context, type, sem, size);
}

static const struct verbs_context_ops cxi_ctx_ops = {
	.query_qp_semantics = cxi_query_qp_semantics,
	.query_device_ex = cxi_query_device,
	.query_port = cxi_query_port,
	.alloc_pd = cxi_alloc_pd,
	.dealloc_pd = cxi_dealloc_pd,
	.alloc_job = cxi_alloc_job,
	.dealloc_job = cxi_dealloc_job,
	.query_job = cxi_query_job,
	.insert_addr = cxi_insert_addr,
	.remove_addr = cxi_remove_addr,
	.query_addr = cxi_query_addr,
	.export_job = cxi_export_job,
	.import_job = cxi_import_job,
	.create_jkey = cxi_create_jkey,
	.destroy_jkey = cxi_destroy_jkey,
	.reg_mr = cxi_reg_mr,
	.reg_mr_ex = cxi_reg_mr_ex,
	.dereg_mr = cxi_dereg_mr,
	.create_cq = cxi_create_cq,
	.create_cq_ex = cxi_create_cq_ex,
	.destroy_cq = cxi_destroy_cq,
	.create_counters = cxi_create_counters,
	.destroy_counters = cxi_destroy_counters,
	.read_counters_ex = cxi_read_counters_ex,
	.poll_cq = cxi_poll_cq,
	.req_notify_cq = cxi_arm_cq,
	.create_qp_ex = cxi_create_qp_ex,
	.modify_qp = cxi_modify_qp,
	.query_qp = cxi_query_qp,
	.destroy_qp = cxi_destroy_qp,
	.post_send = cxi_post_send,
	.post_recv = cxi_post_recv,
	.post_recv64 = cxi_post_recv64,
	.attach_mr = cxi_attach_mr,
	.detach_mr = cxi_detach_mr,
	.create_ah = cxi_create_ah,
	.create_ah_ex = cxi_create_ah_ex,
	.destroy_ah = cxi_destroy_ah,
	.free_context = cxi_free_context,
};

static struct verbs_context *cxi_alloc_context(struct ibv_device *vdev, int cmd_fd,
					       void *private_data)
{
	struct cxi_alloc_ucontext_resp resp = {};
	struct cxi_alloc_ucontext cmd = {};
	struct cxi_context *ctx;
	int ret;

	ctx = verbs_init_and_alloc_context(vdev, cmd_fd, ctx, verbs_ctx, RDMA_DRIVER_CXI);
	if (!ctx)
		return NULL;
	atomic_init(&ctx->send_cookie_seq, 0);

	ret = ibv_cmd_get_context(&ctx->verbs_ctx, &cmd.ibv_cmd, sizeof(cmd), NULL, &resp.ibv_resp,
				  sizeof(resp));
	if (ret) {
		verbs_err(&ctx->verbs_ctx, "ibv_cmd_get_context failed: %s\n", strerror(ret));
		goto err_free_ctx;
	}

	ctx->nid = resp.nid;
	ctx->pid_bits = resp.pid_bits;

	{
		struct cxi_query_device_ex_resp qresp = {};
		struct ibv_device_attr_ex attr = {};
		size_t qresp_size = sizeof(qresp);

		/*
		 * Best-effort: fetch device-wide HW properties (nid,
		 * pid_bits, pid_count, pid_granule, ...) via the driver's
		 * query_device response. This is the only source for them
		 * on the RDMA path (no ioctl/sysfs channel exists there);
		 * see cxi_ibv_devinfo in kernel-headers/rdma/cxiverbs-abi.h.
		 * Failure here is not fatal to context alloc: it only means
		 * cxidv_query_device() will report EOPNOTSUPP later.
		 */
		ret = ibv_cmd_query_device_any(&ctx->verbs_ctx.context, NULL, &attr, sizeof(attr),
					       &qresp.ibv_resp, &qresp_size);
		if (!ret)
			ctx->devinfo = qresp.devinfo;
	}

	ret = pthread_mutex_init(&ctx->tc_lock, NULL);
	if (ret)
		goto err_free_ctx;
	ret = pthread_spin_init(&ctx->qp_table_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret)
		goto err_destroy_tc_lock;
	ret = pthread_spin_init(&ctx->mr_list_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret)
		goto err_free_spinlock;

	verbs_set_ops(&ctx->verbs_ctx, &cxi_ctx_ops);

	return &ctx->verbs_ctx;

err_free_spinlock:
	pthread_spin_destroy(&ctx->qp_table_lock);
err_destroy_tc_lock:
	pthread_mutex_destroy(&ctx->tc_lock);
err_free_ctx:
	verbs_uninit_context(&ctx->verbs_ctx);
	free(ctx);
	errno = ret;
	return NULL;
}

void cxi_free_context(struct ibv_context *ibvctx)
{
	struct cxi_context *ctx = to_cxi_ctx(ibvctx);

	pthread_spin_destroy(&ctx->mr_list_lock);
	pthread_spin_destroy(&ctx->qp_table_lock);
	pthread_mutex_destroy(&ctx->tc_lock);
	verbs_uninit_context(&ctx->verbs_ctx);
	free(ctx);
}

static struct verbs_device *cxi_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct cxi_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->page_size = sysconf(_SC_PAGESIZE);

	return &dev->verbs_dev;
}

static void cxi_uninit_device(struct verbs_device *verbs_device)
{
	struct cxi_device *dev = to_cxi_dev(&verbs_device->device);

	free(dev);
}

static const struct verbs_device_ops cxi_dev_ops = {
	.name = "cxiverbs",
	.match_min_abi_version = CXI_IB_UVERBS_ABI_VERSION,
	.match_max_abi_version = CXI_IB_UVERBS_ABI_VERSION,
	.match_table = cxi_table,
	.alloc_device = cxi_device_alloc,
	.uninit_device = cxi_uninit_device,
	.alloc_context = cxi_alloc_context,
};

bool is_cxi_dev(struct ibv_device *device)
{
	struct verbs_device *verbs_device = verbs_get_device(device);

	return verbs_device->ops == &cxi_dev_ops;
}

PROVIDER_DRIVER(cxiverbs, cxi_dev_ops);
