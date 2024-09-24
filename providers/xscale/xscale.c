// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <sched.h>
#include <sys/param.h>

#include <util/mmio.h>
#include <util/symver.h>

#include "xscale.h"
#include "xsc-abi.h"
#include "xsc_hsi.h"

static const struct verbs_match_ent hca_table[] = {
	VERBS_MODALIAS_MATCH("*xscale*", NULL),
	{}
};

u32 xsc_debug_mask;
static void xsc_free_context(struct ibv_context *ibctx);

static const struct verbs_context_ops xsc_ctx_common_ops = {
	.query_port = xsc_query_port,
	.query_device_ex = xsc_query_device_ex,
	.free_context = xsc_free_context,

	.alloc_pd = xsc_alloc_pd,
	.dealloc_pd = xsc_free_pd,
	.reg_mr = xsc_reg_mr,
	.dereg_mr = xsc_dereg_mr,

	.create_cq = xsc_create_cq,
	.poll_cq = xsc_poll_cq,
	.req_notify_cq = xsc_arm_cq,
	.resize_cq = xsc_resize_cq,
	.destroy_cq = xsc_destroy_cq,

	.create_qp = xsc_create_qp,
	.query_qp = xsc_query_qp,
	.modify_qp = xsc_modify_qp,
	.destroy_qp = xsc_destroy_qp,

	.post_send = xsc_post_send,
	.post_recv = xsc_post_recv,
};

static void open_debug_file(struct xsc_context *ctx)
{
	char *env;

	env = getenv("XSC_DEBUG_FILE");
	if (!env) {
		ctx->dbg_fp = stderr;
		return;
	}

	ctx->dbg_fp = fopen(env, "aw+");
	if (!ctx->dbg_fp) {
		fprintf(stderr, "Failed opening debug file %s, using stderr\n",
			env);
		ctx->dbg_fp = stderr;
		return;
	}
}

static void close_debug_file(struct xsc_context *ctx)
{
	if (ctx->dbg_fp && ctx->dbg_fp != stderr)
		fclose(ctx->dbg_fp);
}

static void set_debug_mask(void)
{
	char *env;

	env = getenv("XSC_DEBUG_MASK");
	if (env)
		xsc_debug_mask = strtol(env, NULL, 0);
}

static int xsc_cmd_get_context(struct xsc_context *context,
			       struct xsc_alloc_ucontext *req, size_t req_len,
			       struct xsc_alloc_ucontext_resp *resp,
			       size_t resp_len)
{
	struct verbs_context *verbs_ctx = &context->ibv_ctx;

	return ibv_cmd_get_context(verbs_ctx, &req->ibv_cmd, req_len,
				   &resp->ibv_resp, resp_len);
}

static int xsc_mmap(struct xsc_device *xdev, struct xsc_context *context,
		    int cmd_fd, int size)
{
	u64 page_mask;

	page_mask = (~(xdev->page_size - 1));
	xsc_dbg(context->dbg_fp, XSC_DBG_CTX, "page size:%d\n", size);
	context->sqm_reg_va =
		mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cmd_fd,
		     context->qpm_tx_db & page_mask);
	if (context->sqm_reg_va == MAP_FAILED)
		return -1;

	xsc_dbg(context->dbg_fp, XSC_DBG_CTX, "qpm reg va:%p\n",
		context->sqm_reg_va);

	context->rqm_reg_va =
		mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cmd_fd,
		     context->qpm_rx_db & page_mask);
	if (context->rqm_reg_va == MAP_FAILED)
		goto free_sqm;

	xsc_dbg(context->dbg_fp, XSC_DBG_CTX, "qpm reg va:%p\n",
		context->rqm_reg_va);

	context->cqm_reg_va =
		mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cmd_fd,
		     context->cqm_next_cid_reg & page_mask);
	if (context->cqm_reg_va == MAP_FAILED)
		goto free_rqm;

	xsc_dbg(context->dbg_fp, XSC_DBG_CTX, "cqm ci va:%p\n",
		context->cqm_reg_va);
	context->db_mmap_size = size;

	context->cqm_armdb_va =
		mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cmd_fd,
		     context->cqm_armdb & page_mask);
	if (context->cqm_armdb_va == MAP_FAILED)
		goto free_cqm;
	xsc_dbg(context->dbg_fp, XSC_DBG_CTX, "cqm armdb va:%p\n",
		context->cqm_armdb_va);

	return 0;

free_cqm:
	munmap(context->cqm_reg_va, size);
free_rqm:
	munmap(context->rqm_reg_va, size);
free_sqm:
	munmap(context->sqm_reg_va, size);

	return -1;
}

static void xsc_munmap(struct xsc_context *context)
{
	if (context->sqm_reg_va)
		munmap(context->sqm_reg_va, context->db_mmap_size);

	if (context->rqm_reg_va)
		munmap(context->rqm_reg_va, context->db_mmap_size);

	if (context->cqm_reg_va)
		munmap(context->cqm_reg_va, context->db_mmap_size);

	if (context->cqm_armdb_va)
		munmap(context->cqm_armdb_va, context->db_mmap_size);
}

static struct verbs_context *xsc_alloc_context(struct ibv_device *ibdev,
					       int cmd_fd, void *private_data)
{
	struct xsc_context *context;
	struct xsc_alloc_ucontext req;
	struct xsc_alloc_ucontext_resp resp;
	int i;
	int page_size;
	struct xsc_device *xdev = to_xdev(ibdev);
	struct verbs_context *v_ctx;
	struct ibv_device_attr_ex device_attr;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_XSC);
	if (!context)
		return NULL;

	v_ctx = &context->ibv_ctx;
	page_size = xdev->page_size;

	open_debug_file(context);
	set_debug_mask();
	if (gethostname(context->hostname, sizeof(context->hostname)))
		strncpy(context->hostname, "host_unknown", NAME_BUFFER_SIZE - 1);

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	if (xsc_cmd_get_context(context, &req, sizeof(req), &resp,
				sizeof(resp)))
		goto err_free;

	context->max_num_qps = resp.qp_tab_size;
	context->max_sq_desc_sz = resp.max_sq_desc_sz;
	context->max_rq_desc_sz = resp.max_rq_desc_sz;
	context->max_send_wr = resp.max_send_wr;
	context->num_ports = resp.num_ports;
	context->max_recv_wr = resp.max_recv_wr;
	context->qpm_tx_db = resp.qpm_tx_db;
	context->qpm_rx_db = resp.qpm_rx_db;
	context->cqm_next_cid_reg = resp.cqm_next_cid_reg;
	context->cqm_armdb = resp.cqm_armdb;
	context->send_ds_num = resp.send_ds_num;
	context->send_ds_shift = xsc_ilog2(resp.send_ds_num);
	context->recv_ds_num = resp.recv_ds_num;
	context->recv_ds_shift = xsc_ilog2(resp.recv_ds_num);
	xsc_init_hw_ops(context);

	xsc_dbg(context->dbg_fp, XSC_DBG_CTX,
		"max_num_qps:%u, max_sq_desc_sz:%u max_rq_desc_sz:%u\n",
		context->max_num_qps, context->max_sq_desc_sz,
		context->max_rq_desc_sz);
	xsc_dbg(context->dbg_fp, XSC_DBG_CTX,
		"max_send_wr:%u, num_ports:%u, max_recv_wr:%u\n",
		context->max_send_wr,
		context->num_ports, context->max_recv_wr);
	xsc_dbg(context->dbg_fp, XSC_DBG_CTX,
		"send_ds_num:%u shift:%u recv_ds_num:%u shift:%u\n",
		context->send_ds_num, context->send_ds_shift,
		context->recv_ds_num, context->recv_ds_shift);

	pthread_mutex_init(&context->qp_table_mutex, NULL);
	for (i = 0; i < XSC_QP_TABLE_SIZE; ++i)
		context->qp_table[i].refcnt = 0;

	context->page_size = page_size;
	if (xsc_mmap(xdev, context, cmd_fd, page_size))
		goto err_free;

	verbs_set_ops(v_ctx, &xsc_ctx_common_ops);

	memset(&device_attr, 0, sizeof(device_attr));
	if (!xsc_query_device_ex(&v_ctx->context, NULL, &device_attr,
				 sizeof(struct ibv_device_attr_ex))) {
		context->max_cqe = device_attr.orig_attr.max_cqe;
	}

	return v_ctx;

err_free:
	verbs_uninit_context(&context->ibv_ctx);
	close_debug_file(context);
	free(context);
	return NULL;
}

static void xsc_free_context(struct ibv_context *ibctx)
{
	struct xsc_context *context = to_xctx(ibctx);

	xsc_dbg(context->dbg_fp, XSC_DBG_CTX, "\n");
	xsc_munmap(context);

	verbs_uninit_context(&context->ibv_ctx);
	close_debug_file(context);
	free(context);
}

static void xsc_uninit_device(struct verbs_device *verbs_device)
{
	struct xsc_device *xdev = to_xdev(&verbs_device->device);

	free(xdev);
}

static struct verbs_device *xsc_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct xsc_device *xdev;

	xdev = calloc(1, sizeof(*xdev));
	if (!xdev)
		return NULL;

	xdev->page_size = sysconf(_SC_PAGESIZE);

	return &xdev->verbs_dev;
}

static const struct verbs_device_ops xsc_dev_ops = {
	.name = "xscale",
	.match_min_abi_version = XSC_UVERBS_MIN_ABI_VERSION,
	.match_max_abi_version = XSC_UVERBS_MAX_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = xsc_device_alloc,
	.uninit_device = xsc_uninit_device,
	.alloc_context = xsc_alloc_context,
};

PROVIDER_DRIVER(xscale, xsc_dev_ops);
