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

DECLARE_DRV_CMD(mana_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT, empty,
		empty);

DECLARE_DRV_CMD(mana_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD, empty, empty);

static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_MANA),
	{},
};

struct mana_context *to_mctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct mana_context, ibv_ctx.context);
}

void *mana_alloc_mem(uint32_t size)
{
	void *buf;

	buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (buf == MAP_FAILED)
		return NULL;
	return buf;
}

int mana_query_device_ex(struct ibv_context *context,
			 const struct ibv_query_device_ex_input *input,
			 struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	int ret;

	ret = ibv_cmd_query_device_any(context, input, attr, attr_size, &resp,
				       &resp_size);

	verbs_debug(verbs_get_ctx(context),
		    "device attr max_qp %d max_qp_wr %d max_cqe %d\n",
		    attr->orig_attr.max_qp, attr->orig_attr.max_qp_wr,
		    attr->orig_attr.max_cqe);

	return ret;
}

int mana_query_port(struct ibv_context *context, uint8_t port,
		    struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

struct ibv_pd *mana_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct mana_alloc_pd_resp resp;
	struct mana_pd *pd;
	int ret;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	ret = ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd, sizeof(cmd),
			       &resp.ibv_resp, sizeof(resp));
	if (ret) {
		verbs_err(verbs_get_ctx(context), "Failed to allocate PD\n");
		errno = ret;
		free(pd);
		return NULL;
	}

	return &pd->ibv_pd;
}

struct ibv_pd *
mana_alloc_parent_domain(struct ibv_context *context,
			 struct ibv_parent_domain_init_attr *attr)
{
	struct mana_parent_domain *mparent_domain;

	if (ibv_check_alloc_parent_domain(attr)) {
		errno = EINVAL;
		return NULL;
	}

	if (!check_comp_mask(attr->comp_mask,
			     IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT)) {
		verbs_err(
			verbs_get_ctx(context),
			"This driver supports IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT only\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	mparent_domain = calloc(1, sizeof(*mparent_domain));
	if (!mparent_domain) {
		errno = ENOMEM;
		return NULL;
	}

	mparent_domain->mpd.mprotection_domain =
		container_of(attr->pd, struct mana_pd, ibv_pd);
	ibv_initialize_parent_domain(&mparent_domain->mpd.ibv_pd, attr->pd);

	if (attr->comp_mask & IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT)
		mparent_domain->pd_context = attr->pd_context;

	return &mparent_domain->mpd.ibv_pd;
}

int mana_dealloc_pd(struct ibv_pd *ibpd)
{
	int ret;
	struct mana_pd *pd = container_of(ibpd, struct mana_pd, ibv_pd);

	if (pd->mprotection_domain) {
		struct mana_parent_domain *parent_domain =
			container_of(pd, struct mana_parent_domain, mpd);

		free(parent_domain);
		return 0;
	}

	ret = ibv_cmd_dealloc_pd(ibpd);
	if (ret) {
		verbs_err(verbs_get_ctx(ibpd->context),
			  "Failed to deallocate PD\n");
		return ret;
	}

	free(pd);

	return 0;
}

struct ibv_mr *mana_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
				  size_t length, uint64_t iova, int fd,
				  int access)
{
	struct verbs_mr *vmr;
	int ret;

	vmr = calloc(1, sizeof(*vmr));
	if (!vmr)
		return NULL;

	ret = ibv_cmd_reg_dmabuf_mr(pd, offset, length, iova, fd, access, vmr, NULL);
	if (ret) {
		verbs_err(verbs_get_ctx(pd->context),
			  "Failed to register dma-buf MR\n");
		errno = ret;
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

struct ibv_mr *mana_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			   uint64_t hca_va, int access)
{
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;
	int ret;

	vmr = malloc(sizeof(*vmr));
	if (!vmr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		verbs_err(verbs_get_ctx(pd->context),
			  "Failed to register MR\n");
		errno = ret;
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

int mana_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret) {
		verbs_err(verbs_get_ctx(vmr->ibv_mr.context),
			  "Failed to deregister MR\n");
		return ret;
	}

	free(vmr);
	return 0;
}

static void mana_free_context(struct ibv_context *ibctx)
{
	struct mana_context *context = to_mctx(ibctx);
	int i;

	for (i = 0; i < MANA_QP_TABLE_SIZE; ++i) {
		if (context->qp_stable[i].refcnt)
			free(context->qp_stable[i].table);
		if (context->qp_rtable[i].refcnt)
			free(context->qp_rtable[i].table);
	}
	pthread_mutex_destroy(&context->qp_table_mutex);

	munmap(context->db_page, DOORBELL_PAGE_SIZE);
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void mana_async_event(struct ibv_context *context,
			     struct ibv_async_event *event)
{
	struct ibv_qp *ibvqp;

	switch (event->event_type) {
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_PATH_MIG_ERR:
		ibvqp = event->element.qp;
		mana_qp_move_flush_err(ibvqp);
		break;
	default:
		break;
	}
}

static const struct verbs_context_ops mana_ctx_ops = {
	.alloc_pd = mana_alloc_pd,
	.async_event = mana_async_event,
	.alloc_parent_domain = mana_alloc_parent_domain,
	.create_cq = mana_create_cq,
	.create_qp = mana_create_qp,
	.create_qp_ex = mana_create_qp_ex,
	.create_rwq_ind_table = mana_create_rwq_ind_table,
	.create_wq = mana_create_wq,
	.dealloc_pd = mana_dealloc_pd,
	.dereg_mr = mana_dereg_mr,
	.destroy_cq = mana_destroy_cq,
	.destroy_qp = mana_destroy_qp,
	.destroy_rwq_ind_table = mana_destroy_rwq_ind_table,
	.destroy_wq = mana_destroy_wq,
	.free_context = mana_free_context,
	.modify_wq = mana_modify_wq,
	.modify_qp = mana_modify_qp,
	.poll_cq = mana_poll_cq,
	.post_recv = mana_post_recv,
	.post_send = mana_post_send,
	.query_device_ex = mana_query_device_ex,
	.query_port = mana_query_port,
	.reg_dmabuf_mr = mana_reg_dmabuf_mr,
	.reg_mr = mana_reg_mr,
	.req_notify_cq = mana_arm_cq,
};

static struct verbs_device *mana_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct mana_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->verbs_dev;
}

static void mana_uninit_device(struct verbs_device *verbs_device)
{
	struct mana_device *dev =
		container_of(verbs_device, struct mana_device, verbs_dev);

	free(dev);
}

static struct verbs_context *mana_alloc_context(struct ibv_device *ibdev,
						int cmd_fd, void *private_data)
{
	int ret, i;
	struct mana_context *context;
	struct mana_alloc_ucontext_resp resp;
	struct ibv_get_context cmd;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_MANA);
	if (!context)
		return NULL;

	ret = ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				  NULL, &resp.ibv_resp, sizeof(resp));
	if (ret) {
		verbs_err(&context->ibv_ctx, "Failed to get ucontext\n");
		errno = ret;
		goto free_ctx;
	}

	verbs_set_ops(&context->ibv_ctx, &mana_ctx_ops);

	pthread_mutex_init(&context->qp_table_mutex, NULL);
	for (i = 0; i < MANA_QP_TABLE_SIZE; ++i) {
		context->qp_stable[i].refcnt = 0;
		context->qp_rtable[i].refcnt = 0;
	}

	context->db_page = mmap(NULL, DOORBELL_PAGE_SIZE, PROT_WRITE,
				MAP_SHARED, context->ibv_ctx.context.cmd_fd, 0);
	if (context->db_page == MAP_FAILED) {
		verbs_err(&context->ibv_ctx, "Failed to map doorbell page\n");
		errno = ENOENT;
		goto free_ctx;
	}
	verbs_debug(&context->ibv_ctx, "Mapped db_page=%p\n", context->db_page);

	return &context->ibv_ctx;

free_ctx:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static const struct verbs_device_ops mana_dev_ops = {
	.name = "mana",
	.match_min_abi_version = MANA_IB_UVERBS_ABI_VERSION,
	.match_max_abi_version = MANA_IB_UVERBS_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = mana_device_alloc,
	.uninit_device = mana_uninit_device,
	.alloc_context = mana_alloc_context,
};

PROVIDER_DRIVER(mana, mana_dev_ops);
