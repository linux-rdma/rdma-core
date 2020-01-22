/*
 * Copyright (C) 2006-2007 QLogic Corporation, All rights reserved.
 * Copyright (c) 2005. PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Patent licenses, if any, provided herein do not apply to
 * combinations of this program with other software, or any other
 * product whatsoever.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "ipathverbs.h"
#include "ipath-abi.h"

static void ipath_free_context(struct ibv_context *ibctx);

#ifndef PCI_VENDOR_ID_PATHSCALE
#define PCI_VENDOR_ID_PATHSCALE			0x1fc1
#endif

#ifndef PCI_VENDOR_ID_QLOGIC
#define PCI_VENDOR_ID_QLOGIC			0x1077
#endif

#ifndef PCI_DEVICE_ID_INFINIPATH_HT
#define PCI_DEVICE_ID_INFINIPATH_HT		0x000d
#endif

#ifndef PCI_DEVICE_ID_INFINIPATH_PE800
#define PCI_DEVICE_ID_INFINIPATH_PE800		0x0010
#endif

#ifndef PCI_DEVICE_ID_INFINIPATH_6220
#define PCI_DEVICE_ID_INFINIPATH_6220		0x6220
#endif

#ifndef PCI_DEVICE_ID_INFINIPATH_7220
#define PCI_DEVICE_ID_INFINIPATH_7220		0x7220
#endif

#ifndef PCI_DEVICE_ID_INFINIPATH_7322
#define PCI_DEVICE_ID_INFINIPATH_7322		0x7322
#endif

#define HCA(v, d)                                                              \
	VERBS_PCI_MATCH(PCI_VENDOR_ID_##v, PCI_DEVICE_ID_INFINIPATH_##d, NULL)
static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_QIB),
	HCA(PATHSCALE,	HT),
	HCA(PATHSCALE,	PE800),
	HCA(QLOGIC,	6220),
	HCA(QLOGIC,	7220),
	HCA(QLOGIC,	7322),
	{}
};

static const struct verbs_context_ops ipath_ctx_common_ops = {
	.free_context	= ipath_free_context,
	.query_device	= ipath_query_device,
	.query_port	= ipath_query_port,

	.alloc_pd	= ipath_alloc_pd,
	.dealloc_pd	= ipath_free_pd,

	.reg_mr		= ipath_reg_mr,
	.dereg_mr	= ipath_dereg_mr,

	.create_cq	= ipath_create_cq,
	.poll_cq	= ipath_poll_cq,
	.req_notify_cq	= ibv_cmd_req_notify_cq,
	.resize_cq	= ipath_resize_cq,
	.destroy_cq	= ipath_destroy_cq,

	.create_srq	= ipath_create_srq,
	.modify_srq	= ipath_modify_srq,
	.query_srq	= ipath_query_srq,
	.destroy_srq	= ipath_destroy_srq,
	.post_srq_recv	= ipath_post_srq_recv,

	.create_qp	= ipath_create_qp,
	.query_qp	= ipath_query_qp,
	.modify_qp	= ipath_modify_qp,
	.destroy_qp	= ipath_destroy_qp,

	.post_send	= ipath_post_send,
	.post_recv	= ipath_post_recv,

	.create_ah	= ipath_create_ah,
	.destroy_ah	= ipath_destroy_ah,

	.attach_mcast	= ibv_cmd_attach_mcast,
	.detach_mcast	= ibv_cmd_detach_mcast
};

static const struct verbs_context_ops ipath_ctx_v1_ops = {
	.create_cq = ipath_create_cq_v1,
	.poll_cq = ibv_cmd_poll_cq,
	.resize_cq = ipath_resize_cq_v1,
	.destroy_cq = ipath_destroy_cq_v1,
	.create_srq = ipath_create_srq_v1,
	.destroy_srq = ipath_destroy_srq_v1,
	.modify_srq = ipath_modify_srq_v1,
	.post_srq_recv = ibv_cmd_post_srq_recv,
	.create_qp = ipath_create_qp_v1,
	.destroy_qp = ipath_destroy_qp_v1,
	.post_recv = ibv_cmd_post_recv,
};

static struct verbs_context *ipath_alloc_context(struct ibv_device *ibdev,
						 int cmd_fd,
						 void *private_data)
{
	struct ipath_context	    *context;
	struct ibv_get_context       cmd;
	struct ib_uverbs_get_context_resp  resp;
	struct ipath_device         *dev;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_QIB);
	if (!context)
		return NULL;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd,
				sizeof cmd, &resp, sizeof resp))
		goto err_free;

	verbs_set_ops(&context->ibv_ctx, &ipath_ctx_common_ops);
	dev = to_idev(ibdev);
	if (dev->abi_version == 1)
		verbs_set_ops(&context->ibv_ctx, &ipath_ctx_v1_ops);
	return &context->ibv_ctx;

err_free:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void ipath_free_context(struct ibv_context *ibctx)
{
	struct ipath_context *context = to_ictx(ibctx);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void ipath_uninit_device(struct verbs_device *verbs_device)
{
	struct ipath_device *dev = to_idev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *
ipath_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct ipath_device    *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->abi_version = sysfs_dev->abi_ver;

	return &dev->ibv_dev;
}

static const struct verbs_device_ops ipath_dev_ops = {
	.name = "ipathverbs",
	.match_min_abi_version = 0,
	.match_max_abi_version = INT_MAX,
	.match_table = hca_table,
	.alloc_device = ipath_device_alloc,
	.uninit_device  = ipath_uninit_device,
	.alloc_context = ipath_alloc_context,
};
PROVIDER_DRIVER(ipathverbs, ipath_dev_ops);
