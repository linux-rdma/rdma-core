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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ipathverbs.h"
#include "ipath-abi.h"

#ifndef PCI_VENDOR_ID_PATHSCALE
#define PCI_VENDOR_ID_PATHSCALE			0x1fc1
#endif

#ifndef PCI_VENDOR_ID_QLOGIC
#define PCI_VENDOR_ID_QLOGIC			0x1077
#endif

#ifndef PCI_DEVICE_ID_INFINIPATH_SPINNERET
#define PCI_DEVICE_ID_INFINIPATH_SPINNERET	0x000a
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

#define HCA(v, d, t) \
	{ .vendor = PCI_VENDOR_ID_##v,			\
	  .device = PCI_DEVICE_ID_INFINIPATH_##d,	\
	  .type = IPATH_##t }

struct {
	unsigned		vendor;
	unsigned		device;
	enum ipath_hca_type	type;
} hca_table[] = {
	HCA(PATHSCALE,	SPINNERET, SPINNERET),
	HCA(PATHSCALE,	HT,	  HT),
	HCA(PATHSCALE,	PE800,	  PE800),
	HCA(QLOGIC,	6220,	  7220),
	HCA(QLOGIC,	7220,	  7220),
};

static struct ibv_context_ops ipath_ctx_ops = {
	.query_device	= ipath_query_device,
	.query_port	= ipath_query_port,

	.alloc_pd	= ipath_alloc_pd,
	.dealloc_pd	= ipath_free_pd,

	.reg_mr		= ipath_reg_mr,
	.dereg_mr	= ipath_dereg_mr,

	.create_cq	= ipath_create_cq,
	.poll_cq	= ipath_poll_cq,
	.req_notify_cq	= ibv_cmd_req_notify_cq,
	.cq_event	= NULL,
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

	.post_send	= ibv_cmd_post_send,
	.post_recv	= ipath_post_recv,

	.create_ah	= ipath_create_ah,
	.destroy_ah	= ipath_destroy_ah,

	.attach_mcast	= ibv_cmd_attach_mcast,
	.detach_mcast	= ibv_cmd_detach_mcast
};

static struct ibv_context *ipath_alloc_context(struct ibv_device *ibdev,
					       int cmd_fd)
{
	struct ipath_context	    *context;
	struct ibv_get_context       cmd;
	struct ibv_get_context_resp  resp;
	struct ipath_device         *dev;

	context = malloc(sizeof *context);
	if (!context)
		return NULL;
	context->ibv_ctx.cmd_fd = cmd_fd;
	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd,
				sizeof cmd, &resp, sizeof resp))
		goto err_free;

	context->ibv_ctx.ops = ipath_ctx_ops;
	dev = to_idev(ibdev);
	if (dev->abi_version == 1) {
		context->ibv_ctx.ops.create_cq     = ipath_create_cq_v1;
		context->ibv_ctx.ops.poll_cq       = ibv_cmd_poll_cq;
		context->ibv_ctx.ops.resize_cq     = ipath_resize_cq_v1;
		context->ibv_ctx.ops.destroy_cq    = ipath_destroy_cq_v1;
		context->ibv_ctx.ops.create_srq    = ipath_create_srq_v1;
		context->ibv_ctx.ops.destroy_srq   = ipath_destroy_srq_v1;
		context->ibv_ctx.ops.modify_srq    = ipath_modify_srq_v1;
		context->ibv_ctx.ops.post_srq_recv = ibv_cmd_post_srq_recv;
		context->ibv_ctx.ops.create_qp     = ipath_create_qp_v1;
		context->ibv_ctx.ops.destroy_qp    = ipath_destroy_qp_v1;
		context->ibv_ctx.ops.post_recv     = ibv_cmd_post_recv;
	}
	return &context->ibv_ctx;

err_free:
	free(context);
	return NULL;
}

static void ipath_free_context(struct ibv_context *ibctx)
{
	struct ipath_context *context = to_ictx(ibctx);

	free(context);
}

static struct ibv_device_ops ipath_dev_ops = {
	.alloc_context	= ipath_alloc_context,
	.free_context	= ipath_free_context
};

static struct ibv_device *ipath_driver_init(const char *uverbs_sys_path,
					    int abi_version)
{
	char			value[8];
	struct ipath_device    *dev;
	unsigned                vendor, device;
	int                     i;

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/vendor",
				value, sizeof value) < 0)
		return NULL;
	sscanf(value, "%i", &vendor);

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/device",
				value, sizeof value) < 0)
		return NULL;
	sscanf(value, "%i", &device);

	for (i = 0; i < sizeof hca_table / sizeof hca_table[0]; ++i)
		if (vendor == hca_table[i].vendor &&
		    device == hca_table[i].device)
			goto found;

	return NULL;

found:
	dev = malloc(sizeof *dev);
	if (!dev) {
		fprintf(stderr, PFX "Fatal: couldn't allocate device for %s\n",
			uverbs_sys_path);
		return NULL;
	}

	dev->ibv_dev.ops = ipath_dev_ops;
	dev->hca_type    = hca_table[i].type;
	dev->abi_version = abi_version;

	return &dev->ibv_dev;
}

#ifdef HAVE_IBV_REGISTER_DRIVER
static __attribute__((constructor)) void ipath_register_driver(void)
{
	ibv_register_driver("ipathverbs", ipath_driver_init);
}
#else
/*
 * Export the old libsysfs sysfs_class_device-based driver entry point
 * if libibverbs does not export an ibv_register_driver() function.
 */
struct ibv_device *openib_driver_init(struct sysfs_class_device *sysdev)
{
        int abi_ver = 0;
        char value[8];

        if (ibv_read_sysfs_file(sysdev->path, "abi_version",
                                value, sizeof value) > 0)
                abi_ver = strtol(value, NULL, 10);

        return ipath_driver_init(sysdev->path, abi_ver);
}
#endif /* HAVE_IBV_REGISTER_DRIVER */
