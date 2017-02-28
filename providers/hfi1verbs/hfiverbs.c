/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Intel Corporation
  www.intel.com

  BSD LICENSE

  Copyright(c) 2015 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Copyright (C) 2006-2007 QLogic Corporation, All rights reserved.
  Copyright (c) 2005. PathScale, Inc. All rights reserved.

*/

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "hfiverbs.h"
#include "hfi-abi.h"

#ifndef PCI_VENDOR_ID_INTEL
#define PCI_VENDOR_ID_INTEL			0x8086
#endif

#ifndef PCI_DEVICE_ID_INTEL0
#define PCI_DEVICE_ID_HFI_INTEL0		0x24f0
#endif

#ifndef PCI_DEVICE_ID_INTEL1
#define PCI_DEVICE_ID_HFI_INTEL1		0x24f1
#endif

#define HFI(v, d) \
	{ .vendor = PCI_VENDOR_ID_##v,			\
	  .device = PCI_DEVICE_ID_HFI_##d }

static struct {
	unsigned		vendor;
	unsigned		device;
} hca_table[] = {
	HFI(INTEL, INTEL0),
	HFI(INTEL, INTEL1),
};

static struct ibv_context_ops hfi1_ctx_ops = {
	.query_device	= hfi1_query_device,
	.query_port	= hfi1_query_port,

	.alloc_pd	= hfi1_alloc_pd,
	.dealloc_pd	= hfi1_free_pd,

	.reg_mr		= hfi1_reg_mr,
	.dereg_mr	= hfi1_dereg_mr,

	.create_cq	= hfi1_create_cq,
	.poll_cq	= hfi1_poll_cq,
	.req_notify_cq	= ibv_cmd_req_notify_cq,
	.cq_event	= NULL,
	.resize_cq	= hfi1_resize_cq,
	.destroy_cq	= hfi1_destroy_cq,

	.create_srq	= hfi1_create_srq,
	.modify_srq	= hfi1_modify_srq,
	.query_srq	= hfi1_query_srq,
	.destroy_srq	= hfi1_destroy_srq,
	.post_srq_recv	= hfi1_post_srq_recv,

	.create_qp	= hfi1_create_qp,
	.query_qp	= hfi1_query_qp,
	.modify_qp	= hfi1_modify_qp,
	.destroy_qp	= hfi1_destroy_qp,

	.post_send	= hfi1_post_send,
	.post_recv	= hfi1_post_recv,

	.create_ah	= hfi1_create_ah,
	.destroy_ah	= hfi1_destroy_ah,

	.attach_mcast	= ibv_cmd_attach_mcast,
	.detach_mcast	= ibv_cmd_detach_mcast
};

static struct ibv_context *hfi1_alloc_context(struct ibv_device *ibdev,
					       int cmd_fd)
{
	struct hfi1_context	    *context;
	struct ibv_get_context       cmd;
	struct ibv_get_context_resp  resp;
	struct hfi1_device         *dev;

	context = malloc(sizeof *context);
	if (!context)
		return NULL;
	memset(context, 0, sizeof *context);
	context->ibv_ctx.cmd_fd = cmd_fd;
	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd,
				sizeof cmd, &resp, sizeof resp))
		goto err_free;

	context->ibv_ctx.ops = hfi1_ctx_ops;
	dev = to_idev(ibdev);
	if (dev->abi_version == 1) {
		context->ibv_ctx.ops.create_cq     = hfi1_create_cq_v1;
		context->ibv_ctx.ops.poll_cq       = ibv_cmd_poll_cq;
		context->ibv_ctx.ops.resize_cq     = hfi1_resize_cq_v1;
		context->ibv_ctx.ops.destroy_cq    = hfi1_destroy_cq_v1;
		context->ibv_ctx.ops.create_srq    = hfi1_create_srq_v1;
		context->ibv_ctx.ops.destroy_srq   = hfi1_destroy_srq_v1;
		context->ibv_ctx.ops.modify_srq    = hfi1_modify_srq_v1;
		context->ibv_ctx.ops.post_srq_recv = ibv_cmd_post_srq_recv;
		context->ibv_ctx.ops.create_qp     = hfi1_create_qp_v1;
		context->ibv_ctx.ops.destroy_qp    = hfi1_destroy_qp_v1;
		context->ibv_ctx.ops.post_recv     = ibv_cmd_post_recv;
	}
	return &context->ibv_ctx;

err_free:
	free(context);
	return NULL;
}

static void hfi1_free_context(struct ibv_context *ibctx)
{
	struct hfi1_context *context = to_ictx(ibctx);

	free(context);
}

static struct verbs_device_ops hfi1_dev_ops = {
	.alloc_context	= hfi1_alloc_context,
	.free_context	= hfi1_free_context
};

static struct verbs_device *hfi1_driver_init(const char *uverbs_sys_path,
					     int abi_version)
{
	char			value[8];
	struct hfi1_device    *dev;
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
	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		fprintf(stderr, PFX "Fatal: couldn't allocate device for %s\n",
			uverbs_sys_path);
		return NULL;
	}

	dev->ibv_dev.ops = &hfi1_dev_ops;
	dev->abi_version = abi_version;

	return &dev->ibv_dev;
}

static __attribute__((constructor)) void hfi1_register_driver(void)
{
	ibv_register_driver("hfi1verbs", hfi1_driver_init);
}
