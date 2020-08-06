/*******************************************************************************
*
* Copyright (c) 2015-2016 Intel Corporation.  All rights reserved.
*
* This software is available to you under a choice of one of two
* licenses.  You may choose to be licensed under the terms of the GNU
* General Public License (GPL) Version 2, available from the file
* COPYING in the main directory of this source tree, or the
* OpenFabrics.org BSD license below:
*
*   Redistribution and use in source and binary forms, with or
*   without modification, are permitted provided that the following
*   conditions are met:
*
*    - Redistributions of source code must retain the above
*	copyright notice, this list of conditions and the following
*	disclaimer.
*
*    - Redistributions in binary form must reproduce the above
*	copyright notice, this list of conditions and the following
*	disclaimer in the documentation and/or other materials
*	provided with the distribution.
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
*******************************************************************************/

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "i40e_devids.h"
#include "i40iw_umain.h"
#include "i40iw-abi.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static void i40iw_ufree_context(struct ibv_context *ibctx);

#define INTEL_HCA(v, d) VERBS_PCI_MATCH(v, d, NULL)
static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_I40IW),
#ifdef I40E_DEV_ID_X722_A0
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_A0),
#endif
#ifdef I40E_DEV_ID_X722_A0_VF
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_A0_VF),
#endif
#ifdef I40E_DEV_ID_KX_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_KX_X722),
#endif
#ifdef I40E_DEV_ID_QSFP_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_QSFP_X722),
#endif
#ifdef I40E_DEV_ID_SFP_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_SFP_X722),
#endif
#ifdef I40E_DEV_ID_1G_BASE_T_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_1G_BASE_T_X722),
#endif
#ifdef I40E_DEV_ID_10G_BASE_T_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_10G_BASE_T_X722),
#endif
#ifdef I40E_DEV_ID_SFP_I_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_SFP_I_X722),
#endif
#ifdef I40E_DEV_ID_X722_VF
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_VF),
#endif
#ifdef I40E_DEV_ID_X722_VF_HV
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_VF_HV),
#endif
#ifdef I40E_DEV_ID_X722_FPGA
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_FPGA),
#endif
#ifdef I40E_DEV_ID_X722_FPGA_VF
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_FPGA_VF),
#endif
	{}
};

static const struct verbs_context_ops i40iw_uctx_ops = {
	.query_device	= i40iw_uquery_device,
	.query_port	= i40iw_uquery_port,
	.alloc_pd	= i40iw_ualloc_pd,
	.dealloc_pd	= i40iw_ufree_pd,
	.reg_mr		= i40iw_ureg_mr,
	.dereg_mr	= i40iw_udereg_mr,
	.create_cq	= i40iw_ucreate_cq,
	.poll_cq	= i40iw_upoll_cq,
	.req_notify_cq	= i40iw_uarm_cq,
	.cq_event	= i40iw_cq_event,
	.destroy_cq	= i40iw_udestroy_cq,
	.create_qp	= i40iw_ucreate_qp,
	.query_qp	= i40iw_uquery_qp,
	.modify_qp	= i40iw_umodify_qp,
	.destroy_qp	= i40iw_udestroy_qp,
	.post_send	= i40iw_upost_send,
	.post_recv	= i40iw_upost_recv,
	.async_event	= i40iw_async_event,
	.free_context	= i40iw_ufree_context,
};

/**
 * i40iw_ualloc_context - allocate context for user app
 * @ibdev: pointer to device created during i40iw_driver_init
 * @cmd_fd: save fd for the device
 *
 * Returns callback routines table and calls driver for allocating
 * context and getting back resource information to return as ibv_context.
 */

static struct verbs_context *i40iw_ualloc_context(struct ibv_device *ibdev,
						  int cmd_fd,
						  void *private_data)
{
	struct ibv_pd *ibv_pd;
	struct i40iw_uvcontext *iwvctx;
	struct i40iw_get_context cmd;
	struct i40iw_get_context_resp resp;

	iwvctx = verbs_init_and_alloc_context(ibdev, cmd_fd, iwvctx, ibv_ctx,
					      RDMA_DRIVER_I40IW);
	if (!iwvctx)
		return NULL;

	cmd.userspace_ver = I40IW_ABI_VER;
	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_get_context(&iwvctx->ibv_ctx, (struct ibv_get_context *)&cmd,
				sizeof(cmd), &resp.ibv_resp, sizeof(resp))) {

		cmd.userspace_ver = 4;
		if (ibv_cmd_get_context(&iwvctx->ibv_ctx, (struct ibv_get_context *)&cmd,
				sizeof(cmd), &resp.ibv_resp, sizeof(resp)))
			goto err_free;

	}

	if (resp.kernel_ver > I40IW_ABI_VER) {
		fprintf(stderr, PFX "%s: incompatible kernel driver version: %d.  Need version %d\n",
			__func__, resp.kernel_ver, I40IW_ABI_VER);
		goto err_free;
	}

	verbs_set_ops(&iwvctx->ibv_ctx, &i40iw_uctx_ops);
	iwvctx->max_pds = resp.max_pds;
	iwvctx->max_qps = resp.max_qps;
	iwvctx->wq_size = resp.wq_size;
	iwvctx->abi_ver = resp.kernel_ver;

	i40iw_device_init_uk(&iwvctx->dev);
	ibv_pd = i40iw_ualloc_pd(&iwvctx->ibv_ctx.context);
	if (!ibv_pd)
		goto err_free;
	ibv_pd->context = &iwvctx->ibv_ctx.context;
	iwvctx->iwupd = to_i40iw_upd(ibv_pd);

	return &iwvctx->ibv_ctx;

err_free:
	fprintf(stderr, PFX "%s: failed to allocate context for device.\n", __func__);
	verbs_uninit_context(&iwvctx->ibv_ctx);
	free(iwvctx);

	return NULL;
}

/**
 * i40iw_ufree_context - free context that was allocated
 * @ibctx: context allocated ptr
 */
static void i40iw_ufree_context(struct ibv_context *ibctx)
{
	struct i40iw_uvcontext *iwvctx = to_i40iw_uctx(ibctx);

	i40iw_ufree_pd(&iwvctx->iwupd->ibv_pd);

	verbs_uninit_context(&iwvctx->ibv_ctx);
	free(iwvctx);
}

static void i40iw_uninit_device(struct verbs_device *verbs_device)
{
	struct i40iw_udevice *dev = to_i40iw_udev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *
i40iw_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct i40iw_udevice *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->page_size = I40IW_HW_PAGE_SIZE;
	return &dev->ibv_dev;
}

static const struct verbs_device_ops i40iw_udev_ops = {
	.name = "i40iw",
	.match_min_abi_version = 0,
	.match_max_abi_version = INT_MAX,
	.match_table = hca_table,
	.alloc_device = i40iw_device_alloc,
	.uninit_device  = i40iw_uninit_device,
	.alloc_context = i40iw_ualloc_context,
};
PROVIDER_DRIVER(i40iw, i40iw_udev_ops);
