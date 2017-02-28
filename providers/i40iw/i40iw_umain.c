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

#define INTEL_HCA(v, d, t)		\
	{ .vendor = v,		\
	  .device = d,		\
	  .type = INTEL_ ## t }

static struct {
	unsigned int vendor;
	unsigned int device;
	enum i40iw_uhca_type type;
} hca_table[] = {
#ifdef I40E_DEV_ID_X722_A0
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_A0, i40iw),
#endif
#ifdef I40E_DEV_ID_X722_A0_VF
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_A0_VF, i40iw),
#endif
#ifdef I40E_DEV_ID_KX_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_KX_X722, i40iw),
#endif
#ifdef I40E_DEV_ID_QSFP_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_QSFP_X722, i40iw),
#endif
#ifdef I40E_DEV_ID_SFP_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_SFP_X722, i40iw),
#endif
#ifdef I40E_DEV_ID_1G_BASE_T_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_1G_BASE_T_X722, i40iw),
#endif
#ifdef I40E_DEV_ID_10G_BASE_T_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_10G_BASE_T_X722, i40iw),
#endif
#ifdef I40E_DEV_ID_SFP_I_X722
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_SFP_I_X722, i40iw),
#endif
#ifdef I40E_DEV_ID_X722_VF
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_VF, i40iw),
#endif
#ifdef I40E_DEV_ID_X722_VF_HV
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_VF_HV, i40iw),
#endif
#ifdef I40E_DEV_ID_X722_FPGA
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_FPGA, i40iw),
#endif
#ifdef I40E_DEV_ID_X722_FPGA_VF
	INTEL_HCA(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_FPGA_VF, i40iw),
#endif
};

static struct ibv_context *i40iw_ualloc_context(struct ibv_device *, int);
static void i40iw_ufree_context(struct ibv_context *);

static struct ibv_context_ops i40iw_uctx_ops = {
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
	.resize_cq	= i40iw_uresize_cq,
	.destroy_cq	= i40iw_udestroy_cq,
	.create_srq	= NULL,
	.modify_srq	= NULL,
	.query_srq	= NULL,
	.destroy_srq	= NULL,
	.post_srq_recv	= NULL,
	.create_qp	= i40iw_ucreate_qp,
	.query_qp	= i40iw_uquery_qp,
	.modify_qp	= i40iw_umodify_qp,
	.destroy_qp	= i40iw_udestroy_qp,
	.post_send	= i40iw_upost_send,
	.post_recv	= i40iw_upost_recv,
	.create_ah	= i40iw_ucreate_ah,
	.destroy_ah	= i40iw_udestroy_ah,
	.attach_mcast	= i40iw_uattach_mcast,
	.detach_mcast	= i40iw_udetach_mcast,
	.async_event	= i40iw_async_event
};

/**
 * i40iw_ualloc_context - allocate context for user app
 * @ibdev: pointer to device created during i40iw_driver_init
 * @cmd_fd: save fd for the device
 *
 * Returns callback routines table and calls driver for allocating
 * context and getting back resource information to return as ibv_context.
 */

static struct ibv_context *i40iw_ualloc_context(struct ibv_device *ibdev, int cmd_fd)
{
	struct ibv_pd *ibv_pd;
	struct i40iw_uvcontext *iwvctx;
	struct i40iw_get_context cmd;
	struct i40iw_ualloc_ucontext_resp resp;

	iwvctx = malloc(sizeof(*iwvctx));
	if (!iwvctx)
		return NULL;

	memset(iwvctx, 0, sizeof(*iwvctx));
	iwvctx->ibv_ctx.cmd_fd = cmd_fd;
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

	iwvctx->ibv_ctx.device = ibdev;
	iwvctx->ibv_ctx.ops = i40iw_uctx_ops;
	iwvctx->max_pds = resp.max_pds;
	iwvctx->max_qps = resp.max_qps;
	iwvctx->wq_size = resp.wq_size;
	iwvctx->abi_ver = resp.kernel_ver;

	i40iw_device_init_uk(&iwvctx->dev);
	ibv_pd = i40iw_ualloc_pd(&iwvctx->ibv_ctx);
	if (!ibv_pd)
		goto err_free;
	ibv_pd->context = &iwvctx->ibv_ctx;
	iwvctx->iwupd = to_i40iw_upd(ibv_pd);

	return &iwvctx->ibv_ctx;

err_free:
	fprintf(stderr, PFX "%s: failed to allocate context for device.\n", __func__);
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

	free(iwvctx);
}

static struct ibv_device_ops i40iw_udev_ops = {
	.alloc_context	= i40iw_ualloc_context,
	.free_context	= i40iw_ufree_context
};

/**
 * i40iw_driver_init - create device struct and provide callback routines for user context
 * @uverbs_sys_path: sys path
 * @abi_version: not used
 */
static struct verbs_device *i40iw_driver_init(const char *uverbs_sys_path,
					      int abi_version)
{
	char value[16];
	struct i40iw_udevice *dev;
	unsigned int vendor, device;
	int i;

	if ((ibv_read_sysfs_file(uverbs_sys_path, "device/vendor", value, sizeof(value)) < 0) ||
	    (sscanf(value, "%i", &vendor) != 1))
		return NULL;

	if ((ibv_read_sysfs_file(uverbs_sys_path, "device/device", value, sizeof(value)) < 0) ||
	    (sscanf(value, "%i", &device) != 1))
		return NULL;

	for (i = 0; i < sizeof(hca_table) / sizeof(hca_table[0]); ++i) {
		if (vendor == hca_table[i].vendor &&
		    device == hca_table[i].device)
			goto found;
	}

	return NULL;
found:
	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		fprintf(stderr, PFX "%s: failed to allocate memory for device object\n", __func__);
		return NULL;
	}

	dev->ibv_dev.device.ops = i40iw_udev_ops;
	dev->hca_type = hca_table[i].type;
	dev->page_size = I40IW_HW_PAGE_SIZE;
	return &dev->ibv_dev;
}

static __attribute__ ((constructor)) void i40iw_register_driver(void)
{
	ibv_register_driver("i40iw", i40iw_driver_init);
}
