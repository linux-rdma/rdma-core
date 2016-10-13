/*
 * Copyright (c) 2006 - 2010 Intel Corporation.  All rights reserved.
 * Copyright (c) 2006 Open Grid Computing, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * gpl-2.0.txt in the main directory of this source tree, or the
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "nes_umain.h"
#include "nes-abi.h"

unsigned int nes_debug_level = 0;
long int page_size;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef PCI_VENDOR_ID_NETEFFECT
#define PCI_VENDOR_ID_NETEFFECT		0x1678
#endif

#define HCA(v, d, t)                            \
	{ .vendor = PCI_VENDOR_ID_##v,              \
	  .device = d,    \
	  .type = NETEFFECT_##t }

static struct {
	unsigned vendor;
	unsigned device;
	enum nes_uhca_type type;
} hca_table[] = {
	HCA(NETEFFECT, 0x0100, nes),
	HCA(NETEFFECT, 0x0110, nes),
};

static struct ibv_context *nes_ualloc_context(struct ibv_device *, int);
static void nes_ufree_context(struct ibv_context *);

static struct ibv_context_ops nes_uctx_ops = {
	.query_device = nes_uquery_device,
	.query_port = nes_uquery_port,
	.alloc_pd = nes_ualloc_pd,
	.dealloc_pd = nes_ufree_pd,
	.reg_mr = nes_ureg_mr,
	.dereg_mr = nes_udereg_mr,
	.create_cq = nes_ucreate_cq,
	.poll_cq = nes_upoll_cq,
	.req_notify_cq = nes_uarm_cq,
	.cq_event = nes_cq_event,
	.resize_cq = nes_uresize_cq,
	.destroy_cq = nes_udestroy_cq,
	.create_srq = NULL,
	.modify_srq = NULL,
	.query_srq = NULL,
	.destroy_srq = NULL,
	.post_srq_recv = NULL,
	.create_qp = nes_ucreate_qp,
	.query_qp = nes_uquery_qp,
	.modify_qp = nes_umodify_qp,
	.destroy_qp = nes_udestroy_qp,
	.post_send = nes_upost_send,
	.post_recv = nes_upost_recv,
	.create_ah = nes_ucreate_ah,
	.destroy_ah = nes_udestroy_ah,
	.attach_mcast = nes_uattach_mcast,
	.detach_mcast = nes_udetach_mcast,
	.async_event = nes_async_event
};


/**
 * nes_ualloc_context
 */
static struct ibv_context *nes_ualloc_context(struct ibv_device *ibdev, int cmd_fd)
{
	struct ibv_pd *ibv_pd;
	struct nes_uvcontext *nesvctx;
	struct nes_get_context cmd;
	struct nes_ualloc_ucontext_resp resp;
	char value[16];
	uint32_t nes_drv_opt = 0;

	page_size = sysconf(_SC_PAGESIZE);

	nesvctx = malloc(sizeof *nesvctx);
	if (!nesvctx)
		return NULL;

	memset(nesvctx, 0, sizeof *nesvctx);
	nesvctx->ibv_ctx.cmd_fd = cmd_fd;
	cmd.userspace_ver = NES_ABI_USERSPACE_VER;

	if (ibv_cmd_get_context(&nesvctx->ibv_ctx, (struct ibv_get_context *)&cmd, sizeof cmd,
			&resp.ibv_resp, sizeof(resp)))
		goto err_free;

	if (resp.kernel_ver != NES_ABI_KERNEL_VER) {
	 	fprintf(stderr, PFX "%s: Invalid kernel driver version detected. Detected %d, should be %d\n",
			__FUNCTION__, resp.kernel_ver, NES_ABI_KERNEL_VER);
		goto err_free;
	}

	if (ibv_read_sysfs_file("/sys/module/iw_nes", "parameters/nes_drv_opt",
			value, sizeof(value)) > 0) {
		sscanf(value, "%d", &nes_drv_opt);
	} else if (ibv_read_sysfs_file("/sys/module/iw_nes", "nes_drv_opt",
				value, sizeof(value)) > 0) {
			sscanf(value, "%d", &nes_drv_opt);
	}

	nesvctx->ibv_ctx.device = ibdev;

	if (nes_drv_opt & NES_DRV_OPT_NO_DB_READ)
		nes_uctx_ops.poll_cq = nes_upoll_cq_no_db_read;

	nesvctx->ibv_ctx.ops = nes_uctx_ops;
	nesvctx->max_pds = resp.max_pds;
	nesvctx->max_qps = resp.max_qps;
	nesvctx->wq_size = resp.wq_size;
	nesvctx->virtwq = resp.virtwq;
	nesvctx->mcrqf = 0;

	/* Get a doorbell region for the CQs */
	ibv_pd = nes_ualloc_pd(&nesvctx->ibv_ctx);
	if (!ibv_pd)
		goto err_free;
	ibv_pd->context = &nesvctx->ibv_ctx;
	nesvctx->nesupd = to_nes_upd(ibv_pd);

	return &nesvctx->ibv_ctx;

err_free:
 	fprintf(stderr, PFX "%s: Failed to allocate context for device.\n", __FUNCTION__);
	free(nesvctx);

	return NULL;
}


/**
 * nes_ufree_context
 */
static void nes_ufree_context(struct ibv_context *ibctx)
{
	struct nes_uvcontext *nesvctx = to_nes_uctx(ibctx);
	nes_ufree_pd(&nesvctx->nesupd->ibv_pd);

	free(nesvctx);
}


static struct ibv_device_ops nes_udev_ops = {
	.alloc_context = nes_ualloc_context,
	.free_context = nes_ufree_context
};


/**
 * nes_driver_init
 */
struct ibv_device *nes_driver_init(const char *uverbs_sys_path, int abi_version)
{
	char value[16];
	struct nes_udevice *dev;
	unsigned vendor, device;
	int i;

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/vendor",
			value, sizeof(value)) < 0) {
		return NULL;
	}
	sscanf(value, "%i", &vendor);

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/device",
			value, sizeof(value)) < 0) {
		return NULL;
	}
	sscanf(value, "%i", &device);

	for (i = 0; i < sizeof hca_table / sizeof hca_table[0]; ++i)
		if (vendor == hca_table[i].vendor &&
				device == hca_table[i].device)
			goto found;

	return NULL;

found:
	if (ibv_read_sysfs_file("/sys/module/iw_nes", "parameters/debug_level",
			value, sizeof(value)) > 0) {
		sscanf(value, "%u", &nes_debug_level);
	} else if (ibv_read_sysfs_file("/sys/module/iw_nes", "debug_level",
				value, sizeof(value)) > 0) {
			sscanf(value, "%u", &nes_debug_level);
	}

	dev = malloc(sizeof *dev);
	if (!dev) {
		nes_debug(NES_DBG_INIT, "Fatal: couldn't allocate device for libnes\n");
		return NULL;
	}

	dev->ibv_dev.ops = nes_udev_ops;
	dev->hca_type = hca_table[i].type;
	dev->page_size = sysconf(_SC_PAGESIZE);

	nes_debug(NES_DBG_INIT, "libnes initialized\n");

	return &dev->ibv_dev;
}


/**
 * nes_register_driver
 */
static __attribute__((constructor)) void nes_register_driver(void)
{
	/* fprintf(stderr, PFX "nes_register_driver: call ibv_register_driver()\n"); */

	ibv_register_driver("nes", nes_driver_init);
}
