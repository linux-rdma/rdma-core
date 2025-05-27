// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "zxdh_devids.h"
#include "zxdh_zrdma.h"
#include "zxdh_abi.h"
#include "private_verbs_cmd.h"

#define ZXDH_HCA(v, d) VERBS_PCI_MATCH(v, d, NULL)
static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_ZXDH),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_EVB, ZXDH_DEV_ID_ADAPTIVE_EVB_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_EVB, ZXDH_DEV_ID_ADAPTIVE_EVB_VF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E312, ZXDH_DEV_ID_ADAPTIVE_E312_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E312, ZXDH_DEV_ID_ADAPTIVE_E312_VF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E310, ZXDH_DEV_ID_ADAPTIVE_E310_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E310, ZXDH_DEV_ID_ADAPTIVE_E310_VF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E310_RDMA, ZXDH_DEV_ID_ADAPTIVE_E310_RDMA_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E310_RDMA, ZXDH_DEV_ID_ADAPTIVE_E310_RDMA_VF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E316, ZXDH_DEV_ID_ADAPTIVE_E316_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E316, ZXDH_DEV_ID_ADAPTIVE_E316_VF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_X512, ZXDH_DEV_ID_ADAPTIVE_X512_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_X512, ZXDH_DEV_ID_ADAPTIVE_X512_VF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E312_TY_CLOUD, ZXDH_DEV_ID_ADAPTIVE_E312_TY_CLOUD_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E312_TY_CLOUD, ZXDH_DEV_ID_ADAPTIVE_E312_TY_CLOUD_VF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E310_TY_CLOUD, ZXDH_DEV_ID_ADAPTIVE_E310_TY_CLOUD_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E310_TY_CLOUD, ZXDH_DEV_ID_ADAPTIVE_E310_TY_CLOUD_VF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E312S_D, ZXDH_DEV_ID_ADAPTIVE_E312S_D_PF),
	ZXDH_HCA(PCI_VENDOR_ID_ZXDH_E312S_D, ZXDH_DEV_ID_ADAPTIVE_E312S_D_VF),
	{}
};

/**
 * zxdh_ufree_context - free context that was allocated
 * @ibctx: context allocated ptr
 */
static void zxdh_ufree_context(struct ibv_context *ibctx)
{
	struct zxdh_uvcontext *iwvctx;

	iwvctx = container_of(ibctx, struct zxdh_uvcontext, ibv_ctx.context);

	zxdh_ufree_pd(&iwvctx->iwupd->ibv_pd);
	zxdh_munmap(iwvctx->sq_db);
	zxdh_munmap(iwvctx->cq_db);
	verbs_uninit_context(&iwvctx->ibv_ctx);
	free(iwvctx);
}

static const struct verbs_context_ops zxdh_uctx_ops = {
	.alloc_mw = zxdh_ualloc_mw,
	.alloc_pd = zxdh_ualloc_pd,
	.attach_mcast = zxdh_uattach_mcast,
	.bind_mw = zxdh_ubind_mw,
	.cq_event = zxdh_cq_event,
	.create_ah = zxdh_ucreate_ah,
	.create_cq = zxdh_ucreate_cq,
	.create_cq_ex = zxdh_ucreate_cq_ex,
	.create_qp = zxdh_ucreate_qp,
	.create_qp_ex = zxdh_ucreate_qp_ex,
	.create_srq = zxdh_ucreate_srq,
	.dealloc_mw = zxdh_udealloc_mw,
	.dealloc_pd = zxdh_ufree_pd,
	.dereg_mr = zxdh_udereg_mr,
	.destroy_ah = zxdh_udestroy_ah,
	.destroy_cq = zxdh_udestroy_cq,
	.modify_cq = zxdh_umodify_cq,
	.destroy_qp = zxdh_udestroy_qp,
	.destroy_srq = zxdh_udestroy_srq,
	.detach_mcast = zxdh_udetach_mcast,
	.modify_qp = zxdh_umodify_qp,
	.modify_srq = zxdh_umodify_srq,
	.poll_cq = zxdh_upoll_cq,
	.post_recv = zxdh_upost_recv,
	.post_send = zxdh_upost_send,
	.post_srq_recv = zxdh_upost_srq_recv,
	.query_device_ex = zxdh_uquery_device_ex,
	.query_port = zxdh_uquery_port,
	.query_qp = zxdh_uquery_qp,
	.query_srq = zxdh_uquery_srq,
	.reg_mr = zxdh_ureg_mr,
	.rereg_mr = zxdh_urereg_mr,
	.req_notify_cq = zxdh_uarm_cq,
	.resize_cq = zxdh_uresize_cq,
	.free_context = zxdh_ufree_context,
	.get_srq_num = zxdh_uget_srq_num,
};

/**
 * zxdh_ualloc_context - allocate context for user app
 * @ibdev: ib device created during zxdh_driver_init
 * @cmd_fd: save fd for the device
 * @private_data: device private data
 *
 * Returns callback routine table and calls driver for allocating
 * context and getting back resource information to return as ibv_context.
 */
static struct verbs_context *zxdh_ualloc_context(struct ibv_device *ibdev,
						 int cmd_fd, void *private_data)
{
	struct ibv_pd *ibv_pd;
	struct zxdh_uvcontext *iwvctx;
	struct zxdh_get_context cmd;
	struct zxdh_get_context_resp resp = {};
	__u64 sq_db_mmap_key, cq_db_mmap_key;

	iwvctx = verbs_init_and_alloc_context(ibdev, cmd_fd, iwvctx, ibv_ctx,
					      RDMA_DRIVER_ZXDH);
	if (!iwvctx)
		return NULL;

	zxdh_set_debug_mask();
	iwvctx->zxdh_write_imm_split_switch = zxdh_get_write_imm_split_switch();

	cmd.userspace_ver = ZXDH_CONTEXT_VER_V1;
	if (ibv_cmd_get_context(&iwvctx->ibv_ctx,
				(struct ibv_get_context *)&cmd, sizeof(cmd),
				NULL, &resp.ibv_resp, sizeof(resp)))
		goto err_free;

	verbs_set_ops(&iwvctx->ibv_ctx, &zxdh_uctx_ops);

	iwvctx->dev_attrs.feature_flags = resp.feature_flags;
	iwvctx->dev_attrs.max_hw_wq_frags = resp.max_hw_wq_frags;
	iwvctx->dev_attrs.max_hw_read_sges = resp.max_hw_read_sges;
	iwvctx->dev_attrs.max_hw_inline = resp.max_hw_inline;
	iwvctx->dev_attrs.max_hw_rq_quanta = resp.max_hw_rq_quanta;
	iwvctx->dev_attrs.max_hw_srq_quanta = resp.max_hw_srq_quanta;
	iwvctx->dev_attrs.max_hw_wq_quanta = resp.max_hw_wq_quanta;
	iwvctx->dev_attrs.max_hw_srq_wr = resp.max_hw_srq_wr;
	iwvctx->dev_attrs.max_hw_sq_chunk = resp.max_hw_sq_chunk;
	iwvctx->dev_attrs.max_hw_cq_size = resp.max_hw_cq_size;
	iwvctx->dev_attrs.min_hw_cq_size = resp.min_hw_cq_size;
	iwvctx->abi_ver = ZXDH_ABI_VER;
	iwvctx->dev_attrs.chip_rev = resp.chip_rev;
	iwvctx->dev_attrs.rdma_tool_flags = resp.rdma_tool_flags;

	sq_db_mmap_key = resp.sq_db_mmap_key;
	cq_db_mmap_key = resp.cq_db_mmap_key;

	iwvctx->dev_attrs.db_addr_type = resp.db_addr_type;
	iwvctx->dev_attrs.sq_db_pa = resp.sq_db_pa;
	iwvctx->dev_attrs.cq_db_pa = resp.cq_db_pa;

	if (iwvctx->dev_attrs.db_addr_type != ZXDH_DB_ADDR_BAR)
		goto err_free;

	iwvctx->sq_db = zxdh_mmap(cmd_fd, sq_db_mmap_key);
	if (iwvctx->sq_db == MAP_FAILED)
		goto err_free;

	iwvctx->cq_db = zxdh_mmap(cmd_fd, cq_db_mmap_key);
	if (iwvctx->cq_db == MAP_FAILED) {
		zxdh_munmap(iwvctx->sq_db);
		goto err_free;
	}
	ibv_pd = zxdh_ualloc_pd(&iwvctx->ibv_ctx.context);
	if (!ibv_pd) {
		zxdh_munmap(iwvctx->sq_db);
		zxdh_munmap(iwvctx->cq_db);
		goto err_free;
	}

	ibv_pd->context = &iwvctx->ibv_ctx.context;
	iwvctx->iwupd = container_of(ibv_pd, struct zxdh_upd, ibv_pd);
	add_private_ops(iwvctx);
	return &iwvctx->ibv_ctx;
err_free:
	free(iwvctx);
	return NULL;
}

static void zxdh_uninit_device(struct verbs_device *verbs_device)
{
	struct zxdh_udevice *dev;

	dev = container_of(&verbs_device->device, struct zxdh_udevice,
			   ibv_dev.device);
	free(dev);
}

static struct verbs_device *zxdh_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct zxdh_udevice *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->ibv_dev;
}

static const struct verbs_device_ops zxdh_udev_ops = {
	.alloc_context = zxdh_ualloc_context,
	.alloc_device = zxdh_device_alloc,
	.match_max_abi_version = ZXDH_MAX_ABI_VERSION,
	.match_min_abi_version = ZXDH_MIN_ABI_VERSION,
	.match_table = hca_table,
	.name = "zrdma",
	.uninit_device = zxdh_uninit_device,
};

PROVIDER_DRIVER(zrdma, zxdh_udev_ops);
