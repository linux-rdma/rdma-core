/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems.  All rights reserved.
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>

#include "mthca.h"
#include "mthca-abi.h"

static void mthca_free_context(struct ibv_context *ibctx);

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX			0x15b3
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_TAVOR
#define PCI_DEVICE_ID_MELLANOX_TAVOR		0x5a44
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_ARBEL_COMPAT
#define PCI_DEVICE_ID_MELLANOX_ARBEL_COMPAT	0x6278
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_ARBEL
#define PCI_DEVICE_ID_MELLANOX_ARBEL		0x6282
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_SINAI_OLD
#define PCI_DEVICE_ID_MELLANOX_SINAI_OLD	0x5e8c
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_SINAI
#define PCI_DEVICE_ID_MELLANOX_SINAI		0x6274
#endif

#ifndef PCI_VENDOR_ID_TOPSPIN
#define PCI_VENDOR_ID_TOPSPIN			0x1867
#endif

#define HCA(v, d, t)                                                           \
	VERBS_PCI_MATCH(PCI_VENDOR_ID_##v, PCI_DEVICE_ID_MELLANOX_##d,         \
			(void *)(MTHCA_##t))
static const struct verbs_match_ent hca_table[] = {
	HCA(MELLANOX, TAVOR,	    TAVOR),
	HCA(MELLANOX, ARBEL_COMPAT, TAVOR),
	HCA(MELLANOX, ARBEL,	    ARBEL),
	HCA(MELLANOX, SINAI_OLD,    ARBEL),
	HCA(MELLANOX, SINAI,	    ARBEL),
	HCA(TOPSPIN,  TAVOR,	    TAVOR),
	HCA(TOPSPIN,  ARBEL_COMPAT, TAVOR),
	HCA(TOPSPIN,  ARBEL,	    ARBEL),
	HCA(TOPSPIN,  SINAI_OLD,    ARBEL),
	HCA(TOPSPIN,  SINAI,	    ARBEL),
	{}
};

static const struct verbs_context_ops mthca_ctx_common_ops = {
	.query_device  = mthca_query_device,
	.query_port    = mthca_query_port,
	.alloc_pd      = mthca_alloc_pd,
	.dealloc_pd    = mthca_free_pd,
	.reg_mr        = mthca_reg_mr,
	.dereg_mr      = mthca_dereg_mr,
	.create_cq     = mthca_create_cq,
	.poll_cq       = mthca_poll_cq,
	.resize_cq     = mthca_resize_cq,
	.destroy_cq    = mthca_destroy_cq,
	.create_srq    = mthca_create_srq,
	.modify_srq    = mthca_modify_srq,
	.query_srq     = mthca_query_srq,
	.destroy_srq   = mthca_destroy_srq,
	.create_qp     = mthca_create_qp,
	.query_qp      = mthca_query_qp,
	.modify_qp     = mthca_modify_qp,
	.destroy_qp    = mthca_destroy_qp,
	.create_ah     = mthca_create_ah,
	.destroy_ah    = mthca_destroy_ah,
	.attach_mcast  = ibv_cmd_attach_mcast,
	.detach_mcast  = ibv_cmd_detach_mcast,
	.free_context = mthca_free_context,
};

static const struct verbs_context_ops mthca_ctx_arbel_ops = {
	.cq_event = mthca_arbel_cq_event,
	.post_recv = mthca_arbel_post_recv,
	.post_send = mthca_arbel_post_send,
	.post_srq_recv = mthca_arbel_post_srq_recv,
	.req_notify_cq = mthca_arbel_arm_cq,
};

static const struct verbs_context_ops mthca_ctx_tavor_ops = {
	.post_recv = mthca_tavor_post_recv,
	.post_send = mthca_tavor_post_send,
	.post_srq_recv = mthca_tavor_post_srq_recv,
	.req_notify_cq = mthca_tavor_arm_cq,
};

static struct verbs_context *mthca_alloc_context(struct ibv_device *ibdev,
						 int cmd_fd,
						 void *private_data)
{
	struct mthca_context            *context;
	struct ibv_get_context           cmd;
	struct umthca_alloc_ucontext_resp resp;
	int                              i;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_MTHCA);
	if (!context)
		return NULL;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp))
		goto err_free;

	context->num_qps        = resp.qp_tab_size;
	context->qp_table_shift = ffs(context->num_qps) - 1 - MTHCA_QP_TABLE_BITS;
	context->qp_table_mask  = (1 << context->qp_table_shift) - 1;

	if (mthca_is_memfree(&context->ibv_ctx.context)) {
		context->db_tab = mthca_alloc_db_tab(resp.uarc_size);
		if (!context->db_tab)
			goto err_free;
	} else
		context->db_tab = NULL;

	pthread_mutex_init(&context->qp_table_mutex, NULL);
	for (i = 0; i < MTHCA_QP_TABLE_SIZE; ++i)
		context->qp_table[i].refcnt = 0;

	context->uar = mmap(NULL, to_mdev(ibdev)->page_size, PROT_WRITE,
			    MAP_SHARED, cmd_fd, 0);
	if (context->uar == MAP_FAILED)
		goto err_db_tab;

	pthread_spin_init(&context->uar_lock, PTHREAD_PROCESS_PRIVATE);

	context->pd = mthca_alloc_pd(&context->ibv_ctx.context);
	if (!context->pd)
		goto err_unmap;

	context->pd->context = &context->ibv_ctx.context;

	verbs_set_ops(&context->ibv_ctx, &mthca_ctx_common_ops);
	if (mthca_is_memfree(&context->ibv_ctx.context))
		verbs_set_ops(&context->ibv_ctx, &mthca_ctx_arbel_ops);
	else
		verbs_set_ops(&context->ibv_ctx, &mthca_ctx_tavor_ops);

	return &context->ibv_ctx;

err_unmap:
	munmap(context->uar, to_mdev(ibdev)->page_size);

err_db_tab:
	mthca_free_db_tab(context->db_tab);

err_free:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void mthca_free_context(struct ibv_context *ibctx)
{
	struct mthca_context *context = to_mctx(ibctx);

	mthca_free_pd(context->pd);
	munmap(context->uar, to_mdev(ibctx->device)->page_size);
	mthca_free_db_tab(context->db_tab);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void mthca_uninit_device(struct verbs_device *verbs_device)
{
	struct mthca_device *dev = to_mdev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *
mthca_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct mthca_device    *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->hca_type    = (uintptr_t)sysfs_dev->match->driver_data;
	dev->page_size   = sysconf(_SC_PAGESIZE);

	return &dev->ibv_dev;
}

static const struct verbs_device_ops mthca_dev_ops = {
	.name = "mthca",
	.match_min_abi_version = 0,
	.match_max_abi_version = MTHCA_UVERBS_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = mthca_device_alloc,
	.uninit_device = mthca_uninit_device,
	.alloc_context = mthca_alloc_context,
};
PROVIDER_DRIVER(mthca, mthca_dev_ops);
