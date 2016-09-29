/*
 * Copyright (C) 2008-2013 Emulex.  All rights reserved.
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "ocrdma_main.h"
#include "ocrdma_abi.h"
#include "ocrdma_list.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PCI_VENDOR_ID_EMULEX		0x10DF
#define PCI_DEVICE_ID_EMULEX_GEN1	0xe220
#define PCI_DEVICE_ID_EMULEX_GEN2        0x720
#define PCI_DEVICE_ID_EMULEX_GEN2_VF     0x728

#define UCNA(v, d)                            \
	{ .vendor = PCI_VENDOR_ID_##v,        \
	  .device = PCI_DEVICE_ID_EMULEX_##d }

struct {
	unsigned vendor;
	unsigned device;
} ucna_table[] = {
	UCNA(EMULEX, GEN1), UCNA(EMULEX, GEN2), UCNA(EMULEX, GEN2_VF)
};

static DBLY_LIST_HEAD(ocrdma_dev_list);

static struct ibv_context *ocrdma_alloc_context(struct ibv_device *, int);
static void ocrdma_free_context(struct ibv_context *);

static struct ibv_context_ops ocrdma_ctx_ops = {
	.query_device = ocrdma_query_device,
	.query_port = ocrdma_query_port,
	.alloc_pd = ocrdma_alloc_pd,
	.dealloc_pd = ocrdma_free_pd,
	.reg_mr = ocrdma_reg_mr,
	.dereg_mr = ocrdma_dereg_mr,
	.create_cq = ocrdma_create_cq,
	.poll_cq = ocrdma_poll_cq,
	.req_notify_cq = ocrdma_arm_cq,
	.resize_cq = ocrdma_resize_cq,
	.destroy_cq = ocrdma_destroy_cq,

	.create_qp = ocrdma_create_qp,
	.query_qp = ocrdma_query_qp,
	.modify_qp = ocrdma_modify_qp,
	.destroy_qp = ocrdma_destroy_qp,
	.post_send = ocrdma_post_send,
	.post_recv = ocrdma_post_recv,
	.create_ah = ocrdma_create_ah,
	.destroy_ah = ocrdma_destroy_ah,

	.create_srq = ocrdma_create_srq,
	.modify_srq = ocrdma_modify_srq,
	.query_srq = ocrdma_query_srq,
	.destroy_srq = ocrdma_destroy_srq,
	.post_srq_recv = ocrdma_post_srq_recv,
	.attach_mcast = ocrdma_attach_mcast,
	.detach_mcast = ocrdma_detach_mcast
};

static struct ibv_device_ops ocrdma_dev_ops = {
	.alloc_context = ocrdma_alloc_context,
	.free_context = ocrdma_free_context
};

/*
 * ocrdma_alloc_context
 */
static struct ibv_context *ocrdma_alloc_context(struct ibv_device *ibdev,
						int cmd_fd)
{
	struct ocrdma_devctx *ctx;
	struct ocrdma_get_context cmd;
	struct ocrdma_alloc_ucontext_resp resp;

	ctx = calloc(1, sizeof(struct ocrdma_devctx));
	if (!ctx)
		return NULL;
	memset(&resp, 0, sizeof(resp));

	ctx->ibv_ctx.cmd_fd = cmd_fd;

	if (ibv_cmd_get_context(&ctx->ibv_ctx,
				(struct ibv_get_context *)&cmd, sizeof cmd,
				&resp.ibv_resp, sizeof(resp)))
		goto cmd_err;

	ctx->ibv_ctx.device = ibdev;
	ctx->ibv_ctx.ops = ocrdma_ctx_ops;
	get_ocrdma_dev(ibdev)->id = resp.dev_id;
	get_ocrdma_dev(ibdev)->max_inline_data = resp.max_inline_data;
	get_ocrdma_dev(ibdev)->wqe_size = resp.wqe_size;
	get_ocrdma_dev(ibdev)->rqe_size = resp.rqe_size;
	memcpy(get_ocrdma_dev(ibdev)->fw_ver, resp.fw_ver, sizeof(resp.fw_ver));
	get_ocrdma_dev(ibdev)->dpp_wqe_size = resp.dpp_wqe_size;

	ctx->ah_tbl =
	    mmap(NULL, resp.ah_tbl_len, PROT_READ | PROT_WRITE, MAP_SHARED,
		 cmd_fd, resp.ah_tbl_page);

	if (ctx->ah_tbl == MAP_FAILED)
		goto cmd_err;
	ctx->ah_tbl_len = resp.ah_tbl_len;
	ocrdma_init_ahid_tbl(ctx);

	return &ctx->ibv_ctx;

cmd_err:
	ocrdma_err("%s: Failed to allocate context for device.\n", __func__);
	free(ctx);
	return NULL;
}

/*
 * ocrdma_free_context
 */
static void ocrdma_free_context(struct ibv_context *ibctx)
{
	struct ocrdma_devctx *ctx = get_ocrdma_ctx(ibctx);

	if (ctx->ah_tbl)
		munmap((void *)ctx->ah_tbl, ctx->ah_tbl_len);

	free(ctx);
}

/**
 * ocrdma_driver_init
 */
struct ibv_device *ocrdma_driver_init(const char *uverbs_sys_path,
				      int abi_version)
{

	char value[16];
	struct ocrdma_device *dev;
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

	for (i = 0; i < sizeof ucna_table / sizeof ucna_table[0]; ++i) {
		if (vendor == ucna_table[i].vendor &&
		    device == ucna_table[i].device)
			goto found;
	}
	return NULL;
found:
	if (abi_version != OCRDMA_ABI_VERSION) {
		fprintf(stderr,
		  "Fatal: libocrdma ABI version %d of %s is not supported.\n",
		  abi_version, uverbs_sys_path);
		return NULL;
	}

	dev = malloc(sizeof *dev);
	if (!dev) {
		ocrdma_err("%s() Fatal: fail allocate device for libocrdma\n",
			   __func__);
		return NULL;
	}
	bzero(dev, sizeof *dev);
	dev->qp_tbl = malloc(OCRDMA_MAX_QP * sizeof(struct ocrdma_qp *));
	if (!dev->qp_tbl)
		goto qp_err;
	bzero(dev->qp_tbl, OCRDMA_MAX_QP * sizeof(struct ocrdma_qp *));
	pthread_mutex_init(&dev->dev_lock, NULL);
	pthread_spin_init(&dev->flush_q_lock, PTHREAD_PROCESS_PRIVATE);
	dev->ibv_dev.ops = ocrdma_dev_ops;
	INIT_DBLY_LIST_NODE(&dev->entry);
	list_lock(&ocrdma_dev_list);
	list_add_node_tail(&dev->entry, &ocrdma_dev_list);
	list_unlock(&ocrdma_dev_list);
	return &dev->ibv_dev;
qp_err:
	free(dev);
	return NULL;
}

/*
 * ocrdma_register_driver
 */
static __attribute__ ((constructor))
void ocrdma_register_driver(void)
{
	ibv_register_driver("ocrdma", ocrdma_driver_init);
}

static __attribute__ ((destructor))
void ocrdma_unregister_driver(void)
{
	struct ocrdma_list_node *cur, *tmp;
	struct ocrdma_device *dev;
	list_lock(&ocrdma_dev_list);
	list_for_each_node_safe(cur, tmp, &ocrdma_dev_list) {
		dev = list_node(cur, struct ocrdma_device, entry);
		pthread_mutex_destroy(&dev->dev_lock);
		pthread_spin_destroy(&dev->flush_q_lock);
		list_del_node(&dev->entry);
		/*
		 * Avoid freeing the dev here since MPI get SIGSEGV
		 * in few error cases because of reference to ib_dev
		 * after free.
		 * TODO Bug 135437 fix it properly to avoid mem leak
		 */
		/* free(dev); */
	}
	list_unlock(&ocrdma_dev_list);
}
