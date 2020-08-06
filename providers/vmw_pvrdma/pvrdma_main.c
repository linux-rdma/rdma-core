/*
 * Copyright (c) 2012-2016 VMware, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of EITHER the GNU General Public License
 * version 2 as published by the Free Software Foundation or the BSD
 * 2-Clause License. This program is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; WITHOUT EVEN THE IMPLIED
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License version 2 for more details at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program available in the file COPYING in the main
 * directory of this source tree.
 *
 * The BSD 2-Clause License
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "pvrdma.h"

static void pvrdma_free_context(struct ibv_context *ibctx);

/*
 * VMware PVRDMA vendor id and PCI device id.
 */
#define PCI_VENDOR_ID_VMWARE		0x15AD
#define PCI_DEVICE_ID_VMWARE_PVRDMA	0x0820

static const struct verbs_context_ops pvrdma_ctx_ops = {
	.free_context = pvrdma_free_context,
	.query_device = pvrdma_query_device,
	.query_port = pvrdma_query_port,
	.alloc_pd = pvrdma_alloc_pd,
	.dealloc_pd = pvrdma_free_pd,

	.reg_mr = pvrdma_reg_mr,
	.dereg_mr = pvrdma_dereg_mr,
	.create_cq = pvrdma_create_cq,
	.poll_cq = pvrdma_poll_cq,
	.req_notify_cq = pvrdma_req_notify_cq,
	.destroy_cq = pvrdma_destroy_cq,

	.create_qp = pvrdma_create_qp,
	.query_qp = pvrdma_query_qp,
	.modify_qp = pvrdma_modify_qp,
	.destroy_qp = pvrdma_destroy_qp,

	.create_srq = pvrdma_create_srq,
	.modify_srq = pvrdma_modify_srq,
	.query_srq = pvrdma_query_srq,
	.destroy_srq = pvrdma_destroy_srq,
	.post_srq_recv = pvrdma_post_srq_recv,

	.post_send = pvrdma_post_send,
	.post_recv = pvrdma_post_recv,
	.create_ah = pvrdma_create_ah,
	.destroy_ah = pvrdma_destroy_ah,
};

int pvrdma_alloc_buf(struct pvrdma_buf *buf, size_t size, int page_size)
{
	int ret;

	buf->length = align(size, page_size);
	buf->buf = mmap(NULL, buf->length, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf->buf == MAP_FAILED)
		return errno;

	ret = ibv_dontfork_range(buf->buf, size);
	if (ret)
		munmap(buf->buf, buf->length);

	return ret;
}

void pvrdma_free_buf(struct pvrdma_buf *buf)
{
	ibv_dofork_range(buf->buf, buf->length);
	munmap(buf->buf, buf->length);
}

static int pvrdma_init_context_shared(struct pvrdma_context *context,
				      struct ibv_device *ibdev,
				      int cmd_fd)
{
	struct ibv_get_context cmd;
	struct user_pvrdma_alloc_ucontext_resp resp;

	context->ibv_ctx.context.cmd_fd = cmd_fd;
	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp)))
		return errno;

	context->qp_tbl = calloc(resp.qp_tab_size & 0xFFFF,
				 sizeof(struct pvrdma_qp *));
	if (!context->qp_tbl)
		return -ENOMEM;

	context->uar = mmap(NULL, to_vdev(ibdev)->page_size, PROT_WRITE,
			    MAP_SHARED, cmd_fd, 0);
	if (context->uar == MAP_FAILED) {
		free(context->qp_tbl);
		return errno;
	}

	pthread_spin_init(&context->uar_lock, PTHREAD_PROCESS_PRIVATE);

	verbs_set_ops(&context->ibv_ctx, &pvrdma_ctx_ops);

	return 0;
}

static void pvrdma_free_context_shared(struct pvrdma_context *context,
				       struct pvrdma_device *dev)
{
	munmap(context->uar, dev->page_size);
	free(context->qp_tbl);
}

static struct verbs_context *pvrdma_alloc_context(struct ibv_device *ibdev,
						  int cmd_fd,
						  void *private_data)
{
	struct pvrdma_context *context;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_VMW_PVRDMA);
	if (!context)
		return NULL;

	if (pvrdma_init_context_shared(context, ibdev, cmd_fd)) {
		verbs_uninit_context(&context->ibv_ctx);
		free(context);
		return NULL;
	}

	return &context->ibv_ctx;
}

static void pvrdma_free_context(struct ibv_context *ibctx)
{
	struct pvrdma_context *context = to_vctx(ibctx);

	pvrdma_free_context_shared(context, to_vdev(ibctx->device));
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void pvrdma_uninit_device(struct verbs_device *verbs_device)
{
	struct pvrdma_device *dev = to_vdev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *
pvrdma_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct pvrdma_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->abi_version = sysfs_dev->abi_ver;
	dev->page_size   = sysconf(_SC_PAGESIZE);

	return &dev->ibv_dev;
}

static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_VMW_PVRDMA),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_VMWARE, PCI_DEVICE_ID_VMWARE_PVRDMA,
			NULL),
	{}
};

static const struct verbs_device_ops pvrdma_dev_ops = {
	.name = "pvrdma",
	.match_min_abi_version = PVRDMA_UVERBS_ABI_VERSION,
	.match_max_abi_version = PVRDMA_UVERBS_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = pvrdma_device_alloc,
	.uninit_device = pvrdma_uninit_device,
	.alloc_context = pvrdma_alloc_context,
};
PROVIDER_DRIVER(vmw_pvrdma, pvrdma_dev_ops);
