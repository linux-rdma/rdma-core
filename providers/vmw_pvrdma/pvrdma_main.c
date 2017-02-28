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

/*
 * VMware PVRDMA vendor id and PCI device id.
 */
#define PCI_VENDOR_ID_VMWARE		0x15AD
#define PCI_DEVICE_ID_VMWARE_PVRDMA	0x0820

static struct ibv_context_ops pvrdma_ctx_ops = {
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

	context->ibv_ctx.cmd_fd = cmd_fd;
	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp)))
		return errno;

	context->qp_tbl = calloc(resp.udata.qp_tab_size & 0xFFFF,
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
	context->ibv_ctx.ops = pvrdma_ctx_ops;

	return 0;
}

static void pvrdma_free_context_shared(struct pvrdma_context *context,
				       struct pvrdma_device *dev)
{
	munmap(context->uar, dev->page_size);
	free(context->qp_tbl);
}

static struct ibv_context *pvrdma_alloc_context(struct ibv_device *ibdev,
						int cmd_fd)
{
	struct pvrdma_context *context;

	context = malloc(sizeof(*context));
	if (!context)
		return NULL;

	memset(context, 0, sizeof(*context));

	if (pvrdma_init_context_shared(context, ibdev, cmd_fd)) {
		free(context);
		return NULL;
	}

	return &context->ibv_ctx;
}

static void pvrdma_free_context(struct ibv_context *ibctx)
{
	struct pvrdma_context *context = to_vctx(ibctx);

	pvrdma_free_context_shared(context, to_vdev(ibctx->device));
	free(context);
}

static struct verbs_device_ops pvrdma_dev_ops = {
	.alloc_context = pvrdma_alloc_context,
	.free_context  = pvrdma_free_context
};

static struct pvrdma_device *pvrdma_driver_init_shared(
						const char *uverbs_sys_path,
						int abi_version)
{
	struct pvrdma_device *dev;
	char value[8];
	unsigned int vendor_id, device_id;

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/vendor",
				value, sizeof(value)) < 0)
		return NULL;
	vendor_id = strtol(value, NULL, 16);

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/device",
				value, sizeof(value)) < 0)
		return NULL;
	device_id = strtol(value, NULL, 16);

	if (vendor_id != PCI_VENDOR_ID_VMWARE ||
	    device_id != PCI_DEVICE_ID_VMWARE_PVRDMA)
		return NULL;

	/* We support only a single ABI version for now. */
	if (abi_version != PVRDMA_UVERBS_ABI_VERSION) {
		fprintf(stderr, PFX "ABI version %d of %s is not "
			"supported (supported %d)\n",
			abi_version, uverbs_sys_path,
			PVRDMA_UVERBS_ABI_VERSION);
		return NULL;
	}

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		fprintf(stderr, PFX "couldn't allocate device for %s\n",
			uverbs_sys_path);
		return NULL;
	}

	dev->abi_version = abi_version;
	dev->page_size   = sysconf(_SC_PAGESIZE);
	dev->ibv_dev.ops = &pvrdma_dev_ops;

	return dev;
}

static struct verbs_device *pvrdma_driver_init(const char *uverbs_sys_path,
					       int abi_version)
{
	struct pvrdma_device *dev = pvrdma_driver_init_shared(uverbs_sys_path,
							      abi_version);
	if (!dev)
		return NULL;

	return &dev->ibv_dev;
}

static __attribute__((constructor)) void pvrdma_register_driver(void)
{
	verbs_register_driver("pvrdma", pvrdma_driver_init);
}
