/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: Device detection and initializatoin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "main.h"
#include "verbs.h"

#define PCI_VENDOR_ID_BROADCOM		0x14E4

#define CNA(v, d)					\
	{	.vendor = PCI_VENDOR_ID_##v,		\
		.device = d }

static const struct {
	unsigned int vendor;
	unsigned int device;
} cna_table[] = {
	CNA(BROADCOM, 0x16C0),  /* BCM57417 NPAR */
	CNA(BROADCOM, 0x16CE),  /* BMC57311 */
	CNA(BROADCOM, 0x16CF),  /* BMC57312 */
	CNA(BROADCOM, 0x16DF),  /* BMC57314 */
	CNA(BROADCOM, 0x16E5),  /* BMC57314 VF */
	CNA(BROADCOM, 0x16E2),  /* BMC57417 */
	CNA(BROADCOM, 0x16E3),  /* BMC57416 */
	CNA(BROADCOM, 0x16D6),  /* BMC57412*/
	CNA(BROADCOM, 0x16D7),  /* BMC57414 */
	CNA(BROADCOM, 0x16D8),  /* BMC57416 Cu */
	CNA(BROADCOM, 0x16D9),  /* BMC57417 Cu */
	CNA(BROADCOM, 0x16C1),  /* BMC57414 VF */
	CNA(BROADCOM, 0x16EF),  /* BCM57416 NPAR */
	CNA(BROADCOM, 0x16ED),  /* BCM57414 NPAR */
	CNA(BROADCOM, 0x16EB)   /* BCM57412 NPAR */
};

static struct ibv_context_ops bnxt_re_cntx_ops = {
	.query_device  = bnxt_re_query_device,
	.query_port    = bnxt_re_query_port,
	.alloc_pd      = bnxt_re_alloc_pd,
	.dealloc_pd    = bnxt_re_free_pd,
	.reg_mr        = bnxt_re_reg_mr,
	.dereg_mr      = bnxt_re_dereg_mr,
	.create_cq     = bnxt_re_create_cq,
	.poll_cq       = bnxt_re_poll_cq,
	.req_notify_cq = bnxt_re_arm_cq,
	.cq_event      = bnxt_re_cq_event,
	.resize_cq     = bnxt_re_resize_cq,
	.destroy_cq    = bnxt_re_destroy_cq,
	.create_srq    = bnxt_re_create_srq,
	.modify_srq    = bnxt_re_modify_srq,
	.query_srq     = bnxt_re_query_srq,
	.destroy_srq   = bnxt_re_destroy_srq,
	.post_srq_recv = bnxt_re_post_srq_recv,
	.create_qp     = bnxt_re_create_qp,
	.query_qp      = bnxt_re_query_qp,
	.modify_qp     = bnxt_re_modify_qp,
	.destroy_qp    = bnxt_re_destroy_qp,
	.post_send     = bnxt_re_post_send,
	.post_recv     = bnxt_re_post_recv,
	.create_ah     = bnxt_re_create_ah,
	.destroy_ah    = bnxt_re_destroy_ah
};

/* Context Init functions */
static int bnxt_re_init_context(struct verbs_device *vdev,
				struct ibv_context *ibvctx, int cmd_fd)
{
	struct ibv_get_context cmd;
	struct bnxt_re_cntx_resp resp;
	struct bnxt_re_dev *dev;
	struct bnxt_re_context *cntx;

	dev = to_bnxt_re_dev(&vdev->device);
	cntx = to_bnxt_re_context(ibvctx);

	memset(&resp, 0, sizeof(resp));
	ibvctx->cmd_fd = cmd_fd;
	if (ibv_cmd_get_context(ibvctx, &cmd, sizeof(cmd),
				&resp.resp, sizeof(resp)))
		return errno;

	cntx->dev_id = resp.dev_id;
	cntx->max_qp = resp.max_qp;
	dev->pg_size = resp.pg_size;
	dev->cqe_size = resp.cqe_size;
	dev->max_cq_depth = resp.max_cqd;
	pthread_spin_init(&cntx->fqlock, PTHREAD_PROCESS_PRIVATE);
	ibvctx->ops = bnxt_re_cntx_ops;

	return 0;
}

static void bnxt_re_uninit_context(struct verbs_device *vdev,
				   struct ibv_context *ibvctx)
{
	struct bnxt_re_context *cntx;

	cntx = to_bnxt_re_context(ibvctx);
	/* Unmap if anything device specific was mapped in init_context. */
	pthread_spin_destroy(&cntx->fqlock);
}

static struct verbs_device_ops bnxt_re_dev_ops = {
	.init_context = bnxt_re_init_context,
	.uninit_context = bnxt_re_uninit_context,
};

static struct verbs_device *bnxt_re_driver_init(const char *uverbs_sys_path,
						int abi_version)
{
	char value[10];
	struct bnxt_re_dev *dev;
	unsigned int vendor, device;
	int i;

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/vendor",
				value, sizeof(value)) < 0)
		return NULL;
	vendor = strtol(value, NULL, 16);

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/device",
				value, sizeof(value)) < 0)
		return NULL;
	device = strtol(value, NULL, 16);

	for (i = 0; i < sizeof(cna_table) / sizeof(cna_table[0]); ++i)
		if (vendor == cna_table[i].vendor &&
		    device == cna_table[i].device)
			goto found;
	return NULL;
found:
	if (abi_version != BNXT_RE_ABI_VERSION) {
		fprintf(stderr, DEV "FATAL: Max supported ABI of %s is %d "
			"check for the latest version of kernel driver and"
			"user library\n", uverbs_sys_path, abi_version);
		return NULL;
	}

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		fprintf(stderr, DEV "Failed to allocate device for %s\n",
			uverbs_sys_path);
		return NULL;
	}

	dev->vdev.sz = sizeof(*dev);
	dev->vdev.size_of_context =
		sizeof(struct bnxt_re_context) - sizeof(struct ibv_context);
	dev->vdev.ops = &bnxt_re_dev_ops;

	return &dev->vdev;
}

static __attribute__((constructor)) void bnxt_re_register_driver(void)
{
	verbs_register_driver("bnxt_re", bnxt_re_driver_init);
}
