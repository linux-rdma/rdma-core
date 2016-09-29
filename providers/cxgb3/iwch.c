/*
 * Copyright (c) 2006-2007 Chelsio, Inc. All rights reserved.
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
#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>

#include "iwch.h"
#include "iwch-abi.h"

#define PCI_VENDOR_ID_CHELSIO		0x1425
#define PCI_DEVICE_ID_CHELSIO_PE9000_2C	0x0020
#define PCI_DEVICE_ID_CHELSIO_T302E	0x0021
#define PCI_DEVICE_ID_CHELSIO_T310E	0x0022
#define PCI_DEVICE_ID_CHELSIO_T320X	0x0023
#define PCI_DEVICE_ID_CHELSIO_T302X	0x0024
#define PCI_DEVICE_ID_CHELSIO_T320E	0x0025
#define PCI_DEVICE_ID_CHELSIO_T310X	0x0026
#define PCI_DEVICE_ID_CHELSIO_T3B10	0x0030
#define PCI_DEVICE_ID_CHELSIO_T3B20	0x0031
#define PCI_DEVICE_ID_CHELSIO_T3B02	0x0032
#define PCI_DEVICE_ID_CHELSIO_T3C20	0x0035
#define PCI_DEVICE_ID_CHELSIO_S320E	0x0036

#define HCA(v, d, t) \
	{ .vendor = PCI_VENDOR_ID_##v,			\
	  .device = PCI_DEVICE_ID_CHELSIO_##d,		\
	  .type = CHELSIO_##t }

struct {
	unsigned vendor;
	unsigned device;
	enum iwch_hca_type type;
} hca_table[] = {
	HCA(CHELSIO, PE9000_2C, T3B),
	HCA(CHELSIO, T302E, T3A),
	HCA(CHELSIO, T302X, T3A),
	HCA(CHELSIO, T310E, T3A),
	HCA(CHELSIO, T310X, T3A),
	HCA(CHELSIO, T320E, T3A),
	HCA(CHELSIO, T320X, T3A),
	HCA(CHELSIO, T3B10, T3B),
	HCA(CHELSIO, T3B20, T3B),
	HCA(CHELSIO, T3B02, T3B),
	HCA(CHELSIO, T3C20, T3B),
	HCA(CHELSIO, S320E, T3B),
};

static struct ibv_context_ops iwch_ctx_ops = {
	.query_device = iwch_query_device,
	.query_port = iwch_query_port,
	.alloc_pd = iwch_alloc_pd,
	.dealloc_pd = iwch_free_pd,
	.reg_mr = iwch_reg_mr,
	.dereg_mr = iwch_dereg_mr,
	.create_cq = iwch_create_cq,
	.resize_cq = iwch_resize_cq,
	.destroy_cq = iwch_destroy_cq,
	.create_srq = iwch_create_srq,
	.modify_srq = iwch_modify_srq,
	.destroy_srq = iwch_destroy_srq,
	.create_qp = iwch_create_qp,
	.modify_qp = iwch_modify_qp,
	.destroy_qp = iwch_destroy_qp,
	.query_qp = iwch_query_qp,
	.create_ah = iwch_create_ah,
	.destroy_ah = iwch_destroy_ah,
	.attach_mcast = iwch_attach_mcast,
	.detach_mcast = iwch_detach_mcast,
	.post_srq_recv = iwch_post_srq_recv,
	.req_notify_cq = iwch_arm_cq,
};

static struct ibv_context *iwch_alloc_context(struct ibv_device *ibdev,
					      int cmd_fd)
{
	struct iwch_context *context;
	struct ibv_get_context cmd;
	struct iwch_alloc_ucontext_resp resp;
	struct iwch_device *rhp = to_iwch_dev(ibdev);

	context = malloc(sizeof *context);
	if (!context)
		return NULL;

	memset(context, 0, sizeof *context);
	context->ibv_ctx.cmd_fd = cmd_fd;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp))
		goto err_free;

	context->ibv_ctx.device = ibdev;
	context->ibv_ctx.ops = iwch_ctx_ops;

	switch (rhp->hca_type) {
	case CHELSIO_T3B:
		PDBG("%s T3B device\n", __FUNCTION__);
		context->ibv_ctx.ops.async_event = t3b_async_event;
		context->ibv_ctx.ops.post_send = t3b_post_send;
		context->ibv_ctx.ops.post_recv = t3b_post_recv;
		context->ibv_ctx.ops.poll_cq = t3b_poll_cq;
		break;
	case CHELSIO_T3A:
		PDBG("%s T3A device\n", __FUNCTION__);
		context->ibv_ctx.ops.async_event = NULL;
		context->ibv_ctx.ops.post_send = t3a_post_send;
		context->ibv_ctx.ops.post_recv = t3a_post_recv;
		context->ibv_ctx.ops.poll_cq = t3a_poll_cq;
		break;
	default:
		PDBG("%s unknown hca type %d\n", __FUNCTION__, rhp->hca_type);
		goto err_free;
		break;
	}	

	return &context->ibv_ctx;

err_free:
	free(context);
	return NULL;
}

static void iwch_free_context(struct ibv_context *ibctx)
{
	struct iwch_context *context = to_iwch_ctx(ibctx);

	free(context);
}

static struct ibv_device_ops iwch_dev_ops = {
	.alloc_context = iwch_alloc_context,
	.free_context = iwch_free_context
};

static struct ibv_device *cxgb3_driver_init(const char *uverbs_sys_path,
					    int abi_version)
{
	char devstr[IBV_SYSFS_PATH_MAX], ibdev[16], value[32], *cp;
	struct iwch_device *dev;
	unsigned vendor, device, fw_maj, fw_min;
	int i;

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

	/* 
	 * Verify that the firmware major number matches.  Major number
	 * mismatches are fatal.  Minor number mismatches are tolerated.
	 */
	if (ibv_read_sysfs_file(uverbs_sys_path, "ibdev", 
				ibdev, sizeof ibdev) < 0)
		return NULL;

	memset(devstr, 0, sizeof devstr);
	snprintf(devstr, sizeof devstr, "%s/class/infiniband/%s", 
		 ibv_get_sysfs_path(), ibdev);
	if (ibv_read_sysfs_file(devstr, "fw_ver", value, sizeof value) < 0)
		return NULL;

	cp = strtok(value+1, ".");
	sscanf(cp, "%i", &fw_maj);
	cp = strtok(NULL, ".");
	sscanf(cp, "%i", &fw_min);

	if (fw_maj < FW_MAJ) {
		fprintf(stderr, "libcxgb3: Fatal firmware version mismatch.  "
			"Firmware major number is %u and libcxgb3 needs %u.\n",
			fw_maj, FW_MAJ);	
		fflush(stderr);
		return NULL;
	}

	DBGLOG("libcxgb3");

	if ((signed int)fw_min < FW_MIN) {
		PDBG("libcxgb3: non-fatal firmware version mismatch.  "
			"Firmware minor number is %u and libcxgb3 needs %u.\n",
			fw_min, FW_MIN);
		fflush(stderr);
	}

	if (abi_version > ABI_VERS) {
		PDBG("libcxgb3: ABI version mismatch.  "
			"Kernel driver ABI is %u and libcxgb3 needs <= %u.\n",
			abi_version, ABI_VERS);	
		fflush(stderr);
		return NULL;
	}

	PDBG("%s found vendor %d device %d type %d\n", 
	     __FUNCTION__, vendor, device, hca_table[i].type);

	dev = malloc(sizeof *dev);
	if (!dev) {
		return NULL;
	}

	pthread_spin_init(&dev->lock, PTHREAD_PROCESS_PRIVATE);
	dev->ibv_dev.ops = iwch_dev_ops;
	dev->hca_type = hca_table[i].type;
	dev->abi_version = abi_version;

	iwch_page_size = sysconf(_SC_PAGESIZE);
	iwch_page_shift = long_log2(iwch_page_size);
	iwch_page_mask = iwch_page_size - 1;

	dev->mmid2ptr = calloc(T3_MAX_NUM_STAG, sizeof(void *));
	if (!dev->mmid2ptr) {
		goto err1;
	}
	dev->qpid2ptr = calloc(T3_MAX_NUM_QP, sizeof(void *)); 
	if (!dev->qpid2ptr) {
		goto err2;
	}
	dev->cqid2ptr = calloc(T3_MAX_NUM_CQ, sizeof(void *));
	if (!dev->cqid2ptr) 
		goto err3;

	return &dev->ibv_dev;

err3:
	free(dev->qpid2ptr);
err2:
	free(dev->mmid2ptr);
err1:
	free(dev);
	return NULL;
}

static __attribute__((constructor)) void cxgb3_register_driver(void)
{
	ibv_register_driver("cxgb3", cxgb3_driver_init);
}
