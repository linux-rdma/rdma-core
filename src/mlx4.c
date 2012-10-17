/*
 * Copyright (c) 2007 Cisco, Inc.  All rights reserved.
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
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>

#ifndef HAVE_IBV_REGISTER_DRIVER
#include <sysfs/libsysfs.h>
#endif

#include "mlx4.h"
#include "mlx4-abi.h"

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX			0x15b3
#endif

#define HCA(v, d) \
	{ .vendor = PCI_VENDOR_ID_##v,			\
	  .device = d }

struct {
	unsigned		vendor;
	unsigned		device;
} hca_table[] = {
	HCA(MELLANOX, 0x6340),	/* MT25408 "Hermon" SDR */
	HCA(MELLANOX, 0x634a),	/* MT25408 "Hermon" DDR */
	HCA(MELLANOX, 0x6354),	/* MT25408 "Hermon" QDR */
	HCA(MELLANOX, 0x6732),	/* MT25408 "Hermon" DDR PCIe gen2 */
	HCA(MELLANOX, 0x673c),	/* MT25408 "Hermon" QDR PCIe gen2 */
	HCA(MELLANOX, 0x6368),	/* MT25408 "Hermon" EN 10GigE */
	HCA(MELLANOX, 0x6750),	/* MT25408 "Hermon" EN 10GigE PCIe gen2 */
	HCA(MELLANOX, 0x6372),	/* MT25458 ConnectX EN 10GBASE-T 10GigE */
	HCA(MELLANOX, 0x675a),	/* MT25458 ConnectX EN 10GBASE-T+Gen2 10GigE */
	HCA(MELLANOX, 0x6764),	/* MT26468 ConnectX EN 10GigE PCIe gen2*/
	HCA(MELLANOX, 0x6746),	/* MT26438 ConnectX EN 40GigE PCIe gen2 5GT/s */
	HCA(MELLANOX, 0x676e),	/* MT26478 ConnectX2 40GigE PCIe gen2 */
	HCA(MELLANOX, 0x1002),	/* MT25400 Family [ConnectX-2 Virtual Function] */
	HCA(MELLANOX, 0x1003),	/* MT27500 Family [ConnectX-3] */
	HCA(MELLANOX, 0x1004),	/* MT27500 Family [ConnectX-3 Virtual Function] */
	HCA(MELLANOX, 0x1005),	/* MT27510 Family */
	HCA(MELLANOX, 0x1006),	/* MT27511 Family */
	HCA(MELLANOX, 0x1007),	/* MT27520 Family */
	HCA(MELLANOX, 0x1008),	/* MT27521 Family */
	HCA(MELLANOX, 0x1009),	/* MT27530 Family */
	HCA(MELLANOX, 0x100a),	/* MT27531 Family */
	HCA(MELLANOX, 0x100b),	/* MT27540 Family */
	HCA(MELLANOX, 0x100c),	/* MT27541 Family */
	HCA(MELLANOX, 0x100d),	/* MT27550 Family */
	HCA(MELLANOX, 0x100e),	/* MT27551 Family */
	HCA(MELLANOX, 0x100f),	/* MT27560 Family */
	HCA(MELLANOX, 0x1010),	/* MT27561 Family */
};

static struct ibv_context_ops mlx4_ctx_ops = {
	.query_device  = mlx4_query_device,
	.query_port    = mlx4_query_port,
	.alloc_pd      = mlx4_alloc_pd,
	.dealloc_pd    = mlx4_free_pd,
	.reg_mr	       = mlx4_reg_mr,
	.dereg_mr      = mlx4_dereg_mr,
	.create_cq     = mlx4_create_cq,
	.poll_cq       = mlx4_poll_cq,
	.req_notify_cq = mlx4_arm_cq,
	.cq_event      = mlx4_cq_event,
	.resize_cq     = mlx4_resize_cq,
	.destroy_cq    = mlx4_destroy_cq,
	.create_srq    = mlx4_create_srq,
	.modify_srq    = mlx4_modify_srq,
	.query_srq     = mlx4_query_srq,
	.destroy_srq   = mlx4_destroy_srq,
	.post_srq_recv = mlx4_post_srq_recv,
	.create_qp     = mlx4_create_qp,
	.query_qp      = mlx4_query_qp,
	.modify_qp     = mlx4_modify_qp,
	.destroy_qp    = mlx4_destroy_qp,
	.post_send     = mlx4_post_send,
	.post_recv     = mlx4_post_recv,
	.create_ah     = mlx4_create_ah,
	.destroy_ah    = mlx4_destroy_ah,
	.attach_mcast  = ibv_cmd_attach_mcast,
	.detach_mcast  = ibv_cmd_detach_mcast
};

static struct ibv_context *mlx4_alloc_context(struct ibv_device *ibdev, int cmd_fd)
{
	struct mlx4_context	       *context;
	struct ibv_get_context		cmd;
	struct mlx4_alloc_ucontext_resp resp;
	int				i;
	struct mlx4_alloc_ucontext_resp_v3 resp_v3;
	__u16				bf_reg_size;
	struct mlx4_device		*dev = to_mdev(ibdev);

	context = calloc(1, sizeof *context);
	if (!context)
		return NULL;

	context->ibv_ctx.cmd_fd = cmd_fd;

	if (dev->abi_version <= MLX4_UVERBS_NO_DEV_CAPS_ABI_VERSION) {
		if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof cmd,
					&resp_v3.ibv_resp, sizeof resp_v3))
			goto err_free;

		context->num_qps  = resp_v3.qp_tab_size;
		bf_reg_size	  = resp_v3.bf_reg_size;
		context->cqe_size = sizeof (struct mlx4_cqe);
	} else  {
		if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof cmd,
					&resp.ibv_resp, sizeof resp))
			goto err_free;

		context->num_qps  = resp.qp_tab_size;
		bf_reg_size	  = resp.bf_reg_size;
		if (resp.dev_caps & MLX4_USER_DEV_CAP_64B_CQE)
			context->cqe_size = resp.cqe_size;
		else
			context->cqe_size = sizeof (struct mlx4_cqe);
	}

	context->qp_table_shift = ffs(context->num_qps) - 1 - MLX4_QP_TABLE_BITS;
	context->qp_table_mask	= (1 << context->qp_table_shift) - 1;

	pthread_mutex_init(&context->qp_table_mutex, NULL);
	for (i = 0; i < MLX4_QP_TABLE_SIZE; ++i)
		context->qp_table[i].refcnt = 0;

	for (i = 0; i < MLX4_NUM_DB_TYPE; ++i)
		context->db_list[i] = NULL;

	pthread_mutex_init(&context->db_list_mutex, NULL);

	context->uar = mmap(NULL, to_mdev(ibdev)->page_size, PROT_WRITE,
			    MAP_SHARED, cmd_fd, 0);
	if (context->uar == MAP_FAILED)
		goto err_free;

	if (bf_reg_size) {
		context->bf_page = mmap(NULL, to_mdev(ibdev)->page_size,
					PROT_WRITE, MAP_SHARED, cmd_fd,
					to_mdev(ibdev)->page_size);
		if (context->bf_page == MAP_FAILED) {
			fprintf(stderr, PFX "Warning: BlueFlame available, "
				"but failed to mmap() BlueFlame page.\n");
				context->bf_page     = NULL;
				context->bf_buf_size = 0;
		} else {
			context->bf_buf_size = bf_reg_size / 2;
			context->bf_offset   = 0;
			pthread_spin_init(&context->bf_lock, PTHREAD_PROCESS_PRIVATE);
		}
	} else {
		context->bf_page     = NULL;
		context->bf_buf_size = 0;
	}

	pthread_spin_init(&context->uar_lock, PTHREAD_PROCESS_PRIVATE);

	context->ibv_ctx.ops = mlx4_ctx_ops;

	return &context->ibv_ctx;

err_free:
	free(context);
	return NULL;
}

static void mlx4_free_context(struct ibv_context *ibctx)
{
	struct mlx4_context *context = to_mctx(ibctx);

	munmap(context->uar, to_mdev(ibctx->device)->page_size);
	if (context->bf_page)
		munmap(context->bf_page, to_mdev(ibctx->device)->page_size);
	free(context);
}

static struct ibv_device_ops mlx4_dev_ops = {
	.alloc_context = mlx4_alloc_context,
	.free_context  = mlx4_free_context
};

static struct ibv_device *mlx4_driver_init(const char *uverbs_sys_path, int abi_version)
{
	char			value[8];
	struct mlx4_device    *dev;
	unsigned		vendor, device;
	int			i;

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
	if (abi_version < MLX4_UVERBS_MIN_ABI_VERSION ||
	    abi_version > MLX4_UVERBS_MAX_ABI_VERSION) {
		fprintf(stderr, PFX "Fatal: ABI version %d of %s is not supported "
			"(min supported %d, max supported %d)\n",
			abi_version, uverbs_sys_path,
			MLX4_UVERBS_MIN_ABI_VERSION,
			MLX4_UVERBS_MAX_ABI_VERSION);
		return NULL;
	}

	dev = malloc(sizeof *dev);
	if (!dev) {
		fprintf(stderr, PFX "Fatal: couldn't allocate device for %s\n",
			uverbs_sys_path);
		return NULL;
	}

	dev->ibv_dev.ops = mlx4_dev_ops;
	dev->page_size   = sysconf(_SC_PAGESIZE);
	dev->abi_version = abi_version;

	return &dev->ibv_dev;
}

#ifdef HAVE_IBV_REGISTER_DRIVER
static __attribute__((constructor)) void mlx4_register_driver(void)
{
	ibv_register_driver("mlx4", mlx4_driver_init);
}
#else
/*
 * Export the old libsysfs sysfs_class_device-based driver entry point
 * if libibverbs does not export an ibv_register_driver() function.
 */
struct ibv_device *openib_driver_init(struct sysfs_class_device *sysdev)
{
	int abi_version = 0;
	char value[8];

	if (ibv_read_sysfs_file(sysdev->path, "abi_version",
				value, sizeof value) > 0)
		abi_ver = strtol(value, NULL, 10);

	return mlx4_driver_init(sysdev->path, abi_version);
}
#endif /* HAVE_IBV_REGISTER_DRIVER */
