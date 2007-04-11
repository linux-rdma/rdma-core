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

#ifndef HAVE_IBV_READ_SYSFS_FILE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#include "mlx4.h"
#include "mlx4-abi.h"

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX			0x15b3
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_SDR
#define PCI_DEVICE_ID_MELLANOX_HERMON_SDR	0x6340
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_DDR
#define PCI_DEVICE_ID_MELLANOX_HERMON_DDR	0x634a
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_QDR
#define PCI_DEVICE_ID_MELLANOX_HERMON_QDR	0x6354
#endif

#define HCA(v, d) \
	{ .vendor = PCI_VENDOR_ID_##v,			\
	  .device = PCI_DEVICE_ID_MELLANOX_##d }

struct {
	unsigned		vendor;
	unsigned		device;
} hca_table[] = {
	HCA(MELLANOX, HERMON_SDR),
	HCA(MELLANOX, HERMON_DDR),
	HCA(MELLANOX, HERMON_QDR),
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
	.attach_mcast  = mlx4_attach_mcast,
	.detach_mcast  = mlx4_detach_mcast
};

static struct ibv_context *mlx4_alloc_context(struct ibv_device *ibdev, int cmd_fd)
{
	struct mlx4_context	       *context;
	struct ibv_get_context		cmd;
	struct mlx4_alloc_ucontext_resp resp;
	int				i;

	context = malloc(sizeof *context);
	if (!context)
		return NULL;

	context->ibv_ctx.cmd_fd = cmd_fd;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp))
		goto err_free;

	context->num_qps	= resp.qp_tab_size;
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
	free(context);
}

static struct ibv_device_ops mlx4_dev_ops = {
	.alloc_context = mlx4_alloc_context,
	.free_context  = mlx4_free_context
};

/*
 * Keep a private implementation of HAVE_IBV_READ_SYSFS_FILE to handle
 * old versions of libibverbs that didn't implement it.  This can be
 * removed when libibverbs 1.0.3 or newer is available "everywhere."
 */
#ifndef HAVE_IBV_READ_SYSFS_FILE
static int ibv_read_sysfs_file(const char *dir, const char *file,
			       char *buf, size_t size)
{
	char path[256];
	int fd;
	int len;

	snprintf(path, sizeof path, "%s/%s", dir, file);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, size);

	close(fd);

	if (len > 0 && buf[len - 1] == '\n')
		buf[--len] = '\0';

	return len;
}
#endif /* HAVE_IBV_READ_SYSFS_FILE */

static struct ibv_device *mlx4_driver_init(const char *uverbs_sys_path,
					    int abi_version)
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
	if (abi_version > MLX4_UVERBS_ABI_VERSION) {
		fprintf(stderr, PFX "Fatal: ABI version %d of %s is too new (expected %d)\n",
			abi_version, uverbs_sys_path, MLX4_UVERBS_ABI_VERSION);
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
	int abi_ver = 0;
	char value[8];

	if (ibv_read_sysfs_file(sysdev->path, "abi_version",
				value, sizeof value) > 0)
		abi_ver = strtol(value, NULL, 10);

	return mlx4_driver_init(sysdev->path, abi_ver);
}
#endif /* HAVE_IBV_REGISTER_DRIVER */
