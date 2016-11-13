/*
 * Copyright (c) 2016 Hisilicon Limited.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "hns_roce_u.h"
#include "hns_roce_u_abi.h"

#define HID_LEN			15
#define DEV_MATCH_LEN		128

static const struct {
	char	 hid[HID_LEN];
} acpi_table[] = {
	{"acpi:HISI00D1:"},
	{},
};

static const struct {
	char	 compatible[DEV_MATCH_LEN];
} dt_table[] = {
	{"hisilicon,hns-roce-v1"},
	{},
};

static struct ibv_context *hns_roce_alloc_context(struct ibv_device *ibdev,
						  int cmd_fd)
{
	int i;
	struct ibv_get_context cmd;
	struct ibv_device_attr dev_attrs;
	struct hns_roce_context *context;
	struct hns_roce_alloc_ucontext_resp resp;
	struct hns_roce_device *hr_dev = to_hr_dev(ibdev);

	context = calloc(1, sizeof(*context));
	if (!context)
		return NULL;

	context->ibv_ctx.cmd_fd = cmd_fd;
	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp)))
		goto err_free;

	context->num_qps = resp.qp_tab_size;
	context->qp_table_shift = ffs(context->num_qps) - 1 -
				  HNS_ROCE_QP_TABLE_BITS;
	context->qp_table_mask = (1 << context->qp_table_shift) - 1;

	pthread_mutex_init(&context->qp_table_mutex, NULL);
	for (i = 0; i < HNS_ROCE_QP_TABLE_SIZE; ++i)
		context->qp_table[i].refcnt = 0;

	context->uar = mmap(NULL, to_hr_dev(ibdev)->page_size,
			    PROT_READ | PROT_WRITE, MAP_SHARED, cmd_fd, 0);
	if (context->uar == MAP_FAILED) {
		fprintf(stderr, PFX "Warning: failed to mmap() uar page.\n");
		goto err_free;
	}

	pthread_spin_init(&context->uar_lock, PTHREAD_PROCESS_PRIVATE);

	context->max_qp_wr = dev_attrs.max_qp_wr;
	context->max_sge = dev_attrs.max_sge;
	context->max_cqe = dev_attrs.max_cqe;

	return &context->ibv_ctx;

err_free:
	free(context);
	return NULL;
}

static void hns_roce_free_context(struct ibv_context *ibctx)
{
	struct hns_roce_context *context = to_hr_ctx(ibctx);

	munmap(context->uar, to_hr_dev(ibctx->device)->page_size);

	context->uar = NULL;

	free(context);
	context = NULL;
}

static struct ibv_device_ops hns_roce_dev_ops = {
	.alloc_context = hns_roce_alloc_context,
	.free_context	= hns_roce_free_context
};

static struct ibv_device *hns_roce_driver_init(const char *uverbs_sys_path,
					       int abi_version)
{
	struct hns_roce_device  *dev;
	char			 value[128];
	int			 i;

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/modalias",
				value, sizeof(value)) > 0)
		for (i = 0; i < sizeof(acpi_table) / sizeof(acpi_table[0]); ++i)
			if (!strcmp(value, acpi_table[i].hid))
				goto found;

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/of_node/compatible",
				value, sizeof(value)) > 0)
		for (i = 0; i < sizeof(dt_table) / sizeof(dt_table[0]); ++i)
			if (!strcmp(value, dt_table[i].compatible))
				goto found;

	return NULL;

found:
	dev = malloc(sizeof(struct hns_roce_device));
	if (!dev) {
		fprintf(stderr, PFX "Fatal: couldn't allocate device for %s\n",
			uverbs_sys_path);
		return NULL;
	}

	dev->ibv_dev.ops = hns_roce_dev_ops;
	dev->page_size   = sysconf(_SC_PAGESIZE);
	return &dev->ibv_dev;
}

static __attribute__((constructor)) void hns_roce_register_driver(void)
{
	ibv_register_driver("hns", hns_roce_driver_init);
}
