/*
 * Copyright (c) 2015-2016  QLogic Corporation
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
 *        disclaimer in the documentation and /or other materials
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "qelr.h"
#include "qelr_main.h"
#include "qelr_chain.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static void qelr_free_context(struct ibv_context *ibctx);

#define PCI_VENDOR_ID_QLOGIC           (0x1077)
#define PCI_DEVICE_ID_QLOGIC_57980S    (0x1629)
#define PCI_DEVICE_ID_QLOGIC_57980S_40 (0x1634)
#define PCI_DEVICE_ID_QLOGIC_57980S_10 (0x1666)
#define PCI_DEVICE_ID_QLOGIC_57980S_MF (0x1636)
#define PCI_DEVICE_ID_QLOGIC_57980S_100 (0x1644)
#define PCI_DEVICE_ID_QLOGIC_57980S_50  (0x1654)
#define PCI_DEVICE_ID_QLOGIC_57980S_25  (0x1656)
#define PCI_DEVICE_ID_QLOGIC_57980S_IOV (0x1664)
#define PCI_DEVICE_ID_QLOGIC_AH         (0x8070)
#define PCI_DEVICE_ID_QLOGIC_AH_IOV     (0x8090)

uint32_t qelr_dp_level;
uint32_t qelr_dp_module;

#define QHCA(d)                                                                \
	VERBS_PCI_MATCH(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_##d, NULL)
static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_QEDR),
	QHCA(57980S),
	QHCA(57980S_40),
	QHCA(57980S_10),
	QHCA(57980S_MF),
	QHCA(57980S_100),
	QHCA(57980S_50),
	QHCA(57980S_25),
	QHCA(57980S_IOV),
	QHCA(AH),
	QHCA(AH_IOV),
	{}
};

static const struct verbs_context_ops qelr_ctx_ops = {
	.query_device = qelr_query_device,
	.query_port = qelr_query_port,
	.alloc_pd = qelr_alloc_pd,
	.dealloc_pd = qelr_dealloc_pd,
	.reg_mr = qelr_reg_mr,
	.dereg_mr = qelr_dereg_mr,
	.create_cq = qelr_create_cq,
	.poll_cq = qelr_poll_cq,
	.req_notify_cq = qelr_arm_cq,
	.cq_event = qelr_cq_event,
	.destroy_cq = qelr_destroy_cq,
	.create_qp = qelr_create_qp,
	.query_qp = qelr_query_qp,
	.modify_qp = qelr_modify_qp,
	.destroy_qp = qelr_destroy_qp,
	.create_srq = qelr_create_srq,
	.destroy_srq = qelr_destroy_srq,
	.modify_srq = qelr_modify_srq,
	.query_srq = qelr_query_srq,
	.post_srq_recv = qelr_post_srq_recv,
	.post_send = qelr_post_send,
	.post_recv = qelr_post_recv,
	.async_event = qelr_async_event,
	.free_context = qelr_free_context,
};

static void qelr_uninit_device(struct verbs_device *verbs_device)
{
	struct qelr_device *dev = get_qelr_dev(&verbs_device->device);

	free(dev);
}

static void qelr_open_debug_file(struct qelr_devctx *ctx)
{
	char *env;

	env = getenv("QELR_DEBUG_FILE");
	if (!env) {
		ctx->dbg_fp = stderr;
		DP_VERBOSE(ctx->dbg_fp, QELR_MSG_INIT,
			   "Debug file opened: stderr\n");
		return;
	}

	ctx->dbg_fp = fopen(env, "aw+");
	if (!ctx->dbg_fp) {
		fprintf(stderr, "Failed opening debug file %s, using stderr\n",
			env);
		ctx->dbg_fp = stderr;
		DP_VERBOSE(ctx->dbg_fp, QELR_MSG_INIT,
			   "Debug file opened: stderr\n");
		return;
	}

	DP_VERBOSE(ctx->dbg_fp, QELR_MSG_INIT, "Debug file opened: %s\n", env);
}

static void qelr_close_debug_file(struct qelr_devctx *ctx)
{
	if (ctx->dbg_fp && ctx->dbg_fp != stderr)
		fclose(ctx->dbg_fp);
}

static void qelr_set_debug_mask(void)
{
	char *env;

	qelr_dp_level = QELR_LEVEL_NOTICE;
	qelr_dp_module = 0;

	env = getenv("QELR_DP_LEVEL");
	if (env)
		qelr_dp_level = atoi(env);

	env = getenv("QELR_DP_MODULE");
	if (env)
		qelr_dp_module = atoi(env);
}

static struct verbs_context *qelr_alloc_context(struct ibv_device *ibdev,
						int cmd_fd,
						void *private_data)
{
	struct qelr_devctx *ctx;
	struct qelr_alloc_context cmd;
	struct qelr_alloc_context_resp resp;

	ctx = verbs_init_and_alloc_context(ibdev, cmd_fd, ctx, ibv_ctx,
					   RDMA_DRIVER_QEDR);
	if (!ctx)
		return NULL;

	memset(&resp, 0, sizeof(resp));

	qelr_open_debug_file(ctx);
	qelr_set_debug_mask();

	cmd.context_flags |= QEDR_ALLOC_UCTX_DB_REC;
	if (ibv_cmd_get_context(&ctx->ibv_ctx, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp)))
		goto cmd_err;

	verbs_set_ops(&ctx->ibv_ctx, &qelr_ctx_ops);

	ctx->kernel_page_size = sysconf(_SC_PAGESIZE);
	ctx->db_pa = resp.db_pa;
	ctx->db_size = resp.db_size;

	/* Set dpm flags according to protocol */
	if (IS_ROCE(ibdev)) {
		if (resp.dpm_flags & QEDR_DPM_TYPE_ROCE_ENHANCED)
			ctx->dpm_flags = QELR_DPM_FLAGS_ENHANCED;

		if (resp.dpm_flags & QEDR_DPM_TYPE_ROCE_LEGACY)
			ctx->dpm_flags |= QELR_DPM_FLAGS_LEGACY;
	} else {
		if (resp.dpm_flags & QEDR_DPM_TYPE_IWARP_LEGACY)
			ctx->dpm_flags = QELR_DPM_FLAGS_LEGACY;
	}

	/* Defaults set for backward-forward compatibility */
	if (resp.dpm_flags & QEDR_DPM_SIZES_SET) {
		ctx->ldpm_limit_size = resp.ldpm_limit_size;
		ctx->edpm_trans_size = resp.edpm_trans_size;
	} else {
		ctx->ldpm_limit_size = QEDR_LDPM_MAX_SIZE;
		ctx->edpm_trans_size = QEDR_EDPM_TRANS_SIZE;
	}

	ctx->max_send_wr = resp.max_send_wr;
	ctx->max_recv_wr = resp.max_recv_wr;
	ctx->max_srq_wr = resp.max_srq_wr;
	ctx->sges_per_send_wr = resp.sges_per_send_wr;
	ctx->sges_per_recv_wr = resp.sges_per_recv_wr;
	ctx->sges_per_srq_wr = resp.sges_per_recv_wr;
	ctx->max_cqes = resp.max_cqes;

	ctx->db_addr = mmap(NULL, ctx->db_size, PROT_WRITE, MAP_SHARED,
			    cmd_fd, ctx->db_pa);

	if (ctx->db_addr == MAP_FAILED) {
		int errsv = errno;

		DP_ERR(ctx->dbg_fp,
		       "alloc context: doorbell mapping failed resp.db_pa = %llx resp.db_size=%d context->cmd_fd=%d errno=%d\n",
		       resp.db_pa, resp.db_size, cmd_fd, errsv);
		goto cmd_err;
	}

	return &ctx->ibv_ctx;

cmd_err:
	qelr_err("%s: Failed to allocate context for device.\n", __func__);
	qelr_close_debug_file(ctx);
	verbs_uninit_context(&ctx->ibv_ctx);
	free(ctx);
	return NULL;
}

static void qelr_free_context(struct ibv_context *ibctx)
{
	struct qelr_devctx *ctx = get_qelr_ctx(ibctx);

	if (ctx->db_addr)
		munmap(ctx->db_addr, ctx->db_size);

	qelr_close_debug_file(ctx);
	verbs_uninit_context(&ctx->ibv_ctx);
	free(ctx);
}

static struct verbs_device *qelr_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct qelr_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->ibv_dev;
}

static const struct verbs_device_ops qelr_dev_ops = {
	.name = "qedr",
	.match_min_abi_version = QELR_ABI_VERSION,
	.match_max_abi_version = QELR_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = qelr_device_alloc,
	.uninit_device = qelr_uninit_device,
	.alloc_context = qelr_alloc_context,
};
PROVIDER_DRIVER(qedr, qelr_dev_ops);
