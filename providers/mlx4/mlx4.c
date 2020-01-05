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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>

#include "mlx4.h"
#include "mlx4-abi.h"

static void mlx4_free_context(struct ibv_context *ibv_ctx);

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX			0x15b3
#endif

#define HCA(v, d) VERBS_PCI_MATCH(PCI_VENDOR_ID_##v, d, NULL)
static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_MLX4),
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
	VERBS_MODALIAS_MATCH("vmbus:3daf2e8ca732094bab99bd1f1c86b501", NULL), /* Microsoft Azure Network Direct */
	{}
};

static const struct verbs_context_ops mlx4_ctx_ops = {
	.query_device  = mlx4_query_device,
	.query_port    = mlx4_query_port,
	.alloc_pd      = mlx4_alloc_pd,
	.dealloc_pd    = mlx4_free_pd,
	.reg_mr	       = mlx4_reg_mr,
	.rereg_mr      = mlx4_rereg_mr,
	.dereg_mr      = mlx4_dereg_mr,
	.alloc_mw      = mlx4_alloc_mw,
	.dealloc_mw    = mlx4_dealloc_mw,
	.bind_mw       = mlx4_bind_mw,
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
	.detach_mcast  = ibv_cmd_detach_mcast,

	.close_xrcd = mlx4_close_xrcd,
	.create_cq_ex = mlx4_create_cq_ex,
	.create_flow = mlx4_create_flow,
	.create_qp_ex = mlx4_create_qp_ex,
	.create_rwq_ind_table = mlx4_create_rwq_ind_table,
	.create_srq_ex = mlx4_create_srq_ex,
	.create_wq = mlx4_create_wq,
	.destroy_flow = mlx4_destroy_flow,
	.destroy_rwq_ind_table = mlx4_destroy_rwq_ind_table,
	.destroy_wq = mlx4_destroy_wq,
	.get_srq_num = verbs_get_srq_num,
	.modify_cq = mlx4_modify_cq,
	.modify_wq = mlx4_modify_wq,
	.open_qp = mlx4_open_qp,
	.open_xrcd = mlx4_open_xrcd,
	.query_device_ex = mlx4_query_device_ex,
	.query_rt_values = mlx4_query_rt_values,
	.free_context = mlx4_free_context,
};

static int mlx4_map_internal_clock(struct mlx4_device *mdev,
				   struct ibv_context *ibv_ctx)
{
	struct mlx4_context *context = to_mctx(ibv_ctx);
	void *hca_clock_page;

	hca_clock_page = mmap(NULL, mdev->page_size,
			      PROT_READ, MAP_SHARED, ibv_ctx->cmd_fd,
			      mdev->page_size * 3);

	if (hca_clock_page == MAP_FAILED) {
		fprintf(stderr, PFX
			"Warning: Timestamp available,\n"
			"but failed to mmap() hca core clock page.\n");
		return -1;
	}

	context->hca_core_clock = hca_clock_page +
		(context->core_clock.offset & (mdev->page_size - 1));
	return 0;
}

static struct verbs_context *mlx4_alloc_context(struct ibv_device *ibdev,
						  int cmd_fd,
						  void *private_data)
{
	struct mlx4_context	       *context;
	struct ibv_get_context		cmd;
	struct mlx4_alloc_ucontext_resp resp;
	int				i;
	struct mlx4_alloc_ucontext_v3_resp resp_v3;
	__u16				bf_reg_size;
	struct mlx4_device              *dev = to_mdev(ibdev);
	struct verbs_context		*verbs_ctx;
	struct ibv_device_attr_ex	dev_attrs;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_MLX4);
	if (!context)
		return NULL;

	verbs_ctx = &context->ibv_ctx;

	if (dev->abi_version <= MLX4_UVERBS_NO_DEV_CAPS_ABI_VERSION) {
		if (ibv_cmd_get_context(verbs_ctx, &cmd, sizeof(cmd),
					&resp_v3.ibv_resp, sizeof(resp_v3)))
			goto failed;

		context->num_qps  = resp_v3.qp_tab_size;
		bf_reg_size	  = resp_v3.bf_reg_size;
		context->cqe_size = sizeof (struct mlx4_cqe);
	} else  {
		if (ibv_cmd_get_context(verbs_ctx, &cmd, sizeof(cmd),
					&resp.ibv_resp, sizeof(resp)))
			goto failed;

		context->num_qps  = resp.qp_tab_size;
		bf_reg_size	  = resp.bf_reg_size;
		if (resp.dev_caps & MLX4_USER_DEV_CAP_LARGE_CQE)
			context->cqe_size = resp.cqe_size;
		else
			context->cqe_size = sizeof (struct mlx4_cqe);
	}

	context->qp_table_shift = ffs(context->num_qps) - 1 - MLX4_QP_TABLE_BITS;
	context->qp_table_mask	= (1 << context->qp_table_shift) - 1;
	for (i = 0; i < MLX4_PORTS_NUM; ++i)
		context->port_query_cache[i].valid = 0;

	pthread_mutex_init(&context->qp_table_mutex, NULL);
	for (i = 0; i < MLX4_QP_TABLE_SIZE; ++i)
		context->qp_table[i].refcnt = 0;

	for (i = 0; i < MLX4_NUM_DB_TYPE; ++i)
		context->db_list[i] = NULL;

	mlx4_init_xsrq_table(&context->xsrq_table, context->num_qps);
	pthread_mutex_init(&context->db_list_mutex, NULL);

	context->uar_mmap_offset = 0;
	context->uar = mmap(NULL, dev->page_size, PROT_WRITE,
			    MAP_SHARED, cmd_fd, context->uar_mmap_offset);
	if (context->uar == MAP_FAILED)
		goto failed;

	if (bf_reg_size) {
		context->bf_page = mmap(NULL, dev->page_size,
					PROT_WRITE, MAP_SHARED, cmd_fd,
					dev->page_size);
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

	verbs_set_ops(verbs_ctx, &mlx4_ctx_ops);

	context->hca_core_clock = NULL;
	memset(&dev_attrs, 0, sizeof(dev_attrs));
	if (!mlx4_query_device_ex(&verbs_ctx->context, NULL, &dev_attrs,
				  sizeof(struct ibv_device_attr_ex))) {
		context->max_qp_wr = dev_attrs.orig_attr.max_qp_wr;
		context->max_sge = dev_attrs.orig_attr.max_sge;
		if (context->core_clock.offset_valid)
			mlx4_map_internal_clock(dev, &verbs_ctx->context);
	}

	return verbs_ctx;

failed:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void mlx4_free_context(struct ibv_context *ibv_ctx)
{
	struct mlx4_context *context = to_mctx(ibv_ctx);
	struct mlx4_device *mdev = to_mdev(ibv_ctx->device);

	munmap(context->uar, mdev->page_size);
	if (context->bf_page)
		munmap(context->bf_page, mdev->page_size);
	if (context->hca_core_clock)
		munmap(context->hca_core_clock - context->core_clock.offset,
		       mdev->page_size);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void mlx4_uninit_device(struct verbs_device *verbs_device)
{
	struct mlx4_device *dev = to_mdev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *mlx4_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct mlx4_device *dev;

	dev = calloc(1, sizeof *dev);
	if (!dev)
		return NULL;

	dev->page_size   = sysconf(_SC_PAGESIZE);
	dev->abi_version = sysfs_dev->abi_ver;

	return &dev->verbs_dev;
}

static const struct verbs_device_ops mlx4_dev_ops = {
	.name = "mlx4",
	.match_min_abi_version = MLX4_UVERBS_MIN_ABI_VERSION,
	.match_max_abi_version = MLX4_UVERBS_MAX_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = mlx4_device_alloc,
	.uninit_device = mlx4_uninit_device,
	.alloc_context = mlx4_alloc_context,
};
PROVIDER_DRIVER(mlx4, mlx4_dev_ops);

static int mlx4dv_get_qp(struct ibv_qp *qp_in,
			 struct mlx4dv_qp *qp_out)
{
	struct mlx4_qp *mqp = to_mqp(qp_in);
	struct mlx4_context *ctx = to_mctx(qp_in->context);
	uint64_t mask_out = 0;

	qp_out->buf.buf = mqp->buf.buf;
	qp_out->buf.length = mqp->buf.length;

	qp_out->rdb = mqp->db;
	qp_out->sdb = (uint32_t *) (ctx->uar + MLX4_SEND_DOORBELL);
	qp_out->doorbell_qpn = mqp->doorbell_qpn;

	qp_out->sq.wqe_cnt = mqp->sq.wqe_cnt;
	qp_out->sq.wqe_shift = mqp->sq.wqe_shift;
	qp_out->sq.offset = mqp->sq.offset;

	qp_out->rq.wqe_cnt = mqp->rq.wqe_cnt;
	qp_out->rq.wqe_shift = mqp->rq.wqe_shift;
	qp_out->rq.offset = mqp->rq.offset;

	if (qp_out->comp_mask & MLX4DV_QP_MASK_UAR_MMAP_OFFSET) {
		qp_out->uar_mmap_offset = ctx->uar_mmap_offset;
		mask_out |= MLX4DV_QP_MASK_UAR_MMAP_OFFSET;
	}

	qp_out->comp_mask = mask_out;

	return 0;
}

static int mlx4dv_get_cq(struct ibv_cq *cq_in,
			 struct mlx4dv_cq *cq_out)
{
	struct mlx4_cq *mcq = to_mcq(cq_in);
	struct mlx4_context *mctx = to_mctx(cq_in->context);
	uint64_t mask_out = 0;

	cq_out->buf.buf = mcq->buf.buf;
	cq_out->buf.length = mcq->buf.length;
	cq_out->cqn = mcq->cqn;
	cq_out->set_ci_db = mcq->set_ci_db;
	cq_out->arm_db = mcq->arm_db;
	cq_out->arm_sn = mcq->arm_sn;
	cq_out->cqe_size = mcq->cqe_size;
	cq_out->cqe_cnt = mcq->ibv_cq.cqe + 1;

	mcq->flags |= MLX4_CQ_FLAGS_DV_OWNED;

	if (cq_out->comp_mask & MLX4DV_CQ_MASK_UAR) {
		cq_out->cq_uar = mctx->uar;
		mask_out |= MLX4DV_CQ_MASK_UAR;
	}

	cq_out->comp_mask = mask_out;
	return 0;
}

static int mlx4dv_get_srq(struct ibv_srq *srq_in,
			  struct mlx4dv_srq *srq_out)
{
	struct mlx4_srq *msrq = to_msrq(srq_in);

	srq_out->comp_mask = 0;
	srq_out->buf.buf = msrq->buf.buf;
	srq_out->buf.length = msrq->buf.length;
	srq_out->wqe_shift = msrq->wqe_shift;
	srq_out->head = msrq->head;
	srq_out->tail = msrq->tail;
	srq_out->db = msrq->db;

	return 0;
}

static int mlx4dv_get_rwq(struct ibv_wq *wq_in, struct mlx4dv_rwq *wq_out)
{
	struct mlx4_qp *mqp = wq_to_mqp(wq_in);

	wq_out->comp_mask = 0;

	wq_out->buf.buf = mqp->buf.buf;
	wq_out->buf.length = mqp->buf.length;

	wq_out->rdb = mqp->db;

	wq_out->rq.wqe_cnt = mqp->rq.wqe_cnt;
	wq_out->rq.wqe_shift = mqp->rq.wqe_shift;
	wq_out->rq.offset = mqp->rq.offset;

	return 0;
}

int mlx4dv_init_obj(struct mlx4dv_obj *obj, uint64_t obj_type)
{
	int ret = 0;

	if (obj_type & MLX4DV_OBJ_QP)
		ret = mlx4dv_get_qp(obj->qp.in, obj->qp.out);
	if (!ret && (obj_type & MLX4DV_OBJ_CQ))
		ret = mlx4dv_get_cq(obj->cq.in, obj->cq.out);
	if (!ret && (obj_type & MLX4DV_OBJ_SRQ))
		ret = mlx4dv_get_srq(obj->srq.in, obj->srq.out);
	if (!ret && (obj_type & MLX4DV_OBJ_RWQ))
		ret = mlx4dv_get_rwq(obj->rwq.in, obj->rwq.out);

	return ret;
}

int mlx4dv_query_device(struct ibv_context *ctx_in,
			struct mlx4dv_context *attrs_out)
{
	struct mlx4_context *mctx = to_mctx(ctx_in);

	attrs_out->version   = 0;
	attrs_out->comp_mask = 0;

	attrs_out->max_inl_recv_sz = mctx->max_inl_recv_sz;

	return 0;
}

int mlx4dv_set_context_attr(struct ibv_context *context,
			    enum mlx4dv_set_ctx_attr_type attr_type,
			    void *attr)
{
	struct mlx4_context *ctx = to_mctx(context);

	switch (attr_type) {
	case MLX4DV_SET_CTX_ATTR_LOG_WQS_RANGE_SZ:
		ctx->log_wqs_range_sz = *((uint8_t *)attr);
		break;
	case MLX4DV_SET_CTX_ATTR_BUF_ALLOCATORS:
		ctx->extern_alloc = *((struct mlx4dv_ctx_allocators *)attr);
		break;
	default:
		return ENOTSUP;
	}

	return 0;
}
