// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <ccan/array_size.h>

#include <util/compiler.h>
#include <util/mmio.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <infiniband/cmd_write.h>

#include "xscale.h"
#include "xsc-abi.h"
#include "xsc_hw.h"
#include "xsc_api.h"

int xsc_single_threaded;

int xsc_query_port(struct ibv_context *context, uint8_t port,
		   struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

struct ibv_pd *xsc_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct xsc_alloc_pd_resp resp;
	struct xsc_pd *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd, sizeof(cmd),
			&resp.ibv_resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}

	atomic_init(&pd->refcount, 1);
	pd->pdn = resp.pdn;
	xsc_dbg(to_xctx(context)->dbg_fp, XSC_DBG_PD, "pd number:%u\n", pd->pdn);

	return &pd->ibv_pd;
}

int xsc_free_pd(struct ibv_pd *pd)
{
	int ret;
	struct xsc_pd *xpd = to_xpd(pd);

	if (atomic_load(&xpd->refcount) > 1)
		return EBUSY;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	xsc_dbg(to_xctx(pd->context)->dbg_fp, XSC_DBG_PD, "dealloc pd\n");
	free(xpd);

	return 0;
}

struct ibv_mr *xsc_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			  uint64_t hca_va, int acc)
{
	struct xsc_mr *mr;
	struct ibv_reg_mr cmd;
	int ret;
	enum ibv_access_flags access = (enum ibv_access_flags)acc;
	struct ib_uverbs_reg_mr_resp resp;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access,
			     &mr->vmr, &cmd, sizeof(cmd), &resp,
			     sizeof(resp));
	if (ret) {
		free(mr);
		return NULL;
	}
	mr->alloc_flags = acc;

	xsc_dbg(to_xctx(pd->context)->dbg_fp, XSC_DBG_MR, "lkey:%u, rkey:%u\n",
			mr->vmr.ibv_mr.lkey, mr->vmr.ibv_mr.rkey);

	return &mr->vmr.ibv_mr;
}

struct ibv_mr *xsc_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset, size_t length,
				 uint64_t iova, int fd, int acc)
{
	struct xsc_mr *mr;
	int ret;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	ret = ibv_cmd_reg_dmabuf_mr(pd, offset, length, iova, fd, acc,
				    &mr->vmr, NULL);
	if (ret) {
		free(mr);
		return NULL;
	}
	mr->alloc_flags = acc;

	return &mr->vmr.ibv_mr;
}

int xsc_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	if (vmr->mr_type == IBV_MR_TYPE_NULL_MR)
		goto free;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

free:
	free(vmr);
	return 0;
}

static int xsc_round_up_power_of_two(long long sz)
{
	long long ret;

	for (ret = 1; ret < sz; ret <<= 1)
		; /* nothing */

	if (ret > INT_MAX) {
		fprintf(stderr, "%s: roundup overflow\n", __func__);
		return -ENOMEM;
	}

	return (int)ret;
}

static int align_queue_size(long long req)
{
	return xsc_round_up_power_of_two(req);
}

enum {
	CREATE_CQ_SUPPORTED_WC_FLAGS = IBV_WC_STANDARD_FLAGS		|
				       IBV_WC_EX_WITH_COMPLETION_TIMESTAMP
};

enum {
	CREATE_CQ_SUPPORTED_COMP_MASK = IBV_CQ_INIT_ATTR_MASK_FLAGS
};

enum {
	CREATE_CQ_SUPPORTED_FLAGS =
		IBV_CREATE_CQ_ATTR_SINGLE_THREADED |
		IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN
};

static int xsc_cqe_depth_check(void)
{
	char *e;

	e = getenv("XSC_CQE_DEPTH_CHECK");
	if (e && !strcmp(e, "n"))
		return 0;

	return 1;
}

static void init_cqe(struct xsc_context *xctx, struct xsc_buf *buf, int ncqe, int cqe_sz)
{
	int i;

	if (buf->type != XSC_ALLOC_TYPE_GPU) {
		for (i = 0; i < ncqe; i++) {
			struct xsc_cqe *cqe = (struct xsc_cqe *)(buf->buf + i * cqe_sz);

			cqe->data3 |= FIELD_PREP(XSC_CQE_OWNER_MASK, 1);
		}
	} else {
		xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "cq buff is given by gpu,do nothing in host.\n");
	}
}

static struct ibv_cq_ex *create_cq(struct ibv_context *context,
				   const struct ibv_cq_init_attr_ex *cq_attr,
				   int cq_alloc_flags,
				   struct xscdv_cq_init_attr *xcq_attr,
				   struct xscdv_devx_umem_in *umem_in)
{
	struct xsc_create_cq		cmd = {};
	struct xsc_create_cq_resp	resp = {};
	struct xsc_create_cq_ex	cmd_ex = {};
	struct xsc_create_cq_ex_resp	resp_ex = {};
	struct xsc_ib_create_cq       *cmd_drv;
	struct xsc_ib_create_cq_resp  *resp_drv;
	struct xsc_cq		       *cq;
	int				cqe_sz;
	int				ret;
	int				ncqe;
	struct xsc_context *xctx = to_xctx(context);
	bool				use_ex = false;
	char *env;

	if (!cq_attr->cqe) {
		xsc_err("CQE invalid\n");
		errno = EINVAL;
		return NULL;
	}

	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "CQE number:%u\n", cq_attr->cqe);

	if (cq_attr->comp_mask & ~CREATE_CQ_SUPPORTED_COMP_MASK) {
		xsc_err("Unsupported comp_mask for create cq\n");
		errno = EINVAL;
		return NULL;
	}

	if (cq_attr->comp_mask & IBV_CQ_INIT_ATTR_MASK_FLAGS &&
			cq_attr->flags & ~CREATE_CQ_SUPPORTED_FLAGS) {
		xsc_err("Unsupported creation flags requested for create cq\n");
		errno = EINVAL;
		return NULL;
	}

	if (cq_attr->wc_flags & ~CREATE_CQ_SUPPORTED_WC_FLAGS) {
		xsc_err("unsupported wc flags:0x%lx\n", cq_attr->wc_flags);
		errno = ENOTSUP;
		return NULL;
	}

	cq = calloc(1, sizeof(*cq));
	if (!cq) {
		xsc_err("Alloc CQ failed\n");
		errno = ENOMEM;
		return NULL;
	}

	if (cq_attr->comp_mask & IBV_CQ_INIT_ATTR_MASK_FLAGS) {
		if (cq_attr->flags & IBV_CREATE_CQ_ATTR_SINGLE_THREADED)
			cq->flags |= XSC_CQ_FLAGS_SINGLE_THREADED;
		if (cq_attr->flags & IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN)
			use_ex = true;
	}

	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "use_ex:%u\n", use_ex);

	cmd_drv = use_ex ? &cmd_ex.drv_payload : &cmd.drv_payload;
	resp_drv = use_ex ? &resp_ex.drv_payload : &resp.drv_payload;

	cq->cons_index = 0;

	if (xsc_spinlock_init(&cq->lock, !xsc_single_threaded))
		goto err;

	ncqe = align_queue_size(cq_attr->cqe);
	if (ncqe < XSC_CQE_RING_DEPTH_MIN) {
		xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "CQE ring size %u is not enough, set it as %u\n",
			ncqe, XSC_CQE_RING_DEPTH_MIN);
		ncqe = XSC_CQE_RING_DEPTH_MIN;
	}

	if (ncqe > xctx->max_cqe) {
		if (xsc_cqe_depth_check()) {
			xsc_err("CQE ring size %u exceeds CQE ring depth %u, abort!\n",
				ncqe, xctx->max_cqe);
			errno = EINVAL;
			goto err_spl;
		} else {
			xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "CQE ring size %u exceeds the MAX ring szie, set it as %u\n",
				ncqe, xctx->max_cqe);
			ncqe = xctx->max_cqe;
		}
	}

	cqe_sz = (xctx->hw_feature_flag & XSC_HW_FEATURE_FLAG_SUPPORT_CQE64) ?
		XSC_CQE_SIZE64 : XSC_CQE_SIZE;
	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "CQE number:%u, size:%u\n", ncqe, cqe_sz);

	if (xsc_alloc_cq_buf(to_xctx(context), cq, &cq->buf_a, ncqe, cqe_sz, umem_in)) {
		xsc_err("Alloc cq buffer failed.\n");
		errno = ENOMEM;
		goto err_spl;
	}

	cq->arm_sn			= 0;
	cq->cqe_sz			= cqe_sz;
	cq->flags			= cq_alloc_flags;

	cmd_drv->buf_addr = (uintptr_t) cq->buf_a.buf;
	cmd_drv->db_addr = (uintptr_t) cq->dbrec;
	cmd_drv->cqe_size = cqe_sz;

	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "buf_addr:%p\n", cq->buf_a.buf);

	if (cq_alloc_flags & XSC_CQ_FLAGS_EXTENDED)
		xsc_cq_fill_pfns(cq, cq_attr);

	if (cq->buf_a.type == XSC_ALLOC_TYPE_GPU) {
		cq->flags |= XSC_CQ_FLAGS_OWNED_BY_GPU;
		cmd_drv->dmabuf_fd = umem_in->dmabuf_fd;
		cmd_drv->dmabuf_sz = umem_in->size;
		xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "cq_buf %p, buffer size:0x%lx, dmabuf_fd:%d\n",
			umem_in->addr, umem_in->size, umem_in->dmabuf_fd);
	} else {
		cmd_drv->dmabuf_fd = -1;
		cmd_drv->dmabuf_sz = 0;
	}

	if (use_ex) {
		struct ibv_cq_init_attr_ex cq_attr_ex = *cq_attr;

		cq_attr_ex.cqe = ncqe;
		ret = ibv_cmd_create_cq_ex(context, &cq_attr_ex, NULL,
					   &cq->verbs_cq,
					   &cmd_ex.ibv_cmd, sizeof(cmd_ex),
					   &resp_ex.ibv_resp, sizeof(resp_ex),
					   0);
	} else {
		ret = ibv_cmd_create_cq(context, ncqe, cq_attr->channel,
					cq_attr->comp_vector,
					ibv_cq_ex_to_cq(&cq->verbs_cq.cq_ex),
					&cmd.ibv_cmd, sizeof(cmd),
					&resp.ibv_resp, sizeof(resp));
	}

	if (ret) {
		xsc_err("ibv_cmd_create_cq failed,ret %d\n", ret);
		goto err_buf;
	}

	cq->active_buf = &cq->buf_a;
	cq->resize_buf = NULL;
	cq->cqn = resp_drv->cqn;
	cq->stall_enable = to_xctx(context)->stall_enable;
	cq->stall_adaptive_enable = to_xctx(context)->stall_adaptive_enable;
	cq->stall_cycles = to_xctx(context)->stall_cycles;

	cq->db = xctx->cqm_reg_va +
		(xctx->cqm_next_cid_reg & (xctx->page_size - 1));
	cq->armdb = xctx->cqm_armdb_va +
		(xctx->cqm_armdb & (xctx->page_size - 1));
	cq->cqe_cnt = ncqe;
	cq->log2_cq_ring_sz = xsc_ilog2(ncqe);

	init_cqe(xctx, &cq->buf_a, ncqe, cqe_sz);

	env = getenv("XSC_DISABLE_FLUSH_ERROR");
	cq->disable_flush_error_cqe = env ? true : false;
	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "cqe count:%u cqn:%u cq_buf:%p cq_buf_sz:0x%lx dmabuf_fd:%d\n",
		cq->cqe_cnt, cq->cqn, cq->buf_a.buf, cq->buf_a.length,
		umem_in ? umem_in->dmabuf_fd : -1);
	list_head_init(&cq->err_state_qp_list);
	return &cq->verbs_cq.cq_ex;


err_buf:
	xsc_free_cq_buf(to_xctx(context), &cq->buf_a);

err_spl:
	xsc_spinlock_destroy(&cq->lock);

err:
	free(cq);

	return NULL;
}

struct ibv_cq *xsc_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel,
			      int comp_vector)
{
	struct ibv_cq_ex *cq;
	struct ibv_cq_init_attr_ex cq_attr = {.cqe = cqe, .channel = channel,
						.comp_vector = comp_vector,
						.wc_flags = IBV_WC_STANDARD_FLAGS};

	if (cqe <= 0) {
		errno = EINVAL;
		return NULL;
	}

	cq = create_cq(context, &cq_attr, 0, NULL, NULL);
	return cq ? ibv_cq_ex_to_cq(cq) : NULL;
}

struct ibv_cq_ex *xsc_create_cq_ex(struct ibv_context *context,
				    struct ibv_cq_init_attr_ex *cq_attr)
{
	return create_cq(context, cq_attr, XSC_CQ_FLAGS_EXTENDED, NULL, NULL);
}

int xsc_resize_cq(struct ibv_cq *ibcq, int cqe)
{
	struct xsc_cq *cq = to_xcq(ibcq);

	if (cqe < 0) {
		errno = EINVAL;
		return errno;
	}

	xsc_spin_lock(&cq->lock);
	cq->active_cqes = cq->verbs_cq.cq_ex.cqe;
	/* currently we don't change cqe size */
	cq->resize_cqe_sz = cq->cqe_sz;
	cq->resize_cqes = cq->verbs_cq.cq_ex.cqe;
	xsc_spin_unlock(&cq->lock);
	cq->resize_buf = NULL;
	return 0;
}

int xsc_destroy_cq(struct ibv_cq *cq)
{
	int ret;
	struct xsc_err_state_qp_node *tmp, *err_qp_node;

	xsc_dbg(to_xctx(cq->context)->dbg_fp, XSC_DBG_CQ, "\n");
	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	list_for_each_safe(&to_xcq(cq)->err_state_qp_list, err_qp_node, tmp, entry) {
		list_del(&err_qp_node->entry);
		free(err_qp_node);
	}

	xsc_free_cq_buf(to_xctx(cq->context), to_xcq(cq)->active_buf);
	free(to_xcq(cq));

	return 0;
}

static int xsc_calc_sq_size(struct xsc_context *ctx,
			     struct ibv_qp_init_attr_ex *attr,
			     struct xsc_qp *qp)
{
	int wqe_size;
	int wq_size;
	int wq_size_min = 0;
	int max_inline_cap;
	int max_sge = (ctx->device_id == XSC_MC_PF_DEV_ID_DIAMOND ||
			ctx->device_id == XSC_MC_PF_DEV_ID_DIAMOND_NEXT) ? 1 : 4;

	if (!attr->cap.max_send_wr)
		return 0;

	if (attr->cap.max_send_sge > max_sge) {
		xsc_err("max_send_sge:%d exceeded\n", attr->cap.max_send_sge);
		return -EINVAL;
	}

	wqe_size = 1 << (XSC_BASE_WQE_SHIFT + ctx->send_ds_shift);

	wq_size = xsc_round_up_power_of_two(attr->cap.max_send_wr);

	if (attr->qp_type != IBV_QPT_RAW_PACKET)
		wq_size_min = XSC_SEND_WQE_RING_DEPTH_MIN;
	if (wq_size < wq_size_min) {
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "WQE size %u is not enough, set it as %u\n",
				wq_size, wq_size_min);
		wq_size = wq_size_min;
	}

	if (wq_size > ctx->max_send_wqebb) {
		if (ctx->device_id == XSC_MC_PF_DEV_ID_DIAMOND ||
		    ctx->device_id == XSC_MC_PF_DEV_ID_DIAMOND_NEXT) {
			xsc_err("WQE size %u exceeds WQE ring depth\n", wq_size);
			return -EINVAL;
		}
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
				"WQE size %u exceeds WQE ring depth, set it as %u\n",
				wq_size, ctx->max_send_wqebb);
		wq_size = ctx->max_send_wqebb;
	}

	qp->sq.wqe_cnt = wq_size;
	qp->sq.ds_cnt = wq_size << ctx->send_ds_shift;
	qp->sq.seg_cnt = 1 << ctx->send_ds_shift;
	qp->sq.wqe_shift = XSC_BASE_WQE_SHIFT + ctx->send_ds_shift;
	qp->sq.max_gs = attr->cap.max_send_sge;
	qp->sq.max_post = qp->sq.wqe_cnt;

	if (ctx->device_id == XSC_MC_PF_DEV_ID_DIAMOND ||
	    ctx->device_id == XSC_MC_PF_DEV_ID_DIAMOND_NEXT)
		max_inline_cap = 64;
	else
		max_inline_cap = (qp->sq.seg_cnt - 2) * sizeof(struct xsc_wqe_data_seg);
	if (attr->cap.max_inline_data > max_inline_cap)
		return -EINVAL;
	qp->max_inline_data = attr->cap.max_inline_data;

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "Send WQE count:%u, max post:%u wqe shift:%u\n",
			qp->sq.wqe_cnt, qp->sq.max_post, qp->sq.wqe_shift);

	return wqe_size * qp->sq.wqe_cnt;
}

enum {
	DV_CREATE_WQ_SUPPORTED_COMP_MASK = XSCDV_WQ_INIT_ATTR_MASK_STRIDING_RQ
};

static int xsc_calc_rq_size(struct xsc_context *ctx,
			     struct ibv_qp_init_attr_ex *attr,
			     struct xsc_qp *qp)
{
	int wqe_size;
	int wq_size;
	int wq_size_min = 0;
	int recv_ds_shift = 0;

	if (!attr->cap.max_recv_wr)
		return 0;

	recv_ds_shift = xsc_get_recv_ds_shift(ctx, attr->qp_type);
	wqe_size = 1 << (XSC_BASE_WQE_SHIFT + recv_ds_shift);

	wq_size = xsc_round_up_power_of_two(attr->cap.max_recv_wr);
	/* due to hardware limit, rdma rq depth should be one send wqe ds num at least*/
	if (attr->qp_type != IBV_QPT_RAW_PACKET)
		wq_size_min = ctx->send_ds_num;
	if (wq_size < wq_size_min) {
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "WQE size %u is not enough, set it as %u\n",
				wq_size, wq_size_min);
		wq_size = wq_size_min;
	}

	if (wq_size > ctx->max_recv_wr) {
		if (ctx->device_id == XSC_MC_PF_DEV_ID_DIAMOND ||
		    ctx->device_id == XSC_MC_PF_DEV_ID_DIAMOND_NEXT) {
			xsc_err("WQE size %u exceeds WQE ring depth\n", wq_size);
			return -EINVAL;
		}
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
				"WQE size %u exceeds WQE ring depth, set it as %u\n",
				wq_size, ctx->max_recv_wr);
		wq_size = ctx->max_recv_wr;
	}

	qp->rq.wqe_cnt = wq_size;
	qp->rq.ds_cnt = qp->rq.wqe_cnt << recv_ds_shift;
	qp->rq.seg_cnt = 1 << recv_ds_shift;
	qp->rq.wqe_shift = XSC_BASE_WQE_SHIFT + recv_ds_shift;
	qp->rq.max_post = qp->rq.wqe_cnt;
	qp->rq.max_gs = attr->cap.max_recv_sge;

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "Recv WQE count:%u, max post:%u wqe shift:%u\n",
			qp->rq.wqe_cnt, qp->rq.max_post, qp->rq.wqe_shift);
	return wqe_size * qp->rq.wqe_cnt;
}

static int xsc_calc_wq_size(struct xsc_context *ctx,
			     struct ibv_qp_init_attr_ex *attr,
			     struct xsc_qp *qp)
{
	int ret;
	int result;

	ret = xsc_calc_sq_size(ctx, attr, qp);
	if (ret < 0)
		return ret;

	result = ret;

	ret = xsc_calc_rq_size(ctx, attr, qp);
	if (ret < 0)
		return ret;

	result += ret;

	qp->sq.offset = ret;
	qp->rq.offset = 0;

	return result;
}

static const char *qptype2key(enum ibv_qp_type type)
{
	switch (type) {
	case IBV_QPT_RC: return "HUGE_RC";
	case IBV_QPT_UC: return "HUGE_UC";
	case IBV_QPT_UD: return "HUGE_UD";
	case IBV_QPT_RAW_PACKET: return "HUGE_RAW_ETH";
	default: return "HUGE_NA";
	}
}

static int xsc_alloc_qp_buf(struct ibv_context *context,
			     struct ibv_qp_init_attr_ex *attr,
			     struct xsc_qp *qp,
			     int size, struct xscdv_devx_umem_in *umem_in)
{
	int err;
	enum xsc_alloc_type alloc_type;
	enum xsc_alloc_type default_alloc_type = XSC_ALLOC_TYPE_ANON;
	const char *qp_huge_key;

	if (qp->sq.wqe_cnt) {
		qp->sq.wrid = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wrid));
		if (!qp->sq.wrid) {
			errno = ENOMEM;
			err = -1;
			return err;
		}

		qp->sq.wr_data = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wr_data));
		if (!qp->sq.wr_data) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}

		qp->sq.wqe_head = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wqe_head));
		if (!qp->sq.wqe_head) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}

		qp->sq.need_flush = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.need_flush));
		if (!qp->sq.need_flush) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}
		memset(qp->sq.need_flush, 0, qp->sq.wqe_cnt);

		qp->sq.wr_opcode = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wr_opcode));
		if (!qp->sq.wr_opcode) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}
	}

	if (qp->rq.wqe_cnt) {
		qp->rq.wrid = malloc(qp->rq.wqe_cnt * sizeof(uint64_t));
		if (!qp->rq.wrid) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}
	}

	if (umem_in) {
		if (umem_in->comp_mask & XSCDV_UMEM_MASK_DMABUF) {
			if (umem_in->dmabuf_fd == -1) {
				xsc_dbg(to_xctx(context)->dbg_fp, XSC_DBG_QP,
					"dmabuf_fd is invalid :%u\n", umem_in->dmabuf_fd);
				err = -ENOMEM;
				goto ex_wrid;
			}
		}

		qp->buf.type = XSC_ALLOC_TYPE_GPU;
		qp->buf.buf = umem_in->addr;
		qp->buf.length = umem_in->size;

		xsc_dbg(to_xctx(context)->dbg_fp, XSC_DBG_QP,
			"qp_buf(%p),qp_buf_size=0x%lx is given by gpu memory, infact need size=0x%x.\n",
			qp->buf.buf, qp->buf.length, size);
	} else {
		/* compatibility support */
		qp_huge_key  = qptype2key(qp->ibv_qp->qp_type);
		if (xsc_use_huge(qp_huge_key))
			default_alloc_type = XSC_ALLOC_TYPE_HUGE;

		xsc_get_alloc_type(to_xctx(context), XSC_QP_PREFIX, &alloc_type,
				   default_alloc_type);

		err = xsc_alloc_prefered_buf(to_xctx(context), &qp->buf,
					     align(qp->buf_size,
						   to_xdev(context->device)->page_size),
					     to_xdev(context->device)->page_size,
					     alloc_type,
					     XSC_QP_PREFIX);

		if (err) {
			err = -ENOMEM;
			goto ex_wrid;
		}

		memset(qp->buf.buf, 0, qp->buf_size);

		if (attr->qp_type == IBV_QPT_RAW_PACKET ||
		    qp->flags & XSC_QP_FLAGS_USE_UNDERLAY) {
			size_t aligned_sq_buf_size = align(qp->sq_buf_size,
							   to_xdev(context->device)->page_size);
			/* For Raw Packet QP, allocate a separate buffer for the SQ */
			err = xsc_alloc_prefered_buf(to_xctx(context), &qp->sq_buf,
						     aligned_sq_buf_size,
						     to_xdev(context->device)->page_size,
						     alloc_type,
						     XSC_QP_PREFIX);
			if (err) {
				err = -ENOMEM;
				goto rq_buf;
			}

			memset(qp->sq_buf.buf, 0, aligned_sq_buf_size);
		}
	}

	return 0;
rq_buf:
	xsc_free_actual_buf(to_xctx(context), &qp->buf);
ex_wrid:
	if (qp->rq.wrid)
		free(qp->rq.wrid);

	if (qp->sq.wqe_head)
		free(qp->sq.wqe_head);

	if (qp->sq.wr_data)
		free(qp->sq.wr_data);
	if (qp->sq.wrid)
		free(qp->sq.wrid);

	if (qp->sq.need_flush)
		free(qp->sq.need_flush);

	if (qp->sq.wr_opcode)
		free(qp->sq.wr_opcode);

	return err;
}

static void xsc_free_qp_buf(struct xsc_context *ctx, struct xsc_qp *qp)
{
	if (qp->buf.type != XSC_ALLOC_TYPE_GPU) {
		xsc_free_actual_buf(ctx, &qp->buf);

		if (qp->sq_buf.buf)
			xsc_free_actual_buf(ctx, &qp->sq_buf);
	}

	if (qp->rq.wrid)
		free(qp->rq.wrid);

	if (qp->sq.wqe_head)
		free(qp->sq.wqe_head);

	if (qp->sq.wrid)
		free(qp->sq.wrid);

	if (qp->sq.wr_data)
		free(qp->sq.wr_data);

	if (qp->sq.need_flush)
		free(qp->sq.need_flush);

	if (qp->sq.wr_opcode)
		free(qp->sq.wr_opcode);
}

enum {
	XSC_CREATE_QP_SUP_COMP_MASK = (IBV_QP_INIT_ATTR_PD |
				       IBV_QP_INIT_ATTR_CREATE_FLAGS |
				       IBV_QP_INIT_ATTR_SEND_OPS_FLAGS |
				       IBV_QP_INIT_ATTR_MAX_TSO_HEADER),
};

enum {
	XSC_DV_CREATE_QP_SUP_COMP_MASK = XSCDV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS |
					  XSCDV_QP_INIT_ATTR_MASK_DC
};

enum {
	XSC_CREATE_QP_EX2_COMP_MASK = (IBV_QP_INIT_ATTR_CREATE_FLAGS |
					IBV_QP_INIT_ATTR_MAX_TSO_HEADER |
					IBV_QP_INIT_ATTR_IND_TABLE |
					IBV_QP_INIT_ATTR_RX_HASH),
};

enum {
	XSCDV_QP_CREATE_SUP_FLAGS =
		(XSCDV_QP_CREATE_TUNNEL_OFFLOADS |
		 XSCDV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC |
		 XSCDV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_MC |
		 XSCDV_QP_CREATE_DISABLE_SCATTER_TO_CQE |
		 XSCDV_QP_CREATE_ALLOW_SCATTER_TO_CQE),
};

static int xsc_cmd_create_qp_ex(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *attr,
				struct xsc_create_qp *cmd,
				struct xsc_qp *qp,
				struct xsc_create_qp_resp *resp,
				struct xsc_create_qp_ex_resp *resp_ex)
{
	struct xsc_create_qp_ex cmd_ex;
	int ret;

	if (attr->comp_mask & XSC_CREATE_QP_EX2_COMP_MASK) {
		memset(&cmd_ex, 0, sizeof(cmd_ex));
		*ibv_create_qp_ex_to_reg(&cmd_ex.ibv_cmd) = cmd->ibv_cmd.core_payload;
		cmd_ex.drv_payload = cmd->drv_payload;

		ret = ibv_cmd_create_qp_ex2(context, &qp->verbs_qp,
					    attr, &cmd_ex.ibv_cmd,
					    sizeof(cmd_ex), &resp_ex->ibv_resp,
					    sizeof(*resp_ex), NULL);
	} else {
		ret = ibv_cmd_create_qp_ex(context, &qp->verbs_qp, attr,
					   &cmd->ibv_cmd, sizeof(*cmd),
					   &resp->ibv_resp, sizeof(*resp));
	}

	return ret;
}

static struct ibv_qp *create_qp(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *attr,
				struct xscdv_qp_init_attr *xqp_attr,
				struct xscdv_devx_umem_in *umem_in)
{
	struct xsc_create_qp		cmd;
	struct xsc_create_qp_resp	resp;
	struct xsc_create_qp_ex_resp  resp_ex;
	struct xsc_qp		       *qp;
	int				ret;
	struct xsc_context	       *ctx = to_xctx(context);
	struct ibv_qp		       *ibqp;
	struct xsc_parent_domain *xparent_domain;
	struct xsc_device	       *xdev = to_xdev(context->device);

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "comp_mask=0x%x.\n", attr->comp_mask);

	if (attr->comp_mask & ~XSC_CREATE_QP_SUP_COMP_MASK) {
		xsc_err("Not supported comp_mask:0x%x\n", attr->comp_mask);
		return NULL;
	}

	/*check qp_type*/
	if ((attr->qp_type != IBV_QPT_RC) && (attr->qp_type != IBV_QPT_RAW_PACKET)) {
		xsc_err("Not supported qp_type:0x%x\n", attr->qp_type);
		return NULL;
	}

	qp = calloc(1, sizeof(*qp));
	if (!qp) {
		xsc_err("QP calloc failed\n");
		return NULL;
	}

	ibqp = &qp->verbs_qp.qp;
	qp->ibv_qp = ibqp;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));
	memset(&resp_ex, 0, sizeof(resp_ex));

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) {
		ret = xsc_qp_fill_wr_pfns(ctx, qp, attr);
		if (ret) {
			errno = ret;
			xsc_err("Fill wr pfns failed\n");
			goto err;
		}
	}

	ret = xsc_calc_wq_size(ctx, attr, qp);
	if (ret < 0) {
		xsc_err("Calculate WQ size failed\n");
		errno = EINVAL;
		goto err;
	}

	qp->buf_size = ret;
	qp->sq_buf_size = 0;

	if (xsc_alloc_qp_buf(context, attr, qp, ret, umem_in)) {
		xsc_err("Alloc QP buffer failed\n");
		errno = ENOMEM;
		goto err;
	}

	qp->sq_start = qp->buf.buf + qp->sq.offset;
	qp->rq_start = qp->buf.buf + qp->rq.offset;
	qp->sq.qend = qp->buf.buf + qp->sq.offset +
			(qp->sq.wqe_cnt << qp->sq.wqe_shift);

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "sq start:%p, sq qend:%p, buffer size:%u\n",
			qp->sq_start, qp->sq.qend, qp->buf_size);

	xsc_init_qp_indices(qp);

	if (xsc_spinlock_init_pd(&qp->sq.lock, attr->pd) ||
			xsc_spinlock_init_pd(&qp->rq.lock, attr->pd))
		goto err_free_qp_buf;

	cmd.buf_addr = (uintptr_t) qp->buf.buf;
	cmd.db_addr = (uintptr_t) qp->db;
	cmd.sq_wqe_count = qp->sq.ds_cnt;
	cmd.rq_wqe_count = qp->rq.ds_cnt;
	cmd.rq_wqe_shift = qp->rq.wqe_shift;

	if (qp->buf.type == XSC_ALLOC_TYPE_GPU) {
		qp->flags |= XSC_QP_FLAG_OWNED_BY_GPU;
		cmd.dmabuf_fd = umem_in->dmabuf_fd;
		cmd.dmabuf_sz = umem_in->size;
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "wq_buf %p, buffer size:0x%lx, dmabuf_fd:%d\n",
			umem_in->addr, umem_in->size, umem_in->dmabuf_fd);
	} else {
		cmd.dmabuf_fd = -1;
		cmd.dmabuf_sz = 0;
	}

	if (attr->qp_type == IBV_QPT_RAW_PACKET) {
		if (attr->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS) {
			if (attr->create_flags & XSC_QP_CREATE_RAWPACKET_TSO) {
				cmd.flags |= XSC_QP_FLAG_RAWPACKET_TSO;/*revert to command flags*/
				xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
						"revert create_flags(0x%x) to cmd_flags(0x%x)\n",
						attr->create_flags, cmd.flags);
			}

			if (attr->create_flags & XSC_QP_CREATE_RAWPACKET_TX) {
				cmd.flags |= XSC_QP_FLAG_RAWPACKET_TX;/*revert to command flags*/
				xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
						"revert create_flags(0x%x) to cmd_flags(0x%x)\n",
						attr->create_flags, cmd.flags);
			}

			if (attr->create_flags & XSC_QP_CREATE_RAWPACKET_SNIFFER) {
				cmd.flags |= XSC_QP_FLAG_RAWPACKET_SNIFFER;
				qp->flags |= XSC_QP_FLAG_RAWPACKET_SNIFFER;
				xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
					"revert create_flags(0x%x) to cmd_flags(0x%x)\n",
					attr->create_flags, cmd.flags);
			}

			attr->comp_mask &= ~IBV_QP_INIT_ATTR_CREATE_FLAGS;
		}

		if (attr->comp_mask & IBV_QP_INIT_ATTR_MAX_TSO_HEADER)
			cmd.flags |= XSC_QP_FLAG_RAWPACKET_TSO;

	} else if (attr->qp_type == IBV_QPT_RC) {
		if (attr->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS) {
			if (attr->create_flags & XSC_QP_CREATE_WORC) {
				cmd.flags |= XSC_QP_FLAG_WORC;
				xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
					"revert create_flags(0x%x) to cmd_flags(0x%x)\n",
					attr->create_flags, cmd.flags);
			}
			attr->comp_mask &= ~IBV_QP_INIT_ATTR_CREATE_FLAGS;
		}
	}

	pthread_mutex_lock(&ctx->qp_table_mutex);

	xparent_domain = to_xparent_domain(attr->pd);

	ret = xsc_cmd_create_qp_ex(context, attr, &cmd, qp, &resp, &resp_ex);
	if (ret) {
		xsc_err("ibv_cmd_create_qp_ex failed,ret %d\n", ret);
		errno = ret;
		goto err_free_uidx;
	}

	if (qp->sq.wqe_cnt || qp->rq.wqe_cnt) {
		ret = xsc_store_qp(ctx, ibqp->qp_num, qp);
		if (ret) {
			xsc_err("xsc_store_qp failed,ret %d\n", ret);
			errno = EINVAL;
			goto err_destroy;
		}
	}

	pthread_mutex_unlock(&ctx->qp_table_mutex);

	qp->rq.max_post = qp->rq.wqe_cnt;

	if (attr->sq_sig_all)
		qp->sq_signal_bits = 1;
	else
		qp->sq_signal_bits = 0;

	if (ctx->atomic_cap)
		qp->atomics_enabled = 1;

	attr->cap.max_send_wr = qp->sq.max_post;
	attr->cap.max_recv_wr = qp->rq.max_post;
	attr->cap.max_recv_sge = qp->rq.max_gs;

	qp->rsc.type = XSC_RSC_TYPE_QP;
	qp->rsc.rsn = ibqp->qp_num;

	if (xparent_domain)
		atomic_fetch_add(&xparent_domain->xpd.refcount, 1);

	qp->rqn = ibqp->qp_num;
	qp->sqn = ibqp->qp_num;

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "qp rqn:%u, sqn:%u\n", qp->rqn, qp->sqn);
	if (ctx->multidb_num && ctx->device_id != XSC_MC_PF_DEV_ID_DIAMOND) {
		pthread_mutex_lock(&context->mutex);
		qp->sq.db = ctx->mdb_base + ctx->tx_multidb_base +
			(ctx->tx_mdb_idx & (ctx->multidb_num - 1)) * sizeof(uint32_t);
		ctx->tx_mdb_idx++;
		pthread_mutex_unlock(&context->mutex);
	} else {
		qp->sq.db = ctx->sqm_reg_va + (ctx->qpm_tx_db & (xdev->page_size - 1));
	}
	qp->rq.db = ctx->rqm_reg_va + (ctx->qpm_rx_db & (xdev->page_size - 1));

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)
		qp->verbs_qp.comp_mask |= VERBS_QP_EX;

	return ibqp;

err_destroy:
	ibv_cmd_destroy_qp(ibqp);

err_free_uidx:
	pthread_mutex_unlock(&to_xctx(context)->qp_table_mutex);

err_free_qp_buf:
	xsc_free_qp_buf(ctx, qp);

err:
	free(qp);

	return NULL;
}

struct ibv_qp *xsc_create_qp(struct ibv_pd *pd,
			      struct ibv_qp_init_attr *attr)
{
	struct ibv_qp *qp;
	struct ibv_qp_init_attr_ex attrx;

	memset(&attrx, 0, sizeof(attrx));
	memcpy(&attrx, attr, sizeof(*attr));
	attrx.comp_mask = IBV_QP_INIT_ATTR_PD;
	attrx.pd = pd;
	qp = create_qp(pd->context, &attrx, NULL, NULL);
	if (qp)
		memcpy(attr, &attrx, sizeof(*attr));

	return qp;
}

struct ibv_qp *xsc_create_qp_ex(struct ibv_context *context,
				 struct ibv_qp_init_attr_ex *attr)
{
	return create_qp(context, attr, NULL, NULL);
}

static void xsc_lock_cqs(struct ibv_qp *qp)
{
	struct xsc_cq *send_cq = to_xcq(qp->send_cq);
	struct xsc_cq *recv_cq = to_xcq(qp->recv_cq);

	if (send_cq && recv_cq) {
		if (send_cq == recv_cq) {
			xsc_spin_lock(&send_cq->lock);
		} else if (send_cq->cqn < recv_cq->cqn) {
			xsc_spin_lock(&send_cq->lock);
			xsc_spin_lock(&recv_cq->lock);
		} else {
			xsc_spin_lock(&recv_cq->lock);
			xsc_spin_lock(&send_cq->lock);
		}
	} else if (send_cq) {
		xsc_spin_lock(&send_cq->lock);
	} else if (recv_cq) {
		xsc_spin_lock(&recv_cq->lock);
	}
}

static void xsc_unlock_cqs(struct ibv_qp *qp)
{
	struct xsc_cq *send_cq = to_xcq(qp->send_cq);
	struct xsc_cq *recv_cq = to_xcq(qp->recv_cq);

	if (send_cq && recv_cq) {
		if (send_cq == recv_cq) {
			xsc_spin_unlock(&send_cq->lock);
		} else if (send_cq->cqn < recv_cq->cqn) {
			xsc_spin_unlock(&recv_cq->lock);
			xsc_spin_unlock(&send_cq->lock);
		} else {
			xsc_spin_unlock(&send_cq->lock);
			xsc_spin_unlock(&recv_cq->lock);
		}
	} else if (send_cq) {
		xsc_spin_unlock(&send_cq->lock);
	} else if (recv_cq) {
		xsc_spin_unlock(&recv_cq->lock);
	}
}

int xsc_destroy_qp(struct ibv_qp *ibqp)
{
	struct xsc_qp *qp = to_xqp(ibqp);
	struct xsc_context *ctx = to_xctx(ibqp->context);
	int ret;
	struct xsc_parent_domain *xparent_domain = to_xparent_domain(ibqp->pd);
	struct xsc_err_state_qp_node *tmp, *err_rq_node, *err_sq_node;

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "\n");

	pthread_mutex_lock(&ctx->qp_table_mutex);

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		pthread_mutex_unlock(&ctx->qp_table_mutex);
		return ret;
	}

	xsc_lock_cqs(ibqp);

	list_for_each_safe(&to_xcq(ibqp->recv_cq)->err_state_qp_list, err_rq_node, tmp, entry) {
		if (err_rq_node->qp_id == qp->rsc.rsn) {
			list_del(&err_rq_node->entry);
			free(err_rq_node);
		}
	}

	list_for_each_safe(&to_xcq(ibqp->send_cq)->err_state_qp_list, err_sq_node, tmp, entry) {
		if (err_sq_node->qp_id == qp->rsc.rsn) {
			list_del(&err_sq_node->entry);
			free(err_sq_node);
		}
	}

	if (!(qp->flags & XSC_QP_FLAG_OWNED_BY_GPU)) {
		__xsc_cq_clean(to_xcq(ibqp->recv_cq), qp->rsc.rsn);
		if (ibqp->send_cq != ibqp->recv_cq)
			__xsc_cq_clean(to_xcq(ibqp->send_cq), qp->rsc.rsn);
	}

	if (qp->sq.wqe_cnt || qp->rq.wqe_cnt)
		xsc_clear_qp(ctx, ibqp->qp_num);

	xsc_unlock_cqs(ibqp);
	pthread_mutex_unlock(&ctx->qp_table_mutex);

	xsc_free_qp_buf(ctx, qp);

	if (xparent_domain)
		atomic_fetch_sub(&xparent_domain->xpd.refcount, 1);

	free(qp);

	return 0;
}

int xsc_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		  int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct xsc_qp *qp = to_xqp(ibqp);
	int ret;

	xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP, "\n");

	if (qp->rss_qp)
		return EINVAL;

	ret = ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr, &cmd, sizeof(cmd));
	if (ret)
		return ret;

	init_attr->cap.max_send_wr     = qp->sq.max_post;
	init_attr->cap.max_send_sge    = qp->sq.max_gs;
	init_attr->cap.max_inline_data = qp->max_inline_data;

	attr->cap = init_attr->cap;
	if (qp->err_occurred) {
		qp->err_occurred = 0;
		qp->ibv_qp->state = IBV_QPS_ERR;
		attr->qp_state = IBV_QPS_ERR;
	}

	return 0;
}

enum {
	XSC_MODIFY_QP_EX_ATTR_MASK = IBV_QP_RATE_LIMIT,
};

int xsc_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct xsc_qp *xqp = to_xqp(qp);
	int ret;

	xsc_dbg(to_xctx(qp->context)->dbg_fp, XSC_DBG_QP, "\n");
	ret = ibv_cmd_modify_qp(qp, attr, attr_mask,
				&cmd, sizeof(cmd));


	if (!ret && (attr_mask & IBV_QP_STATE) &&
			attr->qp_state == IBV_QPS_RESET) {
		if (xqp->flags & XSC_QP_FLAG_OWNED_BY_GPU) {
			xsc_dbg(to_xctx(qp->context)->dbg_fp, XSC_DBG_QP,
				"qp buf is given by GPU, do nothing in host\n");
		} else {
			if (qp->recv_cq)
				xsc_cq_clean(to_xcq(qp->recv_cq), xqp->rsc.rsn);

			if (qp->send_cq != qp->recv_cq && qp->send_cq)
				xsc_cq_clean(to_xcq(qp->send_cq),
					     to_xqp(qp)->rsc.rsn);
		}

		xsc_init_qp_indices(xqp);
	}

	if (!ret && (attr_mask & IBV_QP_STATE))
		qp->state = attr->qp_state;

	/*workaround: generate flush err cqe if qp status turns to ERR*/
	if (!ret && (attr_mask & IBV_QP_STATE)) {
		xsc_lock_cqs(qp);
		ret = xsc_err_state_qp(qp, attr->cur_qp_state, attr->qp_state);
		xsc_unlock_cqs(qp);
	}

	return ret;
}

static void xsc_set_fw_version(struct ibv_device_attr *attr,
			       union xsc_ib_fw_ver *fw_ver)
{
	uint8_t ver_major = fw_ver->s.ver_major;
	uint8_t ver_minor = fw_ver->s.ver_minor;
	uint16_t ver_patch = fw_ver->s.ver_patch;
	uint32_t ver_tweak = fw_ver->s.ver_tweak;

	if (ver_tweak == 0) {
		snprintf(attr->fw_ver, sizeof(attr->fw_ver), "v%u.%u.%u",
			 ver_major, ver_minor, ver_patch);
	} else {
		snprintf(attr->fw_ver, sizeof(attr->fw_ver), "v%u.%u.%u+%u",
			 ver_major, ver_minor, ver_patch, ver_tweak);
	}
}

int xsc_query_device_ex(struct ibv_context *context,
			const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	union xsc_ib_fw_ver raw_fw_ver;
	int err;

	raw_fw_ver.data = 0;
	err = ibv_cmd_query_device_any(context, input, attr, attr_size,
				       &resp, &resp_size);
	if (err)
		return err;

	raw_fw_ver.data = resp.base.fw_ver;
	xsc_set_fw_version(&attr->orig_attr, &raw_fw_ver);

	return 0;
}
