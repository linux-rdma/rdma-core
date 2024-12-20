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
#include "xsc_hsi.h"

int xsc_query_port(struct ibv_context *context, u8 port,
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
	xsc_dbg(to_xctx(context)->dbg_fp, XSC_DBG_PD, "pd number:%u\n",
		pd->pdn);

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
			  u64 hca_va, int acc)
{
	struct xsc_mr *mr;
	struct ibv_reg_mr cmd;
	int ret;
	enum ibv_access_flags access = (enum ibv_access_flags)acc;
	struct ib_uverbs_reg_mr_resp resp;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, &mr->vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(mr);
		return NULL;
	}
	mr->alloc_flags = acc;

	xsc_dbg(to_xctx(pd->context)->dbg_fp, XSC_DBG_MR, "lkey:%u, rkey:%u\n",
		mr->vmr.ibv_mr.lkey, mr->vmr.ibv_mr.rkey);

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

int xsc_round_up_power_of_two(long long sz)
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

enum { CREATE_CQ_SUPPORTED_WC_FLAGS =
	       IBV_WC_STANDARD_FLAGS | IBV_WC_EX_WITH_COMPLETION_TIMESTAMP |
	       IBV_WC_EX_WITH_CVLAN | IBV_WC_EX_WITH_FLOW_TAG |
	       IBV_WC_EX_WITH_TM_INFO |
	       IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK };

enum { CREATE_CQ_SUPPORTED_COMP_MASK = IBV_CQ_INIT_ATTR_MASK_FLAGS };

enum { CREATE_CQ_SUPPORTED_FLAGS = IBV_CREATE_CQ_ATTR_SINGLE_THREADED |
				   IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN };

static int xsc_cqe_depth_check(void)
{
	char *e;

	e = getenv("XSC_CQE_DEPTH_CHECK");
	if (e && !strcmp(e, "n"))
		return 0;

	return 1;
}

static struct ibv_cq_ex *create_cq(struct ibv_context *context,
				   const struct ibv_cq_init_attr_ex *cq_attr,
				   int cq_alloc_flags)
{
	struct xsc_create_cq cmd = {};
	struct xsc_create_cq_resp resp = {};
	struct xsc_create_cq_ex cmd_ex = {};
	struct xsc_create_cq_ex_resp resp_ex = {};
	struct xsc_ib_create_cq *cmd_drv;
	struct xsc_ib_create_cq_resp *resp_drv;
	struct xsc_cq *cq;
	int cqe_sz;
	int ret;
	int ncqe;
	struct xsc_context *xctx = to_xctx(context);
	bool use_ex = false;
	char *env;
	int i;

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
		xsc_err("unsupported flags:0x%" PRIx64 "\n", cq_attr->wc_flags);
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
		if (cq_attr->flags & IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN)
			use_ex = true;
	}

	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "use_ex:%u\n", use_ex);

	cmd_drv = use_ex ? &cmd_ex.drv_payload : &cmd.drv_payload;
	resp_drv = use_ex ? &resp_ex.drv_payload : &resp.drv_payload;

	cq->cons_index = 0;

	if (xsc_spinlock_init(&cq->lock))
		goto err;

	ncqe = align_queue_size(cq_attr->cqe);
	if (ncqe < XSC_CQE_RING_DEPTH_MIN) {
		xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ,
			"CQE ring size %u is not enough, set it as %u\n", ncqe,
			XSC_CQE_RING_DEPTH_MIN);
		ncqe = XSC_CQE_RING_DEPTH_MIN;
	}

	if (ncqe > xctx->max_cqe) {
		if (xsc_cqe_depth_check()) {
			xsc_err("CQE ring size %u exceeds CQE ring depth %u, abort!\n",
				ncqe, xctx->max_cqe);
			errno = EINVAL;
			goto err_spl;
		} else {
			xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ,
				"CQE ring size %u exceeds the MAX ring szie, set it as %u\n",
				ncqe, xctx->max_cqe);
			ncqe = xctx->max_cqe;
		}
	}

	cqe_sz = XSC_CQE_SIZE;
	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "CQE number:%u, size:%u\n", ncqe,
		cqe_sz);

	if (xsc_alloc_cq_buf(to_xctx(context), cq, &cq->buf, ncqe, cqe_sz)) {
		xsc_err("Alloc cq buffer failed.\n");
		errno = ENOMEM;
		goto err_spl;
	}

	cq->cqe_sz = cqe_sz;
	cq->flags = cq_alloc_flags;

	cmd_drv->buf_addr = (uintptr_t)cq->buf.buf;
	cmd_drv->cqe_size = cqe_sz;

	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "buf_addr:%p\n", cq->buf.buf);

	if (use_ex) {
		struct ibv_cq_init_attr_ex cq_attr_ex = *cq_attr;

		cq_attr_ex.cqe = ncqe;
		ret = ibv_cmd_create_cq_ex(context, &cq_attr_ex, &cq->verbs_cq,
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

	cq->active_buf = &cq->buf;
	cq->resize_buf = NULL;
	cq->cqn = resp_drv->cqn;

	cq->db = xctx->cqm_reg_va +
		 (xctx->cqm_next_cid_reg & (xctx->page_size - 1));
	cq->armdb =
		xctx->cqm_armdb_va + (xctx->cqm_armdb & (xctx->page_size - 1));
	cq->cqe_cnt = ncqe;
	cq->log2_cq_ring_sz = xsc_ilog2(ncqe);

	for (i = 0; i < ncqe; i++) {
		struct xsc_cqe *cqe = (struct xsc_cqe *)(cq->active_buf->buf +
							 i * cq->cqe_sz);
		u32 owner_data = 0;

		owner_data |= FIELD_PREP(CQE_DATA2_OWNER_MASK, 1);
		cqe->data2 = htole32(owner_data);
	}

	env = getenv("XSC_DISABLE_FLUSH_ERROR");
	cq->disable_flush_error_cqe = env ? true : false;
	xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ, "cqe count:%u cqn:%u\n", cq->cqe_cnt,
		cq->cqn);
	list_head_init(&cq->err_state_qp_list);
	return &cq->verbs_cq.cq_ex;

err_buf:
	xsc_free_cq_buf(to_xctx(context), &cq->buf);

err_spl:
	xsc_spinlock_destroy(&cq->lock);

err:
	free(cq);

	return NULL;
}

struct ibv_cq *xsc_create_cq(struct ibv_context *context, int cqe,
			     struct ibv_comp_channel *channel, int comp_vector)
{
	struct ibv_cq_ex *cq;
	struct ibv_cq_init_attr_ex cq_attr = { .cqe = cqe,
					       .channel = channel,
					       .comp_vector = comp_vector,
					       .wc_flags =
						       IBV_WC_STANDARD_FLAGS };

	if (cqe <= 0) {
		errno = EINVAL;
		return NULL;
	}

	cq = create_cq(context, &cq_attr, 0);
	return cq ? ibv_cq_ex_to_cq(cq) : NULL;
}

int xsc_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	struct xsc_cq *cq = to_xcq(ibvcq);
	struct xsc_context *ctx = to_xctx(ibvcq->context);

	ctx->hw_ops->update_cq_db(cq->armdb, cq->cqn, cq->cons_index,
				  solicited);

	return 0;
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

	list_for_each_safe(&to_xcq(cq)->err_state_qp_list, err_qp_node, tmp,
			   entry) {
		list_del(&err_qp_node->entry);
		free(err_qp_node);
	}

	xsc_free_cq_buf(to_xctx(cq->context), to_xcq(cq)->active_buf);
	free(to_xcq(cq));

	return 0;
}

static void xsc_set_fw_version(struct ibv_device_attr *attr,
			       union xsc_ib_fw_ver *fw_ver)
{
	u8 ver_major = fw_ver->s.ver_major;
	u8 ver_minor = fw_ver->s.ver_minor;
	u16 ver_patch = fw_ver->s.ver_patch;
	u32 ver_tweak = fw_ver->s.ver_tweak;

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

static int xsc_calc_sq_size(struct xsc_context *ctx,
			    struct ibv_qp_init_attr_ex *attr, struct xsc_qp *qp)
{
	int wqe_size;
	int wq_size;
	int wq_size_min = 0;

	if (!attr->cap.max_send_wr)
		return 0;

	wqe_size = 1 << (XSC_BASE_WQE_SHIFT + ctx->send_ds_shift);

	wq_size = xsc_round_up_power_of_two(attr->cap.max_send_wr);

	if (attr->qp_type != IBV_QPT_RAW_PACKET)
		wq_size_min = XSC_SEND_WQE_RING_DEPTH_MIN;
	if (wq_size < wq_size_min) {
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
			"WQE size %u is not enough, set it as %u\n", wq_size,
			wq_size_min);
		wq_size = wq_size_min;
	}

	if (wq_size > ctx->max_send_wr) {
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
			"WQE size %u exceeds WQE ring depth, set it as %u\n",
			wq_size, ctx->max_send_wr);
		wq_size = ctx->max_send_wr;
	}

	qp->max_inline_data = attr->cap.max_inline_data;
	qp->sq.wqe_cnt = wq_size;
	qp->sq.ds_cnt = wq_size << ctx->send_ds_shift;
	qp->sq.seg_cnt = 1 << ctx->send_ds_shift;
	qp->sq.wqe_shift = XSC_BASE_WQE_SHIFT + ctx->send_ds_shift;
	qp->sq.max_gs = attr->cap.max_send_sge;
	qp->sq.max_post = qp->sq.wqe_cnt;
	if (attr->cap.max_inline_data >
	    (qp->sq.seg_cnt - 2) * sizeof(struct xsc_wqe_data_seg))
		return -EINVAL;

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
		"Send WQE count:%u, max post:%u wqe shift:%u\n", qp->sq.wqe_cnt,
		qp->sq.max_post, qp->sq.wqe_shift);

	return wqe_size * qp->sq.wqe_cnt;
}

static int xsc_calc_rq_size(struct xsc_context *ctx,
			    struct ibv_qp_init_attr_ex *attr, struct xsc_qp *qp)
{
	int wqe_size;
	int wq_size;
	int wq_size_min = 0;

	if (!attr->cap.max_recv_wr)
		return 0;

	wqe_size = 1 << (XSC_BASE_WQE_SHIFT + ctx->recv_ds_shift);

	wq_size = xsc_round_up_power_of_two(attr->cap.max_recv_wr);
	/* due to hardware limit, rdma rq depth should be
	 * one send wqe ds num at least
	 */
	if (attr->qp_type != IBV_QPT_RAW_PACKET)
		wq_size_min = ctx->send_ds_num;
	if (wq_size < wq_size_min) {
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
			"WQE size %u is not enough, set it as %u\n", wq_size,
			wq_size_min);
		wq_size = wq_size_min;
	}

	if (wq_size > ctx->max_recv_wr) {
		xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
			"WQE size %u exceeds WQE ring depth, set it as %u\n",
			wq_size, ctx->max_recv_wr);
		wq_size = ctx->max_recv_wr;
	}

	qp->rq.wqe_cnt = wq_size;
	qp->rq.ds_cnt = qp->rq.wqe_cnt << ctx->recv_ds_shift;
	qp->rq.seg_cnt = 1 << ctx->recv_ds_shift;
	qp->rq.wqe_shift = XSC_BASE_WQE_SHIFT + ctx->recv_ds_shift;
	qp->rq.max_post = qp->rq.wqe_cnt;
	qp->rq.max_gs = attr->cap.max_recv_sge;

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
		"Recv WQE count:%u, max post:%u wqe shift:%u\n", qp->rq.wqe_cnt,
		qp->rq.max_post, qp->rq.wqe_shift);
	return wqe_size * qp->rq.wqe_cnt;
}

static int xsc_calc_wq_size(struct xsc_context *ctx,
			    struct ibv_qp_init_attr_ex *attr, struct xsc_qp *qp)
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

static int xsc_alloc_qp_buf(struct ibv_context *context,
			    struct ibv_qp_init_attr_ex *attr, struct xsc_qp *qp,
			    int size)
{
	int err;

	if (qp->sq.wqe_cnt) {
		qp->sq.wrid = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wrid));
		if (!qp->sq.wrid) {
			errno = ENOMEM;
			err = -1;
			return err;
		}

		qp->sq.wqe_head =
			malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wqe_head));
		if (!qp->sq.wqe_head) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}

		qp->sq.need_flush =
			malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.need_flush));
		if (!qp->sq.need_flush) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}
		memset(qp->sq.need_flush, 0, qp->sq.wqe_cnt);

		qp->sq.wr_opcode =
			malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wr_opcode));
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

	err = xsc_alloc_buf(&qp->buf,
			    align(qp->buf_size,
				  to_xdev(context->device)->page_size),
			    to_xdev(context->device)->page_size);
	if (err) {
		err = -ENOMEM;
		goto ex_wrid;
	}

	memset(qp->buf.buf, 0, qp->buf_size);

	if (attr->qp_type == IBV_QPT_RAW_PACKET) {
		size_t aligned_sq_buf_size = align(qp->sq_buf_size,
						   to_xdev(context->device)->page_size);
		/* For Raw Packet QP, allocate a separate buffer for the SQ */
		err = xsc_alloc_buf(&qp->sq_buf,
				    aligned_sq_buf_size,
				    to_xdev(context->device)->page_size);
		if (err) {
			err = -ENOMEM;
			goto rq_buf;
		}

		memset(qp->sq_buf.buf, 0, aligned_sq_buf_size);
	}

	return 0;
rq_buf:
	xsc_free_buf(&qp->buf);
ex_wrid:
	if (qp->rq.wrid)
		free(qp->rq.wrid);

	if (qp->sq.wqe_head)
		free(qp->sq.wqe_head);

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
	xsc_free_buf(&qp->buf);

	if (qp->sq_buf.buf)
		xsc_free_buf(&qp->sq_buf);

	if (qp->rq.wrid)
		free(qp->rq.wrid);

	if (qp->sq.wqe_head)
		free(qp->sq.wqe_head);

	if (qp->sq.wrid)
		free(qp->sq.wrid);

	if (qp->sq.need_flush)
		free(qp->sq.need_flush);

	if (qp->sq.wr_opcode)
		free(qp->sq.wr_opcode);
}

enum { XSC_CREATE_QP_SUP_COMP_MASK =
	       (IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_CREATE_FLAGS),
};

void xsc_init_qp_indices(struct xsc_qp *qp)
{
	qp->sq.head = 0;
	qp->sq.tail = 0;
	qp->rq.head = 0;
	qp->rq.tail = 0;
	qp->sq.cur_post = 0;
}

static struct ibv_qp *create_qp(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *attr)
{
	struct xsc_create_qp cmd;
	struct xsc_create_qp_resp resp;
	struct xsc_create_qp_ex_resp resp_ex;
	struct xsc_qp *qp;
	int ret;
	struct xsc_context *ctx = to_xctx(context);
	struct ibv_qp *ibqp;
	struct xsc_device *xdev = to_xdev(context->device);

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "comp_mask=0x%x.\n", attr->comp_mask);

	if (attr->comp_mask & ~XSC_CREATE_QP_SUP_COMP_MASK) {
		xsc_err("Not supported comp_mask:0x%x\n", attr->comp_mask);
		return NULL;
	}

	/*check qp_type*/
	if (attr->qp_type != IBV_QPT_RC &&
	    attr->qp_type != IBV_QPT_RAW_PACKET) {
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

	ret = xsc_calc_wq_size(ctx, attr, qp);
	if (ret < 0) {
		xsc_err("Calculate WQ size failed\n");
		errno = EINVAL;
		goto err;
	}

	qp->buf_size = ret;
	qp->sq_buf_size = 0;

	if (xsc_alloc_qp_buf(context, attr, qp, ret)) {
		xsc_err("Alloc QP buffer failed\n");
		errno = ENOMEM;
		goto err;
	}

	qp->sq_start = qp->buf.buf + qp->sq.offset;
	qp->rq_start = qp->buf.buf + qp->rq.offset;
	qp->sq.qend = qp->buf.buf + qp->sq.offset +
		      (qp->sq.wqe_cnt << qp->sq.wqe_shift);

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
		"sq start:%p, sq qend:%p, buffer size:%u\n", qp->sq_start,
		qp->sq.qend, qp->buf_size);

	xsc_init_qp_indices(qp);

	if (xsc_spinlock_init(&qp->sq.lock) ||
	    xsc_spinlock_init(&qp->rq.lock))
		goto err_free_qp_buf;

	cmd.buf_addr = (uintptr_t)qp->buf.buf;
	cmd.sq_wqe_count = qp->sq.ds_cnt;
	cmd.rq_wqe_count = qp->rq.ds_cnt;
	cmd.rq_wqe_shift = qp->rq.wqe_shift;

	if (attr->qp_type == IBV_QPT_RAW_PACKET) {
		if (attr->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS) {
			if (attr->create_flags & XSC_QP_CREATE_RAWPACKET_TSO) {
				cmd.flags |= XSC_QP_FLAG_RAWPACKET_TSO;
				xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
					"revert create_flags(0x%x) to cmd_flags(0x%x)\n",
					attr->create_flags, cmd.flags);
			}

			if (attr->create_flags & XSC_QP_CREATE_RAWPACKET_TX) {
				cmd.flags |= XSC_QP_FLAG_RAWPACKET_TX;
				xsc_dbg(ctx->dbg_fp, XSC_DBG_QP,
					"revert create_flags(0x%x) to cmd_flags(0x%x)\n",
					attr->create_flags, cmd.flags);
			}
			attr->comp_mask &= ~IBV_QP_INIT_ATTR_CREATE_FLAGS;
		}
	}

	pthread_mutex_lock(&ctx->qp_table_mutex);

	ret = ibv_cmd_create_qp_ex(context, &qp->verbs_qp, attr, &cmd.ibv_cmd,
				   sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (ret) {
		xsc_err("ibv_cmd_create_qp_ex failed,ret %d\n", ret);
		errno = ret;
		goto err_free_qp_buf;
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

	attr->cap.max_send_wr = qp->sq.max_post;
	attr->cap.max_recv_wr = qp->rq.max_post;
	attr->cap.max_recv_sge = qp->rq.max_gs;

	qp->rsc.rsn = ibqp->qp_num;

	qp->rqn = ibqp->qp_num;
	qp->sqn = ibqp->qp_num;

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "qp rqn:%u, sqn:%u\n", qp->rqn,
		qp->sqn);
	qp->sq.db = ctx->sqm_reg_va + (ctx->qpm_tx_db & (xdev->page_size - 1));
	qp->rq.db = ctx->rqm_reg_va + (ctx->qpm_rx_db & (xdev->page_size - 1));

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)
		qp->verbs_qp.comp_mask |= VERBS_QP_EX;

	return ibqp;

err_destroy:
	ibv_cmd_destroy_qp(ibqp);

err_free_qp_buf:
	pthread_mutex_unlock(&to_xctx(context)->qp_table_mutex);
	xsc_free_qp_buf(ctx, qp);

err:
	free(qp);

	return NULL;
}

struct ibv_qp *xsc_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct ibv_qp *qp;
	struct ibv_qp_init_attr_ex attrx;

	memset(&attrx, 0, sizeof(attrx));
	memcpy(&attrx, attr, sizeof(*attr));
	attrx.comp_mask = IBV_QP_INIT_ATTR_PD;
	attrx.pd = pd;
	qp = create_qp(pd->context, &attrx);
	if (qp)
		memcpy(attr, &attrx, sizeof(*attr));

	return qp;
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
	struct xsc_err_state_qp_node *tmp, *err_rq_node, *err_sq_node;

	xsc_dbg(ctx->dbg_fp, XSC_DBG_QP, "\n");

	pthread_mutex_lock(&ctx->qp_table_mutex);

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		pthread_mutex_unlock(&ctx->qp_table_mutex);
		return ret;
	}

	xsc_lock_cqs(ibqp);

	list_for_each_safe(&to_xcq(ibqp->recv_cq)->err_state_qp_list,
			   err_rq_node, tmp, entry) {
		if (err_rq_node->qp_id == qp->rsc.rsn) {
			list_del(&err_rq_node->entry);
			free(err_rq_node);
		}
	}

	list_for_each_safe(&to_xcq(ibqp->send_cq)->err_state_qp_list,
			   err_sq_node, tmp, entry) {
		if (err_sq_node->qp_id == qp->rsc.rsn) {
			list_del(&err_sq_node->entry);
			free(err_sq_node);
		}
	}

	__xsc_cq_clean(to_xcq(ibqp->recv_cq), qp->rsc.rsn);
	if (ibqp->send_cq != ibqp->recv_cq)
		__xsc_cq_clean(to_xcq(ibqp->send_cq), qp->rsc.rsn);

	if (qp->sq.wqe_cnt || qp->rq.wqe_cnt)
		xsc_clear_qp(ctx, ibqp->qp_num);

	xsc_unlock_cqs(ibqp);
	pthread_mutex_unlock(&ctx->qp_table_mutex);

	xsc_free_qp_buf(ctx, qp);

	free(qp);

	return 0;
}

int xsc_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask,
		 struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct xsc_qp *qp = to_xqp(ibqp);
	int ret;

	xsc_dbg(to_xctx(ibqp->context)->dbg_fp, XSC_DBG_QP, "\n");

	ret = ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr, &cmd,
			       sizeof(cmd));
	if (ret)
		return ret;

	init_attr->cap.max_send_wr = qp->sq.max_post;
	init_attr->cap.max_send_sge = qp->sq.max_gs;
	init_attr->cap.max_inline_data = qp->max_inline_data;

	attr->cap = init_attr->cap;
	attr->qp_state = qp->ibv_qp->state;

	return 0;
}

int xsc_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct xsc_qp *xqp = to_xqp(qp);
	int ret;

	xsc_dbg(to_xctx(qp->context)->dbg_fp, XSC_DBG_QP, "\n");
	ret = ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));

	if (!ret && (attr_mask & IBV_QP_STATE) &&
	    attr->qp_state == IBV_QPS_RESET) {
		if (qp->recv_cq)
			xsc_cq_clean(to_xcq(qp->recv_cq), xqp->rsc.rsn);

		if (qp->send_cq != qp->recv_cq && qp->send_cq)
			xsc_cq_clean(to_xcq(qp->send_cq), to_xqp(qp)->rsc.rsn);

		xsc_init_qp_indices(xqp);
	}

	if (!ret && (attr_mask & IBV_QP_STATE))
		qp->state = attr->qp_state;

	/*workaround: generate flush err cqe if qp status turns to ERR*/
	if (!ret && (attr_mask & IBV_QP_STATE))
		ret = xsc_err_state_qp(qp, attr->cur_qp_state, attr->qp_state);

	return ret;
}
