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
