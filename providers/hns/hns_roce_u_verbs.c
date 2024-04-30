/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
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
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <ccan/ilog.h>
#include <ccan/minmax.h>
#include "hns_roce_u.h"
#include "hns_roce_u_db.h"
#include "hns_roce_u_hw_v2.h"

void hns_roce_init_qp_indices(struct hns_roce_qp *qp)
{
	qp->sq.head = 0;
	qp->sq.tail = 0;
	qp->rq.head = 0;
	qp->rq.tail = 0;
	qp->next_sge = 0;
}

int hns_roce_u_query_device(struct ibv_context *context,
			    const struct ibv_query_device_ex_input *input,
			    struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	int ret;
	uint64_t raw_fw_ver;
	unsigned int major, minor, sub_minor;

	ret = ibv_cmd_query_device_any(context, input, attr, attr_size, &resp,
				       &resp_size);
	if (ret)
		return ret;

	raw_fw_ver = resp.base.fw_ver;
	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->orig_attr.fw_ver, sizeof(attr->orig_attr.fw_ver),
		 "%u.%u.%03u", major, minor, sub_minor);

	return 0;
}

int hns_roce_u_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

struct ibv_pd *hns_roce_u_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct hns_roce_pd *pd;
	struct hns_roce_alloc_pd_resp resp = {};

	pd = malloc(sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd, sizeof(cmd),
			     &resp.ibv_resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}

	pd->pdn = resp.pdn;

	return &pd->ibv_pd;
}

int hns_roce_u_free_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(to_hr_pd(pd));

	return ret;
}

struct ibv_xrcd *hns_roce_u_open_xrcd(struct ibv_context *context,
				      struct ibv_xrcd_init_attr *xrcd_init_attr)
{
	struct ib_uverbs_open_xrcd_resp resp = {};
	struct ibv_open_xrcd cmd = {};
	struct verbs_xrcd *xrcd;
	int ret;

	xrcd = calloc(1, sizeof(*xrcd));
	if (!xrcd)
		return NULL;

	ret = ibv_cmd_open_xrcd(context, xrcd, sizeof(*xrcd), xrcd_init_attr,
				&cmd, sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(xrcd);
		return NULL;
	}

	return &xrcd->xrcd;
}

int hns_roce_u_close_xrcd(struct ibv_xrcd *ibv_xrcd)
{
	struct verbs_xrcd *xrcd =
			container_of(ibv_xrcd, struct verbs_xrcd, xrcd);
	int ret;

	ret = ibv_cmd_close_xrcd(xrcd);
	if (!ret)
		free(xrcd);

	return ret;
}

struct ibv_mr *hns_roce_u_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 uint64_t hca_va, int access)
{
	int ret;
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;

	if (!addr) {
		verbs_err(verbs_get_ctx(pd->context),
			  "2nd parm addr is NULL!\n");
		return NULL;
	}

	if (!length) {
		verbs_err(verbs_get_ctx(pd->context),
			  "3st parm length is 0!\n");
		return NULL;
	}

	vmr = malloc(sizeof(*vmr));
	if (!vmr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

int hns_roce_u_rereg_mr(struct verbs_mr *vmr, int flags, struct ibv_pd *pd,
			void *addr, size_t length, int access)
{
	struct ibv_rereg_mr cmd;
	struct ib_uverbs_rereg_mr_resp resp;

	return ibv_cmd_rereg_mr(vmr, flags, addr, length, (uintptr_t)addr,
				access, pd, &cmd, sizeof(cmd), &resp,
				sizeof(resp));
}

int hns_roce_u_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);

	return ret;
}

int hns_roce_u_bind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		       struct ibv_mw_bind *mw_bind)
{
	struct ibv_mw_bind_info *bind_info = &mw_bind->bind_info;
	struct ibv_send_wr *bad_wr = NULL;
	struct ibv_send_wr wr = {};
	int ret;

	if (bind_info->mw_access_flags & ~(IBV_ACCESS_REMOTE_WRITE |
	    IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC))
		return EINVAL;

	wr.opcode = IBV_WR_BIND_MW;
	wr.next = NULL;

	wr.wr_id = mw_bind->wr_id;
	wr.send_flags = mw_bind->send_flags;

	wr.bind_mw.mw = mw;
	wr.bind_mw.rkey = ibv_inc_rkey(mw->rkey);
	wr.bind_mw.bind_info = mw_bind->bind_info;

	ret = hns_roce_u_v2_post_send(qp, &wr, &bad_wr);
	if (ret)
		return ret;

	mw->rkey = wr.bind_mw.rkey;

	return 0;
}

struct ibv_mw *hns_roce_u_alloc_mw(struct ibv_pd *pd, enum ibv_mw_type type)
{
	struct ibv_mw *mw;
	struct ibv_alloc_mw cmd = {};
	struct ib_uverbs_alloc_mw_resp resp = {};

	mw = malloc(sizeof(*mw));
	if (!mw)
		return NULL;

	if (ibv_cmd_alloc_mw(pd, type, mw, &cmd, sizeof(cmd),
			     &resp, sizeof(resp))) {
		free(mw);
		return NULL;
	}

	return mw;
}

int hns_roce_u_dealloc_mw(struct ibv_mw *mw)
{
	int ret;

	ret = ibv_cmd_dealloc_mw(mw);
	if (ret)
		return ret;

	free(mw);

	return 0;
}

enum {
	CREATE_CQ_SUPPORTED_WC_FLAGS = IBV_WC_STANDARD_FLAGS |
				       IBV_WC_EX_WITH_CVLAN,
};

static int verify_cq_create_attr(struct ibv_cq_init_attr_ex *attr,
				 struct hns_roce_context *context)
{
	if (!attr->cqe || attr->cqe > context->max_cqe)
		return EINVAL;

	if (attr->comp_mask)
		return EOPNOTSUPP;

	if (!check_comp_mask(attr->wc_flags, CREATE_CQ_SUPPORTED_WC_FLAGS))
		return EOPNOTSUPP;

	attr->cqe = max_t(uint32_t, HNS_ROCE_MIN_CQE_NUM,
			  roundup_pow_of_two(attr->cqe));

	return 0;
}

static int hns_roce_alloc_cq_buf(struct hns_roce_cq *cq)
{
	int buf_size = hr_hw_page_align(cq->cq_depth * cq->cqe_size);

	if (hns_roce_alloc_buf(&cq->buf, buf_size, HNS_HW_PAGE_SIZE))
		return -ENOMEM;

	return 0;
}

static int exec_cq_create_cmd(struct ibv_context *context,
			      struct hns_roce_cq *cq,
			      struct ibv_cq_init_attr_ex *attr)
{
	struct hns_roce_create_cq_ex_resp resp_ex = {};
	struct hns_roce_ib_create_cq_resp *resp_drv;
	struct hns_roce_create_cq_ex cmd_ex = {};
	struct hns_roce_ib_create_cq *cmd_drv;
	int ret;

	cmd_drv = &cmd_ex.drv_payload;
	resp_drv = &resp_ex.drv_payload;

	cmd_drv->buf_addr = (uintptr_t)cq->buf.buf;
	cmd_drv->db_addr = (uintptr_t)cq->db;
	cmd_drv->cqe_size = (uintptr_t)cq->cqe_size;

	ret = ibv_cmd_create_cq_ex(context, attr, &cq->verbs_cq,
				   &cmd_ex.ibv_cmd, sizeof(cmd_ex),
				   &resp_ex.ibv_resp, sizeof(resp_ex), 0);
	if (ret)
		return ret;

	cq->cqn = resp_drv->cqn;
	cq->flags = resp_drv->cap_flags;

	return 0;
}

static struct ibv_cq_ex *create_cq(struct ibv_context *context,
			 struct ibv_cq_init_attr_ex *attr)
{
	struct hns_roce_context *hr_ctx = to_hr_ctx(context);
	struct hns_roce_cq *cq;
	int ret;

	ret = verify_cq_create_attr(attr, hr_ctx);
	if (ret)
		goto err;

	cq = calloc(1, sizeof(*cq));
	if (!cq) {
		errno = ENOMEM;
		goto err;
	}

	ret = pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);
	if (ret)
		goto err_lock;

	cq->cq_depth = attr->cqe;
	cq->cqe_size = hr_ctx->cqe_size;

	ret = hns_roce_alloc_cq_buf(cq);
	if (ret)
		goto err_buf;

	cq->db = hns_roce_alloc_db(hr_ctx, HNS_ROCE_CQ_TYPE_DB);
	if (!cq->db) {
		ret = ENOMEM;
		goto err_db;
	}

	*cq->db = 0;

	ret = exec_cq_create_cmd(context, cq, attr);
	if (ret)
		goto err_cmd;

	cq->arm_sn = 1;

	return &cq->verbs_cq.cq_ex;

err_cmd:
	hns_roce_free_db(hr_ctx, cq->db, HNS_ROCE_CQ_TYPE_DB);
err_db:
	hns_roce_free_buf(&cq->buf);
err_lock:
err_buf:
	free(cq);
err:
	if (ret < 0)
		ret = -ret;

	errno = ret;
	return NULL;
}

struct ibv_cq *hns_roce_u_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct ibv_cq_ex *cq;
	struct ibv_cq_init_attr_ex attr = {
		.cqe = cqe,
		.channel = channel,
		.comp_vector = comp_vector,
	};

	cq = create_cq(context, &attr);
	return cq ? ibv_cq_ex_to_cq(cq) : NULL;
}

struct ibv_cq_ex *hns_roce_u_create_cq_ex(struct ibv_context *context,
					  struct ibv_cq_init_attr_ex *attr)
{
	struct ibv_cq_ex *cq;

	cq = create_cq(context, attr);
	if (cq)
		hns_roce_attach_cq_ex_ops(cq, attr->wc_flags);

	return cq;
}

void hns_roce_u_cq_event(struct ibv_cq *cq)
{
	to_hr_cq(cq)->arm_sn++;
}

int hns_roce_u_modify_cq(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr)
{
	struct ibv_modify_cq cmd = {};

	return ibv_cmd_modify_cq(cq, attr, &cmd, sizeof(cmd));
}

int hns_roce_u_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	hns_roce_free_db(to_hr_ctx(cq->context), to_hr_cq(cq)->db,
				   HNS_ROCE_CQ_TYPE_DB);
	hns_roce_free_buf(&to_hr_cq(cq)->buf);
	free(to_hr_cq(cq));

	return ret;
}

static int hns_roce_store_srq(struct hns_roce_context *ctx,
			      struct hns_roce_srq *srq)
{
	uint32_t tind = to_hr_srq_table_index(srq->srqn, ctx);

	pthread_mutex_lock(&ctx->srq_table_mutex);

	if (!ctx->srq_table[tind].refcnt) {
		ctx->srq_table[tind].table =
					calloc(ctx->srq_table_mask + 1,
					       sizeof(struct hns_roce_srq *));
		if (!ctx->srq_table[tind].table) {
			pthread_mutex_unlock(&ctx->srq_table_mutex);
			return -ENOMEM;
		}
	}

	++ctx->srq_table[tind].refcnt;
	ctx->srq_table[tind].table[srq->srqn & ctx->srq_table_mask] = srq;

	pthread_mutex_unlock(&ctx->srq_table_mutex);

	return 0;
}

struct hns_roce_srq *hns_roce_find_srq(struct hns_roce_context *ctx,
				       uint32_t srqn)
{
	uint32_t tind = to_hr_srq_table_index(srqn, ctx);

	if (ctx->srq_table[tind].refcnt)
		return ctx->srq_table[tind].table[srqn & ctx->srq_table_mask];
	else
		return NULL;
}

static void hns_roce_clear_srq(struct hns_roce_context *ctx, uint32_t srqn)
{
	uint32_t tind = to_hr_srq_table_index(srqn, ctx);

	pthread_mutex_lock(&ctx->srq_table_mutex);

	if (!--ctx->srq_table[tind].refcnt)
		free(ctx->srq_table[tind].table);
	else
		ctx->srq_table[tind].table[srqn & ctx->srq_table_mask] = NULL;

	pthread_mutex_unlock(&ctx->srq_table_mutex);
}

static int verify_srq_create_attr(struct hns_roce_context *context,
				  struct ibv_srq_init_attr_ex *attr)
{
	if (attr->srq_type != IBV_SRQT_BASIC &&
	    attr->srq_type != IBV_SRQT_XRC)
		return -EINVAL;

	if (!attr->attr.max_sge ||
	    attr->attr.max_wr > context->max_srq_wr ||
	    attr->attr.max_sge > context->max_srq_sge)
		return -EINVAL;

	attr->attr.max_wr = max_t(uint32_t, attr->attr.max_wr,
				  HNS_ROCE_MIN_SRQ_WQE_NUM);

	return 0;
}

static void set_srq_param(struct ibv_context *context, struct hns_roce_srq *srq,
			  struct ibv_srq_init_attr_ex *attr)
{
	struct hns_roce_context *ctx = to_hr_ctx(context);

	if (to_hr_dev(context->device)->hw_version == HNS_ROCE_HW_VER2)
		srq->rsv_sge = 1;

	srq->wqe_cnt = roundup_pow_of_two(attr->attr.max_wr);
	srq->max_gs = roundup_pow_of_two(attr->attr.max_sge + srq->rsv_sge);
	srq->wqe_shift = hr_ilog32(roundup_pow_of_two(HNS_ROCE_SGE_SIZE *
						      srq->max_gs));
	attr->attr.max_sge = srq->max_gs;
	attr->attr.srq_limit = 0;

	srq->srq_rinl_buf.wqe_cnt = 0;
	if (ctx->config & HNS_ROCE_RSP_CQE_INLINE_FLAGS)
		srq->srq_rinl_buf.wqe_cnt = srq->wqe_cnt;
}

static int alloc_srq_idx_que(struct hns_roce_srq *srq)
{
	struct hns_roce_idx_que	*idx_que = &srq->idx_que;
	unsigned int buf_size;
	int i;

	idx_que->entry_shift = hr_ilog32(HNS_ROCE_IDX_QUE_ENTRY_SZ);
	idx_que->bitmap_cnt = align(srq->wqe_cnt, BIT_CNT_PER_LONG) /
				    BIT_CNT_PER_LONG;
	idx_que->bitmap = calloc(idx_que->bitmap_cnt, sizeof(unsigned long));
	if (!idx_que->bitmap)
		return -ENOMEM;

	buf_size = to_hr_hem_entries_size(srq->wqe_cnt, idx_que->entry_shift);
	if (hns_roce_alloc_buf(&idx_que->buf, buf_size, HNS_HW_PAGE_SIZE)) {
		free(idx_que->bitmap);
		idx_que->bitmap = NULL;
		return -ENOMEM;
	}

	/* init the idx_que bitmap */
	for (i = 0; i < idx_que->bitmap_cnt; ++i)
		idx_que->bitmap[i] = ~(0UL);

	idx_que->head = 0;
	idx_que->tail = 0;

	return 0;
}

static int alloc_srq_wqe_buf(struct hns_roce_srq *srq)
{
	int buf_size = to_hr_hem_entries_size(srq->wqe_cnt, srq->wqe_shift);

	return hns_roce_alloc_buf(&srq->wqe_buf, buf_size, HNS_HW_PAGE_SIZE);
}

static int alloc_recv_rinl_buf(uint32_t max_sge,
			       struct hns_roce_rinl_buf *rinl_buf);

static void free_recv_rinl_buf(struct hns_roce_rinl_buf *rinl_buf);

static int alloc_srq_buf(struct hns_roce_srq *srq)
{
	int ret;

	ret = alloc_srq_idx_que(srq);
	if (ret)
		return ret;

	ret = alloc_srq_wqe_buf(srq);
	if (ret)
		goto err_idx_que;

	if (srq->srq_rinl_buf.wqe_cnt) {
		ret = alloc_recv_rinl_buf(srq->max_gs, &srq->srq_rinl_buf);
		if (ret)
			goto err_wqe_buf;
	}

	srq->wrid = calloc(srq->wqe_cnt, sizeof(*srq->wrid));
	if (!srq->wrid) {
		ret = -ENOMEM;
		goto err_inl_buf;
	}

	return 0;

err_inl_buf:
	free_recv_rinl_buf(&srq->srq_rinl_buf);
err_wqe_buf:
	hns_roce_free_buf(&srq->wqe_buf);
err_idx_que:
	hns_roce_free_buf(&srq->idx_que.buf);
	free(srq->idx_que.bitmap);

	return ret;
}

static void free_srq_buf(struct hns_roce_srq *srq)
{
	free(srq->wrid);
	hns_roce_free_buf(&srq->wqe_buf);
	free_recv_rinl_buf(&srq->srq_rinl_buf);
	hns_roce_free_buf(&srq->idx_que.buf);
	free(srq->idx_que.bitmap);
}

static int exec_srq_create_cmd(struct ibv_context *context,
			       struct hns_roce_srq *srq,
			       struct ibv_srq_init_attr_ex *init_attr)
{
	struct hns_roce_create_srq_ex_resp resp_ex = {};
	struct hns_roce_create_srq_ex cmd_ex = {};
	int ret;

	cmd_ex.buf_addr = (uintptr_t)srq->wqe_buf.buf;
	cmd_ex.que_addr = (uintptr_t)srq->idx_que.buf.buf;
	cmd_ex.db_addr = (uintptr_t)srq->rdb;
	cmd_ex.req_cap_flags |= HNS_ROCE_SRQ_CAP_RECORD_DB;

	ret = ibv_cmd_create_srq_ex(context, &srq->verbs_srq, init_attr,
				    &cmd_ex.ibv_cmd, sizeof(cmd_ex),
				    &resp_ex.ibv_resp, sizeof(resp_ex));
	if (ret)
		return ret;

	srq->srqn = resp_ex.srqn;
	srq->cap_flags = resp_ex.cap_flags;

	return 0;
}

static struct ibv_srq *create_srq(struct ibv_context *context,
				  struct ibv_srq_init_attr_ex *init_attr)
{
	struct hns_roce_context *hr_ctx = to_hr_ctx(context);
	struct hns_roce_srq *srq;
	int ret;

	ret = verify_srq_create_attr(hr_ctx, init_attr);
	if (ret)
		goto err;

	srq = calloc(1, sizeof(*srq));
	if (!srq) {
		ret = -ENOMEM;
		goto err;
	}

	if (pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_free_srq;

	set_srq_param(context, srq, init_attr);
	if (alloc_srq_buf(srq))
		goto err_free_srq;

	srq->rdb = hns_roce_alloc_db(hr_ctx, HNS_ROCE_SRQ_TYPE_DB);
	if (!srq->rdb)
		goto err_srq_buf;

	*srq->rdb = 0;

	ret = exec_srq_create_cmd(context, srq, init_attr);
	if (ret)
		goto err_srq_db;

	ret = hns_roce_store_srq(hr_ctx, srq);
	if (ret)
		goto err_destroy_srq;

	srq->max_gs = init_attr->attr.max_sge;
	init_attr->attr.max_sge =
		min(init_attr->attr.max_sge - srq->rsv_sge, hr_ctx->max_srq_sge);

	return &srq->verbs_srq.srq;

err_destroy_srq:
	ibv_cmd_destroy_srq(&srq->verbs_srq.srq);

err_srq_db:
	hns_roce_free_db(hr_ctx, srq->rdb, HNS_ROCE_SRQ_TYPE_DB);

err_srq_buf:
	free_srq_buf(srq);

err_free_srq:
	free(srq);

err:
	if (ret < 0)
		ret = -ret;

	errno = ret;
	return NULL;
}

struct ibv_srq *hns_roce_u_create_srq(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *attr)
{
	struct ibv_srq_init_attr_ex attrx = {};
	struct ibv_srq *srq;

	memcpy(&attrx, attr, sizeof(*attr));
	attrx.comp_mask = IBV_SRQ_INIT_ATTR_PD;
	attrx.pd = pd;

	srq = create_srq(pd->context, &attrx);
	if (srq)
		memcpy(attr, &attrx, sizeof(*attr));

	return srq;
}

struct ibv_srq *hns_roce_u_create_srq_ex(struct ibv_context *context,
					 struct ibv_srq_init_attr_ex *attr)
{
	return create_srq(context, attr);
}

int hns_roce_u_get_srq_num(struct ibv_srq *ibv_srq, uint32_t *srq_num)
{
	*srq_num = to_hr_srq(ibv_srq)->srqn;

	return 0;
}

int hns_roce_u_modify_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
			  int srq_attr_mask)
{
	struct ibv_modify_srq cmd;

	return ibv_cmd_modify_srq(srq, srq_attr, srq_attr_mask, &cmd,
				  sizeof(cmd));
}

int hns_roce_u_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr)
{
	struct ibv_query_srq cmd;
	int ret;

	ret = ibv_cmd_query_srq(srq, srq_attr, &cmd, sizeof(cmd));
	srq_attr->max_sge -= to_hr_srq(srq)->rsv_sge;

	return ret;
}

int hns_roce_u_destroy_srq(struct ibv_srq *ibv_srq)
{
	struct hns_roce_context *ctx = to_hr_ctx(ibv_srq->context);
	struct hns_roce_srq *srq = to_hr_srq(ibv_srq);
	int ret;

	ret = ibv_cmd_destroy_srq(ibv_srq);
	if (ret)
		return ret;

	hns_roce_clear_srq(ctx, srq->srqn);

	hns_roce_free_db(ctx, srq->rdb, HNS_ROCE_SRQ_TYPE_DB);
	free_srq_buf(srq);
	free(srq);

	return 0;
}

enum {
	HNSDV_QP_SUP_COMP_MASK = HNSDV_QP_INIT_ATTR_MASK_QP_CONGEST_TYPE,
};

static int check_hnsdv_qp_attr(struct hns_roce_context *ctx,
			       struct hnsdv_qp_init_attr *hns_attr)
{
	if (!hns_attr)
		return 0;

	if (!check_comp_mask(hns_attr->comp_mask, HNSDV_QP_SUP_COMP_MASK)) {
		verbs_err(&ctx->ibv_ctx, "invalid hnsdv comp_mask 0x%x.\n",
			  hns_attr->comp_mask);
		return EINVAL;
	}

	return 0;
}

enum {
	CREATE_QP_SUP_COMP_MASK = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_XRCD |
				  IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
};

static int check_qp_create_mask(struct hns_roce_context *ctx,
				struct ibv_qp_init_attr_ex *attr)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ctx->ibv_ctx.context.device);

	if (!check_comp_mask(attr->comp_mask, CREATE_QP_SUP_COMP_MASK))
		return EOPNOTSUPP;

	switch (attr->qp_type) {
	case IBV_QPT_UD:
		if (hr_dev->hw_version == HNS_ROCE_HW_VER2)
			return EINVAL;
		SWITCH_FALLTHROUGH;
	case IBV_QPT_RC:
	case IBV_QPT_XRC_SEND:
		if (!(attr->comp_mask & IBV_QP_INIT_ATTR_PD))
			return EINVAL;
		break;
	case IBV_QPT_XRC_RECV:
		if (!(attr->comp_mask & IBV_QP_INIT_ATTR_XRCD))
			return EINVAL;
		break;
	default:
		return EOPNOTSUPP;
	}

	return 0;
}

static int hns_roce_qp_has_rq(struct ibv_qp_init_attr_ex *attr)
{
	if (attr->qp_type == IBV_QPT_XRC_SEND ||
	    attr->qp_type == IBV_QPT_XRC_RECV || attr->srq)
		return 0;

	return 1;
}

static int verify_qp_create_cap(struct hns_roce_context *ctx,
				struct ibv_qp_init_attr_ex *attr)
{
	struct ibv_qp_cap *cap = &attr->cap;
	uint32_t min_wqe_num;
	int has_rq;

	if (!cap->max_send_wr && attr->qp_type != IBV_QPT_XRC_RECV)
		return -EINVAL;

	if (cap->max_send_wr > ctx->max_qp_wr ||
	    cap->max_recv_wr > ctx->max_qp_wr ||
	    cap->max_send_sge > ctx->max_sge  ||
	    cap->max_recv_sge > ctx->max_sge)
		return -EINVAL;

	has_rq = hns_roce_qp_has_rq(attr);
	if (!has_rq) {
		cap->max_recv_wr = 0;
		cap->max_recv_sge = 0;
	}

	min_wqe_num = HNS_ROCE_V2_MIN_WQE_NUM;
	if (cap->max_send_wr < min_wqe_num)
		cap->max_send_wr = min_wqe_num;

	if (cap->max_recv_wr) {
		if (cap->max_recv_wr < min_wqe_num)
			cap->max_recv_wr = min_wqe_num;

		if (!cap->max_recv_sge)
			return -EINVAL;
	}

	return 0;
}

static int verify_qp_create_attr(struct hns_roce_context *ctx,
				 struct ibv_qp_init_attr_ex *attr,
				 struct hnsdv_qp_init_attr *hns_attr)
{
	int ret;

	ret = check_qp_create_mask(ctx, attr);
	if (ret)
		return ret;

	ret = check_hnsdv_qp_attr(ctx, hns_attr);
	if (ret)
		return ret;

	return verify_qp_create_cap(ctx, attr);
}

static int alloc_recv_rinl_buf(uint32_t max_sge,
			       struct hns_roce_rinl_buf *rinl_buf)
{
	unsigned int cnt;
	int i;

	cnt = rinl_buf->wqe_cnt;
	rinl_buf->wqe_list = calloc(cnt, sizeof(struct hns_roce_rinl_wqe));
	if (!rinl_buf->wqe_list)
		return ENOMEM;

	rinl_buf->wqe_list[0].sg_list = calloc(cnt * max_sge,
					       sizeof(struct ibv_sge));
	if (!rinl_buf->wqe_list[0].sg_list) {
		free(rinl_buf->wqe_list);
		return ENOMEM;
	}

	for (i = 0; i < cnt; i++) {
		int wqe_size = i * max_sge;

		rinl_buf->wqe_list[i].sg_list =
			  &rinl_buf->wqe_list[0].sg_list[wqe_size];
	}

	return 0;
}

static void free_recv_rinl_buf(struct hns_roce_rinl_buf *rinl_buf)
{
	if (rinl_buf->wqe_list) {
		if (rinl_buf->wqe_list[0].sg_list) {
			free(rinl_buf->wqe_list[0].sg_list);
			rinl_buf->wqe_list[0].sg_list = NULL;
		}

		free(rinl_buf->wqe_list);
		rinl_buf->wqe_list = NULL;
	}
}

static void get_best_multi_region_pg_shift(struct hns_roce_device *hr_dev,
					   struct hns_roce_context *ctx,
					   struct hns_roce_qp *qp)
{
	uint32_t ext_sge_size;
	uint32_t sq_size;
	uint32_t rq_size;
	uint8_t pg_shift;

	if (!(ctx->config & HNS_ROCE_RSP_UCTX_DYN_QP_PGSZ_FLAGS)) {
		qp->pageshift = HNS_HW_PAGE_SHIFT;
		return;
	}

	/*
	* The larger the pagesize used, the better the performance, but it
	* may waste more memory. Therefore, we use the least common multiple
	* (aligned to power of 2) of sq wqe buffer size and rq wqe buffer
	* size as the pagesize. And the wqe buffer page cannot be larger
	* than the buffer size used by extend sge. Additionally, since the
	* kernel cannot guarantee the allocation of contiguous memory larger
	* than the system page, the pagesize must be smaller than the system
	* page.
	*/
	sq_size = qp->sq.wqe_cnt << qp->sq.wqe_shift;
	ext_sge_size = qp->ex_sge.sge_cnt << qp->ex_sge.sge_shift;
	rq_size = qp->rq.wqe_cnt << qp->rq.wqe_shift;

	pg_shift = max_t(uint8_t, sq_size ? hr_ilog32(sq_size) : 0,
			 rq_size ? hr_ilog32(rq_size) : 0);
	pg_shift = ext_sge_size ?
		   min_t(uint8_t, pg_shift, hr_ilog32(ext_sge_size)) :
		   pg_shift;
	pg_shift = max_t(uint8_t, pg_shift,  HNS_HW_PAGE_SHIFT);
	qp->pageshift = min_t(uint8_t, pg_shift, hr_ilog32(hr_dev->page_size));
}

static int calc_qp_buff_size(struct hns_roce_device *hr_dev,
			     struct hns_roce_context *ctx,
			     struct hns_roce_qp *qp)
{
	struct hns_roce_wq *sq = &qp->sq;
	struct hns_roce_wq *rq = &qp->rq;
	unsigned int page_size;
	unsigned int size;

	qp->buf_size = 0;
	get_best_multi_region_pg_shift(hr_dev, ctx, qp);
	page_size = 1 << qp->pageshift;

	/* SQ WQE */
	sq->offset = 0;
	size = align(sq->wqe_cnt << sq->wqe_shift, page_size);
	qp->buf_size += size;

	/* extend SGE WQE in SQ */
	qp->ex_sge.offset = qp->buf_size;
	if (qp->ex_sge.sge_cnt > 0) {
		size = align(qp->ex_sge.sge_cnt << qp->ex_sge.sge_shift,
			     page_size);
		qp->buf_size += size;
	}

	/* RQ WQE */
	rq->offset = qp->buf_size;
	size = align(rq->wqe_cnt << rq->wqe_shift, page_size);
	qp->buf_size += size;

	if (qp->buf_size < 1)
		return EINVAL;

	return 0;
}

static void qp_free_wqe(struct hns_roce_qp *qp)
{
	free_recv_rinl_buf(&qp->rq_rinl_buf);
	if (qp->sq.wqe_cnt)
		free(qp->sq.wrid);

	if (qp->rq.wqe_cnt)
		free(qp->rq.wrid);
	hns_roce_free_buf(&qp->buf);
}

static int qp_alloc_wqe(struct ibv_qp_cap *cap, struct hns_roce_qp *qp,
			struct hns_roce_context *ctx)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ctx->ibv_ctx.context.device);

	if (calc_qp_buff_size(hr_dev, ctx, qp))
		return -EINVAL;

	qp->sq.wrid = malloc(qp->sq.wqe_cnt * sizeof(uint64_t));
	if (!qp->sq.wrid)
		return -ENOMEM;

	if (qp->rq.wqe_cnt) {
		qp->rq.wrid = malloc(qp->rq.wqe_cnt * sizeof(uint64_t));
		if (!qp->rq.wrid)
			goto err_alloc;
	}

	if (qp->rq_rinl_buf.wqe_cnt) {
		if (alloc_recv_rinl_buf(cap->max_recv_sge, &qp->rq_rinl_buf))
			goto err_alloc;
	}

	if (hns_roce_alloc_buf(&qp->buf, qp->buf_size, 1 << qp->pageshift))
		goto err_alloc;

	return 0;

err_alloc:
	free_recv_rinl_buf(&qp->rq_rinl_buf);
	if (qp->rq.wrid)
		free(qp->rq.wrid);

	if (qp->sq.wrid)
		free(qp->sq.wrid);

	return -ENOMEM;
}

/**
 *  Calculated sge num according to attr's max_send_sge
 */
static unsigned int get_sge_num_from_max_send_sge(bool is_ud,
						  uint32_t max_send_sge)
{
	unsigned int std_sge_num;
	unsigned int min_sge;

	std_sge_num = is_ud ? 0 : HNS_ROCE_SGE_IN_WQE;
	min_sge = is_ud ? 1 : 0;
	return max_send_sge > std_sge_num ? (max_send_sge - std_sge_num) :
				min_sge;
}

/**
 *  Calculated sge num according to attr's max_inline_data
 */
static unsigned int get_sge_num_from_max_inl_data(bool is_ud,
						  uint32_t max_inline_data)
{
	unsigned int inline_sge = 0;

	inline_sge = max_inline_data / HNS_ROCE_SGE_SIZE;
	/*
	 * if max_inline_data less than
	 * HNS_ROCE_SGE_IN_WQE * HNS_ROCE_SGE_SIZE,
	 * In addition to ud's mode, no need to extend sge.
	 */
	if (!is_ud && inline_sge <= HNS_ROCE_SGE_IN_WQE)
		inline_sge = 0;

	return inline_sge;
}

static void set_ext_sge_param(struct hns_roce_context *ctx,
			      struct ibv_qp_init_attr_ex *attr,
			      struct hns_roce_qp *qp, unsigned int wr_cnt)
{
	bool is_ud = (qp->verbs_qp.qp.qp_type == IBV_QPT_UD);
	unsigned int ext_wqe_sge_cnt;
	unsigned int inline_ext_sge;
	unsigned int total_sge_cnt;
	unsigned int std_sge_num;

	qp->ex_sge.sge_shift = HNS_ROCE_SGE_SHIFT;
	std_sge_num = is_ud ? 0 : HNS_ROCE_SGE_IN_WQE;
	ext_wqe_sge_cnt = get_sge_num_from_max_send_sge(is_ud,
							attr->cap.max_send_sge);

	if (ctx->config & HNS_ROCE_RSP_EXSGE_FLAGS) {
		attr->cap.max_inline_data = min_t(uint32_t, roundup_pow_of_two(
						  attr->cap.max_inline_data),
						  ctx->max_inline_data);

		inline_ext_sge = max(ext_wqe_sge_cnt,
				     get_sge_num_from_max_inl_data(is_ud,
						    attr->cap.max_inline_data));
		qp->sq.ext_sge_cnt = inline_ext_sge ?
					roundup_pow_of_two(inline_ext_sge) : 0;
		qp->sq.max_gs = min((qp->sq.ext_sge_cnt + std_sge_num),
				    ctx->max_sge);

		ext_wqe_sge_cnt = qp->sq.ext_sge_cnt;
	} else {
		qp->sq.max_gs = max(1U, attr->cap.max_send_sge);
		qp->sq.max_gs = min(qp->sq.max_gs, ctx->max_sge);
		qp->sq.ext_sge_cnt = qp->sq.max_gs;
	}

	/* If the number of extended sge is not zero, they MUST use the
	 * space of HNS_HW_PAGE_SIZE at least.
	 */
	if (ext_wqe_sge_cnt) {
		total_sge_cnt = roundup_pow_of_two(wr_cnt * ext_wqe_sge_cnt);
		qp->ex_sge.sge_cnt = max(total_sge_cnt,
					 (unsigned int)HNS_HW_PAGE_SIZE /
					  HNS_ROCE_SGE_SIZE);
	}
}

static void hns_roce_set_qp_params(struct ibv_qp_init_attr_ex *attr,
				   struct hns_roce_qp *qp,
				   struct hns_roce_context *ctx)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ctx->ibv_ctx.context.device);
	unsigned int cnt;

	qp->verbs_qp.qp.qp_type = attr->qp_type;

	if (attr->cap.max_recv_wr) {
		if (hr_dev->hw_version == HNS_ROCE_HW_VER2)
			qp->rq.rsv_sge = 1;

		qp->rq.max_gs = roundup_pow_of_two(attr->cap.max_recv_sge +
						   qp->rq.rsv_sge);
		qp->rq.wqe_shift = hr_ilog32(HNS_ROCE_SGE_SIZE * qp->rq.max_gs);
		cnt = roundup_pow_of_two(attr->cap.max_recv_wr);
		qp->rq.wqe_cnt = cnt;
		qp->rq.shift = hr_ilog32(cnt);
		if (ctx->config & (HNS_ROCE_RSP_RQ_INLINE_FLAGS |
				   HNS_ROCE_RSP_CQE_INLINE_FLAGS))
			qp->rq_rinl_buf.wqe_cnt = cnt;

		attr->cap.max_recv_wr = qp->rq.wqe_cnt;
		attr->cap.max_recv_sge = qp->rq.max_gs;
	}

	if (attr->cap.max_send_wr) {
		qp->sq.wqe_shift = HNS_ROCE_SQWQE_SHIFT;
		cnt = roundup_pow_of_two(attr->cap.max_send_wr);
		qp->sq.wqe_cnt = cnt;
		qp->sq.shift = hr_ilog32(cnt);

		set_ext_sge_param(ctx, attr, qp, cnt);

		qp->sq.max_post = min(ctx->max_qp_wr, cnt);

		qp->sq_signal_bits = attr->sq_sig_all ? 0 : 1;

		attr->cap.max_send_wr = qp->sq.max_post;
	}
}

static void qp_free_db(struct hns_roce_qp *qp, struct hns_roce_context *ctx)
{
	if (qp->sdb)
		hns_roce_free_db(ctx, qp->sdb, HNS_ROCE_QP_TYPE_DB);

	if (qp->rdb)
		hns_roce_free_db(ctx, qp->rdb, HNS_ROCE_QP_TYPE_DB);
}

static int qp_alloc_db(struct ibv_qp_init_attr_ex *attr, struct hns_roce_qp *qp,
		       struct hns_roce_context *ctx)
{
	if (attr->cap.max_send_wr) {
		qp->sdb = hns_roce_alloc_db(ctx, HNS_ROCE_QP_TYPE_DB);
		if (!qp->sdb)
			return -ENOMEM;

		*qp->sdb = 0;
	}

	if (attr->cap.max_recv_sge) {
		qp->rdb = hns_roce_alloc_db(ctx, HNS_ROCE_QP_TYPE_DB);
		if (!qp->rdb) {
			if (qp->sdb)
				hns_roce_free_db(ctx, qp->sdb,
						 HNS_ROCE_QP_TYPE_DB);

			return -ENOMEM;
		}

		*qp->rdb = 0;
	}

	return 0;
}

static int hns_roce_store_qp(struct hns_roce_context *ctx,
			     struct hns_roce_qp *qp)
{
	uint32_t qpn = qp->verbs_qp.qp.qp_num;
	uint32_t tind = to_hr_qp_table_index(qpn, ctx);

	pthread_mutex_lock(&ctx->qp_table_mutex);
	if (!ctx->qp_table[tind].refcnt) {
		ctx->qp_table[tind].table = calloc(ctx->qp_table_mask + 1,
						  sizeof(struct hns_roce_qp *));
		if (!ctx->qp_table[tind].table) {
			pthread_mutex_unlock(&ctx->qp_table_mutex);
			return -ENOMEM;
		}
	}

	++qp->refcnt;
	++ctx->qp_table[tind].refcnt;
	ctx->qp_table[tind].table[qpn & ctx->qp_table_mask] = qp;
	pthread_mutex_unlock(&ctx->qp_table_mutex);

	return 0;
}

static int to_cmd_cong_type(uint8_t cong_type, __u64 *cmd_cong_type)
{
	switch (cong_type) {
	case HNSDV_QP_CREATE_ENABLE_DCQCN:
		*cmd_cong_type = HNS_ROCE_CREATE_QP_FLAGS_DCQCN;
		break;
	case HNSDV_QP_CREATE_ENABLE_LDCP:
		*cmd_cong_type = HNS_ROCE_CREATE_QP_FLAGS_LDCP;
		break;
	case HNSDV_QP_CREATE_ENABLE_HC3:
		*cmd_cong_type = HNS_ROCE_CREATE_QP_FLAGS_HC3;
		break;
	case HNSDV_QP_CREATE_ENABLE_DIP:
		*cmd_cong_type = HNS_ROCE_CREATE_QP_FLAGS_DIP;
		break;
	default:
		return EINVAL;
	}

	return 0;
}

static int qp_exec_create_cmd(struct ibv_qp_init_attr_ex *attr,
			      struct hns_roce_qp *qp,
			      struct hns_roce_context *ctx,
			      uint64_t *dwqe_mmap_key,
			      struct hnsdv_qp_init_attr *hns_attr)
{
	struct hns_roce_create_qp_ex_resp resp_ex = {};
	struct hns_roce_create_qp_ex cmd_ex = {};
	int ret;

	cmd_ex.sdb_addr = (uintptr_t)qp->sdb;
	cmd_ex.db_addr = (uintptr_t)qp->rdb;
	cmd_ex.buf_addr = (uintptr_t)qp->buf.buf;
	cmd_ex.log_sq_stride = qp->sq.wqe_shift;
	cmd_ex.log_sq_bb_count = hr_ilog32(qp->sq.wqe_cnt);
	cmd_ex.pageshift = qp->pageshift;

	if (hns_attr &&
	    hns_attr->comp_mask & HNSDV_QP_INIT_ATTR_MASK_QP_CONGEST_TYPE) {
		ret = to_cmd_cong_type(hns_attr->congest_type,
				       &cmd_ex.cong_type_flags);
		if (ret)
			return ret;
		cmd_ex.comp_mask |= HNS_ROCE_CREATE_QP_MASK_CONGEST_TYPE;
	}

	ret = ibv_cmd_create_qp_ex2(&ctx->ibv_ctx.context, &qp->verbs_qp, attr,
				    &cmd_ex.ibv_cmd, sizeof(cmd_ex),
				    &resp_ex.ibv_resp, sizeof(resp_ex));

	qp->flags = resp_ex.drv_payload.cap_flags;
	*dwqe_mmap_key = resp_ex.drv_payload.dwqe_mmap_key;

	return ret;
}

static void qp_setup_config(struct ibv_qp_init_attr_ex *attr,
			    struct hns_roce_qp *qp,
			    struct hns_roce_context *ctx)
{
	hns_roce_init_qp_indices(qp);

	if (qp->rq.wqe_cnt) {
		qp->rq.wqe_cnt = attr->cap.max_recv_wr;
		qp->rq.max_gs = attr->cap.max_recv_sge;

		/* adjust the RQ's cap based on the reported device's cap */
		attr->cap.max_recv_wr =
			min(ctx->max_qp_wr, attr->cap.max_recv_wr);
		attr->cap.max_recv_sge -= qp->rq.rsv_sge;
		qp->rq.max_post = attr->cap.max_recv_wr;
	}

	qp->max_inline_data = attr->cap.max_inline_data;

	if (qp->flags & HNS_ROCE_QP_CAP_DIRECT_WQE)
		qp->sq.db_reg = qp->dwqe_page;
	else
		qp->sq.db_reg = ctx->uar + ROCEE_VF_DB_CFG0_OFFSET;
}

void hns_roce_free_qp_buf(struct hns_roce_qp *qp, struct hns_roce_context *ctx)
{
	qp_free_db(qp, ctx);
	qp_free_wqe(qp);
}

static int hns_roce_alloc_qp_buf(struct ibv_qp_init_attr_ex *attr,
				 struct hns_roce_qp *qp,
				 struct hns_roce_context *ctx)
{
	int ret;

	if (pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE) ||
	    pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE))
		return -ENOMEM;

	ret = qp_alloc_wqe(&attr->cap, qp, ctx);
	if (ret)
		return ret;

	ret = qp_alloc_db(attr, qp, ctx);
	if (ret)
		qp_free_wqe(qp);

	return ret;
}

static int mmap_dwqe(struct ibv_context *ibv_ctx, struct hns_roce_qp *qp,
		     uint64_t dwqe_mmap_key)
{
	qp->dwqe_page = mmap(NULL, HNS_ROCE_DWQE_PAGE_SIZE, PROT_WRITE,
			     MAP_SHARED, ibv_ctx->cmd_fd, dwqe_mmap_key);
	if (qp->dwqe_page == MAP_FAILED)
		return -EINVAL;

	return 0;
}

static struct ibv_qp *create_qp(struct ibv_context *ibv_ctx,
				struct ibv_qp_init_attr_ex *attr,
				struct hnsdv_qp_init_attr *hns_attr)
{
	struct hns_roce_context *context = to_hr_ctx(ibv_ctx);
	struct hns_roce_qp *qp;
	uint64_t dwqe_mmap_key;
	int ret;

	ret = verify_qp_create_attr(context, attr, hns_attr);
	if (ret)
		goto err;

	qp = calloc(1, sizeof(*qp));
	if (!qp) {
		ret = -ENOMEM;
		goto err;
	}

	hns_roce_set_qp_params(attr, qp, context);

	ret = hns_roce_alloc_qp_buf(attr, qp, context);
	if (ret)
		goto err_buf;

	ret = qp_exec_create_cmd(attr, qp, context, &dwqe_mmap_key, hns_attr);
	if (ret)
		goto err_cmd;

	ret = hns_roce_attach_qp_ex_ops(attr, qp);
	if (ret)
		goto err_ops;

	ret = hns_roce_store_qp(context, qp);
	if (ret)
		goto err_ops;

	if (qp->flags & HNS_ROCE_QP_CAP_DIRECT_WQE) {
		ret = mmap_dwqe(ibv_ctx, qp, dwqe_mmap_key);
		if (ret)
			goto err_dwqe;
	}

	qp_setup_config(attr, qp, context);

	return &qp->verbs_qp.qp;

err_dwqe:
	hns_roce_v2_clear_qp(context, qp);
err_ops:
	ibv_cmd_destroy_qp(&qp->verbs_qp.qp);
err_cmd:
	hns_roce_free_qp_buf(qp, context);
err_buf:
	free(qp);
err:
	if (ret < 0)
		ret = -ret;

	errno = ret;
	return NULL;
}

struct ibv_qp *hns_roce_u_create_qp(struct ibv_pd *pd,
				    struct ibv_qp_init_attr *attr)
{
	struct ibv_qp_init_attr_ex attrx = {};
	struct ibv_qp *qp;

	memcpy(&attrx, attr, sizeof(*attr));
	attrx.comp_mask = IBV_QP_INIT_ATTR_PD;
	attrx.pd = pd;

	qp = create_qp(pd->context, &attrx, NULL);
	if (qp)
		memcpy(attr, &attrx, sizeof(*attr));

	return qp;
}

struct ibv_qp *hns_roce_u_create_qp_ex(struct ibv_context *context,
				       struct ibv_qp_init_attr_ex *attr)
{
	return create_qp(context, attr, NULL);
}

struct ibv_qp *hnsdv_create_qp(struct ibv_context *context,
			       struct ibv_qp_init_attr_ex *qp_attr,
			       struct hnsdv_qp_init_attr *hns_attr)
{
	if (!context || !qp_attr) {
		errno = EINVAL;
		return NULL;
	}

	if (!is_hns_dev(context->device)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return create_qp(context, qp_attr, hns_attr);
}

int hnsdv_query_device(struct ibv_context *context,
		       struct hnsdv_context *attrs_out)
{
	struct hns_roce_device *hr_dev = to_hr_dev(context->device);

	if (!hr_dev || !attrs_out)
		return EINVAL;

	if (!is_hns_dev(context->device)) {
		verbs_err(verbs_get_ctx(context), "not a HNS RoCE device!\n");
		return EOPNOTSUPP;
	}
	memset(attrs_out, 0, sizeof(*attrs_out));

	attrs_out->comp_mask |= HNSDV_CONTEXT_MASK_CONGEST_TYPE;
	attrs_out->congest_type = hr_dev->congest_cap;

	return 0;
}

struct ibv_qp *hns_roce_u_open_qp(struct ibv_context *context,
				  struct ibv_qp_open_attr *attr)
{
	struct ib_uverbs_create_qp_resp resp;
	struct ibv_open_qp cmd;
	struct hns_roce_qp *qp;
	int ret;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	ret = ibv_cmd_open_qp(context, &qp->verbs_qp, sizeof(qp->verbs_qp),
			      attr, &cmd, sizeof(cmd), &resp, sizeof(resp));
	if (ret)
		goto err_buf;

	ret = hns_roce_store_qp(to_hr_ctx(context), qp);
	if (ret)
		goto err_cmd;

	return &qp->verbs_qp.qp;

err_cmd:
	ibv_cmd_destroy_qp(&qp->verbs_qp.qp);
err_buf:
	free(qp);
	return NULL;
}

int hns_roce_u_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
			int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct hns_roce_qp *qp = to_hr_qp(ibqp);
	struct ibv_query_qp cmd;
	int ret;

	ret = ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr, &cmd,
			       sizeof(cmd));
	if (ret)
		return ret;

	init_attr->cap.max_send_wr = qp->sq.max_post;
	init_attr->cap.max_send_sge = qp->sq.max_gs;

	if (init_attr->cap.max_recv_wr)
		init_attr->cap.max_recv_sge -= qp->rq.rsv_sge;

	attr->cap = init_attr->cap;

	return ret;
}

static uint16_t get_ah_udp_sport(const struct ibv_ah_attr *attr)
{
	uint32_t fl = attr->grh.flow_label & IB_GRH_FLOWLABEL_MASK;
	uint16_t sport;

	if (!fl)
		sport = get_random() % (IB_ROCE_UDP_ENCAP_VALID_PORT_MAX + 1 -
					IB_ROCE_UDP_ENCAP_VALID_PORT_MIN) +
			IB_ROCE_UDP_ENCAP_VALID_PORT_MIN;
	else
		sport = ibv_flow_label_to_udp_sport(fl);

	return sport;
}

static int get_tclass(struct ibv_context *context, struct ibv_ah_attr *attr,
		      uint8_t *tclass)
{
#define DSCP_SHIFT 2
	enum ibv_gid_type_sysfs gid_type;
	int ret;

	ret = ibv_query_gid_type(context, attr->port_num, attr->grh.sgid_index,
				 &gid_type);
	if (ret)
		return ret;

	*tclass = gid_type == IBV_GID_TYPE_SYSFS_ROCE_V2 ?
		  attr->grh.traffic_class >> DSCP_SHIFT :
		  attr->grh.traffic_class;

	return ret;
}

struct ibv_ah *hns_roce_u_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct hns_roce_device *hr_dev = to_hr_dev(pd->context->device);
	struct hns_roce_create_ah_resp resp = {};
	struct hns_roce_ah *ah;

	/* HIP08 don't support create ah */
	if (hr_dev->hw_version == HNS_ROCE_HW_VER2)
		return NULL;

	ah = malloc(sizeof(*ah));
	if (!ah)
		return NULL;

	memset(ah, 0, sizeof(*ah));

	ah->av.port = attr->port_num;
	ah->av.sl = attr->sl;

	if (attr->is_global) {
		ah->av.gid_index = attr->grh.sgid_index;
		ah->av.hop_limit = attr->grh.hop_limit;

		if (get_tclass(pd->context, attr, &ah->av.tclass))
			goto err;

		ah->av.flowlabel = attr->grh.flow_label;

		memcpy(ah->av.dgid, attr->grh.dgid.raw, ARRAY_SIZE(ah->av.dgid));
	}

	if (ibv_cmd_create_ah(pd, &ah->ibv_ah, attr, &resp.ibv_resp,
			      sizeof(resp)))
		goto err;

	if (memcmp(ah->av.mac, resp.dmac, ETH_ALEN))
		memcpy(ah->av.mac, resp.dmac, ETH_ALEN);
	else if (ibv_resolve_eth_l2_from_gid(pd->context, attr,
					     ah->av.mac, NULL))
		goto err;

	if (resp.tc_mode == HNS_ROCE_TC_MAP_MODE_DSCP)
		ah->av.sl = resp.priority;

	ah->av.udp_sport = get_ah_udp_sport(attr);

	return &ah->ibv_ah;

err:
	free(ah);
	return NULL;
}

int hns_roce_u_destroy_ah(struct ibv_ah *ah)
{
	int ret;

	ret = ibv_cmd_destroy_ah(ah);
	if (ret)
		return ret;

	free(to_hr_ah(ah));

	return 0;
}
