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
#include "hns_roce_u_hw_v1.h"
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
		 "%d.%d.%03d", major, minor, sub_minor);

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

struct ibv_mr *hns_roce_u_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 uint64_t hca_va, int access)
{
	int ret;
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;

	if (!addr) {
		fprintf(stderr, "2nd parm addr is NULL!\n");
		return NULL;
	}

	if (!length) {
		fprintf(stderr, "3st parm length is 0!\n");
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

	if (!bind_info->mr && bind_info->length)
		return EINVAL;

	if (mw->pd != qp->pd)
		return EINVAL;

	if (bind_info->mr && (mw->pd != bind_info->mr->pd))
		return EINVAL;

	if (mw->type != IBV_MW_TYPE_1)
		return EINVAL;

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

static int hns_roce_verify_cq(int *cqe, struct hns_roce_context *context)
{
	if (*cqe < 1 || *cqe > context->max_cqe)
		return -EINVAL;

	*cqe = max((uint64_t)HNS_ROCE_MIN_CQE_NUM, roundup_pow_of_two(*cqe));

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
			      struct hns_roce_cq *cq, int cqe,
			      struct ibv_comp_channel *channel, int comp_vector)
{
	struct hns_roce_ib_create_cq_resp *resp_drv;
	struct hns_roce_create_cq_resp resp = {};
	struct hns_roce_ib_create_cq *cmd_drv;
	struct hns_roce_create_cq cmd = {};
	int ret;

	cmd_drv = &cmd.drv_payload;
	resp_drv = &resp.drv_payload;

	cmd_drv->buf_addr = (uintptr_t)cq->buf.buf;
	cmd_drv->db_addr = (uintptr_t)cq->db;
	cmd_drv->cqe_size = (uintptr_t)cq->cqe_size;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret)
		return ret;

	cq->cqn = resp_drv->cqn;
	cq->flags = resp_drv->cap_flags;

	return 0;
}

struct ibv_cq *hns_roce_u_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct hns_roce_device *hr_dev = to_hr_dev(context->device);
	struct hns_roce_context *hr_ctx = to_hr_ctx(context);
	struct hns_roce_cq *cq;
	int ret;

	ret = hns_roce_verify_cq(&cqe, hr_ctx);
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

	cq->cq_depth = cqe;
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

	ret = exec_cq_create_cmd(context, cq, cqe, channel, comp_vector);
	if (ret)
		goto err_cmd;

	cq->arm_sn = 1;

	return &cq->ibv_cq;

err_cmd:
	if (hr_dev->hw_version != HNS_ROCE_HW_VER1)
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

	if (to_hr_dev(cq->context->device)->hw_version != HNS_ROCE_HW_VER1)
		hns_roce_free_db(to_hr_ctx(cq->context), to_hr_cq(cq)->db,
				 HNS_ROCE_CQ_TYPE_DB);
	hns_roce_free_buf(&to_hr_cq(cq)->buf);
	free(to_hr_cq(cq));

	return ret;
}

static int hns_roce_create_idx_que(struct hns_roce_srq *srq)
{
	struct hns_roce_idx_que	*idx_que = &srq->idx_que;
	unsigned int buf_size;
	int i;

	idx_que->entry_shift = hr_ilog32(HNS_ROCE_IDX_QUE_ENTRY_SZ);
	idx_que->bitmap_cnt = align(srq->wqe_cnt, BIT_CNT_PER_LONG) /
				    BIT_CNT_PER_LONG;
	idx_que->bitmap = calloc(idx_que->bitmap_cnt, sizeof(unsigned long));
	if (!idx_que->bitmap)
		return ENOMEM;

	buf_size = to_hr_hem_entries_size(srq->wqe_cnt, idx_que->entry_shift);
	if (hns_roce_alloc_buf(&idx_que->buf, buf_size, HNS_HW_PAGE_SIZE)) {
		free(idx_que->bitmap);
		idx_que->bitmap = NULL;
		return ENOMEM;
	}

	/* init the idx_que bitmap */
	for (i = 0; i < idx_que->bitmap_cnt; ++i)
		idx_que->bitmap[i] = ~(0UL);

	return 0;
}

static int hns_roce_alloc_srq_buf(struct hns_roce_srq *srq)
{
	int srq_buf_size;

	srq->wrid = calloc(srq->wqe_cnt, sizeof(unsigned long));
	if (!srq->wrid)
		return ENOMEM;

	srq->wqe_shift = hr_ilog32(roundup_pow_of_two(HNS_ROCE_SGE_SIZE *
						      srq->max_gs));
	srq_buf_size = to_hr_hem_entries_size(srq->wqe_cnt, srq->wqe_shift);

	/* allocate srq wqe buf */
	if (hns_roce_alloc_buf(&srq->buf, srq_buf_size, HNS_HW_PAGE_SIZE)) {
		free(srq->wrid);
		return ENOMEM;
	}

	srq->head = 0;
	srq->tail = srq->wqe_cnt - 1;

	return 0;
}

struct ibv_srq *hns_roce_u_create_srq(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *init_attr)
{
	struct hns_roce_create_srq	cmd;
	struct hns_roce_create_srq_resp resp;
	struct hns_roce_srq		*srq;
	int ret;

	if (init_attr->attr.max_wr > HNS_ROCE_MAX_SRQWQE_NUM ||
	    init_attr->attr.max_sge > HNS_ROCE_MAX_SRQSGE_NUM)
		return NULL;

	srq = calloc(1, sizeof(*srq));
	if (!srq)
		return NULL;

	if (pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE))
		goto out;

	srq->wqe_cnt = roundup_pow_of_two(init_attr->attr.max_wr + 1);
	srq->max_gs = init_attr->attr.max_sge;

	ret = hns_roce_create_idx_que(srq);
	if (ret)
		goto out;

	ret = hns_roce_alloc_srq_buf(srq);
	if (ret)
		goto err_idx_que;

	srq->db = hns_roce_alloc_db(to_hr_ctx(pd->context),
				    HNS_ROCE_QP_TYPE_DB);
	if (!srq->db)
		goto err_srq_buf;

	*(srq->db) = 0;
	cmd.buf_addr = (uintptr_t)srq->buf.buf;
	cmd.que_addr = (uintptr_t)srq->idx_que.buf.buf;
	cmd.db_addr = (uintptr_t)srq->db;

	ret = ibv_cmd_create_srq(pd, &srq->verbs_srq.srq, init_attr,
				&cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp,
				sizeof(resp));
	if (ret)
		goto err_srq_db;

	srq->srqn = resp.srqn;
	return &srq->verbs_srq.srq;

err_srq_db:
	hns_roce_free_db(to_hr_ctx(pd->context), srq->db, HNS_ROCE_QP_TYPE_DB);

err_srq_buf:
	free(srq->wrid);
	hns_roce_free_buf(&srq->buf);

err_idx_que:
	free(srq->idx_que.bitmap);
	hns_roce_free_buf(&srq->idx_que.buf);
out:
	free(srq);
	return NULL;
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

	return ibv_cmd_query_srq(srq, srq_attr, &cmd, sizeof(cmd));
}

int hns_roce_u_destroy_srq(struct ibv_srq *srq)
{
	int ret;

	ret = ibv_cmd_destroy_srq(srq);
	if (ret)
		return ret;

	hns_roce_free_db(to_hr_ctx(srq->context), to_hr_srq(srq)->db,
			 HNS_ROCE_QP_TYPE_DB);
	hns_roce_free_buf(&to_hr_srq(srq)->buf);
	free(to_hr_srq(srq)->wrid);
	hns_roce_free_buf(&to_hr_srq(srq)->idx_que.buf);
	free(to_hr_srq(srq)->idx_que.bitmap);
	free(to_hr_srq(srq));

	return 0;
}

enum {
	CREATE_QP_SUP_CREATE_FLAGS = 0,
};

enum {
	CREATE_QP_SUP_COMP_MASK = IBV_QP_INIT_ATTR_PD |
				  IBV_QP_INIT_ATTR_CREATE_FLAGS,
};

static int check_qp_create_mask(struct ibv_qp_init_attr_ex *attr)
{
	if (!check_comp_mask(attr->comp_mask, CREATE_QP_SUP_COMP_MASK))
		return -EOPNOTSUPP;

	if (attr->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS &&
	    !check_comp_mask(attr->create_flags, CREATE_QP_SUP_CREATE_FLAGS))
		return -EOPNOTSUPP;

	return 0;
}

static int verify_qp_create_cap(struct hns_roce_context *ctx,
				struct ibv_qp_init_attr_ex *attr)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ctx->ibv_ctx.context.device);
	struct ibv_qp_cap *cap = &attr->cap;
	uint32_t min_wqe_num;

	if (!cap->max_send_wr ||
	    cap->max_send_wr > ctx->max_qp_wr ||
	    cap->max_recv_wr > ctx->max_qp_wr ||
	    cap->max_send_sge > ctx->max_sge  ||
	    cap->max_recv_sge > ctx->max_sge)
		return -EINVAL;

	min_wqe_num = hr_dev->hw_version == HNS_ROCE_HW_VER1 ?
		      HNS_ROCE_V1_MIN_WQE_NUM : HNS_ROCE_V2_MIN_WQE_NUM;

	if (cap->max_send_wr < min_wqe_num)
		cap->max_send_wr = min_wqe_num;

	if (cap->max_recv_wr && cap->max_recv_wr < min_wqe_num)
		cap->max_recv_wr = min_wqe_num;

	if (!(attr->qp_type == IBV_QPT_RC ||
	      (attr->qp_type == IBV_QPT_UD &&
	       hr_dev->hw_version >= HNS_ROCE_HW_VER3)))
		return -EOPNOTSUPP;

	return 0;
}

static int verify_qp_create_attr(struct hns_roce_context *ctx,
				 struct ibv_qp_init_attr_ex *attr)
{
	int ret;

	ret = check_qp_create_mask(attr);
	if (ret)
		return ret;

	return verify_qp_create_cap(ctx, attr);
}

static int qp_alloc_recv_inl_buf(struct ibv_qp_cap *cap,
				 struct hns_roce_qp *qp)
{
	unsigned int cnt;
	int i;

	cnt = qp->rq_rinl_buf.wqe_cnt;
	qp->rq_rinl_buf.wqe_list = calloc(cnt,
					  sizeof(struct hns_roce_rinl_wqe));
	if (!qp->rq_rinl_buf.wqe_list)
		return ENOMEM;

	qp->rq_rinl_buf.wqe_list[0].sg_list = calloc(cnt * cap->max_recv_sge,
					sizeof(struct hns_roce_rinl_sge));
	if (!qp->rq_rinl_buf.wqe_list[0].sg_list) {
		free(qp->rq_rinl_buf.wqe_list);
		return ENOMEM;
	}

	for (i = 0; i < cnt; i++) {
		int wqe_size = i * cap->max_recv_sge;

		qp->rq_rinl_buf.wqe_list[i].sg_list =
			  &(qp->rq_rinl_buf.wqe_list[0].sg_list[wqe_size]);
	}

	return 0;
}

static void qp_free_recv_inl_buf(struct hns_roce_qp *qp)
{
	if (qp->rq_rinl_buf.wqe_list) {
		if (qp->rq_rinl_buf.wqe_list[0].sg_list) {
			free(qp->rq_rinl_buf.wqe_list[0].sg_list);
			qp->rq_rinl_buf.wqe_list[0].sg_list = NULL;
		}

		free(qp->rq_rinl_buf.wqe_list);
		qp->rq_rinl_buf.wqe_list = NULL;
	}
}

static int calc_qp_buff_size(struct hns_roce_device *hr_dev,
			     struct hns_roce_qp *qp)
{
	struct hns_roce_wq *sq, *rq;
	unsigned int size;

	if (hr_dev->hw_version == HNS_ROCE_HW_VER1 &&
	    qp->rq.wqe_shift > qp->sq.wqe_shift) {
		sq = &qp->rq;
		rq = &qp->sq;
	} else {
		sq = &qp->sq;
		rq = &qp->rq;
	}

	qp->buf_size = 0;

	/* SQ WQE */
	sq->offset = 0;
	size = to_hr_hem_entries_size(sq->wqe_cnt, sq->wqe_shift);
	qp->buf_size += size;

	/* extend SGE WQE in SQ */
	qp->ex_sge.offset = qp->buf_size;
	if (qp->ex_sge.sge_cnt > 0) {
		size = to_hr_hem_entries_size(qp->ex_sge.sge_cnt,
					      qp->ex_sge.sge_shift);
		qp->buf_size += size;
	}

	/* RQ WQE */
	rq->offset = qp->buf_size;
	size = to_hr_hem_entries_size(rq->wqe_cnt, rq->wqe_shift);
	qp->buf_size += size;

	if (qp->buf_size < 1)
		return EINVAL;

	return 0;
}

static void qp_free_wqe(struct hns_roce_qp *qp)
{
	qp_free_recv_inl_buf(qp);
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

	if (calc_qp_buff_size(hr_dev, qp))
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
		if (qp_alloc_recv_inl_buf(cap, qp))
			goto err_alloc;
	}

	if (hns_roce_alloc_buf(&qp->buf, qp->buf_size, HNS_HW_PAGE_SIZE))
		goto err_alloc;

	return 0;

err_alloc:
	qp_free_recv_inl_buf(qp);
	if (qp->rq.wrid)
		free(qp->rq.wrid);

	if (qp->sq.wrid)
		free(qp->sq.wrid);

	return -ENOMEM;
}

static void set_extend_sge_param(struct hns_roce_device *hr_dev,
				 struct ibv_qp_init_attr_ex *attr,
				 struct hns_roce_qp *qp, unsigned int wr_cnt)
{
	int cnt = 0;

	if (hr_dev->hw_version == HNS_ROCE_HW_VER1) {
		qp->sq.max_gs = HNS_ROCE_SGE_IN_WQE;
	} else {
		qp->sq.max_gs = attr->cap.max_send_sge;
		if (attr->qp_type == IBV_QPT_UD)
			cnt = roundup_pow_of_two(wr_cnt * qp->sq.max_gs);
		else if (qp->sq.max_gs > HNS_ROCE_SGE_IN_WQE)
			cnt = roundup_pow_of_two(wr_cnt *
						 (qp->sq.max_gs -
						  HNS_ROCE_SGE_IN_WQE));
	}

	qp->ex_sge.sge_shift = HNS_ROCE_SGE_SHIFT;
	qp->ex_sge.sge_cnt = cnt;
}

static void hns_roce_set_qp_params(struct ibv_qp_init_attr_ex *attr,
				   struct hns_roce_qp *qp,
				   struct hns_roce_context *ctx)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ctx->ibv_ctx.context.device);
	unsigned int cnt;

	qp->verbs_qp.qp.qp_type = attr->qp_type;

	if (attr->cap.max_recv_wr) {
		qp->rq.max_gs = max(1U, attr->cap.max_recv_sge);
		if (hr_dev->hw_version == HNS_ROCE_HW_VER1)
			qp->rq.wqe_shift =
				hr_ilog32(sizeof(struct hns_roce_rc_rq_wqe));
		else
			qp->rq.wqe_shift =
				hr_ilog32(HNS_ROCE_SGE_SIZE * qp->rq.max_gs);

		cnt = roundup_pow_of_two(attr->cap.max_recv_wr);
		qp->rq.wqe_cnt = cnt;
		qp->rq.shift = hr_ilog32(cnt);
		if (hr_dev->hw_version == HNS_ROCE_HW_VER1)
			qp->rq_rinl_buf.wqe_cnt = 0;
		else
			qp->rq_rinl_buf.wqe_cnt = cnt;
	}

	if (attr->cap.max_send_wr) {
		qp->sq.wqe_shift =
			hr_ilog32(sizeof(struct hns_roce_rc_send_wqe));
		cnt = roundup_pow_of_two(attr->cap.max_send_wr);
		qp->sq.wqe_cnt = cnt;
		qp->sq.shift = hr_ilog32(cnt);

		set_extend_sge_param(hr_dev, attr, qp, cnt);

		qp->sq.max_post = min(ctx->max_qp_wr, cnt);
		qp->sq.max_gs = min(ctx->max_sge, qp->sq.max_gs);

		qp->sq_signal_bits = attr->sq_sig_all ? 0 : 1;

		attr->cap.max_send_wr = qp->sq.max_post;
	}
}

static void qp_free_db(struct hns_roce_qp *qp, struct hns_roce_context *ctx)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ctx->ibv_ctx.context.device);

	if (hr_dev->hw_version == HNS_ROCE_HW_VER1)
		return;

	if (qp->sdb)
		hns_roce_free_db(ctx, qp->sdb, HNS_ROCE_QP_TYPE_DB);

	if (qp->rdb)
		hns_roce_free_db(ctx, qp->rdb, HNS_ROCE_QP_TYPE_DB);
}

static int qp_alloc_db(struct ibv_qp_init_attr_ex *attr, struct hns_roce_qp *qp,
		       struct hns_roce_context *ctx)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ctx->ibv_ctx.context.device);

	if (hr_dev->hw_version == HNS_ROCE_HW_VER1)
		return 0;

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

static int hns_roce_store_qp(struct hns_roce_context *ctx, uint32_t qpn,
			     struct hns_roce_qp *qp)
{
	uint32_t tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;

	pthread_mutex_lock(&ctx->qp_table_mutex);
	if (!ctx->qp_table[tind].refcnt) {
		ctx->qp_table[tind].table = calloc(ctx->qp_table_mask + 1,
						  sizeof(struct hns_roce_qp *));
		if (!ctx->qp_table[tind].table) {
			pthread_mutex_unlock(&ctx->qp_table_mutex);
			return -ENOMEM;
		}
	}

	++ctx->qp_table[tind].refcnt;
	ctx->qp_table[tind].table[qpn & ctx->qp_table_mask] = qp;
	pthread_mutex_unlock(&ctx->qp_table_mutex);

	return 0;
}

static int qp_exec_create_cmd(struct ibv_qp_init_attr_ex *attr,
			      struct hns_roce_qp *qp,
			      struct hns_roce_context *ctx)
{
	struct hns_roce_create_qp_ex_resp resp_ex = {};
	struct hns_roce_create_qp_ex cmd_ex = {};
	int ret;

	cmd_ex.sdb_addr = (uintptr_t)qp->sdb;
	cmd_ex.db_addr = (uintptr_t)qp->rdb;
	cmd_ex.buf_addr = (uintptr_t)qp->buf.buf;
	cmd_ex.log_sq_stride = qp->sq.wqe_shift;
	cmd_ex.log_sq_bb_count = hr_ilog32(qp->sq.wqe_cnt);

	ret = ibv_cmd_create_qp_ex2(&ctx->ibv_ctx.context, &qp->verbs_qp, attr,
				    &cmd_ex.ibv_cmd, sizeof(cmd_ex),
				    &resp_ex.ibv_resp, sizeof(resp_ex));

	qp->flags = resp_ex.drv_payload.cap_flags;

	return ret;
}

static void qp_setup_config(struct ibv_qp_init_attr_ex *attr,
			    struct hns_roce_qp *qp,
			    struct hns_roce_context *ctx)
{
	hns_roce_init_qp_indices(qp);

	/* adjust rq maxima to not exceed reported device maxima */
	attr->cap.max_recv_wr = min(ctx->max_qp_wr, attr->cap.max_recv_wr);
	attr->cap.max_recv_sge = min(ctx->max_sge, attr->cap.max_recv_sge);
	qp->rq.wqe_cnt = attr->cap.max_recv_wr;
	qp->rq.max_gs = attr->cap.max_recv_sge;
	qp->rq.max_post = attr->cap.max_recv_wr;

	qp->max_inline_data = attr->cap.max_inline_data;
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

static struct ibv_qp *create_qp(struct ibv_context *ibv_ctx,
				struct ibv_qp_init_attr_ex *attr)
{
	struct hns_roce_context *context = to_hr_ctx(ibv_ctx);
	struct hns_roce_qp *qp;
	int ret;

	ret = verify_qp_create_attr(context, attr);
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

	ret = qp_exec_create_cmd(attr, qp, context);
	if (ret)
		goto err_cmd;

	ret = hns_roce_store_qp(context, qp->verbs_qp.qp.qp_num, qp);
	if (ret)
		goto err_store;

	qp_setup_config(attr, qp, context);

	return &qp->verbs_qp.qp;

err_store:
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

	qp = create_qp(pd->context, &attrx);
	if (qp)
		memcpy(attr, &attrx, sizeof(*attr));

	return qp;
}

struct ibv_qp *hns_roce_u_create_qp_ex(struct ibv_context *context,
				       struct ibv_qp_init_attr_ex *attr)
{
	return create_qp(context, attr);
}

int hns_roce_u_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
			int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	int ret;
	struct ibv_query_qp cmd;
	struct hns_roce_qp *qp = to_hr_qp(ibqp);

	ret = ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr, &cmd,
			       sizeof(cmd));
	if (ret)
		return ret;

	init_attr->cap.max_send_wr = qp->sq.max_post;
	init_attr->cap.max_send_sge = qp->sq.max_gs;

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
	struct ib_uverbs_create_ah_resp resp = {};
	struct hns_roce_ah *ah;

	/* HIP08 don't support create ah */
	if (hr_dev->hw_version < HNS_ROCE_HW_VER3)
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

	if (ibv_cmd_create_ah(pd, &ah->ibv_ah, attr, &resp, sizeof(resp)))
		goto err;

	if (ibv_resolve_eth_l2_from_gid(pd->context, attr, ah->av.mac, NULL))
		goto err;

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
