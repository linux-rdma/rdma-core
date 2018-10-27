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
#include <fcntl.h>
#include <unistd.h>
#include <ccan/minmax.h>
#include "hns_roce_u.h"
#include "hns_roce_u_abi.h"
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
			    struct ibv_device_attr *attr)
{
	int ret;
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	unsigned int major, minor, sub_minor;

	ret = ibv_cmd_query_device(context, attr, &raw_fw_ver, &cmd,
				   sizeof(cmd));
	if (ret)
		return ret;

	major	   = (raw_fw_ver >> 32) & 0xffff;
	minor	   = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof(attr->fw_ver), "%d.%d.%03d", major, minor,
		 sub_minor);

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
	struct hns_roce_alloc_pd_resp resp;

	pd = (struct hns_roce_pd *)malloc(sizeof(*pd));
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
				 int access)
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

	ret = ibv_cmd_reg_mr(pd, addr, length, (uintptr_t)addr, access, vmr,
			     &cmd, sizeof(cmd), &resp, sizeof(resp));
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

	if ((mw->pd != qp->pd) || (mw->pd != bind_info->mr->pd))
		return EINVAL;

	if (mw->type != IBV_MW_TYPE_1)
		return EINVAL;

	if (!bind_info->mr && bind_info->length)
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

static int align_cq_size(int req)
{
	int nent;

	for (nent = HNS_ROCE_MIN_CQE_NUM; nent < req; nent <<= 1)
		;

	return nent;
}

static int align_qp_size(int req)
{
	int nent;

	for (nent = HNS_ROCE_MIN_WQE_NUM; nent < req; nent <<= 1)
		;

	return nent;
}

static int align_queue_size(int req)
{
	int nent;

	for (nent = 1; nent < req; nent <<= 1)
		;

	return nent;
}

static int align_srq_size(int req)
{
	int nent;

	for (nent = 1; nent < req; nent <<= 1)
		;

	return nent;
}

static void hns_roce_set_sq_sizes(struct hns_roce_qp *qp,
				  struct ibv_qp_cap *cap, enum ibv_qp_type type)
{
	struct hns_roce_context *ctx = to_hr_ctx(qp->ibv_qp.context);

	cap->max_send_sge = min(ctx->max_sge, qp->sq.max_gs);
	qp->sq.max_post = min(ctx->max_qp_wr, qp->sq.wqe_cnt);
	cap->max_send_wr = qp->sq.max_post;
	qp->max_inline_data  = 32;
	cap->max_inline_data = qp->max_inline_data;
}

static int hns_roce_verify_cq(int *cqe, struct hns_roce_context *context)
{
	struct hns_roce_device *hr_dev =
		to_hr_dev(context->ibv_ctx.context.device);

	if (hr_dev->hw_version == HNS_ROCE_HW_VER1)
		if (*cqe < HNS_ROCE_MIN_CQE_NUM) {
			fprintf(stderr,
				"cqe = %d, less than minimum CQE number.\n",
				*cqe);
			*cqe = HNS_ROCE_MIN_CQE_NUM;
		}

	if (*cqe > context->max_cqe)
		return -1;

	return 0;
}

static int hns_roce_alloc_cq_buf(struct hns_roce_device *dev,
				 struct hns_roce_buf *buf, int nent)
{
	if (hns_roce_alloc_buf(buf,
			align(nent * HNS_ROCE_CQE_ENTRY_SIZE, dev->page_size),
			dev->page_size))
		return -1;
	memset(buf->buf, 0, nent * HNS_ROCE_CQE_ENTRY_SIZE);

	return 0;
}

static void hns_roce_calc_sq_wqe_size(struct ibv_qp_cap *cap,
				      enum ibv_qp_type type,
				      struct hns_roce_qp *qp)
{
	int size = sizeof(struct hns_roce_rc_send_wqe);

	for (qp->sq.wqe_shift = 6; 1 << qp->sq.wqe_shift < size;
	     qp->sq.wqe_shift++)
		;
}

struct ibv_cq *hns_roce_u_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct hns_roce_create_cq	cmd = {};
	struct hns_roce_create_cq_resp	resp = {};
	struct hns_roce_cq		*cq;
	int				ret;

	if (hns_roce_verify_cq(&cqe, to_hr_ctx(context)))
		return NULL;

	cq = malloc(sizeof(*cq));
	if (!cq)
		return NULL;

	cq->cons_index = 0;

	if (pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE))
		goto err;

	if (to_hr_dev(context->device)->hw_version == HNS_ROCE_HW_VER1)
		cqe = align_cq_size(cqe);
	else
		cqe = align_queue_size(cqe);

	if (hns_roce_alloc_cq_buf(to_hr_dev(context->device), &cq->buf, cqe))
		goto err;

	cmd.buf_addr = (uintptr_t) cq->buf.buf;

	if (to_hr_dev(context->device)->hw_version != HNS_ROCE_HW_VER1) {
		cq->set_ci_db = hns_roce_alloc_db(to_hr_ctx(context),
						  HNS_ROCE_CQ_TYPE_DB);
		if (!cq->set_ci_db)
			goto err_buf;

		cmd.db_addr  = (uintptr_t) cq->set_ci_db;
	}

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret)
		goto err_db;

	cq->cqn = resp.cqn;
	cq->cq_depth = cqe;
	cq->flags = resp.cap_flags;

	if (to_hr_dev(context->device)->hw_version == HNS_ROCE_HW_VER1)
		cq->set_ci_db = to_hr_ctx(context)->cq_tptr_base + cq->cqn * 2;

	cq->arm_db    = cq->set_ci_db;
	cq->arm_sn    = 1;
	*(cq->set_ci_db) = 0;
	*(cq->arm_db) = 0;

	return &cq->ibv_cq;

err_db:
	if (to_hr_dev(context->device)->hw_version != HNS_ROCE_HW_VER1)
		hns_roce_free_db(to_hr_ctx(context), cq->set_ci_db,
				 HNS_ROCE_CQ_TYPE_DB);

err_buf:
	hns_roce_free_buf(&cq->buf);

err:
	free(cq);

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
		hns_roce_free_db(to_hr_ctx(cq->context),
				 to_hr_cq(cq)->set_ci_db, HNS_ROCE_CQ_TYPE_DB);
	hns_roce_free_buf(&to_hr_cq(cq)->buf);
	free(to_hr_cq(cq));

	return ret;
}

static int hns_roce_create_idx_que(struct ibv_pd *pd, struct hns_roce_srq *srq)
{
	struct hns_roce_idx_que	*idx_que = &srq->idx_que;
	uint32_t bitmap_num;
	int i;

	idx_que->entry_sz = HNS_ROCE_IDX_QUE_ENTRY_SZ;

	/* bits needed in bitmap*/
	bitmap_num = align(srq->max, BIT_CNT_PER_BYTE * sizeof(uint64_t));

	idx_que->bitmap = calloc(1, bitmap_num / BIT_CNT_PER_BYTE);
	if (!idx_que->bitmap)
		return -1;

	/* bitmap_num indicates amount of u64 */
	bitmap_num = bitmap_num / (BIT_CNT_PER_BYTE * sizeof(uint64_t));

	idx_que->buf_size = srq->max * idx_que->entry_sz;
	if (hns_roce_alloc_buf(&idx_que->buf, align(idx_que->buf_size, 0x1000),
			       to_hr_dev(pd->context->device)->page_size)) {
		free(idx_que->bitmap);
		idx_que->bitmap = NULL;
		return -1;
	}

	memset(idx_que->buf.buf, 0, idx_que->buf_size);

	/*init the idx_que bitmap */
	for (i = 0; i < bitmap_num; ++i)
		idx_que->bitmap[i] = ~(0UL);

	return 0;
}

static int hns_roce_alloc_srq_buf(struct ibv_pd *pd, struct ibv_srq_attr *attr,
				  struct hns_roce_srq *srq)
{
	int srq_buf_size;
	int srq_size;

	srq->wrid = calloc(1, srq->max * sizeof(unsigned long));
	if (!srq->wrid)
		return -1;

	/* srq size */
	srq_size = srq->max_gs * sizeof(struct hns_roce_v2_wqe_data_seg);

	for (srq->wqe_shift = 4; 1 << srq->wqe_shift < srq_size;
	     ++srq->wqe_shift)
		; /* nothing */

	srq_buf_size = srq->max << srq->wqe_shift;

	/* allocate srq wqe buf */
	if (hns_roce_alloc_buf(&srq->buf, srq_buf_size,
			       to_hr_dev(pd->context->device)->page_size)) {
		free(srq->wrid);
		return -1;
	}

	memset(srq->buf.buf, 0, srq_buf_size);

	srq->head = 0;
	srq->tail = srq->max - 1;

	return 0;
}

struct ibv_srq *hns_roce_u_create_srq(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *srq_init_attr)
{
	struct hns_roce_create_srq	cmd;
	struct hns_roce_create_srq_resp resp;
	struct hns_roce_srq		*srq;
	int ret;

	if (srq_init_attr->attr.max_wr > (1 << 15) ||
	    srq_init_attr->attr.max_sge > (1 << 8))
		return NULL;

	srq = calloc(1, sizeof(*srq));
	if (!srq)
		return NULL;

	if (pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE))
		goto out;

	srq->max = align_srq_size(srq_init_attr->attr.max_wr + 1);
	srq->max_gs = srq_init_attr->attr.max_sge;

	ret = hns_roce_create_idx_que(pd, srq);
	if (ret) {
		fprintf(stderr, "hns_roce_create_idx_que failed!\n");
		goto out;
	}

	if (hns_roce_alloc_srq_buf(pd, &srq_init_attr->attr, srq)) {
		fprintf(stderr, "hns_roce_alloc_srq_buf failed!\n");
		goto err_idx_que;
	}

	srq->db = hns_roce_alloc_db(to_hr_ctx(pd->context),
				    HNS_ROCE_QP_TYPE_DB);
	if (!srq->db)
		goto err_srq_buf;

	*(srq->db) = 0;
	cmd.buf_addr = (uintptr_t)srq->buf.buf;
	cmd.que_addr = (uintptr_t)srq->idx_que.buf.buf;
	cmd.db_addr = (uintptr_t)srq->db;

	ret = ibv_cmd_create_srq(pd, &srq->verbs_srq.srq, srq_init_attr,
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
	free(&srq->idx_que.bitmap);
	hns_roce_free_buf(&srq->idx_que.buf);
out:
	free(srq);
	return NULL;
}

static int hns_roce_verify_qp(struct ibv_qp_init_attr *attr,
			      struct hns_roce_context *context)
{
	struct hns_roce_device *hr_dev =
		to_hr_dev(context->ibv_ctx.context.device);

	if (hr_dev->hw_version == HNS_ROCE_HW_VER1) {
		if (attr->cap.max_send_wr < HNS_ROCE_MIN_WQE_NUM) {
			fprintf(stderr,
				"max_send_wr = %d, less than minimum WQE number.\n",
				attr->cap.max_send_wr);
				attr->cap.max_send_wr = HNS_ROCE_MIN_WQE_NUM;
		}

		if (attr->cap.max_recv_wr < HNS_ROCE_MIN_WQE_NUM) {
			fprintf(stderr,
				"max_recv_wr = %d, less than minimum WQE number.\n",
				attr->cap.max_recv_wr);
				attr->cap.max_recv_wr = HNS_ROCE_MIN_WQE_NUM;
		}
	}

	if (attr->cap.max_recv_sge < 1)
		attr->cap.max_recv_sge = 1;
	if (attr->cap.max_send_wr > context->max_qp_wr ||
	    attr->cap.max_recv_wr > context->max_qp_wr ||
	    attr->cap.max_send_sge > context->max_sge  ||
	    attr->cap.max_recv_sge > context->max_sge)
		return -1;

	if ((attr->qp_type != IBV_QPT_RC) && (attr->qp_type != IBV_QPT_UD))
		return -1;

	if ((attr->qp_type == IBV_QPT_RC) &&
	    (attr->cap.max_inline_data > HNS_ROCE_RC_WQE_INLINE_DATA_MAX_LEN))
		return -1;

	if (attr->qp_type == IBV_QPT_UC)
		return -1;

	return 0;
}

static int hns_roce_alloc_qp_buf(struct ibv_pd *pd, struct ibv_qp_cap *cap,
				 enum ibv_qp_type type, struct hns_roce_qp *qp)
{
	int i;
	int page_size = to_hr_dev(pd->context->device)->page_size;

	qp->sq.wrid =
		(unsigned long *)malloc(qp->sq.wqe_cnt * sizeof(uint64_t));
	if (!qp->sq.wrid)
		return -1;

	if (qp->rq.wqe_cnt) {
		qp->rq.wrid = malloc(qp->rq.wqe_cnt * sizeof(uint64_t));
		if (!qp->rq.wrid) {
			free(qp->sq.wrid);
			return -1;
		}
	}

	if (to_hr_dev(pd->context->device)->hw_version == HNS_ROCE_HW_VER1) {
		for (qp->rq.wqe_shift = 4; 1 << qp->rq.wqe_shift <
			sizeof(struct hns_roce_rc_send_wqe); qp->rq.wqe_shift++)
			;

		qp->buf_size = align((qp->sq.wqe_cnt << qp->sq.wqe_shift),
				     page_size) +
			       (qp->rq.wqe_cnt << qp->rq.wqe_shift);

		if (qp->rq.wqe_shift > qp->sq.wqe_shift) {
			qp->rq.offset = 0;
			qp->sq.offset = qp->rq.wqe_cnt << qp->rq.wqe_shift;
		} else {
			qp->rq.offset = align((qp->sq.wqe_cnt <<
					      qp->sq.wqe_shift), page_size);
			qp->sq.offset = 0;
		}
	} else {
		for (qp->rq.wqe_shift = 4; 1 << qp->rq.wqe_shift < 16 *
				cap->max_recv_sge; qp->rq.wqe_shift++)
			;

		if (qp->sq.max_gs > 2)
			qp->sge.sge_shift = 4;
		else
			qp->sge.sge_shift = 0;

		/* alloc recv inline buf*/
		qp->rq_rinl_buf.wqe_list =
			(struct hns_roce_rinl_wqe *)calloc(1, qp->rq.wqe_cnt *
					      sizeof(struct hns_roce_rinl_wqe));
		if (!qp->rq_rinl_buf.wqe_list) {
			if (qp->rq.wqe_cnt)
				free(qp->rq.wrid);
			free(qp->sq.wrid);
			return -1;
		}

		qp->rq_rinl_buf.wqe_cnt = qp->rq.wqe_cnt;

		qp->rq_rinl_buf.wqe_list[0].sg_list =
			(struct hns_roce_rinl_sge *)calloc(1, qp->rq.wqe_cnt *
			  cap->max_recv_sge * sizeof(struct hns_roce_rinl_sge));
		if (!qp->rq_rinl_buf.wqe_list[0].sg_list) {
			if (qp->rq.wqe_cnt)
				free(qp->rq.wrid);
			free(qp->sq.wrid);
			free(qp->rq_rinl_buf.wqe_list);
			return -1;
		}
		for (i = 0; i < qp->rq_rinl_buf.wqe_cnt; i++) {
			int wqe_size = i * cap->max_recv_sge;

			qp->rq_rinl_buf.wqe_list[i].sg_list =
			  &(qp->rq_rinl_buf.wqe_list[0].sg_list[wqe_size]);
		}

		qp->buf_size = align((qp->sq.wqe_cnt << qp->sq.wqe_shift),
				     page_size) +
			       align((qp->sge.sge_cnt << qp->sge.sge_shift),
				     page_size) +
			       (qp->rq.wqe_cnt << qp->rq.wqe_shift);

		if (qp->sge.sge_cnt) {
			qp->sq.offset = 0;
			qp->sge.offset = align((qp->sq.wqe_cnt <<
						qp->sq.wqe_shift), page_size);
			qp->rq.offset = qp->sge.offset +
					align((qp->sge.sge_cnt <<
					qp->sge.sge_shift), page_size);
		} else {
			qp->sq.offset = 0;
			qp->sge.offset = 0;
			qp->rq.offset = align((qp->sq.wqe_cnt <<
						qp->sq.wqe_shift), page_size);
		}
	}

	if (hns_roce_alloc_buf(&qp->buf, align(qp->buf_size, page_size),
			       to_hr_dev(pd->context->device)->page_size)) {
		if (qp->rq.wqe_cnt)
			free(qp->sq.wrid);
		free(qp->rq.wrid);
		return -1;
	}

	memset(qp->buf.buf, 0, qp->buf_size);

	return 0;
}

static int hns_roce_store_qp(struct hns_roce_context *ctx, uint32_t qpn,
			     struct hns_roce_qp *qp)
{
	int tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;

	if (!ctx->qp_table[tind].refcnt) {
		ctx->qp_table[tind].table = calloc(ctx->qp_table_mask + 1,
						  sizeof(struct hns_roce_qp *));
		if (!ctx->qp_table[tind].table)
			return -1;
	}

	++ctx->qp_table[tind].refcnt;
	ctx->qp_table[tind].table[qpn & ctx->qp_table_mask] = qp;

	return 0;
}

struct ibv_qp *hns_roce_u_create_qp(struct ibv_pd *pd,
				    struct ibv_qp_init_attr *attr)
{
	int ret;
	struct hns_roce_qp *qp = NULL;
	struct hns_roce_create_qp cmd = {};
	struct hns_roce_create_qp_resp resp = {};
	struct hns_roce_context *context = to_hr_ctx(pd->context);
	unsigned int sge_ex_count;

	if (hns_roce_verify_qp(attr, context)) {
		fprintf(stderr, "hns_roce_verify_sizes failed!\n");
		return NULL;
	}

	qp = malloc(sizeof(*qp));
	if (!qp) {
		fprintf(stderr, "malloc failed!\n");
		return NULL;
	}

	hns_roce_calc_sq_wqe_size(&attr->cap, attr->qp_type, qp);

	if (to_hr_dev(pd->context->device)->hw_version == HNS_ROCE_HW_VER1) {
		qp->sq.wqe_cnt = align_qp_size(attr->cap.max_send_wr);
		qp->rq.wqe_cnt = align_qp_size(attr->cap.max_recv_wr);
	} else {
		qp->sq.wqe_cnt = align_queue_size(attr->cap.max_send_wr);
		qp->rq.wqe_cnt = align_queue_size(attr->cap.max_recv_wr);
	}

	if (to_hr_dev(pd->context->device)->hw_version == HNS_ROCE_HW_VER1) {
		qp->sq.max_gs = 2;
	} else {
		qp->sq.max_gs = attr->cap.max_send_sge;
		if (qp->sq.max_gs > 2) {
			sge_ex_count = qp->sq.wqe_cnt * (qp->sq.max_gs - 2);
			for (qp->sge.sge_cnt = 1; qp->sge.sge_cnt <
				sge_ex_count; qp->sge.sge_cnt <<= 1)
				;
		} else {
			qp->sge.sge_cnt = 0;
		}
	}

	if (hns_roce_alloc_qp_buf(pd, &attr->cap, attr->qp_type, qp)) {
		fprintf(stderr, "hns_roce_alloc_qp_buf failed!\n");
		goto err_buf;
	}

	hns_roce_init_qp_indices(qp);

	if (pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE) ||
	    pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE)) {
		fprintf(stderr, "pthread_spin_init failed!\n");
		goto err_free;
	}

	if ((to_hr_dev(pd->context->device)->hw_version != HNS_ROCE_HW_VER1) &&
		attr->cap.max_send_sge) {
		qp->sdb = hns_roce_alloc_db(context, HNS_ROCE_QP_TYPE_DB);
		if (!qp->sdb)
			goto err_free;

		*(qp->sdb) = 0;
		cmd.sdb_addr = (uintptr_t)qp->sdb;
	} else
		cmd.sdb_addr = 0;

	if ((to_hr_dev(pd->context->device)->hw_version != HNS_ROCE_HW_VER1) &&
	    attr->cap.max_recv_sge) {
		qp->rdb = hns_roce_alloc_db(context, HNS_ROCE_QP_TYPE_DB);
		if (!qp->rdb)
			goto err_sq_db;

		*(qp->rdb) = 0;
		cmd.db_addr = (uintptr_t) qp->rdb;
	} else
		cmd.db_addr = 0;

	cmd.buf_addr = (uintptr_t) qp->buf.buf;
	cmd.log_sq_stride = qp->sq.wqe_shift;
	for (cmd.log_sq_bb_count = 0; qp->sq.wqe_cnt > 1 << cmd.log_sq_bb_count;
	     ++cmd.log_sq_bb_count)
		;

	memset(cmd.reserved, 0, sizeof(cmd.reserved));

	pthread_mutex_lock(&to_hr_ctx(pd->context)->qp_table_mutex);

	ret = ibv_cmd_create_qp(pd, &qp->ibv_qp, attr, &cmd.ibv_cmd,
				sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (ret) {
		fprintf(stderr, "ibv_cmd_create_qp failed!\n");
		goto err_rq_db;
	}

	ret = hns_roce_store_qp(to_hr_ctx(pd->context), qp->ibv_qp.qp_num, qp);
	if (ret) {
		fprintf(stderr, "hns_roce_store_qp failed!\n");
		goto err_destroy;
	}
	pthread_mutex_unlock(&to_hr_ctx(pd->context)->qp_table_mutex);

	qp->rq.wqe_cnt = attr->cap.max_recv_wr;
	qp->rq.max_gs	= attr->cap.max_recv_sge;
	qp->flags	= resp.cap_flags;

	/* adjust rq maxima to not exceed reported device maxima */
	attr->cap.max_recv_wr = min(context->max_qp_wr, attr->cap.max_recv_wr);
	attr->cap.max_recv_sge = min(context->max_sge, attr->cap.max_recv_sge);

	qp->rq.max_post = attr->cap.max_recv_wr;
	hns_roce_set_sq_sizes(qp, &attr->cap, attr->qp_type);

	qp->sq_signal_bits = attr->sq_sig_all ? 0 : 1;

	return &qp->ibv_qp;

err_destroy:
	ibv_cmd_destroy_qp(&qp->ibv_qp);

err_rq_db:
	pthread_mutex_unlock(&to_hr_ctx(pd->context)->qp_table_mutex);
	if ((to_hr_dev(pd->context->device)->hw_version != HNS_ROCE_HW_VER1) &&
	    attr->cap.max_recv_sge)
		hns_roce_free_db(context, qp->rdb, HNS_ROCE_QP_TYPE_DB);

err_sq_db:
	if ((to_hr_dev(pd->context->device)->hw_version != HNS_ROCE_HW_VER1) &&
	    attr->cap.max_send_sge)
		hns_roce_free_db(context, qp->sdb, HNS_ROCE_QP_TYPE_DB);

err_free:
	free(qp->sq.wrid);
	if (qp->rq.wqe_cnt)
		free(qp->rq.wrid);
	hns_roce_free_buf(&qp->buf);

err_buf:
	free(qp);

	return NULL;
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
	init_attr->cap.max_inline_data = qp->max_inline_data;

	attr->cap = init_attr->cap;

	return ret;
}
