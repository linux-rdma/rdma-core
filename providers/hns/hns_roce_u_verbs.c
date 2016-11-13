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
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <ccan/minmax.h>
#include "hns_roce_u.h"
#include "hns_roce_u_abi.h"
#include "hns_roce_u_hw_v1.h"

void hns_roce_init_qp_indices(struct hns_roce_qp *qp)
{
	qp->sq.head = 0;
	qp->sq.tail = 0;
	qp->rq.head = 0;
	qp->rq.tail = 0;
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
	struct ibv_mr *mr;
	struct ibv_reg_mr cmd;
	struct ibv_reg_mr_resp resp;

	if (!addr) {
		fprintf(stderr, "2nd parm addr is NULL!\n");
		return NULL;
	}

	if (!length) {
		fprintf(stderr, "3st parm length is 0!\n");
		return NULL;
	}

	mr = malloc(sizeof(*mr));
	if (!mr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, (uintptr_t) addr, access, mr,
			     &cmd, sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(mr);
		return NULL;
	}

	return mr;
}

int hns_roce_u_dereg_mr(struct ibv_mr *mr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(mr);
	if (ret)
		return ret;

	free(mr);

	return ret;
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

static void hns_roce_set_sq_sizes(struct hns_roce_qp *qp,
				  struct ibv_qp_cap *cap, enum ibv_qp_type type)
{
	struct hns_roce_context *ctx = to_hr_ctx(qp->ibv_qp.context);

	qp->sq.max_gs = 2;
	cap->max_send_sge = min(ctx->max_sge, qp->sq.max_gs);
	qp->sq.max_post = min(ctx->max_qp_wr, qp->sq.wqe_cnt);
	cap->max_send_wr = qp->sq.max_post;
	qp->max_inline_data  = 32;
	cap->max_inline_data = qp->max_inline_data;
}

static int hns_roce_verify_cq(int *cqe, struct hns_roce_context *context)
{
	if (*cqe < HNS_ROCE_MIN_CQE_NUM) {
		fprintf(stderr, "cqe = %d, less than minimum CQE number.\n",
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
	struct hns_roce_create_cq	cmd;
	struct hns_roce_create_cq_resp	resp;
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

	cqe = align_cq_size(cqe);

	if (hns_roce_alloc_cq_buf(to_hr_dev(context->device), &cq->buf, cqe))
		goto err;

	cmd.buf_addr = (uintptr_t) cq->buf.buf;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret)
		goto err_db;

	cq->cqn = resp.cqn;
	cq->cq_depth = cqe;

	if (to_hr_dev(context->device)->hw_version == HNS_ROCE_HW_VER1)
		cq->set_ci_db = to_hr_ctx(context)->cq_tptr_base + cq->cqn * 2;
	else
		cq->set_ci_db = to_hr_ctx(context)->uar +
				ROCEE_DB_OTHERS_L_0_REG;

	cq->arm_db    = cq->set_ci_db;
	cq->arm_sn    = 1;
	*(cq->set_ci_db) = 0;
	*(cq->arm_db) = 0;

	return &cq->ibv_cq;

err_db:
	hns_roce_free_buf(&cq->buf);

err:
	free(cq);

	return NULL;
}

void hns_roce_u_cq_event(struct ibv_cq *cq)
{
	to_hr_cq(cq)->arm_sn++;
}

int hns_roce_u_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	hns_roce_free_buf(&to_hr_cq(cq)->buf);
	free(to_hr_cq(cq));

	return ret;
}

static int hns_roce_verify_qp(struct ibv_qp_init_attr *attr,
			      struct hns_roce_context *context)
{
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

	for (qp->rq.wqe_shift = 4;
	     1 << qp->rq.wqe_shift < sizeof(struct hns_roce_rc_send_wqe);
	     qp->rq.wqe_shift++)
		;

	qp->buf_size = align((qp->sq.wqe_cnt << qp->sq.wqe_shift), 0x1000) +
		      (qp->rq.wqe_cnt << qp->rq.wqe_shift);

	if (qp->rq.wqe_shift > qp->sq.wqe_shift) {
		qp->rq.offset = 0;
		qp->sq.offset = qp->rq.wqe_cnt << qp->rq.wqe_shift;
	} else {
		qp->rq.offset = align((qp->sq.wqe_cnt << qp->sq.wqe_shift),
				       0x1000);
		qp->sq.offset = 0;
	}

	if (hns_roce_alloc_buf(&qp->buf, align(qp->buf_size, 0x1000),
			       to_hr_dev(pd->context->device)->page_size)) {
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
	struct hns_roce_create_qp cmd;
	struct ibv_create_qp_resp resp;
	struct hns_roce_context *context = to_hr_ctx(pd->context);

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
	qp->sq.wqe_cnt = align_qp_size(attr->cap.max_send_wr);
	qp->rq.wqe_cnt = align_qp_size(attr->cap.max_recv_wr);

	if (hns_roce_alloc_qp_buf(pd, &attr->cap, attr->qp_type, qp)) {
		fprintf(stderr, "hns_roce_alloc_qp_buf failed!\n");
		goto err;
	}

	hns_roce_init_qp_indices(qp);

	if (pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE) ||
	    pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE)) {
		fprintf(stderr, "pthread_spin_init failed!\n");
		goto err_free;
	}

	cmd.buf_addr = (uintptr_t) qp->buf.buf;
	cmd.log_sq_stride = qp->sq.wqe_shift;
	for (cmd.log_sq_bb_count = 0; qp->sq.wqe_cnt > 1 << cmd.log_sq_bb_count;
	     ++cmd.log_sq_bb_count)
		;

	memset(cmd.reserved, 0, sizeof(cmd.reserved));

	pthread_mutex_lock(&to_hr_ctx(pd->context)->qp_table_mutex);

	ret = ibv_cmd_create_qp(pd, &qp->ibv_qp, attr, &cmd.ibv_cmd,
				sizeof(cmd), &resp, sizeof(resp));
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

err_free:
	free(qp->sq.wrid);
	if (qp->rq.wqe_cnt)
		free(qp->rq.wrid);
	hns_roce_free_buf(&qp->buf);

err:
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
