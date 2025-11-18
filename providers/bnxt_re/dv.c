// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: Direct verbs API function definitions.
 */

#include <stdio.h>
#include <sys/mman.h>

#include "main.h"
#include "bnxt_re-abi.h"
#include "bnxt_re_dv.h"
#include "./verbs.h"
#include "dv_internal.h"

/* Returns details about the default Doorbell page for ucontext */
int bnxt_re_dv_get_default_db_region(struct ibv_context *ibvctx,
				     struct bnxt_re_dv_db_region_attr *out)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dv_db_region_attr attr = {};
	int ret;

	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DBR,
			       BNXT_RE_METHOD_DBR_QUERY,
			       1);

	fill_attr_out_ptr(cmd, BNXT_RE_DV_QUERY_DBR_ATTR, &attr);

	ret = execute_ioctl(ibvctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n", __func__, ret);
		return ret;
	}
	out->dbr = cntx->udpi.dbpage;
	out->dpi = attr.dpi;
	out->umdbr = attr.umdbr;
	return 0;
}

int bnxt_re_dv_free_db_region(struct ibv_context *ctx,
			      struct bnxt_re_dv_db_region_attr *attr)
{
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ctx->device);
	int ret;

	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DBR,
			       BNXT_RE_METHOD_DBR_FREE,
			       1);

	if (attr->dbr != MAP_FAILED)
		munmap(attr->dbr, dev->pg_size);

	bnxt_trace_dv(NULL, DEV "%s: DV DBR: handle: 0x%x\n", __func__, attr->handle);
	fill_attr_in_obj(cmd, BNXT_RE_DV_FREE_DBR_HANDLE, attr->handle);

	ret = execute_ioctl(ctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n",
			__func__, ret);
		errno = ret;
		return ret;
	}

	free(attr);
	return 0;
}

struct bnxt_re_dv_db_region_attr *
bnxt_re_dv_alloc_db_region(struct ibv_context *ctx)
{
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ctx->device);
	struct bnxt_re_dv_db_region_attr attr = {}, *out;
	struct ib_uverbs_attr *handle;
	uint64_t mmap_offset = 0;
	int ret;

	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DBR,
			       BNXT_RE_METHOD_DBR_ALLOC,
			       3);

	out = calloc(1, sizeof(*out));
	if (!out) {
		errno = ENOMEM;
		return NULL;
	}

	handle = fill_attr_out_obj(cmd, BNXT_RE_DV_ALLOC_DBR_HANDLE);
	fill_attr_out_ptr(cmd, BNXT_RE_DV_ALLOC_DBR_ATTR, &attr);
	fill_attr_out_ptr(cmd, BNXT_RE_DV_ALLOC_DBR_OFFSET, &mmap_offset);

	ret = execute_ioctl(ctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n",
			__func__, ret);
		free(out);
		errno = ret;
		return NULL;
	}
	out->handle = read_attr_obj(BNXT_RE_DV_ALLOC_DBR_HANDLE, handle);
	out->dpi = attr.dpi;
	out->umdbr = attr.umdbr;

	out->dbr = mmap(NULL, dev->pg_size, PROT_WRITE,
			MAP_SHARED, ctx->cmd_fd, mmap_offset);
	if (out->dbr == MAP_FAILED) {
		fprintf(stderr, DEV "%s: mmap failed\n", __func__);
		bnxt_re_dv_free_db_region(ctx, out);
		errno = ENOMEM;
		return NULL;
	}
	bnxt_trace_dv(NULL, "%s: DV DBR: handle: 0x%x\n", __func__, out->handle);

	return out;
}

void *bnxt_re_dv_umem_reg(struct ibv_context *ibvctx, struct bnxt_re_dv_umem_reg_attr *in)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_UMEM,
			       BNXT_RE_METHOD_UMEM_REG,
			       6);
	struct ib_uverbs_attr *handle;
	struct bnxt_re_dv_umem_internal *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem) {
		errno = ENOMEM;
		return NULL;
	}
	if (ibv_dontfork_range(in->addr, in->size))
		goto err;

	fill_attr_in_uint64(cmd, BNXT_RE_UMEM_OBJ_REG_ADDR, (uintptr_t)in->addr);
	fill_attr_in_uint64(cmd, BNXT_RE_UMEM_OBJ_REG_LEN, in->size);
	fill_attr_in_uint32(cmd, BNXT_RE_UMEM_OBJ_REG_ACCESS, in->access_flags);
	if (in->comp_mask & BNXT_RE_DV_UMEM_FLAGS_DMABUF) {
		if (in->dmabuf_fd == -1) {
			fprintf(stderr, "%s: failed: EBADF\n", __func__);
			errno = EBADF;
			goto err;
		}
		fill_attr_in_fd(cmd, BNXT_RE_UMEM_OBJ_REG_DMABUF_FD,
				in->dmabuf_fd);
	}
	fill_attr_in_uint64(cmd, BNXT_RE_UMEM_OBJ_REG_PGSZ_BITMAP,
			    in->pgsz_bitmap);
	handle = fill_attr_out_obj(cmd, BNXT_RE_UMEM_OBJ_REG_HANDLE);

	ret = execute_ioctl(ibvctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n", __func__, ret);
		goto err_umem_reg_cmd;
	}

	umem->handle = read_attr_obj(BNXT_RE_UMEM_OBJ_REG_HANDLE, handle);
	umem->context = ibvctx;
	umem->addr = in->addr;
	umem->size = in->size;

	bnxt_trace_dv(NULL, "%s: DV Umem Reg: handle: 0x%x addr: %" PRIuPTR " size: %zu\n",
		      __func__, umem->handle, (uintptr_t)umem->addr, umem->size);
	return (void *)umem;
err_umem_reg_cmd:
	ibv_dofork_range(in->addr, in->size);
err:
	free(umem);
	return NULL;
}

int bnxt_re_dv_umem_dereg(void *umem_handle)
{
	struct bnxt_re_dv_umem_internal *umem = umem_handle;

	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_UMEM,
			       BNXT_RE_METHOD_UMEM_DEREG,
			       1);
	int ret;

	bnxt_trace_dv(NULL, "%s: DV Umem Dereg: handle: 0x%x\n",
		      __func__, umem->handle);
	fill_attr_in_obj(cmd, BNXT_RE_UMEM_OBJ_DEREG_HANDLE, umem->handle);
	ret = execute_ioctl(umem->context, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n",
			__func__, ret);
		return ret;
	}

	ibv_dofork_range(umem->addr, umem->size);
	free(umem);
	return 0;
}

static struct ibv_context *bnxt_re_to_ibvctx(struct bnxt_re_context *cntx)
{
	return &cntx->ibvctx.context;
}

static bool bnxt_re_dv_is_valid_umem(struct bnxt_re_dev *dev,
				     struct bnxt_re_dv_umem_internal *umem,
				     uint64_t offset, uint32_t size)
{
	return ((offset == get_aligned(offset, dev->pg_size)) &&
		(offset + size <= umem->size));
}

static int bnxt_re_dv_create_cq_cmd(struct bnxt_re_dev *dev,
				    struct ibv_context *ibvctx,
				    struct bnxt_re_cq *cq,
				    struct bnxt_re_dv_cq_init_attr *cq_attr,
				    uint64_t comp_mask,
				    struct bnxt_re_dv_cq_resp *resp)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DV_CQ,
			       BNXT_RE_METHOD_DV_CREATE_CQ,
			       5);
	struct bnxt_re_dv_umem_internal *cq_umem = cq->cq_umem;
	uint64_t offset = cq_attr->cq_umem_offset;
	struct bnxt_re_dv_cq_req req = {};
	struct ib_uverbs_attr *handle;
	uint32_t size;
	int ret;

	/* Input args */
	req.ncqe = cq_attr->ncqe;
	req.va = 0;
	req.comp_mask = comp_mask;
	fill_attr_in_ptr(cmd, BNXT_RE_DV_CREATE_CQ_REQ, &req);

	size = cq_attr->ncqe * bnxt_re_get_cqe_sz();
	if (!bnxt_re_dv_is_valid_umem(dev, cq_umem, offset, size)) {
		fprintf(stderr,
			"%s: Invalid cq_umem: handle: 0x%x offset: %" PRIx64 " size: 0x%x\n",
			__func__, cq_umem->handle, offset, size);
		return -EINVAL;
	}
	fill_attr_in_uint64(cmd, BNXT_RE_DV_CREATE_CQ_UMEM_OFFSET, offset);
	fill_attr_in_obj(cmd, BNXT_RE_DV_CREATE_CQ_UMEM_HANDLE,
			 cq_umem->handle);
	bnxt_trace_dv(NULL,
		      "%s: cq_umem: handle: 0x%x offset: %" PRIx64 " size: 0x%x\n",
		      __func__, cq_umem->handle, offset, size);

	/* Output args */
	handle = fill_attr_out_obj(cmd, BNXT_RE_DV_CREATE_CQ_HANDLE);
	fill_attr_out_ptr(cmd, BNXT_RE_DV_CREATE_CQ_RESP, resp);

	bnxt_trace_dv(NULL, "%s: ncqe: %d va: 0x%" PRIx64 " comp_mask: 0x%" PRIx64 "\n",
		      __func__, req.ncqe, (uint64_t)req.va, (uint64_t)req.comp_mask);

	ret = execute_ioctl(ibvctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n", __func__, ret);
		return ret;
	}
	cq->ibvcq.handle = read_attr_obj(BNXT_RE_DV_CREATE_CQ_HANDLE, handle);

	bnxt_trace_dv(NULL, "%s: CQ handle: 0x%x\n", __func__, cq->ibvcq.handle);
	bnxt_trace_dv(NULL,
		      "%s: CQ cqid: 0x%x tail: 0x%x phase: 0x%x comp_mask: 0x%llx\n",
		      __func__, resp->cqid, resp->tail, resp->phase, resp->comp_mask);

	return 0;
}

static int bnxt_re_dv_init_cq(struct ibv_context *ibvctx, struct bnxt_re_cq *cq,
			      struct bnxt_re_dv_cq_resp *resp)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);

	cq->cqid = resp->cqid;
	cq->phase = resp->phase;
	cq->cqq->tail = resp->tail;
	cq->udpi = &cntx->udpi;
	cq->cntx = cntx;
	cq->rand.seed = cq->cqid;
	if (resp->comp_mask & BNXT_RE_CQ_TOGGLE_PAGE_SUPPORT) {
		bnxt_trace_dv(NULL, "%s: toggle page is unsupported, cqid: 0x%x\n",
			      __func__, resp->cqid);
		return -EOPNOTSUPP;
	}
	pthread_spin_init(&cq->cqq->qlock, PTHREAD_PROCESS_PRIVATE);
	list_head_init(&cq->sfhead);
	list_head_init(&cq->rfhead);
	list_head_init(&cq->prev_cq_head);
	return 0;
}

struct ibv_cq *bnxt_re_dv_create_cq(struct ibv_context *ibvctx,
				    struct bnxt_re_dv_cq_init_attr *cq_attr)
{
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);
	struct bnxt_re_dv_umem_internal *cq_umem = cq_attr->umem_handle;
	struct bnxt_re_dv_cq_resp resp = {};
	uint64_t comp_mask = 0;
	struct bnxt_re_cq *cq;
	int ret;

	if (cq_attr->ncqe > dev->max_cq_depth)
		return NULL;

	cq = calloc(1, (sizeof(*cq)));
	if (!cq)
		return NULL;

	cq->cqq = NULL;
	cq->cq_umem = cq_umem;

	ret = bnxt_re_dv_create_cq_cmd(dev, ibvctx, cq, cq_attr, comp_mask, &resp);
	if (ret) {
		fprintf(stderr, "%s: bnxt_re_dv_create_cq_cmd() failed\n", __func__);
		goto fail;
	}

	ret = bnxt_re_dv_init_cq(ibvctx, cq, &resp);
	if (ret) {
		fprintf(stderr, "%s: bnxt_re_dv_create_cq_cmd() failed\n", __func__);
		goto fail;
	}

	cq->dv_cq_flags |= BNXT_DV_CQ_FLAGS_VALID;
	return &cq->ibvcq;

fail:
	free(cq);
	return NULL;
}

int bnxt_re_dv_destroy_cq(struct ibv_cq *ibvcq)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DV_CQ,
			       BNXT_RE_METHOD_DV_DESTROY_CQ,
			       1);
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);
	struct ibv_context *ibvctx = bnxt_re_to_ibvctx(cq->cntx);
	int ret;

	fill_attr_in_obj(cmd, BNXT_RE_DV_DESTROY_CQ_HANDLE, ibvcq->handle);
	bnxt_trace_dv(NULL, "%s: CQ handle: 0x%x\n", __func__, ibvcq->handle);

	ret = execute_ioctl(ibvctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n", __func__, ret);
		return ret;
	}

	free(cq);
	return ret;
}

static void bnxt_re_dv_init_ib_qp(struct ibv_context *ibvctx,
				  struct ibv_qp_init_attr_ex *attr,
				  struct bnxt_re_qp *qp)
{
	struct ibv_qp *ibvqp = qp->ibvqp;

	ibvqp->handle =	qp->qp_handle;
	ibvqp->qp_num =	qp->qpid;
	ibvqp->context = ibvctx;
	ibvqp->qp_context = attr->qp_context;
	ibvqp->pd = attr->pd;
	ibvqp->send_cq = attr->send_cq;
	ibvqp->recv_cq = attr->recv_cq;
	ibvqp->srq = attr->srq;
	ibvqp->qp_type = attr->qp_type;
	ibvqp->state = IBV_QPS_RESET;
	ibvqp->events_completed = 0;
	pthread_mutex_init(&ibvqp->mutex, NULL);
	pthread_cond_init(&ibvqp->cond, NULL);
}

static void bnxt_re_dv_init_qp(struct ibv_context *ibvctx,
			       struct ibv_qp_init_attr_ex *attr,
			       struct bnxt_re_qp *qp,
			       struct bnxt_re_dv_create_qp_resp *resp)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct ibv_device_attr *devattr;
	struct bnxt_re_qpcap *cap;
	struct bnxt_re_dev *rdev;

	qp->qpid = resp->qpid;
	qp->qptyp = attr->qp_type;
	qp->qpst = IBV_QPS_RESET;
	qp->scq = to_bnxt_re_cq(attr->send_cq);
	qp->rcq = to_bnxt_re_cq(attr->recv_cq);
	if (attr->srq)
		qp->srq = to_bnxt_re_srq(attr->srq);
	qp->rand.seed = qp->qpid;
	qp->sq_psn = 0;

	rdev = cntx->rdev;
	devattr = &rdev->devattr;
	cap = &qp->cap;
	cap->max_ssge = attr->cap.max_send_sge;
	cap->max_rsge = attr->cap.max_recv_sge;
	cap->max_inline = attr->cap.max_inline_data;
	cap->sqsig = attr->sq_sig_all;
	cap->is_atomic_cap = devattr->atomic_cap;
	fque_init_node(&qp->snode);
	fque_init_node(&qp->rnode);

	bnxt_re_dv_init_ib_qp(ibvctx, attr, qp);
}

static void fill_ib_attr_from_dv_qp_attr(struct bnxt_re_dv_qp_init_attr *dv_qp_attr,
					 struct ibv_qp_init_attr *attr)
{
	attr->send_cq = dv_qp_attr->send_cq;
	attr->recv_cq = dv_qp_attr->recv_cq;
	attr->srq = dv_qp_attr->srq;
	attr->cap.max_send_wr = dv_qp_attr->max_send_wr;
	attr->cap.max_send_sge = dv_qp_attr->max_send_sge;
	attr->qp_type =  dv_qp_attr->qp_type;
	attr->cap.max_inline_data =  dv_qp_attr->max_inline_data;
	attr->cap.max_recv_wr =  dv_qp_attr->max_recv_wr;
	attr->cap.max_recv_sge =  dv_qp_attr->max_recv_sge;
}

static int
bnxt_re_dv_create_qp_cmd(struct ibv_context *ibvctx,
			 struct bnxt_re_dv_qp_init_attr *dv_qp_attr,
			 struct bnxt_re_dv_create_qp_resp *resp,
			 struct bnxt_re_qp *qp)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DV_QP,
			       BNXT_RE_METHOD_DV_CREATE_QP,
			       9);
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dv_db_region_attr *db_attr = NULL;
	struct bnxt_re_dv_create_qp_req req = {};
	struct bnxt_re_dv_umem_internal *sq_umem = NULL;
	struct bnxt_re_dv_umem_internal *rq_umem = NULL;
	struct ib_uverbs_attr *handle;
	struct bnxt_re_cq *re_cq;
	uint64_t offset;
	uint32_t size;
	int ret;

	req.qp_type = dv_qp_attr->qp_type;
	req.max_send_wr = dv_qp_attr->max_send_wr;
	req.max_recv_wr = dv_qp_attr->max_recv_wr;
	req.max_send_sge = dv_qp_attr->max_send_sge;
	req.max_recv_sge = dv_qp_attr->max_recv_sge;
	req.max_inline_data = dv_qp_attr->max_inline_data;

	req.pd_id = qp->re_pd->pdid;
	req.qp_handle = dv_qp_attr->qp_handle;

	sq_umem = dv_qp_attr->sq_umem_handle;
	fill_attr_in_obj(cmd, BNXT_RE_DV_CREATE_QP_SQ_UMEM_HANDLE,
			 sq_umem->handle);

	offset = dv_qp_attr->sq_umem_offset;
	size = dv_qp_attr->sq_len;
	if (!bnxt_re_dv_is_valid_umem(cntx->rdev, sq_umem, offset, size)) {
		fprintf(stderr,
			"%s: Invalid sq_umem: handle: 0x%x offset: %" PRIx64 " size: 0x%x\n",
			__func__, sq_umem->handle, offset, size);
		return -EINVAL;
	}
	bnxt_trace_dv(NULL, "%s: sq_umem: handle: 0x%x offset: %" PRIx64 " size: 0x%x\n",
		      __func__, sq_umem->handle, offset, size);
	req.sq_va = 0;
	req.sq_umem_offset = offset;
	req.sq_len = size;
	req.sq_slots = dv_qp_attr->sq_slots;
	req.sq_wqe_sz = dv_qp_attr->sq_wqe_sz;
	req.sq_psn_sz = dv_qp_attr->sq_psn_sz;
	req.sq_npsn = dv_qp_attr->sq_npsn;

	if (!dv_qp_attr->srq) {
		rq_umem = dv_qp_attr->rq_umem_handle;
		fill_attr_in_obj(cmd, BNXT_RE_DV_CREATE_QP_RQ_UMEM_HANDLE,
				 rq_umem->handle);
		offset = dv_qp_attr->rq_umem_offset;
		size = dv_qp_attr->rq_len;
		if (!bnxt_re_dv_is_valid_umem(cntx->rdev, rq_umem, offset, size)) {
			fprintf(stderr,
				"%s: Invalid rq_umem: handle: 0x%x offset: %" PRIx64 " size: 0x%x\n",
				__func__, rq_umem->handle, offset, size);
			return -EINVAL;
		}
		bnxt_trace_dv(NULL, "%s: rq_umem: handle: 0x%x offset: %" PRIx64 " size: 0x%x\n",
			      __func__, rq_umem->handle, offset, size);

		req.rq_umem_offset = offset;
		req.rq_len = size;
		req.rq_slots = dv_qp_attr->rq_slots;
		req.rq_wqe_sz = dv_qp_attr->rq_wqe_sz;
	} else {
		fill_attr_in_obj(cmd, BNXT_RE_DV_CREATE_QP_SRQ_HANDLE,
				 dv_qp_attr->srq->handle);
	}

	fill_attr_in_ptr(cmd, BNXT_RE_DV_CREATE_QP_REQ, &req);

	re_cq = to_bnxt_re_cq(dv_qp_attr->send_cq);
	fill_attr_in_obj(cmd, BNXT_RE_DV_CREATE_QP_SEND_CQ_HANDLE,
			 re_cq->ibvcq.handle);

	re_cq = to_bnxt_re_cq(dv_qp_attr->recv_cq);
	fill_attr_in_obj(cmd, BNXT_RE_DV_CREATE_QP_RECV_CQ_HANDLE,
			 re_cq->ibvcq.handle);

	if (dv_qp_attr->dbr_handle) {
		db_attr = dv_qp_attr->dbr_handle;
		fill_attr_in_obj(cmd, BNXT_RE_DV_CREATE_QP_DBR_HANDLE,
				 db_attr->handle);
		qp->dv_dpi.dbpage = db_attr->dbr;
		qp->dv_dpi.dpindx = db_attr->dpi;
		qp->udpi = &qp->dv_dpi;
	} else {
		qp->udpi = &cntx->udpi;
	}

	/* Output args */
	handle = fill_attr_out_obj(cmd, BNXT_RE_DV_CREATE_QP_HANDLE);
	fill_attr_out_ptr(cmd, BNXT_RE_DV_CREATE_QP_RESP, resp);

	ret = execute_ioctl(ibvctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n", __func__, ret);
		return ret;
	}

	qp->qp_handle = read_attr_obj(BNXT_RE_DV_CREATE_QP_HANDLE, handle);
	bnxt_trace_dv(NULL, "%s: QP handle: 0x%x qpid: 0x%x\n",
		      __func__, qp->qp_handle, resp->qpid);

	return 0;
}

struct ibv_qp *bnxt_re_dv_create_qp(struct ibv_pd *ibvpd,
				    struct bnxt_re_dv_qp_init_attr *dv_qp_attr)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct bnxt_re_dv_create_qp_resp resp = {};
	struct ibv_qp_init_attr_ex attr_ex;
	struct ibv_qp_init_attr attr = {};
	struct bnxt_re_qp *qp;
	int rc;

	qp = malloc(sizeof(*qp));
	if (!qp)
		return NULL;

	memset(qp, 0, sizeof(*qp));
	qp->ibvqp = &qp->vqp.qp;
	qp->mem = NULL;
	qp->cctx = &cntx->cctx;
	qp->cntx = cntx;
	qp->qpmode = cntx->wqe_mode & BNXT_RE_WQE_MODE_VARIABLE;
	qp->re_pd = to_bnxt_re_pd(ibvpd);

	dv_qp_attr->qp_handle = (uintptr_t)qp;

	rc = bnxt_re_dv_create_qp_cmd(ibvpd->context, dv_qp_attr, &resp, qp);
	if (rc) {
		free(qp);
		return NULL;
	}

	memset(&attr_ex, 0, sizeof(attr_ex));
	fill_ib_attr_from_dv_qp_attr(dv_qp_attr, &attr);
	memcpy(&attr_ex, &attr, sizeof(attr));
	attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = ibvpd;

	bnxt_re_dv_init_qp(ibvpd->context, &attr_ex, qp, &resp);
	return qp->ibvqp;
}

int bnxt_re_dv_destroy_qp(struct ibv_qp *ibvqp)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DV_QP,
			       BNXT_RE_METHOD_DV_DESTROY_QP,
			       1);
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct ibv_context *ibvctx;
	struct bnxt_re_mem *mem;
	int ret;

	qp->qpst = IBV_QPS_RESET;
	fill_attr_in_obj(cmd, BNXT_RE_DV_DESTROY_QP_HANDLE, qp->qp_handle);
	bnxt_trace_dv(NULL, "%s: QP handle: 0x%x\n", __func__, qp->qp_handle);

	ibvctx = bnxt_re_to_ibvctx(qp->cntx);
	ret = execute_ioctl(ibvctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n", __func__, ret);
		return ret;
	}
	bnxt_re_cleanup_cq(qp, qp->rcq);
	if (qp->scq != qp->rcq)
		bnxt_re_cleanup_cq(qp, qp->scq);
	mem = qp->mem;
	bnxt_re_free_mem(mem);
	return 0;
}

int bnxt_re_dv_query_qp(void *qp_handle, struct ib_uverbs_qp_attr *qp_attr)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DV_QP,
			       BNXT_RE_METHOD_DV_QUERY_QP,
			       2);
	struct ibv_qp *ibvqp = qp_handle;
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	int ret;

	bnxt_trace_dv(NULL, DEV "DV Query QP: handle: 0x%x\n", qp->qp_handle);
	fill_attr_in_obj(cmd, BNXT_RE_DV_QUERY_QP_HANDLE, qp->qp_handle);
	fill_attr_out_ptr(cmd, BNXT_RE_DV_QUERY_QP_ATTR, qp_attr);

	ret = execute_ioctl(qp->ibvqp->context, cmd);
	if (ret)
		fprintf(stderr, DEV "DV Query QP error %d\n", ret);

	return ret;
}

static void bnxt_re_dv_copy_qp_attr(struct ib_uverbs_qp_attr *dst,
				    struct ibv_qp_attr *src, int attr_mask)
{
	dst->qp_state           = src->qp_state;
	dst->cur_qp_state       = src->cur_qp_state;
	dst->path_mtu           = src->path_mtu;
	dst->path_mig_state     = src->path_mig_state;
	dst->qkey               = src->qkey;
	dst->rq_psn             = src->rq_psn;
	dst->sq_psn             = src->sq_psn;
	dst->dest_qp_num        = src->dest_qp_num;
	dst->qp_access_flags    = src->qp_access_flags;
	dst->max_send_wr        = src->cap.max_send_wr;
	dst->max_recv_wr        = src->cap.max_recv_wr;
	dst->max_send_sge       = src->cap.max_send_sge;
	dst->max_recv_sge       = src->cap.max_recv_sge;
	dst->max_inline_data    = src->cap.max_inline_data;
	dst->pkey_index         = src->pkey_index;
	dst->alt_pkey_index     = src->alt_pkey_index;
	dst->en_sqd_async_notify = src->en_sqd_async_notify;
	dst->sq_draining        = src->sq_draining;
	dst->max_rd_atomic      = src->max_rd_atomic;
	dst->max_dest_rd_atomic = src->max_dest_rd_atomic;
	dst->min_rnr_timer      = src->min_rnr_timer;
	dst->port_num           = src->port_num;
	dst->timeout            = src->timeout;
	dst->retry_cnt          = src->retry_cnt;
	dst->rnr_retry          = src->rnr_retry;
	dst->alt_port_num       = src->alt_port_num;
	dst->alt_timeout        = src->alt_timeout;

	dst->qp_attr_mask = attr_mask;

	dst->ah_attr.sl = src->ah_attr.sl;
	dst->ah_attr.src_path_bits = src->ah_attr.src_path_bits;
	dst->ah_attr.port_num = src->ah_attr.port_num;
	dst->ah_attr.dlid = src->ah_attr.dlid;
	dst->ah_attr.is_global  = src->ah_attr.is_global;
	memcpy(&dst->ah_attr.grh.dgid, &src->ah_attr.grh.dgid, 16);
	dst->ah_attr.grh.sgid_index = src->ah_attr.grh.sgid_index;
	dst->ah_attr.grh.hop_limit = src->ah_attr.grh.hop_limit;
	dst->ah_attr.grh.traffic_class = src->ah_attr.grh.traffic_class;
	dst->ah_attr.grh.flow_label = src->ah_attr.grh.flow_label;
}

int bnxt_re_dv_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr, int attr_mask)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_DV_QP,
			       BNXT_RE_METHOD_DV_MODIFY_QP,
			       2);
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct ib_uverbs_qp_attr uattr = {};
	int ret;

	bnxt_re_dv_copy_qp_attr(&uattr, attr, attr_mask);

	bnxt_trace_dv(NULL, DEV "DV Modify QP: handle: 0x%x\n", qp->qp_handle);
	fill_attr_in_obj(cmd, BNXT_RE_DV_MODIFY_QP_HANDLE, qp->qp_handle);
	fill_attr_in_ptr(cmd, BNXT_RE_DV_MODIFY_QP_REQ, &uattr);

	ret = execute_ioctl(qp->ibvqp->context, cmd);
	if (ret) {
		fprintf(stderr, DEV "DV Modify QP v2 error %d\n", ret);
		return ret;
	}

	if (attr_mask & IBV_QP_SQ_PSN)
		qp->sq_psn = attr->sq_psn;
	if (attr_mask & IBV_QP_PATH_MTU)
		qp->mtu = (0x80 << attr->path_mtu);

	return ret;
}
