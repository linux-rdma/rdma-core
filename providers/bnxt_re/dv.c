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
			       BNXT_RE_OBJECT_DEFAULT_DBR,
			       BNXT_RE_METHOD_GET_DEFAULT_DBR,
			       1);

	fill_attr_out_ptr(cmd, BNXT_RE_DV_DEFAULT_DBR_ATTR, &attr);

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

	return out;
}

struct bnxt_re_dv_umem *bnxt_re_dv_umem_reg(struct ibv_context *ibvctx,
					    struct bnxt_re_dv_umem_reg_attr *in)
{
	struct bnxt_re_dv_umem *umem;
	int ret;

	ret = ibv_dontfork_range(in->addr, in->size);
	if (ret) {
		errno = ret;
		return NULL;
	}

	if (in->comp_mask & BNXT_RE_DV_UMEM_FLAGS_DMABUF &&
	    (in->dmabuf_fd == -1)) {
		fprintf(stderr, "%s: failed: EBADF\n", __func__);
		errno = EBADF;
		goto err;
	}

	umem = calloc(1, sizeof(*umem));
	if (!umem) {
		errno = ENOMEM;
		goto err;
	}

	umem->context = ibvctx;
	umem->addr = in->addr;
	umem->size = in->size;
	umem->access_flags = in->access_flags;
	umem->pgsz_bitmap = in->pgsz_bitmap;
	umem->dmabuf_fd = (in->comp_mask & BNXT_RE_DV_UMEM_FLAGS_DMABUF) ?
				in->dmabuf_fd : -1;
	return umem;

err:
	ibv_dofork_range(in->addr, in->size);
	return NULL;
}

int bnxt_re_dv_umem_dereg(struct bnxt_re_dv_umem *umem)
{
	ibv_dofork_range(umem->addr, umem->size);
	free(umem);
	return 0;
}

static bool bnxt_re_dv_is_valid_umem(struct bnxt_re_dev *dev,
				     struct bnxt_re_dv_umem *umem,
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
				    struct ubnxt_re_cq_resp *resp)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct verbs_create_cq_prov_attr prov_attr = {};
	struct bnxt_re_dv_umem *cq_umem = cq->cq_umem;
	struct ibv_cq_init_attr_ex cq_attr_ex = {};
	uint64_t offset = cq_attr->cq_umem_offset;
	struct ubnxt_re_cq cmd = {};
	uint32_t cmd_flags = 0;
	uint32_t size;
	int ret;

	size = cq_attr->ncqe * bnxt_re_get_cqe_sz();
	if (!bnxt_re_dv_is_valid_umem(dev, cq_umem, offset, size)) {
		fprintf(stderr,
			"Invalid cq_umem: %" PRIuPTR " offset: %" PRIx64 " size: 0x%x\n",
			(uintptr_t)cq_umem, offset, size);
		return -EINVAL;
	}

	cmd.cq_handle = (uintptr_t)cq;
	cmd.ncqe = cq_attr->ncqe;
	cmd.comp_mask = comp_mask;

	prov_attr.buffer.length = size;
	if (cq_umem->dmabuf_fd >= 0) {
		prov_attr.buffer.dmabuf.fd = cq_umem->dmabuf_fd;
		prov_attr.buffer.dmabuf.offset = (uintptr_t)(cq_umem->addr) + offset;
		cmd_flags = CREATE_CQ_CMD_FLAGS_WITH_MEM_DMABUF;
	} else {
		prov_attr.buffer.ptr = (uint8_t *)(cq_umem->addr + offset);
		cmd_flags = CREATE_CQ_CMD_FLAGS_WITH_MEM_VA;
	}

	cq_attr_ex.cqe = cq_attr->ncqe;
	cq_attr_ex.comp_mask = 0;
	cq_attr_ex.flags = 0;

	memset(resp, 0, sizeof(*resp));
	ret = ibv_cmd_create_cq_ex(ibvctx, &cq_attr_ex, &prov_attr,
				   (struct verbs_cq *)&cq->ibvcq,
				   (struct ibv_create_cq_ex *)&cmd.ibv_cmd, sizeof(cmd),
				   (struct ib_uverbs_ex_create_cq_resp *)&resp->ibv_resp,
				   sizeof(*resp), cmd_flags);
	if (ret) {
		fprintf(stderr, "%s: ibv_cmd_create_cq_ex() failed: %d\n", __func__, ret);
		return ret;
	}

	cq->cqid = resp->cqid;
	cq->phase = resp->phase;
	cq->cqq->tail = resp->tail;
	cq->udpi = &cntx->udpi;
	cq->cntx = cntx;
	cq->rand.seed = cq->cqid;

	return 0;
}

static int bnxt_re_dv_init_cq(struct ibv_context *ibvctx, struct bnxt_re_cq *cq,
			      struct ubnxt_re_cq_resp *resp)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);

	cq->cqid = resp->cqid;
	cq->phase = resp->phase;
	cq->cqq->tail = resp->tail;
	cq->udpi = &cntx->udpi;
	cq->cntx = cntx;
	cq->rand.seed = cq->cqid;
	if (resp->comp_mask & BNXT_RE_CQ_TOGGLE_PAGE_SUPPORT)
		return -EOPNOTSUPP;
	pthread_spin_init(&cq->cqq->qlock, PTHREAD_PROCESS_PRIVATE);
	list_head_init(&cq->sfhead);
	list_head_init(&cq->rfhead);
	list_head_init(&cq->prev_cq_head);
	return 0;
}

struct ibv_cq *bnxt_re_dv_create_cq(struct ibv_context *ibvctx,
				    struct bnxt_re_dv_cq_init_attr *cq_attr)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);
	struct bnxt_re_dv_umem *cq_umem = cq_attr->umem_handle;
	uint64_t comp_mask = BNXT_RE_CQ_DV_CQ_ENABLE;
	struct ubnxt_re_cq_resp resp = {};
	struct bnxt_re_cq *cq;
	int ret;

	if (!(cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_DV_CQ_ENABLED))
		return NULL;

	if (cq_attr->ncqe > dev->max_cq_depth)
		return NULL;

	cq = calloc(1, (sizeof(*cq)));
	if (!cq)
		return NULL;

	cq->cqq = NULL;
	cq->cq_umem = cq_umem;

	ret = bnxt_re_dv_create_cq_cmd(dev, ibvctx, cq, cq_attr, comp_mask, &resp);
	if (ret) {
		fprintf(stderr, "%s: bnxt_re_dv_create_cq_cmd() failed: %d\n",
			__func__, ret);
		goto fail;
	}

	ret = bnxt_re_dv_init_cq(ibvctx, cq, &resp);
	if (ret) {
		fprintf(stderr, "%s: bnxt_re_dv_init_cq() failed: %d\n",
			__func__, ret);
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
	int ret;

	ret = bnxt_re_destroy_cq(ibvcq);
	if (ret)
		fprintf(stderr, "%s: bnxt_re_destroy_cq() failed: %d\n",
			__func__, ret);
	return ret;
}

static void bnxt_re_dv_init_ib_qp(struct ibv_context *ibvctx,
				  struct ibv_qp_init_attr_ex *attr,
				  struct bnxt_re_qp *qp)
{
	struct ibv_qp *ibvqp = qp->ibvqp;

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
			       struct ubnxt_re_qp_resp *resp)
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
			 struct ibv_qp_init_attr_ex *attr_ex,
			 struct ubnxt_re_qp_resp *resp,
			 struct bnxt_re_qp *qp)
{
	DECLARE_COMMAND_BUFFER_LINK(driver_attrs, UVERBS_OBJECT_QP,
				    UVERBS_METHOD_QP_CREATE, 1, NULL);
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dv_db_region_attr *db_attr = NULL;
	struct verbs_create_qp_prov_attr prov_attr = {};
	struct bnxt_re_dv_umem *sq_umem = NULL;
	struct bnxt_re_dv_umem *rq_umem = NULL;
	struct ubnxt_re_qp req = {};
	uint32_t cmd_flags = 0;
	uint64_t offset;
	uint32_t size;
	int ret;

	req.qp_handle = dv_qp_attr->qp_handle;

	/* Setup SQ buffer attributes */
	sq_umem = dv_qp_attr->sq_umem_handle;
	offset = dv_qp_attr->sq_umem_offset;
	size = dv_qp_attr->sq_len;
	if (!bnxt_re_dv_is_valid_umem(cntx->rdev, sq_umem, offset, size)) {
		fprintf(stderr,
			"Invalid sq_umem: %" PRIuPTR " offset: %" PRIx64 " size: 0x%x\n",
			(uintptr_t)sq_umem, offset, size);
		return -EINVAL;
	}
	prov_attr.sq_buffer.length = size;
	if (sq_umem->dmabuf_fd >= 0) {
		prov_attr.sq_buffer.dmabuf.fd = sq_umem->dmabuf_fd;
		prov_attr.sq_buffer.dmabuf.offset = (uintptr_t)(sq_umem->addr) + offset;
		cmd_flags |= CREATE_QP_CMD_FLAGS_WITH_SQ_MEM_DMABUF;
	} else {
		prov_attr.sq_buffer.ptr = (uint8_t *)(sq_umem->addr + offset);
		cmd_flags |= CREATE_QP_CMD_FLAGS_WITH_SQ_MEM_VA;
	}
	req.sq_slots = dv_qp_attr->sq_slots;
	req.sq_wqe_sz = dv_qp_attr->sq_wqe_sz;
	req.sq_psn_sz = dv_qp_attr->sq_psn_sz;
	req.sq_npsn = dv_qp_attr->sq_npsn;

	/* Setup RQ buffer attributes */
	if (!dv_qp_attr->srq) {
		rq_umem = dv_qp_attr->rq_umem_handle;
		offset = dv_qp_attr->rq_umem_offset;
		size = dv_qp_attr->rq_len;
		if (!bnxt_re_dv_is_valid_umem(cntx->rdev, rq_umem, offset, size)) {
			fprintf(stderr,
				"Invalid rq_umem: %" PRIuPTR "  offset: %" PRIx64 " size: 0x%x\n",
				(uintptr_t)rq_umem, offset, size);
			return -EINVAL;
		}
		prov_attr.rq_buffer.length = size;
		if (rq_umem->dmabuf_fd >= 0) {
			prov_attr.rq_buffer.dmabuf.fd = rq_umem->dmabuf_fd;
			prov_attr.rq_buffer.dmabuf.offset = (uintptr_t)(rq_umem->addr) + offset;
			cmd_flags |= CREATE_QP_CMD_FLAGS_WITH_RQ_MEM_DMABUF;
		} else {
			prov_attr.rq_buffer.ptr = (uint8_t *)(rq_umem->addr + offset);
			cmd_flags |= CREATE_QP_CMD_FLAGS_WITH_RQ_MEM_VA;
		}
		req.rq_slots = dv_qp_attr->rq_slots;
		req.rq_wqe_sz = dv_qp_attr->rq_wqe_sz;
	}

	req.comp_mask = BNXT_RE_QP_REQ_MASK_DV_QP_ENABLE;
	if (dv_qp_attr->dbr_handle) {
		db_attr = dv_qp_attr->dbr_handle;
		qp->dv_dpi.dbpage = db_attr->dbr;
		qp->dv_dpi.dpindx = db_attr->dpi;
		qp->udpi = &qp->dv_dpi;
		fill_attr_in_obj(driver_attrs, BNXT_RE_CREATE_QP_ATTR_DBR_HANDLE,
				 db_attr->handle);
	} else {
		qp->udpi = &cntx->udpi;
	}
	ret = ibv_cmd_create_qp_ex3(ibvctx, &qp->vqp, attr_ex, &prov_attr,
				    &req.ibv_cmd, sizeof(req), &resp->ibv_resp,
				    sizeof(*resp), cmd_flags, driver_attrs);
	if (ret) {
		fprintf(stderr, "%s: ibv_cmd_create_qp_ex3() failed: %d\n",
			__func__, ret);
		return ret;
	}
	return 0;
}

struct ibv_qp *bnxt_re_dv_create_qp(struct ibv_pd *ibvpd,
				    struct bnxt_re_dv_qp_init_attr *dv_qp_attr)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct ibv_qp_init_attr_ex attr_ex;
	struct ibv_qp_init_attr attr = {};
	struct ubnxt_re_qp_resp resp = {};
	struct bnxt_re_qp *qp;
	int rc;

	if (!(cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_DV_QP_ENABLED))
		return NULL;

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
	memset(&attr_ex, 0, sizeof(attr_ex));
	fill_ib_attr_from_dv_qp_attr(dv_qp_attr, &attr);
	memcpy(&attr_ex, &attr, sizeof(attr));
	attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = ibvpd;

	rc = bnxt_re_dv_create_qp_cmd(ibvpd->context, dv_qp_attr, &attr_ex, &resp, qp);
	if (rc) {
		free(qp);
		return NULL;
	}

	bnxt_re_dv_init_qp(ibvpd->context, &attr_ex, qp, &resp);
	return qp->ibvqp;
}

int bnxt_re_dv_destroy_qp(struct ibv_qp *ibvqp)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct bnxt_re_mem *mem;
	int ret;

	qp->qpst = IBV_QPS_RESET;
	ret = ibv_cmd_destroy_qp(ibvqp);
	if (ret) {
		fprintf(stderr, "%s: ibv_cmd_destroy_qp() failed: %d\n",
			__func__, ret);
		return ret;
	}
	bnxt_re_cleanup_cq(qp, qp->rcq);
	if (qp->scq != qp->rcq)
		bnxt_re_cleanup_cq(qp, qp->scq);
	mem = qp->mem;
	bnxt_re_free_mem(mem);
	return 0;
}

static void bnxt_re_dv_copy_to_uattr(struct ib_uverbs_qp_attr *dst,
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

int bnxt_re_dv_query_qp(void *qp_handle, struct ib_uverbs_qp_attr *qp_attr)
{
	struct ibv_qp *ibvqp = qp_handle;
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct ibv_qp_init_attr init_attr = {};
	struct ibv_qp_attr attr = {};
	struct ibv_query_qp cmd;
	int rc;

	rc = ibv_cmd_query_qp(ibvqp, &attr, qp_attr->qp_attr_mask, &init_attr,
			      &cmd, sizeof(cmd));
	if (!rc) {
		qp->qpst = ibvqp->state;
		bnxt_re_dv_copy_to_uattr(qp_attr, &attr, qp_attr->qp_attr_mask);
	}
	return rc;
}

int bnxt_re_dv_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct ibv_modify_qp cmd = {};
	int rc;

	rc = ibv_cmd_modify_qp(ibvqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (rc) {
		fprintf(stderr, "DV Modify QP error: %d\n", rc);
		return rc;
	}

	if (attr_mask & IBV_QP_SQ_PSN)
		qp->sq_psn = attr->sq_psn;
	if (attr_mask & IBV_QP_PATH_MTU)
		qp->mtu = (0x80 << attr->path_mtu);
	return rc;
}
