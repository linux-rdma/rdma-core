// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
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

	fill_attr_out_ptr(cmd, BNXT_RE_DEFAULT_DBR_ATTR, &attr);

	ret = execute_ioctl(ibvctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n", __func__, ret);
		return ret;
	}
	out->dbr = (uint64_t *)cntx->udpi.dbpage;
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

	fill_attr_in_obj(cmd, BNXT_RE_FREE_DBR_HANDLE, attr->handle);

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
	struct bnxt_re_dv_db_region_attr *out;
	struct bnxt_re_db_region attr = {};
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

	handle = fill_attr_out_obj(cmd, BNXT_RE_ALLOC_DBR_HANDLE);
	fill_attr_out_ptr(cmd, BNXT_RE_ALLOC_DBR_ATTR, &attr);
	fill_attr_out_ptr(cmd, BNXT_RE_ALLOC_DBR_OFFSET, &mmap_offset);

	ret = execute_ioctl(ctx, cmd);
	if (ret) {
		fprintf(stderr, "%s: execute_ioctl() failed: %d\n",
			__func__, ret);
		free(out);
		errno = ret;
		return NULL;
	}
	out->handle = read_attr_obj(BNXT_RE_ALLOC_DBR_HANDLE, handle);
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

	if (in->comp_mask & BNXT_RE_DV_UMEM_FLAGS_DMABUF &&
	    (in->dmabuf_fd == -1)) {
		errno = EBADF;
		return NULL;
	}

	/* One dontfork call covering the entire addr range being
	 * registered, regardless of how many objects are later
	 * carved from it.
	 */
	ret = ibv_dontfork_range(in->addr, in->size);
	if (ret) {
		errno = ret;
		return NULL;
	}

	umem = calloc(1, sizeof(*umem));
	if (!umem) {
		errno = ENOMEM;
		goto err;
	}

	umem->context = ibvctx;
	umem->addr = in->addr;
	umem->size = in->size;
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
	return ((offset == align(offset, dev->pg_size)) &&
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
	uint64_t offset = cq_attr->umem_offset;
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
	cq->udpi = &cntx->udpi;
	cq->cntx = cntx;
	cq->rand.seed = cq->cqid;

	return 0;
}

struct ibv_cq *bnxt_re_dv_create_cq(struct ibv_context *ibvctx,
				    struct bnxt_re_dv_cq_init_attr *cq_attr)
{
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);
	struct bnxt_re_dv_umem *cq_umem = cq_attr->umem_handle;
	uint64_t comp_mask = BNXT_RE_CQ_FIXED_NUM_CQE_ENABLE;
	struct ubnxt_re_cq_resp resp = {};
	struct bnxt_re_cq *cq;
	int ret;

	if (!(dev->vdev.core_support & IB_UVERBS_CORE_SUPPORT_ROBUST_UDATA)) {
		fprintf(stderr, "Robust udata is not supported\n");
		return NULL;
	}

	if (cq_attr->ncqe > dev->max_cq_depth)
		return NULL;

	cq = calloc(1, (sizeof(*cq)));
	if (!cq)
		return NULL;

	cq->cq_umem = cq_umem;
	ret = bnxt_re_dv_create_cq_cmd(dev, ibvctx, cq, cq_attr, comp_mask, &resp);
	if (ret) {
		fprintf(stderr, "%s: bnxt_re_dv_create_cq_cmd() failed: %d\n",
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
