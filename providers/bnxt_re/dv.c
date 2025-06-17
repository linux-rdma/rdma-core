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
