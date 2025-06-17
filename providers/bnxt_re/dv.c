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
	if (ret)
		return ret;

	out->dbr = (uint64_t *)cntx->udpi.dbpage;
	out->dpi = attr.dpi;
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
		free(out);
		errno = ret;
		return NULL;
	}
	out->handle = read_attr_obj(BNXT_RE_ALLOC_DBR_HANDLE, handle);
	out->dpi = attr.dpi;

	out->dbr = mmap(NULL, dev->pg_size, PROT_WRITE,
			MAP_SHARED, ctx->cmd_fd, mmap_offset);
	if (out->dbr == MAP_FAILED) {
		bnxt_re_dv_free_db_region(ctx, out);
		errno = ENOMEM;
		return NULL;
	}

	return out;
}
