// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2026, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
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
