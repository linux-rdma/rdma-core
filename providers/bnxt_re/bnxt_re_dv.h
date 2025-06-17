/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2026, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#ifndef __BNXT_RE_DV_H__
#define __BNXT_RE_DV_H__

#include <stdint.h>
#include <infiniband/verbs.h>
#ifdef __cplusplus
extern "C" {
#endif

struct bnxt_re_dv_db_region_attr {
	uint32_t handle;
	uint32_t dpi;
	uint64_t *dbr;
};

struct bnxt_re_dv_db_region_attr *
bnxt_re_dv_alloc_db_region(struct ibv_context *ctx);
int bnxt_re_dv_free_db_region(struct ibv_context *ctx,
			      struct bnxt_re_dv_db_region_attr *attr);
int bnxt_re_dv_get_default_db_region(struct ibv_context *ibvctx,
				     struct bnxt_re_dv_db_region_attr *out);
#ifdef __cplusplus
}
#endif
#endif /* __BNXT_RE_DV_H__ */
