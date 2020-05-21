// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "mlx5dv_dr.h"

struct dr_ptrn_mngr {
	struct mlx5dv_dr_domain *dmn;
	struct dr_icm_pool *ptrn_icm_pool;
};

struct dr_ptrn_mngr *
dr_ptrn_mngr_create(struct mlx5dv_dr_domain *dmn)
{
	struct dr_ptrn_mngr *mngr;

	if (!dr_domain_is_support_modify_hdr_cache(dmn))
		return NULL;

	mngr = calloc(1, sizeof(*mngr));
	if (!mngr) {
		errno = ENOMEM;
		return NULL;
	}

	mngr->dmn = dmn;
	mngr->ptrn_icm_pool = dr_icm_pool_create(dmn, DR_ICM_TYPE_MODIFY_HDR_PTRN);
	if (!mngr->ptrn_icm_pool) {
		dr_dbg(dmn, "Couldn't get modify-header-pattern memory for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto free_mngr;
	}

	return mngr;

free_mngr:
	free(mngr);
	return NULL;
}

void dr_ptrn_mngr_destroy(struct dr_ptrn_mngr *mngr)
{
	if (!mngr)
		return;

	dr_icm_pool_destroy(mngr->ptrn_icm_pool);
	free(mngr);
}
