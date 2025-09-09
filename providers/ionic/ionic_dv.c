// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#include "ionic.h"
#include "ionic_dv.h"

uint8_t ionic_dv_ctx_get_udma_count(struct ibv_context *ibctx)
{
	if (!is_ionic_ctx(ibctx))
		return 0;

	return to_ionic_ctx(ibctx)->udma_count;
}

uint8_t ionic_dv_ctx_get_udma_mask(struct ibv_context *ibctx)
{
	if (!is_ionic_ctx(ibctx))
		return 0;

	return ionic_ctx_udma_mask(to_ionic_ctx(ibctx));
}

uint8_t ionic_dv_pd_get_udma_mask(struct ibv_pd *ibpd)
{
	if (!is_ionic_pd(ibpd))
		return 0;

	return to_ionic_pd(ibpd)->udma_mask;
}

int ionic_dv_pd_set_udma_mask(struct ibv_pd *ibpd, uint8_t udma_mask)
{
	if (!is_ionic_pd(ibpd))
		return EPERM;

	if (udma_mask & ~ionic_ctx_udma_mask(to_ionic_ctx(ibpd->context)))
		return EINVAL;

	to_ionic_pd(ibpd)->udma_mask = udma_mask;

	return 0;
}
