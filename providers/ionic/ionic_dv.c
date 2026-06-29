// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#include "ionic.h"
#include "ionic_dv.h"

bool ionic_dv_is_ionic_ctx(struct ibv_context *ibctx)
{
	return is_ionic_ctx(ibctx);
}

bool ionic_dv_is_ionic_pd(struct ibv_pd *ibpd)
{
	return is_ionic_pd(ibpd);
}

bool ionic_dv_is_ionic_cq(struct ibv_cq *ibcq)
{
	return is_ionic_cq(ibcq);
}

bool ionic_dv_is_ionic_qp(struct ibv_qp *ibqp)
{
	return is_ionic_qp(ibqp);
}

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

uint8_t ionic_dv_cq_get_udma_mask(struct ibv_cq *ibcq)
{
	if (!is_ionic_cq(ibcq))
		return 0;

	return to_ionic_vcq(ibcq)->udma_mask;
}

uint8_t ionic_dv_qp_get_udma_idx(struct ibv_qp *ibqp)
{
	if (!is_ionic_qp(ibqp))
		return 0;

	return to_ionic_qp(ibqp)->udma_idx;
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

int ionic_dv_pd_set_expdb_mask(struct ibv_pd *ibpd, uint8_t mask)
{
	struct ionic_pd *pd;

	if (!is_ionic_pd(ibpd))
		return EPERM;

	pd = to_ionic_pd(ibpd);
	pd->expdb_mask = mask & ((IONIC_EXPDB_512 << 1) - 1);

	return 0;
}

static uint8_t ionic_dv_cmb_val(bool enable, bool expdb, bool require)
{
	uint8_t cmb = 0;

	if (enable) {
		cmb = IONIC_CMB_ENABLE;

		if (expdb)
			cmb |= IONIC_CMB_EXPDB;

		if (require)
			cmb |= IONIC_CMB_REQUIRE;
	}

	return cmb;
}

int ionic_dv_pd_set_sqcmb(struct ibv_pd *ibpd, bool enable, bool expdb, bool require)
{
	struct ionic_ctx *ctx;
	struct ionic_pd *pd;

	if (!is_ionic_pd(ibpd))
		return EPERM;

	ctx = to_ionic_ctx(ibpd->context);
	pd = to_ionic_pd(ibpd);

	if (enable && expdb) {
		if (require && !ctx->sq_expdb)
			return EINVAL;

		expdb = ctx->sq_expdb;
	}

	pd->sq_cmb = ionic_dv_cmb_val(enable, expdb, require);

	return 0;
}

int ionic_dv_pd_set_rqcmb(struct ibv_pd *ibpd, bool enable, bool expdb, bool require)
{
	struct ionic_ctx *ctx;
	struct ionic_pd *pd;

	if (!is_ionic_pd(ibpd))
		return EPERM;

	ctx = to_ionic_ctx(ibpd->context);
	pd = to_ionic_pd(ibpd);

	if (enable && expdb) {
		if (require && !ctx->rq_expdb)
			return EINVAL;

		expdb = ctx->rq_expdb;
	}

	pd->rq_cmb = ionic_dv_cmb_val(enable, expdb, require);

	return 0;
}

int ionic_dv_qp_set_gda(struct ibv_qp *ibqp, bool enable_send, bool enable_recv)
{
	struct ionic_qp *qp;

	if (!is_ionic_qp(ibqp))
		return EPERM;

	qp = to_ionic_qp(ibqp);

	if (enable_send && qp->sq.cmb & IONIC_CMB_EXPDB)
		return EINVAL;

	if (enable_recv && qp->rq.cmb & IONIC_CMB_EXPDB)
		return EINVAL;

	qp->sq.gda = enable_send;
	qp->rq.gda = enable_recv;

	return 0;
}

int ionic_dv_qp_get_send_dbell_data(struct ibv_qp *ibqp, uint64_t *dbdata)
{
	struct ionic_qp *qp;

	if (!is_ionic_qp(ibqp))
		return EPERM;

	qp = to_ionic_qp(ibqp);

	*dbdata = ionic_queue_dbell_val(&qp->sq.queue);

	return 0;
}

int ionic_dv_qp_get_recv_dbell_data(struct ibv_qp *ibqp, uint64_t *dbdata)
{
	struct ionic_qp *qp;

	if (!is_ionic_qp(ibqp))
		return EPERM;

	qp = to_ionic_qp(ibqp);

	*dbdata = ionic_queue_dbell_val(&qp->rq.queue);

	return 0;
}
