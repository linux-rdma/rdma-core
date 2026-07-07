// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <util/compiler.h>
#include <infiniband/opcode.h>

#include "xscale.h"
#include "xsc_hw.h"

static void *get_cqe(struct xsc_cq *cq, int n)
{
	return cq->active_buf->buf + n * cq->cqe_sz;
}

static void *get_sw_cqe(struct xsc_cq *cq, int n)
{
	int cid = n & (cq->verbs_cq.cq_ex.cqe - 1);
	struct xsc_cqe *cqe = get_cqe(cq, cid);

	if (likely(xsc_get_cqe_sw_own(cqe, n, cq->log2_cq_ring_sz)))
		return cqe;
	else
		return NULL;
}

static void update_cons_index(struct xsc_cq *cq)
{
	struct xsc_context *ctx = to_xctx(ibv_cq_ex_to_cq(&cq->verbs_cq.cq_ex)->context);

	xsc_hw_set_cq_ci(ctx->device_id, cq->db, cq->cqn, cq->cons_index);
}

void xsc_cq_fill_pfns(struct xsc_cq *cq, const struct ibv_cq_init_attr_ex *cq_attr)
{
}

static int is_equal_rsn(struct xsc_cqe *cqe, uint32_t rsn)
{
	uint32_t qp_id = FIELD_GET(XSC_CQE_QP_ID_MASK, cqe->data1);

	qp_id = RD_LE_16(qp_id);
	return rsn == qp_id;
}

static inline int free_res_cqe(struct xsc_cqe *cqe, uint32_t rsn)
{
	if (is_equal_rsn(cqe, rsn))
		return 1;

	return 0;
}

void __xsc_cq_clean(struct xsc_cq *cq, uint32_t rsn)
{
	uint32_t prod_index;
	int nfreed = 0;
	struct xsc_cqe *cqe, *dest;
	uint8_t owner_bit;

	if (!cq || cq->flags & XSC_CQ_FLAGS_DV_OWNED)
		return;
	xsc_dbg(to_xctx(cq->verbs_cq.cq_ex.context)->dbg_fp, XSC_DBG_CQ, "\n");

	/*
	 * First we need to find the current producer index, so we
	 * know where to start cleaning from.  It doesn't matter if HW
	 * adds new entries after this loop -- the QP we're worried
	 * about is already in RESET, so the new entries won't come
	 * from our QP and therefore don't need to be checked.
	 */
	for (prod_index = cq->cons_index; get_sw_cqe(cq, prod_index); ++prod_index)
		if (prod_index == cq->cons_index + cq->verbs_cq.cq_ex.cqe)
			break;

	/*
	 * Now sweep backwards through the CQ, removing CQ entries
	 * that match our QP by copying older entries on top of them.
	 */
	while ((int) --prod_index - (int) cq->cons_index >= 0) {
		cqe = get_cqe(cq, prod_index & (cq->verbs_cq.cq_ex.cqe - 1));
		if (free_res_cqe(cqe, rsn)) {
			++nfreed;
		} else if (nfreed) {
			dest = get_cqe(cq, (prod_index + nfreed) & (cq->verbs_cq.cq_ex.cqe - 1));
			owner_bit = FIELD_GET(XSC_CQE_OWNER_MASK, dest->data3);
			memcpy(dest, cqe, cq->cqe_sz);
			dest->data3 |= FIELD_PREP(XSC_CQE_OWNER_MASK, owner_bit);
		}
	}

	if (nfreed) {
		cq->cons_index += nfreed;
		/*
		 * Make sure update of buffer contents is done before
		 * updating consumer index.
		 */
		udma_to_device_barrier();
		update_cons_index(cq);
	}
}

void xsc_cq_clean(struct xsc_cq *cq, uint32_t qpn)
{
	xsc_spin_lock(&cq->lock);
	__xsc_cq_clean(cq, qpn);
	xsc_spin_unlock(&cq->lock);
}

int xsc_use_huge(const char *key)
{
	char *e;

	e = getenv(key);
	if (e && !strcmp(e, "y"))
		return 1;

	return 0;
}

int xsc_alloc_cq_buf(struct xsc_context *xctx, struct xsc_cq *cq,
		      struct xsc_buf *buf, int nent, int cqe_sz,
		      struct xscdv_devx_umem_in *umem_in)
{
	struct xsc_device *xdev = to_xdev(xctx->ibv_ctx.context.device);
	int ret;
	enum xsc_alloc_type type;
	enum xsc_alloc_type default_type = XSC_ALLOC_TYPE_ANON;

	if (umem_in) {
		if (umem_in->comp_mask & XSCDV_UMEM_MASK_DMABUF) {
			if (umem_in->dmabuf_fd == -1) {
				xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ,
					"dmabuf_fd is invalid :%u\n",
					umem_in->dmabuf_fd);
				return -1;
			}
		}

		buf->type = XSC_ALLOC_TYPE_GPU;
		buf->buf = umem_in->addr;
		buf->length = umem_in->size;

		xsc_dbg(xctx->dbg_fp, XSC_DBG_CQ,
			"cq_buf(%p),cq_buf_size=0x%lx is given by gpu memory,infact need size=0x%x.\n",
			buf->buf, buf->length, (nent * cqe_sz));
	} else {
		if (xsc_use_huge("HUGE_CQ"))
			default_type = XSC_ALLOC_TYPE_HUGE;

		xsc_get_alloc_type(xctx, XSC_CQ_PREFIX, &type, default_type);

		ret = xsc_alloc_prefered_buf(xctx, buf,
					     align(nent * cqe_sz, xdev->page_size),
					     xdev->page_size,
					     type,
					     XSC_CQ_PREFIX);

		if (ret)
			return -1;

		memset(buf->buf, 0, nent * cqe_sz);
	}

	return 0;
}

int xsc_free_cq_buf(struct xsc_context *ctx, struct xsc_buf *buf)
{
	if (buf->type != XSC_ALLOC_TYPE_GPU)
		return xsc_free_actual_buf(ctx, buf);
	else
		return 0;
}
