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
#include "xsc_hsi.h"

void xsc_cq_fill_pfns(struct xsc_cq *cq, const struct ibv_cq_init_attr_ex *cq_attr)
{
}

static int xsc_use_huge(const char *key)
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
