// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#include <errno.h>
#include <string.h>

#include "ionic.h"
#include "ionic_queue.h"
#include "ionic_memory.h"
#include "ionic_fw.h"

static void ionic_queue_map(struct ionic_queue *q, struct ionic_pd *pd, uint64_t pd_tag, int stride)
{
	size_t align = IONIC_PAGE_SIZE;

	if (align < stride)
		align = stride;

	q->user_buf = NULL;

	if (pd && pd->alloc_buf) {
		struct ibv_buf *got;

		got = pd->alloc_buf(&pd->ibpd, pd->pd_context, q->size, align,
				    pd_tag);
		if (got != IBV_BUF_ALLOCATOR_USE_DEFAULT) {
			if (!got) {
				q->ptr = NULL;
				return;
			}
			if (got->dmabuf_fd != -1 &&
			    !to_ionic_ctx(pd->ibpd.context)->cq_qp_buf_umem) {
				pd->free_buf(&pd->ibpd, pd->pd_context, got,
					     pd_tag);
				errno = EOPNOTSUPP;
				q->ptr = NULL;
				return;
			}
			q->ptr = got->addr;
			q->user_buf = got;
			q->pd = pd;
			q->pd_tag = pd_tag;
			return;
		}
	}

	if (pd && pd->alloc) {
		q->ptr = pd->alloc(&pd->ibpd, pd->pd_context, q->size, align, pd_tag);
		if (q->ptr != IBV_ALLOCATOR_USE_DEFAULT) {
			q->pd = pd;
			q->pd_tag = pd_tag;
			return;
		}
	}

	q->ptr = ionic_map_anon(q->size);
}

static void ionic_queue_unmap(struct ionic_queue *q)
{
	struct ionic_pd *pd = q->pd;

	if (pd && q->user_buf) {
		pd->free_buf(&pd->ibpd, pd->pd_context, q->user_buf, q->pd_tag);
		q->ptr = NULL;
		q->user_buf = NULL;
		q->pd = NULL;
		q->pd_tag = 0;
		return;
	}

	if (pd) {
		pd->free(&pd->ibpd, pd->pd_context, q->ptr, q->pd_tag);
		q->ptr = NULL;
		q->pd = NULL;
		q->pd_tag = 0;
		return;
	}

	ionic_unmap(q->ptr, q->size);
}

int ionic_queue_init(struct ionic_queue *q, struct ionic_pd *pd,
		     uint64_t pd_tag, int pg_shift, int depth, size_t stride)
{
	if (depth < 0 || depth > IONIC_QUEUE_DEPTH_MAX)
		return -EINVAL;

	if (stride == 0 || stride > IONIC_QUEUE_STRIDE_MAX)
		return -EINVAL;

	if (depth == 0)
		depth = 1;

	q->depth_log2 = ilog32(depth);
	q->stride_log2 = ilog64(stride - 1);

	if (q->depth_log2 + q->stride_log2 < pg_shift)
		q->depth_log2 = pg_shift - q->stride_log2;

	q->size = BIT_ULL(q->depth_log2 + q->stride_log2);
	q->mask = BIT(q->depth_log2) - 1;

	if (pd_tag == IONIC_PD_TAG_RCQ)
		q->size += IONIC_RCQ_SIZE;

	ionic_queue_map(q, pd, pd_tag, stride);
	if (!q->ptr)
		return errno;

	q->prod = 0;
	q->cons = 0;
	q->dbell = 0;

	return 0;
}

void ionic_queue_destroy(struct ionic_queue *q)
{
	ionic_queue_unmap(q);
}
