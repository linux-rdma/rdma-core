/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#define _GNU_SOURCE
#include <config.h>

#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "mlx5.h"

struct mlx5_db_page {
	cl_map_item_t			cl_map;
	struct list_node		available;
	struct mlx5_buf			buf;
	int				num_db;
	int				use_cnt;
	unsigned long			free[0];
};

static struct mlx5_db_page *__add_page(struct mlx5_context *context,
				       struct ibv_pd *pd)
{
	struct mlx5_db_page *page;
	int ps = to_mdev(context->ibv_ctx.context.device)->page_size;
	int pp;
	int i;
	int nlong;
	int ret;

	pp = ps / context->cache_line_size;
	nlong = (pp + 8 * sizeof(long) - 1) / (8 * sizeof(long));

	page = malloc(sizeof *page + nlong * sizeof(long));
	if (!page)
		return NULL;

	if (mlx5_is_dmabuf_alloc(pd)) {
		page->buf.mparent_domain = to_mparent_domain(pd);
		ret = mlx5_alloc_buf_dmabuf(context, &page->buf, ps, pd);
	} else if (mlx5_is_extern_alloc(context)) {
		ret = mlx5_alloc_buf_extern(context, &page->buf, ps, pd);
	} else {
		ret = mlx5_alloc_buf(&page->buf, ps, ps, pd);
	}
	if (ret) {
		free(page);
		return NULL;
	}

	page->num_db  = pp;
	page->use_cnt = 0;
	for (i = 0; i < nlong; ++i)
		page->free[i] = ~0;

	cl_qmap_insert(&context->dbr_map, (uintptr_t) page->buf.ibv_buf.addr,
		       &page->cl_map);
	list_add(&context->dbr_available_pages, &page->available);

	return page;
}

__be32 *mlx5_alloc_dbrec(struct mlx5_context *context, struct ibv_pd *pd,
			 bool *custom_alloc)
{
	struct mlx5_db_page *page;
	__be32 *db = NULL;
	int i, j;

	if (!mlx5_is_dmabuf_alloc(pd) && mlx5_is_custom_alloc(pd)) {
		struct mlx5_parent_domain *mparent_domain = to_mparent_domain(pd);

		db = mparent_domain->alloc(&mparent_domain->mpd.ibv_pd,
				   mparent_domain->pd_context, 8, 8,
				   MLX5DV_RES_TYPE_DBR);

		if (db == IBV_ALLOCATOR_USE_DEFAULT)
			goto default_alloc;

		if (!db)
			return NULL;

		*custom_alloc = true;
		return db;
	}

default_alloc:
	pthread_mutex_lock(&context->dbr_map_mutex);

	/* DMA-buf and non-DMA-buf pages must not be mixed. */
	list_for_each(&context->dbr_available_pages, page, available) {
		if (mlx5_is_dmabuf_alloc(pd) ==
			(page->buf.type == MLX5_ALLOC_TYPE_DMABUF))
			goto found;
	}

	page = __add_page(context, pd);
	if (!page)
		goto out;

found:
	++page->use_cnt;
	if (page->use_cnt == page->num_db)
		list_del(&page->available);

	for (i = 0; !page->free[i]; ++i)
		/* nothing */;

	j = ffsl(page->free[i]);
	--j;
	page->free[i] &= ~(1UL << j);
	db = page->buf.ibv_buf.addr + (i * 8 * sizeof(long) + j) * context->cache_line_size;

out:
	pthread_mutex_unlock(&context->dbr_map_mutex);

	return db;
}

void mlx5_free_db(struct mlx5_context *context, __be32 *db, struct ibv_pd *pd,
		  bool custom_alloc)
{
	struct mlx5_db_page *page;
	uintptr_t ps = to_mdev(context->ibv_ctx.context.device)->page_size;
	cl_map_item_t *item;
	int i;

	if (custom_alloc) {
		struct mlx5_parent_domain *mparent_domain = to_mparent_domain(pd);

		mparent_domain->free(&mparent_domain->mpd.ibv_pd,
				     mparent_domain->pd_context,
				     db, MLX5DV_RES_TYPE_DBR);
		return;
	}

	pthread_mutex_lock(&context->dbr_map_mutex);

	item = cl_qmap_get(&context->dbr_map, (uintptr_t) db & ~(ps - 1));

	assert(item != cl_qmap_end(&context->dbr_map));

	page = (container_of(item, struct mlx5_db_page, cl_map));
	i = ((void *) db - page->buf.ibv_buf.addr) / context->cache_line_size;
	page->free[i / (8 * sizeof(long))] |= 1UL << (i % (8 * sizeof(long)));
	if (page->use_cnt == page->num_db)
		list_add(&context->dbr_available_pages, &page->available);

	if (!--page->use_cnt) {
		cl_qmap_remove_item(&context->dbr_map, item);
		list_del(&page->available);

		mlx5_free_actual_buf(context, &page->buf);

		free(page);
	}

	pthread_mutex_unlock(&context->dbr_map_mutex);
}
