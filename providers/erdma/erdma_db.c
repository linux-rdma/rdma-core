// SPDX-License-Identifier: GPL-2.0 or OpenIB.org BSD (MIT) See COPYING file

// Authors: Cheng Xu <chengyou@linux.alibaba.com>
// Copyright (c) 2020-2021, Alibaba Group.

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <util/bitmap.h>
#include <util/util.h>

#include "erdma.h"
#include "erdma_db.h"

#define ERDMA_DBREC_SIZE 16

struct erdma_dbrecord_page {
	struct list_node list;
	void *page_buf;
	uint32_t cnt;
	uint32_t used;
	unsigned long *bitmap;
};

uint64_t *erdma_alloc_dbrecords(struct erdma_context *ctx)
{
	struct erdma_dbrecord_page *page = NULL;
	uint32_t free_idx, dbrecords_per_page;
	uint64_t *db_records = NULL;
	int rv;

	pthread_mutex_lock(&ctx->dbrecord_pages_mutex);

	list_for_each(&ctx->dbrecord_pages_list, page, list)
		if (page->used < page->cnt)
			goto found;

	dbrecords_per_page = ctx->page_size / ERDMA_DBREC_SIZE;

	page = calloc(1, sizeof(*page));
	if (!page)
		goto err_out;

	page->bitmap = bitmap_alloc1(dbrecords_per_page);
	if (!page->bitmap)
		goto err_bitmap;

	rv = posix_memalign(&page->page_buf, ctx->page_size, ctx->page_size);
	if (rv)
		goto err_alloc;

	page->cnt = dbrecords_per_page;
	page->used = 0;

	list_node_init(&page->list);
	list_add_tail(&ctx->dbrecord_pages_list, &page->list);

found:
	++page->used;

	free_idx = bitmap_find_first_bit(page->bitmap, 0, page->cnt);
	bitmap_clear_bit(page->bitmap, free_idx);

	db_records = page->page_buf + free_idx * ERDMA_DBREC_SIZE;

	pthread_mutex_unlock(&ctx->dbrecord_pages_mutex);

	return db_records;

err_alloc:
	free(page->bitmap);
err_bitmap:
	free(page);
err_out:
	pthread_mutex_unlock(&ctx->dbrecord_pages_mutex);

	return NULL;
}

void erdma_dealloc_dbrecords(struct erdma_context *ctx, uint64_t *dbrec)
{
	uint32_t page_mask = ~(ctx->page_size - 1);
	struct erdma_dbrecord_page *page;
	uint32_t idx;

	pthread_mutex_lock(&ctx->dbrecord_pages_mutex);

	list_for_each(&ctx->dbrecord_pages_list, page, list)
		if (((uintptr_t)dbrec & page_mask) == (uintptr_t)page->page_buf)
			goto found;

	goto out;

found:
	idx = ((uintptr_t)dbrec - (uintptr_t)page->page_buf) / ERDMA_DBREC_SIZE;

	bitmap_set_bit(page->bitmap, idx);

	page->used--;
	if (!page->used) {
		list_del(&page->list);
		free(page->bitmap);
		free(page);
	}

out:
	pthread_mutex_unlock(&ctx->dbrecord_pages_mutex);
}
