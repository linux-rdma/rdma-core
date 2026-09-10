// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <config.h>

#include <signal.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "xscale.h"
#include "bitmap.h"

static int xsc_bitmap_init(struct xsc_bitmap *bitmap, uint32_t num,
			    uint32_t mask)
{
	bitmap->last = 0;
	bitmap->top  = 0;
	bitmap->max  = num;
	bitmap->avail = num;
	bitmap->mask = mask;
	bitmap->avail = bitmap->max;
	bitmap->table = calloc(BITS_TO_LONGS(bitmap->max), sizeof(*bitmap->table));
	if (!bitmap->table)
		return -ENOMEM;

	return 0;
}

static void bitmap_free_range(struct xsc_bitmap *bitmap, uint32_t obj,
			      int cnt)
{
	int i;

	obj &= bitmap->max - 1;

	for (i = 0; i < cnt; i++)
		xsc_clear_bit(obj + i, bitmap->table);
	bitmap->last = min(bitmap->last, obj);
	bitmap->top = (bitmap->top + bitmap->max) & bitmap->mask;
	bitmap->avail += cnt;
}

static int bitmap_empty(struct xsc_bitmap *bitmap)
{
	return (bitmap->avail == bitmap->max) ? 1 : 0;
}

static int bitmap_avail(struct xsc_bitmap *bitmap)
{
	return bitmap->avail;
}

static void xsc_bitmap_cleanup(struct xsc_bitmap *bitmap)
{
	if (bitmap->table)
		free(bitmap->table);
}

static void free_huge_mem(struct xsc_hugetlb_mem *hmem)
{
	xsc_bitmap_cleanup(&hmem->bitmap);
	if (shmdt(hmem->shmaddr) == -1)
		xsc_dbg(stderr, XSC_DBG_CONTIG, "%s\n", strerror(errno));
	shmctl(hmem->shmid, IPC_RMID, NULL);
	free(hmem);
}

static int xsc_bitmap_alloc(struct xsc_bitmap *bitmap)
{
	uint32_t obj;
	int ret;

	obj = xsc_find_first_zero_bit(bitmap->table, bitmap->max);
	if (obj < bitmap->max) {
		xsc_set_bit(obj, bitmap->table);
		bitmap->last = (obj + 1);
		if (bitmap->last == bitmap->max)
			bitmap->last = 0;
		obj |= bitmap->top;
		ret = obj;
	} else
		ret = -1;

	if (ret != -1)
		--bitmap->avail;

	return ret;
}

static uint32_t find_aligned_range(unsigned long *bitmap,
				   uint32_t start, uint32_t nbits,
				   int len, int alignment)
{
	uint32_t end, i;

again:
	start = align(start, alignment);

	while ((start < nbits) && xsc_test_bit(start, bitmap))
		start += alignment;

	if (start >= nbits)
		return -1;

	end = start + len;
	if (end > nbits)
		return -1;

	for (i = start + 1; i < end; i++) {
		if (xsc_test_bit(i, bitmap)) {
			start = i + 1;
			goto again;
		}
	}

	return start;
}

static int bitmap_alloc_range(struct xsc_bitmap *bitmap, int cnt,
			      int align)
{
	uint32_t obj;
	int ret, i;

	if (cnt == 1 && align == 1)
		return xsc_bitmap_alloc(bitmap);

	if (cnt > bitmap->max)
		return -1;

	obj = find_aligned_range(bitmap->table, bitmap->last,
				 bitmap->max, cnt, align);
	if (obj >= bitmap->max) {
		bitmap->top = (bitmap->top + bitmap->max) & bitmap->mask;
		obj = find_aligned_range(bitmap->table, 0, bitmap->max,
					 cnt, align);
	}

	if (obj < bitmap->max) {
		for (i = 0; i < cnt; i++)
			xsc_set_bit(obj + i, bitmap->table);
		if (obj == bitmap->last) {
			bitmap->last = (obj + cnt);
			if (bitmap->last >= bitmap->max)
				bitmap->last = 0;
		}
		obj |= bitmap->top;
		ret = obj;
	} else
		ret = -1;

	if (ret != -1)
		bitmap->avail -= cnt;

	return obj;
}

static struct xsc_hugetlb_mem *alloc_huge_mem(size_t size)
{
	struct xsc_hugetlb_mem *hmem;
	size_t shm_len;

	hmem = malloc(sizeof(*hmem));
	if (!hmem)
		return NULL;

	shm_len = align(size, XSC_SHM_LENGTH);
	hmem->shmid = shmget(IPC_PRIVATE, shm_len, SHM_HUGETLB | SHM_R | SHM_W);
	if (hmem->shmid == -1) {
		xsc_dbg(stderr, XSC_DBG_CONTIG, "%s\n", strerror(errno));
		goto out_free;
	}

	hmem->shmaddr = shmat(hmem->shmid, XSC_SHM_ADDR, XSC_SHMAT_FLAGS);
	if (hmem->shmaddr == (void *)-1) {
		xsc_dbg(stderr, XSC_DBG_CONTIG, "%s\n", strerror(errno));
		goto out_rmid;
	}

	if (xsc_bitmap_init(&hmem->bitmap, shm_len / XSC_Q_CHUNK_SIZE,
			     shm_len / XSC_Q_CHUNK_SIZE - 1)) {
		xsc_dbg(stderr, XSC_DBG_CONTIG, "%s\n", strerror(errno));
		goto out_shmdt;
	}

	/*
	 * Marked to be destroyed when process detaches from shmget segment
	 */
	shmctl(hmem->shmid, IPC_RMID, NULL);

	return hmem;

out_shmdt:
	if (shmdt(hmem->shmaddr) == -1)
		xsc_dbg(stderr, XSC_DBG_CONTIG, "%s\n", strerror(errno));

out_rmid:
	shmctl(hmem->shmid, IPC_RMID, NULL);

out_free:
	free(hmem);
	return NULL;
}

static int alloc_huge_buf(struct xsc_context *xctx, struct xsc_buf *buf,
			  size_t size, int page_size)
{
	int found = 0;
	int nchunk;
	struct xsc_hugetlb_mem *hmem;
	int ret;

	buf->length = align(size, XSC_Q_CHUNK_SIZE);
	nchunk = buf->length / XSC_Q_CHUNK_SIZE;

	if (!nchunk)
		return 0;

	xsc_spin_lock(&xctx->hugetlb_lock);
	list_for_each(&xctx->hugetlb_list, hmem, entry) {
		if (bitmap_avail(&hmem->bitmap)) {
			buf->base = bitmap_alloc_range(&hmem->bitmap, nchunk, 1);
			if (buf->base != -1) {
				buf->hmem = hmem;
				found = 1;
				break;
			}
		}
	}
	xsc_spin_unlock(&xctx->hugetlb_lock);

	if (!found) {
		hmem = alloc_huge_mem(buf->length);
		if (!hmem)
			return -1;

		buf->base = bitmap_alloc_range(&hmem->bitmap, nchunk, 1);
		if (buf->base == -1) {
			free_huge_mem(hmem);
			/* TBD: remove after proven stability */
			fprintf(stderr, "BUG: huge allocation\n");
			return -1;
		}

		buf->hmem = hmem;

		xsc_spin_lock(&xctx->hugetlb_lock);
		if (bitmap_avail(&hmem->bitmap))
			list_add(&xctx->hugetlb_list, &hmem->entry);
		else
			list_add_tail(&xctx->hugetlb_list, &hmem->entry);
		xsc_spin_unlock(&xctx->hugetlb_lock);
	}

	buf->buf = hmem->shmaddr + buf->base * XSC_Q_CHUNK_SIZE;

	ret = ibv_dontfork_range(buf->buf, buf->length);
	if (ret)
		goto out_fork;

	buf->type = XSC_ALLOC_TYPE_HUGE;

	return 0;

out_fork:
	xsc_spin_lock(&xctx->hugetlb_lock);
	bitmap_free_range(&hmem->bitmap, buf->base, nchunk);
	if (bitmap_empty(&hmem->bitmap)) {
		list_del(&hmem->entry);
		xsc_spin_unlock(&xctx->hugetlb_lock);
		free_huge_mem(hmem);
	} else
		xsc_spin_unlock(&xctx->hugetlb_lock);

	return -1;
}

static void free_huge_buf(struct xsc_context *ctx, struct xsc_buf *buf)
{
	int nchunk;

	nchunk = buf->length / XSC_Q_CHUNK_SIZE;
	if (!nchunk)
		return;

	xsc_spin_lock(&ctx->hugetlb_lock);
	bitmap_free_range(&buf->hmem->bitmap, buf->base, nchunk);
	if (bitmap_empty(&buf->hmem->bitmap)) {
		list_del(&buf->hmem->entry);
		xsc_spin_unlock(&ctx->hugetlb_lock);
		free_huge_mem(buf->hmem);
	} else
		xsc_spin_unlock(&ctx->hugetlb_lock);
}

static void xsc_free_buf_extern(struct xsc_context *ctx, struct xsc_buf *buf)
{
	ibv_dofork_range(buf->buf, buf->length);
	ctx->extern_alloc.free(buf->buf, ctx->extern_alloc.data);
}

static int xsc_alloc_buf_extern(struct xsc_context *ctx, struct xsc_buf *buf,
		size_t size)
{
	void *addr;

	addr = ctx->extern_alloc.alloc(size, ctx->extern_alloc.data);
	if (addr || size == 0) {
		if (ibv_dontfork_range(addr, size)) {
			xsc_err("External mode dontfork_range failed\n");
			ctx->extern_alloc.free(addr,
				ctx->extern_alloc.data);
			return -1;
		}
		buf->buf = addr;
		buf->length = size;
		buf->type = XSC_ALLOC_TYPE_EXTERNAL;
		return 0;
	}

	xsc_err("External alloc failed\n");
	return -1;
}

int xsc_alloc_prefered_buf(struct xsc_context *xctx,
			    struct xsc_buf *buf,
			    size_t size, int page_size,
			    enum xsc_alloc_type type,
			    const char *component)
{
	int ret;

	/*
	 * Fallback mechanism priority:
	 *	huge pages
	 *	contig pages
	 *	default
	 */
	if (type == XSC_ALLOC_TYPE_HUGE ||
	    type == XSC_ALLOC_TYPE_PREFER_HUGE ||
	    type == XSC_ALLOC_TYPE_ALL) {
		ret = alloc_huge_buf(xctx, buf, size, page_size);
		if (!ret)
			return 0;

		if (type == XSC_ALLOC_TYPE_HUGE)
			return -1;

		xsc_dbg(xctx->dbg_fp, XSC_DBG_CONTIG, "Huge mode allocation failed, fallback to %s mode\n",
			 XSC_ALLOC_TYPE_ALL ? "contig" : "default");
	}

	if (type == XSC_ALLOC_TYPE_CONTIG ||
	    type == XSC_ALLOC_TYPE_PREFER_CONTIG ||
	    type == XSC_ALLOC_TYPE_ALL) {
		ret = xsc_alloc_buf_contig(xctx, buf, size, page_size, component);
		if (!ret)
			return 0;

		if (type == XSC_ALLOC_TYPE_CONTIG)
			return -1;
		xsc_dbg(xctx->dbg_fp, XSC_DBG_CONTIG, "Contig allocation failed, fallback to default mode\n");
	}

	if (type == XSC_ALLOC_TYPE_EXTERNAL)
		return xsc_alloc_buf_extern(xctx, buf, size);

	return xsc_alloc_buf(buf, size, page_size);

}

int xsc_free_actual_buf(struct xsc_context *ctx, struct xsc_buf *buf)
{
	int err = 0;

	switch (buf->type) {
	case XSC_ALLOC_TYPE_ANON:
		xsc_free_buf(buf);
		break;

	case XSC_ALLOC_TYPE_HUGE:
		free_huge_buf(ctx, buf);
		break;

	case XSC_ALLOC_TYPE_CONTIG:
		xsc_free_buf_contig(ctx, buf);
		break;

	case XSC_ALLOC_TYPE_EXTERNAL:
		xsc_free_buf_extern(ctx, buf);
		break;

	default:
		fprintf(stderr, "Bad allocation type\n");
	}

	return err;
}

/* This function computes log2(v) rounded up.
 * We don't want to have a dependency to libm which exposes ceil & log2 APIs.
 * Code was written based on public domain code:
 *	URL: http://graphics.stanford.edu/~seander/bithacks.html#IntegerLog.
 */
static uint32_t xsc_get_block_order(uint32_t v)
{
	static const uint32_t bits_arr[] = {0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000};
	static const uint32_t shift_arr[] = {1, 2, 4, 8, 16};
	int i;
	uint32_t input_val = v;
	register uint32_t r = 0;/* result of log2(v) will go here */

	for (i = 4; i >= 0; i--) {
		if (v & bits_arr[i]) {
			v >>= shift_arr[i];
			r |= shift_arr[i];
		}
	}
	/* Rounding up if required */
	r += !!(input_val & ((1 << r) - 1));

	return r;
}

static bool xsc_is_extern_alloc(struct xsc_context *context)
{
	return context->extern_alloc.alloc && context->extern_alloc.free;
}

void xsc_get_alloc_type(struct xsc_context *context,
			 const char *component,
			 enum xsc_alloc_type *alloc_type,
			 enum xsc_alloc_type default_type)
{
	char *env_value;
	char name[128];

	if (xsc_is_extern_alloc(context)) {
		*alloc_type = XSC_ALLOC_TYPE_EXTERNAL;
		return;
	}

	snprintf(name, sizeof(name), "%s_ALLOC_TYPE", component);

	*alloc_type = default_type;

	env_value = getenv(name);
	if (env_value) {
		if (!strcasecmp(env_value, "ANON"))
			*alloc_type = XSC_ALLOC_TYPE_ANON;
		else if (!strcasecmp(env_value, "HUGE"))
			*alloc_type = XSC_ALLOC_TYPE_HUGE;
		else if (!strcasecmp(env_value, "CONTIG"))
			*alloc_type = XSC_ALLOC_TYPE_CONTIG;
		else if (!strcasecmp(env_value, "PREFER_CONTIG"))
			*alloc_type = XSC_ALLOC_TYPE_PREFER_CONTIG;
		else if (!strcasecmp(env_value, "PREFER_HUGE"))
			*alloc_type = XSC_ALLOC_TYPE_PREFER_HUGE;
		else if (!strcasecmp(env_value, "ALL"))
			*alloc_type = XSC_ALLOC_TYPE_ALL;
	}
}

static void xsc_alloc_get_env_info(int *max_block_log,
				    int *min_block_log,
				    const char *component)

{
	char *env;
	int value;
	char name[128];

	/* First set defaults */
	*max_block_log = XSC_MAX_LOG2_CONTIG_BLOCK_SIZE;
	*min_block_log = XSC_MIN_LOG2_CONTIG_BLOCK_SIZE;

	snprintf(name, sizeof(name), "%s_MAX_LOG2_CONTIG_BSIZE", component);
	env = getenv(name);
	if (env) {
		value = atoi(env);
		if (value <= XSC_MAX_LOG2_CONTIG_BLOCK_SIZE &&
		    value >= XSC_MIN_LOG2_CONTIG_BLOCK_SIZE)
			*max_block_log = value;
		else
			fprintf(stderr, "Invalid value %d for %s\n",
				value, name);
	}
	sprintf(name, "%s_MIN_LOG2_CONTIG_BSIZE", component);
	env = getenv(name);
	if (env) {
		value = atoi(env);
		if (value >= XSC_MIN_LOG2_CONTIG_BLOCK_SIZE &&
		    value  <=  *max_block_log)
			*min_block_log = value;
		else
			fprintf(stderr, "Invalid value %d for %s\n",
				value, name);
	}
}

int xsc_alloc_buf_contig(struct xsc_context *xctx,
			  struct xsc_buf *buf, size_t size,
			  int page_size,
			  const char *component)
{
	void *addr = MAP_FAILED;
	int block_size_exp;
	int max_block_log;
	int min_block_log;
	struct ibv_context *context = &xctx->ibv_ctx.context;
	off_t offset;

	xsc_alloc_get_env_info(&max_block_log,
				&min_block_log,
				component);

	block_size_exp = xsc_get_block_order(size);

	if (block_size_exp > max_block_log)
		block_size_exp = max_block_log;

	do {
		offset = 0;
		set_command(XSC_IB_MMAP_GET_CONTIGUOUS_PAGES, &offset);
		set_order(block_size_exp, &offset);
		addr = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED,
			    context->cmd_fd, page_size * offset);
		if (addr != MAP_FAILED)
			break;

		/*
		 *  The kernel returns EINVAL if not supported
		 */
		if (errno == EINVAL)
			return -1;

		block_size_exp -= 1;
	} while (block_size_exp >= min_block_log);
	xsc_dbg(xctx->dbg_fp, XSC_DBG_CONTIG, "block order %d, addr %p\n", block_size_exp, addr);

	if (addr == MAP_FAILED)
		return -1;

	if (ibv_dontfork_range(addr, size)) {
		munmap(addr, size);
		return -1;
	}

	buf->buf = addr;
	buf->length = size;
	buf->type = XSC_ALLOC_TYPE_CONTIG;

	return 0;
}

void xsc_free_buf_contig(struct xsc_context *xctx, struct xsc_buf *buf)
{
	ibv_dofork_range(buf->buf, buf->length);
	munmap(buf->buf, buf->length);
}

int xsc_alloc_buf(struct xsc_buf *buf, size_t size, int page_size)
{
	int ret;
	int al_size;

	al_size = align(size, page_size);
	ret = posix_memalign(&buf->buf, page_size, al_size);
	if (ret)
		return ret;

	ret = ibv_dontfork_range(buf->buf, al_size);
	if (ret)
		free(buf->buf);

	if (!ret) {
		buf->length = al_size;
		buf->type = XSC_ALLOC_TYPE_ANON;
	}

	return ret;
}

void xsc_free_buf(struct xsc_buf *buf)
{
	ibv_dofork_range(buf->buf, buf->length);
	free(buf->buf);
}
