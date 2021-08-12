/*
 * Copyright (c) 2016 Hisilicon Limited.
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

#include <errno.h>
#include <sys/mman.h>
#include <util/util.h>

#include "hns_roce_u.h"

int hns_roce_alloc_buf(struct hns_roce_buf *buf, unsigned int size,
		       int page_size)
{
	int ret;

	buf->length = align(size, page_size);
	buf->buf = mmap(NULL, buf->length, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf->buf == MAP_FAILED)
		return errno;

	ret = ibv_dontfork_range(buf->buf, buf->length);
	if (ret)
		munmap(buf->buf, buf->length);

	return ret;
}

void hns_roce_free_buf(struct hns_roce_buf *buf)
{
	ibv_dofork_range(buf->buf, buf->length);

	munmap(buf->buf, buf->length);
}

struct hns_roce_dca_mem {
	uint32_t handle;
	struct list_node entry;
	struct hns_roce_buf buf;
	struct hns_roce_context *ctx;
};

static void free_dca_mem(struct hns_roce_context *ctx,
			 struct hns_roce_dca_mem *mem)
{
	hns_roce_free_buf(&mem->buf);
	free(mem);
}

static struct hns_roce_dca_mem *alloc_dca_mem(uint32_t size)
{
	struct hns_roce_dca_mem *mem = NULL;
	int ret;

	mem = malloc(sizeof(struct hns_roce_dca_mem));
	if (!mem) {
		errno = ENOMEM;
		return NULL;
	}

	ret = hns_roce_alloc_buf(&mem->buf, size, HNS_HW_PAGE_SIZE);
	if (ret) {
		errno = ENOMEM;
		free(mem);
		return NULL;
	}

	return mem;
}

static inline uint64_t dca_mem_to_key(struct hns_roce_dca_mem *dca_mem)
{
	return (uintptr_t)dca_mem;
}

static struct hns_roce_dca_mem *key_to_dca_mem(struct hns_roce_dca_ctx *ctx,
					       uint64_t key)
{
	struct hns_roce_dca_mem *mem;
	struct hns_roce_dca_mem *tmp;

	list_for_each_safe(&ctx->mem_list, mem, tmp, entry) {
		if (dca_mem_to_key(mem) == key)
			return mem;
	}

	return NULL;
}

static inline void *dca_mem_addr(struct hns_roce_dca_mem *dca_mem, int offset)
{
	return dca_mem->buf.buf + offset;
}

static int register_dca_mem(struct hns_roce_context *ctx, uint64_t key,
			    void *addr, uint32_t size, uint32_t *handle)
{
	struct ib_uverbs_attr *attr;
	int ret;

	DECLARE_COMMAND_BUFFER(cmd, HNS_IB_OBJECT_DCA_MEM,
			       HNS_IB_METHOD_DCA_MEM_REG, 4);
	fill_attr_in_uint32(cmd, HNS_IB_ATTR_DCA_MEM_REG_LEN, size);
	fill_attr_in_uint64(cmd, HNS_IB_ATTR_DCA_MEM_REG_ADDR,
			    ioctl_ptr_to_u64(addr));
	fill_attr_in_uint64(cmd, HNS_IB_ATTR_DCA_MEM_REG_KEY, key);
	attr = fill_attr_out_obj(cmd, HNS_IB_ATTR_DCA_MEM_REG_HANDLE);

	ret = execute_ioctl(&ctx->ibv_ctx.context, cmd);
	if (ret)
		return ret;

	*handle = read_attr_obj(HNS_IB_ATTR_DCA_MEM_REG_HANDLE, attr);

	return 0;
}

static void deregister_dca_mem(struct hns_roce_context *ctx, uint32_t handle)
{
	DECLARE_COMMAND_BUFFER(cmd, HNS_IB_OBJECT_DCA_MEM,
			       HNS_IB_METHOD_DCA_MEM_DEREG, 1);
	fill_attr_in_obj(cmd, HNS_IB_ATTR_DCA_MEM_DEREG_HANDLE, handle);
	execute_ioctl(&ctx->ibv_ctx.context, cmd);
}

void hns_roce_cleanup_dca_mem(struct hns_roce_context *ctx)
{
	struct hns_roce_dca_ctx *dca_ctx = &ctx->dca_ctx;
	struct hns_roce_dca_mem *mem;
	struct hns_roce_dca_mem *tmp;

	list_for_each_safe(&dca_ctx->mem_list, mem, tmp, entry)
		deregister_dca_mem(ctx, mem->handle);
}

struct hns_dca_mem_shrink_resp {
	uint32_t free_mems;
	uint64_t free_key;
};

static int shrink_dca_mem(struct hns_roce_context *ctx, uint32_t handle,
			  uint64_t size, struct hns_dca_mem_shrink_resp *resp)
{
	DECLARE_COMMAND_BUFFER(cmd, HNS_IB_OBJECT_DCA_MEM,
			       HNS_IB_METHOD_DCA_MEM_SHRINK, 4);
	fill_attr_in_obj(cmd, HNS_IB_ATTR_DCA_MEM_SHRINK_HANDLE, handle);
	fill_attr_in_uint64(cmd, HNS_IB_ATTR_DCA_MEM_SHRINK_RESERVED_SIZE, size);
	fill_attr_out(cmd, HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_KEY,
		      &resp->free_key, sizeof(resp->free_key));
	fill_attr_out(cmd, HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_MEMS,
		      &resp->free_mems, sizeof(resp->free_mems));

	return execute_ioctl(&ctx->ibv_ctx.context, cmd);
}

struct hns_dca_mem_query_resp {
	uint64_t key;
	uint32_t offset;
	uint32_t page_count;
};

static int query_dca_mem(struct hns_roce_context *ctx, uint32_t handle,
			 uint32_t index, struct hns_dca_mem_query_resp *resp)
{
	DECLARE_COMMAND_BUFFER(cmd, HNS_IB_OBJECT_DCA_MEM,
			       HNS_IB_METHOD_DCA_MEM_QUERY, 5);
	fill_attr_in_obj(cmd, HNS_IB_ATTR_DCA_MEM_QUERY_HANDLE, handle);
	fill_attr_in_uint32(cmd, HNS_IB_ATTR_DCA_MEM_QUERY_PAGE_INDEX, index);
	fill_attr_out(cmd, HNS_IB_ATTR_DCA_MEM_QUERY_OUT_KEY,
		      &resp->key, sizeof(resp->key));
	fill_attr_out(cmd, HNS_IB_ATTR_DCA_MEM_QUERY_OUT_OFFSET,
		      &resp->offset, sizeof(resp->offset));
	fill_attr_out(cmd, HNS_IB_ATTR_DCA_MEM_QUERY_OUT_PAGE_COUNT,
		      &resp->page_count, sizeof(resp->page_count));
	return execute_ioctl(&ctx->ibv_ctx.context, cmd);
}

void hns_roce_detach_dca_mem(struct hns_roce_context *ctx, uint32_t handle,
			     struct hns_roce_dca_detach_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmd, HNS_IB_OBJECT_DCA_MEM,
			       HNS_IB_METHOD_DCA_MEM_DETACH, 4);
	fill_attr_in_obj(cmd, HNS_IB_ATTR_DCA_MEM_DETACH_HANDLE, handle);
	fill_attr_in_uint32(cmd, HNS_IB_ATTR_DCA_MEM_DETACH_SQ_INDEX,
			    attr->sq_index);
	execute_ioctl(&ctx->ibv_ctx.context, cmd);
}

struct hns_dca_mem_attach_resp {
#define HNS_DCA_ATTACH_OUT_FLAGS_NEW_BUFFER BIT(0)
	uint32_t alloc_flags;
	uint32_t alloc_pages;
};

static int attach_dca_mem(struct hns_roce_context *ctx, uint32_t handle,
			  struct hns_roce_dca_attach_attr *attr,
			  struct hns_dca_mem_attach_resp *resp)
{
	DECLARE_COMMAND_BUFFER(cmd, HNS_IB_OBJECT_DCA_MEM,
			       HNS_IB_METHOD_DCA_MEM_ATTACH, 6);
	fill_attr_in_obj(cmd, HNS_IB_ATTR_DCA_MEM_ATTACH_HANDLE, handle);
	fill_attr_in_uint32(cmd, HNS_IB_ATTR_DCA_MEM_ATTACH_SQ_OFFSET,
			    attr->sq_offset);
	fill_attr_in_uint32(cmd, HNS_IB_ATTR_DCA_MEM_ATTACH_SGE_OFFSET,
			    attr->sge_offset);
	fill_attr_in_uint32(cmd, HNS_IB_ATTR_DCA_MEM_ATTACH_RQ_OFFSET,
			    attr->rq_offset);
	fill_attr_out(cmd, HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_FLAGS,
		      &resp->alloc_flags, sizeof(resp->alloc_flags));
	fill_attr_out(cmd, HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_PAGES,
		      &resp->alloc_pages, sizeof(resp->alloc_pages));
	return execute_ioctl(&ctx->ibv_ctx.context, cmd);
}

static bool add_dca_mem_enabled(struct hns_roce_dca_ctx *ctx,
				uint32_t alloc_size)
{
	bool enable;

	pthread_spin_lock(&ctx->lock);

	if (ctx->unit_size == 0) /* Pool size can't be increased */
		enable = false;
	else if (ctx->max_size == HNS_DCA_MAX_MEM_SIZE) /* Pool size no limit */
		enable = true;
	else /* Pool size doesn't exceed max size */
		enable = (ctx->curr_size + alloc_size) < ctx->max_size;

	pthread_spin_unlock(&ctx->lock);

	return enable;
}

static bool shrink_dca_mem_enabled(struct hns_roce_dca_ctx *ctx)
{
	bool enable;

	pthread_spin_lock(&ctx->lock);
	enable = ctx->mem_cnt > 0 && ctx->min_size < ctx->max_size;
	pthread_spin_unlock(&ctx->lock);

	return enable;
}

static int add_dca_mem(struct hns_roce_context *ctx, uint32_t size)
{
	struct hns_roce_dca_ctx *dca_ctx = &ctx->dca_ctx;
	struct hns_roce_dca_mem *mem;
	int ret;

	if (!add_dca_mem_enabled(&ctx->dca_ctx, size))
		return -ENOMEM;

	/* Step 1: Alloc DCA mem address */
	mem = alloc_dca_mem(
		DIV_ROUND_UP(size, dca_ctx->unit_size) * dca_ctx->unit_size);
	if (!mem)
		return -ENOMEM;

	/* Step 2: Register DCA mem uobject to pin user address */
	ret = register_dca_mem(ctx, dca_mem_to_key(mem), dca_mem_addr(mem, 0),
			       mem->buf.length, &mem->handle);
	if (ret) {
		free_dca_mem(ctx, mem);
		return ret;
	}

	/* Step 3: Add DCA mem node to pool */
	pthread_spin_lock(&dca_ctx->lock);
	list_add_tail(&dca_ctx->mem_list, &mem->entry);
	dca_ctx->mem_cnt++;
	dca_ctx->curr_size += mem->buf.length;
	pthread_spin_unlock(&dca_ctx->lock);

	return 0;
}

void hns_roce_shrink_dca_mem(struct hns_roce_context *ctx)
{
	struct hns_roce_dca_ctx *dca_ctx = &ctx->dca_ctx;
	struct hns_dca_mem_shrink_resp resp = {};
	struct hns_roce_dca_mem *mem;
	int dca_mem_cnt;
	uint32_t handle;
	int ret;

	pthread_spin_lock(&dca_ctx->lock);
	dca_mem_cnt = ctx->dca_ctx.mem_cnt;
	pthread_spin_unlock(&dca_ctx->lock);
	while (dca_mem_cnt > 0 && shrink_dca_mem_enabled(dca_ctx)) {
		resp.free_mems = 0;
		/* Step 1: Use any DCA mem uobject to shrink pool */
		pthread_spin_lock(&dca_ctx->lock);
		mem = list_tail(&dca_ctx->mem_list,
				struct hns_roce_dca_mem, entry);
		handle = mem ? mem->handle : 0;
		pthread_spin_unlock(&dca_ctx->lock);
		if (!mem)
			break;

		ret = shrink_dca_mem(ctx, handle, dca_ctx->min_size, &resp);
		if (ret || likely(resp.free_mems < 1))
			break;

		/* Step 2: Remove shrunk DCA mem node from pool */
		pthread_spin_lock(&dca_ctx->lock);
		mem = key_to_dca_mem(dca_ctx, resp.free_key);
		if (mem) {
			list_del(&mem->entry);
			dca_ctx->mem_cnt--;
			dca_ctx->curr_size -= mem->buf.length;
		}

		handle = mem ? mem->handle : 0;
		pthread_spin_unlock(&dca_ctx->lock);
		if (!mem)
			break;

		/* Step 3: Destroy DCA mem uobject */
		deregister_dca_mem(ctx, handle);
		free_dca_mem(ctx, mem);
		/* No any free memory after deregister 1 DCA mem */
		if (resp.free_mems <= 1)
			break;

		dca_mem_cnt--;
	}
}

static void config_dca_pages(void *addr, struct hns_roce_dca_buf *buf,
			     uint32_t page_index, int page_count)
{
	void **pages = &buf->bufs[page_index];
	int page_size = 1 << buf->shift;
	int i;

	for (i = 0; i < page_count; i++) {
		pages[i] = addr;
		addr += page_size;
	}
}

static int setup_dca_buf(struct hns_roce_context *ctx, uint32_t handle,
			 struct hns_roce_dca_buf *buf, uint32_t page_count)
{
	struct hns_roce_dca_ctx *dca_ctx = &ctx->dca_ctx;
	struct hns_dca_mem_query_resp resp = {};
	struct hns_roce_dca_mem *mem;
	uint32_t idx = 0;
	int ret;

	while (idx < page_count && idx < buf->max_cnt) {
		resp.page_count = 0;
		ret = query_dca_mem(ctx, handle, idx, &resp);
		if (ret)
			return -ENOMEM;
		if (resp.page_count < 1)
			break;

		pthread_spin_lock(&dca_ctx->lock);
		mem = key_to_dca_mem(dca_ctx, resp.key);
		if (mem && resp.offset < mem->buf.length) {
			config_dca_pages(dca_mem_addr(mem, resp.offset),
					 buf, idx, resp.page_count);
		} else {
			pthread_spin_unlock(&dca_ctx->lock);
			break;
		}
		pthread_spin_unlock(&dca_ctx->lock);

		idx += resp.page_count;
	}

	return (idx >= page_count) ? 0 : -ENOMEM;
}

#define DCAN_TO_SYNC_BIT(n) ((n) * HNS_DCA_BITS_PER_STATUS)
#define DCAN_TO_STAT_BIT(n) DCAN_TO_SYNC_BIT(n)

#define MAX_DCA_TRY_LOCK_TIMES 10
bool hns_roce_dca_start_post(struct hns_roce_dca_ctx *ctx, uint32_t dcan)
{
	atomic_bitmap_t *st = ctx->sync_status;
	int try_times = 0;

	if (!st || dcan >= ctx->max_qps)
		return true;

	while (test_and_set_bit_lock(st, DCAN_TO_SYNC_BIT(dcan)))
		if (try_times++ > MAX_DCA_TRY_LOCK_TIMES)
			return false;

	return true;
}

void hns_roce_dca_stop_post(struct hns_roce_dca_ctx *ctx, uint32_t dcan)
{
	atomic_bitmap_t *st = ctx->sync_status;

	if (!st || dcan >= ctx->max_qps)
		return;

	clear_bit_unlock(st, DCAN_TO_SYNC_BIT(dcan));
}

static bool check_dca_is_attached(struct hns_roce_dca_ctx *ctx, uint32_t dcan)
{
	atomic_bitmap_t *st = ctx->buf_status;

	if (!st || dcan >= ctx->max_qps)
		return false;

	return atomic_test_bit(st, DCAN_TO_STAT_BIT(dcan));
}

#define DCA_EXPAND_MEM_TRY_TIMES	3
int hns_roce_attach_dca_mem(struct hns_roce_context *ctx, uint32_t handle,
			    struct hns_roce_dca_attach_attr *attr,
			    uint32_t size, struct hns_roce_dca_buf *buf)
{
	uint32_t buf_pages = size >> buf->shift;
	struct hns_dca_mem_attach_resp resp = {};
	bool is_new_buf = true;
	int try_times = 0;
	int ret = 0;

	if (!attr->force && check_dca_is_attached(&ctx->dca_ctx, buf->dcan))
		return 0;

	do {
		resp.alloc_pages = 0;
		ret = attach_dca_mem(ctx, handle, attr, &resp);
		if (ret)
			break;

		if (resp.alloc_pages >= buf_pages) {
			is_new_buf = !!(resp.alloc_flags &
				     HNS_DCA_ATTACH_OUT_FLAGS_NEW_BUFFER);
			break;
		}

		ret = add_dca_mem(ctx, size);
		if (ret)
			break;
	} while (try_times++ < DCA_EXPAND_MEM_TRY_TIMES);

	if (ret || resp.alloc_pages < buf_pages)
		return -ENOMEM;


	/* No need config user address if DCA config not changed */
	if (!is_new_buf && buf->bufs[0])
		return 0;

	return setup_dca_buf(ctx, handle, buf, buf_pages);
}
