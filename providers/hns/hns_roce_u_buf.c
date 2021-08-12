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

int hns_roce_add_dca_mem(struct hns_roce_context *ctx, uint32_t size)
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
