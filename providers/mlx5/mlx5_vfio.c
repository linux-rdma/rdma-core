// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#define _GNU_SOURCE
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/param.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <util/mmio.h>

#include <ccan/array_size.h>

#include "mlx5dv.h"
#include "mlx5_vfio.h"
#include "mlx5.h"
#include "mlx5_ifc.h"

enum {
	MLX5_VFIO_CMD_VEC_IDX,
};

enum {
	MLX5_VFIO_SUPP_MR_ACCESS_FLAGS = IBV_ACCESS_LOCAL_WRITE |
		IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ |
		IBV_ACCESS_REMOTE_ATOMIC | IBV_ACCESS_RELAXED_ORDERING,
	MLX5_VFIO_SUPP_UMEM_ACCESS_FLAGS = IBV_ACCESS_LOCAL_WRITE |
		IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ,
};

static int mlx5_vfio_give_pages(struct mlx5_vfio_context *ctx, uint16_t func_id,
				int32_t npages, bool is_event);
static int mlx5_vfio_reclaim_pages(struct mlx5_vfio_context *ctx, uint32_t func_id,
				   int npages);

static void mlx5_vfio_free_cmd_msg(struct mlx5_vfio_context *ctx,
				   struct mlx5_cmd_msg *msg);

static int mlx5_vfio_alloc_cmd_msg(struct mlx5_vfio_context *ctx,
				   uint32_t size, struct mlx5_cmd_msg *msg);

static int mlx5_vfio_post_cmd(struct mlx5_vfio_context *ctx, void *in,
			      int ilen, void *out, int olen,
			      unsigned int slot, bool async);

static int mlx5_vfio_register_mem(struct mlx5_vfio_context *ctx,
				  void *vaddr, uint64_t iova, uint64_t size)
{
	struct vfio_iommu_type1_dma_map dma_map = { .argsz = sizeof(dma_map) };

	dma_map.vaddr = (uintptr_t)vaddr;
	dma_map.size = size;
	dma_map.iova = iova;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	return ioctl(ctx->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
}

static void mlx5_vfio_unregister_mem(struct mlx5_vfio_context *ctx,
				     uint64_t iova, uint64_t size)
{
	struct vfio_iommu_type1_dma_unmap dma_unmap = {};

	dma_unmap.argsz = sizeof(struct vfio_iommu_type1_dma_unmap);
	dma_unmap.size = size;
	dma_unmap.iova = iova;

	if (ioctl(ctx->container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap))
		assert(false);
}

static struct page_block *mlx5_vfio_new_block(struct mlx5_vfio_context *ctx)
{
	struct page_block *page_block;
	int err;

	page_block = calloc(1, sizeof(*page_block));
	if (!page_block) {
		errno = ENOMEM;
		return NULL;
	}

	err = posix_memalign(&page_block->page_ptr, MLX5_VFIO_BLOCK_SIZE,
			     MLX5_VFIO_BLOCK_SIZE);
	if (err) {
		errno = err;
		goto err;
	}

	err = iset_alloc_range(ctx->iova_alloc, MLX5_VFIO_BLOCK_SIZE, &page_block->iova);
	if (err)
		goto err_range;

	bitmap_fill(page_block->free_pages, MLX5_VFIO_BLOCK_NUM_PAGES);
	err = mlx5_vfio_register_mem(ctx, page_block->page_ptr, page_block->iova,
				     MLX5_VFIO_BLOCK_SIZE);
	if (err)
		goto err_reg;

	list_add(&ctx->mem_alloc.block_list, &page_block->next_block);
	return page_block;

err_reg:
	iset_insert_range(ctx->iova_alloc, page_block->iova,
			  MLX5_VFIO_BLOCK_SIZE);
err_range:
	free(page_block->page_ptr);
err:
	free(page_block);
	return NULL;
}

static void mlx5_vfio_free_block(struct mlx5_vfio_context *ctx,
				 struct page_block *page_block)
{
	mlx5_vfio_unregister_mem(ctx, page_block->iova, MLX5_VFIO_BLOCK_SIZE);
	iset_insert_range(ctx->iova_alloc, page_block->iova, MLX5_VFIO_BLOCK_SIZE);
	list_del(&page_block->next_block);
	free(page_block->page_ptr);
	free(page_block);
}

static int mlx5_vfio_alloc_page(struct mlx5_vfio_context *ctx, uint64_t *iova)
{
	struct page_block *page_block;
	unsigned long pg;
	int ret = 0;

	pthread_mutex_lock(&ctx->mem_alloc.block_list_mutex);
	while (true) {
		list_for_each(&ctx->mem_alloc.block_list, page_block, next_block) {
			pg = bitmap_ffs(page_block->free_pages, 0, MLX5_VFIO_BLOCK_NUM_PAGES);
			if (pg != MLX5_VFIO_BLOCK_NUM_PAGES) {
				bitmap_clear_bit(page_block->free_pages, pg);
				*iova = page_block->iova + pg * MLX5_ADAPTER_PAGE_SIZE;
				goto end;
			}
		}
		if (!mlx5_vfio_new_block(ctx)) {
			ret = -1;
			goto end;
		}
	}
end:
	pthread_mutex_unlock(&ctx->mem_alloc.block_list_mutex);
	return ret;
}

static void mlx5_vfio_free_page(struct mlx5_vfio_context *ctx, uint64_t iova)
{
	struct page_block *page_block;
	unsigned long pg;

	pthread_mutex_lock(&ctx->mem_alloc.block_list_mutex);
	list_for_each(&ctx->mem_alloc.block_list, page_block, next_block) {
		if (page_block->iova > iova ||
		    (page_block->iova + MLX5_VFIO_BLOCK_SIZE <= iova))
			continue;

		pg = (iova - page_block->iova) / MLX5_ADAPTER_PAGE_SIZE;
		assert(!bitmap_test_bit(page_block->free_pages, pg));
		bitmap_set_bit(page_block->free_pages, pg);
		if (bitmap_full(page_block->free_pages, MLX5_VFIO_BLOCK_NUM_PAGES))
			mlx5_vfio_free_block(ctx, page_block);
		goto end;
	}

	assert(false);
end:
	pthread_mutex_unlock(&ctx->mem_alloc.block_list_mutex);
}

static int cmd_status_to_err(uint8_t status)
{
	switch (status) {
	case MLX5_CMD_STAT_OK:				return 0;
	case MLX5_CMD_STAT_INT_ERR:			return EIO;
	case MLX5_CMD_STAT_BAD_OP_ERR:			return EINVAL;
	case MLX5_CMD_STAT_BAD_PARAM_ERR:		return EINVAL;
	case MLX5_CMD_STAT_BAD_SYS_STATE_ERR:		return EIO;
	case MLX5_CMD_STAT_BAD_RES_ERR:			return EINVAL;
	case MLX5_CMD_STAT_RES_BUSY:			return EBUSY;
	case MLX5_CMD_STAT_LIM_ERR:			return ENOMEM;
	case MLX5_CMD_STAT_BAD_RES_STATE_ERR:		return EINVAL;
	case MLX5_CMD_STAT_IX_ERR:			return EINVAL;
	case MLX5_CMD_STAT_NO_RES_ERR:			return EAGAIN;
	case MLX5_CMD_STAT_BAD_INP_LEN_ERR:		return EIO;
	case MLX5_CMD_STAT_BAD_OUTP_LEN_ERR:		return EIO;
	case MLX5_CMD_STAT_BAD_QP_STATE_ERR:		return EINVAL;
	case MLX5_CMD_STAT_BAD_PKT_ERR:			return EINVAL;
	case MLX5_CMD_STAT_BAD_SIZE_OUTS_CQES_ERR:	return EINVAL;
	default:					return EIO;
	}
}

static const char *cmd_status_str(uint8_t status)
{
	switch (status) {
	case MLX5_CMD_STAT_OK:
		return "OK";
	case MLX5_CMD_STAT_INT_ERR:
		return "internal error";
	case MLX5_CMD_STAT_BAD_OP_ERR:
		return "bad operation";
	case MLX5_CMD_STAT_BAD_PARAM_ERR:
		return "bad parameter";
	case MLX5_CMD_STAT_BAD_SYS_STATE_ERR:
		return "bad system state";
	case MLX5_CMD_STAT_BAD_RES_ERR:
		return "bad resource";
	case MLX5_CMD_STAT_RES_BUSY:
		return "resource busy";
	case MLX5_CMD_STAT_LIM_ERR:
		return "limits exceeded";
	case MLX5_CMD_STAT_BAD_RES_STATE_ERR:
		return "bad resource state";
	case MLX5_CMD_STAT_IX_ERR:
		return "bad index";
	case MLX5_CMD_STAT_NO_RES_ERR:
		return "no resources";
	case MLX5_CMD_STAT_BAD_INP_LEN_ERR:
		return "bad input length";
	case MLX5_CMD_STAT_BAD_OUTP_LEN_ERR:
		return "bad output length";
	case MLX5_CMD_STAT_BAD_QP_STATE_ERR:
		return "bad QP state";
	case MLX5_CMD_STAT_BAD_PKT_ERR:
		return "bad packet (discarded)";
	case MLX5_CMD_STAT_BAD_SIZE_OUTS_CQES_ERR:
		return "bad size too many outstanding CQEs";
	default:
		return "unknown status";
	}
}

static struct mlx5_eqe *get_eqe(struct mlx5_eq *eq, uint32_t entry)
{
	return eq->vaddr + entry * MLX5_EQE_SIZE;
}

static struct mlx5_eqe *mlx5_eq_get_eqe(struct mlx5_eq *eq, uint32_t cc)
{
	uint32_t ci = eq->cons_index + cc;
	struct mlx5_eqe *eqe;

	eqe = get_eqe(eq, ci & (eq->nent - 1));
	eqe = ((eqe->owner & 1) ^ !!(ci & eq->nent)) ? NULL : eqe;

	if (eqe)
		udma_from_device_barrier();

	return eqe;
}

static void eq_update_ci(struct mlx5_eq *eq, uint32_t cc, int arm)
{
	__be32 *addr = eq->doorbell + (arm ? 0 : 2);
	uint32_t val;

	eq->cons_index += cc;
	val = (eq->cons_index & 0xffffff) | (eq->eqn << 24);

	mmio_write32_be(addr, htobe32(val));
	udma_to_device_barrier();
}

static int mlx5_vfio_handle_page_req_event(struct mlx5_vfio_context *ctx,
					   struct mlx5_eqe *eqe)
{
	struct mlx5_eqe_page_req *req = &eqe->data.req_pages;
	int32_t num_pages;
	int16_t func_id;

	func_id = be16toh(req->func_id);
	num_pages = be32toh(req->num_pages);

	if (num_pages > 0)
		return mlx5_vfio_give_pages(ctx, func_id, num_pages, true);

	return mlx5_vfio_reclaim_pages(ctx, func_id, -1 * num_pages);
}

static void mlx5_cmd_mbox_status(void *out, uint8_t *status, uint32_t *syndrome)
{
	*status = DEVX_GET(mbox_out, out, status);
	*syndrome = DEVX_GET(mbox_out, out, syndrome);
}

static int mlx5_vfio_cmd_check(struct mlx5_vfio_context *ctx, void *in, void *out)
{
	uint32_t syndrome;
	uint8_t  status;
	uint16_t opcode;
	uint16_t op_mod;

	mlx5_cmd_mbox_status(out, &status, &syndrome);
	if (!status)
		return 0;

	opcode = DEVX_GET(mbox_in, in, opcode);
	op_mod = DEVX_GET(mbox_in, in, op_mod);

	mlx5_err(ctx->dbg_fp,
		 "mlx5_vfio_op_code(0x%x), op_mod(0x%x) failed, status %s(0x%x), syndrome (0x%x)\n",
		 opcode, op_mod,
		 cmd_status_str(status), status, syndrome);

	errno = cmd_status_to_err(status);
	return errno;
}

static int mlx5_copy_from_msg(void *to, struct mlx5_cmd_msg *from, int size,
			      struct mlx5_cmd_layout *cmd_lay)
{
	struct mlx5_cmd_block *block;
	struct mlx5_cmd_mailbox *next;
	int copy;

	copy = min_t(int, size, sizeof(cmd_lay->out));
	memcpy(to, cmd_lay->out, copy);
	size -= copy;
	to += copy;

	next = from->next;
	while (size) {
		if (!next) {
			assert(false);
			errno = ENOMEM;
			return errno;
		}

		copy = min_t(int, size, MLX5_CMD_DATA_BLOCK_SIZE);
		block = next->buf;

		memcpy(to, block->data, copy);
		to += copy;
		size -= copy;
		next = next->next;
	}

	return 0;
}

static int mlx5_copy_to_msg(struct mlx5_cmd_msg *to, void *from, int size,
			    struct mlx5_cmd_layout *cmd_lay)
{
	struct mlx5_cmd_block *block;
	struct mlx5_cmd_mailbox *next;
	int copy;

	copy = min_t(int, size, sizeof(cmd_lay->in));
	memcpy(cmd_lay->in, from, copy);
	size -= copy;
	from += copy;

	next = to->next;
	while (size) {
		if (!next) {
			assert(false);
			errno = ENOMEM;
			return errno;
		}

		copy = min_t(int, size, MLX5_CMD_DATA_BLOCK_SIZE);
		block = next->buf;
		memcpy(block->data, from, copy);
		from += copy;
		size -= copy;
		next = next->next;
	}

	return 0;
}

/* The HCA will think the queue has overflowed if we don't tell it we've been
 * processing events.
 * We create EQs with MLX5_NUM_SPARE_EQE extra entries,
 * so we must update our consumer index at least that often.
 */
static inline uint32_t mlx5_eq_update_cc(struct mlx5_eq *eq, uint32_t cc)
{
	if (unlikely(cc >= MLX5_NUM_SPARE_EQE)) {
		eq_update_ci(eq, cc, 0);
		cc = 0;
	}
	return cc;
}

static int mlx5_vfio_process_page_request_comp(struct mlx5_vfio_context *ctx,
					       unsigned long slot)
{
	struct mlx5_vfio_cmd_slot *cmd_slot = &ctx->cmd.cmds[slot];
	struct cmd_async_data *cmd_data = &cmd_slot->curr;
	int num_claimed;
	int ret, i;

	ret = mlx5_copy_from_msg(cmd_data->buff_out, &cmd_slot->out,
				 cmd_data->olen, cmd_slot->lay);
	if (ret)
		goto end;

	ret = mlx5_vfio_cmd_check(ctx, cmd_data->buff_in, cmd_data->buff_out);
	if (ret)
		goto end;

	if (DEVX_GET(manage_pages_in, cmd_data->buff_in, op_mod) == MLX5_PAGES_GIVE)
		goto end;

	num_claimed = DEVX_GET(manage_pages_out, cmd_data->buff_out, output_num_entries);
	if (num_claimed > DEVX_GET(manage_pages_in, cmd_data->buff_in, input_num_entries)) {
		ret = EINVAL;
		errno = ret;
		goto end;
	}

	for (i = 0; i < num_claimed; i++)
		mlx5_vfio_free_page(ctx, DEVX_GET64(manage_pages_out, cmd_data->buff_out, pas[i]));

end:
	free(cmd_data->buff_in);
	free(cmd_data->buff_out);
	cmd_slot->in_use = false;
	if (!ret && cmd_slot->is_pending) {
		cmd_data = &cmd_slot->pending;

		pthread_mutex_lock(&cmd_slot->lock);
		cmd_slot->is_pending = false;
		ret = mlx5_vfio_post_cmd(ctx, cmd_data->buff_in, cmd_data->ilen,
					 cmd_data->buff_out, cmd_data->olen, slot, true);
		pthread_mutex_unlock(&cmd_slot->lock);
	}
	return ret;
}

static int mlx5_vfio_cmd_comp(struct mlx5_vfio_context *ctx, unsigned long slot)
{
	uint64_t u = 1;
	ssize_t s;

	s = write(ctx->cmd.cmds[slot].completion_event_fd, &u,
		  sizeof(uint64_t));
	if (s != sizeof(uint64_t))
		return -1;

	return 0;
}

static int mlx5_vfio_process_cmd_eqe(struct mlx5_vfio_context *ctx,
				     struct mlx5_eqe *eqe)
{
	struct mlx5_eqe_cmd *cmd_eqe = &eqe->data.cmd;
	unsigned long vector = be32toh(cmd_eqe->vector);
	unsigned long slot;
	int count = 0;
	int ret;

	for (slot = 0; slot < MLX5_MAX_COMMANDS; slot++) {
		if (vector & (1 << slot)) {
			assert(ctx->cmd.cmds[slot].comp_func);
			ret = ctx->cmd.cmds[slot].comp_func(ctx, slot);
			if (ret)
				return ret;

			vector &= ~(1 << slot);
			count++;
		}
	}

	assert(!vector && count);
	return 0;
}

static int mlx5_vfio_process_async_events(struct mlx5_vfio_context *ctx)
{
	struct mlx5_eqe *eqe;
	int ret = 0;
	int cc = 0;

	pthread_mutex_lock(&ctx->eq_lock);
	while ((eqe = mlx5_eq_get_eqe(&ctx->async_eq, cc))) {
		switch (eqe->type) {
		case MLX5_EVENT_TYPE_CMD:
			ret = mlx5_vfio_process_cmd_eqe(ctx, eqe);
			break;
		case MLX5_EVENT_TYPE_PAGE_REQUEST:
			ret = mlx5_vfio_handle_page_req_event(ctx, eqe);
			break;
		default:
			break;
		}

		cc = mlx5_eq_update_cc(&ctx->async_eq, ++cc);
		if (ret)
			goto out;
	}

out:
	eq_update_ci(&ctx->async_eq, cc, 1);
	pthread_mutex_unlock(&ctx->eq_lock);
	return ret;
}

static int mlx5_vfio_enlarge_cmd_msg(struct mlx5_vfio_context *ctx, struct mlx5_cmd_msg *cmd_msg,
				     struct mlx5_cmd_layout *cmd_lay, uint32_t len, bool is_in)
{
	int err;

	mlx5_vfio_free_cmd_msg(ctx, cmd_msg);
	err = mlx5_vfio_alloc_cmd_msg(ctx, len, cmd_msg);
	if (err)
		return err;

	if (is_in)
		cmd_lay->iptr = htobe64(cmd_msg->next->iova);
	else
		cmd_lay->optr = htobe64(cmd_msg->next->iova);

	return 0;
}

static int mlx5_vfio_wait_event(struct mlx5_vfio_context *ctx,
				unsigned int slot)
{
	struct mlx5_cmd_layout *cmd_lay = ctx->cmd.cmds[slot].lay;
	uint64_t u;
	ssize_t s;
	int err;

	struct pollfd fds[2] = {
		{ .fd = ctx->cmd_comp_fd, .events = POLLIN },
		{ .fd = ctx->cmd.cmds[slot].completion_event_fd, .events = POLLIN }
		};

	while (true) {
		err = poll(fds, 2, -1);
		if (err < 0 && errno != EAGAIN) {
			mlx5_err(ctx->dbg_fp, "mlx5_vfio_wait_event, poll failed, errno=%d\n", errno);
			return errno;
		}
		if (fds[0].revents & POLLIN) {
			s = read(fds[0].fd, &u, sizeof(uint64_t));
			if (s < 0 && errno != EAGAIN) {
				mlx5_err(ctx->dbg_fp, "mlx5_vfio_wait_event, read failed, errno=%d\n", errno);
				return errno;
			}

			err = mlx5_vfio_process_async_events(ctx);
			if (err)
				return err;
		}
		if (fds[1].revents & POLLIN) {
			s = read(fds[1].fd, &u, sizeof(uint64_t));
			if (s < 0 && errno != EAGAIN) {
				mlx5_err(ctx->dbg_fp, "mlx5_vfio_wait_event, read failed, slot=%d, errno=%d\n",
					 slot, errno);
				return errno;
			}
			if (!(mmio_read8(&cmd_lay->status_own) & 0x1))
				return 0;
		}
	}
}

/* One minute for the sake of bringup */
#define MLX5_CMD_TIMEOUT_MSEC (60 * 1000)

static int mlx5_vfio_poll_timeout(struct mlx5_cmd_layout *cmd_lay)
{
	static struct timeval start, curr;
	uint64_t ms_start, ms_curr;

	gettimeofday(&start, NULL);
	ms_start = (uint64_t)start.tv_sec * 1000 + start.tv_usec / 1000;
	do {
		if (!(mmio_read8(&cmd_lay->status_own) & 0x1))
			return 0;
		sched_yield();
		gettimeofday(&curr, NULL);
		ms_curr = (uint64_t)curr.tv_sec * 1000 + curr.tv_usec / 1000;
	} while (ms_curr - ms_start < MLX5_CMD_TIMEOUT_MSEC);

	errno = ETIMEDOUT;
	return errno;
}

static int mlx5_vfio_cmd_prep_in(struct mlx5_vfio_context *ctx,
				 struct mlx5_cmd_msg *cmd_in,
				 struct mlx5_cmd_layout *cmd_lay,
				 void *in, int ilen)
{
	int err;

	if (ilen > cmd_in->len) {
		err = mlx5_vfio_enlarge_cmd_msg(ctx, cmd_in, cmd_lay, ilen, true);
		if (err)
			return err;
	}

	err = mlx5_copy_to_msg(cmd_in, in, ilen, cmd_lay);
	if (err)
		return err;

	cmd_lay->ilen = htobe32(ilen);
	return 0;
}

static int mlx5_vfio_cmd_prep_out(struct mlx5_vfio_context *ctx,
				  struct mlx5_cmd_msg *cmd_out,
				  struct mlx5_cmd_layout *cmd_lay, int olen)
{
	struct mlx5_cmd_mailbox *tmp;
	struct mlx5_cmd_block *block;

	cmd_lay->olen = htobe32(olen);

	/* zeroing output header */
	memset(cmd_lay->out, 0, sizeof(cmd_lay->out));

	if (olen > cmd_out->len)
		/* Upon enlarge output message is zeroed */
		return mlx5_vfio_enlarge_cmd_msg(ctx, cmd_out, cmd_lay, olen, false);

	/* zeroing output message */
	tmp = cmd_out->next;
	olen -= min_t(int, olen, sizeof(cmd_lay->out));
	while (olen > 0) {
		block = tmp->buf;
		memset(block->data, 0, MLX5_CMD_DATA_BLOCK_SIZE);
		olen -= MLX5_CMD_DATA_BLOCK_SIZE;
		tmp = tmp->next;
		assert(tmp || olen <= 0);
	}
	return 0;
}

static int mlx5_vfio_post_cmd(struct mlx5_vfio_context *ctx, void *in,
			      int ilen, void *out, int olen,
			      unsigned int slot, bool async)
{
	struct mlx5_init_seg *init_seg = ctx->bar_map;
	struct mlx5_cmd_layout *cmd_lay = ctx->cmd.cmds[slot].lay;
	struct mlx5_cmd_msg *cmd_in = &ctx->cmd.cmds[slot].in;
	struct mlx5_cmd_msg *cmd_out = &ctx->cmd.cmds[slot].out;
	int err;

	/* Lock was taken by caller */
	if (async && ctx->cmd.cmds[slot].in_use) {
		struct cmd_async_data *pending = &ctx->cmd.cmds[slot].pending;

		if (ctx->cmd.cmds[slot].is_pending) {
			assert(false);
			return EINVAL;
		}

		/* We might get another PAGE EVENT before previous CMD was completed.
		 * Save the new work and once get the CMD completion go and do the job.
		 */
		pending->buff_in = in;
		pending->buff_out = out;
		pending->ilen = ilen;
		pending->olen = olen;

		ctx->cmd.cmds[slot].is_pending = true;
		return 0;
	}

	err = mlx5_vfio_cmd_prep_in(ctx, cmd_in, cmd_lay, in, ilen);
	if (err)
		return err;

	err = mlx5_vfio_cmd_prep_out(ctx, cmd_out, cmd_lay, olen);
	if (err)
		return err;

	if (async) {
		ctx->cmd.cmds[slot].in_use = true;
		ctx->cmd.cmds[slot].curr.ilen = ilen;
		ctx->cmd.cmds[slot].curr.olen = olen;
		ctx->cmd.cmds[slot].curr.buff_in = in;
		ctx->cmd.cmds[slot].curr.buff_out = out;
	}

	cmd_lay->status_own = 0x1;

	udma_to_device_barrier();
	mmio_write32_be(&init_seg->cmd_dbell, htobe32(0x1 << slot));
	return 0;
}

static int mlx5_vfio_cmd_exec(struct mlx5_vfio_context *ctx, void *in,
			       int ilen, void *out, int olen,
			       unsigned int slot)
{
	struct mlx5_cmd_layout *cmd_lay = ctx->cmd.cmds[slot].lay;
	struct mlx5_cmd_msg *cmd_out = &ctx->cmd.cmds[slot].out;
	int err;

	pthread_mutex_lock(&ctx->cmd.cmds[slot].lock);
	err = mlx5_vfio_post_cmd(ctx, in, ilen, out, olen, slot, false);
	if (err)
		goto end;

	if (ctx->have_eq) {
		err = mlx5_vfio_wait_event(ctx, slot);
		if (err)
			goto end;
	} else {
		err = mlx5_vfio_poll_timeout(cmd_lay);
		if (err)
			goto end;
		udma_from_device_barrier();
	}

	err = mlx5_copy_from_msg(out, cmd_out, olen, cmd_lay);
	if (err)
		goto end;

	err = mlx5_vfio_cmd_check(ctx, in, out);
end:
	pthread_mutex_unlock(&ctx->cmd.cmds[slot].lock);
	return err;
}

static int mlx5_vfio_enable_pci_cmd(struct mlx5_vfio_context *ctx)
{
	struct vfio_region_info pci_config_reg = {};
	uint16_t pci_com_buf = 0x6;
	char buffer[4096];

	pci_config_reg.argsz = sizeof(pci_config_reg);
	pci_config_reg.index = VFIO_PCI_CONFIG_REGION_INDEX;

	if (ioctl(ctx->device_fd, VFIO_DEVICE_GET_REGION_INFO, &pci_config_reg))
		return -1;

	if (pwrite(ctx->device_fd, &pci_com_buf, 2, pci_config_reg.offset + 0x4) != 2)
		return -1;

	if (pread(ctx->device_fd, buffer, pci_config_reg.size, pci_config_reg.offset)
			!= pci_config_reg.size)
		return -1;

	return 0;
}

static void free_cmd_box(struct mlx5_vfio_context *ctx,
			 struct mlx5_cmd_mailbox *mailbox)
{
	mlx5_vfio_unregister_mem(ctx, mailbox->iova, MLX5_ADAPTER_PAGE_SIZE);
	iset_insert_range(ctx->iova_alloc, mailbox->iova, MLX5_ADAPTER_PAGE_SIZE);
	free(mailbox->buf);
	free(mailbox);
}

static struct mlx5_cmd_mailbox *alloc_cmd_box(struct mlx5_vfio_context *ctx)
{
	struct mlx5_cmd_mailbox *mailbox;
	int ret;

	mailbox = calloc(1, sizeof(*mailbox));
	if (!mailbox) {
		errno = ENOMEM;
		return NULL;
	}

	ret = posix_memalign(&mailbox->buf, MLX5_ADAPTER_PAGE_SIZE,
			     MLX5_ADAPTER_PAGE_SIZE);
	if (ret) {
		errno = ret;
		goto err_free;
	}

	memset(mailbox->buf, 0, MLX5_ADAPTER_PAGE_SIZE);

	ret = iset_alloc_range(ctx->iova_alloc, MLX5_ADAPTER_PAGE_SIZE, &mailbox->iova);
	if (ret)
		goto err_tree;

	ret = mlx5_vfio_register_mem(ctx, mailbox->buf, mailbox->iova,
				     MLX5_ADAPTER_PAGE_SIZE);
	if (ret)
		goto err_reg;

	return mailbox;

err_reg:
	iset_insert_range(ctx->iova_alloc, mailbox->iova,
			  MLX5_ADAPTER_PAGE_SIZE);
err_tree:
	free(mailbox->buf);
err_free:
	free(mailbox);
	return NULL;
}

static int mlx5_calc_cmd_blocks(uint32_t msg_len)
{
	int size = msg_len;
	int blen = size - min_t(int, 16, size);

	return DIV_ROUND_UP(blen, MLX5_CMD_DATA_BLOCK_SIZE);
}

static void mlx5_vfio_free_cmd_msg(struct mlx5_vfio_context *ctx,
				   struct mlx5_cmd_msg *msg)
{
	struct mlx5_cmd_mailbox *head = msg->next;
	struct mlx5_cmd_mailbox *next;

	while (head) {
		next = head->next;
		free_cmd_box(ctx, head);
		head = next;
	}
	msg->len = 0;
}

static int mlx5_vfio_alloc_cmd_msg(struct mlx5_vfio_context *ctx,
				   uint32_t size, struct mlx5_cmd_msg *msg)
{
	struct mlx5_cmd_mailbox *tmp, *head = NULL;
	struct mlx5_cmd_block *block;
	int i, num_blocks;

	msg->len = size;
	num_blocks = mlx5_calc_cmd_blocks(size);

	for (i = 0; i < num_blocks; i++) {
		tmp = alloc_cmd_box(ctx);
		if (!tmp)
			goto err_alloc;

		block = tmp->buf;
		tmp->next = head;
		block->next = htobe64(tmp->next ? tmp->next->iova : 0);
		block->block_num = htobe32(num_blocks - i - 1);
		head = tmp;
	}
	msg->next = head;
	return 0;

err_alloc:
	while (head) {
		tmp = head->next;
		free_cmd_box(ctx, head);
		head = tmp;
	}
	msg->len = 0;
	return -1;
}

static void mlx5_vfio_free_cmd_slot(struct mlx5_vfio_context *ctx, int slot)
{
	struct mlx5_vfio_cmd_slot *cmd_slot = &ctx->cmd.cmds[slot];

	mlx5_vfio_free_cmd_msg(ctx, &cmd_slot->in);
	mlx5_vfio_free_cmd_msg(ctx, &cmd_slot->out);
	close(cmd_slot->completion_event_fd);
}

static int mlx5_vfio_setup_cmd_slot(struct mlx5_vfio_context *ctx, int slot)
{
	struct mlx5_vfio_cmd *cmd = &ctx->cmd;
	struct mlx5_vfio_cmd_slot *cmd_slot = &cmd->cmds[slot];
	struct mlx5_cmd_layout *cmd_lay;
	int ret;

	ret = mlx5_vfio_alloc_cmd_msg(ctx, 4096, &cmd_slot->in);
	if (ret)
		return ret;

	ret = mlx5_vfio_alloc_cmd_msg(ctx, 4096, &cmd_slot->out);
	if (ret)
		goto err;

	cmd_lay = cmd->vaddr + (slot * (1 << cmd->log_stride));
	cmd_lay->type = MLX5_PCI_CMD_XPORT;
	cmd_lay->iptr = htobe64(cmd_slot->in.next->iova);
	cmd_lay->optr = htobe64(cmd_slot->out.next->iova);

	cmd_slot->lay = cmd_lay;
	cmd_slot->completion_event_fd = eventfd(0, EFD_CLOEXEC);
	if (cmd_slot->completion_event_fd < 0) {
		ret = -1;
		goto err_fd;
	}

	if (slot != MLX5_MAX_COMMANDS - 1)
		cmd_slot->comp_func = mlx5_vfio_cmd_comp;
	else
		cmd_slot->comp_func = mlx5_vfio_process_page_request_comp;

	pthread_mutex_init(&cmd_slot->lock, NULL);

	return 0;

err_fd:
	mlx5_vfio_free_cmd_msg(ctx, &cmd_slot->out);
err:
	mlx5_vfio_free_cmd_msg(ctx, &cmd_slot->in);
	return ret;
}

static int mlx5_vfio_init_cmd_interface(struct mlx5_vfio_context *ctx)
{
	struct mlx5_init_seg *init_seg = ctx->bar_map;
	struct mlx5_vfio_cmd *cmd = &ctx->cmd;
	uint16_t cmdif_rev;
	uint32_t cmd_h, cmd_l;
	int ret;

	cmdif_rev = be32toh(init_seg->cmdif_rev_fw_sub) >> 16;

	if (cmdif_rev != 5) {
		errno = EINVAL;
		return -1;
	}

	cmd_l = be32toh(init_seg->cmdq_addr_l_sz) & 0xff;
	ctx->cmd.log_sz = cmd_l >> 4 & 0xf;
	ctx->cmd.log_stride = cmd_l & 0xf;
	if (1 << ctx->cmd.log_sz > MLX5_MAX_COMMANDS) {
		errno = EINVAL;
		return -1;
	}

	if (ctx->cmd.log_sz + ctx->cmd.log_stride > MLX5_ADAPTER_PAGE_SHIFT) {
		errno = EINVAL;
		return -1;
	}

	/* The initial address must be 4K aligned */
	ret = posix_memalign(&cmd->vaddr, MLX5_ADAPTER_PAGE_SIZE,
			     MLX5_ADAPTER_PAGE_SIZE);
	if (ret) {
		errno = ret;
		return -1;
	}

	memset(cmd->vaddr, 0, MLX5_ADAPTER_PAGE_SIZE);

	ret = iset_alloc_range(ctx->iova_alloc, MLX5_ADAPTER_PAGE_SIZE, &cmd->iova);
	if (ret)
		goto err_free;

	ret = mlx5_vfio_register_mem(ctx, cmd->vaddr, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
	if (ret)
		goto err_reg;

	cmd_h = (uint32_t)((uint64_t)(cmd->iova) >> 32);
	cmd_l = (uint32_t)(uint64_t)(cmd->iova);

	init_seg->cmdq_addr_h = htobe32(cmd_h);
	init_seg->cmdq_addr_l_sz = htobe32(cmd_l);

	/* Make sure firmware sees the complete address before we proceed */
	udma_to_device_barrier();

	ret = mlx5_vfio_setup_cmd_slot(ctx, 0);
	if (ret)
		goto err_slot_0;

	ret = mlx5_vfio_setup_cmd_slot(ctx, MLX5_MAX_COMMANDS - 1);
	if (ret)
		goto err_slot_1;

	ret = mlx5_vfio_enable_pci_cmd(ctx);
	if (!ret)
		return 0;

	mlx5_vfio_free_cmd_slot(ctx, MLX5_MAX_COMMANDS - 1);
err_slot_1:
	mlx5_vfio_free_cmd_slot(ctx, 0);
err_slot_0:
	mlx5_vfio_unregister_mem(ctx, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
err_reg:
	iset_insert_range(ctx->iova_alloc, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
err_free:
	free(cmd->vaddr);
	return ret;
}

static void mlx5_vfio_clean_cmd_interface(struct mlx5_vfio_context *ctx)
{
	struct mlx5_vfio_cmd *cmd = &ctx->cmd;

	mlx5_vfio_free_cmd_slot(ctx, 0);
	mlx5_vfio_free_cmd_slot(ctx, MLX5_MAX_COMMANDS - 1);
	mlx5_vfio_unregister_mem(ctx, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
	iset_insert_range(ctx->iova_alloc, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
	free(cmd->vaddr);
}

static void set_iova_min_page_size(struct mlx5_vfio_context *ctx,
				   uint64_t iova_pgsizes)
{
	int i;

	for (i = MLX5_ADAPTER_PAGE_SHIFT; i < 64; i++) {
		if (iova_pgsizes & (1 << i)) {
			ctx->iova_min_page_size = 1 << i;
			return;
		}
	}

	assert(false);
}

/* if the kernel does not report usable IOVA regions, choose the legacy region */
#define MLX5_VFIO_IOVA_MIN1 0x10000ULL
#define MLX5_VFIO_IOVA_MAX1 0xFEDFFFFFULL
#define MLX5_VFIO_IOVA_MIN2 0xFEF00000ULL
#define MLX5_VFIO_IOVA_MAX2 ((1ULL << 39) - 1)

static int mlx5_vfio_get_iommu_info(struct mlx5_vfio_context *ctx)
{
	struct vfio_iommu_type1_info *info;
	int ret, i;
	void *ptr;
	uint32_t offset;

	info = calloc(1, sizeof(*info));
	if (!info) {
		errno = ENOMEM;
		return -1;
	}

	info->argsz = sizeof(*info);
	ret = ioctl(ctx->container_fd, VFIO_IOMMU_GET_INFO, info);
	if (ret)
		goto end;

	if (info->argsz > sizeof(*info)) {
		info = realloc(info, info->argsz);
		if (!info) {
			errno = ENOMEM;
			ret = -1;
			goto end;
		}

		ret = ioctl(ctx->container_fd, VFIO_IOMMU_GET_INFO, info);
		if (ret)
			goto end;
	}

	set_iova_min_page_size(ctx, (info->flags & VFIO_IOMMU_INFO_PGSIZES) ?
			       info->iova_pgsizes : 4096);

	if (!(info->flags & VFIO_IOMMU_INFO_CAPS))
		goto set_legacy;

	offset = info->cap_offset;
	while (offset) {
		struct vfio_iommu_type1_info_cap_iova_range *iova_range;
		struct vfio_info_cap_header *header;

		ptr = (void *)info + offset;
		header = ptr;

		if (header->id != VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE) {
			offset = header->next;
			continue;
		}

		iova_range = (struct vfio_iommu_type1_info_cap_iova_range *)header;

		for (i = 0; i < iova_range->nr_iovas; i++) {
			ret = iset_insert_range(ctx->iova_alloc, iova_range->iova_ranges[i].start,
						iova_range->iova_ranges[i].end -
						iova_range->iova_ranges[i].start + 1);
			if (ret)
				goto end;
		}

		goto end;
	}

set_legacy:
	ret = iset_insert_range(ctx->iova_alloc, MLX5_VFIO_IOVA_MIN1,
				MLX5_VFIO_IOVA_MAX1 - MLX5_VFIO_IOVA_MIN1 + 1);
	if (!ret)
		ret = iset_insert_range(ctx->iova_alloc, MLX5_VFIO_IOVA_MIN2,
					MLX5_VFIO_IOVA_MAX2 - MLX5_VFIO_IOVA_MIN2 + 1);

end:
	free(info);
	return ret;
}

static void mlx5_vfio_clean_device_dma(struct mlx5_vfio_context *ctx)
{
	struct page_block *page_block, *tmp;

	list_for_each_safe(&ctx->mem_alloc.block_list, page_block,
			   tmp, next_block)
		mlx5_vfio_free_block(ctx, page_block);

	iset_destroy(ctx->iova_alloc);
}

static int mlx5_vfio_init_device_dma(struct mlx5_vfio_context *ctx)
{
	ctx->iova_alloc = iset_create();
	if (!ctx->iova_alloc)
		return -1;

	list_head_init(&ctx->mem_alloc.block_list);
	pthread_mutex_init(&ctx->mem_alloc.block_list_mutex, NULL);

	if (mlx5_vfio_get_iommu_info(ctx))
		goto err;

	/* create an initial block of DMA memory ready to be used */
	if (!mlx5_vfio_new_block(ctx))
		goto err;

	return 0;
err:
	iset_destroy(ctx->iova_alloc);
	return -1;
}

static void mlx5_vfio_uninit_bar0(struct mlx5_vfio_context *ctx)
{
	munmap(ctx->bar_map, ctx->bar_map_size);
}

static int mlx5_vfio_init_bar0(struct mlx5_vfio_context *ctx)
{
	struct vfio_region_info reg = { .argsz = sizeof(reg) };
	void *base;
	int err;

	reg.index = 0;
	err = ioctl(ctx->device_fd, VFIO_DEVICE_GET_REGION_INFO, &reg);
	if (err)
		return err;

	base = mmap(NULL, reg.size, PROT_READ | PROT_WRITE, MAP_SHARED,
		    ctx->device_fd, reg.offset);
	if (base == MAP_FAILED)
		return -1;

	ctx->bar_map = (struct mlx5_init_seg *)base;
	ctx->bar_map_size = reg.size;
	return 0;
}

#define MLX5_VFIO_MAX_INTR_VEC_ID 1
#define MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
			      sizeof(int) * (MLX5_VFIO_MAX_INTR_VEC_ID))

/* enable MSI-X interrupts */
static int
mlx5_vfio_enable_msix(struct mlx5_vfio_context *ctx)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int len;
	int *fd_ptr;

	len = sizeof(irq_set_buf);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	irq_set->start = 0;
	fd_ptr = (int *)&irq_set->data;
	fd_ptr[MLX5_VFIO_CMD_VEC_IDX] = ctx->cmd_comp_fd;

	return ioctl(ctx->device_fd, VFIO_DEVICE_SET_IRQS, irq_set);
}

static int mlx5_vfio_init_async_fd(struct mlx5_vfio_context *ctx)
{
	struct vfio_irq_info irq = { .argsz = sizeof(irq) };

	irq.index = VFIO_PCI_MSIX_IRQ_INDEX;
	if (ioctl(ctx->device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq))
		return -1;

	/* fail if this vector cannot be used with eventfd */
	if ((irq.flags & VFIO_IRQ_INFO_EVENTFD) == 0)
		return -1;

	/* set up an eventfd for command completion interrupts */
	ctx->cmd_comp_fd = eventfd(0, EFD_CLOEXEC | O_NONBLOCK);
	if (ctx->cmd_comp_fd < 0)
		return -1;

	if (mlx5_vfio_enable_msix(ctx))
		goto err_msix;

	return 0;

err_msix:
	close(ctx->cmd_comp_fd);
	return -1;
}

static void mlx5_vfio_close_fds(struct mlx5_vfio_context *ctx)
{
	close(ctx->device_fd);
	close(ctx->container_fd);
	close(ctx->group_fd);
	close(ctx->cmd_comp_fd);
}

static int mlx5_vfio_open_fds(struct mlx5_vfio_context *ctx,
			      struct mlx5_vfio_device *mdev)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };

	/* Create a new container */
	ctx->container_fd = open("/dev/vfio/vfio", O_RDWR);

	if (ctx->container_fd < 0)
		return -1;

	if (ioctl(ctx->container_fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION)
		goto close_cont;

	if (!ioctl(ctx->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU))
		/* Doesn't support the IOMMU driver we want. */
		goto close_cont;

	/* Open the group */
	ctx->group_fd = open(mdev->vfio_path, O_RDWR);
	if (ctx->group_fd < 0)
		goto close_cont;

	/* Test the group is viable and available */
	if (ioctl(ctx->group_fd, VFIO_GROUP_GET_STATUS, &group_status))
		goto close_group;

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		/* Group is not viable (ie, not all devices bound for vfio) */
		errno = EINVAL;
		goto close_group;
	}

	/* Add the group to the container */
	if (ioctl(ctx->group_fd, VFIO_GROUP_SET_CONTAINER, &ctx->container_fd))
		goto close_group;

	/* Enable the IOMMU model we want */
	if (ioctl(ctx->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU))
		goto close_group;

	/* Get a file descriptor for the device */
	ctx->device_fd = ioctl(ctx->group_fd, VFIO_GROUP_GET_DEVICE_FD,
			       mdev->pci_name);
	if (ctx->device_fd < 0)
		goto close_group;

	if (mlx5_vfio_init_async_fd(ctx))
		goto close_group;

	return 0;

close_group:
	close(ctx->group_fd);
close_cont:
	close(ctx->container_fd);
	return -1;
}

enum {
	MLX5_EQE_OWNER_INIT_VAL = 0x1,
};

static void init_eq_buf(struct mlx5_eq *eq)
{
	struct mlx5_eqe *eqe;
	int i;

	for (i = 0; i < eq->nent; i++) {
		eqe = get_eqe(eq, i);
		eqe->owner = MLX5_EQE_OWNER_INIT_VAL;
	}
}

static uint64_t uar2iova(struct mlx5_vfio_context *ctx, uint32_t index)
{
	return (uint64_t)(uintptr_t)((void *)ctx->bar_map + (index * MLX5_ADAPTER_PAGE_SIZE));
}

static int mlx5_vfio_alloc_uar(struct mlx5_vfio_context *ctx, uint32_t *uarn)
{
	uint32_t out[DEVX_ST_SZ_DW(alloc_uar_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(alloc_uar_in)] = {};
	int err;

	DEVX_SET(alloc_uar_in, in, opcode, MLX5_CMD_OP_ALLOC_UAR);
	err = mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
	if (!err)
		*uarn = DEVX_GET(alloc_uar_out, out, uar);

	return err;
}

static void mlx5_vfio_dealloc_uar(struct mlx5_vfio_context *ctx, uint32_t uarn)
{
	uint32_t out[DEVX_ST_SZ_DW(dealloc_uar_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(dealloc_uar_in)] = {};

	DEVX_SET(dealloc_uar_in, in, opcode, MLX5_CMD_OP_DEALLOC_UAR);
	DEVX_SET(dealloc_uar_in, in, uar, uarn);
	mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
}

static void mlx5_vfio_destroy_eq(struct mlx5_vfio_context *ctx, struct mlx5_eq *eq)
{
	uint32_t in[DEVX_ST_SZ_DW(destroy_eq_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(destroy_eq_out)] = {};

	DEVX_SET(destroy_eq_in, in, opcode, MLX5_CMD_OP_DESTROY_EQ);
	DEVX_SET(destroy_eq_in, in, eq_number, eq->eqn);

	mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
	mlx5_vfio_unregister_mem(ctx, eq->iova, eq->iova_size);
	iset_insert_range(ctx->iova_alloc, eq->iova, eq->iova_size);
	free(eq->vaddr);
}

static void destroy_async_eqs(struct mlx5_vfio_context *ctx)
{
	ctx->have_eq = false;
	mlx5_vfio_destroy_eq(ctx, &ctx->async_eq);
	mlx5_vfio_dealloc_uar(ctx, ctx->eqs_uar.uarn);
}

static int
create_map_eq(struct mlx5_vfio_context *ctx, struct mlx5_eq *eq,
	      struct mlx5_eq_param *param)
{
	uint32_t out[DEVX_ST_SZ_DW(create_eq_out)] = {};
	uint8_t vecidx = param->irq_index;
	__be64 *pas;
	void *eqc;
	int inlen;
	uint32_t *in;
	int err;
	int i;
	int alloc_size;

	pthread_mutex_init(&ctx->eq_lock, NULL);
	eq->nent = roundup_pow_of_two(param->nent + MLX5_NUM_SPARE_EQE);
	eq->cons_index = 0;
	alloc_size = eq->nent * MLX5_EQE_SIZE;
	eq->iova_size = max(roundup_pow_of_two(alloc_size), ctx->iova_min_page_size);

	inlen = DEVX_ST_SZ_BYTES(create_eq_in) +
		DEVX_FLD_SZ_BYTES(create_eq_in, pas[0]) * 1;

	in = calloc(1, inlen);
	if (!in)
		return ENOMEM;

	pas = (__be64 *)DEVX_ADDR_OF(create_eq_in, in, pas);

	err = posix_memalign(&eq->vaddr, eq->iova_size, alloc_size);
	if (err) {
		errno = err;
		goto end;
	}

	err = iset_alloc_range(ctx->iova_alloc, eq->iova_size, &eq->iova);
	if (err)
		goto err_range;

	err = mlx5_vfio_register_mem(ctx, eq->vaddr, eq->iova, eq->iova_size);
	if (err)
		goto err_reg;

	pas[0] = htobe64(eq->iova);
	init_eq_buf(eq);
	DEVX_SET(create_eq_in, in, opcode, MLX5_CMD_OP_CREATE_EQ);

	for (i = 0; i < 4; i++)
		DEVX_ARRAY_SET64(create_eq_in, in, event_bitmask, i,
				 param->mask[i]);

	eqc = DEVX_ADDR_OF(create_eq_in, in, eq_context_entry);
	DEVX_SET(eqc, eqc, log_eq_size, ilog32(eq->nent - 1));
	DEVX_SET(eqc, eqc, uar_page, ctx->eqs_uar.uarn);
	DEVX_SET(eqc, eqc, intr, vecidx);
	DEVX_SET(eqc, eqc, log_page_size, ilog32(eq->iova_size - 1) - MLX5_ADAPTER_PAGE_SHIFT);

	err = mlx5_vfio_cmd_exec(ctx, in, inlen, out, sizeof(out), 0);
	if (err)
		goto err_cmd;

	eq->vecidx = vecidx;
	eq->eqn = DEVX_GET(create_eq_out, out, eq_number);
	eq->doorbell = (void *)(uintptr_t)ctx->eqs_uar.iova + MLX5_EQ_DOORBEL_OFFSET;

	free(in);
	return 0;

err_cmd:
	mlx5_vfio_unregister_mem(ctx, eq->iova, eq->iova_size);
err_reg:
	iset_insert_range(ctx->iova_alloc, eq->iova, eq->iova_size);
err_range:
	free(eq->vaddr);
end:
	free(in);
	return err;
}

static int
setup_async_eq(struct mlx5_vfio_context *ctx, struct mlx5_eq_param *param,
	       struct mlx5_eq *eq)
{
	int err;

	err = create_map_eq(ctx, eq, param);
	if (err)
		return err;

	eq_update_ci(eq, 0, 1);

	return 0;
}

static int create_async_eqs(struct mlx5_vfio_context *ctx)
{
	struct mlx5_eq_param param = {};
	int err;

	err = mlx5_vfio_alloc_uar(ctx, &ctx->eqs_uar.uarn);
	if (err)
		return err;

	ctx->eqs_uar.iova = uar2iova(ctx, ctx->eqs_uar.uarn);

	param = (struct mlx5_eq_param) {
		.irq_index = MLX5_VFIO_CMD_VEC_IDX,
		.nent = MLX5_NUM_CMD_EQE,
		.mask[0] = 1ull << MLX5_EVENT_TYPE_CMD |
			   1ull << MLX5_EVENT_TYPE_PAGE_REQUEST,
	};

	err = setup_async_eq(ctx, &param, &ctx->async_eq);
	if (err)
		goto err;

	ctx->have_eq = true;
	return 0;
err:
	mlx5_vfio_dealloc_uar(ctx, ctx->eqs_uar.uarn);
	return err;
}

static int mlx5_vfio_reclaim_pages(struct mlx5_vfio_context *ctx, uint32_t func_id,
				   int npages)
{
	uint32_t inlen = DEVX_ST_SZ_BYTES(manage_pages_in);
	int outlen;
	uint32_t *out;
	void *in;
	int err;
	int slot = MLX5_MAX_COMMANDS - 1;

	outlen = DEVX_ST_SZ_BYTES(manage_pages_out);

	outlen += npages * DEVX_FLD_SZ_BYTES(manage_pages_out, pas[0]);
	out = calloc(1, outlen);
	if (!out) {
		errno = ENOMEM;
		return errno;
	}

	in = calloc(1, inlen);
	if (!in) {
		err = ENOMEM;
		errno = err;
		goto out_free;
	}

	DEVX_SET(manage_pages_in, in, opcode, MLX5_CMD_OP_MANAGE_PAGES);
	DEVX_SET(manage_pages_in, in, op_mod, MLX5_PAGES_TAKE);
	DEVX_SET(manage_pages_in, in, function_id, func_id);
	DEVX_SET(manage_pages_in, in, input_num_entries, npages);

	pthread_mutex_lock(&ctx->cmd.cmds[slot].lock);
	err = mlx5_vfio_post_cmd(ctx, in, inlen, out, outlen, slot, true);
	pthread_mutex_unlock(&ctx->cmd.cmds[slot].lock);
	if (!err)
		return 0;

	free(in);
out_free:
	free(out);
	return err;
}

static int mlx5_vfio_enable_hca(struct mlx5_vfio_context *ctx)
{
	uint32_t in[DEVX_ST_SZ_DW(enable_hca_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(enable_hca_out)] = {};

	DEVX_SET(enable_hca_in, in, opcode, MLX5_CMD_OP_ENABLE_HCA);
	return mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
}

static int mlx5_vfio_set_issi(struct mlx5_vfio_context *ctx)
{
	uint32_t query_in[DEVX_ST_SZ_DW(query_issi_in)] = {};
	uint32_t query_out[DEVX_ST_SZ_DW(query_issi_out)] = {};
	uint32_t set_in[DEVX_ST_SZ_DW(set_issi_in)] = {};
	uint32_t set_out[DEVX_ST_SZ_DW(set_issi_out)] = {};
	uint32_t sup_issi;
	int err;

	DEVX_SET(query_issi_in, query_in, opcode, MLX5_CMD_OP_QUERY_ISSI);
	err = mlx5_vfio_cmd_exec(ctx, query_in, sizeof(query_in), query_out,
				 sizeof(query_out), 0);
	if (err)
		return err;

	sup_issi = DEVX_GET(query_issi_out, query_out, supported_issi_dw0);

	if (!(sup_issi & (1 << 1))) {
		errno = EOPNOTSUPP;
		return errno;
	}

	DEVX_SET(set_issi_in, set_in, opcode, MLX5_CMD_OP_SET_ISSI);
	DEVX_SET(set_issi_in, set_in, current_issi, 1);
	return mlx5_vfio_cmd_exec(ctx, set_in, sizeof(set_in), set_out,
				  sizeof(set_out), 0);
}

static int mlx5_vfio_give_pages(struct mlx5_vfio_context *ctx,
				uint16_t func_id,
				int32_t npages,
				bool is_event)
{
	int32_t out[DEVX_ST_SZ_DW(manage_pages_out)] = {};
	int inlen = DEVX_ST_SZ_BYTES(manage_pages_in);
	int slot = MLX5_MAX_COMMANDS - 1;
	void *outp = out;
	int i, err;
	int32_t *in;
	uint64_t iova;

	inlen += npages * DEVX_FLD_SZ_BYTES(manage_pages_in, pas[0]);
	in = calloc(1, inlen);
	if (!in) {
		errno = ENOMEM;
		return errno;
	}

	if (is_event) {
		outp = calloc(1, sizeof(out));
		if (!outp) {
			errno = ENOMEM;
			err = errno;
			goto end;
		}
	}

	for (i = 0; i < npages; i++) {
		err = mlx5_vfio_alloc_page(ctx, &iova);
		if (err)
			goto err;

		DEVX_ARRAY_SET64(manage_pages_in, in, pas, i, iova);
	}

	DEVX_SET(manage_pages_in, in, opcode, MLX5_CMD_OP_MANAGE_PAGES);
	DEVX_SET(manage_pages_in, in, op_mod, MLX5_PAGES_GIVE);
	DEVX_SET(manage_pages_in, in, function_id, func_id);
	DEVX_SET(manage_pages_in, in, input_num_entries, npages);

	if (is_event) {
		pthread_mutex_lock(&ctx->cmd.cmds[slot].lock);
		err = mlx5_vfio_post_cmd(ctx, in, inlen, outp, sizeof(out), slot, true);
		pthread_mutex_unlock(&ctx->cmd.cmds[slot].lock);
	} else {
		err = mlx5_vfio_cmd_exec(ctx, in, inlen, outp, sizeof(out), slot);
	}

	if (!err) {
		if (is_event)
			return 0;
		goto end;
	}
err:
	if (is_event)
		free(outp);
	for (i--; i >= 0; i--)
		mlx5_vfio_free_page(ctx, DEVX_GET64(manage_pages_in, in, pas[i]));
end:
	free(in);
	return err;
}

static int mlx5_vfio_query_pages(struct mlx5_vfio_context *ctx, int boot,
				 uint16_t *func_id, int32_t *npages)
{
	uint32_t query_pages_in[DEVX_ST_SZ_DW(query_pages_in)] = {};
	uint32_t query_pages_out[DEVX_ST_SZ_DW(query_pages_out)] = {};
	int ret;

	DEVX_SET(query_pages_in, query_pages_in, opcode, MLX5_CMD_OP_QUERY_PAGES);
	DEVX_SET(query_pages_in, query_pages_in, op_mod, boot ? 0x01 : 0x02);

	ret = mlx5_vfio_cmd_exec(ctx, query_pages_in, sizeof(query_pages_in),
				 query_pages_out, sizeof(query_pages_out), 0);
	if (ret)
		return ret;

	*npages = DEVX_GET(query_pages_out, query_pages_out, num_pages);
	*func_id = DEVX_GET(query_pages_out, query_pages_out, function_id);

	return 0;
}

static int mlx5_vfio_satisfy_startup_pages(struct mlx5_vfio_context *ctx,
					   int boot)
{
	uint16_t function_id;
	int32_t npages = 0;
	int ret;

	ret = mlx5_vfio_query_pages(ctx, boot, &function_id, &npages);
	if (ret)
		return ret;

	return mlx5_vfio_give_pages(ctx, function_id, npages, false);
}

static int mlx5_vfio_access_reg(struct mlx5_vfio_context *ctx, void *data_in,
				int size_in, void *data_out, int size_out,
				uint16_t reg_id, int arg, int write)
{
	int outlen = DEVX_ST_SZ_BYTES(access_register_out) + size_out;
	int inlen = DEVX_ST_SZ_BYTES(access_register_in) + size_in;
	int err = ENOMEM;
	uint32_t *out = NULL;
	uint32_t *in = NULL;
	void *data;

	in = calloc(1, inlen);
	out = calloc(1, outlen);
	if (!in || !out) {
		errno = ENOMEM;
		goto out;
	}

	data = DEVX_ADDR_OF(access_register_in, in, register_data);
	memcpy(data, data_in, size_in);

	DEVX_SET(access_register_in, in, opcode, MLX5_CMD_OP_ACCESS_REG);
	DEVX_SET(access_register_in, in, op_mod, !write);
	DEVX_SET(access_register_in, in, argument, arg);
	DEVX_SET(access_register_in, in, register_id, reg_id);

	err = mlx5_vfio_cmd_exec(ctx, in, inlen, out, outlen, 0);
	if (err)
		goto out;

	data = DEVX_ADDR_OF(access_register_out, out, register_data);
	memcpy(data_out, data, size_out);

out:
	free(out);
	free(in);
	return err;
}

static int mlx5_vfio_get_caps_mode(struct mlx5_vfio_context *ctx,
				   enum mlx5_cap_type cap_type,
				   enum mlx5_cap_mode cap_mode)
{
	uint8_t in[DEVX_ST_SZ_BYTES(query_hca_cap_in)] = {};
	int out_sz = DEVX_ST_SZ_BYTES(query_hca_cap_out);
	void *out, *hca_caps;
	uint16_t opmod = (cap_type << 1) | (cap_mode & 0x01);
	int err;

	out = calloc(1, out_sz);
	if (!out) {
		errno = ENOMEM;
		return errno;
	}

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, opmod);
	err = mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, out_sz, 0);
	if (err)
		goto query_ex;

	hca_caps = DEVX_ADDR_OF(query_hca_cap_out, out, capability);

	switch (cap_mode) {
	case HCA_CAP_OPMOD_GET_MAX:
		memcpy(ctx->caps.hca_max[cap_type], hca_caps,
		       DEVX_UN_SZ_BYTES(hca_cap_union));
		break;
	case HCA_CAP_OPMOD_GET_CUR:
		memcpy(ctx->caps.hca_cur[cap_type], hca_caps,
		       DEVX_UN_SZ_BYTES(hca_cap_union));
		break;
	default:
		err = EINVAL;
		assert(false);
		break;
	}

query_ex:
	free(out);
	return err;
}

enum mlx5_vport_roce_state {
	MLX5_VPORT_ROCE_DISABLED = 0,
	MLX5_VPORT_ROCE_ENABLED  = 1,
};

static int mlx5_vfio_nic_vport_update_roce_state(struct mlx5_vfio_context *ctx,
						 enum mlx5_vport_roce_state state)
{
	uint32_t out[DEVX_ST_SZ_DW(modify_nic_vport_context_out)] = {};
	int inlen = DEVX_ST_SZ_BYTES(modify_nic_vport_context_in);
	void *in;
	int err;

	in = calloc(1, inlen);
	if (!in) {
		errno = ENOMEM;
		return errno;
	}

	DEVX_SET(modify_nic_vport_context_in, in, field_select.roce_en, 1);
	DEVX_SET(modify_nic_vport_context_in, in, nic_vport_context.roce_en,
		 state);
	DEVX_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_vfio_cmd_exec(ctx, in, inlen, out, sizeof(out), 0);

	free(in);

	return err;
}

static int mlx5_vfio_get_caps(struct mlx5_vfio_context *ctx, enum mlx5_cap_type cap_type)
{
	int ret;

	ret = mlx5_vfio_get_caps_mode(ctx, cap_type, HCA_CAP_OPMOD_GET_CUR);
	if (ret)
		return ret;

	return mlx5_vfio_get_caps_mode(ctx, cap_type, HCA_CAP_OPMOD_GET_MAX);
}

static int handle_hca_cap_roce(struct mlx5_vfio_context *ctx, void *set_ctx,
			       int ctx_size)
{
	int err;
	uint32_t out[DEVX_ST_SZ_DW(set_hca_cap_out)] = {};
	void *set_hca_cap;

	if (!MLX5_VFIO_CAP_GEN(ctx, roce))
		return 0;

	err = mlx5_vfio_get_caps(ctx, MLX5_CAP_ROCE);
	if (err)
		return err;

	if (MLX5_VFIO_CAP_ROCE(ctx, sw_r_roce_src_udp_port) ||
	    !MLX5_VFIO_CAP_ROCE_MAX(ctx, sw_r_roce_src_udp_port))
		return 0;

	set_hca_cap = DEVX_ADDR_OF(set_hca_cap_in, set_ctx, capability);
	memcpy(set_hca_cap, ctx->caps.hca_cur[MLX5_CAP_ROCE],
	       DEVX_ST_SZ_BYTES(roce_cap));
	DEVX_SET(roce_cap, set_hca_cap, sw_r_roce_src_udp_port, 1);
	DEVX_SET(set_hca_cap_in, set_ctx, opcode, MLX5_CMD_OP_SET_HCA_CAP);
	DEVX_SET(set_hca_cap_in, set_ctx, op_mod, MLX5_SET_HCA_CAP_OP_MOD_ROCE);
	return mlx5_vfio_cmd_exec(ctx, set_ctx, ctx_size, out, sizeof(out), 0);
}

static int handle_hca_cap(struct mlx5_vfio_context *ctx, void *set_ctx, int set_sz)
{
	struct mlx5_vfio_device *dev = to_mvfio_dev(ctx->vctx.context.device);
	int sys_page_shift = ilog32(dev->page_size - 1);
	uint32_t out[DEVX_ST_SZ_DW(set_hca_cap_out)] = {};
	void *set_hca_cap;
	int err;

	err = mlx5_vfio_get_caps(ctx, MLX5_CAP_GENERAL);
	if (err)
		return err;

	set_hca_cap = DEVX_ADDR_OF(set_hca_cap_in, set_ctx,
				   capability);
	memcpy(set_hca_cap, ctx->caps.hca_cur[MLX5_CAP_GENERAL],
	       DEVX_ST_SZ_BYTES(cmd_hca_cap));

	/* disable cmdif checksum */
	DEVX_SET(cmd_hca_cap, set_hca_cap, cmdif_checksum, 0);

	if (dev->flags & MLX5DV_VFIO_CTX_FLAGS_INIT_LINK_DOWN)
		DEVX_SET(cmd_hca_cap, set_hca_cap, disable_link_up_by_init_hca, 1);

	DEVX_SET(cmd_hca_cap, set_hca_cap, log_uar_page_sz, sys_page_shift - 12);

	if (MLX5_VFIO_CAP_GEN_MAX(ctx, mkey_by_name))
		DEVX_SET(cmd_hca_cap, set_hca_cap, mkey_by_name, 1);

	DEVX_SET(set_hca_cap_in, set_ctx, opcode, MLX5_CMD_OP_SET_HCA_CAP);
	DEVX_SET(set_hca_cap_in, set_ctx, op_mod, MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE);

	return mlx5_vfio_cmd_exec(ctx, set_ctx, set_sz, out, sizeof(out), 0);
}

static int set_hca_cap(struct mlx5_vfio_context *ctx)
{
	int set_sz = DEVX_ST_SZ_BYTES(set_hca_cap_in);
	void *set_ctx;
	int err;

	set_ctx = calloc(1, set_sz);
	if (!set_ctx) {
		errno = ENOMEM;
		return errno;
	}

	err = handle_hca_cap(ctx, set_ctx, set_sz);
	if (err)
		goto out;

	memset(set_ctx, 0, set_sz);
	err = handle_hca_cap_roce(ctx, set_ctx, set_sz);
out:
	free(set_ctx);
	return err;
}

static int mlx5_vfio_set_hca_ctrl(struct mlx5_vfio_context *ctx)
{
	struct mlx5_reg_host_endianness he_in = {};
	struct mlx5_reg_host_endianness he_out = {};

	he_in.he = MLX5_SET_HOST_ENDIANNESS;
	return mlx5_vfio_access_reg(ctx, &he_in, sizeof(he_in),
				    &he_out, sizeof(he_out),
				    MLX5_REG_HOST_ENDIANNESS, 0, 1);
}

static int mlx5_vfio_init_hca(struct mlx5_vfio_context *ctx)
{
	uint32_t in[DEVX_ST_SZ_DW(init_hca_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(init_hca_out)] = {};

	DEVX_SET(init_hca_in, in, opcode, MLX5_CMD_OP_INIT_HCA);
	return mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
}

static int fw_initializing(struct mlx5_init_seg *init_seg)
{
	return be32toh(init_seg->initializing) >> 31;
}

static int wait_fw_init(struct mlx5_init_seg *init_seg, uint32_t max_wait_mili)
{
	int num_loops = max_wait_mili / FW_INIT_WAIT_MS;
	int loop = 0;

	while (fw_initializing(init_seg)) {
		usleep(FW_INIT_WAIT_MS * 1000);
		loop++;
		if (loop == num_loops) {
			errno = EBUSY;
			return errno;
		}
	}

	return 0;
}

static int mlx5_vfio_teardown_hca_regular(struct mlx5_vfio_context *ctx)
{
	uint32_t in[DEVX_ST_SZ_DW(teardown_hca_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(teardown_hca_out)] = {};

	DEVX_SET(teardown_hca_in, in, opcode, MLX5_CMD_OP_TEARDOWN_HCA);
	DEVX_SET(teardown_hca_in, in, profile, MLX5_TEARDOWN_HCA_IN_PROFILE_GRACEFUL_CLOSE);
	return mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
}

enum mlx5_cmd_addr_l_sz_offset {
	MLX5_NIC_IFC_OFFSET = 8,
};

enum {
	MLX5_NIC_IFC_DISABLED = 1,
	MLX5_NIC_IFC_SW_RESET = 7,
};

static uint8_t mlx5_vfio_get_nic_state(struct mlx5_vfio_context *ctx)
{
	return (be32toh(mmio_read32_be(&ctx->bar_map->cmdq_addr_l_sz)) >> 8) & 7;
}

static void mlx5_vfio_set_nic_state(struct mlx5_vfio_context *ctx, uint8_t state)
{
	uint32_t cur_cmdq_addr_l_sz;

	cur_cmdq_addr_l_sz = be32toh(mmio_read32_be(&ctx->bar_map->cmdq_addr_l_sz));
	mmio_write32_be(&ctx->bar_map->cmdq_addr_l_sz,
			htobe32((cur_cmdq_addr_l_sz & 0xFFFFF000) |
				state << MLX5_NIC_IFC_OFFSET));
}

#define MLX5_FAST_TEARDOWN_WAIT_MS 3000
#define MLX5_FAST_TEARDOWN_WAIT_ONCE_MS 1
static int mlx5_vfio_teardown_hca_fast(struct mlx5_vfio_context *ctx)
{
	uint32_t out[DEVX_ST_SZ_DW(teardown_hca_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(teardown_hca_in)] = {};
	int waited = 0, state, ret;

	DEVX_SET(teardown_hca_in, in, opcode, MLX5_CMD_OP_TEARDOWN_HCA);
	DEVX_SET(teardown_hca_in, in, profile,
		 MLX5_TEARDOWN_HCA_IN_PROFILE_PREPARE_FAST_TEARDOWN);
	ret = mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
	if (ret)
		return ret;

	state = DEVX_GET(teardown_hca_out, out, state);
	if (state == MLX5_TEARDOWN_HCA_OUT_FORCE_STATE_FAIL) {
		mlx5_err(ctx->dbg_fp, "teardown with fast mode failed\n");
		return EIO;
	}

	mlx5_vfio_set_nic_state(ctx, MLX5_NIC_IFC_DISABLED);
	do {
		if (mlx5_vfio_get_nic_state(ctx) == MLX5_NIC_IFC_DISABLED)
			break;
		usleep(MLX5_FAST_TEARDOWN_WAIT_ONCE_MS * 1000);
		waited += MLX5_FAST_TEARDOWN_WAIT_ONCE_MS;
	} while (waited < MLX5_FAST_TEARDOWN_WAIT_MS);

	if (mlx5_vfio_get_nic_state(ctx) != MLX5_NIC_IFC_DISABLED) {
		mlx5_err(ctx->dbg_fp, "NIC IFC still %d after %ums.\n",
			 mlx5_vfio_get_nic_state(ctx), waited);
		return EIO;
	}

	return 0;
}

static int mlx5_vfio_teardown_hca(struct mlx5_vfio_context *ctx)
{
	int err;

	if (MLX5_VFIO_CAP_GEN(ctx, fast_teardown)) {
		err = mlx5_vfio_teardown_hca_fast(ctx);
		if (!err)
			return 0;
	}

	return mlx5_vfio_teardown_hca_regular(ctx);
}

static bool sensor_pci_not_working(struct mlx5_init_seg *init_seg)
{
	/* Offline PCI reads return 0xffffffff */
	return (be32toh(mmio_read32_be(&init_seg->health.fw_ver)) == 0xffffffff);
}

enum mlx5_fatal_assert_bit_offsets {
	MLX5_RFR_OFFSET = 31,
};

static bool sensor_fw_synd_rfr(struct mlx5_init_seg *init_seg)
{
	uint32_t rfr = be32toh(mmio_read32_be(&init_seg->health.rfr)) >> MLX5_RFR_OFFSET;
	uint8_t synd = mmio_read8(&init_seg->health.synd);

	return (rfr && synd);
}

enum  {
	MLX5_SENSOR_NO_ERR = 0,
	MLX5_SENSOR_PCI_COMM_ERR = 1,
	MLX5_SENSOR_NIC_DISABLED = 3,
	MLX5_SENSOR_NIC_SW_RESET = 4,
	MLX5_SENSOR_FW_SYND_RFR = 5,
};

static uint32_t mlx5_health_check_fatal_sensors(struct mlx5_vfio_context *ctx)
{
	if (sensor_pci_not_working(ctx->bar_map))
		return MLX5_SENSOR_PCI_COMM_ERR;

	if (mlx5_vfio_get_nic_state(ctx) == MLX5_NIC_IFC_DISABLED)
		return MLX5_SENSOR_NIC_DISABLED;

	if (mlx5_vfio_get_nic_state(ctx) == MLX5_NIC_IFC_SW_RESET)
		return MLX5_SENSOR_NIC_SW_RESET;

	if (sensor_fw_synd_rfr(ctx->bar_map))
		return MLX5_SENSOR_FW_SYND_RFR;

	return MLX5_SENSOR_NO_ERR;
}

enum {
	MLX5_HEALTH_SYNDR_FW_ERR = 0x1,
	MLX5_HEALTH_SYNDR_IRISC_ERR = 0x7,
	MLX5_HEALTH_SYNDR_HW_UNRECOVERABLE_ERR = 0x8,
	MLX5_HEALTH_SYNDR_CRC_ERR = 0x9,
	MLX5_HEALTH_SYNDR_FETCH_PCI_ERR = 0xa,
	MLX5_HEALTH_SYNDR_HW_FTL_ERR = 0xb,
	MLX5_HEALTH_SYNDR_ASYNC_EQ_OVERRUN_ERR = 0xc,
	MLX5_HEALTH_SYNDR_EQ_ERR = 0xd,
	MLX5_HEALTH_SYNDR_EQ_INV = 0xe,
	MLX5_HEALTH_SYNDR_FFSER_ERR = 0xf,
	MLX5_HEALTH_SYNDR_HIGH_TEMP = 0x10,
};

static const char *hsynd_str(u8 synd)
{
	switch (synd) {
	case MLX5_HEALTH_SYNDR_FW_ERR:
		return "firmware internal error";
	case MLX5_HEALTH_SYNDR_IRISC_ERR:
		return "irisc not responding";
	case MLX5_HEALTH_SYNDR_HW_UNRECOVERABLE_ERR:
		return "unrecoverable hardware error";
	case MLX5_HEALTH_SYNDR_CRC_ERR:
		return "firmware CRC error";
	case MLX5_HEALTH_SYNDR_FETCH_PCI_ERR:
		return "ICM fetch PCI error";
	case MLX5_HEALTH_SYNDR_HW_FTL_ERR:
		return "HW fatal error\n";
	case MLX5_HEALTH_SYNDR_ASYNC_EQ_OVERRUN_ERR:
		return "async EQ buffer overrun";
	case MLX5_HEALTH_SYNDR_EQ_ERR:
		return "EQ error";
	case MLX5_HEALTH_SYNDR_EQ_INV:
		return "Invalid EQ referenced";
	case MLX5_HEALTH_SYNDR_FFSER_ERR:
		return "FFSER error";
	case MLX5_HEALTH_SYNDR_HIGH_TEMP:
		return "High temperature";
	default:
		return "unrecognized error";
	}
}

static void print_health_info(struct mlx5_vfio_context *ctx)
{
	struct mlx5_init_seg *iseg = ctx->bar_map;
	struct health_buffer *h = &iseg->health;
	char fw_str[18] = {};
	int i;

	/* If the syndrome is 0, the device is OK and no need to print buffer */
	if (!mmio_read8(&h->synd))
		return;

	for (i = 0; i < ARRAY_SIZE(h->assert_var); i++)
		mlx5_err(ctx->dbg_fp, "assert_var[%d] 0x%08x\n",
			 i, be32toh(mmio_read32_be(h->assert_var + i)));

	mlx5_err(ctx->dbg_fp, "assert_exit_ptr 0x%08x\n",
		 be32toh(mmio_read32_be(&h->assert_exit_ptr)));
	mlx5_err(ctx->dbg_fp, "assert_callra 0x%08x\n",
		 be32toh(mmio_read32_be(&h->assert_callra)));
	sprintf(fw_str, "%d.%d.%d",
		be32toh(mmio_read32_be(&iseg->fw_rev)) & 0xffff,
		be32toh(mmio_read32_be(&iseg->fw_rev)) >> 16,
		be32toh(mmio_read32_be(&iseg->cmdif_rev_fw_sub)) & 0xffff);
	mlx5_err(ctx->dbg_fp, "fw_ver %s\n", fw_str);
	mlx5_err(ctx->dbg_fp, "hw_id 0x%08x\n", be32toh(mmio_read32_be(&h->hw_id)));
	mlx5_err(ctx->dbg_fp, "irisc_index %d\n", mmio_read8(&h->irisc_index));
	mlx5_err(ctx->dbg_fp, "synd 0x%x: %s\n", mmio_read8(&h->synd),
		 hsynd_str(mmio_read8(&h->synd)));
	mlx5_err(ctx->dbg_fp, "ext_synd 0x%04x\n",
		 be16toh(mmio_read16_be(&h->ext_synd)));
	mlx5_err(ctx->dbg_fp, "raw fw_ver 0x%08x\n",
		 be32toh(mmio_read32_be(&iseg->fw_rev)));
}

static void mlx5_vfio_poll_health(struct mlx5_vfio_context *ctx)
{
	struct mlx5_vfio_health_state *hstate = &ctx->health_state;
	uint32_t fatal_error, count;
	struct timeval tv;
	uint64_t time;
	int ret;

	ret = gettimeofday(&tv, NULL);
	if (ret)
		return;

	time = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
	if (time - hstate->prev_time < POLL_HEALTH_INTERVAL)
		return;

	fatal_error = mlx5_health_check_fatal_sensors(ctx);
	if (fatal_error) {
		mlx5_err(ctx->dbg_fp, "%s: Fatal error %u detected\n",
			 __func__, fatal_error);
		goto err;
	}
	count = be32toh(mmio_read32_be(&ctx->bar_map->health_counter)) & 0xffffff;
	if (count == hstate->prev_count)
		++hstate->miss_counter;
	else
		hstate->miss_counter = 0;

	hstate->prev_time = time;
	hstate->prev_count = count;
	if (hstate->miss_counter == MAX_MISSES) {
		mlx5_err(ctx->dbg_fp,
			 "device's health compromised - reached miss count\n");
		goto err;
	}

	return;
err:
	print_health_info(ctx);
	abort();
}

static int mlx5_vfio_setup_function(struct mlx5_vfio_context *ctx)
{
	int err;

	err = wait_fw_init(ctx->bar_map, FW_PRE_INIT_TIMEOUT_MILI);
	if (err)
		return err;

	err = mlx5_vfio_enable_hca(ctx);
	if (err)
		return err;

	err = mlx5_vfio_set_issi(ctx);
	if (err)
		return err;

	err = mlx5_vfio_satisfy_startup_pages(ctx, 1);
	if (err)
		return err;

	err = mlx5_vfio_set_hca_ctrl(ctx);
	if (err)
		return err;

	err = set_hca_cap(ctx);
	if (err)
		return err;

	if (!MLX5_VFIO_CAP_GEN(ctx, umem_uid_0)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	err = mlx5_vfio_satisfy_startup_pages(ctx, 0);
	if (err)
		return err;

	err = mlx5_vfio_init_hca(ctx);
	if (err)
		return err;

	if (MLX5_VFIO_CAP_GEN(ctx, port_type) == MLX5_CAP_PORT_TYPE_ETH)
		err = mlx5_vfio_nic_vport_update_roce_state(ctx, MLX5_VPORT_ROCE_ENABLED);

	return err;
}

static struct ibv_pd *mlx5_vfio_alloc_pd(struct ibv_context *ibctx)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);
	uint32_t in[DEVX_ST_SZ_DW(alloc_pd_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(alloc_pd_out)] = {0};
	int err;
	struct mlx5_pd *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	DEVX_SET(alloc_pd_in, in, opcode, MLX5_CMD_OP_ALLOC_PD);
	err = mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);

	if (err)
		goto err;

	pd->pdn = DEVX_GET(alloc_pd_out, out, pd);

	return &pd->ibv_pd;
err:
	free(pd);
	return NULL;
}

static int mlx5_vfio_dealloc_pd(struct ibv_pd *pd)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(pd->context);
	uint32_t in[DEVX_ST_SZ_DW(dealloc_pd_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(dealloc_pd_out)] = {};
	struct mlx5_pd *mpd = to_mpd(pd);
	int ret;

	DEVX_SET(dealloc_pd_in, in, opcode, MLX5_CMD_OP_DEALLOC_PD);
	DEVX_SET(dealloc_pd_in, in, pd, mpd->pdn);

	ret = mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
	if (ret)
		return ret;

	free(mpd);
	return 0;
}

static size_t calc_num_dma_blocks(uint64_t iova, size_t length,
				   unsigned long pgsz)
{
	return (size_t)((align(iova + length, pgsz) -
			 align_down(iova, pgsz)) / pgsz);
}

static int get_octo_len(uint64_t addr, uint64_t len, int page_shift)
{
	uint64_t page_size = 1ULL << page_shift;
	uint64_t offset;
	int npages;

	offset = addr & (page_size - 1);
	npages = align(len + offset, page_size) >> page_shift;
	return (npages + 1) / 2;
}

static inline uint32_t mlx5_mkey_to_idx(uint32_t mkey)
{
	return mkey >> 8;
}

static inline uint32_t mlx5_idx_to_mkey(uint32_t mkey_idx)
{
	return mkey_idx << 8;
}

static void set_mkc_access_pd_addr_fields(void *mkc, int acc, uint64_t start_addr,
					  struct ibv_pd *pd)
{
	struct mlx5_pd *mpd = to_mpd(pd);

	DEVX_SET(mkc, mkc, a, !!(acc & IBV_ACCESS_REMOTE_ATOMIC));
	DEVX_SET(mkc, mkc, rw, !!(acc & IBV_ACCESS_REMOTE_WRITE));
	DEVX_SET(mkc, mkc, rr, !!(acc & IBV_ACCESS_REMOTE_READ));
	DEVX_SET(mkc, mkc, lw, !!(acc & IBV_ACCESS_LOCAL_WRITE));
	DEVX_SET(mkc, mkc, lr, 1);
	/* Application is responsible to set based on caps */
	DEVX_SET(mkc, mkc, relaxed_ordering_write,
		 !!(acc & IBV_ACCESS_RELAXED_ORDERING));
	DEVX_SET(mkc, mkc, relaxed_ordering_read,
		 !!(acc & IBV_ACCESS_RELAXED_ORDERING));
	DEVX_SET(mkc, mkc, pd, mpd->pdn);
	DEVX_SET(mkc, mkc, qpn, 0xffffff);
	DEVX_SET64(mkc, mkc, start_addr, start_addr);
}

static int mlx5_vfio_dereg_mr(struct verbs_mr *vmr)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(vmr->ibv_mr.context);
	struct mlx5_vfio_mr *mr = to_mvfio_mr(&vmr->ibv_mr);
	uint32_t in[DEVX_ST_SZ_DW(destroy_mkey_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(destroy_mkey_in)] = {};
	int ret;

	DEVX_SET(destroy_mkey_in, in, opcode, MLX5_CMD_OP_DESTROY_MKEY);
	DEVX_SET(destroy_mkey_in, in, mkey_index, mlx5_mkey_to_idx(vmr->ibv_mr.lkey));
	ret = mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
	if (ret)
		return ret;

	mlx5_vfio_unregister_mem(ctx, mr->iova + mr->iova_aligned_offset,
				 mr->iova_reg_size);
	iset_insert_range(ctx->iova_alloc, mr->iova, mr->iova_page_size);

	free(vmr);
	return 0;
}

static void mlx5_vfio_populate_pas(uint64_t dma_addr, int num_dma, size_t page_size,
				  __be64 *pas, uint64_t access_flags)
{
	int i;

	for (i = 0; i < num_dma; i++) {
		*pas = htobe64(dma_addr | access_flags);
		pas++;
		dma_addr += page_size;
	}
}

static uint64_t calc_spanning_page_size(uint64_t start, uint64_t length)
{
	/* Compute a page_size such that:
	 * start & (page_size-1) == (start + length) & (page_size - 1)
	 */
	uint64_t diffs = start ^ (start + length - 1);

	return roundup_pow_of_two(diffs + 1);
}

static struct ibv_mr *mlx5_vfio_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				       uint64_t hca_va, int access)
{
	struct mlx5_vfio_device *dev = to_mvfio_dev(pd->context->device);
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(pd->context);
	uint32_t out[DEVX_ST_SZ_DW(create_mkey_out)] = {};
	uint32_t mkey_index;
	uint32_t *in;
	int inlen, num_pas, ret;
	struct mlx5_vfio_mr *mr;
	struct verbs_mr *vmr;
	int page_shift, iova_min_page_shift;
	__be64 *pas;
	uint8_t key;
	void *mkc;
	void *aligned_va;

	if (!check_comp_mask(access, MLX5_VFIO_SUPP_MR_ACCESS_FLAGS)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (((uint64_t)(uintptr_t)addr & (ctx->iova_min_page_size - 1)) !=
	    (hca_va & (ctx->iova_min_page_size - 1))) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	mr = calloc(1, sizeof(*mr));
	if (!mr) {
		errno = ENOMEM;
		return NULL;
	}

	/* Page size that encloses the start and end of the mkey's hca_va range */
	mr->iova_page_size = max(calc_spanning_page_size(hca_va, length),
				 ctx->iova_min_page_size);

	ret = iset_alloc_range(ctx->iova_alloc, mr->iova_page_size, &mr->iova);
	if (ret)
		goto end;

	aligned_va = (void *)(uintptr_t)((unsigned long)addr & ~(ctx->iova_min_page_size - 1));
	page_shift = ilog32(mr->iova_page_size - 1);
	iova_min_page_shift = ilog32(ctx->iova_min_page_size - 1);
	if (page_shift > iova_min_page_shift)
		/* Ensure the low bis of the mkey VA match the low bits of the IOVA because the mkc
		 * start_addr specifies both the wire VA and the DMA VA.
		 */
		mr->iova_aligned_offset = hca_va & GENMASK(page_shift - 1, iova_min_page_shift);

	mr->iova_reg_size = align(length + hca_va, ctx->iova_min_page_size) -
				  align_down(hca_va, ctx->iova_min_page_size);

	assert(mr->iova_page_size >= mr->iova_aligned_offset + mr->iova_reg_size);
	ret = mlx5_vfio_register_mem(ctx, aligned_va,
				     mr->iova + mr->iova_aligned_offset,
				     mr->iova_reg_size);

	if (ret)
		goto err_reg;

	num_pas = 1;
	if (page_shift > MLX5_MAX_PAGE_SHIFT) {
		page_shift = MLX5_MAX_PAGE_SHIFT;
		num_pas = calc_num_dma_blocks(hca_va, length, (1ULL << MLX5_MAX_PAGE_SHIFT));
	}

	inlen = DEVX_ST_SZ_BYTES(create_mkey_in) + (sizeof(*pas) * align(num_pas, 2));

	in = calloc(1, inlen);
	if (!in) {
		errno = ENOMEM;
		goto err_in;
	}

	pas = (__be64 *)DEVX_ADDR_OF(create_mkey_in, in, klm_pas_mtt);
	mlx5_vfio_populate_pas(mr->iova, num_pas, (1ULL << page_shift), pas, MLX5_MTT_PRESENT);

	DEVX_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	DEVX_SET(create_mkey_in, in, pg_access, 1);
	mkc = DEVX_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	set_mkc_access_pd_addr_fields(mkc, access, hca_va, pd);
	DEVX_SET(mkc, mkc, free, 0);
	DEVX_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	DEVX_SET64(mkc, mkc, len, length);
	DEVX_SET(mkc, mkc, bsf_octword_size, 0);
	DEVX_SET(mkc, mkc, translations_octword_size,
		 get_octo_len(hca_va, length, page_shift));
	DEVX_SET(mkc, mkc, log_page_size, page_shift);

	DEVX_SET(create_mkey_in, in, translations_octword_actual_size,
		 get_octo_len(hca_va, length, page_shift));

	key = atomic_fetch_add(&dev->mkey_var, 1);
	DEVX_SET(mkc, mkc, mkey_7_0, key);

	ret = mlx5_vfio_cmd_exec(ctx, in, inlen, out, sizeof(out), 0);
	if (ret)
		goto err_exec;

	free(in);
	mkey_index = DEVX_GET(create_mkey_out, out, mkey_index);
	vmr = &mr->vmr;
	vmr->ibv_mr.lkey = key | mlx5_idx_to_mkey(mkey_index);
	vmr->ibv_mr.rkey = vmr->ibv_mr.lkey;
	vmr->ibv_mr.context = pd->context;
	vmr->mr_type = IBV_MR_TYPE_MR;
	vmr->access = access;
	vmr->ibv_mr.handle = 0;

	return &mr->vmr.ibv_mr;

err_exec:
	free(in);
err_in:
	mlx5_vfio_unregister_mem(ctx, mr->iova + mr->iova_aligned_offset,
				 mr->iova_reg_size);
err_reg:
	iset_insert_range(ctx->iova_alloc, mr->iova, mr->iova_page_size);
end:
	free(mr);
	return NULL;
}

static int vfio_devx_query_eqn(struct ibv_context *ibctx, uint32_t vector,
			       uint32_t *eqn)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);

	if (vector > ibctx->num_comp_vectors - 1)
		return EINVAL;

	/* For now use the singleton EQN created for async events */
	*eqn = ctx->async_eq.eqn;
	return 0;
}

static struct mlx5dv_devx_uar *
vfio_devx_alloc_uar(struct ibv_context *ibctx, uint32_t flags)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);
	struct mlx5_devx_uar *uar;

	if (flags != MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	uar = calloc(1, sizeof(*uar));
	if (!uar) {
		errno = ENOMEM;
		return NULL;
	}

	uar->dv_devx_uar.page_id = ctx->eqs_uar.uarn;
	uar->dv_devx_uar.base_addr = (void *)(uintptr_t)ctx->eqs_uar.iova;
	uar->dv_devx_uar.reg_addr = uar->dv_devx_uar.base_addr + MLX5_BF_OFFSET;
	uar->context = ibctx;

	return &uar->dv_devx_uar;
}

static void vfio_devx_free_uar(struct mlx5dv_devx_uar *dv_devx_uar)
{
	free(dv_devx_uar);
}

static struct mlx5dv_devx_umem *
_vfio_devx_umem_reg(struct ibv_context *context,
		    void *addr, size_t size, uint32_t access,
		    uint64_t pgsz_bitmap)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(context);
	uint32_t out[DEVX_ST_SZ_DW(create_umem_out)] = {};
	struct mlx5_vfio_devx_umem *vfio_umem;
	int iova_page_shift;
	uint64_t iova_size;
	int ret;
	void *in;
	uint32_t inlen;
	__be64 *mtt;
	void *umem;
	bool writeable;
	void *aligned_va;
	int num_pas;

	if (!check_comp_mask(access, MLX5_VFIO_SUPP_UMEM_ACCESS_FLAGS)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if ((access & IBV_ACCESS_REMOTE_WRITE) &&
	    !(access & IBV_ACCESS_LOCAL_WRITE)) {
		errno = EINVAL;
		return NULL;
	}

	/* Page size that encloses the start and end of the umem range */
	iova_size = max(roundup_pow_of_two(size + ((uint64_t)(uintptr_t)addr & (ctx->iova_min_page_size - 1))),
			ctx->iova_min_page_size);

	if (!(iova_size & pgsz_bitmap)) {
		/* input should include the iova page size */
		errno = EOPNOTSUPP;
		return NULL;
	}

	writeable = access &
		(IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

	vfio_umem = calloc(1, sizeof(*vfio_umem));
	if (!vfio_umem) {
		errno = ENOMEM;
		return NULL;
	}

	vfio_umem->iova_size = iova_size;
	if (ibv_dontfork_range(addr, size))
		goto err;

	ret = iset_alloc_range(ctx->iova_alloc, vfio_umem->iova_size, &vfio_umem->iova);
	if (ret)
		goto err_alloc;

	/* The registration's arguments have to reflect real VA presently mapped into the process */
	aligned_va = (void *)(uintptr_t)((unsigned long) addr & ~(ctx->iova_min_page_size - 1));
	vfio_umem->iova_reg_size = align((addr + size) - aligned_va, ctx->iova_min_page_size);
	ret = mlx5_vfio_register_mem(ctx, aligned_va, vfio_umem->iova, vfio_umem->iova_reg_size);
	if (ret)
		goto err_reg;

	iova_page_shift = ilog32(vfio_umem->iova_size - 1);
	num_pas = 1;
	if (iova_page_shift > MLX5_MAX_PAGE_SHIFT) {
		iova_page_shift = MLX5_MAX_PAGE_SHIFT;
		num_pas = DIV_ROUND_UP(vfio_umem->iova_size, (1ULL << iova_page_shift));
	}

	inlen = DEVX_ST_SZ_BYTES(create_umem_in) + DEVX_ST_SZ_BYTES(mtt) * num_pas;

	in = calloc(1, inlen);
	if (!in) {
		errno = ENOMEM;
		goto err_in;
	}

	umem = DEVX_ADDR_OF(create_umem_in, in, umem);
	mtt = (__be64 *)DEVX_ADDR_OF(umem, umem, mtt);

	DEVX_SET(create_umem_in, in, opcode, MLX5_CMD_OP_CREATE_UMEM);
	DEVX_SET64(umem, umem, num_of_mtt, num_pas);
	DEVX_SET(umem, umem, log_page_size, iova_page_shift - MLX5_ADAPTER_PAGE_SHIFT);
	DEVX_SET(umem, umem, page_offset, addr - aligned_va);

	mlx5_vfio_populate_pas(vfio_umem->iova, num_pas, (1ULL << iova_page_shift), mtt,
			       (writeable ? MLX5_MTT_WRITE : 0) | MLX5_MTT_READ);

	ret = mlx5_vfio_cmd_exec(ctx, in, inlen, out, sizeof(out), 0);
	if (ret)
		goto err_exec;

	free(in);

	vfio_umem->dv_devx_umem.umem_id = DEVX_GET(create_umem_out, out, umem_id);
	vfio_umem->context = context;
	vfio_umem->addr = addr;
	vfio_umem->size = size;
	return &vfio_umem->dv_devx_umem;

err_exec:
	free(in);
err_in:
	mlx5_vfio_unregister_mem(ctx, vfio_umem->iova, vfio_umem->iova_reg_size);
err_reg:
	iset_insert_range(ctx->iova_alloc, vfio_umem->iova, vfio_umem->iova_size);
err_alloc:
	ibv_dofork_range(addr, size);
err:
	free(vfio_umem);
	return NULL;
}

static struct mlx5dv_devx_umem *
vfio_devx_umem_reg(struct ibv_context *context,
		   void *addr, size_t size, uint32_t access)
{
	return _vfio_devx_umem_reg(context, addr, size, access, UINT64_MAX);
}

static struct mlx5dv_devx_umem *
vfio_devx_umem_reg_ex(struct ibv_context *ctx, struct mlx5dv_devx_umem_in *in)
{
	if (!check_comp_mask(in->comp_mask, 0)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return _vfio_devx_umem_reg(ctx, in->addr, in->size, in->access, in->pgsz_bitmap);
}

static int vfio_devx_umem_dereg(struct mlx5dv_devx_umem *dv_devx_umem)
{
	struct mlx5_vfio_devx_umem *vfio_umem =
		container_of(dv_devx_umem, struct mlx5_vfio_devx_umem,
			     dv_devx_umem);
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(vfio_umem->context);
	uint32_t in[DEVX_ST_SZ_DW(create_umem_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(create_umem_out)] = {};
	int ret;

	DEVX_SET(destroy_umem_in, in, opcode, MLX5_CMD_OP_DESTROY_UMEM);
	DEVX_SET(destroy_umem_in, in, umem_id, dv_devx_umem->umem_id);

	ret = mlx5_vfio_cmd_exec(ctx, in, sizeof(in), out, sizeof(out), 0);
	if (ret)
		return ret;

	mlx5_vfio_unregister_mem(ctx, vfio_umem->iova, vfio_umem->iova_reg_size);
	iset_insert_range(ctx->iova_alloc, vfio_umem->iova, vfio_umem->iova_size);
	ibv_dofork_range(vfio_umem->addr, vfio_umem->size);
	free(vfio_umem);
	return 0;
}

static int vfio_init_obj(struct mlx5dv_obj *obj, uint64_t obj_type)
{
	struct ibv_pd *pd_in = obj->pd.in;
	struct mlx5dv_pd *pd_out = obj->pd.out;
	struct mlx5_pd *mpd = to_mpd(pd_in);

	if (obj_type != MLX5DV_OBJ_PD)
		return EOPNOTSUPP;

	pd_out->comp_mask = 0;
	pd_out->pdn = mpd->pdn;
	return 0;
}

static int vfio_devx_general_cmd(struct ibv_context *context, const void *in,
				 size_t inlen, void *out, size_t outlen)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(context);

	return mlx5_vfio_cmd_exec(ctx, (void *)in, inlen, out, outlen, 0);
}

static bool devx_is_obj_create_cmd(const void *in)
{
	uint16_t opcode = DEVX_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_CREATE_GENERAL_OBJECT:
	case MLX5_CMD_OP_CREATE_MKEY:
	case MLX5_CMD_OP_CREATE_CQ:
	case MLX5_CMD_OP_ALLOC_PD:
	case MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN:
	case MLX5_CMD_OP_CREATE_RMP:
	case MLX5_CMD_OP_CREATE_SQ:
	case MLX5_CMD_OP_CREATE_RQ:
	case MLX5_CMD_OP_CREATE_RQT:
	case MLX5_CMD_OP_CREATE_TIR:
	case MLX5_CMD_OP_CREATE_TIS:
	case MLX5_CMD_OP_ALLOC_Q_COUNTER:
	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
	case MLX5_CMD_OP_CREATE_FLOW_COUNTER:
	case MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT:
	case MLX5_CMD_OP_ALLOC_MODIFY_HEADER_CONTEXT:
	case MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_CREATE_QP:
	case MLX5_CMD_OP_CREATE_SRQ:
	case MLX5_CMD_OP_CREATE_XRC_SRQ:
	case MLX5_CMD_OP_CREATE_DCT:
	case MLX5_CMD_OP_CREATE_XRQ:
	case MLX5_CMD_OP_ATTACH_TO_MCG:
	case MLX5_CMD_OP_ALLOC_XRCD:
		return true;
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
	{
		uint8_t op_mod = DEVX_GET(set_fte_in, in, op_mod);

		if (op_mod == 0)
			return true;
		return false;
	}
	case MLX5_CMD_OP_CREATE_PSV:
	{
		uint8_t num_psv = DEVX_GET(create_psv_in, in, num_psv);

		if (num_psv == 1)
			return true;
		return false;
	}
	default:
		return false;
	}
}

static uint32_t devx_get_created_obj_id(const void *in, const void *out,
					uint16_t opcode)
{
	switch (opcode) {
	case MLX5_CMD_OP_CREATE_GENERAL_OBJECT:
		return DEVX_GET(general_obj_out_cmd_hdr, out, obj_id);
	case MLX5_CMD_OP_CREATE_UMEM:
		return DEVX_GET(create_umem_out, out, umem_id);
	case MLX5_CMD_OP_CREATE_MKEY:
		return DEVX_GET(create_mkey_out, out, mkey_index);
	case MLX5_CMD_OP_CREATE_CQ:
		return DEVX_GET(create_cq_out, out, cqn);
	case MLX5_CMD_OP_ALLOC_PD:
		return DEVX_GET(alloc_pd_out, out, pd);
	case MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN:
		return DEVX_GET(alloc_transport_domain_out, out,
				transport_domain);
	case MLX5_CMD_OP_CREATE_RMP:
		return DEVX_GET(create_rmp_out, out, rmpn);
	case MLX5_CMD_OP_CREATE_SQ:
		return DEVX_GET(create_sq_out, out, sqn);
	case MLX5_CMD_OP_CREATE_RQ:
		return DEVX_GET(create_rq_out, out, rqn);
	case MLX5_CMD_OP_CREATE_RQT:
		return DEVX_GET(create_rqt_out, out, rqtn);
	case MLX5_CMD_OP_CREATE_TIR:
		return DEVX_GET(create_tir_out, out, tirn);
	case MLX5_CMD_OP_CREATE_TIS:
		return DEVX_GET(create_tis_out, out, tisn);
	case MLX5_CMD_OP_ALLOC_Q_COUNTER:
		return DEVX_GET(alloc_q_counter_out, out, counter_set_id);
	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
		return DEVX_GET(create_flow_table_out, out, table_id);
	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
		return DEVX_GET(create_flow_group_out, out, group_id);
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
		return DEVX_GET(set_fte_in, in, flow_index);
	case MLX5_CMD_OP_CREATE_FLOW_COUNTER:
		return DEVX_GET(alloc_flow_counter_out, out, flow_counter_id);
	case MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT:
		return DEVX_GET(alloc_packet_reformat_context_out, out,
				packet_reformat_id);
	case MLX5_CMD_OP_ALLOC_MODIFY_HEADER_CONTEXT:
		return DEVX_GET(alloc_modify_header_context_out, out,
				modify_header_id);
	case MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT:
		return DEVX_GET(create_scheduling_element_out, out,
				scheduling_element_id);
	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
		return DEVX_GET(add_vxlan_udp_dport_in, in, vxlan_udp_port);
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
		return DEVX_GET(set_l2_table_entry_in, in, table_index);
	case MLX5_CMD_OP_CREATE_QP:
		return DEVX_GET(create_qp_out, out, qpn);
	case MLX5_CMD_OP_CREATE_SRQ:
		return DEVX_GET(create_srq_out, out, srqn);
	case MLX5_CMD_OP_CREATE_XRC_SRQ:
		return DEVX_GET(create_xrc_srq_out, out, xrc_srqn);
	case MLX5_CMD_OP_CREATE_DCT:
		return DEVX_GET(create_dct_out, out, dctn);
	case MLX5_CMD_OP_CREATE_XRQ:
		return DEVX_GET(create_xrq_out, out, xrqn);
	case MLX5_CMD_OP_ATTACH_TO_MCG:
		return DEVX_GET(attach_to_mcg_in, in, qpn);
	case MLX5_CMD_OP_ALLOC_XRCD:
		return DEVX_GET(alloc_xrcd_out, out, xrcd);
	case MLX5_CMD_OP_CREATE_PSV:
		return DEVX_GET(create_psv_out, out, psv0_index);
	default:
		/* The entry must match to one of the devx_is_obj_create_cmd */
		assert(false);
		return 0;
	}
}

static void devx_obj_build_destroy_cmd(const void *in, void *out,
				       void *din, uint32_t *dinlen,
				       struct mlx5dv_devx_obj *obj)
{
	uint16_t opcode = DEVX_GET(general_obj_in_cmd_hdr, in, opcode);
	uint16_t uid = DEVX_GET(general_obj_in_cmd_hdr, in, uid);
	uint32_t *obj_id = &obj->object_id;

	*obj_id = devx_get_created_obj_id(in, out, opcode);
	*dinlen = DEVX_ST_SZ_BYTES(general_obj_in_cmd_hdr);
	DEVX_SET(general_obj_in_cmd_hdr, din, uid, uid);

	switch (opcode) {
	case MLX5_CMD_OP_CREATE_GENERAL_OBJECT:
		DEVX_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_GENERAL_OBJECT);
		DEVX_SET(general_obj_in_cmd_hdr, din, obj_id, *obj_id);
		DEVX_SET(general_obj_in_cmd_hdr, din, obj_type,
			 DEVX_GET(general_obj_in_cmd_hdr, in, obj_type));
		break;

	case MLX5_CMD_OP_CREATE_UMEM:
		DEVX_SET(destroy_umem_in, din, opcode,
			 MLX5_CMD_OP_DESTROY_UMEM);
		DEVX_SET(destroy_umem_in, din, umem_id, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_MKEY:
		DEVX_SET(destroy_mkey_in, din, opcode,
			 MLX5_CMD_OP_DESTROY_MKEY);
		DEVX_SET(destroy_mkey_in, din, mkey_index, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_CQ:
		DEVX_SET(destroy_cq_in, din, opcode, MLX5_CMD_OP_DESTROY_CQ);
		DEVX_SET(destroy_cq_in, din, cqn, *obj_id);
		break;
	case MLX5_CMD_OP_ALLOC_PD:
		DEVX_SET(dealloc_pd_in, din, opcode, MLX5_CMD_OP_DEALLOC_PD);
		DEVX_SET(dealloc_pd_in, din, pd, *obj_id);
		break;
	case MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN:
		DEVX_SET(dealloc_transport_domain_in, din, opcode,
			 MLX5_CMD_OP_DEALLOC_TRANSPORT_DOMAIN);
		DEVX_SET(dealloc_transport_domain_in, din, transport_domain,
			 *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_RMP:
		DEVX_SET(destroy_rmp_in, din, opcode, MLX5_CMD_OP_DESTROY_RMP);
		DEVX_SET(destroy_rmp_in, din, rmpn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_SQ:
		DEVX_SET(destroy_sq_in, din, opcode, MLX5_CMD_OP_DESTROY_SQ);
		DEVX_SET(destroy_sq_in, din, sqn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_RQ:
		DEVX_SET(destroy_rq_in, din, opcode, MLX5_CMD_OP_DESTROY_RQ);
		DEVX_SET(destroy_rq_in, din, rqn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_RQT:
		DEVX_SET(destroy_rqt_in, din, opcode, MLX5_CMD_OP_DESTROY_RQT);
		DEVX_SET(destroy_rqt_in, din, rqtn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_TIR:
		DEVX_SET(destroy_tir_in, din, opcode, MLX5_CMD_OP_DESTROY_TIR);
		DEVX_SET(destroy_tir_in, din, tirn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_TIS:
		DEVX_SET(destroy_tis_in, din, opcode, MLX5_CMD_OP_DESTROY_TIS);
		DEVX_SET(destroy_tis_in, din, tisn, *obj_id);
		break;
	case MLX5_CMD_OP_ALLOC_Q_COUNTER:
		DEVX_SET(dealloc_q_counter_in, din, opcode,
			 MLX5_CMD_OP_DEALLOC_Q_COUNTER);
		DEVX_SET(dealloc_q_counter_in, din, counter_set_id, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
		*dinlen = DEVX_ST_SZ_BYTES(destroy_flow_table_in);
		DEVX_SET(destroy_flow_table_in, din, other_vport,
			 DEVX_GET(create_flow_table_in,  in, other_vport));
		DEVX_SET(destroy_flow_table_in, din, vport_number,
			 DEVX_GET(create_flow_table_in,  in, vport_number));
		DEVX_SET(destroy_flow_table_in, din, table_type,
			 DEVX_GET(create_flow_table_in,  in, table_type));
		DEVX_SET(destroy_flow_table_in, din, table_id, *obj_id);
		DEVX_SET(destroy_flow_table_in, din, opcode,
			 MLX5_CMD_OP_DESTROY_FLOW_TABLE);
		break;
	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
		*dinlen = DEVX_ST_SZ_BYTES(destroy_flow_group_in);
		DEVX_SET(destroy_flow_group_in, din, other_vport,
			 DEVX_GET(create_flow_group_in, in, other_vport));
		DEVX_SET(destroy_flow_group_in, din, vport_number,
			 DEVX_GET(create_flow_group_in, in, vport_number));
		DEVX_SET(destroy_flow_group_in, din, table_type,
			 DEVX_GET(create_flow_group_in, in, table_type));
		DEVX_SET(destroy_flow_group_in, din, table_id,
			 DEVX_GET(create_flow_group_in, in, table_id));
		DEVX_SET(destroy_flow_group_in, din, group_id, *obj_id);
		DEVX_SET(destroy_flow_group_in, din, opcode,
			 MLX5_CMD_OP_DESTROY_FLOW_GROUP);
		break;
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
		*dinlen = DEVX_ST_SZ_BYTES(delete_fte_in);
		DEVX_SET(delete_fte_in, din, other_vport,
			 DEVX_GET(set_fte_in,  in, other_vport));
		DEVX_SET(delete_fte_in, din, vport_number,
			 DEVX_GET(set_fte_in, in, vport_number));
		DEVX_SET(delete_fte_in, din, table_type,
			 DEVX_GET(set_fte_in, in, table_type));
		DEVX_SET(delete_fte_in, din, table_id,
			 DEVX_GET(set_fte_in, in, table_id));
		DEVX_SET(delete_fte_in, din, flow_index, *obj_id);
		DEVX_SET(delete_fte_in, din, opcode,
			 MLX5_CMD_OP_DELETE_FLOW_TABLE_ENTRY);
		break;
	case MLX5_CMD_OP_CREATE_FLOW_COUNTER:
		DEVX_SET(dealloc_flow_counter_in, din, opcode,
			 MLX5_CMD_OP_DEALLOC_FLOW_COUNTER);
		DEVX_SET(dealloc_flow_counter_in, din, flow_counter_id,
			 *obj_id);
		break;
	case MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT:
		DEVX_SET(dealloc_packet_reformat_context_in, din, opcode,
			 MLX5_CMD_OP_DEALLOC_PACKET_REFORMAT_CONTEXT);
		DEVX_SET(dealloc_packet_reformat_context_in, din,
			 packet_reformat_id, *obj_id);
		break;
	case MLX5_CMD_OP_ALLOC_MODIFY_HEADER_CONTEXT:
		DEVX_SET(dealloc_modify_header_context_in, din, opcode,
			 MLX5_CMD_OP_DEALLOC_MODIFY_HEADER_CONTEXT);
		DEVX_SET(dealloc_modify_header_context_in, din,
			 modify_header_id, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT:
		*dinlen = DEVX_ST_SZ_BYTES(destroy_scheduling_element_in);
		DEVX_SET(destroy_scheduling_element_in, din,
			 scheduling_hierarchy,
			 DEVX_GET(create_scheduling_element_in, in,
				  scheduling_hierarchy));
		DEVX_SET(destroy_scheduling_element_in, din,
			 scheduling_element_id, *obj_id);
		DEVX_SET(destroy_scheduling_element_in, din, opcode,
			 MLX5_CMD_OP_DESTROY_SCHEDULING_ELEMENT);
		break;
	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
		*dinlen = DEVX_ST_SZ_BYTES(delete_vxlan_udp_dport_in);
		DEVX_SET(delete_vxlan_udp_dport_in, din, vxlan_udp_port, *obj_id);
		DEVX_SET(delete_vxlan_udp_dport_in, din, opcode,
			 MLX5_CMD_OP_DELETE_VXLAN_UDP_DPORT);
		break;
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
		*dinlen = DEVX_ST_SZ_BYTES(delete_l2_table_entry_in);
		DEVX_SET(delete_l2_table_entry_in, din, table_index, *obj_id);
		DEVX_SET(delete_l2_table_entry_in, din, opcode,
			 MLX5_CMD_OP_DELETE_L2_TABLE_ENTRY);
		break;
	case MLX5_CMD_OP_CREATE_QP:
		DEVX_SET(destroy_qp_in, din, opcode, MLX5_CMD_OP_DESTROY_QP);
		DEVX_SET(destroy_qp_in, din, qpn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_SRQ:
		DEVX_SET(destroy_srq_in, din, opcode, MLX5_CMD_OP_DESTROY_SRQ);
		DEVX_SET(destroy_srq_in, din, srqn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_XRC_SRQ:
		DEVX_SET(destroy_xrc_srq_in, din, opcode,
			 MLX5_CMD_OP_DESTROY_XRC_SRQ);
		DEVX_SET(destroy_xrc_srq_in, din, xrc_srqn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_DCT:
		DEVX_SET(destroy_dct_in, din, opcode, MLX5_CMD_OP_DESTROY_DCT);
		DEVX_SET(destroy_dct_in, din, dctn, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_XRQ:
		DEVX_SET(destroy_xrq_in, din, opcode, MLX5_CMD_OP_DESTROY_XRQ);
		DEVX_SET(destroy_xrq_in, din, xrqn, *obj_id);
		break;
	case MLX5_CMD_OP_ATTACH_TO_MCG:
		*dinlen = DEVX_ST_SZ_BYTES(detach_from_mcg_in);
		DEVX_SET(detach_from_mcg_in, din, qpn,
			 DEVX_GET(attach_to_mcg_in, in, qpn));
		memcpy(DEVX_ADDR_OF(detach_from_mcg_in, din, multicast_gid),
		       DEVX_ADDR_OF(attach_to_mcg_in, in, multicast_gid),
		       DEVX_FLD_SZ_BYTES(attach_to_mcg_in, multicast_gid));
		DEVX_SET(detach_from_mcg_in, din, opcode,
			 MLX5_CMD_OP_DETACH_FROM_MCG);
		DEVX_SET(detach_from_mcg_in, din, qpn, *obj_id);
		break;
	case MLX5_CMD_OP_ALLOC_XRCD:
		DEVX_SET(dealloc_xrcd_in, din, opcode,
			 MLX5_CMD_OP_DEALLOC_XRCD);
		DEVX_SET(dealloc_xrcd_in, din, xrcd, *obj_id);
		break;
	case MLX5_CMD_OP_CREATE_PSV:
		DEVX_SET(destroy_psv_in, din, opcode,
			 MLX5_CMD_OP_DESTROY_PSV);
		DEVX_SET(destroy_psv_in, din, psvn, *obj_id);
		break;
	default:
		/* The entry must match to one of the devx_is_obj_create_cmd */
		assert(false);
		break;
	}
}

static struct mlx5dv_devx_obj *
vfio_devx_obj_create(struct ibv_context *context, const void *in,
		     size_t inlen, void *out, size_t outlen)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(context);
	struct mlx5_devx_obj *obj;
	int ret;

	if (!devx_is_obj_create_cmd(in)) {
		errno = EINVAL;
		return NULL;
	}

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	ret = mlx5_vfio_cmd_exec(ctx, (void *)in, inlen, out, outlen, 0);
	if (ret)
		goto fail;

	devx_obj_build_destroy_cmd(in, out, obj->dinbox,
				   &obj->dinlen, &obj->dv_obj);
	obj->dv_obj.context = context;

	return &obj->dv_obj;
fail:
	free(obj);
	return NULL;
}

static int vfio_devx_obj_query(struct mlx5dv_devx_obj *obj, const void *in,
				size_t inlen, void *out, size_t outlen)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(obj->context);

	return mlx5_vfio_cmd_exec(ctx, (void *)in, inlen, out, outlen, 0);
}

static int vfio_devx_obj_modify(struct mlx5dv_devx_obj *obj, const void *in,
				size_t inlen, void *out, size_t outlen)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(obj->context);

	return mlx5_vfio_cmd_exec(ctx, (void *)in, inlen, out, outlen, 0);
}

static int vfio_devx_obj_destroy(struct mlx5dv_devx_obj *obj)
{
	struct mlx5_devx_obj *mobj = container_of(obj,
						  struct mlx5_devx_obj, dv_obj);
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(obj->context);
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)];
	int ret;

	ret = mlx5_vfio_cmd_exec(ctx, mobj->dinbox, mobj->dinlen,
				 out, sizeof(out), 0);
	if (ret)
		return ret;

	free(mobj);
	return 0;
}

static struct mlx5_dv_context_ops mlx5_vfio_dv_ctx_ops = {
	.devx_general_cmd = vfio_devx_general_cmd,
	.devx_obj_create = vfio_devx_obj_create,
	.devx_obj_query = vfio_devx_obj_query,
	.devx_obj_modify = vfio_devx_obj_modify,
	.devx_obj_destroy = vfio_devx_obj_destroy,
	.devx_query_eqn = vfio_devx_query_eqn,
	.devx_alloc_uar = vfio_devx_alloc_uar,
	.devx_free_uar = vfio_devx_free_uar,
	.devx_umem_reg = vfio_devx_umem_reg,
	.devx_umem_reg_ex = vfio_devx_umem_reg_ex,
	.devx_umem_dereg = vfio_devx_umem_dereg,
	.init_obj = vfio_init_obj,
};

static void mlx5_vfio_uninit_context(struct mlx5_vfio_context *ctx)
{
	mlx5_close_debug_file(ctx->dbg_fp);

	verbs_uninit_context(&ctx->vctx);
	free(ctx);
}

static void mlx5_vfio_free_context(struct ibv_context *ibctx)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);

	destroy_async_eqs(ctx);
	mlx5_vfio_teardown_hca(ctx);
	mlx5_vfio_clean_cmd_interface(ctx);
	mlx5_vfio_clean_device_dma(ctx);
	mlx5_vfio_uninit_bar0(ctx);
	mlx5_vfio_close_fds(ctx);
	mlx5_vfio_uninit_context(ctx);
}

static const struct verbs_context_ops mlx5_vfio_common_ops = {
	.alloc_pd = mlx5_vfio_alloc_pd,
	.dealloc_pd = mlx5_vfio_dealloc_pd,
	.reg_mr = mlx5_vfio_reg_mr,
	.dereg_mr = mlx5_vfio_dereg_mr,
	.free_context = mlx5_vfio_free_context,
};

static struct verbs_context *
mlx5_vfio_alloc_context(struct ibv_device *ibdev,
			int cmd_fd, void *private_data)
{
	struct mlx5_vfio_device *mdev = to_mvfio_dev(ibdev);
	struct mlx5_vfio_context *mctx;

	cmd_fd = -1;

	mctx = verbs_init_and_alloc_context(ibdev, cmd_fd, mctx, vctx,
					    RDMA_DRIVER_UNKNOWN);
	if (!mctx)
		return NULL;

	mlx5_open_debug_file(&mctx->dbg_fp);
	mlx5_set_debug_mask();

	if (mlx5_vfio_open_fds(mctx, mdev))
		goto err;

	if (mlx5_vfio_init_bar0(mctx))
		goto close_fds;

	if (mlx5_vfio_init_device_dma(mctx))
		goto err_bar;

	if (mlx5_vfio_init_cmd_interface(mctx))
		goto err_dma;

	if (mlx5_vfio_setup_function(mctx))
		goto clean_cmd;

	if (create_async_eqs(mctx))
		goto func_teardown;

	verbs_set_ops(&mctx->vctx, &mlx5_vfio_common_ops);
	mctx->dv_ctx_ops = &mlx5_vfio_dv_ctx_ops;

	/* For now only a singelton EQ is supported */
	mctx->vctx.context.num_comp_vectors = 1;

	return &mctx->vctx;

func_teardown:
	mlx5_vfio_teardown_hca(mctx);
clean_cmd:
	mlx5_vfio_clean_cmd_interface(mctx);
err_dma:
	mlx5_vfio_clean_device_dma(mctx);
err_bar:
	mlx5_vfio_uninit_bar0(mctx);
close_fds:
	mlx5_vfio_close_fds(mctx);
err:
	mlx5_vfio_uninit_context(mctx);
	return NULL;
}

static void mlx5_vfio_uninit_device(struct verbs_device *verbs_device)
{
	struct mlx5_vfio_device *dev = to_mvfio_dev(&verbs_device->device);

	free(dev->pci_name);
	free(dev);
}

static const struct verbs_device_ops mlx5_vfio_dev_ops = {
	.name = "mlx5_vfio",
	.alloc_context = mlx5_vfio_alloc_context,
	.uninit_device = mlx5_vfio_uninit_device,
};

static bool is_mlx5_pci(const char *pci_path)
{
	const struct verbs_match_ent *ent;
	uint16_t vendor_id, device_id;
	char pci_info_path[256];
	char buff[128];
	int fd;

	snprintf(pci_info_path, sizeof(pci_info_path), "%s/vendor", pci_path);
	fd = open(pci_info_path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read(fd, buff, sizeof(buff)) <= 0)
		goto err;

	vendor_id = strtoul(buff, NULL, 0);
	close(fd);

	snprintf(pci_info_path, sizeof(pci_info_path), "%s/device", pci_path);
	fd = open(pci_info_path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read(fd, buff, sizeof(buff)) <= 0)
		goto err;

	device_id = strtoul(buff, NULL, 0);
	close(fd);

	for (ent = mlx5_hca_table; ent->kind != VERBS_MATCH_SENTINEL; ent++) {
		if (ent->kind != VERBS_MATCH_PCI)
			continue;
		if (ent->device == device_id && ent->vendor == vendor_id)
			return true;
	}

	return false;

err:
	close(fd);
	return false;
}

static int mlx5_vfio_get_iommu_group_id(const char *pci_name)
{
	int seg, bus, slot, func;
	int ret, groupid;
	char path[128], iommu_group_path[128], *group_name;
	struct stat st;
	ssize_t len;

	ret = sscanf(pci_name, "%04x:%02x:%02x.%d", &seg, &bus, &slot, &func);
	if (ret != 4)
		return -1;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
		 seg, bus, slot, func);

	ret = stat(path, &st);
	if (ret < 0)
		return -1;

	if (!is_mlx5_pci(path))
		return -1;

	strncat(path, "iommu_group", sizeof(path) - strlen(path) - 1);

	len = readlink(path, iommu_group_path, sizeof(iommu_group_path));
	if (len <= 0)
		return -1;

	iommu_group_path[len] = 0;
	group_name = basename(iommu_group_path);

	if (sscanf(group_name, "%d", &groupid) != 1)
		return -1;

	snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
	ret = stat(path, &st);
	if (ret < 0)
		return -1;

	return groupid;
}

static int mlx5_vfio_get_handle(struct mlx5_vfio_device *vfio_dev,
			 struct mlx5dv_vfio_context_attr *attr)
{
	int iommu_group;

	iommu_group = mlx5_vfio_get_iommu_group_id(attr->pci_name);
	if (iommu_group < 0)
		return -1;

	sprintf(vfio_dev->vfio_path, "/dev/vfio/%d", iommu_group);
	vfio_dev->pci_name = strdup(attr->pci_name);

	return 0;
}

int mlx5dv_vfio_get_events_fd(struct ibv_context *ibctx)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);

	return ctx->cmd_comp_fd;
}

int mlx5dv_vfio_process_events(struct ibv_context *ibctx)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);
	uint64_t u;
	ssize_t s;

	mlx5_vfio_poll_health(ctx);

	/* read to re-arm the FD and process all existing events */
	s = read(ctx->cmd_comp_fd, &u, sizeof(uint64_t));
	if (s < 0 && errno != EAGAIN) {
		mlx5_err(ctx->dbg_fp, "%s, read failed, errno=%d\n",
			 __func__, errno);
		return errno;
	}

	return mlx5_vfio_process_async_events(ctx);
}

struct ibv_device **
mlx5dv_get_vfio_device_list(struct mlx5dv_vfio_context_attr *attr)
{
	struct mlx5_vfio_device *vfio_dev;
	struct ibv_device **list = NULL;
	int err;

	if (!check_comp_mask(attr->comp_mask, 0) ||
	    !check_comp_mask(attr->flags, MLX5DV_VFIO_CTX_FLAGS_INIT_LINK_DOWN)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	list = calloc(1, sizeof(struct ibv_device *));
	if (!list) {
		errno = ENOMEM;
		return NULL;
	}

	vfio_dev = calloc(1, sizeof(*vfio_dev));
	if (!vfio_dev) {
		errno = ENOMEM;
		goto end;
	}

	vfio_dev->vdev.ops = &mlx5_vfio_dev_ops;
	atomic_init(&vfio_dev->vdev.refcount, 1);

	/* Find the vfio handle for attrs, store in mlx5_vfio_device */
	err = mlx5_vfio_get_handle(vfio_dev, attr);
	if (err)
		goto err_get;

	vfio_dev->flags = attr->flags;
	vfio_dev->page_size = sysconf(_SC_PAGESIZE);
	atomic_init(&vfio_dev->mkey_var, 0);

	list[0] = &vfio_dev->vdev.device;
	return list;

err_get:
	free(vfio_dev);
end:
	free(list);
	return NULL;
}

bool is_mlx5_vfio_dev(struct ibv_device *device)
{
	struct verbs_device *verbs_device = verbs_get_device(device);

	return verbs_device->ops == &mlx5_vfio_dev_ops;
}
