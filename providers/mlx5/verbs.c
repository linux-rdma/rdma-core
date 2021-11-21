/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
 * Copyright (c) 2020 Intel Corporation.  All rights reserved.
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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ccan/array_size.h>

#include <util/compiler.h>
#include <util/mmio.h>
#include <util/util.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/mlx5_user_ioctl_cmds.h>
#include <infiniband/cmd_write.h>

#include "mlx5.h"
#include "mlx5-abi.h"
#include "wqe.h"
#include "mlx5_ifc.h"

int mlx5_single_threaded = 0;

static inline int is_xrc_tgt(int type)
{
	return type == IBV_QPT_XRC_RECV;
}

static int mlx5_read_clock(struct ibv_context *context, uint64_t *cycles)
{
	unsigned int clockhi, clocklo, clockhi1;
	int i;
	struct mlx5_context *ctx = to_mctx(context);

	if (!ctx->hca_core_clock)
		return EOPNOTSUPP;

	/* Handle wraparound */
	for (i = 0; i < 2; i++) {
		clockhi = be32toh(mmio_read32_be(ctx->hca_core_clock));
		clocklo = be32toh(mmio_read32_be(ctx->hca_core_clock + 4));
		clockhi1 = be32toh(mmio_read32_be(ctx->hca_core_clock));
		if (clockhi == clockhi1)
			break;
	}

	*cycles = (uint64_t)clockhi << 32 | (uint64_t)clocklo;

	return 0;
}

int mlx5_query_rt_values(struct ibv_context *context,
			 struct ibv_values_ex *values)
{
	uint32_t comp_mask = 0;
	int err = 0;

	if (!check_comp_mask(values->comp_mask, IBV_VALUES_MASK_RAW_CLOCK))
		return EINVAL;

	if (values->comp_mask & IBV_VALUES_MASK_RAW_CLOCK) {
		uint64_t cycles;

		err = mlx5_read_clock(context, &cycles);
		if (!err) {
			values->raw_clock.tv_sec = 0;
			values->raw_clock.tv_nsec = cycles;
			comp_mask |= IBV_VALUES_MASK_RAW_CLOCK;
		}
	}

	values->comp_mask = comp_mask;

	return err;
}

int mlx5_query_port(struct ibv_context *context, uint8_t port,
		     struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}

void mlx5_async_event(struct ibv_context *context,
		      struct ibv_async_event *event)
{
	struct mlx5_context *ctx;

	switch (event->event_type) {
	case IBV_EVENT_DEVICE_FATAL:
		ctx = to_mctx(context);
		ctx->flags |= MLX5_CTX_FLAGS_FATAL_STATE;
		break;
	default:
		break;
	}
}

struct ibv_pd *mlx5_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd       cmd;
	struct mlx5_alloc_pd_resp resp;
	struct mlx5_pd		 *pd;

	pd = calloc(1, sizeof *pd);
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd, sizeof cmd,
			     &resp.ibv_resp, sizeof resp)) {
		free(pd);
		return NULL;
	}

	atomic_init(&pd->refcount, 1);
	pd->pdn = resp.pdn;
	pthread_mutex_init(&pd->opaque_mr_mutex, NULL);

	return &pd->ibv_pd;
}

static void mlx5_free_uar(struct ibv_context *ctx,
			  struct mlx5_bf *bf)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_UAR,
			       MLX5_IB_METHOD_UAR_OBJ_DESTROY,
			       1);

	if (!bf->length)
		goto end;

	if (bf->mmaped_entry && munmap(bf->uar, bf->length))
		assert(false);

	if (!bf->dyn_alloc_uar)
		goto end;

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_UAR_OBJ_DESTROY_HANDLE, bf->uar_handle);
	if (execute_ioctl(ctx, cmd))
		assert(false);

end:
	free(bf);
}

static struct mlx5_bf *
mlx5_alloc_dyn_uar(struct ibv_context *context, uint32_t flags)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_UAR,
			       MLX5_IB_METHOD_UAR_OBJ_ALLOC,
			       5);

	struct ib_uverbs_attr *handle;
	struct mlx5_context *ctx = to_mctx(context);
	struct mlx5_bf *bf;
	bool legacy_mode = false;
	off_t offset;
	int ret;

	if (ctx->flags & MLX5_CTX_FLAGS_NO_KERN_DYN_UAR) {
		if (flags == MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC) {
			errno = EOPNOTSUPP;
			return NULL;
		}

		if (ctx->curr_legacy_dyn_sys_uar_page >
			ctx->max_num_legacy_dyn_uar_sys_page) {
			errno = ENOSPC;
			return NULL;
		}

		legacy_mode = true;
	}

	bf = calloc(1, sizeof(*bf));
	if (!bf) {
		errno = ENOMEM;
		return NULL;
	}

	if (legacy_mode) {
		struct mlx5_device *dev = to_mdev(context->device);

		offset = get_uar_mmap_offset(ctx->curr_legacy_dyn_sys_uar_page, dev->page_size,
				   MLX5_IB_MMAP_ALLOC_WC);
		bf->length = dev->page_size;
		goto do_mmap;
	}

	bf->dyn_alloc_uar = true;
	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE);
	fill_attr_const_in(cmd, MLX5_IB_ATTR_UAR_OBJ_ALLOC_TYPE,
			   flags);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET,
			  &bf->uar_mmap_offset);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH, &bf->length);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID, &bf->page_id);

	ret = execute_ioctl(context, cmd);
	if (ret) {
		free(bf);
		return NULL;
	}

do_mmap:
	bf->uar = mmap(NULL, bf->length, PROT_WRITE, MAP_SHARED,
		       context->cmd_fd,
		       legacy_mode ? offset : bf->uar_mmap_offset);

	if (bf->uar == MAP_FAILED)
		goto err;

	bf->mmaped_entry = true;

	if (legacy_mode)
		ctx->curr_legacy_dyn_sys_uar_page++;
	else
		bf->uar_handle = read_attr_obj(MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE,
					       handle);

	bf->nc_mode = (flags == MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC);

	return bf;

err:
	mlx5_free_uar(context, bf);
	return NULL;
}

static void mlx5_insert_dyn_uuars(struct mlx5_context *ctx,
				 struct mlx5_bf *bf_uar)
{
	int index_in_uar, index_uar_in_page;
	int num_bfregs_per_page;
	struct list_head *head;
	struct mlx5_bf *bf = bf_uar;
	int j;

	num_bfregs_per_page = ctx->num_uars_per_page * MLX5_NUM_NON_FP_BFREGS_PER_UAR;
	if (bf_uar->qp_dedicated)
		head = &ctx->dyn_uar_qp_dedicated_list;
	else if (bf_uar->qp_shared)
		head = &ctx->dyn_uar_qp_shared_list;
	else
		head = &ctx->dyn_uar_bf_list;

	for (j = 0; j < num_bfregs_per_page; j++) {
		if (j != 0) {
			bf = calloc(1, sizeof(*bf));
			if (!bf)
				return;
		}

		index_uar_in_page = (j % num_bfregs_per_page) /
				    MLX5_NUM_NON_FP_BFREGS_PER_UAR;
		index_in_uar = j % MLX5_NUM_NON_FP_BFREGS_PER_UAR;
		bf->reg = bf_uar->uar + (index_uar_in_page * MLX5_ADAPTER_PAGE_SIZE) +
					 MLX5_BF_OFFSET + (index_in_uar * ctx->bf_reg_size);
		bf->buf_size = bf_uar->nc_mode ? 0 : ctx->bf_reg_size / 2;
		/* set to non zero is BF entry, will be detected as part of post_send */
		bf->uuarn = bf_uar->nc_mode ? 0 : 1;
		list_node_init(&bf->uar_entry);
		list_add_tail(head, &bf->uar_entry);
		if (!bf_uar->dyn_alloc_uar)
			bf->bfreg_dyn_index = (ctx->curr_legacy_dyn_sys_uar_page - 1) * num_bfregs_per_page + j;
		bf->dyn_alloc_uar = bf_uar->dyn_alloc_uar;
		bf->need_lock = bf_uar->qp_shared && !mlx5_single_threaded;
		mlx5_spinlock_init(&bf->lock, bf->need_lock);
		if (j != 0) {
			bf->uar = bf_uar->uar;
			bf->page_id = bf_uar->page_id + index_uar_in_page;
			bf->uar_handle = bf_uar->uar_handle;
			bf->nc_mode = bf_uar->nc_mode;
			if (bf_uar->dyn_alloc_uar)
				bf->uar_mmap_offset = bf_uar->uar_mmap_offset;
		}
		if (bf_uar->qp_dedicated) {
			ctx->qp_alloc_dedicated_uuars++;
			bf->qp_dedicated = true;
		} else if (bf_uar->qp_shared) {
			ctx->qp_alloc_shared_uuars++;
			bf->qp_shared = true;
		}
	}
}

static void mlx5_put_qp_uar(struct mlx5_context *ctx, struct mlx5_bf *bf)
{
	if (!bf || (!bf->qp_dedicated && !bf->qp_shared))
		return;

	pthread_mutex_lock(&ctx->dyn_bfregs_mutex);
	if (bf->qp_dedicated)
		list_add_tail(&ctx->dyn_uar_qp_dedicated_list,
			      &bf->uar_entry);
	else
		bf->count--;
	pthread_mutex_unlock(&ctx->dyn_bfregs_mutex);
}

static int mlx5_alloc_qp_uar(struct ibv_context *context, bool dedicated)
{
	struct mlx5_context *ctx = to_mctx(context);
	struct mlx5_bf *bf;

	bf = mlx5_alloc_dyn_uar(context, MLX5_IB_UAPI_UAR_ALLOC_TYPE_BF);
	if (!bf)
		return -1;

	if (dedicated)
		bf->qp_dedicated = true;
	else
		bf->qp_shared = true;

	mlx5_insert_dyn_uuars(ctx, bf);
	return 0;
}

static struct mlx5_bf *mlx5_get_qp_uar(struct ibv_context *context)
{
	struct mlx5_context *ctx = to_mctx(context);
	struct mlx5_bf *bf = NULL, *bf_entry;

	if (ctx->shut_up_bf || !ctx->bf_reg_size)
		return ctx->nc_uar;

	pthread_mutex_lock(&ctx->dyn_bfregs_mutex);
	do {
		bf = list_pop(&ctx->dyn_uar_qp_dedicated_list, struct mlx5_bf, uar_entry);
		if (bf)
			break;

		if (ctx->qp_alloc_dedicated_uuars < ctx->qp_max_dedicated_uuars) {
			if (mlx5_alloc_qp_uar(context, true))
				break;
			continue;
		}

		if (ctx->qp_alloc_shared_uuars < ctx->qp_max_shared_uuars) {
			if (mlx5_alloc_qp_uar(context, false))
				break;
		}

		/* Looking for a shared uuar with the less concurrent usage */
		list_for_each(&ctx->dyn_uar_qp_shared_list, bf_entry, uar_entry) {
			if (!bf) {
				bf = bf_entry;
			} else {
				if (bf_entry->count < bf->count)
					bf = bf_entry;
			}
		}
		bf->count++;
	} while (!bf);

	pthread_mutex_unlock(&ctx->dyn_bfregs_mutex);
	return bf;
}

/* Returns a dedicated UAR */
static struct mlx5_bf *mlx5_attach_dedicated_uar(struct ibv_context *context,
						 uint32_t flags)
{
	struct mlx5_context *ctx = to_mctx(context);
	struct mlx5_bf *bf;
	struct list_head *head;

	pthread_mutex_lock(&ctx->dyn_bfregs_mutex);
	head = &ctx->dyn_uar_bf_list;
	bf = list_pop(head, struct mlx5_bf, uar_entry);
	if (!bf) {
		bf = mlx5_alloc_dyn_uar(context, flags);
		if (!bf)
			goto end;
		mlx5_insert_dyn_uuars(ctx, bf);
		bf = list_pop(head, struct mlx5_bf, uar_entry);
		assert(bf);
	}
end:
	pthread_mutex_unlock(&ctx->dyn_bfregs_mutex);
	return bf;
}

static void mlx5_detach_dedicated_uar(struct ibv_context *context, struct mlx5_bf *bf)
{
	struct mlx5_context *ctx = to_mctx(context);

	pthread_mutex_lock(&ctx->dyn_bfregs_mutex);
	list_add_tail(&ctx->dyn_uar_bf_list,
		      &bf->uar_entry);
	pthread_mutex_unlock(&ctx->dyn_bfregs_mutex);
	return;
}

struct ibv_td *mlx5_alloc_td(struct ibv_context *context, struct ibv_td_init_attr *init_attr)
{
	struct mlx5_td	*td;

	if (init_attr->comp_mask) {
		errno = EINVAL;
		return NULL;
	}

	td = calloc(1, sizeof(*td));
	if (!td) {
		errno = ENOMEM;
		return NULL;
	}

	td->bf = mlx5_attach_dedicated_uar(context, 0);
	if (!td->bf) {
		free(td);
		return NULL;
	}

	td->ibv_td.context = context;
	atomic_init(&td->refcount, 1);

	return &td->ibv_td;
}

int mlx5_dealloc_td(struct ibv_td *ib_td)
{
	struct mlx5_td	*td;

	td = to_mtd(ib_td);
	if (atomic_load(&td->refcount) > 1)
		return EBUSY;

	mlx5_detach_dedicated_uar(ib_td->context, td->bf);
	free(td);

	return 0;
}


void mlx5_set_singleton_nc_uar(struct ibv_context *context)
{

	struct mlx5_context *ctx = to_mctx(context);
	struct mlx5_devx_uar *devx_uar;

	ctx->nc_uar = mlx5_alloc_dyn_uar(context,
					 MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC);
	if (!ctx->nc_uar)
		return;

	ctx->nc_uar->reg = ctx->nc_uar->uar + MLX5_BF_OFFSET;

	/* set the singleton devx NC UAR fields */
	devx_uar = &ctx->nc_uar->devx_uar;
	devx_uar->dv_devx_uar.reg_addr = ctx->nc_uar->reg;
	devx_uar->dv_devx_uar.base_addr = ctx->nc_uar->uar;
	devx_uar->dv_devx_uar.page_id = ctx->nc_uar->page_id;
	devx_uar->dv_devx_uar.mmap_off = ctx->nc_uar->uar_mmap_offset;
	devx_uar->dv_devx_uar.comp_mask = 0;
	devx_uar->context = context;
}

static struct mlx5dv_devx_uar *
mlx5_get_singleton_nc_uar(struct ibv_context *context)
{
	struct mlx5_context *ctx = to_mctx(context);

	if (!ctx->nc_uar) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return &ctx->nc_uar->devx_uar.dv_devx_uar;
}

struct ibv_pd *
mlx5_alloc_parent_domain(struct ibv_context *context,
			 struct ibv_parent_domain_init_attr *attr)
{
	struct mlx5_parent_domain *mparent_domain;

	if (ibv_check_alloc_parent_domain(attr))
		return NULL;

	if (!check_comp_mask(attr->comp_mask,
			     IBV_PARENT_DOMAIN_INIT_ATTR_ALLOCATORS |
			     IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT)) {
		errno = EINVAL;
		return NULL;
	}

	mparent_domain = calloc(1, sizeof(*mparent_domain));
	if (!mparent_domain) {
		errno = ENOMEM;
		return NULL;
	}

	if (attr->td) {
		mparent_domain->mtd = to_mtd(attr->td);
		atomic_fetch_add(&mparent_domain->mtd->refcount, 1);
	}

	mparent_domain->mpd.mprotection_domain = to_mpd(attr->pd);
	atomic_fetch_add(&mparent_domain->mpd.mprotection_domain->refcount, 1);
	atomic_init(&mparent_domain->mpd.refcount, 1);

	ibv_initialize_parent_domain(
	    &mparent_domain->mpd.ibv_pd,
	    &mparent_domain->mpd.mprotection_domain->ibv_pd);

	if (attr->comp_mask & IBV_PARENT_DOMAIN_INIT_ATTR_ALLOCATORS) {
		mparent_domain->alloc = attr->alloc;
		mparent_domain->free = attr->free;
	}

	if (attr->comp_mask & IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT)
		mparent_domain->pd_context = attr->pd_context;

	return &mparent_domain->mpd.ibv_pd;
}

static int mlx5_dealloc_parent_domain(struct mlx5_parent_domain *mparent_domain)
{
	if (atomic_load(&mparent_domain->mpd.refcount) > 1)
		return EBUSY;

	atomic_fetch_sub(&mparent_domain->mpd.mprotection_domain->refcount, 1);

	if (mparent_domain->mtd)
		atomic_fetch_sub(&mparent_domain->mtd->refcount, 1);

	free(mparent_domain);
	return 0;
}

static int _mlx5_free_pd(struct ibv_pd *pd, bool unimport)
{
	int ret;
	struct mlx5_parent_domain *mparent_domain = to_mparent_domain(pd);
	struct mlx5_pd *mpd = to_mpd(pd);

	if (mparent_domain) {
		if (unimport)
			return EINVAL;

		return mlx5_dealloc_parent_domain(mparent_domain);
	}

	if (atomic_load(&mpd->refcount) > 1)
		return EBUSY;

	if (mpd->opaque_mr) {
		ret = mlx5_dereg_mr(verbs_get_mr(mpd->opaque_mr));
		if (ret)
			return ret;

		mpd->opaque_mr = NULL;
		free(mpd->opaque_buf);
	}

	if (unimport)
		goto end;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

end:
	free(mpd);
	return 0;
}

int mlx5_free_pd(struct ibv_pd *pd)
{
	return _mlx5_free_pd(pd, false);
}

struct ibv_mr *mlx5_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			   uint64_t hca_va, int acc)
{
	struct mlx5_mr *mr;
	struct ibv_reg_mr cmd;
	int ret;
	enum ibv_access_flags access = (enum ibv_access_flags)acc;
	struct ib_uverbs_reg_mr_resp resp;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, &mr->vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(mr);
		return NULL;
	}
	mr->alloc_flags = acc;

	return &mr->vmr.ibv_mr;
}

struct ibv_mr *mlx5_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset, size_t length,
				  uint64_t iova, int fd, int acc)
{
	struct mlx5_mr *mr;
	int ret;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	ret = ibv_cmd_reg_dmabuf_mr(pd, offset, length, iova, fd, acc,
				    &mr->vmr);
	if (ret) {
		free(mr);
		return NULL;
	}
	mr->alloc_flags = acc;

	return &mr->vmr.ibv_mr;
}

struct ibv_mr *mlx5_alloc_null_mr(struct ibv_pd *pd)
{
	struct mlx5_mr *mr;
	struct mlx5_context *ctx = to_mctx(pd->context);

	if (ctx->dump_fill_mkey == MLX5_INVALID_LKEY) {
		errno = ENOTSUP;
		return NULL;
	}

	mr = calloc(1, sizeof(*mr));
	if (!mr) {
		errno = ENOMEM;
		return NULL;
	}

	mr->vmr.ibv_mr.lkey = ctx->dump_fill_mkey;

	mr->vmr.ibv_mr.context = pd->context;
	mr->vmr.ibv_mr.pd      = pd;
	mr->vmr.ibv_mr.addr    = NULL;
	mr->vmr.ibv_mr.length  = SIZE_MAX;
	mr->vmr.mr_type = IBV_MR_TYPE_NULL_MR;

	return &mr->vmr.ibv_mr;
}

enum {
	MLX5_DM_ALLOWED_ACCESS = IBV_ACCESS_LOCAL_WRITE		|
				 IBV_ACCESS_REMOTE_WRITE	|
				 IBV_ACCESS_REMOTE_READ		|
				 IBV_ACCESS_REMOTE_ATOMIC	|
				 IBV_ACCESS_ZERO_BASED		|
				 IBV_ACCESS_OPTIONAL_RANGE
};

struct ibv_mr *mlx5_reg_dm_mr(struct ibv_pd *pd, struct ibv_dm *ibdm,
			      uint64_t dm_offset, size_t length,
			      unsigned int acc)
{
	struct mlx5_dm *dm = to_mdm(ibdm);
	struct mlx5_mr *mr;
	int ret;

	if (acc & ~MLX5_DM_ALLOWED_ACCESS) {
		errno = EINVAL;
		return NULL;
	}

	mr = calloc(1, sizeof(*mr));
	if (!mr) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ibv_cmd_reg_dm_mr(pd, &dm->verbs_dm, dm_offset, length, acc,
				&mr->vmr, NULL);
	if (ret) {
		free(mr);
		return NULL;
	}

	mr->alloc_flags = acc;

	return &mr->vmr.ibv_mr;
}

int mlx5_rereg_mr(struct verbs_mr *vmr, int flags, struct ibv_pd *pd,
		  void *addr, size_t length, int access)
{
	struct ibv_rereg_mr cmd;
	struct ib_uverbs_rereg_mr_resp resp;

	return ibv_cmd_rereg_mr(vmr, flags, addr, length, (uintptr_t)addr,
				access, pd, &cmd, sizeof(cmd), &resp,
				sizeof(resp));
}

int mlx5_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	if (vmr->mr_type == IBV_MR_TYPE_NULL_MR)
		goto free;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

free:
	free(vmr);
	return 0;
}

int mlx5_advise_mr(struct ibv_pd *pd,
		   enum ibv_advise_mr_advice advice,
		   uint32_t flags,
		   struct ibv_sge *sg_list,
		   uint32_t num_sge)
{
	return ibv_cmd_advise_mr(pd, advice, flags, sg_list, num_sge);
}

struct ibv_pd *mlx5_import_pd(struct ibv_context *context,
			      uint32_t pd_handle)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       UVERBS_OBJECT_PD,
			       MLX5_IB_METHOD_PD_QUERY,
			       2);

	struct mlx5_pd *pd;
	int ret;

	pd = calloc(1, sizeof *pd);
	if (!pd)
		return NULL;

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_QUERY_PD_HANDLE, pd_handle);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_QUERY_PD_RESP_PDN, &pd->pdn);

	ret = execute_ioctl(context, cmd);
	if (ret) {
		free(pd);
		return NULL;
	}

	pd->ibv_pd.context = context;
	pd->ibv_pd.handle = pd_handle;
	atomic_init(&pd->refcount, 1);
	pthread_mutex_init(&pd->opaque_mr_mutex, NULL);

	return &pd->ibv_pd;
}

void mlx5_unimport_pd(struct ibv_pd *pd)
{
	if (_mlx5_free_pd(pd, true))
		assert(false);
}

struct ibv_mr *mlx5_import_mr(struct ibv_pd *pd,
			      uint32_t mr_handle)
{
	struct mlx5_mr *mr;
	int ret;

	mr = calloc(1, sizeof *mr);
	if (!mr)
		return NULL;

	ret = ibv_cmd_query_mr(pd, &mr->vmr, mr_handle);
	if (ret) {
		free(mr);
		return NULL;
	}

	return &mr->vmr.ibv_mr;
}

void mlx5_unimport_mr(struct ibv_mr *ibmr)
{
	free(to_mmr(ibmr));
}

struct ibv_mw *mlx5_alloc_mw(struct ibv_pd *pd, enum ibv_mw_type type)
{
	struct ibv_mw *mw;
	struct ibv_alloc_mw cmd;
	struct ib_uverbs_alloc_mw_resp resp;
	int ret;

	mw = malloc(sizeof(*mw));
	if (!mw)
		return NULL;

	memset(mw, 0, sizeof(*mw));

	ret = ibv_cmd_alloc_mw(pd, type, mw, &cmd, sizeof(cmd), &resp,
			       sizeof(resp));
	if (ret) {
		free(mw);
		return NULL;
	}

	return mw;
}

int mlx5_dealloc_mw(struct ibv_mw *mw)
{
	int ret;

	ret = ibv_cmd_dealloc_mw(mw);
	if (ret)
		return ret;

	free(mw);
	return 0;
}

static int get_cqe_size(struct mlx5dv_cq_init_attr *mlx5cq_attr)
{
	char *env;
	int size = 64;

	if (mlx5cq_attr &&
	    (mlx5cq_attr->comp_mask & MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE)) {
		size = mlx5cq_attr->cqe_size;
	} else {
		env = getenv("MLX5_CQE_SIZE");
		if (env)
			size = atoi(env);
	}

	switch (size) {
	case 64:
	case 128:
		return size;

	default:
		return -EINVAL;
	}
}

static int use_scatter_to_cqe(void)
{
	char *env;

	env = getenv("MLX5_SCATTER_TO_CQE");
	if (env && !strcmp(env, "0"))
		return 0;

	return 1;
}

static int srq_sig_enabled(void)
{
	char *env;

	env = getenv("MLX5_SRQ_SIGNATURE");
	if (env)
		return 1;

	return 0;
}

static int qp_sig_enabled(void)
{
	char *env;

	env = getenv("MLX5_QP_SIGNATURE");
	if (env)
		return 1;

	return 0;
}

enum {
	CREATE_CQ_SUPPORTED_WC_FLAGS = IBV_WC_STANDARD_FLAGS	|
				       IBV_WC_EX_WITH_COMPLETION_TIMESTAMP |
				       IBV_WC_EX_WITH_CVLAN |
				       IBV_WC_EX_WITH_FLOW_TAG |
				       IBV_WC_EX_WITH_TM_INFO |
				       IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK
};

enum {
	CREATE_CQ_SUPPORTED_COMP_MASK = IBV_CQ_INIT_ATTR_MASK_FLAGS |
					IBV_CQ_INIT_ATTR_MASK_PD
};

enum {
	CREATE_CQ_SUPPORTED_FLAGS =
		IBV_CREATE_CQ_ATTR_SINGLE_THREADED |
		IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN
};

enum {
	MLX5_DV_CREATE_CQ_SUP_COMP_MASK =
		(MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE |
		 MLX5DV_CQ_INIT_ATTR_MASK_FLAGS |
		 MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE),
};

static struct ibv_cq_ex *create_cq(struct ibv_context *context,
				   const struct ibv_cq_init_attr_ex *cq_attr,
				   int cq_alloc_flags,
				   struct mlx5dv_cq_init_attr *mlx5cq_attr)
{
	struct mlx5_create_cq_ex	cmd_ex = {};
	struct mlx5_create_cq_ex_resp	resp_ex = {};
	struct mlx5_ib_create_cq       *cmd_drv;
	struct mlx5_ib_create_cq_resp  *resp_drv;
	struct mlx5_cq		       *cq;
	int				cqe_sz;
	int				ret;
	int				ncqe;
	int				rc;
	struct mlx5_context *mctx = to_mctx(context);
	FILE *fp = to_mctx(context)->dbg_fp;

	if (!cq_attr->cqe) {
		mlx5_dbg(fp, MLX5_DBG_CQ, "CQE invalid\n");
		errno = EINVAL;
		return NULL;
	}

	if (cq_attr->comp_mask & ~CREATE_CQ_SUPPORTED_COMP_MASK) {
		mlx5_dbg(fp, MLX5_DBG_CQ,
			 "Unsupported comp_mask for create_cq\n");
		errno = EINVAL;
		return NULL;
	}

	if (cq_attr->comp_mask & IBV_CQ_INIT_ATTR_MASK_FLAGS &&
	    cq_attr->flags & ~CREATE_CQ_SUPPORTED_FLAGS) {
		mlx5_dbg(fp, MLX5_DBG_CQ,
			 "Unsupported creation flags requested for create_cq\n");
		errno = EINVAL;
		return NULL;
	}

	if (cq_attr->wc_flags & ~CREATE_CQ_SUPPORTED_WC_FLAGS) {
		mlx5_dbg(fp, MLX5_DBG_CQ, "\n");
		errno = ENOTSUP;
		return NULL;
	}

	if (mlx5cq_attr &&
	    !check_comp_mask(mlx5cq_attr->comp_mask,
			     MLX5_DV_CREATE_CQ_SUP_COMP_MASK)) {
		mlx5_dbg(fp, MLX5_DBG_CQ,
			 "unsupported vendor comp_mask for %s\n", __func__);
		errno = EINVAL;
		return NULL;
	}

	cq =  calloc(1, sizeof *cq);
	if (!cq) {
		mlx5_dbg(fp, MLX5_DBG_CQ, "\n");
		return NULL;
	}

	if (cq_attr->comp_mask & IBV_CQ_INIT_ATTR_MASK_FLAGS) {
		if (cq_attr->flags & IBV_CREATE_CQ_ATTR_SINGLE_THREADED)
			cq->flags |= MLX5_CQ_FLAGS_SINGLE_THREADED;
	}

	if (cq_attr->comp_mask & IBV_CQ_INIT_ATTR_MASK_PD) {
		if (!(to_mparent_domain(cq_attr->parent_domain))) {
			errno = EINVAL;
			goto err;
		}
		cq->parent_domain = cq_attr->parent_domain;
	}

	if (cq_alloc_flags & MLX5_CQ_FLAGS_EXTENDED) {
		rc = mlx5_cq_fill_pfns(cq, cq_attr, mctx);
		if (rc) {
			errno = rc;
			goto err;
		}
	}

	cmd_drv = &cmd_ex.drv_payload;
	resp_drv = &resp_ex.drv_payload;
	cq->cons_index = 0;

	if (mlx5_spinlock_init(&cq->lock, !mlx5_single_threaded))
		goto err;

	ncqe = align_queue_size(cq_attr->cqe + 1);
	if ((ncqe > (1 << 24)) || (ncqe < (cq_attr->cqe + 1))) {
		mlx5_dbg(fp, MLX5_DBG_CQ, "ncqe %d\n", ncqe);
		errno = EINVAL;
		goto err_spl;
	}

	cqe_sz = get_cqe_size(mlx5cq_attr);
	if (cqe_sz < 0) {
		mlx5_dbg(fp, MLX5_DBG_CQ, "\n");
		errno = -cqe_sz;
		goto err_spl;
	}

	if (mlx5_alloc_cq_buf(to_mctx(context), cq, &cq->buf_a, ncqe, cqe_sz)) {
		mlx5_dbg(fp, MLX5_DBG_CQ, "\n");
		goto err_spl;
	}

	cq->dbrec  = mlx5_alloc_dbrec(to_mctx(context), cq->parent_domain,
				      &cq->custom_db);
	if (!cq->dbrec) {
		mlx5_dbg(fp, MLX5_DBG_CQ, "\n");
		goto err_buf;
	}

	cq->dbrec[MLX5_CQ_SET_CI]	= 0;
	cq->dbrec[MLX5_CQ_ARM_DB]	= 0;
	cq->arm_sn			= 0;
	cq->cqe_sz			= cqe_sz;
	cq->flags			= cq_alloc_flags;

	cmd_drv->buf_addr = (uintptr_t) cq->buf_a.buf;
	cmd_drv->db_addr  = (uintptr_t) cq->dbrec;
	cmd_drv->cqe_size = cqe_sz;

	if (mlx5cq_attr) {
		if (mlx5cq_attr->comp_mask & MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE) {
			if (mctx->cqe_comp_caps.max_num &&
			    (mlx5cq_attr->cqe_comp_res_format &
			     mctx->cqe_comp_caps.supported_format)) {
				cmd_drv->cqe_comp_en = 1;
				cmd_drv->cqe_comp_res_format = mlx5cq_attr->cqe_comp_res_format;
			} else {
				mlx5_dbg(fp, MLX5_DBG_CQ, "CQE Compression is not supported\n");
				errno = EINVAL;
				goto err_db;
			}
		}

		if (mlx5cq_attr->comp_mask & MLX5DV_CQ_INIT_ATTR_MASK_FLAGS) {
			if (mlx5cq_attr->flags & ~(MLX5DV_CQ_INIT_ATTR_FLAGS_RESERVED - 1)) {
				mlx5_dbg(fp, MLX5_DBG_CQ,
					 "Unsupported vendor flags for create_cq\n");
				errno = EINVAL;
				goto err_db;
			}

			if (mlx5cq_attr->flags & MLX5DV_CQ_INIT_ATTR_FLAGS_CQE_PAD) {
				if (!(mctx->vendor_cap_flags &
				      MLX5_VENDOR_CAP_FLAGS_CQE_128B_PAD) ||
				    (cqe_sz != 128)) {
					mlx5_dbg(fp, MLX5_DBG_CQ,
						 "%dB CQE paddind is not supported\n",
						 cqe_sz);
					errno = EINVAL;
					goto err_db;
				}

				cmd_drv->flags |= MLX5_IB_CREATE_CQ_FLAGS_CQE_128B_PAD;
			}
		}
	}

	if (mctx->flags & MLX5_CTX_FLAGS_REAL_TIME_TS_SUPPORTED &&
	    !(cq_attr->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP) &&
	    cq_attr->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK)
		cmd_drv->flags |= MLX5_IB_CREATE_CQ_FLAGS_REAL_TIME_TS;

	if (mctx->nc_uar) {
		cmd_drv->flags |= MLX5_IB_CREATE_CQ_FLAGS_UAR_PAGE_INDEX;
		cmd_drv->uar_page_index = mctx->nc_uar->page_id;
	}

	{
		struct ibv_cq_init_attr_ex cq_attr_ex = *cq_attr;

		cq_attr_ex.cqe = ncqe - 1;
		ret = ibv_cmd_create_cq_ex(context, &cq_attr_ex, &cq->verbs_cq,
					   &cmd_ex.ibv_cmd, sizeof(cmd_ex),
					   &resp_ex.ibv_resp, sizeof(resp_ex),
					   CREATE_CQ_CMD_FLAGS_TS_IGNORED_EX);
	}

	if (ret) {
		mlx5_dbg(fp, MLX5_DBG_CQ, "ret %d\n", ret);
		goto err_db;
	}

	if (cq->parent_domain)
		atomic_fetch_add(&to_mparent_domain(cq->parent_domain)->mpd.refcount, 1);
	cq->active_buf = &cq->buf_a;
	cq->resize_buf = NULL;
	cq->cqn = resp_drv->cqn;
	cq->stall_enable = to_mctx(context)->stall_enable;
	cq->stall_adaptive_enable = to_mctx(context)->stall_adaptive_enable;
	cq->stall_cycles = to_mctx(context)->stall_cycles;

	return &cq->verbs_cq.cq_ex;

err_db:
	mlx5_free_db(to_mctx(context), cq->dbrec, cq->parent_domain, cq->custom_db);

err_buf:
	mlx5_free_cq_buf(to_mctx(context), &cq->buf_a);

err_spl:
	mlx5_spinlock_destroy(&cq->lock);

err:
	free(cq);

	return NULL;
}

struct ibv_cq *mlx5_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel,
			      int comp_vector)
{
	struct ibv_cq_ex *cq;
	struct ibv_cq_init_attr_ex cq_attr = {.cqe = cqe, .channel = channel,
						.comp_vector = comp_vector,
						.wc_flags = IBV_WC_STANDARD_FLAGS};

	if (cqe <= 0) {
		errno = EINVAL;
		return NULL;
	}

	cq = create_cq(context, &cq_attr, 0, NULL);
	return cq ? ibv_cq_ex_to_cq(cq) : NULL;
}

struct ibv_cq_ex *mlx5_create_cq_ex(struct ibv_context *context,
				    struct ibv_cq_init_attr_ex *cq_attr)
{
	return create_cq(context, cq_attr, MLX5_CQ_FLAGS_EXTENDED, NULL);
}

static struct ibv_cq_ex *_mlx5dv_create_cq(struct ibv_context *context,
					   struct ibv_cq_init_attr_ex *cq_attr,
					   struct mlx5dv_cq_init_attr *mlx5_cq_attr)
{
	struct ibv_cq_ex *cq;

	cq = create_cq(context, cq_attr, MLX5_CQ_FLAGS_EXTENDED, mlx5_cq_attr);
	if (!cq)
		return NULL;

	verbs_init_cq(ibv_cq_ex_to_cq(cq), context,
		      cq_attr->channel, cq_attr->cq_context);
	return cq;
}

struct ibv_cq_ex *mlx5dv_create_cq(struct ibv_context *context,
				      struct ibv_cq_init_attr_ex *cq_attr,
				      struct mlx5dv_cq_init_attr *mlx5_cq_attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->create_cq) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_cq(context, cq_attr, mlx5_cq_attr);
}

int mlx5_resize_cq(struct ibv_cq *ibcq, int cqe)
{
	struct mlx5_cq *cq = to_mcq(ibcq);
	struct mlx5_resize_cq_resp resp;
	struct mlx5_resize_cq cmd;
	struct mlx5_context *mctx = to_mctx(ibcq->context);
	int err;

	if (cqe < 0) {
		errno = EINVAL;
		return errno;
	}

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	if (((long long)cqe * 64) > INT_MAX)
		return EINVAL;

	mlx5_spin_lock(&cq->lock);
	cq->active_cqes = cq->verbs_cq.cq.cqe;
	if (cq->active_buf == &cq->buf_a)
		cq->resize_buf = &cq->buf_b;
	else
		cq->resize_buf = &cq->buf_a;

	cqe = align_queue_size(cqe + 1);
	if (cqe == ibcq->cqe + 1) {
		cq->resize_buf = NULL;
		err = 0;
		goto out;
	}

	/* currently we don't change cqe size */
	cq->resize_cqe_sz = cq->cqe_sz;
	cq->resize_cqes = cqe;
	err = mlx5_alloc_cq_buf(mctx, cq, cq->resize_buf, cq->resize_cqes, cq->resize_cqe_sz);
	if (err) {
		cq->resize_buf = NULL;
		errno = ENOMEM;
		goto out;
	}

	cmd.buf_addr = (uintptr_t)cq->resize_buf->buf;
	cmd.cqe_size = cq->resize_cqe_sz;

	err = ibv_cmd_resize_cq(ibcq, cqe - 1, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (err)
		goto out_buf;

	mlx5_cq_resize_copy_cqes(mctx, cq);
	mlx5_free_cq_buf(mctx, cq->active_buf);
	cq->active_buf = cq->resize_buf;
	cq->verbs_cq.cq.cqe = cqe - 1;
	mlx5_spin_unlock(&cq->lock);
	cq->resize_buf = NULL;
	return 0;

out_buf:
	mlx5_free_cq_buf(mctx, cq->resize_buf);
	cq->resize_buf = NULL;

out:
	mlx5_spin_unlock(&cq->lock);
	return err;
}

int mlx5_destroy_cq(struct ibv_cq *cq)
{
	int ret;
	struct mlx5_cq *mcq = to_mcq(cq);

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	mlx5_free_db(to_mctx(cq->context), mcq->dbrec, mcq->parent_domain,
		     mcq->custom_db);
	mlx5_free_cq_buf(to_mctx(cq->context), mcq->active_buf);
	if (mcq->parent_domain)
		atomic_fetch_sub(&to_mparent_domain(mcq->parent_domain)->mpd.refcount, 1);
	free(mcq);

	return 0;
}

struct ibv_srq *mlx5_create_srq(struct ibv_pd *pd,
				struct ibv_srq_init_attr *attr)
{
	struct mlx5_create_srq      cmd;
	struct mlx5_create_srq_resp resp;
	struct mlx5_srq		   *srq;
	int			    ret;
	struct mlx5_context	   *ctx;
	int			    max_sge;
	struct ibv_srq		   *ibsrq;

	ctx = to_mctx(pd->context);
	srq = calloc(1, sizeof *srq);
	if (!srq) {
		mlx5_err(ctx->dbg_fp, "%s-%d:\n", __func__, __LINE__);
		return NULL;
	}
	ibsrq = &srq->vsrq.srq;

	memset(&cmd, 0, sizeof cmd);
	if (mlx5_spinlock_init_pd(&srq->lock, pd)) {
		mlx5_err(ctx->dbg_fp, "%s-%d:\n", __func__, __LINE__);
		goto err;
	}

	if (attr->attr.max_wr > ctx->max_srq_recv_wr) {
		mlx5_err(ctx->dbg_fp, "%s-%d:max_wr %d, max_srq_recv_wr %d\n", __func__, __LINE__,
			 attr->attr.max_wr, ctx->max_srq_recv_wr);
		errno = EINVAL;
		goto err;
	}

	/*
	 * this calculation does not consider required control segments. The
	 * final calculation is done again later. This is done so to avoid
	 * overflows of variables
	 */
	max_sge = ctx->max_rq_desc_sz / sizeof(struct mlx5_wqe_data_seg);
	if (attr->attr.max_sge > max_sge) {
		mlx5_err(ctx->dbg_fp, "%s-%d:max_wr %d, max_srq_recv_wr %d\n", __func__, __LINE__,
			attr->attr.max_wr, ctx->max_srq_recv_wr);
		errno = EINVAL;
		goto err;
	}

	srq->max_gs  = attr->attr.max_sge;
	srq->counter = 0;

	if (mlx5_alloc_srq_buf(pd->context, srq, attr->attr.max_wr, pd)) {
		mlx5_err(ctx->dbg_fp, "%s-%d:\n", __func__, __LINE__);
		goto err;
	}

	srq->db = mlx5_alloc_dbrec(to_mctx(pd->context), pd, &srq->custom_db);
	if (!srq->db) {
		mlx5_err(ctx->dbg_fp, "%s-%d:\n", __func__, __LINE__);
		goto err_free;
	}

	if (!srq->custom_db)
		*srq->db = 0;

	cmd.buf_addr = (uintptr_t) srq->buf.buf;
	cmd.db_addr  = (uintptr_t) srq->db;
	srq->wq_sig = srq_sig_enabled();
	if (srq->wq_sig)
		cmd.flags = MLX5_SRQ_FLAG_SIGNATURE;

	attr->attr.max_sge = srq->max_gs;
	pthread_mutex_lock(&ctx->srq_table_mutex);

	/* Override max_wr to let kernel know about extra WQEs for the
	 * wait queue.
	 */
	attr->attr.max_wr = srq->max - 1;

	ret = ibv_cmd_create_srq(pd, ibsrq, attr, &cmd.ibv_cmd, sizeof(cmd),
				 &resp.ibv_resp, sizeof(resp));
	if (ret)
		goto err_db;

	/* Override kernel response that includes the wait queue with the real
	 * number of WQEs that are applicable for the application.
	 */
	attr->attr.max_wr = srq->tail;

	ret = mlx5_store_srq(ctx, resp.srqn, srq);
	if (ret)
		goto err_destroy;

	pthread_mutex_unlock(&ctx->srq_table_mutex);

	srq->srqn = resp.srqn;
	srq->rsc.rsn = resp.srqn;
	srq->rsc.type = MLX5_RSC_TYPE_SRQ;

	return ibsrq;

err_destroy:
	ibv_cmd_destroy_srq(ibsrq);

err_db:
	pthread_mutex_unlock(&ctx->srq_table_mutex);
	mlx5_free_db(to_mctx(pd->context), srq->db, pd, srq->custom_db);

err_free:
	free(srq->wrid);
	mlx5_free_actual_buf(ctx, &srq->buf);

err:
	free(srq);

	return NULL;
}

int mlx5_modify_srq(struct ibv_srq *srq,
		    struct ibv_srq_attr *attr,
		    int attr_mask)
{
	struct ibv_modify_srq cmd;

	return ibv_cmd_modify_srq(srq, attr, attr_mask, &cmd, sizeof cmd);
}

int mlx5_query_srq(struct ibv_srq *srq,
		    struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(srq, attr, &cmd, sizeof cmd);
}

int mlx5_destroy_srq(struct ibv_srq *srq)
{
	int ret;
	struct mlx5_srq *msrq = to_msrq(srq);
	struct mlx5_context *ctx = to_mctx(srq->context);

	if (msrq->cmd_qp) {
		ret = mlx5_destroy_qp(msrq->cmd_qp);
		if (ret)
			return ret;
		msrq->cmd_qp = NULL;
	}

	ret = ibv_cmd_destroy_srq(srq);
	if (ret)
		return ret;

	if (ctx->cqe_version && msrq->rsc.type == MLX5_RSC_TYPE_XSRQ)
		mlx5_clear_uidx(ctx, msrq->rsc.rsn);
	else
		mlx5_clear_srq(ctx, msrq->srqn);

	mlx5_free_db(ctx, msrq->db, srq->pd, msrq->custom_db);
	mlx5_free_actual_buf(ctx, &msrq->buf);
	free(msrq->tm_list);
	free(msrq->wrid);
	free(msrq->op);
	free(msrq);

	return 0;
}

static int _sq_overhead(struct mlx5_qp *qp,
			enum ibv_qp_type qp_type,
			uint64_t ops,
			uint64_t mlx5_ops)
{
	size_t size = sizeof(struct mlx5_wqe_ctrl_seg);
	size_t rdma_size = 0;
	size_t atomic_size = 0;
	size_t mw_size = 0;

	/* Operation overhead */
	if (ops & (IBV_QP_EX_WITH_RDMA_WRITE |
		   IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM |
		   IBV_QP_EX_WITH_RDMA_READ))
		rdma_size = sizeof(struct mlx5_wqe_ctrl_seg) +
			    sizeof(struct mlx5_wqe_raddr_seg);

	if (ops & (IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP |
		   IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD))
		atomic_size = sizeof(struct mlx5_wqe_ctrl_seg) +
			      sizeof(struct mlx5_wqe_raddr_seg) +
			      sizeof(struct mlx5_wqe_atomic_seg);

	if (ops & (IBV_QP_EX_WITH_BIND_MW | IBV_QP_EX_WITH_LOCAL_INV) ||
	    (mlx5_ops & (MLX5DV_QP_EX_WITH_MR_INTERLEAVED |
			 MLX5DV_QP_EX_WITH_MR_LIST)))
		mw_size = sizeof(struct mlx5_wqe_ctrl_seg) +
			  sizeof(struct mlx5_wqe_umr_ctrl_seg) +
			  sizeof(struct mlx5_wqe_mkey_context_seg) +
			  max_t(size_t, sizeof(struct mlx5_wqe_umr_klm_seg), 64);

	size = max_t(size_t, size, rdma_size);
	size = max_t(size_t, size, atomic_size);
	size = max_t(size_t, size, mw_size);

	/* Transport overhead */
	switch (qp_type) {
	case IBV_QPT_DRIVER:
		if (qp->dc_type != MLX5DV_DCTYPE_DCI)
			return -EINVAL;
		SWITCH_FALLTHROUGH;

	case IBV_QPT_UD:
		size += sizeof(struct mlx5_wqe_datagram_seg);
		if (qp->flags & MLX5_QP_FLAGS_USE_UNDERLAY)
			size += sizeof(struct mlx5_wqe_eth_seg) +
				sizeof(struct mlx5_wqe_eth_pad);
		break;

	case IBV_QPT_XRC_RECV:
	case IBV_QPT_XRC_SEND:
		size += sizeof(struct mlx5_wqe_xrc_seg);
		break;

	case IBV_QPT_RAW_PACKET:
		size += sizeof(struct mlx5_wqe_eth_seg);
		break;

	case IBV_QPT_RC:
	case IBV_QPT_UC:
		break;

	default:
		return -EINVAL;
	}

	return size;
}

static int sq_overhead(struct mlx5_qp *qp, struct ibv_qp_init_attr_ex *attr,
		       struct mlx5dv_qp_init_attr *mlx5_qp_attr)
{
	uint64_t ops;
	uint64_t mlx5_ops = 0;

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) {
		ops = attr->send_ops_flags;
	} else {
		switch (attr->qp_type) {
		case IBV_QPT_RC:
		case IBV_QPT_UC:
		case IBV_QPT_DRIVER:
		case IBV_QPT_XRC_RECV:
		case IBV_QPT_XRC_SEND:
			ops = IBV_QP_EX_WITH_SEND |
			      IBV_QP_EX_WITH_SEND_WITH_INV |
			      IBV_QP_EX_WITH_SEND_WITH_IMM |
			      IBV_QP_EX_WITH_RDMA_WRITE |
			      IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM |
			      IBV_QP_EX_WITH_RDMA_READ |
			      IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP |
			      IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD |
			      IBV_QP_EX_WITH_LOCAL_INV |
			      IBV_QP_EX_WITH_BIND_MW;
			break;

		case IBV_QPT_UD:
			ops = IBV_QP_EX_WITH_SEND |
			      IBV_QP_EX_WITH_SEND_WITH_IMM |
			      IBV_QP_EX_WITH_TSO;
			break;

		case IBV_QPT_RAW_PACKET:
			ops = IBV_QP_EX_WITH_SEND |
			      IBV_QP_EX_WITH_TSO;
			break;

		default:
			return -EINVAL;
		}
	}


	if (mlx5_qp_attr &&
	    mlx5_qp_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS)
		mlx5_ops = mlx5_qp_attr->send_ops_flags;

	return _sq_overhead(qp, attr->qp_type, ops, mlx5_ops);
}

static int mlx5_calc_send_wqe(struct mlx5_context *ctx,
			      struct ibv_qp_init_attr_ex *attr,
			      struct mlx5dv_qp_init_attr *mlx5_qp_attr,
			      struct mlx5_qp *qp)
{
	int size;
	int inl_size = 0;
	int max_gather;
	int tot_size;

	size = sq_overhead(qp, attr, mlx5_qp_attr);
	if (size < 0)
		return size;

	if (attr->cap.max_inline_data) {
		inl_size = size + align(sizeof(struct mlx5_wqe_inl_data_seg) +
			attr->cap.max_inline_data, 16);
	}

	if (attr->comp_mask & IBV_QP_INIT_ATTR_MAX_TSO_HEADER) {
		size += align(attr->max_tso_header, 16);
		qp->max_tso_header = attr->max_tso_header;
	}

	max_gather = (ctx->max_sq_desc_sz - size) /
		sizeof(struct mlx5_wqe_data_seg);
	if (attr->cap.max_send_sge > max_gather)
		return -EINVAL;

	size += attr->cap.max_send_sge * sizeof(struct mlx5_wqe_data_seg);
	tot_size = max_int(size, inl_size);

	if (tot_size > ctx->max_sq_desc_sz)
		return -EINVAL;

	return align(tot_size, MLX5_SEND_WQE_BB);
}

static int mlx5_calc_rcv_wqe(struct mlx5_context *ctx,
			     struct ibv_qp_init_attr_ex *attr,
			     struct mlx5_qp *qp)
{
	uint32_t size;
	int num_scatter;

	if (attr->srq)
		return 0;

	num_scatter = max_t(uint32_t, attr->cap.max_recv_sge, 1);
	size = sizeof(struct mlx5_wqe_data_seg) * num_scatter;
	if (qp->wq_sig)
		size += sizeof(struct mlx5_rwqe_sig);

	if (size > ctx->max_rq_desc_sz)
		return -EINVAL;

	size = roundup_pow_of_two(size);

	return size;
}

static int mlx5_calc_sq_size(struct mlx5_context *ctx,
			     struct ibv_qp_init_attr_ex *attr,
			     struct mlx5dv_qp_init_attr *mlx5_qp_attr,
			     struct mlx5_qp *qp)
{
	int wqe_size;
	int wq_size;
	FILE *fp = ctx->dbg_fp;

	if (!attr->cap.max_send_wr)
		return 0;

	wqe_size = mlx5_calc_send_wqe(ctx, attr, mlx5_qp_attr, qp);
	if (wqe_size < 0) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		return wqe_size;
	}

	if (wqe_size > ctx->max_sq_desc_sz) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		return -EINVAL;
	}

	qp->max_inline_data = wqe_size - sq_overhead(qp, attr, mlx5_qp_attr) -
		sizeof(struct mlx5_wqe_inl_data_seg);
	attr->cap.max_inline_data = qp->max_inline_data;

	/*
	 * to avoid overflow, we limit max_send_wr so
	 * that the multiplication will fit in int
	 */
	if (attr->cap.max_send_wr > 0x7fffffff / ctx->max_sq_desc_sz) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		return -EINVAL;
	}

	wq_size = roundup_pow_of_two(attr->cap.max_send_wr * wqe_size);
	qp->sq.wqe_cnt = wq_size / MLX5_SEND_WQE_BB;
	if (qp->sq.wqe_cnt > ctx->max_send_wqebb) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		return -EINVAL;
	}

	qp->sq.wqe_shift = STATIC_ILOG_32(MLX5_SEND_WQE_BB) - 1;
	qp->sq.max_gs = attr->cap.max_send_sge;
	qp->sq.max_post = wq_size / wqe_size;

	return wq_size;
}

enum {
	DV_CREATE_WQ_SUPPORTED_COMP_MASK = MLX5DV_WQ_INIT_ATTR_MASK_STRIDING_RQ
};

static int mlx5_calc_rwq_size(struct mlx5_context *ctx,
			      struct mlx5_rwq *rwq,
			      struct ibv_wq_init_attr *attr,
			      struct mlx5dv_wq_init_attr *mlx5wq_attr)
{
	size_t wqe_size;
	int wq_size;
	uint32_t num_scatter;
	int is_mprq = 0;
	int scat_spc;

	if (!attr->max_wr)
		return -EINVAL;
	if (mlx5wq_attr) {
		if (!check_comp_mask(mlx5wq_attr->comp_mask,
				     DV_CREATE_WQ_SUPPORTED_COMP_MASK))
			return -EINVAL;

		is_mprq = !!(mlx5wq_attr->comp_mask &
			     MLX5DV_WQ_INIT_ATTR_MASK_STRIDING_RQ);
	}

	/* TBD: check caps for RQ */
	num_scatter = max_t(uint32_t, attr->max_sge, 1);
	wqe_size = sizeof(struct mlx5_wqe_data_seg) * num_scatter +
		sizeof(struct mlx5_wqe_srq_next_seg) * is_mprq;

	if (rwq->wq_sig)
		wqe_size += sizeof(struct mlx5_rwqe_sig);

	if (wqe_size <= 0 || wqe_size > ctx->max_rq_desc_sz)
		return -EINVAL;

	wqe_size = roundup_pow_of_two(wqe_size);
	wq_size = roundup_pow_of_two(attr->max_wr) * wqe_size;
	wq_size = max(wq_size, MLX5_SEND_WQE_BB);
	rwq->rq.wqe_cnt = wq_size / wqe_size;
	rwq->rq.wqe_shift = ilog32(wqe_size - 1);
	rwq->rq.max_post = 1 << ilog32(wq_size / wqe_size - 1);
	scat_spc = wqe_size -
		((rwq->wq_sig) ? sizeof(struct mlx5_rwqe_sig) : 0) -
		is_mprq * sizeof(struct mlx5_wqe_srq_next_seg);
	rwq->rq.max_gs = scat_spc / sizeof(struct mlx5_wqe_data_seg);
	return wq_size;
}

static int mlx5_calc_rq_size(struct mlx5_context *ctx,
			     struct ibv_qp_init_attr_ex *attr,
			     struct mlx5_qp *qp)
{
	int wqe_size;
	int wq_size;
	int scat_spc;
	FILE *fp = ctx->dbg_fp;

	if (!attr->cap.max_recv_wr)
		return 0;

	if (attr->cap.max_recv_wr > ctx->max_recv_wr) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		return -EINVAL;
	}

	wqe_size = mlx5_calc_rcv_wqe(ctx, attr, qp);
	if (wqe_size < 0 || wqe_size > ctx->max_rq_desc_sz) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		return -EINVAL;
	}

	wq_size = roundup_pow_of_two(attr->cap.max_recv_wr) * wqe_size;
	if (wqe_size) {
		wq_size = max(wq_size, MLX5_SEND_WQE_BB);
		qp->rq.wqe_cnt = wq_size / wqe_size;
		qp->rq.wqe_shift = ilog32(wqe_size - 1);
		qp->rq.max_post = 1 << ilog32(wq_size / wqe_size - 1);
		scat_spc = wqe_size -
			(qp->wq_sig ? sizeof(struct mlx5_rwqe_sig) : 0);
		qp->rq.max_gs = scat_spc / sizeof(struct mlx5_wqe_data_seg);
	} else {
		qp->rq.wqe_cnt = 0;
		qp->rq.wqe_shift = 0;
		qp->rq.max_post = 0;
		qp->rq.max_gs = 0;
	}
	return wq_size;
}

static int mlx5_calc_wq_size(struct mlx5_context *ctx,
			     struct ibv_qp_init_attr_ex *attr,
			     struct mlx5dv_qp_init_attr *mlx5_qp_attr,
			     struct mlx5_qp *qp)
{
	int ret;
	int result;

	ret = mlx5_calc_sq_size(ctx, attr, mlx5_qp_attr, qp);
	if (ret < 0)
		return ret;

	result = ret;
	ret = mlx5_calc_rq_size(ctx, attr, qp);
	if (ret < 0)
		return ret;

	result += ret;

	qp->sq.offset = ret;
	qp->rq.offset = 0;

	return result;
}

static void map_uuar(struct ibv_context *context, struct mlx5_qp *qp,
		     int uuar_index, struct mlx5_bf *dyn_bf)
{
	struct mlx5_context *ctx = to_mctx(context);

	if (!dyn_bf)
		qp->bf = &ctx->bfs[uuar_index];
	else
		qp->bf = dyn_bf;
}

static const char *qptype2key(enum ibv_qp_type type)
{
	switch (type) {
	case IBV_QPT_RC: return "HUGE_RC";
	case IBV_QPT_UC: return "HUGE_UC";
	case IBV_QPT_UD: return "HUGE_UD";
	case IBV_QPT_RAW_PACKET: return "HUGE_RAW_ETH";
	default: return "HUGE_NA";
	}
}

static size_t mlx5_set_custom_qp_alignment(struct ibv_context *context,
					   struct mlx5_qp *qp)
{
	uint32_t max_stride;
	uint32_t buf_page;

	/* The main QP buffer alignment requirement is QP_PAGE_SIZE /
	 * MLX5_QPC_PAGE_OFFSET_QUANTA. In case the buffer is contig, then
	 * QP_PAGE_SIZE is the buffer size align to system page_size roundup to
	 * the next pow of two.
	 */
	buf_page = roundup_pow_of_two(align(qp->buf_size,
					    to_mdev(context->device)->page_size));
	/* Another QP buffer alignment requirement is to consider send wqe and
	 * receive wqe strides.
	 */
	max_stride = max((1 << qp->sq.wqe_shift), (1 << qp->rq.wqe_shift));
	return max(max_stride, buf_page / MLX5_QPC_PAGE_OFFSET_QUANTA);
}

static int mlx5_alloc_qp_buf(struct ibv_context *context,
			     struct ibv_qp_init_attr_ex *attr,
			     struct mlx5_qp *qp,
			     int size)
{
	int err;
	enum mlx5_alloc_type alloc_type;
	enum mlx5_alloc_type default_alloc_type = MLX5_ALLOC_TYPE_ANON;
	const char *qp_huge_key;
	size_t req_align = to_mdev(context->device)->page_size;

	if (qp->sq.wqe_cnt) {
		qp->sq.wrid = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wrid));
		if (!qp->sq.wrid) {
			errno = ENOMEM;
			err = -1;
			return err;
		}

		qp->sq.wr_data = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wr_data));
		if (!qp->sq.wr_data) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}

		qp->sq.wqe_head = malloc(qp->sq.wqe_cnt * sizeof(*qp->sq.wqe_head));
		if (!qp->sq.wqe_head) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}
	}

	if (qp->rq.wqe_cnt) {
		qp->rq.wrid = malloc(qp->rq.wqe_cnt * sizeof(uint64_t));
		if (!qp->rq.wrid) {
			errno = ENOMEM;
			err = -1;
			goto ex_wrid;
		}
	}

	/* compatibility support */
	qp_huge_key  = qptype2key(qp->ibv_qp->qp_type);
	if (mlx5_use_huge(qp_huge_key))
		default_alloc_type = MLX5_ALLOC_TYPE_HUGE;

	mlx5_get_alloc_type(to_mctx(context), attr->pd, MLX5_QP_PREFIX,
			    &alloc_type, default_alloc_type);

	if (alloc_type == MLX5_ALLOC_TYPE_CUSTOM) {
		qp->buf.mparent_domain = to_mparent_domain(attr->pd);
		if (attr->qp_type != IBV_QPT_RAW_PACKET &&
		    !(qp->flags & MLX5_QP_FLAGS_USE_UNDERLAY))
			req_align = mlx5_set_custom_qp_alignment(context, qp);
		qp->buf.req_alignment = req_align;
		qp->buf.resource_type = MLX5DV_RES_TYPE_QP;
	}

	err = mlx5_alloc_prefered_buf(to_mctx(context), &qp->buf,
				      align(qp->buf_size, req_align),
				      to_mdev(context->device)->page_size,
				      alloc_type,
				      MLX5_QP_PREFIX);

	if (err) {
		err = -ENOMEM;
		goto ex_wrid;
	}

	if (qp->buf.type != MLX5_ALLOC_TYPE_CUSTOM)
		memset(qp->buf.buf, 0, qp->buf_size);

	if (attr->qp_type == IBV_QPT_RAW_PACKET ||
	    qp->flags & MLX5_QP_FLAGS_USE_UNDERLAY) {
		size_t aligned_sq_buf_size = align(qp->sq_buf_size,
						   to_mdev(context->device)->page_size);

		if (alloc_type == MLX5_ALLOC_TYPE_CUSTOM) {
			qp->sq_buf.mparent_domain = to_mparent_domain(attr->pd);
			qp->sq_buf.req_alignment = to_mdev(context->device)->page_size;
			qp->sq_buf.resource_type = MLX5DV_RES_TYPE_QP;
		}

		/* For Raw Packet QP, allocate a separate buffer for the SQ */
		err = mlx5_alloc_prefered_buf(to_mctx(context), &qp->sq_buf,
					      aligned_sq_buf_size,
					      to_mdev(context->device)->page_size,
					      alloc_type,
					      MLX5_QP_PREFIX);
		if (err) {
			err = -ENOMEM;
			goto rq_buf;
		}

		if (qp->sq_buf.type != MLX5_ALLOC_TYPE_CUSTOM)
			memset(qp->sq_buf.buf, 0, aligned_sq_buf_size);
	}

	return 0;
rq_buf:
	mlx5_free_actual_buf(to_mctx(context), &qp->buf);
ex_wrid:
	if (qp->rq.wrid)
		free(qp->rq.wrid);

	if (qp->sq.wqe_head)
		free(qp->sq.wqe_head);

	if (qp->sq.wr_data)
		free(qp->sq.wr_data);
	if (qp->sq.wrid)
		free(qp->sq.wrid);

	return err;
}

static void mlx5_free_qp_buf(struct mlx5_context *ctx, struct mlx5_qp *qp)
{
	mlx5_free_actual_buf(ctx, &qp->buf);

	if (qp->sq_buf.buf)
		mlx5_free_actual_buf(ctx, &qp->sq_buf);

	if (qp->rq.wrid)
		free(qp->rq.wrid);

	if (qp->sq.wqe_head)
		free(qp->sq.wqe_head);

	if (qp->sq.wrid)
		free(qp->sq.wrid);

	if (qp->sq.wr_data)
		free(qp->sq.wr_data);
}

int mlx5_set_ece(struct ibv_qp *qp, struct ibv_ece *ece)
{
	struct mlx5_context *context = to_mctx(qp->context);
	struct mlx5_qp *mqp = to_mqp(qp);

	if (ece->comp_mask) {
		errno = EINVAL;
		return errno;
	}

	if (ece->vendor_id != PCI_VENDOR_ID_MELLANOX) {
		errno = EINVAL;
		return errno;
	}

	if (!(context->flags & MLX5_CTX_FLAGS_ECE_SUPPORTED)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	mqp->set_ece = ece->options;
	/* Clean previously returned ECE options */
	mqp->get_ece = 0;
	return 0;
}

int mlx5_query_ece(struct ibv_qp *qp, struct ibv_ece *ece)
{
	struct mlx5_qp *mqp = to_mqp(qp);

	ece->vendor_id = PCI_VENDOR_ID_MELLANOX;
	ece->options = mqp->get_ece;
	ece->comp_mask = 0;
	return 0;
}

static int mlx5_cmd_create_rss_qp(struct ibv_context *context,
				 struct ibv_qp_init_attr_ex *attr,
				 struct mlx5_qp *qp,
				 uint32_t mlx5_create_flags)
{
	struct mlx5_create_qp_ex_rss cmd_ex_rss = {};
	struct mlx5_create_qp_ex_resp resp = {};
	struct mlx5_ib_create_qp_resp *resp_drv;
	int ret;

	if (attr->rx_hash_conf.rx_hash_key_len > sizeof(cmd_ex_rss.rx_hash_key)) {
		errno = EINVAL;
		return errno;
	}

	cmd_ex_rss.rx_hash_fields_mask = attr->rx_hash_conf.rx_hash_fields_mask;
	cmd_ex_rss.rx_hash_function = attr->rx_hash_conf.rx_hash_function;
	cmd_ex_rss.rx_key_len = attr->rx_hash_conf.rx_hash_key_len;
	cmd_ex_rss.flags = mlx5_create_flags;
	memcpy(cmd_ex_rss.rx_hash_key, attr->rx_hash_conf.rx_hash_key,
			attr->rx_hash_conf.rx_hash_key_len);

	ret = ibv_cmd_create_qp_ex2(context, &qp->verbs_qp,
				    attr,
				    &cmd_ex_rss.ibv_cmd, sizeof(cmd_ex_rss),
				    &resp.ibv_resp, sizeof(resp));
	if (ret)
		return ret;

	resp_drv = &resp.drv_payload;

	if (resp_drv->comp_mask & MLX5_IB_CREATE_QP_RESP_MASK_TIRN)
		qp->tirn = resp_drv->tirn;

	if (resp_drv->comp_mask & MLX5_IB_CREATE_QP_RESP_MASK_TIR_ICM_ADDR)
		qp->tir_icm_addr = resp_drv->tir_icm_addr;

	qp->rss_qp = 1;
	return 0;
}

static int mlx5_cmd_create_qp_ex(struct ibv_context *context,
				 struct ibv_qp_init_attr_ex *attr,
				 struct mlx5_create_qp *cmd,
				 struct mlx5_qp *qp,
				 struct mlx5_create_qp_ex_resp *resp)
{
	struct mlx5_create_qp_ex cmd_ex;
	int ret;

	memset(&cmd_ex, 0, sizeof(cmd_ex));
	*ibv_create_qp_ex_to_reg(&cmd_ex.ibv_cmd) = cmd->ibv_cmd.core_payload;

	cmd_ex.drv_payload = cmd->drv_payload;

	ret = ibv_cmd_create_qp_ex2(context, &qp->verbs_qp,
				    attr, &cmd_ex.ibv_cmd,
				    sizeof(cmd_ex), &resp->ibv_resp,
				    sizeof(*resp));

	return ret;
}

enum {
	MLX5_CREATE_QP_SUP_COMP_MASK = (IBV_QP_INIT_ATTR_PD |
					IBV_QP_INIT_ATTR_XRCD |
					IBV_QP_INIT_ATTR_CREATE_FLAGS |
					IBV_QP_INIT_ATTR_MAX_TSO_HEADER |
					IBV_QP_INIT_ATTR_IND_TABLE |
					IBV_QP_INIT_ATTR_RX_HASH |
					IBV_QP_INIT_ATTR_SEND_OPS_FLAGS),
};

enum {
	MLX5_DV_CREATE_QP_SUP_COMP_MASK = MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS |
					  MLX5DV_QP_INIT_ATTR_MASK_DC |
					  MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS |
					  MLX5DV_QP_INIT_ATTR_MASK_DCI_STREAMS
};

enum {
	MLX5_CREATE_QP_EX2_COMP_MASK = (IBV_QP_INIT_ATTR_CREATE_FLAGS |
					IBV_QP_INIT_ATTR_MAX_TSO_HEADER |
					IBV_QP_INIT_ATTR_IND_TABLE |
					IBV_QP_INIT_ATTR_RX_HASH),
};

enum {
	MLX5DV_QP_CREATE_SUP_FLAGS =
		(MLX5DV_QP_CREATE_TUNNEL_OFFLOADS |
		 MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC |
		 MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_MC |
		 MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE |
		 MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE |
		 MLX5DV_QP_CREATE_PACKET_BASED_CREDIT_MODE |
		 MLX5DV_QP_CREATE_SIG_PIPELINING),
};

static int create_dct(struct ibv_context *context,
		      struct ibv_qp_init_attr_ex *attr,
		      struct mlx5dv_qp_init_attr *mlx5_qp_attr,
		      struct mlx5_qp *qp, uint32_t mlx5_create_flags)
{
	struct mlx5_create_qp		cmd = {};
	struct mlx5_create_qp_resp	resp = {};
	int				ret;
	struct mlx5_context	       *ctx = to_mctx(context);
	int32_t				usr_idx = 0xffffff;
	FILE *fp = ctx->dbg_fp;

	if (!check_comp_mask(attr->comp_mask, IBV_QP_INIT_ATTR_PD)) {
		mlx5_dbg(fp, MLX5_DBG_QP,
			 "Unsupported comp_mask for %s\n", __func__);
		errno = EINVAL;
		return errno;
	}

	if (!check_comp_mask(mlx5_qp_attr->comp_mask,
			     MLX5DV_QP_INIT_ATTR_MASK_DC |
			     MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS)) {
		mlx5_dbg(fp, MLX5_DBG_QP,
			 "Unsupported vendor comp_mask for %s\n", __func__);
		errno = EINVAL;
		return errno;
	}

	if (!check_comp_mask(mlx5_create_flags, MLX5_QP_FLAG_SCATTER_CQE)) {
		mlx5_dbg(fp, MLX5_DBG_QP,
			 "Unsupported creation flags requested for DCT QP\n");
		errno = EINVAL;
		return errno;
	}

	if (!(ctx->vendor_cap_flags & MLX5_VENDOR_CAP_FLAGS_SCAT2CQE_DCT))
		mlx5_create_flags &= ~MLX5_QP_FLAG_SCATTER_CQE;

	cmd.flags = MLX5_QP_FLAG_TYPE_DCT | mlx5_create_flags;
	cmd.access_key = mlx5_qp_attr->dc_init_attr.dct_access_key;

	if (ctx->cqe_version) {
		usr_idx = mlx5_store_uidx(ctx, qp);
		if (usr_idx < 0) {
			mlx5_dbg(fp, MLX5_DBG_QP, "Couldn't find free user index\n");
			errno = ENOMEM;
			return errno;
		}
	}
	cmd.uidx = usr_idx;
	if (ctx->flags & MLX5_CTX_FLAGS_ECE_SUPPORTED)
		/* Create QP should start from ECE version 1 as a trigger */
		cmd.ece_options = 0x10000000;

	ret = ibv_cmd_create_qp_ex(context, &qp->verbs_qp,
				   attr, &cmd.ibv_cmd, sizeof(cmd),
				   &resp.ibv_resp, sizeof(resp));
	if (ret) {
		mlx5_dbg(fp, MLX5_DBG_QP, "Couldn't create dct, ret %d\n", ret);
		if (ctx->cqe_version)
			mlx5_clear_uidx(ctx, cmd.uidx);
		return ret;
	}

	qp->get_ece = resp.ece_options;
	qp->dc_type = MLX5DV_DCTYPE_DCT;
	qp->rsc.type = MLX5_RSC_TYPE_QP;
	if (ctx->cqe_version)
		qp->rsc.rsn = usr_idx;
	return 0;
}

#define MLX5_OPAQUE_BUF_LEN 64
static int reg_opaque_mr(struct ibv_pd *pd)
{
	struct mlx5_pd *mpd = to_mpd(pd);
	int ret = 0;

	pthread_mutex_lock(&mpd->opaque_mr_mutex);
	if (mpd->opaque_mr)
		goto out;

	ret = posix_memalign(&mpd->opaque_buf, MLX5_OPAQUE_BUF_LEN,
			     MLX5_OPAQUE_BUF_LEN);
	if (ret) {
		errno = ret;
		goto out;
	}

	mpd->opaque_mr =
		mlx5_reg_mr(&mpd->ibv_pd, mpd->opaque_buf, MLX5_OPAQUE_BUF_LEN,
			    (uint64_t)(uintptr_t)mpd->opaque_buf, IBV_ACCESS_LOCAL_WRITE);
	if (!mpd->opaque_mr) {
		ret = errno;
		free(mpd->opaque_buf);
		mpd->opaque_buf = NULL;
	}

out:
	pthread_mutex_unlock(&mpd->opaque_mr_mutex);
	return ret;
}

static int qp_init_wr_memcpy(struct mlx5_qp *mqp,
			     struct ibv_qp_init_attr_ex *attr,
			     struct mlx5dv_qp_init_attr *mlx5_attr)
{
	struct mlx5_context *mctx;

	if (!(attr->comp_mask & IBV_QP_INIT_ATTR_PD)) {
		errno = EINVAL;
		return errno;
	}

	mctx = to_mctx(attr->pd->context);
	if (!mctx->dma_mmo_caps.dma_mmo_sq && !mctx->dma_mmo_caps.dma_mmo_qp) {
		errno = EOPNOTSUPP;
		return errno;
	}

	if (mctx->dma_mmo_caps.dma_mmo_qp)
		mqp->need_mmo_enable = 1;

	return reg_opaque_mr(attr->pd);
}

static struct ibv_qp *create_qp(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *attr,
				struct mlx5dv_qp_init_attr *mlx5_qp_attr)
{
	struct mlx5_create_qp		cmd;
	struct mlx5_create_qp_resp	resp;
	struct mlx5_create_qp_ex_resp  resp_ex;
	struct mlx5_qp		       *qp;
	int				ret;
	struct mlx5_context	       *ctx = to_mctx(context);
	struct ibv_qp		       *ibqp;
	int32_t				usr_idx = 0;
	uint32_t			mlx5_create_flags = 0;
	struct mlx5_bf			*bf = NULL;
	FILE *fp = ctx->dbg_fp;
	struct mlx5_parent_domain *mparent_domain;
	struct mlx5_ib_create_qp_resp  *resp_drv;

	if (attr->comp_mask & ~MLX5_CREATE_QP_SUP_COMP_MASK)
		return NULL;

	if ((attr->comp_mask & IBV_QP_INIT_ATTR_MAX_TSO_HEADER) &&
	    (attr->qp_type != IBV_QPT_RAW_PACKET))
		return NULL;

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS &&
	    (attr->comp_mask & IBV_QP_INIT_ATTR_RX_HASH ||
	     (attr->qp_type == IBV_QPT_DRIVER &&
	      mlx5_qp_attr &&
	      mlx5_qp_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_DC &&
	      mlx5_qp_attr->dc_init_attr.dc_type == MLX5DV_DCTYPE_DCT))) {
		errno = EINVAL;
		return NULL;
	}

	qp = calloc(1, sizeof(*qp));
	if (!qp) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		return NULL;
	}

	ibqp = &qp->verbs_qp.qp;
	qp->ibv_qp = ibqp;

	if ((attr->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS) &&
		(attr->create_flags & IBV_QP_CREATE_SOURCE_QPN)) {

		if (attr->qp_type != IBV_QPT_UD) {
			errno = EINVAL;
			goto err;
		}

		qp->flags |= MLX5_QP_FLAGS_USE_UNDERLAY;
	}

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));
	memset(&resp_ex, 0, sizeof(resp_ex));

	if (use_scatter_to_cqe())
		mlx5_create_flags |= MLX5_QP_FLAG_SCATTER_CQE;

	if (mlx5_qp_attr) {
		if (!check_comp_mask(mlx5_qp_attr->comp_mask,
				     MLX5_DV_CREATE_QP_SUP_COMP_MASK)) {
			mlx5_dbg(fp, MLX5_DBG_QP,
				 "Unsupported vendor comp_mask for create_qp\n");
			errno = EINVAL;
			goto err;
		}

		if ((mlx5_qp_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_DC) &&
		    (attr->qp_type != IBV_QPT_DRIVER)) {
			mlx5_dbg(fp, MLX5_DBG_QP, "DC QP must be of type IBV_QPT_DRIVER\n");
			errno = EINVAL;
			goto err;
		}
		if (mlx5_qp_attr->comp_mask &
		    MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS) {
			if (!check_comp_mask(mlx5_qp_attr->create_flags,
					     MLX5DV_QP_CREATE_SUP_FLAGS)) {
				mlx5_dbg(fp, MLX5_DBG_QP,
					 "Unsupported creation flags requested for create_qp\n");
				errno = EINVAL;
				goto err;
			}
			if (mlx5_qp_attr->create_flags &
			    MLX5DV_QP_CREATE_TUNNEL_OFFLOADS) {
				mlx5_create_flags |= MLX5_QP_FLAG_TUNNEL_OFFLOADS;
			}
			if (mlx5_qp_attr->create_flags &
			    MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC) {
				mlx5_create_flags |=
					MLX5_QP_FLAG_TIR_ALLOW_SELF_LB_UC;
			}
			if (mlx5_qp_attr->create_flags &
			    MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_MC) {
				mlx5_create_flags |=
					MLX5_QP_FLAG_TIR_ALLOW_SELF_LB_MC;
			}
			if (mlx5_qp_attr->create_flags &
			    MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE) {
				if (mlx5_qp_attr->create_flags &
				    MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE) {
					mlx5_dbg(fp, MLX5_DBG_QP,
						 "Wrong usage of creation flags requested for create_qp\n");
					errno = EINVAL;
					goto err;
				}
				mlx5_create_flags &= ~MLX5_QP_FLAG_SCATTER_CQE;
			}
			if (mlx5_qp_attr->create_flags &
			    MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE) {
				mlx5_create_flags |=
					(MLX5_QP_FLAG_ALLOW_SCATTER_CQE |
					 MLX5_QP_FLAG_SCATTER_CQE);
			}
			if (mlx5_qp_attr->create_flags &
			    MLX5DV_QP_CREATE_PACKET_BASED_CREDIT_MODE)
				mlx5_create_flags |= MLX5_QP_FLAG_PACKET_BASED_CREDIT_MODE;

			if (mlx5_qp_attr->create_flags &
			    MLX5DV_QP_CREATE_SIG_PIPELINING) {
				if (!(to_mctx(context)->flags &
				      MLX5_CTX_FLAGS_SQD2RTS_SUPPORTED)) {
					errno = EOPNOTSUPP;
					goto err;
				}
				qp->flags |= MLX5_QP_FLAGS_DRAIN_SIGERR;
			}

		}

		if (attr->qp_type == IBV_QPT_DRIVER) {
			if (mlx5_qp_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_DC) {
				if (mlx5_qp_attr->dc_init_attr.dc_type == MLX5DV_DCTYPE_DCT) {
					ret = create_dct(context, attr, mlx5_qp_attr,
							 qp, mlx5_create_flags);
					if (ret)
						goto err;
					return ibqp;
				} else if (mlx5_qp_attr->dc_init_attr.dc_type == MLX5DV_DCTYPE_DCI) {
					mlx5_create_flags |= MLX5_QP_FLAG_TYPE_DCI;
					qp->dc_type = MLX5DV_DCTYPE_DCI;
					if (mlx5_qp_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_DCI_STREAMS) {
						if ((ctx->dci_streams_caps.max_log_num_concurent <
						     mlx5_qp_attr->dc_init_attr.dci_streams.log_num_concurent) ||
						    (ctx->dci_streams_caps.max_log_num_errored <
						     mlx5_qp_attr->dc_init_attr.dci_streams.log_num_errored)) {
							errno = EINVAL;
							goto err;
						}

						mlx5_create_flags |= MLX5_QP_FLAG_DCI_STREAM;
						cmd.dci_streams.log_num_concurent =
							mlx5_qp_attr->dc_init_attr.dci_streams.log_num_concurent;
						cmd.dci_streams.log_num_errored =
							mlx5_qp_attr->dc_init_attr.dci_streams.log_num_errored;
					}
				} else {
					errno = EINVAL;
					goto err;
				}
			} else {
				errno = EINVAL;
				goto err;
			}
		}

	} else {
		if (attr->qp_type == IBV_QPT_DRIVER)
			goto err;
	}

	if (attr->comp_mask & IBV_QP_INIT_ATTR_RX_HASH) {
		/* Scatter2CQE is unsupported for RSS QP */
		mlx5_create_flags &= ~MLX5_QP_FLAG_SCATTER_CQE;

		ret = mlx5_cmd_create_rss_qp(context, attr, qp,
					     mlx5_create_flags);
		if (ret)
			goto err;

		return ibqp;
	}

	if (ctx->atomic_cap)
		qp->atomics_enabled = 1;

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS ||
	    (mlx5_qp_attr &&
	     mlx5_qp_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS)) {
		/*
		 * Scatter2cqe, which is a data-path optimization, is disabled
		 * since driver DC data-path doesn't support it.
		 */
		if (mlx5_qp_attr &&
		    mlx5_qp_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_DC) {
			mlx5_create_flags &= ~MLX5_QP_FLAG_SCATTER_CQE;
		}

		ret = mlx5_qp_fill_wr_pfns(qp, attr, mlx5_qp_attr);
		if (ret) {
			errno = ret;
			mlx5_dbg(fp, MLX5_DBG_QP, "Failed to handle operations flags (errno %d)\n", errno);
			goto err;
		}

		if (mlx5_qp_attr &&
		    (mlx5_qp_attr->comp_mask &
		     MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS) &&
		    (mlx5_qp_attr->send_ops_flags & MLX5DV_QP_EX_WITH_MEMCPY)) {
			ret = qp_init_wr_memcpy(qp, attr, mlx5_qp_attr);
			if (ret)
				goto err;
		}
	}

	cmd.flags = mlx5_create_flags;
	qp->wq_sig = qp_sig_enabled();
	if (qp->wq_sig)
		cmd.flags |= MLX5_QP_FLAG_SIGNATURE;

	ret = mlx5_calc_wq_size(ctx, attr, mlx5_qp_attr, qp);
	if (ret < 0) {
		errno = -ret;
		goto err;
	}

	if (attr->qp_type == IBV_QPT_RAW_PACKET ||
	    qp->flags & MLX5_QP_FLAGS_USE_UNDERLAY) {
		qp->buf_size = qp->sq.offset;
		qp->sq_buf_size = ret - qp->buf_size;
		qp->sq.offset = 0;
	} else {
		qp->buf_size = ret;
		qp->sq_buf_size = 0;
	}

	if (mlx5_alloc_qp_buf(context, attr, qp, ret)) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		goto err;
	}

	if (attr->qp_type == IBV_QPT_RAW_PACKET ||
	    qp->flags & MLX5_QP_FLAGS_USE_UNDERLAY) {
		qp->sq_start = qp->sq_buf.buf;
		qp->sq.qend = qp->sq_buf.buf +
				(qp->sq.wqe_cnt << qp->sq.wqe_shift);
	} else {
		qp->sq_start = qp->buf.buf + qp->sq.offset;
		qp->sq.qend = qp->buf.buf + qp->sq.offset +
				(qp->sq.wqe_cnt << qp->sq.wqe_shift);
	}

	mlx5_init_qp_indices(qp);

	if (mlx5_spinlock_init_pd(&qp->sq.lock, attr->pd) ||
			mlx5_spinlock_init_pd(&qp->rq.lock, attr->pd))
		goto err_free_qp_buf;

	qp->db = mlx5_alloc_dbrec(ctx, attr->pd, &qp->custom_db);
	if (!qp->db) {
		mlx5_dbg(fp, MLX5_DBG_QP, "\n");
		goto err_free_qp_buf;
	}

	if (!qp->custom_db) {
		qp->db[MLX5_RCV_DBR] = 0;
		qp->db[MLX5_SND_DBR] = 0;
	}

	cmd.buf_addr = (uintptr_t) qp->buf.buf;
	cmd.sq_buf_addr = (attr->qp_type == IBV_QPT_RAW_PACKET ||
			   qp->flags & MLX5_QP_FLAGS_USE_UNDERLAY) ?
			  (uintptr_t) qp->sq_buf.buf : 0;
	cmd.db_addr  = (uintptr_t) qp->db;
	cmd.sq_wqe_count = qp->sq.wqe_cnt;
	cmd.rq_wqe_count = qp->rq.wqe_cnt;
	cmd.rq_wqe_shift = qp->rq.wqe_shift;

	if (!ctx->cqe_version) {
		cmd.uidx = 0xffffff;
		pthread_mutex_lock(&ctx->qp_table_mutex);
	} else if (!is_xrc_tgt(attr->qp_type)) {
		usr_idx = mlx5_store_uidx(ctx, qp);
		if (usr_idx < 0) {
			mlx5_dbg(fp, MLX5_DBG_QP, "Couldn't find free user index\n");
			goto err_rq_db;
		}

		cmd.uidx = usr_idx;
	}

	mparent_domain = to_mparent_domain(attr->pd);
	if (mparent_domain && mparent_domain->mtd)
		bf = mparent_domain->mtd->bf;

	if (!bf && !(ctx->flags & MLX5_CTX_FLAGS_NO_KERN_DYN_UAR)) {
		bf = mlx5_get_qp_uar(context);
		if (!bf)
			goto err_free_uidx;
	}

	if (bf) {
		if (bf->dyn_alloc_uar) {
			cmd.bfreg_index = bf->page_id;
			cmd.flags |= MLX5_QP_FLAG_UAR_PAGE_INDEX;
		} else {
			cmd.bfreg_index = bf->bfreg_dyn_index;
			cmd.flags |= MLX5_QP_FLAG_BFREG_INDEX;
		}
	}

	if (ctx->flags & MLX5_CTX_FLAGS_ECE_SUPPORTED)
		/* Create QP should start from ECE version 1 as a trigger */
		cmd.ece_options = 0x10000000;

	if (attr->comp_mask & MLX5_CREATE_QP_EX2_COMP_MASK)
		ret = mlx5_cmd_create_qp_ex(context, attr, &cmd, qp, &resp_ex);
	else
		ret = ibv_cmd_create_qp_ex(context, &qp->verbs_qp,
					   attr, &cmd.ibv_cmd, sizeof(cmd),
					   &resp.ibv_resp, sizeof(resp));
	if (ret) {
		mlx5_dbg(fp, MLX5_DBG_QP, "ret %d\n", ret);
		goto err_free_uidx;
	}

	resp_drv = attr->comp_mask & MLX5_CREATE_QP_EX2_COMP_MASK ?
			&resp_ex.drv_payload : &resp.drv_payload;
	if (!ctx->cqe_version) {
		if (qp->sq.wqe_cnt || qp->rq.wqe_cnt) {
			ret = mlx5_store_qp(ctx, ibqp->qp_num, qp);
			if (ret) {
				mlx5_dbg(fp, MLX5_DBG_QP, "ret %d\n", ret);
				goto err_destroy;
			}
		}

		pthread_mutex_unlock(&ctx->qp_table_mutex);
	}

	qp->get_ece = resp_drv->ece_options;
	map_uuar(context, qp, resp_drv->bfreg_index, bf);

	qp->rq.max_post = qp->rq.wqe_cnt;
	if (attr->sq_sig_all)
		qp->sq_signal_bits = MLX5_WQE_CTRL_CQ_UPDATE;
	else
		qp->sq_signal_bits = 0;

	attr->cap.max_send_wr = qp->sq.max_post;
	attr->cap.max_recv_wr = qp->rq.max_post;
	attr->cap.max_recv_sge = qp->rq.max_gs;

	qp->rsc.type = MLX5_RSC_TYPE_QP;
	qp->rsc.rsn = (ctx->cqe_version && !is_xrc_tgt(attr->qp_type)) ?
		      usr_idx : ibqp->qp_num;

	if (mparent_domain)
		atomic_fetch_add(&mparent_domain->mpd.refcount, 1);

	if (resp_drv->comp_mask & MLX5_IB_CREATE_QP_RESP_MASK_TIRN)
		qp->tirn = resp_drv->tirn;

	if (resp_drv->comp_mask & MLX5_IB_CREATE_QP_RESP_MASK_TISN)
		qp->tisn = resp_drv->tisn;

	if (resp_drv->comp_mask & MLX5_IB_CREATE_QP_RESP_MASK_RQN)
		qp->rqn = resp_drv->rqn;

	if (resp_drv->comp_mask & MLX5_IB_CREATE_QP_RESP_MASK_SQN)
		qp->sqn = resp_drv->sqn;

	if (resp_drv->comp_mask & MLX5_IB_CREATE_QP_RESP_MASK_TIR_ICM_ADDR)
		qp->tir_icm_addr = resp_drv->tir_icm_addr;

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)
		qp->verbs_qp.comp_mask |= VERBS_QP_EX;

	return ibqp;

err_destroy:
	ibv_cmd_destroy_qp(ibqp);

err_free_uidx:
	if (bf)
		mlx5_put_qp_uar(ctx, bf);
	if (!ctx->cqe_version)
		pthread_mutex_unlock(&to_mctx(context)->qp_table_mutex);
	else if (!is_xrc_tgt(attr->qp_type))
		mlx5_clear_uidx(ctx, usr_idx);

err_rq_db:
	mlx5_free_db(to_mctx(context), qp->db, attr->pd, qp->custom_db);

err_free_qp_buf:
	mlx5_free_qp_buf(ctx, qp);

err:
	free(qp);

	return NULL;
}

struct ibv_qp *mlx5_create_qp(struct ibv_pd *pd,
			      struct ibv_qp_init_attr *attr)
{
	struct ibv_qp *qp;
	struct ibv_qp_init_attr_ex attrx;

	memset(&attrx, 0, sizeof(attrx));
	memcpy(&attrx, attr, sizeof(*attr));
	attrx.comp_mask = IBV_QP_INIT_ATTR_PD;
	attrx.pd = pd;
	qp = create_qp(pd->context, &attrx, NULL);
	if (qp)
		memcpy(attr, &attrx, sizeof(*attr));

	return qp;
}

static void mlx5_lock_cqs(struct ibv_qp *qp)
{
	struct mlx5_cq *send_cq = to_mcq(qp->send_cq);
	struct mlx5_cq *recv_cq = to_mcq(qp->recv_cq);

	if (send_cq && recv_cq) {
		if (send_cq == recv_cq) {
			mlx5_spin_lock(&send_cq->lock);
		} else if (send_cq->cqn < recv_cq->cqn) {
			mlx5_spin_lock(&send_cq->lock);
			mlx5_spin_lock(&recv_cq->lock);
		} else {
			mlx5_spin_lock(&recv_cq->lock);
			mlx5_spin_lock(&send_cq->lock);
		}
	} else if (send_cq) {
		mlx5_spin_lock(&send_cq->lock);
	} else if (recv_cq) {
		mlx5_spin_lock(&recv_cq->lock);
	}
}

static void mlx5_unlock_cqs(struct ibv_qp *qp)
{
	struct mlx5_cq *send_cq = to_mcq(qp->send_cq);
	struct mlx5_cq *recv_cq = to_mcq(qp->recv_cq);

	if (send_cq && recv_cq) {
		if (send_cq == recv_cq) {
			mlx5_spin_unlock(&send_cq->lock);
		} else if (send_cq->cqn < recv_cq->cqn) {
			mlx5_spin_unlock(&recv_cq->lock);
			mlx5_spin_unlock(&send_cq->lock);
		} else {
			mlx5_spin_unlock(&send_cq->lock);
			mlx5_spin_unlock(&recv_cq->lock);
		}
	} else if (send_cq) {
		mlx5_spin_unlock(&send_cq->lock);
	} else if (recv_cq) {
		mlx5_spin_unlock(&recv_cq->lock);
	}
}

int mlx5_destroy_qp(struct ibv_qp *ibqp)
{
	struct mlx5_qp *qp = to_mqp(ibqp);
	struct mlx5_context *ctx = to_mctx(ibqp->context);
	int ret;
	struct mlx5_parent_domain *mparent_domain = to_mparent_domain(ibqp->pd);

	if (qp->rss_qp) {
		ret = ibv_cmd_destroy_qp(ibqp);
		if (ret)
			return ret;
		goto free;
	}

	if (!ctx->cqe_version)
		pthread_mutex_lock(&ctx->qp_table_mutex);

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		if (!ctx->cqe_version)
			pthread_mutex_unlock(&ctx->qp_table_mutex);
		return ret;
	}

	mlx5_lock_cqs(ibqp);

	__mlx5_cq_clean(to_mcq(ibqp->recv_cq), qp->rsc.rsn,
			ibqp->srq ? to_msrq(ibqp->srq) : NULL);
	if (ibqp->send_cq != ibqp->recv_cq)
		__mlx5_cq_clean(to_mcq(ibqp->send_cq), qp->rsc.rsn, NULL);

	if (!ctx->cqe_version) {
		if (qp->dc_type == MLX5DV_DCTYPE_DCT) {
			/* The QP was inserted to the tracking table only after
			 * that it was modifed to RTR
			 */
			if (ibqp->state == IBV_QPS_RTR)
				mlx5_clear_qp(ctx, ibqp->qp_num);
		} else {
			if (qp->sq.wqe_cnt || qp->rq.wqe_cnt)
				mlx5_clear_qp(ctx, ibqp->qp_num);
		}
	}

	mlx5_unlock_cqs(ibqp);
	if (!ctx->cqe_version)
		pthread_mutex_unlock(&ctx->qp_table_mutex);
	else if (!is_xrc_tgt(ibqp->qp_type))
		mlx5_clear_uidx(ctx, qp->rsc.rsn);

	if (qp->dc_type != MLX5DV_DCTYPE_DCT) {
		mlx5_free_db(ctx, qp->db, ibqp->pd, qp->custom_db);
		mlx5_free_qp_buf(ctx, qp);
	}
free:
	if (mparent_domain)
		atomic_fetch_sub(&mparent_domain->mpd.refcount, 1);

	mlx5_put_qp_uar(ctx, qp->bf);
	free(qp);

	return 0;
}

static int query_dct_in_order(struct ibv_qp *qp)
{
	uint32_t in_dct[DEVX_ST_SZ_DW(query_dct_in)] = {};
	uint32_t out_dct[DEVX_ST_SZ_DW(query_dct_out)] = {};
	int ret;

	DEVX_SET(query_dct_in, in_dct, opcode, MLX5_CMD_OP_QUERY_DCT);
	DEVX_SET(query_dct_in, in_dct, dctn, qp->qp_num);
	ret = mlx5dv_devx_qp_query(qp, in_dct, sizeof(in_dct), out_dct,
				   sizeof(out_dct));
	if (ret)
		return 0;

	return DEVX_GET(query_dct_out, out_dct, dctc.data_in_order);
}

int mlx5_query_qp_data_in_order(struct ibv_qp *qp, enum ibv_wr_opcode op,
				uint32_t flags)
{
	uint32_t in_qp[DEVX_ST_SZ_DW(query_qp_in)] = {};
	uint32_t out_qp[DEVX_ST_SZ_DW(query_qp_out)] = {};
	struct mlx5_context *mctx = to_mctx(qp->context);
	struct mlx5_qp *mqp = to_mqp(qp);
	int ret;

	if (flags || !mctx->qp_data_in_order_cap)
		return 0;

	if (mqp->dc_type == MLX5DV_DCTYPE_DCT)
		return query_dct_in_order(qp);

	if (qp->state != IBV_QPS_RTS)
		return 0;

	DEVX_SET(query_qp_in, in_qp, opcode, MLX5_CMD_OP_QUERY_QP);
	DEVX_SET(query_qp_in, in_qp, qpn, qp->qp_num);
	ret = mlx5dv_devx_qp_query(qp, in_qp, sizeof(in_qp), out_qp,
				   sizeof(out_qp));
	if (ret)
		return 0;

	return DEVX_GET(query_qp_out, out_qp, qpc.data_in_order);
}

int mlx5_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		  int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct mlx5_qp *qp = to_mqp(ibqp);
	int ret;

	if (qp->rss_qp)
		return EOPNOTSUPP;

	ret = ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr, &cmd, sizeof(cmd));
	if (ret)
		return ret;

	init_attr->cap.max_send_wr     = qp->sq.max_post;
	init_attr->cap.max_send_sge    = qp->sq.max_gs;
	init_attr->cap.max_inline_data = qp->max_inline_data;

	attr->cap = init_attr->cap;

	return 0;
}

enum {
	MLX5_MODIFY_QP_EX_ATTR_MASK = IBV_QP_RATE_LIMIT,
};

static int modify_dct(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		      int attr_mask)
{
	struct mlx5_modify_qp cmd_ex = {};
	struct mlx5_modify_qp_ex_resp resp = {};
	struct mlx5_qp *mqp = to_mqp(qp);
	struct mlx5_context *context = to_mctx(qp->context);
	int min_resp_size;
	bool dct_create;
	int ret;

	cmd_ex.ece_options = mqp->set_ece;
	ret = ibv_cmd_modify_qp_ex(qp, attr, attr_mask, &cmd_ex.ibv_cmd,
				   sizeof(cmd_ex), &resp.ibv_resp,
				   sizeof(resp));
	if (ret)
		return ret;

	/* dct is created in hardware and gets unique qp number when QP
	 * is modified to RTR so operations that require QP number need
	 * to be delayed to this time
	 */
	dct_create =
		(attr_mask & IBV_QP_STATE) &&
		(attr->qp_state == IBV_QPS_RTR);

	if (!dct_create)
		return 0;

	min_resp_size =
		offsetof(typeof(resp), dctn) +
		sizeof(resp.dctn) -
		sizeof(resp.ibv_resp);

	if (resp.response_length < min_resp_size) {
		errno = EINVAL;
		return errno;
	}

	qp->qp_num = resp.dctn;
	if (mqp->set_ece) {
		mqp->set_ece = 0;
		mqp->get_ece = resp.ece_options;
	}

	if (!context->cqe_version) {
		pthread_mutex_lock(&context->qp_table_mutex);
		ret = mlx5_store_qp(context, qp->qp_num, mqp);
		if (!ret)
			mqp->rsc.rsn = qp->qp_num;
		else
			errno = ENOMEM;
		pthread_mutex_unlock(&context->qp_table_mutex);
		return ret ? errno : 0;
	}
	return 0;
}

static int qp_enable_mmo(struct ibv_qp *qp)
{
	uint32_t in[DEVX_ST_SZ_DW(init2init_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(init2init_qp_out)] = {};
	void *qpce = DEVX_ADDR_OF(init2init_qp_in, in, qpc_data_ext);

	DEVX_SET(init2init_qp_in, in, opcode, MLX5_CMD_OP_INIT2INIT_QP);
	DEVX_SET(init2init_qp_in, in, qpc_ext, 1);
	DEVX_SET(init2init_qp_in, in, qpn, qp->qp_num);
	DEVX_SET64(init2init_qp_in, in, opt_param_mask_95_32,
		   MLX5_QPC_OPT_MASK_32_INIT2INIT_MMO);

	DEVX_SET(qpc_ext, qpce, mmo, 1);

	return mlx5dv_devx_qp_modify(qp, in, sizeof(in), out, sizeof(out));
}

int mlx5_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct mlx5_modify_qp cmd_ex = {};
	struct mlx5_modify_qp_ex_resp resp = {};
	struct mlx5_qp *mqp = to_mqp(qp);
	struct mlx5_context *context = to_mctx(qp->context);
	int ret;
	__be32 *db;

	if (mqp->dc_type == MLX5DV_DCTYPE_DCT)
		return modify_dct(qp, attr, attr_mask);

	if (mqp->rss_qp)
		return EOPNOTSUPP;

	if (mqp->flags & MLX5_QP_FLAGS_USE_UNDERLAY) {
		if (attr_mask & ~(IBV_QP_STATE | IBV_QP_CUR_STATE))
			return EINVAL;

		/* Underlay QP is UD over infiniband */
		if (context->cached_device_cap_flags & IBV_DEVICE_UD_IP_CSUM)
			mqp->qp_cap_cache |= MLX5_CSUM_SUPPORT_UNDERLAY_UD |
					     MLX5_RX_CSUM_VALID;
	}

	if (attr_mask & IBV_QP_PORT) {
		switch (qp->qp_type) {
		case IBV_QPT_RAW_PACKET:
			if (context->cached_link_layer[attr->port_num - 1] ==
			     IBV_LINK_LAYER_ETHERNET) {
				if (context->cached_device_cap_flags &
				    IBV_DEVICE_RAW_IP_CSUM)
					mqp->qp_cap_cache |=
						MLX5_CSUM_SUPPORT_RAW_OVER_ETH |
						MLX5_RX_CSUM_VALID;

				if (ibv_is_qpt_supported(
				 context->cached_tso_caps.supported_qpts,
				 IBV_QPT_RAW_PACKET))
					mqp->max_tso =
					     context->cached_tso_caps.max_tso;
			}
			break;
		default:
			break;
		}
	}

	if (attr_mask & MLX5_MODIFY_QP_EX_ATTR_MASK || mqp->set_ece) {
		cmd_ex.ece_options = mqp->set_ece;
		ret = ibv_cmd_modify_qp_ex(qp, attr, attr_mask, &cmd_ex.ibv_cmd,
					   sizeof(cmd_ex), &resp.ibv_resp,
					   sizeof(resp));
	} else {
		ret = ibv_cmd_modify_qp(qp, attr, attr_mask,
					&cmd, sizeof(cmd));
	}

	if (!ret && mqp->set_ece) {
		mqp->set_ece = 0;
		mqp->get_ece = resp.ece_options;
	}

	if (!ret		       &&
	    (attr_mask & IBV_QP_STATE) &&
	    attr->qp_state == IBV_QPS_RESET) {
		if (qp->recv_cq) {
			mlx5_cq_clean(to_mcq(qp->recv_cq), mqp->rsc.rsn,
				      qp->srq ? to_msrq(qp->srq) : NULL);
		}
		if (qp->send_cq != qp->recv_cq && qp->send_cq)
			mlx5_cq_clean(to_mcq(qp->send_cq),
				      to_mqp(qp)->rsc.rsn, NULL);

		mlx5_init_qp_indices(mqp);
		db = mqp->db;
		db[MLX5_RCV_DBR] = 0;
		db[MLX5_SND_DBR] = 0;
	}

	/*
	 * When the Raw Packet QP is in INIT state, its RQ
	 * underneath is already in RDY, which means it can
	 * receive packets. According to the IB spec, a QP can't
	 * receive packets until moved to RTR state. To achieve this,
	 * for Raw Packet QPs, we update the doorbell record
	 * once the QP is moved to RTR.
	 */
	if (!ret &&
	    (attr_mask & IBV_QP_STATE) &&
	    attr->qp_state == IBV_QPS_RTR &&
	    (qp->qp_type == IBV_QPT_RAW_PACKET ||
	     mqp->flags & MLX5_QP_FLAGS_USE_UNDERLAY)) {
		mlx5_spin_lock(&mqp->rq.lock);
		mqp->db[MLX5_RCV_DBR] = htobe32(mqp->rq.head & 0xffff);
		mlx5_spin_unlock(&mqp->rq.lock);
	}

	if (!ret &&
	    (attr_mask & IBV_QP_STATE) &&
	    attr->qp_state == IBV_QPS_INIT &&
	    (mqp->flags & MLX5_QP_FLAGS_DRAIN_SIGERR)) {
		ret = mlx5_modify_qp_drain_sigerr(qp);
	}

	if (!ret && (attr_mask & IBV_QP_STATE) &&
	    (attr->qp_state == IBV_QPS_INIT) && mqp->need_mmo_enable)
		ret = qp_enable_mmo(qp);

	return ret;
}

int mlx5_modify_qp_rate_limit(struct ibv_qp *qp,
			      struct ibv_qp_rate_limit_attr *attr)
{
	struct ibv_qp_attr qp_attr = {};
	struct ib_uverbs_ex_modify_qp_resp resp = {};
	struct mlx5_modify_qp cmd = {};
	struct mlx5_context *mctx = to_mctx(qp->context);
	int ret;

	if (attr->comp_mask)
		return EINVAL;

	if ((attr->max_burst_sz ||
	     attr->typical_pkt_sz) &&
	    (!attr->rate_limit ||
	     !(mctx->packet_pacing_caps.cap_flags &
	       MLX5_IB_PP_SUPPORT_BURST)))
		return EINVAL;

	cmd.burst_info.max_burst_sz = attr->max_burst_sz;
	cmd.burst_info.typical_pkt_sz = attr->typical_pkt_sz;
	qp_attr.rate_limit = attr->rate_limit;

	ret = ibv_cmd_modify_qp_ex(qp, &qp_attr, IBV_QP_RATE_LIMIT,
				   &cmd.ibv_cmd, sizeof(cmd), &resp,
				   sizeof(resp));

	return ret;
}

/*
 * IB spec version 1.3. Table 224 Rate to mlx5 rate
 * conversion table on best effort basis.
 */
static const uint8_t ib_to_mlx5_rate_table[] = {
	0,	/* Invalid to unlimited */
	0,	/* Invalid to unlimited */
	7,	/* 2.5 Gbps */
	8,	/* 10Gbps */
	9,	/* 30Gbps */
	10,	/* 5 Gbps */
	11,	/* 20 Gbps */
	12,	/* 40 Gbps */
	13,	/* 60 Gbps */
	14,	/* 80 Gbps */
	15,	/* 120 Gbps */
	11,	/* 14 Gbps to 20 Gbps */
	13,	/* 56 Gbps to 60 Gbps */
	15,	/* 112 Gbps to 120 Gbps */
	0,	/* 168 Gbps to unlimited */
	9,	/* 25 Gbps to 30 Gbps */
	15,	/* 100 Gbps to 120 Gbps */
	0,	/* 200 Gbps to unlimited */
	0,	/* 300 Gbps to unlimited */
	9,	/* 28 Gbps to 30 Gbps */
	13,	/* 50 Gbps to 60 Gbps */
	0,	/* 400 Gbps to unlimited */
	0,	/* 600 Gbps to unlimited */
};

static uint8_t ah_attr_to_mlx5_rate(enum ibv_rate ah_static_rate)
{
	if (ah_static_rate >= ARRAY_SIZE(ib_to_mlx5_rate_table))
		return 0;
	return ib_to_mlx5_rate_table[ah_static_rate];
}

static void mlx5_ah_set_udp_sport(struct mlx5_ah *ah,
				  const struct ibv_ah_attr *attr)
{
	uint16_t sport;
	uint32_t fl;

	fl = attr->grh.flow_label & IB_GRH_FLOWLABEL_MASK;
	if (fl)
		sport = ibv_flow_label_to_udp_sport(fl);
	else
		sport = get_random() % (IB_ROCE_UDP_ENCAP_VALID_PORT_MAX + 1
					- IB_ROCE_UDP_ENCAP_VALID_PORT_MIN)
			+ IB_ROCE_UDP_ENCAP_VALID_PORT_MIN;

	ah->av.rlid = htobe16(sport);
}

struct ibv_ah *mlx5_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct mlx5_context *ctx = to_mctx(pd->context);
	struct ibv_port_attr port_attr;
	struct mlx5_ah *ah;
	uint8_t static_rate;
	uint32_t gid_type;
	__be32 tmp;
	uint8_t grh;
	bool is_eth;
	bool grh_req;

	if (attr->port_num < 1 || attr->port_num > ctx->num_ports)
		return NULL;

	if (ctx->cached_link_layer[attr->port_num - 1]) {
		is_eth = ctx->cached_link_layer[attr->port_num - 1] ==
			IBV_LINK_LAYER_ETHERNET;
		grh_req = ctx->cached_port_flags[attr->port_num - 1] &
			IBV_QPF_GRH_REQUIRED;
	} else {
		if (ibv_query_port(pd->context, attr->port_num, &port_attr))
			return NULL;

		is_eth = port_attr.link_layer == IBV_LINK_LAYER_ETHERNET;
		grh_req = port_attr.flags & IBV_QPF_GRH_REQUIRED;
	}

	if (unlikely((!attr->is_global) && (is_eth || grh_req))) {
		errno = EINVAL;
		return NULL;
	}

	ah = calloc(1, sizeof *ah);
	if (!ah)
		return NULL;

	static_rate = ah_attr_to_mlx5_rate(attr->static_rate);
	if (is_eth) {
		if (ibv_query_gid_type(pd->context, attr->port_num,
				       attr->grh.sgid_index, &gid_type))
			goto err;

		if (gid_type == IBV_GID_TYPE_SYSFS_ROCE_V2)
			mlx5_ah_set_udp_sport(ah, attr);

		/* Since RoCE packets must contain GRH, this bit is reserved
		 * for RoCE and shouldn't be set.
		 */
		grh = 0;
		ah->av.stat_rate_sl = (static_rate << 4) | ((attr->sl & 0x7) << 1);
	} else {
		ah->av.fl_mlid = attr->src_path_bits & 0x7f;
		ah->av.rlid = htobe16(attr->dlid);
		grh = 1;
		ah->av.stat_rate_sl = (static_rate << 4) | (attr->sl & 0xf);
	}
	if (attr->is_global) {
		ah->av.tclass = attr->grh.traffic_class;
		ah->av.hop_limit = attr->grh.hop_limit;
		tmp = htobe32((grh << 30) |
			    ((attr->grh.sgid_index & 0xff) << 20) |
			    (attr->grh.flow_label & IB_GRH_FLOWLABEL_MASK));
		ah->av.grh_gid_fl = tmp;
		memcpy(ah->av.rgid, attr->grh.dgid.raw, 16);
	}

	if (is_eth) {
		if (ctx->cmds_supp_uhw & MLX5_USER_CMDS_SUPP_UHW_CREATE_AH) {
			struct mlx5_create_ah_resp resp = {};

			if (ibv_cmd_create_ah(pd, &ah->ibv_ah, attr, &resp.ibv_resp, sizeof(resp)))
				goto err;

			ah->kern_ah = true;
			memcpy(ah->av.rmac, resp.dmac, ETHERNET_LL_SIZE);
		} else {
			if (ibv_resolve_eth_l2_from_gid(pd->context, attr,
							ah->av.rmac, NULL))
				goto err;
		}
	}

	pthread_mutex_init(&ah->mutex, NULL);
	ah->is_global = attr->is_global;

	return &ah->ibv_ah;
err:
	free(ah);
	return NULL;
}

int mlx5_destroy_ah(struct ibv_ah *ah)
{
	struct mlx5_ah *mah = to_mah(ah);
	int err;

	if (mah->kern_ah) {
		err = ibv_cmd_destroy_ah(ah);
		if (err)
			return err;
	}

	if (mah->ah_qp_mapping)
		mlx5dv_devx_obj_destroy(mah->ah_qp_mapping);

	free(mah);
	return 0;
}

static int _mlx5dv_map_ah_to_qp(struct ibv_ah *ah, uint32_t qp_num)
{
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_av_qp_mapping_in)] = {};
	struct mlx5_context *mctx = to_mctx(ah->context);
	struct mlx5_ah *mah = to_mah(ah);
	uint8_t sgid_index;
	void *attr;
	int ret = 0;

	if (!(mctx->general_obj_types_caps &
	      (1ULL << MLX5_OBJ_TYPE_AV_QP_MAPPING)) ||
	    !mah->is_global)
		return EOPNOTSUPP;

	attr = DEVX_ADDR_OF(create_av_qp_mapping_in, in, hdr);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_OBJ_TYPE_AV_QP_MAPPING);

	sgid_index = (be32toh(mah->av.grh_gid_fl) >> 20) & 0xff;
	attr = DEVX_ADDR_OF(create_av_qp_mapping_in, in, mapping);
	DEVX_SET(av_qp_mapping, attr, qpn, qp_num);
	DEVX_SET(av_qp_mapping, attr, remote_address_vector.sl_or_eth_prio,
		 mah->av.stat_rate_sl);
	DEVX_SET(av_qp_mapping, attr, remote_address_vector.src_addr_index,
		 sgid_index);
	memcpy(DEVX_ADDR_OF(av_qp_mapping, attr,
			    remote_address_vector.rgid_or_rip),
	       mah->av.rgid, sizeof(mah->av.rgid));

	pthread_mutex_lock(&mah->mutex);
	if (!mah->ah_qp_mapping) {
		mah->ah_qp_mapping = mlx5dv_devx_obj_create(
			ah->context, in, sizeof(in), out, sizeof(out));
		if (!mah->ah_qp_mapping)
			ret = errno;
	}
	pthread_mutex_unlock(&mah->mutex);

	return ret;
}

int mlx5dv_map_ah_to_qp(struct ibv_ah *ah, uint32_t qp_num)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ah->context);

	if (!dvops || !dvops->map_ah_to_qp)
		return EOPNOTSUPP;

	return dvops->map_ah_to_qp(ah, qp_num);
}

int mlx5_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return ibv_cmd_attach_mcast(qp, gid, lid);
}

int mlx5_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return ibv_cmd_detach_mcast(qp, gid, lid);
}

struct ibv_qp *mlx5_create_qp_ex(struct ibv_context *context,
				 struct ibv_qp_init_attr_ex *attr)
{
	return create_qp(context, attr, NULL);
}

static struct ibv_qp *_mlx5dv_create_qp(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *qp_attr,
				struct mlx5dv_qp_init_attr *mlx5_qp_attr)
{
	return create_qp(context, qp_attr, mlx5_qp_attr);
}

struct ibv_qp *mlx5dv_create_qp(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *qp_attr,
				struct mlx5dv_qp_init_attr *mlx5_qp_attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->create_qp) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_qp(context, qp_attr, mlx5_qp_attr);
}

struct mlx5dv_qp_ex *mlx5dv_qp_ex_from_ibv_qp_ex(struct ibv_qp_ex *qp)
{
	return &(container_of(qp, struct mlx5_qp, verbs_qp.qp_ex))->dv_qp;
}

int mlx5_get_srq_num(struct ibv_srq *srq, uint32_t *srq_num)
{
	struct mlx5_srq *msrq = to_msrq(srq);

	/* May be used by DC users in addition to XRC ones, as there is no
	 * indication on the SRQ for DC usage we can't force the above check.
	 * Even DC users are encouraged to use mlx5dv_init_obj() to get
	 * the SRQN.
	 */
	*srq_num = msrq->srqn;
	return 0;
}

struct ibv_qp *mlx5_open_qp(struct ibv_context *context,
			    struct ibv_qp_open_attr *attr)
{
	struct ibv_open_qp cmd;
	struct ib_uverbs_create_qp_resp resp;
	struct mlx5_qp *qp;
	int ret;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	ret = ibv_cmd_open_qp(context, &qp->verbs_qp, sizeof(qp->verbs_qp),
			      attr, &cmd, sizeof(cmd), &resp, sizeof(resp));
	if (ret)
		goto err;

	return &qp->verbs_qp.qp;

err:
	free(qp);
	return NULL;
}

struct ibv_xrcd *
mlx5_open_xrcd(struct ibv_context *context,
	       struct ibv_xrcd_init_attr *xrcd_init_attr)
{
	int err;
	struct verbs_xrcd *xrcd;
	struct ibv_open_xrcd cmd = {};
	struct ib_uverbs_open_xrcd_resp resp = {};

	xrcd = calloc(1, sizeof(*xrcd));
	if (!xrcd)
		return NULL;

	err = ibv_cmd_open_xrcd(context, xrcd, sizeof(*xrcd), xrcd_init_attr,
				&cmd, sizeof(cmd), &resp, sizeof(resp));
	if (err) {
		free(xrcd);
		return NULL;
	}

	return &xrcd->xrcd;
}

int mlx5_close_xrcd(struct ibv_xrcd *ib_xrcd)
{
	struct verbs_xrcd *xrcd = container_of(ib_xrcd, struct verbs_xrcd, xrcd);
	int ret;

	ret = ibv_cmd_close_xrcd(xrcd);
	if (!ret)
		free(xrcd);

	return ret;
}

static struct ibv_qp *
create_cmd_qp(struct ibv_context *context,
	      struct ibv_srq_init_attr_ex *srq_attr,
	      struct ibv_srq *srq)
{
	struct ibv_qp_init_attr_ex init_attr = {};
	FILE *fp = to_mctx(context)->dbg_fp;
	struct ibv_port_attr port_attr;
	struct ibv_modify_qp qcmd = {};
	struct ibv_qp_attr attr = {};
	struct ibv_query_port pcmd;
	struct ibv_qp *qp;
	int attr_mask;
	int port = 1;
	int ret;

	ret = ibv_cmd_query_port(context, port, &port_attr,
				 &pcmd, sizeof(pcmd));
	if (ret) {
		mlx5_dbg(fp, MLX5_DBG_QP, "ret %d\n", ret);
		return NULL;
	}

	init_attr.qp_type = IBV_QPT_RC;
	init_attr.srq = srq;
	/* Command QP will be used to pass MLX5_OPCODE_TAG_MATCHING messages
	 * to add/remove tag matching list entries.
	 * WQ size is based on max_ops parameter holding max number of
	 * outstanding list operations.
	 */
	init_attr.cap.max_send_wr = srq_attr->tm_cap.max_ops;
	/* Tag matching list entry will point to a single sge buffer */
	init_attr.cap.max_send_sge = 1;
	init_attr.comp_mask = IBV_QP_INIT_ATTR_PD;
	init_attr.pd = srq_attr->pd;
	init_attr.send_cq = srq_attr->cq;
	init_attr.recv_cq = srq_attr->cq;

	qp = create_qp(context, &init_attr, NULL);
	if (!qp)
		return NULL;

	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = port;
	attr_mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX
		  | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

	ret = ibv_cmd_modify_qp(qp, &attr, attr_mask, &qcmd, sizeof(qcmd));
	if (ret) {
		mlx5_dbg(fp, MLX5_DBG_QP, "ret %d\n", ret);
		goto err;
	}

	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = IBV_MTU_256;
	attr.dest_qp_num = qp->qp_num; /* Loopback */
	attr.ah_attr.dlid = port_attr.lid;
	attr.ah_attr.port_num = port;
	attr_mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU
		  | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN
		  | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

	ret = ibv_cmd_modify_qp(qp, &attr, attr_mask, &qcmd, sizeof(qcmd));
	if (ret) {
		mlx5_dbg(fp, MLX5_DBG_QP, "ret %d\n", ret);
		goto err;
	}

	attr.qp_state = IBV_QPS_RTS;
	attr_mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT
		  | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN
		  | IBV_QP_MAX_QP_RD_ATOMIC;

	ret = ibv_cmd_modify_qp(qp, &attr, attr_mask, &qcmd, sizeof(qcmd));
	if (ret) {
		mlx5_dbg(fp, MLX5_DBG_QP, "ret %d\n", ret);
		goto err;
	}

	return qp;

err:
	mlx5_destroy_qp(qp);
	return NULL;
}

struct ibv_srq *mlx5_create_srq_ex(struct ibv_context *context,
				   struct ibv_srq_init_attr_ex *attr)
{
	int err;
	struct mlx5_create_srq_ex cmd;
	struct mlx5_create_srq_resp resp;
	struct mlx5_srq *msrq;
	struct mlx5_context *ctx = to_mctx(context);
	int max_sge;
	struct ibv_srq *ibsrq;
	int uidx;

	if (!(attr->comp_mask & IBV_SRQ_INIT_ATTR_TYPE) ||
	    (attr->srq_type == IBV_SRQT_BASIC))
		return mlx5_create_srq(attr->pd,
				       (struct ibv_srq_init_attr *)attr);

	if (attr->srq_type != IBV_SRQT_XRC &&
	    attr->srq_type != IBV_SRQT_TM) {
		errno = EINVAL;
		return NULL;
	}

	/* An extended CQ is required to read TM information from */
	if (attr->srq_type == IBV_SRQT_TM &&
	    !(attr->cq && (to_mcq(attr->cq)->flags & MLX5_CQ_FLAGS_EXTENDED))) {
		errno = EINVAL;
		return NULL;
	}

	msrq = calloc(1, sizeof(*msrq));
	if (!msrq)
		return NULL;

	ibsrq = (struct ibv_srq *)&msrq->vsrq;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	if (mlx5_spinlock_init_pd(&msrq->lock, attr->pd)) {
		mlx5_err(ctx->dbg_fp, "%s-%d:\n", __func__, __LINE__);
		goto err;
	}

	if (attr->attr.max_wr > ctx->max_srq_recv_wr) {
		mlx5_err(ctx->dbg_fp, "%s-%d:max_wr %d, max_srq_recv_wr %d\n",
			 __func__, __LINE__, attr->attr.max_wr,
			 ctx->max_srq_recv_wr);
		errno = EINVAL;
		goto err;
	}

	/*
	 * this calculation does not consider required control segments. The
	 * final calculation is done again later. This is done so to avoid
	 * overflows of variables
	 */
	max_sge = ctx->max_recv_wr / sizeof(struct mlx5_wqe_data_seg);
	if (attr->attr.max_sge > max_sge) {
		mlx5_err(ctx->dbg_fp, "%s-%d:max_wr %d, max_srq_recv_wr %d\n",
			 __func__, __LINE__, attr->attr.max_wr,
			 ctx->max_srq_recv_wr);
		errno = EINVAL;
		goto err;
	}

	msrq->max_gs  = attr->attr.max_sge;
	msrq->counter = 0;

	if (mlx5_alloc_srq_buf(context, msrq, attr->attr.max_wr, attr->pd)) {
		mlx5_err(ctx->dbg_fp, "%s-%d:\n", __func__, __LINE__);
		goto err;
	}

	msrq->db = mlx5_alloc_dbrec(ctx, attr->pd, &msrq->custom_db);
	if (!msrq->db) {
		mlx5_err(ctx->dbg_fp, "%s-%d:\n", __func__, __LINE__);
		goto err_free;
	}

	if (!msrq->custom_db)
		*msrq->db = 0;

	cmd.buf_addr = (uintptr_t)msrq->buf.buf;
	cmd.db_addr  = (uintptr_t)msrq->db;
	msrq->wq_sig = srq_sig_enabled();
	if (msrq->wq_sig)
		cmd.flags = MLX5_SRQ_FLAG_SIGNATURE;

	attr->attr.max_sge = msrq->max_gs;
	if (ctx->cqe_version) {
		uidx = mlx5_store_uidx(ctx, msrq);
		if (uidx < 0) {
			mlx5_dbg(ctx->dbg_fp, MLX5_DBG_QP, "Couldn't find free user index\n");
			goto err_free_db;
		}
		cmd.uidx = uidx;
	} else {
		cmd.uidx = 0xffffff;
		pthread_mutex_lock(&ctx->srq_table_mutex);
	}

	/* Override max_wr to let kernel know about extra WQEs for the
	 * wait queue.
	 */
	attr->attr.max_wr = msrq->max - 1;

	err = ibv_cmd_create_srq_ex(context, &msrq->vsrq,
				    attr, &cmd.ibv_cmd, sizeof(cmd),
				    &resp.ibv_resp, sizeof(resp));

	/* Override kernel response that includes the wait queue with the real
	 * number of WQEs that are applicable for the application.
	 */
	attr->attr.max_wr = msrq->tail;

	if (err)
		goto err_free_uidx;

	if (attr->srq_type == IBV_SRQT_TM) {
		int i;

		msrq->cmd_qp = create_cmd_qp(context, attr, ibsrq);
		if (!msrq->cmd_qp)
			goto err_destroy;

		msrq->tm_list = calloc(attr->tm_cap.max_num_tags + 1,
				       sizeof(struct mlx5_tag_entry));
		if (!msrq->tm_list)
			goto err_free_cmd;
		for (i = 0; i < attr->tm_cap.max_num_tags; i++)
			msrq->tm_list[i].next = &msrq->tm_list[i + 1];
		msrq->tm_head = &msrq->tm_list[0];
		msrq->tm_tail = &msrq->tm_list[attr->tm_cap.max_num_tags];

		msrq->op = calloc(to_mqp(msrq->cmd_qp)->sq.wqe_cnt,
				  sizeof(struct mlx5_srq_op));
		if (!msrq->op)
			goto err_free_tm;
		msrq->op_head = 0;
		msrq->op_tail = 0;
	}

	if (!ctx->cqe_version) {
		err = mlx5_store_srq(to_mctx(context), resp.srqn, msrq);
		if (err)
			goto err_free_tm;

		pthread_mutex_unlock(&ctx->srq_table_mutex);
	}

	msrq->srqn = resp.srqn;
	msrq->rsc.type = MLX5_RSC_TYPE_XSRQ;
	msrq->rsc.rsn = ctx->cqe_version ? cmd.uidx : resp.srqn;

	return ibsrq;

err_free_tm:
	free(msrq->tm_list);
	free(msrq->op);
err_free_cmd:
	if (msrq->cmd_qp)
		mlx5_destroy_qp(msrq->cmd_qp);
err_destroy:
	ibv_cmd_destroy_srq(ibsrq);

err_free_uidx:
	if (ctx->cqe_version)
		mlx5_clear_uidx(ctx, cmd.uidx);
	else
		pthread_mutex_unlock(&ctx->srq_table_mutex);

err_free_db:
	mlx5_free_db(ctx, msrq->db, attr->pd, msrq->custom_db);

err_free:
	free(msrq->wrid);
	mlx5_free_actual_buf(ctx, &msrq->buf);

err:
	free(msrq);

	return NULL;
}

static void get_pci_atomic_caps(struct ibv_context *context,
				struct ibv_device_attr_ex *attr)
{
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint16_t opmod = (MLX5_CAP_ATOMIC << 1) | HCA_CAP_OPMOD_GET_CUR;
	int ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, opmod);

	ret = mlx5dv_devx_general_cmd(context, in, sizeof(in), out,
				      sizeof(out));
	if (!ret) {
		attr->pci_atomic_caps.fetch_add =
			DEVX_GET(query_hca_cap_out, out,
				 capability.atomic_caps.fetch_add_pci_atomic);
		attr->pci_atomic_caps.swap =
			DEVX_GET(query_hca_cap_out, out,
				 capability.atomic_caps.swap_pci_atomic);
		attr->pci_atomic_caps.compare_swap =
			DEVX_GET(query_hca_cap_out, out,
			capability.atomic_caps.compare_swap_pci_atomic);
	}
}

static void get_hca_general_caps_2(struct mlx5_context *mctx)
{
	uint16_t opmod = MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE_CAP_2 |
		HCA_CAP_OPMOD_GET_CUR;
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	int ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, opmod);

	ret = mlx5dv_devx_general_cmd(&mctx->ibv_ctx.context, in, sizeof(in),
				      out, sizeof(out));
	if (ret)
		return;

	mctx->hca_cap_2_caps.log_reserved_qpns_per_obj =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap_2.log_reserved_qpn_granularity);
}

static void get_hca_sig_caps(uint32_t *hca_caps, struct mlx5_context *mctx)
{
	if (!DEVX_GET(query_hca_cap_out, hca_caps,
		      capability.cmd_hca_cap.sho) ||
	    !DEVX_GET(query_hca_cap_out, hca_caps,
		      capability.cmd_hca_cap.sigerr_domain_and_sig_type))
		return;

	/* Basic signature offload features */
	mctx->sig_caps.block_prot =
		MLX5DV_SIG_PROT_CAP_T10DIF | MLX5DV_SIG_PROT_CAP_CRC;

	mctx->sig_caps.block_size =
		MLX5DV_BLOCK_SIZE_CAP_512 | MLX5DV_BLOCK_SIZE_CAP_520 |
		MLX5DV_BLOCK_SIZE_CAP_4096 | MLX5DV_BLOCK_SIZE_CAP_4160;

	mctx->sig_caps.t10dif_bg =
		MLX5DV_SIG_T10DIF_BG_CAP_CRC | MLX5DV_SIG_T10DIF_BG_CAP_CSUM;

	mctx->sig_caps.crc_type = MLX5DV_SIG_CRC_TYPE_CAP_CRC32;

	/* Optional signature offload features */
	if (DEVX_GET(query_hca_cap_out, hca_caps,
		     capability.cmd_hca_cap.sig_block_4048))
		mctx->sig_caps.block_size |= MLX5DV_BLOCK_SIZE_CAP_4048;

	if (DEVX_GET(query_hca_cap_out, hca_caps,
		     capability.cmd_hca_cap.sig_crc32c))
		mctx->sig_caps.crc_type |= MLX5DV_SIG_CRC_TYPE_CAP_CRC32C;

	if (DEVX_GET(query_hca_cap_out, hca_caps,
		     capability.cmd_hca_cap.sig_crc64_xp10))
		mctx->sig_caps.crc_type |= MLX5DV_SIG_CRC_TYPE_CAP_CRC64_XP10;
}

static void get_hca_general_caps(struct mlx5_context *mctx)
{
	uint16_t opmod = MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE |
		HCA_CAP_OPMOD_GET_CUR;
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	int ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, opmod);

	ret = mlx5dv_devx_general_cmd(&mctx->ibv_ctx.context, in, sizeof(in),
				      out, sizeof(out));
	if (ret)
		return;

	mctx->qp_data_in_order_cap =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.qp_data_in_order);

	mctx->entropy_caps.num_lag_ports =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.num_lag_ports);

	mctx->entropy_caps.lag_tx_port_affinity =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.lag_tx_port_affinity);

	mctx->entropy_caps.rts2rts_qp_udp_sport =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.rts2rts_qp_udp_sport);

	mctx->entropy_caps.rts2rts_lag_tx_port_affinity =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.rts2rts_lag_tx_port_affinity);

	mctx->qos_caps.qos =
		DEVX_GET(query_hca_cap_out, out, capability.cmd_hca_cap.qos);

	mctx->qpc_extension_cap =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.qpc_extension);

	mctx->general_obj_types_caps =
		DEVX_GET64(query_hca_cap_out, out,
			   capability.cmd_hca_cap.general_obj_types);

	get_hca_sig_caps(out, mctx);

	if (DEVX_GET(query_hca_cap_out, out, capability.cmd_hca_cap.crypto))
		mctx->crypto_caps.flags |= MLX5DV_CRYPTO_CAPS_CRYPTO;

	if (DEVX_GET(query_hca_cap_out, out, capability.cmd_hca_cap.aes_xts))
		mctx->crypto_caps.crypto_engines |=
			MLX5DV_CRYPTO_ENGINES_CAP_AES_XTS;

	if (DEVX_GET(query_hca_cap_out, out,
		     capability.cmd_hca_cap.hca_cap_2))
		get_hca_general_caps_2(mctx);

	mctx->dma_mmo_caps.dma_mmo_sq =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.dma_mmo_sq);
	mctx->dma_mmo_caps.dma_mmo_qp =
		DEVX_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.dma_mmo_qp);

	if (mctx->dma_mmo_caps.dma_mmo_sq || mctx->dma_mmo_caps.dma_mmo_qp) {
		uint8_t log_sz;

		log_sz = DEVX_GET(query_hca_cap_out, out,
				  capability.cmd_hca_cap.log_dma_mmo_max_size);
		if (log_sz)
			mctx->dma_mmo_caps.dma_max_size = 1ULL << log_sz;
		else
			mctx->dma_mmo_caps.dma_max_size = MLX5_DMA_MMO_MAX_SIZE;
	}
}

static void get_qos_caps(struct mlx5_context *mctx)
{
	uint16_t opmod = MLX5_SET_HCA_CAP_OP_MOD_QOS |
		HCA_CAP_OPMOD_GET_CUR;
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	int ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, opmod);

	ret = mlx5dv_devx_general_cmd(&mctx->ibv_ctx.context, in, sizeof(in), out,
				      sizeof(out));
	if (ret)
		return;

	mctx->qos_caps.nic_sq_scheduling =
		DEVX_GET(query_hca_cap_out, out,
			 capability.qos_caps.nic_sq_scheduling);
	if (mctx->qos_caps.nic_sq_scheduling) {
		mctx->qos_caps.nic_bw_share =
			DEVX_GET(query_hca_cap_out, out,
				 capability.qos_caps.nic_bw_share);
		mctx->qos_caps.nic_rate_limit =
			DEVX_GET(query_hca_cap_out, out,
				 capability.qos_caps.nic_rate_limit);
	}
	mctx->qos_caps.nic_qp_scheduling =
		DEVX_GET(query_hca_cap_out, out,
			 capability.qos_caps.nic_qp_scheduling);
	mctx->qos_caps.nic_element_type =
		DEVX_GET(query_hca_cap_out, out,
			 capability.qos_caps.nic_element_type);
	mctx->qos_caps.nic_tsar_type =
		DEVX_GET(query_hca_cap_out, out,
			 capability.qos_caps.nic_tsar_type);
}

static void get_crypto_caps(struct mlx5_context *mctx)
{
	uint16_t opmod = MLX5_SET_HCA_CAP_OP_MOD_CRYPTO | HCA_CAP_OPMOD_GET_CUR;
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	int ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, opmod);

	ret = mlx5dv_devx_general_cmd(&mctx->ibv_ctx.context, in, sizeof(in),
				      out, sizeof(out));
	if (ret)
		return;

	if (DEVX_GET(query_hca_cap_out, out,
		     capability.crypto_caps.wrapped_crypto_operational))
		mctx->crypto_caps.flags |=
			MLX5DV_CRYPTO_CAPS_WRAPPED_CRYPTO_OPERATIONAL;

	if (DEVX_GET(query_hca_cap_out, out,
		     capability.crypto_caps
			     .wrapped_crypto_going_to_commissioning))
		mctx->crypto_caps.flags |=
			MLX5DV_CRYPTO_CAPS_WRAPPED_CRYPTO_GOING_TO_COMMISSIONING;

	if (DEVX_GET(query_hca_cap_out, out,
		     capability.crypto_caps.wrapped_import_method) &
	    MLX5_CRYPTO_CAPS_WRAPPED_IMPORT_METHOD_AES)
		mctx->crypto_caps.wrapped_import_method |=
			MLX5DV_CRYPTO_WRAPPED_IMPORT_METHOD_CAP_AES_XTS;

	mctx->crypto_caps.log_max_num_deks =
		DEVX_GET(query_hca_cap_out, out,
			 capability.crypto_caps.log_max_num_deks);
	mctx->crypto_caps.failed_selftests =
		DEVX_GET(query_hca_cap_out, out,
			 capability.crypto_caps.failed_selftests);
}

int mlx5_query_device_ex(struct ibv_context *context,
			 const struct ibv_query_device_ex_input *input,
			 struct ibv_device_attr_ex *attr,
			 size_t attr_size)
{
	struct mlx5_context *mctx = to_mctx(context);
	struct mlx5_query_device_ex_resp resp = {};
	size_t resp_size =
		(mctx->cmds_supp_uhw & MLX5_USER_CMDS_SUPP_UHW_QUERY_DEVICE) ?
			sizeof(resp) :
			sizeof(resp.ibv_resp);
	struct ibv_device_attr *a;
	uint64_t raw_fw_ver;
	unsigned sub_minor;
	unsigned major;
	unsigned minor;
	int err;

	err = ibv_cmd_query_device_any(context, input, attr, attr_size,
				       &resp.ibv_resp, &resp_size);
	if (err)
		return err;

	if (attr_size >= offsetofend(struct ibv_device_attr_ex, tso_caps)) {
		attr->tso_caps.max_tso = resp.tso_caps.max_tso;
		attr->tso_caps.supported_qpts = resp.tso_caps.supported_qpts;
	}
	if (attr_size >= offsetofend(struct ibv_device_attr_ex, rss_caps)) {
		attr->rss_caps.rx_hash_fields_mask =
			resp.rss_caps.rx_hash_fields_mask;
		attr->rss_caps.rx_hash_function =
			resp.rss_caps.rx_hash_function;
	}
	if (attr_size >=
	    offsetofend(struct ibv_device_attr_ex, packet_pacing_caps)) {
		attr->packet_pacing_caps.qp_rate_limit_min =
			resp.packet_pacing_caps.qp_rate_limit_min;
		attr->packet_pacing_caps.qp_rate_limit_max =
			resp.packet_pacing_caps.qp_rate_limit_max;
		attr->packet_pacing_caps.supported_qpts =
			resp.packet_pacing_caps.supported_qpts;
	}

	if (attr_size >= offsetofend(struct ibv_device_attr_ex, pci_atomic_caps))
		get_pci_atomic_caps(context, attr);

	raw_fw_ver = resp.ibv_resp.base.fw_ver;
	major     = (raw_fw_ver >> 32) & 0xffff;
	minor     = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;
	a = &attr->orig_attr;
	snprintf(a->fw_ver, sizeof(a->fw_ver), "%d.%d.%04d",
		 major, minor, sub_minor);

	return 0;
}

void mlx5_query_device_ctx(struct mlx5_context *mctx)
{
	struct ibv_device_attr_ex device_attr;
	struct mlx5_query_device_ex_resp resp = {};
	size_t resp_size =
		(mctx->cmds_supp_uhw & MLX5_USER_CMDS_SUPP_UHW_QUERY_DEVICE) ?
			sizeof(resp) :
			sizeof(resp.ibv_resp);

	get_hca_general_caps(mctx);

	if (mctx->qos_caps.qos)
		get_qos_caps(mctx);

	if (mctx->crypto_caps.flags & MLX5DV_CRYPTO_CAPS_CRYPTO)
		get_crypto_caps(mctx);

	if (ibv_cmd_query_device_any(&mctx->ibv_ctx.context, NULL, &device_attr,
				     sizeof(device_attr), &resp.ibv_resp,
				     &resp_size))
		return;

	mctx->cached_device_cap_flags = device_attr.orig_attr.device_cap_flags;
	mctx->atomic_cap = device_attr.orig_attr.atomic_cap;
	mctx->max_dm_size = device_attr.max_dm_size;
	mctx->cached_tso_caps = resp.tso_caps;

	if (resp.mlx5_ib_support_multi_pkt_send_wqes & MLX5_IB_ALLOW_MPW)
		mctx->vendor_cap_flags |= MLX5_VENDOR_CAP_FLAGS_MPW_ALLOWED;

	if (resp.mlx5_ib_support_multi_pkt_send_wqes & MLX5_IB_SUPPORT_EMPW)
		mctx->vendor_cap_flags |= MLX5_VENDOR_CAP_FLAGS_ENHANCED_MPW;

	mctx->cqe_comp_caps.max_num = resp.cqe_comp_caps.max_num;
	mctx->cqe_comp_caps.supported_format =
		resp.cqe_comp_caps.supported_format;
	mctx->sw_parsing_caps.sw_parsing_offloads =
		resp.sw_parsing_caps.sw_parsing_offloads;
	mctx->sw_parsing_caps.supported_qpts =
		resp.sw_parsing_caps.supported_qpts;
	mctx->striding_rq_caps.min_single_stride_log_num_of_bytes =
		resp.striding_rq_caps.min_single_stride_log_num_of_bytes;
	mctx->striding_rq_caps.max_single_stride_log_num_of_bytes =
		resp.striding_rq_caps.max_single_stride_log_num_of_bytes;
	mctx->striding_rq_caps.min_single_wqe_log_num_of_strides =
		resp.striding_rq_caps.min_single_wqe_log_num_of_strides;
	mctx->striding_rq_caps.max_single_wqe_log_num_of_strides =
		resp.striding_rq_caps.max_single_wqe_log_num_of_strides;
	mctx->striding_rq_caps.supported_qpts =
		resp.striding_rq_caps.supported_qpts;
	mctx->tunnel_offloads_caps = resp.tunnel_offloads_caps;
	mctx->packet_pacing_caps = resp.packet_pacing_caps;
	mctx->dci_streams_caps.max_log_num_concurent =
		resp.dci_streams_caps.max_log_num_concurent;
	mctx->dci_streams_caps.max_log_num_errored =
		resp.dci_streams_caps.max_log_num_errored;

	if (resp.flags & MLX5_IB_QUERY_DEV_RESP_FLAGS_CQE_128B_COMP)
		mctx->vendor_cap_flags |= MLX5_VENDOR_CAP_FLAGS_CQE_128B_COMP;

	if (resp.flags & MLX5_IB_QUERY_DEV_RESP_FLAGS_CQE_128B_PAD)
		mctx->vendor_cap_flags |= MLX5_VENDOR_CAP_FLAGS_CQE_128B_PAD;

	if (resp.flags & MLX5_IB_QUERY_DEV_RESP_PACKET_BASED_CREDIT_MODE)
		mctx->vendor_cap_flags |=
			MLX5_VENDOR_CAP_FLAGS_PACKET_BASED_CREDIT_MODE;

	if (resp.flags & MLX5_IB_QUERY_DEV_RESP_FLAGS_SCAT2CQE_DCT)
		mctx->vendor_cap_flags |= MLX5_VENDOR_CAP_FLAGS_SCAT2CQE_DCT;
}

static int rwq_sig_enabled(struct ibv_context *context)
{
	char *env;

	env = getenv("MLX5_RWQ_SIGNATURE");
	if (env)
		return 1;

	return 0;
}

static void mlx5_free_rwq_buf(struct mlx5_rwq *rwq, struct ibv_context *context)
{
	struct mlx5_context *ctx = to_mctx(context);

	mlx5_free_actual_buf(ctx, &rwq->buf);
	free(rwq->rq.wrid);
}

static int mlx5_alloc_rwq_buf(struct ibv_context *context,
			      struct ibv_pd *pd,
			      struct mlx5_rwq *rwq,
			      int size)
{
	int err;
	enum mlx5_alloc_type alloc_type;

	mlx5_get_alloc_type(to_mctx(context), pd, MLX5_RWQ_PREFIX,
			    &alloc_type, MLX5_ALLOC_TYPE_ANON);

	rwq->rq.wrid = malloc(rwq->rq.wqe_cnt * sizeof(uint64_t));
	if (!rwq->rq.wrid) {
		errno = ENOMEM;
		return -1;
	}

	if (alloc_type == MLX5_ALLOC_TYPE_CUSTOM) {
		rwq->buf.mparent_domain = to_mparent_domain(pd);
		rwq->buf.req_alignment = to_mdev(context->device)->page_size;
		rwq->buf.resource_type = MLX5DV_RES_TYPE_RWQ;
	}

	err = mlx5_alloc_prefered_buf(to_mctx(context), &rwq->buf,
				      align(rwq->buf_size, to_mdev
				      (context->device)->page_size),
				      to_mdev(context->device)->page_size,
				      alloc_type,
				      MLX5_RWQ_PREFIX);

	if (err) {
		free(rwq->rq.wrid);
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

static struct ibv_wq *create_wq(struct ibv_context *context,
			 struct ibv_wq_init_attr *attr,
			 struct mlx5dv_wq_init_attr *mlx5wq_attr)
{
	struct mlx5_create_wq		cmd;
	struct mlx5_create_wq_resp		resp;
	int				err;
	struct mlx5_rwq			*rwq;
	struct mlx5_context	*ctx = to_mctx(context);
	int ret;
	int32_t				usr_idx = 0;
	FILE *fp = ctx->dbg_fp;

	if (attr->wq_type != IBV_WQT_RQ)
		return NULL;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	rwq = calloc(1, sizeof(*rwq));
	if (!rwq)
		return NULL;

	rwq->wq_sig = rwq_sig_enabled(context);
	if (rwq->wq_sig)
		cmd.flags = MLX5_WQ_FLAG_SIGNATURE;

	ret = mlx5_calc_rwq_size(ctx, rwq, attr, mlx5wq_attr);
	if (ret < 0) {
		errno = -ret;
		goto err;
	}

	rwq->buf_size = ret;
	if (mlx5_alloc_rwq_buf(context, attr->pd, rwq, ret))
		goto err;

	mlx5_init_rwq_indices(rwq);

	if (mlx5_spinlock_init_pd(&rwq->rq.lock, attr->pd))
		goto err_free_rwq_buf;

	rwq->db = mlx5_alloc_dbrec(ctx, attr->pd, &rwq->custom_db);
	if (!rwq->db)
		goto err_free_rwq_buf;

	if (!rwq->custom_db) {
		rwq->db[MLX5_RCV_DBR] = 0;
		rwq->db[MLX5_SND_DBR] = 0;
	}

	rwq->pbuff = rwq->buf.buf + rwq->rq.offset;
	rwq->recv_db =  &rwq->db[MLX5_RCV_DBR];
	cmd.buf_addr = (uintptr_t)rwq->buf.buf;
	cmd.db_addr  = (uintptr_t)rwq->db;
	cmd.rq_wqe_count = rwq->rq.wqe_cnt;
	cmd.rq_wqe_shift = rwq->rq.wqe_shift;
	usr_idx = mlx5_store_uidx(ctx, rwq);
	if (usr_idx < 0) {
		mlx5_dbg(fp, MLX5_DBG_QP, "Couldn't find free user index\n");
		goto err_free_db_rec;
	}

	cmd.user_index = usr_idx;

	if (mlx5wq_attr) {
		if (mlx5wq_attr->comp_mask & MLX5DV_WQ_INIT_ATTR_MASK_STRIDING_RQ) {
			if ((mlx5wq_attr->striding_rq_attrs.single_stride_log_num_of_bytes <
			    ctx->striding_rq_caps.min_single_stride_log_num_of_bytes) ||
			    (mlx5wq_attr->striding_rq_attrs.single_stride_log_num_of_bytes >
			     ctx->striding_rq_caps.max_single_stride_log_num_of_bytes)) {
				errno = EINVAL;
				goto err_create;
			}

			if ((mlx5wq_attr->striding_rq_attrs.single_wqe_log_num_of_strides <
			     ctx->striding_rq_caps.min_single_wqe_log_num_of_strides) ||
			    (mlx5wq_attr->striding_rq_attrs.single_wqe_log_num_of_strides >
			     ctx->striding_rq_caps.max_single_wqe_log_num_of_strides)) {
				errno = EINVAL;
				goto err_create;
			}

			cmd.single_stride_log_num_of_bytes =
				mlx5wq_attr->striding_rq_attrs.single_stride_log_num_of_bytes;
			cmd.single_wqe_log_num_of_strides =
				mlx5wq_attr->striding_rq_attrs.single_wqe_log_num_of_strides;
			cmd.two_byte_shift_en =
				mlx5wq_attr->striding_rq_attrs.two_byte_shift_en;
			cmd.comp_mask |= MLX5_IB_CREATE_WQ_STRIDING_RQ;
		}
	}

	err = ibv_cmd_create_wq(context, attr, &rwq->wq, &cmd.ibv_cmd,
				sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (err)
		goto err_create;

	rwq->rsc.type = MLX5_RSC_TYPE_RWQ;
	rwq->rsc.rsn =  cmd.user_index;

	rwq->wq.post_recv = mlx5_post_wq_recv;
	return &rwq->wq;

err_create:
	mlx5_clear_uidx(ctx, cmd.user_index);
err_free_db_rec:
	mlx5_free_db(to_mctx(context), rwq->db, attr->pd, rwq->custom_db);
err_free_rwq_buf:
	mlx5_free_rwq_buf(rwq, context);
err:
	free(rwq);
	return NULL;
}

struct ibv_wq *mlx5_create_wq(struct ibv_context *context,
			      struct ibv_wq_init_attr *attr)
{
	return create_wq(context, attr, NULL);
}

static struct ibv_wq *_mlx5dv_create_wq(struct ibv_context *context,
					struct ibv_wq_init_attr *attr,
					struct mlx5dv_wq_init_attr *mlx5_wq_attr)
{
	return create_wq(context, attr, mlx5_wq_attr);
}

struct ibv_wq *mlx5dv_create_wq(struct ibv_context *context,
				struct ibv_wq_init_attr *attr,
				struct mlx5dv_wq_init_attr *mlx5_wq_attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->create_wq) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_wq(context, attr, mlx5_wq_attr);
}

int mlx5_modify_wq(struct ibv_wq *wq, struct ibv_wq_attr *attr)
{
	struct mlx5_modify_wq	cmd = {};
	struct mlx5_rwq *rwq = to_mrwq(wq);

	if ((attr->attr_mask & IBV_WQ_ATTR_STATE) &&
	    attr->wq_state == IBV_WQS_RDY) {
		if ((attr->attr_mask & IBV_WQ_ATTR_CURR_STATE) &&
		    attr->curr_wq_state != wq->state)
			return -EINVAL;

		if (wq->state == IBV_WQS_RESET) {
			mlx5_spin_lock(&to_mcq(wq->cq)->lock);
			__mlx5_cq_clean(to_mcq(wq->cq),
					rwq->rsc.rsn, NULL);
			mlx5_spin_unlock(&to_mcq(wq->cq)->lock);
			mlx5_init_rwq_indices(rwq);
			rwq->db[MLX5_RCV_DBR] = 0;
			rwq->db[MLX5_SND_DBR] = 0;
		}
	}

	return ibv_cmd_modify_wq(wq, attr, &cmd.ibv_cmd, sizeof(cmd));
}

int mlx5_destroy_wq(struct ibv_wq *wq)
{
	struct mlx5_rwq *rwq = to_mrwq(wq);
	int ret;

	ret = ibv_cmd_destroy_wq(wq);
	if (ret)
		return ret;

	mlx5_spin_lock(&to_mcq(wq->cq)->lock);
	__mlx5_cq_clean(to_mcq(wq->cq), rwq->rsc.rsn, NULL);
	mlx5_spin_unlock(&to_mcq(wq->cq)->lock);
	mlx5_clear_uidx(to_mctx(wq->context), rwq->rsc.rsn);
	mlx5_free_db(to_mctx(wq->context), rwq->db, wq->pd, rwq->custom_db);
	mlx5_free_rwq_buf(rwq, wq->context);
	free(rwq);

	return 0;
}

static void free_flow_counters_descriptions(struct mlx5_ib_create_flow *cmd)
{
	int i;

	for (i = 0; i < cmd->ncounters_data; i++)
		free(cmd->data[i].counters_data);
}

static int get_flow_mcounters(struct mlx5_flow *mflow,
			      struct ibv_flow_attr *flow_attr,
			      struct mlx5_counters **mcounters,
			      uint32_t *data_size)
{
	struct ibv_flow_spec *ib_spec;
	uint32_t ncounters_used = 0;
	int i;

	ib_spec = (struct ibv_flow_spec *)(flow_attr + 1);
	for (i = 0; i < flow_attr->num_of_specs; i++, ib_spec = (void *)ib_spec + ib_spec->hdr.size) {
		if (ib_spec->hdr.type != IBV_FLOW_SPEC_ACTION_COUNT)
			continue;

		/* currently support only one counters data */
		if (ncounters_used > 0)
			return EINVAL;

		*mcounters  = to_mcounters(ib_spec->flow_count.counters);
		ncounters_used++;
	}

	*data_size = ncounters_used * sizeof(struct mlx5_ib_flow_counters_data);
	return 0;
}

static int allocate_flow_counters_descriptions(struct mlx5_counters *mcounters,
					       struct mlx5_ib_create_flow *cmd)
{
	struct mlx5_ib_flow_counters_data *mcntrs_data;
	struct mlx5_ib_flow_counters_desc *cntrs_data;
	struct mlx5_counter_node *cntr_node;
	uint32_t ncounters;
	int j = 0;

	mcntrs_data = cmd->data;
	ncounters = mcounters->ncounters;

	/* mlx5_attach_counters_point_flow was never called */
	if (!ncounters)
		return EINVAL;

	/* each counter has both index and description */
	cntrs_data = calloc(ncounters, sizeof(*cntrs_data));
	if (!cntrs_data)
		return ENOMEM;

	list_for_each(&mcounters->counters_list, cntr_node, entry) {
		cntrs_data[j].description = cntr_node->desc;
		cntrs_data[j].index = cntr_node->index;
		j++;
	}

	scrub_ptr_attr(cntrs_data);
	mcntrs_data[cmd->ncounters_data].counters_data = cntrs_data;
	mcntrs_data[cmd->ncounters_data].ncounters = ncounters;
	cmd->ncounters_data++;

	return 0;
}

struct ibv_flow *mlx5_create_flow(struct ibv_qp *qp, struct ibv_flow_attr *flow_attr)
{
	struct mlx5_ib_create_flow *cmd;
	uint32_t required_cmd_size = 0;
	struct ibv_flow *flow_id;
	struct mlx5_flow *mflow;
	int ret;

	mflow = calloc(1, sizeof(*mflow));
	if (!mflow) {
		errno = ENOMEM;
		return NULL;
	}

	ret = get_flow_mcounters(mflow, flow_attr, &mflow->mcounters, &required_cmd_size);
	if (ret) {
		errno = ret;
		goto err_get_mcounters;
	}

	required_cmd_size += sizeof(*cmd);
	cmd = calloc(1, required_cmd_size);
	if (!cmd) {
		errno = ENOMEM;
		goto err_get_mcounters;
	}

	if (mflow->mcounters) {
		pthread_mutex_lock(&mflow->mcounters->lock);
		/* if the counters already bound no need to pass its description */
		if (!mflow->mcounters->refcount) {
			ret = allocate_flow_counters_descriptions(mflow->mcounters, cmd);
			if (ret) {
				errno = ret;
				goto err_desc_alloc;
			}
		}
	}

	flow_id = &mflow->flow_id;
	ret = ibv_cmd_create_flow(qp, flow_id, flow_attr,
				  cmd, required_cmd_size);
	if (ret)
		goto err_create_flow;

	if (mflow->mcounters) {
		free_flow_counters_descriptions(cmd);
		mflow->mcounters->refcount++;
		pthread_mutex_unlock(&mflow->mcounters->lock);
	}

	free(cmd);

	return flow_id;

err_create_flow:
	if (mflow->mcounters) {
		free_flow_counters_descriptions(cmd);
		pthread_mutex_unlock(&mflow->mcounters->lock);
	}
err_desc_alloc:
	free(cmd);
err_get_mcounters:
	free(mflow);
	return NULL;
}

int mlx5_destroy_flow(struct ibv_flow *flow_id)
{
	struct mlx5_flow *mflow = to_mflow(flow_id);
	int ret;

	ret = ibv_cmd_destroy_flow(flow_id);
	if (ret)
		return ret;

	if (mflow->mcounters) {
		pthread_mutex_lock(&mflow->mcounters->lock);
		mflow->mcounters->refcount--;
		pthread_mutex_unlock(&mflow->mcounters->lock);
	}

	free(mflow);
	return 0;
}

struct ibv_rwq_ind_table *mlx5_create_rwq_ind_table(struct ibv_context *context,
						    struct ibv_rwq_ind_table_init_attr *init_attr)
{
	struct mlx5_create_rwq_ind_table_resp resp;
	struct ibv_rwq_ind_table *ind_table;
	int err;

	memset(&resp, 0, sizeof(resp));
	ind_table = calloc(1, sizeof(*ind_table));
	if (!ind_table)
		return NULL;

	err = ibv_cmd_create_rwq_ind_table(context, init_attr, ind_table,
					   &resp.ibv_resp, sizeof(resp));
	if (err)
		goto err;

	return ind_table;

err:
	free(ind_table);
	return NULL;
}

int mlx5_destroy_rwq_ind_table(struct ibv_rwq_ind_table *rwq_ind_table)
{
	int ret;

	ret = ibv_cmd_destroy_rwq_ind_table(rwq_ind_table);

	if (ret)
		return ret;

	free(rwq_ind_table);
	return 0;
}

int mlx5_modify_cq(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr)
{
	struct ibv_modify_cq cmd = {};

	return ibv_cmd_modify_cq(cq, attr, &cmd, sizeof(cmd));
}

static struct ibv_flow_action *_mlx5_create_flow_action_esp(struct ibv_context *ctx,
							    struct ibv_flow_action_esp_attr *attr,
							    struct ibv_command_buffer *driver_attr)
{
	struct verbs_flow_action *action;
	int ret;

	if (!check_comp_mask(attr->comp_mask, IBV_FLOW_ACTION_ESP_MASK_ESN)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	action = calloc(1, sizeof(*action));
	if (!action) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ibv_cmd_create_flow_action_esp(ctx, attr, action, driver_attr);
	if (ret) {
		free(action);
		return NULL;
	}

	return &action->action;
}

struct ibv_flow_action *mlx5_create_flow_action_esp(struct ibv_context *ctx,
						    struct ibv_flow_action_esp_attr *attr)
{
	return _mlx5_create_flow_action_esp(ctx, attr, NULL);
}

static struct ibv_flow_action *
_mlx5dv_create_flow_action_esp(struct ibv_context *ctx,
			       struct ibv_flow_action_esp_attr *esp,
			       struct mlx5dv_flow_action_esp *mlx5_attr)
{
	DECLARE_COMMAND_BUFFER_LINK(driver_attr, UVERBS_OBJECT_FLOW_ACTION,
				    UVERBS_METHOD_FLOW_ACTION_ESP_CREATE, 1,
				    NULL);

	if (!check_comp_mask(mlx5_attr->comp_mask,
			     MLX5DV_FLOW_ACTION_ESP_MASK_FLAGS)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (mlx5_attr->comp_mask & MLX5DV_FLOW_ACTION_ESP_MASK_FLAGS) {
		if (!check_comp_mask(mlx5_attr->action_flags,
				     MLX5_IB_UAPI_FLOW_ACTION_FLAGS_REQUIRE_METADATA)) {
			errno = EOPNOTSUPP;
			return NULL;
		}
		fill_attr_in_uint64(driver_attr, MLX5_IB_ATTR_CREATE_FLOW_ACTION_FLAGS,
				    mlx5_attr->action_flags);
	}

	return _mlx5_create_flow_action_esp(ctx, esp, driver_attr);
}

struct ibv_flow_action *mlx5dv_create_flow_action_esp(struct ibv_context *ctx,
						      struct ibv_flow_action_esp_attr *esp,
						      struct mlx5dv_flow_action_esp *mlx5_attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->create_flow_action_esp) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_flow_action_esp(ctx, esp,
						      mlx5_attr);
}

int mlx5_modify_flow_action_esp(struct ibv_flow_action *action,
				struct ibv_flow_action_esp_attr *attr)
{
	struct verbs_flow_action *vaction =
		container_of(action, struct verbs_flow_action, action);

	if (!check_comp_mask(attr->comp_mask, IBV_FLOW_ACTION_ESP_MASK_ESN))
		return EOPNOTSUPP;

	return ibv_cmd_modify_flow_action_esp(vaction, attr, NULL);
}

static struct ibv_flow_action *
_mlx5dv_create_flow_action_modify_header(struct ibv_context *ctx,
					 size_t actions_sz,
					 uint64_t actions[],
					 enum mlx5dv_flow_table_type ft_type)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_FLOW_ACTION,
			       MLX5_IB_METHOD_FLOW_ACTION_CREATE_MODIFY_HEADER,
			       3);
	struct ib_uverbs_attr *handle = fill_attr_out_obj(cmd,
							  MLX5_IB_ATTR_CREATE_MODIFY_HEADER_HANDLE);
	struct verbs_flow_action *action;
	int ret;

	fill_attr_in(cmd, MLX5_IB_ATTR_CREATE_MODIFY_HEADER_ACTIONS_PRM,
		     actions, actions_sz);
	fill_attr_const_in(cmd, MLX5_IB_ATTR_CREATE_MODIFY_HEADER_FT_TYPE,
			   ft_type);

	action = calloc(1, sizeof(*action));
	if (!action) {
		errno = ENOMEM;
		return NULL;
	}

	ret = execute_ioctl(ctx, cmd);
	if (ret) {
		free(action);
		return NULL;
	}

	action->action.context = ctx;
	action->type = IBV_FLOW_ACTION_UNSPECIFIED;
	action->handle = read_attr_obj(MLX5_IB_ATTR_CREATE_MODIFY_HEADER_HANDLE,
				       handle);

	return &action->action;
}

struct ibv_flow_action *mlx5dv_create_flow_action_modify_header(struct ibv_context *ctx,
								size_t actions_sz,
								uint64_t actions[],
								enum mlx5dv_flow_table_type ft_type)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->create_flow_action_modify_header) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_flow_action_modify_header(ctx, actions_sz,
								actions, ft_type);

}

static struct ibv_flow_action *
_mlx5dv_create_flow_action_packet_reformat(struct ibv_context *ctx,
					   size_t data_sz,
					   void *data,
					   enum mlx5dv_flow_action_packet_reformat_type reformat_type,
					   enum mlx5dv_flow_table_type ft_type)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_FLOW_ACTION,
			       MLX5_IB_METHOD_FLOW_ACTION_CREATE_PACKET_REFORMAT, 4);
	struct ib_uverbs_attr *handle = fill_attr_out_obj(cmd,
							  MLX5_IB_ATTR_CREATE_PACKET_REFORMAT_HANDLE);
	struct verbs_flow_action *action;
	int ret;

	if ((!data && data_sz) || (data && !data_sz)) {
		errno = EINVAL;
		return NULL;
	}

	if (data && data_sz)
		fill_attr_in(cmd,
			     MLX5_IB_ATTR_CREATE_PACKET_REFORMAT_DATA_BUF,
			     data, data_sz);

	fill_attr_const_in(cmd, MLX5_IB_ATTR_CREATE_PACKET_REFORMAT_TYPE,
			   reformat_type);

	fill_attr_const_in(cmd, MLX5_IB_ATTR_CREATE_PACKET_REFORMAT_FT_TYPE,
			   ft_type);

	action = calloc(1, sizeof(*action));
	if (!action) {
		errno = ENOMEM;
		return NULL;
	}

	ret = execute_ioctl(ctx, cmd);
	if (ret) {
		free(action);
		return NULL;
	}

	action->action.context = ctx;
	action->type = IBV_FLOW_ACTION_UNSPECIFIED;
	action->handle = read_attr_obj(MLX5_IB_ATTR_CREATE_PACKET_REFORMAT_HANDLE,
				       handle);

	return &action->action;
}

struct ibv_flow_action *
mlx5dv_create_flow_action_packet_reformat(struct ibv_context *ctx,
					  size_t data_sz,
					  void *data,
					  enum mlx5dv_flow_action_packet_reformat_type reformat_type,
					  enum mlx5dv_flow_table_type ft_type)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->create_flow_action_packet_reformat) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_flow_action_packet_reformat(ctx, data_sz, data,
								  reformat_type, ft_type);
}

int mlx5_destroy_flow_action(struct ibv_flow_action *action)
{
	struct verbs_flow_action *vaction =
		container_of(action, struct verbs_flow_action, action);
	int ret = ibv_cmd_destroy_flow_action(vaction);

	if (!ret)
		free(action);

	return ret;
}

static inline int mlx5_access_dm(struct ibv_dm *ibdm, uint64_t dm_offset,
				 void *host_addr, size_t length,
				 uint32_t read)
{
	struct mlx5_dm *dm = to_mdm(ibdm);
	atomic_uint32_t *dm_ptr =
		(atomic_uint32_t *)dm->start_va + dm_offset / 4;
	uint32_t *host_ptr = host_addr;
	const uint32_t *host_end = host_ptr + length / 4;

	if (dm_offset + length > dm->length)
		return EFAULT;

	/* Due to HW limitation, DM access address and length must be aligned
	 * to 4 bytes.
	 */
	if ((length & 3) || (dm_offset & 3))
		return EINVAL;

	/* Copy granularity should be 4 Bytes since we enforce copy size to be
	 * a multiple of 4 bytes.
	 */
	if (read) {
		while (host_ptr != host_end) {
			*host_ptr = atomic_load_explicit(dm_ptr,
							 memory_order_relaxed);
			host_ptr++;
			dm_ptr++;
		}
	} else {
		while (host_ptr != host_end) {
			atomic_store_explicit(dm_ptr, *host_ptr,
					      memory_order_relaxed);
			host_ptr++;
			dm_ptr++;
		}
	}

	return 0;
}
static inline int mlx5_memcpy_to_dm(struct ibv_dm *ibdm, uint64_t dm_offset,
				    const void *host_addr, size_t length)
{
	return mlx5_access_dm(ibdm, dm_offset, (void *)host_addr, length, 0);
}

static inline int mlx5_memcpy_from_dm(void *host_addr, struct ibv_dm *ibdm,
				      uint64_t dm_offset, size_t length)
{
	return mlx5_access_dm(ibdm, dm_offset, host_addr, length, 1);
}

static void *dm_mmap(struct ibv_context *context, struct mlx5_dm *mdm,
		     uint16_t page_idx, size_t length)
{
	int page_size = to_mdev(context->device)->page_size;
	uint64_t act_size = align(length, page_size);
	off_t offset = 0;

	set_command(MLX5_IB_MMAP_DEVICE_MEM, &offset);
	set_extended_index(page_idx, &offset);
	return mmap(NULL, act_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		    context->cmd_fd, page_size * offset);
}

static void *_mlx5dv_dm_map_op_addr(struct ibv_dm *dm, uint8_t op)
{
	int page_size = to_mdev(dm->context->device)->page_size;
	struct mlx5_dm *mdm = to_mdm(dm);
	uint64_t start_offset;
	uint16_t page_idx;
	void *va;
	int ret;

	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DM,
			       MLX5_IB_METHOD_DM_MAP_OP_ADDR, 4);
	fill_attr_in_obj(cmdb, MLX5_IB_ATTR_DM_MAP_OP_ADDR_REQ_HANDLE,
			 mdm->verbs_dm.handle);
	fill_attr_in(cmdb, MLX5_IB_ATTR_DM_MAP_OP_ADDR_REQ_OP, &op, sizeof(op));

	fill_attr_out(cmdb, MLX5_IB_ATTR_DM_MAP_OP_ADDR_RESP_START_OFFSET,
		      &start_offset, sizeof(start_offset));
	fill_attr_out(cmdb, MLX5_IB_ATTR_DM_MAP_OP_ADDR_RESP_PAGE_INDEX,
		      &page_idx, sizeof(page_idx));

	ret = execute_ioctl(dm->context, cmdb);
	if (ret)
		return NULL;

	va = dm_mmap(dm->context, mdm, page_idx, mdm->length);
	if (va == MAP_FAILED)
		return NULL;

	return va + (start_offset & (page_size - 1));
}

void *mlx5dv_dm_map_op_addr(struct ibv_dm *dm, uint8_t op)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(dm->context);

	if (!dvops || !dvops->dm_map_op_addr) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->dm_map_op_addr(dm, op);
}

void mlx5_unimport_dm(struct ibv_dm *ibdm)
{
	struct mlx5_dm *dm = to_mdm(ibdm);
	size_t act_size = align(dm->length,
				to_mdev(ibdm->context->device)->page_size);

	munmap(dm->mmap_va, act_size);
	free(dm);
}

struct ibv_dm *mlx5_import_dm(struct ibv_context *context,
			      uint32_t dm_handle)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_DM, MLX5_IB_METHOD_DM_QUERY,
			       4);
	int page_size = to_mdev(context->device)->page_size;
	uint64_t start_offset, length;
	struct mlx5_dm *dm;
	uint16_t page_idx;
	void *va;
	int ret;

	dm = calloc(1, sizeof(*dm));
	if (!dm) {
		errno = ENOMEM;
		return NULL;
	}

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_QUERY_DM_REQ_HANDLE, dm_handle);
	fill_attr_out(cmd, MLX5_IB_ATTR_QUERY_DM_RESP_START_OFFSET,
		      &start_offset, sizeof(start_offset));
	fill_attr_out(cmd, MLX5_IB_ATTR_QUERY_DM_RESP_PAGE_INDEX,
		      &page_idx, sizeof(page_idx));
	fill_attr_out(cmd, MLX5_IB_ATTR_QUERY_DM_RESP_LENGTH, &length,
		      sizeof(length));

	ret = execute_ioctl(context, cmd);
	if (ret)
		goto free_dm;

	va = dm_mmap(context, dm, page_idx, length);
	if (va == MAP_FAILED)
		goto free_dm;

	dm->mmap_va = va;
	dm->length = length;
	dm->start_va = va + (start_offset & (page_size - 1));
	dm->verbs_dm.dm.memcpy_to_dm = mlx5_memcpy_to_dm;
	dm->verbs_dm.dm.memcpy_from_dm = mlx5_memcpy_from_dm;
	dm->verbs_dm.dm.context = context;
	dm->verbs_dm.handle = dm->verbs_dm.dm.handle = dm_handle;

	return &dm->verbs_dm.dm;
free_dm:
	free(dm);
	return NULL;
}

static int alloc_dm_memic(struct ibv_context *ctx,
			  struct mlx5_dm *dm,
			  struct ibv_alloc_dm_attr *dm_attr,
			  struct ibv_command_buffer *cmdb)
{
	int page_size = to_mdev(ctx->device)->page_size;
	uint64_t start_offset;
	uint16_t page_idx;
	void *va;

	if (dm_attr->length > to_mctx(ctx)->max_dm_size) {
		errno = EINVAL;
		return errno;
	}

	fill_attr_out(cmdb, MLX5_IB_ATTR_ALLOC_DM_RESP_START_OFFSET,
		      &start_offset, sizeof(start_offset));

	fill_attr_out(cmdb, MLX5_IB_ATTR_ALLOC_DM_RESP_PAGE_INDEX,
		      &page_idx, sizeof(page_idx));

	if (ibv_cmd_alloc_dm(ctx, dm_attr, &dm->verbs_dm, cmdb))
		return EINVAL;

	va = dm_mmap(ctx, dm, page_idx, dm_attr->length);
	if (va == MAP_FAILED) {
		ibv_cmd_free_dm(&dm->verbs_dm);
		return ENOMEM;
	}

	dm->mmap_va = va;
	dm->start_va = va + (start_offset & (page_size - 1));
	dm->verbs_dm.dm.memcpy_to_dm = mlx5_memcpy_to_dm;
	dm->verbs_dm.dm.memcpy_from_dm = mlx5_memcpy_from_dm;

	return 0;
}

static int alloc_dm_steering_sw_icm(struct ibv_context *ctx,
				    struct mlx5_dm *dm,
				    struct ibv_alloc_dm_attr *dm_attr,
				    struct ibv_command_buffer *cmdb)
{
	uint64_t start_offset;

	fill_attr_out(cmdb, MLX5_IB_ATTR_ALLOC_DM_RESP_START_OFFSET,
		      &start_offset, sizeof(start_offset));

	if (ibv_cmd_alloc_dm(ctx, dm_attr, &dm->verbs_dm, cmdb))
		return EINVAL;

	/* For SW ICM we get address in the start_offset attribute */
	dm->remote_va = start_offset;

	return 0;
}

static struct ibv_dm *
_mlx5dv_alloc_dm(struct ibv_context *context,
		 struct ibv_alloc_dm_attr *dm_attr,
		 struct mlx5dv_alloc_dm_attr *mlx5_dm_attr)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DM, UVERBS_METHOD_DM_ALLOC,
			       3);
	struct ib_uverbs_attr *type_attr;
	struct mlx5_dm *dm;
	int err;

	if ((mlx5_dm_attr->type != MLX5DV_DM_TYPE_MEMIC) &&
	    (mlx5_dm_attr->type != MLX5DV_DM_TYPE_STEERING_SW_ICM) &&
	    (mlx5_dm_attr->type != MLX5DV_DM_TYPE_HEADER_MODIFY_SW_ICM)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (!check_comp_mask(dm_attr->comp_mask, 0) ||
	    !check_comp_mask(mlx5_dm_attr->comp_mask, 0)) {
		errno = EINVAL;
		return NULL;
	}

	dm = calloc(1, sizeof(*dm));
	if (!dm) {
		errno = ENOMEM;
		return NULL;
	}

	type_attr = fill_attr_const_in(cmdb,  MLX5_IB_ATTR_ALLOC_DM_REQ_TYPE,
				       mlx5_dm_attr->type);

	if (mlx5_dm_attr->type == MLX5DV_DM_TYPE_MEMIC) {
		attr_optional(type_attr);
		err = alloc_dm_memic(context, dm, dm_attr, cmdb);
	} else {
		err = alloc_dm_steering_sw_icm(context, dm, dm_attr, cmdb);
	}

	if (err)
		goto err_free_mem;

	dm->length = dm_attr->length;

	return &dm->verbs_dm.dm;

err_free_mem:
	free(dm);

	return NULL;
}

struct ibv_dm *
mlx5dv_alloc_dm(struct ibv_context *context,
		struct ibv_alloc_dm_attr *dm_attr,
		struct mlx5dv_alloc_dm_attr *mlx5_dm_attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->alloc_dm) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->alloc_dm(context, dm_attr, mlx5_dm_attr);
}

int mlx5_free_dm(struct ibv_dm *ibdm)
{
	struct mlx5_device *mdev = to_mdev(ibdm->context->device);
	struct mlx5_dm *dm = to_mdm(ibdm);
	size_t act_size = align(dm->length, mdev->page_size);
	int ret;

	ret = ibv_cmd_free_dm(&dm->verbs_dm);

	if (ret)
		return ret;

	if (dm->mmap_va)
		munmap(dm->mmap_va, act_size);
	free(dm);
	return 0;
}

struct ibv_dm *mlx5_alloc_dm(struct ibv_context *context,
			     struct ibv_alloc_dm_attr *dm_attr)
{
	struct mlx5dv_alloc_dm_attr mlx5_attr = { .type = MLX5DV_DM_TYPE_MEMIC };

	return mlx5dv_alloc_dm(context, dm_attr, &mlx5_attr);
}

struct ibv_counters *mlx5_create_counters(struct ibv_context *context,
					  struct ibv_counters_init_attr *init_attr)
{
	struct mlx5_counters *mcntrs;
	int ret;

	if (!check_comp_mask(init_attr->comp_mask, 0)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	mcntrs = calloc(1, sizeof(*mcntrs));
	if (!mcntrs) {
		errno = ENOMEM;
		return NULL;
	}

	pthread_mutex_init(&mcntrs->lock, NULL);
	ret = ibv_cmd_create_counters(context,
				      init_attr,
				      &mcntrs->vcounters,
				      NULL);
	if (ret)
		goto err_create;

	list_head_init(&mcntrs->counters_list);

	return &mcntrs->vcounters.counters;

err_create:
	free(mcntrs);
	return NULL;
}

int mlx5_destroy_counters(struct ibv_counters *counters)
{
	struct mlx5_counters *mcntrs = to_mcounters(counters);
	struct mlx5_counter_node *tmp, *cntrs_node;
	int ret;

	ret = ibv_cmd_destroy_counters(&mcntrs->vcounters);
	if (ret)
		return ret;

	list_for_each_safe(&mcntrs->counters_list, cntrs_node, tmp, entry) {
		list_del(&cntrs_node->entry);
		free(cntrs_node);
	}

	free(mcntrs);
	return 0;
}

int mlx5_attach_counters_point_flow(struct ibv_counters *counters,
				    struct ibv_counter_attach_attr *attr,
				    struct ibv_flow *flow)
{
	struct mlx5_counters *mcntrs = to_mcounters(counters);
	struct mlx5_counter_node *cntrs_node;
	int ret;

	/* The driver supports only the static binding mode as part of ibv_create_flow */
	if (flow)
		return ENOTSUP;

	if (!check_comp_mask(attr->comp_mask, 0))
		return EOPNOTSUPP;

	/* Check whether the attached counter is supported */
	if (attr->counter_desc < IBV_COUNTER_PACKETS ||
	    attr->counter_desc  > IBV_COUNTER_BYTES)
		return ENOTSUP;

	cntrs_node = calloc(1, sizeof(*cntrs_node));
	if (!cntrs_node)
		return ENOMEM;

	pthread_mutex_lock(&mcntrs->lock);
	/* The counter is bound to a flow, attach is not allowed */
	if (mcntrs->refcount) {
		ret = EBUSY;
		goto err_already_bound;
	}

	cntrs_node->index = attr->index;
	cntrs_node->desc = attr->counter_desc;
	list_add(&mcntrs->counters_list, &cntrs_node->entry);
	mcntrs->ncounters++;
	pthread_mutex_unlock(&mcntrs->lock);

	return 0;

err_already_bound:
	pthread_mutex_unlock(&mcntrs->lock);
	free(cntrs_node);
	return ret;
}

int mlx5_read_counters(struct ibv_counters *counters,
		       uint64_t *counters_value,
		       uint32_t ncounters,
		       uint32_t flags)
{
	struct mlx5_counters *mcntrs = to_mcounters(counters);

	return ibv_cmd_read_counters(&mcntrs->vcounters,
				     counters_value,
				     ncounters,
				     flags,
				     NULL);

}

static struct mlx5dv_flow_matcher *
_mlx5dv_create_flow_matcher(struct ibv_context *context,
			    struct mlx5dv_flow_matcher_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmd, MLX5_IB_OBJECT_FLOW_MATCHER,
			       MLX5_IB_METHOD_FLOW_MATCHER_CREATE,
			       6);
	struct mlx5dv_flow_matcher *flow_matcher;
	struct ib_uverbs_attr *handle;
	int ret;

	if (!check_comp_mask(attr->comp_mask,
			     MLX5DV_FLOW_MATCHER_MASK_FT_TYPE)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	flow_matcher = calloc(1, sizeof(*flow_matcher));
	if (!flow_matcher) {
		errno = ENOMEM;
		return NULL;
	}

	if (attr->type !=  IBV_FLOW_ATTR_NORMAL) {
		errno = EOPNOTSUPP;
		goto err;
	}

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_FLOW_MATCHER_CREATE_HANDLE);
	fill_attr_in(cmd, MLX5_IB_ATTR_FLOW_MATCHER_MATCH_MASK,
		     attr->match_mask->match_buf,
		     attr->match_mask->match_sz);
	fill_attr_in(cmd, MLX5_IB_ATTR_FLOW_MATCHER_MATCH_CRITERIA,
		     &attr->match_criteria_enable, sizeof(attr->match_criteria_enable));
	fill_attr_in_enum(cmd, MLX5_IB_ATTR_FLOW_MATCHER_FLOW_TYPE,
			  IBV_FLOW_ATTR_NORMAL, &attr->priority,
			  sizeof(attr->priority));

	if (attr->comp_mask & MLX5DV_FLOW_MATCHER_MASK_FT_TYPE)
		fill_attr_const_in(cmd, MLX5_IB_ATTR_FLOW_MATCHER_FT_TYPE,
				   attr->ft_type);
	if (attr->flags)
		fill_attr_const_in(cmd, MLX5_IB_ATTR_FLOW_MATCHER_FLOW_FLAGS,
				   attr->flags);

	ret = execute_ioctl(context, cmd);
	if (ret)
		goto err;

	flow_matcher->context = context;
	flow_matcher->handle = read_attr_obj(MLX5_IB_ATTR_FLOW_MATCHER_CREATE_HANDLE, handle);

	return flow_matcher;

err:
	free(flow_matcher);
	return NULL;
}

struct mlx5dv_flow_matcher *
mlx5dv_create_flow_matcher(struct ibv_context *context,
			   struct mlx5dv_flow_matcher_attr *attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->create_flow_matcher) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_flow_matcher(context, attr);
}

static int _mlx5dv_destroy_flow_matcher(struct mlx5dv_flow_matcher *flow_matcher)
{
	DECLARE_COMMAND_BUFFER(cmd, MLX5_IB_OBJECT_FLOW_MATCHER,
			       MLX5_IB_METHOD_FLOW_MATCHER_DESTROY,
			       1);
	int ret;

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_FLOW_MATCHER_DESTROY_HANDLE, flow_matcher->handle);
	ret = execute_ioctl(flow_matcher->context, cmd);
	verbs_is_destroy_err(&ret);

	if (ret)
		return ret;

	free(flow_matcher);
	return 0;
}

int mlx5dv_destroy_flow_matcher(struct mlx5dv_flow_matcher *flow_matcher)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(flow_matcher->context);

	if (!dvops || !dvops->destroy_flow_matcher)
		return EOPNOTSUPP;

	return dvops->destroy_flow_matcher(flow_matcher);
}

#define CREATE_FLOW_MAX_FLOW_ACTIONS_SUPPORTED 8
struct ibv_flow *
_mlx5dv_create_flow(struct mlx5dv_flow_matcher *flow_matcher,
		    struct mlx5dv_flow_match_parameters *match_value,
		    size_t num_actions,
		    struct mlx5dv_flow_action_attr actions_attr[],
		    struct mlx5_flow_action_attr_aux actions_attr_aux[])
{
	uint32_t flow_actions[CREATE_FLOW_MAX_FLOW_ACTIONS_SUPPORTED];
	struct verbs_flow_action *vaction;
	int num_flow_actions = 0;
	struct mlx5_flow *mflow;
	bool have_qp = false;
	bool have_dest_devx = false;
	bool have_flow_tag = false;
	bool have_counter = false;
	bool have_default = false;
	bool have_drop = false;
	int ret;
	int i;
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_FLOW,
			       MLX5_IB_METHOD_CREATE_FLOW,
			       8);
	struct ib_uverbs_attr *handle;
	enum mlx5dv_flow_action_type type;

	mflow = calloc(1, sizeof(*mflow));
	if (!mflow) {
		errno = ENOMEM;
		return NULL;
	}

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_CREATE_FLOW_HANDLE);
	fill_attr_in(cmd, MLX5_IB_ATTR_CREATE_FLOW_MATCH_VALUE,
		    match_value->match_buf,
		    match_value->match_sz);
	fill_attr_in_obj(cmd, MLX5_IB_ATTR_CREATE_FLOW_MATCHER, flow_matcher->handle);

	for (i = 0; i < num_actions; i++) {
		type = actions_attr[i].type;
		switch (type) {
		case MLX5DV_FLOW_ACTION_DEST_IBV_QP:
			if (have_qp || have_dest_devx || have_default ||
			    have_drop) {
				errno = EOPNOTSUPP;
				goto err;
			}
			fill_attr_in_obj(cmd, MLX5_IB_ATTR_CREATE_FLOW_DEST_QP,
					 actions_attr[i].qp->handle);
			have_qp = true;
			break;
		case MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION:
			if (num_flow_actions ==
			    CREATE_FLOW_MAX_FLOW_ACTIONS_SUPPORTED) {
				errno = EOPNOTSUPP;
				goto err;
			}
			vaction = container_of(actions_attr[i].action,
					       struct verbs_flow_action,
					       action);

			flow_actions[num_flow_actions] = vaction->handle;
			num_flow_actions++;
			break;
		case MLX5DV_FLOW_ACTION_DEST_DEVX:
			if (have_dest_devx || have_qp || have_default ||
			    have_drop) {
				errno = EOPNOTSUPP;
				goto err;
			}
			fill_attr_in_obj(cmd, MLX5_IB_ATTR_CREATE_FLOW_DEST_DEVX,
					 actions_attr[i].obj->handle);
			have_dest_devx = true;
			break;
		case MLX5DV_FLOW_ACTION_TAG:
			if (have_flow_tag) {
				errno = EINVAL;
				goto err;
			}
			fill_attr_in_uint32(cmd,
					    MLX5_IB_ATTR_CREATE_FLOW_TAG,
					    actions_attr[i].tag_value);
			have_flow_tag = true;
			break;
		case MLX5DV_FLOW_ACTION_COUNTERS_DEVX:
			if (have_counter) {
				errno = EOPNOTSUPP;
				goto err;
			}
			fill_attr_in_objs_arr(cmd,
					      MLX5_IB_ATTR_CREATE_FLOW_ARR_COUNTERS_DEVX,
					      &actions_attr[i].obj->handle, 1);

			if (actions_attr_aux &&
			    actions_attr_aux[i].type == MLX5_FLOW_ACTION_COUNTER_OFFSET)
				fill_attr_in_ptr_array(cmd,
						       MLX5_IB_ATTR_CREATE_FLOW_ARR_COUNTERS_DEVX_OFFSET,
						       &actions_attr_aux[i].offset, 1);

			have_counter = true;
			break;
		case MLX5DV_FLOW_ACTION_DEFAULT_MISS:
			if (have_qp || have_dest_devx || have_default ||
			    have_drop) {
				errno = EOPNOTSUPP;
				goto err;
			}
			fill_attr_in_uint32(cmd,
					    MLX5_IB_ATTR_CREATE_FLOW_FLAGS,
					    MLX5_IB_ATTR_CREATE_FLOW_FLAGS_DEFAULT_MISS);
			have_default = true;
			break;
		case MLX5DV_FLOW_ACTION_DROP:
			if (have_qp || have_dest_devx || have_default ||
			    have_drop) {
				errno = EOPNOTSUPP;
				goto err;
			}
			fill_attr_in_uint32(cmd,
					    MLX5_IB_ATTR_CREATE_FLOW_FLAGS,
					    MLX5_IB_ATTR_CREATE_FLOW_FLAGS_DROP);
			have_drop = true;
			break;
		default:
			errno = EOPNOTSUPP;
			goto err;
		}
	}

	if (num_flow_actions)
		fill_attr_in_objs_arr(cmd,
				      MLX5_IB_ATTR_CREATE_FLOW_ARR_FLOW_ACTIONS,
				      flow_actions,
				      num_flow_actions);
	ret = execute_ioctl(flow_matcher->context, cmd);
	if (ret)
		goto err;

	mflow->flow_id.handle = read_attr_obj(MLX5_IB_ATTR_CREATE_FLOW_HANDLE, handle);
	mflow->flow_id.context = flow_matcher->context;
	return &mflow->flow_id;
err:
	free(mflow);
	return NULL;
}

struct ibv_flow *
mlx5dv_create_flow(struct mlx5dv_flow_matcher *flow_matcher,
		   struct mlx5dv_flow_match_parameters *match_value,
		   size_t num_actions,
		   struct mlx5dv_flow_action_attr actions_attr[])
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(flow_matcher->context);

	if (!dvops || !dvops->create_flow) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_flow(flow_matcher,
				  match_value,
				  num_actions,
				  actions_attr,
				  NULL);
}

static struct mlx5dv_devx_umem *
__mlx5dv_devx_umem_reg_ex(struct ibv_context *context,
			 struct mlx5dv_devx_umem_in *in,
			 bool legacy)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_UMEM,
			       MLX5_IB_METHOD_DEVX_UMEM_REG,
			       6);
	struct ib_uverbs_attr *pgsz_bitmap;
	struct ib_uverbs_attr *handle;
	struct mlx5_devx_umem *umem;
	int ret;

	if (!check_comp_mask(in->comp_mask, 0)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	umem = calloc(1, sizeof(*umem));
	if (!umem) {
		errno = ENOMEM;
		return NULL;
	}

	if (ibv_dontfork_range(in->addr, in->size))
		goto err;

	fill_attr_in_uint64(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_ADDR, (intptr_t)in->addr);
	fill_attr_in_uint64(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_LEN, in->size);
	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_ACCESS, in->access);
	pgsz_bitmap = fill_attr_in_uint64(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_PGSZ_BITMAP,
					 in->pgsz_bitmap);
	if (legacy)
		attr_optional(pgsz_bitmap);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_OUT_ID,
		      &umem->dv_devx_umem.umem_id,
		      sizeof(umem->dv_devx_umem.umem_id));
	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_HANDLE);

	ret = execute_ioctl(context, cmd);
	if (ret)
		goto err_umem_reg_cmd;

	umem->handle = read_attr_obj(MLX5_IB_ATTR_DEVX_UMEM_REG_HANDLE, handle);
	umem->context = context;
	umem->addr = in->addr;
	umem->size = in->size;

	return &umem->dv_devx_umem;

err_umem_reg_cmd:
	ibv_dofork_range(in->addr, in->size);
err:
	free(umem);
	return NULL;
}

static struct mlx5dv_devx_umem *
_mlx5dv_devx_umem_reg(struct ibv_context *context, void *addr, size_t size, uint32_t access)
{
	struct mlx5dv_devx_umem_in umem_in = {};

	umem_in.access = access;
	umem_in.addr = addr;
	umem_in.size = size;

	umem_in.pgsz_bitmap = UINT64_MAX & ~(MLX5_ADAPTER_PAGE_SIZE - 1);

	return __mlx5dv_devx_umem_reg_ex(context, &umem_in, true);
}

static struct mlx5dv_devx_umem *
_mlx5dv_devx_umem_reg_ex(struct ibv_context *ctx, struct mlx5dv_devx_umem_in *umem_in)
{
	return __mlx5dv_devx_umem_reg_ex(ctx, umem_in, false);
}

struct mlx5dv_devx_umem *
mlx5dv_devx_umem_reg_ex(struct ibv_context *ctx, struct mlx5dv_devx_umem_in *umem_in)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->devx_umem_reg_ex) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->devx_umem_reg_ex(ctx, umem_in);
}

struct mlx5dv_devx_umem *
mlx5dv_devx_umem_reg(struct ibv_context *context, void *addr, size_t size, uint32_t access)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->devx_umem_reg) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->devx_umem_reg(context, addr, size, access);

}

static int _mlx5dv_devx_umem_dereg(struct mlx5dv_devx_umem *dv_devx_umem)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_UMEM,
			       MLX5_IB_METHOD_DEVX_UMEM_DEREG,
			       1);
	int ret;
	struct mlx5_devx_umem *umem = container_of(dv_devx_umem, struct mlx5_devx_umem,
						    dv_devx_umem);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_UMEM_DEREG_HANDLE, umem->handle);
	ret = execute_ioctl(umem->context, cmd);
	if (ret)
		return ret;

	ibv_dofork_range(umem->addr, umem->size);
	free(umem);
	return 0;
}

int mlx5dv_devx_umem_dereg(struct mlx5dv_devx_umem *dv_devx_umem)
{
	struct mlx5_devx_umem *umem = container_of(dv_devx_umem, struct mlx5_devx_umem,
						   dv_devx_umem);
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(umem->context);

	if (!dvops || !dvops->devx_umem_dereg)
		return EOPNOTSUPP;

	return dvops->devx_umem_dereg(dv_devx_umem);

}

static void set_devx_obj_info(const void *in, const void *out,
			      struct mlx5dv_devx_obj *obj)
{
	uint16_t opcode;
	uint16_t obj_type;

	opcode = DEVX_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
		obj->type = MLX5_DEVX_FLOW_TABLE;
		obj->object_id = DEVX_GET(create_flow_table_out, out, table_id);
		break;
	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
		obj->type = MLX5_DEVX_FLOW_GROUP;
		obj->object_id = DEVX_GET(create_flow_group_out, out, group_id);
		break;
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
		obj->type = MLX5_DEVX_FLOW_TABLE_ENTRY;
		obj->object_id = DEVX_GET(set_fte_in, in, flow_index);
		break;
	case MLX5_CMD_OP_CREATE_FLOW_COUNTER:
		obj->type = MLX5_DEVX_FLOW_COUNTER;
		obj->object_id = DEVX_GET(alloc_flow_counter_out, out, flow_counter_id);
		break;
	case MLX5_CMD_OP_CREATE_GENERAL_OBJECT:
		obj_type = DEVX_GET(general_obj_in_cmd_hdr, in, obj_type);
		if (obj_type == MLX5_OBJ_TYPE_FLOW_METER)
			obj->type = MLX5_DEVX_FLOW_METER;
		else if (obj_type == MLX5_OBJ_TYPE_FLOW_SAMPLER)
			obj->type = MLX5_DEVX_FLOW_SAMPLER;
		else if (obj_type == MLX5_OBJ_TYPE_ASO_FIRST_HIT)
			obj->type = MLX5_DEVX_ASO_FIRST_HIT;
		else if (obj_type == MLX5_OBJ_TYPE_ASO_FLOW_METER)
			obj->type = MLX5_DEVX_ASO_FLOW_METER;
		else if (obj_type == MLX5_OBJ_TYPE_ASO_CT)
			obj->type = MLX5_DEVX_ASO_CT;

		obj->log_obj_range = DEVX_GET(general_obj_in_cmd_hdr, in, log_obj_range);
		obj->object_id = DEVX_GET(general_obj_out_cmd_hdr, out, obj_id);
		break;
	case MLX5_CMD_OP_CREATE_QP:
		obj->type = MLX5_DEVX_QP;
		obj->object_id = DEVX_GET(create_qp_out, out, qpn);
		break;
	case MLX5_CMD_OP_CREATE_TIR:
		obj->type = MLX5_DEVX_TIR;
		obj->object_id = DEVX_GET(create_tir_out, out, tirn);
		obj->rx_icm_addr = DEVX_GET(create_tir_out, out, icm_address_31_0);
		obj->rx_icm_addr |= (uint64_t)DEVX_GET(create_tir_out, out, icm_address_39_32) << 32;
		obj->rx_icm_addr |= (uint64_t)DEVX_GET(create_tir_out, out, icm_address_63_40) << 40;
		break;
	case MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT:
		obj->type = MLX5_DEVX_PKT_REFORMAT_CTX;
		obj->object_id = DEVX_GET(alloc_packet_reformat_context_out,
					  out, packet_reformat_id);
		break;
	default:
		break;
	}
}

static struct mlx5dv_devx_obj *
_mlx5dv_devx_obj_create(struct ibv_context *context, const void *in,
			size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_CREATE,
			       3);
	struct ib_uverbs_attr *handle;
	struct mlx5dv_devx_obj *obj;
	int ret;

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_CREATE_HANDLE);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_OUT, out, outlen);

	ret = execute_ioctl(context, cmd);
	if (ret)
		goto err;

	obj->handle = read_attr_obj(MLX5_IB_ATTR_DEVX_OBJ_CREATE_HANDLE, handle);
	obj->context = context;
	set_devx_obj_info(in, out, obj);

	return obj;
err:
	free(obj);
	return NULL;
}

struct mlx5dv_devx_obj *
mlx5dv_devx_obj_create(struct ibv_context *context, const void *in,
			 size_t inlen, void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->devx_obj_create) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->devx_obj_create(context, in, inlen, out, outlen);
}

static int
_mlx5dv_devx_obj_query(struct mlx5dv_devx_obj *obj, const void *in,
		       size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_QUERY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE, obj->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT, out, outlen);

	return execute_ioctl(obj->context, cmd);
}

int mlx5dv_devx_obj_query(struct mlx5dv_devx_obj *obj, const void *in, size_t inlen,
			  void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(obj->context);

	if (!dvops || !dvops->devx_obj_query)
		return EOPNOTSUPP;

	return dvops->devx_obj_query(obj, in, inlen, out, outlen);
}

static int _mlx5dv_devx_obj_modify(struct mlx5dv_devx_obj *obj, const void *in,
				   size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_MODIFY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE, obj->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT, out, outlen);

	return execute_ioctl(obj->context, cmd);
}

int mlx5dv_devx_obj_modify(struct mlx5dv_devx_obj *obj, const void *in,
			   size_t inlen, void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(obj->context);

	if (!dvops || !dvops->devx_obj_modify)
		return EOPNOTSUPP;

	return dvops->devx_obj_modify(obj, in, inlen, out, outlen);
}

static int _mlx5dv_devx_obj_destroy(struct mlx5dv_devx_obj *obj)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_DESTROY,
			       1);
	int ret;

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_DESTROY_HANDLE, obj->handle);
	ret = execute_ioctl(obj->context, cmd);

	if (ret)
		return ret;
	free(obj);
	return 0;
}

int mlx5dv_devx_obj_destroy(struct mlx5dv_devx_obj *obj)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(obj->context);

	if (!dvops || !dvops->devx_obj_destroy)
		return EOPNOTSUPP;

	return dvops->devx_obj_destroy(obj);
}

static int _mlx5dv_devx_general_cmd(struct ibv_context *context, const void *in,
				    size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX,
			       MLX5_IB_METHOD_DEVX_OTHER,
			       2);

	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OTHER_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OTHER_CMD_OUT, out, outlen);

	return execute_ioctl(context, cmd);
}

int mlx5dv_devx_general_cmd(struct ibv_context *context, const void *in, size_t inlen,
			    void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->devx_general_cmd)
		return EOPNOTSUPP;

	return dvops->devx_general_cmd(context, in, inlen, out, outlen);
}

static int __mlx5dv_query_port(struct ibv_context *context,
			       uint32_t port_num,
			       struct mlx5dv_port *info, size_t info_len)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       UVERBS_OBJECT_DEVICE,
			       MLX5_IB_METHOD_QUERY_PORT,
			       2);

	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_QUERY_PORT_PORT_NUM, port_num);
	fill_attr_out(cmd, MLX5_IB_ATTR_QUERY_PORT, info, info_len);

	return execute_ioctl(context, cmd);
}

int _mlx5dv_query_port(struct ibv_context *context,
		       uint32_t port_num,
		       struct mlx5dv_port *info, size_t info_len)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->query_port)
		return EOPNOTSUPP;

	return dvops->query_port(context, port_num, info, info_len);
}

void clean_dyn_uars(struct ibv_context *context)
{
	struct mlx5_context *ctx = to_mctx(context);
	struct mlx5_bf *bf, *tmp_bf;

	list_for_each_safe(&ctx->dyn_uar_bf_list, bf, tmp_bf, uar_entry) {
		list_del(&bf->uar_entry);
		mlx5_free_uar(context, bf);
	}

	list_for_each_safe(&ctx->dyn_uar_qp_dedicated_list, bf, tmp_bf, uar_entry) {
		list_del(&bf->uar_entry);
		mlx5_free_uar(context, bf);
	}

	list_for_each_safe(&ctx->dyn_uar_qp_shared_list, bf, tmp_bf, uar_entry) {
		list_del(&bf->uar_entry);
		mlx5_free_uar(context, bf);
	}

	if (ctx->nc_uar)
		mlx5_free_uar(context, ctx->nc_uar);
}

static struct mlx5dv_devx_uar *
_mlx5dv_devx_alloc_uar(struct ibv_context *context, uint32_t flags)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX,
			       MLX5_IB_METHOD_DEVX_QUERY_UAR,
			       2);

	int ret;
	struct mlx5_bf *bf;

	if (!check_comp_mask(flags, MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (flags & MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC)
		return mlx5_get_singleton_nc_uar(context);

	bf = mlx5_attach_dedicated_uar(context, flags);
	if (!bf)
		return NULL;

	if (bf->dyn_alloc_uar)
		bf->devx_uar.dv_devx_uar.page_id = bf->page_id;
	else {
		fill_attr_in_uint32(cmd, MLX5_IB_ATTR_DEVX_QUERY_UAR_USER_IDX,
				    bf->bfreg_dyn_index);
		fill_attr_out_ptr(cmd, MLX5_IB_ATTR_DEVX_QUERY_UAR_DEV_IDX,
			      &bf->devx_uar.dv_devx_uar.page_id);

		ret = execute_ioctl(context, cmd);
		if (ret) {
			mlx5_detach_dedicated_uar(context, bf);
			return NULL;
		}
	}

	bf->devx_uar.dv_devx_uar.reg_addr = bf->reg;
	bf->devx_uar.dv_devx_uar.base_addr = bf->uar;
	bf->devx_uar.dv_devx_uar.mmap_off = bf->uar_mmap_offset;
	bf->devx_uar.dv_devx_uar.comp_mask = 0;
	bf->devx_uar.context = context;
	return &bf->devx_uar.dv_devx_uar;
}

struct mlx5dv_devx_uar *
mlx5dv_devx_alloc_uar(struct ibv_context *context, uint32_t flags)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->devx_alloc_uar) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->devx_alloc_uar(context, flags);
}

static void _mlx5dv_devx_free_uar(struct mlx5dv_devx_uar *dv_devx_uar)
{
	struct mlx5_bf *bf = container_of(dv_devx_uar, struct mlx5_bf,
					  devx_uar.dv_devx_uar);

	if (bf->nc_mode)
		return;

	mlx5_detach_dedicated_uar(bf->devx_uar.context, bf);
}

void mlx5dv_devx_free_uar(struct mlx5dv_devx_uar *dv_devx_uar)
{
	struct mlx5_devx_uar *uar = container_of(dv_devx_uar, struct mlx5_devx_uar,
						 dv_devx_uar);
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(uar->context);

	if (!dvops || !dvops->devx_free_uar)
		return;

	dvops->devx_free_uar(dv_devx_uar);
}

static int _mlx5dv_devx_query_eqn(struct ibv_context *context,
				   uint32_t vector, uint32_t *eqn)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX,
			       MLX5_IB_METHOD_DEVX_QUERY_EQN,
			       2);

	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_DEVX_QUERY_EQN_USER_VEC, vector);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_DEVX_QUERY_EQN_DEV_EQN, eqn);

	return execute_ioctl(context, cmd);
}

int mlx5dv_devx_query_eqn(struct ibv_context *context, uint32_t vector,
			  uint32_t *eqn)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->devx_query_eqn)
		return EOPNOTSUPP;

	return dvops->devx_query_eqn(context, vector, eqn);
}

static int _mlx5dv_devx_cq_query(struct ibv_cq *cq, const void *in,
				  size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_QUERY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE, cq->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT, out, outlen);

	return execute_ioctl(cq->context, cmd);
}

int mlx5dv_devx_cq_query(struct ibv_cq *cq, const void *in, size_t inlen,
				void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(cq->context);

	if (!dvops || !dvops->devx_cq_query)
		return EOPNOTSUPP;

	return dvops->devx_cq_query(cq, in, inlen, out, outlen);
}

static int _mlx5dv_devx_cq_modify(struct ibv_cq *cq, const void *in,
				   size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_MODIFY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE, cq->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT, out, outlen);

	return execute_ioctl(cq->context, cmd);
}

int mlx5dv_devx_cq_modify(struct ibv_cq *cq, const void *in, size_t inlen,
				void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(cq->context);

	if (!dvops || !dvops->devx_cq_modify)
		return EOPNOTSUPP;

	return dvops->devx_cq_modify(cq, in, inlen, out, outlen);
}

static int _mlx5dv_devx_qp_query(struct ibv_qp *qp, const void *in,
				  size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_QUERY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE, qp->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT, out, outlen);

	return execute_ioctl(qp->context, cmd);
}

int mlx5dv_devx_qp_query(struct ibv_qp *qp, const void *in, size_t inlen,
				void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(qp->context);

	if (!dvops || !dvops->devx_qp_query)
		return EOPNOTSUPP;

	return dvops->devx_qp_query(qp, in, inlen, out, outlen);
}

static int _mlx5dv_devx_qp_modify(struct ibv_qp *qp, const void *in,
				   size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_MODIFY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE, qp->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT, out, outlen);

	return execute_ioctl(qp->context, cmd);
}

int mlx5dv_devx_qp_modify(struct ibv_qp *qp, const void *in, size_t inlen,
			  void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(qp->context);

	if (!dvops || !dvops->devx_qp_modify)
		return EOPNOTSUPP;

	return dvops->devx_qp_modify(qp, in, inlen, out, outlen);
}

static int _mlx5dv_devx_srq_query(struct ibv_srq *srq, const void *in,
				   size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_QUERY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE, srq->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT, out, outlen);

	return execute_ioctl(srq->context, cmd);
}

int mlx5dv_devx_srq_query(struct ibv_srq *srq, const void *in, size_t inlen,
			  void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(srq->context);

	if (!dvops || !dvops->devx_srq_query)
		return EOPNOTSUPP;

	return dvops->devx_srq_query(srq, in, inlen, out, outlen);
}

static int _mlx5dv_devx_srq_modify(struct ibv_srq *srq, const void *in,
				    size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_MODIFY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE, srq->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT, out, outlen);

	return execute_ioctl(srq->context, cmd);
}

int mlx5dv_devx_srq_modify(struct ibv_srq *srq, const void *in, size_t inlen,
			   void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(srq->context);

	if (!dvops || !dvops->devx_srq_modify)
		return EOPNOTSUPP;

	return dvops->devx_srq_modify(srq, in, inlen, out, outlen);
}

static int _mlx5dv_devx_wq_query(struct ibv_wq *wq, const void *in, size_t inlen,
				  void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_QUERY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE, wq->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT, out, outlen);

	return execute_ioctl(wq->context, cmd);
}

int mlx5dv_devx_wq_query(struct ibv_wq *wq, const void *in, size_t inlen,
			 void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(wq->context);

	if (!dvops || !dvops->devx_wq_query)
		return EOPNOTSUPP;

	return dvops->devx_wq_query(wq, in, inlen, out, outlen);
}

static int _mlx5dv_devx_wq_modify(struct ibv_wq *wq, const void *in,
				   size_t inlen, void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_MODIFY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE, wq->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT, out, outlen);

	return execute_ioctl(wq->context, cmd);
}

int mlx5dv_devx_wq_modify(struct ibv_wq *wq, const void *in, size_t inlen,
			  void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(wq->context);

	if (!dvops || !dvops->devx_wq_modify)
		return EOPNOTSUPP;

	return dvops->devx_wq_modify(wq, in, inlen, out, outlen);
}

static int _mlx5dv_devx_ind_tbl_query(struct ibv_rwq_ind_table *ind_tbl,
				       const void *in, size_t inlen,
				       void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_QUERY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE, ind_tbl->ind_tbl_handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT, out, outlen);

	return execute_ioctl(ind_tbl->context, cmd);
}


int mlx5dv_devx_ind_tbl_query(struct ibv_rwq_ind_table *ind_tbl, const void *in,
			      size_t inlen, void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ind_tbl->context);

	if (!dvops || !dvops->devx_ind_tbl_query)
		return EOPNOTSUPP;

	return dvops->devx_ind_tbl_query(ind_tbl, in, inlen, out, outlen);
}

static int _mlx5dv_devx_ind_tbl_modify(struct ibv_rwq_ind_table *ind_tbl,
					const void *in, size_t inlen,
					void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_MODIFY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE, ind_tbl->ind_tbl_handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN, in, inlen);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT, out, outlen);

	return execute_ioctl(ind_tbl->context, cmd);
}

int mlx5dv_devx_ind_tbl_modify(struct ibv_rwq_ind_table *ind_tbl,
			       const void *in, size_t inlen,
			       void *out, size_t outlen)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ind_tbl->context);

	if (!dvops || !dvops->devx_ind_tbl_modify)
		return EOPNOTSUPP;

	return dvops->devx_ind_tbl_modify(ind_tbl, in, inlen, out, outlen);
}

static struct mlx5dv_devx_cmd_comp *
_mlx5dv_devx_create_cmd_comp(struct ibv_context *context)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_ASYNC_CMD_FD,
			       MLX5_IB_METHOD_DEVX_ASYNC_CMD_FD_ALLOC,
			       1);
	struct ib_uverbs_attr *handle;
	struct mlx5dv_devx_cmd_comp *cmd_comp;
	int ret;

	cmd_comp = calloc(1, sizeof(*cmd_comp));
	if (!cmd_comp) {
		errno = ENOMEM;
		return NULL;
	}

	handle = fill_attr_out_fd(cmd,
				  MLX5_IB_ATTR_DEVX_ASYNC_CMD_FD_ALLOC_HANDLE,
				  0);

	ret = execute_ioctl(context, cmd);
	if (ret)
		goto err;

	cmd_comp->fd = read_attr_fd(
		MLX5_IB_ATTR_DEVX_ASYNC_CMD_FD_ALLOC_HANDLE, handle);
	return cmd_comp;
err:
	free(cmd_comp);
	return NULL;
}

struct mlx5dv_devx_cmd_comp *
mlx5dv_devx_create_cmd_comp(struct ibv_context *context)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->devx_create_cmd_comp) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->devx_create_cmd_comp(context);
}

static void _mlx5dv_devx_destroy_cmd_comp(
			struct mlx5dv_devx_cmd_comp *cmd_comp)
{
	close(cmd_comp->fd);
	free(cmd_comp);
}

void mlx5dv_devx_destroy_cmd_comp(
			struct mlx5dv_devx_cmd_comp *cmd_comp)
{
	_mlx5dv_devx_destroy_cmd_comp(cmd_comp);
}

static struct mlx5dv_devx_event_channel *
_mlx5dv_devx_create_event_channel(struct ibv_context *context,
				   enum mlx5dv_devx_create_event_channel_flags flags)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_ASYNC_EVENT_FD,
			       MLX5_IB_METHOD_DEVX_ASYNC_EVENT_FD_ALLOC,
			       2);
	struct ib_uverbs_attr *handle;
	struct mlx5_devx_event_channel *event_channel;
	int ret;

	event_channel = calloc(1, sizeof(*event_channel));
	if (!event_channel) {
		errno = ENOMEM;
		return NULL;
	}

	handle = fill_attr_out_fd(cmd,
				  MLX5_IB_ATTR_DEVX_ASYNC_EVENT_FD_ALLOC_HANDLE,
				  0);
	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_DEVX_ASYNC_EVENT_FD_ALLOC_FLAGS,
			    flags);

	ret = execute_ioctl(context, cmd);
	if (ret)
		goto err;

	event_channel->dv_event_channel.fd = read_attr_fd(
		MLX5_IB_ATTR_DEVX_ASYNC_EVENT_FD_ALLOC_HANDLE, handle);
	event_channel->context = context;
	return &event_channel->dv_event_channel;
err:
	free(event_channel);
	return NULL;
}

struct mlx5dv_devx_event_channel *
mlx5dv_devx_create_event_channel(struct ibv_context *context,
				 enum mlx5dv_devx_create_event_channel_flags flags)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->devx_create_event_channel) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->devx_create_event_channel(context, flags);
}

static void _mlx5dv_devx_destroy_event_channel(
			struct mlx5dv_devx_event_channel *dv_event_channel)
{
	struct mlx5_devx_event_channel *event_channel =
			container_of(dv_event_channel, struct mlx5_devx_event_channel,
				     dv_event_channel);

	close(dv_event_channel->fd);
	free(event_channel);
}

void mlx5dv_devx_destroy_event_channel(
			struct mlx5dv_devx_event_channel *dv_event_channel)
{
	struct mlx5_devx_event_channel *ech =
			container_of(dv_event_channel, struct mlx5_devx_event_channel,
				     dv_event_channel);
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ech->context);

	if (!dvops || !dvops->devx_destroy_event_channel)
		return;

	return dvops->devx_destroy_event_channel(dv_event_channel);
}

static int
_mlx5dv_devx_subscribe_devx_event(struct mlx5dv_devx_event_channel *dv_event_channel,
				  struct mlx5dv_devx_obj *obj, /* can be NULL for unaffiliated events */
				  uint16_t events_sz,
				  uint16_t events_num[],
				  uint64_t cookie)
{
	struct mlx5_devx_event_channel *event_channel =
			container_of(dv_event_channel, struct mlx5_devx_event_channel,
				     dv_event_channel);
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX,
			       MLX5_IB_METHOD_DEVX_SUBSCRIBE_EVENT,
			       4);

	fill_attr_in_fd(cmd, MLX5_IB_ATTR_DEVX_SUBSCRIBE_EVENT_FD_HANDLE, dv_event_channel->fd);
	fill_attr_in_uint64(cmd, MLX5_IB_ATTR_DEVX_SUBSCRIBE_EVENT_COOKIE, cookie);
	if (obj)
		fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_SUBSCRIBE_EVENT_OBJ_HANDLE, obj->handle);

	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_SUBSCRIBE_EVENT_TYPE_NUM_LIST, events_num, events_sz);

	return execute_ioctl(event_channel->context, cmd);
}

int mlx5dv_devx_subscribe_devx_event(struct mlx5dv_devx_event_channel *dv_event_channel,
				     struct mlx5dv_devx_obj *obj, /* can be NULL for unaffiliated events */
				     uint16_t events_sz,
				     uint16_t events_num[],
				     uint64_t cookie)
{
	struct mlx5_devx_event_channel *event_channel =
			container_of(dv_event_channel, struct mlx5_devx_event_channel,
				     dv_event_channel);
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(event_channel->context);

	if (!dvops || !dvops->devx_subscribe_devx_event)
		return EOPNOTSUPP;

	return dvops->devx_subscribe_devx_event(dv_event_channel, obj,
							 events_sz, events_num,
							 cookie);
}

static int _mlx5dv_devx_subscribe_devx_event_fd(struct mlx5dv_devx_event_channel *dv_event_channel,
						int fd,
						struct mlx5dv_devx_obj *obj, /* can be NULL for unaffiliated events */
						uint16_t event_num)
{
	struct mlx5_devx_event_channel *event_channel =
			container_of(dv_event_channel, struct mlx5_devx_event_channel,
				     dv_event_channel);
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX,
			       MLX5_IB_METHOD_DEVX_SUBSCRIBE_EVENT,
			       4);

	fill_attr_in_fd(cmd, MLX5_IB_ATTR_DEVX_SUBSCRIBE_EVENT_FD_HANDLE, dv_event_channel->fd);
	if (obj)
		fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_SUBSCRIBE_EVENT_OBJ_HANDLE, obj->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_SUBSCRIBE_EVENT_TYPE_NUM_LIST,
		     &event_num, sizeof(event_num));
	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_DEVX_SUBSCRIBE_EVENT_FD_NUM, fd);

	return execute_ioctl(event_channel->context, cmd);
}

int mlx5dv_devx_subscribe_devx_event_fd(struct mlx5dv_devx_event_channel *dv_event_channel,
					int fd,
					struct mlx5dv_devx_obj *obj, /* can be NULL for unaffiliated events */
					uint16_t event_num)
{
	struct mlx5_devx_event_channel *event_channel =
			container_of(dv_event_channel, struct mlx5_devx_event_channel,
				     dv_event_channel);
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(event_channel->context);

	if (!dvops || !dvops->devx_subscribe_devx_event_fd)
		return EOPNOTSUPP;

	return dvops->devx_subscribe_devx_event_fd(dv_event_channel, fd,
							    obj, event_num);
}

static int _mlx5dv_devx_obj_query_async(struct mlx5dv_devx_obj *obj, const void *in,
					size_t inlen, size_t outlen,
					uint64_t wr_id,
					struct mlx5dv_devx_cmd_comp *cmd_comp)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_ASYNC_QUERY,
			       5);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_HANDLE, obj->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_CMD_IN, in, inlen);
	fill_attr_const_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_OUT_LEN, outlen);
	fill_attr_in_uint64(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_WR_ID, wr_id);
	fill_attr_in_fd(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_FD, cmd_comp->fd);

	return execute_ioctl(obj->context, cmd);
}

int mlx5dv_devx_obj_query_async(struct mlx5dv_devx_obj *obj, const void *in,
				size_t inlen, size_t outlen,
				uint64_t wr_id,
				struct mlx5dv_devx_cmd_comp *cmd_comp)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(obj->context);

	if (!dvops || !dvops->devx_obj_query_async)
		return EOPNOTSUPP;

	return dvops->devx_obj_query_async(obj, in, inlen, outlen,
						    wr_id, cmd_comp);
}

static int _mlx5dv_devx_get_async_cmd_comp(struct mlx5dv_devx_cmd_comp *cmd_comp,
					   struct mlx5dv_devx_async_cmd_hdr *cmd_resp,
					   size_t cmd_resp_len)
{
	ssize_t bytes;

	bytes = read(cmd_comp->fd, cmd_resp, cmd_resp_len);
	if (bytes < 0)
		return errno;

	if (bytes < sizeof(*cmd_resp))
		return EINVAL;

	return 0;
}

int mlx5dv_devx_get_async_cmd_comp(struct mlx5dv_devx_cmd_comp *cmd_comp,
				   struct mlx5dv_devx_async_cmd_hdr *cmd_resp,
				   size_t cmd_resp_len)
{
	return _mlx5dv_devx_get_async_cmd_comp(cmd_comp, cmd_resp,
					       cmd_resp_len);
}

static int mlx5_destroy_sig_psvs(struct mlx5_sig_ctx *sig)
{
	int ret = 0;

	if (sig->block.mem_psv) {
		ret = mlx5_destroy_psv(sig->block.mem_psv);
		if (!ret)
			sig->block.mem_psv = NULL;
	}
	if (!ret && sig->block.wire_psv) {
		ret = mlx5_destroy_psv(sig->block.wire_psv);
		if (!ret)
			sig->block.wire_psv = NULL;
	}

	return ret;
}

static int mlx5_create_sig_psvs(struct ibv_pd *pd,
				struct mlx5dv_mkey_init_attr *attr,
				struct mlx5_sig_ctx *sig)
{
	int err;

	if (attr->create_flags & MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE) {
		sig->block.mem_psv = mlx5_create_psv(pd);
		if (!sig->block.mem_psv)
			return errno;

		sig->block.wire_psv = mlx5_create_psv(pd);
		if (!sig->block.wire_psv) {
			err = errno;
			goto err_destroy_psvs;
		}
	}

	return 0;
err_destroy_psvs:
	mlx5_destroy_sig_psvs(sig);
	return err;
}

static struct mlx5_sig_ctx *mlx5_create_sig_ctx(struct ibv_pd *pd,
						struct mlx5dv_mkey_init_attr *attr)
{
	struct mlx5_sig_ctx *sig;
	int err;

	if (!to_mctx(pd->context)->sig_caps.block_prot) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	sig = calloc(1, sizeof(*sig));
	if (!sig) {
		errno = ENOMEM;
		return NULL;
	}

	err = mlx5_create_sig_psvs(pd, attr, sig);
	if (err) {
		errno = err;
		goto err_free_sig;
	}

	sig->err_exists = false;
	sig->err_count = 1;
	sig->err_count_updated = true;

	return sig;
err_free_sig:
	free(sig);
	return NULL;
}

static int mlx5_destroy_sig_ctx(struct mlx5_sig_ctx *sig)
{
	int ret;

	ret = mlx5_destroy_sig_psvs(sig);
	if (!ret)
		free(sig);

	return ret;
}

static ssize_t _mlx5dv_devx_get_event(struct mlx5dv_devx_event_channel *event_channel,
				      struct mlx5dv_devx_async_event_hdr *event_data,
				      size_t event_resp_len)
{
	ssize_t bytes;

	bytes = read(event_channel->fd, event_data, event_resp_len);
	if (bytes < 0)
		return -1;

	/* cookie should be always exist */
	if (bytes < sizeof(*event_data)) {
		errno = EINVAL;
		return -1;
	}

	/* event data may be omitted in case no EQE data exists (e.g. completion event on a CQ) */
	return bytes;
}

ssize_t mlx5dv_devx_get_event(struct mlx5dv_devx_event_channel *event_channel,
			      struct mlx5dv_devx_async_event_hdr *event_data,
			      size_t event_resp_len)
{
	return _mlx5dv_devx_get_event(event_channel,
				      event_data,
				      event_resp_len);
}

static struct mlx5dv_mkey *
_mlx5dv_create_mkey(struct mlx5dv_mkey_init_attr *mkey_init_attr)
{
	uint32_t out[DEVX_ST_SZ_DW(create_mkey_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_mkey_in)] = {};
	struct mlx5_mkey *mkey;
	bool sig_mkey;
	bool crypto_mkey;
	struct ibv_pd *pd = mkey_init_attr->pd;
	size_t bsf_size = 0;
	void *mkc;

	if (!mkey_init_attr->create_flags ||
	    !check_comp_mask(mkey_init_attr->create_flags,
			     MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
			     MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE |
			     MLX5DV_MKEY_INIT_ATTR_FLAGS_CRYPTO)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	mkey = calloc(1, sizeof(*mkey));
	if (!mkey) {
		errno = ENOMEM;
		return NULL;
	}

	sig_mkey = mkey_init_attr->create_flags &
		   MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE;

	if (sig_mkey) {
		mkey->sig = mlx5_create_sig_ctx(pd, mkey_init_attr);
		if (!mkey->sig)
			goto err_free_mkey;

		bsf_size += sizeof(struct mlx5_bsf);
	}

	crypto_mkey = mkey_init_attr->create_flags &
		      MLX5DV_MKEY_INIT_ATTR_FLAGS_CRYPTO;

	if (crypto_mkey) {
		if (!(to_mctx(pd->context)->crypto_caps.crypto_engines &
		      MLX5DV_CRYPTO_ENGINES_CAP_AES_XTS) ||
		    !(to_mctx(pd->context)->crypto_caps.flags &
		      MLX5DV_CRYPTO_CAPS_WRAPPED_CRYPTO_OPERATIONAL)) {
			errno = EOPNOTSUPP;
			goto err_destroy_sig_ctx;
		}

		mkey->crypto = calloc(1, sizeof(*mkey->crypto));
		if (!mkey->crypto) {
			errno = ENOMEM;
			goto err_destroy_sig_ctx;
		}

		bsf_size += sizeof(struct mlx5_crypto_bsf);
	}

	mkey->num_desc = align(mkey_init_attr->max_entries, 4);
	DEVX_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	mkc = DEVX_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	DEVX_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_KLMS);
	DEVX_SET(mkc, mkc, free, 1);
	DEVX_SET(mkc, mkc, umr_en, 1);
	DEVX_SET(mkc, mkc, pd, to_mpd(pd)->pdn);
	DEVX_SET(mkc, mkc, translations_octword_size, mkey->num_desc);
	DEVX_SET(mkc, mkc, lr, 1);
	DEVX_SET(mkc, mkc, qpn, 0xffffff);
	DEVX_SET(mkc, mkc, mkey_7_0, 0);
	if (crypto_mkey)
		DEVX_SET(mkc, mkc, crypto_en, 1);
	if (sig_mkey || crypto_mkey) {
		DEVX_SET(mkc, mkc, bsf_en, 1);
		DEVX_SET(mkc, mkc, bsf_octword_size, bsf_size / 16);
	}

	mkey->devx_obj = mlx5dv_devx_obj_create(pd->context, in, sizeof(in),
						out, sizeof(out));
	if (!mkey->devx_obj)
		goto err_free_crypto;

	mkey_init_attr->max_entries = mkey->num_desc;
	mkey->dv_mkey.lkey = (DEVX_GET(create_mkey_out, out, mkey_index) << 8) | 0;
	mkey->dv_mkey.rkey = mkey->dv_mkey.lkey;

	if (mlx5_store_mkey(to_mctx(pd->context), mkey->dv_mkey.lkey >> 8, mkey)) {
		errno = ENOMEM;
		goto err_destroy_mkey_obj;
	}

	return &mkey->dv_mkey;
err_destroy_mkey_obj:
	mlx5dv_devx_obj_destroy(mkey->devx_obj);
err_free_crypto:
	if (crypto_mkey)
		free(mkey->crypto);
err_destroy_sig_ctx:
	if (sig_mkey)
		mlx5_destroy_sig_ctx(mkey->sig);
err_free_mkey:
	free(mkey);
	return NULL;
}

struct mlx5dv_mkey *mlx5dv_create_mkey(struct mlx5dv_mkey_init_attr *mkey_init_attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(mkey_init_attr->pd->context);

	if (!dvops || !dvops->create_mkey) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->create_mkey(mkey_init_attr);
}

static int _mlx5dv_destroy_mkey(struct mlx5dv_mkey *dv_mkey)
{
	struct mlx5_mkey *mkey = container_of(dv_mkey, struct mlx5_mkey,
					  dv_mkey);
	struct mlx5_context *mctx = to_mctx(mkey->devx_obj->context);
	int ret;

	if (mkey->sig) {
		ret = mlx5_destroy_sig_ctx(mkey->sig);
		if (ret)
			return ret;

		mkey->sig = NULL;
	}

	ret = mlx5dv_devx_obj_destroy(mkey->devx_obj);
	if (ret)
		return ret;

	if (mkey->crypto)
		free(mkey->crypto);

	mlx5_clear_mkey(mctx, dv_mkey->lkey >> 8);
	free(mkey);
	return 0;
}

int mlx5dv_destroy_mkey(struct mlx5dv_mkey *dv_mkey)
{
	struct mlx5_mkey *mkey = container_of(dv_mkey, struct mlx5_mkey,
					      dv_mkey);
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(mkey->devx_obj->context);

	if (!dvops || !dvops->destroy_mkey)
		return EOPNOTSUPP;

	return dvops->destroy_mkey(dv_mkey);
}

enum {
	MLX5_SIGERR_CQE_SYNDROME_REFTAG = 1 << 11,
	MLX5_SIGERR_CQE_SYNDROME_APPTAG = 1 << 12,
	MLX5_SIGERR_CQE_SYNDROME_GUARD = 1 << 13,

	MLX5_SIGERR_CQE_SIG_TYPE_BLOCK = 0,
	MLX5_SIGERR_CQE_SIG_TYPE_TRANSACTION = 1,

	MLX5_SIGERR_CQE_DOMAIN_WIRE = 0,
	MLX5_SIGERR_CQE_DOMAIN_MEMORY = 1,
};

static void mlx5_decode_sigerr(struct mlx5_sig_err *mlx5_err,
			       struct mlx5_sig_block_domain *bd,
			       struct mlx5dv_mkey_err *err_info)
{
	struct mlx5dv_sig_err *dv_err = &err_info->err.sig;

	dv_err->offset = mlx5_err->offset;

	if (mlx5_err->syndrome & MLX5_SIGERR_CQE_SYNDROME_REFTAG) {
		err_info->err_type = MLX5DV_MKEY_SIG_BLOCK_BAD_REFTAG;
		dv_err->expected_value = mlx5_err->expected & 0xffffffff;
		dv_err->actual_value = mlx5_err->actual & 0xffffffff;

	} else if (mlx5_err->syndrome & MLX5_SIGERR_CQE_SYNDROME_APPTAG) {
		err_info->err_type = MLX5DV_MKEY_SIG_BLOCK_BAD_APPTAG;
		dv_err->expected_value = (mlx5_err->expected >> 32) & 0xffff;
		dv_err->actual_value = (mlx5_err->actual >> 32) & 0xffff;

	} else {
		err_info->err_type = MLX5DV_MKEY_SIG_BLOCK_BAD_GUARD;

		if (bd->sig_type == MLX5_SIG_TYPE_T10DIF) {
			dv_err->expected_value = mlx5_err->expected >> 48;
			dv_err->actual_value = mlx5_err->actual >> 48;

		} else if (bd->sig.crc.type == MLX5DV_SIG_CRC_TYPE_CRC64_XP10) {
			dv_err->expected_value = mlx5_err->expected;
			dv_err->actual_value = mlx5_err->actual;

		} else {
			/* CRC32 or CRC32C */
			dv_err->expected_value = mlx5_err->expected >> 32;
			dv_err->actual_value = mlx5_err->actual >> 32;
		}
	}
}

int _mlx5dv_mkey_check(struct mlx5dv_mkey *dv_mkey,
		       struct mlx5dv_mkey_err *err_info,
		       size_t err_info_size)
{
	struct mlx5_mkey *mkey = container_of(dv_mkey, struct mlx5_mkey,
					      dv_mkey);
	struct mlx5_sig_ctx *sig_ctx = mkey->sig;
	FILE *fp = to_mctx(mkey->devx_obj->context)->dbg_fp;
	struct mlx5_sig_err *sig_err;
	struct mlx5_sig_block_domain *domain;

	if (!sig_ctx)
		return EINVAL;

	if (!sig_ctx->err_exists) {
		err_info->err_type = MLX5DV_MKEY_NO_ERR;
		return 0;
	}

	sig_err = &sig_ctx->err_info;

	if (!(sig_err->syndrome & (MLX5_SIGERR_CQE_SYNDROME_REFTAG |
				   MLX5_SIGERR_CQE_SYNDROME_APPTAG |
				   MLX5_SIGERR_CQE_SYNDROME_GUARD))) {
		mlx5_dbg(fp, MLX5_DBG_CQ,
			 "unknown signature error, syndrome 0x%x\n",
			 sig_err->syndrome);
		return EINVAL;
	}

	if (sig_err->sig_type != MLX5_SIGERR_CQE_SIG_TYPE_BLOCK) {
		mlx5_dbg(fp, MLX5_DBG_CQ,
			 "not supported signature type 0x%x\n",
			 sig_err->sig_type);
		return EINVAL;
	}

	switch (sig_err->domain) {
	case MLX5_SIGERR_CQE_DOMAIN_WIRE:
		domain = &sig_ctx->block.attr.wire;
		break;
	case MLX5_SIGERR_CQE_DOMAIN_MEMORY:
		domain = &sig_ctx->block.attr.mem;
		break;
	default:
		mlx5_dbg(fp, MLX5_DBG_CQ, "unknown signature domain 0x%x\n",
			 sig_err->domain);
		return EINVAL;
	}

	if (domain->sig_type == MLX5_SIG_TYPE_NONE) {
		mlx5_dbg(fp, MLX5_DBG_CQ,
			 "unexpected signature error for non-signature domain\n");
		return EINVAL;
	}

	mlx5_decode_sigerr(sig_err, domain, err_info);
	sig_ctx->err_exists = false;

	return 0;
}

static int _mlx5dv_crypto_login(struct ibv_context *context,
				struct mlx5dv_crypto_login_attr *login_attr)
{
	uint32_t in[DEVX_ST_SZ_DW(create_crypto_login_obj_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	struct mlx5_context *mctx = to_mctx(context);
	int ret = 0;
	void *attr;

	if (!(mctx->crypto_caps.flags & MLX5DV_CRYPTO_CAPS_CRYPTO) ||
	    !(mctx->crypto_caps.flags &
	      MLX5DV_CRYPTO_CAPS_WRAPPED_CRYPTO_OPERATIONAL))
		return EOPNOTSUPP;

	if (!(mctx->general_obj_types_caps &
	      (1ULL << MLX5_OBJ_TYPE_CRYPTO_LOGIN)))
		return EOPNOTSUPP;

	if (login_attr->comp_mask)
		return EINVAL;

	if (login_attr->credential_id & 0xff000000 ||
	    login_attr->import_kek_id & 0xff000000)
		return EINVAL;

	pthread_mutex_lock(&mctx->crypto_login_mutex);
	if (mctx->crypto_login) {
		ret = EEXIST;
		goto out;
	}

	attr = DEVX_ADDR_OF(create_crypto_login_obj_in, in, hdr);
	DEVX_SET(general_obj_in_cmd_hdr, attr, opcode,
		 MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr, attr, obj_type,
		 MLX5_OBJ_TYPE_CRYPTO_LOGIN);

	attr = DEVX_ADDR_OF(create_crypto_login_obj_in, in, login_obj);
	DEVX_SET(crypto_login_obj, attr, credential_pointer,
		 login_attr->credential_id);
	DEVX_SET(crypto_login_obj, attr, session_import_kek_ptr,
		 login_attr->import_kek_id);
	memcpy(DEVX_ADDR_OF(crypto_login_obj, attr, credential),
	       login_attr->credential, sizeof(login_attr->credential));

	mctx->crypto_login = mlx5dv_devx_obj_create(context, in, sizeof(in),
						    out, sizeof(out));
	if (!mctx->crypto_login)
		ret = errno;

out:
	pthread_mutex_unlock(&mctx->crypto_login_mutex);
	return ret;
}

int mlx5dv_crypto_login(struct ibv_context *context,
			struct mlx5dv_crypto_login_attr *login_attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->crypto_login)
		return EOPNOTSUPP;

	return dvops->crypto_login(context, login_attr);
}

static int
_mlx5dv_crypto_login_query_state(struct ibv_context *context,
				 enum mlx5dv_crypto_login_state *state)
{
	uint32_t out[DEVX_ST_SZ_DW(query_crypto_login_obj_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(general_obj_in_cmd_hdr)] = {};
	struct mlx5_context *mctx = to_mctx(context);
	uint8_t crypto_login_state;
	void *attr;
	int ret;

	pthread_mutex_lock(&mctx->crypto_login_mutex);
	if (!mctx->crypto_login) {
		*state = MLX5DV_CRYPTO_LOGIN_STATE_NO_LOGIN;
		ret = 0;
		goto out;
	}

	DEVX_SET(general_obj_in_cmd_hdr, in, opcode,
		 MLX5_CMD_OP_QUERY_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_type,
		 MLX5_OBJ_TYPE_CRYPTO_LOGIN);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_id,
		 mctx->crypto_login->object_id);

	ret = mlx5dv_devx_obj_query(mctx->crypto_login, in, sizeof(in), out,
				    sizeof(out));
	if (ret)
		goto out;

	attr = DEVX_ADDR_OF(query_crypto_login_obj_out, out, obj);
	crypto_login_state = DEVX_GET(crypto_login_obj, attr, state);

	switch (crypto_login_state) {
	case MLX5_CRYPTO_LOGIN_OBJ_STATE_VALID:
		*state = MLX5DV_CRYPTO_LOGIN_STATE_VALID;
		break;
	case MLX5_CRYPTO_LOGIN_OBJ_STATE_INVALID:
		*state = MLX5DV_CRYPTO_LOGIN_STATE_INVALID;
		break;
	default:
		ret = EINVAL;
		break;
	}

out:
	pthread_mutex_unlock(&mctx->crypto_login_mutex);
	return ret;
}

int mlx5dv_crypto_login_query_state(struct ibv_context *context,
				    enum mlx5dv_crypto_login_state *state)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->crypto_login_query_state)
		return EOPNOTSUPP;

	return dvops->crypto_login_query_state(context, state);
}

static int _mlx5dv_crypto_logout(struct ibv_context *context)
{
	struct mlx5_context *mctx = to_mctx(context);
	int ret;

	pthread_mutex_lock(&mctx->crypto_login_mutex);
	if (!mctx->crypto_login) {
		ret = ENOENT;
		goto out;
	}

	ret = mlx5dv_devx_obj_destroy(mctx->crypto_login);
	if (ret)
		goto out;

	mctx->crypto_login = NULL;

out:
	pthread_mutex_unlock(&mctx->crypto_login_mutex);
	return ret;
}

int mlx5dv_crypto_logout(struct ibv_context *context)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->crypto_logout)
		return EOPNOTSUPP;

	return dvops->crypto_logout(context);
}

static struct mlx5dv_dek *
_mlx5dv_dek_create(struct ibv_context *context,
		   struct mlx5dv_dek_init_attr *init_attr)
{
	uint32_t in[DEVX_ST_SZ_DW(create_encryption_key_obj_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	struct mlx5_context *mctx = to_mctx(context);
	struct mlx5dv_devx_obj *obj;
	struct mlx5dv_dek *dek;
	uint8_t key_size;
	void *attr;

	if (!(mctx->general_obj_types_caps & (1ULL << MLX5_OBJ_TYPE_DEK))) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (init_attr->key_purpose != MLX5DV_CRYPTO_KEY_PURPOSE_AES_XTS) {
		errno = EINVAL;
		return NULL;
	}

	switch (init_attr->key_size) {
	case MLX5DV_CRYPTO_KEY_SIZE_128:
		key_size = MLX5_ENCRYPTION_KEY_OBJ_KEY_SIZE_SIZE_128;
		break;
	case MLX5DV_CRYPTO_KEY_SIZE_256:
		key_size = MLX5_ENCRYPTION_KEY_OBJ_KEY_SIZE_SIZE_256;
		break;
	default:
		errno = EINVAL;
		return NULL;
	}

	if (init_attr->comp_mask) {
		errno = EINVAL;
		return NULL;
	}

	dek = calloc(1, sizeof(*dek));
	if (!dek) {
		errno = ENOMEM;
		return NULL;
	}

	attr = DEVX_ADDR_OF(create_encryption_key_obj_in, in, hdr);
	DEVX_SET(general_obj_in_cmd_hdr, attr, opcode,
		 MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr, attr, obj_type, MLX5_OBJ_TYPE_DEK);

	attr = DEVX_ADDR_OF(create_encryption_key_obj_in, in, key_obj);
	DEVX_SET(encryption_key_obj, attr, key_size, key_size);
	DEVX_SET(encryption_key_obj, attr, has_keytag, !!init_attr->has_keytag);
	DEVX_SET(encryption_key_obj, attr, key_purpose,
		 MLX5_ENCRYPTION_KEY_OBJ_KEY_PURPOSE_AES_XTS);
	DEVX_SET(encryption_key_obj, attr, pd, to_mpd(init_attr->pd)->pdn);
	memcpy(DEVX_ADDR_OF(encryption_key_obj, attr, opaque),
	       init_attr->opaque, sizeof(init_attr->opaque));
	memcpy(DEVX_ADDR_OF(encryption_key_obj, attr, key), init_attr->key,
	       sizeof(init_attr->key));

	obj = mlx5dv_devx_obj_create(context, in, sizeof(in), out, sizeof(out));
	if (!obj) {
		free(dek);
		return NULL;
	}

	dek->devx_obj = obj;

	return dek;
}

struct mlx5dv_dek *mlx5dv_dek_create(struct ibv_context *context,
				     struct mlx5dv_dek_init_attr *init_attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->dek_create) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->dek_create(context, init_attr);
}

static int _mlx5dv_dek_query(struct mlx5dv_dek *dek,
			     struct mlx5dv_dek_attr *dek_attr)
{
	uint32_t out[DEVX_ST_SZ_DW(query_encryption_key_obj_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(general_obj_in_cmd_hdr)] = {};
	uint8_t dek_state;
	void *attr;
	int ret;

	if (dek_attr->comp_mask)
		return EINVAL;

	DEVX_SET(general_obj_in_cmd_hdr, in, opcode,
		 MLX5_CMD_OP_QUERY_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_type, MLX5_OBJ_TYPE_DEK);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_id, dek->devx_obj->object_id);

	ret = mlx5dv_devx_obj_query(dek->devx_obj, in, sizeof(in), out,
				    sizeof(out));
	if (ret)
		return ret;

	attr = DEVX_ADDR_OF(query_encryption_key_obj_out, out, obj);
	dek_state = DEVX_GET(encryption_key_obj, attr, state);
	switch (dek_state) {
	case MLX5_ENCRYPTION_KEY_OBJ_STATE_READY:
		dek_attr->state = MLX5DV_DEK_STATE_READY;
		break;
	case MLX5_ENCRYPTION_KEY_OBJ_STATE_ERROR:
		dek_attr->state = MLX5DV_DEK_STATE_ERROR;
		break;
	default:
		return EINVAL;
	}
	memcpy(dek_attr->opaque, DEVX_ADDR_OF(encryption_key_obj, attr, opaque),
	       sizeof(dek_attr->opaque));

	return 0;
}

int mlx5dv_dek_query(struct mlx5dv_dek *dek, struct mlx5dv_dek_attr *dek_attr)
{
	struct mlx5_dv_context_ops *dvops =
		mlx5_get_dv_ops(dek->devx_obj->context);

	if (!dvops || !dvops->dek_query)
		return EOPNOTSUPP;

	return dvops->dek_query(dek, dek_attr);
}

static int _mlx5dv_dek_destroy(struct mlx5dv_dek *dek)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(dek->devx_obj);
	if (ret)
		return ret;

	free(dek);

	return 0;
}

int mlx5dv_dek_destroy(struct mlx5dv_dek *dek)
{
	struct mlx5_dv_context_ops *dvops =
		mlx5_get_dv_ops(dek->devx_obj->context);

	if (!dvops || !dvops->dek_destroy)
		return EOPNOTSUPP;

	return dvops->dek_destroy(dek);
}

static struct mlx5dv_var *
_mlx5dv_alloc_var(struct ibv_context *context, uint32_t flags)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_VAR,
			       MLX5_IB_METHOD_VAR_OBJ_ALLOC,
			       4);

	struct ib_uverbs_attr *handle;
	struct mlx5_var_obj *obj;
	int ret;

	if (flags) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_VAR_OBJ_ALLOC_HANDLE);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_VAR_OBJ_ALLOC_MMAP_OFFSET,
		      &obj->dv_var.mmap_off);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_VAR_OBJ_ALLOC_MMAP_LENGTH,
		      &obj->dv_var.length);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_VAR_OBJ_ALLOC_PAGE_ID,
		      &obj->dv_var.page_id);

	ret = execute_ioctl(context, cmd);
	if (ret)
		goto err;

	obj->handle = read_attr_obj(MLX5_IB_ATTR_VAR_OBJ_ALLOC_HANDLE, handle);
	obj->context = context;

	return &obj->dv_var;

err:
	free(obj);
	return NULL;
}

struct mlx5dv_var *
mlx5dv_alloc_var(struct ibv_context *context, uint32_t flags)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->alloc_var) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->alloc_var(context, flags);
}

static void _mlx5dv_free_var(struct mlx5dv_var *dv_var)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_VAR,
			       MLX5_IB_METHOD_VAR_OBJ_DESTROY,
			       1);

	struct mlx5_var_obj *obj = container_of(dv_var, struct mlx5_var_obj,
						dv_var);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_VAR_OBJ_DESTROY_HANDLE, obj->handle);
	if (execute_ioctl(obj->context, cmd))
		assert(false);

	free(obj);
}

void mlx5dv_free_var(struct mlx5dv_var *dv_var)
{
	struct mlx5_var_obj *obj = container_of(dv_var, struct mlx5_var_obj,
						dv_var);
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(obj->context);

	if (!dvops || !dvops->free_var)
		return;

	return dvops->free_var(dv_var);
}

static struct mlx5dv_pp *_mlx5dv_pp_alloc(struct ibv_context *context,
					  size_t pp_context_sz,
					  const void *pp_context,
					  uint32_t flags)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_PP,
			       MLX5_IB_METHOD_PP_OBJ_ALLOC,
			       4);

	struct ib_uverbs_attr *handle;
	struct mlx5_pp_obj *obj;
	int ret;

	if (!check_comp_mask(flags,
	    MLX5_IB_UAPI_PP_ALLOC_FLAGS_DEDICATED_INDEX)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_PP_OBJ_ALLOC_HANDLE);
	fill_attr_in(cmd, MLX5_IB_ATTR_PP_OBJ_ALLOC_CTX,
		     pp_context, pp_context_sz);
	fill_attr_const_in(cmd, MLX5_IB_ATTR_PP_OBJ_ALLOC_FLAGS, flags);
	fill_attr_out_ptr(cmd, MLX5_IB_ATTR_PP_OBJ_ALLOC_INDEX,
		      &obj->dv_pp.index);

	ret = execute_ioctl(context, cmd);
	if (ret)
		goto err;

	obj->handle = read_attr_obj(MLX5_IB_ATTR_PP_OBJ_ALLOC_HANDLE, handle);
	obj->context = context;

	return &obj->dv_pp;

err:
	free(obj);
	return NULL;
}

struct mlx5dv_pp *mlx5dv_pp_alloc(struct ibv_context *context,
				  size_t pp_context_sz,
				  const void *pp_context,
				  uint32_t flags)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(context);

	if (!dvops || !dvops->pp_alloc) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->pp_alloc(context, pp_context_sz,
			       pp_context, flags);
}

static void _mlx5dv_pp_free(struct mlx5dv_pp *dv_pp)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_PP,
			       MLX5_IB_METHOD_PP_OBJ_DESTROY,
			       1);

	struct mlx5_pp_obj *obj = container_of(dv_pp, struct mlx5_pp_obj,
					       dv_pp);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_PP_OBJ_DESTROY_HANDLE, obj->handle);
	if (execute_ioctl(obj->context, cmd))
		assert(false);

	free(obj);
}

void mlx5dv_pp_free(struct mlx5dv_pp *dv_pp)
{
	struct mlx5_pp_obj *obj = container_of(dv_pp, struct mlx5_pp_obj, dv_pp);
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(obj->context);

	if (!dvops || !dvops->pp_free)
		return;

	dvops->pp_free(dv_pp);
}

void mlx5_set_dv_ctx_ops(struct mlx5_dv_context_ops *ops)
{
	ops->devx_general_cmd = _mlx5dv_devx_general_cmd;

	ops->devx_obj_create = _mlx5dv_devx_obj_create;

	ops->devx_obj_query = _mlx5dv_devx_obj_query;
	ops->devx_obj_modify = _mlx5dv_devx_obj_modify;
	ops->devx_obj_destroy = _mlx5dv_devx_obj_destroy;

	ops->devx_query_eqn = _mlx5dv_devx_query_eqn;

	ops->devx_cq_query = _mlx5dv_devx_cq_query;
	ops->devx_cq_modify = _mlx5dv_devx_cq_modify;

	ops->devx_qp_query = _mlx5dv_devx_qp_query;
	ops->devx_qp_modify = _mlx5dv_devx_qp_modify;

	ops->devx_srq_query = _mlx5dv_devx_srq_query;
	ops->devx_srq_modify = _mlx5dv_devx_srq_modify;

	ops->devx_wq_query = _mlx5dv_devx_wq_query;
	ops->devx_wq_modify = _mlx5dv_devx_wq_modify;

	ops->devx_ind_tbl_query = _mlx5dv_devx_ind_tbl_query;
	ops->devx_ind_tbl_modify = _mlx5dv_devx_ind_tbl_modify;

	ops->devx_create_cmd_comp = _mlx5dv_devx_create_cmd_comp;
	ops->devx_destroy_cmd_comp = _mlx5dv_devx_destroy_cmd_comp;

	ops->devx_create_event_channel = _mlx5dv_devx_create_event_channel;
	ops->devx_destroy_event_channel = _mlx5dv_devx_destroy_event_channel;

	ops->devx_subscribe_devx_event = _mlx5dv_devx_subscribe_devx_event;
	ops->devx_subscribe_devx_event_fd = _mlx5dv_devx_subscribe_devx_event_fd;

	ops->devx_obj_query_async = _mlx5dv_devx_obj_query_async;
	ops->devx_get_async_cmd_comp = _mlx5dv_devx_get_async_cmd_comp;

	ops->devx_get_event = _mlx5dv_devx_get_event;

	ops->devx_alloc_uar = _mlx5dv_devx_alloc_uar;
	ops->devx_free_uar = _mlx5dv_devx_free_uar;

	ops->devx_umem_reg = _mlx5dv_devx_umem_reg;
	ops->devx_umem_reg_ex = _mlx5dv_devx_umem_reg_ex;
	ops->devx_umem_dereg = _mlx5dv_devx_umem_dereg;

	ops->create_mkey = _mlx5dv_create_mkey;
	ops->destroy_mkey = _mlx5dv_destroy_mkey;

	ops->crypto_login = _mlx5dv_crypto_login;
	ops->crypto_login_query_state = _mlx5dv_crypto_login_query_state;
	ops->crypto_logout = _mlx5dv_crypto_logout;

	ops->dek_create = _mlx5dv_dek_create;
	ops->dek_query = _mlx5dv_dek_query;
	ops->dek_destroy = _mlx5dv_dek_destroy;

	ops->alloc_var = _mlx5dv_alloc_var;
	ops->free_var = _mlx5dv_free_var;

	ops->pp_alloc = _mlx5dv_pp_alloc;
	ops->pp_free = _mlx5dv_pp_free;

	ops->create_cq = _mlx5dv_create_cq;
	ops->create_qp = _mlx5dv_create_qp;
	ops->create_wq = _mlx5dv_create_wq;

	ops->alloc_dm = _mlx5dv_alloc_dm;
	ops->dm_map_op_addr = _mlx5dv_dm_map_op_addr;

	ops->create_flow_action_esp = _mlx5dv_create_flow_action_esp;
	ops->create_flow_action_modify_header = _mlx5dv_create_flow_action_modify_header;
	ops->create_flow_action_packet_reformat = _mlx5dv_create_flow_action_packet_reformat;
	ops->create_flow_matcher = _mlx5dv_create_flow_matcher;
	ops->destroy_flow_matcher = _mlx5dv_destroy_flow_matcher;
	ops->create_flow = _mlx5dv_create_flow;

	ops->map_ah_to_qp = _mlx5dv_map_ah_to_qp;
	ops->query_port = __mlx5dv_query_port;
}
