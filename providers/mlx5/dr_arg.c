// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "mlx5dv_dr.h"

#define DR_ICM_MODIFY_HDR_GRANULARITY_4K 12

/* modify-header arg pool */
enum dr_arg_chunk_size {
	DR_ARG_CHUNK_SIZE_1,
	DR_ARG_CHUNK_SIZE_MIN = DR_ARG_CHUNK_SIZE_1, /* keep updated when changing */
	DR_ARG_CHUNK_SIZE_2,
	DR_ARG_CHUNK_SIZE_3,
	DR_ARG_CHUNK_SIZE_4,
	DR_ARG_CHUNK_SIZE_MAX,
};

/* argument pool area */
struct dr_arg_pool {
	enum dr_arg_chunk_size	log_chunk_size;
	struct mlx5dv_dr_domain	*dmn;
	struct list_head	free_list;
	pthread_mutex_t		mutex;
};

struct dr_arg_mngr {
	struct mlx5dv_dr_domain *dmn;
	struct dr_arg_pool *pools[DR_ARG_CHUNK_SIZE_MAX];
};

static int dr_arg_pool_alloc_objs(struct dr_arg_pool *pool)
{
	struct dr_arg_obj *arg_obj, *tmp_arg;
	struct mlx5dv_devx_obj *devx_obj;
	uint16_t object_range;
	LIST_HEAD(cur_list);
	int num_of_objects;
	int i;

	object_range =
		pool->dmn->info.caps.log_header_modify_argument_granularity;

	object_range =
		max_t(uint32_t,
		      pool->dmn->info.caps.log_header_modify_argument_granularity,
		      DR_ICM_MODIFY_HDR_GRANULARITY_4K);
	object_range =
		min_t(uint32_t,
		      pool->dmn->info.caps.log_header_modify_argument_max_alloc,
		      object_range);

	if (pool->log_chunk_size > object_range) {
		dr_dbg(pool->dmn, "Required chunk size (%d) is not supported\n",
		       pool->log_chunk_size);
		errno = ENOMEM;
		return errno;
	}

	num_of_objects = (1 << (object_range - pool->log_chunk_size));
	/* Only one devx object per range */
	devx_obj = dr_devx_create_modify_header_arg(pool->dmn->ctx,
						    object_range,
						    pool->dmn->pd_num);
	if (!devx_obj) {
		dr_dbg(pool->dmn, "failed allocating object with range: %d:\n",
		       object_range);
		return errno;
	}

	for (i = 0; i < num_of_objects; i++) {
		arg_obj = calloc(1, sizeof(struct dr_arg_pool));
		if (!arg_obj) {
			errno = ENOMEM;
			goto clean_arg_obj;
		}

		arg_obj->log_chunk_size = pool->log_chunk_size;

		list_add_tail(&cur_list, &arg_obj->list_node);

		arg_obj->obj = devx_obj;
		arg_obj->obj_offset = i * (1 << pool->log_chunk_size);
	}
	list_append_list(&pool->free_list, &cur_list);

	return 0;

clean_arg_obj:
	mlx5dv_devx_obj_destroy(devx_obj);
	list_for_each_safe(&cur_list, arg_obj, tmp_arg, list_node) {
		list_del(&arg_obj->list_node);
		free(arg_obj);
	}
	return errno;
}

static struct dr_arg_obj *dr_arg_pool_get_arg_obj(struct dr_arg_pool *pool)
{
	struct dr_arg_obj *arg_obj = NULL;
	int ret;

	pthread_mutex_lock(&pool->mutex);
	if (list_empty(&pool->free_list)) {
		ret = dr_arg_pool_alloc_objs(pool);
		if (ret)
			goto out;
	}

	arg_obj = list_pop(&pool->free_list, struct dr_arg_obj, list_node);
	if (!arg_obj)
		assert(false);

out:
	pthread_mutex_unlock(&pool->mutex);
	return arg_obj;
}

static void dr_arg_pool_put_arg_obj(struct dr_arg_pool *pool,
				    struct dr_arg_obj *arg_obj)
{
	pthread_mutex_lock(&pool->mutex);
	list_add(&pool->free_list, &arg_obj->list_node);
	pthread_mutex_unlock(&pool->mutex);
}

static struct dr_arg_pool *dr_arg_pool_create(struct mlx5dv_dr_domain *dmn,
					      enum dr_arg_chunk_size chunk_size)
{
	struct dr_arg_pool *pool;

	pool = calloc(1, sizeof(struct dr_arg_pool));
	if (!pool) {
		errno = ENOMEM;
		return NULL;
	}

	pool->dmn = dmn;

	list_head_init(&pool->free_list);
	pthread_mutex_init(&pool->mutex, NULL);

	pool->log_chunk_size = chunk_size;
	if (dr_arg_pool_alloc_objs(pool))
		goto free_pool;

	return pool;

free_pool:
	free(pool);

	return NULL;
}

static void dr_arg_pool_destroy(struct dr_arg_pool *pool)
{
	struct dr_arg_obj *tmp_arg;
	struct dr_arg_obj *arg_obj;

	list_for_each_safe(&pool->free_list, arg_obj, tmp_arg, list_node) {
		list_del(&arg_obj->list_node);
		if (!arg_obj->obj_offset) /* the first in range */
			mlx5dv_devx_obj_destroy(arg_obj->obj);
		free(arg_obj);
	}

	pthread_mutex_destroy(&pool->mutex);

	free(pool);
}

static enum dr_arg_chunk_size
dr_arg_get_chunk_size(uint16_t num_of_actions)
{
	if (num_of_actions <= 8)
		return DR_ARG_CHUNK_SIZE_1;
	if (num_of_actions <= 16)
		return DR_ARG_CHUNK_SIZE_2;
	if (num_of_actions <= 32)
		return DR_ARG_CHUNK_SIZE_3;
	if (num_of_actions <= 64)
		return DR_ARG_CHUNK_SIZE_4;

	errno = EINVAL;
	return DR_ARG_CHUNK_SIZE_MAX;
}

uint32_t dr_arg_get_object_id(struct dr_arg_obj *arg_obj)
{
	return (arg_obj->obj->object_id + arg_obj->obj_offset);
}

struct dr_arg_obj *dr_arg_get_obj(struct dr_arg_mngr *mngr,
				  uint16_t num_of_actions,
				  uint8_t *data)
{
	uint32_t size = dr_arg_get_chunk_size(num_of_actions);
	struct dr_arg_obj *arg_obj;
	int ret;

	if (size >= DR_ARG_CHUNK_SIZE_MAX)
		return NULL;

	arg_obj = dr_arg_pool_get_arg_obj(mngr->pools[size]);
	if (!arg_obj) {
		dr_dbg(mngr->dmn, "Failed allocating args object for modify header\n");
		return NULL;
	}

	if (!mngr->dmn->info.use_mqs) {
		/* write it into the hw */
		ret = dr_send_postsend_args(mngr->dmn, dr_arg_get_object_id(arg_obj),
					    num_of_actions, data, 0);
		if (ret) {
			dr_dbg(mngr->dmn, "Failed writing args object\n");
			goto put_obj;
		}
	}

	return arg_obj;

put_obj:
	dr_arg_put_obj(mngr, arg_obj);
	return NULL;
}

void dr_arg_put_obj(struct dr_arg_mngr *mngr, struct dr_arg_obj *arg_obj)
{
	dr_arg_pool_put_arg_obj(mngr->pools[arg_obj->log_chunk_size],
				arg_obj);
}

struct dr_arg_mngr*
dr_arg_mngr_create(struct mlx5dv_dr_domain *dmn)
{
	struct dr_arg_mngr *pool_mngr;
	int i;

	if (!dr_domain_is_support_modify_hdr_cache(dmn))
		return NULL;

	pool_mngr = calloc(1, sizeof(struct dr_arg_mngr));
	if (!pool_mngr) {
		errno = ENOMEM;
		return NULL;
	}

	pool_mngr->dmn = dmn;

	for (i = 0; i < DR_ARG_CHUNK_SIZE_MAX; i++) {
		pool_mngr->pools[i] = dr_arg_pool_create(dmn, i);
		if (!pool_mngr->pools[i])
			goto clean_pools;
	}

	return pool_mngr;

clean_pools:
	for (i--; i >= 0; i--)
		dr_arg_pool_destroy(pool_mngr->pools[i]);

	free(pool_mngr);
	return NULL;
}

void dr_arg_mngr_destroy(struct dr_arg_mngr *mngr)
{
	struct dr_arg_pool **pools;
	int i;

	if (!mngr)
		return;

	pools = mngr->pools;
	for (i = 0; i < DR_ARG_CHUNK_SIZE_MAX; i++)
		dr_arg_pool_destroy(pools[i]);

	free(mngr);
}
