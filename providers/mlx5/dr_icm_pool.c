/*
 * Copyright (c) 2019, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include "mlx5dv_dr.h"

#define DR_ICM_MODIFY_HDR_ALIGN_BASE	64

struct dr_icm_pool;

#define DR_ICM_SYNC_THRESHOLD (64 * 1024 * 1024)

struct dr_icm_bucket {
	struct dr_icm_pool	*pool;

	/* It is safe to allocate chunks from this list, now HW is guaranteed
	 * to not access this memory
	 */
	struct list_head	free_list;
	unsigned int		free_list_count;

	/* This is the list of used chunks, HW may be accessing this memory */
	struct list_head	used_list;
	unsigned int		used_list_count;

	/* HW may be accessing this memory but at some future,
	 * undetermined time, it might cease to do so. Before deciding to call
	 * sync_ste, this list is moved to tmp_list
	 */
	struct list_head	hot_list;
	unsigned int		hot_list_count;

	/* Temporary list, entries from the hot list are moved to this list.
	 * sync_ste is executed and then tmp_list is concatenated to the free list
	 */
	struct list_head	tmp_list;
	unsigned int		tmp_list_count;

	uint32_t		total_chunks;
	uint32_t		num_of_entries;
	uint32_t		entry_size;
	pthread_mutex_t		mutex;
};

struct dr_icm_pool {
	struct dr_icm_bucket	*buckets;
	enum dr_icm_type	icm_type;
	enum dr_icm_chunk_size	max_log_chunk_sz;
	enum dr_icm_chunk_size	num_of_buckets;
	struct list_head	icm_mr_list;
	pthread_mutex_t		mr_mutex;
	struct mlx5dv_dr_domain	*dmn;
};

struct dr_icm_mr {
	struct dr_icm_pool	*pool;
	struct ibv_mr		*mr;
	struct ibv_dm		*dm;
	size_t			used_length;
	uint64_t		icm_start_addr;
	struct list_node	mr_list;
};

static struct dr_icm_mr *
dr_icm_pool_mr_create(struct dr_icm_pool *pool,
		      enum mlx5_ib_uapi_dm_type dm_type,
		      size_t align_base)
{
	struct mlx5dv_alloc_dm_attr mlx5_dm_attr = {};
	struct ibv_alloc_dm_attr dm_attr = {};
	struct dr_icm_mr *icm_mr;
	struct mlx5_dm *dm;
	size_t align_diff;

	icm_mr = calloc(1, sizeof(struct dr_icm_mr));
	if (!icm_mr) {
		errno = ENOMEM;
		return NULL;
	}

	icm_mr->pool = pool;
	list_node_init(&icm_mr->mr_list);

	mlx5_dm_attr.type = dm_type;

	/* 2^log_biggest_table * entry-size * double-for-alignment */
	dm_attr.length = dr_icm_pool_chunk_size_to_byte(pool->max_log_chunk_sz,
							pool->icm_type) * 2;

	icm_mr->dm = mlx5dv_alloc_dm(pool->dmn->ctx, &dm_attr, &mlx5_dm_attr);
	if (!icm_mr->dm) {
		dr_dbg(pool->dmn, "Failed allocating DM\n");
		goto free_icm_mr;
	}

	/* Register device memory */
	icm_mr->mr = ibv_reg_dm_mr(pool->dmn->pd, icm_mr->dm, 0,
				   dm_attr.length,
				   IBV_ACCESS_ZERO_BASED |
				   IBV_ACCESS_REMOTE_WRITE |
				   IBV_ACCESS_LOCAL_WRITE |
				   IBV_ACCESS_REMOTE_READ);
	if (!icm_mr->mr) {
		dr_dbg(pool->dmn, "Failed DM registration\n");
		goto free_dm;
	}

	dm = to_mdm(icm_mr->dm);
	icm_mr->icm_start_addr = dm->remote_va;

	align_diff = icm_mr->icm_start_addr % align_base;
	if (align_diff)
		icm_mr->used_length = align_base - align_diff;

	list_add_tail(&pool->icm_mr_list, &icm_mr->mr_list);

	return icm_mr;

free_dm:
	mlx5_free_dm(icm_mr->dm);
free_icm_mr:
	free(icm_mr);
	return NULL;
}

static  void dr_icm_pool_mr_destroy(struct dr_icm_mr *icm_mr)
{
	list_del(&icm_mr->mr_list);
	ibv_dereg_mr(icm_mr->mr);
	mlx5_free_dm(icm_mr->dm);
	free(icm_mr);
}

static int dr_icm_chunk_ste_init(struct dr_icm_chunk *chunk)
{
	struct dr_icm_bucket *bucket = chunk->bucket;
	struct dr_icm_pool *pool = bucket->pool;

	chunk->ste_arr = calloc(bucket->num_of_entries, sizeof(struct dr_ste));
	if (!chunk->ste_arr) {
		dr_dbg(pool->dmn, "Failed allocating ste_arr for chunk\n");
		errno = ENOMEM;
		return errno;
	}

	chunk->hw_ste_arr = calloc(bucket->num_of_entries, DR_STE_SIZE_REDUCED);
	if (!chunk->hw_ste_arr) {
		dr_dbg(pool->dmn, "Failed allocating hw_ste_arr for chunk\n");
		errno = ENOMEM;
		goto out_free_ste_arr;
	}

	chunk->miss_list = malloc(bucket->num_of_entries *
				  sizeof(struct list_head));
	if (!chunk->miss_list) {
		dr_dbg(pool->dmn, "Failed allocating miss_list for chunk\n");
		errno = ENOMEM;
		goto out_free_hw_ste_arr;
	}

	return 0;

out_free_hw_ste_arr:
	free(chunk->hw_ste_arr);
out_free_ste_arr:
	free(chunk->ste_arr);
	return errno;
}

static int dr_icm_chunks_create(struct dr_icm_bucket *bucket)
{
	size_t mr_free_size, mr_req_size, mr_row_size;
	struct dr_icm_pool *pool = bucket->pool;
	enum mlx5_ib_uapi_dm_type dm_type;
	struct dr_icm_chunk *chunk;
	struct dr_icm_mr *icm_mr;
	size_t align_base;
	int i;

	mr_req_size = bucket->num_of_entries * bucket->entry_size;
	mr_row_size = dr_icm_pool_chunk_size_to_byte(pool->max_log_chunk_sz,
						     pool->icm_type);

	if (pool->icm_type == DR_ICM_TYPE_STE) {
		dm_type = MLX5_IB_UAPI_DM_TYPE_STEERING_SW_ICM;
		/* Align base is the biggest chunk size / row size */
		align_base = mr_row_size;
	} else {
		dm_type = MLX5_IB_UAPI_DM_TYPE_HEADER_MODIFY_SW_ICM;
		/* Align base is 64B */
		align_base = DR_ICM_MODIFY_HDR_ALIGN_BASE;
	}

	pthread_mutex_lock(&pool->mr_mutex);
	icm_mr = list_tail(&pool->icm_mr_list, struct dr_icm_mr, mr_list);
	if (icm_mr)
		mr_free_size = icm_mr->mr->length - icm_mr->used_length;

	if (!icm_mr || mr_free_size < mr_row_size) {
		icm_mr = dr_icm_pool_mr_create(pool, dm_type, align_base);
		if (!icm_mr)
			goto out_err;
	}

	/* Create memory aligned chunks */
	for (i = 0; i < mr_row_size / mr_req_size; i++) {
		chunk = calloc(1, sizeof(struct dr_icm_chunk));
		if (!chunk) {
			errno = ENOMEM;
			goto out_err;
		}

		chunk->bucket = bucket;
		chunk->rkey = icm_mr->mr->rkey;
		chunk->mr_addr = (uintptr_t)icm_mr->mr->addr + icm_mr->used_length;
		chunk->icm_addr = (uintptr_t)icm_mr->icm_start_addr + icm_mr->used_length;
		icm_mr->used_length += mr_req_size;
		chunk->num_of_entries = bucket->num_of_entries;
		chunk->byte_size = chunk->num_of_entries * bucket->entry_size;

		if (pool->icm_type == DR_ICM_TYPE_STE)
			if (dr_icm_chunk_ste_init(chunk))
				goto out_free_chunk;

		list_node_init(&chunk->chunk_list);
		list_add(&bucket->free_list, &chunk->chunk_list);
		bucket->free_list_count++;
		bucket->total_chunks++;
	}
	pthread_mutex_unlock(&pool->mr_mutex);
	return 0;

out_free_chunk:
	free(chunk);
out_err:
	pthread_mutex_unlock(&pool->mr_mutex);
	return errno;
}

static void dr_icm_chunk_ste_cleanup(struct dr_icm_chunk *chunk)
{
	free(chunk->miss_list);
	free(chunk->hw_ste_arr);
	free(chunk->ste_arr);
}

static void dr_icm_chunk_destroy(struct dr_icm_chunk *chunk)
{
	struct dr_icm_bucket *bucket = chunk->bucket;

	list_del(&chunk->chunk_list);
	bucket->total_chunks--;

	if (bucket->pool->icm_type == DR_ICM_TYPE_STE)
		dr_icm_chunk_ste_cleanup(chunk);

	free(chunk);
}

static void dr_icm_bucket_init(struct dr_icm_pool *pool,
			       struct dr_icm_bucket *bucket,
			       enum dr_icm_chunk_size chunk_size)
{
	if (pool->icm_type == DR_ICM_TYPE_STE)
		bucket->entry_size = DR_STE_SIZE;
	else
		bucket->entry_size = DR_MODIFY_ACTION_SIZE;

	bucket->num_of_entries = dr_icm_pool_chunk_size_to_entries(chunk_size);
	bucket->pool = pool;
	pthread_mutex_init(&bucket->mutex, NULL);
	list_head_init(&bucket->free_list);
	list_head_init(&bucket->used_list);
	list_head_init(&bucket->hot_list);
	list_head_init(&bucket->tmp_list);
}

static void dr_icm_bucket_cleanup(struct dr_icm_bucket *bucket)
{
	struct dr_icm_chunk *chunk, *next;

	pthread_mutex_destroy(&bucket->mutex);
	list_append_list(&bucket->free_list, &bucket->tmp_list);
	list_append_list(&bucket->free_list, &bucket->hot_list);

	list_for_each_safe(&bucket->free_list, chunk, next, chunk_list)
		dr_icm_chunk_destroy(chunk);

	assert(bucket->total_chunks == 0);

	/* Cleanup of unreturned chunks */
	list_for_each_safe(&bucket->used_list, chunk, next, chunk_list)
		dr_icm_chunk_destroy(chunk);
}

static uint64_t dr_icm_hot_mem_size(struct dr_icm_pool *pool)
{
	uint64_t hot_size = 0;
	int i;

	for (i = 0; i < pool->num_of_buckets; i++)
		hot_size += pool->buckets[i].hot_list_count *
			    dr_icm_pool_chunk_size_to_byte(i, pool->icm_type);

	return hot_size;
}

static bool dr_icm_reuse_hot_entries(struct dr_icm_pool *pool,
				     struct dr_icm_bucket *bucket)
{
	uint64_t bytes_for_sync;

	bytes_for_sync = dr_icm_hot_mem_size(pool);
	if (bytes_for_sync < DR_ICM_SYNC_THRESHOLD || !bucket->hot_list_count)
		return false;

	return true;
}

static void dr_icm_chill_bucket_start(struct dr_icm_bucket *bucket)
{
	list_append_list(&bucket->tmp_list, &bucket->hot_list);
	bucket->tmp_list_count += bucket->hot_list_count;
	bucket->hot_list_count = 0;
}

static void dr_icm_chill_bucket_end(struct dr_icm_bucket *bucket)
{
	list_append_list(&bucket->free_list, &bucket->tmp_list);
	bucket->free_list_count += bucket->tmp_list_count;
	bucket->tmp_list_count = 0;
}

static void dr_icm_chill_bucket_abort(struct dr_icm_bucket *bucket)
{
	list_append_list(&bucket->hot_list, &bucket->tmp_list);
	bucket->hot_list_count += bucket->tmp_list_count;
	bucket->tmp_list_count = 0;
}

static void dr_icm_chill_buckets_start(struct dr_icm_pool *pool,
				       struct dr_icm_bucket *cb,
				       bool bucks[DR_CHUNK_SIZE_MAX])
{
	struct dr_icm_bucket *bucket;
	int i;

	for (i = 0; i < pool->num_of_buckets; i++) {
		bucket = &pool->buckets[i];
		if (bucket == cb) {
			dr_icm_chill_bucket_start(bucket);
			continue;
		}

		/* Freeing the mutex is done at the end of that process, after
		 * sync_ste was executed at dr_icm_chill_buckets_end func.
		 */
		if (!pthread_mutex_trylock(&bucket->mutex)) {
			dr_icm_chill_bucket_start(bucket);
			bucks[i] = true;
		}
	}
}

static void dr_icm_chill_buckets_end(struct dr_icm_pool *pool,
				     struct dr_icm_bucket *cb,
				     bool bucks[DR_CHUNK_SIZE_MAX])
{
	struct dr_icm_bucket *bucket;
	int i;

	for (i = 0; i < pool->num_of_buckets; i++) {
		bucket = &pool->buckets[i];
		if (bucket == cb) {
			dr_icm_chill_bucket_end(bucket);
			continue;
		}

		if (!bucks[i])
			continue;

		dr_icm_chill_bucket_end(bucket);
		pthread_mutex_unlock(&bucket->mutex);
	}
}

static void dr_icm_chill_buckets_abort(struct dr_icm_pool *pool,
				       struct dr_icm_bucket *cb,
				       bool bucks[DR_CHUNK_SIZE_MAX])
{
	struct dr_icm_bucket *bucket;
	int i;

	for (i = 0; i < pool->num_of_buckets; i++) {
		bucket = &pool->buckets[i];
		if (bucket == cb) {
			dr_icm_chill_bucket_abort(bucket);
			continue;
		}

		if (!bucks[i])
			continue;

		dr_icm_chill_bucket_abort(bucket);
		pthread_mutex_unlock(&bucket->mutex);
	}
}

/* Allocate an ICM chunk, each chunk holds a piece of ICM memory and
 * also memory used for HW STE management for optimisations.
 */
struct dr_icm_chunk *dr_icm_alloc_chunk(struct dr_icm_pool *pool,
					enum dr_icm_chunk_size chunk_size)
{
	bool bucks[DR_CHUNK_SIZE_MAX] = {};
	struct dr_icm_bucket *bucket;
	struct dr_icm_chunk *chunk;
	int err;

	if (chunk_size > pool->max_log_chunk_sz) {
		errno = EINVAL;
		return NULL;
	}

	bucket = &pool->buckets[chunk_size];

	pthread_mutex_lock(&bucket->mutex);

	/* Take chunk from pool if available, otherwise allocate new chunks */
	if (list_empty(&bucket->free_list)) {
		if (dr_icm_reuse_hot_entries(pool, bucket)) {
			dr_icm_chill_buckets_start(pool, bucket, bucks);
			err = dr_devx_sync_steering(pool->dmn->ctx);
			if (err) {
				dr_icm_chill_buckets_abort(pool, bucket, bucks);
				dr_dbg(pool->dmn, "Sync_steering failed\n");
				chunk = NULL;
				goto out;
			}
			dr_icm_chill_buckets_end(pool, bucket, bucks);
		} else {
			dr_icm_chunks_create(bucket);
		}
	}

	chunk = list_tail(&bucket->free_list, struct dr_icm_chunk, chunk_list);
	if (chunk) {
		list_del_init(&chunk->chunk_list);
		list_add_tail(&bucket->used_list, &chunk->chunk_list);
		bucket->free_list_count--;
		bucket->used_list_count++;
	}
out:
	pthread_mutex_unlock(&bucket->mutex);
	return chunk;
}

void dr_icm_free_chunk(struct dr_icm_chunk *chunk)
{
	struct dr_icm_bucket *bucket = chunk->bucket;

	if (bucket->pool->icm_type == DR_ICM_TYPE_STE) {
		memset(chunk->ste_arr, 0,
		       bucket->num_of_entries * sizeof(struct dr_ste));
		memset(chunk->hw_ste_arr, 0,
		       bucket->num_of_entries * DR_STE_SIZE_REDUCED);
	}

	pthread_mutex_lock(&bucket->mutex);
	list_del_init(&chunk->chunk_list);
	list_add_tail(&bucket->hot_list, &chunk->chunk_list);
	bucket->hot_list_count++;
	bucket->used_list_count--;
	pthread_mutex_unlock(&bucket->mutex);
}

struct dr_icm_pool *dr_icm_pool_create(struct mlx5dv_dr_domain *dmn,
				       enum dr_icm_type icm_type)
{
	enum dr_icm_chunk_size max_log_chunk_sz;
	struct dr_icm_pool *pool;
	int i;

	if (icm_type == DR_ICM_TYPE_STE)
		max_log_chunk_sz = dmn->info.max_log_sw_icm_sz;
	else
		max_log_chunk_sz = dmn->info.max_log_action_icm_sz;

	pool = calloc(1, sizeof(struct dr_icm_pool));
	if (!pool) {
		errno = ENOMEM;
		return NULL;
	}

	pool->buckets = calloc(max_log_chunk_sz + 1, sizeof(struct dr_icm_bucket));
	if (!pool->buckets) {
		errno = ENOMEM;
		goto free_pool;
	}

	pool->dmn = dmn;
	pool->icm_type = icm_type;
	pool->max_log_chunk_sz = max_log_chunk_sz;
	pool->num_of_buckets = max_log_chunk_sz + 1;
	list_head_init(&pool->icm_mr_list);

	for (i = 0; i < pool->num_of_buckets; i++)
		dr_icm_bucket_init(pool, &pool->buckets[i], i);

	pthread_mutex_init(&pool->mr_mutex, NULL);

	return pool;

free_pool:
	free(pool);
	return NULL;
}

void dr_icm_pool_destroy(struct dr_icm_pool *pool)
{
	struct dr_icm_mr *icm_mr, *next;
	int i;

	pthread_mutex_destroy(&pool->mr_mutex);

	list_for_each_safe(&pool->icm_mr_list, icm_mr, next, mr_list)
		dr_icm_pool_mr_destroy(icm_mr);

	for (i = 0; i < pool->num_of_buckets; i++)
		dr_icm_bucket_cleanup(&pool->buckets[i]);

	free(pool->buckets);
	free(pool);
}
