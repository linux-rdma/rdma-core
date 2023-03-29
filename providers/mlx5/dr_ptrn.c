// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "mlx5dv_dr.h"
#include "dr_ste.h"

enum dr_ptrn_modify_hdr_action_id {
	DR_PTRN_MODIFY_HDR_ACTION_ID_NOP = 0x00,
	DR_PTRN_MODIFY_HDR_ACTION_ID_COPY = 0x05,
	DR_PTRN_MODIFY_HDR_ACTION_ID_SET = 0x06,
	DR_PTRN_MODIFY_HDR_ACTION_ID_ADD = 0x07,
	DR_PTRN_MODIFY_HDR_ACTION_ID_INSERT_INLINE = 0x0a,
};

struct dr_ptrn_mngr {
	struct mlx5dv_dr_domain *dmn;
	struct dr_icm_pool *ptrn_icm_pool;
	/* cache for modify_header ptrn */
	struct list_head ptrn_list;
	pthread_mutex_t modify_hdr_mutex;
};

int dr_ptrn_sync_pool(struct dr_ptrn_mngr *ptrn_mngr)
{
	return dr_icm_pool_sync_pool(ptrn_mngr->ptrn_icm_pool);
}

/* Cache structure and functions */
static bool dr_ptrn_compare_modify_hdr(size_t cur_num_of_actions,
				       __be64 cur_hw_actions[],
				       size_t num_of_actions,
				       __be64 hw_actions[])
{
	int i;

	if (cur_num_of_actions != num_of_actions)
		return false;

	for (i = 0; i < num_of_actions; i++) {
		u8 action_id =
			DEVX_GET(ste_double_action_add_v1, &hw_actions[i], action_id);

		if (action_id == DR_PTRN_MODIFY_HDR_ACTION_ID_COPY) {
			if (hw_actions[i] != cur_hw_actions[i])
				return false;
		} else {
			if ((__force __be32)hw_actions[i] !=
			    (__force __be32)cur_hw_actions[i])
				return false;
		}
	}

	return true;
}

static bool dr_ptrn_compare_pattern(enum dr_ptrn_type type,
				    size_t cur_num_of_actions,
				    __be64 cur_hw_action[],
				    size_t num_of_actions,
				    __be64 hw_action[])
{
	if (cur_num_of_actions != num_of_actions)
		return false;

	switch (type) {
	case DR_PTRN_TYP_MODIFY_HDR:
		return dr_ptrn_compare_modify_hdr(cur_num_of_actions,
						  (__be64 *)cur_hw_action,
						  num_of_actions,
						  (__be64 *)hw_action);
	case DR_PTRN_TYP_TNL_L3_TO_L2:
		return true;
	default:
		assert(false);
		return false;
	}
}

static struct dr_ptrn_obj *
dr_ptrn_find_cached_pattern(struct dr_ptrn_mngr *mngr,
			    enum dr_ptrn_type type,
			    size_t num_of_actions,
			    __be64 hw_actions[])
{
	struct dr_ptrn_obj *tmp;
	struct dr_ptrn_obj *cached_pattern;

	list_for_each_safe(&mngr->ptrn_list, cached_pattern, tmp, list) {
		if (dr_ptrn_compare_pattern(type,
					    cached_pattern->rewrite_param.num_of_actions,
					    (__be64 *)cached_pattern->rewrite_param.data,
					    num_of_actions,
					    hw_actions)) {
			list_del(&cached_pattern->list);
			list_add(&mngr->ptrn_list, &cached_pattern->list);
			return cached_pattern;
		}
	}

	return NULL;
}

static struct dr_ptrn_obj *
dr_ptrn_alloc_pattern(struct dr_ptrn_mngr *mngr,
		      uint16_t num_of_actions, uint8_t *data)
{
	struct dr_ptrn_obj *pattern;
	struct dr_icm_chunk *chunk;
	uint32_t chunck_size;
	uint32_t index;

	chunck_size = ilog32(num_of_actions - 1);
	/* HW modify action index granularity is at least 64B */
	chunck_size = max_t(uint32_t, chunck_size, DR_CHUNK_SIZE_8);

	chunk = dr_icm_alloc_chunk(mngr->ptrn_icm_pool, chunck_size);
	if (!chunk) {
		errno = ENOMEM;
		return NULL;
	}

	index = (dr_icm_pool_get_chunk_icm_addr(chunk) -
		 mngr->dmn->info.caps.hdr_modify_pattern_icm_addr) /
		ACTION_CACHE_LINE_SIZE;

	pattern = calloc(1, sizeof(struct dr_ptrn_obj));
	if (!pattern) {
		errno = ENOMEM;
		goto free_chunk;
	}

	pattern->rewrite_param.data = calloc(1, num_of_actions * DR_MODIFY_ACTION_SIZE);
	if (!pattern->rewrite_param.data) {
		errno = ENOMEM;
		goto free_pattern;
	}

	memcpy(pattern->rewrite_param.data, data, num_of_actions * DR_MODIFY_ACTION_SIZE);
	pattern->rewrite_param.chunk = chunk;
	pattern->rewrite_param.index = index;
	pattern->rewrite_param.num_of_actions = num_of_actions;

	list_add(&mngr->ptrn_list, &pattern->list);
	atomic_init(&pattern->refcount, 0);
	return pattern;

free_pattern:
	free(pattern);
free_chunk:
	dr_icm_free_chunk(chunk);
	return NULL;
}

static void
dr_ptrn_free_pattern(struct dr_ptrn_obj *pattern)
{
	list_del(&pattern->list);
	dr_icm_free_chunk(pattern->rewrite_param.chunk);
	free(pattern->rewrite_param.data);
	free(pattern);
}

struct dr_ptrn_obj *
dr_ptrn_cache_get_pattern(struct dr_ptrn_mngr *mngr,
			  enum dr_ptrn_type type,
			  uint16_t num_of_actions,
			  uint8_t *data)
{
	struct dr_ptrn_obj *pattern;
	uint64_t *hw_actions;
	uint8_t action_id;
	int i;

	pthread_mutex_lock(&mngr->modify_hdr_mutex);
	pattern = dr_ptrn_find_cached_pattern(mngr,
					      type,
					      num_of_actions,
					      (__be64 *)data);
	if (!pattern) {
		/* Alloc and add new pattern to cache */
		pattern = dr_ptrn_alloc_pattern(mngr, num_of_actions, data);
		if (!pattern)
			goto out_unlock;

		hw_actions = (uint64_t *)pattern->rewrite_param.data;
		/* Here we mask the pattern data to create a valid pattern
		 * since we do an OR operation between the arg and pattern
		 */
		for (i = 0; i < num_of_actions; i++) {
			action_id = DR_STE_GET(double_action_add_v1, &hw_actions[i], action_id);

			if (action_id == DR_PTRN_MODIFY_HDR_ACTION_ID_SET ||
			    action_id == DR_PTRN_MODIFY_HDR_ACTION_ID_ADD ||
			    action_id == DR_PTRN_MODIFY_HDR_ACTION_ID_INSERT_INLINE)
				DR_STE_SET(double_action_set_v1, &hw_actions[i], inline_data, 0);
		}

		if (dr_send_postsend_pattern(mngr->dmn,
					     pattern->rewrite_param.chunk,
					     num_of_actions,
					     pattern->rewrite_param.data))
			goto free_pattern;
	}
	atomic_fetch_add(&pattern->refcount, 1);
	pthread_mutex_unlock(&mngr->modify_hdr_mutex);

	return pattern;

free_pattern:
	dr_ptrn_free_pattern(pattern);
out_unlock:
	pthread_mutex_unlock(&mngr->modify_hdr_mutex);
	return NULL;
}

void
dr_ptrn_cache_put_pattern(struct dr_ptrn_mngr *mngr,
			  struct dr_ptrn_obj *pattern)
{
	pthread_mutex_lock(&mngr->modify_hdr_mutex);

	if (atomic_fetch_sub(&pattern->refcount, 1) != 1)
		goto out;

	dr_ptrn_free_pattern(pattern);
out:
	pthread_mutex_unlock(&mngr->modify_hdr_mutex);
}

struct dr_ptrn_mngr *
dr_ptrn_mngr_create(struct mlx5dv_dr_domain *dmn)
{
	struct dr_ptrn_mngr *mngr;

	if (!dr_domain_is_support_modify_hdr_cache(dmn))
		return NULL;

	mngr = calloc(1, sizeof(*mngr));
	if (!mngr) {
		errno = ENOMEM;
		return NULL;
	}

	mngr->dmn = dmn;
	mngr->ptrn_icm_pool = dr_icm_pool_create(dmn, DR_ICM_TYPE_MODIFY_HDR_PTRN);
	if (!mngr->ptrn_icm_pool) {
		dr_dbg(dmn, "Couldn't get modify-header-pattern memory for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto free_mngr;
	}

	list_head_init(&mngr->ptrn_list);
	return mngr;

free_mngr:
	free(mngr);
	return NULL;
}

void dr_ptrn_mngr_destroy(struct dr_ptrn_mngr *mngr)
{
	struct dr_ptrn_obj *tmp;
	struct dr_ptrn_obj *pattern;

	if (!mngr)
		return;

	list_for_each_safe(&mngr->ptrn_list, pattern, tmp, list) {
		list_del(&pattern->list);
		free(pattern->rewrite_param.data);
		free(pattern);
	}

	dr_icm_pool_destroy(mngr->ptrn_icm_pool);
	free(mngr);
}
