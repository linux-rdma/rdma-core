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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <ccan/minmax.h>
#include "mlx5dv_dr.h"

#define DR_RULE_MAX_STE_CHAIN (DR_RULE_MAX_STES + DR_ACTION_MAX_STES)

struct dr_rule_action_member {
	struct mlx5dv_dr_action *action;
	struct list_node	list;
};

static int dr_rule_append_to_miss_list(struct dr_ste *new_last_ste,
				       struct list_head *miss_list,
				       struct list_head *send_list)
{
	struct dr_ste_send_info *ste_info_last;
	struct dr_ste *last_ste;

	/* The new entry will be inserted after the last */
	last_ste = list_tail(miss_list, struct dr_ste, miss_list_node);
	assert(last_ste);

	ste_info_last = calloc(1, sizeof(*ste_info_last));
	if (!ste_info_last) {
		errno = ENOMEM;
		return errno;
	}

	dr_ste_set_miss_addr(last_ste->hw_ste, dr_ste_get_icm_addr(new_last_ste));
	list_add_tail(miss_list, &new_last_ste->miss_list_node);

	dr_send_fill_and_append_ste_send_info(last_ste, DR_STE_SIZE_REDUCED,
					      0, last_ste->hw_ste,
					      ste_info_last, send_list, true);

	return 0;
}

static struct dr_ste
*dr_rule_create_collision_htbl(struct mlx5dv_dr_matcher *matcher,
			       struct dr_matcher_rx_tx *nic_matcher,
			       uint8_t *hw_ste)
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_htbl *new_htbl;
	struct dr_ste *ste;

	/* Create new table for miss entry */
	new_htbl = dr_ste_htbl_alloc(dmn->ste_icm_pool,
				     DR_CHUNK_SIZE_1,
				     DR_STE_LU_TYPE_DONT_CARE,
				     0);
	if (!new_htbl) {
		dr_dbg(dmn, "Failed allocating collision table\n");
		return NULL;
	}

	/* One and only entry, never grows */
	ste = new_htbl->ste_arr;
	dr_ste_set_miss_addr(hw_ste, nic_matcher->e_anchor->chunk->icm_addr);
	dr_htbl_get(new_htbl);

	return ste;
}

static struct dr_ste *dr_rule_create_collision_entry(struct mlx5dv_dr_matcher *matcher,
						     struct dr_matcher_rx_tx *nic_matcher,
						     uint8_t *hw_ste,
						     struct dr_ste *orig_ste)
{
	struct dr_ste *ste;

	ste = dr_rule_create_collision_htbl(matcher, nic_matcher, hw_ste);
	if (!ste) {
		dr_dbg(matcher->tbl->dmn, "Failed creating collision entry\n");
		return NULL;
	}

	ste->ste_chain_location = orig_ste->ste_chain_location;

	/* In collision entry, all members share the same miss_list_head */
	ste->htbl->miss_list = dr_ste_get_miss_list(orig_ste);

	/* Next table */
	if (dr_ste_create_next_htbl(matcher, nic_matcher, ste, hw_ste,
				    DR_CHUNK_SIZE_1)) {
		dr_dbg(matcher->tbl->dmn, "Failed allocating table\n");
		goto free_tbl;
	}

	return ste;

free_tbl:
	dr_ste_free(ste, matcher, nic_matcher);
	return NULL;
}

static int dr_rule_handle_one_ste_in_update_list(struct dr_ste_send_info *ste_info,
						 struct mlx5dv_dr_domain *dmn)
{
	int ret;

	list_del(&ste_info->send_list);
	ret = dr_send_postsend_ste(dmn, ste_info->ste, ste_info->data,
				   ste_info->size, ste_info->offset);
	if (ret)
		goto out;
	/* Copy data to ste, only reduced size, the last 16B (mask)
	 * is already written to the hw.
	 */
	memcpy(ste_info->ste->hw_ste, ste_info->data, DR_STE_SIZE_REDUCED);

out:
	free(ste_info);
	return ret;
}

static int dr_rule_send_update_list(struct list_head *send_ste_list,
				    struct mlx5dv_dr_domain *dmn,
				    bool is_reverse)
{
	struct dr_ste_send_info *ste_info, *tmp_ste_info;
	int ret;

	if (is_reverse) {
		list_for_each_rev_safe(send_ste_list, ste_info, tmp_ste_info,
				       send_list) {
			ret = dr_rule_handle_one_ste_in_update_list(ste_info,
								    dmn);
			if (ret)
				return ret;
		}
	} else {
		list_for_each_safe(send_ste_list, ste_info, tmp_ste_info,
				   send_list) {
			ret = dr_rule_handle_one_ste_in_update_list(ste_info,
								    dmn);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static struct dr_ste *dr_rule_find_ste_in_miss_list(struct list_head *miss_list,
						    uint8_t *hw_ste)
{
	struct dr_ste *ste;

	/* Check if hw_ste is present in the list */
	list_for_each(miss_list, ste, miss_list_node)
		if (dr_ste_equal_tag(ste->hw_ste, hw_ste))
			return ste;

	return NULL;
}

static struct dr_ste *
dr_rule_rehash_handle_collision(struct mlx5dv_dr_matcher *matcher,
				struct dr_matcher_rx_tx *nic_matcher,
				struct list_head *update_list,
				struct dr_ste *col_ste,
				uint8_t *hw_ste)
{
	struct dr_ste *new_ste;
	int ret;

	new_ste = dr_rule_create_collision_htbl(matcher, nic_matcher, hw_ste);
	if (!new_ste)
		return NULL;

	/* In collision entry, all members share the same miss_list_head */
	new_ste->htbl->miss_list = dr_ste_get_miss_list(col_ste);

	/* Update the previous from the list */
	ret = dr_rule_append_to_miss_list(new_ste,
					  dr_ste_get_miss_list(col_ste),
					  update_list);
	if (ret) {
		dr_dbg(matcher->tbl->dmn, "Failed update dup entry\n");
		goto err_exit;
	}

	return new_ste;

err_exit:
	dr_ste_free(new_ste, matcher, nic_matcher);
	return NULL;
}

static void dr_rule_rehash_copy_ste_ctrl(struct mlx5dv_dr_matcher *matcher,
					 struct dr_matcher_rx_tx *nic_matcher,
					 struct dr_ste *cur_ste,
					 struct dr_ste *new_ste)
{
	new_ste->next_htbl = cur_ste->next_htbl;
	new_ste->ste_chain_location = cur_ste->ste_chain_location;

	if (!dr_ste_is_last_in_rule(nic_matcher, new_ste->ste_chain_location))
		new_ste->next_htbl->pointing_ste = new_ste;

	/*
	 * We need to copy the refcount since this ste
	 * may have been traversed several times
	 */
	atomic_init(&new_ste->refcount, atomic_load(&cur_ste->refcount));

	/* Link old STEs rule_mem list to the new ste */
	dr_rule_update_rule_member(cur_ste, new_ste);
	list_head_init(&new_ste->rule_list);
	list_append_list(&new_ste->rule_list, &cur_ste->rule_list);
}

static struct dr_ste *dr_rule_rehash_copy_ste(struct mlx5dv_dr_matcher *matcher,
					      struct dr_matcher_rx_tx *nic_matcher,
					      struct dr_ste *cur_ste,
					      struct dr_ste_htbl *new_htbl,
					      struct list_head *update_list)
{
	uint8_t hw_ste[DR_STE_SIZE] = {};
	struct dr_ste_send_info *ste_info;
	bool use_update_list = false;
	struct dr_ste *new_ste;
	uint8_t sb_idx;
	int new_idx;

	/* Copy STE mask from the matcher */
	sb_idx = cur_ste->ste_chain_location - 1;
	dr_ste_set_bit_mask(hw_ste, nic_matcher->ste_builder[sb_idx].bit_mask);

	/* Copy STE control and tag */
	memcpy(hw_ste, cur_ste->hw_ste, DR_STE_SIZE_REDUCED);

	new_idx = dr_ste_calc_hash_index(hw_ste, new_htbl);
	new_ste = &new_htbl->ste_arr[new_idx];

	if (dr_ste_not_used_ste(new_ste)) {
		dr_htbl_get(new_htbl);
		list_add_tail(dr_ste_get_miss_list(new_ste), &new_ste->miss_list_node);
	} else {
		new_ste = dr_rule_rehash_handle_collision(matcher,
							  nic_matcher,
							  update_list,
							  new_ste,
							  hw_ste);
		if (!new_ste) {
			dr_dbg(matcher->tbl->dmn, "Failed adding collision entry, index: %d\n",
			       new_idx);
			return NULL;
		}
		new_htbl->ctrl.num_of_collisions++;
		use_update_list = true;
	}

	memcpy(new_ste->hw_ste, hw_ste, DR_STE_SIZE_REDUCED);

	new_htbl->ctrl.num_of_valid_entries++;

	if (use_update_list) {
		ste_info = calloc(1, sizeof(*ste_info));
		if (!ste_info) {
			dr_dbg(matcher->tbl->dmn, "Failed allocating ste_info\n");
			errno = ENOMEM;
			goto err_exit;
		}
		dr_send_fill_and_append_ste_send_info(new_ste, DR_STE_SIZE, 0,
						      hw_ste, ste_info,
						      update_list, true);
	}

	dr_rule_rehash_copy_ste_ctrl(matcher, nic_matcher, cur_ste, new_ste);

	return new_ste;

err_exit:
	dr_ste_free(new_ste, matcher, nic_matcher);
	return NULL;
}

static int dr_rule_rehash_copy_miss_list(struct mlx5dv_dr_matcher *matcher,
					 struct dr_matcher_rx_tx *nic_matcher,
					 struct list_head *cur_miss_list,
					 struct dr_ste_htbl *new_htbl,
					 struct list_head *update_list)
{
	struct dr_ste *tmp_ste, *cur_ste, *new_ste;

	list_for_each_safe(cur_miss_list, cur_ste, tmp_ste, miss_list_node) {
		new_ste = dr_rule_rehash_copy_ste(matcher,
						  nic_matcher,
						  cur_ste,
						  new_htbl,
						  update_list);
		if (!new_ste)
			goto err_insert;

		list_del(&cur_ste->miss_list_node);
		dr_htbl_put(cur_ste->htbl);
	}
	return 0;

err_insert:
	dr_dbg(matcher->tbl->dmn, "Fatal error during resize\n");
	assert(false);
	return errno;
}

static int dr_rule_rehash_copy_htbl(struct mlx5dv_dr_matcher *matcher,
				    struct dr_matcher_rx_tx *nic_matcher,
				    struct dr_ste_htbl *cur_htbl,
				    struct dr_ste_htbl *new_htbl,
				    struct list_head *update_list)
{
	struct dr_ste *cur_ste;
	int cur_entries;
	int err = 0;
	int i;

	cur_entries = dr_icm_pool_chunk_size_to_entries(cur_htbl->chunk_size);

	for (i = 0; i < cur_entries; i++) {
		cur_ste = &cur_htbl->ste_arr[i];
		if (dr_ste_not_used_ste(cur_ste)) /* Empty, nothing to copy */
			continue;

		err = dr_rule_rehash_copy_miss_list(matcher,
						    nic_matcher,
						    dr_ste_get_miss_list(cur_ste),
						    new_htbl,
						    update_list);
		if (err)
			goto clean_copy;
	}

clean_copy:
	return err;
}

static struct dr_ste_htbl *dr_rule_rehash_htbl(struct mlx5dv_dr_rule *rule,
					       struct dr_rule_rx_tx *nic_rule,
					       struct dr_ste_htbl *cur_htbl,
					       uint8_t ste_location,
					       struct list_head *update_list,
					       enum dr_icm_chunk_size new_size)
{
	struct dr_matcher_rx_tx *nic_matcher = nic_rule->nic_matcher;
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	struct mlx5dv_dr_matcher *matcher = rule->matcher;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_send_info *del_ste_info, *tmp_ste_info;
	uint8_t formated_ste[DR_STE_SIZE] = {};
	struct dr_ste_send_info *ste_info;
	struct dr_htbl_connect_info info;
	LIST_HEAD(rehash_table_send_list);
	struct dr_ste_htbl *new_htbl;
	struct dr_ste *ste_to_update;
	int err;

	ste_info = calloc(1, sizeof(*ste_info));
	if (!ste_info) {
		errno = ENOMEM;
		return NULL;
	}

	new_htbl = dr_ste_htbl_alloc(dmn->ste_icm_pool,
				     new_size,
				     cur_htbl->lu_type,
				     cur_htbl->byte_mask);
	if (!new_htbl) {
		dr_dbg(dmn, "Failed to allocate new hash table\n");
		goto free_ste_info;
	}

	/* Write new table to HW */
	info.type = CONNECT_MISS;
	info.miss_icm_addr = nic_matcher->e_anchor->chunk->icm_addr;
	dr_ste_set_formated_ste(dmn->info.caps.gvmi,
				nic_dmn,
				new_htbl,
				formated_ste,
				&info);

	new_htbl->pointing_ste = cur_htbl->pointing_ste;
	new_htbl->pointing_ste->next_htbl = new_htbl;
	err = dr_rule_rehash_copy_htbl(matcher,
				       nic_matcher,
				       cur_htbl,
				       new_htbl,
				       &rehash_table_send_list);
	if (err)
		goto free_new_htbl;

	if (dr_send_postsend_htbl(dmn, new_htbl, formated_ste,
				  nic_matcher->ste_builder[ste_location - 1].bit_mask)) {
		dr_dbg(dmn, "Failed writing table to HW\n");
		goto free_new_htbl;
	}

	/*
	 * Writing to the hw is done in regular order of rehash_table_send_list,
	 * in order to have the origin data written before the miss address of
	 * collision entries, if exists.
	 */
	if (dr_rule_send_update_list(&rehash_table_send_list, dmn, false)) {
		dr_dbg(dmn, "Failed updating table to HW\n");
		goto free_ste_list;
	}

	/* Connect previous hash table to current */
	if (ste_location == 1) {
		/* The previous table is an anchor, anchors size is always one STE */
		struct dr_ste_htbl *prev_htbl = cur_htbl->pointing_ste->htbl;

		/* On matcher s_anchor we keep an extra refcount */
		dr_htbl_get(new_htbl);
		dr_htbl_put(cur_htbl);

		nic_matcher->s_htbl = new_htbl;

		/*
		 * It is safe to operate dr_ste_set_hit_addr on the hw_ste here
		 * (48B len) which works only on first 32B
		 */
		dr_ste_set_hit_addr(prev_htbl->ste_arr[0].hw_ste,
				    new_htbl->chunk->icm_addr,
				    new_htbl->chunk->num_of_entries);

		ste_to_update = &prev_htbl->ste_arr[0];
	} else {
		dr_ste_set_hit_addr_by_next_htbl(cur_htbl->pointing_ste->hw_ste,
						 new_htbl);
		ste_to_update = cur_htbl->pointing_ste;
	}

	dr_send_fill_and_append_ste_send_info(ste_to_update, DR_STE_SIZE_REDUCED,
					      0, ste_to_update->hw_ste, ste_info,
					      update_list, false);

	return new_htbl;

free_ste_list:
	/* Clean all ste_info's from the new table */
	list_for_each_safe(&rehash_table_send_list, del_ste_info, tmp_ste_info,
			   send_list) {
		list_del(&del_ste_info->send_list);
		free(del_ste_info);
	}

free_new_htbl:
	dr_ste_htbl_free(new_htbl);
free_ste_info:
	free(ste_info);
	return NULL;
}

static struct dr_ste_htbl *dr_rule_rehash(struct mlx5dv_dr_rule *rule,
					  struct dr_rule_rx_tx *nic_rule,
					  struct dr_ste_htbl *cur_htbl,
					  uint8_t ste_location,
					  struct list_head *update_list)
{
	struct mlx5dv_dr_domain *dmn = rule->matcher->tbl->dmn;
	enum dr_icm_chunk_size new_size;

	new_size = dr_icm_next_higher_chunk(cur_htbl->chunk_size);
	new_size = min_t(uint32_t, new_size, dmn->info.max_log_sw_icm_sz);

	if (new_size == cur_htbl->chunk_size)
		return NULL; /* Skip rehash, we already at the max size */

	return dr_rule_rehash_htbl(rule, nic_rule, cur_htbl, ste_location,
				   update_list, new_size);
}

static struct dr_ste *dr_rule_handle_collision(struct mlx5dv_dr_matcher *matcher,
					       struct dr_matcher_rx_tx *nic_matcher,
					       struct dr_ste *ste,
					       uint8_t *hw_ste,
					       struct list_head *miss_list,
					       struct list_head *send_list)
{
	struct dr_ste_send_info *ste_info;
	struct dr_ste *new_ste;

	ste_info = calloc(1, sizeof(*ste_info));
	if (!ste_info) {
		dr_dbg(matcher->tbl->dmn, "Failed allocating ste_info\n");
		errno = ENOMEM;
		return NULL;
	}

	new_ste = dr_rule_create_collision_entry(matcher, nic_matcher, hw_ste, ste);
	if (!new_ste) {
		dr_dbg(matcher->tbl->dmn, "Failed creating collision entry\n");
		goto free_send_info;
	}

	if (dr_rule_append_to_miss_list(new_ste, miss_list, send_list)) {
		dr_dbg(matcher->tbl->dmn, "Failed to update prev miss_list\n");
		goto err_exit;
	}

	dr_send_fill_and_append_ste_send_info(new_ste, DR_STE_SIZE, 0, hw_ste,
					      ste_info, send_list, false);

	ste->htbl->ctrl.num_of_collisions++;
	ste->htbl->ctrl.num_of_valid_entries++;

	return new_ste;

err_exit:
	dr_ste_free(new_ste, matcher, nic_matcher);
free_send_info:
	free(ste_info);
	return NULL;
}

static void dr_rule_remove_action_members(struct mlx5dv_dr_rule *rule)
{
	struct dr_rule_action_member *action_mem;
	struct dr_rule_action_member *tmp;

	list_for_each_safe(&rule->rule_actions_list, action_mem, tmp, list) {
		list_del(&action_mem->list);
		atomic_fetch_sub(&action_mem->action->refcount, 1);
		free(action_mem);
	}
}

static int dr_rule_add_action_members(struct mlx5dv_dr_rule *rule,
				      size_t num_actions,
				      struct mlx5dv_dr_action *actions[])
{
	struct dr_rule_action_member *action_mem;
	int i;

	for (i = 0; i < num_actions; i++) {
		action_mem = calloc(1, sizeof(*action_mem));
		if (!action_mem) {
			errno = ENOMEM;
			goto free_action_members;
		}

		action_mem->action = actions[i];
		list_node_init(&action_mem->list);
		list_add_tail(&rule->rule_actions_list, &action_mem->list);
		atomic_fetch_add(&action_mem->action->refcount, 1);
	}

	return 0;

free_action_members:
	dr_rule_remove_action_members(rule);
	return errno;
}

/*
 * While the pointer of ste is no longer valid, like while moving ste to be
 * the first in the miss_list, and to be in the origin table,
 * all rule-members that are attached to this ste should update their ste member
 * to the new pointer
 */
void dr_rule_update_rule_member(struct dr_ste *ste, struct dr_ste *new_ste)
{
	struct dr_rule_member *rule_mem;

	list_for_each(&ste->rule_list, rule_mem, use_ste_list)
		rule_mem->ste = new_ste;
}

static void dr_rule_clean_rule_members(struct mlx5dv_dr_rule *rule,
				       struct dr_rule_rx_tx *nic_rule)
{
	struct dr_rule_member *rule_mem;
	struct dr_rule_member *tmp_mem;

	list_for_each_safe(&nic_rule->rule_members_list, rule_mem, tmp_mem, list) {
		list_del(&rule_mem->list);
		list_del(&rule_mem->use_ste_list);
		dr_ste_put(rule_mem->ste, rule->matcher, nic_rule->nic_matcher);
		free(rule_mem);
	}
}

static bool dr_rule_need_enlarge_hash(struct dr_ste_htbl *htbl,
				      struct mlx5dv_dr_domain *dmn,
				      struct dr_domain_rx_tx *nic_dmn)
{
	struct dr_ste_htbl_ctrl *ctrl = &htbl->ctrl;

	if (dmn->info.max_log_sw_icm_sz <= htbl->chunk_size)
		return false;

	if (!ctrl->may_grow)
		return false;

	if (ctrl->num_of_collisions >= ctrl->increase_threshold &&
	    (ctrl->num_of_valid_entries - ctrl->num_of_collisions) >= ctrl->increase_threshold)
		return true;

	return false;
}

static int dr_rule_add_member(struct dr_rule_rx_tx *nic_rule,
			      struct dr_ste *ste)
{
	struct dr_rule_member *rule_mem;

	rule_mem = calloc(1, sizeof(*rule_mem));
	if (!rule_mem) {
		errno = ENOMEM;
		return errno;
	}

	rule_mem->ste = ste;
	list_add_tail(&nic_rule->rule_members_list, &rule_mem->list);

	list_add_tail(&ste->rule_list, &rule_mem->use_ste_list);

	return 0;
}

static int dr_rule_handle_action_stes(struct mlx5dv_dr_rule *rule,
				      struct dr_rule_rx_tx *nic_rule,
				      struct list_head *send_ste_list,
				      struct dr_ste *last_ste,
				      uint8_t *hw_ste_arr,
				      uint32_t new_hw_ste_arr_sz)
{
	struct dr_matcher_rx_tx *nic_matcher = nic_rule->nic_matcher;
	struct dr_ste_send_info *ste_info_arr[DR_ACTION_MAX_STES];
	uint8_t num_of_builders = nic_matcher->num_of_builders;
	struct mlx5dv_dr_matcher *matcher = rule->matcher;
	uint8_t *curr_hw_ste, *prev_hw_ste;
	struct dr_ste *action_ste;
	int i, k, ret;

	/* Two cases:
	 * 1. num_of_builders is equal to new_hw_ste_arr_sz, the action in the ste
	 * 2. num_of_builders is less then new_hw_ste_arr_sz, new ste was added
	 *    to support the action.
	 */
	if (num_of_builders == new_hw_ste_arr_sz)
		return 0;

	for (i = num_of_builders, k = 0; i < new_hw_ste_arr_sz; i++, k++) {
		curr_hw_ste = hw_ste_arr + i * DR_STE_SIZE;
		prev_hw_ste = (i == 0) ? curr_hw_ste : hw_ste_arr + ((i - 1) * DR_STE_SIZE);
		action_ste = dr_rule_create_collision_htbl(matcher,
							   nic_matcher,
							   curr_hw_ste);
		if (!action_ste)
			return errno;

		dr_ste_get(action_ste);

		/* While free ste we go over the miss list, so add this ste to the list */
		list_add_tail(dr_ste_get_miss_list(action_ste),
			      &action_ste->miss_list_node);

		ste_info_arr[k] = calloc(1, sizeof(struct dr_ste_send_info));
		if (!ste_info_arr[k]) {
			dr_dbg(matcher->tbl->dmn, "Failed allocate ste_info, k: %d\n", k);
			errno = ENOMEM;
			ret = errno;
			goto err_exit;
		}

		/* Point current ste to the new action */
		dr_ste_set_hit_addr_by_next_htbl(prev_hw_ste, action_ste->htbl);
		ret = dr_rule_add_member(nic_rule, action_ste);
		if (ret) {
			dr_dbg(matcher->tbl->dmn, "Failed adding rule member\n");
			goto free_ste_info;
		}
		dr_send_fill_and_append_ste_send_info(action_ste, DR_STE_SIZE, 0,
						      curr_hw_ste,
						      ste_info_arr[k],
						      send_ste_list, false);
	}

	return 0;

free_ste_info:
	free(ste_info_arr[k]);
err_exit:
	dr_ste_put(action_ste, matcher, nic_matcher);
	return ret;
}

static int dr_rule_handle_empty_entry(struct mlx5dv_dr_matcher *matcher,
				      struct dr_matcher_rx_tx *nic_matcher,
				      struct dr_ste_htbl *cur_htbl,
				      struct dr_ste *ste,
				      uint8_t ste_location,
				      uint8_t *hw_ste,
				      struct list_head *miss_list,
				      struct list_head *send_list)
{
	struct dr_ste_send_info *ste_info;

	/* Take ref on table, only on first time this ste is used */
	dr_htbl_get(cur_htbl);

	/* new entry -> new branch */
	list_add_tail(miss_list, &ste->miss_list_node);

	dr_ste_set_miss_addr(hw_ste, nic_matcher->e_anchor->chunk->icm_addr);

	ste->ste_chain_location = ste_location;

	ste_info = calloc(1, sizeof(*ste_info));
	if (!ste_info) {
		dr_dbg(matcher->tbl->dmn, "Failed allocating ste_info\n");
		errno = ENOMEM;
		goto clean_ste_setting;
	}

	if (dr_ste_create_next_htbl(matcher,
				    nic_matcher,
				    ste,
				    hw_ste,
				    DR_CHUNK_SIZE_1)) {
		dr_dbg(matcher->tbl->dmn, "Failed allocating table\n");
		goto clean_ste_info;
	}

	cur_htbl->ctrl.num_of_valid_entries++;

	dr_send_fill_and_append_ste_send_info(ste, DR_STE_SIZE, 0, hw_ste,
					      ste_info, send_list, false);

	return 0;

clean_ste_info:
	free(ste_info);

clean_ste_setting:
	list_del_init(&ste->miss_list_node);
	dr_htbl_put(cur_htbl);

	return ENOMEM;
}

static struct dr_ste *dr_rule_handle_ste_branch(struct mlx5dv_dr_rule *rule,
						struct dr_rule_rx_tx *nic_rule,
						struct list_head *send_ste_list,
						struct dr_ste_htbl *cur_htbl,
						uint8_t *hw_ste,
						uint8_t ste_location,
						struct dr_ste_htbl **put_htbl)
{
	struct dr_matcher_rx_tx *nic_matcher = nic_rule->nic_matcher;
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	struct mlx5dv_dr_matcher *matcher = rule->matcher;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_htbl *new_htbl;
	struct list_head *miss_list;
	struct dr_ste *matched_ste;
	bool skip_rehash = false;
	struct dr_ste *ste;
	int index;

again:
	index = dr_ste_calc_hash_index(hw_ste, cur_htbl);
	miss_list = &cur_htbl->chunk->miss_list[index];
	ste = &cur_htbl->ste_arr[index];

	if (dr_ste_not_used_ste(ste)) {
		if (dr_rule_handle_empty_entry(matcher, nic_matcher, cur_htbl,
					       ste, ste_location,
					       hw_ste, miss_list,
					       send_ste_list))
			return NULL;
	} else {
		/* Hash table index in use, check if this ste is in the miss list */
		matched_ste = dr_rule_find_ste_in_miss_list(miss_list, hw_ste);
		if (matched_ste) {
			/*
			 * if it is last STE in the chain, and has the same tag
			 * it means that all the previous stes are the same,
			 * if so, this rule is duplicated.
			 */
			if (dr_ste_is_last_in_rule(nic_matcher, matched_ste->ste_chain_location)) {
				dr_dbg(dmn, "Duplicate rule inserted, aborting\n");
				errno = EINVAL;
				return NULL;
			}
			return matched_ste;
		}

		if (!skip_rehash && dr_rule_need_enlarge_hash(cur_htbl, dmn, nic_dmn)) {
			/* Hash table index in use, try to resize of the hash */
			skip_rehash = true;

			/*
			 * Hold the table till we update.
			 * Release in dr_rule_create_rule_nr()
			 */
			*put_htbl = cur_htbl;
			dr_htbl_get(cur_htbl);

			new_htbl = dr_rule_rehash(rule, nic_rule, cur_htbl,
						  ste_location, send_ste_list);
			if (!new_htbl) {
				dr_htbl_put(cur_htbl);
				dr_dbg(dmn, "Failed creating rehash table, htbl-log_size: %d\n",
				       cur_htbl->chunk_size);
			} else {
				cur_htbl = new_htbl;
			}
			goto again;
		} else {
			/* Hash table index in use, add another collision (miss) */
			ste = dr_rule_handle_collision(matcher,
						       nic_matcher,
						       ste,
						       hw_ste,
						       miss_list,
						       send_ste_list);
			if (!ste) {
				dr_dbg(dmn, "Failed adding collision entry, index: %d\n",
				       index);
				return NULL;
			}
		}
	}
	return ste;
}

static bool dr_rule_cmp_value_to_mask(uint8_t *mask, uint8_t *value,
				      uint32_t s_idx, uint32_t e_idx)
{
	uint32_t i;

	for (i = s_idx; i < e_idx; i++) {
		if (value[i] & ~mask[i]) {
			errno = EINVAL;
			return false;
		}
	}
	return true;
}

static bool dr_rule_verify(struct mlx5dv_dr_matcher *matcher,
			   struct mlx5dv_flow_match_parameters *value,
			   struct dr_match_param *param)
{
	uint8_t match_criteria = matcher->match_criteria;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	uint8_t *mask_p = (uint8_t *)&matcher->mask;
	uint8_t *param_p = (uint8_t *)param;
	size_t value_size = value->match_sz;
	uint32_t s_idx, e_idx;

	if (!value_size ||
	    (value_size > sizeof(struct dr_match_param) ||
	     (value_size % sizeof(uint32_t)))) {
		dr_dbg(dmn, "Rule parameters length is incorrect\n");
		errno = EINVAL;
		return false;
	}

	dr_ste_copy_param(matcher->match_criteria, param, value);

	if (match_criteria & DR_MATCHER_CRITERIA_OUTER) {
		s_idx = offsetof(struct dr_match_param, outer);
		e_idx = min(s_idx + sizeof(param->outer), value_size);

		if (!dr_rule_cmp_value_to_mask(mask_p, param_p, s_idx, e_idx)) {
			dr_dbg(dmn, "Rule outer parameters contains a value not specified by mask\n");
			return false;
		}
	}

	if (match_criteria & DR_MATCHER_CRITERIA_MISC) {
		s_idx = offsetof(struct dr_match_param, misc);
		e_idx = min(s_idx + sizeof(param->misc), value_size);

		if (!dr_rule_cmp_value_to_mask(mask_p, param_p, s_idx, e_idx)) {
			dr_dbg(dmn, "Rule misc parameters contains a value not specified by mask\n");
			return false;
		}
	}

	if (match_criteria & DR_MATCHER_CRITERIA_INNER) {
		s_idx = offsetof(struct dr_match_param, inner);
		e_idx = min(s_idx + sizeof(param->inner), value_size);

		if (!dr_rule_cmp_value_to_mask(mask_p, param_p, s_idx, e_idx)) {
			dr_dbg(dmn, "Rule inner parameters contains a value not specified by mask\n");
			return false;
		}
	}

	if (match_criteria & DR_MATCHER_CRITERIA_MISC2) {
		s_idx = offsetof(struct dr_match_param, misc2);
		e_idx = min(s_idx + sizeof(param->misc2), value_size);

		if (!dr_rule_cmp_value_to_mask(mask_p, param_p, s_idx, e_idx)) {
			dr_dbg(dmn, "Rule misc2 parameters contains a value not specified by mask\n");
			return false;
		}
	}

	if (match_criteria & DR_MATCHER_CRITERIA_MISC3) {
		s_idx = offsetof(struct dr_match_param, misc3);
		e_idx = min(s_idx + sizeof(param->misc3), value_size);

		if (!dr_rule_cmp_value_to_mask(mask_p, param_p, s_idx, e_idx)) {
			dr_dbg(dmn, "Rule misc3 parameters contains a value not specified by mask\n");
			return false;
		}
	}
	return true;
}

static int dr_rule_destroy_rule_nic(struct mlx5dv_dr_rule *rule,
				    struct dr_rule_rx_tx *nic_rule)
{
	dr_rule_clean_rule_members(rule, nic_rule);
	return 0;
}

static int dr_rule_destroy_rule_fdb(struct mlx5dv_dr_rule *rule)
{
	dr_rule_destroy_rule_nic(rule, &rule->rx);
	dr_rule_destroy_rule_nic(rule, &rule->tx);
	return 0;
}

static int dr_rule_destroy_rule(struct mlx5dv_dr_rule *rule)
{
	struct mlx5dv_dr_domain *dmn = rule->matcher->tbl->dmn;

	switch (dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		dr_rule_destroy_rule_nic(rule, &rule->rx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		dr_rule_destroy_rule_nic(rule, &rule->tx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		dr_rule_destroy_rule_fdb(rule);
		break;
	default:
		errno = EINVAL;
		return errno;
	}

	dr_rule_remove_action_members(rule);
	free(rule);
	return 0;
}

static int dr_rule_destroy_rule_root(struct mlx5dv_dr_rule *rule)
{
	int ret;

	ret = ibv_destroy_flow(rule->flow);
	if (ret)
		return ret;

	dr_rule_remove_action_members(rule);
	free(rule);
	return 0;
}

static int dr_rule_skip(enum mlx5dv_dr_domain_type domain,
			enum dr_ste_entry_type ste_type,
			struct dr_match_param *mask,
			struct dr_match_param *value)
{
	if (domain == MLX5DV_DR_DOMAIN_TYPE_FDB) {
		if (mask->misc.source_port) {
			if (ste_type == DR_STE_TYPE_RX)
				if (value->misc.source_port != WIRE_PORT)
					return 1;

			if (ste_type == DR_STE_TYPE_TX)
				if (value->misc.source_port == WIRE_PORT)
					return 1;
		}
	}

	return 0;
}

static int
dr_rule_create_rule_nic(struct mlx5dv_dr_rule *rule,
			struct dr_rule_rx_tx *nic_rule,
			struct dr_match_param *param,
			size_t num_actions,
			struct mlx5dv_dr_action *actions[])
{
	uint8_t hw_ste_arr[DR_RULE_MAX_STE_CHAIN * DR_STE_SIZE] = {};
	struct dr_matcher_rx_tx *nic_matcher = nic_rule->nic_matcher;
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	struct mlx5dv_dr_matcher *matcher = rule->matcher;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_send_info *ste_info, *tmp_ste_info;
	struct dr_ste_htbl *htbl = NULL;
	struct dr_ste_htbl *cur_htbl;
	uint32_t new_hw_ste_arr_sz;
	LIST_HEAD(send_ste_list);
	struct dr_ste *ste = NULL; /* Fix compilation warning */
	int ret, i;

	list_head_init(&nic_rule->rule_members_list);

	if (dr_rule_skip(dmn->type, nic_dmn->ste_type, &matcher->mask, param))
		return 0;

	/* Set the tag values inside the ste array */
	ret = dr_ste_build_ste_arr(matcher, nic_matcher, param, hw_ste_arr);
	if (ret)
		goto out_err;

	/* Set the actions values/addresses inside the ste array */
	ret = dr_actions_build_ste_arr(matcher, nic_matcher, actions,
				       num_actions, hw_ste_arr,
				       &new_hw_ste_arr_sz);
	if (ret)
		goto out_err;

	cur_htbl = nic_matcher->s_htbl;

	/*
	 * Go over the array of STEs, and build dr_ste accordingly.
	 * The loop is over only the builders which are equeal or less to the
	 * number of stes, in case we have actions that lives in other stes.
	 */
	for (i = 0; i < nic_matcher->num_of_builders; i++) {
		/* Calculate CRC and keep new ste entry */
		uint8_t *cur_hw_ste_ent = hw_ste_arr + (i * DR_STE_SIZE);

		ste = dr_rule_handle_ste_branch(rule,
						nic_rule,
						&send_ste_list,
						cur_htbl,
						cur_hw_ste_ent,
						i + 1,
						&htbl);
		if (!ste) {
			dr_dbg(dmn, "Failed creating next branch\n");
			ret = errno;
			goto free_rule;
		}

		cur_htbl = ste->next_htbl;

		/* Keep all STEs in the rule struct */
		ret = dr_rule_add_member(nic_rule, ste);
		if (ret) {
			dr_dbg(dmn, "Failed adding rule member index %d\n", i);
			goto free_ste;
		}

		dr_ste_get(ste);
	}

	/* Connect actions */
	ret = dr_rule_handle_action_stes(rule, nic_rule, &send_ste_list,
					 ste, hw_ste_arr, new_hw_ste_arr_sz);
	if (ret) {
		dr_dbg(dmn, "Failed apply actions\n");
		goto free_rule;
	}
	ret = dr_rule_send_update_list(&send_ste_list, dmn, true);
	if (ret) {
		dr_dbg(dmn, "Failed sending ste!\n");
		goto free_rule;
	}

	if (htbl)
		dr_htbl_put(htbl);

	return 0;

free_ste:
	dr_ste_put(ste, matcher, nic_matcher);
free_rule:
	dr_rule_clean_rule_members(rule, nic_rule);
	/* Clean all ste_info's */
	list_for_each_safe(&send_ste_list, ste_info, tmp_ste_info, send_list) {
		list_del(&ste_info->send_list);
		free(ste_info);
	}
out_err:
	return ret;
}

static int
dr_rule_create_rule_fdb(struct mlx5dv_dr_rule *rule,
			struct dr_match_param *param,
			size_t num_actions,
			struct mlx5dv_dr_action *actions[])
{
	struct dr_match_param copy_param = {};
	int ret;

	/*
	 * Copy match_param since they will be consumed during the first
	 * nic_rule insertion.
	 */
	memcpy(&copy_param, param, sizeof(struct dr_match_param));

	ret = dr_rule_create_rule_nic(rule, &rule->rx, param,
				      num_actions, actions);
	if (ret)
		return ret;

	ret = dr_rule_create_rule_nic(rule, &rule->tx, &copy_param,
				      num_actions, actions);
	if (ret)
		goto destroy_rule_nic_rx;

	return 0;

destroy_rule_nic_rx:
	dr_rule_destroy_rule_nic(rule, &rule->rx);
	return ret;
}

static struct mlx5dv_dr_rule *
dr_rule_create_rule(struct mlx5dv_dr_matcher *matcher,
		    struct mlx5dv_flow_match_parameters *value,
		    size_t num_actions,
		    struct mlx5dv_dr_action *actions[])
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_match_param param = {};
	struct mlx5dv_dr_rule *rule;
	int ret;

	if (!dr_rule_verify(matcher, value, &param))
		return NULL;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		errno = ENOMEM;
		return NULL;
	}

	rule->matcher = matcher;
	list_head_init(&rule->rule_actions_list);

	ret = dr_rule_add_action_members(rule, num_actions, actions);
	if (ret)
		goto free_rule;

	switch (dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		rule->rx.nic_matcher = &matcher->rx;
		ret = dr_rule_create_rule_nic(rule, &rule->rx, &param,
					      num_actions, actions);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		rule->tx.nic_matcher = &matcher->tx;
		ret = dr_rule_create_rule_nic(rule, &rule->tx, &param,
					      num_actions, actions);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		rule->rx.nic_matcher = &matcher->rx;
		rule->tx.nic_matcher = &matcher->tx;
		ret = dr_rule_create_rule_fdb(rule, &param,
					      num_actions, actions);
		break;
	default:
		ret = EINVAL;
		errno = ret;
		break;
	}

	if (ret)
		goto remove_action_members;

	return rule;

remove_action_members:
	dr_rule_remove_action_members(rule);
free_rule:
	free(rule);

	return NULL;
}

static struct mlx5dv_dr_rule *
dr_rule_create_rule_root(struct mlx5dv_dr_matcher *matcher,
			 struct mlx5dv_flow_match_parameters *value,
			 size_t num_actions,
			 struct mlx5dv_dr_action *actions[])
{
	struct mlx5dv_flow_action_attr *attr;
	struct mlx5dv_dr_rule *rule;
	int ret;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		errno = ENOMEM;
		return NULL;
	}

	rule->matcher = matcher;
	list_head_init(&rule->rule_actions_list);

	attr = calloc(num_actions, sizeof(*attr));
	if (!attr) {
		errno = ENOMEM;
		goto free_rule;
	}

	ret = dr_actions_build_attr(matcher, actions, num_actions, attr);
	if (ret)
		goto free_attr;

	ret = dr_rule_add_action_members(rule, num_actions, actions);
	if (ret)
		goto free_attr;

	rule->flow = mlx5dv_create_flow(matcher->dv_matcher,
					value,
					num_actions,
					attr);
	if (!rule->flow)
		goto remove_action_members;

	free(attr);

	return rule;

remove_action_members:
	dr_rule_remove_action_members(rule);
free_attr:
	free(attr);
free_rule:
	free(rule);
	return NULL;
}

struct mlx5dv_dr_rule *mlx5dv_dr_rule_create(struct mlx5dv_dr_matcher *matcher,
					     struct mlx5dv_flow_match_parameters *value,
					     size_t num_actions,
					     struct mlx5dv_dr_action *actions[])
{
	struct mlx5dv_dr_rule *rule;

	pthread_mutex_lock(&matcher->tbl->dmn->mutex);
	atomic_fetch_add(&matcher->refcount, 1);

	if (dr_is_root_table(matcher->tbl))
		rule = dr_rule_create_rule_root(matcher, value, num_actions, actions);
	else
		rule = dr_rule_create_rule(matcher, value, num_actions, actions);

	if (!rule)
		atomic_fetch_sub(&matcher->refcount, 1);

	pthread_mutex_unlock(&matcher->tbl->dmn->mutex);

	return rule;
}

int mlx5dv_dr_rule_destroy(struct mlx5dv_dr_rule *rule)
{
	struct mlx5dv_dr_matcher *matcher = rule->matcher;
	struct mlx5dv_dr_table *tbl = rule->matcher->tbl;
	int ret;

	pthread_mutex_lock(&tbl->dmn->mutex);

	if (dr_is_root_table(tbl))
		ret = dr_rule_destroy_rule_root(rule);
	else
		ret = dr_rule_destroy_rule(rule);

	pthread_mutex_unlock(&tbl->dmn->mutex);

	if (!ret)
		atomic_fetch_sub(&matcher->refcount, 1);
	return ret;
}
